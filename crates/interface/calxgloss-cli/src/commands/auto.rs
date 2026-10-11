//! The `auto` command — smart pipeline dispatcher.
//!
//! Handles classification, batch translation, and the interactive
//! file-selection flow.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use calxgloss::DllCategory;
use calxgloss::PipelineControl;
use calxgloss::PipelineRunRequest;
use calxgloss::ProgressEvent;
use calxgloss::RunScope;
use calxgloss::RunTarget;
use calxgloss::StopSignal;
use calxgloss::TranslationEvents;
use calxgloss::UnitCancellation;
use calxgloss_ghidra::{GhidraClient, GhidraConfig};
use calxgloss_git::BranchCreationPolicy;
use calxgloss_git::DependencyPolicy;
use calxgloss_git::GitManager;
use calxgloss_llm::LlmClient;
use calxgloss_llm::LlmConfig;
use calxgloss_translator::RetryConfig;
use calxgloss_translator::TranslationPipeline;
use calxgloss_translator::build_hallucination_detector;
use tracing::{info, warn};

use crate::Settings;
use crate::commands::classify::handle_classify;
use crate::commands::{classification_record_exists, scan_targets};
use crate::utils::*;

/// Run batch translation for a single DLL.
///
/// This function encapsulates all the plumbing needed to translate one DLL:
/// Ghidra setup, LLM client, test generator, pipeline, git operations, and
/// result reporting.  Both `handle_auto` and `handle_live` call this.
///
/// `scope` restricts which functions re-enter the translation queue based on
/// the recorded attempt history (see [`scope_functions`]);
/// [`RunScope::AllFunctions`] keeps the plain behaviour.
// The per-binary plumbing (Ghidra, LLM, git, live hooks) is one coherent
// pass — bundling it into a struct would scatter the call site for no gain.
#[allow(clippy::too_many_arguments)]
pub async fn run_translation_for_dll(
    binary: &str,
    binary_path: &Path,
    workspace: &Path,
    skip_git: bool,
    settings: &Settings,
    events: Option<&TranslationEvents>,
    no_callgraph: bool,
    callgraph_cache: Option<PathBuf>,
    callgraph_verbose: bool,
    refresh_ghidra_cache: bool,
    stop: Option<&StopSignal>,
    control: Option<&PipelineControl>,
    cancellation: Option<&UnitCancellation>,
    scope: RunScope,
) -> Result<()> {
    // The workspace — git, src/, scratch all live here.

    // Announce the per-binary pass so the dashboard can mark this binary as
    // being worked on before any unit event exists — function enumeration,
    // analysis recovery, and test generation can run for minutes first.
    if let Some(ev) = events {
        ev.emit(ProgressEvent::BatchStarted {
            binary: binary.to_string().into(),
        });
    }

    // Get Ghidra client to list functions
    let ghidra_url = &settings.ghidra_url.value;
    let mut ghidra_config = GhidraConfig::new(ghidra_url)
        .with_context(|| format!("Failed to parse GhidraMCP URL: {}", ghidra_url))?;
    if let Some(key) = &settings.ghidra_api_key {
        ghidra_config = ghidra_config.with_api_key(key.value.clone());
    }
    let ghidra = GhidraClient::from_config(ghidra_config)
        .with_context(|| format!("Failed to connect to GhidraMCP at {}", ghidra_url))?;

    // List functions from Ghidra
    let summaries = ghidra
        .list_functions()
        .await
        .with_context(|| "Failed to list functions from GhidraMCP")?;

    if summaries.is_empty() {
        warn!("GhidraMCP returned no functions");
        println_content("No functions found in the open Ghidra program.");
        return Ok(());
    }

    let function_names: Vec<String> = summaries.into_iter().map(|s| s.name).collect();
    info!(
        count = function_names.len(),
        "Enumerated functions from Ghidra"
    );

    // W2.3 scope selectors: only-queued / only-failed restrict the queue plan
    // to functions whose recorded attempt history matches, making the filter
    // observable in the batch summary and per-unit events.
    let function_names = scope_functions(binary, workspace, scope, function_names)?;
    if function_names.is_empty() {
        // Still emit the batch summary so the dashboard sees the pass happened.
        if let Some(ev) = events {
            ev.emit(ProgressEvent::BatchSummary {
                binary: binary.to_string().into(),
                total_functions: 0,
                success_count: 0,
                failure_count: 0,
                total_attempts: 0,
                total_tokens: 0,
            });
        }
        info!("Skipping translation for {binary}: no functions match scope {scope}");
        return Ok(());
    }

    // Get LLM settings
    let llm_url = settings.require_llm_url()?;
    let llm_model = settings.require_llm_model()?;
    let max_tokens = settings.max_tokens.value;
    let temperature = settings.temperature.value;
    let max_retries = settings.max_retries.value;

    let retry_strategy = match &settings.retry_strategy {
        Some(r) => parse_retry_strategy(&r.value)?,
        None => RetryStrategy::CompileFix,
    };

    info!(
        binary = %binary,
        function_count = function_names.len(),
        "Starting batch translation"
    );

    // Initialize output directory
    let modules_dir = workspace.join("src").join("modules");
    std::fs::create_dir_all(&modules_dir).context("Failed to create modules directory")?;

    // Initialize LLM client
    let mut llm_config = LlmConfig::new(llm_url, llm_model)
        .with_context(|| format!("Failed to parse LLM URL: {}", llm_url))?;
    if let Some(key) = &settings.llm_api_key {
        llm_config = llm_config.with_api_key(key.value.clone());
    }
    llm_config = llm_config
        .with_max_tokens(max_tokens)
        .with_temperature(temperature);
    let llm = LlmClient::new(llm_config).context("Failed to create LLM client")?;

    // Initialize analyzer, test generator
    let testgen = calxgloss_testgen::TestGenerator::new(workspace);

    // Build translation pipeline
    let api_mappings = calxgloss_pal::ApiMappings::default();
    let detector = build_hallucination_detector(&ghidra, &api_mappings).await;
    let mut pipeline = TranslationPipeline::new(ghidra, llm, api_mappings)
        .with_testgen(testgen)
        .with_hallucination_detector(detector);
    if no_callgraph {
        pipeline = pipeline.with_no_callgraph();
    }
    if let Some(ref cache_dir) = callgraph_cache {
        pipeline = pipeline.with_callgraph_cache_dir(cache_dir);
    }
    if callgraph_verbose {
        pipeline = pipeline.with_callgraph_verbose();
    }
    if let Some(events) = events {
        pipeline = pipeline.with_events(events.clone());
    }
    if let Some(stop) = stop {
        pipeline = pipeline.with_stop_signal(stop.clone());
    }
    if let Some(control) = control {
        pipeline = pipeline.with_pipeline_control(control.clone());
    }
    if let Some(cancellation) = cancellation {
        pipeline = pipeline.with_unit_cancellation(cancellation.clone());
    }
    pipeline = pipeline.with_workspace(workspace);
    // The batch's shared Ghidra read cache keys on the target binary's
    // file bytes (issue #105).
    pipeline = pipeline.with_binary_path(binary_path);
    // The refresh escape hatch (issue #106): force the cache cold when the
    // operator says the Ghidra program changed under unchanged bytes.
    if refresh_ghidra_cache {
        pipeline = pipeline.with_refresh_ghidra_cache();
    }

    // Git setup
    let mut git = if !skip_git {
        info!("Initializing git repository");
        let git_config = calxgloss_git::InitConfig::default();
        Some(
            GitManager::init_repo(workspace, Some(git_config))
                .context("Failed to initialize git repository")?,
        )
    } else {
        info!("Skipping git operations");
        None
    };

    // Initialize verifier for retry loop
    let verifier = Verifier::new(workspace).context("Failed to create verifier")?;

    let retry_config = RetryConfig {
        max_attempts: max_retries,
        strategy: retry_strategy,
        escalate_on_failure: true,
    };

    // Run batch translation with an inline callback that handles git operations
    // for each function immediately after it completes.
    //
    // This enables incremental git commits: as soon as a function's translation
    // pipeline finishes (including retries), the result is written, committed,
    // and merged — before the next function even starts.
    let batch_result = pipeline
        .batch_translate(
            binary,
            &function_names,
            &retry_config,
            &verifier,
            Some(&mut |_dll, _function, func_result| {
                if !func_result.success {
                    return true;
                }

                let rust_code = func_result.rust_code.as_ref().unwrap();
                let output_path = modules_dir
                    .join(&func_result.function)
                    .join("translated.rs");
                if let Err(e) = std::fs::create_dir_all(output_path.parent().unwrap())
                    .context("Failed to create output directory")
                {
                    warn!(error = %e, "Failed to create output directory");
                    return true;
                }
                if let Err(e) = std::fs::write(&output_path, rust_code).with_context(|| {
                    format!(
                        "Failed to write translated code to {}",
                        output_path.display()
                    )
                }) {
                    warn!(error = %e, "Failed to write translated code");
                    return true;
                }

                if let Some(ref mut git_manager) = git
                    && let Ok(branch_result) = git_manager.create_branch(
                        binary,
                        &func_result.function,
                        1,
                        Some(&BranchCreationPolicy::Warn(DependencyPolicy {
                            category: DllCategory::ProjectSpecific,
                            crate_replacement: None,
                        })),
                    )
                {
                    let branch_info = &branch_result.branch;
                    print_git_status(branch_info, false);

                    if let Some(output_path_str) = output_path.to_str()
                        && let Ok(_commit) = git_manager.commit(
                            branch_info,
                            &format!(
                                "re/auto/{}: translate {} (batch attempt)",
                                func_result.function, binary
                            ),
                            &[output_path_str],
                        )
                        && let Ok(merge_result) = git_manager.merge_to_main(branch_info)
                    {
                        match &merge_result {
                            calxgloss_git::MergeResult::Merged { merge_hash } => {
                                info!(hash = %merge_hash, "Translation accepted and merged");
                            }
                            calxgloss_git::MergeResult::AlreadyUpToDate => {
                                info!("Branch was already up to date with main");
                            }
                            calxgloss_git::MergeResult::Conflicts {
                                conflicted_files,
                                error,
                            } => {
                                warn!(files = ?conflicted_files, error = %error, "Merge conflicts");
                            }
                        }
                        func_result.branch = Some(branch_info.clone());
                    }
                }
                true
            }),
        )
        .await
        .with_context(|| format!("Batch translation failed for DLL: {}", binary))?;

    print_batch_summary(&batch_result);

    // Emit batch summary event for live mode
    if let Some(events) = events {
        let total_attempts: usize = batch_result
            .results
            .iter()
            .map(|r| r.retry_result.attempts.len())
            .sum();
        let total_tokens: usize = batch_result
            .results
            .iter()
            .flat_map(|r| &r.retry_result.attempts)
            .filter_map(|a| a.tokens_used)
            .sum();
        events.emit(ProgressEvent::BatchSummary {
            binary: binary.to_string().into(),
            total_functions: batch_result.total_count(),
            success_count: batch_result.success_count(),
            failure_count: batch_result.failure_count(),
            total_attempts,
            total_tokens,
        });
    }

    if batch_result.all_success() {
        println!(
            "\n  {}",
            green_bold(&format!(
                "Batch complete: all {} functions translated successfully",
                batch_result.total_count()
            ))
        );
    } else if batch_result.any_success() {
        println!(
            "\n  {}",
            yellow_bold(&format!(
                "Batch complete: {} succeeded, {} failed out of {} functions",
                batch_result.success_count(),
                batch_result.failure_count(),
                batch_result.total_count()
            ))
        );
    } else {
        println!(
            "\n  {}",
            red_bold(&format!(
                "Batch complete: all {} functions failed",
                batch_result.total_count()
            ))
        );
    }

    println!();
    println_content("To review, run: calxgloss dashboard");
    println_content(
        "To see the web UI (requires server feature): cargo run --features server --bin web_server",
    );
    println!();

    Ok(())
}

/// Handle the `auto` subcommand: detects project state and runs classification
/// then batch translation.
///
/// `run` carries the W2.3 start/restart selectors: `target` restricts the run
/// to one binary, `phase=Classify` forces re-classification, and `scope`
/// restricts which functions re-enter the translation queue (see
/// [`scope_functions`]). `None` keeps the plain `auto` behaviour.
// Mirrors the CLI flag surface plus the live-mode hooks; every caller
// passes the same settings-derived values, so a struct would only rename
// the plumbing.
#[allow(clippy::too_many_arguments)]
pub async fn handle_auto(
    target: Option<PathBuf>,
    binaries_arg: Option<String>,
    _all_functions: bool,
    classify_only: bool,
    skip_git: bool,
    settings: &Settings,
    continue_mode: bool,
    events: Option<&TranslationEvents>,
    workspace: PathBuf,
    no_callgraph: bool,
    callgraph_cache: Option<PathBuf>,
    callgraph_verbose: bool,
    refresh_ghidra_cache: bool,
    stop: Option<&StopSignal>,
    control: Option<&PipelineControl>,
    cancellation: Option<&UnitCancellation>,
    run: Option<&PipelineRunRequest>,
) -> Result<()> {
    info!("Auto mode: detecting project state");

    // target_dir is required: it's the directory containing DLLs/EXEs.
    let target_dir = settings
        .target_dir
        .as_ref()
        .map(|r| PathBuf::from(&r.value))
        .or_else(|| target.clone())
        .ok_or_else(|| anyhow::anyhow!(
            "target_dir is required.\n\nSet it via:\n  --target-dir <path>\n  [target_dir] in calxgloss.toml\n  CALXGLOSS_TARGET_DIR env var"
        ))?;

    info!(path = ?target_dir, "Auto mode: using target directory");
    info!(path = ?workspace, "Auto mode: using workspace");

    // Discover or accept DLL list
    let dlls = if let Some(ref dll_list) = binaries_arg {
        dll_list
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    } else {
        scan_targets(&target_dir)
    };

    if dlls.is_empty() {
        println!(
            "  {} No DLL/EXE files found in {}.",
            red_bold("✗"),
            target_dir.display()
        );
        println_content(
            "Specify files explicitly: calxgloss auto --binaries \"eqgame.dll,myapp.exe\"",
        );
        anyhow::bail!("No files found");
    }

    // W2.3 target selector: restrict the run to one binary. A name that is
    // not in the discovered set is a clear error, not a silent no-op.
    let dlls = match run.map(|r| &r.target) {
        None | Some(RunTarget::All) => dlls,
        Some(RunTarget::Binary(id)) => {
            let name = id.as_str();
            if !dlls.iter().any(|d| d.eq_ignore_ascii_case(name)) {
                anyhow::bail!(
                    "run target {name} was not found in {}",
                    target_dir.display()
                );
            }
            dlls.into_iter()
                .filter(|d| d.eq_ignore_ascii_case(name))
                .collect()
        }
    };
    // `phase=Classify` re-runs classification even for already-classified
    // binaries; the default phase leaves the detection logic untouched.
    let force_classify = run.is_some_and(|r| r.phase == calxgloss::RunPhase::Classify);

    println!();
    hsep_bold();
    println_content(format!(
        "  Calxgloss Auto — {} file(s) found",
        bold(&dlls.len().to_string())
    ));
    hsep();
    println_content("");
    for binary in &dlls {
        println_content(format!(
            "  • {}{}",
            bold(binary),
            if classification_record_exists(&workspace, binary) {
                format!("  [{}] already classified", yellow_bold("done"))
            } else {
                format!("  [{}] needs classification", red_bold("pending"))
            }
        ));
    }
    println_content("");

    // Determine which DLLs are classified and which are not
    let mut classified: Vec<String> = dlls
        .iter()
        .filter(|d| !force_classify && classification_record_exists(&workspace, d))
        .cloned()
        .collect();
    let unclassified: Vec<String> = dlls
        .iter()
        .filter(|d| force_classify || !classification_record_exists(&workspace, d))
        .cloned()
        .collect();

    // Step 1: Classify unclassified files
    if !unclassified.is_empty() {
        println!(
            "  {} Classifying {} unclassified file(s)…",
            cyan_bold("→"),
            bold(&unclassified.len().to_string())
        );
        println_content("");
        handle_classify(
            &unclassified,
            &target_dir,
            &workspace,
            skip_git,
            settings,
            events,
        )
        .await?;
        println_content("");
        if !continue_mode {
            println_content(
                "Classification complete. Review the report above, then run again to translate.",
            );
            println!();
            return Ok(());
        }
        println_content("Classification complete. Starting translation…");

        // Newly classified DLLs are now ready — fold them into the classified list
        // so the translation loop picks them up.
        classified.extend(unclassified);
    }

    // All files are classified
    if classified.is_empty() {
        println_content("No classified files found; nothing to do.");
        return Ok(());
    }

    println!(
        "  {} {} file(s) classified, ready for translation",
        green_bold("✓"),
        bold(&classified.len().to_string())
    );
    println_content("");

    if classify_only {
        println_content("Classification complete. All files are classified.");
        println_content("Re-run without --classify-only to start translation.");
        return Ok(());
    }

    if continue_mode {
        // Translate all classified files in sequence (non-interactive).
        println!();
        println!(
            "  {} Translating {} file(s) in sequence…",
            cyan_bold("→"),
            bold(&classified.len().to_string())
        );
        println!();

        // Publish the plan before the first pass starts so the dashboard
        // can show the whole queue — in this exact order — not just the
        // binary currently in flight.
        if let Some(ev) = events {
            ev.emit(ProgressEvent::QueuePlanned {
                binaries: classified.clone(),
            });
        }

        for binary in &classified {
            if stop.is_some_and(|s| s.is_stopped()) {
                println!();
                println_content("Stop requested — skipping remaining binaries.");
                println_content("Work completed so far is saved; restart to continue.");
                break;
            }
            // Issue #90: a stop requested through the pipeline control (or a
            // run that already reached a terminal state) also ends the queue
            // between binaries — the pipeline itself halts at unit
            // boundaries, this keeps us from starting the next pass.
            if control.is_some_and(|c| c.state().is_halted()) {
                println!();
                println_content("Pipeline stop requested — skipping remaining binaries.");
                println_content("Work completed so far is saved; restart to continue.");
                break;
            }
            println!(
                "  {} Translating functions from {}…",
                cyan_bold("→"),
                bold(binary)
            );
            println!();
            run_translation_for_dll(
                binary,
                &target_dir.join(binary),
                &workspace,
                skip_git,
                settings,
                events,
                no_callgraph,
                callgraph_cache.clone(),
                callgraph_verbose,
                refresh_ghidra_cache,
                stop,
                control,
                cancellation,
                run.map(|r| r.scope).unwrap_or_default(),
            )
            .await?;
        }
    } else {
        // Ask which file to translate (interactive mode).
        println!();
        println!("  {} Which file would you like to translate?", bold("?"));
        println!();
        for (i, binary) in classified.iter().enumerate() {
            let num = i + 1;
            println_content(format!("  {}  {}", num, bold(binary)));
        }
        println_content("");
        println_content("Enter a number (or 0 to cancel):");
        print!("  > ");
        std::io::Write::flush(&mut std::io::stdout()).ok();

        let mut input = String::new();
        std::io::stdin().read_line(&mut input).ok();
        let choice: usize = input.trim().parse().unwrap_or(0);

        if choice == 0 || choice > classified.len() {
            println!();
            println_content("Cancelled.");
            return Ok(());
        }

        let binary = &classified[choice - 1];
        println!();
        println!(
            "  {} Translating functions from {}…",
            cyan_bold("→"),
            bold(binary)
        );
        println!();

        run_translation_for_dll(
            binary,
            &target_dir.join(binary),
            &workspace,
            skip_git,
            settings,
            events,
            no_callgraph,
            callgraph_cache,
            callgraph_verbose,
            refresh_ghidra_cache,
            stop,
            control,
            cancellation,
            run.map(|r| r.scope).unwrap_or_default(),
        )
        .await?;
    }

    Ok(())
}

/// Filter the enumerated functions down to the ones the run scope admits.
///
/// The scope reads the recorded attempt history (`re/analysis/token_usage.json`):
/// a function is *attempted* when it has any recorded attempt for this binary,
/// and *succeeded* when any attempt succeeded.
///
/// * [`RunScope::AllFunctions`] — everything (the plain behaviour).
/// * [`RunScope::OnlyQueued`] — never attempted: the backlog a first run left
///   untouched (skipped by the call-graph plan or blocked by a stop).
/// * [`RunScope::OnlyFailed`] — attempted but never succeeded: the retry set.
///
/// A missing history file means nothing was attempted, so `OnlyQueued` keeps
/// the whole list and `OnlyFailed` keeps none.
pub(crate) fn scope_functions(
    binary: &str,
    workspace: &Path,
    scope: RunScope,
    functions: Vec<String>,
) -> Result<Vec<String>> {
    if scope == RunScope::AllFunctions {
        return Ok(functions);
    }
    let log = calxgloss_analysis::TokenUsageLogger::new(workspace)
        .load()
        .unwrap_or_default();
    let identity = calxgloss_types::BinaryIdentity::new(binary);
    Ok(functions
        .into_iter()
        .filter(|name| {
            let entries: Vec<_> = log
                .entries
                .iter()
                .filter(|e| e.binary == identity && e.function == *name)
                .collect();
            match scope {
                RunScope::OnlyQueued => entries.is_empty(),
                RunScope::OnlyFailed => !entries.is_empty() && !entries.iter().any(|e| e.success),
                RunScope::AllFunctions => true,
            }
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use calxgloss_types::TokenUsageEntry;

    fn sample_functions() -> Vec<String> {
        ["DrawSprite", "DrawVertex", "UpdateGame"]
            .iter()
            .map(|s| s.to_string())
            .collect()
    }

    fn temp_workspace() -> tempfile::TempDir {
        tempfile::tempdir().expect("temp workspace")
    }

    #[test]
    fn scope_all_functions_keeps_everything_without_reading_history() {
        let workspace = temp_workspace();
        let kept = scope_functions(
            "game_logic.dll",
            workspace.path(),
            RunScope::AllFunctions,
            sample_functions(),
        )
        .expect("all-functions scope never fails");
        assert_eq!(kept, sample_functions());
    }

    #[test]
    fn scope_filters_follow_the_recorded_attempt_history() {
        let workspace = temp_workspace();
        let logger = calxgloss_analysis::TokenUsageLogger::new(workspace.path());
        // DrawSprite: attempted and succeeded. DrawVertex: attempted, failed
        // twice. UpdateGame: never attempted.
        logger.record(TokenUsageEntry::new(
            "game_logic.dll",
            "DrawSprite",
            1,
            "initial",
            100,
            true,
        ));
        logger.record(TokenUsageEntry::new(
            "game_logic.dll",
            "DrawVertex",
            1,
            "initial",
            100,
            false,
        ));
        logger.record(TokenUsageEntry::new(
            "game_logic.dll",
            "DrawVertex",
            2,
            "compile_fix",
            100,
            false,
        ));

        let queued = scope_functions(
            "game_logic.dll",
            workspace.path(),
            RunScope::OnlyQueued,
            sample_functions(),
        )
        .expect("scope filter should succeed");
        assert_eq!(queued, ["UpdateGame"]);

        let failed = scope_functions(
            "game_logic.dll",
            workspace.path(),
            RunScope::OnlyFailed,
            sample_functions(),
        )
        .expect("scope filter should succeed");
        assert_eq!(failed, ["DrawVertex"]);
    }

    #[test]
    fn scope_without_history_file_keeps_all_for_queued_and_none_for_failed() {
        let workspace = temp_workspace();
        let queued = scope_functions(
            "game_logic.dll",
            workspace.path(),
            RunScope::OnlyQueued,
            sample_functions(),
        )
        .expect("missing history is not an error");
        assert_eq!(queued, sample_functions());

        let failed = scope_functions(
            "game_logic.dll",
            workspace.path(),
            RunScope::OnlyFailed,
            sample_functions(),
        )
        .expect("missing history is not an error");
        assert!(failed.is_empty());
    }

    #[test]
    fn scope_ignores_other_binaries_history() {
        let workspace = temp_workspace();
        let logger = calxgloss_analysis::TokenUsageLogger::new(workspace.path());
        logger.record(TokenUsageEntry::new(
            "other.dll",
            "DrawSprite",
            1,
            "initial",
            100,
            true,
        ));

        let queued = scope_functions(
            "game_logic.dll",
            workspace.path(),
            RunScope::OnlyQueued,
            sample_functions(),
        )
        .expect("scope filter should succeed");
        assert_eq!(queued, sample_functions());
    }
}
