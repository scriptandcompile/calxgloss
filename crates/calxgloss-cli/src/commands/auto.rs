//! The `auto` command — smart pipeline dispatcher.
//!
//! Handles classification, batch translation, and the interactive
//! file-selection flow.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use calxgloss::DllCategory;
use calxgloss::ProgressEvent;
use calxgloss::TranslationEvents;
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
pub async fn run_translation_for_dll(
    dll: &str,
    output_dir: &Path,
    skip_git: bool,
    settings: &Settings,
    events: Option<&TranslationEvents>,
    no_callgraph: bool,
) -> Result<()> {
    // output_dir is the workspace directory — git, src/, scratch all live here.

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
        dll = %dll,
        function_count = function_names.len(),
        "Starting batch translation"
    );

    // Initialize output directory
    let modules_dir = output_dir.join("src").join("modules");
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
    let testgen = calxgloss_testgen::TestGenerator::new(output_dir);

    // Build translation pipeline
    let api_mappings = calxgloss_pal::ApiMappings::default();
    let detector = build_hallucination_detector(&ghidra, &api_mappings).await;
    let mut pipeline = TranslationPipeline::new(ghidra, llm, api_mappings)
        .with_testgen(testgen)
        .with_hallucination_detector(detector);
    if no_callgraph {
        pipeline = pipeline.with_no_callgraph();
    }
    if let Some(events) = events {
        pipeline = pipeline.with_events(events.clone());
    }

    // Git setup
    let mut git = if !skip_git {
        info!("Initializing git repository");
        let git_config = calxgloss_git::InitConfig::default();
        Some(
            GitManager::init_repo(output_dir, Some(git_config))
                .context("Failed to initialize git repository")?,
        )
    } else {
        info!("Skipping git operations");
        None
    };

    // Initialize verifier for retry loop
    let verifier = Verifier::new(output_dir).context("Failed to create verifier")?;

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
            dll,
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
                        dll,
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
                                func_result.function, dll
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
        .with_context(|| format!("Batch translation failed for DLL: {}", dll))?;

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
            dll: dll.to_string(),
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
#[allow(clippy::too_many_arguments)]
pub async fn handle_auto(
    target: Option<PathBuf>,
    dlls_arg: Option<String>,
    _all_functions: bool,
    classify_only: bool,
    skip_git: bool,
    settings: &Settings,
    continue_mode: bool,
    events: Option<&TranslationEvents>,
    repo_dir: PathBuf,
    no_callgraph: bool,
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
    info!(path = ?repo_dir, "Auto mode: using repo directory");

    // Discover or accept DLL list
    let dlls = if let Some(ref dll_list) = dlls_arg {
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
        println_content("Specify files explicitly: calxgloss auto --dlls \"eqgame.dll,myapp.exe\"");
        anyhow::bail!("No files found");
    }

    println!();
    hsep_bold();
    println_content(format!(
        "  Calxgloss Auto — {} file(s) found",
        bold(&dlls.len().to_string())
    ));
    hsep();
    println_content("");
    for dll in &dlls {
        println_content(format!(
            "  • {}{}",
            bold(dll),
            if classification_record_exists(&repo_dir, dll) {
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
        .filter(|d| classification_record_exists(&repo_dir, d))
        .cloned()
        .collect();
    let unclassified: Vec<String> = dlls
        .iter()
        .filter(|d| !classification_record_exists(&repo_dir, d))
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
            &repo_dir,
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

    let output_dir = repo_dir;

    if continue_mode {
        // Translate all classified files in sequence (non-interactive).
        println!();
        println!(
            "  {} Translating {} file(s) in sequence…",
            cyan_bold("→"),
            bold(&classified.len().to_string())
        );
        println!();

        for dll in &classified {
            println!(
                "  {} Translating functions from {}…",
                cyan_bold("→"),
                bold(dll)
            );
            println!();
            run_translation_for_dll(dll, &output_dir, skip_git, settings, events, no_callgraph).await?;
        }
    } else {
        // Ask which file to translate (interactive mode).
        println!();
        println!("  {} Which file would you like to translate?", bold("?"));
        println!();
        for (i, dll) in classified.iter().enumerate() {
            let num = i + 1;
            println_content(format!("  {}  {}", num, bold(dll)));
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

        let dll = &classified[choice - 1];
        println!();
        println!(
            "  {} Translating functions from {}…",
            cyan_bold("→"),
            bold(dll)
        );
        println!();

        run_translation_for_dll(dll, &output_dir, skip_git, settings, events, no_callgraph).await?;
    }

    Ok(())
}
