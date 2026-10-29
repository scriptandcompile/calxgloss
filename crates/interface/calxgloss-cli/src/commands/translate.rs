//! The `translate` command — translate a single function.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use calxgloss::ContextTier;
use calxgloss::DllCategory;
use calxgloss::GitBranch;
use calxgloss_config::Resolved;
use calxgloss_git::BranchCreationPolicy;
use calxgloss_git::DependencyPolicy;
use calxgloss_git::GitManager;
use calxgloss_translator::Translation;
use calxgloss_translator::assembly::LlmSelection;
use calxgloss_translator::assembly::assemble;
use calxgloss_verify::VerificationResult;
use tracing::{error, info, warn};

use crate::Settings;
use crate::cli_types::TranslateArgs;
use crate::commands::auto::GitAcceptedAttempts;
use crate::commands::run_options::{PassFlags, command_pass_spec};
use crate::utils::*;

/// Handle the `translate` subcommand: translate a single function from disassembly.
pub async fn handle_translate(
    args: &TranslateArgs,
    settings: &Settings,
    workspace: PathBuf,
    callgraph_cache: Option<PathBuf>,
    callgraph_verbose: bool,
) -> Result<()> {
    let TranslateArgs {
        target,
        binary,
        function,
        skip_git,
        no_callgraph,
        ..
    } = args;
    let (target, binary, function) = (target.as_path(), binary.as_str(), function.as_str());
    let skip_git = *skip_git;
    let no_callgraph = *no_callgraph;

    // A .NET managed binary is refused here, before the analysis engine
    // loads or the LLM is contacted — the analysis engine decompiles
    // native code, and a managed assembly's IL is not in the disassembly
    // the translator reads (#235).
    guard_managed_binary(&workspace, binary, target)?;

    // The pass description (issue #326): the resolved settings folded
    // once, then this command's flags, the resolved workspace, and the
    // named binary added on. This is the same fold-and-assembly route an
    // auto run takes, minus the run's stop/pause controls, which stay
    // out on the command side. The fold refuses an unknown retry
    // strategy up front. A record holding no endpoint pair meets the
    // settings layer's "not configured" guidance here — the demand is
    // placed at the command that talks to the LLM, before any analysis-
    // engine load, since `classify` and `verify` never do.
    let mut spec = command_pass_spec(
        settings,
        &workspace,
        binary,
        target,
        PassFlags {
            no_callgraph,
            callgraph_cache,
            callgraph_verbose,
            refresh_cache: false,
        },
    )?;

    // Logging the layer that supplied the endpoint is what makes a surprising
    // model name diagnosable from a log alone.
    let source_of = |r: &Option<Resolved<String>>| {
        r.as_ref()
            .map_or_else(|| "unset".to_string(), |r| r.source.to_string())
    };

    let Some(llm) = spec.llm.as_ref() else {
        // `command_pass_spec` refuses a record without an endpoint pair, so
        // this is already unreachable; say so as an error, not a panic.
        anyhow::bail!("the pass description carries no LLM selection");
    };
    let llm_model_name = match llm {
        LlmSelection::Description(desc) => {
            info!(
                target = ?target,
                binary = %binary,
                function = %function,
                llm_url = %desc.endpoint,
                llm_url_source = source_of(&settings.llm_url),
                llm_model = %desc.model,
                llm_model_source = source_of(&settings.llm_model),
                "Starting translation"
            );
            desc.model.clone()
        }
        LlmSelection::Client(client) => client.model().to_string(),
    };

    // `target` is the path the function is being translated out of: the
    // Kuna engine loads the file itself, so the same path is used for
    // both the scan and the output placement below.

    // Set up the output crate directory structure.
    let (_, crate_src_dir) =
        setup_translation_crate(&workspace, binary).context("Failed to create output crate")?;

    // Kuna is the only analysis engine (issue #214): the scan source is
    // loaded in-process from the target file, so there is no server to
    // attach to and no wrong-program guard to run — the file named on the
    // command line is the program the scan reads.
    let kuna = load_kuna_at(settings, target)?;

    // Git setup
    let mut git = if !skip_git {
        info!("Initializing git repository");
        let git_config = calxgloss_git::InitConfig::default();
        Some(
            GitManager::init_repo(&workspace, Some(git_config))
                .context("Failed to initialize git repository")?,
        )
    } else {
        info!("Skipping git operations");
        None
    };

    // Carry-over seeding (issue #299), set up exactly as the auto pass
    // sets it up (issue #326): with git in play, the pipeline can ask the
    // branch history whether a paired previous-version twin has an
    // accepted (merged) translation to seed attempt 1 from. With
    // `--skip-git` there is no history to ask, and the unit translates
    // from scratch.
    if let Some(git_manager) = git.as_ref() {
        spec.accepted_attempt_source = Some(Arc::new(GitAcceptedAttempts {
            workspace: git_manager.repo_path().to_path_buf(),
        }));
    }

    // Assemble the complete pass once from the description (issue #326):
    // the LLM client from the folded endpoint description, the detector,
    // testgen, the verifier, and the retry policy all arrive through the
    // seam. The command builds none of these itself — no `with_*`
    // builder chain, no hand-built retry-config ladder.
    let pass = assemble(&spec, &kuna)
        .await
        .with_context(|| format!("Failed to assemble the translation pass for {binary}"))?;

    let retry_result = pass
        .pipeline
        .try_translate_with_retry(binary, function, &pass.retry, &pass.verifier)
        .await
        .with_context(|| format!("Translation with retry failed for {}", function))?;

    // Process the retry result
    let mut last_translation: Option<Translation> = None;
    let mut last_branch: Option<GitBranch> = None;

    for attempt in &retry_result.attempts {
        info!(
            attempt = attempt.attempt,
            compiled = attempt.compiled,
            tests_passed = attempt.tests_passed,
            tests_total = attempt.tests_total,
            retry_strategy = %attempt.retry_strategy,
            "Processing attempt"
        );

        if attempt.rust_code.is_empty() {
            warn!(attempt = attempt.attempt, "Attempt produced no code");
            continue;
        }

        // Print attempt summary
        println!(
            "\n{}",
            yellow_bold(&format!(
                "Attempt {}/{} (retry strategy: {}) — {}",
                attempt.attempt,
                pass.retry.max_attempts,
                attempt.retry_strategy,
                if attempt.is_successful() {
                    green_bold("PASS")
                } else {
                    red_bold("FAIL")
                }
            ))
        );

        if !attempt.compiled {
            println!(
                "  Compilation: failed ({} errors)",
                attempt.compilation_errors.len()
            );
            for error in &attempt.compilation_errors {
                println!("    {}", error);
            }
        } else {
            println!(
                "  Compilation: passed | Tests: {}/{} passed",
                attempt.tests_passed, attempt.tests_total
            );
            if !attempt.failed_tests.is_empty() {
                println!("  Failed tests:");
                for test in &attempt.failed_tests {
                    println!("    - {}", test);
                }
            }
        }

        // Write translated code for this attempt.
        let output_path = write_translation_function(&crate_src_dir, function, &attempt.rust_code)?;

        // Git automation
        if let Some(ref mut git) = git {
            let branch_result = git
                .create_branch(
                    binary,
                    function,
                    attempt.attempt,
                    Some(&BranchCreationPolicy::Warn(DependencyPolicy {
                        category: DllCategory::ProjectSpecific,
                        crate_replacement: None,
                    })),
                )
                .context("Failed to create git branch")?;

            let branch_info = &branch_result.branch;
            print_git_status(branch_info, false);

            // Commit the translated code
            let output_path_str = output_path.to_string_lossy().to_string();
            let _commit = git
                .commit(
                    branch_info,
                    &format!(
                        "re/translation/{}: translate {} (attempt {}, retry strategy: {})",
                        function, binary, attempt.attempt, attempt.retry_strategy
                    ),
                    &[&output_path_str],
                )
                .context("Failed to commit translated code")?;

            if attempt.is_successful() {
                // Merge if successful. A successful attempt merges straight to main —
                // human review is not wired into this path yet.
                let merge_result = git
                    .merge_to_main(branch_info)
                    .context("Failed to merge branch to main")?;

                last_branch = Some(branch_info.clone());

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

                // We found a successful attempt — break out of the loop
                last_translation = Some(Translation {
                    binary: binary.to_string().into(),
                    function: function.to_string(),
                    function_address: None,
                    rust_code: attempt.rust_code.clone(),
                    prompt_used: String::new(),
                    model: llm_model_name.clone(),
                    tokens_used: None,
                    baseline_tests: Vec::new(),
                    call_graph: Vec::new(),
                    call_graph_context: Vec::new(),
                    disassembly_hints: Vec::new(),
                    context_tier: ContextTier::WithTests,
                });
                break;
            } else if attempt.attempt >= pass.retry.max_attempts {
                // Last attempt failed — show failure status
                print_failure(
                    branch_info,
                    &VerificationResult {
                        compiled: attempt.compiled,
                        compilation_errors: attempt.compilation_errors.clone(),
                        tests_passed: attempt.tests_passed,
                        tests_total: attempt.tests_total,
                        failed_tests: Vec::new(),
                    },
                );
                last_branch = Some(branch_info.clone());
            }
        }
    }

    // Final summary
    match (&last_translation, &last_branch) {
        (Some(t), Some(b)) => {
            println!();
            let status = if skip_git {
                "git operations skipped"
            } else {
                "completed and merged"
            };
            println!(
                "{} Translation {} of {} for {} ({:.0} lines of Rust) {}",
                green_bold("SUCCESS"),
                t.model,
                function,
                b.binary,
                t.rust_code.lines().count() as f64,
                status
            );
        }
        (None, Some(b)) => {
            println!();
            error!(
                branch = %b.name,
                "All translation attempts failed. Check logs for details."
            );
            return Err(anyhow::anyhow!(
                "All {} translation attempts failed for {} ({})",
                pass.retry.max_attempts,
                b.function,
                b.binary
            ));
        }
        (None, None) => {
            error!("Translation failed with no translation result");
            return Err(anyhow::anyhow!("Translation failed"));
        }
        (Some(_), None) if skip_git => {
            println!();
            warn!("Translation completed but git operations were skipped.");
        }
        _ => {}
    }

    // Nothing to release: the Kuna analysis engine was loaded
    // in-process, and there is no server (issue #214).

    Ok(())
}
