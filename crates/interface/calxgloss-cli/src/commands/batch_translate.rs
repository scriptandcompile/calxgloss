//! The `batch-translate` command — translate multiple functions at once.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use calxgloss::DllCategory;
use calxgloss_git::BranchCreationPolicy;
use calxgloss_git::DependencyPolicy;
use calxgloss_git::GitManager;
use calxgloss_translator::assembly::assemble;
use tracing::{info, warn};

use crate::Settings;
use crate::cli_types::BatchTranslateArgs;
use crate::commands::auto::GitAcceptedAttempts;
use crate::commands::run_options::{PassFlags, command_pass_spec};
use crate::utils::*;

/// Handle the `batch-translate` subcommand: translate multiple functions from a DLL.
pub async fn handle_batch_translate(
    args: &BatchTranslateArgs,
    settings: &Settings,
    workspace: PathBuf,
    callgraph_cache: Option<PathBuf>,
    callgraph_verbose: bool,
) -> Result<()> {
    let BatchTranslateArgs {
        target,
        binary,
        functions,
        all_functions,
        skip_git,
        no_callgraph,
        refresh_cache,
        ..
    } = args;
    let (target, binary) = (target.as_path(), binary.as_str());
    let skip_git = *skip_git;
    let no_callgraph = *no_callgraph;
    let refresh_cache = *refresh_cache;

    // A .NET managed binary is refused here, before the analysis engine
    // loads or the LLM is contacted — the same guard `translate` runs
    // (issue #235).
    guard_managed_binary(&workspace, binary, target)?;

    // The pass description (issue #326): the resolved settings folded
    // once, then this command's flags added on — the call-graph options,
    // the refresh-cache flag, the resolved workspace, and the named
    // target. The batch's pass assembles from the same kind of
    // description an auto run folds, so batch results can be compared to
    // auto results option for option: one construction, not a second
    // builder. The fold refuses an unknown retry strategy up front, and
    // a record holding no endpoint pair meets the settings layer's "not
    // configured" guidance before any analysis-engine load.
    let mut spec = command_pass_spec(
        settings,
        &workspace,
        binary,
        target,
        PassFlags {
            no_callgraph,
            callgraph_cache,
            callgraph_verbose,
            refresh_cache,
        },
    )?;

    info!(
        target = ?target,
        binary = %binary,
        all_functions = %all_functions,
        "Starting batch translation"
    );

    // Kuna is the only analysis engine (issue #214): the scan source is
    // loaded in-process from the target file, so there is no server to
    // attach to and no wrong-program guard to run — the file named on the
    // command line is the program every listing and translation below
    // reads.
    let kuna = load_kuna_at(settings, target)?;

    // Determine which functions to translate
    let function_list = if *all_functions {
        // List all functions from the analysis engine
        use calxgloss_decomp::ScanSource;
        let summaries = ScanSource::functions(&kuna)
            .await
            .with_context(|| "Failed to list functions from the engine")?;

        if summaries.is_empty() {
            warn!("the engine listed no functions; nothing to translate");
            println!("No functions found in the loaded program.");
            return Ok(());
        }

        let names: Vec<String> = summaries.into_iter().map(|s| s.name).collect();
        info!(count = names.len(), "Enumerated functions from the engine");
        names
    } else if let Some(comma_sep) = functions {
        // Parse comma-separated function names
        let names: Vec<String> = comma_sep
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if names.is_empty() {
            anyhow::bail!(
                "No functions specified. Use --functions \"Func1,Func2\" or --all-functions"
            );
        }
        names
    } else {
        // No --functions and no --all-functions: the command stops and
        // asks for one of them.
        anyhow::bail!("Specify either --functions \"Func1,Func2\" or --all-functions");
    };

    let _target_dir = target.parent().unwrap_or(target).to_path_buf();

    // Set up the output crate directory structure.
    let (_, crate_src_dir) =
        setup_translation_crate(&workspace, binary).context("Failed to create output crate")?;

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
    // `--skip-git` there is no history to ask, and the batch translates
    // from scratch.
    if let Some(git_manager) = git.as_ref() {
        spec.accepted_attempt_source = Some(Arc::new(GitAcceptedAttempts {
            workspace: git_manager.repo_path().to_path_buf(),
        }));
    }

    // Assemble the complete pass once from the description (issue #326):
    // the LLM client from the folded endpoint description, the detector,
    // testgen, the verifier, and the retry policy all arrive through the
    // seam. The seam also receives the batch's read-cache key
    // (issue #105) and the refresh-cache option (issue #106), which the
    // description carries now. The command builds none of these itself —
    // no `with_*` builder chain here.
    let pass = assemble(&spec, &kuna)
        .await
        .with_context(|| format!("Failed to assemble the translation pass for {binary}"))?;

    // Run batch translation with an inline callback that handles git operations
    // for each function immediately after it completes.
    let batch_result = pass
        .pipeline
        .batch_translate(
            binary,
            &function_list,
            &pass.retry,
            &pass.verifier,
            Some(&mut |_dll, _function, func_result| {
                // A unit with no translated code — failed, or a refused
                // root recorded skipped — has nothing to write or commit.
                let Some(rust_code) = func_result.rust_code.as_ref() else {
                    return true;
                };

                // Register the function as a module and write the file. Returns the path
                // so we can reference it in the git commit below.
                let output_path = match write_translation_function(
                    &crate_src_dir,
                    &func_result.function,
                    rust_code,
                ) {
                    Ok(p) => p,
                    Err(e) => {
                        warn!(error = %e, "Failed to write translated function");
                        return true;
                    }
                };

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
                            // Carry-over provenance (issue #299): when
                            // attempt 1 was seeded from an accepted
                            // translation of a paired previous-version
                            // function, the commit says so and names the
                            // source — the same note the auto pass writes
                            // (issue #326). A fresh unit's message is
                            // unchanged, byte for byte.
                            &match func_result.carry_over.as_ref() {
                                Some(seed) => format!(
                                    "re/batch/{}: translate {} (batch attempt, {})",
                                    func_result.function,
                                    binary,
                                    seed.commit_note()
                                ),
                                None => format!(
                                    "re/batch/{}: translate {} (batch attempt)",
                                    func_result.function, binary
                                ),
                            },
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

    // Print batch summary
    print_batch_summary(&batch_result);

    // Final status
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

    // Nothing to release: the Kuna analysis engine was loaded
    // in-process, and there is no server (issue #214).

    Ok(())
}
