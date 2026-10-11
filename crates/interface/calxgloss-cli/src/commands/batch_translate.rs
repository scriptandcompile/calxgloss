//! The `batch-translate` command — translate multiple functions at once.

use std::path::PathBuf;

use anyhow::{Context, Result};
use calxgloss::DllCategory;
use calxgloss_git::BranchCreationPolicy;
use calxgloss_git::DependencyPolicy;
use calxgloss_git::GitManager;
use calxgloss_translator::RetryConfig;
use calxgloss_translator::TranslationPipeline;
use calxgloss_translator::build_hallucination_detector;
use calxgloss_verify::Verifier;
use tracing::{info, warn};

use crate::Settings;
use crate::cli_types::BatchTranslateArgs;
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
        ..
    } = args;
    let (target, binary) = (target.as_path(), binary.as_str());
    let skip_git = *skip_git;
    let no_callgraph = *no_callgraph;

    let llm_url = settings.require_llm_url()?;
    let llm_model = settings.require_llm_model()?;
    let ghidra_url = settings.ghidra_url.value.as_str();
    let max_tokens = settings.max_tokens.value;
    let temperature = settings.temperature.value;
    let max_retries = settings.max_retries.value;

    // Parse the retry strategy from the CLI flag or config.
    let retry_strategy = match &settings.retry_strategy {
        Some(r) => parse_retry_strategy(&r.value)?,
        None => RetryStrategy::CompileFix, // default
    };

    info!(
        target = ?target,
        binary = %binary,
        all_functions = %all_functions,
        "Starting batch translation"
    );

    // Determine which functions to translate
    let function_list = if *all_functions {
        // List all functions from Ghidra
        let ghidra_url_clone = ghidra_url.to_string();
        let mut ghidra_config = calxgloss_ghidra::GhidraConfig::new(&ghidra_url_clone)
            .with_context(|| format!("Failed to parse GhidraMCP URL: {}", ghidra_url))?;
        if let Some(key) = &settings.ghidra_api_key {
            ghidra_config = ghidra_config.with_api_key(key.value.clone());
        }
        let ghidra = calxgloss_ghidra::GhidraClient::from_config(ghidra_config)
            .with_context(|| format!("Failed to connect to GhidraMCP at {}", ghidra_url))?;

        let summaries = ghidra
            .list_functions()
            .await
            .with_context(|| "Failed to list functions from GhidraMCP")?;

        if summaries.is_empty() {
            warn!("GhidraMCP returned no functions; nothing to translate");
            println!("No functions found in the open Ghidra program.");
            return Ok(());
        }

        let names: Vec<String> = summaries.into_iter().map(|s| s.name).collect();
        info!(count = names.len(), "Enumerated functions from Ghidra");
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
        // No --functions and no --all-functions: default to all exports
        anyhow::bail!("Specify either --functions \"Func1,Func2\" or --all-functions");
    };

    let _target_dir = target.parent().unwrap_or(target).to_path_buf();

    // Set up the output crate directory structure.
    let (_, crate_src_dir) =
        setup_translation_crate(&workspace, binary).context("Failed to create output crate")?;

    // Initialize Ghidra client
    let mut ghidra_config = calxgloss_ghidra::GhidraConfig::new(ghidra_url)
        .with_context(|| format!("Failed to parse GhidraMCP URL: {}", ghidra_url))?;
    if let Some(key) = &settings.ghidra_api_key {
        ghidra_config = ghidra_config.with_api_key(key.value.clone());
    }
    let ghidra = calxgloss_ghidra::GhidraClient::from_config(ghidra_config)
        .with_context(|| format!("Failed to connect to GhidraMCP at {}", ghidra_url))?;

    // Initialize LLM client
    let mut llm_config = calxgloss_llm::LlmConfig::new(llm_url, llm_model)
        .with_context(|| format!("Failed to parse LLM URL: {}", llm_url))?;

    if let Some(key) = &settings.llm_api_key {
        llm_config = llm_config.with_api_key(key.value.clone());
    }
    llm_config = llm_config
        .with_max_tokens(max_tokens)
        .with_temperature(temperature);

    let llm = calxgloss_llm::LlmClient::new(llm_config).context("Failed to create LLM client")?;

    // Initialize analyzer and test generator
    let testgen = calxgloss_testgen::TestGenerator::new(&workspace);

    // Build translation pipeline
    let api_mappings = calxgloss_pal::ApiMappings::default();
    let detector = build_hallucination_detector(&ghidra, &api_mappings).await;
    let mut pipeline = TranslationPipeline::new(ghidra, llm, api_mappings)
        .with_testgen(testgen)
        .with_hallucination_detector(detector);
    if no_callgraph {
        pipeline = pipeline.with_no_callgraph();
    }
    if let Some(cache_dir) = callgraph_cache {
        pipeline = pipeline.with_callgraph_cache_dir(cache_dir);
    }
    if callgraph_verbose {
        pipeline = pipeline.with_callgraph_verbose();
    }
    pipeline = pipeline.with_workspace(&workspace);
    // The batch's shared Ghidra read cache keys on the target binary's
    // file bytes (issue #105) — hand the pipeline the file it was given.
    pipeline = pipeline.with_binary_path(target);

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

    // Initialize verifier for retry loop
    let verifier = Verifier::new(&workspace).context("Failed to create verifier")?;

    // Configure retry behavior
    let retry_config = RetryConfig {
        max_attempts: max_retries,
        strategy: retry_strategy,
        escalate_on_failure: true,
    };

    // Run batch translation with an inline callback that handles git operations
    // for each function immediately after it completes.
    let batch_result = pipeline
        .batch_translate(
            binary,
            &function_list,
            &retry_config,
            &verifier,
            Some(&mut |_dll, _function, func_result| {
                if !func_result.success {
                    return true;
                }

                let rust_code = func_result.rust_code.as_ref().unwrap();

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
                            &format!(
                                "re/batch/{}: translate {} (batch attempt)",
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

    Ok(())
}
