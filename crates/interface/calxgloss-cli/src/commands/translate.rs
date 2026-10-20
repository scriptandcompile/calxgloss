//! The `translate` command — translate a single function.

use std::path::PathBuf;

use anyhow::{Context, Result};
use calxgloss::ContextTier;
use calxgloss::DllCategory;
use calxgloss::GitBranch;
use calxgloss_config::Resolved;
use calxgloss_git::BranchCreationPolicy;
use calxgloss_git::DependencyPolicy;
use calxgloss_git::GitManager;
use calxgloss_translator::RetryConfig;
use calxgloss_translator::Translation;
use calxgloss_translator::TranslationPipeline;
use calxgloss_translator::build_hallucination_detector;
use calxgloss_verify::VerificationResult;
use tracing::{error, info, warn};

use crate::Settings;
use crate::cli_types::TranslateArgs;
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

    // A .NET managed binary is refused here, before the engine loads or the
    // LLM is contacted — the engine decompiles native code, and a managed
    // assembly's IL is not in the disassembly the translator reads (#235).
    guard_managed_binary(&workspace, binary, target)?;

    // Demanded here rather than at startup: `classify` and `verify` never talk
    // to the LLM, so making the endpoint mandatory for them would force users
    // to configure something they do not use.
    let llm_url = settings.require_llm_url()?;
    let llm_model = settings.require_llm_model()?;
    let context_window = settings.context_window.value;
    let temperature = settings.temperature.value;
    let max_retries = settings.max_retries.value;

    // Parse the retry strategy from the CLI flag or config.
    let retry_strategy = match &settings.retry_strategy {
        Some(r) => parse_retry_strategy(&r.value)?,
        None => RetryStrategy::CompileFix, // default
    };

    // Logging the layer that supplied the endpoint is what makes a surprising
    // model name diagnosable from a log alone.
    let source_of = |r: &Option<Resolved<String>>| {
        r.as_ref()
            .map_or_else(|| "unset".to_string(), |r| r.source.to_string())
    };

    info!(
        target = ?target,
        binary = %binary,
        function = %function,
        llm_url = %llm_url,
        llm_url_source = source_of(&settings.llm_url),
        llm_model = %llm_model,
        llm_model_source = source_of(&settings.llm_model),
        "Starting translation"
    );

    // `target` is the path the function is being translated out of: the
    // Kuna engine loads the file itself, so the same path feeds both the
    // scan and the output placement below.

    // Set up the output crate directory structure.
    let (_, crate_src_dir) =
        setup_translation_crate(&workspace, binary).context("Failed to create output crate")?;

    // Kuna is the only analysis engine (issue #214): the scan source is
    // loaded in-process from the target file, so there is no server to
    // attach to and no wrong-program guard to run — the file named on the
    // command line is the program the scan reads.
    let kuna = load_kuna_at(settings, target)?;

    // Initialize LLM client
    let mut llm_config = calxgloss_llm::LlmConfig::new(llm_url, llm_model)
        .with_context(|| format!("Failed to parse LLM URL: {}", llm_url))?;

    if let Some(key) = &settings.llm_api_key {
        llm_config = llm_config.with_api_key(key.value.clone());
    }
    llm_config = llm_config
        .with_context_window(context_window)
        .with_temperature(temperature);

    let llm = calxgloss_llm::LlmClient::new(llm_config).context("Failed to create LLM client")?;

    // Initialize analyzer and test generator
    let testgen = calxgloss_testgen::TestGenerator::new(&workspace);

    let llm_model_name = llm.model().to_string();

    // Build translation pipeline
    let api_mappings = calxgloss_pal::ApiMappings::default();
    let detector = build_hallucination_detector(&kuna, &api_mappings).await;
    let mut pipeline = TranslationPipeline::new(kuna, llm, api_mappings)
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
        max_context_tier: None,
    };
    let retry_result = pipeline
        .try_translate_with_retry(binary, function, &retry_config, &verifier)
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
            strategy = %attempt.strategy,
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
                "Attempt {}/{} (strategy: {}) — {}",
                attempt.attempt,
                retry_config.max_attempts,
                attempt.strategy,
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
                        "re/translation/{}: translate {} (attempt {}, strategy: {})",
                        function, binary, attempt.attempt, attempt.strategy
                    ),
                    &[&output_path_str],
                )
                .context("Failed to commit translated code")?;

            if attempt.is_successful() {
                // Merge if successful
                let merge_result = git
                    .merge_to_main(branch_info)
                    .context("Failed to merge branch to main")?;

                let accepted = true; // Auto-accept successful attempts
                if !accepted {
                    warn!("Translation rejected by human reviewer");
                    continue;
                }

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
            } else if attempt.attempt >= retry_config.max_attempts {
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
                max_retries,
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

    // Release the server if we spawned it; an attached one is left running.

    Ok(())
}
