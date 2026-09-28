//! Calxgloss CLI — Reverse Engineering Harness
//!
//! A command-line interface for the Calxgloss reverse engineering system.
//! Wires together GhidraMCP analysis, LLM-assisted translation, test generation,
//! verification, and Git automation into a unified workflow.
//!
//! # Commands
//!
//! - `classify` — Classify DLLs for a target executable
//! - `translate` — Translate a single function from disassembly to Rust
//! - `batch-translate` — Translate multiple functions from a single DLL
//! - `verify` — Verify a previously translated function
//! - `config` — Show the configuration in force and where each value came from
//!
//! # Configuration
//!
//! Server addresses come from, most specific first: a command-line flag, an
//! environment variable, a TOML file, then a built-in default. Run
//! `calxgloss config` to see which layer won for each setting.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use calxgloss::GitBranch;
use calxgloss_analysis::Analyzer;
use calxgloss_config::{FileConfig, GhidraSection, Layers, LlmSection, Resolved, load};
use calxgloss_ghidra::{GhidraClient, GhidraConfig};
use calxgloss_git::GitManager;
use calxgloss_llm::{LlmClient, LlmConfig};
use calxgloss_pal::ApiMappings;
use calxgloss_reports::{
    print_batch_summary, print_classification_report, print_failure, print_git_status,
    print_verification_results,
};
use calxgloss_testgen::TestGenerator;
use calxgloss_translator::{RetryConfig, RetryStrategy, TranslationPipeline};
use calxgloss_verify::Verifier;
use clap::{Args, Parser, Subcommand};
use tracing::{debug, error, info, warn};

mod settings;

use settings::Settings;

// ============================================================
// CLI argument parsing
// ============================================================

/// Calxgloss — Reverse Engineering Harness
///
/// Decompile binaries to cross-platform Rust via LLM-assisted translation.
#[derive(Parser, Debug)]
#[command(name = env!("CARGO_PKG_NAME"), about, version = env!("CARGO_PKG_VERSION"))]
struct Cli {
    /// Enable verbose output (equivalent to RUST_LOG=debug)
    #[arg(long, short = 'v', action = clap::ArgAction::Count)]
    verbose: u8,

    /// Log format: text, json, or pretty (default: pretty)
    #[arg(long, default_value = "pretty")]
    log_format: String,

    /// Path to a TOML configuration file
    ///
    /// Overrides the search for ./calxgloss.toml and
    /// ~/.config/calxgloss/config.toml. The named file must exist, so a typo
    /// fails loudly instead of silently falling back.
    #[arg(long, global = true, value_name = "FILE")]
    config: Option<PathBuf>,

    /// GhidraMCP server URL (default: http://127.0.0.1:8080)
    #[arg(long, global = true)]
    ghidra_url: Option<String>,

    /// API key for the GhidraMCP server (optional)
    #[arg(long, global = true)]
    ghidra_api_key: Option<String>,

    /// LLM server URL (OpenAI-compatible API)
    #[arg(long, global = true)]
    llm_url: Option<String>,

    /// LLM model name
    #[arg(long, global = true)]
    llm_model: Option<String>,

    /// API key for the LLM server (optional)
    #[arg(long, global = true)]
    llm_api_key: Option<String>,

    /// Maximum tokens for LLM generation (default: 8192)
    #[arg(long, global = true)]
    max_tokens: Option<usize>,

    /// LLM temperature (0.0 = deterministic, higher = more creative) (default: 0.1)
    #[arg(long, global = true)]
    temperature: Option<f32>,

    /// Number of retry attempts on translation failure (default: 3)
    #[arg(long, global = true)]
    max_retries: Option<u32>,

    #[command(subcommand)]
    command: Command,
}

/// Arguments for the `translate` subcommand.
///
/// The connection settings live on [`Cli`] as global flags, so they mean the
/// same thing for every subcommand and `calxgloss config` can show an override.
#[derive(Args, Debug)]
struct TranslateArgs {
    /// Path to the target executable
    #[arg(long)]
    target: PathBuf,

    /// DLL name containing the function
    #[arg(long)]
    dll: String,

    /// Function name to translate
    #[arg(long)]
    function: String,

    /// Output directory for translated code (default: same as target directory)
    #[arg(long)]
    output_dir: Option<PathBuf>,

    /// Skip git operations
    #[arg(long)]
    skip_git: bool,
}

/// Arguments for the `batch-translate` subcommand.
#[derive(Args, Debug)]
struct BatchTranslateArgs {
    /// Path to the target executable
    #[arg(long)]
    target: PathBuf,

    /// DLL name containing the functions to translate
    #[arg(long)]
    dll: String,

    /// Comma-separated list of function names to translate (e.g., "Func1,Func2,Func3")
    #[arg(long)]
    functions: Option<String>,

    /// Translate all exported functions from the DLL (overrides --functions)
    #[arg(long)]
    all_functions: bool,

    /// Output directory for translated code (default: same as target directory)
    #[arg(long)]
    output_dir: Option<PathBuf>,

    /// Skip git operations
    #[arg(long)]
    skip_git: bool,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Classify DLLs, choosing how to treat each one
    Classify {
        /// The DLLs to classify are named here because Ghidra serves a single
        /// open program and cannot list what a target links against.
        #[arg(long, required = true)]
        dll: Vec<String>,
    },

    /// Translate a single function from disassembly to Rust
    Translate(TranslateArgs),

    /// Translate multiple functions from a single DLL in one pass
    BatchTranslate(BatchTranslateArgs),

    /// Show the configuration in force and where each value came from
    ///
    /// Secrets are reported as `<set>` rather than printed, so this output is
    /// safe to paste into a bug report.
    Config,

    /// Verify a previously translated function against baseline tests
    Verify {
        /// DLL name
        #[arg(long)]
        dll: String,

        /// Function name
        #[arg(long)]
        function: String,

        /// Path to the translated Rust source file
        #[arg(long)]
        rust_source: PathBuf,

        /// Path to baseline test data (default: auto-discovered)
        #[arg(long)]
        baseline_path: Option<PathBuf>,
    },
}

// ============================================================
// Logging setup
// ============================================================

fn init_logging(verbosity: u8, format: &str) {
    let level = match verbosity {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };

    match format {
        "json" => {
            tracing_subscriber::fmt()
                .json()
                .with_env_filter(level)
                .init();
        }
        "text" => {
            tracing_subscriber::fmt()
                .with_target(false)
                .with_env_filter(level)
                .init();
        }
        _ => {
            tracing_subscriber::fmt()
                .with_target(false)
                .with_env_filter(level)
                .init();
        }
    };

    debug!("Logging initialized: level={}, format={}", level, format);
}

// ============================================================
// Terminal formatting helpers (mirrors calxgloss-reports internals)
// ============================================================

const ANSI_RESET: &str = "\x1b[0m";
const ANSI_BOLD: &str = "\x1b[1m";
const ANSI_GREEN: &str = "\x1b[32m";
const ANSI_RED: &str = "\x1b[31m";
const ANSI_YELLOW: &str = "\x1b[33m";
const ANSI_CYAN: &str = "\x1b[36m";

fn bold(text: &str) -> String {
    format!("{}{}{}", ANSI_BOLD, text, ANSI_RESET)
}

fn bold_color(text: &str, code: &str) -> String {
    format!("{}{}{}{}", ANSI_BOLD, code, text, ANSI_RESET)
}

fn green_bold(text: &str) -> String {
    bold_color(text, ANSI_GREEN)
}

fn red_bold(text: &str) -> String {
    bold_color(text, ANSI_RED)
}

fn yellow_bold(text: &str) -> String {
    bold_color(text, ANSI_YELLOW)
}

fn cyan_bold(text: &str) -> String {
    bold_color(text, ANSI_CYAN)
}

fn white_bold(text: &str) -> String {
    bold(text)
}

// ============================================================
// Classify command handler
// ============================================================

async fn handle_classify(dlls: &[String], settings: &Settings) -> Result<()> {
    info!(count = dlls.len(), "Classifying DLLs");

    // Initialize Ghidra client
    let ghidra_url = &settings.ghidra_url.value;
    let mut config = GhidraConfig::new(ghidra_url)
        .with_context(|| format!("Failed to parse GhidraMCP URL: {}", ghidra_url))?;

    if let Some(key) = &settings.ghidra_api_key {
        config = config.with_api_key(key.value.clone());
    }

    let ghidra = GhidraClient::from_config(config)
        .with_context(|| format!("Failed to connect to GhidraMCP at {}", ghidra_url))?;

    // Initialize analyzer
    let api_mappings = ApiMappings::default();
    let analyzer = Analyzer::new(ghidra, api_mappings);

    let classifications = analyzer.classify_dlls(dlls).await?;

    // Print report
    print_classification_report(&classifications);

    info!(count = classifications.len(), "Classification complete");
    Ok(())
}

// ============================================================
// Translate command handler
// ============================================================

async fn handle_translate(args: &TranslateArgs, settings: &Settings) -> Result<()> {
    let TranslateArgs {
        target,
        dll,
        function,
        output_dir,
        skip_git,
        ..
    } = args;
    let (target, dll, function) = (target.as_path(), dll.as_str(), function.as_str());
    let skip_git = *skip_git;

    // Demanded here rather than at startup: `classify` and `verify` never talk
    // to the LLM, so making the endpoint mandatory for them would force users
    // to configure something they do not use.
    let llm_url = settings.require_llm_url()?;
    let llm_model = settings.require_llm_model()?;
    let ghidra_url = settings.ghidra_url.value.as_str();
    let max_tokens = settings.max_tokens.value;
    let temperature = settings.temperature.value;
    let max_retries = settings.max_retries.value;

    // Logging the layer that supplied the endpoint is what makes a surprising
    // model name diagnosable from a log alone.
    let source_of = |r: &Option<Resolved<String>>| {
        r.as_ref()
            .map_or_else(|| "unset".to_string(), |r| r.source.to_string())
    };

    info!(
        target = ?target,
        dll = %dll,
        function = %function,
        llm_url = %llm_url,
        llm_url_source = source_of(&settings.llm_url),
        llm_model = %llm_model,
        llm_model_source = source_of(&settings.llm_model),
        "Starting translation"
    );

    // `target` is the path the function is being translated out of, used here
    // only to place the output. Ghidra identifies the program itself, so the
    // path is not sent to it.
    let target_dir = target.parent().unwrap_or(target).to_path_buf();
    let output_dir = output_dir.clone().unwrap_or(target_dir);

    // Create output directory structure
    let modules_dir = output_dir.join("src").join("modules");
    std::fs::create_dir_all(&modules_dir).context("Failed to create modules directory")?;

    // Initialize Ghidra client
    let mut ghidra_config = GhidraConfig::new(ghidra_url)
        .with_context(|| format!("Failed to parse GhidraMCP URL: {}", ghidra_url))?;
    if let Some(key) = &settings.ghidra_api_key {
        ghidra_config = ghidra_config.with_api_key(key.value.clone());
    }
    let ghidra = GhidraClient::from_config(ghidra_config)
        .with_context(|| format!("Failed to connect to GhidraMCP at {}", ghidra_url))?;

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

    // Initialize analyzer and test generator
    let api_mappings = ApiMappings::default();
    let testgen = TestGenerator::new(&output_dir);

    let llm_model_name = llm.model().to_string();

    // Build translation pipeline
    let pipeline = TranslationPipeline::new(ghidra, llm, api_mappings).with_testgen(testgen);

    // Git setup
    let mut git = if !skip_git {
        info!("Initializing git repository");
        let git_config = calxgloss_git::InitConfig::default();
        Some(
            GitManager::init_repo(&output_dir, Some(git_config))
                .context("Failed to initialize git repository")?,
        )
    } else {
        info!("Skipping git operations");
        None
    };

    // Initialize verifier for retry loop
    let verifier = Verifier::new(&output_dir).context("Failed to create verifier")?;

    // Configure retry behavior
    let retry_config = RetryConfig {
        max_attempts: max_retries,
        strategy: RetryStrategy::CompileFix,
        escalate_on_failure: true,
    };

    // Run translation with automatic retry on verification failure
    let retry_result = pipeline
        .try_translate_with_retry(dll, function, &retry_config, &verifier)
        .await
        .with_context(|| format!("Translation with retry failed for {}", function))?;

    // Process the retry result
    let mut last_translation: Option<calxgloss_translator::Translation> = None;
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

        // Write translated code for this attempt
        let output_path = modules_dir.join(function).join("translated.rs");
        std::fs::create_dir_all(output_path.parent().unwrap())
            .context("Failed to create output directory")?;
        std::fs::write(&output_path, &attempt.rust_code).with_context(|| {
            format!(
                "Failed to write translated code to {}",
                output_path.display()
            )
        })?;
        info!(path = %output_path.display(), "Wrote translated code");

        // Git automation
        if let Some(ref mut git) = git {
            let branch_result = git
                .create_branch(dll, function, attempt.attempt)
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
                        function, dll, attempt.attempt, attempt.strategy
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
                last_translation = Some(calxgloss_translator::Translation {
                    dll: dll.to_string(),
                    function: function.to_string(),
                    rust_code: attempt.rust_code.clone(),
                    prompt_used: String::new(),
                    model: llm_model_name.clone(),
                    tokens_used: None,
                    baseline_tests: Vec::new(),
                });
                break;
            } else if attempt.attempt >= retry_config.max_attempts {
                // Last attempt failed — show failure status
                print_failure(
                    branch_info,
                    &calxgloss_verify::VerificationResult {
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
                b.dll,
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
                b.dll
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

    Ok(())
}

// ============================================================
// Verify command handler
// ============================================================

// ============================================================
// Batch translate command handler
// ============================================================

async fn handle_batch_translate(args: &BatchTranslateArgs, settings: &Settings) -> Result<()> {
    let BatchTranslateArgs {
        target,
        dll,
        functions,
        all_functions,
        output_dir,
        skip_git,
    } = args;
    let (target, dll) = (target.as_path(), dll.as_str());
    let skip_git = *skip_git;

    let llm_url = settings.require_llm_url()?;
    let llm_model = settings.require_llm_model()?;
    let ghidra_url = settings.ghidra_url.value.as_str();
    let max_tokens = settings.max_tokens.value;
    let temperature = settings.temperature.value;
    let max_retries = settings.max_retries.value;

    info!(
        target = ?target,
        dll = %dll,
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

    let target_dir = target.parent().unwrap_or(target).to_path_buf();
    let output_dir = output_dir.clone().unwrap_or(target_dir);

    // Create output directory structure
    let modules_dir = output_dir.join("src").join("modules");
    std::fs::create_dir_all(&modules_dir).context("Failed to create modules directory")?;

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
    let api_mappings = calxgloss_pal::ApiMappings::default();
    let testgen = calxgloss_testgen::TestGenerator::new(&output_dir);

    // Build translation pipeline
    let pipeline = calxgloss_translator::TranslationPipeline::new(ghidra, llm, api_mappings)
        .with_testgen(testgen);

    // Git setup
    let mut git = if !skip_git {
        info!("Initializing git repository");
        let git_config = calxgloss_git::InitConfig::default();
        Some(
            calxgloss_git::GitManager::init_repo(&output_dir, Some(git_config))
                .context("Failed to initialize git repository")?,
        )
    } else {
        info!("Skipping git operations");
        None
    };

    // Initialize verifier for retry loop
    let verifier =
        calxgloss_verify::Verifier::new(&output_dir).context("Failed to create verifier")?;

    // Configure retry behavior
    let retry_config = calxgloss_translator::RetryConfig {
        max_attempts: max_retries,
        strategy: calxgloss_translator::RetryStrategy::CompileFix,
        escalate_on_failure: true,
    };

    // Run batch translation
    let mut batch_result = pipeline
        .batch_translate(dll, &function_list, &retry_config, &verifier)
        .await
        .with_context(|| format!("Batch translation failed for DLL: {}", dll))?;

    // Git operations: commit each function that succeeded
    if let Some(ref mut git_manager) = git {
        for func_result in batch_result.results.iter_mut() {
            if !func_result.success {
                continue;
            }

            let rust_code = func_result.rust_code.as_ref().unwrap();
            let output_path = modules_dir
                .join(&func_result.function)
                .join("translated.rs");
            std::fs::create_dir_all(output_path.parent().unwrap())
                .context("Failed to create output directory")?;
            std::fs::write(&output_path, rust_code).with_context(|| {
                format!(
                    "Failed to write translated code to {}",
                    output_path.display()
                )
            })?;

            let branch_result = git_manager
                .create_branch(dll, &func_result.function, 1)
                .context("Failed to create git branch")?;

            let branch_info = &branch_result.branch;
            print_git_status(branch_info, false);

            let output_path_str = output_path.to_string_lossy().to_string();
            let _commit = git_manager
                .commit(
                    branch_info,
                    &format!(
                        "re/batch/{}: translate {} (batch attempt)",
                        func_result.function, dll
                    ),
                    &[&output_path_str],
                )
                .context("Failed to commit translated code")?;

            let merge_result = git_manager
                .merge_to_main(branch_info)
                .context("Failed to merge branch to main")?;

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

            // Set the branch on the result (we already have a mutable ref via enumerate)
            func_result.branch = Some(branch_info.clone());
        }
    }

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

// ============================================================
// Verify command handler
// ============================================================

async fn handle_verify(
    dll: &str,
    function: &str,
    rust_source: &Path,
    baseline_path: Option<&Path>,
) -> Result<()> {
    info!(dll = %dll, function = %function, "Starting verification");

    let target_dir = rust_source
        .parent()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    let output_dir = baseline_path.map(PathBuf::from).unwrap_or(target_dir);

    // Read the translated Rust code
    let rust_code = std::fs::read_to_string(rust_source)
        .with_context(|| format!("Failed to read Rust source from {}", rust_source.display()))?;

    info!(code_len = rust_code.len(), "Loaded translated code");

    // Load baseline tests if available
    let baseline_path = baseline_path
        .map(PathBuf::from)
        .or_else(|| Some(TestGenerator::new(&output_dir).baseline_path(dll, function)));

    let baseline_tests: Vec<calxgloss::TestCase> = match &baseline_path {
        Some(path) if path.exists() => {
            info!(path = %path.display(), "Loading baseline tests");
            serde_json::from_str(
                &std::fs::read_to_string(path)
                    .with_context(|| format!("Failed to read baseline from {}", path.display()))?,
            )
            .with_context(|| format!("Failed to parse baseline from {}", path.display()))?
        }
        _ => {
            info!("No baseline found, proceeding without tests");
            Vec::new()
        }
    };

    // Verify
    let verifier = Verifier::new(&output_dir).context("Failed to create verifier")?;
    let verification = verifier
        .verify(dll, function, &rust_code, &baseline_tests)
        .await
        .context("Verification failed")?;

    // Print results
    println!();
    println!(
        "{} Verification Results {}",
        cyan_bold(&"═".repeat(58)),
        cyan_bold(&"═".repeat(58))
    );
    println!("  {}{}", white_bold("  Function: "), function);
    println!("  {}{}", white_bold("  DLL: "), dll);
    println!("  {}{}", white_bold("  Source: "), rust_source.display());
    println!("{}", cyan_bold(&"═".repeat(58)));
    print_verification_results(&verification);
    println!("{}", cyan_bold(&"═".repeat(58)));

    let all_passed = verification.tests_passed == verification.tests_total;
    if all_passed || verification.tests_total == 0 {
        if verification.tests_total > 0 {
            println!(
                "  {}{}",
                white_bold("  Status: "),
                green_bold("PASS \u{2713}")
            );
        } else {
            println!(
                "  {}{}",
                white_bold("  Status: "),
                yellow_bold("PASS (no baseline tests)")
            );
        }
    } else {
        println!(
            "  {}{}",
            white_bold("  Status: "),
            red_bold("FAIL \u{2717}")
        );
    }

    Ok(())
}

// ============================================================
// Entry point
// ============================================================

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    init_logging(cli.verbose, &cli.log_format);

    info!(
        version = env!("CARGO_PKG_VERSION"),
        target = ?std::env::args().next(),
        "Calxgloss starting"
    );

    // Layer configuration once, so every command sees the same values and a
    // malformed file is reported before any work starts rather than halfway
    // through a translation.
    let loaded = load(cli.config.as_deref())?;
    if let Some(path) = &loaded.path {
        debug!(path = %path.display(), "Loaded config file");
    }
    let mut layers = Layers::from_env();
    layers.file = loaded.file.clone();

    // The global flags form the highest-priority layer, shared by every
    // subcommand so `config` reports the same values a real run would use.
    let flags = FileConfig {
        ghidra: GhidraSection {
            url: cli.ghidra_url.clone(),
            api_key: cli.ghidra_api_key.clone(),
        },
        llm: LlmSection {
            url: cli.llm_url.clone(),
            model: cli.llm_model.clone(),
            api_key: cli.llm_api_key.clone(),
            max_tokens: cli.max_tokens,
            temperature: cli.temperature,
            max_retries: cli.max_retries,
        },
    };
    let settings = Settings::resolve(&layers, flags, &loaded);

    // Run the appropriate command
    let result = match cli.command {
        Command::Config => {
            print!("{}", settings::render(&settings));
            Ok(())
        }
        Command::Classify { dll } => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("Failed to create tokio runtime")?
            .block_on(handle_classify(&dll, &settings)),
        Command::Translate(args) => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("Failed to create tokio runtime")?
            .block_on(handle_translate(&args, &settings)),
        Command::BatchTranslate(args) => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("Failed to create tokio runtime")?
            .block_on(handle_batch_translate(&args, &settings)),
        Command::Verify {
            dll,
            function,
            rust_source,
            baseline_path,
        } => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("Failed to create tokio runtime")?
            .block_on(handle_verify(
                &dll,
                &function,
                &rust_source,
                baseline_path.as_deref(),
            )),
    };

    if let Err(ref e) = result {
        error!("Error: {}", e);
    }

    result
}
