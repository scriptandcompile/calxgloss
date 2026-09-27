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
//! - `verify` — Verify a previously translated function

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use calxgloss::GitBranch;
use calxgloss_analysis::Analyzer;
use calxgloss_ghidra::{GhidraClient, GhidraConfig};
use calxgloss_git::GitManager;
use calxgloss_llm::{LlmClient, LlmConfig};
use calxgloss_pal::ApiMappings;
use calxgloss_reports::{
    print_classification_report, print_failure, print_git_status, print_translation_summary,
    print_verification_results, prompt_acceptance,
};
use calxgloss_testgen::TestGenerator;
use calxgloss_translator::TranslationPipeline;
use calxgloss_verify::Verifier;
use clap::{Parser, Subcommand};
use tracing::{debug, error, info, warn};

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

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Classify DLLs for a target executable
    Classify {
        /// Path to the target executable
        #[arg(long)]
        target: PathBuf,

        /// GhidraMCP server URL
        #[arg(long, default_value = "http://localhost:8080")]
        ghidra_url: String,

        /// API key for the GhidraMCP server (optional)
        #[arg(long)]
        ghidra_api_key: Option<String>,
    },

    /// Translate a single function from disassembly to Rust
    Translate {
        /// Path to the target executable
        #[arg(long)]
        target: PathBuf,

        /// DLL name containing the function
        #[arg(long)]
        dll: String,

        /// Function name to translate
        #[arg(long)]
        function: String,

        /// GhidraMCP server URL
        #[arg(long, default_value = "http://localhost:8080")]
        ghidra_url: String,

        /// LLM server URL (OpenAI-compatible API)
        #[arg(long, default_value = "http://localhost:8081/v1")]
        llm_url: String,

        /// LLM model name
        #[arg(long, default_value = "qwen3-235b-a22b")]
        llm_model: String,

        /// API key for the LLM server (optional)
        #[arg(long)]
        llm_api_key: Option<String>,

        /// Output directory for translated code (default: same as target directory)
        #[arg(long)]
        output_dir: Option<PathBuf>,

        /// Maximum tokens for LLM generation
        #[arg(long, default_value = "8192")]
        max_tokens: usize,

        /// LLM temperature (0.0 = deterministic, higher = more creative)
        #[arg(long, default_value = "0.1")]
        temperature: f32,

        /// Skip git operations
        #[arg(long)]
        skip_git: bool,

        /// Number of retry attempts on translation failure
        #[arg(long, default_value = "3")]
        max_retries: u32,
    },

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

async fn handle_classify(
    target: &Path,
    ghidra_url: &str,
    ghidra_api_key: Option<&str>,
) -> Result<()> {
    info!(target = ?target, "Classifying target");

    // Initialize Ghidra client
    let mut config = GhidraConfig::new(ghidra_url)
        .with_context(|| format!("Failed to parse GhidraMCP URL: {}", ghidra_url))?;

    if let Some(key) = ghidra_api_key {
        config = config.with_api_key(key.to_string());
    }

    let ghidra = GhidraClient::from_config(config)
        .with_context(|| format!("Failed to connect to GhidraMCP at {}", ghidra_url))?;

    // Initialize analyzer
    let api_mappings = ApiMappings::default();
    let analyzer = Analyzer::new(ghidra, api_mappings);

    // Classify all DLLs for the target
    let target_exe = target.to_string_lossy().to_string();
    let classifications = analyzer.classify_target(&target_exe).await?;

    // Print report
    print_classification_report(&classifications);

    info!(count = classifications.len(), "Classification complete");
    Ok(())
}

// ============================================================
// Translate command handler
// ============================================================

async fn handle_translate(
    target: &Path,
    dll: &str,
    function: &str,
    ghidra_url: &str,
    llm_url: &str,
    llm_model: &str,
    llm_api_key: Option<&str>,
    output_dir: Option<&Path>,
    max_tokens: usize,
    temperature: f32,
    skip_git: bool,
    max_retries: u32,
) -> Result<()> {
    info!(
        target = ?target,
        dll = %dll,
        function = %function,
        "Starting translation"
    );

    let target_exe = target.to_string_lossy().to_string();
    let target_dir = target.parent().unwrap_or(target).to_path_buf();
    let output_dir = output_dir.map(PathBuf::from).unwrap_or(target_dir);

    // Create output directory structure
    let modules_dir = output_dir.join("src").join("modules");
    std::fs::create_dir_all(&modules_dir).context("Failed to create modules directory")?;

    // Initialize Ghidra client
    let ghidra_config = GhidraConfig::new(ghidra_url)
        .with_context(|| format!("Failed to parse GhidraMCP URL: {}", ghidra_url))?;
    let ghidra = GhidraClient::from_config(ghidra_config)
        .with_context(|| format!("Failed to connect to GhidraMCP at {}", ghidra_url))?;

    // Initialize LLM client
    let mut llm_config = LlmConfig::new(llm_url, llm_model)
        .with_context(|| format!("Failed to parse LLM URL: {}", llm_url))?;

    if let Some(key) = llm_api_key {
        llm_config = llm_config.with_api_key(key.to_string());
    }
    llm_config = llm_config
        .with_max_tokens(max_tokens)
        .with_temperature(temperature);

    let llm = LlmClient::new(llm_config).context("Failed to create LLM client")?;

    // Initialize analyzer and test generator
    let api_mappings = ApiMappings::default();
    let testgen = TestGenerator::new(&output_dir);

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

    // Run translation with retries
    let mut last_translation: Option<calxgloss_translator::Translation> = None;
    let mut last_branch: Option<GitBranch> = None;

    for attempt in 1..=max_retries {
        info!(attempt, "Translation attempt {}/{}", attempt, max_retries);

        // Run translation
        let translation = pipeline
            .translate(&target_exe, dll, function)
            .await
            .with_context(|| format!("Translation failed on attempt {}", attempt))?;

        last_translation = Some(translation.clone());

        // Print summary
        print_translation_summary(&translation);

        // Write translated code
        let output_path = modules_dir.join(function).join("translated.rs");
        std::fs::create_dir_all(output_path.parent().unwrap())
            .context("Failed to create output directory")?;
        std::fs::write(&output_path, &translation.rust_code).with_context(|| {
            format!(
                "Failed to write translated code to {}",
                output_path.display()
            )
        })?;
        info!(path = %output_path.display(), "Wrote translated code");

        // Verify
        let verifier = Verifier::new(&output_dir).context("Failed to create verifier")?;
        let verification = verifier
            .verify(
                dll,
                function,
                &translation.rust_code,
                &translation.baseline_tests,
            )
            .await
            .context("Verification failed")?;

        print_verification_results(&verification);

        // Git automation
        if let Some(ref mut git) = git {
            let branch_result = git
                .create_branch(dll, function, attempt)
                .context("Failed to create git branch")?;

            let branch_info = &branch_result.branch;
            print_git_status(branch_info, false);

            // Commit the translated code
            let output_path_str = output_path.to_string_lossy().to_string();
            let _commit = git
                .commit(
                    branch_info,
                    &format!(
                        "re/translation/{}: translate {} (attempt {})",
                        function, dll, attempt
                    ),
                    &[&output_path_str],
                )
                .context("Failed to commit translated code")?;

            // Merge if all tests pass
            if verification.tests_passed == verification.tests_total && verification.tests_total > 0
            {
                let merge_result = git
                    .merge_to_main(branch_info)
                    .context("Failed to merge branch to main")?;

                // Prompt for human acceptance if there were failures
                let accepted =
                    if verification.tests_total > 0 && !verification.failed_tests.is_empty() {
                        prompt_acceptance()
                    } else {
                        true
                    };

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
                break;
            } else if verification.tests_total == 0 {
                // No tests — accept by default
                info!("No baseline tests — accepting translation");
                let merge_result = git
                    .merge_to_main(branch_info)
                    .context("Failed to merge branch to main")?;

                last_branch = Some(branch_info.clone());

                match &merge_result {
                    calxgloss_git::MergeResult::Merged { merge_hash } => {
                        info!(hash = %merge_hash, "Translation accepted and merged (no tests)");
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
                break;
            }

            // Show failure status
            print_failure(branch_info, &verification);
            last_branch = Some(branch_info.clone());

            warn!(
                passed = verification.tests_passed,
                total = verification.tests_total,
                "Tests did not all pass — retrying"
            );
        }

        // If all tests pass (or no tests exist), we're done
        if verification.tests_passed == verification.tests_total || verification.tests_total == 0 {
            break;
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

    // Run the appropriate command
    let result = match cli.command {
        Command::Classify {
            target,
            ghidra_url,
            ghidra_api_key,
        } => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("Failed to create tokio runtime")?
            .block_on(handle_classify(
                &target,
                &ghidra_url,
                ghidra_api_key.as_deref(),
            )),
        Command::Translate {
            target,
            dll,
            function,
            ghidra_url,
            llm_url,
            llm_model,
            llm_api_key,
            output_dir,
            max_tokens,
            temperature,
            skip_git,
            max_retries,
        } => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("Failed to create tokio runtime")?
            .block_on(handle_translate(
                &target,
                &dll,
                &function,
                &ghidra_url,
                &llm_url,
                &llm_model,
                llm_api_key.as_deref(),
                output_dir.as_deref(),
                max_tokens,
                temperature,
                skip_git,
                max_retries,
            )),
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
