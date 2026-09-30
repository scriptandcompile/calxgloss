//! Calxgloss CLI — Reverse Engineering Harness
//!
//! A command-line interface for the Calxgloss reverse engineering system.
//! Wires together GhidraMCP analysis, LLM-assisted translation, test generation,
//! verification, and Git automation into a unified workflow.
//!
//! # Commands
//!
//! - `init` — Create a `calxgloss.toml` configuration file
//! - `classify` — Classify DLLs for a target executable
//! - `translate` — Translate a single function from disassembly to Rust
//! - `batch-translate` — Translate multiple functions from a single DLL
//! - `verify` — Verify a previously translated function
//! - `config` — Show the configuration in force and where each value came from
//! - `dashboard` — Show a structured terminal review dashboard
//! - `serve` — Start the web review UI HTTP server
//! - `auto` — Detect project state and run the next step automatically
//! - `live` — Start both `auto` and `serve` concurrently
//!
//! If called with no subcommand, the tool defaults to `auto` mode: it scans
//! the current directory, reads any existing config, determines whether DLLs
//! still need classification or if batch translation should start, and runs
//! the appropriate step.
//!
//! # Configuration
//!
//! Server addresses come from, most specific first: a command-line flag, an
//! environment variable, a TOML file, then a built-in default. Run
//! `calxgloss config` to see which layer won for each setting.

use std::path::{Path, PathBuf};

/// Resolve the repo directory: `--repo` flag > settings > CWD.
///
/// This is the single point of resolution for commands that use the
/// config-file / env-var layer (`auto`, `translate`, `batch-translate`).
fn resolve_repo_dir(cli_repo: Option<&PathBuf>, settings: &Settings) -> PathBuf {
    cli_repo
        .cloned()
        .or_else(|| settings.repo_dir.as_ref().map(|r| PathBuf::from(&r.value)))
        .unwrap_or_else(|| std::env::current_dir().expect("Failed to read current directory"))
}

/// Resolve the repo directory for `live` and `serve`: `--repo` flag > CWD.
///
/// These commands always operate on the workspace in the current directory
/// (where `.git`, `src/`, `scratch/` live).  Config file and env-var
/// overrides are ignored — only an explicit `--repo` flag can change this.
fn resolve_live_repo_dir(cli_repo: Option<&PathBuf>) -> PathBuf {
    cli_repo
        .cloned()
        .unwrap_or_else(|| std::env::current_dir().expect("Failed to read current directory"))
}

use anyhow::{Context, Result};
use calxgloss::DllCategory;
use calxgloss::GitBranch;
use calxgloss::TranslationEvents;
use calxgloss::ProgressEvent;
use calxgloss_analysis::Analyzer;
use calxgloss_config::{
    EXAMPLE, FileConfig, GhidraSection, Layers, LlmSection, PROJECT_FILE, Resolved, load,
};
use calxgloss_ghidra::{GhidraClient, GhidraConfig};
use calxgloss_git::{BranchCreationPolicy, DependencyPolicy, GitManager};
use calxgloss_llm::{LlmClient, LlmConfig};
use calxgloss_pal::ApiMappings;
use calxgloss_reports::dashboard::{
    DashboardBuilder, UnitViewData, ViewTarget, render_dashboard, render_dashboard_follow,
    render_unit_view,
};
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

/// Parse a retry strategy string into a [`RetryStrategy`].
fn parse_retry_strategy(s: &str) -> Result<RetryStrategy> {
    Ok(match s {
        "compile_fix" => RetryStrategy::CompileFix,
        "test_fix" => RetryStrategy::TestFix,
        "escalate" => RetryStrategy::Escalate,
        "edge_case_fix" => RetryStrategy::EdgeCaseFix,
        "auto" => {
            // Auto mode starts with compile_fix and cycles through all strategies.
            // The cycling happens in the retry loop itself.
            RetryStrategy::CompileFix
        }
        other => anyhow::bail!(
            "Unknown retry strategy '{}'. Valid strategies: compile_fix, test_fix, \
             escalate, edge_case_fix, auto",
            other
        ),
    })
}

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

    /// Target directory for DLLs and output
    ///
    /// Overrides the `target_dir` setting in the config file.
    #[arg(long, global = true, value_name = "DIR")]
    target_dir: Option<PathBuf>,

    /// Repo directory for translation output
    ///
    /// Overrides the `repo_dir` setting in the config file. This is the
    /// directory where `src/`, `re/`, scratch, and the `.git` repo are
    /// created. For `live`/`serve` defaults to CWD and ignores config/env.
    /// For other commands defaults to CWD if no config setting is present.
    #[arg(long, global = true, value_name = "DIR")]
    repo_dir: Option<PathBuf>,

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

    /// Retry strategy: compile_fix, test_fix, escalate, edge_case_fix, or auto
    /// (auto cycles through all strategies on each failure)
    #[arg(long, global = true, value_parser = ["compile_fix", "test_fix", "escalate", "edge_case_fix", "auto"])]
    strategy: Option<String>,

    #[command(subcommand)]
    command: Option<Command>,
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
    /// Create a `calxgloss.toml` configuration file in the current directory.
    ///
    /// Writes a commented-out template with example settings for `[ghidra]`
    /// and `[llm]` sections. If a file already exists, it is overwritten.
    Init,

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

    /// Show a structured terminal dashboard of review status
    ///
    /// Reads all `re/*` git branches, patch records, and baseline files
    /// to produce a summary table of translation units and their status.
    ///
    /// Use `--follow` to watch for changes and auto-refresh.
    /// Use subcommands to act on units:
    /// - `accept <target>` — merge the unit's branch into main
    /// - `reject <target> --reason "..."` — send back with comments
    /// - `view <target>` — inspect a single unit of work in detail
    Dashboard {
        /// Follow mode: continuously watch for new/changed branches
        #[arg(long, short)]
        follow: bool,

        /// Refresh interval in seconds (default: 2, only in --follow mode)
        #[arg(long, default_value = "2")]
        interval: u64,

        #[command(subcommand)]
        command: Option<DashboardSubcommand>,
    },

    /// Automatically detect project state and run the next step.
    ///
    /// Scans the target directory for DLLs and EXEs, checks whether classification
    /// records exist in `re/classify/`, and either runs classification or
    /// batch translation accordingly.
    ///
    /// If a `calxgloss.toml` is missing, prompts to create one first.
    Auto {
        /// Path to the target executable directory
        #[arg(long)]
        target: Option<PathBuf>,

        /// DLLs or EXEs to process (default: scan the target directory for .dll and .exe files)
        #[arg(long)]
        dlls: Option<String>,

        /// Translate all exported functions (requires classification to be complete)
        #[arg(long)]
        all_functions: bool,

        /// Only classify DLLs, do not proceed to translation
        #[arg(long)]
        classify_only: bool,

        /// Skip git operations
        #[arg(long)]
        skip_git: bool,
    },

    /// Start the web review UI server
    ///
    /// Launches an HTTP server that serves the review dashboard frontend
    /// and exposes a REST API for branch acceptance, send-back, and patch
    /// requests.
    ///
    /// # Arguments
    ///
    /// * `--repo` — Path to the resultant (Git) repository. Defaults to the
    ///   current directory.
    /// * `--port` — TCP port to listen on (default: 3000).
    ///
    /// # Examples
    ///
    /// ```text
    /// calxgloss serve                    # Uses current directory, port 3000
    /// calxgloss serve --repo /data/game_re  # Custom repo path
    /// calxgloss serve --port 8080        # Custom port
    /// ```
    Serve {
        /// Path to the Git repository to review
        #[arg(long, short)]
        repo: Option<PathBuf>,

        /// Port to listen on (default: 3000)
        #[arg(long, short = 'p', default_value = "3000")]
        port: u16,
    },

    /// Start the translation pipeline and web review UI together
    ///
    /// Runs `auto` (classification + batch translation) in the foreground
    /// and `serve` (web review UI) in the background, both in the same
    /// process.  Pressing Ctrl+C stops both.
    ///
    /// This is the recommended entry point for day-to-day work: translation
    /// happens while you review units in the browser.
    ///
    /// # Arguments
    ///
    /// * `--port` — TCP port for the review UI (default: 3000).
    /// * `--repo` — Path to the Git repository to review.
    /// * `--target` — Path to the target executable directory (passed to auto).
    /// * `--dlls` — Comma-separated DLL names (passed to auto).
    /// * `--all-functions` — Translate all exported functions (passed to auto).
    /// * `--classify-only` — Only classify, do not translate (passed to auto).
    /// * `--skip-git` — Skip git operations (passed to auto).
    ///
    /// # Examples
    ///
    /// ```text
    /// calxgloss live                           # Start auto + UI on port 3000
    /// calxgloss live --port 8080               # Custom port
    /// calxgloss live --dlls "eqgame,eqmain"    # Pre-select DLLs
    /// ```
    Live {
        /// Port to listen on (default: 3000)
        #[arg(long, short = 'p', default_value = "3000")]
        port: u16,

        /// Path to the Git repository to review
        #[arg(long, short)]
        repo: Option<PathBuf>,

        /// Path to the target executable directory
        #[arg(long)]
        target: Option<PathBuf>,

        /// DLLs to process, comma-separated
        #[arg(long)]
        dlls: Option<String>,

        /// Translate all exported functions (requires classification to be complete)
        #[arg(long)]
        all_functions: bool,

        /// Only classify DLLs, do not proceed to translation
        #[arg(long)]
        classify_only: bool,

        /// Skip git operations
        #[arg(long)]
        skip_git: bool,
    },
}

/// Subcommands for the dashboard.
#[derive(Subcommand, Debug)]
enum DashboardSubcommand {
    /// Show a detailed view of a single translation unit
    ///
    /// Displays justification, diff summary, test results, and attempt history.
    ///
    /// # Arguments
    ///
    /// * `<target>` — Unit identifier in the format `dll/function` or `dll/function/vN`
    ///
    /// # Examples
    ///
    /// ```text
    /// calxgloss dashboard view game_logic/DrawPrimitive
    /// calxgloss dashboard view game_logic/DrawPrimitive/v3
    /// ```
    View {
        /// Unit to view: `<dll>/<function>` or `<dll>/<function>/vN`
        #[arg(value_name = "TARGET")]
        target: String,
    },

    /// Accept a unit — merge its branch into main
    ///
    /// The unit identifier is in the format `dll/function` or
    /// `dll/function/vN`.  If no version is given, the latest attempt is
    /// accepted.
    ///
    /// # Examples
    ///
    /// ```text
    /// calxgloss dashboard accept game_logic/DrawPrimitive
    /// calxgloss dashboard accept game_logic/DrawPrimitive/v3
    /// ```
    Accept {
        /// Unit to accept: `<dll>/<function>` or `<dll>/<function>/vN`
        #[arg(value_name = "TARGET")]
        target: String,
    },

    /// Reject a unit and send it back for fixes
    ///
    /// Records the rejection reason in `re/rejections/{dll}/{function}/vN.json`
    /// so the dashboard can display send-back history.
    ///
    /// # Arguments
    ///
    /// * `<target>` — Unit identifier in the format `dll/function` or `dll/function/vN`
    /// * `--reason` — Optional rejection reason (shown in the dashboard)
    ///
    /// # Examples
    ///
    /// ```text
    /// calxgloss dashboard reject game_logic/DrawPrimitive/v2 --reason "wrong shader mapping"
    /// ```
    Reject {
        /// Unit to reject: `<dll>/<function>` or `<dll>/<function>/vN`
        #[arg(value_name = "TARGET")]
        target: String,

        /// Rejection reason (optional)
        #[arg(long, short)]
        reason: Option<String>,
    },

    /// Accept all pending units in dependency order
    ///
    /// Walks the review queue, topologically sorts units so dependencies
    /// are accepted first, then merges each branch into `main` and writes
    /// the acceptance record.
    ///
    /// Only units with status `Queued` or `PendingReview` are accepted.
    /// Already-accepted, merged, or rejected units are skipped silently.
    ///
    /// # Arguments
    ///
    /// * `--all` — Accept **all** non-merged `re/*` branches (including
    ///   `Blocked` and `SendBack` units) instead of only queued/pending.
    ///
    /// # Examples
    ///
    /// ```text
    /// calxgloss dashboard accept-all
    /// calxgloss dashboard accept-all --all
    /// ```
    AcceptAll {
        /// Accept every unmerged translation branch, including blocked and
        /// send-back units.
        #[arg(long, short)]
        all: bool,
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

fn dim(text: &str) -> String {
    format!("{}{}{}", "\x1b[2m", text, ANSI_RESET)
}

fn format_dim(text: &str) -> String {
    dim(text)
}

/// Width of horizontal dividers (no vertical borders, no corners).
const SEP_WIDTH: usize = 78;

/// A single horizontal divider.
fn hsep() {
    println!("  {}", "─".repeat(SEP_WIDTH));
}

/// A bold horizontal divider.
fn hsep_bold() {
    println!("  {}", "═".repeat(SEP_WIDTH));
}

/// Prints a line of content, padded to SEP_WIDTH with spaces.
/// Safe for ANSI codes and multi-byte UTF-8.
fn println_content(content: impl AsRef<str>) {
    let s = content.as_ref();
    let visible: String = s.chars().filter(|c| !c.is_control()).collect();
    let padded = if visible.len() < SEP_WIDTH {
        format!("{:<SEP_WIDTH$}", s)
    } else {
        let mut end = SEP_WIDTH.min(visible.len());
        while !visible.is_char_boundary(end) {
            end -= 1;
        }
        let mut vcount = 0usize;
        let mut bend = 0usize;
        for (bi, ch) in s.chars().enumerate() {
            if !ch.is_control() {
                vcount += 1;
            }
            if vcount >= end {
                bend = bi + ch.len_utf8();
                break;
            }
        }
        s[..bend].to_string()
    };
    println!("  {}", padded);
}

// ============================================================
// Dashboard accept/reject helpers
// ============================================================

/// Walk up from CWD to find the Git repository root.
fn find_repo_path() -> Result<PathBuf> {
    let path = std::env::current_dir()?;
    let mut search = path.clone();
    for _ in 0..10 {
        if search.join(".git").exists() || search.join(".git").is_dir() {
            return Ok(search.clone());
        }
        if !search.pop() {
            break;
        }
    }
    Ok(path)
}

/// Resolve a ViewTarget to the actual git branch name.
///
/// Searches all translation branches (`re/*`) and returns the first one
/// whose DLL and function match the target, optionally checking the
/// attempt number.
fn resolve_branch(
    git: &GitManager,
    target: &calxgloss_reports::dashboard::ViewTarget,
) -> Result<String> {
    let candidates = git.list_translation_branches()?;
    let target_dll = target.dll.clone();
    let target_func = target.function.clone();
    let target_attempt = target.specific_attempt;

    for branch in &candidates {
        // Must start with re/
        if !branch.starts_with("re/") {
            continue;
        }

        // Use the public matching function from reports
        if !calxgloss_reports::dashboard::branch_matches(
            branch,
            &target_dll,
            &target_func,
            target_attempt,
        ) {
            continue;
        }

        return Ok(branch.clone());
    }

    // Collect available branches for a helpful error message
    let available: Vec<String> = candidates
        .iter()
        .filter(|b| b.starts_with("re/") && b.contains(&target_dll) && b.contains(&target_func))
        .cloned()
        .collect();

    if available.is_empty() {
        let all_branches: String = candidates
            .iter()
            .take(10)
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        anyhow::bail!(
            "No translation branch found for '{}/{}'.\n\
             Available branches: {}",
            target_dll,
            target_func,
            all_branches
        )
    } else {
        anyhow::bail!(
            "No translation branch found for '{}/{}'.\n\
             Possible matches (check attempt number): {}",
            target_dll,
            target_func,
            available.join(", ")
        )
    }
}

/// Parse a git branch name back into (dll, function, attempt) components.
///
/// Accepts branches in the format `re/{dll}/{function}v{N}` or
/// `re/{dll_without_dot}/{function}v{N}`.
fn parse_branch_for_accept(branch: &str) -> (String, String, u32) {
    // Strip re/ prefix
    let rest = branch.strip_prefix("re/").unwrap_or(branch);

    // Split into path and attempt suffix
    // e.g. "game_logic/DrawSpritev1" → path="game_logic/DrawSprite", attempt=1
    let (path, attempt) = if let Some(vpos) = rest.rfind('v') {
        let after_v = &rest[vpos + 1..];
        if after_v.chars().all(|c| c.is_ascii_digit()) && !after_v.is_empty() {
            (rest, after_v.parse().unwrap_or(1))
        } else {
            (rest, 1)
        }
    } else {
        (rest, 1)
    };

    // Split path into dll and function on first /
    let parts: Vec<&str> = path.splitn(2, '/').collect();
    let dll = parts[0].to_string();
    let function = parts.get(1).map(|s| s.to_string()).unwrap_or_default();

    (dll, function, attempt)
}

// ============================================================
// Classify command handler
// ============================================================

async fn handle_classify(
    dlls: &[String],
    target_dir: &Path,
    repo_dir: &Path,
    skip_git: bool,
    settings: &Settings,
    events: Option<&TranslationEvents>,
) -> Result<()> {
    info!(count = dlls.len(), "Classifying DLLs");

    // Initialize Ghidra client (needed only for fallback when PE parse fails)
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

    // Symbol counts come from PE headers on disk — accurate per-DLL.
    let classifications = analyzer.classify_dlls(dlls, target_dir).await?;

    // Write classification records to disk and commit.
    let classify_dir = repo_dir.join("re").join("classify");
    std::fs::create_dir_all(&classify_dir).with_context(|| {
        format!("Failed to create classification directory: {}", classify_dir.display())
    })?;

    let mut written = Vec::new();
    for c in &classifications {
        let sanitized: String = c
            .dll
            .chars()
            .map(|ch| match ch {
                '/' | '\\' => '_',
                other => other,
            })
            .collect();
        let record_path = classify_dir.join(format!("{sanitized}.json"));
        let json = serde_json::to_string_pretty(&c)
            .with_context(|| format!("Failed to serialize classification for {}", c.dll))?;
        std::fs::write(&record_path, &json).with_context(|| {
            format!(
                "Failed to write classification record for {}",
                c.dll
            )
        })?;
        let record_path_str = record_path.to_string_lossy().to_string();
        written.push(record_path_str.clone());
        info!(dll = %c.dll, record = %record_path_str, "Wrote classification record");

        // Emit classification complete event for live mode
        if let Some(events) = events {
            events.emit(ProgressEvent::ClassificationComplete {
                dll: c.dll.clone(),
                category: format!("{:?}", c.category),
                strategy: format!("{:?}", c.strategy),
                crate_replacement: c.crate_replacement.clone(),
                exported_symbols: c.exports_count,
                imported_symbols: c.imports_count,
            });
        }
    }

    // Commit classification records to git (unless skip_git).
    if !skip_git && !written.is_empty() {
        if let Ok(git) = GitManager::open(repo_dir) {
            let _commit = git
                .commit_to_main(
                    &format!(
                        "classify: record classification for {} DLL(s)",
                        written.len()
                    ),
                    &written,
                )
                .context("Failed to commit classification records");
        }
    }

    // Print report
    print_classification_report(&classifications);

    info!(count = classifications.len(), "Classification complete");
    Ok(())
}

// ============================================================
// Init command handler
// ============================================================

fn handle_init() -> Result<()> {
    let path = PathBuf::from(PROJECT_FILE);
    let config = EXAMPLE.to_string();
    std::fs::write(&path, &config)
        .with_context(|| format!("Failed to write configuration to {}", path.display()))?;
    println!(
        "  {} Created {}",
        green_bold("✓"),
        bold(&path.display().to_string())
    );
    println!();
    println_content("Edit this file with your GhidraMCP and LLM server addresses.");
    println_content("Then run `calxgloss auto` to start the pipeline.");
    println_content("");
    println_content("  ghidra.url → GhidraMCP server endpoint");
    println_content("  llm.url    → OpenAI-compatible LLM server");
    println_content("  llm.model  → model identifier the server reports");
    println!();
    Ok(())
}

// ============================================================
// Auto command handler — smart pipeline dispatcher
// ============================================================

/// Scans a directory for DLL and EXE files.
fn scan_targets(target_dir: &Path) -> Vec<String> {
    let mut exe_files = Vec::new();
    let mut dll_files = Vec::new();
    if let Ok(entries) = std::fs::read_dir(target_dir) {
        for entry in entries.filter_map(|e| e.ok()) {
            let file_name = entry.file_name();
            let name = file_name.to_string_lossy().to_lowercase();
            if name.ends_with(".exe") {
                exe_files.push(file_name.to_string_lossy().to_string());
            } else if name.ends_with(".dll") {
                dll_files.push(file_name.to_string_lossy().to_string());
            }
        }
    }
    exe_files.sort();
    dll_files.sort();
    exe_files.extend(dll_files);
    exe_files
}

/// Check whether a classification record exists for the given file.
fn classification_record_exists(base_path: &Path, dll: &str) -> bool {
    let sanitized: String = dll
        .chars()
        .map(|c| match c {
            '/' | '\\' => '_',
            other => other,
        })
        .collect();
    let record = base_path
        .join("re")
        .join("classify")
        .join(format!("{sanitized}.json"));
    record.is_file()
}

/// Run batch translation for a single DLL.
///
/// This function encapsulates all the plumbing needed to translate one DLL:
/// Ghidra setup, LLM client, test generator, pipeline, git operations, and
/// result reporting.  Both `handle_auto` and `handle_live` call this.
async fn run_translation_for_dll(
    dll: &str,
    output_dir: &Path,
    skip_git: bool,
    settings: &Settings,
    events: Option<&TranslationEvents>,
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
    let mut llm_config = calxgloss_llm::LlmConfig::new(llm_url, llm_model)
        .with_context(|| format!("Failed to parse LLM URL: {}", llm_url))?;
    if let Some(key) = &settings.llm_api_key {
        llm_config = llm_config.with_api_key(key.value.clone());
    }
    llm_config = llm_config
        .with_max_tokens(max_tokens)
        .with_temperature(temperature);
    let llm = calxgloss_llm::LlmClient::new(llm_config).context("Failed to create LLM client")?;

    // Initialize analyzer, test generator
    let api_mappings = calxgloss_pal::ApiMappings::default();
    let testgen = calxgloss_testgen::TestGenerator::new(output_dir);

    // Build translation pipeline
    let mut pipeline = calxgloss_translator::TranslationPipeline::new(ghidra, llm, api_mappings)
        .with_testgen(testgen);
    if let Some(events) = events {
        pipeline = pipeline.with_events(events.clone());
    }

    // Git setup
    let mut git = if !skip_git {
        info!("Initializing git repository");
        let git_config = calxgloss_git::InitConfig::default();
        Some(
            calxgloss_git::GitManager::init_repo(output_dir, Some(git_config))
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

    // Run batch translation
    let mut batch_result = pipeline
        .batch_translate(dll, &function_names, &retry_config, &verifier)
        .await
        .with_context(|| format!("Batch translation failed for DLL: {}", dll))?;

    // Git operations: commit each successful function
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
                .create_branch(
                    dll,
                    &func_result.function,
                    1,
                    Some(&BranchCreationPolicy::Warn(DependencyPolicy {
                        category: DllCategory::ProjectSpecific,
                        crate_replacement: None,
                    })),
                )
                .context("Failed to create git branch")?;

            let branch_info = &branch_result.branch;
            print_git_status(branch_info, false);

            let output_path_str = output_path.to_string_lossy().to_string();
            let _commit = git_manager
                .commit(
                    branch_info,
                    &format!(
                        "re/auto/{}: translate {} (batch attempt)",
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
            func_result.branch = Some(branch_info.clone());
        }
    }

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

async fn handle_auto(
    target: Option<PathBuf>,
    dlls_arg: Option<String>,
    _all_functions: bool,
    classify_only: bool,
    skip_git: bool,
    settings: &Settings,
    continue_mode: bool,
    events: Option<&TranslationEvents>,
    repo_dir: PathBuf,
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
        handle_classify(&unclassified, &target_dir, &repo_dir, skip_git, settings, events).await?;
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
            run_translation_for_dll(dll, &output_dir, skip_git, settings, events).await?;
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

        run_translation_for_dll(dll, &output_dir, skip_git, settings, events).await?;
    }

    Ok(())
}

// ============================================================
// Translate command handler
// ============================================================

async fn handle_translate(args: &TranslateArgs, settings: &Settings, repo_dir: PathBuf) -> Result<()> {
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
    // Use the output_dir arg if provided, otherwise use the resolved repo_dir.
    let output_dir = output_dir
        .clone()
        .unwrap_or(repo_dir);

    // Demanded here rather than at startup: `classify` and `verify` never talk
    // to the LLM, so making the endpoint mandatory for them would force users
    // to configure something they do not use.
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
    let _target_dir = target.parent().unwrap_or(target).to_path_buf();

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
        strategy: retry_strategy,
        escalate_on_failure: true,
    };
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
                .create_branch(
                    dll,
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
                    function_address: None,
                    rust_code: attempt.rust_code.clone(),
                    prompt_used: String::new(),
                    model: llm_model_name.clone(),
                    tokens_used: None,
                    baseline_tests: Vec::new(),
                    call_graph: Vec::new(),
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

async fn handle_batch_translate(args: &BatchTranslateArgs, settings: &Settings, repo_dir: PathBuf) -> Result<()> {
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
    // Use the output_dir arg if provided, otherwise use the resolved repo_dir.
    let output_dir = output_dir
        .clone()
        .unwrap_or(repo_dir);

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

    let _target_dir = target.parent().unwrap_or(target).to_path_buf();

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
        strategy: retry_strategy,
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
                .create_branch(
                    dll,
                    &func_result.function,
                    1,
                    Some(&BranchCreationPolicy::Warn(DependencyPolicy {
                        category: DllCategory::ProjectSpecific,
                        crate_replacement: None,
                    })),
                )
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
// Dashboard command handler
// ============================================================

async fn handle_dashboard(follow: bool, interval_secs: u64) -> Result<()> {
    info!("Starting dashboard");

    // Find the git repository — walk up from CWD
    let mut repo_path = std::env::current_dir()?;

    // Walk up to find the .git directory
    let mut found_git = false;
    let mut search_path = repo_path.clone();
    for _ in 0..10 {
        if search_path.join(".git").exists() || search_path.join(".git").is_dir() {
            found_git = true;
            repo_path = search_path.clone();
            break;
        }
        if !search_path.pop() {
            break;
        }
    }

    if !found_git {
        // Try the current directory anyway (it might be a repo)
        repo_path = std::env::current_dir()?;
    }

    info!(path = ?repo_path, "Found git repository");

    let git = GitManager::open(&repo_path).context("Failed to open git repository")?;

    let interval = std::time::Duration::from_secs(interval_secs);

    if follow {
        info!(interval_secs = interval_secs, "Entering follow mode");
        render_dashboard_follow(&git, interval).context("Follow mode failed")?;
    } else {
        let builder = DashboardBuilder::new(&git);
        let dashboard = builder.build().context("Failed to build dashboard")?;
        render_dashboard(&dashboard, false);
    }

    Ok(())
}

// ============================================================
// Dashboard view subcommand handler
// ============================================================

/// Handles the `dashboard view <target>` subcommand.
async fn handle_dashboard_view(target: &str) -> Result<()> {
    info!(target = %target, "Starting dashboard view");

    // Parse target using the shared type from reports crate
    let view_target = ViewTarget::parse(target)
        .context("Invalid target format. Use: <dll>/<function> or <dll>/<function>/vN")?;
    info!(
        dll = %view_target.dll,
        function = %view_target.function,
        attempt = ?view_target.specific_attempt,
        "Parsed view target"
    );

    // Find the git repository — walk up from CWD
    let mut repo_path = std::env::current_dir()?;
    let mut found_git = false;
    let mut search_path = repo_path.clone();
    for _ in 0..10 {
        if search_path.join(".git").exists() || search_path.join(".git").is_dir() {
            found_git = true;
            repo_path = search_path.clone();
            break;
        }
        if !search_path.pop() {
            break;
        }
    }
    if !found_git {
        repo_path = std::env::current_dir()?;
    }

    let git = GitManager::open(&repo_path).context("Failed to open git repository")?;

    // Build the unit view data using the shared type from reports crate
    let unit_data = UnitViewData::load(&git, &view_target, &repo_path)
        .context("Failed to load unit view data")?;

    // Render the view
    render_unit_view(&unit_data);

    Ok(())
}

// ============================================================
// Dashboard accept subcommand handler
// ============================================================

/// Handles the `dashboard accept <target>` subcommand.
///
/// Merges the named branch into `main` and writes an acceptance record.
async fn handle_dashboard_accept(target: &str) -> Result<()> {
    info!(target = %target, "Handling dashboard accept");

    let view_target =
        ViewTarget::parse(target).context("Invalid target format. Use: <dll>/<function>/vN")?;
    info!(
        dll = %view_target.dll,
        function = %view_target.function,
        attempt = ?view_target.specific_attempt,
        "Parsed accept target"
    );

    // Find the git repository
    let repo_path = find_repo_path()?;
    let git = GitManager::open(&repo_path).context("Failed to open git repository")?;

    // Resolve the branch name: find the matching translation branch
    let branch_name = resolve_branch(&git, &view_target)
        .context("Could not find a matching branch for this unit")?;

    info!(branch = %branch_name, "Resolved branch for acceptance");

    // Parse the branch name into a GitBranch for the accept operation
    let (dll, function, attempt) = parse_branch_for_accept(&branch_name);
    let branch = GitBranch::new(&dll, &function, attempt).context("Invalid branch name")?;

    // Check if already merged
    if git.is_branch_merged_into_main(&branch.name)? {
        println!();
        println!(
            "  {} Branch '{}' is already merged into main.",
            yellow_bold("◉"),
            branch.name
        );
        println!();
        return Ok(());
    }

    // Perform the merge + accept
    println!();
    println!("  Merging branch '{}' into main...", bold(&branch.name));

    match git.accept_branch(&branch) {
        Ok(calxgloss_git::MergeResult::Merged { merge_hash }) => {
            println!(
                "  {} Branch '{}' merged into main (commit: {}).",
                green_bold("✓"),
                branch.name,
                &merge_hash[..7]
            );
            println!(
                "  {} Unit '{}/{}' is now accepted.",
                green_bold("✓"),
                view_target.dll,
                view_target.function
            );
        }
        Ok(calxgloss_git::MergeResult::AlreadyUpToDate) => {
            println!(
                "  {} Branch '{}' is already up to date with main.",
                yellow_bold("◉"),
                branch.name
            );
        }
        Ok(calxgloss_git::MergeResult::Conflicts {
            conflicted_files,
            error,
        }) => {
            println!(
                "  {} Merge conflicts on branch '{}': {}",
                red_bold("✗"),
                branch.name,
                error
            );
            println!("  Conflicted files: {}", conflicted_files.join(", "));
            return Err(anyhow::anyhow!(
                "Merge conflicts: {}",
                conflicted_files.join(", ")
            ));
        }
        Err(e) => {
            println!(
                "  {} Failed to accept branch '{}': {}",
                red_bold("✗"),
                branch.name,
                e
            );
            return Err(anyhow::anyhow!("Accept failed: {}", e));
        }
    }

    println!();
    Ok(())
}

// ============================================================
// Dashboard reject subcommand handler
// ============================================================

/// Handles the `dashboard reject <target> --reason "..."` subcommand.
///
/// Records the rejection in `re/rejections/{dll}/{function}/vN.json`.
async fn handle_dashboard_reject(target: &str, reason: Option<&str>) -> Result<()> {
    info!(target = %target, reason = ?reason, "Handling dashboard reject");

    let view_target =
        ViewTarget::parse(target).context("Invalid target format. Use: <dll>/<function>/vN")?;
    info!(
        dll = %view_target.dll,
        function = %view_target.function,
        attempt = ?view_target.specific_attempt,
        "Parsed reject target"
    );

    let reason = reason.unwrap_or("no reason provided");

    // Find the git repository
    let repo_path = find_repo_path()?;
    let git = GitManager::open(&repo_path).context("Failed to open git repository")?;

    // Resolve the branch name: find the matching translation branch
    let branch_name = resolve_branch(&git, &view_target)
        .context("Could not find a matching branch for this unit")?;

    info!(branch = %branch_name, "Resolved branch for rejection");

    // Parse the branch name into a GitBranch for the reject operation
    let (dll, function, attempt) = parse_branch_for_accept(&branch_name);
    let branch = GitBranch::new(&dll, &function, attempt).context("Invalid branch name")?;

    // Perform the rejection
    println!();
    println!(
        "  {} Branch '{}' will be sent back for fixes.",
        red_bold("✗"),
        branch.name
    );
    println!("  {} Rejection reason: \"{}\"", bold("Reason:"), reason);

    match git.reject_branch(&branch, reason) {
        Ok(rejection_path) => {
            println!(
                "  {} Rejection recorded at: {}",
                green_bold("✓"),
                rejection_path.display()
            );
            println!(
                "  {} Unit '{}/{}' has been sent back.",
                red_bold("✗"),
                view_target.dll,
                view_target.function
            );
        }
        Err(e) => {
            println!(
                "  {} Failed to reject branch '{}': {}",
                red_bold("✗"),
                branch.name,
                e
            );
            return Err(anyhow::anyhow!("Reject failed: {}", e));
        }
    }

    println!();
    Ok(())
}

// ============================================================
// Dashboard accept-all subcommand handler
// ============================================================

/// Handles the `dashboard accept-all` subcommand.
///
/// Builds the dashboard, topologically sorts pending units by dependency,
/// and accepts each one in order.
async fn handle_dashboard_accept_all(all_flag: bool) -> Result<()> {
    // Find the git repository
    let repo_path = find_repo_path()?;
    let git = GitManager::open(&repo_path).context("Failed to open git repository")?;

    // Build the dashboard
    let builder = calxgloss_reports::dashboard::DashboardBuilder::new(&git);
    let dashboard = builder
        .build()
        .context("Failed to build review dashboard")?;

    // Determine which units to accept
    let to_accept: Vec<&calxgloss::UnitOfWork> = if all_flag {
        // Accept every non-merged branch in the dashboard
        dashboard
            .review_queue
            .iter()
            .filter(|u| !matches!(u.status, calxgloss::ReviewStatus::Accepted))
            .filter(|u| !matches!(u.status, calxgloss::ReviewStatus::Merged))
            .collect()
    } else {
        // Accept only queued and pending-review units, in dependency order
        dashboard.pending_in_dependency_order()
    };

    if to_accept.is_empty() {
        println!();
        if all_flag {
            println!("  {} No unmerged branches to accept.", dim("◉"));
        } else {
            println!("  {} No pending units to accept.", dim("◉"));
        }
        println!();
        return Ok(());
    }

    let total = to_accept.len();
    println!();
    hsep_bold();
    println_content(format!(
        "  Batch Accept: {} units — dependency order",
        bold(&total.to_string())
    ));
    hsep();
    println_content("");

    let mut accepted = 0;
    let mut skipped = 0;
    let mut failed = 0;

    for unit in &to_accept {
        // Quick check: if already merged, skip
        let branch_name = resolve_branch(
            &git,
            &ViewTarget {
                dll: unit.dll.clone(),
                function: unit.function.clone().unwrap_or_default(),
                specific_attempt: Some(unit.attempt),
            },
        );

        let branch_name = match branch_name {
            Ok(name) => name,
            Err(_) => {
                println!(
                    "  {} {} [{}] — branch not found",
                    yellow_bold("◉"),
                    dim(&format!("{}/{}", unit.dll, unit.name)),
                    red_bold("skip")
                );
                skipped += 1;
                continue;
            }
        };

        // Check if already merged
        if git.is_branch_merged_into_main(&branch_name)? {
            println!(
                "  {} {} [{}] — already merged",
                dim(" "),
                format_dim(&format!("{}/{}", unit.dll, unit.name)),
                dim("skipped")
            );
            skipped += 1;
            continue;
        }

        // Parse the branch into a GitBranch
        let (dll, function, attempt) = parse_branch_for_accept(&branch_name);
        let branch = match GitBranch::new(&dll, &function, attempt) {
            Ok(b) => b,
            Err(e) => {
                println!(
                    "  {} {} [{}] — {}",
                    red_bold("✗"),
                    format_dim(&format!("{}/{}", unit.dll, unit.name)),
                    red_bold("error"),
                    e
                );
                failed += 1;
                continue;
            }
        };

        // Accept the branch
        match git.accept_branch(&branch) {
            Ok(calxgloss_git::MergeResult::Merged { merge_hash }) => {
                println!(
                    "  {} {} [v{}] — {} ({})",
                    green_bold("✓"),
                    format_dim(&format!("{}/{}", unit.dll, unit.name)),
                    unit.attempt,
                    green_bold("accepted"),
                    &merge_hash[..7]
                );
                accepted += 1;
            }
            Ok(calxgloss_git::MergeResult::AlreadyUpToDate) => {
                println!(
                    "  {} {} [v{}] — {}",
                    yellow_bold("◉"),
                    format_dim(&format!("{}/{}", unit.dll, unit.name)),
                    unit.attempt,
                    yellow_bold("up to date")
                );
                skipped += 1;
            }
            Ok(calxgloss_git::MergeResult::Conflicts {
                conflicted_files,
                error,
            }) => {
                println!(
                    "  {} {} [v{}] — {} ({})",
                    red_bold("✗"),
                    format_dim(&format!("{}/{}", unit.dll, unit.name)),
                    unit.attempt,
                    red_bold("conflict"),
                    error
                );
                println_content(format!(
                    "    Conflicted files: {}",
                    conflicted_files.join(", ")
                ));
                failed += 1;
            }
            Err(e) => {
                println!(
                    "  {} {} [v{}] — {} ({})",
                    red_bold("✗"),
                    format_dim(&format!("{}/{}", unit.dll, unit.name)),
                    unit.attempt,
                    red_bold("failed"),
                    e
                );
                failed += 1;
            }
        }
    }

    println_content("");
    hsep();
    let summary_parts = [
        green_bold(&format!("Accepted:  {}", accepted)),
        yellow_bold(&format!("Skipped:   {}", skipped)),
        red_bold(&format!("Failed:    {}", failed)),
    ];
    println_content(summary_parts.join("  │  "));
    hsep_bold();
    println!();

    if failed > 0 {
        return Err(anyhow::anyhow!(
            "Batch accept completed with {} failure(s)",
            failed
        ));
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
    let label = if dll.to_lowercase().ends_with(".exe") {
        "File:"
    } else {
        "DLL:"
    };
    println!("  {}{}", white_bold(&format!("  {label} ")), dll);
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
// Serve command handler
// ============================================================

/// Handles the `serve` subcommand: starts the web review UI HTTP server.
async fn handle_serve(repo_dir: PathBuf, port: u16) -> Result<()> {
    info!(repo = ?repo_dir, port, "Starting web review UI server");

    if !repo_dir.exists() {
        anyhow::bail!(
            "Repository path does not exist: {}\n\nMake sure the path points to the \
             resultant (git) workspace that contains the translation work.",
            repo_dir.display()
        );
    }

    // Print startup banner before moving repo_dir into ServerState
    println!();
    println_content(format!(
        "  {}",
        bold(&format!(
            "Calxgloss Review UI — serving at http://127.0.0.1:{port}"
        ))
    ));
    hsep();
    println_content("");
    println_content(format!(
        "  Repository: {}",
        bold(&repo_dir.display().to_string())
    ));
    println_content(format!("  Port:       {port}"));
    println_content(format!(
        "  Dashboard:  {}",
        bold(&format!("http://127.0.0.1:{port}/"))
    ));
    println_content(format!(
        "  API root:   {}",
        bold(&format!("http://127.0.0.1:{port}/api/"))
    ));
    println_content("");
    println_content("  Press Ctrl+C to stop");
    println!();

    let server_state = calxgloss_web::ServerState::new(repo_dir);
    println_content("Endpoints:");
    println_content("    GET  /                  Dashboard frontend");
    println_content("    GET  /api/dashboard     Full review dashboard JSON");
    println_content("    GET  /api/queue         Review queue (dependency-ordered)");
    println_content("    GET  /api/graph         Dependency graph data");
    println_content("    GET  /api/units/:id     Unit detail");
    println_content("    GET  /api/units/:id/diff  Git diff between branch and main");
    println_content("    POST /api/units/:id/accept    Accept (merge to main)");
    println_content("    POST /api/units/:id/send-back Send back with comments");
    println_content("    POST /api/units/:id/patch     Request patch (retry translation)");
    println!();
    hsep_bold();
    println!();

    // Start the axum server
    calxgloss_web::serve(server_state, port, None).await?;

    Ok(())
}

// ============================================================
// Live command handler — auto + serve concurrently
// ============================================================

/// Handles the `live` subcommand: starts both the auto pipeline and the
/// web review UI in the same process.
async fn handle_live(
    target: Option<PathBuf>,
    dlls: Option<String>,
    all_functions: bool,
    classify_only: bool,
    skip_git: bool,
    repo_dir: PathBuf,
    port: u16,
    settings: &Settings,
) -> Result<()> {
    info!(
        port,
        repo = ?repo_dir,
        classify_only,
        skip_git,
        "Starting live mode: auto + serve"
    );

    // Print startup banner
    println!();
    hsep_bold();
    println_content("  Calxgloss Live — Auto Pipeline + Review UI");
    hsep();
    println_content("");

    let port_str = port.to_string();
    println_content(format!(
        "  Review UI:    {}",
        bold(&format!("http://127.0.0.1:{port_str}"))
    ));
    println_content("  Translation:  running in foreground");
    println_content("");
    println_content("  Press Ctrl+C to stop both");
    println!();
    hsep_bold();
    println!();

    // Spawn the serve task in the background.  The task binds the TCP listener
    // and sends the ready signal itself so the caller knows when the socket is
    // actually reachable.  Errors before the bind (or bind failures) are also
    // reported through the channel to avoid a spurious "panicked" message.
    let (ready_tx, ready_rx) =
        tokio::sync::oneshot::channel::<std::result::Result<std::net::SocketAddr, anyhow::Error>>();

    // Create the shared event channel before spawning.  The broadcast sender
    // is clonable, so we pass a clone to the serve task and keep the original
    // for the pipeline.
    let events = TranslationEvents::new(256);
    let events_clone = events.clone();

    // Progress state for live dashboard updates.
    let progress = calxgloss_web::ProgressState::new();

    let serve_repo_dir = repo_dir.clone();
    let serve_progress = progress.clone();

    let serve_handle = tokio::spawn(async move {
        let repo_dir = serve_repo_dir;

        // Bind the listener and signal readiness — this happens outside of
        // serve() so we can report bind failures through the channel.
        let listener = match tokio::net::TcpListener::bind(format!("0.0.0.0:{port}")).await {
            Ok(l) => l,
            Err(e) => {
                let _ = ready_tx.send(Err(e.into()));
                return;
            }
        };
        let local_addr = listener
            .local_addr()
            .unwrap_or_else(|_| std::net::SocketAddr::from(([127, 0, 0, 1], port)));
        let _ = ready_tx.send(Ok(local_addr));

        let server_state = calxgloss_web::ServerState::new(repo_dir);

        // Build the router with WebSocket support so the frontend can stream
        // progress events over the upgrade endpoint.
        let event_rx = events_clone.subscribe();
        let manager = calxgloss_web::SessionManager::new_with_broadcast(event_rx);
        let router =
            calxgloss_web::build_router_with_ws(server_state.clone(), manager, serve_progress);
        let _ = calxgloss_web::serve_with_listener(listener, router)
            .await
            .map_err(|e| {
                error!("Review UI server error: {e}");
            });
    });

    // Wait briefly for the server to signal readiness — fail fast if it
    // panicked during startup.
    // Timeout → Receiver::recv() → inner Result
    match tokio::time::timeout(std::time::Duration::from_secs(5), ready_rx).await {
        Ok(Ok(Ok(addr))) => {
            debug!(%addr, "Review UI is ready");
        }
        Ok(Ok(Err(e))) => {
            serve_handle.abort();
            let _ = serve_handle.await;
            anyhow::bail!("Failed to start review UI: {e}");
        }
        Ok(Err(_recv_err)) => {
            serve_handle.abort();
            let _ = serve_handle.await;
            anyhow::bail!("Serve task panicked while starting (recv error)");
        }
        Err(_elapsed) => {
            debug!("Server startup signal not received in time; continuing anyway");
        }
    }

    // Run the auto pipeline in the foreground (this blocks until complete).
    let auto_result = handle_auto(
        target,
        dlls,
        all_functions,
        classify_only,
        skip_git,
        settings,
        true,          // continue mode — don't stop after classification, translate all
        Some(&events), // pass event emitter for live progress streaming
        repo_dir,      // resolved repo_dir (same value used by serve task)
    )
    .await;

    // Auto is done — shut down the server gracefully.
    // The server handle is a tokio::JoinHandle; we drop it which sends the
    // cancel signal to the spawned task.  Then wait for cleanup.
    serve_handle.abort();
    let _ = serve_handle.await;

    match auto_result {
        Ok(()) => {
            println!();
            hsep_bold();
            println_content("  Auto pipeline finished.");
            println_content("  Review UI stopped.");
            hsep_bold();
            println!();
            Ok(())
        }
        Err(e) => {
            println!();
            hsep_bold();
            println_content("  Auto pipeline failed.");
            println_content(format!("  Error: {}", red_bold(&e.to_string())));
            hsep_bold();
            println!();
            Err(e)
        }
    }
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
        target_dir: cli
            .target_dir
            .as_ref()
            .map(|p| p.to_string_lossy().to_string()),
        repo_dir: cli
            .repo_dir
            .as_ref()
            .map(|p| p.to_string_lossy().to_string()),
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
            strategy: cli.strategy.clone(),
        },
    };
    let settings = Settings::resolve(&layers, flags, &loaded);

    // target_dir is required for all commands that do real work.
    // `config` is the only command that doesn't need it, so we check
    // here and fail fast with a helpful message.
    if let Some(ref target) = cli.command {
        match target {
            Command::Config => {}
            _ if settings.target_dir.is_none() => {
                anyhow::bail!(
                    "target_dir is required.\n\nSet it via:\n  --target-dir <path>\n  [target_dir] in calxgloss.toml\n  CALXGLOSS_TARGET_DIR env var"
                );
            }
            _ => {}
        }
    }

    // Run the appropriate command
    // No subcommand defaults to `auto` mode.
    let command = cli.command.unwrap_or(Command::Auto {
        target: None,
        dlls: None,
        all_functions: false,
        classify_only: false,
        skip_git: false,
    });
    let result = match command {
        Command::Config => {
            print!("{}", settings::render(&settings));
            Ok(())
        }
        Command::Classify { dll } => {
            let target_dir = settings
                .target_dir
                .as_ref()
                .map(|t| PathBuf::from(&t.value))
                .unwrap_or_else(|| std::env::current_dir().expect("Failed to read current directory"));
            let target_dir = target_dir.as_ref();
            let repo_dir = resolve_repo_dir(cli.repo_dir.as_ref(), &settings);
            let skip_git = false;
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("Failed to create tokio runtime")?
                .block_on(handle_classify(&dll, target_dir, &repo_dir, skip_git, &settings, None))
        }
        Command::Translate(args) => {
            let repo_dir = resolve_repo_dir(cli.repo_dir.as_ref(), &settings);
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("Failed to create tokio runtime")?
                .block_on(handle_translate(&args, &settings, repo_dir))
        }
        Command::BatchTranslate(args) => {
            let repo_dir = resolve_repo_dir(cli.repo_dir.as_ref(), &settings);
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("Failed to create tokio runtime")?
                .block_on(handle_batch_translate(&args, &settings, repo_dir))
        }
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
        Command::Dashboard {
            follow: _,
            interval: _,
            command: Some(DashboardSubcommand::View { target }),
        } => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("Failed to create tokio runtime")?
            .block_on(handle_dashboard_view(&target)),
        Command::Dashboard {
            follow: _,
            interval: _,
            command: Some(DashboardSubcommand::Accept { target }),
        } => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("Failed to create tokio runtime")?
            .block_on(handle_dashboard_accept(&target)),
        Command::Dashboard {
            follow: _,
            interval: _,
            command: Some(DashboardSubcommand::Reject { target, reason }),
        } => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("Failed to create tokio runtime")?
            .block_on(handle_dashboard_reject(&target, reason.as_deref())),
        Command::Dashboard {
            follow: _,
            interval: _,
            command: Some(DashboardSubcommand::AcceptAll { all }),
        } => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("Failed to create tokio runtime")?
            .block_on(handle_dashboard_accept_all(all)),
        Command::Dashboard {
            follow,
            interval,
            command: None,
        } => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("Failed to create tokio runtime")?
            .block_on(handle_dashboard(follow, interval)),
        Command::Init => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("Failed to create tokio runtime")?
            .block_on(async { handle_init() }),
        Command::Auto {
            target,
            dlls,
            all_functions,
            classify_only,
            skip_git,
        } => {
            let repo_dir = resolve_repo_dir(cli.repo_dir.as_ref(), &settings);
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("Failed to create tokio runtime")?
                .block_on(handle_auto(
                    target,
                    dlls,
                    all_functions,
                    classify_only,
                    skip_git,
                    &settings,
                    false, // interactive mode — prompt user, stop after classification
                    None,  // no event emitter in interactive mode
                    repo_dir,
                ))
        }
        Command::Serve { port, .. } => {
            // serve always uses CWD as repo_dir — config / env overrides are
            // ignored because the workspace (where .git, src/, scratch/ live)
            // is always where the user runs the command from.
            let repo_dir = resolve_live_repo_dir(cli.repo_dir.as_ref());
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("Failed to create tokio runtime")?
                .block_on(handle_serve(repo_dir, port))
        }
        Command::Live {
            target,
            dlls,
            all_functions,
            classify_only,
            skip_git,
            port,
            ..
        } => {
            // live always uses CWD as repo_dir — config / env overrides are
            // ignored because the workspace (where .git, src/, scratch/ live)
            // is always where the user runs the command from.
            let repo_dir = resolve_live_repo_dir(cli.repo_dir.as_ref());
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("Failed to create tokio runtime")?
                .block_on(handle_live(
                    target,
                    dlls,
                    all_functions,
                    classify_only,
                    skip_git,
                    repo_dir,
                    port,
                    &settings,
                ))
        }
    };

    if let Err(ref e) = result {
        error!("Error: {}", e);
    }

    result
}
