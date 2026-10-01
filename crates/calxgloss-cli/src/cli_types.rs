//! CLI argument parsing types.
//!
//! Defines the [`Cli`], [`Command`], [`DashboardSubcommand`],
//! [`TranslateArgs`], and [`BatchTranslateArgs`] types that `clap` uses
//! for command-line argument parsing.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

/// Calxgloss — Reverse Engineering Harness
///
/// Decompile binaries to cross-platform Rust via LLM-assisted translation.
#[derive(Parser, Debug)]
#[command(name = env!("CARGO_PKG_NAME"), about, version = env!("CARGO_PKG_VERSION"))]
pub(super) struct Cli {
    /// Enable verbose output (equivalent to RUST_LOG=debug)
    #[arg(long, short = 'v', action = clap::ArgAction::Count)]
    pub(super) verbose: u8,

    /// Log format: text, json, or pretty (default: pretty)
    #[arg(long, default_value = "pretty")]
    pub(super) log_format: String,

    /// Path to a TOML configuration file
    ///
    /// Overrides the search for ./calxgloss.toml and
    /// ~/.config/calxgloss/config.toml. The named file must exist, so a typo
    /// fails loudly instead of silently falling back.
    #[arg(long, global = true, value_name = "FILE")]
    pub(super) config: Option<PathBuf>,

    /// Target directory for DLLs and output
    ///
    /// Overrides the `target_dir` setting in the config file.
    #[arg(long, global = true, value_name = "DIR")]
    pub(super) target_dir: Option<PathBuf>,

    /// Repo directory for translation output
    ///
    /// Overrides the `repo_dir` setting in the config file. This is the
    /// directory where `src/`, `re/`, scratch, and the `.git` repo are
    /// created. For `live`/`serve` defaults to CWD and ignores config/env.
    /// For other commands defaults to CWD if no config setting is present.
    #[arg(long, global = true, value_name = "DIR")]
    pub(super) repo_dir: Option<PathBuf>,

    /// GhidraMCP server URL (default: http://127.0.0.1:8080)
    #[arg(long, global = true)]
    pub(super) ghidra_url: Option<String>,

    /// API key for the GhidraMCP server (optional)
    #[arg(long, global = true)]
    pub(super) ghidra_api_key: Option<String>,

    /// LLM server URL (OpenAI-compatible API)
    #[arg(long, global = true)]
    pub(super) llm_url: Option<String>,

    /// LLM model name
    #[arg(long, global = true)]
    pub(super) llm_model: Option<String>,

    /// API key for the LLM server (optional)
    #[arg(long, global = true)]
    pub(super) llm_api_key: Option<String>,

    /// Maximum tokens for LLM generation (default: 8192)
    #[arg(long, global = true)]
    pub(super) max_tokens: Option<usize>,

    /// LLM temperature (0.0 = deterministic, higher = more creative) (default: 0.1)
    #[arg(long, global = true)]
    pub(super) temperature: Option<f32>,

    /// Number of retry attempts on translation failure (default: 3)
    #[arg(long, global = true)]
    pub(super) max_retries: Option<u32>,

    /// Retry strategy: compile_fix, test_fix, escalate, edge_case_fix, or auto
    /// (auto cycles through all strategies on each failure)
    #[arg(long, global = true, value_parser = ["compile_fix", "test_fix", "escalate", "edge_case_fix", "auto"])]
    pub(super) strategy: Option<String>,

    #[command(subcommand)]
    pub(super) command: Option<Command>,
}

/// Arguments for the `translate` subcommand.
///
/// The connection settings live on [`Cli`] as global flags, so they mean the
/// same thing for every subcommand and `calxgloss config` can show an override.
#[derive(Args, Debug)]
pub(super) struct TranslateArgs {
    /// Path to the target executable
    #[arg(long)]
    pub(super) target: PathBuf,

    /// DLL name containing the function
    #[arg(long)]
    pub(super) dll: String,

    /// Function name to translate
    #[arg(long)]
    pub(super) function: String,

    /// Output directory for translated code (default: same as target directory)
    #[arg(long)]
    pub(super) output_dir: Option<PathBuf>,

    /// Skip git operations
    #[arg(long)]
    pub(super) skip_git: bool,
}

/// Arguments for the `batch-translate` subcommand.
#[derive(Args, Debug)]
pub(super) struct BatchTranslateArgs {
    /// Path to the target executable
    #[arg(long)]
    pub(super) target: PathBuf,

    /// DLL name containing the functions to translate
    #[arg(long)]
    pub(super) dll: String,

    /// Comma-separated list of function names to translate (e.g., "Func1,Func2,Func3")
    #[arg(long)]
    pub(super) functions: Option<String>,

    /// Translate all exported functions from the DLL (overrides --functions)
    #[arg(long)]
    pub(super) all_functions: bool,

    /// Output directory for translated code (default: same as target directory)
    #[arg(long)]
    pub(super) output_dir: Option<PathBuf>,

    /// Skip git operations
    #[arg(long)]
    pub(super) skip_git: bool,
}

/// Subcommands for the CLI.
#[derive(Subcommand, Debug)]
pub(super) enum Command {
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

    /// Generate shim layers for all crate-replacement DLLs automatically.
    ///
    /// After `classify` marks DLLs as `CrateReplacement`, this command runs
    /// the full shim pipeline: generate API mappings (LLM) → generate source
    /// code → generate tests → verify → persist.
    ///
    /// Artifacts are written to `re/shims/<dll_name>/` and committed to git.
    ///
    /// # Arguments
    ///
    /// * `--dll` — Process only this specific DLL. Omit to process all
    ///   `CrateReplacement` DLLs listed in the classification records.
    /// * `--skip-git` — Skip git commit of the generated artifacts.
    AutoShim {
        /// Process only this specific DLL (default: all crate-replacement DLLs)
        #[arg(long)]
        dll: Option<String>,

        /// Skip git commit of generated artifacts
        #[arg(long)]
        skip_git: bool,
    },
}

/// Subcommands for the dashboard.
#[derive(Subcommand, Debug)]
pub(super) enum DashboardSubcommand {
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
