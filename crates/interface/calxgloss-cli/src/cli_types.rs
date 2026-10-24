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

    /// Target directory for DLLs and EXEs (read-only)
    ///
    /// Overrides the `target_dir` setting in the config file.
    #[arg(long, global = true, value_name = "DIR")]
    pub(super) target_dir: Option<PathBuf>,

    /// Workspace directory: where the translated Rust, `re/`, scratch, and the
    /// `.git` repo live
    ///
    /// Overrides the `workspace` setting in the config file. For
    /// `live`/`serve` defaults to CWD and ignores config/env.
    /// For other commands defaults to CWD if no config setting is present.
    #[arg(long, global = true, value_name = "DIR")]
    pub(super) workspace: Option<PathBuf>,

    /// LLM server URL (OpenAI-compatible API)
    #[arg(long, global = true)]
    pub(super) llm_url: Option<String>,

    /// LLM model name
    #[arg(long, global = true)]
    pub(super) llm_model: Option<String>,

    /// API key for the LLM server (optional)
    #[arg(long, global = true)]
    pub(super) llm_api_key: Option<String>,

    /// Token budget for a single LLM request: prompt + output (default: 8192)
    #[arg(long, global = true)]
    pub(super) context_window: Option<usize>,

    /// LLM temperature (0.0 = deterministic, higher = more creative) (default: 0.1)
    #[arg(long, global = true)]
    pub(super) temperature: Option<f32>,

    /// Number of retry attempts on translation failure (default: 3)
    #[arg(long, global = true)]
    pub(super) max_retries: Option<u32>,

    /// Per-request LLM timeout in seconds, covering the server's generation
    /// time (default: 300)
    #[arg(long, global = true, value_name = "SECONDS")]
    pub(super) timeout_secs: Option<u64>,

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
    pub(super) binary: String,

    /// Function name to translate
    #[arg(long)]
    pub(super) function: String,

    /// Skip git operations
    #[arg(long)]
    pub(super) skip_git: bool,

    /// Skip call-graph extraction (faster when call-graph context is not needed)
    #[arg(long)]
    pub(super) no_callgraph: bool,

    /// Custom directory for call graph cache files
    ///
    /// By default, call graphs are stored in `{workspace}/re/analysis/`. This
    /// flag overrides the default location.
    #[arg(long, value_name = "DIR")]
    pub(super) callgraph_cache: Option<PathBuf>,

    /// Print call-graph statistics after building the graph
    ///
    /// Displays function count, root/middle/leaf breakdown, call-type
    /// distribution, and external API count.
    #[arg(long)]
    pub(super) callgraph_verbose: bool,
}

/// Arguments for the `batch-translate` subcommand.
#[derive(Args, Debug)]
pub(super) struct BatchTranslateArgs {
    /// Path to the target executable
    #[arg(long)]
    pub(super) target: PathBuf,

    /// DLL name containing the functions to translate
    #[arg(long)]
    pub(super) binary: String,

    /// Comma-separated list of function names to translate (e.g., "Func1,Func2,Func3")
    #[arg(long)]
    pub(super) functions: Option<String>,

    /// Translate all exported functions from the DLL (overrides --functions)
    #[arg(long)]
    pub(super) all_functions: bool,

    /// Skip git operations
    #[arg(long)]
    pub(super) skip_git: bool,

    /// Skip call-graph extraction (faster when call-graph context is not needed)
    #[arg(long)]
    pub(super) no_callgraph: bool,

    /// Custom directory for call graph cache files
    ///
    /// By default, call graphs are stored in `{workspace}/re/analysis/`. This
    /// flag overrides the default location.
    #[arg(long, value_name = "DIR")]
    pub(super) callgraph_cache: Option<PathBuf>,

    /// Print call-graph statistics after building the graph
    ///
    /// Displays function count, root/middle/leaf breakdown, call-type
    /// distribution, and external API count.
    #[arg(long)]
    pub(super) callgraph_verbose: bool,

    /// Force fresh engine reads, ignoring and rewriting the batch's scan
    /// read cache (`re/cache/`)
    ///
    /// The cache's manifest keys on the binary's bytes, so a hand-edited
    /// cache is not detected — use this after tampering with one.
    /// Deleting the binary's cache directory by hand does the same without
    /// a run.
    #[arg(long)]
    pub(super) refresh_cache: bool,
}

/// Arguments for `doctor`.
#[derive(Args, Debug)]
pub(super) struct DoctorArgs {
    /// Accepted for compatibility with older scripts; there is nothing to
    /// install — the Kuna engine is compiled in (issue #214)
    #[arg(long)]
    pub(super) fix: bool,

    /// Target binary to load
    ///
    /// Doctor loads this file in-process with the Kuna engine and reports
    /// its program identity, so the binary must be named.
    #[arg(long, value_name = "FILE")]
    pub(super) binary: Option<PathBuf>,
}

/// Subcommands for the CLI.
#[derive(Subcommand, Debug)]
pub(super) enum Command {
    /// Create a `calxgloss.toml` configuration file in the current directory.
    ///
    /// Writes a commented-out template with example settings for the
    /// `[llm]` section. If a file already exists, it is overwritten.
    Init,

    /// Report the analysis engine in one read-only pass
    ///
    /// Kuna is the only analysis engine (issue #214): it is compiled in,
    /// so there is no install, extension, JVM, or server port to check.
    /// The `--binary` target is loaded in-process and its program identity
    /// is reported; any failure carries a remediation hint and exits
    /// non-zero so CI can gate on this command.
    ///
    /// # Examples
    ///
    /// ```text
    /// calxgloss doctor --binary target.dll
    /// ```
    Doctor(DoctorArgs),

    /// Classify DLLs, choosing how to treat each one
    Classify {
        /// The DLLs to classify are named here because the engine serves a
        /// single open program and cannot list what a target links against.
        #[arg(long, required = true)]
        binary: Vec<String>,
    },

    /// Translate a single function from disassembly to Rust
    Translate(TranslateArgs),

    /// Translate multiple functions from a single DLL in one pass
    BatchTranslate(BatchTranslateArgs),

    /// Recover the type database for a binary.
    ///
    /// Runs the three recovery scans — named types from the engine's type
    /// system, vtable detection, and string-guided struct inference —
    /// against the loaded program and saves the result to
    /// `re/analysis/typesdb/<binary>.json` in the workspace, alongside a
    /// generated `re/analysis/typesdb/<binary>.rs` file of `#[repr(C)]`
    /// Rust declarations recovered from the database. Batch
    /// translation recovers this automatically before its first batch
    /// when no database is cached; this command is the manual entry
    /// point: it rebuilds the database on demand and can print what a
    /// cached one holds.
    ///
    /// # Arguments
    ///
    /// * `--binary` — Binary to scan, e.g. `eqmain.dll`. Names the
    ///   persisted file.
    /// * `--show` — Print a summary of the cached database, and the path
    ///   of its Rust declarations file when one exists, without running
    ///   the scans.
    /// * `--no-tag` — Detect vtable methods without writing
    ///   `vtable-method` tags back into the program.
    ///
    /// # Examples
    ///
    /// ```text
    /// calxgloss typesdb --binary eqmain.dll
    /// calxgloss typesdb --binary eqmain.dll --show
    /// ```
    Typesdb {
        /// Binary to scan, e.g. `eqmain.dll`
        #[arg(long, required = true)]
        binary: String,

        /// Show the cached database instead of running the scans
        #[arg(long)]
        show: bool,

        /// Do not attempt vtable-method tag write-back
        #[arg(long)]
        no_tag: bool,
    },

    /// Infer parameter types for a binary.
    ///
    /// Runs the three inference detectors — C++ this-pointer detection,
    /// parameter-size detection, and known-type propagation — against the
    /// currently open program and saves the result to
    /// `re/analysis/typeinfer/<binary>.json` in the workspace. Batch
    /// translation runs the same scan automatically before its first
    /// batch when no result is cached; this command is the manual entry
    /// point: it rebuilds the result on demand and can print what a
    /// cached one holds.
    ///
    /// # Arguments
    ///
    /// * `--binary` — Binary to scan, e.g. `eqmain.dll`. Names the
    ///   persisted file.
    /// * `--show` — Print a summary of the cached result without running
    ///   the scan.
    /// * `--write-back` — After the scan, apply the surviving inferences
    ///   back through the engine type-write API:
    ///   missing named types are created, undefined-typed parameters,
    ///   returns, and locals are narrowed, and a concrete slot is never
    ///   overwritten. Works with `--show` too, applying the cached result.
    /// * `--confidence-floor` — Minimum confidence (0–100) a record needs
    ///   to be written back. Records below it are skipped with the reason
    ///   reported. Default 70.
    ///
    /// # Examples
    ///
    /// ```text
    /// calxgloss typeinfer --binary eqmain.dll
    /// calxgloss typeinfer --binary eqmain.dll --show
    /// calxgloss typeinfer --binary eqmain.dll --write-back
    /// calxgloss typeinfer --binary eqmain.dll --write-back --confidence-floor 85
    /// ```
    Typeinfer {
        /// Binary to scan, e.g. `eqmain.dll`
        #[arg(long, required = true)]
        binary: String,

        /// Show the cached result instead of running the scan
        #[arg(long)]
        show: bool,

        /// Apply the inferences back through the engine type-write API
        #[arg(long)]
        write_back: bool,

        /// Minimum confidence (0-100) a record needs to be written back
        #[arg(long, default_value_t = 70, value_name = "CONFIDENCE")]
        confidence_floor: u8,
    },

    /// Recognize algorithms in a binary.
    ///
    /// Runs the three recognition detectors — control flow signature
    /// matching, string-guided hints, and callback pattern detection —
    /// against the currently open program and saves the result to
    /// `re/analysis/algorithm/<binary>.json` in the workspace. Batch
    /// translation runs the same scan automatically before its first
    /// batch when no result is cached; this command is the manual entry
    /// point: it rebuilds the result on demand and can print what a
    /// cached one holds.
    ///
    /// # Arguments
    ///
    /// * `--binary` — Binary to scan, e.g. `eqmain.dll`. Names the
    ///   persisted file.
    /// * `--show` — Print a summary of the cached result without running
    ///   the scan.
    /// * `--patterns` — JSON pattern database file: run the scan with
    ///   the file's control flow signatures, string signatures, and
    ///   callback contracts instead of the built-in standard sets. A
    ///   malformed file fails the run naming its path. Ignored on the
    ///   `--show` path, which reads a cached result.
    ///
    /// # Examples
    ///
    /// ```text
    /// calxgloss algorithm --binary eqmain.dll
    /// calxgloss algorithm --binary eqmain.dll --show
    /// calxgloss algorithm --binary eqmain.dll --patterns my-patterns.json
    /// ```
    Algorithm {
        /// Binary to scan, e.g. `eqmain.dll`
        #[arg(long, required = true)]
        binary: String,

        /// Show the cached result instead of running the scan
        #[arg(long)]
        show: bool,

        /// JSON pattern database replacing the built-in signature sets
        #[arg(long, value_name = "FILE")]
        patterns: Option<PathBuf>,
    },

    /// Detect memory lifecycles (allocation/release pairs, handle
    /// lifetimes, reference counting) for a binary.
    ///
    /// The lifecycle findings are persisted per binary to
    /// `re/analysis/memory/<binary>.json` in the workspace — the same file
    /// batch translation will read as prompt context. `--show` prints a
    /// cached result without running the scan.
    ///
    /// # Arguments
    ///
    /// * `--binary` — Binary to scan, e.g. `eqmain.dll`. Names the
    ///   persisted file.
    /// * `--show` — Print a summary of the cached result.
    ///
    /// # Examples
    ///
    /// ```text
    /// calxgloss memory --binary eqmain.dll --show
    /// ```
    Memory {
        /// Binary to scan, e.g. `eqmain.dll`
        #[arg(long, required = true)]
        binary: String,

        /// Show the cached result instead of running the scan
        #[arg(long)]
        show: bool,
    },

    /// Identify known-library functions (statically linked CRT/STL code)
    /// for a binary by matching normalized decompiled bodies against a
    /// signature set.
    ///
    /// The identification findings are persisted per binary to
    /// `re/analysis/libmatch/<binary>.json` in the workspace. `--show`
    /// prints a cached result without running the scan.
    ///
    /// # Arguments
    ///
    /// * `--binary` — Binary to scan, e.g. `eqmain.dll`. Names the
    ///   persisted file.
    /// * `--show` — Print a summary of the cached result.
    /// * `--signatures` — JSON signature database file: run the scan
    ///   with the file's signatures instead of the built-in starter
    ///   set, whole. A malformed file fails the run naming its path.
    ///   Ignored on the `--show` path, which reads a cached result.
    ///
    /// # Examples
    ///
    /// ```text
    /// calxgloss libmatch --binary eqmain.dll --show
    /// calxgloss libmatch --binary eqmain.dll --signatures my-signatures.json
    /// ```
    Libmatch {
        /// Binary to scan, e.g. `eqmain.dll`
        #[arg(long, required = true)]
        binary: String,

        /// Show the cached result instead of running the scan
        #[arg(long)]
        show: bool,

        /// JSON signature database replacing the built-in signature set
        #[arg(long, value_name = "FILE")]
        signatures: Option<PathBuf>,
    },

    /// Review a binary version change's function pairings before the run.
    ///
    /// Loads the pairing documents the auto run's version-pairing scan
    /// step leaves in `re/analysis/bdiff/` for a binary identity and
    /// lists each old↔new pair with its confidence and match family,
    /// plus the functions paired on neither side — old-only and
    /// new-only. The live document is the one naming the target
    /// directory's current bytes as its new side; a document naming a
    /// since-replaced version is stale and reported as such, never
    /// printed as an empty success. Pure report: no scan runs, no
    /// engine read.
    ///
    /// # Arguments
    ///
    /// * `--binary` — Binary identity to review, e.g. `eqmain.dll`.
    ///
    /// # Examples
    ///
    /// ```text
    /// calxgloss bdiff --binary eqmain.dll
    /// ```
    Bdiff {
        /// Binary identity to review, e.g. `eqmain.dll`
        #[arg(long, required = true)]
        binary: String,
    },

    /// Detect concurrency constructs (mutex/lock pairings, atomic
    /// operations, thread spawns) for a binary.
    ///
    /// The concurrency findings are persisted per binary to
    /// `re/analysis/sync/<binary>.json` in the workspace — the same file
    /// batch translation will read as prompt context. `--show` prints a
    /// cached result without running the scan.
    ///
    /// # Arguments
    ///
    /// * `--binary` — Binary to scan, e.g. `eqmain.dll`. Names the
    ///   persisted file.
    /// * `--show` — Print a summary of the cached result.
    ///
    /// # Examples
    ///
    /// ```text
    /// calxgloss sync --binary eqmain.dll --show
    /// ```
    Sync {
        /// Binary to scan, e.g. `eqmain.dll`
        #[arg(long, required = true)]
        binary: String,

        /// Show the cached result instead of running the scan
        #[arg(long)]
        show: bool,
    },

    /// Record the global-state reference sets (which functions read and
    /// write which program globals) for a binary.
    ///
    /// The access records and the derived purity summary are persisted
    /// per binary to `re/analysis/globalstate/<binary>.json` in the
    /// workspace — the same file batch translation will read as prompt
    /// context. `--show` prints a cached result without running the
    /// scan.
    ///
    /// # Arguments
    ///
    /// * `--binary` — Binary to scan, e.g. `eqmain.dll`. Names the
    ///   persisted file.
    /// * `--show` — Print a summary of the cached result.
    ///
    /// # Examples
    ///
    /// ```text
    /// calxgloss globalstate --binary eqmain.dll --show
    /// ```
    GlobalState {
        /// Binary to scan, e.g. `eqmain.dll`
        #[arg(long, required = true)]
        binary: String,

        /// Show the cached result instead of running the scan
        #[arg(long)]
        show: bool,
    },

    /// Detect constant structures (bitflag groups, enum candidates,
    /// repeated magic numbers) for a binary.
    ///
    /// The constant findings are persisted per binary to
    /// `re/analysis/consts/<binary>.json` in the workspace — the same file
    /// batch translation will read as prompt context. `--show` prints a
    /// cached result without running the scan.
    ///
    /// # Arguments
    ///
    /// * `--binary` — Binary to scan, e.g. `eqmain.dll`. Names the
    ///   persisted file.
    /// * `--show` — Print a summary of the cached result.
    ///
    /// # Examples
    ///
    /// ```text
    /// calxgloss consts --binary eqmain.dll --show
    /// ```
    Consts {
        /// Binary to scan, e.g. `eqmain.dll`
        #[arg(long, required = true)]
        binary: String,

        /// Show the cached result instead of running the scan
        #[arg(long)]
        show: bool,
    },

    /// Detect callback and function-pointer tables in the open binary
    ///
    /// Finds the dispatch patterns ChatGPT most often flattens: arrays
    /// of function pointers called as `table[i](...)`, explicit
    /// registration calls like `set_callback(handler)`, and
    /// switch/jump-table dispatch.
    ///
    /// The callback findings are persisted per binary to
    /// `re/analysis/callback/<binary>.json` in the workspace — the same
    /// file batch translation will read as prompt context. `--show`
    /// prints a cached result without running the scan. When the
    /// workspace also caches a type-inference result, its records fill
    /// real closure contracts into the registration and chain
    /// suggestions; without one the scan is exactly what it was.
    ///
    /// # Arguments
    ///
    /// * `--binary` — Binary to scan, e.g. `eqmain.dll`. Names the
    ///   persisted file.
    /// * `--show` — Print a summary of the cached result.
    ///
    /// # Examples
    ///
    /// ```text
    /// calxgloss callback --binary eqmain.dll --show
    /// ```
    Callback {
        /// Binary to scan, e.g. `eqmain.dll`
        #[arg(long, required = true)]
        binary: String,

        /// Show the cached result instead of running the scan
        #[arg(long)]
        show: bool,
    },

    /// Detect control-flow patterns in the open binary
    ///
    /// Finds the structural patterns ChatGPT most often flattens:
    /// switch-shaped if/else-if chains, self-recursive functions,
    /// state-machine patterns (named-constant chains with transition
    /// assignments), and a per-function inventory of the branch sites —
    /// guards, loop exits, and switch arms — that Rust `if`/`match` arms
    /// should keep explicit.
    ///
    /// The control-flow findings are persisted per binary to
    /// `re/analysis/controlflow/<binary>.json` in the workspace — the same
    /// file batch translation will read as prompt context. `--show`
    /// prints a cached result without running the scan.
    ///
    /// # Arguments
    ///
    /// * `--binary` — Binary to scan, e.g. `eqmain.dll`. Names the
    ///   persisted file.
    /// * `--show` — Print a summary of the cached result.
    ///
    /// # Examples
    ///
    /// ```text
    /// calxgloss controlflow --binary eqmain.dll --show
    /// ```
    #[command(name = "controlflow")]
    ControlFlow {
        /// Binary to scan, e.g. `eqmain.dll`
        #[arg(long, required = true)]
        binary: String,

        /// Show the cached result instead of running the scan
        #[arg(long)]
        show: bool,
    },

    /// Map program strings to the functions that use them
    ///
    /// Classifies the binary's strings into their roles — error
    /// messages, file paths, resource names, debug logs, format strings
    /// — and ties each to the functions that reference it, inferring the
    /// Rust argument types format-string calls carry.
    ///
    /// The string-context findings are persisted per binary to
    /// `re/analysis/stringctx/<binary>.json` in the workspace — the same
    /// file batch translation will read as prompt context. `--show`
    /// prints a cached result without running the scan.
    ///
    /// # Arguments
    ///
    /// * `--binary` — Binary to scan, e.g. `eqmain.dll`. Names the
    ///   persisted file.
    /// * `--show` — Print a summary of the cached result.
    ///
    /// # Examples
    ///
    /// ```text
    /// calxgloss stringctx --binary eqmain.dll --show
    /// ```
    #[command(name = "stringctx")]
    StringCtx {
        /// Binary to scan, e.g. `eqmain.dll`
        #[arg(long, required = true)]
        binary: String,

        /// Show the cached result instead of running the scan
        #[arg(long)]
        show: bool,
    },

    /// Identify the libraries and APIs of a binary
    ///
    /// Reads the binary's import table and identifies the libraries it
    /// imports — DirectX 9, SDL2, Win32, POSIX, PNG, zlib, stdio, the
    /// C++ STL — mapping each identified API to the Rust crate that
    /// stands in for it, and records the APIs each function reaches
    /// through the call graph.
    ///
    /// The API findings are persisted per binary to
    /// `re/analysis/apidetect/<binary>.json` in the workspace — the same
    /// file batch translation will read as prompt context. `--show`
    /// prints a cached result without running the scan.
    ///
    /// # Arguments
    ///
    /// * `--binary` — Binary to scan, e.g. `eqmain.dll`. Names the
    ///   persisted file.
    /// * `--show` — Print a summary of the cached result.
    ///
    /// # Examples
    ///
    /// ```text
    /// calxgloss apidetect --binary eqmain.dll --show
    /// ```
    #[command(name = "apidetect")]
    ApiDetect {
        /// Binary to scan, e.g. `eqmain.dll`
        #[arg(long, required = true)]
        binary: String,

        /// Show the cached result instead of running the scan
        #[arg(long)]
        show: bool,
    },

    /// Detect endianness and serialization patterns (byte-swap calls,
    /// bit-packing chains, magic-byte comparisons) for a binary.
    ///
    /// The serialization findings are persisted per binary to
    /// `re/analysis/serialize/<binary>.json` in the workspace — the same
    /// file batch translation will read as prompt context. `--show`
    /// prints a cached result without running the scan.
    ///
    /// # Arguments
    ///
    /// * `--binary` — Binary to scan, e.g. `eqmain.dll`. Names the
    ///   persisted file.
    /// * `--show` — Print a summary of the cached result.
    ///
    /// # Examples
    ///
    /// ```text
    /// calxgloss serialize --binary eqmain.dll --show
    /// ```
    Serialize {
        /// Binary to scan, e.g. `eqmain.dll`
        #[arg(long, required = true)]
        binary: String,

        /// Show the cached result instead of running the scan
        #[arg(long)]
        show: bool,
    },

    /// Detect error-handling idioms (spelled SEH frames) for a binary
    /// by reading each decompiled body for the shapes that spell them.
    ///
    /// The detection findings are persisted per binary to
    /// `re/analysis/errhandling/<binary>.json` in the workspace. `--show`
    /// prints a cached result without running the scan.
    ///
    /// # Arguments
    ///
    /// * `--binary` — Binary to scan, e.g. `eqmain.dll`. Names the
    ///   persisted file.
    /// * `--show` — Print a summary of the cached result.
    ///
    /// # Examples
    ///
    /// ```text
    /// calxgloss errhandling --binary eqmain.dll --show
    /// ```
    Errhandling {
        /// Binary to scan, e.g. `eqmain.dll`
        #[arg(long, required = true)]
        binary: String,

        /// Show the cached result instead of running the scan
        #[arg(long)]
        show: bool,
    },

    /// Flag float/SIMD usage (which functions do float math, and what
    /// shape it takes) for a binary by reading each decompiled body for
    /// the evidence that spells it.
    ///
    /// One flag per flagged function — scalar float math, vector/matrix
    /// idioms, or both — is persisted per binary to
    /// `re/analysis/floatsimd/<binary>.json` in the workspace — the same
    /// file batch translation will read as prompt context. `--show`
    /// prints a cached result without running the scan.
    ///
    /// # Arguments
    ///
    /// * `--binary` — Binary to scan, e.g. `eqmain.dll`. Names the
    ///   persisted file.
    /// * `--show` — Print a summary of the cached result.
    ///
    /// # Examples
    ///
    /// ```text
    /// calxgloss floatsimd --binary eqmain.dll --show
    /// ```
    Floatsimd {
        /// Binary to scan, e.g. `eqmain.dll`
        #[arg(long, required = true)]
        binary: String,

        /// Show the cached result instead of running the scan
        #[arg(long)]
        show: bool,
    },

    /// Show the configuration in force and where each value came from
    ///
    /// Secrets are reported as `<set>` rather than printed, so this output is
    /// safe to paste into a bug report.
    Config,

    /// Verify a previously translated function against baseline tests
    Verify {
        /// DLL name
        #[arg(long)]
        binary: String,

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

        /// Binaries to process (default: scan the target directory for .dll and .exe files)
        #[arg(long)]
        binaries: Option<String>,

        /// Translate all exported functions (requires classification to be complete)
        #[arg(long)]
        all_functions: bool,

        /// Only classify DLLs, do not proceed to translation
        #[arg(long)]
        classify_only: bool,

        /// Skip git operations
        #[arg(long)]
        skip_git: bool,

        /// Skip call-graph extraction (faster when call-graph context is not needed)
        #[arg(long)]
        no_callgraph: bool,

        /// Custom directory for call graph cache files
        ///
        /// By default, call graphs are stored in `{workspace}/re/analysis/`. This
        /// flag overrides the default location.
        #[arg(long, value_name = "DIR")]
        callgraph_cache: Option<PathBuf>,

        /// Print call-graph statistics after building the graph
        ///
        /// Displays function count, root/middle/leaf breakdown, call-type
        /// distribution, and external API count.
        #[arg(long)]
        callgraph_verbose: bool,

        /// Force fresh engine reads, ignoring and rewriting the batch's
        /// scan read cache (`re/cache/`)
        ///
        /// The cache's manifest keys on the binary's bytes, so a hand-edited
        /// cache is not detected — use this after tampering with one.
        /// Deleting the binary's cache directory by hand does the same
        /// without a run.
        #[arg(long)]
        refresh_cache: bool,
    },

    /// Start the web review UI server
    ///
    /// Launches an HTTP server that serves the review dashboard frontend
    /// and exposes a REST API for branch acceptance, send-back, and patch
    /// requests.
    ///
    /// # Arguments
    ///
    /// * `--workspace` — Path to the workspace to review (defaults to CWD).
    /// * `--port` — TCP port to listen on (default: 3000).
    ///
    /// # Examples
    ///
    /// ```text
    /// calxgloss serve                    # Uses current directory, port 3000
    /// calxgloss serve --workspace /data/game_re  # Custom workspace
    /// calxgloss serve --port 8080        # Custom port
    /// ```
    Serve {
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
    /// * `--workspace` — Path to the workspace to translate into and review.
    /// * `--target` — Path to the target executable directory (passed to auto).
    /// * `--binaries` — Comma-separated binary names (passed to auto).
    /// * `--all-functions` — Translate all exported functions (passed to auto).
    /// * `--classify-only` — Only classify, do not translate (passed to auto).
    /// * `--skip-git` — Skip git operations (passed to auto).
    /// * `--no-callgraph` — Skip call-graph extraction (passed to auto).
    /// * `--callgraph-verbose` — Print call-graph statistics (passed to auto).
    ///
    /// # Examples
    ///
    /// ```text
    /// calxgloss live                           # Start auto + UI on port 3000
    /// calxgloss live --port 8080               # Custom port
    /// calxgloss live --binaries "eqgame,eqmain" # Pre-select binaries
    /// ```
    Live {
        /// Port to listen on (default: 3000)
        #[arg(long, short = 'p', default_value = "3000")]
        port: u16,

        /// Path to the target executable directory
        #[arg(long)]
        target: Option<PathBuf>,

        /// Binaries to process, comma-separated
        #[arg(long)]
        binaries: Option<String>,

        /// Translate all exported functions (requires classification to be complete)
        #[arg(long)]
        all_functions: bool,

        /// Only classify DLLs, do not proceed to translation
        #[arg(long)]
        classify_only: bool,

        /// Skip git operations
        #[arg(long)]
        skip_git: bool,

        /// Skip call-graph extraction (faster when call-graph context is not needed)
        #[arg(long)]
        no_callgraph: bool,

        /// Custom directory for call graph cache files
        ///
        /// By default, call graphs are stored in `{workspace}/re/analysis/`. This
        /// flag overrides the default location.
        #[arg(long, value_name = "DIR")]
        callgraph_cache: Option<PathBuf>,

        /// Print call-graph statistics after building the graph
        ///
        /// Displays function count, root/middle/leaf breakdown, call-type
        /// distribution, and external API count.
        #[arg(long)]
        callgraph_verbose: bool,

        /// Force fresh engine reads, ignoring and rewriting the batch's
        /// scan read cache (`re/cache/`)
        ///
        /// The cache's manifest keys on the binary's bytes, so a hand-edited
        /// cache is not detected — use this after tampering with one.
        /// Deleting the binary's cache directory by hand does the same
        /// without a run.
        #[arg(long)]
        refresh_cache: bool,
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
    /// * `--binary` — Process only this specific DLL. Omit to process all
    ///   `CrateReplacement` DLLs listed in the classification records.
    /// * `--skip-git` — Skip git commit of the generated artifacts.
    AutoShim {
        /// Process only this specific DLL (default: all crate-replacement DLLs)
        #[arg(long)]
        binary: Option<String>,

        /// Skip git commit of generated artifacts
        #[arg(long)]
        skip_git: bool,
    },

    /// Garbage-collect old translation branches by archiving them.
    ///
    /// Walks all unmerged `re/*` branches, checks their last commit date,
    /// and renames branches older than the staleness threshold (default 7
    /// days) to `refs/archive/re/{binary}/{function}/v{N}` instead of
    /// deleting them. Archived branches remain reachable for reference.
    ///
    /// Use `--dry-run` to preview what would be archived without making
    /// any changes.
    ///
    /// # Arguments
    ///
    /// * `--days` — Staleness threshold in days (default: 7). Branches with
    ///   a last commit older than this many days are archived.
    /// * `--dry-run` — List candidates without archiving any branches.
    Gc {
        /// Staleness threshold in days (default: 7)
        #[arg(long, default_value = "7")]
        days: u64,

        /// List candidates without archiving
        #[arg(long)]
        dry_run: bool,
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
    /// * `<target>` — Unit identifier in the format `binary/function` or `binary/function/vN`
    ///
    /// # Examples
    ///
    /// ```text
    /// calxgloss dashboard view game_logic/DrawPrimitive
    /// calxgloss dashboard view game_logic/DrawPrimitive/v3
    /// ```
    View {
        /// Unit to view: `<binary>/<function>` or `<binary>/<function>/vN`
        #[arg(value_name = "TARGET")]
        target: String,
    },

    /// Accept a unit — merge its branch into main
    ///
    /// The unit identifier is in the format `binary/function` or
    /// `binary/function/vN`.  If no version is given, the latest attempt is
    /// accepted.
    ///
    /// # Examples
    ///
    /// ```text
    /// calxgloss dashboard accept game_logic/DrawPrimitive
    /// calxgloss dashboard accept game_logic/DrawPrimitive/v3
    /// ```
    Accept {
        /// Unit to accept: `<binary>/<function>` or `<binary>/<function>/vN`
        #[arg(value_name = "TARGET")]
        target: String,
    },

    /// Reject a unit and send it back for fixes
    ///
    /// Records the rejection reason in `re/rejections/{binary}/{function}/vN.json`
    /// so the dashboard can display send-back history.
    ///
    /// # Arguments
    ///
    /// * `<target>` — Unit identifier in the format `binary/function` or `binary/function/vN`
    /// * `--reason` — Optional rejection reason (shown in the dashboard)
    ///
    /// # Examples
    ///
    /// ```text
    /// calxgloss dashboard reject game_logic/DrawPrimitive/v2 --reason "wrong shader mapping"
    /// ```
    Reject {
        /// Unit to reject: `<binary>/<function>` or `<binary>/<function>/vN`
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
    /// Already-accepted or rejected units are skipped silently.
    ///
    /// # Arguments
    ///
    /// * `--all` — Accept **all** not-yet-accepted `re/*` branches (including
    ///   `Blocked` and `SendBack` units) instead of only queued/pending.
    ///
    /// # Examples
    ///
    /// ```text
    /// calxgloss dashboard accept-all
    /// calxgloss dashboard accept-all --all
    /// ```
    AcceptAll {
        /// Accept every not-yet-accepted translation branch, including blocked and
        /// send-back units.
        #[arg(long, short)]
        all: bool,
    },
}
