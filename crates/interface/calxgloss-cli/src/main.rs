//! Calxgloss CLI — Reverse Engineering Harness
//!
//! A command-line interface for the Calxgloss reverse engineering system.
//! Wires together in-process Kuna analysis, LLM-assisted translation, test
//! generation, verification, and Git automation into a unified workflow.
//!
//! # Commands
//!
//! - `init` — Create a `calxgloss.toml` configuration file
//! - `classify` — Classify DLLs for a target executable
//! - `auto-shim` — Generate shim layers for crate-replacement DLLs
//! - `translate` — Translate a single function from disassembly to Rust
//! - `batch-translate` — Translate multiple functions from a single DLL
//! - `typesdb` — Recover the type database (named types, vtables, inferred structs) for a binary
//! - `typeinfer` — Infer parameter types (this pointers, sizes, known signatures) for a binary
//! - `algorithm` — Recognize algorithms (control flow shapes, string markers, callback contracts) in a binary
//! - `memory` — Detect memory lifecycles (allocation/release pairs, handle lifetimes, reference counting) for the open binary and cache the result
//! - `sync` — Detect concurrency constructs (mutex pairings, atomic operations, thread spawns) for the open binary and cache the result
//! - `globalstate` — Record the global-state reference sets (which functions read and write which program globals) for the open binary and cache the result
//! - `stringctx` — Map program strings to functions (classification, format-string types) for the open binary and cache the result
//! - `apidetect` — Identify the libraries and APIs of the open binary (import table, per-function API summaries) and cache the result
//! - `verify` — Verify a previously translated function
//! - `config` — Show the configuration in force and where each value came from
//! - `doctor` — Report the analysis engine by loading a target in-process
//! - `dashboard` — Show a structured terminal review dashboard
//! - `gc` — Garbage-collect old translation branches (archive to refs/archive/)
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

mod cli_types;
mod commands;
mod settings;
mod utils;

use std::path::PathBuf;

use anyhow::{Context, Result};
use calxgloss_config::{AnalysisSection, FileConfig, Layers, LlmSection, load};
use calxgloss_web::LogLevelControl;
use clap::Parser;
use tracing::{debug, error, info};

use cli_types::{Cli, Command, DashboardSubcommand};
use settings::Settings;
use utils::*;

// Re-export handler functions for match arm access
use commands::algorithm::handle_algorithm;
use commands::apidetect::handle_apidetect;
use commands::auto::handle_auto;
use commands::auto_shim::handle_auto_shim;
use commands::batch_translate::handle_batch_translate;
use commands::callback::handle_callback;
use commands::classify::handle_classify;
use commands::consts::handle_consts;
use commands::controlflow::handle_controlflow;
use commands::dashboard::{
    handle_dashboard, handle_dashboard_accept, handle_dashboard_accept_all,
    handle_dashboard_reject, handle_dashboard_view,
};
use commands::doctor::handle_doctor;
use commands::gc::handle_gc;
use commands::globalstate::handle_global_state;
use commands::init::handle_init;
use commands::libmatch::handle_libmatch;
use commands::live::handle_live;
use commands::memory::handle_memory;
use commands::serialize::handle_serialize;
use commands::serve::handle_serve;
use commands::stringctx::handle_stringctx;
use commands::sync::handle_sync;
use commands::translate::handle_translate;
use commands::typeinfer::handle_typeinfer;
use commands::typesdb::handle_typesdb;
use commands::verify::handle_verify;

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging — the returned handle controls the reloadable
    // EnvFilter, shared into server state for `PATCH /api/server/log-level`.
    let log_filter = LogLevelControl::new(init_logging(cli.verbose, &cli.log_format));

    // Effective tracing level, shared with serve/live so the server status
    // endpoint reports what logging init actually installed.
    let log_level = log_level_for_verbosity(cli.verbose);

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
        workspace: cli
            .workspace
            .as_ref()
            .map(|p| p.to_string_lossy().to_string()),
        llm: LlmSection {
            url: cli.llm_url.clone(),
            model: cli.llm_model.clone(),
            api_key: cli.llm_api_key.clone(),
            context_window: cli.context_window,
            temperature: cli.temperature,
            max_retries: cli.max_retries,
            strategy: cli.strategy.clone(),
        },
        analysis: AnalysisSection {
            // No flags for the budgets: they belong in the config file
            // (issue #211), not on every command line.
            max_fn_instructions: None,
            max_fn_seconds: None,
            max_fn_memory_mib: None,
        },
    };
    let settings = Settings::resolve(&layers, flags, &loaded);

    // target_dir is required for all commands that do real work: the Kuna
    // engine loads `target_dir/<binary>` in-process, so even the analysis
    // scans (`typesdb`, `typeinfer`, `algorithm`, `memory`, `sync`,
    // `globalstate`, `consts`, `callback`, `controlflow`, `stringctx`,
    // `apidetect`, `serialize`) need it. `config`, `doctor`, and `gc`
    // don't — doctor takes its target as `--binary` directly — so we
    // check here and fail fast with a helpful message.
    if let Some(ref target) = cli.command {
        match target {
            Command::Config | Command::Doctor { .. } | Command::Gc { .. } => {}
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
        binaries: None,
        all_functions: false,
        classify_only: false,
        skip_git: false,
        no_callgraph: false,
        callgraph_cache: None,
        callgraph_verbose: false,
        refresh_cache: false,
    });
    let result = match command {
        Command::Config => {
            print!("{}", settings::render(&settings));
            Ok(())
        }
        Command::Doctor(args) => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("Failed to create tokio runtime")?
            .block_on(handle_doctor(&settings, &args)),
        Command::Classify { binary } => {
            let target_dir = settings
                .target_dir
                .as_ref()
                .map(|t| PathBuf::from(&t.value))
                .unwrap_or_else(|| {
                    std::env::current_dir().expect("Failed to read current directory")
                });
            let target_dir = target_dir.as_ref();
            let workspace = resolve_workspace(cli.workspace.as_ref(), &settings);
            let skip_git = false;
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("Failed to create tokio runtime")?
                .block_on(handle_classify(
                    &binary, target_dir, &workspace, skip_git, &settings, None, None,
                ))
        }
        Command::Translate(args) => {
            let workspace = resolve_workspace(cli.workspace.as_ref(), &settings);
            let callgraph_cache = args.callgraph_cache.clone();
            let callgraph_verbose = args.callgraph_verbose;
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("Failed to create tokio runtime")?
                .block_on(handle_translate(
                    &args,
                    &settings,
                    workspace,
                    callgraph_cache,
                    callgraph_verbose,
                ))
        }
        Command::BatchTranslate(args) => {
            let workspace = resolve_workspace(cli.workspace.as_ref(), &settings);
            let callgraph_cache = args.callgraph_cache.clone();
            let callgraph_verbose = args.callgraph_verbose;
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("Failed to create tokio runtime")?
                .block_on(handle_batch_translate(
                    &args,
                    &settings,
                    workspace,
                    callgraph_cache,
                    callgraph_verbose,
                ))
        }
        Command::Typesdb {
            binary,
            show,
            no_tag,
        } => {
            let workspace = resolve_workspace(cli.workspace.as_ref(), &settings);
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("Failed to create tokio runtime")?
                .block_on(handle_typesdb(&binary, &workspace, show, no_tag, &settings))
        }
        Command::Typeinfer {
            binary,
            show,
            write_back,
            confidence_floor,
        } => {
            let workspace = resolve_workspace(cli.workspace.as_ref(), &settings);
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("Failed to create tokio runtime")?
                .block_on(handle_typeinfer(
                    &binary,
                    &workspace,
                    show,
                    write_back,
                    confidence_floor,
                    &settings,
                ))
        }
        Command::Algorithm {
            binary,
            show,
            patterns,
        } => {
            let workspace = resolve_workspace(cli.workspace.as_ref(), &settings);
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("Failed to create tokio runtime")?
                .block_on(handle_algorithm(
                    &binary,
                    &workspace,
                    show,
                    patterns.as_deref(),
                    &settings,
                ))
        }
        Command::Memory { binary, show } => {
            let workspace = resolve_workspace(cli.workspace.as_ref(), &settings);
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("Failed to create tokio runtime")?
                .block_on(handle_memory(&binary, &workspace, show, &settings))
        }
        Command::Libmatch { binary, show } => {
            let workspace = resolve_workspace(cli.workspace.as_ref(), &settings);
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("Failed to create tokio runtime")?
                .block_on(handle_libmatch(&binary, &workspace, show, &settings))
        }
        Command::Sync { binary, show } => {
            let workspace = resolve_workspace(cli.workspace.as_ref(), &settings);
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("Failed to create tokio runtime")?
                .block_on(handle_sync(&binary, &workspace, show, &settings))
        }
        Command::GlobalState { binary, show } => {
            let workspace = resolve_workspace(cli.workspace.as_ref(), &settings);
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("Failed to create tokio runtime")?
                .block_on(handle_global_state(&binary, &workspace, show, &settings))
        }
        Command::Consts { binary, show } => {
            let workspace = resolve_workspace(cli.workspace.as_ref(), &settings);
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("Failed to create tokio runtime")?
                .block_on(handle_consts(&binary, &workspace, show, &settings))
        }
        Command::Callback { binary, show } => {
            let workspace = resolve_workspace(cli.workspace.as_ref(), &settings);
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("Failed to create tokio runtime")?
                .block_on(handle_callback(&binary, &workspace, show, &settings))
        }
        Command::ControlFlow { binary, show } => {
            let workspace = resolve_workspace(cli.workspace.as_ref(), &settings);
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("Failed to create tokio runtime")?
                .block_on(handle_controlflow(&binary, &workspace, show, &settings))
        }
        Command::StringCtx { binary, show } => {
            let workspace = resolve_workspace(cli.workspace.as_ref(), &settings);
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("Failed to create tokio runtime")?
                .block_on(handle_stringctx(&binary, &workspace, show, &settings))
        }
        Command::ApiDetect { binary, show } => {
            let workspace = resolve_workspace(cli.workspace.as_ref(), &settings);
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("Failed to create tokio runtime")?
                .block_on(handle_apidetect(&binary, &workspace, show, &settings))
        }
        Command::Serialize { binary, show } => {
            let workspace = resolve_workspace(cli.workspace.as_ref(), &settings);
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("Failed to create tokio runtime")?
                .block_on(handle_serialize(&binary, &workspace, show, &settings))
        }
        Command::Verify {
            binary,
            function,
            rust_source,
            baseline_path,
        } => {
            let workspace = resolve_workspace(cli.workspace.as_ref(), &settings);
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("Failed to create tokio runtime")?
                .block_on(handle_verify(
                    &binary,
                    &function,
                    &rust_source,
                    baseline_path.as_deref(),
                    &workspace,
                ))
        }
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
            binaries,
            all_functions,
            classify_only,
            skip_git,
            no_callgraph,
            callgraph_cache,
            callgraph_verbose,
            refresh_cache,
        } => {
            let workspace = resolve_workspace(cli.workspace.as_ref(), &settings);
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("Failed to create tokio runtime")?
                .block_on(handle_auto(
                    target,
                    binaries,
                    all_functions,
                    classify_only,
                    skip_git,
                    &settings,
                    false, // interactive mode — prompt user, stop after classification
                    None,  // no event emitter in interactive mode
                    workspace,
                    no_callgraph,
                    callgraph_cache,
                    callgraph_verbose,
                    refresh_cache,
                    None, // no stop signal — plain auto runs to completion
                    None, // no pipeline control — plain auto has no web server
                    None, // no unit cancellation — plain auto has no web server
                    None, // no run selectors — plain auto has no start/restart channel
                    None, // no scope control — plain auto has no scope endpoints
                    None, // no override control — plain auto has no override endpoints
                    None, // no classification overrides — plain auto has no classification endpoints
                ))
        }
        Command::AutoShim { binary, skip_git } => {
            let target_dir = settings
                .target_dir
                .as_ref()
                .map(|t| PathBuf::from(&t.value))
                .unwrap_or_else(|| {
                    std::env::current_dir().expect("Failed to read current directory")
                });
            let workspace = resolve_workspace(cli.workspace.as_ref(), &settings);
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("Failed to create tokio runtime")?
                .block_on(handle_auto_shim(
                    binary.as_deref(),
                    skip_git,
                    &target_dir,
                    &workspace,
                    &settings,
                ))
        }
        Command::Gc { days, dry_run } => handle_gc(days, dry_run),
        Command::Serve { port } => {
            // serve always uses CWD as the workspace — config / env overrides
            // are ignored because the workspace (where .git, src/, scratch/
            // live) is always where the user runs the command from.
            let workspace = resolve_live_workspace(cli.workspace.as_ref());
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("Failed to create tokio runtime")?
                .block_on(handle_serve(workspace, port, log_level, log_filter))
        }
        Command::Live {
            target,
            binaries,
            all_functions,
            classify_only,
            skip_git,
            port,
            no_callgraph,
            callgraph_cache,
            callgraph_verbose,
            refresh_cache,
        } => {
            // live always uses CWD as the workspace — config / env overrides
            // are ignored because the workspace (where .git, src/, scratch/
            // live) is always where the user runs the command from.
            let workspace = resolve_live_workspace(cli.workspace.as_ref());
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("Failed to create tokio runtime")?
                .block_on(handle_live(
                    target,
                    binaries,
                    all_functions,
                    classify_only,
                    skip_git,
                    workspace,
                    port,
                    &settings,
                    no_callgraph,
                    callgraph_cache,
                    callgraph_verbose,
                    refresh_cache,
                    log_level,
                    log_filter,
                ))
        }
    };

    if let Err(ref e) = result {
        error!("Error: {}", e);
    }

    result
}
