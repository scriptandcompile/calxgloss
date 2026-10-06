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
//! - `auto-shim` — Generate shim layers for crate-replacement DLLs
//! - `translate` — Translate a single function from disassembly to Rust
//! - `batch-translate` — Translate multiple functions from a single DLL
//! - `typesdb` — Recover the type database (named types, vtables, inferred structs) for the binary open in Ghidra
//! - `typeinfer` — Infer parameter types (this pointers, sizes, known signatures) for the binary open in Ghidra
//! - `algorithm` — Recognize algorithms (control flow shapes, string markers, callback contracts) in the binary open in Ghidra
//! - `memory` — Detect memory lifecycles (allocation/release pairs, handle lifetimes, reference counting) for the open binary and cache the result
//! - `verify` — Verify a previously translated function
//! - `config` — Show the configuration in force and where each value came from
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
use calxgloss_config::{FileConfig, GhidraSection, Layers, LlmSection, load};
use clap::Parser;
use tracing::{debug, error, info};

use cli_types::{Cli, Command, DashboardSubcommand};
use settings::Settings;
use utils::*;

// Re-export handler functions for match arm access
use commands::algorithm::handle_algorithm;
use commands::auto::handle_auto;
use commands::auto_shim::handle_auto_shim;
use commands::batch_translate::handle_batch_translate;
use commands::classify::handle_classify;
use commands::dashboard::{
    handle_dashboard, handle_dashboard_accept, handle_dashboard_accept_all,
    handle_dashboard_reject, handle_dashboard_view,
};
use commands::gc::handle_gc;
use commands::init::handle_init;
use commands::live::handle_live;
use commands::memory::handle_memory;
use commands::serve::handle_serve;
use commands::translate::handle_translate;
use commands::typeinfer::handle_typeinfer;
use commands::typesdb::handle_typesdb;
use commands::verify::handle_verify;

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
        workspace: cli
            .workspace
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
    // `config`, `gc`, `typesdb`, `typeinfer`, `algorithm`, and `memory`
    // don't need it — the analysis commands read the program open in
    // Ghidra and write to the workspace — so we check here and fail fast
    // with a helpful message.
    if let Some(ref target) = cli.command {
        match target {
            Command::Config
            | Command::Gc { .. }
            | Command::Typesdb { .. }
            | Command::Typeinfer { .. }
            | Command::Algorithm { .. }
            | Command::Memory { .. } => {}
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
        no_callgraph: false,
        callgraph_cache: None,
        callgraph_verbose: false,
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
                    &dll, target_dir, &workspace, skip_git, &settings, None,
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
        Command::Typesdb { dll, show, no_tag } => {
            let workspace = resolve_workspace(cli.workspace.as_ref(), &settings);
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("Failed to create tokio runtime")?
                .block_on(handle_typesdb(&dll, &workspace, show, no_tag, &settings))
        }
        Command::Typeinfer { dll, show } => {
            let workspace = resolve_workspace(cli.workspace.as_ref(), &settings);
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("Failed to create tokio runtime")?
                .block_on(handle_typeinfer(&dll, &workspace, show, &settings))
        }
        Command::Algorithm { dll, show } => {
            let workspace = resolve_workspace(cli.workspace.as_ref(), &settings);
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("Failed to create tokio runtime")?
                .block_on(handle_algorithm(&dll, &workspace, show, &settings))
        }
        Command::Memory { dll, show } => {
            let workspace = resolve_workspace(cli.workspace.as_ref(), &settings);
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("Failed to create tokio runtime")?
                .block_on(handle_memory(&dll, &workspace, show, &settings))
        }
        Command::Verify {
            dll,
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
                    &dll,
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
            dlls,
            all_functions,
            classify_only,
            skip_git,
            no_callgraph,
            callgraph_cache,
            callgraph_verbose,
        } => {
            let workspace = resolve_workspace(cli.workspace.as_ref(), &settings);
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
                    workspace,
                    no_callgraph,
                    callgraph_cache,
                    callgraph_verbose,
                ))
        }
        Command::AutoShim { dll, skip_git } => {
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
                    dll.as_deref(),
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
                .block_on(handle_serve(workspace, port))
        }
        Command::Live {
            target,
            dlls,
            all_functions,
            classify_only,
            skip_git,
            port,
            no_callgraph,
            callgraph_cache,
            callgraph_verbose,
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
                    dlls,
                    all_functions,
                    classify_only,
                    skip_git,
                    workspace,
                    port,
                    &settings,
                    no_callgraph,
                    callgraph_cache,
                    callgraph_verbose,
                ))
        }
    };

    if let Err(ref e) = result {
        error!("Error: {}", e);
    }

    result
}
