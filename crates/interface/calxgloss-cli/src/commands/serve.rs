//! The `serve` command — start the web review UI HTTP server.

use std::path::PathBuf;

use anyhow::Result;
use calxgloss_web::{ActionsState, LogLevelControl, ServerState, serve};
use tracing::info;

use crate::Settings;
use crate::utils::*;

/// Handle the `serve` subcommand: start the web review UI HTTP server.
///
/// The server's review-actions backend is wired from the resolved settings
/// (issue #327): the one `pipeline_spec` fold the commands run their passes
/// through becomes the server's pass description, and every review-UI patch
/// request assembles its retry pass from it — LLM selection, Kuna budgets,
/// retry policy and all. A server started without LLM settings still serves
/// the review surface; its patch requests fail at request time with the
/// assembly error naming what's missing.
pub async fn handle_serve(
    workspace: PathBuf,
    port: u16,
    log_level: &'static str,
    log_filter: LogLevelControl,
    settings: &Settings,
) -> Result<()> {
    info!(repo = ?workspace, port, "Starting web review UI server");

    if !workspace.exists() {
        anyhow::bail!(
            "Repository path does not exist: {}\n\nMake sure the path points to the \
             resultant (git) workspace that contains the translation work.",
            workspace.display()
        );
    }

    // Fold the resolved settings once (issue #327): the review-actions
    // backend carries the same description the CLI commands run their passes
    // through (`pipeline_spec`, issue #324), so a review-UI patch retry
    // honors the settings the user configured. A fold failure — an
    // unparseable retry-strategy name — stops startup like it stops the
    // commands; a missing LLM pair is deliberately left unset on the
    // description: the server still serves the review surface, and a patch
    // request meets the seam's assembly error at request time.
    let pass_spec = crate::settings::pipeline_spec(settings)?;
    if pass_spec.llm.is_none() {
        info!(
            "no LLM endpoint configured: review-UI patch requests will fail \
             until llm.url/llm.model are set (flag, config file, or env)"
        );
    }
    let target_dir = settings
        .target_dir
        .as_ref()
        .map(|t| PathBuf::from(&t.value));
    let actions = ActionsState::new(workspace.clone(), pass_spec);
    let actions = match target_dir {
        Some(dir) => actions.with_target_dir(dir),
        None => actions,
    };

    // Print startup banner before moving workspace into ServerState
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
        bold(&workspace.display().to_string())
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

    let server_state = ServerState::new(workspace)
        .with_log_level(log_level)
        .with_log_filter(log_filter);
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
    println_content("    GET  /api/server/status Server status (uptime, memory, CPU, connections)");
    println_content("    POST /api/server/shutdown Graceful shutdown (pause pipeline, save, exit)");
    println_content("    POST /api/server/restart  Stop process — restart the command manually");
    println_content("    PATCH /api/server/log-level Change log verbosity (this process only)");
    println_content("    GET  /health            Health probe (workspace, uptime, version)");
    println!();
    hsep_bold();
    println!();

    // Start the axum server with the settings-backed actions backend wired
    // into the router (issue #327) — the review UI's patch button drives a
    // real assembled pass, not a canned response.
    serve(server_state, actions, port, None).await?;

    Ok(())
}
