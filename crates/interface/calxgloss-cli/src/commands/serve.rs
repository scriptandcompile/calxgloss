//! The `serve` command — start the web review UI HTTP server.

use std::path::PathBuf;

use anyhow::Result;
use calxgloss_web::{LogLevelControl, ServerState, serve};
use tracing::info;

use crate::utils::*;

/// Handle the `serve` subcommand: start the web review UI HTTP server.
pub async fn handle_serve(
    workspace: PathBuf,
    port: u16,
    log_level: &'static str,
    log_filter: LogLevelControl,
) -> Result<()> {
    info!(repo = ?workspace, port, "Starting web review UI server");

    if !workspace.exists() {
        anyhow::bail!(
            "Repository path does not exist: {}\n\nMake sure the path points to the \
             resultant (git) workspace that contains the translation work.",
            workspace.display()
        );
    }

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

    // Start the axum server
    serve(server_state, port, None).await?;

    Ok(())
}
