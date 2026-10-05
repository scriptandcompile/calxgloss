//! The `serve` command — start the web review UI HTTP server.

use std::path::PathBuf;

use anyhow::Result;
use calxgloss_web::{ServerState, serve};
use tracing::info;

use crate::utils::*;

/// Handle the `serve` subcommand: start the web review UI HTTP server.
pub async fn handle_serve(repo_dir: PathBuf, port: u16) -> Result<()> {
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

    let server_state = ServerState::new(repo_dir);
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
    serve(server_state, port, None).await?;

    Ok(())
}
