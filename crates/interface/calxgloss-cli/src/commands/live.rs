//! The `live` command — run auto pipeline and web review UI concurrently.

use std::path::PathBuf;

use anyhow::Result;
use calxgloss::{StopSignal, TranslationEvents};
use calxgloss_web::{
    LogLevelControl, ServerState, SessionManager, build_router_with_ws, serve_with_listener,
};
use tracing::{debug, error, info};

use crate::Settings;
use crate::utils::*;

/// Handle the `live` subcommand: start both the auto pipeline and the
/// web review UI in the same process.
#[allow(clippy::too_many_arguments)]
pub async fn handle_live(
    target: Option<PathBuf>,
    dlls: Option<String>,
    all_functions: bool,
    classify_only: bool,
    skip_git: bool,
    workspace: PathBuf,
    port: u16,
    settings: &Settings,
    no_callgraph: bool,
    callgraph_cache: Option<PathBuf>,
    callgraph_verbose: bool,
    log_level: &'static str,
    log_filter: LogLevelControl,
) -> Result<()> {
    info!(
        port,
        repo = ?workspace,
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

    // Shared stop signal — the shutdown/restart endpoints flip it, and the
    // pipeline observes it at unit boundaries.
    let stop_signal = StopSignal::new();

    let serve_workspace = workspace.clone();
    let serve_progress = progress.clone();
    let serve_stop = stop_signal.clone();

    let serve_handle = tokio::spawn(async move {
        let workspace = serve_workspace;

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

        let server_state = ServerState::new(workspace)
            .with_log_level(log_level)
            .with_log_filter(log_filter)
            .with_stop_signal(serve_stop);

        // Build the router with WebSocket support so the frontend can stream
        // progress events over the upgrade endpoint.
        let event_rx = events_clone.subscribe();
        let manager = SessionManager::new_with_broadcast(event_rx);
        let router = build_router_with_ws(server_state.clone(), manager, serve_progress);
        // Watch the state's shutdown flag so `POST /api/server/shutdown`
        // (and `/restart`) stops the accept loop gracefully.
        let shutdown = server_state.shutdown_signal();
        let _ = serve_with_listener(listener, router, shutdown)
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
    let auto_result = crate::commands::auto::handle_auto(
        target,
        dlls,
        all_functions,
        classify_only,
        skip_git,
        settings,
        true,          // continue mode — don't stop after classification, translate all
        Some(&events), // pass event emitter for live progress streaming
        workspace,     // resolved workspace (same value used by serve task)
        no_callgraph,
        callgraph_cache,
        callgraph_verbose,
        Some(&stop_signal), // shutdown/restart endpoints pause at unit boundaries
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
            if stop_signal.is_stopped() {
                println_content("  Stopped gracefully — current unit completed and saved.");
                println_content("  Restart with the same command to continue the run.");
            } else {
                println_content("  Auto pipeline finished.");
                println_content("  Review UI stopped.");
            }
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
