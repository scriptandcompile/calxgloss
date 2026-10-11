//! The `live` command — run auto pipeline and web review UI concurrently.

use std::path::PathBuf;

use anyhow::Result;
use calxgloss::{
    PipelineControl, PipelineRunRequest, PipelineState, RunRequestSignal, StopSignal,
    TranslationEvents, UnitCancellation,
};
use calxgloss_web::{
    LogLevelControl, ServerState, SessionManager, build_router_with_ws, serve_with_listener,
};
use tracing::{debug, error, info};

use crate::Settings;
use crate::utils::*;

/// Walk the shared state machine to the run's terminal state once a run
/// returns (issue #90): success completes the run — walking a pause park
/// released by the stop signal through Stopping first — and failure fails
/// it. Refusals are only debug-logged: the machine may already sit in a
/// terminal state (the operator stopped the run through the control).
fn finish_run(control: &PipelineControl, result: &Result<()>) {
    if result.is_ok() {
        // The shutdown/restart stop signal can release a pause park — the
        // run then ends while the machine still says Paused. Walk it
        // through Stopping so it reaches Complete like any other stopped
        // run, rather than leaving the dashboard stuck on "paused".
        if control.state() == PipelineState::Paused
            && let Err(e) = control.stop()
        {
            debug!("pipeline stop transition refused: {e}");
        }
        if let Err(e) = control.complete() {
            debug!("pipeline complete transition refused: {e}");
        }
    } else if let Err(e) = control.fail() {
        debug!("pipeline fail transition refused: {e}");
    }
}

/// Handle the `live` subcommand: start both the auto pipeline and the
/// web review UI in the same process.
///
/// The pipeline runs inside a loop (issue #92, W2.3): when a run reaches a
/// terminal state the process keeps serving, and the review UI's Start and
/// Restart endpoints queue a [`PipelineRunRequest`] that wakes the loop to
/// re-run the pipeline in-process — no process restart. A `--classify-only`
/// launch runs classification with the state machine Idle and waits for the
/// Start endpoint to begin translation.
// Mirrors the CLI flag surface of `auto` plus the log controls; the flags
// arrive straight from clap, so a struct would only rename the plumbing.
#[allow(clippy::too_many_arguments)]
pub async fn handle_live(
    target: Option<PathBuf>,
    binaries: Option<String>,
    all_functions: bool,
    classify_only: bool,
    skip_git: bool,
    workspace: PathBuf,
    port: u16,
    settings: &Settings,
    no_callgraph: bool,
    callgraph_cache: Option<PathBuf>,
    callgraph_verbose: bool,
    refresh_ghidra_cache: bool,
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

    // Pipeline lifecycle control (issue #90, W2.1) — one state machine
    // shared between the pipeline (which observes it at unit boundaries)
    // and the web server (whose pause/resume/stop endpoints drive it).
    // Every successful transition emits a PipelineStateChanged event on
    // the shared channel, so WS clients see the run's state change live.
    let control = PipelineControl::new().with_events(events.clone());

    // Unit-cancellation handle (issue #91, W2.2) — the pipeline registers
    // each unit it starts, and the cancel-current endpoint cancels whatever
    // unit is in flight. The cancellation emits a UnitCancelled event on
    // the shared channel the moment it lands, so WS clients and the
    // progress state see it like any other lifecycle operation.
    let cancellation = UnitCancellation::new().with_events(events.clone());

    // Run-request channel (issue #92, W2.3) — the Start/Restart endpoints
    // store the next run's selectors here, and the run loop below waits on
    // them to re-run the pipeline inside this same process.
    let run_requests = RunRequestSignal::new();

    // Build the server state here (not inside the serve task) so the run
    // loop can also watch the server's shutdown flag and exit when the
    // operator shuts the server down.
    let server_state = ServerState::new(workspace.clone())
        .with_log_level(log_level)
        .with_log_filter(log_filter)
        .with_stop_signal(stop_signal.clone())
        .with_pipeline_control(control.clone())
        .with_unit_cancellation(cancellation.clone())
        .with_run_requests(run_requests.clone());
    let server_shutdown = server_state.shutdown_signal();
    // The loop below waits on this future across iterations — pin it so the
    // select can borrow it repeatedly.
    tokio::pin!(server_shutdown);

    let serve_progress = progress.clone();

    let serve_handle = tokio::spawn(async move {
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

    // Subscribe before queueing the launch request so the loop below never
    // misses it — and so a Start request arriving later can't be mistaken
    // for the launch request.
    let mut request_rx = run_requests.subscribe();

    // Initial launch. A non-classify-only launch drives the state machine
    // Idle → Running and queues the default run request; a classify-only
    // launch runs classification with the machine Idle and waits for the
    // Start endpoint to begin translation (issue #92).
    let mut classify_only_launch = classify_only;
    if classify_only {
        println_content("  Launch is classify-only — Start translation from the review UI.");
        println!();
    } else {
        if let Err(e) = control.start() {
            debug!("pipeline start transition refused: {e}");
        }
        run_requests.request(PipelineRunRequest::default());
    }

    // The run loop (issue #92, W2.3): each iteration runs one pipeline pass
    // and walks the machine to its terminal state; the loop then waits for
    // the next Start/Restart request, or exits when the server shuts down
    // or the stop signal is set.
    let mut auto_result: Result<()> = Ok(());
    loop {
        let run = if classify_only_launch {
            // The classify-only launch pass: classification with the machine
            // Idle, no run request involved.
            classify_only_launch = false;
            None
        } else {
            let next = tokio::select! {
                changed = request_rx.changed() => {
                    match changed {
                        Ok(()) => request_rx.borrow_and_update().clone(),
                        Err(_) => None,
                    }
                }
                _ = &mut server_shutdown => None,
            };
            match next {
                Some(run) => Some(run),
                None => break,
            }
        };

        // The transition is driven at the endpoint before the request is
        // queued, so a queued request always means the machine is already
        // Running and ready for this run.
        let is_launch_pass = run.is_none();
        if let Some(run) = &run {
            info!(
                phase = %run.phase,
                target = %run.target,
                scope = %run.scope,
                "Starting run requested from the review UI"
            );
        }

        auto_result = crate::commands::auto::handle_auto(
            target.clone(),
            binaries.clone(),
            all_functions,
            // Only the classify-only launch pass classifies; a requested
            // run translates (its phase selector drives re-classification
            // through `run` instead).
            is_launch_pass && classify_only,
            skip_git,
            settings,
            true,              // continue mode — don't stop after classification, translate all
            Some(&events),     // pass event emitter for live progress streaming
            workspace.clone(), // resolved workspace (same value used by serve task)
            no_callgraph,
            callgraph_cache.clone(),
            callgraph_verbose,
            refresh_ghidra_cache,
            Some(&stop_signal), // shutdown/restart endpoints pause at unit boundaries
            Some(&control),     // pause/resume/stop endpoints drive the run
            Some(&cancellation), // cancel-current endpoint aborts the in-flight unit
            run.as_ref(),       // W2.3 start/restart selectors for this run
        )
        .await;

        // Record the run's terminal state on the shared machine so the
        // dashboard reflects how it ended (issue #90). The classify-only
        // launch pass leaves the machine Idle for the Start endpoint.
        if !(is_launch_pass && classify_only) {
            finish_run(&control, &auto_result);
        }

        if let Err(e) = &auto_result {
            error!(error = %e, "Pipeline run failed");
        }

        // A process-level stop (the shutdown/restart endpoints) ends the
        // loop; a pipeline-control stop just ends the run, and the loop
        // waits for a Restart.
        if stop_signal.is_stopped() {
            break;
        }
    }

    // The loop is done — shut down the server gracefully.
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
