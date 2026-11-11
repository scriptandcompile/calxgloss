//! Scenario tests split from `tests/e2e.rs`.
//!
//! Every world here boots through `support::ReviewWorld` (issue #472):
//! `boot_ws_wired()` attaches the same live control handles
//! `calxgloss live` wires — pipeline machine, unit cancellation, run-request
//! channel, scope and the two override handles — while the bare `boot()` and
//! `boot_plain()` worlds attach none — the shape the honest-503 pins
//! serve from. No test in the file sleeps. After the world emits an
//! event, the test waits until the served live view applies it; after a
//! start endpoint, it watches the run-request channel; and a websocket
//! test takes its socket from `ReviewWorld::websocket`, which returns
//! only once the session manager has registered the session.

use super::*;

use super::support::*;
use calxgloss_types::{
    DllCategory, PipelineRunRequest, PipelineState, ProgressEvent, RunPhase, RunScope, RunTarget,
};
use std::time::Duration;

/// Read `/api/pipeline` and collect the served binary row names in order.
async fn row_names(client: &support::Client) -> Vec<String> {
    let (status, body) = client.get_json("/api/pipeline").await;
    assert_eq!(status, 200);
    body["binaries"]
        .as_array()
        .expect("binaries is an array")
        .iter()
        .map(|b| b["binary"].as_str().unwrap_or_default().to_string())
        .collect()
}

// ─────────────────────────────────────────────────────────────
// API-level tests (no browser needed)
// ─────────────────────────────────────────────────────────────

/// Verify that the health endpoint returns `{"status":"ok"}`.
#[tokio::test]
async fn test_health_endpoint() {
    let world = support::ReviewWorld::boot_plain().await;

    let (status, body) = world.client().get_json("/health").await;

    assert_eq!(status, 200);
    assert_eq!(body["status"], "ok");
    assert_eq!(body["repo_accessible"], true);
    // Enhanced health (issue #59): uptime and version, same single endpoint.
    assert!(
        body["uptime_secs"].as_u64().is_some(),
        "health must report uptime_secs"
    );
    assert_eq!(body["version"], env!("CARGO_PKG_VERSION"));
}

/// The enhanced `/health` is registered in **all** routers — assert the
/// live (WebSocket) router answers it with the same JSON contract.
#[tokio::test]
async fn test_health_endpoint_live_router() {
    let world = support::ReviewWorld::boot().await;

    let (status, body) = world.client().get_json("/health").await;

    assert_eq!(status, 200);
    assert_eq!(body["status"], "ok");
    assert_eq!(body["repo_accessible"], true);
    assert!(body["uptime_secs"].as_u64().is_some());
    assert_eq!(body["version"], env!("CARGO_PKG_VERSION"));
}

// ─────────────────────────────────────────────────────────────
// Server status endpoint tests (issue #59)
// ─────────────────────────────────────────────────────────────

/// `GET /api/server/status` on the plain serve router: every documented
/// field is present, and with no live state attached the pipeline status
/// is honestly "unavailable" with zero WebSocket connections.
#[tokio::test]
async fn test_server_status_plain_router() {
    let world = support::ReviewWorld::boot_plain_with_log_level("debug").await;

    let (status, body) = world.client().get_json("/api/server/status").await;

    assert_eq!(status, 200);

    assert_eq!(body["pipeline_status"], "unavailable");
    assert_eq!(body["ws_connections"], 0);
    assert_eq!(body["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(body["log_level"], "debug");
    assert!(
        body["host"].as_str().is_some_and(|h| !h.is_empty()),
        "host must be a non-empty string"
    );
    assert!(body["uptime_secs"].as_u64().is_some());
    assert!(
        body["memory_mb"].as_f64().unwrap_or(0.0) > 0.0,
        "memory_mb should be positive for the running server"
    );
    assert!(body["cpu_percent"].as_f64().unwrap_or(-1.0) >= 0.0);
    assert!(
        body["open_file_handles"].as_u64().unwrap_or(0) > 0,
        "the server process always has open file handles"
    );
}

/// `GET /api/server/status` on the live router: a fed `TranslationStarted`
/// event flips the pipeline status to "running", and a registered WebSocket
/// session is reflected in the connection count.
#[tokio::test]
async fn test_server_status_live_router() {
    let world = support::ReviewWorld::boot().await;

    // A live WebSocket session and an in-flight unit.
    let _ws = world.websocket().await;
    let started = ProgressEvent::TranslationStarted {
        binary: "game_logic.dll".into(),
        function: "DrawPrimitive".into(),
    };
    world.emitter().emit(started.clone());
    world
        .wait_until_unit_applied(&started, "game_logic.dll", "DrawPrimitive", |_| true)
        .await;

    let (status, body) = world.client().get_json("/api/server/status").await;

    assert_eq!(status, 200);

    assert_eq!(body["pipeline_status"], "running");
    assert_eq!(
        body["ws_connections"].as_u64(),
        Some(1),
        "the live session must be counted"
    );
    assert_eq!(body["version"], env!("CARGO_PKG_VERSION"));
}

/// With a live pipeline attached but nothing in flight, the status endpoint
/// reports "idle" — distinct from plain serve's "unavailable".
#[tokio::test]
async fn test_server_status_live_router_idle() {
    let world = support::ReviewWorld::boot().await;

    let (status, body) = world.client().get_json("/api/server/status").await;

    assert_eq!(status, 200);
    assert_eq!(body["pipeline_status"], "idle");
    assert_eq!(body["ws_connections"], 0);
}

/// The live router's pause/resume/stop endpoints drive the shared
/// PipelineControl (issue #90): 200 with the transition in the body, and
/// 409 when the state machine refuses the operation. `/api/server/status`
/// reports the machine's state — "paused" even while a unit record is
/// still in flight, which an in-flight-count guess could not tell apart.
#[tokio::test]
async fn test_pipeline_lifecycle_control_endpoints() {
    let world = support::ReviewWorld::boot_ws_wired().await;
    let control = world.pipeline_control();
    control.start().expect("idle -> running");

    // A unit in flight — the point is that the reported status now follows
    // the state machine, not the in-flight count.
    let started = ProgressEvent::TranslationStarted {
        binary: "game_logic.dll".into(),
        function: "DrawPrimitive".into(),
    };
    world.emitter().emit(started.clone());
    world
        .wait_until_unit_applied(&started, "game_logic.dll", "DrawPrimitive", |_| true)
        .await;

    let get_status = || async {
        let (status, body) = world.client().get_json("/api/server/status").await;
        assert_eq!(status, 200);
        body["pipeline_status"]
            .as_str()
            .unwrap_or_default()
            .to_string()
    };
    assert_eq!(get_status().await, "running");

    // Pause: 200, body reports the transition.
    let (status, body) = world.client().post_lifecycle("/api/pipeline/pause").await;
    assert_eq!(status, 200);
    assert_eq!(body["previous"], "running");
    assert_eq!(body["state"], "paused");

    // Status follows the machine even with the unit record still in flight.
    assert_eq!(get_status().await, "paused");

    // Double pause: the machine refuses — 409, not a silent no-op.
    let (status, body) = world.client().post_lifecycle("/api/pipeline/pause").await;
    assert_eq!(status, 409);
    assert!(
        body["message"]
            .as_str()
            .unwrap_or_default()
            .contains("cannot pause a pipeline that is paused"),
        "409 carries the machine's own message, got: {body}"
    );

    // Resume: back to running.
    let (status, body) = world.client().post_lifecycle("/api/pipeline/resume").await;
    assert_eq!(status, 200);
    assert_eq!(body["previous"], "paused");
    assert_eq!(body["state"], "running");
    assert_eq!(get_status().await, "running");

    // Stop: running -> stopping; resume from stopping is refused.
    let (status, body) = world.client().post_lifecycle("/api/pipeline/stop").await;
    assert_eq!(status, 200);
    assert_eq!(body["state"], "stopping");
    assert_eq!(get_status().await, "stopping");
    let (status, _) = world.client().post_lifecycle("/api/pipeline/resume").await;
    assert_eq!(status, 409, "a stopping pipeline cannot resume");
}

/// Every lifecycle transition reaches WS clients as a raw
/// `pipeline_state_changed` event on the shared broadcast (issue #90) —
/// the dashboard reconciles its buttons from the pushed event, not from a
/// refetch.
#[tokio::test]
async fn test_pipeline_state_changes_reach_ws_clients() {
    use futures_util::StreamExt;
    use tokio_tungstenite::tungstenite::Message;

    let world = support::ReviewWorld::boot_ws_wired().await;
    let control = world.pipeline_control();
    control.start().expect("idle -> running");

    // Connect after the idle→running push so the socket sees only the
    // transitions the endpoints drive.
    let mut ws = world.websocket().await;

    for path in ["/api/pipeline/pause", "/api/pipeline/resume"] {
        let (status, _) = world.client().post_lifecycle(path).await;
        assert_eq!(status, 200, "{path} should succeed");
    }

    // Collect wire messages and pull out the lifecycle events with their
    // previous/state payloads.
    let mut transitions: Vec<(String, String)> = Vec::new();
    for _ in 0..20 {
        if transitions.len() >= 2 {
            break;
        }
        let msg = match tokio::time::timeout(Duration::from_millis(500), ws.raw_mut().next()).await
        {
            Ok(Some(Ok(m))) => m,
            _ => continue,
        };
        if let Message::Text(text) = msg {
            let v: serde_json::Value =
                serde_json::from_str(text.as_str()).expect("wire message is JSON");
            if v["event"].as_str() == Some("pipeline_state_changed") {
                transitions.push((
                    v["previous"].as_str().unwrap_or_default().to_string(),
                    v["state"].as_str().unwrap_or_default().to_string(),
                ));
            }
        }
    }
    assert_eq!(
        transitions,
        vec![
            ("running".to_string(), "paused".to_string()),
            ("paused".to_string(), "running".to_string()),
        ],
        "WS clients should see each lifecycle transition in order"
    );
}

/// A live router built **without** a control attached (the pre-W2.1 wiring)
/// answers the lifecycle endpoints honestly with 503 rather than pretending
/// to control a pipeline it does not hold.
#[tokio::test]
async fn test_pipeline_lifecycle_endpoints_503_without_control() {
    let world = support::ReviewWorld::boot().await;

    for path in [
        "/api/pipeline/pause",
        "/api/pipeline/resume",
        "/api/pipeline/stop",
        // Issue #91: cancel-current is honest the same way — no control
        // attached means no pipeline whose unit could be cancelled.
        "/api/pipeline/cancel-current",
    ] {
        let (status, body) = world.client().post_lifecycle(path).await;
        assert_eq!(status, 503, "{path} without a control should be 503");
        assert!(
            body["message"]
                .as_str()
                .unwrap_or_default()
                .contains("no live pipeline control"),
            "503 explains why, got: {body}"
        );
    }

    // Issue #92: start/restart are honest the same way — with no run-request
    // channel attached there is no live loop a request could wake. Restart
    // carries a JSON body, so it is posted separately from the bodyless ones.
    for (path, body) in [
        ("/api/pipeline/start", None),
        ("/api/pipeline/restart", Some(serde_json::json!({}))),
    ] {
        let (status, body) = match body {
            None => world.client().post_lifecycle(path).await,
            Some(body) => world.client().post_json(path, body).await,
        };
        assert_eq!(status, 503, "{path} without a control should be 503");
        assert!(
            body["message"]
                .as_str()
                .unwrap_or_default()
                .contains("no live pipeline control"),
            "503 explains why, got: {body}"
        );
    }
}

// ─────────────────────────────────────────────────────────────
// Per-binary pause (issue #221, X6)
// ─────────────────────────────────────────────────────────────

/// The per-binary pause/resume endpoints (issue #221) drive the shared
/// scope handle: 200 with the binary and the paused flag in the body, 409
/// with the server's own reason for a binary the workspace has not
/// discovered, and `GET /api/pipeline` reporting the row's `paused` flag
/// from the handle — a plain GET is honest without waiting for an event.
#[tokio::test]
async fn test_pipeline_binary_pause_resume_endpoints() {
    let world = support::ReviewWorld::boot_ws_wired().await;

    // The run's queue plan discovers game_logic.dll — the row exists before
    // anything has started working on it.
    let planned = ProgressEvent::QueuePlanned {
        binaries: vec!["game_logic.dll".to_string()],
    };
    world.emitter().emit(planned.clone());
    world
        .wait_until_applied(&planned, |view| row_has(view, "game_logic.dll"))
        .await;

    let get_row_paused = || async {
        let (status, body) = world.client().get_json("/api/pipeline").await;
        assert_eq!(status, 200);
        body["binaries"]
            .as_array()
            .expect("binaries is an array")
            .iter()
            .find(|b| b["binary"] == "game_logic.dll")
            .expect("the planned binary has a row")
            .get("paused")
            .and_then(|p| p.as_bool())
    };
    assert_eq!(
        get_row_paused().await,
        Some(false),
        "a freshly discovered row is not paused"
    );

    // Pause: 200, body echoes the binary and the flag now in force.
    let (status, body) = world
        .client()
        .post_lifecycle("/api/pipeline/binaries/game_logic.dll/pause")
        .await;
    assert_eq!(status, 200);
    assert_eq!(body["binary"], "game_logic.dll");
    assert_eq!(body["paused"], true);

    // The row data follows the handle — a plain GET is honest without
    // waiting for a BinaryPauseChanged event.
    assert_eq!(
        get_row_paused().await,
        Some(true),
        "GET /api/pipeline reports the pause"
    );

    // A binary the workspace has not discovered: 409 with the server's own
    // reason — a stale click is never a silent no-op.
    let (status, body) = world
        .client()
        .post_lifecycle("/api/pipeline/binaries/nope.dll/pause")
        .await;
    assert_eq!(status, 409);
    assert!(
        body["message"]
            .as_str()
            .unwrap_or_default()
            .contains("has not discovered"),
        "409 carries the server's own reason, got: {body}"
    );

    // The pause is saved in the scope record — a handle re-opened over the
    // same workspace (a restarted run) honors it, on the #107 match rule.
    assert!(
        calxgloss_types::ScopeControl::open(world.repo_path()).is_paused("GAME_LOGIC.DLL"),
        "the endpoint wrote through to the persisted scope record"
    );

    // Resume: back to unpaused, and the row follows.
    let (status, body) = world
        .client()
        .post_lifecycle("/api/pipeline/binaries/game_logic.dll/resume")
        .await;
    assert_eq!(status, 200);
    assert_eq!(body["binary"], "game_logic.dll");
    assert_eq!(body["paused"], false);
    assert_eq!(
        get_row_paused().await,
        Some(false),
        "GET /api/pipeline reports the resume"
    );
}

/// True when the served `/api/pipeline` view already carries a row for the
/// named binary.
fn row_has(view: &serde_json::Value, binary: &str) -> bool {
    view["binaries"]
        .as_array()
        .expect("binaries is an array")
        .iter()
        .any(|b| b["binary"] == binary)
}

/// A pause and a resume reach WS clients as raw `binary_pause_changed`
/// events on the shared broadcast (issue #221) — the dashboard re-renders
/// the rows when the event arrives, without a page reload (issue #222),
/// as the batch-summary events did before it.
#[tokio::test]
async fn test_binary_pause_changed_reaches_ws_clients() {
    use futures_util::StreamExt;
    use tokio_tungstenite::tungstenite::Message;

    let world = support::ReviewWorld::boot_ws_wired().await;

    let mut ws = world.websocket().await;

    // Discover the binary first — an undiscovered name is a 409 and emits
    // no event.
    let planned = ProgressEvent::QueuePlanned {
        binaries: vec!["game_logic.dll".to_string()],
    };
    world.emitter().emit(planned.clone());
    world
        .wait_until_applied(&planned, |view| row_has(view, "game_logic.dll"))
        .await;

    for path in [
        "/api/pipeline/binaries/game_logic.dll/pause",
        "/api/pipeline/binaries/game_logic.dll/resume",
    ] {
        let (status, _) = world.client().post_lifecycle(path).await;
        assert_eq!(status, 200, "{path} should succeed");
    }

    // Collect wire messages and pull out the pause changes with their
    // binary/paused payloads.
    let mut changes: Vec<(String, bool)> = Vec::new();
    for _ in 0..20 {
        if changes.len() >= 2 {
            break;
        }
        let msg = match tokio::time::timeout(Duration::from_millis(500), ws.raw_mut().next()).await
        {
            Ok(Some(Ok(m))) => m,
            _ => continue,
        };
        if let Message::Text(text) = msg {
            let v: serde_json::Value =
                serde_json::from_str(text.as_str()).expect("wire message is JSON");
            if v["event"].as_str() == Some("binary_pause_changed") {
                changes.push((
                    v["binary"].as_str().unwrap_or_default().to_string(),
                    v["paused"].as_bool().unwrap_or(false),
                ));
            }
        }
    }
    assert_eq!(
        changes,
        vec![
            ("game_logic.dll".to_string(), true),
            ("game_logic.dll".to_string(), false),
        ],
        "WS clients should see each pause change in order"
    );
}

// ─────────────────────────────────────────────────────────────
// Per-binary focus — "translate this next" (issue #284)
// ─────────────────────────────────────────────────────────────

/// The focus endpoint records a discovered binary in the scope record's
/// single focus slot: 200 echoing the addressed binary, 409 with the
/// server's own reason for an undiscovered one, last press wins, the slot
/// persists on disk (a re-opened handle honors it on the #107 case-rule),
/// and the served pipeline table moves the focused binary to the front of
/// its planned order, so a re-fetch shows the new plan before the work
/// list reaches its next boundary.
#[tokio::test]
async fn test_pipeline_binary_focus_endpoint() {
    let world = support::ReviewWorld::boot_ws_wired().await;

    let planned = ProgressEvent::QueuePlanned {
        binaries: vec![
            "a.dll".to_string(),
            "b.dll".to_string(),
            "c.dll".to_string(),
        ],
    };
    world.emitter().emit(planned.clone());
    world
        .wait_until_applied(&planned, |view| {
            row_has(view, "a.dll") && row_has(view, "b.dll") && row_has(view, "c.dll")
        })
        .await;
    assert_eq!(
        row_names(world.client()).await,
        ["a.dll", "b.dll", "c.dll"],
        "the plan alone sets the row order"
    );

    // A binary the workspace has not discovered: 409 carrying the server's
    // own reason — a stale click is never a silent no-op.
    let (status, body) = world
        .client()
        .post_lifecycle("/api/pipeline/binaries/nope.dll/focus")
        .await;
    assert_eq!(status, 409);
    assert!(
        body["message"]
            .as_str()
            .unwrap_or_default()
            .contains("has not discovered"),
        "409 carries the server's own reason, got: {body}"
    );

    // Focus c.dll: 200 echoing the addressed binary.
    let (status, body) = world
        .client()
        .post_lifecycle("/api/pipeline/binaries/c.dll/focus")
        .await;
    assert_eq!(status, 200);
    assert_eq!(body["binary"], "c.dll");

    // The served rows follow at once — the focus reads as the front of the
    // plan, matching what the live loop will do at the next boundary.
    assert_eq!(
        row_names(world.client()).await,
        ["c.dll", "a.dll", "b.dll"],
        "GET /api/pipeline hoists the focused binary"
    );

    // One slot, last press wins: b.dll simply replaces c.dll.
    let (status, _) = world
        .client()
        .post_lifecycle("/api/pipeline/binaries/b.dll/focus")
        .await;
    assert_eq!(status, 200);
    assert_eq!(
        row_names(world.client()).await,
        ["b.dll", "a.dll", "c.dll"],
        "the later press is the focus now"
    );

    // The slot is saved in the persisted scope record — a handle re-opened
    // over the same workspace (a restarted run) honors it, on the #107
    // match rule.
    let reopened = calxgloss_types::ScopeControl::open(world.repo_path());
    assert!(reopened.is_focus("B.DLL"), "the focus survives a restart");
}

// ─────────────────────────────────────────────────────────────
// Per-binary start — a row's Start Translation press (issue #285)
// ─────────────────────────────────────────────────────────────

/// One press of a planned row's Start Translation composes the swap
/// server-side: 200 reusing the binary-pause body (the target echoed
/// unpaused, the message naming the binary paused to make way), the scope
/// seam recording the target resumed-and-focused and the binary in flight
/// paused — each change emitted as a `BinaryPauseChanged` on the shared
/// broadcast, target first — the served plan re-ordered with the target at
/// the front at once, and both states persisted for a re-opened handle.
/// The press never moves the run-level machine: a live pass stays
/// live.
#[tokio::test]
async fn test_pipeline_binary_start_swaps_the_in_flight_binary() {
    let world = support::ReviewWorld::boot_ws_wired().await;
    let control = world.pipeline_control();
    control.start().expect("idle -> running");
    let mut seam = world.emitter().subscribe();

    // The run's plan is a.dll, b.dll, c.dll — and a.dll's pass is in
    // flight. c.dll's row shows Start Translation; pressing it swaps the
    // run onto c.dll.
    let planned = ProgressEvent::QueuePlanned {
        binaries: vec![
            "a.dll".to_string(),
            "b.dll".to_string(),
            "c.dll".to_string(),
        ],
    };
    world.emitter().emit(planned.clone());
    let batch = ProgressEvent::BatchStarted {
        binary: "a.dll".into(),
    };
    world.emitter().emit(batch.clone());
    world
        .wait_until_applied(&batch, |view| {
            row_has(view, "a.dll")
                && row_has(view, "b.dll")
                && row_has(view, "c.dll")
                && view["binaries"]
                    .as_array()
                    .expect("binaries is an array")
                    .iter()
                    .any(|b| b["binary"] == "a.dll" && b["processing"] == true)
        })
        .await;

    let (status, body) = world
        .client()
        .post_lifecycle("/api/pipeline/binaries/c.dll/start")
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["binary"], "c.dll");
    assert_eq!(body["paused"], false);
    let message = body["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("c.dll") && message.contains("a.dll"),
        "the message names the binary the swap paused, got: {message}"
    );

    // The scope seam sent exactly the swap's two changes, in composition
    // order: the target resumed and focused, then the in-flight binary
    // paused, to stop at its next unit boundary.
    let mut changes: Vec<(String, bool)> = Vec::new();
    while changes.len() < 2 {
        let event = tokio::time::timeout(Duration::from_millis(500), seam.recv())
            .await
            .expect("both pause changes arrive")
            .expect("event stream open");
        if let ProgressEvent::BinaryPauseChanged { binary, paused } = event {
            changes.push((binary.as_str().to_string(), paused));
        }
    }
    assert_eq!(
        changes,
        vec![("c.dll".to_string(), false), ("a.dll".to_string(), true)],
        "the target is resumed before the in-flight binary is paused"
    );

    // The served rows follow the focus at once — no run-loop boundary has
    // to be reached for the new plan order to show (issue #284's move-to-front).
    assert_eq!(
        row_names(world.client()).await,
        ["c.dll", "a.dll", "b.dll"],
        "the swapped-in target leads the served plan"
    );

    // Both states are saved in the persisted scope record — a handle
    // re-opened over the same workspace honors them on the #107 match rule.
    let reopened = calxgloss_types::ScopeControl::open(world.repo_path());
    assert!(
        reopened.is_paused("A.DLL"),
        "the previous leader stays paused"
    );
    assert!(!reopened.is_paused("C.DLL"), "the target is admitted");
    assert!(
        reopened.is_focus("C.DLL"),
        "the target holds the focus slot"
    );

    // And the swap steered the scope only, never the run-level machine: the run stayed live.
    assert!(
        matches!(control.state(), PipelineState::Running),
        "the composition never walks the run-level machine"
    );
}

/// A Start Translation press that the run cannot honor is refused with
/// the server's own reason, never a silent no-op. An undiscovered binary
/// is a 409 like the pause pair. A discovered binary the live plan no
/// longer names — its pass already completed in this run — is the stale
/// press: 409 naming the reason and pointing at the row's Configure.
#[tokio::test]
async fn test_pipeline_binary_start_refusals() {
    let world = support::ReviewWorld::boot_ws_wired().await;
    let control = world.pipeline_control();
    control.start().expect("idle -> running");

    // The plan names only a.dll; done.dll is discovered (classified) but
    // the live plan no longer names it — its pass is behind this run.
    let planned = ProgressEvent::QueuePlanned {
        binaries: vec!["a.dll".to_string()],
    };
    world.emitter().emit(planned.clone());
    let classified = ProgressEvent::ClassificationComplete {
        binary: "done.dll".into(),
        category: "WindowsOs".into(),
        classification_strategy: "ReverseEngineer".into(),
        crate_replacement: None,
        exported_symbols: 10,
        imported_symbols: 4,
    };
    world.emitter().emit(classified.clone());
    world
        .wait_until_applied(&classified, |view| {
            row_has(view, "a.dll") && row_has(view, "done.dll")
        })
        .await;

    // Undiscovered: 409 with the server's own reason, same rule as pause.
    let (status, body) = world
        .client()
        .post_lifecycle("/api/pipeline/binaries/nope.dll/start")
        .await;
    assert_eq!(status, 409);
    assert!(
        body["message"]
            .as_str()
            .unwrap_or_default()
            .contains("has not discovered"),
        "409 carries the server's own reason, got: {body}"
    );

    // The stale press: discovered, but this run already had its pass —
    // 409 naming the reason and the fix, because re-running a finished
    // pass is restart's job, not this row button's.
    let (status, body) = world
        .client()
        .post_lifecycle("/api/pipeline/binaries/done.dll/start")
        .await;
    assert_eq!(status, 409);
    let message = body["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("already completed its pass") && message.contains("done.dll"),
        "409 names the stale pass and the target, got: {message}"
    );
}

/// The Start Translation press also acts on the lifecycle state of the
/// row it sits on. From Idle it drives the start transition first, then
/// queues a plain run request (transition-first, the ADR-0004 rule the
/// run endpoint follows). From a run-level pause it releases the pause
/// without queueing anything new. A terminal run is refused with the state
/// machine's own message — the row button never reaches restart.
#[tokio::test]
async fn test_pipeline_binary_start_walks_the_run_level_machine() {
    let world = support::ReviewWorld::boot_ws_wired().await;
    let control = world.pipeline_control();
    let mut request_rx = world.run_requests().subscribe();

    let planned = ProgressEvent::QueuePlanned {
        binaries: vec!["a.dll".to_string(), "b.dll".to_string()],
    };
    world.emitter().emit(planned.clone());
    world
        .wait_until_applied(&planned, |view| {
            row_has(view, "a.dll") && row_has(view, "b.dll")
        })
        .await;

    // Idle: the press begins translating with the pressed binary first —
    // 200, the machine moved to Running, and the default full-scope
    // request queued on the shared channel exactly as the run endpoint queues it.
    let (status, body) = world
        .client()
        .post_lifecycle("/api/pipeline/binaries/b.dll/start")
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["paused"], false);
    let message = body["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("b.dll") && !message.contains("paused"),
        "nothing was in flight to pause, got: {message}"
    );
    request_rx.changed().await.expect("a request was queued");
    let queued = request_rx.borrow_and_update().clone();
    assert_eq!(
        queued,
        Some(PipelineRunRequest::default()),
        "the row button queues a plain run — never a recovery, never a scoped workload"
    );
    assert!(
        matches!(control.state(), PipelineState::Running),
        "the start transition is driven before the request"
    );

    // Run-level pause, then a press on the focused row: the pause releases
    // so the swap can proceed, and no second request is queued.
    let (status, body) = world.client().post_lifecycle("/api/pipeline/pause").await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["state"], "paused");
    let (status, body) = world
        .client()
        .post_lifecycle("/api/pipeline/binaries/b.dll/start")
        .await;
    assert_eq!(status, 200, "{body}");
    assert!(
        matches!(control.state(), PipelineState::Running),
        "the press releases the run-level pause"
    );
    assert!(
        !request_rx.has_changed().expect("watch alive"),
        "releasing a pause queues nothing new"
    );

    // Terminal: the machine itself refuses, and its message is carried
    // through verbatim — restarting a finished run is a different verb.
    control.complete().expect("running -> complete");
    let (status, body) = world
        .client()
        .post_lifecycle("/api/pipeline/binaries/a.dll/start")
        .await;
    assert_eq!(status, 409);
    assert!(
        body["message"]
            .as_str()
            .unwrap_or_default()
            .contains("cannot start a pipeline that is complete"),
        "409 carries the machine's own message, got: {body}"
    );
    assert!(
        !request_rx.has_changed().expect("watch alive"),
        "a refused press queues nothing"
    );
}

// ─────────────────────────────────────────────────────────────
// Translation scope controls (issue #93, W2.5)
// ─────────────────────────────────────────────────────────────

/// A live router built **without** a scope handle attached answers the
/// scope endpoints honestly with 503 rather than steering a pipeline it
/// does not hold — the lifecycle endpoints' honesty rule, same shape.
#[tokio::test]
async fn test_scope_endpoints_503_without_control() {
    let world = support::ReviewWorld::boot().await;

    let resp = reqwest::Client::new()
        .get(world.client().url("/api/scope"))
        .send()
        .await
        .expect("request reaches server");
    assert_eq!(resp.status(), 503, "GET /api/scope without a handle is 503");

    for (path, body) in [
        ("/api/scope/binaries", serde_json::json!({"binaries": []})),
        (
            "/api/scope/skip-function",
            serde_json::json!({"binary": "a.dll", "function": "F"}),
        ),
        (
            "/api/scope/priority-function",
            serde_json::json!({"binary": "a.dll", "function": "F"}),
        ),
        (
            "/api/scope/remove-priority-function",
            serde_json::json!({"binary": "a.dll", "function": "F"}),
        ),
        ("/api/scope/constraints", serde_json::json!({})),
    ] {
        let (status, resp_body) = world.client().post_json(path, body).await;
        assert_eq!(status, 503, "{path} without a handle should be 503");
        assert!(
            resp_body["message"]
                .as_str()
                .unwrap_or_default()
                .contains("no scope control"),
            "503 explains why, got: {resp_body}"
        );
    }

    // Issue #221: the per-binary pause endpoints are honest the same way —
    // with no scope handle attached there is no paused set to change.
    // Issue #284: the focus endpoint joins them — no handle, no focus slot.
    // Issue #285: and so the start endpoint — the swap steers through the
    // handle, and with none attached there is nothing to steer.
    for path in [
        "/api/pipeline/binaries/game_logic.dll/pause",
        "/api/pipeline/binaries/game_logic.dll/resume",
        "/api/pipeline/binaries/game_logic.dll/focus",
        "/api/pipeline/binaries/game_logic.dll/start",
    ] {
        let (status, resp_body) = world.client().post_lifecycle(path).await;
        assert_eq!(status, 503, "{path} without a handle should be 503");
        assert!(
            resp_body["message"]
                .as_str()
                .unwrap_or_default()
                .contains("no scope control"),
            "503 explains why, got: {resp_body}"
        );
    }
}

/// The scope endpoints drive the shared handle end to end: mutations land
/// in the status payload, and a handle re-opened over the same workspace
/// (a restarted run) honors the persisted records without re-entering
/// anything (issue #93).
#[tokio::test]
async fn test_scope_endpoints_drive_and_persist_the_operator_scope() {
    let world = support::ReviewWorld::boot_ws_wired().await;

    let (status, body) = world
        .client()
        .post_json(
            "/api/scope/binaries",
            serde_json::json!({"binaries": ["game_logic.dll"]}),
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(body["scope"]["binaries"][0], "game_logic.dll");

    let (status, _) = world
        .client()
        .post_json(
            "/api/scope/skip-function",
            serde_json::json!({"binary": "game_logic.dll", "function": "UpdateScene"}),
        )
        .await;
    assert_eq!(status, 200);

    let (status, _) = world
        .client()
        .post_json(
            "/api/scope/priority-function",
            serde_json::json!({"binary": "game_logic.dll", "function": "DrawPrimitive"}),
        )
        .await;
    assert_eq!(status, 200);

    // Issue #95: the panel's remove button drives the removal endpoint —
    // a prioritized function drops out, the rest of the list stays.
    let (status, _) = world
        .client()
        .post_json(
            "/api/scope/priority-function",
            serde_json::json!({"binary": "game_logic.dll", "function": "RenderFrame"}),
        )
        .await;
    assert_eq!(status, 200);
    let (status, body) = world
        .client()
        .post_json(
            "/api/scope/remove-priority-function",
            serde_json::json!({"binary": "game_logic.dll", "function": "RenderFrame"}),
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(
        body["scope"]["priority_functions"].as_array().map(Vec::len),
        Some(1),
        "the removed priority is gone from the echoed status"
    );

    let (status, body) = world
        .client()
        .post_json(
            "/api/scope/constraints",
            serde_json::json!({
                "max_attempts": 2,
                "max_context_tier": "Disassembly",
                "token_budget": 50000
            }),
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(body["constraints"]["max_attempts"], 2);
    assert_eq!(body["constraints"]["max_context_tier"], "Disassembly");
    assert_eq!(body["constraints"]["token_budget"], 50000);

    // Status read reflects every mutation.
    let (status, body) = world.client().get_json("/api/scope").await;
    assert_eq!(status, 200);
    assert_eq!(
        body["scope"]["skipped_functions"][0]["function"],
        "UpdateScene"
    );
    assert_eq!(
        body["scope"]["priority_functions"][0]["function"],
        "DrawPrimitive"
    );
    // The status also carries the backend's own tier enumeration — the
    // dashboard's tier select populates its values from this instead of
    // hardcoding the variant names (issue #109).
    assert_eq!(
        body["context_tiers"],
        serde_json::json!([
            "Signature",
            "Disassembly",
            "WithTests",
            "ModuleContext",
            "FullModule"
        ]),
        "the scope status names every context tier the constraints may cap at"
    );

    // A restarted run: a fresh handle over the same workspace loads the
    // persisted records — nothing re-entered.
    let reopened = calxgloss_types::ScopeControl::open(world.repo_path());
    let persisted = reopened.scope();
    assert_eq!(persisted.binaries.len(), 1);
    assert!(persisted.is_skipped("game_logic.dll", "UpdateScene"));
    assert!(persisted.is_priority("game_logic.dll", "DrawPrimitive"));
    assert!(
        !persisted.is_priority("game_logic.dll", "RenderFrame"),
        "the priority removal survives a restart"
    );
    assert_eq!(reopened.constraints().max_attempts, Some(2));
    assert_eq!(
        reopened.constraints().max_context_tier,
        Some(calxgloss_types::ContextTier::Disassembly)
    );
    assert_eq!(reopened.constraints().token_budget, Some(50000));
}

// ─────────────────────────────────────────────────────────────
// Per-unit reviewer overrides (issue #96, W2.7)
// ─────────────────────────────────────────────────────────────

/// A live router built **without** an override handle attached answers the
/// override endpoints honestly with 503 rather than steering a pipeline it
/// does not hold — the scope endpoints' honesty rule, same shape.
#[tokio::test]
async fn test_override_endpoints_503_without_control() {
    let world = support::ReviewWorld::boot().await;

    let path = "/api/units/game_logic.dll%2FDrawPrimitive%2Fv1/override";

    let (status, body) = world.client().get_json(path).await;
    assert_eq!(status, 503, "GET override without a handle is 503");
    assert!(
        body["message"]
            .as_str()
            .unwrap_or_default()
            .contains("no unit override control"),
        "503 explains why, got: {body}"
    );

    let status = world
        .client()
        .post_for_status(path, serde_json::json!({"override": {"skip": true}}))
        .await;
    assert_eq!(status, 503, "POST override without a handle is 503");

    let (status, _) = world.client().delete_json(path).await;
    assert_eq!(status, 503, "DELETE override without a handle is 503");
}

/// The override endpoints drive the shared handle end to end: apply lands,
/// GET reads it back, removal clears it, and a handle re-opened over the
/// same workspace (a restarted run) honors the persisted records without
/// re-entering anything (issue #96).
#[tokio::test]
async fn test_override_endpoints_apply_get_and_persist() {
    let world = support::ReviewWorld::boot_ws_wired().await;

    let path = "/api/units/game_logic.dll%2FDrawPrimitive%2Fv1/override";

    // A never-overridden unit reads back honestly: 200 with no override.
    let (status, body) = world.client().get_json(path).await;
    assert_eq!(status, 200);
    assert_eq!(body["unit"], "game_logic.dll/DrawPrimitive/v1");
    assert!(
        body["override"].is_null(),
        "no override set yet, got: {body}"
    );

    // Apply the full record.
    let (status, body) = world
        .client()
        .post_json(
            path,
            serde_json::json!({"override": {
                "tier_override": "FullModule",
                "retry_strategy_override": "escalate",
                "custom_hints": ["uses SSE registers"],
                "skip": false,
                "reviewer_notes": "looks like a blitter"
            }}),
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(body["override"]["tier_override"], "FullModule");
    assert_eq!(body["override"]["retry_strategy_override"], "escalate");
    assert_eq!(body["override"]["custom_hints"][0], "uses SSE registers");
    assert_eq!(body["override"]["reviewer_notes"], "looks like a blitter");

    // A typo'd strategy label is refused — the record's typed field rejects
    // the unknown variant rather than storing an override that looks active
    // but silently does nothing (axum answers the failed JSON extraction
    // with 422, like the classification override's category, issue #120).
    let status = world
        .client()
        .post_for_status(
            path,
            serde_json::json!({"override": {"retry_strategy_override": "escalatte"}}),
        )
        .await;
    assert_eq!(status, 422, "unknown strategy label is rejected");
    let stored = calxgloss_types::OverrideControl::open(world.repo_path())
        .get("game_logic.dll", "DrawPrimitive");
    assert_eq!(
        stored.and_then(|o| o.retry_strategy_override),
        Some(calxgloss_types::RetryStrategy::Escalate),
        "the rejected request must not disturb the stored record"
    );

    // GET reads the same record back.
    let (status, body) = world.client().get_json(path).await;
    assert_eq!(status, 200);
    assert_eq!(body["override"]["tier_override"], "FullModule");

    // A restarted run: a fresh handle over the same workspace loads the
    // persisted record — nothing re-entered.
    let reopened = calxgloss_types::OverrideControl::open(world.repo_path());
    let record = reopened
        .get("game_logic.dll", "DrawPrimitive")
        .expect("the override survives a restart");
    assert_eq!(
        record.tier_override,
        Some(calxgloss_types::ContextTier::FullModule)
    );
    assert_eq!(
        record.retry_strategy_override,
        Some(calxgloss_types::RetryStrategy::Escalate)
    );

    // Removal clears it, and the removal survives the restart too.
    let (status, body) = world.client().delete_json(path).await;
    assert_eq!(status, 200);
    assert!(
        body["override"].is_null(),
        "removal leaves no record, got: {body}"
    );

    let reopened = calxgloss_types::OverrideControl::open(world.repo_path());
    assert!(
        reopened.get("game_logic.dll", "DrawPrimitive").is_none(),
        "the removal survives a restart"
    );
}

/// A live router built **without** a classification-override handle attached
/// answers the classification endpoints honestly with 503 rather than
/// steering a classification it does not hold — the override endpoints'
/// honesty rule, same shape.
#[tokio::test]
async fn test_classification_override_endpoints_503_without_control() {
    let world = support::ReviewWorld::boot().await;

    let path = "/api/binaries/fmod.dll/classification";

    let (status, body) = world.client().get_json(path).await;
    assert_eq!(status, 503, "GET classification without a handle is 503");
    assert!(
        body["message"]
            .as_str()
            .unwrap_or_default()
            .contains("no classification override control"),
        "503 explains why, got: {body}"
    );

    let status = world
        .client()
        .post_for_status(
            path,
            serde_json::json!({"override": {"category": "RuntimeLibrary", "known_runtime": true}}),
        )
        .await;
    assert_eq!(status, 503, "POST classification without a handle is 503");
}

/// The classification endpoints drive the shared handle end to end: the GET
/// reports the recorded classification with its reasoning, an override
/// lands and reads back, a typo'd category is refused, `null` removes it,
/// and a handle re-opened over the same workspace (a restarted run) honors
/// the persisted records without re-entering anything (issue #97).
#[tokio::test]
async fn test_classification_override_endpoints_set_get_and_persist() {
    let world = support::ReviewWorld::boot_ws_wired().await;
    write_canned_classification_record(
        &world.repo_path(),
        "fmod.dll",
        DllCategory::UnknownThirdParty,
    );

    let path = "/api/binaries/fmod.dll/classification";

    // The recorded classification, with its reasoning, and no override yet.
    let (status, body) = world.client().get_json(path).await;
    assert_eq!(status, 200);
    assert_eq!(body["binary"], "fmod.dll");
    assert_eq!(body["classification"]["category"], "UnknownThirdParty");
    assert_eq!(body["classification"]["strategy"], "ReverseEngineer");
    assert!(
        body["classification"]["reason"]
            .as_str()
            .unwrap_or_default()
            .contains("no known library"),
        "the reasoning is included, got: {body}"
    );
    assert!(
        body["override"].is_null(),
        "no override set yet, got: {body}"
    );

    // Apply the override — a runtime-library correction.
    let (status, body) = world
        .client()
        .post_json(
            path,
            serde_json::json!({"override": {
                "category": "RuntimeLibrary",
                "known_runtime": true
            }}),
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(body["override"]["category"], "RuntimeLibrary");
    assert_eq!(body["override"]["known_runtime"], true);

    // A typo'd category is refused — serde rejects the unknown variant
    // rather than storing a decision that means nothing (axum answers the
    // failed JSON extraction with 422).
    let status = world
        .client()
        .post_for_status(
            path,
            serde_json::json!({"override": {"category": "RuntimeLibary"}}),
        )
        .await;
    assert_eq!(status, 422, "unknown category is rejected");
    let stored = calxgloss_types::ClassificationOverrideControl::open(world.repo_path());
    assert_eq!(
        stored.get("fmod.dll").map(|o| o.category),
        Some(calxgloss_types::DllCategory::RuntimeLibrary),
        "the rejected request must not disturb the stored record"
    );

    // GET reads the same record back.
    let (_, body) = world.client().get_json(path).await;
    assert_eq!(body["override"]["category"], "RuntimeLibrary");

    // A restarted run: a fresh handle over the same workspace loads the
    // persisted record — nothing re-entered.
    let reopened = calxgloss_types::ClassificationOverrideControl::open(world.repo_path());
    let record = reopened
        .get("fmod.dll")
        .expect("the override survives a restart");
    assert_eq!(
        record.category,
        calxgloss_types::DllCategory::RuntimeLibrary
    );
    assert!(
        record.is_runtime(),
        "the runtime rule holds across restarts"
    );

    // `override: null` removes it, and the removal survives the restart.
    let (status, body) = world
        .client()
        .post_json(path, serde_json::json!({"override": null}))
        .await;
    assert_eq!(status, 200);
    assert!(
        body["override"].is_null(),
        "removal leaves no record, got: {body}"
    );

    let reopened = calxgloss_types::ClassificationOverrideControl::open(world.repo_path());
    assert!(
        reopened.get("fmod.dll").is_none(),
        "the removal survives a restart"
    );
}

/// The Start endpoint (issue #92) begins translation in a live session that
/// has not translated yet: Idle → Running with 200, the default full-scope
/// request queued on the shared channel for the live loop, the server status
/// following the machine — and a second Start refused with 409 leaving no
/// stale request behind.
#[tokio::test]
async fn test_pipeline_start_endpoint_begins_idle_run() {
    let world = support::ReviewWorld::boot_ws_wired().await;
    let mut request_rx = world.run_requests().subscribe();

    // Start from Idle: 200, the transition in the body.
    let (status, body) = world.client().post_lifecycle("/api/pipeline/start").await;
    assert_eq!(status, 200);
    assert_eq!(body["previous"], "idle");
    assert_eq!(body["state"], "running");

    // The default full-scope request landed on the shared channel — the
    // live loop's subscription sees it.
    request_rx.changed().await.expect("a request was queued");
    let queued = request_rx.borrow_and_update().clone();
    assert_eq!(queued, Some(PipelineRunRequest::default()));

    // Server status follows the machine.
    let (_, body) = world.client().get_json("/api/server/status").await;
    assert_eq!(body["pipeline_status"], "running");

    // A run already in flight cannot be started again — 409 with the
    // machine's own message, and no second request queued.
    let (status, body) = world.client().post_lifecycle("/api/pipeline/start").await;
    assert_eq!(status, 409);
    assert!(
        body["message"]
            .as_str()
            .unwrap_or_default()
            .contains("cannot start a pipeline that is running"),
        "409 carries the machine's own message, got: {body}"
    );
    assert!(
        !request_rx.has_changed().expect("watch alive"),
        "a rejected start must not queue a stale request"
    );
}

/// The Restart endpoint (issue #92) re-runs a finished pipeline in-process:
/// Complete → Running with 200, the body's phase/target/scope selectors
/// recorded verbatim on the shared channel, and a run that is not terminal
/// (still Running) refused with 409 — the operator stops it first.
#[tokio::test]
async fn test_pipeline_restart_endpoint_queues_selectors() {
    let world = support::ReviewWorld::boot_ws_wired().await;
    let control = world.pipeline_control();
    control.start().expect("idle -> running");
    let mut request_rx = world.run_requests().subscribe();

    // A run still in flight cannot restart — the operator stops it first.
    let (status, body) = world
        .client()
        .post_json("/api/pipeline/restart", serde_json::json!({}))
        .await;
    assert_eq!(status, 409);
    assert!(
        body["message"]
            .as_str()
            .unwrap_or_default()
            .contains("cannot restart a pipeline that is running"),
        "409 carries the machine's own message, got: {body}"
    );

    // The run finishes (the live loop would walk this; here the test does).
    control.complete().expect("running -> complete");

    // Restart with the full selector set: 200, Complete → Running.
    let selectors = serde_json::json!({
        "phase": "classify",
        "target": { "binary": "eqgame.dll" },
        "scope": "only_failed",
    });
    let (status, body) = world
        .client()
        .post_json("/api/pipeline/restart", selectors)
        .await;
    assert_eq!(status, 200);
    assert_eq!(body["previous"], "complete");
    assert_eq!(body["state"], "running");
    let message = body["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("classify")
            && message.contains("eqgame.dll")
            && message.contains("failed"),
        "the response message names the selectors the run will honor, got: {body}"
    );

    // The selectors landed on the shared channel exactly as sent.
    request_rx.changed().await.expect("a request was queued");
    let queued = request_rx
        .borrow_and_update()
        .clone()
        .expect("Some request");
    assert_eq!(queued.phase, RunPhase::Classify);
    assert_eq!(
        queued.target,
        RunTarget::Binary(calxgloss_types::BinaryIdentity::new("eqgame.dll"))
    );
    assert_eq!(queued.scope, RunScope::OnlyFailed);

    // A bodyless POST re-runs everything — the defaults.
    control.complete().expect("running -> complete");
    let (status, _) = world.client().post_lifecycle("/api/pipeline/restart").await;
    assert_eq!(status, 200);
    request_rx.changed().await.expect("a request was queued");
    let queued = request_rx
        .borrow_and_update()
        .clone()
        .expect("Some request");
    assert_eq!(queued, PipelineRunRequest::default());
}

/// Start and Restart emit their lifecycle transitions on the shared
/// broadcast, so WS clients see the run begin without a refetch (issue #92)
/// — idle→running from Start, complete→running from Restart.
#[tokio::test]
async fn test_pipeline_start_and_restart_reach_ws_clients() {
    use futures_util::StreamExt;
    use tokio_tungstenite::tungstenite::Message;

    let world = support::ReviewWorld::boot_ws_wired().await;
    let control = world.pipeline_control();

    let mut ws = world.websocket().await;

    // Start the run from Idle over HTTP…
    let (status, _) = world.client().post_lifecycle("/api/pipeline/start").await;
    assert_eq!(status, 200);
    // …the run finishes (the live loop would do this walk)…
    control.stop().expect("running -> stopping");
    control.complete().expect("stopping -> complete");
    // …and Restart begins it again in-process.
    let (status, _) = world
        .client()
        .post_json("/api/pipeline/restart", serde_json::json!({}))
        .await;
    assert_eq!(status, 200);

    let mut transitions: Vec<(String, String)> = Vec::new();
    for _ in 0..20 {
        if transitions.len() >= 4 {
            break;
        }
        let msg = match tokio::time::timeout(Duration::from_millis(500), ws.raw_mut().next()).await
        {
            Ok(Some(Ok(m))) => m,
            _ => continue,
        };
        if let Message::Text(text) = msg {
            let v: serde_json::Value =
                serde_json::from_str(text.as_str()).expect("wire message is JSON");
            if v["event"].as_str() == Some("pipeline_state_changed") {
                transitions.push((
                    v["previous"].as_str().unwrap_or_default().to_string(),
                    v["state"].as_str().unwrap_or_default().to_string(),
                ));
            }
        }
    }
    assert_eq!(
        transitions,
        vec![
            ("idle".to_string(), "running".to_string()),
            ("running".to_string(), "stopping".to_string()),
            ("stopping".to_string(), "complete".to_string()),
            ("complete".to_string(), "running".to_string()),
        ],
        "WS clients should see the start and the restart among the lifecycle transitions"
    );
}

/// The live router's cancel-current endpoint (issue #91, W2.2) drives the
/// shared UnitCancellation: 409 when no unit is in flight (a stale UI
/// cannot drive the run inconsistent), 200 naming the cancelled unit when
/// one is, the cancellation on the WS stream like every other lifecycle
/// operation, the progress state recording the unit cancelled/failed —
/// and the run itself untouched: still running, moving on to the next unit.
#[tokio::test]
async fn test_pipeline_cancel_current_cancels_unit_and_run_continues() {
    use futures_util::StreamExt;
    use tokio_tungstenite::tungstenite::Message;

    let world = support::ReviewWorld::boot_ws_wired().await;
    let control = world.pipeline_control();
    control.start().expect("idle -> running");
    let cancellation = world.unit_cancellation();

    let mut ws = world.websocket().await;

    // Nothing in flight yet — the request is rejected, not silently absorbed.
    let (status, body) = world
        .client()
        .post_lifecycle("/api/pipeline/cancel-current")
        .await;
    assert_eq!(status, 409, "cancelling with no unit in flight is rejected");
    assert!(
        body["message"]
            .as_str()
            .unwrap_or_default()
            .contains("no unit is in flight to cancel"),
        "409 explains why, got: {body}"
    );

    // A unit in flight — fed exactly how live mode feeds it: the pipeline
    // emits TranslationStarted and registers the unit on the handle.
    let started = ProgressEvent::TranslationStarted {
        binary: "game_logic.dll".into(),
        function: "DrawPrimitive".into(),
    };
    world.emitter().emit(started.clone());
    cancellation.begin_unit("game_logic.dll", "DrawPrimitive");
    world
        .wait_until_unit_applied(&started, "game_logic.dll", "DrawPrimitive", |_| true)
        .await;

    // Cancel it: 200 naming the unit that was in flight.
    let (status, body) = world
        .client()
        .post_lifecycle("/api/pipeline/cancel-current")
        .await;
    assert_eq!(status, 200, "a unit in flight can be cancelled");
    assert_eq!(body["binary"], "game_logic.dll");
    assert_eq!(body["function"], "DrawPrimitive");
    assert!(
        body["message"]
            .as_str()
            .unwrap_or_default()
            .contains("continues with the next unit"),
        "the response confirms the run continues, got: {body}"
    );
    assert!(
        cancellation.is_cancelled_for("game_logic.dll", "DrawPrimitive"),
        "the pipeline side sees the cancellation the endpoint made"
    );

    // The cancellation lands on the WS stream like every other lifecycle
    // operation — a raw unit_cancelled event naming the unit.
    let mut saw_cancelled = false;
    for _ in 0..20 {
        if saw_cancelled {
            break;
        }
        let msg = match tokio::time::timeout(Duration::from_millis(500), ws.raw_mut().next()).await
        {
            Ok(Some(Ok(m))) => m,
            _ => continue,
        };
        if let Message::Text(text) = msg {
            let v: serde_json::Value =
                serde_json::from_str(text.as_str()).expect("wire message is JSON");
            if v["event"].as_str() == Some("unit_cancelled") {
                assert_eq!(v["binary"], "game_logic.dll");
                assert_eq!(v["function"], "DrawPrimitive");
                saw_cancelled = true;
            }
        }
    }
    assert!(saw_cancelled, "WS clients must see the cancellation");

    // Progress state records the cancelled unit as finished and failed,
    // named as cancelled so the dashboard can tell it from a plain failure.
    let snapshot = world.progress_state().snapshot().await;
    let entry = snapshot
        .get("game_logic.dll/DrawPrimitive")
        .expect("the cancelled unit is tracked");
    assert!(entry.finished, "the cancelled unit is terminal");
    assert_eq!(entry.succeeded, Some(false), "recorded as failed");
    assert_eq!(
        entry.outcome.as_deref(),
        Some("cancelled"),
        "recorded as cancelled"
    );

    // The run itself is untouched — still running, and it moves on: the
    // pipeline ends the unit, starts the next, and that one can be
    // cancelled too.
    assert_eq!(
        control.state(),
        PipelineState::Running,
        "the run keeps going"
    );
    cancellation.end_unit_was_cancelled();
    let next = ProgressEvent::TranslationStarted {
        binary: "game_logic.dll".into(),
        function: "UpdateScene".into(),
    };
    world.emitter().emit(next.clone());
    cancellation.begin_unit("game_logic.dll", "UpdateScene");
    let (status, body) = world
        .client()
        .post_lifecycle("/api/pipeline/cancel-current")
        .await;
    assert_eq!(status, 200, "the next in-flight unit can be cancelled");
    assert_eq!(body["function"], "UpdateScene");

    // And once the run is between units again, cancel is rejected anew.
    cancellation.end_unit_was_cancelled();
    let (status, _) = world
        .client()
        .post_lifecycle("/api/pipeline/cancel-current")
        .await;
    assert_eq!(status, 409, "nothing in flight between units to cancel");
}
