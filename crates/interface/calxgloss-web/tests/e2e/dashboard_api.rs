//! Scenario tests split from `tests/e2e.rs`.

use super::*;

/// WS phase events (issue #55, W0 Phase 2 tail): after applying each
/// unit-scoped progress event, the live router pushes a `unit_phase` record —
/// the unit's full live state including phase history — over the WebSocket,
/// so the live view updates rows from the pushed record instead of refetching
/// `/api/progress/enhanced`. Raw pipeline events keep flowing unchanged.
#[tokio::test]
async fn test_ws_pushes_unit_phase_records() {
    use futures_util::StreamExt;
    use tokio_tungstenite::tungstenite::Message;

    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path());
    let events = TranslationEvents::new(128);
    let manager = SessionManager::new_with_broadcast(events.subscribe());
    let progress = ProgressState::new();
    let router = build_router_with_ws(state, manager, progress, ws_actions(&fixture));
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let (mut ws, _) = tokio_tungstenite::connect_async(format!(
        "ws://127.0.0.1:{}/api/events/upgrade",
        fixture.port()
    ))
    .await
    .expect("websocket upgrade succeeds");
    // Let the Register command drain before any event is emitted.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Walk one unit through the pipeline: start, tests, tier, LLM call, done.
    for event in [
        ProgressEvent::TranslationStarted {
            binary: "game_logic.dll".into(),
            function: "DrawPrimitive".into(),
        },
        ProgressEvent::TestsGenerated {
            binary: "game_logic.dll".into(),
            function: "DrawPrimitive".into(),
            test_count: 3,
        },
        ProgressEvent::ContextTierSelected {
            binary: "game_logic.dll".into(),
            function: "DrawPrimitive".into(),
            tier: "T2".into(),
            tier_label: "with_tests".into(),
            complexity: "Medium".into(),
            api_call_count: 3,
        },
        ProgressEvent::LlmCallStart {
            binary: "game_logic.dll".into(),
            function: "DrawPrimitive".into(),
            attempt: 2,
            retry_strategy: "decompose".into(),
        },
        ProgressEvent::TranslationCompleted {
            binary: "game_logic.dll".into(),
            function: "DrawPrimitive".into(),
            total_attempts: 2,
            success_strategy: Some("decompose".into()),
        },
    ] {
        events.emit(event);
    }

    // Collect wire messages: raw events keep their `event` tag; each applied
    // unit event is followed by a `unit_phase` record.
    let mut raw_events: Vec<String> = Vec::new();
    let mut records: Vec<serde_json::Value> = Vec::new();
    for _ in 0..40 {
        if records.len() >= 5 {
            break;
        }
        let msg = match tokio::time::timeout(Duration::from_millis(500), ws.next()).await {
            Ok(Some(Ok(m))) => m,
            _ => continue,
        };
        if let Message::Text(text) = msg {
            let v: serde_json::Value =
                serde_json::from_str(text.as_str()).expect("wire message is JSON");
            match v["event"].as_str() {
                Some("unit_phase") => records.push(v["unit"].clone()),
                Some(name) => raw_events.push(name.to_string()),
                None => {}
            }
        }
    }

    // Backward compatibility: the raw pipeline events still arrive tagged.
    for expected in [
        "translation_started",
        "tests_generated",
        "context_tier_selected",
        "llm_call_start",
        "translation_completed",
    ] {
        assert!(
            raw_events.iter().any(|e| e == expected),
            "raw event {expected} should still reach WS clients, got: {raw_events:?}"
        );
    }

    // One record per applied unit event, in event order.
    assert_eq!(
        records.len(),
        5,
        "each unit-scoped event should push one unit_phase record"
    );
    let first = &records[0];
    assert_eq!(first["binary"], "game_logic.dll");
    assert_eq!(first["function"], "DrawPrimitive");
    assert_eq!(first["phase"], "scan_fetch");
    assert_eq!(first["finished"], false);
    assert!(
        first.get("succeeded").is_none(),
        "an in-flight unit never looks succeeded or failed"
    );

    let last = &records[4];
    assert_eq!(last["phase"], "review");
    assert_eq!(last["finished"], true);
    assert_eq!(last["succeeded"], true);
    assert_eq!(last["attempt"], 2);
    assert_eq!(last["retry_strategy"], "decompose");
    assert_eq!(last["context_tier"], "T2");
    assert_eq!(last["tier_label"], "with_tests");
    let history: Vec<&str> = last["phase_history"]
        .as_array()
        .expect("phase history present")
        .iter()
        .map(|r| r["phase"].as_str().unwrap_or_default())
        .collect();
    assert_eq!(
        history,
        ["scan_fetch", "context_tier", "llm_call", "review"],
        "phase history reaches the client in event order"
    );
}

/// Audit-6 (issue #85): one stalled WS client must never hold up the others.
/// The second client connects but never reads a frame; its 128-slot send
/// buffer fills and the server drops its connection. Meanwhile the fast
/// client receives **every** message — proof the broadcast loop never waited
/// on the stalled peer and the upstream event channel never overflowed.
#[tokio::test]
async fn test_stalled_ws_client_is_evicted() {
    use futures_util::StreamExt;
    use tokio_tungstenite::tungstenite::Message;

    const EVENTS: usize = 400;

    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path());
    let events = TranslationEvents::new(1024);
    let manager = SessionManager::new_with_broadcast(events.subscribe());
    let progress = ProgressState::new();
    let router = build_router_with_ws(state, manager, progress, ws_actions(&fixture));
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let ws_url = format!("ws://127.0.0.1:{}/api/events/upgrade", fixture.port());
    let (mut fast, _) = tokio_tungstenite::connect_async(&ws_url)
        .await
        .expect("fast client websocket upgrade succeeds");
    let (mut stalled, _) = tokio_tungstenite::connect_async(&ws_url)
        .await
        .expect("stalled client websocket upgrade succeeds");
    // Let both Register commands drain before any event is emitted.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Drain the fast client in its own task so the test itself is never the
    // slow consumer; a cheap substring check tells raw events (tagged
    // `translation_started`) from the `unit_phase` records interleaved with
    // them.
    let fast_task = tokio::spawn(async move {
        let mut raw_started = 0usize;
        while raw_started < EVENTS {
            match tokio::time::timeout(Duration::from_secs(10), fast.next()).await {
                Ok(Some(Ok(Message::Text(text)))) => {
                    if text.as_str().contains("\"translation_started\"") {
                        raw_started += 1;
                    }
                }
                Ok(Some(Ok(_))) => {}
                Ok(Some(Err(e))) => panic!("fast client errored: {e}"),
                Ok(None) => panic!("fast client connection closed early"),
                Err(_) => panic!("fast client went silent after {raw_started} of {EVENTS} events"),
            }
        }
        raw_started
    });

    // Payloads are deliberately large and emitted in paced bursts: the total
    // (400 events × 2 messages × ~16 KB) comfortably exceeds the 128-slot
    // per-client buffer plus both sockets' kernel buffers, so the stalled
    // client's buffer is guaranteed to fill while the test runs, while the
    // bursts leave the fast client room to keep draining.
    for i in 0..EVENTS {
        events.emit(ProgressEvent::TranslationStarted {
            binary: "game_logic.dll".into(),
            function: format!("DrawPrimitive_{i}_{}", "x".repeat(16384)),
        });
        if i % 25 == 24 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    // The fast client saw every raw event despite the stalled peer.
    let raw_started = tokio::time::timeout(Duration::from_secs(15), fast_task)
        .await
        .expect("fast client receives every event")
        .expect("fast client task does not panic");
    assert_eq!(raw_started, EVENTS);

    // The stalled client never read a frame; the server must have closed its
    // connection once its buffer filled. Reading now drains whatever the
    // kernel still holds, then surfaces the close.
    let mut closed = false;
    while !closed {
        match tokio::time::timeout(Duration::from_secs(5), stalled.next()).await {
            Ok(Some(Ok(Message::Close(_)))) | Ok(Some(Err(_))) | Ok(None) => closed = true,
            Ok(Some(Ok(_))) => {}
            Err(_) => panic!("stalled client was never disconnected"),
        }
    }
}

/// `POST /api/server/shutdown` on the live router with a canned in-flight
/// unit: the response documents the graceful stop, the shared stop signal
/// is set (the pipeline's side of the contract — it breaks at the next
/// unit boundary), and the accept loop stops taking new connections.
///
/// The unit in flight is *not* aborted by the stop: it is still recorded as
/// in flight when the request lands, and the completion event the pipeline
/// emits when that unit finishes is still recorded afterwards. Persisting
/// that finished unit is the pipeline's own contract, covered by
/// `batch_translate_breaks_at_unit_boundary_when_stop_is_requested` in
/// `calxgloss-translator`.
#[tokio::test]
async fn test_server_shutdown_live_router_stops_pipeline_and_server() {
    let fixture = TestFixture::new();
    let stop = calxgloss_types::StopSignal::new();
    let state = ServerState::new(fixture.repo_path()).with_stop_signal(stop.clone());
    let events = TranslationEvents::new(128);
    let manager = SessionManager::new_with_broadcast(events.subscribe());
    let progress = ProgressState::new();
    let router = build_router_with_ws(
        state.clone(),
        manager,
        progress.clone(),
        ws_actions(&fixture),
    );
    let server = spawn_server_with_shutdown(&state, router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    // A unit in flight (fed exactly how live mode feeds ProgressState).
    events.emit(ProgressEvent::TranslationStarted {
        binary: "game_logic.dll".into(),
        function: "DrawPrimitive".into(),
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        progress.in_flight_count().await == 1,
        "a unit must be in flight before the request"
    );
    assert!(!stop.is_stopped(), "no stop before the request");

    let resp = reqwest::Client::new()
        .post(format!(
            "http://127.0.0.1:{}/api/server/shutdown",
            fixture.port()
        ))
        .send()
        .await
        .expect("shutdown request succeeds");

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("body is JSON");
    assert_eq!(body["status"], "shutting_down");
    assert_eq!(body["restart_required"], false);
    assert!(
        body["message"].as_str().is_some_and(|m| !m.is_empty()),
        "shutdown must carry an operator-facing message"
    );

    // The pipeline's side: the shared stop signal is set, so the batch loop
    // ends at the next unit boundary after the in-flight unit completes.
    assert!(stop.is_stopped(), "the shared stop signal must be set");

    // The in-flight unit is not cancelled by the stop — it is still there,
    // unfinished, and the completion the pipeline emits at the boundary is
    // still recorded (that is the state the shutdown is meant to save).
    assert_eq!(
        progress.in_flight_count().await,
        1,
        "the in-flight unit must survive the stop request"
    );
    events.emit(ProgressEvent::TranslationCompleted {
        binary: "game_logic.dll".into(),
        function: "DrawPrimitive".into(),
        total_attempts: 1,
        success_strategy: Some("direct".into()),
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    let snapshot = progress.snapshot().await;
    let entry = snapshot
        .get("game_logic.dll/DrawPrimitive")
        .expect("the in-flight unit is tracked");
    assert!(entry.finished, "the unit completes and is recorded");
    assert_eq!(
        progress.in_flight_count().await,
        0,
        "nothing is left running once the boundary unit is done"
    );

    // The server's side: the accept loop exits gracefully — subsequent
    // connections are refused.
    server
        .await
        .expect("server task exits after graceful shutdown");
    let after = reqwest::get(format!(
        "http://127.0.0.1:{}/api/server/status",
        fixture.port()
    ))
    .await;
    assert!(after.is_err(), "server must stop accepting requests");
}

/// `POST /api/server/restart` returns the manual-restart signal and stops
/// the process — no forking, the operator restarts the command.
#[tokio::test]
async fn test_server_restart_returns_manual_restart_signal() {
    let fixture = TestFixture::new();
    let stop = calxgloss_types::StopSignal::new();
    let state = ServerState::new(fixture.repo_path()).with_stop_signal(stop.clone());
    let router = build_router(state.clone());
    let server = spawn_server_with_shutdown(&state, router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let resp = reqwest::Client::new()
        .post(format!(
            "http://127.0.0.1:{}/api/server/restart",
            fixture.port()
        ))
        .send()
        .await
        .expect("restart request succeeds");

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("body is JSON");
    assert_eq!(body["status"], "stopping");
    assert_eq!(
        body["restart_required"], true,
        "restart must signal manual restart"
    );
    let message = body["message"].as_str().unwrap_or_default();
    assert!(
        message.to_lowercase().contains("restart"),
        "message must tell the operator how to restart, got: {message}"
    );
    assert!(
        stop.is_stopped(),
        "the pipeline must be paused at a boundary"
    );

    server
        .await
        .expect("server task exits after graceful shutdown");
}

/// `PATCH /api/server/log-level`: an invalid level name is rejected with
/// 400, a valid name becomes the level reported by `/api/server/status`
/// for this process only, and a server without a reloadable filter honestly
/// reports 503 instead of pretending to change verbosity.
#[tokio::test]
async fn test_server_log_level_patch_validates_and_updates() {
    let fixture = TestFixture::new();
    // Reload handle without installing the layer globally — the endpoint
    // only needs the handle to reload the filter.
    let (_filter, handle) =
        tracing_subscriber::reload::Layer::new(tracing_subscriber::EnvFilter::new("warn"));
    let state = ServerState::new(fixture.repo_path())
        .with_log_level("warn")
        .with_log_filter(calxgloss_web::LogLevelControl::new(handle));
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{}/api/server/log-level", fixture.port());

    // Invalid names → 4xx, and the active level is unchanged.
    for bad in ["verbose", "everything", ""] {
        let resp = client
            .patch(&url)
            .json(&serde_json::json!({ "level": bad }))
            .send()
            .await
            .expect("patch request succeeds");
        assert!(
            resp.status().is_client_error(),
            "invalid level '{bad}' must be rejected with 4xx, got {}",
            resp.status()
        );
    }

    // Valid name (case-insensitive) → 200 with the normalized level…
    let resp = client
        .patch(&url)
        .json(&serde_json::json!({ "level": "DEBUG" }))
        .send()
        .await
        .expect("patch request succeeds");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("body is JSON");
    assert_eq!(body["level"], "debug");

    // …and the status endpoint now reports it.
    let resp = reqwest::get(format!(
        "http://127.0.0.1:{}/api/server/status",
        fixture.port()
    ))
    .await
    .expect("status request succeeds");
    let body: serde_json::Value = resp.json().await.expect("status body is JSON");
    assert_eq!(body["log_level"], "debug");

    // A server with no reloadable filter attached must not pretend.
    let bare_fixture = TestFixture::new();
    let bare_port = TestFixture::find_free_port();
    let bare_router = build_router(ServerState::new(bare_fixture.repo_path()));
    let _bare_server = spawn_server(bare_router, bare_port).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let resp = client
        .patch(format!(
            "http://127.0.0.1:{}/api/server/log-level",
            bare_port
        ))
        .json(&serde_json::json!({ "level": "debug" }))
        .send()
        .await
        .expect("patch request succeeds");
    assert_eq!(
        resp.status(),
        503,
        "no filter attached must report 503, not a silent success"
    );
}

/// With the CLI-style reloadable filter installed, a valid PATCH changes
/// the verbosity of the running process: a `debug!` record invisible before
/// the change is emitted after it.
#[tokio::test]
async fn test_log_level_patch_changes_running_filter() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tracing_subscriber::layer::SubscriberExt;

    // The reloadable EnvFilter the CLI's logging init installs, plus a
    // counting layer to observe what the filter lets through. `reload::Layer`
    // is not `Clone`, so this subscriber cannot be re-installed per probe with
    // `with_default` — it goes global instead. Nothing else in this binary
    // asserts on log output, and the counting layer ignores every record but
    // the probe marker, so the install stays contained.
    let (filter, handle) =
        tracing_subscriber::reload::Layer::new(tracing_subscriber::EnvFilter::new("warn"));
    let seen = Arc::new(AtomicUsize::new(0));
    let subscriber = tracing_subscriber::registry()
        .with(filter)
        .with(ProbeCountingLayer(seen.clone()));
    tracing::subscriber::set_global_default(subscriber).expect("install global subscriber");

    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path())
        .with_log_level("warn")
        .with_log_filter(calxgloss_web::LogLevelControl::new(handle));
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    tracing::debug!("log-level-probe");
    assert_eq!(
        seen.load(Ordering::SeqCst),
        0,
        "debug records must be filtered out at warn"
    );

    let resp = reqwest::Client::new()
        .patch(format!(
            "http://127.0.0.1:{}/api/server/log-level",
            fixture.port()
        ))
        .json(&serde_json::json!({ "level": "debug" }))
        .send()
        .await
        .expect("patch request succeeds");
    assert_eq!(resp.status(), 200);

    tracing::debug!("log-level-probe");
    assert_eq!(
        seen.load(Ordering::SeqCst),
        1,
        "the running process must emit debug records after the change"
    );
}

/// The lifecycle endpoints are registered in **all three** routers —
/// plain `serve`, actions, and live.
#[tokio::test]
async fn test_lifecycle_endpoints_registered_in_all_routers() {
    // Reload layers kept alive for the test's duration — a reload handle
    // errors once its layer is dropped.
    let (layer_a, handle_a) =
        tracing_subscriber::reload::Layer::new(tracing_subscriber::EnvFilter::new("info"));
    let (layer_b, handle_b) =
        tracing_subscriber::reload::Layer::new(tracing_subscriber::EnvFilter::new("info"));
    let (layer_c, handle_c) =
        tracing_subscriber::reload::Layer::new(tracing_subscriber::EnvFilter::new("info"));
    let _layers = [layer_a, layer_b, layer_c];

    let routers: Vec<(&str, axum::Router)> = vec![
        ("plain", {
            let fixture = TestFixture::new();
            build_router(
                ServerState::new(fixture.repo_path())
                    .with_log_filter(calxgloss_web::LogLevelControl::new(handle_a)),
            )
        }),
        ("actions", {
            let fixture = TestFixture::new();
            let actions = ActionsState::new(fixture.repo_path(), PipelineSpec::default());
            build_router_with_actions(
                ServerState::new(fixture.repo_path())
                    .with_log_filter(calxgloss_web::LogLevelControl::new(handle_b)),
                actions,
            )
        }),
        ("live", {
            let fixture = TestFixture::new();
            let (manager, _tx) = SessionManager::new();
            build_router_with_ws(
                ServerState::new(fixture.repo_path())
                    .with_log_filter(calxgloss_web::LogLevelControl::new(handle_c)),
                manager,
                ProgressState::new(),
                ws_actions(&fixture),
            )
        }),
    ];

    for (name, router) in routers {
        let port = TestFixture::find_free_port();
        let _server = spawn_server(router, port).await;
        tokio::time::sleep(Duration::from_millis(200)).await;

        let client = reqwest::Client::new();

        let resp = client
            .patch(format!("http://127.0.0.1:{port}/api/server/log-level"))
            .json(&serde_json::json!({ "level": "info" }))
            .send()
            .await
            .expect("log-level patch reaches the router");
        assert_eq!(
            resp.status(),
            200,
            "log-level must be registered in the {name} router"
        );

        for path in ["/api/server/shutdown", "/api/server/restart"] {
            let resp = client
                .post(format!("http://127.0.0.1:{port}{path}"))
                .send()
                .await
                .expect("lifecycle post reaches the router");
            assert_eq!(
                resp.status(),
                200,
                "{path} must be registered in the {name} router"
            );
        }
    }
}

/// Verify that the dashboard endpoint returns valid JSON with
/// the expected units, status counts, and dependency graph.
#[tokio::test]
async fn test_dashboard_endpoint() {
    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let resp = reqwest::get(format!("http://127.0.0.1:{}/api/dashboard", fixture.port()))
        .await
        .expect("dashboard request succeeds");

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("dashboard body is JSON");

    // Top-level shape
    assert_eq!(body["success"], true);
    let queue_meta = body["queue_metadata"]
        .as_object()
        .expect("queue_metadata is object");
    assert!(queue_meta["total"].as_u64().unwrap() >= 1);

    let dashboard = body["dashboard"].as_object().expect("dashboard is object");
    let queue = dashboard["review_queue"]
        .as_array()
        .expect("review_queue is array");
    // At least 1 unit in queue (DrawPrimitive v2)
    assert!(
        !queue.is_empty(),
        "at least 1 unit in queue, got {}",
        queue.len()
    );

    // Verify we have the expected units by checking the IDs.
    let unit_ids: Vec<&str> = queue.iter().filter_map(|u| u["id"].as_str()).collect();
    // DrawPrimitive v2 is in the review queue (v1 was merged/accepted)
    assert!(
        unit_ids
            .iter()
            .any(|id| id.contains("game_logic.dll") && id.contains("DrawPrimitive")),
        "DrawPrimitive v2 unit present in queue (IDs: {:?})",
        unit_ids
    );

    // All units (review_queue + recent_activity) should include UpdateScene
    let all_ids: Vec<String> = {
        let review: Vec<String> = queue
            .iter()
            .filter_map(|u| u["id"].as_str())
            .map(|s| s.to_string())
            .collect();
        let recent: Vec<String> = body["dashboard"]
            .get("recent_activity")
            .and_then(|a| a.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|u| u["id"].as_str())
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        [review, recent].concat()
    };
    assert!(
        all_ids
            .iter()
            .any(|id| id.contains("game_logic.dll") && id.contains("UpdateScene")),
        "UpdateScene unit present in dashboard (all: {:?})",
        all_ids
    );

    // Check status counts
    let counts = dashboard["status_counts"]
        .as_object()
        .expect("status_counts is object");
    assert!(counts["accepted"].as_u64().unwrap_or(0) >= 2); // classifications accepted
    assert!(counts["accepted"].as_u64().unwrap_or(0) >= 5); // + DrawPrimitive v1 + UpdateScene + shim (merged branches count as accepted)
}

// ── Test: Dashboard summary data (issue #66) ───────────────────────────

/// Issue #67: baseline artifacts under `re/baseline/{file}/{func}/` must
/// reach the dashboard units — the review queue's baseline columns and the
/// quality summary both join on the verbatim `{file}/{func}` key.
#[tokio::test]
async fn test_dashboard_baseline_counts_attached() {
    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let resp = reqwest::get(format!("http://127.0.0.1:{}/api/dashboard", fixture.port()))
        .await
        .expect("dashboard request succeeds");
    assert_eq!(resp.status(), 200);
    let json: serde_json::Value = resp.json().await.expect("dashboard body is JSON");

    let all_units: Vec<serde_json::Value> = [
        json["dashboard"]["review_queue"]
            .as_array()
            .cloned()
            .unwrap_or_default(),
        json["dashboard"]["recent_activity"]
            .as_array()
            .cloned()
            .unwrap_or_default(),
    ]
    .concat();
    let unit = |id: &str| -> serde_json::Value {
        all_units
            .iter()
            .find(|u| u["id"] == id)
            .cloned()
            .unwrap_or_else(|| panic!("unit {id} present in dashboard payload"))
    };

    let draw = unit("game_logic.dll/DrawPrimitive/v2");
    assert_eq!(
        draw["baseline_tests_passed"].as_u64(),
        Some(3),
        "DrawPrimitive carries its 3 passing baseline tests"
    );
    assert_eq!(draw["baseline_tests_total"].as_u64(), Some(3));

    let update = unit("game_logic.dll/UpdateScene/v1");
    assert_eq!(update["baseline_tests_passed"].as_u64(), Some(1));
    assert_eq!(update["baseline_tests_total"].as_u64(), Some(1));
}

#[tokio::test]
async fn test_dashboard_binary_categories() {
    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let resp = reqwest::get(format!("http://127.0.0.1:{}/api/dashboard", fixture.port()))
        .await
        .expect("dashboard request succeeds");
    assert_eq!(resp.status(), 200);
    let json: serde_json::Value = resp.json().await.expect("dashboard body is JSON");

    // The fixture classifies game_logic.dll.json as ProjectSpecific and
    // d3d9.dll.json as MicrosoftSdk; every category is listed, even at zero.
    let count = |name: &str| {
        json["binary_categories"]
            .as_array()
            .expect("binary_categories is an array")
            .iter()
            .find(|c| c["category"] == name)
            .map(|c| c["count"].as_u64())
    };
    assert_eq!(count("ProjectSpecific"), Some(Some(1)));
    assert_eq!(count("MicrosoftSdk"), Some(Some(1)));
    assert_eq!(count("WindowsOs"), Some(Some(0)));
    assert_eq!(count("KnownThirdParty"), Some(Some(0)));
    assert_eq!(count("UnknownThirdParty"), Some(Some(0)));
    assert_eq!(count("RuntimeLibrary"), Some(Some(0)));
    assert_eq!(count("DotNetManaged"), Some(Some(0)));
}

#[tokio::test]
async fn test_dashboard_quality_summary() {
    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let resp = reqwest::get(format!("http://127.0.0.1:{}/api/dashboard", fixture.port()))
        .await
        .expect("dashboard request succeeds");
    assert_eq!(resp.status(), 200);
    let json: serde_json::Value = resp.json().await.expect("dashboard body is JSON");

    // Fixture unit confidences: 0.5, 0.5 (DrawPrimitive v1/v2), 0.95, 0.95
    // (classify) → average 0.725. Baseline counts reach the units (issue #67):
    // DrawPrimitive v1 and v2 each have the 3/3 baseline artifact and
    // UpdateScene 1/1 → weighted pass rate 7/7. No unit has verification
    // test data → that rate stays null, not a fabricated zero. (The weighted
    // pass-rate math itself is covered by the summary module's unit tests.)
    let qs = &json["quality_summary"];
    let avg = qs["avg_unit_confidence"]
        .as_f64()
        .expect("avg_unit_confidence is a number");
    assert!(
        (avg - 0.725).abs() < 0.01,
        "avg_unit_confidence should be ~0.725, got {}",
        avg
    );
    let rate = qs["baseline_pass_rate"]
        .as_f64()
        .expect("baseline_pass_rate is a number once units carry baseline data");
    assert!(
        (rate - 1.0).abs() < 0.01,
        "baseline_pass_rate should be ~1.0 (7/7 baseline tests), got {}",
        rate
    );
    assert!(
        qs["verification_pass_rate"].is_null(),
        "verification_pass_rate should be null when no unit has verification data"
    );
}

#[tokio::test]
async fn test_dashboard_token_usage_summary() {
    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    // No token log yet → token_usage is null, not zeros.
    let resp = reqwest::get(format!("http://127.0.0.1:{}/api/dashboard", fixture.port()))
        .await
        .expect("dashboard request succeeds");
    let json: serde_json::Value = resp.json().await.expect("dashboard body is JSON");
    assert!(
        json["token_usage"].is_null(),
        "token_usage should be null when no log exists"
    );

    // write_token_usage_log: attempt 1 failed (4096 tokens), attempt 2
    // succeeded (3072 tokens) → total 7168 across 2 calls.
    write_token_usage_log(&fixture, false);
    let resp = reqwest::get(format!("http://127.0.0.1:{}/api/dashboard", fixture.port()))
        .await
        .expect("dashboard request succeeds");
    let json: serde_json::Value = resp.json().await.expect("dashboard body is JSON");
    let tu = &json["token_usage"];
    assert_eq!(tu["total_tokens"].as_u64(), Some(7168));
    assert_eq!(tu["successful_tokens"].as_u64(), Some(3072));
    assert_eq!(tu["failed_tokens"].as_u64(), Some(4096));
    assert_eq!(tu["calls"].as_u64(), Some(2));
}

/// Verify that a single unit detail endpoint returns expected fields.
#[tokio::test]
async fn test_unit_detail_endpoint() {
    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let unit_id = "game_logic.dll/DrawPrimitive/v2";
    let encoded_id = urlencoding::encode(unit_id);
    let resp = reqwest::get(format!(
        "http://127.0.0.1:{}/api/units/{}",
        fixture.port(),
        encoded_id
    ))
    .await
    .expect("unit detail request succeeds");

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("unit detail body is JSON");
    assert_eq!(body["success"], true);

    let unit = body["unit"].as_object().expect("unit is object");
    assert_eq!(unit["id"], unit_id);
    assert_eq!(unit["binary"], "game_logic.dll");
    assert_eq!(unit["function"], "DrawPrimitive");
    assert_eq!(unit["attempt"].as_u64(), Some(2));
    let history = unit["attempt_history"]
        .as_array()
        .expect("attempt_history is array");
    assert!(
        history.len() >= 2,
        "at least 2 attempts in history, got {}",
        history.len()
    );

    // Diff summary should exist
    let diff = unit["diff_summary"]
        .as_object()
        .expect("diff_summary is object");
    assert!(diff["files_changed"].as_u64().unwrap_or(0) >= 1);
}

/// Verify that the queue endpoint returns units sorted by dependency order.
#[tokio::test]
async fn test_queue_endpoint() {
    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let resp = reqwest::get(format!("http://127.0.0.1:{}/api/queue", fixture.port()))
        .await
        .expect("queue request succeeds");

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("queue body is JSON");

    let queue = body["queue"].as_array().expect("queue is array");
    assert!(!queue.is_empty());

    let first = &queue[0];
    assert!(first["id"].as_str().is_some(), "queue entry has an id");
}

/// The overlay endpoints round-trip: an empty overlay degrades to pure
/// dependency order, a PUT persists priorities and order, and a fresh
/// router over the same repo (a server restart) reads them back.
#[tokio::test]
async fn test_queue_overlay_round_trip_and_persistence() {
    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;
    let base = format!("http://127.0.0.1:{}", fixture.port());

    // No overlay yet: empty, but the effective order is still computed.
    let resp = reqwest::get(format!("{base}/api/queue/overlay"))
        .await
        .expect("overlay request succeeds");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("overlay body is JSON");
    assert_eq!(body["success"], true);
    assert!(
        body["overlay"]["order"].as_array().unwrap().is_empty(),
        "no manual order recorded yet"
    );
    assert!(
        !body["queue_order"].as_array().unwrap().is_empty(),
        "effective order exists without an overlay"
    );

    // Record a manual order and a priority.
    let client = reqwest::Client::new();
    let resp = client
        .put(format!("{base}/api/queue/overlay"))
        .json(&serde_json::json!({
            "order": ["game_logic.dll/DrawPrimitive/v2"],
            "priorities": { "game_logic.dll/DrawPrimitive/v2": "high" },
        }))
        .send()
        .await
        .expect("overlay put succeeds");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("overlay put body is JSON");
    assert_eq!(
        body["overlay"]["priorities"]["game_logic.dll/DrawPrimitive/v2"],
        "high"
    );

    // The overlay lives in the repo, beside the other review records.
    let overlay_file = fixture
        .repo_path()
        .join("re")
        .join("review")
        .join("queue_overlay.json");
    assert!(
        overlay_file.exists(),
        "overlay persisted to re/review/queue_overlay.json"
    );

    // A fresh router over the same repo — a server restart — reads it back.
    let restart_port = TestFixture::find_free_port();
    let restart_state = ServerState::new(fixture.repo_path());
    let restart_router = build_router(restart_state);
    let _restart_server = spawn_server(restart_router, restart_port).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    let resp = reqwest::get(format!("http://127.0.0.1:{restart_port}/api/queue/overlay"))
        .await
        .expect("overlay request after restart succeeds");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("restart overlay is JSON");
    assert_eq!(
        body["overlay"]["priorities"]["game_logic.dll/DrawPrimitive/v2"], "high",
        "priority survives a server restart"
    );
    assert_eq!(
        body["overlay"]["order"],
        serde_json::json!(["game_logic.dll/DrawPrimitive/v2"]),
        "manual order survives a server restart"
    );

    // The dashboard response includes the overlay and the effective order.
    let resp = reqwest::get(format!("http://127.0.0.1:{restart_port}/api/dashboard"))
        .await
        .expect("dashboard request succeeds");
    let body: serde_json::Value = resp.json().await.expect("dashboard body is JSON");
    assert_eq!(
        body["queue_overlay"]["priorities"]["game_logic.dll/DrawPrimitive/v2"], "high",
        "dashboard carries the persisted overlay"
    );
    assert!(
        body["queue_order"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("game_logic.dll/DrawPrimitive/v2")),
        "dashboard carries the effective queue order"
    );
}

/// The overlay breaks ties between same-depth units in `/api/queue`, and an
/// invalid priority name is rejected.
#[tokio::test]
async fn test_queue_overlay_breaks_ties_in_queue_endpoint() {
    let fixture = TestFixture::new();
    add_pending_translation(&fixture, "RenderHUD");
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;
    let base = format!("http://127.0.0.1:{}", fixture.port());
    let client = reqwest::Client::new();

    let queue_ids = || async {
        let resp = reqwest::get(format!("{base}/api/queue"))
            .await
            .expect("queue request succeeds");
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.expect("queue body is JSON");
        body["queue"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["id"].as_str().unwrap().to_string())
            .collect::<Vec<String>>()
    };

    let draw = "game_logic.dll/DrawPrimitive/v2";
    let hud = "game_logic.dll/RenderHUD/v1";

    // Both units depend on the same classification, so the graph leaves
    // them tied; the baseline order is the dependency order's own tie-break.
    let ids = queue_ids().await;
    assert!(ids.iter().any(|id| id == draw), "DrawPrimitive queued");
    assert!(ids.iter().any(|id| id == hud), "RenderHUD queued");

    // A manual order flips the tie.
    let resp = client
        .put(format!("{base}/api/queue/overlay"))
        .json(&serde_json::json!({ "order": [hud, draw] }))
        .send()
        .await
        .expect("overlay put succeeds");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("overlay put body is JSON");
    let order = body["queue_order"].as_array().unwrap();
    let hud_at_new = order
        .iter()
        .position(|id| id == hud)
        .expect("RenderHUD ordered");
    let draw_at_new = order
        .iter()
        .position(|id| id == draw)
        .expect("DrawPrimitive ordered");
    assert!(
        hud_at_new < draw_at_new,
        "manual order puts RenderHUD first, got {order:?}"
    );

    let ids = queue_ids().await;
    let hud_at = ids
        .iter()
        .position(|id| id == hud)
        .expect("RenderHUD queued");
    let draw_at = ids
        .iter()
        .position(|id| id == draw)
        .expect("DrawPrimitive queued");
    assert!(hud_at < draw_at, "/api/queue follows the manual order");

    // The "next unit" flow follows the same effective order.
    let resp = reqwest::get(format!("{base}/api/queue/next"))
        .await
        .expect("next request succeeds");
    let body: serde_json::Value = resp.json().await.expect("next body is JSON");
    assert_eq!(
        body["id"].as_str(),
        Some(hud),
        "/api/queue/next follows the manual order"
    );

    // A priority flips it back without touching the manual order.
    let resp = client
        .put(format!("{base}/api/queue/overlay"))
        .json(&serde_json::json!({
            "priorities": { "game_logic.dll/DrawPrimitive/v2": "high" },
        }))
        .send()
        .await
        .expect("priority put succeeds");
    assert_eq!(resp.status(), 200);
    let ids = queue_ids().await;
    let hud_at = ids
        .iter()
        .position(|id| id == hud)
        .expect("RenderHUD queued");
    let draw_at = ids
        .iter()
        .position(|id| id == draw)
        .expect("DrawPrimitive queued");
    assert!(draw_at < hud_at, "HIGH priority sorts first, got {ids:?}");

    let resp = reqwest::get(format!("{base}/api/queue/next"))
        .await
        .expect("next request succeeds");
    let body: serde_json::Value = resp.json().await.expect("next body is JSON");
    assert_eq!(
        body["id"].as_str(),
        Some(draw),
        "/api/queue/next follows the HIGH priority"
    );

    // The order field was untouched by the priorities-only update.
    let resp = reqwest::get(format!("{base}/api/queue/overlay"))
        .await
        .expect("overlay request succeeds");
    let body: serde_json::Value = resp.json().await.expect("overlay body is JSON");
    assert_eq!(
        body["overlay"]["order"],
        serde_json::json!([hud, draw]),
        "priorities-only update keeps the persisted order"
    );

    // An unknown priority name is rejected, not silently accepted.
    let resp = client
        .put(format!("{base}/api/queue/overlay"))
        .json(&serde_json::json!({ "priorities": { hud: "urgent" } }))
        .send()
        .await
        .expect("invalid priority put request");
    assert!(
        resp.status().is_client_error(),
        "invalid priority rejected, got {}",
        resp.status()
    );
}

/// Skip state round-trips through the API (issue #75): skipping a unit
/// moves it to `Skipped` in the dashboard, excludes it from `/api/queue`
/// and `/api/queue/next`, and persists to `re/review/skips.json`;
/// unskipping restores its artifact-derived status. Accepted units refuse
/// the skip with 409.
#[tokio::test]
async fn test_skip_unit_round_trip_and_queue_exclusion() {
    let fixture = TestFixture::new();
    add_pending_translation(&fixture, "RenderHUD");
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;
    let base = format!("http://127.0.0.1:{}", fixture.port());
    let client = reqwest::Client::new();

    let draw = "game_logic.dll/DrawPrimitive/v2";
    let hud = "game_logic.dll/RenderHUD/v1";
    let draw_enc = urlencoding::encode(draw);
    let accepted = "game_logic.dll/UpdateScene/v1";

    let queue_ids = || async {
        let resp = reqwest::get(format!("{base}/api/queue"))
            .await
            .expect("queue request succeeds");
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.expect("queue body is JSON");
        body["queue"]
            .as_array()
            .expect("queue is an array")
            .iter()
            .map(|e| e["id"].as_str().expect("queue entry has an id").to_string())
            .collect::<Vec<String>>()
    };

    // Both units start in the active queue.
    let ids = queue_ids().await;
    assert!(ids.iter().any(|id| id == draw), "DrawPrimitive queued");
    assert!(ids.iter().any(|id| id == hud), "RenderHUD queued");

    // Skip DrawPrimitive.
    let resp = client
        .post(format!("{base}/api/units/{draw_enc}/skip"))
        .send()
        .await
        .expect("skip request succeeds");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("skip body is JSON");
    assert_eq!(body["action"], "skip");
    assert_eq!(body["unit_id"], draw);

    // The dashboard reports it Skipped and tallies it separately.
    let resp = reqwest::get(format!("{base}/api/dashboard"))
        .await
        .expect("dashboard request succeeds");
    let body: serde_json::Value = resp.json().await.expect("dashboard body is JSON");
    let skipped_unit = body["dashboard"]["review_queue"]
        .as_array()
        .expect("review_queue is an array")
        .iter()
        .find(|u| u["id"] == draw)
        .expect("skipped unit stays in the review queue");
    assert_eq!(
        skipped_unit["status"], "Skipped",
        "skipped unit reports Skipped"
    );
    assert_eq!(
        body["dashboard"]["status_counts"]["skipped"].as_u64(),
        Some(1),
        "status counts tally the skipped unit"
    );

    // It leaves the dependency-ordered queue and can never be the next unit.
    let ids = queue_ids().await;
    assert!(
        !ids.iter().any(|id| id == draw),
        "skipped unit excluded from /api/queue, got {ids:?}"
    );
    let resp = reqwest::get(format!("{base}/api/queue/next"))
        .await
        .expect("next request succeeds");
    let body: serde_json::Value = resp.json().await.expect("next body is JSON");
    assert_ne!(
        body["id"].as_str(),
        Some(draw),
        "skipped unit is never the next unit"
    );

    // The skip set lives in the repo, beside the other review records.
    let skips_file = fixture
        .repo_path()
        .join("re")
        .join("review")
        .join("skips.json");
    let raw = std::fs::read_to_string(&skips_file).expect("skips persisted");
    let value: serde_json::Value = serde_json::from_str(&raw).expect("skips is JSON");
    assert_eq!(value["skipped"], serde_json::json!([draw]));

    // An accepted unit refuses the skip — merged branch state is
    // authoritative.
    let resp = client
        .post(format!(
            "{base}/api/units/{}/skip",
            urlencoding::encode(accepted)
        ))
        .send()
        .await
        .expect("skip-accepted request succeeds");
    assert_eq!(resp.status(), 409, "skipping an accepted unit conflicts");

    // An unknown unit is a 404.
    let resp = client
        .post(format!(
            "{base}/api/units/{}/skip",
            urlencoding::encode("nope/nope/v1")
        ))
        .send()
        .await
        .expect("skip-unknown request succeeds");
    assert_eq!(resp.status(), 404);

    // Unskip restores the artifact-derived status and the queue position.
    let resp = client
        .post(format!("{base}/api/units/{draw_enc}/unskip"))
        .send()
        .await
        .expect("unskip request succeeds");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("unskip body is JSON");
    assert_eq!(body["action"], "unskip");

    let ids = queue_ids().await;
    assert!(
        ids.iter().any(|id| id == draw),
        "unskipped unit is back in /api/queue"
    );
    let resp = reqwest::get(format!("{base}/api/dashboard"))
        .await
        .expect("dashboard request succeeds");
    let body: serde_json::Value = resp.json().await.expect("dashboard body is JSON");
    assert_eq!(
        body["dashboard"]["status_counts"]["skipped"].as_u64(),
        Some(0),
        "unskipped unit leaves the skipped tally"
    );
    let restored = body["dashboard"]["review_queue"]
        .as_array()
        .expect("review_queue is an array")
        .iter()
        .find(|u| u["id"] == draw)
        .expect("unit still in the review queue");
    assert_ne!(
        restored["status"], "Skipped",
        "status restored after unskip"
    );
}

/// Batch review actions (issue #78): `POST /api/batch/{skip,accept,send-back}`
/// apply the per-unit action logic to every requested unit and report
/// per-item results in request order — a failing unit (unknown id, already
/// accepted) is recorded as a failure while the rest of the batch lands,
/// with the same persistence and conflict rules as the single-unit endpoints.
#[tokio::test]
async fn test_batch_actions_report_per_item_results() {
    let fixture = TestFixture::new();
    add_pending_translation(&fixture, "RenderHUD");
    add_pending_translation(&fixture, "PlaySound");
    let state = ServerState::new(fixture.repo_path());
    let actions = ActionsState::new(fixture.repo_path(), PipelineSpec::default());
    let router = build_router_with_actions(state.clone(), actions);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;
    let base = format!("http://127.0.0.1:{}", fixture.port());
    let client = reqwest::Client::new();

    let hud = "game_logic.dll/RenderHUD/v1";
    let sound = "game_logic.dll/PlaySound/v1";
    let ghost = "game_logic.dll/NoSuchFunction/v1";
    let sound_enc = urlencoding::encode(sound);

    async fn post_batch(
        base: &str,
        client: &reqwest::Client,
        path: &str,
        body: serde_json::Value,
    ) -> (reqwest::StatusCode, serde_json::Value) {
        let resp = client
            .post(format!("{base}{path}"))
            .json(&body)
            .send()
            .await
            .expect("batch request succeeds");
        let status = resp.status();
        let body: serde_json::Value = resp.json().await.expect("batch body is JSON");
        (status, body)
    }

    // An empty selection is a client error, not an honest no-op.
    let (status, _) = post_batch(
        &base,
        &client,
        "/api/batch/skip",
        serde_json::json!({ "unit_ids": [] }),
    )
    .await;
    assert_eq!(status, 400, "empty batch selection is rejected");

    // Batch skip: both real units land, the unknown one fails per-item.
    let (status, body) = post_batch(
        &base,
        &client,
        "/api/batch/skip",
        serde_json::json!({ "unit_ids": [hud, ghost, sound] }),
    )
    .await;
    assert_eq!(
        status, 200,
        "partial failure still answers 200 with results"
    );
    assert_eq!(body["action"], "skip");
    assert_eq!(
        body["success"], false,
        "one unit failed, so not all succeeded"
    );
    assert_eq!(body["succeeded"], 2);
    assert_eq!(body["failed"], 1);
    let results = body["results"].as_array().expect("results is an array");
    assert_eq!(results.len(), 3, "one result per requested unit");
    assert_eq!(results[0]["unit_id"], hud);
    assert_eq!(results[0]["success"], true);
    assert_eq!(
        results[1]["unit_id"], ghost,
        "results keep the request order"
    );
    assert_eq!(results[1]["success"], false);
    assert!(
        results[1]["message"]
            .as_str()
            .is_some_and(|m| m.contains("not found")),
        "the failure names the reason: {}",
        results[1]["message"]
    );
    assert_eq!(results[2]["unit_id"], sound);
    assert_eq!(results[2]["success"], true);

    // The skips persisted through the per-unit skip logic (issue #75).
    let skips_file = fixture
        .repo_path()
        .join("re")
        .join("review")
        .join("skips.json");
    let raw = std::fs::read_to_string(&skips_file).expect("skips persisted");
    let value: serde_json::Value = serde_json::from_str(&raw).expect("skips is JSON");
    assert_eq!(value["skipped"], serde_json::json!([hud, sound]));

    // Batch accept: the real unit merges, the unknown one fails per-item.
    let (status, body) = post_batch(
        &base,
        &client,
        "/api/batch/accept",
        serde_json::json!({ "unit_ids": [hud, ghost] }),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body["action"], "accept");
    assert_eq!(body["succeeded"], 1);
    assert_eq!(body["failed"], 1);
    let git = GitManager::open(&fixture.repo_path()).expect("open fixture repo");
    assert!(
        git.is_branch_merged_into_main("re/game_logic.dll/RenderHUDv1")
            .expect("merged check"),
        "batch accept merged the unit's branch to main"
    );

    // Batch send-back reuses the per-unit conflict rules: the unit the batch
    // just accepted (persisted Accepted record) refuses the send-back.
    let (status, body) = post_batch(
        &base,
        &client,
        "/api/batch/send-back",
        serde_json::json!({ "unit_ids": [sound, hud], "reason": "batch review pass" }),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body["action"], "send_back");
    assert_eq!(body["succeeded"], 1);
    assert_eq!(body["failed"], 1);
    let results = body["results"].as_array().expect("results is an array");
    assert_eq!(results[0]["unit_id"], sound);
    assert_eq!(results[0]["success"], true);
    assert_eq!(results[1]["unit_id"], hud);
    assert_eq!(
        results[1]["success"], false,
        "an accepted unit refuses batch send-back, like per-unit"
    );
    assert!(
        results[1]["message"]
            .as_str()
            .is_some_and(|m| m.contains("accepted")),
        "the conflict names the landed state: {}",
        results[1]["message"]
    );

    // The dashboard reflects every landed action: RenderHUD stays accepted,
    // and PlaySound's send-back verdict is there once the skip is lifted —
    // the reviewer skip outranks artifact-derived verdicts (issue #75).
    let resp = client
        .post(format!("{base}/api/units/{sound_enc}/unskip"))
        .send()
        .await
        .expect("unskip request succeeds");
    assert_eq!(resp.status(), 200);
    let resp = reqwest::get(format!("{base}/api/dashboard"))
        .await
        .expect("dashboard request succeeds");
    let body: serde_json::Value = resp.json().await.expect("dashboard body is JSON");
    let status_of = |id: &str| {
        body["dashboard"]["review_queue"]
            .as_array()
            .expect("review_queue is an array")
            .iter()
            .chain(
                body["dashboard"]["recent_activity"]
                    .as_array()
                    .expect("recent_activity is an array")
                    .iter(),
            )
            .find(|u| u["id"] == id)
            .map(|u| u["status"].as_str().unwrap_or_default().to_string())
            .unwrap_or_default()
    };
    assert_eq!(status_of(hud), "Accepted");
    assert_eq!(status_of(sound), "SendBack");
}

/// Verify that the dependency graph endpoint returns valid graph data.
#[tokio::test]
async fn test_dependency_graph_endpoint() {
    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let resp = reqwest::get(format!("http://127.0.0.1:{}/api/graph", fixture.port()))
        .await
        .expect("graph request succeeds");

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("graph body is JSON");
    assert_eq!(body["success"], true);

    let graph = body["graph"].as_object().expect("graph is object");
    let nodes = graph["nodes"].as_array().expect("nodes is array");
    assert!(!nodes.is_empty(), "dependency graph has at least one node");

    let edges = graph["edges"].as_array().expect("edges is array");
    assert!(!edges.is_empty(), "dependency graph has at least one edge");

    // Verify node structure
    let first_node = &nodes[0];
    assert!(
        first_node["unit_id"].as_str().is_some(),
        "first node has unit_id: {:?}",
        first_node
    );
    assert!(first_node["name"].as_str().is_some());

    // Enrichment (issue #76): every fixture unit belongs to a binary, so
    // every node has one; edges record their relationship type.
    for node in nodes {
        assert!(
            node["binary"].as_str().is_some(),
            "graph node has binary: {:?}",
            node
        );
    }
    for edge in edges {
        assert!(
            edge["edge_type"].as_str().is_some(),
            "graph edge has edge_type: {:?}",
            edge
        );
    }
}

/// Issue #76: the graph endpoint enriches nodes with token usage joined from
/// `re/analysis/token_usage.json` (same binary + function join as the unit
/// detail), and leaves units with no recorded entries honestly `null`.
#[tokio::test]
async fn test_dependency_graph_token_usage_enrichment() {
    let fixture = TestFixture::new();

    let analysis_dir = fixture.repo_path().join("re").join("analysis");
    std::fs::create_dir_all(&analysis_dir).expect("create analysis dir");
    std::fs::write(
        analysis_dir.join("token_usage.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "entries": [
                {
                    "timestamp": 1767225600,
                    "binary": "game_logic.dll",
                    "function": "DrawPrimitive",
                    "attempt": 1,
                    "strategy": "initial",
                    "context_tier": "disassembly",
                    "tokens_used": 4096,
                    "success": false
                },
                {
                    "timestamp": 1767225900,
                    "binary": "game_logic.dll",
                    "function": "DrawPrimitive",
                    "attempt": 2,
                    "strategy": "compile_fix",
                    "context_tier": "with_tests",
                    "tokens_used": 3072,
                    "success": true
                }
            ]
        }))
        .expect("serialize token log"),
    )
    .expect("write token_usage.json");

    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let resp = reqwest::get(format!("http://127.0.0.1:{}/api/graph", fixture.port()))
        .await
        .expect("graph request succeeds");
    let body: serde_json::Value = resp.json().await.expect("graph body is JSON");
    let nodes = body["graph"]["nodes"].as_array().expect("nodes is array");

    let draw = nodes
        .iter()
        .find(|n| n["unit_id"].as_str() == Some("game_logic.dll/DrawPrimitive/v2"))
        .expect("DrawPrimitive node in graph");
    assert_eq!(
        draw["token_usage"], 7168,
        "DrawPrimitive node carries the summed token usage"
    );

    let update = nodes
        .iter()
        .find(|n| n["unit_id"].as_str() == Some("game_logic.dll/UpdateScene/v1"))
        .expect("UpdateScene node in graph");
    assert_eq!(
        update["token_usage"],
        serde_json::Value::Null,
        "unit with no usage entries stays null, not zero"
    );
}

/// Verify the frontend HTML page loads and contains expected content.
#[tokio::test]
async fn test_frontend_html_loads() {
    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let resp = reqwest::get(format!("http://127.0.0.1:{}", fixture.port()))
        .await
        .expect("index request succeeds");

    assert_eq!(resp.status(), 200);

    // Check content type
    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        content_type.contains("text/html"),
        "content-type should be text/html, got: {content_type}"
    );

    let html = resp.text().await.expect("index body is text");
    assert!(
        html.contains("<title>Calxgloss") || html.contains("Calxgloss — Review Dashboard"),
        "HTML should contain Calxgloss title (got title line with {} chars of content)",
        html.len()
    );
    assert!(
        html.contains("app.js") || html.contains("<script"),
        "HTML should reference JavaScript"
    );
    assert!(
        html.contains("app.css") || html.contains("<link"),
        "HTML should reference CSS"
    );
}

/// Test that a 404 is returned for an unknown unit ID.
#[tokio::test]
async fn test_unit_not_found() {
    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let resp = reqwest::get(format!(
        "http://127.0.0.1:{}/api/units/nonexistent/unit/v1",
        fixture.port()
    ))
    .await
    .expect("unit not found request succeeds");

    assert_eq!(resp.status(), 404);
}

/// Test that the queue/next endpoint returns a single pending unit.
#[tokio::test]
async fn test_next_unit_endpoint() {
    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let resp = reqwest::get(format!(
        "http://127.0.0.1:{}/api/queue/next",
        fixture.port()
    ))
    .await
    .expect("next unit request succeeds");

    assert_eq!(resp.status(), 200);

    let text = resp.text().await.expect("next unit body is text");
    if !text.is_empty() && text != "null" {
        let body: serde_json::Value = serde_json::from_str(&text).expect("next unit JSON is valid");
        assert!(body["id"].as_str().is_some(), "next unit should have an id");
    }
    // null response (empty queue) is also acceptable
}

/// Test that the pipeline progress endpoint returns empty data
/// when no translation is running — including the honest phase records
/// (issue #61): all 8 phases present, Restitching/Documentation always
/// `no_data_source` with no fabricated counts.
#[tokio::test]
async fn test_pipeline_empty_progress() {
    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path());
    let (manager, _event_tx) = SessionManager::new();
    let progress = ProgressState::new();
    let router = build_router_with_ws(state.clone(), manager, progress, ws_actions(&fixture));
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let resp = reqwest::get(format!("http://127.0.0.1:{}/api/pipeline", fixture.port()))
        .await
        .expect("pipeline request succeeds");

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("pipeline body is JSON");
    assert_eq!(body["total_dlls"].as_u64().unwrap_or(0), 0);

    let phases = body["phases"].as_array().expect("phases array is present");
    assert_eq!(phases.len(), 8, "all 8 pipeline phases are reported");
    let states: Vec<&str> = phases
        .iter()
        .map(|p| p["state"].as_str().unwrap_or("?"))
        .collect();
    assert_eq!(
        states,
        [
            "not_started",
            "not_started",
            "not_started",
            "not_started",
            "not_started",
            "not_started",
            "no_data_source",
            "no_data_source"
        ]
    );
    // NoDataSource phases must never carry fabricated counts.
    for p in &phases[6..8] {
        assert!(
            p.get("completed").is_none(),
            "no-data-source phase has no count: {p}"
        );
        assert!(
            p.get("total").is_none(),
            "no-data-source phase has no total: {p}"
        );
    }
    assert!(
        body["binaries"]
            .as_array()
            .expect("binaries array")
            .is_empty()
    );
}
