//! End-to-end tests for the web review UI.
//!
//! These tests spin up the axum server in a real git repository with sample data,
//! then verify both API responses and headless-browser rendering.
//!
//! Run API-level tests: `cargo test --features server --test e2e`
//! Run browser tests:   `cargo test --features server --test e2e headless -- --ignored`

use calxgloss_git::{GitManager, InitConfig};
use calxgloss_types::{
    GitBranch, PipelineControl, PipelineState, ProgressEvent, TestCase, TestResult,
    TranslationEvents, UnitCancellation,
};
use calxgloss_web::{
    ActionsState, LlmIoLog, ProgressState, ServerState, SessionManager, build_dashboard,
    build_router, build_router_with_actions, build_router_with_ws, serve_with_listener,
};
use std::net::TcpListener;
use std::path::PathBuf;
use std::time::Duration;

// ─────────────────────────────────────────────────────────────
// Test fixture setup
// ─────────────────────────────────────────────────────────────

/// A fixture that creates a temporary git repository with sample
/// translation data (branches, patches, baselines, classifications)
/// so the web server has real data to serve.
struct TestFixture {
    dir: tempfile::TempDir,
    port: u16,
}

impl TestFixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("create temp dir");
        let port = Self::find_free_port();

        // Initialise a bare-bones git repo with a README on `main`.
        let config = InitConfig {
            author_name: "Calxgloss Test".into(),
            author_email: "test@calxgloss.test".into(),
            committer_name: None,
            committer_email: None,
        };
        let git = GitManager::init_repo(dir.path(), Some(config)).expect("init git repo");

        // We need the working tree checked out to `main` so that
        // branches can be created with files on them.
        Self::create_sample_data(&git);

        Self { dir, port }
    }

    fn repo_path(&self) -> PathBuf {
        self.dir.path().to_path_buf()
    }

    fn port(&self) -> u16 {
        self.port
    }

    /// Finds a free TCP port by binding to port 0.
    fn find_free_port() -> u16 {
        TcpListener::bind("127.0.0.1:0")
            .expect("bind free port")
            .local_addr()
            .unwrap()
            .port()
    }

    /// Creates sample data that the DashboardBuilder understands:
    /// - A translation branch with a small file committed on it
    /// - A patch record (so the unit has attempt history)
    /// - A baseline file (so the unit has test data)
    /// - A classification JSON
    /// - A shim branch that's merged into main
    fn create_sample_data(git: &GitManager) {
        // 1. A classification record for `game_logic.dll`
        let classify_dir = git.repo_path().join("re").join("classify");
        std::fs::create_dir_all(&classify_dir).unwrap();
        std::fs::write(
            classify_dir.join("game_logic.dll.json"),
            serde_json::json!({
                "category": "ProjectSpecific",
                "strategy": "reverse_engineer",
                "exported_symbols": 24,
                "imported_symbols": 12
            })
            .to_string(),
        )
        .unwrap();

        // Also classify `d3d9.dll` as a crate-replacement target
        std::fs::write(
            classify_dir.join("d3d9.dll.json"),
            serde_json::json!({
                "category": "MicrosoftSdk",
                "strategy": "crate_replacement",
                "crate": "wgpu",
                "exported_symbols": 100,
                "imported_symbols": 5
            })
            .to_string(),
        )
        .unwrap();

        // 2. Create a shim branch `re/shim/wgpu` with a file and merge it into main.
        {
            let shim_branch = GitBranch::new("d3d9.dll", "wgpu", 1).unwrap();
            git.create_branch("d3d9.dll", "wgpu", 1, None).unwrap();

            let shim_file = "src/d3d9_shim.rs";
            std::fs::create_dir_all(git.repo_path().join("src")).unwrap();
            std::fs::write(
                git.repo_path().join(shim_file),
                "// wgpu shim layer for d3d9",
            )
            .unwrap();
            git.commit(&shim_branch, "Add d3d9 shim layer", &[shim_file])
                .unwrap();
            git.merge_to_main(&shim_branch).unwrap();
        }

        // 3. Create a PAL trait branch `re/pal/GraphicsDevice` and merge it.
        {
            let pal_branch = GitBranch::new("pal", "GraphicsDevice", 1).unwrap();
            git.create_branch("pal", "GraphicsDevice", 1, None).unwrap();

            let pal_file = "src/pal/graphics.rs";
            std::fs::create_dir_all(git.repo_path().join("src").join("pal")).unwrap();
            std::fs::write(
                git.repo_path().join(pal_file),
                "// GraphicsDevice PAL trait",
            )
            .unwrap();
            git.commit(&pal_branch, "Add GraphicsDevice PAL trait", &[pal_file])
                .unwrap();
            git.merge_to_main(&pal_branch).unwrap();
        }

        // 4. Create a translation branch `re/game_logic.dll/DrawPrimitivev1`
        //    with a Rust source file.
        {
            let branch = GitBranch::new("game_logic.dll", "DrawPrimitive", 1).unwrap();
            git.create_branch("game_logic.dll", "DrawPrimitive", 1, None)
                .unwrap();

            let src_file = "src/draw_primitive.rs";
            std::fs::create_dir_all(git.repo_path().join("src")).unwrap();
            std::fs::write(
                git.repo_path().join(src_file),
                r#"/// Translated DrawPrimitive function.
/// Maps DirectX9 DrawPrimitive to wgpu encoder.draw().
pub fn draw_primitive(encoder: &mut wgpu::CommandEncoder, _args: &[u8]) {
    // 47 assembly instructions → 12 lines of Rust
    let _ = encoder;
}
"#,
            )
            .unwrap();
            git.commit(&branch, "Translate DrawPrimitive to wgpu", &[src_file])
                .unwrap();
            git.merge_to_main(&branch).unwrap();

            // Create a v2 branch that failed (for attempt history)
            let branch_v2 = GitBranch::new("game_logic.dll", "DrawPrimitive", 2).unwrap();
            git.create_branch("game_logic.dll", "DrawPrimitive", 2, None)
                .unwrap();

            let src_file_v2 = "src/draw_primitive_v2.rs";
            std::fs::create_dir_all(git.repo_path().join("src")).ok();
            std::fs::write(
                git.repo_path().join(src_file_v2),
                r#"/// Attempt 2 — wrong shader constant mapping
pub fn draw_primitive_v2(_encoder: &mut wgpu::CommandEncoder) {
    // buggy implementation
}
"#,
            )
            .unwrap();
            git.commit(
                &branch_v2,
                "Retry DrawPrimitive — fix shader constants",
                &[src_file_v2],
            )
            .unwrap();
        }

        // 5. A second translation: `re/game_logic.dll/UpdateScenev1` (accepted/merged).
        {
            let branch = GitBranch::new("game_logic.dll", "UpdateScene", 1).unwrap();
            git.create_branch("game_logic.dll", "UpdateScene", 1, None)
                .unwrap();

            let src_file = "src/update_scene.rs";
            std::fs::write(
                git.repo_path().join(src_file),
                r#"/// UpdateScene — full translation
pub fn update_scene(world: &mut World) {
    world.update_physics();
    world.update_ai();
}
"#,
            )
            .unwrap();
            git.commit(&branch, "Translate UpdateScene", &[src_file])
                .unwrap();
            // Merge this one so it appears as "accepted"
            git.merge_to_main(&branch).unwrap();
        }

        // 6. Create a patch record for game_logic.dll/DrawPrimitive v1.
        let patch_dir = git
            .repo_path()
            .join("re")
            .join("patches")
            .join("game_logic.dll")
            .join("DrawPrimitive");
        std::fs::create_dir_all(&patch_dir).unwrap();
        let patch_record = serde_json::json!({
            "binary": "game_logic.dll",
            "function": "DrawPrimitive",
            "attempt": 1,
            "branch_name": "re/game_logic.dll/DrawPrimitivev1",
            "committed_at": "2025-09-28T10:00:00Z",
            "error_message": "",
            "compilation_errors": [],
            "test_failures": [],
            "commit_hash": "abc123"
        });
        std::fs::write(
            patch_dir.join("v1.json"),
            serde_json::to_string_pretty(&patch_record).unwrap(),
        )
        .unwrap();

        // Patch record for v2 (this one had compile errors).
        let patch_record_v2 = serde_json::json!({
            "binary": "game_logic.dll",
            "function": "DrawPrimitive",
            "attempt": 2,
            "branch_name": "re/game_logic.dll/DrawPrimitivev2",
            "committed_at": "2025-09-28T11:30:00Z",
            "error_message": "type mismatch in shader constant",
            "compilation_errors": ["mismatched types"],
            "test_failures": ["shader_constant_map_wrong"],
            "commit_hash": "def456"
        });
        std::fs::write(
            patch_dir.join("v2.json"),
            serde_json::to_string_pretty(&patch_record_v2).unwrap(),
        )
        .unwrap();

        // 7. Create baseline test data for DrawPrimitive — in the exact
        //    `Vec<TestResult>` shape `calxgloss-testgen` persists, so the
        //    dashboard's baseline readers parse it (issue #67).
        let baseline_dir = git
            .repo_path()
            .join("re")
            .join("baseline")
            .join("game_logic.dll")
            .join("DrawPrimitive");
        std::fs::create_dir_all(&baseline_dir).unwrap();
        let baseline: Vec<TestResult> = [
            (
                serde_json::json!({"vertices": [1,2,3], "index": 0}),
                serde_json::json!(0),
            ),
            (
                serde_json::json!({"vertices": [], "index": 0}),
                serde_json::json!(0),
            ),
            (
                serde_json::json!({"vertices": [99], "index": -1}),
                serde_json::json!(-1),
            ),
        ]
        .into_iter()
        .map(|(inputs, expected)| baseline_result(inputs, expected, true))
        .collect();
        std::fs::write(
            baseline_dir.join("baseline.json"),
            serde_json::to_string_pretty(&baseline).unwrap(),
        )
        .unwrap();

        // 8. Baseline for UpdateScene
        let baseline_us = git
            .repo_path()
            .join("re")
            .join("baseline")
            .join("game_logic.dll")
            .join("UpdateScene");
        std::fs::create_dir_all(&baseline_us).unwrap();
        let baseline_us_data = vec![baseline_result(
            serde_json::json!({"delta_time": 0.016}),
            serde_json::json!(0),
            true,
        )];
        std::fs::write(
            baseline_us.join("baseline.json"),
            serde_json::to_string_pretty(&baseline_us_data).unwrap(),
        )
        .unwrap();

        // Switch HEAD back to main so the server process works correctly.
        let main_ref = git
            .repo()
            .find_branch("main", git2::BranchType::Local)
            .expect("main branch exists");
        let main_commit = main_ref.get().peel_to_commit().expect("main commit");
        let mut checkout_opts = git2::build::CheckoutBuilder::new();
        checkout_opts.force();
        git.repo()
            .set_head("refs/heads/main")
            .expect("set head to main");
        git.repo()
            .reset(
                main_commit.as_object(),
                git2::ResetType::Hard,
                Some(&mut checkout_opts),
            )
            .expect("reset to main");
    }
}

// ─────────────────────────────────────────────────────────────
// Server helpers
// ─────────────────────────────────────────────────────────────

/// One baseline `TestResult` in the exact shape `calxgloss-testgen`
/// persists to `re/baseline/{file}/{func}/baseline.json` — the observed
/// return equals the expected one when the test passed — so every reader
/// of the artifact parses it (issue #67).
fn baseline_result(
    inputs: serde_json::Value,
    expected: serde_json::Value,
    passed: bool,
) -> TestResult {
    TestResult {
        test_case: TestCase {
            inputs,
            expected_return: expected.clone(),
            expected_side_effects: Vec::new(),
        },
        actual_return: expected,
        actual_side_effects: Vec::new(),
        passed,
        error: None,
    }
}

/// Start the axum server in a background task.
async fn spawn_server(router: axum::Router, port: u16) -> tokio::task::JoinHandle<()> {
    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{port}"))
        .await
        .expect("bind listener");
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    })
}

// ─────────────────────────────────────────────────────────────
// API-level tests (no browser needed)
// ─────────────────────────────────────────────────────────────

/// Verify that the health endpoint returns `{"status":"ok"}`.
#[tokio::test]
async fn test_health_endpoint() {
    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let resp = reqwest::get(format!("http://127.0.0.1:{}/health", fixture.port()))
        .await
        .expect("health request succeeds");

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("health body is JSON");
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
    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path());
    let (manager, _event_tx) = SessionManager::new();
    let progress = ProgressState::new();
    let router = build_router_with_ws(state, manager, progress);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let resp = reqwest::get(format!("http://127.0.0.1:{}/health", fixture.port()))
        .await
        .expect("health request succeeds");

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("health body is JSON");
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
    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path()).with_log_level("debug");
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let resp = reqwest::get(format!(
        "http://127.0.0.1:{}/api/server/status",
        fixture.port()
    ))
    .await
    .expect("server status request succeeds");

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("status body is JSON");

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
    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path());
    let events = TranslationEvents::new(128);
    let manager = SessionManager::new_with_broadcast(events.subscribe());
    let progress = ProgressState::new();
    let router = build_router_with_ws(state, manager.clone(), progress);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    // A live WebSocket session (registered through the same path the upgrade
    // handler uses) and an in-flight unit.
    let _handler = manager.register_client().await;
    events.emit(ProgressEvent::TranslationStarted {
        binary: "game_logic.dll".into(),
        function: "DrawPrimitive".into(),
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    let resp = reqwest::get(format!(
        "http://127.0.0.1:{}/api/server/status",
        fixture.port()
    ))
    .await
    .expect("server status request succeeds");

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("status body is JSON");

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
    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path());
    let (manager, _event_tx) = SessionManager::new();
    let progress = ProgressState::new();
    let router = build_router_with_ws(state, manager, progress);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let resp = reqwest::get(format!(
        "http://127.0.0.1:{}/api/server/status",
        fixture.port()
    ))
    .await
    .expect("server status request succeeds");

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("status body is JSON");
    assert_eq!(body["pipeline_status"], "idle");
    assert_eq!(body["ws_connections"], 0);
}

// ─────────────────────────────────────────────────────────────
// Pipeline lifecycle control (issue #90, W2.1)
// ─────────────────────────────────────────────────────────────

/// POST helper for the lifecycle endpoints (they take no body).
async fn post_lifecycle(port: u16, path: &str) -> (reqwest::StatusCode, serde_json::Value) {
    let resp = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{port}{path}"))
        .send()
        .await
        .expect("lifecycle request reaches server");
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.expect("lifecycle body is JSON");
    (status, body)
}

/// The live router's pause/resume/stop endpoints drive the shared
/// PipelineControl (issue #90): 200 with the transition in the body, 409
/// when the state machine refuses the operation, and `/api/server/status`
/// derived from the machine — "paused" even while a unit record is still
/// in flight, which the old in-flight-count inference could not tell apart.
#[tokio::test]
async fn test_pipeline_lifecycle_control_endpoints() {
    let fixture = TestFixture::new();
    let events = TranslationEvents::new(128);
    let control = PipelineControl::new().with_events(events.clone());
    control.start().expect("idle -> running");
    let state = ServerState::new(fixture.repo_path()).with_pipeline_control(control.clone());
    let manager = SessionManager::new_with_broadcast(events.subscribe());
    let progress = ProgressState::new();
    let router = build_router_with_ws(state, manager, progress);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    // A unit in flight — the point is that the reported status now follows
    // the state machine, not the in-flight count.
    events.emit(ProgressEvent::TranslationStarted {
        binary: "game_logic.dll".into(),
        function: "DrawPrimitive".into(),
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    let get_status = |port: u16| {
        let fixture_port = port;
        async move {
            let resp = reqwest::get(format!("http://127.0.0.1:{fixture_port}/api/server/status",))
                .await
                .expect("server status request succeeds");
            assert_eq!(resp.status(), 200);
            let body: serde_json::Value = resp.json().await.expect("status body is JSON");
            body["pipeline_status"]
                .as_str()
                .unwrap_or_default()
                .to_string()
        }
    };
    assert_eq!(get_status(fixture.port()).await, "running");

    // Pause: 200, body reports the transition.
    let (status, body) = post_lifecycle(fixture.port(), "/api/pipeline/pause").await;
    assert_eq!(status, 200);
    assert_eq!(body["previous"], "running");
    assert_eq!(body["state"], "paused");

    // Status follows the machine even with the unit record still in flight.
    assert_eq!(get_status(fixture.port()).await, "paused");

    // Double pause: the machine refuses — 409, not a silent no-op.
    let (status, body) = post_lifecycle(fixture.port(), "/api/pipeline/pause").await;
    assert_eq!(status, 409);
    assert!(
        body["message"]
            .as_str()
            .unwrap_or_default()
            .contains("cannot pause a pipeline that is paused"),
        "409 carries the machine's own message, got: {body}"
    );

    // Resume: back to running.
    let (status, body) = post_lifecycle(fixture.port(), "/api/pipeline/resume").await;
    assert_eq!(status, 200);
    assert_eq!(body["previous"], "paused");
    assert_eq!(body["state"], "running");
    assert_eq!(get_status(fixture.port()).await, "running");

    // Stop: running -> stopping; resume from stopping is refused.
    let (status, body) = post_lifecycle(fixture.port(), "/api/pipeline/stop").await;
    assert_eq!(status, 200);
    assert_eq!(body["state"], "stopping");
    assert_eq!(get_status(fixture.port()).await, "stopping");
    let (status, _) = post_lifecycle(fixture.port(), "/api/pipeline/resume").await;
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

    let fixture = TestFixture::new();
    let events = TranslationEvents::new(128);
    let control = PipelineControl::new().with_events(events.clone());
    control.start().expect("idle -> running");
    let state = ServerState::new(fixture.repo_path()).with_pipeline_control(control.clone());
    let manager = SessionManager::new_with_broadcast(events.subscribe());
    let progress = ProgressState::new();
    let router = build_router_with_ws(state, manager, progress);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let (mut ws, _) = tokio_tungstenite::connect_async(format!(
        "ws://127.0.0.1:{}/api/events/upgrade",
        fixture.port()
    ))
    .await
    .expect("websocket upgrade succeeds");
    tokio::time::sleep(Duration::from_millis(200)).await;

    for path in ["/api/pipeline/pause", "/api/pipeline/resume"] {
        let (status, _) = post_lifecycle(fixture.port(), path).await;
        assert_eq!(status, 200, "{path} should succeed");
    }

    // Collect wire messages and pull out the lifecycle events with their
    // previous/state payloads.
    let mut transitions: Vec<(String, String)> = Vec::new();
    for _ in 0..20 {
        if transitions.len() >= 2 {
            break;
        }
        let msg = match tokio::time::timeout(Duration::from_millis(500), ws.next()).await {
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
    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path());
    let (manager, _event_tx) = SessionManager::new();
    let progress = ProgressState::new();
    let router = build_router_with_ws(state, manager, progress);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    for path in [
        "/api/pipeline/pause",
        "/api/pipeline/resume",
        "/api/pipeline/stop",
        // Issue #91: cancel-current is honest the same way — no control
        // attached means no pipeline whose unit could be cancelled.
        "/api/pipeline/cancel-current",
    ] {
        let (status, body) = post_lifecycle(fixture.port(), path).await;
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

    let fixture = TestFixture::new();
    let events = TranslationEvents::new(128);
    let control = PipelineControl::new().with_events(events.clone());
    control.start().expect("idle -> running");
    let cancellation = UnitCancellation::new().with_events(events.clone());
    let state = ServerState::new(fixture.repo_path())
        .with_pipeline_control(control.clone())
        .with_unit_cancellation(cancellation.clone());
    let manager = SessionManager::new_with_broadcast(events.subscribe());
    let progress = ProgressState::new();
    let router = build_router_with_ws(state, manager, progress.clone());
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let (mut ws, _) = tokio_tungstenite::connect_async(format!(
        "ws://127.0.0.1:{}/api/events/upgrade",
        fixture.port()
    ))
    .await
    .expect("websocket upgrade succeeds");
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Nothing in flight yet — the request is rejected, not silently absorbed.
    let (status, body) = post_lifecycle(fixture.port(), "/api/pipeline/cancel-current").await;
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
    events.emit(ProgressEvent::TranslationStarted {
        binary: "game_logic.dll".into(),
        function: "DrawPrimitive".into(),
    });
    cancellation.begin_unit("game_logic.dll", "DrawPrimitive");
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Cancel it: 200 naming the unit that was in flight.
    let (status, body) = post_lifecycle(fixture.port(), "/api/pipeline/cancel-current").await;
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
        let msg = match tokio::time::timeout(Duration::from_millis(500), ws.next()).await {
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
    let snapshot = progress.snapshot().await;
    let entry = snapshot
        .get("game_logic.dll/DrawPrimitive")
        .expect("the cancelled unit is tracked");
    assert!(entry.finished, "the cancelled unit is terminal");
    assert_eq!(entry.succeeded, Some(false), "recorded as failed");
    assert_eq!(entry.strategy, "cancelled", "recorded as cancelled");

    // The run itself is untouched — still running, and it moves on: the
    // pipeline ends the unit, starts the next, and that one can be
    // cancelled too.
    assert_eq!(
        control.state(),
        PipelineState::Running,
        "the run keeps going"
    );
    cancellation.end_unit_was_cancelled();
    events.emit(ProgressEvent::TranslationStarted {
        binary: "game_logic.dll".into(),
        function: "UpdateScene".into(),
    });
    cancellation.begin_unit("game_logic.dll", "UpdateScene");
    let (status, body) = post_lifecycle(fixture.port(), "/api/pipeline/cancel-current").await;
    assert_eq!(status, 200, "the next in-flight unit can be cancelled");
    assert_eq!(body["function"], "UpdateScene");

    // And once the run is between units again, cancel is rejected anew.
    cancellation.end_unit_was_cancelled();
    let (status, _) = post_lifecycle(fixture.port(), "/api/pipeline/cancel-current").await;
    assert_eq!(status, 409, "nothing in flight between units to cancel");
}

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
    let router = build_router_with_ws(state, manager, progress);
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
            strategy: "decompose".into(),
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
    assert_eq!(first["phase"], "ghidra_fetch");
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
        ["ghidra_fetch", "context_tier", "llm_call", "review"],
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
    let router = build_router_with_ws(state, manager, progress);
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

// ─────────────────────────────────────────────────────────────
// Server lifecycle endpoint tests (issue #60)
// ─────────────────────────────────────────────────────────────

/// Spawn a server whose accept loop watches the state's shutdown flag,
/// exactly like `serve`/`serve_with_listener` do — so the shutdown/restart
/// endpoints visibly stop it.
async fn spawn_server_with_shutdown(
    state: &ServerState,
    router: axum::Router,
    port: u16,
) -> tokio::task::JoinHandle<()> {
    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{port}"))
        .await
        .expect("bind listener");
    let shutdown = state.shutdown_signal();
    // Same wiring `calxgloss live` uses, so the test exercises the
    // production graceful-shutdown path rather than a hand-rolled one.
    tokio::spawn(async move {
        serve_with_listener(listener, router, shutdown)
            .await
            .expect("server runs to completion");
    })
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
    let router = build_router_with_ws(state.clone(), manager, progress.clone());
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

/// Counts global-subscriber events whose message is the test's probe
/// marker, to prove a `PATCH /api/server/log-level` change actually alters
/// the running process's verbosity — not just the reported string.
struct ProbeCountingLayer(std::sync::Arc<std::sync::atomic::AtomicUsize>);

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for ProbeCountingLayer {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        struct MessageVisitor {
            message: String,
        }
        impl tracing::field::Visit for MessageVisitor {
            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                if field.name() == "message" {
                    self.message = value.to_string();
                }
            }
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                if field.name() == "message" {
                    self.message = format!("{value:?}");
                }
            }
        }

        let mut visitor = MessageVisitor {
            message: String::new(),
        };
        event.record(&mut visitor);
        if visitor.message == "log-level-probe" {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }
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
            let actions = ActionsState::new(fixture.repo_path());
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
    // DrawPrimitive v1 and v2 each carry the 3/3 baseline artifact and
    // UpdateScene 1/1 → weighted pass rate 7/7. No unit carries verification
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

// ─── Queue overlay: manual order & priority (issue #74) ──────────────

/// Adds a second unmerged translation branch (`game_logic.dll/{function}`)
/// so the queue holds two active units at the same dependency depth — a
/// tie the overlay can break.
fn add_pending_translation(fixture: &TestFixture, function: &str) {
    let git = GitManager::open(&fixture.repo_path()).expect("open fixture repo");
    let branch = GitBranch::new("game_logic.dll", function, 1).expect("branch name");
    git.create_branch("game_logic.dll", function, 1, None)
        .expect("create branch");

    let src_file = format!("src/{}.rs", function.to_lowercase());
    std::fs::create_dir_all(fixture.repo_path().join("src")).expect("create src dir");
    std::fs::write(
        fixture.repo_path().join(&src_file),
        format!(
            "/// {function} — pending translation\npub fn {}() {{}}\n",
            function.to_lowercase()
        ),
    )
    .expect("write translation file");
    git.commit(
        &branch,
        &format!("Translate {function}"),
        &[src_file.as_str()],
    )
    .expect("commit branch");
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

    // The dashboard response carries the overlay and the effective order.
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
    let actions = ActionsState::new(fixture.repo_path());
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
    // every node carries one; edges carry their relationship type.
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
    let router = build_router_with_ws(state.clone(), manager, progress);
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

/// Issue #61: feed canned `ProgressEvent`s through the live event channel
/// and assert `/api/pipeline` derives honest per-phase and per-binary
/// progress — including Phase 2.5 (PAL Design) and the two NoDataSource
/// phases (Restitching, Documentation).
#[tokio::test]
async fn test_pipeline_phases_from_canned_events() {
    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path());
    let events = TranslationEvents::new(128);
    let manager = SessionManager::new_with_broadcast(events.subscribe());
    let progress = ProgressState::new();
    let router = build_router_with_ws(state, manager, progress);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    // Two binaries classified; d3d9 via the PAL strategy.
    events.emit(ProgressEvent::ClassificationComplete {
        binary: "dinput8.dll".into(),
        category: "WindowsOs".into(),
        strategy: "ReverseEngineer".into(),
        crate_replacement: None,
        exported_symbols: 10,
        imported_symbols: 4,
    });
    events.emit(ProgressEvent::ClassificationComplete {
        binary: "d3d9.dll".into(),
        category: "WindowsOs".into(),
        strategy: "PalMapping".into(),
        crate_replacement: None,
        exported_symbols: 25,
        imported_symbols: 6,
    });
    // d3d9's batch pass has begun — enumeration/testgen before any unit
    // event exists. The pipeline API must report it as being worked on.
    events.emit(ProgressEvent::BatchStarted {
        binary: "d3d9.dll".into(),
    });

    // game_logic.dll: one unit runs the full flow to review...
    events.emit(ProgressEvent::TranslationStarted {
        binary: "game_logic.dll".into(),
        function: "DrawPrimitive".into(),
    });
    events.emit(ProgressEvent::ApiTaggingComplete {
        binary: "game_logic.dll".into(),
        function: "DrawPrimitive".into(),
        tagged_apis: 3,
    });
    events.emit(ProgressEvent::TestsGenerated {
        binary: "game_logic.dll".into(),
        function: "DrawPrimitive".into(),
        test_count: 3,
    });
    events.emit(ProgressEvent::LlmCallComplete {
        binary: "game_logic.dll".into(),
        function: "DrawPrimitive".into(),
        attempt: 1,
        code_length: 1200,
        tokens_used: Some(4000),
    });
    events.emit(ProgressEvent::TranslationAttemptCompleted {
        binary: "game_logic.dll".into(),
        function: "DrawPrimitive".into(),
        attempt: 1,
        success: true,
        compiled: true,
        tests_passed: 3,
        tests_total: 3,
        strategy: "direct".into(),
        tokens_used: Some(4000),
        compilation_errors: vec![],
        failed_tests: vec![],
    });
    events.emit(ProgressEvent::TranslationCompleted {
        binary: "game_logic.dll".into(),
        function: "DrawPrimitive".into(),
        total_attempts: 1,
        success_strategy: Some("direct".into()),
    });
    // ...and one fails at the compile step.
    events.emit(ProgressEvent::TranslationStarted {
        binary: "game_logic.dll".into(),
        function: "UpdateScene".into(),
    });
    events.emit(ProgressEvent::TestsGenerated {
        binary: "game_logic.dll".into(),
        function: "UpdateScene".into(),
        test_count: 2,
    });
    events.emit(ProgressEvent::LlmCallComplete {
        binary: "game_logic.dll".into(),
        function: "UpdateScene".into(),
        attempt: 3,
        code_length: 900,
        tokens_used: Some(1000),
    });
    events.emit(ProgressEvent::FunctionCompleted {
        binary: "game_logic.dll".into(),
        function: "UpdateScene".into(),
        success: false,
        attempts: 3,
        branch: None,
    });

    // Batch summary for game_logic — the authoritative counts when present.
    events.emit(ProgressEvent::BatchSummary {
        binary: "game_logic.dll".into(),
        total_functions: 5,
        success_count: 2,
        failure_count: 1,
        total_attempts: 4,
        total_tokens: 5000,
    });

    // dinput8.dll: translation in progress, stopped after test generation.
    events.emit(ProgressEvent::TranslationStarted {
        binary: "dinput8.dll".into(),
        function: "GetDeviceState".into(),
    });
    events.emit(ProgressEvent::TestsGenerated {
        binary: "dinput8.dll".into(),
        function: "GetDeviceState".into(),
        test_count: 2,
    });

    // Give the event-forwarding task time to drain the channel.
    tokio::time::sleep(Duration::from_millis(300)).await;

    let resp = reqwest::get(format!("http://127.0.0.1:{}/api/pipeline", fixture.port()))
        .await
        .expect("pipeline request succeeds");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("pipeline body is JSON");

    // ── Aggregate counts (game_logic entered the pipeline unclassified) ──
    assert_eq!(body["total_dlls"], 3);
    assert_eq!(body["classified_count"], 2);
    assert_eq!(body["batch_complete_count"], 1);
    let translating: Vec<&str> = body["currently_translating"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d.as_str().unwrap())
        .collect();
    assert!(
        translating.contains(&"dinput8.dll"),
        "dinput8 is mid-translation"
    );
    assert!(
        !translating.contains(&"game_logic.dll"),
        "game_logic's units all finished"
    );

    // ── Phase states ─────────────────────────────────────────────────
    let phase = |name: &str| -> serde_json::Value {
        body["phases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["phase"].as_str().unwrap_or("") == name)
            .cloned()
            .unwrap_or_else(|| panic!("phase {name} missing from {:?}", body["phases"]))
    };

    // Ingestion: 2 of 3 binaries classified.
    let p = phase("project_ingestion");
    assert_eq!(p["state"], "in_progress");
    assert_eq!(p["completed"], 2);
    assert_eq!(p["total"], 3);

    // Disassembly & tagging: game_logic and dinput8 have tagged functions, d3d9 none.
    let p = phase("disassembly_tagging");
    assert_eq!(p["state"], "in_progress");
    assert_eq!(p["completed"], 2);
    assert_eq!(p["total"], 3);

    // PAL Design (Phase 2.5): d3d9 is the only PAL binary, batch not done.
    let p = phase("pal_design");
    assert_eq!(p["state"], "not_started");
    assert_eq!(p["completed"], 0);
    assert_eq!(p["total"], 1);

    // Test generation: game_logic and dinput8 generated tests.
    let p = phase("test_generation");
    assert_eq!(p["state"], "in_progress");
    assert_eq!(p["completed"], 2);
    assert_eq!(p["total"], 3);

    // Code generation: only game_logic got past the LLM into compile/test.
    let p = phase("rust_code_generation");
    assert_eq!(p["state"], "in_progress");
    assert_eq!(p["completed"], 1);
    assert_eq!(p["total"], 3);

    // Verification: only game_logic reached review.
    let p = phase("behavior_verification");
    assert_eq!(p["state"], "in_progress");
    assert_eq!(p["completed"], 1);
    assert_eq!(p["total"], 3);

    // Restitching & Documentation: never fabricated, always no_data_source.
    let p = phase("restitching");
    assert_eq!(p["state"], "no_data_source");
    assert!(p.get("completed").is_none());
    assert!(p.get("total").is_none());
    let p = phase("documentation");
    assert_eq!(p["state"], "no_data_source");

    // ── Per-binary progress (sorted by name) ─────────────────────────
    let binaries = body["binaries"].as_array().unwrap();
    assert_eq!(binaries.len(), 3);
    let names: Vec<&str> = binaries
        .iter()
        .map(|b| b["binary"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["d3d9.dll", "dinput8.dll", "game_logic.dll"]);

    // d3d9: classified via PAL, batch pass in flight — no fabricated totals.
    let b = &binaries[0];
    assert_eq!(b["strategy"], "PalMapping");
    assert_eq!(
        b["processing"], true,
        "a started batch pass marks the binary as being worked on: {b}"
    );
    assert!(
        b.get("functions_total").is_none(),
        "no batch summary, no total: {b}"
    );
    assert_eq!(b["functions_translated"], 0);
    assert_eq!(b["functions_in_progress"], 0);
    assert!(
        b.get("tokens_used").is_none(),
        "unknown tokens stay unknown: {b}"
    );

    // dinput8: one unit in flight after test generation.
    let b = &binaries[1];
    assert_eq!(b["category"], "WindowsOs");
    assert_eq!(
        b["processing"], false,
        "only the started binary is marked working: {b}"
    );
    assert!(b.get("functions_total").is_none());
    assert_eq!(b["functions_in_progress"], 1);
    assert_eq!(b["functions_translated"], 0);
    assert_eq!(b["functions_failed"], 0);
    assert!(b.get("tokens_used").is_none());

    // game_logic: batch summary is the authoritative source.
    let b = &binaries[2];
    assert_eq!(b["functions_total"], 5);
    assert_eq!(b["functions_translated"], 2);
    assert_eq!(b["functions_failed"], 1);
    assert_eq!(b["functions_in_progress"], 0);
    assert_eq!(b["tokens_used"], 5000);
}

/// Restart gap: a fresh live run over a workspace with prior work emits no
/// classification events (everything is already classified), so the pipeline
/// table must hydrate its rows from the persisted `re/classify` artifacts —
/// and the binary whose batch pass has begun must appear (Working) on
/// `BatchStarted` alone, before any unit event exists.
#[tokio::test]
async fn test_pipeline_restart_hydrates_rows_without_live_classification_events() {
    let fixture = TestFixture::new();
    // The previous run's classification artifact, on disk.
    let classify = fixture.repo_path().join("re").join("classify");
    std::fs::create_dir_all(&classify).expect("create classify dir");
    std::fs::write(
        classify.join("eqmain.dll.json"),
        r#"{"binary":"eqmain.dll","category":"ProjectSpecific","strategy":"ReverseEngineer","exports_count":0,"imports_count":286,"crate_replacement":null}"#,
    )
    .expect("write classification artifact");
    // A crate-replacement record stores strategy as the enum's tagged
    // object form — the writer serializes `Strategy` directly, so the
    // reader must not assume a bare string.
    std::fs::write(
        classify.join("steam_api64.dll.json"),
        r#"{"binary":"steam_api64.dll","category":"KnownThirdParty","strategy":{"CrateReplacement":{"crate_name":"steamworks"}},"exports_count":1019,"imports_count":89,"crate_replacement":"steamworks"}"#,
    )
    .expect("write crate-replacement classification artifact");

    let state = ServerState::new(fixture.repo_path());
    let events = TranslationEvents::new(128);
    let manager = SessionManager::new_with_broadcast(events.subscribe());
    let progress = ProgressState::new();
    let router = build_router_with_ws(state, manager, progress);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    // The restarted run has only begun LaunchPad.exe's pass — no unit
    // events, no classification events.
    events.emit(ProgressEvent::BatchStarted {
        binary: "LaunchPad.exe".into(),
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    let resp = reqwest::get(format!("http://127.0.0.1:{}/api/pipeline", fixture.port()))
        .await
        .expect("pipeline request succeeds");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("pipeline body is JSON");

    let binary = |name: &str| -> serde_json::Value {
        body["binaries"]
            .as_array()
            .unwrap()
            .iter()
            .find(|b| b["binary"].as_str().unwrap_or("") == name)
            .cloned()
            .unwrap_or_else(|| panic!("{name} missing from {:?}", body["binaries"]))
    };

    // The binary being worked on appears on BatchStarted alone.
    let b = binary("LaunchPad.exe");
    assert_eq!(b["processing"], true, "started batch marks it working: {b}");

    // The previously classified binary hydrates from disk.
    let b = binary("eqmain.dll");
    assert_eq!(b["category"], "ProjectSpecific");
    assert_eq!(b["strategy"], "ReverseEngineer");
    assert_eq!(b["processing"], false);

    // A tagged-object strategy hydrates to its variant name — not an
    // empty string that the UI would render as "Unclassified".
    let b = binary("steam_api64.dll");
    assert_eq!(b["category"], "KnownThirdParty");
    assert_eq!(b["strategy"], "CrateReplacement");
    assert_eq!(b["crate_replacement"], "steamworks");

    // Aggregate counts see both sources honestly.
    assert_eq!(body["total_dlls"], 3);
    assert_eq!(
        body["classified_count"], 2,
        "both disk records count as classified"
    );
}

/// The pre-translation passes (call-graph extraction, evidence scans) beat
/// per function while they walk their work list; `/api/pipeline` surfaces
/// the latest beat as `activity` on the processing binary's row — and a
/// pass with no per-item granularity beats with just its name.
#[tokio::test]
async fn test_pipeline_batch_progress_heartbeat_surfaces_on_row() {
    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path());
    let events = TranslationEvents::new(128);
    let manager = SessionManager::new_with_broadcast(events.subscribe());
    let progress = ProgressState::new();
    let router = build_router_with_ws(state, manager, progress);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    events.emit(ProgressEvent::BatchStarted {
        binary: "LaunchPad.exe".into(),
    });
    events.emit(ProgressEvent::BatchProgress {
        binary: "LaunchPad.exe".into(),
        pass: "type inference".into(),
        function: "FUN_1929282".into(),
        index: 1,
        total: 22143,
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    let get_pipeline = || async {
        let resp = reqwest::get(format!("http://127.0.0.1:{}/api/pipeline", fixture.port()))
            .await
            .expect("pipeline request succeeds");
        assert_eq!(resp.status(), 200);
        resp.json::<serde_json::Value>()
            .await
            .expect("pipeline body is JSON")
    };

    let body = get_pipeline().await;
    let b = body["binaries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|b| b["binary"].as_str().unwrap_or("") == "LaunchPad.exe")
        .expect("LaunchPad.exe row present");
    assert_eq!(b["activity"]["pass"], "type inference");
    assert_eq!(b["activity"]["function"], "FUN_1929282");
    assert_eq!(b["activity"]["index"], 1);
    assert_eq!(b["activity"]["total"], 22143);

    // A pass with no per-item granularity: only the name is honest.
    events.emit(ProgressEvent::BatchProgress {
        binary: "LaunchPad.exe".into(),
        pass: "type database".into(),
        function: String::new(),
        index: 0,
        total: 0,
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    let body = get_pipeline().await;
    let b = body["binaries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|b| b["binary"].as_str().unwrap_or("") == "LaunchPad.exe")
        .expect("LaunchPad.exe row present");
    assert_eq!(b["activity"]["pass"], "type database", "latest beat wins");
    assert!(
        b["activity"].get("function").is_none() && b["activity"].get("total").is_none(),
        "unknown position is omitted, never fabricated: {}",
        b["activity"]
    );
}

/// The auto loop processes binaries in a known order (EXEs first, then
/// DLLs, each alphabetical); a `QueuePlanned` event names that plan, and
/// the pipeline table must show rows in queue order — planned binaries
/// first even before their pass starts, unplanned ones after, alphabetical.
#[tokio::test]
async fn test_pipeline_queue_plan_drives_row_order() {
    let fixture = TestFixture::new();
    // A disk-classified binary the queue plan does not name.
    let classify = fixture.repo_path().join("re").join("classify");
    std::fs::create_dir_all(&classify).expect("create classify dir");
    std::fs::write(
        classify.join("zzz.dll.json"),
        r#"{"binary":"zzz.dll","category":"ProjectSpecific","strategy":"ReverseEngineer","exports_count":0,"imports_count":1,"crate_replacement":null}"#,
    )
    .expect("write classification artifact");

    let state = ServerState::new(fixture.repo_path());
    let events = TranslationEvents::new(128);
    let manager = SessionManager::new_with_broadcast(events.subscribe());
    let progress = ProgressState::new();
    let router = build_router_with_ws(state, manager, progress);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    events.emit(ProgressEvent::QueuePlanned {
        binaries: vec![
            "LaunchPad.exe".into(),
            "eqgame.exe".into(),
            "eqmain.dll".into(),
        ],
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    let resp = reqwest::get(format!("http://127.0.0.1:{}/api/pipeline", fixture.port()))
        .await
        .expect("pipeline request succeeds");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("pipeline body is JSON");

    let names: Vec<&str> = body["binaries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| b["binary"].as_str().unwrap_or(""))
        .collect();
    assert_eq!(
        names,
        ["LaunchPad.exe", "eqgame.exe", "eqmain.dll", "zzz.dll"],
        "queue order first (the plan alone makes rows), unplanned after alphabetical"
    );
}

// ─────────────────────────────────────────────────────────────
// Pipeline time estimate + queue effort (issue #64)
// ─────────────────────────────────────────────────────────────

/// Writes a token-usage log to the fixture's `re/analysis/` directory.
/// When `with_durations` is false the entries omit `duration_secs`, exactly
/// like logs written before issue #64, so the average stays unknown.
fn write_token_usage_log(fixture: &TestFixture, with_durations: bool) {
    let analysis_dir = fixture.repo_path().join("re").join("analysis");
    std::fs::create_dir_all(&analysis_dir).expect("create analysis dir");

    let mut entries = Vec::new();
    for (attempt, tokens) in [(1usize, 4096usize), (2, 3072)] {
        let mut entry = serde_json::json!({
            "timestamp": 1767225600 + attempt as u64 * 300,
            "binary": "game_logic.dll",
            "function": "DrawPrimitive",
            "attempt": attempt,
            "strategy": if attempt == 1 { "initial" } else { "compile_fix" },
            "tokens_used": tokens,
            "success": attempt == 2
        });
        if with_durations {
            entry["duration_secs"] = serde_json::json!(100 * attempt as u64);
        }
        entries.push(entry);
    }
    let log = serde_json::json!({ "entries": entries });
    std::fs::write(
        analysis_dir.join("token_usage.json"),
        serde_json::to_string_pretty(&log).expect("serialize token log"),
    )
    .expect("write token log");
}

/// Emits the minimal live events that give one binary a known function
/// total with work remaining (5 total, 2 translated, 1 failed → 2 remain).
fn emit_canned_batch_summary(events: &TranslationEvents) {
    events.emit(ProgressEvent::BatchSummary {
        binary: "game_logic.dll".into(),
        total_functions: 5,
        success_count: 2,
        failure_count: 1,
        total_attempts: 4,
        total_tokens: 5000,
    });
}

/// Issue #64: when the token-usage log carries measured attempt durations
/// and work remains, `/api/pipeline` reports a time estimate derived from
/// the average duration × remaining functions.
#[tokio::test]
async fn test_pipeline_time_estimate_present_with_durations() {
    let fixture = TestFixture::new();
    write_token_usage_log(&fixture, true);

    let state = ServerState::new(fixture.repo_path());
    let events = TranslationEvents::new(128);
    let manager = SessionManager::new_with_broadcast(events.subscribe());
    let progress = ProgressState::new();
    let router = build_router_with_ws(state, manager, progress);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;
    emit_canned_batch_summary(&events);
    tokio::time::sleep(Duration::from_millis(300)).await;

    let resp = reqwest::get(format!("http://127.0.0.1:{}/api/pipeline", fixture.port()))
        .await
        .expect("pipeline request succeeds");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("pipeline body is JSON");

    let est = &body["time_estimate"];
    assert!(
        !est.is_null(),
        "estimate should be present with durations: {body}"
    );
    // Average of 100s and 200s = 150s; remaining = 5 − 2 − 1 = 2.
    assert_eq!(est["avg_attempt_secs"], 150.0);
    assert_eq!(est["remaining_units"], 2);
    assert_eq!(est["estimated_secs"], 300.0);
}

/// Issue #64: when no attempt has a recorded duration (a pre-#64 log),
/// `/api/pipeline` omits the estimate entirely rather than fabricating one.
#[tokio::test]
async fn test_pipeline_time_estimate_absent_without_durations() {
    let fixture = TestFixture::new();
    write_token_usage_log(&fixture, false);

    let state = ServerState::new(fixture.repo_path());
    let events = TranslationEvents::new(128);
    let manager = SessionManager::new_with_broadcast(events.subscribe());
    let progress = ProgressState::new();
    let router = build_router_with_ws(state, manager, progress);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;
    emit_canned_batch_summary(&events);
    tokio::time::sleep(Duration::from_millis(300)).await;

    let resp = reqwest::get(format!("http://127.0.0.1:{}/api/pipeline", fixture.port()))
        .await
        .expect("pipeline request succeeds");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("pipeline body is JSON");

    assert!(
        body.get("time_estimate").is_none(),
        "no durations → no estimate: {body}"
    );
}

/// Issue #64: `/api/dashboard` carries a `queue_effort` map giving each
/// function-level queued unit its estimated per-attempt seconds, taken from
/// that unit's own recorded durations.
#[tokio::test]
async fn test_dashboard_queue_effort_from_durations() {
    let fixture = TestFixture::new();
    write_canned_run_telemetry_with_durations(&fixture);

    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let resp = reqwest::get(format!("http://127.0.0.1:{}/api/dashboard", fixture.port()))
        .await
        .expect("dashboard request succeeds");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("dashboard body is JSON");

    let effort = &body["queue_effort"];
    assert!(effort.is_object(), "queue_effort should be a map: {body}");

    // The dashboard's game_logic.dll/DrawPrimitive unit has its own measured
    // attempts (100s and 200s) → average 150s.
    let unit_id = "game_logic.dll/DrawPrimitive/v2";
    assert_eq!(
        effort.get(unit_id),
        Some(&serde_json::json!(150)),
        "unit with its own durations uses their average: {effort}"
    );
}

/// Issue #64: a queued unit with no recorded attempts of its own falls back
/// to the global average across all measured attempts in the log.
#[tokio::test]
async fn test_dashboard_queue_effort_falls_back_to_global_average() {
    let fixture = TestFixture::new();

    // Durations recorded only for UpdateScene — a function the queued
    // DrawPrimitive/v2 unit is not, so the unit has no own history.
    let analysis_dir = fixture.repo_path().join("re").join("analysis");
    std::fs::create_dir_all(&analysis_dir).expect("create analysis dir");
    let token_log = serde_json::json!({
        "entries": [
            {
                "timestamp": 1767225600,
                "binary": "game_logic.dll",
                "function": "UpdateScene",
                "attempt": 1,
                "strategy": "initial",
                "tokens_used": 4096,
                "success": true,
                "duration_secs": 300
            },
            {
                "timestamp": 1767225900,
                "binary": "game_logic.dll",
                "function": "UpdateScene",
                "attempt": 2,
                "strategy": "compile_fix",
                "tokens_used": 3072,
                "success": true,
                "duration_secs": 500
            }
        ]
    });
    std::fs::write(
        analysis_dir.join("token_usage.json"),
        serde_json::to_string_pretty(&token_log).expect("serialize token log"),
    )
    .expect("write token log");

    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let resp = reqwest::get(format!("http://127.0.0.1:{}/api/dashboard", fixture.port()))
        .await
        .expect("dashboard request succeeds");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("dashboard body is JSON");

    let effort = &body["queue_effort"];
    assert!(effort.is_object(), "queue_effort should be a map: {body}");

    // No own durations → global average of 300s and 500s = 400s.
    let unit_id = "game_logic.dll/DrawPrimitive/v2";
    assert_eq!(
        effort.get(unit_id),
        Some(&serde_json::json!(400)),
        "unit without own durations falls back to the global average: {effort}"
    );
}

/// Like `write_canned_run_telemetry` but the token-usage entries carry
/// durations (100s and 200s for DrawPrimitive's two attempts).
fn write_canned_run_telemetry_with_durations(fixture: &TestFixture) {
    let analysis_dir = fixture.repo_path().join("re").join("analysis");
    std::fs::create_dir_all(&analysis_dir).expect("create analysis dir");

    let token_log = serde_json::json!({
        "entries": [
            {
                "timestamp": 1767225600,
                "binary": "game_logic.dll",
                "function": "DrawPrimitive",
                "attempt": 1,
                "strategy": "initial",
                "context_tier": "disassembly",
                "tokens_used": 4096,
                "success": false,
                "duration_secs": 100
            },
            {
                "timestamp": 1767225900,
                "binary": "game_logic.dll",
                "function": "DrawPrimitive",
                "attempt": 2,
                "strategy": "compile_fix",
                "context_tier": "with_tests",
                "tokens_used": 3072,
                "success": true,
                "duration_secs": 200
            }
        ]
    });
    std::fs::write(
        analysis_dir.join("token_usage.json"),
        serde_json::to_string_pretty(&token_log).expect("serialize token log"),
    )
    .expect("write token log");
}

/// Issue #61: the plain serve and actions routers serve `/api/pipeline`
/// with an honest empty payload (all phases NotStarted / NoDataSource)
/// instead of a 404, so the dashboard phase bar renders everywhere.
#[tokio::test]
async fn test_pipeline_honest_empty_payload_on_non_live_routers() {
    for kind in ["serve", "actions"] {
        let fixture = TestFixture::new();
        let state = ServerState::new(fixture.repo_path());
        let router = if kind == "serve" {
            build_router(state)
        } else {
            build_router_with_actions(state, ActionsState::new(fixture.repo_path()))
        };
        let _server = spawn_server(router, fixture.port()).await;

        tokio::time::sleep(Duration::from_millis(200)).await;

        let resp = reqwest::get(format!("http://127.0.0.1:{}/api/pipeline", fixture.port()))
            .await
            .expect("pipeline request reaches server");
        assert_eq!(resp.status(), 200, "{kind} router serves /api/pipeline");
        let body: serde_json::Value = resp.json().await.expect("pipeline body is JSON");
        assert_eq!(body["total_dlls"], 0);
        let phases = body["phases"].as_array().unwrap();
        assert_eq!(phases.len(), 8);
        assert_eq!(phases[6]["phase"], "restitching");
        assert_eq!(phases[6]["state"], "no_data_source");
        assert_eq!(phases[7]["phase"], "documentation");
        assert_eq!(phases[7]["state"], "no_data_source");
    }
}

/// Issue #61 honesty rule: a batch summary whose functions all failed means
/// the pipeline *ran* the build phases over the binary, but verification
/// succeeded for nothing — Behavior Verification must not report Complete.
#[tokio::test]
async fn test_pipeline_all_failed_batch_not_verification_complete() {
    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path());
    let events = TranslationEvents::new(128);
    let manager = SessionManager::new_with_broadcast(events.subscribe());
    let progress = ProgressState::new();
    let router = build_router_with_ws(state, manager, progress);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    events.emit(ProgressEvent::BatchSummary {
        binary: "broken.dll".into(),
        total_functions: 1,
        success_count: 0,
        failure_count: 1,
        total_attempts: 3,
        total_tokens: 800,
    });

    tokio::time::sleep(Duration::from_millis(300)).await;

    let resp = reqwest::get(format!("http://127.0.0.1:{}/api/pipeline", fixture.port()))
        .await
        .expect("pipeline request succeeds");
    let body: serde_json::Value = resp.json().await.expect("pipeline body is JSON");

    let phase = |name: &str| -> serde_json::Value {
        body["phases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["phase"].as_str().unwrap_or("") == name)
            .cloned()
            .unwrap()
    };

    // The batch ran the build phases over the binary...
    assert_eq!(phase("disassembly_tagging")["state"], "complete");
    assert_eq!(phase("test_generation")["state"], "complete");
    assert_eq!(phase("rust_code_generation")["state"], "complete");
    // ...but nothing verified successfully, so verification is not complete.
    let p = phase("behavior_verification");
    assert_eq!(p["state"], "not_started");
    assert_eq!(p["completed"], 0);
    assert_eq!(p["total"], 1);

    // The binary record keeps the failure counts honest.
    let b = &body["binaries"].as_array().unwrap()[0];
    assert_eq!(b["binary"], "broken.dll");
    assert_eq!(b["functions_translated"], 0);
    assert_eq!(b["functions_failed"], 1);
    assert_eq!(b["tokens_used"], 800);
}

/// Test that the progress endpoint returns empty data when idle.
#[tokio::test]
async fn test_progress_empty() {
    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path());
    let (manager, _event_tx) = SessionManager::new();
    let progress = ProgressState::new();
    let router = build_router_with_ws(state.clone(), manager, progress);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let resp = reqwest::get(format!("http://127.0.0.1:{}/api/progress", fixture.port()))
        .await
        .expect("progress request succeeds");

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("progress body is JSON");
    assert_eq!(body["count"].as_u64().unwrap_or(0), 0);
}

/// Feed canned `ProgressEvent`s through the live wiring (broadcast channel →
/// SessionManager callback → `ProgressState`) and assert `/api/progress`
/// reports the current phase, the phase history in event order, and elapsed
/// time per in-flight unit. The sequence includes a tier escalation:
/// `ContextTierSelected` re-emitted after `LlmCallFailed`, which must show up
/// as a second `context_tier` entry in the history.
#[tokio::test]
async fn test_progress_reports_phase_history() {
    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path());
    let events = TranslationEvents::new(128);
    let manager = SessionManager::new_with_broadcast(events.subscribe());
    let progress = ProgressState::new();
    let router = build_router_with_ws(state.clone(), manager, progress);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let tier = |tier: &str| ProgressEvent::ContextTierSelected {
        binary: "game_logic.dll".into(),
        function: "DrawPrimitive".into(),
        tier: tier.into(),
        tier_label: format!("{tier} label"),
        complexity: "Medium".into(),
        api_call_count: 3,
    };
    for event in [
        ProgressEvent::TranslationStarted {
            binary: "game_logic.dll".into(),
            function: "DrawPrimitive".into(),
        },
        ProgressEvent::GhidraFetchComplete {
            binary: "game_logic.dll".into(),
            function: "DrawPrimitive".into(),
            address: None,
            disassembly_lines: 10,
        },
        ProgressEvent::ApiTaggingComplete {
            binary: "game_logic.dll".into(),
            function: "DrawPrimitive".into(),
            tagged_apis: 3,
        },
        ProgressEvent::TestsGenerated {
            binary: "game_logic.dll".into(),
            function: "DrawPrimitive".into(),
            test_count: 5,
        },
        tier("T1"),
        ProgressEvent::LlmCallStart {
            binary: "game_logic.dll".into(),
            function: "DrawPrimitive".into(),
            attempt: 1,
            strategy: "direct".into(),
        },
        ProgressEvent::LlmCallFailed {
            binary: "game_logic.dll".into(),
            function: "DrawPrimitive".into(),
            attempt: 1,
            strategy: "direct".into(),
            error: "context window exceeded".into(),
        },
        tier("T2"),
        ProgressEvent::LlmCallStart {
            binary: "game_logic.dll".into(),
            function: "DrawPrimitive".into(),
            attempt: 2,
            strategy: "decompose".into(),
        },
        ProgressEvent::LlmCallComplete {
            binary: "game_logic.dll".into(),
            function: "DrawPrimitive".into(),
            attempt: 2,
            code_length: 120,
            tokens_used: None,
        },
        ProgressEvent::TranslationAttemptCompleted {
            binary: "game_logic.dll".into(),
            function: "DrawPrimitive".into(),
            attempt: 2,
            success: true,
            compiled: true,
            tests_passed: 5,
            tests_total: 5,
            compilation_errors: vec![],
            failed_tests: vec![],
            strategy: "decompose".into(),
            tokens_used: None,
        },
        // A second unit that runs to completion: TranslationCompleted moves
        // it to the review phase and marks it finished.
        ProgressEvent::TranslationStarted {
            binary: "game_logic.dll".into(),
            function: "Update".into(),
        },
        ProgressEvent::TranslationCompleted {
            binary: "game_logic.dll".into(),
            function: "Update".into(),
            total_attempts: 1,
            success_strategy: Some("direct".into()),
        },
    ] {
        events.emit(event);
    }
    // The callback spawns a task per event; give them time to land.
    tokio::time::sleep(Duration::from_millis(300)).await;

    let resp = reqwest::get(format!("http://127.0.0.1:{}/api/progress", fixture.port()))
        .await
        .expect("progress request succeeds");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("progress body is JSON");

    assert_eq!(body["count"].as_u64(), Some(2));
    let units = body["in_progress"]
        .as_array()
        .expect("in_progress is an array");
    let unit = units
        .iter()
        .find(|u| u["function"] == "DrawPrimitive")
        .expect("DrawPrimitive unit present");
    assert_eq!(unit["binary"].as_str(), Some("game_logic.dll"));
    assert_eq!(unit["attempt"].as_u64(), Some(2));
    assert_eq!(unit["strategy"].as_str(), Some("decompose"));
    // Current phase: the attempt completed, so the unit is testing.
    assert_eq!(unit["phase"].as_str(), Some("testing"));
    assert_eq!(unit["finished"].as_bool(), Some(false));
    assert!(unit["elapsed_secs"].as_f64().unwrap_or(-1.0) >= 0.0);

    // Phase history in event order, with the escalation visible.
    let history: Vec<&str> = unit["phase_history"]
        .as_array()
        .expect("phase_history is an array")
        .iter()
        .map(|e| e["phase"].as_str().unwrap_or_default())
        .collect();
    assert_eq!(
        history,
        vec![
            "ghidra_fetch",
            "api_tagging",
            "test_gen",
            "context_tier",
            "llm_call",
            "context_tier",
            "llm_call",
            "compiling",
            "testing",
        ]
    );
    for entry in unit["phase_history"]
        .as_array()
        .expect("phase_history is an array")
    {
        assert!(entry["elapsed_secs"].as_f64().unwrap_or(-1.0) >= 0.0);
    }

    // The completed unit reports the review phase and the finished flag.
    let done = units
        .iter()
        .find(|u| u["function"] == "Update")
        .expect("Update unit present");
    assert_eq!(done["phase"].as_str(), Some("review"));
    assert_eq!(done["finished"].as_bool(), Some(true));
    assert_eq!(
        done["phase_history"]
            .as_array()
            .expect("phase_history is an array")
            .iter()
            .map(|e| e["phase"].as_str().unwrap_or_default())
            .collect::<Vec<_>>(),
        vec!["ghidra_fetch", "review"]
    );
}

/// Issue #65: `/api/progress/enhanced` serves the live view's per-unit records
/// from the same canned event stream `/api/progress` reads — phase and elapsed
/// time plus context tier, retry strategy, attempt, baseline/verification pass
/// status, and derived unit confidence. Covers the three evidence shapes the
/// live view must tell apart: a unit with full evidence still in flight, a
/// completed unit with no test evidence reported, and a failed unit whose
/// verified attempt did not compile (confidence 0.0, not absent).
#[tokio::test]
async fn test_progress_enhanced_reports_live_records() {
    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path());
    let events = TranslationEvents::new(128);
    let manager = SessionManager::new_with_broadcast(events.subscribe());
    let progress = ProgressState::new();
    let router = build_router_with_ws(state.clone(), manager, progress);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    for event in [
        // DrawPrimitive: full evidence, still in flight.
        ProgressEvent::TranslationStarted {
            binary: "game_logic.dll".into(),
            function: "DrawPrimitive".into(),
        },
        ProgressEvent::TestsGenerated {
            binary: "game_logic.dll".into(),
            function: "DrawPrimitive".into(),
            test_count: 5,
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
            strategy: "decompose".into(),
        },
        ProgressEvent::TranslationAttemptCompleted {
            binary: "game_logic.dll".into(),
            function: "DrawPrimitive".into(),
            attempt: 2,
            success: false,
            compiled: true,
            tests_passed: 4,
            tests_total: 5,
            compilation_errors: vec![],
            failed_tests: vec![],
            strategy: "decompose".into(),
            tokens_used: None,
        },
        ProgressEvent::BehaviorDivergenceDetected {
            binary: "game_logic.dll".into(),
            function: "DrawPrimitive".into(),
            attempt: 2,
            strategy: "decompose".into(),
            baseline_passed: 4,
            baseline_total: 5,
            edge_tests_passed: 2,
            edge_tests_total: 3,
            failing_edge_cases: vec!["null_handle".into()],
            fault_confidence: 8,
        },
        // Update: completed without any test evidence reported — every
        // unmeasured field must stay absent, not become a fabricated zero.
        ProgressEvent::TranslationStarted {
            binary: "game_logic.dll".into(),
            function: "Update".into(),
        },
        ProgressEvent::TranslationCompleted {
            binary: "game_logic.dll".into(),
            function: "Update".into(),
            total_attempts: 1,
            success_strategy: Some("direct".into()),
        },
        // FailedUnit: a verified attempt that did not compile — confidence is
        // a real 0.0, not absent.
        ProgressEvent::TranslationStarted {
            binary: "kernel32.dll".into(),
            function: "FailedUnit".into(),
        },
        ProgressEvent::LlmCallStart {
            binary: "kernel32.dll".into(),
            function: "FailedUnit".into(),
            attempt: 1,
            strategy: "direct".into(),
        },
        ProgressEvent::TranslationAttemptCompleted {
            binary: "kernel32.dll".into(),
            function: "FailedUnit".into(),
            attempt: 1,
            success: false,
            compiled: false,
            tests_passed: 0,
            tests_total: 3,
            compilation_errors: vec!["unresolved symbol".into()],
            failed_tests: vec![],
            strategy: "direct".into(),
            tokens_used: None,
        },
        ProgressEvent::TranslationFailed {
            binary: "kernel32.dll".into(),
            function: "FailedUnit".into(),
            total_attempts: 1,
        },
    ] {
        events.emit(event);
    }
    // Events flow through one ordered consumer task; give it time to land.
    tokio::time::sleep(Duration::from_millis(300)).await;

    let resp = reqwest::get(format!(
        "http://127.0.0.1:{}/api/progress/enhanced",
        fixture.port()
    ))
    .await
    .expect("enhanced progress request succeeds");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("body is JSON");

    assert_eq!(body["count"].as_u64(), Some(3));
    assert_eq!(body["in_flight"].as_u64(), Some(1));

    // Sorted by (binary, function) so the live view doesn't shuffle rows.
    let units = body["units"].as_array().expect("units is an array");
    let keys: Vec<(&str, &str)> = units
        .iter()
        .map(|u| {
            (
                u["binary"].as_str().unwrap_or_default(),
                u["function"].as_str().unwrap_or_default(),
            )
        })
        .collect();
    assert_eq!(
        keys,
        vec![
            ("game_logic.dll", "DrawPrimitive"),
            ("game_logic.dll", "Update"),
            ("kernel32.dll", "FailedUnit"),
        ]
    );

    let unit = |function: &str| -> serde_json::Value {
        units
            .iter()
            .find(|u| u["function"] == function)
            .cloned()
            .unwrap_or_else(|| panic!("{function} unit present"))
    };

    let draw = unit("DrawPrimitive");
    assert_eq!(draw["phase"].as_str(), Some("testing"));
    assert!(draw["elapsed_secs"].as_f64().unwrap_or(-1.0) >= 0.0);
    assert_eq!(draw["attempt"].as_u64(), Some(2));
    assert_eq!(draw["retry_strategy"].as_str(), Some("decompose"));
    assert_eq!(draw["context_tier"].as_str(), Some("T2"));
    assert_eq!(draw["tier_label"].as_str(), Some("with_tests"));
    assert_eq!(draw["baseline"]["state"].as_str(), Some("failed"));
    assert_eq!(draw["baseline"]["passed"].as_u64(), Some(4));
    assert_eq!(draw["baseline"]["total"].as_u64(), Some(5));
    assert_eq!(draw["verification"]["state"].as_str(), Some("failed"));
    assert_eq!(draw["verification"]["passed"].as_u64(), Some(2));
    assert_eq!(draw["verification"]["total"].as_u64(), Some(3));
    assert_eq!(draw["compiled"].as_bool(), Some(true));
    assert_eq!(draw["unit_confidence"].as_f64(), Some(0.8));
    assert_eq!(draw["finished"].as_bool(), Some(false));
    assert!(
        draw.get("succeeded").is_none(),
        "an in-flight unit never looks succeeded or failed: {draw}"
    );

    let update = unit("Update");
    assert_eq!(update["phase"].as_str(), Some("review"));
    assert_eq!(update["finished"].as_bool(), Some(true));
    assert_eq!(update["succeeded"].as_bool(), Some(true));
    assert_eq!(update["baseline"]["state"].as_str(), Some("not_run"));
    assert_eq!(update["verification"]["state"].as_str(), Some("not_run"));
    for key in [
        "retry_strategy",
        "context_tier",
        "compiled",
        "unit_confidence",
    ] {
        assert!(
            update.get(key).is_none(),
            "{key} was never reported for Update: {update}"
        );
    }

    let failed = unit("FailedUnit");
    assert_eq!(failed["finished"].as_bool(), Some(true));
    assert_eq!(failed["succeeded"].as_bool(), Some(false));
    assert_eq!(failed["compiled"].as_bool(), Some(false));
    assert_eq!(
        failed["unit_confidence"].as_f64(),
        Some(0.0),
        "a verified attempt that did not compile has confidence 0.0"
    );
    assert_eq!(failed["baseline"]["state"].as_str(), Some("failed"));
}

/// Route-table contract: endpoints that read live translation state are
/// registered **only** in the WebSocket (live) router. On the plain serve
/// router and the actions router they must fall through to the static 404,
/// never answer with fabricated empty data. (`/api/pipeline` is no longer
/// on this list — issue #61 moved it to the shared routes, where it serves
/// an honest empty payload; see
/// `test_pipeline_honest_empty_payload_on_non_live_routers`.)
#[tokio::test]
async fn test_live_only_endpoints_absent_from_non_live_routers() {
    for kind in ["serve", "actions"] {
        let fixture = TestFixture::new();
        let state = ServerState::new(fixture.repo_path());
        let router = if kind == "serve" {
            build_router(state)
        } else {
            build_router_with_actions(state, ActionsState::new(fixture.repo_path()))
        };
        let _server = spawn_server(router, fixture.port()).await;

        tokio::time::sleep(Duration::from_millis(200)).await;

        for path in [
            "/api/progress",
            "/api/progress/enhanced",
            "/api/events/upgrade",
        ] {
            let resp = reqwest::get(format!("http://127.0.0.1:{}{}", fixture.port(), path))
                .await
                .expect("request reaches server");
            assert_eq!(
                resp.status(),
                404,
                "{path} must not be routed on the {kind} router"
            );
        }

        // Issue #90: the pipeline lifecycle control endpoints are live-only
        // too — a plain serve/actions router has no pipeline to control.
        // Unrouted POST paths fall through to the GET-only static fallback,
        // which rejects the method with 405 (a GET on them 404s, as above);
        // either way the lifecycle handler never runs.
        for path in [
            "/api/pipeline/pause",
            "/api/pipeline/resume",
            "/api/pipeline/stop",
            "/api/pipeline/cancel-current",
        ] {
            let resp = reqwest::Client::new()
                .post(format!("http://127.0.0.1:{}{}", fixture.port(), path))
                .send()
                .await
                .expect("request reaches server");
            assert_eq!(
                resp.status(),
                405,
                "{path} must not be routed on the {kind} router"
            );
        }
    }
}

/// Issue #77 router contract: `/api/llm-io` is registered in the shared
/// routes — it reads the persisted log, never live pipeline state — so every
/// router answers it. With no log on disk (a workspace that never ran live)
/// it serves an honest empty payload, not a 404 and not fabricated records.
#[tokio::test]
async fn test_llm_io_log_honest_empty_payload_on_non_live_routers() {
    for kind in ["serve", "actions"] {
        let fixture = TestFixture::new();
        let state = ServerState::new(fixture.repo_path());
        let router = if kind == "serve" {
            build_router(state)
        } else {
            build_router_with_actions(state, ActionsState::new(fixture.repo_path()))
        };
        let _server = spawn_server(router, fixture.port()).await;

        tokio::time::sleep(Duration::from_millis(200)).await;

        let resp = reqwest::get(format!("http://127.0.0.1:{}/api/llm-io", fixture.port()))
            .await
            .expect("request reaches server");
        assert_eq!(resp.status(), 200, "{kind} router serves /api/llm-io");
        let body: serde_json::Value = resp.json().await.expect("body is JSON");
        assert_eq!(body["entries"].as_array().expect("entries array").len(), 0);
    }
}

/// Issue #77 write + read round-trip: during a live run every LLM request,
/// response, and failure the pipeline emits is appended to
/// `re/analysis/llm_io/log.jsonl` as it happens, and `GET /api/llm-io`
/// serves the entries back with their metadata and token counts.
#[tokio::test]
async fn test_llm_io_log_round_trip_from_canned_events() {
    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path());
    let events = TranslationEvents::new(128);
    let manager = SessionManager::new_with_broadcast(events.subscribe());
    let progress = ProgressState::new();
    let router = build_router_with_ws(state, manager, progress);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    // A non-LLM event must not touch the log.
    events.emit(ProgressEvent::LlmCallStart {
        binary: "game_logic.dll".into(),
        function: "DrawPrimitive".into(),
        attempt: 1,
        strategy: "direct".into(),
    });
    events.emit(ProgressEvent::LlmRequest {
        binary: "game_logic.dll".into(),
        function: "DrawPrimitive".into(),
        attempt: 1,
        strategy: "direct".into(),
        prompt: "translate DrawPrimitive".into(),
    });
    events.emit(ProgressEvent::LlmResponse {
        binary: "game_logic.dll".into(),
        function: "DrawPrimitive".into(),
        attempt: 1,
        strategy: "direct".into(),
        content: "fn draw_primitive() {}".into(),
        tokens_used: Some(4321),
    });
    events.emit(ProgressEvent::LlmCallFailed {
        binary: "game_logic.dll".into(),
        function: "UpdateScene".into(),
        attempt: 2,
        strategy: "retry".into(),
        error: "connection reset".into(),
    });

    tokio::time::sleep(Duration::from_millis(300)).await;

    // The log is on disk in the analysis directory, not just in memory.
    let log_path = fixture
        .repo_path()
        .join("re")
        .join("analysis")
        .join("llm_io")
        .join("log.jsonl");
    assert!(log_path.is_file(), "live run persists the LLM I/O log");

    let resp = reqwest::get(format!("http://127.0.0.1:{}/api/llm-io", fixture.port()))
        .await
        .expect("request reaches server");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("body is JSON");
    let entries = body["entries"].as_array().expect("entries array");
    assert_eq!(
        entries.len(),
        3,
        "only request/response/error events are logged"
    );

    let request = &entries[0];
    assert_eq!(request["type"], "request");
    assert_eq!(request["binary"], "game_logic.dll");
    assert_eq!(request["function"], "DrawPrimitive");
    assert_eq!(request["attempt"], 1);
    assert_eq!(request["strategy"], "direct");
    assert_eq!(request["content"], "translate DrawPrimitive");
    assert!(request["timestamp"].as_u64().expect("timestamp") > 0);

    let response = &entries[1];
    assert_eq!(response["type"], "response");
    assert_eq!(response["content"], "fn draw_primitive() {}");
    assert_eq!(response["tokens_used"], 4321);

    let failure = &entries[2];
    assert_eq!(failure["type"], "error");
    assert_eq!(failure["function"], "UpdateScene");
    assert_eq!(failure["attempt"], 2);
    assert_eq!(failure["strategy"], "retry");
    assert_eq!(failure["content"], "connection reset");
}

/// Integration test verifying that the full router with actions
/// can serve the dashboard.
#[tokio::test]
async fn test_actions_router_dashboard() {
    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path());
    let actions = ActionsState::new(fixture.repo_path());
    let router = build_router_with_actions(state.clone(), actions);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let resp = reqwest::get(format!("http://127.0.0.1:{}/api/dashboard", fixture.port()))
        .await
        .expect("dashboard request succeeds");

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("dashboard body is JSON");
    assert_eq!(body["success"], true);

    // Server management endpoints register in all three routers — the
    // actions router must serve the status endpoint too.
    let status_resp = reqwest::get(format!(
        "http://127.0.0.1:{}/api/server/status",
        fixture.port()
    ))
    .await
    .expect("server status request succeeds");
    assert_eq!(status_resp.status(), 200);
    let status_body: serde_json::Value = status_resp.json().await.expect("status is JSON");
    assert_eq!(status_body["pipeline_status"], "unavailable");

    // The enhanced /health also registers here (issue #59: all three routers).
    let health_resp = reqwest::get(format!("http://127.0.0.1:{}/health", fixture.port()))
        .await
        .expect("health request succeeds");
    assert_eq!(health_resp.status(), 200);
    let health_body: serde_json::Value = health_resp.json().await.expect("health is JSON");
    assert_eq!(health_body["status"], "ok");
    assert!(health_body["uptime_secs"].as_u64().is_some());
    assert_eq!(health_body["version"], env!("CARGO_PKG_VERSION"));
}

/// Verify that a send-back verdict survives a dashboard rebuild (issue #9):
/// POST /send-back writes a send-back record, and a dashboard rebuilt from
/// disk reports the unit as `send_back` — not `queued`/`pending_review` —
/// so the review state machine (SendBack → Blocked cascade → re-review)
/// has a failing root to cascade from.
#[tokio::test]
async fn test_send_back_verdict_survives_rebuild() {
    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path());
    let actions = ActionsState::new(fixture.repo_path());
    let router = build_router_with_actions(state.clone(), actions);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let unit_id = "game_logic.dll/DrawPrimitive/v2";
    let encoded_id = urlencoding::encode(unit_id);
    let client = reqwest::Client::new();
    let resp = client
        .post(format!(
            "http://127.0.0.1:{}/api/units/{}/send-back",
            fixture.port(),
            encoded_id
        ))
        .json(&serde_json::json!({"reason": "shader constant mapping wrong"}))
        .send()
        .await
        .expect("send-back request succeeds");

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("send-back body is JSON");
    assert_eq!(body["action"], "send_back");

    // Rebuild the dashboard from disk — the verdict must survive the rebuild.
    let dashboard = build_dashboard(&fixture.repo_path()).expect("rebuild dashboard");
    let unit = dashboard
        .review_queue
        .iter()
        .find(|u| u.id == unit_id)
        .expect("sent-back unit still in review queue");
    assert_eq!(unit.status, calxgloss_types::ReviewStatus::SendBack);
    assert!(dashboard.status_counts.send_back >= 1);
}

/// Test that the static file fallback serves CSS and JS correctly.
#[tokio::test]
async fn test_static_files_served() {
    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    // CSS file
    let css_resp = reqwest::get(format!("http://127.0.0.1:{}/app.css", fixture.port()))
        .await
        .expect("CSS request succeeds");

    assert_eq!(css_resp.status(), 200);
    let css_type = css_resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        css_type.contains("css"),
        "CSS content-type, got: {css_type}"
    );

    // JS file
    let js_resp = reqwest::get(format!("http://127.0.0.1:{}/app.js", fixture.port()))
        .await
        .expect("JS request succeeds");

    assert_eq!(js_resp.status(), 200);
    let js_type = js_resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        js_type.contains("javascript") || js_type.contains("application"),
        "JS content-type, got: {js_type}"
    );

    // ES module files under js/ must be served too — the page loads
    // them natively via `import`, so nested paths must resolve.
    let module_resp = reqwest::get(format!(
        "http://127.0.0.1:{}/js/dashboard.js",
        fixture.port()
    ))
    .await
    .expect("module request succeeds");

    assert_eq!(module_resp.status(), 200);
    let module_type = module_resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        module_type.contains("javascript"),
        "module content-type, got: {module_type}"
    );

    // Non-existent file should 404
    let notfound_resp = reqwest::get(format!(
        "http://127.0.0.1:{}/does-not-exist.css",
        fixture.port()
    ))
    .await
    .expect("404 request succeeds");

    assert_eq!(notfound_resp.status(), 404);
}

/// Test the WebSocket upgrade endpoint exists (basic sanity).
/// Full WebSocket E2E would require a WS client — this just checks the route works.
#[tokio::test]
async fn test_websocket_upgrade_exists() {
    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path());
    let (manager, _event_tx) = SessionManager::new();
    let progress = ProgressState::new();
    let router = build_router_with_ws(state.clone(), manager, progress);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    // Attempt a WebSocket upgrade — it should not return a 404.
    let resp = reqwest::get(format!(
        "http://127.0.0.1:{}/api/events/upgrade",
        fixture.port()
    ))
    .await
    .expect("upgrade endpoint exists");

    // Should NOT be 404 — WS upgrade will fail differently.
    assert_ne!(
        resp.status(),
        404,
        "/api/events/upgrade should not return 404"
    );
}

// ─────────────────────────────────────────────────────────────
// Diff endpoint tests
// ─────────────────────────────────────────────────────────────

/// Test the diff endpoint returns structured diff data.
#[tokio::test]
async fn test_unit_diff_endpoint() {
    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let unit_id = "game_logic.dll/DrawPrimitive/v2";
    let encoded_id = urlencoding::encode(unit_id);
    let resp = reqwest::get(format!(
        "http://127.0.0.1:{}/api/units/{}/diff",
        fixture.port(),
        encoded_id
    ))
    .await
    .expect("diff request succeeds");

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("diff body is JSON");
    assert_eq!(body["success"], true);

    let files = body["diff"].as_array().expect("diff is array");
    // Allow empty diff (the diff between main and v2 might be empty
    // depending on the fixture setup).
    // Each file should have a path and hunks
    for file in files {
        assert!(file["path"].as_str().is_some());
        assert!(file["hunks"].as_array().is_some());
    }
}

/// Test the Ghidra context endpoint returns not-found for units without Ghidra artifacts.
/// (Our fixture doesn't create Ghidra data, so this should return not-found gracefully.)
#[tokio::test]
async fn test_unit_ghidra_missing_artifacts() {
    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let unit_id = "game_logic.dll/DrawPrimitive/v2";
    let encoded_id = urlencoding::encode(unit_id);
    let resp = reqwest::get(format!(
        "http://127.0.0.1:{}/api/units/{}/ghidra",
        fixture.port(),
        encoded_id
    ))
    .await
    .expect("ghidra request succeeds");

    // Returns success:true with an empty context when no Ghidra artifacts exist.
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("ghidra body is JSON");
    assert_eq!(body["success"], true);
}
// ─────────────────────────────────────────────────────────────
// Unit process detail tests (issue #62)
// ─────────────────────────────────────────────────────────────

/// Writes canned run-telemetry artifacts for game_logic.dll/DrawPrimitive:
/// a token-usage log (2 attempts, escalated tiers), a fault log (2 faults),
/// and a Ghidra analysis artifact (for the tier rationale).
fn write_canned_run_telemetry(fixture: &TestFixture) {
    let analysis_dir = fixture.repo_path().join("re").join("analysis");
    std::fs::create_dir_all(&analysis_dir).expect("create analysis dir");

    let token_log = serde_json::json!({
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
            },
            {
                "timestamp": 1767226200,
                "binary": "audio.dll",
                "function": "PlaySample",
                "attempt": 1,
                "strategy": "initial",
                "context_tier": "signature",
                "tokens_used": 150,
                "success": true
            }
        ]
    });
    std::fs::write(
        analysis_dir.join("token_usage.json"),
        serde_json::to_string_pretty(&token_log).expect("serialize token log"),
    )
    .expect("write token_usage.json");

    let fault_log = serde_json::json!({
        "entries": [
            {
                "timestamp": 1767225660,
                "binary": "game_logic.dll",
                "function": "DrawPrimitive",
                "attempt": 1,
                "strategy": "initial",
                "category": "context_window_exceeded",
                "severity": "warning",
                "description": "Prompt exceeded context window",
                "recovery": "escalate_context"
            },
            {
                "timestamp": 1767225960,
                "binary": "game_logic.dll",
                "function": "DrawPrimitive",
                "attempt": 2,
                "strategy": "compile_fix",
                "category": "hallucination",
                "severity": "error",
                "description": "Output referenced unknown symbol",
                "recovery": "retry"
            },
            {
                "timestamp": 1767226260,
                "binary": "audio.dll",
                "function": "PlaySample",
                "attempt": 1,
                "strategy": "initial",
                "category": "slow_response",
                "severity": "warning",
                "description": "Response latency exceeded threshold",
                "recovery": "retry"
            }
        ]
    });
    std::fs::write(
        analysis_dir.join("fault_log.json"),
        serde_json::to_string_pretty(&fault_log).expect("serialize fault log"),
    )
    .expect("write fault_log.json");

    let dll_dir = analysis_dir.join("game_logic.dll");
    std::fs::create_dir_all(&dll_dir).expect("create binary dir");
    let ghidra_artifact = serde_json::json!({
        "name": "DrawPrimitive",
        "address": 4198400,
        "binary": "game_logic.dll",
        "disassembly": "push rbp\nmov rbp, rsp\nmov rax, [rdi]\ncall DirectXDraw\ncall Present\nret\npop rbp\nret\nnop\nnop",
        "decompiler_output": "void DrawPrimitive() { DirectXDraw(); Present(); }",
        "windows_apis": [
            { "name": "DirectXDraw", "category": "DirectX", "pal_mapping": "wgpu::Queue::submit" },
            { "name": "Present", "category": "DirectX", "pal_mapping": "wgpu::Surface::present" }
        ],
        "call_graph": []
    });
    std::fs::write(
        dll_dir.join("DrawPrimitive.json"),
        serde_json::to_string_pretty(&ghidra_artifact).expect("serialize ghidra artifact"),
    )
    .expect("write DrawPrimitive.json");
}

/// Fetches the unit detail body for `unit_id` from a plain serve router.
async fn fetch_unit_detail(fixture: &TestFixture, unit_id: &str) -> serde_json::Value {
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let resp = reqwest::get(format!(
        "http://127.0.0.1:{}/api/units/{}",
        fixture.port(),
        urlencoding::encode(unit_id)
    ))
    .await
    .expect("unit detail request succeeds");

    assert_eq!(resp.status(), 200);
    resp.json().await.expect("unit detail body is JSON")
}

#[tokio::test]
async fn test_unit_process_sections_from_canned_artifacts() {
    let fixture = TestFixture::new();
    write_canned_run_telemetry(&fixture);
    let body = fetch_unit_detail(&fixture, "game_logic.dll/DrawPrimitive/v2").await;

    assert_eq!(body["success"], true);
    let process = body["unit"]["process"]
        .as_object()
        .expect("unit detail should include a process object");

    // --- Tier section: derived from the last token-usage attempt ---
    let tier = &process["tier"];
    assert_eq!(tier["tier"], 2, "tier number should be 2 (with_tests)");
    assert_eq!(tier["label"], "with_tests");
    assert!(tier["description"].is_string());
    assert_eq!(
        tier["escalated"], true,
        "tier should be flagged as escalated"
    );

    // Rationale: recomputed from the Ghidra analysis artifact.
    let rationale = &tier["rationale"];
    assert_eq!(
        rationale["api_call_count"], 2,
        "api_call_count should count windows_apis entries"
    );
    assert_eq!(
        rationale["complexity"], "standard",
        "complexity should be detected from the disassembly artifact"
    );

    // Retry strategy history: one record per attempt.
    let attempts = tier["attempts"].as_array().expect("attempts array");
    assert_eq!(attempts.len(), 2);
    assert_eq!(attempts[0]["attempt"], 1);
    assert_eq!(attempts[0]["strategy"], "initial");
    assert_eq!(attempts[0]["tier"], "disassembly");
    assert_eq!(attempts[1]["attempt"], 2);
    assert_eq!(attempts[1]["strategy"], "compile_fix");
    assert_eq!(attempts[1]["tier"], "with_tests");

    // --- Fault section: only this unit's faults, in order ---
    let faults = process["faults"].as_array().expect("faults array");
    assert_eq!(faults.len(), 2, "should include only this unit's faults");
    assert_eq!(faults[0]["attempt"], 1);
    assert_eq!(faults[0]["category"], "context_window_exceeded");
    assert_eq!(faults[0]["severity"], "warning");
    assert_eq!(faults[0]["recovery"], "escalate_context");
    assert_eq!(faults[1]["attempt"], 2);
    assert_eq!(faults[1]["category"], "hallucination");
    assert_eq!(faults[1]["severity"], "error");

    // --- Token section: totals over this unit's attempts ---
    let tokens = &process["tokens"];
    assert_eq!(tokens["total_tokens"], 7168, "4096 + 3072");
    assert_eq!(tokens["successful_tokens"], 3072);
    assert_eq!(tokens["failed_tokens"], 4096);
    assert_eq!(tokens["attempts"], 2);
    let per_attempt = tokens["per_attempt"].as_array().expect("per_attempt array");
    assert_eq!(per_attempt.len(), 2);
    assert_eq!(per_attempt[0]["attempt"], 1);
    assert_eq!(per_attempt[0]["strategy"], "initial");
    assert_eq!(per_attempt[0]["tokens_used"], 4096);
    assert_eq!(per_attempt[0]["success"], false);
    assert_eq!(per_attempt[1]["attempt"], 2);
    assert_eq!(per_attempt[1]["tokens_used"], 3072);
    assert_eq!(per_attempt[1]["success"], true);

    // --- Strategy section: per-strategy success rates ---
    let strategies = process["strategies"].as_array().expect("strategies array");
    assert_eq!(strategies.len(), 2);
    assert_eq!(strategies[0]["strategy"], "initial");
    assert_eq!(strategies[0]["attempts"], 1);
    assert_eq!(strategies[0]["successes"], 0);
    assert_eq!(strategies[0]["success_rate"], 0.0);
    assert_eq!(strategies[1]["strategy"], "compile_fix");
    assert_eq!(strategies[1]["attempts"], 1);
    assert_eq!(strategies[1]["successes"], 1);
    assert_eq!(strategies[1]["success_rate"], 1.0);
}

#[tokio::test]
async fn test_unit_process_degrades_to_empty_sections() {
    let fixture = TestFixture::new();
    let body = fetch_unit_detail(&fixture, "game_logic.dll/UpdateScene/v1").await;

    // No telemetry artifacts exist for this unit — every section must be
    // present but empty, and the response must still be a success.
    assert_eq!(body["success"], true);
    let process = body["unit"]["process"]
        .as_object()
        .expect("unit detail should include a process object");

    let tier = &process["tier"];
    assert!(
        tier["tier"].is_null(),
        "tier should be null when no telemetry exists"
    );
    assert_eq!(tier["attempts"].as_array().unwrap().len(), 0);
    assert!(tier["rationale"].is_null(), "rationale should be null");
    assert!(process["faults"].as_array().unwrap().is_empty());
    assert_eq!(process["tokens"]["total_tokens"], 0);
    assert!(
        process["tokens"]["per_attempt"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(process["strategies"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn test_unit_process_corrupt_artifacts_degrade() {
    let fixture = TestFixture::new();
    let analysis_dir = fixture.repo_path().join("re").join("analysis");
    std::fs::create_dir_all(&analysis_dir).expect("create analysis dir");
    std::fs::write(analysis_dir.join("token_usage.json"), "{{{ not json")
        .expect("write corrupt token log");
    std::fs::write(analysis_dir.join("fault_log.json"), "garbage")
        .expect("write corrupt fault log");
    let dll_dir = analysis_dir.join("game_logic.dll");
    std::fs::create_dir_all(&dll_dir).expect("create binary dir");
    std::fs::write(dll_dir.join("DrawPrimitive.json"), "also not json")
        .expect("write corrupt ghidra artifact");

    let body = fetch_unit_detail(&fixture, "game_logic.dll/DrawPrimitive/v2").await;

    assert_eq!(body["success"], true, "corrupt artifacts must not error");
    let process = body["unit"]["process"]
        .as_object()
        .expect("unit detail should include a process object");
    assert!(process["tier"]["tier"].is_null());
    assert!(process["faults"].as_array().unwrap().is_empty());
    assert_eq!(process["tokens"]["total_tokens"], 0);
    assert!(process["strategies"].as_array().unwrap().is_empty());
}

// ─────────────────────────────────────────────────────────────
// Unit analysis context tests (issue #73)
// ─────────────────────────────────────────────────────────────

/// Writes canned analysis artifacts for game_logic.dll/DrawPrimitive: a
/// function analysis artifact with two identified Windows APIs, and a
/// per-binary call-graph record where DrawPrimitive is called by GameLoop
/// (caller stored as an address) and calls BlitSurface (named edge) and
/// InternalFlush (edge with no recorded name, resolved via target address).
fn write_canned_analysis_context(fixture: &TestFixture) {
    let analysis_dir = fixture.repo_path().join("re").join("analysis");
    std::fs::create_dir_all(&analysis_dir).expect("create analysis dir");

    let dll_dir = analysis_dir.join("game_logic.dll");
    std::fs::create_dir_all(&dll_dir).expect("create binary dir");
    std::fs::write(
        dll_dir.join("DrawPrimitive.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "name": "DrawPrimitive",
            "address": 4198400,
            "binary": "game_logic.dll",
            "disassembly": "push rbp\ncall Present\nret",
            "decompiler_output": "void DrawPrimitive() { Present(); }",
            "windows_apis": [
                { "name": "Present", "category": "DirectX", "pal_mapping": "wgpu::Surface::present" },
                { "name": "CreateFileA", "category": "Win32Core", "pal_mapping": "std::fs::File::open" }
            ],
            "call_graph": []
        }))
        .expect("serialize function artifact"),
    )
    .expect("write DrawPrimitive.json");

    std::fs::write(
        analysis_dir.join("game_logic.dll_call_graph.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "binary": "game_logic.dll",
            "functions": [
                {
                    "name": "DrawPrimitive",
                    "address": 4198400,
                    "callers": [4198656],
                    "callees": [
                        { "source": 4198400, "target": 4198912, "call_site": 4198410, "call_type": "Direct", "callee_name": "BlitSurface" },
                        { "source": 4198400, "target": 4199168, "call_site": 4198420, "call_type": "Direct", "callee_name": "" }
                    ],
                    "node_category": "Middle"
                },
                { "name": "GameLoop", "address": 4198656, "callers": [], "callees": [], "node_category": "Root" },
                { "name": "BlitSurface", "address": 4198912, "callers": [], "callees": [], "node_category": "Leaf" },
                { "name": "InternalFlush", "address": 4199168, "callers": [], "callees": [], "node_category": "Leaf" }
            ]
        }))
        .expect("serialize call graph"),
    )
    .expect("write call graph artifact");
}

#[tokio::test]
async fn test_unit_detail_analysis_from_canned_artifacts() {
    let fixture = TestFixture::new();
    write_canned_analysis_context(&fixture);
    let body = fetch_unit_detail(&fixture, "game_logic.dll/DrawPrimitive/v2").await;

    assert_eq!(body["success"], true);
    let analysis = body["unit"]["analysis"]
        .as_object()
        .expect("unit detail should include an analysis object");

    // Windows API mappings: name, category, and PAL mapping, in artifact order.
    let api_mappings = analysis["api_mappings"]
        .as_array()
        .expect("api_mappings array");
    assert_eq!(api_mappings.len(), 2);
    assert_eq!(api_mappings[0]["name"], "Present");
    assert_eq!(api_mappings[0]["category"], "DirectX");
    assert_eq!(api_mappings[0]["pal_mapping"], "wgpu::Surface::present");
    assert_eq!(api_mappings[1]["name"], "CreateFileA");
    assert_eq!(api_mappings[1]["category"], "Win32Core");
    assert_eq!(api_mappings[1]["pal_mapping"], "std::fs::File::open");

    // Call graph context: caller addresses resolve to names; unnamed callee
    // edges resolve through the graph's function list.
    let call_graph = &analysis["call_graph"];
    let callers = call_graph["callers"].as_array().expect("callers array");
    assert_eq!(callers.len(), 1);
    assert_eq!(
        callers[0], "GameLoop",
        "caller address should resolve to its name"
    );
    let callees = call_graph["callees"].as_array().expect("callees array");
    assert_eq!(callees.len(), 2);
    assert_eq!(callees[0], "BlitSurface");
    assert_eq!(
        callees[1], "InternalFlush",
        "unnamed edge should resolve via target address"
    );
}

#[tokio::test]
async fn test_unit_detail_analysis_degrades_to_empty() {
    let fixture = TestFixture::new();
    let body = fetch_unit_detail(&fixture, "game_logic.dll/DrawPrimitive/v2").await;

    // No analysis artifacts exist — both sections must be present but empty,
    // and the response must still be a success.
    assert_eq!(body["success"], true);
    let analysis = body["unit"]["analysis"]
        .as_object()
        .expect("unit detail should include an analysis object");
    assert!(
        analysis["api_mappings"]
            .as_array()
            .expect("api_mappings array")
            .is_empty()
    );
    assert!(
        analysis["call_graph"]["callers"]
            .as_array()
            .expect("callers array")
            .is_empty()
    );
    assert!(
        analysis["call_graph"]["callees"]
            .as_array()
            .expect("callees array")
            .is_empty()
    );
}

#[tokio::test]
async fn test_unit_detail_analysis_corrupt_artifacts_degrade() {
    let fixture = TestFixture::new();
    let analysis_dir = fixture.repo_path().join("re").join("analysis");
    let dll_dir = analysis_dir.join("game_logic.dll");
    std::fs::create_dir_all(&dll_dir).expect("create binary dir");
    std::fs::write(dll_dir.join("DrawPrimitive.json"), "{{{ not json")
        .expect("write corrupt function artifact");
    std::fs::write(
        analysis_dir.join("game_logic.dll_call_graph.json"),
        "also not json",
    )
    .expect("write corrupt call graph artifact");

    let body = fetch_unit_detail(&fixture, "game_logic.dll/DrawPrimitive/v2").await;

    assert_eq!(body["success"], true, "corrupt artifacts must not error");
    let analysis = body["unit"]["analysis"]
        .as_object()
        .expect("unit detail should include an analysis object");
    assert!(
        analysis["api_mappings"]
            .as_array()
            .expect("api_mappings array")
            .is_empty()
    );
    assert!(
        analysis["call_graph"]["callers"]
            .as_array()
            .expect("callers array")
            .is_empty()
    );
    assert!(
        analysis["call_graph"]["callees"]
            .as_array()
            .expect("callees array")
            .is_empty()
    );
}

/// Test that build_dashboard API (exposed at crate root) builds correctly from the fixture.
#[tokio::test]
async fn test_build_dashboard_api() {
    let fixture = TestFixture::new();
    let dashboard = build_dashboard(&fixture.repo_path()).expect("build dashboard should succeed");

    assert!(
        !dashboard.review_queue.is_empty(),
        "dashboard should have units"
    );

    // Verify we can find the expected units
    let unit_ids: Vec<&str> = dashboard
        .review_queue
        .iter()
        .map(|u| u.id.as_str())
        .collect();
    assert!(
        unit_ids
            .iter()
            .any(|id| id.contains("game_logic.dll") && id.contains("DrawPrimitive")),
        "DrawPrimitive unit present in review queue (IDs: {:?})",
        unit_ids
    );

    // Check all units across review_queue and recent_activity
    let all_ids: Vec<&str> = dashboard
        .review_queue
        .iter()
        .map(|u| u.id.as_str())
        .chain(dashboard.recent_activity.iter().map(|u| u.id.as_str()))
        .collect();
    assert!(
        all_ids
            .iter()
            .any(|id| id.contains("game_logic.dll") && id.contains("DrawPrimitive")),
        "DrawPrimitive unit present (all: {:?})",
        all_ids
    );
    assert!(
        all_ids
            .iter()
            .any(|id| id.contains("game_logic.dll") && id.contains("UpdateScene")),
        "UpdateScene unit present (all: {:?})",
        all_ids
    );

    // Verify status counts
    let counts = &dashboard.status_counts;
    assert!(counts.accepted >= 1); // UpdateScene is merged
    assert!(counts.total() >= 3); // classify + 2 func translations
}

// ─────────────────────────────────────────────────────────────
// Headless browser test (requires Chromium/Chrome installed)
// ─────────────────────────────────────────────────────────────

/// Launch headless Chrome with the flags that work inside containers/CI.
///
/// Chrome's CDP calls are **blocking**, so every browser test must run on a
/// multi-thread runtime (`#[tokio::test(flavor = "multi_thread")]`): on the
/// default current-thread runtime the blocking calls starve the axum server
/// task spawned by the same test, the page is never served, and navigation
/// times out with "The event waited for never came".
fn launch_headless_browser() -> headless_chrome::Browser {
    use headless_chrome::{Browser, LaunchOptionsBuilder};

    Browser::new(
        LaunchOptionsBuilder::default()
            .headless(true)
            .args(vec![
                std::ffi::OsStr::new("--no-sandbox"),
                std::ffi::OsStr::new("--disable-gpu"),
                std::ffi::OsStr::new("--disable-dev-shm-usage"),
                // Wide viewport: narrow windows clamp the pipeline row's
                // head track to its minimum and mask column-alignment
                // bugs that only appear once tracks grow with content.
                std::ffi::OsStr::new("--window-size=1400,900"),
            ])
            .build()
            .expect("build chrome launch options"),
    )
    .expect("launch headless chrome")
}

/// Open a tab on the fixture's server and wait for the page to load.
///
/// `navigate_to` waits for Chrome's `networkAlmostIdle` lifecycle event, which
/// only arrives once the dashboard's own fetches settle — generous by design so
/// a slow machine still passes.
fn open_dashboard_tab(
    browser: &headless_chrome::Browser,
    port: u16,
) -> std::sync::Arc<headless_chrome::Tab> {
    let tab = browser.new_tab().expect("open new tab");
    tab.navigate_to(&format!("http://127.0.0.1:{port}"))
        .expect("navigate to server root");
    tab.wait_until_navigated().expect("wait for navigation");
    tab.enable_runtime().expect("enable runtime");
    tab
}

/// Test that a headless browser can navigate to the server and
/// verify the HTML page loads without JavaScript errors.
///
/// The actual data rendering is verified by the API-level tests above,
/// which are faster and don't require a browser installation.
///
/// This test is marked `#[ignore]` because it requires
/// Chromium/Chrome to be installed on the test machine.
///
/// Run with: `cargo test --features server --test e2e headless -- --ignored`
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Chromium/Chrome installed; run with --ignored"]
async fn test_headless_browser_page_loads() {
    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(500)).await;

    let browser = launch_headless_browser();
    // Navigate to the server's root (HTML page) and wait for it to load.
    let tab = open_dashboard_tab(&browser, fixture.port());

    // Verify the page title contains Calxgloss.
    let title = tab.get_title().expect("get page title");
    assert!(
        title.contains("Calxgloss"),
        "Page title should contain 'Calxgloss', got: {title}"
    );

    // Verify the page content is non-empty.
    let content = tab.get_content().expect("get page content");
    assert!(
        content.len() > 100,
        "Page content should be non-trivial (got {} chars)",
        content.len()
    );

    // Verify the HTML contains the key frontend elements.
    assert!(
        content.contains("app.js") || content.contains("Calxgloss"),
        "Page should contain frontend references or title"
    );

    // Verify the dependency graph endpoint is reachable via fetch.
    // `awaitPromise` must be true here — the expression evaluates to a
    // Promise, and without awaiting it the value is the promise object itself.
    let graph_result = tab
        .evaluate(
            "fetch('/api/graph').then(r => r.ok).catch(() => false)",
            true,
        )
        .expect("evaluate fetch graph");
    let is_graph_ok: bool = graph_result
        .value
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    assert!(
        is_graph_ok,
        "Dependency graph API should be reachable from browser"
    );

    // Verify the dashboard endpoint is reachable via fetch.
    let dashboard_result = tab
        .evaluate(
            "fetch('/api/dashboard').then(r => r.ok).catch(() => false)",
            true,
        )
        .expect("evaluate fetch dashboard");
    let is_dashboard_ok: bool = dashboard_result
        .value
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    assert!(
        is_dashboard_ok,
        "Dashboard API should be reachable from browser"
    );

    tab.close_target().ok();
    drop(browser);
}

/// Headless-browser test for the dashboard server status card (issue #59):
/// the card must render the values served by `GET /api/server/status` —
/// version, uptime, and the pipeline state.
///
/// Run with: `cargo test --features server --test e2e headless -- --ignored`
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Chromium/Chrome installed; run with --ignored"]
async fn test_headless_server_status_card() {
    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(500)).await;

    let browser = launch_headless_browser();
    let tab = open_dashboard_tab(&browser, fixture.port());

    // The card renders asynchronously once the dashboard fetches settle;
    // poll until it appears (up to ~5 seconds).
    let mut rendered = false;
    for _ in 0..25 {
        let found = tab
            .evaluate("!!document.getElementById('server-status-card')", false)
            .ok()
            .and_then(|r| r.value)
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if found {
            rendered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(rendered, "dashboard should render the server status card");

    let text_of = |id: &str| -> String {
        tab.evaluate(
            &format!("document.getElementById('{id}')?.textContent || ''",),
            false,
        )
        .expect("evaluate card text")
        .value
        .and_then(|v| v.as_str().map(String::from))
        .unwrap_or_default()
    };

    let version_text = text_of("server-status-version");
    assert!(
        version_text.contains(env!("CARGO_PKG_VERSION")),
        "status card should show the server version, got: {version_text}"
    );

    let uptime_text = text_of("server-status-uptime");
    assert!(
        !uptime_text.is_empty() && uptime_text != "—",
        "status card should show a non-empty uptime, got: {uptime_text}"
    );

    // Plain serve has no live pipeline — the card must say so honestly.
    assert_eq!(
        text_of("server-status-pipeline"),
        "no pipeline",
        "plain serve status card should report 'no pipeline'"
    );

    tab.close_target().ok();
    drop(browser);
}

/// Headless-browser test for the dashboard server control panel (issue #60):
/// the panel must render with shutdown/restart buttons and a log-level
/// selector populated with the levels the server accepts.
///
/// Run with: `cargo test --features server --test e2e headless -- --ignored`
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Chromium/Chrome installed; run with --ignored"]
async fn test_headless_server_control_panel() {
    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(500)).await;

    let browser = launch_headless_browser();
    let tab = open_dashboard_tab(&browser, fixture.port());

    // The panel renders asynchronously once the dashboard fetches settle;
    // poll until it appears (up to ~5 seconds).
    let mut rendered = false;
    for _ in 0..25 {
        let found = tab
            .evaluate("!!document.getElementById('server-control-panel')", false)
            .ok()
            .and_then(|r| r.value)
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if found {
            rendered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(rendered, "dashboard should render the server control panel");

    let eval_bool = |expr: &str| -> bool {
        tab.evaluate(expr, false)
            .expect("evaluate panel expression")
            .value
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    };

    assert!(
        eval_bool("!!document.getElementById('server-shutdown-btn')"),
        "control panel should have a shutdown button"
    );
    assert!(
        eval_bool("!!document.getElementById('server-restart-btn')"),
        "control panel should have a restart button"
    );

    // The log-level select must offer the levels the server accepts.
    assert!(
        eval_bool(
            "['off','error','warn','info','debug','trace'].every(\
                l => [...document.getElementById('server-loglevel-select').options]\
                    .some(o => o.value === l))"
        ),
        "log-level select should offer off/error/warn/info/debug/trace"
    );
    // And pre-select the level the server reports.
    assert!(
        eval_bool(
            "document.getElementById('server-loglevel-select').value === \
                document.getElementById('server-status-loglevel').textContent"
        ),
        "log-level select should pre-select the current server log level"
    );

    tab.close_target().ok();
    drop(browser);
}

/// Headless-browser test for the dashboard pipeline phase bar (issue #61):
/// in live mode the bar must render one segment per master-plan phase —
/// 8 total, including Phase 2.5 (PAL Design) — and Restitching and
/// Documentation must render as no-data-source, never as zero progress.
///
/// Run with: `cargo test --features server --test e2e headless -- --ignored`
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Chromium/Chrome installed; run with --ignored"]
async fn test_headless_pipeline_phase_bar_live() {
    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path());
    let events = TranslationEvents::new(128);
    let manager = SessionManager::new_with_broadcast(events.subscribe());
    let progress = ProgressState::new();
    let router = build_router_with_ws(state, manager, progress);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    // A little live data so the pipeline panel is visible.
    events.emit(ProgressEvent::ClassificationComplete {
        binary: "d3d9.dll".into(),
        category: "WindowsOs".into(),
        strategy: "PalMapping".into(),
        crate_replacement: None,
        exported_symbols: 25,
        imported_symbols: 6,
    });
    events.emit(ProgressEvent::TranslationStarted {
        binary: "game_logic.dll".into(),
        function: "DrawPrimitive".into(),
    });
    events.emit(ProgressEvent::TestsGenerated {
        binary: "game_logic.dll".into(),
        function: "DrawPrimitive".into(),
        test_count: 3,
    });

    tokio::time::sleep(Duration::from_millis(300)).await;

    let browser = launch_headless_browser();
    let tab = open_dashboard_tab(&browser, fixture.port());

    let eval_bool = |expr: &str| -> bool {
        tab.evaluate(expr, false)
            .ok()
            .and_then(|r| r.value)
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    };
    let eval_len = |expr: &str| -> i64 {
        tab.evaluate(expr, false)
            .ok()
            .and_then(|r| r.value)
            .and_then(|v| v.as_i64())
            .unwrap_or(-1)
    };

    // The bar renders asynchronously once the pipeline fetch settles;
    // poll until all 8 segments appear (up to ~5 seconds).
    let mut rendered = false;
    for _ in 0..25 {
        if eval_len("document.querySelectorAll('#pipeline-phase-bar .phase-segment').length") == 8 {
            rendered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(rendered, "phase bar should render 8 segments in live mode");

    // Segments appear in bar order, Phase 1 → 7 with 2.5 between 2 and 3.
    let phases_json = tab
        .evaluate(
            "JSON.stringify([...document.querySelectorAll('#pipeline-phase-bar .phase-segment')]\
                .map(s => s.dataset.phase))",
            false,
        )
        .expect("evaluate phase segment list")
        .value
        .and_then(|v| v.as_str().map(String::from))
        .unwrap_or_default();
    assert_eq!(
        phases_json,
        r#"["project_ingestion","disassembly_tagging","pal_design","test_generation","rust_code_generation","behavior_verification","restitching","documentation"]"#
    );

    // Phase 2.5 (PAL Design) is present as its own segment.
    assert!(
        eval_bool(
            "!!document.querySelector('#pipeline-phase-bar .phase-segment[data-phase=\"pal_design\"]')"
        ),
        "PAL Design must be its own segment"
    );

    // Restitching & Documentation render honestly as no-data-source.
    for phase in ["restitching", "documentation"] {
        assert!(
            eval_bool(&format!(
                "document.querySelector('#pipeline-phase-bar .phase-segment[data-phase=\"{phase}\"]')\
                    ?.classList.contains('state-no_data_source') === true"
            )),
            "{phase} segment must render as no-data-source, not zero progress"
        );
    }

    tab.close_target().ok();
    drop(browser);
}

/// Headless-browser test for the per-binary progress panel (issue #63):
/// in live mode the pipeline panel must render one row per target binary
/// with its classification strategy, function counts (total, translated,
/// in-progress, queued, failed), token consumption, and success rate —
/// unknown values as em-dashes, never fabricated zeros. The quick-action
/// buttons must be placeholders that announce only: clicking one fires no
/// state-changing request and touches no pipeline state.
///
/// Run with: `cargo test --features server --test e2e headless -- --ignored`
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Chromium/Chrome installed; run with --ignored"]
async fn test_headless_pipeline_binary_rows() {
    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path());
    let events = TranslationEvents::new(128);
    let manager = SessionManager::new_with_broadcast(events.subscribe());
    let progress = ProgressState::new();
    let router = build_router_with_ws(state, manager, progress);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    // Four binaries, one per classification strategy plus an unclassified one:
    // d3d9 via PAL mapping (classified only), dinput8 via crate replacement
    // with one unit in flight, engine via full RE (classified only), and
    // game_logic discovered unclassified with a batch summary as the
    // authoritative count source: 2 of 5 translated, 1 failed, 5000 tokens
    // → 2 queued, 67% success rate.
    events.emit(ProgressEvent::ClassificationComplete {
        binary: "d3d9.dll".into(),
        category: "WindowsOs".into(),
        strategy: "PalMapping".into(),
        crate_replacement: None,
        exported_symbols: 25,
        imported_symbols: 6,
    });
    events.emit(ProgressEvent::ClassificationComplete {
        binary: "dinput8.dll".into(),
        category: "WindowsOs".into(),
        strategy: "CrateReplacement".into(),
        crate_replacement: Some("wgpu".into()),
        exported_symbols: 10,
        imported_symbols: 4,
    });
    events.emit(ProgressEvent::TranslationStarted {
        binary: "dinput8.dll".into(),
        function: "GetDeviceState".into(),
    });
    events.emit(ProgressEvent::ClassificationComplete {
        binary: "engine.dll".into(),
        category: "ProjectSpecific".into(),
        strategy: "ReverseEngineer".into(),
        crate_replacement: None,
        exported_symbols: 40,
        imported_symbols: 12,
    });
    // engine.dll's batch pass is in flight — the row must show it working
    // even though no unit event exists yet.
    events.emit(ProgressEvent::BatchStarted {
        binary: "engine.dll".into(),
    });
    events.emit(ProgressEvent::BatchSummary {
        binary: "game_logic.dll".into(),
        total_functions: 5,
        success_count: 2,
        failure_count: 1,
        total_attempts: 4,
        total_tokens: 5000,
    });

    // Give the event-forwarding task time to drain the channel.
    tokio::time::sleep(Duration::from_millis(300)).await;

    let browser = launch_headless_browser();
    let tab = open_dashboard_tab(&browser, fixture.port());

    let eval_bool = |expr: &str| -> bool {
        tab.evaluate(expr, false)
            .ok()
            .and_then(|r| r.value)
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    };
    let eval_len = |expr: &str| -> i64 {
        tab.evaluate(expr, false)
            .ok()
            .and_then(|r| r.value)
            .and_then(|v| v.as_i64())
            .unwrap_or(-1)
    };
    let eval_text = |expr: &str| -> String {
        tab.evaluate(expr, false)
            .ok()
            .and_then(|r| r.value)
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_default()
    };

    // Rows render asynchronously once the pipeline fetch settles;
    // poll until all four appear (up to ~5 seconds).
    let mut rendered = false;
    for _ in 0..25 {
        if eval_len(
            "document.querySelectorAll('#pipeline-binaries .pipeline-binary-row[data-binary]').length",
        ) == 4
        {
            rendered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        rendered,
        "pipeline panel should render one row per target binary"
    );

    // One row per discovered binary, keyed by name.
    for binary in ["d3d9.dll", "dinput8.dll", "engine.dll", "game_logic.dll"] {
        assert!(
            eval_bool(&format!(
                "!!document.querySelector('#pipeline-binaries [data-binary=\"{binary}\"]')"
            )),
            "row for {binary} should exist"
        );
    }

    let cell_text = |binary: &str, selector: &str| -> String {
        eval_text(&format!(
            "document.querySelector('#pipeline-binaries [data-binary=\"{binary}\"] {selector}')?.textContent || ''"
        ))
    };

    // ── game_logic: counts, tokens, and success rate from the canned batch ──
    assert!(
        cell_text("game_logic.dll", "[data-count=\"total\"]").contains('5'),
        "total functions from the batch summary, got: {}",
        cell_text("game_logic.dll", "[data-count=\"total\"]")
    );
    assert!(
        cell_text("game_logic.dll", "[data-count=\"translated\"]").contains('2'),
        "translated count, got: {}",
        cell_text("game_logic.dll", "[data-count=\"translated\"]")
    );
    assert!(
        cell_text("game_logic.dll", "[data-count=\"failed\"]").contains('1'),
        "failed count, got: {}",
        cell_text("game_logic.dll", "[data-count=\"failed\"]")
    );
    assert!(
        cell_text("game_logic.dll", "[data-count=\"queued\"]").contains('2'),
        "queued = 5 - 2 - 1, got: {}",
        cell_text("game_logic.dll", "[data-count=\"queued\"]")
    );
    assert!(
        cell_text("game_logic.dll", "[data-metric=\"tokens\"]").contains("5,000"),
        "token consumption, got: {}",
        cell_text("game_logic.dll", "[data-metric=\"tokens\"]")
    );
    assert!(
        cell_text("game_logic.dll", "[data-metric=\"success-rate\"]").contains("67%"),
        "success rate 2/3, got: {}",
        cell_text("game_logic.dll", "[data-metric=\"success-rate\"]")
    );

    // ── Status badge lives in the Success column, not beside the name ──
    assert!(
        eval_bool(
            "document.querySelectorAll('#pipeline-binaries .pipeline-binary-head .pipeline-binary-status').length === 0"
        ),
        "no status badge next to the binary name"
    );
    assert!(
        cell_text("d3d9.dll", "[data-metric=\"success-rate\"]").contains("In pipeline"),
        "a binary with no terminal outcomes shows its status in the Success column, got: {}",
        cell_text("d3d9.dll", "[data-metric=\"success-rate\"]")
    );
    assert!(
        cell_text("dinput8.dll", "[data-metric=\"success-rate\"]").contains("Translating"),
        "an in-flight binary shows Translating in the Success column, got: {}",
        cell_text("dinput8.dll", "[data-metric=\"success-rate\"]")
    );
    assert!(
        cell_text("engine.dll", "[data-metric=\"success-rate\"]").contains("Working"),
        "a binary whose batch pass started shows Working in the Success column, got: {}",
        cell_text("engine.dll", "[data-metric=\"success-rate\"]")
    );
    assert!(
        !cell_text("game_logic.dll", "[data-metric=\"success-rate\"]").contains("Batch done"),
        "a real success rate replaces the status placeholder, got: {}",
        cell_text("game_logic.dll", "[data-metric=\"success-rate\"]")
    );

    // ── dinput8: the in-flight unit counts as in progress ──────────────
    assert!(
        cell_text("dinput8.dll", "[data-count=\"in_progress\"]").contains('1'),
        "in-flight unit counted, got: {}",
        cell_text("dinput8.dll", "[data-count=\"in_progress\"]")
    );

    // ── Classification state column ──────────────────────────────────
    assert!(
        cell_text("d3d9.dll", ".pipeline-binary-state").contains("PAL trait"),
        "PAL trait state for a PAL-mapped binary, got: {}",
        cell_text("d3d9.dll", ".pipeline-binary-state")
    );
    assert!(
        cell_text("dinput8.dll", ".pipeline-binary-state").contains("wgpu"),
        "shim state names the replacement crate, got: {}",
        cell_text("dinput8.dll", ".pipeline-binary-state")
    );
    assert_eq!(
        cell_text("engine.dll", ".pipeline-binary-state").trim(),
        "Full RE",
        "a reverse-engineered binary reports Full RE in the state column, got: {}",
        cell_text("engine.dll", ".pipeline-binary-state")
    );
    assert!(
        cell_text("game_logic.dll", ".pipeline-binary-state").contains("Unclassified"),
        "an unclassified binary reports Unclassified in the state column, got: {}",
        cell_text("game_logic.dll", ".pipeline-binary-state")
    );
    assert!(
        eval_bool(
            "[...document.querySelectorAll('#pipeline-binaries .pipeline-binary-status')].every(e => !e.textContent.includes('Classified'))"
        ),
        "no Classified badge — the state column already carries the classification state"
    );
    assert!(
        eval_bool(
            "document.querySelectorAll('#pipeline-binaries .pipeline-binary-strategy').length === 0"
        ),
        "the redundant strategy column is gone"
    );
    // Switch to the Pipeline view so the rows have real layout boxes —
    // hidden elements report zero rects and would pass vacuously.
    tab.evaluate(
        "document.querySelector('.nav-tab[data-view=\"pipeline\"]').click()",
        false,
    )
    .expect("switch to pipeline view");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        eval_bool(
            r#"(() => {
                const pairs = [
                    ['.pipeline-binary-counts', 2],
                    ['.pipeline-binary-cost', 2],
                    ['div:nth-child(4)', 1],
                ];
                for (const [sel, n] of pairs) {
                    const h = document.querySelector(`#pipeline-binaries .pipeline-binary-header ${sel}`);
                    const r = document.querySelector(`#pipeline-binaries .pipeline-binary-row[data-binary] ${sel}`);
                    if (!h || !r) return false;
                    const hb = h.getBoundingClientRect(), rb = r.getBoundingClientRect();
                    if (hb.width < 100 || rb.width < 100) return false;
                    if (Math.abs(hb.left - rb.left) > 2 || Math.abs(hb.width - rb.width) > 2) return false;
                    if (n > 1) {
                        const hc = [...h.children].map(c => c.getBoundingClientRect());
                        const rc = [...r.children].map(c => c.getBoundingClientRect());
                        for (let i = 0; i < n; i++)
                            if (Math.abs(hc[i].left - rc[i].left) > 2) return false;
                    }
                }
                return true;
            })()"#
        ),
        "column headers line up with the data cells beneath them"
    );

    // ── Honesty: unknown totals and tokens are em-dashes ──────────────
    // (success-rate is absent here: with no terminal outcomes the cell
    // shows the status placeholder instead of a rate, never a zero)
    for (binary, selector) in [
        ("d3d9.dll", "[data-metric=\"tokens\"]"),
        ("d3d9.dll", "[data-count=\"total\"]"),
    ] {
        let text = cell_text(binary, selector);
        assert!(
            text.contains('—') && !text.contains('0'),
            "{binary} {selector} must render unknown as —, not a fabricated zero, got: {text}"
        );
    }

    // ── Quick-action buttons: placeholders that announce, never control ──
    assert!(
        eval_bool(
            "[...document.querySelectorAll('#pipeline-binaries [data-binary=\"game_logic.dll\"] .pipeline-binary-actions button')].length === 3"
        ),
        "each row should offer Start Translation, Pause, and Configure"
    );

    // Instrument fetch so any state-changing request becomes observable.
    tab.evaluate(
        "window.__nonGetFetches = 0; const origFetch = window.fetch.bind(window); \
             window.fetch = (...args) => { \
                 const method = ((args[1] && args[1].method) || 'GET').toUpperCase(); \
                 if (method !== 'GET') window.__nonGetFetches++; \
                 return origFetch(...args); \
             }; true",
        false,
    )
    .expect("instrument fetch");

    tab.evaluate(
        "document.querySelector('#pipeline-binaries [data-binary=\"game_logic.dll\"] [data-action=\"start\"]').click() === undefined",
        false,
    )
    .expect("click start-translation placeholder");

    // The click announces the placeholder via a toast…
    let mut announced = false;
    for _ in 0..25 {
        if eval_bool(
            "[...document.querySelectorAll('#toast-container .toast')].some(t => t.textContent.includes('W2'))",
        ) {
            announced = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        announced,
        "placeholder button should announce that pipeline control arrives in W2"
    );
    // …and touches no pipeline state: no state-changing request was fired.
    assert_eq!(
        eval_len("window.__nonGetFetches"),
        0,
        "placeholder buttons must not touch pipeline state"
    );

    tab.close_target().ok();
    drop(browser);
}

/// Headless-browser test for the unit process detail panel (issue #62):
/// clicking a unit backed by canned token-usage and fault-log artifacts
/// must render the four process sections — tier, faults, tokens, strategies.
///
/// Run with: `cargo test --features server --test e2e headless -- --ignored`
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Chromium/Chrome installed; run with --ignored"]
async fn test_headless_unit_process_sections() {
    let fixture = TestFixture::new();
    write_canned_run_telemetry(&fixture);
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(500)).await;

    let browser = launch_headless_browser();
    let tab = open_dashboard_tab(&browser, fixture.port());

    let eval_bool = |expr: &str| -> bool {
        tab.evaluate(expr, false)
            .ok()
            .and_then(|r| r.value)
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    };
    let eval_text = |expr: &str| -> String {
        tab.evaluate(expr, false)
            .ok()
            .and_then(|r| r.value)
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_default()
    };

    // Switch to the queue view so the full queue list renders.
    tab.evaluate(
        "document.querySelector('.nav-tab[data-view=\"queue\"]')?.click() === undefined",
        false,
    )
    .expect("click queue tab");

    // Wait for the telemetry-backed unit to appear in the queue list.
    let mut listed = false;
    for _ in 0..25 {
        if eval_bool(
            "!!document.querySelector('#full-queue-list [data-unit-id=\"game_logic.dll/DrawPrimitive/v2\"]')",
        ) {
            listed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        listed,
        "queue list should contain the DrawPrimitive v2 unit"
    );

    // Click the unit to render its inline detail panel.
    tab.evaluate(
        "document.querySelector('#full-queue-list [data-unit-id=\"game_logic.dll/DrawPrimitive/v2\"]').click() === undefined",
        false,
    )
    .expect("click queue item");

    // The four process sections render asynchronously once the unit fetch
    // settles; poll until all are present (up to ~5 seconds).
    let all_sections = "!!document.getElementById('process-tier-section') && \
         !!document.getElementById('process-faults-section') && \
         !!document.getElementById('process-tokens-section') && \
         !!document.getElementById('process-strategies-section')";
    let mut rendered = false;
    for _ in 0..25 {
        if eval_bool(all_sections) {
            rendered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        rendered,
        "detail panel should render the four process sections"
    );

    // The tier section shows the escalated tier from the canned telemetry.
    let tier_text = eval_text("document.getElementById('process-tier-section')?.textContent || ''");
    assert!(
        tier_text.contains("with_tests"),
        "tier section should show the final tier label, got: {tier_text}"
    );
    assert!(
        tier_text.contains("escalated"),
        "tier section should flag escalation, got: {tier_text}"
    );

    // The fault section lists the canned fault categories.
    let fault_text =
        eval_text("document.getElementById('process-faults-section')?.textContent || ''");
    assert!(
        fault_text.contains("context_window_exceeded") && fault_text.contains("hallucination"),
        "fault section should list both canned faults, got: {fault_text}"
    );

    // The strategy section shows the retry strategies used.
    let strategy_text =
        eval_text("document.getElementById('process-strategies-section')?.textContent || ''");
    assert!(
        strategy_text.contains("initial") && strategy_text.contains("compile_fix"),
        "strategy section should list both strategies, got: {strategy_text}"
    );

    tab.close_target().ok();
    drop(browser);
}

/// Headless-browser test for the unit analysis detail sections (issue #73):
/// clicking a unit backed by a canned function analysis artifact and a
/// canned per-binary call-graph record must render the Windows API mappings
/// and call graph context sections with the artifact's names.
///
/// Run with: `cargo test --features server --test e2e headless -- --ignored`
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Chromium/Chrome installed; run with --ignored"]
async fn test_headless_unit_analysis_sections() {
    let fixture = TestFixture::new();
    write_canned_analysis_context(&fixture);
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(500)).await;

    let browser = launch_headless_browser();
    let tab = open_dashboard_tab(&browser, fixture.port());

    let eval_bool = |expr: &str| -> bool {
        tab.evaluate(expr, false)
            .ok()
            .and_then(|r| r.value)
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    };
    let eval_text = |expr: &str| -> String {
        tab.evaluate(expr, false)
            .ok()
            .and_then(|r| r.value)
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_default()
    };

    // Switch to the queue view so the full queue list renders.
    tab.evaluate(
        "document.querySelector('.nav-tab[data-view=\"queue\"]')?.click() === undefined",
        false,
    )
    .expect("click queue tab");

    // Wait for the artifact-backed unit to appear in the queue list.
    let mut listed = false;
    for _ in 0..25 {
        if eval_bool(
            "!!document.querySelector('#full-queue-list [data-unit-id=\"game_logic.dll/DrawPrimitive/v2\"]')",
        ) {
            listed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        listed,
        "queue list should contain the DrawPrimitive v2 unit"
    );

    // Click the unit to render its inline detail panel.
    tab.evaluate(
        "document.querySelector('#full-queue-list [data-unit-id=\"game_logic.dll/DrawPrimitive/v2\"]').click() === undefined",
        false,
    )
    .expect("click queue item");

    // The two analysis sections render asynchronously once the unit fetch
    // settles; poll until both are present (up to ~5 seconds).
    let all_sections = "!!document.getElementById('api-mappings-section') && \
         !!document.getElementById('call-graph-section')";
    let mut rendered = false;
    for _ in 0..25 {
        if eval_bool(all_sections) {
            rendered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        rendered,
        "detail panel should render the API mappings and call graph sections"
    );

    // The API mappings section lists the canned APIs with category and PAL mapping.
    let api_text = eval_text("document.getElementById('api-mappings-section')?.textContent || ''");
    assert!(
        api_text.contains("Present")
            && api_text.contains("DirectX")
            && api_text.contains("wgpu::Surface::present"),
        "API mappings section should show name, category, and PAL mapping, got: {api_text}"
    );

    // The call graph section lists resolved caller and callee names.
    let cg_text = eval_text("document.getElementById('call-graph-section')?.textContent || ''");
    assert!(
        cg_text.contains("GameLoop") && cg_text.contains("BlitSurface"),
        "call graph section should list caller and callee names, got: {cg_text}"
    );

    tab.close_target().ok();
    drop(browser);
}

/// Headless-browser test for issue #64: with measured attempt durations in
/// the token-usage log, the pipeline panel must show a time estimate and the
/// review queue must render a per-unit effort column.
///
/// Run with: `cargo test --features server --test e2e headless -- --ignored`
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Chromium/Chrome installed; run with --ignored"]
async fn test_headless_pipeline_estimate_and_queue_effort() {
    let fixture = TestFixture::new();
    write_token_usage_log(&fixture, true);

    let state = ServerState::new(fixture.repo_path());
    let events = TranslationEvents::new(128);
    let manager = SessionManager::new_with_broadcast(events.subscribe());
    let progress = ProgressState::new();
    let router = build_router_with_ws(state, manager, progress);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;
    emit_canned_batch_summary(&events);
    tokio::time::sleep(Duration::from_millis(300)).await;

    let browser = launch_headless_browser();
    let tab = open_dashboard_tab(&browser, fixture.port());

    let eval_bool = |expr: &str| -> bool {
        tab.evaluate(expr, false)
            .ok()
            .and_then(|r| r.value)
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    };
    let eval_text = |expr: &str| -> String {
        tab.evaluate(expr, false)
            .ok()
            .and_then(|r| r.value)
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_default()
    };

    // The pipeline panel renders asynchronously; poll until the time
    // estimate is visible (up to ~5 seconds).
    let mut estimate_visible = false;
    for _ in 0..25 {
        if eval_bool(
            "document.getElementById('pipeline-time-estimate')?.style.display !== 'none' \
                && document.getElementById('pipeline-time-estimate')?.textContent.includes('remaining')",
        ) {
            estimate_visible = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        estimate_visible,
        "pipeline time estimate should be visible when durations exist"
    );

    // Switch to the queue view so the full queue list renders.
    tab.evaluate(
        "document.querySelector('.nav-tab[data-view=\"queue\"]')?.click() === undefined",
        false,
    )
    .expect("click queue tab");

    // The DrawPrimitive unit has its own measured attempts → its effort
    // column shows a real duration, not the em-dash placeholder.
    let mut effort_rendered = false;
    for _ in 0..25 {
        if eval_bool(
            "(() => { const el = document.querySelector('#full-queue-list \
                [data-unit-id=\"game_logic.dll/DrawPrimitive/v2\"] .qi-effort'); \
                return !!el && el.textContent !== '—'; })()",
        ) {
            effort_rendered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let effort_text = eval_text(
        "document.querySelector('#full-queue-list \
            [data-unit-id=\"game_logic.dll/DrawPrimitive/v2\"] .qi-effort')?.textContent || ''",
    );
    assert!(
        effort_rendered,
        "queue effort column should show an estimate for the unit, got: {effort_text:?}"
    );

    tab.close_target().ok();
    drop(browser);
}

/// Headless-browser test for issue #74: the queue view renders a priority
/// column (default NORMAL), a synthetic drag through the real drag handlers
/// reorders and persists the manual order, and clicking the chip cycles and
/// persists the priority — both landing in `re/review/queue_overlay.json`.
///
/// Run with: `cargo test --features server --test e2e headless -- --ignored`
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Chromium/Chrome installed; run with --ignored"]
async fn test_headless_queue_priority_and_reorder() {
    let fixture = TestFixture::new();
    add_pending_translation(&fixture, "RenderHUD");

    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let browser = launch_headless_browser();
    let tab = open_dashboard_tab(&browser, fixture.port());

    let eval_bool = |expr: &str| -> bool {
        tab.evaluate(expr, false)
            .ok()
            .and_then(|r| r.value)
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    };

    // Switch to the queue view so the full queue list renders.
    tab.evaluate(
        "document.querySelector('.nav-tab[data-view=\"queue\"]')?.click() === undefined",
        false,
    )
    .expect("click queue tab");

    let draw = "game_logic.dll/DrawPrimitive/v2";
    let hud = "game_logic.dll/RenderHUD/v1";

    // The priority column renders with the default NORMAL for both units.
    let mut priority_rendered = false;
    for _ in 0..25 {
        if eval_bool(
            "(() => { const el = document.querySelector('#full-queue-list \
                [data-unit-id=\"game_logic.dll/DrawPrimitive/v2\"] .qi-priority'); \
                return !!el && el.textContent === 'NORMAL'; })()",
        ) {
            priority_rendered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        priority_rendered,
        "queue priority column should render NORMAL for the unit"
    );

    // Drag reordering through the real handlers: a synthetic drag of
    // RenderHUD onto the top half of DrawPrimitive's row drops it above.
    tab.evaluate(
        &format!(
            "(() => {{ \
                const list = document.querySelector('#full-queue-list'); \
                const hud = list.querySelector('[data-unit-id=\"{hud}\"]'); \
                const draw = list.querySelector('[data-unit-id=\"{draw}\"]'); \
                const y = draw.getBoundingClientRect().top + 1; \
                const opts = (clientY) => ({{ bubbles: true, cancelable: true, clientY }}); \
                hud.dispatchEvent(new DragEvent('dragstart', opts(0))); \
                draw.dispatchEvent(new DragEvent('dragover', opts(y))); \
                draw.dispatchEvent(new DragEvent('drop', opts(y))); \
                return true; \
            }})()"
        ),
        false,
    )
    .expect("synthetic drag reorder");

    let mut reorder_rendered = false;
    for _ in 0..25 {
        if eval_bool(
            "(() => { const first = document.querySelector('#full-queue-list .queue-item-full'); \
                return !!first && first.dataset.unitId === 'game_logic.dll/RenderHUD/v1'; })()",
        ) {
            reorder_rendered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        reorder_rendered,
        "manual reorder should put RenderHUD first in the rendered queue"
    );

    // The drop fires the PUT without awaiting it, so poll the persisted
    // overlay file until the new order lands (up to ~5 seconds).
    let overlay_file = fixture
        .repo_path()
        .join("re")
        .join("review")
        .join("queue_overlay.json");
    let wanted = serde_json::json!([hud, draw]);
    let mut persisted = serde_json::Value::Null;
    for _ in 0..25 {
        if let Ok(raw) = std::fs::read_to_string(&overlay_file) {
            let value: serde_json::Value = serde_json::from_str(&raw).unwrap_or_default();
            if value["order"] == wanted {
                persisted = value;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert_eq!(
        persisted["order"], wanted,
        "reorder persists to the overlay file"
    );

    // Clicking the chip cycles NORMAL → HIGH and persists it.
    tab.evaluate(
        "document.querySelector('#full-queue-list \
            [data-unit-id=\"game_logic.dll/DrawPrimitive/v2\"] .qi-priority')?.click() === undefined",
        false,
    )
    .expect("click priority chip");

    let mut priority_updated = false;
    for _ in 0..25 {
        if eval_bool(
            "(() => { const el = document.querySelector('#full-queue-list \
                [data-unit-id=\"game_logic.dll/DrawPrimitive/v2\"] .qi-priority'); \
                return !!el && el.textContent === 'HIGH'; })()",
        ) {
            priority_updated = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(priority_updated, "clicking the chip should cycle to HIGH");

    let mut persisted = serde_json::Value::Null;
    for _ in 0..25 {
        if let Ok(raw) = std::fs::read_to_string(&overlay_file) {
            let value: serde_json::Value = serde_json::from_str(&raw).unwrap_or_default();
            if value["priorities"][draw].as_str() == Some("high") {
                persisted = value;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert_eq!(
        persisted["priorities"][draw].as_str(),
        Some("high"),
        "priority click persists to the overlay file"
    );

    tab.close_target().ok();
    drop(browser);
}

/// Headless-browser test for issue #75: the queue view renders a skip
/// checkbox per unit, clicking it marks the unit `Skipped` — the row
/// re-renders checked with a Skipped badge — and the skip persists to
/// `re/review/skips.json`; unchecking restores the unit.
///
/// Run with: `cargo test --features server --test e2e headless -- --ignored`
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Chromium/Chrome installed; run with --ignored"]
async fn test_headless_queue_skip_checkbox() {
    let fixture = TestFixture::new();

    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let browser = launch_headless_browser();
    let tab = open_dashboard_tab(&browser, fixture.port());

    let eval_bool = |expr: &str| -> bool {
        tab.evaluate(expr, false)
            .ok()
            .and_then(|r| r.value)
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    };

    // Switch to the queue view so the full queue list renders.
    tab.evaluate(
        "document.querySelector('.nav-tab[data-view=\"queue\"]')?.click() === undefined",
        false,
    )
    .expect("click queue tab");

    let draw = "game_logic.dll/DrawPrimitive/v2";
    let row_sel = format!("#full-queue-list [data-unit-id=\"{draw}\"]");

    // The skip checkbox column renders, unchecked for an active unit.
    let mut checkbox_rendered = false;
    for _ in 0..25 {
        if eval_bool(&format!(
            "(() => {{ const el = document.querySelector('{row_sel} .qi-skip-check'); \
                    return !!el && el.checked === false; }})()"
        )) {
            checkbox_rendered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        checkbox_rendered,
        "queue skip checkbox should render unchecked for the unit"
    );

    // Clicking the checkbox skips the unit.
    tab.evaluate(
        &format!("document.querySelector('{row_sel} .qi-skip-check')?.click() === undefined"),
        false,
    )
    .expect("click skip checkbox");

    // The skip lands in the repo's skip set (poll — the POST is not awaited).
    let skips_file = fixture
        .repo_path()
        .join("re")
        .join("review")
        .join("skips.json");
    let wanted = serde_json::json!([draw]);
    let mut persisted = serde_json::Value::Null;
    for _ in 0..25 {
        if let Ok(raw) = std::fs::read_to_string(&skips_file) {
            let value: serde_json::Value = serde_json::from_str(&raw).unwrap_or_default();
            if value["skipped"] == wanted {
                persisted = value;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert_eq!(
        persisted["skipped"], wanted,
        "skip click persists to re/review/skips.json"
    );

    // After the dashboard reload the row renders checked with a Skipped
    // badge — the checkbox reflects persisted state, not just the click.
    let mut skipped_rendered = false;
    for _ in 0..25 {
        if eval_bool(&format!(
            "(() => {{ const row = document.querySelector('{row_sel}'); \
                    const cb = row?.querySelector('.qi-skip-check'); \
                    const st = row?.querySelector('.qi-status'); \
                    return !!cb && cb.checked === true \
                        && !!st && st.textContent.includes('Skipped'); }})()"
        )) {
            skipped_rendered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        skipped_rendered,
        "skipped unit should re-render checked with a Skipped badge"
    );

    // Unchecking unskips: the skip set empties and the row comes back.
    tab.evaluate(
        &format!("document.querySelector('{row_sel} .qi-skip-check')?.click() === undefined"),
        false,
    )
    .expect("click skip checkbox again");

    let mut unskipped = false;
    for _ in 0..25 {
        if let Ok(raw) = std::fs::read_to_string(&skips_file) {
            let value: serde_json::Value = serde_json::from_str(&raw).unwrap_or_default();
            if value["skipped"].as_array().is_some_and(|a| a.is_empty()) {
                unskipped = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(unskipped, "unchecking empties the persisted skip set");

    let mut restored_rendered = false;
    for _ in 0..25 {
        if eval_bool(&format!(
            "(() => {{ const el = document.querySelector('{row_sel} .qi-skip-check'); \
                    return !!el && el.checked === false; }})()"
        )) {
            restored_rendered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        restored_rendered,
        "unskipped unit should re-render unchecked"
    );

    tab.close_target().ok();
    drop(browser);
}

/// Headless-browser test for issue #78: queue rows carry a multi-select
/// checkbox, the list header has a select-all that marks every visible row,
/// and the batch dropdown applies the chosen action (Skip All here) to all
/// selected units — persisted through the per-unit skip logic, after which
/// the selection clears.
///
/// Run with: `cargo test --features server --test e2e headless -- --ignored`
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Chromium/Chrome installed; run with --ignored"]
async fn test_headless_queue_multiselect_batch_actions() {
    let fixture = TestFixture::new();
    add_pending_translation(&fixture, "RenderHUD");

    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let browser = launch_headless_browser();
    let tab = open_dashboard_tab(&browser, fixture.port());

    let eval_bool = |expr: &str| -> bool {
        tab.evaluate(expr, false)
            .ok()
            .and_then(|r| r.value)
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    };

    // Switch to the queue view so the full queue list renders.
    tab.evaluate(
        "document.querySelector('.nav-tab[data-view=\"queue\"]')?.click() === undefined",
        false,
    )
    .expect("click queue tab");

    let draw = "game_logic.dll/DrawPrimitive/v2";
    let hud = "game_logic.dll/RenderHUD/v1";
    let draw_sel = format!("#full-queue-list [data-unit-id=\"{draw}\"]");
    let hud_sel = format!("#full-queue-list [data-unit-id=\"{hud}\"]");

    // Each row renders an (unchecked) select checkbox beside the skip one.
    let mut selects_rendered = false;
    for _ in 0..25 {
        if eval_bool(&format!(
            "(() => {{ const a = document.querySelector('{draw_sel} .qi-select'); \
                    const b = document.querySelector('{hud_sel} .qi-select'); \
                    return !!a && !a.checked && !!b && !b.checked; }})()"
        )) {
            selects_rendered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        selects_rendered,
        "queue rows should render unchecked select checkboxes"
    );

    // The batch dropdown offers the three batch actions.
    assert!(
        eval_bool(
            "(() => {{ const sel = document.getElementById('batch-action'); \
                    const values = [...sel.options].map(o => o.value); \
                    return values.includes('accept') && values.includes('skip') \
                        && values.includes('send-back'); }})()"
        ),
        "batch dropdown should offer Accept All, Skip All, and Send Back All"
    );

    // Select-all marks every visible row.
    tab.evaluate(
        "document.getElementById('queue-select-all')?.click() === undefined",
        false,
    )
    .expect("click select-all");
    assert!(
        eval_bool(&format!(
            "(() => {{ const a = document.querySelector('{draw_sel} .qi-select'); \
                    const b = document.querySelector('{hud_sel} .qi-select'); \
                    return !!a && a.checked && !!b && b.checked; }})()"
        )),
        "select-all should check every visible row"
    );

    // Choose Skip All from the dropdown: both units land in the persisted
    // skip set through the per-unit skip logic.
    tab.evaluate(
        "(() => { const sel = document.getElementById('batch-action'); \
                sel.value = 'skip'; \
                sel.dispatchEvent(new Event('change')); })() === undefined",
        false,
    )
    .expect("trigger batch skip");

    let skips_file = fixture
        .repo_path()
        .join("re")
        .join("review")
        .join("skips.json");
    let mut persisted = serde_json::Value::Null;
    for _ in 0..25 {
        if let Ok(raw) = std::fs::read_to_string(&skips_file) {
            let value: serde_json::Value = serde_json::from_str(&raw).unwrap_or_default();
            let skipped = value["skipped"].as_array().cloned().unwrap_or_default();
            if skipped.iter().any(|id| id == draw) && skipped.iter().any(|id| id == hud) {
                persisted = value;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let skipped = persisted["skipped"].as_array().cloned().unwrap_or_default();
    assert!(
        skipped.iter().any(|id| id == draw) && skipped.iter().any(|id| id == hud),
        "batch skip persists both selected units, got {skipped:?}"
    );

    // After the dashboard reload the selection is cleared — rows come back
    // with unchecked select checkboxes (and checked skip checkboxes).
    let mut selection_cleared = false;
    for _ in 0..25 {
        if eval_bool(&format!(
            "(() => {{ const a = document.querySelector('{draw_sel} .qi-select'); \
                    const b = document.querySelector('{hud_sel} .qi-select'); \
                    const sa = document.querySelector('{draw_sel} .qi-skip-check'); \
                    const sb = document.querySelector('{hud_sel} .qi-skip-check'); \
                    return !!a && !a.checked && !!b && !b.checked \
                        && !!sa && sa.checked && !!sb && sb.checked; }})()"
        )) {
            selection_cleared = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        selection_cleared,
        "selection should clear after the batch lands, with skips rendered"
    );

    tab.close_target().ok();
    drop(browser);
}

/// Headless-browser test for issue #76: the graph view loads enriched nodes
/// into the canvas renderer, node height encodes token usage, confidence
/// maps to a red→green hue (null stays neutral), and the kind/status/binary
/// selects combine with AND — the summary reports how many nodes survive.
///
/// Run with: `cargo test --features server --test e2e headless -- --ignored`
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Chromium/Chrome installed; run with --ignored"]
async fn test_headless_graph_filters_and_encoding() {
    let fixture = TestFixture::new();

    // Canned usage so DrawPrimitive renders taller than units with none.
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

    let browser = launch_headless_browser();
    let tab = open_dashboard_tab(&browser, fixture.port());

    let eval_bool = |expr: &str| -> bool {
        tab.evaluate(expr, false)
            .ok()
            .and_then(|r| r.value)
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    };
    let eval_str = |expr: &str| -> Option<String> {
        tab.evaluate(expr, false)
            .ok()
            .and_then(|r| r.value)
            .and_then(|v| v.as_str().map(|s| s.to_string()))
    };

    // Switch to the graph view.
    tab.evaluate(
        "document.querySelector('.nav-tab[data-view=\"graph\"]')?.click() === undefined",
        false,
    )
    .expect("click graph tab");

    // The renderer loads the fixture's five units.
    let mut loaded = false;
    for _ in 0..25 {
        if eval_bool("!!window.calxglossGraph && window.calxglossGraph.totalNodeCount >= 5") {
            loaded = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(loaded, "graph renderer should load the fixture nodes");

    // Size encoding: DrawPrimitive (7168 tokens) is taller than UpdateScene
    // (no recorded usage — base size, never zero).
    let mut size_encoded = false;
    for _ in 0..25 {
        if eval_bool(
            "(() => { const g = window.calxglossGraph; if (!g) return false; \
                const draw = g._allNodes.find(n => n.id === 'game_logic.dll/DrawPrimitive/v2'); \
                const update = g._allNodes.find(n => n.id === 'game_logic.dll/UpdateScene/v1'); \
                return !!draw && draw.token_usage === 7168 && !!update \
                    && update.token_usage == null && draw._h > update._h; })()",
        ) {
            size_encoded = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        size_encoded,
        "node height should encode token usage (DrawPrimitive taller, UpdateScene base)"
    );

    // Color encoding: real nodes stay honest (null confidence → neutral),
    // and the 0.0→1.0 range maps to hues 0→140 (red→green).
    let confidence_encoded = eval_bool(
        "(() => { const g = window.calxglossGraph; if (!g) return false; \
            const honest = g._allNodes.every(n => n._confidenceHue === null \
                || (n._confidenceHue >= 0 && n._confidenceHue <= 140)); \
            const all = g._allNodes, edges = g._allEdges; \
            g.setData([ \
                { id: 'lo', name: 'Low', kind: 'function_translation', status: 'queued', confidence: 0.0 }, \
                { id: 'hi', name: 'High', kind: 'function_translation', status: 'queued', confidence: 1.0 } \
            ], []); \
            const lo = g.nodes.find(n => n.id === 'lo'); \
            const hi = g.nodes.find(n => n.id === 'hi'); \
            const mapped = !!lo && lo._confidenceHue === 0 \
                && !!hi && hi._confidenceHue === 140; \
            g.setData(all, edges); \
            return honest && mapped; })()",
    );
    assert!(
        confidence_encoded,
        "confidence should map to hues 0..140 with null staying neutral"
    );

    // Filters combine with AND: binary=d3d9.dll leaves the shim node…
    tab.evaluate(
        "(() => { const sel = document.getElementById('graph-filter-binary'); \
            sel.value = 'd3d9.dll'; \
            sel.dispatchEvent(new Event('change')); })()",
        false,
    )
    .expect("set binary filter");

    let mut binary_filtered = false;
    for _ in 0..25 {
        if eval_bool(
            "(() => { const g = window.calxglossGraph; \
                const sum = document.getElementById('graph-filter-summary'); \
                return !!g && g.visibleNodeCount === 2 && g.totalNodeCount >= 7 \
                    && sum.textContent.includes('2 of'); })()",
        ) {
            binary_filtered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        binary_filtered,
        "binary filter should leave only the d3d9.dll nodes"
    );

    // …and adding kind=shim_layer empties the view (AND, not OR — the two
    // d3d9.dll nodes are a classification and a function translation).
    tab.evaluate(
        "(() => { const sel = document.getElementById('graph-filter-kind'); \
            sel.value = 'shim_layer'; \
            sel.dispatchEvent(new Event('change')); })()",
        false,
    )
    .expect("set kind filter");

    let mut combined_filtered = false;
    for _ in 0..25 {
        if eval_bool(
            "(() => { const g = window.calxglossGraph; \
                return !!g && g.visibleNodeCount === 0; })()",
        ) {
            combined_filtered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        combined_filtered,
        "kind × binary filters must combine with AND"
    );

    // Resetting both selects restores every node, and the summary follows.
    tab.evaluate(
        "(() => { for (const id of ['graph-filter-binary', 'graph-filter-kind']) { \
                const sel = document.getElementById(id); \
                sel.value = 'all'; \
                sel.dispatchEvent(new Event('change')); } })()",
        false,
    )
    .expect("reset filters");

    let summary = eval_str(
        "(() => { const g = window.calxglossGraph; \
            const sum = document.getElementById('graph-filter-summary'); \
            return (g && g.visibleNodeCount === g.totalNodeCount) ? sum.textContent : ''; })()",
    );
    let restored = summary
        .as_deref()
        .is_some_and(|s| s.contains("nodes") && !s.contains(" of "));
    assert!(
        restored,
        "reset filters should restore all nodes, summary reads 'N nodes': {summary:?}"
    );

    tab.close_target().ok();
    drop(browser);
}

/// Headless-browser test for graph export + shareable URLs (issue #79):
/// `toSVG()` serializes the filtered view (visible nodes only, each carrying
/// its unit id), the PNG export runs the same SVG through rasterization, the
/// share URL encodes the active filters and the zoom/pan camera, and opening
/// that URL in a fresh tab restores the same filters and viewport.
///
/// Run with: `cargo test --features server --test e2e headless -- --ignored`
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Chromium/Chrome installed; run with --ignored"]
async fn test_headless_graph_export_and_share_url() {
    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let browser = launch_headless_browser();
    let tab = open_dashboard_tab(&browser, fixture.port());

    let eval_bool = |expr: &str| -> bool {
        tab.evaluate(expr, false)
            .ok()
            .and_then(|r| r.value)
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    };
    let eval_str = |expr: &str| -> Option<String> {
        tab.evaluate(expr, false)
            .ok()
            .and_then(|r| r.value)
            .and_then(|v| v.as_str().map(|s| s.to_string()))
    };

    // Wait for the graph renderer to load the fixture's units.
    let mut loaded = false;
    for _ in 0..25 {
        if eval_bool("!!window.calxglossGraph && window.calxglossGraph.totalNodeCount >= 5") {
            loaded = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(loaded, "graph renderer should load the fixture nodes");

    // Narrow to one binary — export and share must both follow the
    // filtered view, not the full graph.
    tab.evaluate(
        "(() => { const sel = document.getElementById('graph-filter-binary'); \
            sel.value = 'd3d9.dll'; \
            sel.dispatchEvent(new Event('change')); })()",
        false,
    )
    .expect("set binary filter");

    let mut filtered = false;
    for _ in 0..25 {
        if eval_bool("!!window.calxglossGraph && window.calxglossGraph.visibleNodeCount === 2") {
            filtered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        filtered,
        "binary filter should leave the two d3d9.dll nodes"
    );

    // SVG export mirrors the filtered view: the d3d9 nodes are in (their
    // unit ids appear as data-id attributes), game_logic nodes are out.
    let svg = eval_str("window.calxglossGraph.toSVG()").unwrap_or_default();
    assert!(
        svg.contains("<svg"),
        "toSVG should produce an SVG document, got: {svg}"
    );
    assert!(
        svg.contains("d3d9.dll"),
        "SVG export should include the visible d3d9.dll nodes"
    );
    assert!(
        !svg.contains("game_logic.dll"),
        "SVG export should exclude nodes filtered out of the view"
    );

    // PNG export runs the same SVG through rasterization and reports success.
    let png_ok = tab
        .evaluate("window.calxglossExportPNG()", true)
        .ok()
        .and_then(|r| r.value)
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    assert!(
        png_ok,
        "PNG export should rasterize the SVG and produce a blob"
    );

    // Move the camera, then build the share URL — it must encode the
    // active filter and the viewport state.
    tab.evaluate(
        "(() => { const g = window.calxglossGraph; \
            g.scale = 1.5; g.offsetX = 120; g.offsetY = -40; g.draw(); })()",
        false,
    )
    .expect("move camera");

    let share_url = eval_str("window.calxglossShareUrl()").unwrap_or_default();
    for fragment in ["view=graph", "gb=d3d9.dll", "gz=1.5", "gx=120", "gy=-40"] {
        assert!(
            share_url.contains(fragment),
            "share URL {share_url} should encode {fragment}"
        );
    }

    // Opening the shared URL in a fresh tab restores the filter (select and
    // visible node count) and the exact camera.
    let shared_tab = browser.new_tab().expect("open new tab for share URL");
    shared_tab
        .navigate_to(&share_url)
        .expect("navigate to share URL");
    shared_tab
        .wait_until_navigated()
        .expect("wait for share URL navigation");
    shared_tab.enable_runtime().expect("enable runtime");

    let mut restored = false;
    for _ in 0..25 {
        if shared_tab
            .evaluate(
                "(() => { const g = window.calxglossGraph; if (!g) return false; \
                    const sel = document.getElementById('graph-filter-binary'); \
                    return sel.value === 'd3d9.dll' && g.visibleNodeCount === 2 \
                        && Math.abs(g.scale - 1.5) < 0.001 \
                        && Math.abs(g.offsetX - 120) < 0.001 \
                        && Math.abs(g.offsetY + 40) < 0.001; })()",
                false,
            )
            .ok()
            .and_then(|r| r.value)
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            restored = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        restored,
        "opening the shared URL should restore the encoded filters and viewport"
    );

    shared_tab.close_target().ok();
    tab.close_target().ok();
    drop(browser);
}

/// Headless-browser test for the LLM I/O log browser (issue #80): the view
/// loads its history from `GET /api/llm-io` (so it survives a reload),
/// shows a token count per entry, starts entries collapsed and expands
/// them on header click, offers one-click copy per entry, narrows the list
/// through the binary filter and full-text search, and still appends live
/// WebSocket entries on top of the history — without duplicating them when
/// the history reloads on the next view entry.
///
/// Run with: `cargo test --features server --test e2e headless -- --ignored`
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Chromium/Chrome installed; run with --ignored"]
async fn test_headless_llm_log_browser() {
    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path());
    let events = TranslationEvents::new(128);
    let manager = SessionManager::new_with_broadcast(events.subscribe());
    let progress = ProgressState::new();
    let router = build_router_with_ws(state, manager, progress);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    // History from a "previous run": persisted before the page opens, so
    // the view must load it from the server rather than a memory buffer.
    let log = LlmIoLog::new(fixture.repo_path());
    log.record(&ProgressEvent::LlmRequest {
        binary: "game_logic.dll".into(),
        function: "DrawPrimitive".into(),
        attempt: 1,
        strategy: "direct".into(),
        prompt: "translate DrawPrimitive from the decompile".into(),
    });
    log.record(&ProgressEvent::LlmResponse {
        binary: "game_logic.dll".into(),
        function: "DrawPrimitive".into(),
        attempt: 1,
        strategy: "direct".into(),
        content: "fn draw_primitive() {}".into(),
        tokens_used: Some(4321),
    });
    log.record(&ProgressEvent::LlmRequest {
        binary: "d3d9.dll".into(),
        function: "UpdateScene".into(),
        attempt: 2,
        strategy: "compile_fix".into(),
        prompt: "fix the compile errors in UpdateScene".into(),
    });

    let browser = launch_headless_browser();
    let tab = open_dashboard_tab(&browser, fixture.port());

    let eval_bool = |expr: &str| -> bool {
        tab.evaluate(expr, false)
            .ok()
            .and_then(|r| r.value)
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    };
    let eval_text = |expr: &str| -> String {
        tab.evaluate(expr, false)
            .ok()
            .and_then(|r| r.value)
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_default()
    };
    let visible_count = || -> i64 {
        tab.evaluate(
            "document.querySelectorAll('#llm-log-entries .llm-log-entry').length",
            false,
        )
        .ok()
        .and_then(|r| r.value)
        .and_then(|v| v.as_i64())
        .unwrap_or(-1)
    };

    // Switch to the LLM I/O tab.
    tab.evaluate(
        "document.querySelector('.nav-tab[data-view=\"llm-log\"]')?.click() === undefined",
        false,
    )
    .expect("click llm-log tab");

    // The persisted history renders — loaded over HTTP, not from a buffer.
    let mut loaded = false;
    for _ in 0..25 {
        if visible_count() == 3 {
            loaded = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(loaded, "log view should load the persisted history");

    // Token count per entry: the response carries its count, the request
    // shows an honest em dash rather than a fabricated zero.
    let response_meta = eval_text(
        "document.querySelector('#llm-log-entries .llm-log-entry:nth-child(2) .meta').textContent",
    );
    assert!(
        response_meta.contains("4321 tokens"),
        "response entry should show its token count, got: {response_meta}"
    );
    let request_meta = eval_text(
        "document.querySelector('#llm-log-entries .llm-log-entry:nth-child(1) .meta').textContent",
    );
    assert!(
        request_meta.contains('—'),
        "request entry should show an em dash for the unmeasured token count, got: {request_meta}"
    );

    // Entries start collapsed: the body is hidden until the header is clicked.
    assert!(
        eval_bool(
            "document.querySelector('#llm-log-entries .llm-log-entry .llm-log-entry-body').offsetHeight === 0"
        ),
        "entries should start collapsed"
    );
    tab.evaluate(
        "document.querySelector('#llm-log-entries .llm-log-entry .llm-log-entry-header').click() === undefined",
        false,
    )
    .expect("click entry header");
    assert!(
        eval_bool(
            "document.querySelector('#llm-log-entries .llm-log-entry .llm-log-entry-body').offsetHeight > 0"
        ),
        "header click should expand the entry"
    );

    // One-click copy: every entry carries a copy button.
    assert!(
        eval_bool("document.querySelectorAll('#llm-log-entries .llm-log-copy').length === 3"),
        "every entry should have a copy button"
    );

    // Binary filter narrows to one binary.
    tab.evaluate(
        "(() => { const sel = document.getElementById('llm-log-filter-binary'); \
            sel.value = 'd3d9.dll'; \
            sel.dispatchEvent(new Event('change')); })()",
        false,
    )
    .expect("set binary filter");
    assert!(
        visible_count() == 1,
        "binary filter should leave only the d3d9.dll entry"
    );

    // Full-text search through prompt content (filter reset first).
    tab.evaluate(
        "(() => { const sel = document.getElementById('llm-log-filter-binary'); \
            sel.value = ''; \
            sel.dispatchEvent(new Event('change')); \
            const inp = document.getElementById('llm-log-search'); \
            inp.value = 'compile errors'; \
            inp.dispatchEvent(new Event('input')); })()",
        false,
    )
    .expect("set search");
    assert!(
        visible_count() == 1,
        "search should match exactly the entry whose content mentions it"
    );
    let searched_meta =
        eval_text("document.querySelector('#llm-log-entries .llm-log-entry .meta').textContent");
    assert!(
        searched_meta.contains("UpdateScene"),
        "the searched entry should be the UpdateScene prompt, got: {searched_meta}"
    );

    // Reset the search — back to the full history.
    tab.evaluate(
        "(() => { const inp = document.getElementById('llm-log-search'); \
            inp.value = ''; \
            inp.dispatchEvent(new Event('input')); })()",
        false,
    )
    .expect("clear search");
    assert!(
        visible_count() == 3,
        "clearing the search should show all history"
    );

    // Live WebSocket entries still append on top of the history — including
    // a failed call, whose content must match the server log's raw error.
    events.emit(ProgressEvent::LlmRequest {
        binary: "game_logic.dll".into(),
        function: "UpdateScene".into(),
        attempt: 3,
        strategy: "direct".into(),
        prompt: "translate UpdateScene".into(),
    });
    events.emit(ProgressEvent::LlmCallFailed {
        binary: "d3d9.dll".into(),
        function: "UpdateScene".into(),
        attempt: 4,
        strategy: "retry".into(),
        error: "connection reset".into(),
    });
    let mut appended = false;
    for _ in 0..25 {
        if visible_count() == 5 {
            appended = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        appended,
        "live WS entries should append on top of the history"
    );

    // Re-entering the view reloads the history — the live entries were also
    // persisted server-side, and dedup must keep them from showing twice
    // (the error entry's content is the raw error on both sides).
    tab.evaluate(
        "document.querySelector('.nav-tab[data-view=\"dashboard\"]').click(); \
         document.querySelector('.nav-tab[data-view=\"llm-log\"]').click();",
        false,
    )
    .expect("re-enter llm-log view");
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        visible_count() == 5,
        "history reload must not duplicate the live entries"
    );

    tab.close_target().ok();
    drop(browser);
}

/// Headless-browser test for the live translation view (issue #65): in live
/// mode the Live tab must render one progress bar per in-flight unit, labeled
/// with its current phase and the evidence the live stream reported — tier,
/// strategy, attempt, baseline/verification status, confidence — and must
/// update the row when a later event lands over the WebSocket.
///
/// Run with: `cargo test --features server --test e2e headless -- --ignored`
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Chromium/Chrome installed; run with --ignored"]
async fn test_headless_live_view_renders_and_updates() {
    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path());
    let events = TranslationEvents::new(128);
    let manager = SessionManager::new_with_broadcast(events.subscribe());
    let progress = ProgressState::new();
    let router = build_router_with_ws(state, manager, progress);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    // One unit mid-flight with tier, strategy, and pending baseline evidence.
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
            strategy: "decompose".into(),
        },
    ] {
        events.emit(event);
    }
    tokio::time::sleep(Duration::from_millis(300)).await;

    let browser = launch_headless_browser();
    let tab = open_dashboard_tab(&browser, fixture.port());

    let eval_bool = |expr: &str| -> bool {
        tab.evaluate(expr, false)
            .ok()
            .and_then(|r| r.value)
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    };
    let eval_len = |expr: &str| -> i64 {
        tab.evaluate(expr, false)
            .ok()
            .and_then(|r| r.value)
            .and_then(|v| v.as_i64())
            .unwrap_or(-1)
    };
    let eval_text = |expr: &str| -> String {
        tab.evaluate(expr, false)
            .ok()
            .and_then(|r| r.value)
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_default()
    };

    // Switch to the Live tab.
    tab.evaluate(
        "document.querySelector('.nav-tab[data-view=\"live\"]')?.click() === undefined",
        false,
    )
    .expect("click live tab");

    // The row renders asynchronously once the enhanced-progress fetch settles;
    // poll until the unit appears (up to ~5 seconds).
    let mut rendered = false;
    for _ in 0..25 {
        if eval_len(
            "document.querySelectorAll('#live-units .live-unit[data-function=\"DrawPrimitive\"]').length",
        ) == 1
        {
            rendered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        rendered,
        "live view should render one row for the in-flight unit, rows: {}",
        eval_len("document.querySelectorAll('#live-units .live-unit').length")
    );

    // The row carries the phase label and the evidence the stream reported.
    let row = "#live-units .live-unit[data-function=\"DrawPrimitive\"]";
    let row_text = |suffix: &str| -> String {
        eval_text(&format!("document.querySelector('{row}')?{suffix} || ''"))
    };
    assert_eq!(
        row_text(".querySelector('.live-phase')?.textContent"),
        "LLM Call",
        "phase label should read LLM Call"
    );
    let meta = row_text(".querySelector('.live-unit-meta')?.textContent");
    assert!(meta.contains("T2"), "tier visible, got: {meta}");
    assert!(meta.contains("decompose"), "strategy visible, got: {meta}");
    assert!(meta.contains("attempt: 2"), "attempt visible, got: {meta}");
    assert!(
        meta.contains("baseline: 3 queued"),
        "pending baseline shown as queued, not 0 passed, got: {meta}"
    );
    assert!(
        meta.contains("verification: not run"),
        "unmeasured verification says not run, got: {meta}"
    );
    assert!(
        meta.contains("confidence: —"),
        "unverified unit has no confidence, got: {meta}"
    );
    // The elapsed clock is live, not a frozen placeholder.
    let elapsed = row_text(".querySelector('.live-elapsed')?.textContent");
    assert!(
        elapsed.ends_with('s') && elapsed != "s",
        "elapsed clock rendered, got: {elapsed}"
    );

    // A later event over the WebSocket must update the same row: the attempt
    // verifies (confidence 100%) and the unit completes (phase Review).
    events.emit(ProgressEvent::TranslationAttemptCompleted {
        binary: "game_logic.dll".into(),
        function: "DrawPrimitive".into(),
        attempt: 2,
        success: true,
        compiled: true,
        tests_passed: 3,
        tests_total: 3,
        compilation_errors: vec![],
        failed_tests: vec![],
        strategy: "decompose".into(),
        tokens_used: None,
    });
    events.emit(ProgressEvent::TranslationCompleted {
        binary: "game_logic.dll".into(),
        function: "DrawPrimitive".into(),
        total_attempts: 2,
        success_strategy: Some("decompose".into()),
    });

    let mut updated = false;
    for _ in 0..25 {
        if eval_bool(&format!(
            "(() => {{ const r = document.querySelector('{row}'); \
                return !!r && r.classList.contains('finished-ok') && \
                    r.querySelector('.live-phase')?.textContent === 'Review'; }})()"
        )) {
            updated = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(updated, "row should update to Review/finished over the WS");
    let meta = row_text(".querySelector('.live-unit-meta')?.textContent");
    assert!(
        meta.contains("baseline: 3/3 ✓"),
        "verified baseline visible after update, got: {meta}"
    );
    assert!(
        meta.contains("confidence: 100%"),
        "confidence appears once an attempt verifies, got: {meta}"
    );

    // The pushed records carry the phase history — the phase chip's tooltip
    // shows the path the unit walked, escalations and retries included.
    let history = row_text(".querySelector('.live-phase')?.getAttribute('title') || ''");
    assert!(
        history.contains("Ghidra Fetch")
            && history.contains("Context Tier")
            && history.contains("LLM Call")
            && history.contains("Testing")
            && history.contains("Review"),
        "phase history visible on the phase chip, got: {history}"
    );

    tab.close_target().ok();
    drop(browser);
}

/// Headless-browser honesty test for the live translation view (issue #65):
/// outside `calxgloss live` the enhanced endpoint is not routed, so the Live
/// tab must say the live view needs a running pipeline — never render an
/// empty list that masquerades as an idle run.
///
/// Run with: `cargo test --features server --test e2e headless -- --ignored`
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Chromium/Chrome installed; run with --ignored"]
async fn test_headless_live_view_honest_without_live_mode() {
    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(500)).await;

    let browser = launch_headless_browser();
    let tab = open_dashboard_tab(&browser, fixture.port());

    let eval_bool = |expr: &str| -> bool {
        tab.evaluate(expr, false)
            .ok()
            .and_then(|r| r.value)
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    };

    tab.evaluate(
        "document.querySelector('.nav-tab[data-view=\"live\"]')?.click() === undefined",
        false,
    )
    .expect("click live tab");

    // The honest empty state must appear (poll up to ~5 seconds).
    let mut announced = false;
    for _ in 0..25 {
        if eval_bool(
            "(() => { const e = document.getElementById('live-empty'); \
                return !!e && e.style.display !== 'none' && \
                    e.textContent.includes('calxgloss live'); })()",
        ) {
            announced = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        announced,
        "plain serve must announce that the live view needs calxgloss live"
    );
    assert!(
        !eval_bool("document.querySelector('#live-units .live-unit') !== null"),
        "no fabricated unit rows outside live mode"
    );

    tab.close_target().ok();
    drop(browser);
}

/// Headless-browser test for issue #66: the dashboard must render category
/// cards sourced from the classification data, a quality summary computed
/// from the dashboard units, and a token budget visual driven by the
/// token-usage log and a user-set budget.
///
/// Run with: `cargo test --features server --test e2e headless -- --ignored`
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Chromium/Chrome installed; run with --ignored"]
async fn test_headless_dashboard_summary_sections() {
    let fixture = TestFixture::new();
    write_token_usage_log(&fixture, false);

    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let browser = launch_headless_browser();
    let tab = open_dashboard_tab(&browser, fixture.port());

    let eval_bool = |expr: &str| -> bool {
        tab.evaluate(expr, false)
            .ok()
            .and_then(|r| r.value)
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    };
    let eval_text = |expr: &str| -> String {
        tab.evaluate(expr, false)
            .ok()
            .and_then(|r| r.value)
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_default()
    };

    // Category cards: one per DllCategory, with the fixture's counts.
    let mut cards_rendered = false;
    for _ in 0..25 {
        if eval_bool(
            "(() => { const cards = document.querySelectorAll('#category-cards .category-card'); \
                if (cards.length !== 6) return false; \
                const ps = document.querySelector('#category-cards [data-category=\"ProjectSpecific\"]'); \
                const sdk = document.querySelector('#category-cards [data-category=\"MicrosoftSdk\"]'); \
                return !!ps && !!sdk && ps.textContent.includes('1') && sdk.textContent.includes('1'); })()",
        ) {
            cards_rendered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        cards_rendered,
        "category cards should render 6 categories with fixture counts"
    );

    // Quality summary: avg confidence 73% (0.725 rounded), and honest
    // em-dashes for the baseline/verification rates with no data behind them.
    let mut quality_rendered = false;
    for _ in 0..25 {
        if eval_bool(
            "(() => { const el = document.getElementById('quality-summary'); \
                if (!el) return false; const t = el.textContent; \
                return t.includes('73%') && t.includes('—'); })()",
        ) {
            quality_rendered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        quality_rendered,
        "quality summary should show the 73% average confidence and em-dashes for the rates with no data behind them, got: {:?}",
        eval_text("document.getElementById('quality-summary')?.textContent || ''")
    );

    // Token budget: consumed tokens come from the log; the budget itself is
    // a user preference in localStorage. Set it, reload, and check the bar.
    tab.evaluate(
        "localStorage.setItem('calxgloss_token_budget', '10000') === undefined",
        false,
    )
    .expect("set token budget");
    tab.reload(false, None).expect("reload");
    tab.wait_until_navigated().expect("wait for reload");

    let mut budget_rendered = false;
    for _ in 0..25 {
        if eval_bool(
            "(() => { const el = document.getElementById('token-budget'); \
                if (!el) return false; \
                const tokens = el.querySelector('[data-total-tokens]'); \
                if (!tokens || tokens.getAttribute('data-total-tokens') !== '7168') return false; \
                const fill = el.querySelector('.token-budget-fill'); \
                return !!fill && fill.style.width === '71.68%'; })()",
        ) {
            budget_rendered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        budget_rendered,
        "token budget bar should show 7,168 consumed against the 10,000 budget (71.68%), got: {:?}",
        eval_text("document.getElementById('token-budget')?.textContent || ''")
    );

    tab.close_target().ok();
    drop(browser);
}

/// Headless-browser test for issue #66: the pipeline overview must be
/// selectable as the landing view; the preference persists in localStorage
/// and the next page load opens the pipeline view instead of the dashboard.
///
/// Run with: `cargo test --features server --test e2e headless -- --ignored`
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Chromium/Chrome installed; run with --ignored"]
async fn test_headless_landing_view_preference() {
    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let browser = launch_headless_browser();
    let tab = open_dashboard_tab(&browser, fixture.port());

    let eval_bool = |expr: &str| -> bool {
        tab.evaluate(expr, false)
            .ok()
            .and_then(|r| r.value)
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    };

    // The landing selector offers the pipeline view; pick it.
    let has_option =
        eval_bool("!!document.querySelector('#landing-view option[value=\"pipeline\"]')");
    assert!(
        has_option,
        "landing view select should offer the pipeline view"
    );
    tab.evaluate(
        "(() => { const sel = document.getElementById('landing-view'); \
            sel.value = 'pipeline'; \
            sel.dispatchEvent(new Event('change')); })()",
        false,
    )
    .expect("select pipeline landing view");

    // Reload: the pipeline view must be the active one, not the dashboard.
    tab.reload(false, None).expect("reload");
    tab.wait_until_navigated().expect("wait for reload");

    let mut pipeline_active = false;
    for _ in 0..25 {
        if eval_bool(
            "document.getElementById('view-pipeline')?.classList.contains('view-active') === true \
                && document.getElementById('view-dashboard')?.classList.contains('view-active') !== true",
        ) {
            pipeline_active = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        pipeline_active,
        "pipeline view should be the landing view after the preference is saved"
    );
    assert!(
        eval_bool("document.getElementById('landing-view')?.value === 'pipeline'"),
        "landing select should reflect the saved preference"
    );

    tab.close_target().ok();
    drop(browser);
}
