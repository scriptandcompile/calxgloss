//! End-to-end tests for the web review UI.
//!
//! These tests spin up the axum server in a real git repository with sample data,
//! then verify both API responses and headless-browser rendering.
//!
//! Run API-level tests: `cargo test --features server --test e2e`
//! Run browser tests:   `cargo test --features server --test e2e headless -- --ignored`

use calxgloss_git::{GitManager, InitConfig};
use calxgloss_translator::assembly::PipelineSpec;
use calxgloss_types::{
    GitBranch, PipelineControl, PipelineRunRequest, PipelineState, ProgressEvent, RunPhase,
    RunRequestSignal, RunScope, RunTarget, TestCase, TestResult, TranslationEvents,
    UnitCancellation,
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
/// The settings-backed actions backend the live (ws) routers carry (issue
/// #327). The ws surface under test never posts a patch, so the default —
/// LLM-less — description is enough here; a patch request against these
/// routers would fail assembly, exactly what issue #327 specifies for a
/// server started without LLM settings.
fn ws_actions(fixture: &TestFixture) -> ActionsState {
    ActionsState::new(fixture.repo_path(), PipelineSpec::default())
}

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
    let router = build_router_with_ws(state, manager, progress, ws_actions(&fixture));
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
    let router = build_router_with_ws(state, manager.clone(), progress, ws_actions(&fixture));
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
    let router = build_router_with_ws(state, manager, progress, ws_actions(&fixture));
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
    let router = build_router_with_ws(state, manager, progress, ws_actions(&fixture));
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
    let router = build_router_with_ws(state, manager, progress, ws_actions(&fixture));
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
    let router = build_router_with_ws(state, manager, progress, ws_actions(&fixture));
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

    // Issue #92: start/restart are honest the same way — with no run-request
    // channel attached there is no live loop a request could wake. Restart
    // carries a JSON body, so it is posted separately from the bodyless ones.
    for (path, body) in [
        ("/api/pipeline/start", serde_json::json!(null)),
        ("/api/pipeline/restart", serde_json::json!({})),
    ] {
        let mut req =
            reqwest::Client::new().post(format!("http://127.0.0.1:{}{path}", fixture.port()));
        if !body.is_null() {
            req = req.json(&body);
        }
        let resp = req.send().await.expect("request reaches server");
        let status = resp.status();
        let body: serde_json::Value = resp.json().await.expect("body is JSON");
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
    let fixture = TestFixture::new();
    let events = TranslationEvents::new(128);
    let scope =
        calxgloss_types::ScopeControl::open(fixture.repo_path()).with_events(events.clone());
    let state = ServerState::new(fixture.repo_path()).with_scope_control(scope);
    let manager = SessionManager::new_with_broadcast(events.subscribe());
    let progress = ProgressState::new();
    let router = build_router_with_ws(state, manager, progress, ws_actions(&fixture));
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    // The run's queue plan discovers game_logic.dll — the row exists before
    // anything has started working on it.
    events.emit(ProgressEvent::QueuePlanned {
        binaries: vec!["game_logic.dll".to_string()],
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    let get_row_paused = |port: u16| async move {
        let resp = reqwest::get(format!("http://127.0.0.1:{port}/api/pipeline"))
            .await
            .expect("pipeline status request succeeds");
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.expect("pipeline body is JSON");
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
        get_row_paused(fixture.port()).await,
        Some(false),
        "a freshly discovered row is not paused"
    );

    // Pause: 200, body echoes the binary and the flag now in force.
    let (status, body) = post_lifecycle(
        fixture.port(),
        "/api/pipeline/binaries/game_logic.dll/pause",
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body["binary"], "game_logic.dll");
    assert_eq!(body["paused"], true);

    // The row data follows the handle — a plain GET is honest without
    // waiting for a BinaryPauseChanged event.
    assert_eq!(
        get_row_paused(fixture.port()).await,
        Some(true),
        "GET /api/pipeline reports the pause"
    );

    // A binary the workspace has not discovered: 409 with the server's own
    // reason — a stale click is never a silent no-op.
    let (status, body) =
        post_lifecycle(fixture.port(), "/api/pipeline/binaries/nope.dll/pause").await;
    assert_eq!(status, 409);
    assert!(
        body["message"]
            .as_str()
            .unwrap_or_default()
            .contains("has not discovered"),
        "409 carries the server's own reason, got: {body}"
    );

    // The pause rode the scope record — a handle re-opened over the same
    // workspace (a restarted run) honors it, on the #107 match rule.
    assert!(
        calxgloss_types::ScopeControl::open(fixture.repo_path()).is_paused("GAME_LOGIC.DLL"),
        "the endpoint wrote through to the persisted scope record"
    );

    // Resume: back to unpaused, and the row follows.
    let (status, body) = post_lifecycle(
        fixture.port(),
        "/api/pipeline/binaries/game_logic.dll/resume",
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body["binary"], "game_logic.dll");
    assert_eq!(body["paused"], false);
    assert_eq!(
        get_row_paused(fixture.port()).await,
        Some(false),
        "GET /api/pipeline reports the resume"
    );
}

/// A pause and a resume reach WS clients as raw `binary_pause_changed`
/// events on the shared broadcast (issue #221) — the dashboard re-renders
/// the rows when the event arrives, without a page reload (issue #222),
/// following the batch-summary event precedent.
#[tokio::test]
async fn test_binary_pause_changed_reaches_ws_clients() {
    use futures_util::StreamExt;
    use tokio_tungstenite::tungstenite::Message;

    let fixture = TestFixture::new();
    let events = TranslationEvents::new(128);
    let scope =
        calxgloss_types::ScopeControl::open(fixture.repo_path()).with_events(events.clone());
    let state = ServerState::new(fixture.repo_path()).with_scope_control(scope);
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
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Discover the binary first — an undiscovered name is a 409 and emits
    // no event.
    events.emit(ProgressEvent::QueuePlanned {
        binaries: vec!["game_logic.dll".to_string()],
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    for path in [
        "/api/pipeline/binaries/game_logic.dll/pause",
        "/api/pipeline/binaries/game_logic.dll/resume",
    ] {
        let (status, _) = post_lifecycle(fixture.port(), path).await;
        assert_eq!(status, 200, "{path} should succeed");
    }

    // Collect wire messages and pull out the pause changes with their
    // binary/paused payloads.
    let mut changes: Vec<(String, bool)> = Vec::new();
    for _ in 0..20 {
        if changes.len() >= 2 {
            break;
        }
        let msg = match tokio::time::timeout(Duration::from_millis(500), ws.next()).await {
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

/// The focus endpoint parks a discovered binary in the scope record's
/// single focus slot: 200 echoing the addressed binary, 409 with the
/// server's own reason for an undiscovered one, last press wins, the slot
/// persists on disk (a re-opened handle honors it on the #107 case-rule) —
/// and the served pipeline table hoists the focused binary to the front of
/// its planned order, so a re-fetch shows the new plan before the worklist
/// even reaches its next boundary.
#[tokio::test]
async fn test_pipeline_binary_focus_endpoint() {
    let fixture = TestFixture::new();
    let events = TranslationEvents::new(128);
    let scope =
        calxgloss_types::ScopeControl::open(fixture.repo_path()).with_events(events.clone());
    let state = ServerState::new(fixture.repo_path()).with_scope_control(scope);
    let manager = SessionManager::new_with_broadcast(events.subscribe());
    let progress = ProgressState::new();
    let router = build_router_with_ws(state, manager, progress, ws_actions(&fixture));
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    events.emit(ProgressEvent::QueuePlanned {
        binaries: vec![
            "a.dll".to_string(),
            "b.dll".to_string(),
            "c.dll".to_string(),
        ],
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        pipeline_row_names(fixture.port()).await,
        ["a.dll", "b.dll", "c.dll"],
        "the plan alone sets the row order"
    );

    // A binary the workspace has not discovered: 409 carrying the server's
    // own reason — a stale click is never a silent no-op.
    let (status, body) =
        post_lifecycle(fixture.port(), "/api/pipeline/binaries/nope.dll/focus").await;
    assert_eq!(status, 409);
    assert!(
        body["message"]
            .as_str()
            .unwrap_or_default()
            .contains("has not discovered"),
        "409 carries the server's own reason, got: {body}"
    );

    // Focus c.dll: 200 echoing the addressed binary.
    let (status, body) = post_lifecycle(fixture.port(), "/api/pipeline/binaries/c.dll/focus").await;
    assert_eq!(status, 200);
    assert_eq!(body["binary"], "c.dll");

    // The served rows follow at once — the focus reads as the front of the
    // plan, matching what the live loop will do at the next boundary.
    assert_eq!(
        pipeline_row_names(fixture.port()).await,
        ["c.dll", "a.dll", "b.dll"],
        "GET /api/pipeline hoists the focused binary"
    );

    // One slot, last press wins: b.dll replaces c.dll without ceremony.
    let (status, _) = post_lifecycle(fixture.port(), "/api/pipeline/binaries/b.dll/focus").await;
    assert_eq!(status, 200);
    assert_eq!(
        pipeline_row_names(fixture.port()).await,
        ["b.dll", "a.dll", "c.dll"],
        "the later press is the focus now"
    );

    // The slot rode the persisted scope record — a handle re-opened over
    // the same workspace (a restarted run) honors it, on the #107 match
    // rule.
    let reopened = calxgloss_types::ScopeControl::open(fixture.repo_path());
    assert!(reopened.is_focus("B.DLL"), "the focus survives a restart");
}

// ─────────────────────────────────────────────────────────────
// Per-binary start — a row's Start Translation press (issue #285)
// ─────────────────────────────────────────────────────────────

/// One press of a planned row's Start Translation composes the swap
/// server-side: 200 reusing the binary-pause body (the target echoed
/// unpaused, the message naming the binary paused to make way), the scope
/// seam recording the target resumed-and-focused and the binary in flight
/// paused — each change fanned out as a `BinaryPauseChanged` on the shared
/// broadcast, target first — the served plan re-ordered with the target at
/// the front at once, and both answers persisted for a re-opened handle.
/// The run-level machine is never walked by this press: a live pass stays
/// live.
#[tokio::test]
async fn test_pipeline_binary_start_swaps_the_in_flight_binary() {
    let fixture = TestFixture::new();
    let events = TranslationEvents::new(128);
    let mut seam = events.subscribe();
    let scope =
        calxgloss_types::ScopeControl::open(fixture.repo_path()).with_events(events.clone());
    let control = PipelineControl::new().with_events(events.clone());
    control.start().expect("idle -> running");
    let run_requests = RunRequestSignal::new();
    let state = ServerState::new(fixture.repo_path())
        .with_scope_control(scope)
        .with_pipeline_control(control.clone())
        .with_run_requests(run_requests);
    let manager = SessionManager::new_with_broadcast(events.subscribe());
    let progress = ProgressState::new();
    let router = build_router_with_ws(state, manager, progress, ws_actions(&fixture));
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    // The run's plan is a.dll, b.dll, c.dll — and a.dll's pass is in
    // flight. c.dll's row shows Start Translation; pressing it swaps the
    // run onto c.dll.
    events.emit(ProgressEvent::QueuePlanned {
        binaries: vec![
            "a.dll".to_string(),
            "b.dll".to_string(),
            "c.dll".to_string(),
        ],
    });
    events.emit(ProgressEvent::BatchStarted {
        binary: "a.dll".into(),
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    let (status, body) = post_lifecycle(fixture.port(), "/api/pipeline/binaries/c.dll/start").await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["binary"], "c.dll");
    assert_eq!(body["paused"], false);
    let message = body["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("c.dll") && message.contains("a.dll"),
        "the message names the binary the swap paused, got: {message}"
    );

    // The seam saw exactly the swap's two changes, in composition order:
    // the target admitted, then the previous leader held out at the next
    // unit boundary.
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
    // to be reached for the new plan order to show (issue #284's hoist).
    assert_eq!(
        pipeline_row_names(fixture.port()).await,
        ["c.dll", "a.dll", "b.dll"],
        "the swapped-in target leads the served plan"
    );

    // Both answers rode the persisted scope record — a handle re-opened
    // over the same workspace honors them on the #107 match rule.
    let reopened = calxgloss_types::ScopeControl::open(fixture.repo_path());
    assert!(
        reopened.is_paused("A.DLL"),
        "the previous leader stays paused"
    );
    assert!(!reopened.is_paused("C.DLL"), "the target is admitted");
    assert!(
        reopened.is_focus("C.DLL"),
        "the target holds the focus slot"
    );

    // And the swap steered, never lifecycle-walked: the run stayed live.
    assert!(
        matches!(control.state(), PipelineState::Running),
        "the composition never walks the run-level machine"
    );
}

/// A Start Translation press against a run that cannot honor it is refused
/// with the server's own reason, never a silent no-op: an undiscovered
/// binary is 409 like the pause pair, and a discovered binary the live plan
/// no longer names — its pass already completed in this run — is the stale
/// press, 409 naming the reason and pointing at the row's Configure.
#[tokio::test]
async fn test_pipeline_binary_start_refusals() {
    let fixture = TestFixture::new();
    let events = TranslationEvents::new(128);
    let scope =
        calxgloss_types::ScopeControl::open(fixture.repo_path()).with_events(events.clone());
    let control = PipelineControl::new().with_events(events.clone());
    control.start().expect("idle -> running");
    let run_requests = RunRequestSignal::new();
    let state = ServerState::new(fixture.repo_path())
        .with_scope_control(scope)
        .with_pipeline_control(control.clone())
        .with_run_requests(run_requests);
    let manager = SessionManager::new_with_broadcast(events.subscribe());
    let progress = ProgressState::new();
    let router = build_router_with_ws(state, manager, progress, ws_actions(&fixture));
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    // The plan names only a.dll; done.dll is discovered (classified) but
    // the live plan no longer names it — its pass is behind this run.
    events.emit(ProgressEvent::QueuePlanned {
        binaries: vec!["a.dll".to_string()],
    });
    events.emit(ProgressEvent::ClassificationComplete {
        binary: "done.dll".into(),
        category: "WindowsOs".into(),
        classification_strategy: "ReverseEngineer".into(),
        crate_replacement: None,
        exported_symbols: 10,
        imported_symbols: 4,
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Undiscovered: 409 with the server's own reason, same rule as pause.
    let (status, body) =
        post_lifecycle(fixture.port(), "/api/pipeline/binaries/nope.dll/start").await;
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
    // pass is restart's verb, not the row button's.
    let (status, body) =
        post_lifecycle(fixture.port(), "/api/pipeline/binaries/done.dll/start").await;
    assert_eq!(status, 409);
    let message = body["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("already completed its pass") && message.contains("done.dll"),
        "409 names the stale pass and the target, got: {message}"
    );
}

/// The Start Translation press carries the lifecycle truth of the row it
/// sits on: from Idle it drives the start transition before queueing a
/// plain run request (transition-first, the run endpoint's ADR-0004
/// discipline); from a run-level pause it releases the pause without
/// queueing anything new; and a terminal run is refused with the state
/// machine's own message — the row button never reaches restart.
#[tokio::test]
async fn test_pipeline_binary_start_walks_the_run_level_machine() {
    let fixture = TestFixture::new();
    let events = TranslationEvents::new(128);
    let scope =
        calxgloss_types::ScopeControl::open(fixture.repo_path()).with_events(events.clone());
    let control = PipelineControl::new().with_events(events.clone());
    let run_requests = RunRequestSignal::new();
    let mut request_rx = run_requests.subscribe();
    let state = ServerState::new(fixture.repo_path())
        .with_scope_control(scope)
        .with_pipeline_control(control.clone())
        .with_run_requests(run_requests);
    let manager = SessionManager::new_with_broadcast(events.subscribe());
    let progress = ProgressState::new();
    let router = build_router_with_ws(state, manager, progress, ws_actions(&fixture));
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    events.emit(ProgressEvent::QueuePlanned {
        binaries: vec!["a.dll".to_string(), "b.dll".to_string()],
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Idle: the press begins translating with the pressed binary first —
    // 200, the machine walked Running, the default full-scope request
    // queued on the shared channel exactly as the run endpoint queues it.
    let (status, body) = post_lifecycle(fixture.port(), "/api/pipeline/binaries/b.dll/start").await;
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
    let (status, body) = post_lifecycle(fixture.port(), "/api/pipeline/pause").await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["state"], "paused");
    let (status, body) = post_lifecycle(fixture.port(), "/api/pipeline/binaries/b.dll/start").await;
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
    let (status, body) = post_lifecycle(fixture.port(), "/api/pipeline/binaries/a.dll/start").await;
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
    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path());
    let (manager, _event_tx) = SessionManager::new();
    let progress = ProgressState::new();
    let router = build_router_with_ws(state, manager, progress, ws_actions(&fixture));
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let client = reqwest::Client::new();

    let resp = client
        .get(format!("http://127.0.0.1:{}/api/scope", fixture.port()))
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
        let resp = client
            .post(format!("http://127.0.0.1:{}{path}", fixture.port()))
            .json(&body)
            .send()
            .await
            .expect("request reaches server");
        let status = resp.status();
        let resp_body: serde_json::Value = resp.json().await.expect("body is JSON");
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
        let resp = client
            .post(format!("http://127.0.0.1:{}{path}", fixture.port()))
            .send()
            .await
            .expect("request reaches server");
        let status = resp.status();
        let resp_body: serde_json::Value = resp.json().await.expect("body is JSON");
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
    let fixture = TestFixture::new();
    let scope = calxgloss_types::ScopeControl::open(fixture.repo_path());
    let state = ServerState::new(fixture.repo_path()).with_scope_control(scope);
    let (manager, _event_tx) = SessionManager::new();
    let progress = ProgressState::new();
    let router = build_router_with_ws(state, manager, progress, ws_actions(&fixture));
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let client = reqwest::Client::new();
    let base = format!("http://127.0.0.1:{}", fixture.port());

    let resp = client
        .post(format!("{base}/api/scope/binaries"))
        .json(&serde_json::json!({"binaries": ["game_logic.dll"]}))
        .send()
        .await
        .expect("request reaches server");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("body is JSON");
    assert_eq!(body["scope"]["binaries"][0], "game_logic.dll");

    let resp = client
        .post(format!("{base}/api/scope/skip-function"))
        .json(&serde_json::json!({"binary": "game_logic.dll", "function": "UpdateScene"}))
        .send()
        .await
        .expect("request reaches server");
    assert_eq!(resp.status(), 200);

    let resp = client
        .post(format!("{base}/api/scope/priority-function"))
        .json(&serde_json::json!({"binary": "game_logic.dll", "function": "DrawPrimitive"}))
        .send()
        .await
        .expect("request reaches server");
    assert_eq!(resp.status(), 200);

    // Issue #95: the panel's remove button drives the removal endpoint —
    // a prioritized function drops out, the rest of the list stays.
    let resp = client
        .post(format!("{base}/api/scope/priority-function"))
        .json(&serde_json::json!({"binary": "game_logic.dll", "function": "RenderFrame"}))
        .send()
        .await
        .expect("request reaches server");
    assert_eq!(resp.status(), 200);
    let resp = client
        .post(format!("{base}/api/scope/remove-priority-function"))
        .json(&serde_json::json!({"binary": "game_logic.dll", "function": "RenderFrame"}))
        .send()
        .await
        .expect("request reaches server");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("body is JSON");
    assert_eq!(
        body["scope"]["priority_functions"].as_array().map(Vec::len),
        Some(1),
        "the removed priority is gone from the echoed status"
    );

    let resp = client
        .post(format!("{base}/api/scope/constraints"))
        .json(&serde_json::json!({
            "max_attempts": 2,
            "max_context_tier": "Disassembly",
            "token_budget": 50000
        }))
        .send()
        .await
        .expect("request reaches server");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("body is JSON");
    assert_eq!(body["constraints"]["max_attempts"], 2);
    assert_eq!(body["constraints"]["max_context_tier"], "Disassembly");
    assert_eq!(body["constraints"]["token_budget"], 50000);

    // Status read reflects every mutation.
    let resp = client
        .get(format!("{base}/api/scope"))
        .send()
        .await
        .expect("request reaches server");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("body is JSON");
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
    let reopened = calxgloss_types::ScopeControl::open(fixture.repo_path());
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
    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path());
    let (manager, _event_tx) = SessionManager::new();
    let progress = ProgressState::new();
    let router = build_router_with_ws(state, manager, progress, ws_actions(&fixture));
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let client = reqwest::Client::new();
    let url = format!(
        "http://127.0.0.1:{}/api/units/game_logic.dll%2FDrawPrimitive%2Fv1/override",
        fixture.port()
    );

    let resp = client
        .get(&url)
        .send()
        .await
        .expect("request reaches server");
    assert_eq!(resp.status(), 503, "GET override without a handle is 503");
    let body: serde_json::Value = resp.json().await.expect("body is JSON");
    assert!(
        body["message"]
            .as_str()
            .unwrap_or_default()
            .contains("no unit override control"),
        "503 explains why, got: {body}"
    );

    let resp = client
        .post(&url)
        .json(&serde_json::json!({"override": {"skip": true}}))
        .send()
        .await
        .expect("request reaches server");
    assert_eq!(resp.status(), 503, "POST override without a handle is 503");

    let resp = client
        .delete(&url)
        .send()
        .await
        .expect("request reaches server");
    assert_eq!(
        resp.status(),
        503,
        "DELETE override without a handle is 503"
    );
}

/// The override endpoints drive the shared handle end to end: apply lands,
/// GET reads it back, removal clears it, and a handle re-opened over the
/// same workspace (a restarted run) honors the persisted records without
/// re-entering anything (issue #96).
#[tokio::test]
async fn test_override_endpoints_apply_get_and_persist() {
    let fixture = TestFixture::new();
    let overrides = calxgloss_types::OverrideControl::open(fixture.repo_path());
    let state = ServerState::new(fixture.repo_path()).with_override_control(overrides);
    let (manager, _event_tx) = SessionManager::new();
    let progress = ProgressState::new();
    let router = build_router_with_ws(state, manager, progress, ws_actions(&fixture));
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let client = reqwest::Client::new();
    let url = format!(
        "http://127.0.0.1:{}/api/units/game_logic.dll%2FDrawPrimitive%2Fv1/override",
        fixture.port()
    );

    // A never-overridden unit reads back honestly: 200 with no override.
    let resp = client
        .get(&url)
        .send()
        .await
        .expect("request reaches server");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("body is JSON");
    assert_eq!(body["unit"], "game_logic.dll/DrawPrimitive/v1");
    assert!(
        body["override"].is_null(),
        "no override set yet, got: {body}"
    );

    // Apply the full record.
    let resp = client
        .post(&url)
        .json(&serde_json::json!({"override": {
            "tier_override": "FullModule",
            "retry_strategy_override": "escalate",
            "custom_hints": ["uses SSE registers"],
            "skip": false,
            "reviewer_notes": "looks like a blitter"
        }}))
        .send()
        .await
        .expect("request reaches server");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("body is JSON");
    assert_eq!(body["override"]["tier_override"], "FullModule");
    assert_eq!(body["override"]["retry_strategy_override"], "escalate");
    assert_eq!(body["override"]["custom_hints"][0], "uses SSE registers");
    assert_eq!(body["override"]["reviewer_notes"], "looks like a blitter");

    // A typo'd strategy label is refused — the record's typed field rejects
    // the unknown variant rather than storing a force that looks active but
    // silently does nothing (axum answers the failed JSON extraction with
    // 422, like the classification override's category, issue #120).
    let resp = client
        .post(&url)
        .json(&serde_json::json!({"override": {"retry_strategy_override": "escalatte"}}))
        .send()
        .await
        .expect("request reaches server");
    assert_eq!(resp.status(), 422, "unknown strategy label is rejected");
    let stored = calxgloss_types::OverrideControl::open(fixture.repo_path())
        .get("game_logic.dll", "DrawPrimitive");
    assert_eq!(
        stored.and_then(|o| o.retry_strategy_override),
        Some(calxgloss_types::RetryStrategy::Escalate),
        "the rejected request must not disturb the stored record"
    );

    // GET reads the same record back.
    let resp = client
        .get(&url)
        .send()
        .await
        .expect("request reaches server");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("body is JSON");
    assert_eq!(body["override"]["tier_override"], "FullModule");

    // A restarted run: a fresh handle over the same workspace loads the
    // persisted record — nothing re-entered.
    let reopened = calxgloss_types::OverrideControl::open(fixture.repo_path());
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
    let resp = client
        .delete(&url)
        .send()
        .await
        .expect("request reaches server");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("body is JSON");
    assert!(
        body["override"].is_null(),
        "removal leaves no record, got: {body}"
    );

    let reopened = calxgloss_types::OverrideControl::open(fixture.repo_path());
    assert!(
        reopened.get("game_logic.dll", "DrawPrimitive").is_none(),
        "the removal survives a restart"
    );
}

// ─────────────────────────────────────────────────────────────
// Binary classification overrides (issue #97, W2.8)
// ─────────────────────────────────────────────────────────────

/// Seed a `re/classify/fmod.dll.json` artifact — the shape the classify
/// command writes, reasoning included — so the endpoints have a recorded
/// classification to report.
fn write_canned_classification_record(fixture: &TestFixture, binary: &str, category: &str) {
    let dir = fixture.repo_path().join("re").join("classify");
    std::fs::create_dir_all(&dir).expect("classify dir");
    let record = serde_json::json!({
        "binary": binary,
        "category": category,
        "strategy": "ReverseEngineer",
        "exports_count": 10,
        "imports_count": 4,
        "crate_replacement": null,
        "known_runtime": false,
        "reason": "import table matched no known library — treated as unknown third-party"
    });
    std::fs::write(
        dir.join(format!("{binary}.json")),
        serde_json::to_string_pretty(&record).expect("serialize"),
    )
    .expect("classification record written");
}

/// A live router built **without** a classification-override handle attached
/// answers the classification endpoints honestly with 503 rather than
/// steering a classification it does not hold — the override endpoints'
/// honesty rule, same shape.
#[tokio::test]
async fn test_classification_override_endpoints_503_without_control() {
    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path());
    let (manager, _event_tx) = SessionManager::new();
    let progress = ProgressState::new();
    let router = build_router_with_ws(state, manager, progress, ws_actions(&fixture));
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let client = reqwest::Client::new();
    let url = format!(
        "http://127.0.0.1:{}/api/binaries/fmod.dll/classification",
        fixture.port()
    );

    let resp = client
        .get(&url)
        .send()
        .await
        .expect("request reaches server");
    assert_eq!(
        resp.status(),
        503,
        "GET classification without a handle is 503"
    );
    let body: serde_json::Value = resp.json().await.expect("body is JSON");
    assert!(
        body["message"]
            .as_str()
            .unwrap_or_default()
            .contains("no classification override control"),
        "503 explains why, got: {body}"
    );

    let resp = client
        .post(&url)
        .json(
            &serde_json::json!({"override": {"category": "RuntimeLibrary", "known_runtime": true}}),
        )
        .send()
        .await
        .expect("request reaches server");
    assert_eq!(
        resp.status(),
        503,
        "POST classification without a handle is 503"
    );
}

/// The classification endpoints drive the shared handle end to end: the GET
/// reports the recorded classification with its reasoning, an override
/// lands and reads back, a typo'd category is refused, `null` removes it,
/// and a handle re-opened over the same workspace (a restarted run) honors
/// the persisted records without re-entering anything (issue #97).
#[tokio::test]
async fn test_classification_override_endpoints_set_get_and_persist() {
    let fixture = TestFixture::new();
    write_canned_classification_record(&fixture, "fmod.dll", "UnknownThirdParty");
    let overrides = calxgloss_types::ClassificationOverrideControl::open(fixture.repo_path());
    let state =
        ServerState::new(fixture.repo_path()).with_classification_override_control(overrides);
    let (manager, _event_tx) = SessionManager::new();
    let progress = ProgressState::new();
    let router = build_router_with_ws(state, manager, progress, ws_actions(&fixture));
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let client = reqwest::Client::new();
    let url = format!(
        "http://127.0.0.1:{}/api/binaries/fmod.dll/classification",
        fixture.port()
    );

    // The recorded classification, with its reasoning, and no override yet.
    let resp = client
        .get(&url)
        .send()
        .await
        .expect("request reaches server");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("body is JSON");
    assert_eq!(body["binary"], "fmod.dll");
    assert_eq!(body["classification"]["category"], "UnknownThirdParty");
    assert_eq!(body["classification"]["strategy"], "ReverseEngineer");
    assert!(
        body["classification"]["reason"]
            .as_str()
            .unwrap_or_default()
            .contains("no known library"),
        "the reasoning rides along, got: {body}"
    );
    assert!(
        body["override"].is_null(),
        "no override set yet, got: {body}"
    );

    // Apply the override — a runtime-library correction.
    let resp = client
        .post(&url)
        .json(&serde_json::json!({"override": {
            "category": "RuntimeLibrary",
            "known_runtime": true
        }}))
        .send()
        .await
        .expect("request reaches server");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("body is JSON");
    assert_eq!(body["override"]["category"], "RuntimeLibrary");
    assert_eq!(body["override"]["known_runtime"], true);

    // A typo'd category is refused — serde rejects the unknown variant
    // rather than storing a decision that means nothing (axum answers the
    // failed JSON extraction with 422).
    let resp = client
        .post(&url)
        .json(&serde_json::json!({"override": {"category": "RuntimeLibary"}}))
        .send()
        .await
        .expect("request reaches server");
    assert_eq!(resp.status(), 422, "unknown category is rejected");
    let stored = calxgloss_types::ClassificationOverrideControl::open(fixture.repo_path());
    assert_eq!(
        stored.get("fmod.dll").map(|o| o.category),
        Some(calxgloss_types::DllCategory::RuntimeLibrary),
        "the rejected request must not disturb the stored record"
    );

    // GET reads the same record back.
    let resp = client
        .get(&url)
        .send()
        .await
        .expect("request reaches server");
    let body: serde_json::Value = resp.json().await.expect("body is JSON");
    assert_eq!(body["override"]["category"], "RuntimeLibrary");

    // A restarted run: a fresh handle over the same workspace loads the
    // persisted record — nothing re-entered.
    let reopened = calxgloss_types::ClassificationOverrideControl::open(fixture.repo_path());
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
    let resp = client
        .post(&url)
        .json(&serde_json::json!({"override": null}))
        .send()
        .await
        .expect("request reaches server");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("body is JSON");
    assert!(
        body["override"].is_null(),
        "removal leaves no record, got: {body}"
    );

    let reopened = calxgloss_types::ClassificationOverrideControl::open(fixture.repo_path());
    assert!(
        reopened.get("fmod.dll").is_none(),
        "the removal survives a restart"
    );
}

// ─────────────────────────────────────────────────────────────
// Pipeline start & restart (issue #92, W2.3)
// ─────────────────────────────────────────────────────────────

/// POST helper for the start/restart endpoints, which may carry a JSON
/// run-request body (issue #92).
async fn post_run(
    port: u16,
    path: &str,
    body: serde_json::Value,
) -> (reqwest::StatusCode, serde_json::Value) {
    let mut req = reqwest::Client::new().post(format!("http://127.0.0.1:{port}{path}"));
    if !body.is_null() {
        req = req.json(&body);
    }
    let resp = req.send().await.expect("run request reaches server");
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.expect("run body is JSON");
    (status, body)
}

/// The Start endpoint (issue #92) begins translation in a live session that
/// has not translated yet: Idle → Running with 200, the default full-scope
/// request queued on the shared channel for the live loop, the server status
/// following the machine — and a second Start refused with 409 leaving no
/// stale request behind.
#[tokio::test]
async fn test_pipeline_start_endpoint_begins_idle_run() {
    let fixture = TestFixture::new();
    let events = TranslationEvents::new(128);
    let control = PipelineControl::new().with_events(events.clone());
    let run_requests = RunRequestSignal::new();
    let mut request_rx = run_requests.subscribe();
    let state = ServerState::new(fixture.repo_path())
        .with_pipeline_control(control.clone())
        .with_run_requests(run_requests.clone());
    let manager = SessionManager::new_with_broadcast(events.subscribe());
    let progress = ProgressState::new();
    let router = build_router_with_ws(state, manager, progress, ws_actions(&fixture));
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    // Start from Idle: 200, the transition in the body.
    let (status, body) = post_run(
        fixture.port(),
        "/api/pipeline/start",
        serde_json::json!(null),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body["previous"], "idle");
    assert_eq!(body["state"], "running");

    // The default full-scope request landed on the shared channel — the
    // live loop's subscription sees it.
    request_rx.changed().await.expect("a request was queued");
    let queued = request_rx.borrow_and_update().clone();
    assert_eq!(queued, Some(PipelineRunRequest::default()));

    // Server status follows the machine.
    let resp = reqwest::get(format!(
        "http://127.0.0.1:{}/api/server/status",
        fixture.port()
    ))
    .await
    .expect("server status request succeeds");
    let body: serde_json::Value = resp.json().await.expect("status body is JSON");
    assert_eq!(body["pipeline_status"], "running");

    // A run already in flight cannot be started again — 409 with the
    // machine's own message, and no second request queued.
    let (status, body) = post_run(
        fixture.port(),
        "/api/pipeline/start",
        serde_json::json!(null),
    )
    .await;
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
    let fixture = TestFixture::new();
    let events = TranslationEvents::new(128);
    let control = PipelineControl::new().with_events(events.clone());
    control.start().expect("idle -> running");
    let run_requests = RunRequestSignal::new();
    let mut request_rx = run_requests.subscribe();
    let state = ServerState::new(fixture.repo_path())
        .with_pipeline_control(control.clone())
        .with_run_requests(run_requests.clone());
    let manager = SessionManager::new_with_broadcast(events.subscribe());
    let progress = ProgressState::new();
    let router = build_router_with_ws(state, manager, progress, ws_actions(&fixture));
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    // A run still in flight cannot restart — the operator stops it first.
    let (status, body) = post_run(
        fixture.port(),
        "/api/pipeline/restart",
        serde_json::json!({}),
    )
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
    let (status, body) = post_run(fixture.port(), "/api/pipeline/restart", selectors).await;
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
    let (status, _) = post_run(
        fixture.port(),
        "/api/pipeline/restart",
        serde_json::json!(null),
    )
    .await;
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

    let fixture = TestFixture::new();
    let events = TranslationEvents::new(128);
    let control = PipelineControl::new().with_events(events.clone());
    let run_requests = RunRequestSignal::new();
    let state = ServerState::new(fixture.repo_path())
        .with_pipeline_control(control.clone())
        .with_run_requests(run_requests.clone());
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
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Start the run from Idle over HTTP…
    let (status, _) = post_run(
        fixture.port(),
        "/api/pipeline/start",
        serde_json::json!(null),
    )
    .await;
    assert_eq!(status, 200);
    // …the run finishes (the live loop would do this walk)…
    control.stop().expect("running -> stopping");
    control.complete().expect("stopping -> complete");
    // …and Restart begins it again in-process.
    let (status, _) = post_run(
        fixture.port(),
        "/api/pipeline/restart",
        serde_json::json!({}),
    )
    .await;
    assert_eq!(status, 200);

    let mut transitions: Vec<(String, String)> = Vec::new();
    for _ in 0..20 {
        if transitions.len() >= 4 {
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
    let router = build_router_with_ws(state, manager, progress.clone(), ws_actions(&fixture));
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
    let router = build_router_with_ws(state, manager, progress, ws_actions(&fixture));
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    // Two binaries classified; d3d9 via the PAL strategy.
    events.emit(ProgressEvent::ClassificationComplete {
        binary: "dinput8.dll".into(),
        category: "WindowsOs".into(),
        classification_strategy: "ReverseEngineer".into(),
        crate_replacement: None,
        exported_symbols: 10,
        imported_symbols: 4,
    });
    events.emit(ProgressEvent::ClassificationComplete {
        binary: "d3d9.dll".into(),
        category: "WindowsOs".into(),
        classification_strategy: "PalMapping".into(),
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
        retry_strategy: "direct".into(),
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

    // ── Per-binary progress (PAL row pinned last, issue #242) ────────
    let binaries = body["binaries"].as_array().unwrap();
    assert_eq!(binaries.len(), 3);
    let names: Vec<&str> = binaries
        .iter()
        .map(|b| b["binary"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["dinput8.dll", "game_logic.dll", "d3d9.dll"]);

    // d3d9: classified via PAL, batch pass in flight — no fabricated totals.
    let b = &binaries[2];
    assert_eq!(b["classification_strategy"], "PalMapping");
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
    let b = &binaries[0];
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
    let b = &binaries[1];
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
    let router = build_router_with_ws(state, manager, progress, ws_actions(&fixture));
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
    assert_eq!(b["classification_strategy"], "ReverseEngineer");
    assert_eq!(b["processing"], false);

    // A tagged-object strategy hydrates to its variant name — not an
    // empty string that the UI would render as "Unclassified".
    let b = binary("steam_api64.dll");
    assert_eq!(b["category"], "KnownThirdParty");
    assert_eq!(b["classification_strategy"], "CrateReplacement");
    assert_eq!(b["crate_replacement"], "steamworks");

    // Aggregate counts see both sources honestly.
    assert_eq!(body["total_dlls"], 3);
    assert_eq!(
        body["classified_count"], 2,
        "both disk records count as classified"
    );
}

/// The pre-batch scan phase beats once around its whole group under the
/// phase name (issue #239), and the call-graph pass beats per function
/// while it walks its work list; `/api/pipeline` surfaces the latest
/// beat as `activity` on the processing binary's row — and a phase beat
/// with no per-item granularity beats with just its name.
#[tokio::test]
async fn test_pipeline_batch_progress_heartbeat_surfaces_on_row() {
    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path());
    let events = TranslationEvents::new(128);
    let manager = SessionManager::new_with_broadcast(events.subscribe());
    let progress = ProgressState::new();
    let router = build_router_with_ws(state, manager, progress, ws_actions(&fixture));
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    events.emit(ProgressEvent::BatchStarted {
        binary: "LaunchPad.exe".into(),
    });
    events.emit(ProgressEvent::BatchProgress {
        binary: "LaunchPad.exe".into(),
        pass: "evidence scans".into(),
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
    assert_eq!(b["activity"]["pass"], "evidence scans");
    assert_eq!(b["activity"]["function"], "FUN_1929282");
    assert_eq!(b["activity"]["index"], 1);
    assert_eq!(b["activity"]["total"], 22143);

    // A phase beat before its first listing has no per-item
    // granularity: only the name is honest.
    events.emit(ProgressEvent::BatchProgress {
        binary: "LaunchPad.exe".into(),
        pass: "evidence scans".into(),
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
    assert_eq!(b["activity"]["pass"], "evidence scans", "latest beat wins");
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
    let router = build_router_with_ws(state, manager, progress, ws_actions(&fixture));
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

/// GET /api/pipeline's `binaries` array as the row-name sequence it serves.
async fn pipeline_row_names(port: u16) -> Vec<String> {
    let resp = reqwest::get(format!("http://127.0.0.1:{port}/api/pipeline"))
        .await
        .expect("pipeline request succeeds");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("pipeline body is JSON");
    body["binaries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| b["binary"].as_str().unwrap_or("").to_string())
        .collect()
}

/// GET /api/pipeline's `binaries` array as the full JSON records it serves.
async fn pipeline_binary_rows(port: u16) -> Vec<serde_json::Value> {
    let resp = reqwest::get(format!("http://127.0.0.1:{port}/api/pipeline"))
        .await
        .expect("pipeline request succeeds");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("pipeline body is JSON");
    body["binaries"].as_array().unwrap().clone()
}

/// The `binaries` row for one binary, by name.
fn binary_row<'a>(rows: &'a [serde_json::Value], name: &str) -> &'a serde_json::Value {
    rows.iter()
        .find(|r| r["binary"] == name)
        .unwrap_or_else(|| panic!("{name} row present in {rows:?}"))
}

/// Issue #242: PAL-mapped binaries pin to the bottom of the pipeline table.
/// The order is three-tier — queue-planned non-PAL rows in queue-plan order,
/// unplanned non-PAL rows alphabetical, then PalMapping rows alphabetical —
/// and a PAL binary the queue plan names still sorts after every non-PAL
/// row: display order reflects translation intent, not a queue accident.
#[tokio::test]
async fn test_pipeline_pal_binaries_sort_last() {
    let fixture = TestFixture::new();
    // Disk-classified, unplanned: one PAL binary and one reverse-engineered
    // one, named so plain alphabetical order would interleave them.
    let classify = fixture.repo_path().join("re").join("classify");
    std::fs::create_dir_all(&classify).expect("create classify dir");
    std::fs::write(
        classify.join("aaa_pal.dll.json"),
        r#"{"binary":"aaa_pal.dll","category":"WindowsOs","strategy":"PalMapping","exports_count":0,"imports_count":1,"crate_replacement":null}"#,
    )
    .expect("write PAL classification artifact");
    std::fs::write(
        classify.join("zzz.dll.json"),
        r#"{"binary":"zzz.dll","category":"ProjectSpecific","strategy":"ReverseEngineer","exports_count":0,"imports_count":1,"crate_replacement":null}"#,
    )
    .expect("write RE classification artifact");

    let state = ServerState::new(fixture.repo_path());
    let events = TranslationEvents::new(128);
    let manager = SessionManager::new_with_broadcast(events.subscribe());
    let progress = ProgressState::new();
    let router = build_router_with_ws(state, manager, progress, ws_actions(&fixture));
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    // Live-classified, both named in the queue plan: one PAL, one crate
    // replacement — the mix the acceptance criteria ask for.
    events.emit(ProgressEvent::ClassificationComplete {
        binary: "d3d9.dll".into(),
        category: "WindowsOs".into(),
        classification_strategy: "PalMapping".into(),
        crate_replacement: None,
        exported_symbols: 25,
        imported_symbols: 6,
    });
    events.emit(ProgressEvent::ClassificationComplete {
        binary: "dinput8.dll".into(),
        category: "MicrosoftSdk".into(),
        classification_strategy: "CrateReplacement".into(),
        crate_replacement: Some("dinput8-rs".into()),
        exported_symbols: 10,
        imported_symbols: 2,
    });
    events.emit(ProgressEvent::QueuePlanned {
        binaries: vec![
            "LaunchPad.exe".into(),
            "d3d9.dll".into(),
            "eqmain.dll".into(),
            "dinput8.dll".into(),
        ],
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    assert_eq!(
        pipeline_row_names(fixture.port()).await,
        [
            "LaunchPad.exe", // planned non-PAL, in plan order…
            "eqmain.dll",
            "dinput8.dll", // …the planned crate-replacement row stays with them
            "zzz.dll",     // unplanned non-PAL, alphabetical
            "aaa_pal.dll", // PAL rows last, alphabetical among themselves…
            "d3d9.dll",    // …even when the plan names them mid-list
        ],
        "PAL rows pin to the bottom; non-PAL order is queue-plan then alphabetical"
    );
}

/// Issue #242: classification changes move rows for free. The order is
/// recomputed per poll from the merged live-over-disk classifications, so a
/// re-classification into PAL mapping sinks the row and one out of PAL
/// mapping lifts it back — on the very next request, with no restart.
#[tokio::test]
async fn test_pipeline_pal_reclassification_relocates_row_on_next_poll() {
    let fixture = TestFixture::new();
    // Disk records start the pair the "wrong" way round for alphabetical
    // order: fmod.dll reverse-engineered, d3d9.dll PAL-mapped.
    let classify = fixture.repo_path().join("re").join("classify");
    std::fs::create_dir_all(&classify).expect("create classify dir");
    std::fs::write(
        classify.join("fmod.dll.json"),
        r#"{"binary":"fmod.dll","category":"ProjectSpecific","strategy":"ReverseEngineer","exports_count":0,"imports_count":1,"crate_replacement":null}"#,
    )
    .expect("write RE classification artifact");
    std::fs::write(
        classify.join("d3d9.dll.json"),
        r#"{"binary":"d3d9.dll","category":"WindowsOs","strategy":"PalMapping","exports_count":0,"imports_count":1,"crate_replacement":null}"#,
    )
    .expect("write PAL classification artifact");

    let state = ServerState::new(fixture.repo_path());
    let events = TranslationEvents::new(128);
    let manager = SessionManager::new_with_broadcast(events.subscribe());
    let progress = ProgressState::new();
    let router = build_router_with_ws(state, manager, progress, ws_actions(&fixture));
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    assert_eq!(
        pipeline_row_names(fixture.port()).await,
        ["fmod.dll", "d3d9.dll"],
        "non-PAL row first, PAL row pinned last"
    );

    // The operator corrects both classifications — live events supersede
    // the disk records, exactly as the row's rendered strategy does.
    events.emit(ProgressEvent::ClassificationComplete {
        binary: "fmod.dll".into(),
        category: "WindowsOs".into(),
        classification_strategy: "PalMapping".into(),
        crate_replacement: None,
        exported_symbols: 0,
        imported_symbols: 1,
    });
    events.emit(ProgressEvent::ClassificationComplete {
        binary: "d3d9.dll".into(),
        category: "ProjectSpecific".into(),
        classification_strategy: "ReverseEngineer".into(),
        crate_replacement: None,
        exported_symbols: 0,
        imported_symbols: 1,
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    assert_eq!(
        pipeline_row_names(fixture.port()).await,
        ["d3d9.dll", "fmod.dll"],
        "both rows relocate on the next poll — into and out of the PAL tier"
    );
}

// ─────────────────────────────────────────────────────────────
// Pipeline PAL-readiness summary (issue #243, part of #223)
// ─────────────────────────────────────────────────────────────

/// Seed the artifacts the pipeline PAL-readiness tests pin: disk
/// classification records routing d3d9.dll to PalMapping and game_logic.dll
/// to ReverseEngineer, per-function analysis artifacts under
/// `re/analysis/d3d9.dll/` recording DirectX and Win32Core API-call
/// categories, and a generated shared PAL crate under `scratch/pal/src/`
/// defining GraphicsDevice but not PlatformCore — the partially defined
/// trait set the summary must report honestly.
fn write_pipeline_pal_readiness_fixtures(fixture: &TestFixture) {
    let classify = fixture.repo_path().join("re").join("classify");
    std::fs::create_dir_all(&classify).expect("classify dir");
    std::fs::write(
        classify.join("d3d9.dll.json"),
        r#"{"binary":"d3d9.dll","category":"WindowsOs","strategy":"PalMapping","exports_count":0,"imports_count":1,"crate_replacement":null}"#,
    )
    .expect("write PAL classification artifact");
    std::fs::write(
        classify.join("game_logic.dll.json"),
        r#"{"binary":"game_logic.dll","category":"ProjectSpecific","strategy":"ReverseEngineer","exports_count":0,"imports_count":1,"crate_replacement":null}"#,
    )
    .expect("write RE classification artifact");

    let analysis = fixture
        .repo_path()
        .join("re")
        .join("analysis")
        .join("d3d9.dll");
    std::fs::create_dir_all(&analysis).expect("d3d9 analysis dir");
    std::fs::write(
        analysis.join("CreateDevice.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "function_name": "CreateDevice",
            "windows_apis": [
                { "name": "Direct3DCreate9", "category": "DirectX" },
                { "name": "CreateFileA", "category": "Win32Core" }
            ]
        }))
        .unwrap(),
    )
    .expect("CreateDevice artifact written");
    std::fs::write(
        analysis.join("Present.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "function_name": "Present",
            "windows_apis": [
                { "name": "IDXGISwapChain::Present", "category": "DirectX11" }
            ]
        }))
        .unwrap(),
    )
    .expect("Present artifact written");

    let pal_src = fixture.repo_path().join("scratch").join("pal").join("src");
    std::fs::create_dir_all(&pal_src).expect("scratch pal src dir");
    std::fs::write(
        pal_src.join("stub_content.rs"),
        "pub trait GraphicsDevice {\n    fn create_device(width: u32, height: u32) -> Self;\n}\n",
    )
    .expect("pal stub content written");
}

/// Issue #243: a PalMapping row carries the PAL-readiness summary — the
/// traits its recorded API-call categories demand (DirectX and DirectX11
/// grouping into GraphicsDevice, Win32Core into PlatformCore), sorted by
/// trait name, each flagged defined or missing against the workspace's
/// generated PAL/shim sources. Non-PAL rows carry no `pal` field at all.
#[tokio::test]
async fn test_pipeline_pal_row_carries_trait_readiness_summary() {
    let fixture = TestFixture::new();
    write_pipeline_pal_readiness_fixtures(&fixture);

    let state = ServerState::new(fixture.repo_path());
    let events = TranslationEvents::new(128);
    let manager = SessionManager::new_with_broadcast(events.subscribe());
    let progress = ProgressState::new();
    let router = build_router_with_ws(state, manager, progress, ws_actions(&fixture));
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let rows = pipeline_binary_rows(fixture.port()).await;
    assert_eq!(
        binary_row(&rows, "d3d9.dll")["pal"]["traits"],
        serde_json::json!([
            { "name": "GraphicsDevice", "defined": true },
            { "name": "PlatformCore", "defined": false },
        ]),
        "the PAL row reports the demanded traits with their defined/missing flags"
    );
    assert!(
        binary_row(&rows, "game_logic.dll").get("pal").is_none(),
        "a ReverseEngineer row has no PAL summary field at all"
    );
}

/// Issue #243: a PAL binary whose artifacts record no API-call categories
/// honestly reports no summary — the field is omitted, never an empty
/// structure fabricated in its place.
#[tokio::test]
async fn test_pipeline_pal_binary_without_categories_reports_no_summary() {
    let fixture = TestFixture::new();
    // The classification routes it to PAL mapping, but no analysis
    // artifacts exist to derive traits from.
    let classify = fixture.repo_path().join("re").join("classify");
    std::fs::create_dir_all(&classify).expect("classify dir");
    std::fs::write(
        classify.join("d3d9.dll.json"),
        r#"{"binary":"d3d9.dll","category":"WindowsOs","strategy":"PalMapping","exports_count":0,"imports_count":1,"crate_replacement":null}"#,
    )
    .expect("write PAL classification artifact");

    let state = ServerState::new(fixture.repo_path());
    let events = TranslationEvents::new(128);
    let manager = SessionManager::new_with_broadcast(events.subscribe());
    let progress = ProgressState::new();
    let router = build_router_with_ws(state, manager, progress, ws_actions(&fixture));
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let rows = pipeline_binary_rows(fixture.port()).await;
    assert!(
        binary_row(&rows, "d3d9.dll").get("pal").is_none(),
        "no recorded categories means no summary, not an empty one"
    );
}

/// Issue #243: the summary recomputes per poll. A newly defined trait in
/// the generated PAL sources flips its flag to defined on the next refresh,
/// and a classification override out of PAL mapping drops the summary
/// entirely — both with no restart and no special handling.
#[tokio::test]
async fn test_pipeline_pal_readiness_recomputes_per_poll() {
    let fixture = TestFixture::new();
    write_pipeline_pal_readiness_fixtures(&fixture);

    let state = ServerState::new(fixture.repo_path());
    let events = TranslationEvents::new(128);
    let manager = SessionManager::new_with_broadcast(events.subscribe());
    let progress = ProgressState::new();
    let router = build_router_with_ws(state, manager, progress, ws_actions(&fixture));
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let rows = pipeline_binary_rows(fixture.port()).await;
    assert_eq!(
        binary_row(&rows, "d3d9.dll")["pal"]["traits"][1]["defined"],
        false,
        "PlatformCore is missing on the first poll"
    );

    // Trait design advances: the generated PAL crate now defines
    // PlatformCore too.
    let pal_src = fixture.repo_path().join("scratch").join("pal").join("src");
    std::fs::write(
        pal_src.join("platform_core.rs"),
        "pub trait PlatformCore {\n    fn open(path: &str) -> Self;\n}\n",
    )
    .expect("platform core trait written");

    let rows = pipeline_binary_rows(fixture.port()).await;
    assert_eq!(
        binary_row(&rows, "d3d9.dll")["pal"]["traits"][1]["defined"],
        true,
        "the next poll reflects the newly defined trait"
    );

    // The operator reclassifies the binary out of PAL mapping — the live
    // event supersedes the disk record and the summary disappears.
    events.emit(ProgressEvent::ClassificationComplete {
        binary: "d3d9.dll".into(),
        category: "ProjectSpecific".into(),
        classification_strategy: "ReverseEngineer".into(),
        crate_replacement: None,
        exported_symbols: 0,
        imported_symbols: 1,
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    let rows = pipeline_binary_rows(fixture.port()).await;
    assert!(
        binary_row(&rows, "d3d9.dll").get("pal").is_none(),
        "reclassified out of PAL mapping: no summary on the next poll"
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
    let router = build_router_with_ws(state, manager, progress, ws_actions(&fixture));
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
    let router = build_router_with_ws(state, manager, progress, ws_actions(&fixture));
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
            build_router_with_actions(
                state,
                ActionsState::new(fixture.repo_path(), PipelineSpec::default()),
            )
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
    let router = build_router_with_ws(state, manager, progress, ws_actions(&fixture));
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
    let router = build_router_with_ws(state.clone(), manager, progress, ws_actions(&fixture));
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
    let router = build_router_with_ws(state.clone(), manager, progress, ws_actions(&fixture));
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
        ProgressEvent::ScanFetchComplete {
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
            retry_strategy: "direct".into(),
        },
        ProgressEvent::LlmCallFailed {
            binary: "game_logic.dll".into(),
            function: "DrawPrimitive".into(),
            attempt: 1,
            retry_strategy: "direct".into(),
            error: "context window exceeded".into(),
        },
        tier("T2"),
        ProgressEvent::LlmCallStart {
            binary: "game_logic.dll".into(),
            function: "DrawPrimitive".into(),
            attempt: 2,
            retry_strategy: "decompose".into(),
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
            retry_strategy: "decompose".into(),
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
    assert_eq!(unit["retry_strategy"].as_str(), Some("decompose"));
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
            "scan_fetch",
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
        vec!["scan_fetch", "review"]
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
    let router = build_router_with_ws(state.clone(), manager, progress, ws_actions(&fixture));
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
            retry_strategy: "decompose".into(),
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
            retry_strategy: "decompose".into(),
            tokens_used: None,
        },
        ProgressEvent::BehaviorDivergenceDetected {
            binary: "game_logic.dll".into(),
            function: "DrawPrimitive".into(),
            attempt: 2,
            retry_strategy: "decompose".into(),
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
            retry_strategy: "direct".into(),
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
            retry_strategy: "direct".into(),
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
            build_router_with_actions(
                state,
                ActionsState::new(fixture.repo_path(), PipelineSpec::default()),
            )
        };
        let _server = spawn_server(router, fixture.port()).await;

        tokio::time::sleep(Duration::from_millis(200)).await;

        for path in [
            "/api/progress",
            "/api/progress/enhanced",
            "/api/events/upgrade",
            // Issue #96: the override GET is live-only too — a GET on an
            // unrouted path falls through to the static 404.
            "/api/units/game_logic.dll%2FDrawPrimitive%2Fv1/override",
            // Issue #97: the classification GET is live-only too.
            "/api/binaries/fmod.dll/classification",
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
            // Issue #92: start/restart are live-only too.
            "/api/pipeline/start",
            "/api/pipeline/restart",
            // Issue #93: the scope control endpoints are live-only too.
            "/api/scope",
            "/api/scope/binaries",
            "/api/scope/skip-function",
            "/api/scope/priority-function",
            "/api/scope/remove-priority-function",
            "/api/scope/constraints",
            // Issue #96: the per-unit override endpoints are live-only too.
            "/api/units/game_logic.dll%2FDrawPrimitive%2Fv1/override",
            // Issue #97: the classification override endpoints are live-only too.
            "/api/binaries/fmod.dll/classification",
            // Issue #221: the per-binary pause endpoints are live-only too.
            "/api/pipeline/binaries/game_logic.dll/pause",
            "/api/pipeline/binaries/game_logic.dll/resume",
            // Issue #284: the focus endpoint too.
            "/api/pipeline/binaries/game_logic.dll/focus",
            // Issue #285: and the start endpoint — a plain serve/actions
            // router has no run to swap onto a binary.
            "/api/pipeline/binaries/game_logic.dll/start",
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
            build_router_with_actions(
                state,
                ActionsState::new(fixture.repo_path(), PipelineSpec::default()),
            )
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
    let router = build_router_with_ws(state, manager, progress, ws_actions(&fixture));
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    // A non-LLM event must not touch the log.
    events.emit(ProgressEvent::LlmCallStart {
        binary: "game_logic.dll".into(),
        function: "DrawPrimitive".into(),
        attempt: 1,
        retry_strategy: "direct".into(),
    });
    events.emit(ProgressEvent::LlmRequest {
        binary: "game_logic.dll".into(),
        function: "DrawPrimitive".into(),
        attempt: 1,
        retry_strategy: "direct".into(),
        prompt: "translate DrawPrimitive".into(),
    });
    events.emit(ProgressEvent::LlmResponse {
        binary: "game_logic.dll".into(),
        function: "DrawPrimitive".into(),
        attempt: 1,
        retry_strategy: "direct".into(),
        content: "fn draw_primitive() {}".into(),
        tokens_used: Some(4321),
    });
    events.emit(ProgressEvent::LlmCallFailed {
        binary: "game_logic.dll".into(),
        function: "UpdateScene".into(),
        attempt: 2,
        retry_strategy: "retry".into(),
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
    assert_eq!(request["retry_strategy"], "direct");
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
    assert_eq!(failure["retry_strategy"], "retry");
    assert_eq!(failure["content"], "connection reset");
}

/// The web view's Clear button must clear the persisted log, not just the
/// browser buffer: `POST /api/llm-io/clear` empties the file so the next
/// `GET /api/llm-io` honestly answers empty again instead of restoring the
/// history on reload.
#[tokio::test]
async fn test_llm_io_clear_empties_the_persisted_log() {
    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    // Seed the persisted log the way a live run would.
    let log = LlmIoLog::new(fixture.repo_path());
    log.record(&ProgressEvent::LlmRequest {
        binary: "game_logic.dll".into(),
        function: "DrawPrimitive".into(),
        attempt: 1,
        retry_strategy: "direct".into(),
        prompt: "translate DrawPrimitive".into(),
    });
    log.record(&ProgressEvent::LlmResponse {
        binary: "game_logic.dll".into(),
        function: "DrawPrimitive".into(),
        attempt: 1,
        retry_strategy: "direct".into(),
        content: "fn draw_primitive() {}".into(),
        tokens_used: Some(4321),
    });

    let resp = reqwest::get(format!("http://127.0.0.1:{}/api/llm-io", fixture.port()))
        .await
        .expect("request reaches server");
    let body: serde_json::Value = resp.json().await.expect("body is JSON");
    assert_eq!(body["entries"].as_array().expect("entries array").len(), 2);

    let resp = reqwest::Client::new()
        .post(format!(
            "http://127.0.0.1:{}/api/llm-io/clear",
            fixture.port()
        ))
        .send()
        .await
        .expect("clear request reaches server");
    assert_eq!(resp.status(), 200, "clear succeeds on the shared router");
    let body: serde_json::Value = resp.json().await.expect("body is JSON");
    assert_eq!(body["dropped"].as_u64().expect("dropped count"), 2);

    // The file is gone, and the reload payload is honestly empty.
    let log_path = fixture
        .repo_path()
        .join("re")
        .join("analysis")
        .join("llm_io")
        .join("log.jsonl");
    assert!(!log_path.exists(), "the persisted log file is deleted");

    let resp = reqwest::get(format!("http://127.0.0.1:{}/api/llm-io", fixture.port()))
        .await
        .expect("request reaches server");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("body is JSON");
    assert_eq!(
        body["entries"].as_array().expect("entries array").len(),
        0,
        "a reload after clear restores nothing"
    );
}

// ─────────────────────────────────────────────────────────────
// Fault analytics (issue #125, W3.1)
// ─────────────────────────────────────────────────────────────

/// UTC day boundaries the fault fixtures bucket against: 2026-10-01 through
/// 2026-10-04, midnight. The trend endpoint buckets on these exact days.
const FAULT_DAY_1: u64 = 1_790_812_800; // 2026-10-01T00:00:00Z
const FAULT_DAY_4: u64 = 1_791_072_000; // 2026-10-04T00:00:00Z

/// One fault-log entry with every field spelled out — the fixture's exact
/// values are what the endpoint assertions pin.
fn fault_entry(
    binary: &str,
    function: &str,
    attempt: u32,
    strategy: &str,
    category: &str,
    severity: &str,
    timestamp: u64,
) -> serde_json::Value {
    serde_json::json!({
        "binary": binary,
        "function": function,
        "attempt": attempt,
        "strategy": strategy,
        "category": category,
        "severity": severity,
        "description": format!("{category} detected in {function}"),
        "recovery": format!("recovery guidance for {function}"),
        "timestamp": timestamp,
    })
}

/// Writes a deterministic fault log fixture into the repo's analysis
/// directory — the file the analytics endpoints read on demand.
fn write_fault_log_fixture(repo_path: &std::path::Path, entries: &[serde_json::Value]) {
    let dir = repo_path.join("re").join("analysis");
    std::fs::create_dir_all(&dir).expect("analysis dir exists");
    std::fs::write(
        dir.join("fault_log.json"),
        serde_json::to_string(&serde_json::json!({ "entries": entries }))
            .expect("fixture serializes"),
    )
    .expect("fixture written");
}

/// The six-entry fixture both analytics tests share: three faults for
/// `game_logic.dll/DrawSprite` on 2026-10-01 and three for
/// `d3d9.dll/UpdateScene` on 2026-10-04 — leaving 10-02 and 10-03 as gap
/// days the trend must fill with honest zeros.
fn sample_fault_entries() -> Vec<serde_json::Value> {
    vec![
        fault_entry(
            "game_logic.dll",
            "DrawSprite",
            1,
            "initial",
            "context_window_exceeded",
            "error",
            FAULT_DAY_1 + 60,
        ),
        fault_entry(
            "game_logic.dll",
            "DrawSprite",
            2,
            "compile_fix",
            "hallucination",
            "error",
            FAULT_DAY_1 + 120,
        ),
        fault_entry(
            "game_logic.dll",
            "DrawSprite",
            3,
            "retry",
            "resource_exhaustion",
            "warning",
            FAULT_DAY_1 + 180,
        ),
        fault_entry(
            "d3d9.dll",
            "UpdateScene",
            1,
            "initial",
            "infinite_loop",
            "critical",
            FAULT_DAY_4 + 60,
        ),
        fault_entry(
            "d3d9.dll",
            "UpdateScene",
            2,
            "compile_fix",
            "hallucination",
            "error",
            FAULT_DAY_4 + 120,
        ),
        fault_entry(
            "d3d9.dll",
            "UpdateScene",
            3,
            "retry",
            "slow_response",
            "warning",
            FAULT_DAY_4 + 180,
        ),
    ]
}

/// GETs a URL and returns the status with the parsed body.
async fn get_json(url: &str) -> (reqwest::StatusCode, serde_json::Value) {
    let resp = reqwest::get(url).await.expect("request reaches server");
    let status = resp.status();
    let body = resp.json().await.unwrap_or(serde_json::Value::Null);
    (status, body)
}

/// Issue #125 router contract: every faults analytics endpoint is
/// registered in the shared routes — they read the persisted fault log,
/// never live pipeline state — so both the plain and the live router
/// answer them. With no log on disk they serve honest empty payloads,
/// not 404s and not fabricated zeros.
#[tokio::test]
async fn test_faults_analytics_registered_in_plain_and_live_routers() {
    for kind in ["plain", "live"] {
        let fixture = TestFixture::new();
        let state = ServerState::new(fixture.repo_path());
        let router = if kind == "plain" {
            build_router(state)
        } else {
            let events = TranslationEvents::new(128);
            let manager = SessionManager::new_with_broadcast(events.subscribe());
            build_router_with_ws(state, manager, ProgressState::new(), ws_actions(&fixture))
        };
        let _server = spawn_server(router, fixture.port()).await;

        tokio::time::sleep(Duration::from_millis(200)).await;

        let base = format!("http://127.0.0.1:{}", fixture.port());
        let (status, body) = get_json(&format!("{base}/api/faults")).await;
        assert_eq!(status, 200, "{kind} router serves /api/faults");
        assert_eq!(body["entries"].as_array().expect("entries array").len(), 0);
        assert_eq!(body["total_in_log"].as_u64().expect("total_in_log"), 0);

        let (status, body) = get_json(&format!("{base}/api/faults/summary")).await;
        assert_eq!(status, 200, "{kind} router serves /api/faults/summary");
        assert_eq!(body["total"].as_u64().expect("total"), 0);
        assert_eq!(
            body["by_category"]
                .as_array()
                .expect("by_category array")
                .len(),
            0
        );
        // Severity is a closed vocabulary — always all three cards.
        assert_eq!(
            body["by_severity"]
                .as_array()
                .expect("by_severity array")
                .len(),
            3
        );

        let (status, body) = get_json(&format!("{base}/api/faults/by-binary")).await;
        assert_eq!(status, 200, "{kind} router serves /api/faults/by-binary");
        assert_eq!(
            body["binaries"].as_array().expect("binaries array").len(),
            0
        );

        let (status, body) = get_json(&format!("{base}/api/faults/trend")).await;
        assert_eq!(status, 200, "{kind} router serves /api/faults/trend");
        assert_eq!(body["days"].as_array().expect("days array").len(), 0);
    }
}

/// Issue #125 exact-JSON contract: against a deterministic fixture log,
/// each endpoint answers with exactly the counts, breakdowns, and trend
/// buckets the fixture implies — fields verbatim, ordering as documented.
#[tokio::test]
async fn test_faults_api_exact_json_from_fixture_log() {
    let fixture = TestFixture::new();
    write_fault_log_fixture(&fixture.repo_path(), &sample_fault_entries());
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let base = format!("http://127.0.0.1:{}", fixture.port());

    // The fault list: every entry verbatim, oldest first, with the full
    // attempt identity triple and the attached recovery guidance.
    let (status, body) = get_json(&format!("{base}/api/faults")).await;
    assert_eq!(status, 200);
    assert_eq!(body["total_in_log"].as_u64().expect("total_in_log"), 6);
    assert_eq!(
        body["entries"],
        serde_json::Value::Array(sample_fault_entries()),
        "the whole list is served verbatim, oldest first, with the full identity triple"
    );

    // Summary cards: exact counts by category (highest first, ties
    // alphabetical) and by severity (fixed warning → error → critical).
    let (status, body) = get_json(&format!("{base}/api/faults/summary")).await;
    assert_eq!(status, 200);
    assert_eq!(body["total"].as_u64().expect("total"), 6);
    assert_eq!(
        body["by_category"],
        serde_json::json!([
            {"name": "hallucination", "count": 2},
            {"name": "context_window_exceeded", "count": 1},
            {"name": "infinite_loop", "count": 1},
            {"name": "resource_exhaustion", "count": 1},
            {"name": "slow_response", "count": 1},
        ])
    );
    assert_eq!(
        body["by_severity"],
        serde_json::json!([
            {"name": "warning", "count": 2},
            {"name": "error", "count": 3},
            {"name": "critical", "count": 1},
        ])
    );

    // Per-binary bars: exact counts, highest first, ties alphabetical.
    let (status, body) = get_json(&format!("{base}/api/faults/by-binary")).await;
    assert_eq!(status, 200);
    assert_eq!(
        body["binaries"],
        serde_json::json!([
            {"binary": "d3d9.dll", "count": 3},
            {"binary": "game_logic.dll", "count": 3},
        ])
    );

    // Trend: contiguous UTC day buckets from the first to the last fault
    // day — gap days 10-02 and 10-03 carry honest zeros — plus the 3-day
    // trailing moving average clipped to the bucketed range.
    let (status, body) = get_json(&format!("{base}/api/faults/trend")).await;
    assert_eq!(status, 200);
    assert_eq!(
        body["days"],
        serde_json::json!([
            {"date": "2026-10-01", "count": 3, "moving_average": 3.0},
            {"date": "2026-10-02", "count": 0, "moving_average": 1.5},
            {"date": "2026-10-03", "count": 0, "moving_average": 1.0},
            {"date": "2026-10-04", "count": 3, "moving_average": 1.0},
        ]),
        "per-day buckets and the 3-day moving average match the fixture exactly"
    );
}

/// Issue #125 filter contract: category, binary, and the inclusive
/// `from`/`to` UTC date range narrow every endpoint — the cards, bars,
/// trend, and table always describe the same filtered set — while
/// `total_in_log` keeps reporting the unfiltered log size.
#[tokio::test]
async fn test_faults_api_filters_narrow_every_endpoint() {
    let fixture = TestFixture::new();
    write_fault_log_fixture(&fixture.repo_path(), &sample_fault_entries());
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let base = format!("http://127.0.0.1:{}", fixture.port());

    // Category filter: only the two hallucination faults survive.
    let (status, body) = get_json(&format!("{base}/api/faults?category=hallucination")).await;
    assert_eq!(status, 200);
    let entries = body["entries"].as_array().expect("entries array");
    assert_eq!(
        entries.len(),
        2,
        "category filter leaves the two hallucinations"
    );
    assert!(
        entries
            .iter()
            .all(|e| e["category"] == "hallucination" && e["severity"] == "error")
    );
    assert_eq!(
        body["total_in_log"].as_u64().expect("total_in_log"),
        6,
        "the log's own size survives filtering"
    );
    let (status, body) =
        get_json(&format!("{base}/api/faults/summary?category=hallucination")).await;
    assert_eq!(status, 200);
    assert_eq!(body["total"].as_u64().expect("total"), 2);
    assert_eq!(
        body["by_category"],
        serde_json::json!([{"name": "hallucination", "count": 2}])
    );
    let (status, body) = get_json(&format!("{base}/api/faults/trend?category=hallucination")).await;
    assert_eq!(status, 200);
    assert_eq!(
        body["days"],
        serde_json::json!([
            {"date": "2026-10-01", "count": 1, "moving_average": 1.0},
            {"date": "2026-10-02", "count": 0, "moving_average": 0.5},
            {"date": "2026-10-03", "count": 0, "moving_average": 0.3333333333333333},
            {"date": "2026-10-04", "count": 1, "moving_average": 0.3333333333333333},
        ]),
        "the trend buckets the filtered set the same way"
    );

    // Binary filter: only the d3d9.dll faults.
    let (status, body) = get_json(&format!("{base}/api/faults?binary=d3d9.dll")).await;
    assert_eq!(status, 200);
    let entries = body["entries"].as_array().expect("entries array");
    assert_eq!(entries.len(), 3);
    assert!(
        entries
            .iter()
            .all(|e| e["binary"] == "d3d9.dll" && e["function"] == "UpdateScene")
    );
    let (status, body) = get_json(&format!("{base}/api/faults/by-binary?binary=d3d9.dll")).await;
    assert_eq!(status, 200);
    assert_eq!(
        body["binaries"],
        serde_json::json!([{"binary": "d3d9.dll", "count": 3}])
    );
    let (status, body) = get_json(&format!("{base}/api/faults?binary=D3D9.DLL")).await;
    assert_eq!(status, 200);
    assert_eq!(
        body["entries"].as_array().expect("entries array").len(),
        3,
        "the binary filter matches case-insensitively, like every other binary comparison"
    );

    // Date range: inclusive on both ends, compared on UTC days. The gap
    // days alone match nothing — the trend then honestly answers empty.
    let (status, body) =
        get_json(&format!("{base}/api/faults?from=2026-10-02&to=2026-10-03")).await;
    assert_eq!(status, 200);
    assert_eq!(
        body["entries"].as_array().expect("entries array").len(),
        0,
        "the gap days hold no faults"
    );
    let (status, body) = get_json(&format!(
        "{base}/api/faults/trend?from=2026-10-02&to=2026-10-03"
    ))
    .await;
    assert_eq!(status, 200);
    assert_eq!(
        body["days"].as_array().expect("days array").len(),
        0,
        "no matching faults means no fabricated zero run"
    );

    // `from` alone keeps everything from that day on.
    let (status, body) = get_json(&format!("{base}/api/faults?from=2026-10-04")).await;
    assert_eq!(status, 200);
    assert_eq!(
        body["entries"].as_array().expect("entries array").len(),
        3,
        "the inclusive from bound keeps the 10-04 faults"
    );
}

/// Issue #125 filter honesty: a malformed filter value is refused with 400
/// naming the accepted shape — an operator who typed a filter is never
/// silently shown unfiltered data.
#[tokio::test]
async fn test_faults_api_bad_filter_answers_400() {
    let fixture = TestFixture::new();
    write_fault_log_fixture(&fixture.repo_path(), &sample_fault_entries());
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let base = format!("http://127.0.0.1:{}", fixture.port());

    let (status, body) = get_json(&format!("{base}/api/faults?category=nonsense")).await;
    assert_eq!(status, 400, "an unknown category is refused, not ignored");
    let message = body["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("nonsense") && message.contains("hallucination"),
        "the 400 names the bad value and the vocabulary, got: {message}"
    );

    let (status, _) = get_json(&format!("{base}/api/faults/summary?from=not-a-date")).await;
    assert_eq!(status, 400, "a malformed from date is refused");

    let (status, _) = get_json(&format!("{base}/api/faults/trend?to=2026-13-01")).await;
    assert_eq!(status, 400, "an out-of-range to date is refused");
}

/// Issue #125 honest degradation: a corrupt fault log loads as empty — the
/// analytics endpoints answer 200 with empty payloads, and the view's
/// empty state (driven by `total_in_log` and `total`) never renders a
/// wall of zeros for a log it cannot read.
#[tokio::test]
async fn test_faults_api_corrupt_log_honest_empty() {
    let fixture = TestFixture::new();
    let dir = fixture.repo_path().join("re").join("analysis");
    std::fs::create_dir_all(&dir).expect("analysis dir exists");
    std::fs::write(dir.join("fault_log.json"), "{ not json").expect("corrupt log written");
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let base = format!("http://127.0.0.1:{}", fixture.port());

    let (status, body) = get_json(&format!("{base}/api/faults")).await;
    assert_eq!(status, 200, "a corrupt log degrades, never errors");
    assert_eq!(body["entries"].as_array().expect("entries array").len(), 0);
    assert_eq!(body["total_in_log"].as_u64().expect("total_in_log"), 0);

    let (status, body) = get_json(&format!("{base}/api/faults/summary")).await;
    assert_eq!(status, 200);
    assert_eq!(body["total"].as_u64().expect("total"), 0);
    assert_eq!(
        body["by_category"].as_array().expect("by_category").len(),
        0
    );

    let (status, body) = get_json(&format!("{base}/api/faults/trend")).await;
    assert_eq!(status, 200);
    assert_eq!(body["days"].as_array().expect("days array").len(), 0);
}

// ─────────────────────────────────────────────────────────────
// Token usage analytics (issue #126, W3.2)
// ─────────────────────────────────────────────────────────────

/// One token-usage entry with every field spelled out — the fixture's
/// exact values are what the endpoint assertions pin. An empty tier omits
/// `context_tier` entirely, the shape entries written before tier tracking
/// (and by older versions) carry on disk.
// One parameter per fixture field — the whole point is spelling every
// field out, so folding them into a struct would only hide the values.
#[allow(clippy::too_many_arguments)]
fn token_usage_entry(
    binary: &str,
    function: &str,
    attempt: u32,
    strategy: &str,
    tokens: usize,
    success: bool,
    tier: &str,
    timestamp: u64,
) -> serde_json::Value {
    let mut entry = serde_json::json!({
        "binary": binary,
        "function": function,
        "attempt": attempt,
        "strategy": strategy,
        "tokens_used": tokens,
        "success": success,
        "timestamp": timestamp,
    });
    if !tier.is_empty() {
        entry["context_tier"] = serde_json::Value::String(tier.into());
    }
    entry
}

/// Writes a deterministic token usage log fixture into the repo's analysis
/// directory — the file the analytics endpoints read on demand.
fn write_token_usage_fixture(repo_path: &std::path::Path, entries: &[serde_json::Value]) {
    let dir = repo_path.join("re").join("analysis");
    std::fs::create_dir_all(&dir).expect("analysis dir exists");
    std::fs::write(
        dir.join("token_usage.json"),
        serde_json::to_string(&serde_json::json!({ "entries": entries }))
            .expect("fixture serializes"),
    )
    .expect("fixture written");
}

/// The five-entry fixture the exact-JSON tests share: three attempts on
/// `game_logic.dll/DrawSprite` on 2026-10-01 and two on
/// `d3d9.dll/UpdateScene` on 2026-10-04. Token totals divide exactly
/// (15000/5000 of 20000) so percentage shares pin as clean floats, and the
/// 3000-token ties in the tier and strategy breakdowns pin the alphabetical
/// tie rule.
fn sample_token_usage_entries() -> Vec<serde_json::Value> {
    vec![
        token_usage_entry(
            "game_logic.dll",
            "DrawSprite",
            1,
            "initial",
            4000,
            false,
            "stub",
            FAULT_DAY_1 + 60,
        ),
        token_usage_entry(
            "game_logic.dll",
            "DrawSprite",
            2,
            "compile_fix",
            3000,
            true,
            "disassembly",
            FAULT_DAY_1 + 120,
        ),
        token_usage_entry(
            "game_logic.dll",
            "DrawSprite",
            3,
            "escalate",
            8000,
            false,
            "module_context",
            FAULT_DAY_1 + 180,
        ),
        token_usage_entry(
            "d3d9.dll",
            "UpdateScene",
            1,
            "initial",
            2000,
            true,
            "stub",
            FAULT_DAY_4 + 60,
        ),
        token_usage_entry(
            "d3d9.dll",
            "UpdateScene",
            2,
            "retry",
            3000,
            false,
            "",
            FAULT_DAY_4 + 120,
        ),
    ]
}

/// Issue #126 router contract: every token-usage analytics endpoint is
/// registered in the shared routes — they read the persisted token usage
/// log, never live pipeline state — so both the plain and the live router
/// answer them. With no log on disk they serve honest empty payloads.
#[tokio::test]
async fn test_token_usage_analytics_registered_in_plain_and_live_routers() {
    for kind in ["plain", "live"] {
        let fixture = TestFixture::new();
        let state = ServerState::new(fixture.repo_path());
        let router = if kind == "plain" {
            build_router(state)
        } else {
            let events = TranslationEvents::new(128);
            let manager = SessionManager::new_with_broadcast(events.subscribe());
            build_router_with_ws(state, manager, ProgressState::new(), ws_actions(&fixture))
        };
        let _server = spawn_server(router, fixture.port()).await;

        tokio::time::sleep(Duration::from_millis(200)).await;

        let base = format!("http://127.0.0.1:{}", fixture.port());

        let (status, body) = get_json(&format!("{base}/api/token-usage/summary")).await;
        assert_eq!(status, 200, "{kind} router serves /api/token-usage/summary");
        assert_eq!(
            body["total_tokens"].as_u64().expect("total_tokens"),
            0,
            "{kind} router reports zero tokens with no log"
        );
        assert_eq!(
            body["total_in_log"].as_u64().expect("total_in_log"),
            0,
            "{kind} router reports an empty log with no log"
        );

        for path in [
            "/api/token-usage/by-binary",
            "/api/token-usage/by-tier",
            "/api/token-usage/by-strategy",
        ] {
            let (status, _) = get_json(&format!("{base}{path}")).await;
            assert_eq!(status, 200, "{kind} router serves {path}");
        }

        let (_, body) = get_json(&format!("{base}/api/token-usage/by-binary")).await;
        assert!(
            body["binaries"]
                .as_array()
                .expect("binaries array")
                .is_empty(),
            "no log means no fabricated bars"
        );
        let (_, body) = get_json(&format!("{base}/api/token-usage/by-tier")).await;
        assert!(
            body["tiers"].as_array().expect("tiers array").is_empty(),
            "no log means no fabricated tiers"
        );
        let (_, body) = get_json(&format!("{base}/api/token-usage/by-strategy")).await;
        assert!(
            body["strategies"]
                .as_array()
                .expect("strategies array")
                .is_empty(),
            "no log means no fabricated strategies"
        );
    }
}

/// Issue #126 exact-JSON contract: against a deterministic fixture log,
/// each endpoint answers with exactly the totals, percentage shares, and
/// per-strategy success rates the fixture implies — ordering highest first,
/// ties alphabetical.
#[tokio::test]
async fn test_token_usage_api_exact_json_from_fixture_log() {
    let fixture = TestFixture::new();
    write_token_usage_fixture(&fixture.repo_path(), &sample_token_usage_entries());
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let base = format!("http://127.0.0.1:{}", fixture.port());

    // Summary split: total tokens consumed, split into successful and
    // failed attempts, plus the log's own size for the honest empty state.
    let (status, body) = get_json(&format!("{base}/api/token-usage/summary")).await;
    assert_eq!(status, 200);
    assert_eq!(
        body,
        serde_json::json!({
            "total_tokens": 20_000,
            "successful_tokens": 5_000,
            "failed_tokens": 15_000,
            "total_attempts": 5,
            "total_in_log": 5,
        })
    );

    // Per-binary breakdown with percentage shares of the filtered total.
    let (status, body) = get_json(&format!("{base}/api/token-usage/by-binary")).await;
    assert_eq!(status, 200);
    assert_eq!(
        body["binaries"],
        serde_json::json!([
            {"binary": "game_logic.dll", "tokens": 15_000, "share_percent": 75.0},
            {"binary": "d3d9.dll", "tokens": 5_000, "share_percent": 25.0},
        ])
    );

    // Per-tier breakdown — the untracked (no `context_tier`) entries form
    // their own honest bucket; the 3000-token tie sorts alphabetically.
    let (status, body) = get_json(&format!("{base}/api/token-usage/by-tier")).await;
    assert_eq!(status, 200);
    assert_eq!(
        body["tiers"],
        serde_json::json!([
            {"tier": "module_context", "tokens": 8_000, "attempts": 1},
            {"tier": "stub", "tokens": 6_000, "attempts": 2},
            {"tier": "", "tokens": 3_000, "attempts": 1},
            {"tier": "disassembly", "tokens": 3_000, "attempts": 1},
        ])
    );

    // Per-strategy breakdown with a success rate per strategy — the 3000-
    // token tie between compile_fix and retry sorts alphabetically.
    let (status, body) = get_json(&format!("{base}/api/token-usage/by-strategy")).await;
    assert_eq!(status, 200);
    assert_eq!(
        body["strategies"],
        serde_json::json!([
            {"strategy": "escalate", "tokens": 8_000, "attempts": 1, "successes": 0, "success_rate": 0.0},
            {"strategy": "initial", "tokens": 6_000, "attempts": 2, "successes": 1, "success_rate": 50.0},
            {"strategy": "compile_fix", "tokens": 3_000, "attempts": 1, "successes": 1, "success_rate": 100.0},
            {"strategy": "retry", "tokens": 3_000, "attempts": 1, "successes": 0, "success_rate": 0.0},
        ])
    );
}

/// Issue #126 time-range contract: the `from`/`to` inclusive UTC date range
/// narrows every endpoint the same way — summary, bars, tiers, and strategy
/// rows always describe the same filtered set — while `total_in_log` keeps
/// reporting the unfiltered log size. A malformed date is refused with 400.
#[tokio::test]
async fn test_token_usage_api_time_range_narrows_every_endpoint() {
    let fixture = TestFixture::new();
    write_token_usage_fixture(&fixture.repo_path(), &sample_token_usage_entries());
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let base = format!("http://127.0.0.1:{}", fixture.port());

    // `from` alone keeps everything from that UTC day on: only the two
    // 2026-10-04 d3d9.dll attempts survive.
    let (status, body) = get_json(&format!("{base}/api/token-usage/summary?from=2026-10-04")).await;
    assert_eq!(status, 200);
    assert_eq!(
        body,
        serde_json::json!({
            "total_tokens": 5_000,
            "successful_tokens": 2_000,
            "failed_tokens": 3_000,
            "total_attempts": 2,
            "total_in_log": 5,
        })
    );
    let (status, body) =
        get_json(&format!("{base}/api/token-usage/by-binary?from=2026-10-04")).await;
    assert_eq!(status, 200);
    assert_eq!(
        body["binaries"],
        serde_json::json!([
            {"binary": "d3d9.dll", "tokens": 5_000, "share_percent": 100.0},
        ]),
        "the share is of the filtered total, not the whole log"
    );
    let (status, body) = get_json(&format!("{base}/api/token-usage/by-tier?from=2026-10-04")).await;
    assert_eq!(status, 200);
    assert_eq!(
        body["tiers"],
        serde_json::json!([
            {"tier": "", "tokens": 3_000, "attempts": 1},
            {"tier": "stub", "tokens": 2_000, "attempts": 1},
        ])
    );
    let (status, body) = get_json(&format!(
        "{base}/api/token-usage/by-strategy?from=2026-10-04"
    ))
    .await;
    assert_eq!(status, 200);
    assert_eq!(
        body["strategies"],
        serde_json::json!([
            {"strategy": "retry", "tokens": 3_000, "attempts": 1, "successes": 0, "success_rate": 0.0},
            {"strategy": "initial", "tokens": 2_000, "attempts": 1, "successes": 1, "success_rate": 100.0},
        ])
    );

    // An inclusive range holding no attempts answers with zeros and empty
    // breakdowns — never a fabricated row of buckets.
    let (status, body) = get_json(&format!(
        "{base}/api/token-usage/summary?from=2026-10-02&to=2026-10-03"
    ))
    .await;
    assert_eq!(status, 200);
    assert_eq!(body["total_tokens"].as_u64().expect("total_tokens"), 0);
    assert_eq!(
        body["total_in_log"].as_u64().expect("total_in_log"),
        5,
        "the log's own size survives filtering"
    );
    let (_, body) = get_json(&format!(
        "{base}/api/token-usage/by-binary?from=2026-10-02&to=2026-10-03"
    ))
    .await;
    assert!(
        body["binaries"]
            .as_array()
            .expect("binaries array")
            .is_empty(),
        "no matching attempts means no bars"
    );

    // Malformed dates are refused with 400 naming the accepted shape —
    // an operator who typed a filter is never silently shown everything.
    let (status, body) = get_json(&format!("{base}/api/token-usage/summary?from=not-a-date")).await;
    assert_eq!(status, 400, "a malformed from date is refused");
    let message = body["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("not-a-date") && message.contains("YYYY-MM-DD"),
        "the 400 names the bad value and the accepted shape, got: {message}"
    );

    let (status, _) = get_json(&format!("{base}/api/token-usage/by-strategy?to=2026-13-01")).await;
    assert_eq!(status, 400, "an out-of-range to date is refused");
}

/// Issue #126 honest degradation: a corrupt token usage log loads as empty —
/// the endpoints answer 200 with empty payloads so the view's empty state
/// (driven by `total_in_log`) never renders a wall of zeros for a log it
/// cannot read.
#[tokio::test]
async fn test_token_usage_api_corrupt_log_honest_empty() {
    let fixture = TestFixture::new();
    let dir = fixture.repo_path().join("re").join("analysis");
    std::fs::create_dir_all(&dir).expect("analysis dir exists");
    std::fs::write(dir.join("token_usage.json"), "{ not json").expect("corrupt log written");
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let base = format!("http://127.0.0.1:{}", fixture.port());

    let (status, body) = get_json(&format!("{base}/api/token-usage/summary")).await;
    assert_eq!(status, 200, "a corrupt log degrades, never errors");
    assert_eq!(body["total_tokens"].as_u64().expect("total_tokens"), 0);
    assert_eq!(body["total_in_log"].as_u64().expect("total_in_log"), 0);

    let (status, body) = get_json(&format!("{base}/api/token-usage/by-binary")).await;
    assert_eq!(status, 200);
    assert!(
        body["binaries"]
            .as_array()
            .expect("binaries array")
            .is_empty(),
        "a corrupt log means no bars, not zero bars"
    );
}

// ─────────────────────────────────────────────────────────────
// Strategy analytics (issue #127, W3.3)
// ─────────────────────────────────────────────────────────────

/// One prompt-strategy entry with every field spelled out — the fixture's
/// exact values are what the endpoint assertions pin.
fn strategy_entry(
    binary: &str,
    dll_category: &str,
    strategy: &str,
    success: bool,
    attempt: u32,
    timestamp: u64,
) -> serde_json::Value {
    serde_json::json!({
        "binary": binary,
        "dll_category": dll_category,
        "retry_strategy": strategy,
        "success": success,
        "attempt": attempt,
        "timestamp": timestamp,
    })
}

/// Writes a deterministic prompt-strategy log fixture into the repo's
/// analysis directory — the file the analytics endpoints read on demand.
fn write_strategy_fixture(repo_path: &std::path::Path, entries: &[serde_json::Value]) {
    let dir = repo_path.join("re").join("analysis");
    std::fs::create_dir_all(&dir).expect("analysis dir exists");
    std::fs::write(
        dir.join("prompt_strategy_log.json"),
        serde_json::to_string(&serde_json::json!({ "entries": entries }))
            .expect("fixture serializes"),
    )
    .expect("fixture written");
}

/// The six-entry fixture the exact-JSON tests share: four attempts on
/// `game_logic.dll/DrawSprite` (ProjectSpecific) on 2026-10-01 and two on
/// `d3d9.dll/UpdateScene` (KnownThirdParty) on 2026-10-04. Success counts
/// divide exactly (2/4 and 1/2) so pass rates pin as clean floats, and
/// `initial`/`retry` tie at two attempts to pin the alphabetical tie rule.
fn sample_strategy_entries() -> Vec<serde_json::Value> {
    vec![
        strategy_entry(
            "game_logic.dll",
            "ProjectSpecific",
            "initial",
            false,
            1,
            FAULT_DAY_1 + 60,
        ),
        strategy_entry(
            "game_logic.dll",
            "ProjectSpecific",
            "compile_fix",
            true,
            2,
            FAULT_DAY_1 + 120,
        ),
        strategy_entry(
            "game_logic.dll",
            "ProjectSpecific",
            "escalate",
            false,
            3,
            FAULT_DAY_1 + 180,
        ),
        strategy_entry(
            "game_logic.dll",
            "ProjectSpecific",
            "retry",
            true,
            4,
            FAULT_DAY_1 + 240,
        ),
        strategy_entry(
            "d3d9.dll",
            "KnownThirdParty",
            "initial",
            true,
            1,
            FAULT_DAY_4 + 60,
        ),
        strategy_entry(
            "d3d9.dll",
            "KnownThirdParty",
            "retry",
            false,
            2,
            FAULT_DAY_4 + 120,
        ),
    ]
}

/// Issue #127 router contract: both strategy-analytics endpoints are
/// registered in the shared routes — they read the persisted prompt-
/// strategy log, never live pipeline state — so both the plain and the
/// live router answer them. With no log on disk they serve honest empty
/// payloads.
#[tokio::test]
async fn test_strategy_analytics_registered_in_plain_and_live_routers() {
    for kind in ["plain", "live"] {
        let fixture = TestFixture::new();
        let state = ServerState::new(fixture.repo_path());
        let router = if kind == "plain" {
            build_router(state)
        } else {
            let events = TranslationEvents::new(128);
            let manager = SessionManager::new_with_broadcast(events.subscribe());
            build_router_with_ws(state, manager, ProgressState::new(), ws_actions(&fixture))
        };
        let _server = spawn_server(router, fixture.port()).await;

        tokio::time::sleep(Duration::from_millis(200)).await;

        let base = format!("http://127.0.0.1:{}", fixture.port());

        for path in [
            "/api/strategy-analytics/by-strategy",
            "/api/strategy-analytics/by-category",
        ] {
            let (status, body) = get_json(&format!("{base}{path}")).await;
            assert_eq!(status, 200, "{kind} router serves {path}");
            assert_eq!(
                body["total_in_log"].as_u64().expect("total_in_log"),
                0,
                "{kind} router reports an empty log with no log"
            );
        }

        let (_, body) = get_json(&format!("{base}/api/strategy-analytics/by-strategy")).await;
        assert!(
            body["strategies"]
                .as_array()
                .expect("strategies array")
                .is_empty(),
            "no log means no fabricated strategies"
        );
        let (_, body) = get_json(&format!("{base}/api/strategy-analytics/by-category")).await;
        assert!(
            body["categories"]
                .as_array()
                .expect("categories array")
                .is_empty(),
            "no log means no fabricated categories"
        );
    }
}

/// Issue #127 exact-JSON contract: against a deterministic fixture log,
/// each endpoint answers with exactly the attempt, success, failure, and
/// pass-rate numbers the fixture implies — most attempts first, ties
/// alphabetical.
#[tokio::test]
async fn test_strategy_analytics_api_exact_json_from_fixture_log() {
    let fixture = TestFixture::new();
    write_strategy_fixture(&fixture.repo_path(), &sample_strategy_entries());
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let base = format!("http://127.0.0.1:{}", fixture.port());

    // Per-strategy breakdown — the initial/retry tie at two attempts
    // sorts alphabetically ahead of the single-attempt strategies.
    let (status, body) = get_json(&format!("{base}/api/strategy-analytics/by-strategy")).await;
    assert_eq!(status, 200);
    assert_eq!(
        body,
        serde_json::json!({
            "strategies": [
                {"strategy": "initial", "attempts": 2, "successes": 1, "failures": 1, "pass_rate": 50.0},
                {"strategy": "retry", "attempts": 2, "successes": 1, "failures": 1, "pass_rate": 50.0},
                {"strategy": "compile_fix", "attempts": 1, "successes": 1, "failures": 0, "pass_rate": 100.0},
                {"strategy": "escalate", "attempts": 1, "successes": 0, "failures": 1, "pass_rate": 0.0},
            ],
            "total_in_log": 6,
        })
    );

    // Per-category breakdown — ProjectSpecific (4 attempts) before
    // KnownThirdParty (2), pass rates as percentages.
    let (status, body) = get_json(&format!("{base}/api/strategy-analytics/by-category")).await;
    assert_eq!(status, 200);
    assert_eq!(
        body,
        serde_json::json!({
            "categories": [
                {"category": "ProjectSpecific", "attempts": 4, "successes": 2, "failures": 2, "pass_rate": 50.0},
                {"category": "KnownThirdParty", "attempts": 2, "successes": 1, "failures": 1, "pass_rate": 50.0},
            ],
            "total_in_log": 6,
        })
    );
}

/// Issue #127 time-range contract: the `from`/`to` inclusive UTC date
/// range narrows both endpoints the same way — the strategy table and the
/// category bars always describe the same filtered set — while
/// `total_in_log` keeps reporting the unfiltered log size. A malformed
/// date is refused with 400.
#[tokio::test]
async fn test_strategy_analytics_api_time_range_narrows_every_endpoint() {
    let fixture = TestFixture::new();
    write_strategy_fixture(&fixture.repo_path(), &sample_strategy_entries());
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let base = format!("http://127.0.0.1:{}", fixture.port());

    // `from` alone keeps everything from that UTC day on: only the two
    // 2026-10-04 d3d9.dll attempts survive.
    let (status, body) = get_json(&format!(
        "{base}/api/strategy-analytics/by-strategy?from=2026-10-04"
    ))
    .await;
    assert_eq!(status, 200);
    assert_eq!(
        body["strategies"],
        serde_json::json!([
            {"strategy": "initial", "attempts": 1, "successes": 1, "failures": 0, "pass_rate": 100.0},
            {"strategy": "retry", "attempts": 1, "successes": 0, "failures": 1, "pass_rate": 0.0},
        ])
    );
    assert_eq!(
        body["total_in_log"].as_u64().expect("total_in_log"),
        6,
        "the log's own size survives filtering"
    );
    let (status, body) = get_json(&format!(
        "{base}/api/strategy-analytics/by-category?from=2026-10-04"
    ))
    .await;
    assert_eq!(status, 200);
    assert_eq!(
        body["categories"],
        serde_json::json!([
            {"category": "KnownThirdParty", "attempts": 2, "successes": 1, "failures": 1, "pass_rate": 50.0},
        ]),
        "only the in-range category survives"
    );

    // An inclusive range holding no attempts answers with empty breakdowns
    // — never a fabricated row of buckets.
    let (status, body) = get_json(&format!(
        "{base}/api/strategy-analytics/by-strategy?from=2026-10-02&to=2026-10-03"
    ))
    .await;
    assert_eq!(status, 200);
    assert!(
        body["strategies"]
            .as_array()
            .expect("strategies array")
            .is_empty(),
        "no matching attempts means no rows"
    );
    let (_, body) = get_json(&format!(
        "{base}/api/strategy-analytics/by-category?from=2026-10-02&to=2026-10-03"
    ))
    .await;
    assert!(
        body["categories"]
            .as_array()
            .expect("categories array")
            .is_empty(),
        "no matching attempts means no bars"
    );

    // Malformed dates are refused with 400 naming the accepted shape —
    // an operator who typed a filter is never silently shown everything.
    let (status, body) = get_json(&format!(
        "{base}/api/strategy-analytics/by-strategy?from=not-a-date"
    ))
    .await;
    assert_eq!(status, 400, "a malformed from date is refused");
    let message = body["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("not-a-date") && message.contains("YYYY-MM-DD"),
        "the 400 names the bad value and the accepted shape, got: {message}"
    );

    let (status, _) = get_json(&format!(
        "{base}/api/strategy-analytics/by-category?to=2026-13-01"
    ))
    .await;
    assert_eq!(status, 400, "an out-of-range to date is refused");
}

/// Issue #127 honest degradation: a corrupt prompt-strategy log loads as
/// empty — the endpoints answer 200 with empty payloads so the view's
/// empty state (driven by `total_in_log`) never renders a wall of zeros
/// for a log it cannot read.
#[tokio::test]
async fn test_strategy_analytics_api_corrupt_log_honest_empty() {
    let fixture = TestFixture::new();
    let dir = fixture.repo_path().join("re").join("analysis");
    std::fs::create_dir_all(&dir).expect("analysis dir exists");
    std::fs::write(dir.join("prompt_strategy_log.json"), "{ not json")
        .expect("corrupt log written");
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let base = format!("http://127.0.0.1:{}", fixture.port());

    let (status, body) = get_json(&format!("{base}/api/strategy-analytics/by-strategy")).await;
    assert_eq!(status, 200, "a corrupt log degrades, never errors");
    assert_eq!(body["total_in_log"].as_u64().expect("total_in_log"), 0);
    assert!(
        body["strategies"]
            .as_array()
            .expect("strategies array")
            .is_empty(),
        "a corrupt log means no rows, not zero rows"
    );

    let (status, body) = get_json(&format!("{base}/api/strategy-analytics/by-category")).await;
    assert_eq!(status, 200);
    assert!(
        body["categories"]
            .as_array()
            .expect("categories array")
            .is_empty(),
        "a corrupt log means no bars, not zero bars"
    );
}

// ─────────────────────────────────────────────────────────────
// LLM performance metrics (issue #128, W3.4)
// ─────────────────────────────────────────────────────────────

/// One token-usage entry carrying a recorded attempt duration — the same
/// shape as `token_usage_entry` plus `duration_secs`. `duration: None`
/// writes the pre-duration-tracking shape (the field omitted entirely),
/// which the percentile math must exclude rather than impute as zero.
// One parameter per fixture field — the whole point is spelling every
// field out, so folding them into a struct would only hide the values.
#[allow(clippy::too_many_arguments)]
fn llm_metrics_token_entry(
    binary: &str,
    function: &str,
    attempt: u32,
    strategy: &str,
    tokens: usize,
    success: bool,
    tier: &str,
    timestamp: u64,
    duration: Option<u64>,
) -> serde_json::Value {
    let mut entry = token_usage_entry(
        binary, function, attempt, strategy, tokens, success, tier, timestamp,
    );
    if let Some(secs) = duration {
        entry["duration_secs"] = serde_json::json!(secs);
    }
    entry
}

/// One resource-exhaustion fault carrying the `metadata.reason` the
/// pipeline's `ResourceExhaustionFault` writes — the timeout kind is what
/// the metrics endpoints count, and the overloaded kind is what they must
/// leave out.
fn resource_exhaustion_fault_entry(
    binary: &str,
    function: &str,
    attempt: u32,
    strategy: &str,
    reason: &str,
    timestamp: u64,
) -> serde_json::Value {
    serde_json::json!({
        "binary": binary,
        "function": function,
        "attempt": attempt,
        "strategy": strategy,
        "category": "resource_exhaustion",
        "severity": "warning",
        "description": format!("{reason} — resource exhaustion in {function}"),
        "recovery": "switch to a smaller/faster model for this translation",
        "timestamp": timestamp,
        "metadata": { "reason": reason, "elapsed_secs": 300 },
    })
}

/// Writes the deterministic fixture pair the metrics tests share: nine
/// token-usage attempts (four on `game_logic.dll/DrawSprite` starting
/// 2026-10-01, five on 2026-10-04) and four faults. Seven attempts
/// recorded durations — 10/20/30/40/50/60/70 seconds, so nearest-rank
/// P50/P95/P99 pin as 40/70/70 — and two predate duration tracking,
/// excluded from the percentiles, never imputed. The faults hold exactly
/// two timeout-kind resource-exhaustion events (one per fixture day),
/// one overloaded resource-exhaustion event that must not count as a
/// timeout, and one slow-response fault that must not count either.
fn write_llm_metrics_fixtures(repo_path: &std::path::Path) {
    write_token_usage_fixture(
        repo_path,
        &[
            llm_metrics_token_entry(
                "game_logic.dll",
                "DrawSprite",
                1,
                "initial",
                4000,
                false,
                "stub",
                FAULT_DAY_1 + 60,
                Some(10),
            ),
            llm_metrics_token_entry(
                "game_logic.dll",
                "DrawSprite",
                2,
                "compile_fix",
                3000,
                true,
                "stub",
                FAULT_DAY_1 + 120,
                Some(30),
            ),
            llm_metrics_token_entry(
                "game_logic.dll",
                "DrawSprite",
                3,
                "escalate",
                8000,
                false,
                "stub",
                FAULT_DAY_1 + 180,
                None,
            ),
            llm_metrics_token_entry(
                "game_logic.dll",
                "DrawSprite",
                4,
                "retry",
                3000,
                true,
                "disassembly",
                FAULT_DAY_1 + 240,
                Some(50),
            ),
            llm_metrics_token_entry(
                "game_logic.dll",
                "DrawSprite",
                5,
                "initial",
                2000,
                true,
                "disassembly",
                FAULT_DAY_4 + 300,
                None,
            ),
            llm_metrics_token_entry(
                "d3d9.dll",
                "UpdateScene",
                1,
                "initial",
                2000,
                true,
                "",
                FAULT_DAY_4 + 60,
                Some(20),
            ),
            llm_metrics_token_entry(
                "d3d9.dll",
                "UpdateScene",
                2,
                "retry",
                3000,
                false,
                "",
                FAULT_DAY_4 + 120,
                Some(40),
            ),
            llm_metrics_token_entry(
                "d3d9.dll",
                "UpdateScene",
                3,
                "initial",
                5000,
                true,
                "module_context",
                FAULT_DAY_4 + 180,
                Some(60),
            ),
            llm_metrics_token_entry(
                "d3d9.dll",
                "UpdateScene",
                4,
                "compile_fix",
                6000,
                true,
                "module_context",
                FAULT_DAY_4 + 240,
                Some(70),
            ),
        ],
    );
    write_fault_log_fixture(
        repo_path,
        &[
            resource_exhaustion_fault_entry(
                "game_logic.dll",
                "DrawSprite",
                3,
                "escalate",
                "timeout",
                FAULT_DAY_1 + 200,
            ),
            resource_exhaustion_fault_entry(
                "game_logic.dll",
                "DrawSprite",
                4,
                "retry",
                "overloaded",
                FAULT_DAY_1 + 260,
            ),
            fault_entry(
                "d3d9.dll",
                "UpdateScene",
                2,
                "retry",
                "slow_response",
                "warning",
                FAULT_DAY_4 + 150,
            ),
            resource_exhaustion_fault_entry(
                "d3d9.dll",
                "UpdateScene",
                3,
                "initial",
                "timeout",
                FAULT_DAY_4 + 210,
            ),
        ],
    );
}

/// Issue #128 router contract: both llm-metrics endpoints are registered
/// in the shared routes — they read the persisted logs, never live
/// pipeline state — so both the plain and the live router answer them.
/// With no logs on disk they serve honest empty payloads: null
/// percentiles, not zeros.
#[tokio::test]
async fn test_llm_metrics_registered_in_plain_and_live_routers() {
    for kind in ["plain", "live"] {
        let fixture = TestFixture::new();
        let state = ServerState::new(fixture.repo_path());
        let router = if kind == "plain" {
            build_router(state)
        } else {
            let events = TranslationEvents::new(128);
            let manager = SessionManager::new_with_broadcast(events.subscribe());
            build_router_with_ws(state, manager, ProgressState::new(), ws_actions(&fixture))
        };
        let _server = spawn_server(router, fixture.port()).await;

        tokio::time::sleep(Duration::from_millis(200)).await;

        let base = format!("http://127.0.0.1:{}", fixture.port());

        for path in ["/api/llm-metrics/summary", "/api/llm-metrics/by-tier"] {
            let (status, _) = get_json(&format!("{base}{path}")).await;
            assert_eq!(status, 200, "{kind} router serves {path}");
        }

        let (_, body) = get_json(&format!("{base}/api/llm-metrics/summary")).await;
        assert_eq!(
            body["total_in_log"].as_u64().expect("total_in_log"),
            0,
            "{kind} router reports an empty log with no log"
        );
        for key in ["p50_secs", "p95_secs", "p99_secs"] {
            assert!(
                body[key].is_null(),
                "{kind} router answers {key} as unmeasured, never a fabricated zero"
            );
        }
        assert!(
            body["timeout_trend"]
                .as_array()
                .expect("timeout_trend array")
                .is_empty(),
            "no log means no fabricated trend buckets"
        );
        let (_, body) = get_json(&format!("{base}/api/llm-metrics/by-tier")).await;
        assert!(
            body["tiers"].as_array().expect("tiers array").is_empty(),
            "no log means no fabricated tiers"
        );
    }
}

/// Issue #128 exact-JSON contract: against deterministic fixture logs,
/// the summary pins exact nearest-rank P50/P95/P99 over the *recorded*
/// durations — the two entries without a duration are excluded, never
/// imputed — and counts exactly the two timeout-kind faults, bucketed
/// per UTC day with the gap days filled. The by-tier endpoint pins the
/// per-tier correlation, including the untracked empty-label bucket.
#[tokio::test]
async fn test_llm_metrics_api_exact_json_from_fixture_logs() {
    let fixture = TestFixture::new();
    write_llm_metrics_fixtures(&fixture.repo_path());
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let base = format!("http://127.0.0.1:{}", fixture.port());

    let (status, body) = get_json(&format!("{base}/api/llm-metrics/summary")).await;
    assert_eq!(status, 200);
    assert_eq!(
        body,
        serde_json::json!({
            "total_attempts": 9,
            "measured_attempts": 7,
            "p50_secs": 40,
            "p95_secs": 70,
            "p99_secs": 70,
            "timeouts": 2,
            "timeout_trend": [
                {"date": "2026-10-01", "count": 1},
                {"date": "2026-10-02", "count": 0},
                {"date": "2026-10-03", "count": 0},
                {"date": "2026-10-04", "count": 1},
            ],
            "total_in_log": 9,
        }),
        "percentiles cover only the measured durations; the overloaded and \
         slow-response faults stay out of the timeout count"
    );

    // Most attempts first; the 2-attempt tie sorts alphabetically, with
    // the untracked empty label honestly first. The disassembly tier has
    // one measured and one unmeasured attempt; a tier with nothing
    // measured would answer null percentiles.
    let (status, body) = get_json(&format!("{base}/api/llm-metrics/by-tier")).await;
    assert_eq!(status, 200);
    assert_eq!(
        body,
        serde_json::json!({
            "tiers": [
                {"tier": "stub", "attempts": 3, "measured_attempts": 2, "p50_secs": 10, "p95_secs": 30},
                {"tier": "", "attempts": 2, "measured_attempts": 2, "p50_secs": 20, "p95_secs": 40},
                {"tier": "disassembly", "attempts": 2, "measured_attempts": 1, "p50_secs": 50, "p95_secs": 50},
                {"tier": "module_context", "attempts": 2, "measured_attempts": 2, "p50_secs": 60, "p95_secs": 70},
            ],
            "total_in_log": 9,
        })
    );
}

/// Issue #128 time-range contract: the `from`/`to` inclusive UTC date
/// range narrows both endpoints the same way — cards, trend, and tier
/// table always describe the same window — while `total_in_log` keeps
/// reporting the unfiltered log size. A malformed date is refused with
/// 400 naming the accepted shape.
#[tokio::test]
async fn test_llm_metrics_api_time_range_narrows_every_endpoint() {
    let fixture = TestFixture::new();
    write_llm_metrics_fixtures(&fixture.repo_path());
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let base = format!("http://127.0.0.1:{}", fixture.port());

    // `from` alone keeps everything from that UTC day on: only the five
    // 2026-10-04 attempts survive — four measured (20/40/60/70, so P50
    // pins at 40) and one unmeasured — and only the 2026-10-04 timeout.
    let (status, body) = get_json(&format!("{base}/api/llm-metrics/summary?from=2026-10-04")).await;
    assert_eq!(status, 200);
    assert_eq!(
        body,
        serde_json::json!({
            "total_attempts": 5,
            "measured_attempts": 4,
            "p50_secs": 40,
            "p95_secs": 70,
            "p99_secs": 70,
            "timeouts": 1,
            "timeout_trend": [
                {"date": "2026-10-04", "count": 1},
            ],
            "total_in_log": 9,
        }),
        "the log's own size survives filtering"
    );
    let (status, body) = get_json(&format!("{base}/api/llm-metrics/by-tier?from=2026-10-04")).await;
    assert_eq!(status, 200);
    assert_eq!(
        body["tiers"],
        serde_json::json!([
            {"tier": "", "attempts": 2, "measured_attempts": 2, "p50_secs": 20, "p95_secs": 40},
            {"tier": "module_context", "attempts": 2, "measured_attempts": 2, "p50_secs": 60, "p95_secs": 70},
            {"tier": "disassembly", "attempts": 1, "measured_attempts": 0, "p50_secs": null, "p95_secs": null},
        ]),
        "the in-range disassembly attempt is unmeasured — percentiles stay \
         null, never imputed"
    );

    // An inclusive range holding no attempts answers with null percentiles
    // and empty breakdowns — never a fabricated run of zeros.
    let (status, body) = get_json(&format!(
        "{base}/api/llm-metrics/summary?from=2026-10-02&to=2026-10-03"
    ))
    .await;
    assert_eq!(status, 200);
    assert!(
        body["p50_secs"].is_null(),
        "nothing measured means no percentile"
    );
    assert_eq!(body["timeouts"].as_u64().expect("timeouts"), 0);
    assert!(
        body["timeout_trend"]
            .as_array()
            .expect("timeout_trend array")
            .is_empty(),
        "no matching timeouts means no buckets"
    );
    let (_, body) = get_json(&format!(
        "{base}/api/llm-metrics/by-tier?from=2026-10-02&to=2026-10-03"
    ))
    .await;
    assert!(
        body["tiers"].as_array().expect("tiers array").is_empty(),
        "no matching attempts means no rows"
    );

    // Malformed dates are refused with 400 naming the accepted shape —
    // an operator who typed a filter is never silently shown everything.
    let (status, body) = get_json(&format!("{base}/api/llm-metrics/summary?from=not-a-date")).await;
    assert_eq!(status, 400, "a malformed from date is refused");
    let message = body["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("not-a-date") && message.contains("YYYY-MM-DD"),
        "the 400 names the bad value and the accepted shape, got: {message}"
    );

    let (status, _) = get_json(&format!("{base}/api/llm-metrics/by-tier?to=2026-13-01")).await;
    assert_eq!(status, 400, "an out-of-range to date is refused");
}

/// Issue #128 honest degradation: a corrupt token usage log loads as
/// empty — the endpoints answer 200 with null percentiles and empty
/// breakdowns so the view's empty state (driven by `total_in_log`) never
/// renders a wall of zeros. A corrupt fault log likewise answers zero
/// timeouts while the duration percentiles keep computing from the
/// intact token log.
#[tokio::test]
async fn test_llm_metrics_api_corrupt_logs_honest_empty() {
    let fixture = TestFixture::new();
    let dir = fixture.repo_path().join("re").join("analysis");
    std::fs::create_dir_all(&dir).expect("analysis dir exists");
    std::fs::write(dir.join("token_usage.json"), "{ not json").expect("corrupt log written");
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let base = format!("http://127.0.0.1:{}", fixture.port());

    let (status, body) = get_json(&format!("{base}/api/llm-metrics/summary")).await;
    assert_eq!(status, 200, "a corrupt log degrades, never errors");
    assert_eq!(body["total_in_log"].as_u64().expect("total_in_log"), 0);
    assert!(
        body["p50_secs"].is_null(),
        "a corrupt log means unmeasured, not zero"
    );
    assert_eq!(body["timeouts"].as_u64().expect("timeouts"), 0);

    let (status, body) = get_json(&format!("{base}/api/llm-metrics/by-tier")).await;
    assert_eq!(status, 200);
    assert!(
        body["tiers"].as_array().expect("tiers array").is_empty(),
        "a corrupt log means no rows, not zero rows"
    );

    // The other direction: the fault log corrupts, the token log survives.
    std::fs::write(dir.join("fault_log.json"), "{ not json").expect("corrupt fault log written");
    write_token_usage_fixture(
        &fixture.repo_path(),
        &[llm_metrics_token_entry(
            "game_logic.dll",
            "DrawSprite",
            1,
            "initial",
            4000,
            false,
            "stub",
            FAULT_DAY_1 + 60,
            Some(10),
        )],
    );
    let (status, body) = get_json(&format!("{base}/api/llm-metrics/summary")).await;
    assert_eq!(status, 200);
    assert_eq!(body["p50_secs"].as_u64().expect("p50_secs"), 10);
    assert_eq!(body["timeouts"].as_u64().expect("timeouts"), 0);
    assert!(
        body["timeout_trend"]
            .as_array()
            .expect("timeout_trend array")
            .is_empty(),
        "a corrupt fault log means no buckets, not zero buckets"
    );
}

// ─────────────────────────────────────────────────────────────
// Binaries view (issue #130, W4.1)
// ─────────────────────────────────────────────────────────────

/// Issue #130 router contract: `/api/binaries/list` is registered in the
/// shared routes — it reads only persisted history, never live pipeline
/// state — so both the plain and the live router answer it. The fixture's
/// initial classification records carry no `binary` field, so
/// `disk_classifications` skips them and the list is honestly empty.
#[tokio::test]
async fn test_binaries_list_registered_in_plain_and_live_routers() {
    for kind in ["plain", "live"] {
        let fixture = TestFixture::new();
        let state = ServerState::new(fixture.repo_path());
        let router = if kind == "plain" {
            build_router(state)
        } else {
            let events = TranslationEvents::new(128);
            let manager = SessionManager::new_with_broadcast(events.subscribe());
            build_router_with_ws(state, manager, ProgressState::new(), ws_actions(&fixture))
        };
        let _server = spawn_server(router, fixture.port()).await;

        tokio::time::sleep(Duration::from_millis(200)).await;

        let base = format!("http://127.0.0.1:{}", fixture.port());
        let (status, body) = get_json(&format!("{base}/api/binaries/list")).await;
        assert_eq!(status, 200, "{kind} router serves /api/binaries/list");
        assert!(
            body["binaries"]
                .as_array()
                .expect("binaries array")
                .is_empty(),
            "{kind} router answers an empty list when no classification \
             record is readable — never a wall of zero rows"
        );
    }
}

/// Seed the full-shape persisted history the exact-JSON test pins:
/// classification records carrying the `binary` field the artifact reader
/// requires (overwriting the fixture's minimal ones), a corrupt record
/// that must be skipped, a classification override on `d3d9.dll`, and a
/// token-usage log with a differently-spelled binary to pin the
/// case-insensitive join.
fn write_binaries_list_fixtures(fixture: &TestFixture) {
    let classify = fixture.repo_path().join("re").join("classify");
    std::fs::create_dir_all(&classify).expect("classify dir");
    std::fs::write(
        classify.join("game_logic.dll.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "binary": "game_logic.dll",
            "category": "ProjectSpecific",
            "strategy": "ReverseEngineer",
            "exports_count": 24,
            "imports_count": 12,
            "crate_replacement": null,
            "known_runtime": false,
            "reason": "project-built binary — reverse engineer from disassembly"
        }))
        .unwrap(),
    )
    .expect("game_logic classification written");
    std::fs::write(
        classify.join("d3d9.dll.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "binary": "d3d9.dll",
            "category": "MicrosoftSdk",
            "strategy": "CrateReplacement",
            "exports_count": 100,
            "imports_count": 5,
            "crate_replacement": "wgpu",
            "known_runtime": false,
            "reason": "Direct3D 9 — replaced with wgpu behind a shim layer"
        }))
        .unwrap(),
    )
    .expect("d3d9 classification written");
    // A corrupt record is no record at all — it must not become a row.
    std::fs::write(classify.join("broken.dll.json"), "{ not json")
        .expect("corrupt classification written");

    // The persisted override layer: d3d9.dll steered to KnownThirdParty
    // with a different target crate — exact-key match on the filename.
    let analysis = fixture.repo_path().join("re").join("analysis");
    std::fs::create_dir_all(&analysis).expect("analysis dir");
    std::fs::write(
        analysis.join("classification_overrides.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "overrides": {
                "d3d9.dll": {
                    "category": "KnownThirdParty",
                    "crate_replacement": "wgpu-rs",
                    "known_runtime": false
                }
            }
        }))
        .unwrap(),
    )
    .expect("override record written");

    // Token totals: game_logic.dll 100 + 50, plus a 25-token entry under
    // a different spelling that must join into the same row; d3d9.dll 75;
    // other.dll 999 belongs to no row — no classification record names it.
    write_token_usage_fixture(
        &fixture.repo_path(),
        &[
            token_usage_entry(
                "game_logic.dll",
                "DrawPrimitive",
                1,
                "initial",
                100,
                false,
                "",
                1,
            ),
            token_usage_entry(
                "game_logic.dll",
                "UpdateScene",
                1,
                "initial",
                50,
                true,
                "",
                2,
            ),
            token_usage_entry(
                "GAME_LOGIC.DLL",
                "DrawPrimitive",
                2,
                "escalate",
                25,
                true,
                "",
                3,
            ),
            token_usage_entry("d3d9.dll", "CreateDevice", 1, "initial", 75, true, "", 4),
            token_usage_entry("other.dll", "Whatever", 1, "initial", 999, true, "", 5),
        ],
    );
}

/// Issue #130 exact-JSON contract: rows aggregate category/strategy from
/// the classification records with the persisted override layer applied,
/// function counts from all the review dashboard's units (queue plus
/// recent activity — where the merged, accepted ones live), and token
/// totals from the token-usage log with a case-insensitive join. Corrupt
/// records are skipped; rows sort alphabetically.
#[tokio::test]
async fn test_binaries_list_api_exact_json_from_fixture() {
    let fixture = TestFixture::new();
    write_binaries_list_fixtures(&fixture);
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let base = format!("http://127.0.0.1:{}", fixture.port());
    let (status, body) = get_json(&format!("{base}/api/binaries/list")).await;
    assert_eq!(status, 200);
    assert_eq!(
        body,
        serde_json::json!({
            "binaries": [
                {
                    "binary": "d3d9.dll",
                    // The override wins over the recorded MicrosoftSdk
                    // classification, and its strategy label follows the
                    // category — CrateReplacement, with the override's
                    // target crate shown.
                    "category": "KnownThirdParty",
                    "strategy": "CrateReplacement",
                    "crate_replacement": "wgpu-rs",
                    "overridden": true,
                    // The merged `re/d3d9.dll/wgpu` branch is an accepted
                    // unit in the dashboard — the row counts what the
                    // dashboard holds.
                    "functions_total": 1,
                    "functions_done": 1,
                    "functions_queued": 0,
                    "functions_failed": 0,
                    "tokens_used": 75,
                },
                {
                    "binary": "game_logic.dll",
                    "category": "ProjectSpecific",
                    "strategy": "ReverseEngineer",
                    "overridden": false,
                    // Three units: merged DrawPrimitive v1 and UpdateScene
                    // v1 (accepted) plus the unmerged v2 branch (patch
                    // record → pending review); the "GAME_LOGIC.DLL" token
                    // entry joins in case-insensitively.
                    "functions_total": 3,
                    "functions_done": 2,
                    "functions_queued": 1,
                    "functions_failed": 0,
                    "tokens_used": 175,
                },
            ],
        }),
        "the corrupt record is skipped, the override layer is applied, and \
         other.dll's tokens belong to no row"
    );
}

/// Issue #132 router contract: `/api/binaries/{name}` is registered in
/// the shared routes — it reads only persisted history, never live
/// pipeline state — so both the plain and the live router answer it with
/// the full detail payload.
#[tokio::test]
async fn test_binaries_detail_registered_in_plain_and_live_routers() {
    for kind in ["plain", "live"] {
        let fixture = TestFixture::new();
        write_binaries_list_fixtures(&fixture);
        let state = ServerState::new(fixture.repo_path());
        let router = if kind == "plain" {
            build_router(state)
        } else {
            let events = TranslationEvents::new(128);
            let manager = SessionManager::new_with_broadcast(events.subscribe());
            build_router_with_ws(state, manager, ProgressState::new(), ws_actions(&fixture))
        };
        let _server = spawn_server(router, fixture.port()).await;

        tokio::time::sleep(Duration::from_millis(200)).await;

        let base = format!("http://127.0.0.1:{}", fixture.port());
        let (status, body) = get_json(&format!("{base}/api/binaries/game_logic.dll")).await;
        assert_eq!(status, 200, "{kind} router serves /api/binaries/{{name}}");
        assert_eq!(body["binary"].as_str().expect("binary"), "game_logic.dll");
        assert_eq!(
            body["functions"].as_array().expect("functions array").len(),
            3,
            "{kind} router: the same three dashboard units the summary row counts"
        );
    }
}

/// Issue #132 exact-JSON contract: the detail carries the classification
/// decision in force — the override layer applied, exactly what the
/// analyzer would act on — with its reasoning and symbol counts, plus
/// the per-function list with each unit's review status. The lookup
/// is case-insensitive like every other server binary join; an unknown
/// or corrupt-record name honestly 404s rather than rendering an empty
/// shell.
#[tokio::test]
async fn test_binaries_detail_api_exact_json_from_fixture() {
    let fixture = TestFixture::new();
    write_binaries_list_fixtures(&fixture);
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let base = format!("http://127.0.0.1:{}", fixture.port());

    // The overridden binary: category, strategy, and crate come from the
    // override in force, and so does the reason — the analyzer's own
    // account of an overridden decision, not the heuristic's.
    let (status, body) = get_json(&format!("{base}/api/binaries/d3d9.dll")).await;
    assert_eq!(status, 200);
    assert_eq!(
        body,
        serde_json::json!({
            "binary": "d3d9.dll",
            "category": "KnownThirdParty",
            "strategy": "CrateReplacement",
            "crate_replacement": "wgpu-rs",
            "overridden": true,
            "known_runtime": false,
            "reason": "operator override — KnownThirdParty (category set from the dashboard)",
            "exports_count": 100,
            "imports_count": 5,
            "functions": [
                { "function": "wgpu", "attempt": 1, "status": "Accepted" },
            ],
        }),
        "the override-in-force decision exactly as the analyzer would act \
         on it, with the per-function list"
    );

    // The un-overridden binary: the recorded decision verbatim, and the
    // function list spelling out where each attempt stands — the stalled
    // v2 sits right next to the accepted v1.
    let (status, body) = get_json(&format!("{base}/api/binaries/game_logic.dll")).await;
    assert_eq!(status, 200);
    assert_eq!(
        body,
        serde_json::json!({
            "binary": "game_logic.dll",
            "category": "ProjectSpecific",
            "strategy": "ReverseEngineer",
            "overridden": false,
            "known_runtime": false,
            "reason": "project-built binary — reverse engineer from disassembly",
            "exports_count": 24,
            "imports_count": 12,
            "functions": [
                { "function": "DrawPrimitive", "attempt": 1, "status": "Accepted" },
                { "function": "DrawPrimitive", "attempt": 2, "status": "PendingReview" },
                { "function": "UpdateScene", "attempt": 1, "status": "Accepted" },
            ],
        }),
        "the recorded decision with the per-function review statuses"
    );

    // A differently-spelled name finds the same binary — the
    // case-insensitive join every other server comparison makes — and
    // the response carries the record's verbatim identity.
    let (status, body) = get_json(&format!("{base}/api/binaries/GAME_LOGIC.DLL")).await;
    assert_eq!(status, 200, "the lookup is case-insensitive");
    assert_eq!(
        body["binary"].as_str().expect("binary"),
        "game_logic.dll",
        "the verbatim record name answers, not the requested spelling"
    );

    // Unknown names honestly 404 — no empty shell.
    for name in ["nope.dll", "broken.dll"] {
        let (status, body) = get_json(&format!("{base}/api/binaries/{name}")).await;
        assert_eq!(status, 404, "{name} has no readable classification record");
        assert_eq!(
            body["error"].as_bool(),
            Some(true),
            "{name}: the 404 carries the honest error payload"
        );
        assert!(
            body["message"].as_str().expect("message").contains(name),
            "the message names the binary the request asked for"
        );
    }
}

// ── Binaries shim tracker API (issue #133, W4.3) ───────────────────────

/// Seed the shim artifacts and shim branches the shim-tracker tests
/// pin, on top of `write_binaries_list_fixtures`: readable mappings and
/// a verification result for `d3d9.dll` (whose in-force override names
/// `wgpu-rs`) with the `re/shim/wgpu-rs` branch merged into main, and a
/// crate-replacement `fmod.dll` whose shim was generated but whose
/// `re/shim/fmod-rs` branch a reviewer sent back.
fn write_shim_tracker_fixtures(fixture: &TestFixture) {
    let classify = fixture.repo_path().join("re").join("classify");
    std::fs::write(
        classify.join("fmod.dll.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "binary": "fmod.dll",
            "category": "KnownThirdParty",
            "strategy": "CrateReplacement",
            "exports_count": 40,
            "imports_count": 3,
            "crate_replacement": "fmod-rs",
            "known_runtime": false,
            "reason": "audio middleware — replaced with fmod-rs behind a shim layer"
        }))
        .unwrap(),
    )
    .expect("fmod classification written");

    // The shim pipeline's persisted artifacts for d3d9.dll — the exact
    // layout `shim_pipeline::persist_shim_artifacts` writes.
    let shim_dir = fixture
        .repo_path()
        .join("re")
        .join("shims")
        .join("d3d9.dll");
    std::fs::create_dir_all(&shim_dir).expect("shim artifact dir");
    std::fs::write(
        shim_dir.join("mappings.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "source_dll": "d3d9.dll",
            "target_crate": "wgpu-rs",
            "mappings": [
                { "original_api": "Present", "crate_api": "wgpu::Queue::submit" },
                { "original_api": "Clear", "crate_api": "wgpu::RenderPass::clear_color" }
            ]
        }))
        .unwrap(),
    )
    .expect("shim mappings written");
    std::fs::write(
        shim_dir.join("verification.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "compiled": true,
            "compilation_errors": [],
            "compilation_warnings": [],
            "tests_passed": 7,
            "tests_total": 8,
            "edge_tests_passed": 2,
            "edge_tests_total": 2,
            "failed_tests": [],
            "mapping_results": []
        }))
        .unwrap(),
    )
    .expect("shim verification written");

    // The dashboard's branch model: `re/shim/wgpu-rs` merged into main
    // (the crate the d3d9.dll override in force names), and
    // `re/shim/fmod-rs` unmerged with a reviewer's send-back record —
    // fmod.dll's generated artifacts still on disk (generated, then sent back).
    let fmod_shim_dir = fixture
        .repo_path()
        .join("re")
        .join("shims")
        .join("fmod.dll");
    std::fs::create_dir_all(&fmod_shim_dir).expect("fmod shim artifact dir");
    std::fs::write(
        fmod_shim_dir.join("mappings.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "source_dll": "fmod.dll",
            "target_crate": "fmod-rs",
            "mappings": [
                { "original_api": "FSOUND_Init", "crate_api": "fmod_rs::init" },
                { "original_api": "FSOUND_Close", "crate_api": "fmod_rs::close" }
            ]
        }))
        .unwrap(),
    )
    .expect("fmod mappings written");
    let git = GitManager::open(&fixture.repo_path()).expect("open fixture repo");
    {
        let branch = GitBranch::new("shim", "wgpu-rs", 1).expect("wgpu-rs shim branch name");
        git.create_branch("shim", "wgpu-rs", 1, None)
            .expect("wgpu-rs branch created");
        let shim_file = "src/wgpu_rs_shim.rs";
        std::fs::create_dir_all(git.repo_path().join("src")).expect("src dir");
        std::fs::write(git.repo_path().join(shim_file), "// wgpu-rs shim layer")
            .expect("wgpu-rs shim written");
        git.commit(&branch, "Add wgpu-rs shim layer", &[shim_file])
            .expect("wgpu-rs shim committed");
        git.merge_to_main(&branch).expect("wgpu-rs branch merged");
    }
    {
        let branch = GitBranch::new("shim", "fmod-rs", 1).expect("fmod-rs shim branch name");
        git.create_branch("shim", "fmod-rs", 1, None)
            .expect("fmod-rs branch created");
        let shim_file = "src/fmod_rs_shim.rs";
        std::fs::write(git.repo_path().join(shim_file), "// fmod-rs shim layer")
            .expect("fmod-rs shim written");
        git.commit(&branch, "Add fmod-rs shim layer", &[shim_file])
            .expect("fmod-rs shim committed");
        // The reviewer's send-back verdict, as `reject_branch` persists it.
        let rejections = fixture
            .repo_path()
            .join("re")
            .join("rejections")
            .join("shim")
            .join("fmod-rs");
        std::fs::create_dir_all(&rejections).expect("rejection dir");
        std::fs::write(
            rejections.join("v1.json"),
            serde_json::json!({
                "function": "fmod-rs",
                "reason": "mapping table incomplete — send back",
                "requested_changes": "regenerate the missing exports",
                "reviewed_at": "2026-09-05T00:00:00Z",
            })
            .to_string(),
        )
        .expect("send-back record written");
    }
}

/// Issue #133 router contract: `/api/binaries/{name}/shim-status` is
/// registered in the shared routes — it reads only persisted artifacts,
/// never live pipeline state — so both the plain and the live router
/// answer it with the tracker payload.
#[tokio::test]
async fn test_binaries_shim_status_registered_in_plain_and_live_routers() {
    for kind in ["plain", "live"] {
        let fixture = TestFixture::new();
        write_binaries_list_fixtures(&fixture);
        write_shim_tracker_fixtures(&fixture);
        let state = ServerState::new(fixture.repo_path());
        let router = if kind == "plain" {
            build_router(state)
        } else {
            let events = TranslationEvents::new(128);
            let manager = SessionManager::new_with_broadcast(events.subscribe());
            build_router_with_ws(state, manager, ProgressState::new(), ws_actions(&fixture))
        };
        let _server = spawn_server(router, fixture.port()).await;

        tokio::time::sleep(Duration::from_millis(200)).await;

        let base = format!("http://127.0.0.1:{}", fixture.port());
        let (status, body) = get_json(&format!("{base}/api/binaries/d3d9.dll/shim-status")).await;
        assert_eq!(
            status, 200,
            "{kind} router serves /api/binaries/{{name}}/shim-status"
        );
        assert_eq!(
            body["generated"].as_bool(),
            Some(true),
            "{kind} router: the persisted shim artifacts answer"
        );
        assert_eq!(body["mapping_count"].as_u64().expect("mapping_count"), 2);
    }
}

/// Issue #133 exact-JSON contract: the tracker reports existence,
/// mapping count, verification outcome, and merged/sent-back state from
/// persisted artifacts only. The crate joined to is the one the
/// override in force names (`wgpu-rs`, not the recorded `wgpu`); a
/// reverse-engineered binary honestly reports no shim expected; a
/// crate-replacement binary whose branch a reviewer sent back carries
/// the sent-back verdict. The lookup is case-insensitive; unknown and
/// corrupt-record names honestly 404.
#[tokio::test]
async fn test_binaries_shim_status_api_exact_json_from_fixture() {
    let fixture = TestFixture::new();
    write_binaries_list_fixtures(&fixture);
    write_shim_tracker_fixtures(&fixture);
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let base = format!("http://127.0.0.1:{}", fixture.port());

    // The crate-replacement binary with artifacts and a merged shim
    // branch: every fact comes from the persisted shim files and the
    // branch model.
    let (status, body) = get_json(&format!("{base}/api/binaries/d3d9.dll/shim-status")).await;
    assert_eq!(status, 200);
    assert_eq!(
        body,
        serde_json::json!({
            "binary": "d3d9.dll",
            "shim_expected": true,
            // The crate in force is the override's, and so is the
            // branch joined to.
            "crate_replacement": "wgpu-rs",
            "generated": true,
            "mapping_count": 2,
            "verification": {
                "compiled": true,
                "tests_passed": 7,
                "tests_total": 8,
                "edge_tests_passed": 2,
                "edge_tests_total": 2,
            },
            "branch": { "name": "re/shim/wgpu-rs", "merged": true, "sent_back": false },
        }),
        "existence, mapping count, verification, and merged state from \
         persisted artifacts only"
    );

    // The reverse-engineered binary: honestly no shim expected, and no
    // derived fields on the wire at all.
    let (status, body) = get_json(&format!("{base}/api/binaries/game_logic.dll/shim-status")).await;
    assert_eq!(status, 200);
    assert_eq!(
        body,
        serde_json::json!({
            "binary": "game_logic.dll",
            "shim_expected": false,
            "generated": false,
        }),
        "a reverse-engineered binary honestly reports no shim expected"
    );

    // The crate-replacement binary whose shim was generated but whose branch
    // was sent back: the artifacts and the reviewer's verdict both answer.
    let (status, body) = get_json(&format!("{base}/api/binaries/fmod.dll/shim-status")).await;
    assert_eq!(status, 200);
    assert_eq!(
        body,
        serde_json::json!({
            "binary": "fmod.dll",
            "shim_expected": true,
            "crate_replacement": "fmod-rs",
            "generated": true,
            "mapping_count": 2,
            "branch": { "name": "re/shim/fmod-rs", "merged": false, "sent_back": true },
        }),
        "no artifacts is honestly not generated; the send-back record \
         still folds to the branch's acceptance state"
    );

    // A differently-spelled name finds the same binary — the
    // case-insensitive join every other server comparison makes — and
    // the response carries the record's verbatim identity.
    let (status, body) = get_json(&format!("{base}/api/binaries/D3D9.DLL/shim-status")).await;
    assert_eq!(status, 200, "the lookup is case-insensitive");
    assert_eq!(
        body["binary"].as_str().expect("binary"),
        "d3d9.dll",
        "the verbatim record name answers, not the requested spelling"
    );

    // Unknown names honestly 404 — no empty shell.
    for name in ["nope.dll", "broken.dll"] {
        let (status, body) = get_json(&format!("{base}/api/binaries/{name}/shim-status")).await;
        assert_eq!(status, 404, "{name} has no readable classification record");
        assert_eq!(
            body["error"].as_bool(),
            Some(true),
            "{name}: the 404 carries the honest error payload"
        );
    }
}

/// Issue #133 honest-degradation contract: a corrupt `mappings.json` is
/// no shim — the tracker answers "not generated" with the derived
/// fields absent, never a zeroed count; a corrupt `verification.json`
/// leaves the verification absent while the readable mappings still
/// answer.
#[tokio::test]
async fn test_binaries_shim_status_honest_missing_and_corrupt_artifacts() {
    let fixture = TestFixture::new();
    write_binaries_list_fixtures(&fixture);
    write_shim_tracker_fixtures(&fixture);

    // d3d9.dll's mappings go corrupt — the verification file stays
    // readable, but the shim's existence itself is unreadable.
    let shim_dir = fixture
        .repo_path()
        .join("re")
        .join("shims")
        .join("d3d9.dll");
    std::fs::write(shim_dir.join("mappings.json"), "{ not json").expect("corrupt mappings");

    // A second crate-replacement binary with both artifacts corrupt.
    let classify = fixture.repo_path().join("re").join("classify");
    std::fs::write(
        classify.join("ogg.dll.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "binary": "ogg.dll",
            "category": "KnownThirdParty",
            "strategy": "CrateReplacement",
            "exports_count": 10,
            "imports_count": 1,
            "crate_replacement": "ogg-rs",
            "known_runtime": false,
            "reason": "audio codec — replaced with ogg-rs"
        }))
        .unwrap(),
    )
    .expect("ogg classification written");
    let ogg_dir = fixture.repo_path().join("re").join("shims").join("ogg.dll");
    std::fs::create_dir_all(&ogg_dir).expect("ogg shim dir");
    std::fs::write(ogg_dir.join("mappings.json"), "not json at all").expect("corrupt mappings");
    std::fs::write(ogg_dir.join("verification.json"), "{{{").expect("corrupt verification");

    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let base = format!("http://127.0.0.1:{}", fixture.port());

    // Corrupt mappings: honestly not generated — no mapping count, even
    // though the verification artifact is still readable.
    let (status, body) = get_json(&format!("{base}/api/binaries/d3d9.dll/shim-status")).await;
    assert_eq!(status, 200);
    assert_eq!(
        body,
        serde_json::json!({
            "binary": "d3d9.dll",
            "shim_expected": true,
            "crate_replacement": "wgpu-rs",
            "generated": false,
            "verification": {
                "compiled": true,
                "tests_passed": 7,
                "tests_total": 8,
                "edge_tests_passed": 2,
                "edge_tests_total": 2,
            },
            "branch": { "name": "re/shim/wgpu-rs", "merged": true, "sent_back": false },
        }),
        "a corrupt mappings.json is no shim — honestly not generated, \
         never a zeroed count"
    );

    // Both artifacts corrupt: the honest empty payload — not generated,
    // no mapping count, no verification, no branch in the model.
    let (status, body) = get_json(&format!("{base}/api/binaries/ogg.dll/shim-status")).await;
    assert_eq!(status, 200);
    assert_eq!(
        body,
        serde_json::json!({
            "binary": "ogg.dll",
            "shim_expected": true,
            "crate_replacement": "ogg-rs",
            "generated": false,
        }),
        "corrupt artifacts are no artifacts — the payload stays empty"
    );
}

// ── Binaries PAL tracker API (issue #134, W4.4) ────────────────────────

/// Seed the artifacts the PAL-tracker tests pin, on top of
/// `write_binaries_list_fixtures`: per-function analysis artifacts under
/// `re/analysis/d3d9.dll/` whose `windows_apis` carry categories
/// (DirectX, DirectX11, Win32Core — one corrupt artifact contributing
/// nothing), the generated shared PAL crate under `scratch/pal/src/`
/// defining `GraphicsDevice` but not `PlatformCore`, and the binary's
/// generated shim source under `re/shims/d3d9.dll/shim.rs` defining no
/// trait at all.
fn write_pal_tracker_fixtures(fixture: &TestFixture) {
    let analysis = fixture
        .repo_path()
        .join("re")
        .join("analysis")
        .join("d3d9.dll");
    std::fs::create_dir_all(&analysis).expect("d3d9 analysis dir");
    std::fs::write(
        analysis.join("CreateDevice.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "function_name": "CreateDevice",
            "windows_apis": [
                { "name": "Direct3DCreate9", "category": "DirectX", "pal_mapping": "wgpu::Instance" },
                { "name": "CreateFileA", "category": "Win32Core", "pal_mapping": "std::fs::File::open" }
            ]
        }))
        .unwrap(),
    )
    .expect("CreateDevice artifact written");
    std::fs::write(
        analysis.join("Present.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "function_name": "Present",
            "windows_apis": [
                { "name": "IDXGISwapChain::Present", "category": "DirectX11", "pal_mapping": "wgpu::Surface::present" }
            ]
        }))
        .unwrap(),
    )
    .expect("Present artifact written");
    // A corrupt function artifact is no artifact — it names no category.
    std::fs::write(analysis.join("broken.json"), "{ not json").expect("corrupt artifact written");

    // The generated shared PAL crate the verifier writes under
    // `scratch/pal/`: defines GraphicsDevice (and AudioDevice) but not
    // PlatformCore.
    let pal_src = fixture.repo_path().join("scratch").join("pal").join("src");
    std::fs::create_dir_all(&pal_src).expect("scratch pal src dir");
    std::fs::write(
        pal_src.join("stub_content.rs"),
        "pub trait GraphicsDevice {\n    fn create_device(width: u32, height: u32) -> Self;\n}\n\npub trait AudioDevice {\n    fn play(&mut self, samples: &[f32]);\n}\n",
    )
    .expect("pal stub content written");

    // The binary's generated shim source: functions, no trait definitions.
    let shim_dir = fixture
        .repo_path()
        .join("re")
        .join("shims")
        .join("d3d9.dll");
    std::fs::create_dir_all(&shim_dir).expect("d3d9 shim dir");
    std::fs::write(
        shim_dir.join("shim.rs"),
        "// generated shim layer\nunsafe fn present() {}\n",
    )
    .expect("shim source written");
}

/// Issue #134 router contract: `/api/binaries/{name}/pal-status` is
/// registered in the shared routes — it derives on demand from persisted
/// artifacts, never live pipeline state — so both the plain and the live
/// router answer it with the tracker payload.
#[tokio::test]
async fn test_binaries_pal_status_registered_in_plain_and_live_routers() {
    for kind in ["plain", "live"] {
        let fixture = TestFixture::new();
        write_binaries_list_fixtures(&fixture);
        write_pal_tracker_fixtures(&fixture);
        let state = ServerState::new(fixture.repo_path());
        let router = if kind == "plain" {
            build_router(state)
        } else {
            let events = TranslationEvents::new(128);
            let manager = SessionManager::new_with_broadcast(events.subscribe());
            build_router_with_ws(state, manager, ProgressState::new(), ws_actions(&fixture))
        };
        let _server = spawn_server(router, fixture.port()).await;

        tokio::time::sleep(Duration::from_millis(200)).await;

        let base = format!("http://127.0.0.1:{}", fixture.port());
        let (status, body) = get_json(&format!("{base}/api/binaries/d3d9.dll/pal-status")).await;
        assert_eq!(
            status, 200,
            "{kind} router serves /api/binaries/{{name}}/pal-status"
        );
        assert_eq!(
            body["traits"].as_array().map(|t| t.len()),
            Some(2),
            "{kind} router: the derived traits answer"
        );
    }
}

/// Issue #134 exact-JSON contract: needed traits come only from the
/// persisted per-function analysis artifacts' API-call categories, mapped
/// category→trait with the translator's Tier-4 shape — DirectX and
/// DirectX11 group into one GraphicsDevice, Win32Core into PlatformCore
/// — sorted by trait name with verbatim sorted categories. Existence is
/// detected from the workspace's generated PAL/shim source artifacts:
/// GraphicsDevice exists (the scratch PAL crate defines it),
/// PlatformCore is missing. A binary with no API-call artifacts honestly
/// answers an empty trait list; the lookup is case-insensitive; unknown
/// and corrupt-record names honestly 404.
#[tokio::test]
async fn test_binaries_pal_status_api_exact_json_from_fixture() {
    let fixture = TestFixture::new();
    write_binaries_list_fixtures(&fixture);
    write_pal_tracker_fixtures(&fixture);
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let base = format!("http://127.0.0.1:{}", fixture.port());

    // The binary with API-call artifacts and a generated PAL source:
    // every fact derives from persisted artifacts only.
    let (status, body) = get_json(&format!("{base}/api/binaries/d3d9.dll/pal-status")).await;
    assert_eq!(status, 200);
    assert_eq!(
        body,
        serde_json::json!({
            "binary": "d3d9.dll",
            "traits": [
                {
                    "name": "GraphicsDevice",
                    "categories": ["DirectX", "DirectX11"],
                    "exists": true,
                },
                {
                    "name": "PlatformCore",
                    "categories": ["Win32Core"],
                    "exists": false,
                },
            ],
        }),
        "needed traits derive from the persisted API-call categories, \
         existence from the generated PAL source"
    );

    // The binary with no per-function artifacts at all: the honest empty
    // payload — no fabricated trait list.
    let (status, body) = get_json(&format!("{base}/api/binaries/game_logic.dll/pal-status")).await;
    assert_eq!(status, 200);
    assert_eq!(
        body,
        serde_json::json!({
            "binary": "game_logic.dll",
            "traits": [],
        }),
        "no API-call artifacts means no derived traits — never a \
         fabricated list"
    );

    // A differently-spelled name finds the same binary — the
    // case-insensitive join every other server comparison makes — and
    // the response carries the record's verbatim identity.
    let (status, body) = get_json(&format!("{base}/api/binaries/D3D9.DLL/pal-status")).await;
    assert_eq!(status, 200, "the lookup is case-insensitive");
    assert_eq!(
        body["binary"].as_str().expect("binary"),
        "d3d9.dll",
        "the verbatim record name answers, not the requested spelling"
    );

    // Unknown names honestly 404 — no empty shell.
    for name in ["nope.dll", "broken.dll"] {
        let (status, body) = get_json(&format!("{base}/api/binaries/{name}/pal-status")).await;
        assert_eq!(status, 404, "{name} has no readable classification record");
        assert_eq!(
            body["error"].as_bool(),
            Some(true),
            "{name}: the 404 carries the honest error payload"
        );
    }
}

/// Issue #134 honest-degradation contract: a corrupt function artifact
/// names no category while the readable ones still derive traits; with
/// no generated PAL/shim source anywhere every needed trait is honestly
/// missing; with no readable API-call artifacts at all the payload is
/// the honest empty list.
#[tokio::test]
async fn test_binaries_pal_status_honest_missing_and_corrupt_artifacts() {
    let fixture = TestFixture::new();
    write_binaries_list_fixtures(&fixture);
    write_pal_tracker_fixtures(&fixture);

    // No generated PAL/shim source anywhere: delete the scratch PAL
    // crate and the shim source.
    std::fs::remove_dir_all(fixture.repo_path().join("scratch"))
        .expect("scratch pal crate removed");
    std::fs::remove_file(
        fixture
            .repo_path()
            .join("re")
            .join("shims")
            .join("d3d9.dll")
            .join("shim.rs"),
    )
    .expect("shim source removed");

    // A second binary whose only readable artifact carries an Audio
    // category — its other artifact is corrupt and names nothing.
    let classify = fixture.repo_path().join("re").join("classify");
    std::fs::write(
        classify.join("ogg.dll.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "binary": "ogg.dll",
            "category": "KnownThirdParty",
            "strategy": "CrateReplacement",
            "exports_count": 10,
            "imports_count": 1,
            "crate_replacement": "ogg-rs",
            "known_runtime": false,
            "reason": "audio codec — replaced with ogg-rs"
        }))
        .unwrap(),
    )
    .expect("ogg classification written");
    let ogg_dir = fixture
        .repo_path()
        .join("re")
        .join("analysis")
        .join("ogg.dll");
    std::fs::create_dir_all(&ogg_dir).expect("ogg analysis dir");
    std::fs::write(
        ogg_dir.join("PlaySample.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "function_name": "PlaySample",
            "windows_apis": [
                { "name": "waveOutWrite", "category": "Audio", "pal_mapping": "cpal" }
            ]
        }))
        .unwrap(),
    )
    .expect("PlaySample artifact written");
    std::fs::write(ogg_dir.join("broken.json"), "not json at all")
        .expect("corrupt artifact written");

    // A third binary whose every artifact is corrupt: no artifact at all.
    let dsound_dir = fixture
        .repo_path()
        .join("re")
        .join("analysis")
        .join("dsound.dll");
    std::fs::create_dir_all(&dsound_dir).expect("dsound analysis dir");
    std::fs::write(dsound_dir.join("DirectSoundCreate.json"), "{{{")
        .expect("corrupt artifact written");
    std::fs::write(
        classify.join("dsound.dll.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "binary": "dsound.dll",
            "category": "WindowsOs",
            "strategy": "PalMapping",
            "exports_count": 8,
            "imports_count": 2,
            "known_runtime": false,
            "reason": "Windows OS dll — PAL mapping"
        }))
        .unwrap(),
    )
    .expect("dsound classification written");

    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let base = format!("http://127.0.0.1:{}", fixture.port());

    // Needed traits still derive (the corrupt d3d9 artifact named
    // nothing); with no generated PAL/shim source every trait is
    // honestly missing.
    let (status, body) = get_json(&format!("{base}/api/binaries/d3d9.dll/pal-status")).await;
    assert_eq!(status, 200);
    assert_eq!(
        body,
        serde_json::json!({
            "binary": "d3d9.dll",
            "traits": [
                { "name": "GraphicsDevice", "categories": ["DirectX", "DirectX11"], "exists": false },
                { "name": "PlatformCore", "categories": ["Win32Core"], "exists": false },
            ],
        }),
        "no generated PAL/shim source means every needed trait is \
         honestly missing"
    );

    // The corrupt artifact is skipped; the readable one still derives.
    let (status, body) = get_json(&format!("{base}/api/binaries/ogg.dll/pal-status")).await;
    assert_eq!(status, 200);
    assert_eq!(
        body,
        serde_json::json!({
            "binary": "ogg.dll",
            "traits": [
                { "name": "AudioDevice", "categories": ["Audio"], "exists": false },
            ],
        }),
        "a corrupt artifact names no category; the readable one still answers"
    );

    // Every artifact corrupt: the honest empty payload.
    let (status, body) = get_json(&format!("{base}/api/binaries/dsound.dll/pal-status")).await;
    assert_eq!(status, 200);
    assert_eq!(
        body,
        serde_json::json!({
            "binary": "dsound.dll",
            "traits": [],
        }),
        "corrupt artifacts are no artifacts — the trait list stays empty"
    );
}

// ── Unit attempts API (issue #131, W4.5) ───────────────────────────────

/// Issue #131 router contract: `/api/units/{id}/attempts` is registered in
/// the shared routes — it reads only persisted history, never live
/// pipeline state — so both the plain and the live router answer it. The
/// fixture's two DrawPrimitive branches and two patch records form the
/// attempt set; with no token or fault log seeded, the metadata fields
/// honestly stay absent rather than zeroed.
#[tokio::test]
async fn test_unit_attempts_registered_in_plain_and_live_routers() {
    for kind in ["plain", "live"] {
        let fixture = TestFixture::new();
        let state = ServerState::new(fixture.repo_path());
        let router = if kind == "plain" {
            build_router(state)
        } else {
            let events = TranslationEvents::new(128);
            let manager = SessionManager::new_with_broadcast(events.subscribe());
            build_router_with_ws(state, manager, ProgressState::new(), ws_actions(&fixture))
        };
        let _server = spawn_server(router, fixture.port()).await;

        tokio::time::sleep(Duration::from_millis(200)).await;

        let base = format!("http://127.0.0.1:{}", fixture.port());
        let (status, body) = get_json(&format!(
            "{base}/api/units/game_logic.dll%2FDrawPrimitive%2Fv2/attempts"
        ))
        .await;
        assert_eq!(
            status, 200,
            "{kind} router serves /api/units/{{id}}/attempts"
        );
        assert_eq!(
            body["unit_id"].as_str().expect("unit_id"),
            "game_logic.dll/DrawPrimitive/v2"
        );
        let attempts = body["attempts"].as_array().expect("attempts array");
        assert_eq!(attempts.len(), 2, "{kind} router: both persisted attempts");
        assert!(body["comparable"].as_bool().expect("comparable"));
        let v1 = &attempts[0];
        assert_eq!(v1["attempt"].as_u64().expect("attempt"), 1);
        assert_eq!(
            v1["branch"].as_str().expect("branch"),
            "re/game_logic.dll/DrawPrimitivev1"
        );
        assert!(
            v1.get("strategy").is_none() && v1.get("tokens_used").is_none(),
            "{kind} router: no token log means absent fields, not zeros"
        );
        assert_eq!(v1["commit_hash"].as_str().expect("commit_hash"), "abc123");
    }
}

/// The exact-JSON pin for the attempt join: the union of the fixture's
/// branches and patch records, a branch-only v3 created in-test, the
/// case-insensitive token-log join ("GAME_LOGIC.DLL"), the fault log as
/// the strategy fallback for the attempt the token log never recorded,
/// and the token log winning over the fault log where both name an
/// attempt. Absent metadata stays off the wire entirely.
#[tokio::test]
async fn test_unit_attempts_api_exact_json_from_fixture() {
    let fixture = TestFixture::new();

    // A third attempt that exists only as a branch — no patch record, no
    // token entry — so the union's "nothing dropped" half is pinned.
    let git = GitManager::open(&fixture.repo_path()).expect("open fixture repo");
    git.create_branch("game_logic.dll", "DrawPrimitive", 3, None)
        .expect("v3 branch");

    write_token_usage_fixture(
        &fixture.repo_path(),
        &[
            token_usage_entry(
                "game_logic.dll",
                "DrawPrimitive",
                1,
                "initial",
                4000,
                false,
                "stub",
                1759053600,
            ),
            // The differently-spelled binary must join case-insensitively.
            token_usage_entry(
                "GAME_LOGIC.DLL",
                "DrawPrimitive",
                2,
                "escalate",
                2500,
                true,
                "with_tests",
                1759059000,
            ),
            // Same attempt number, different function — must not join.
            token_usage_entry(
                "game_logic.dll",
                "UpdateScene",
                1,
                "initial",
                999,
                true,
                "stub",
                1759053600,
            ),
        ],
    );
    write_fault_log_fixture(
        &fixture.repo_path(),
        &[
            // Names attempt 1 too — the token log wins where both speak.
            fault_entry(
                "game_logic.dll",
                "DrawPrimitive",
                1,
                "compile_fix",
                "infinite_loop",
                "critical",
                1759053700,
            ),
            // The only source naming attempt 3's strategy.
            fault_entry(
                "game_logic.dll",
                "DrawPrimitive",
                3,
                "test_fix",
                "behavior_divergence",
                "warning",
                1759060000,
            ),
        ],
    );

    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let base = format!("http://127.0.0.1:{}", fixture.port());
    let (status, body) = get_json(&format!(
        "{base}/api/units/game_logic.dll%2FDrawPrimitive%2Fv2/attempts"
    ))
    .await;
    assert_eq!(status, 200);
    assert_eq!(
        body,
        serde_json::json!({
            "unit_id": "game_logic.dll/DrawPrimitive/v2",
            "attempts": [
                {
                    "attempt": 1,
                    "branch": "re/game_logic.dll/DrawPrimitivev1",
                    "strategy": "initial",
                    "context_tier": "stub",
                    "tokens_used": 4000,
                    "success": false,
                    "compiled": true,
                    "compilation_errors": [],
                    "commit_hash": "abc123",
                    "committed_at": "2025-09-28T10:00:00Z",
                },
                {
                    "attempt": 2,
                    "branch": "re/game_logic.dll/DrawPrimitivev2",
                    "strategy": "escalate",
                    "context_tier": "with_tests",
                    "tokens_used": 2500,
                    "success": true,
                    "compiled": false,
                    "compilation_errors": ["mismatched types"],
                    "tests_failed": 1,
                    "test_failures": ["shader_constant_map_wrong"],
                    "commit_hash": "def456",
                    "committed_at": "2025-09-28T11:30:00Z",
                },
                {
                    "attempt": 3,
                    "branch": "re/game_logic.dll/DrawPrimitivev3",
                    "strategy": "test_fix",
                },
            ],
            "comparable": true,
        }),
        "the attempt set is the union of branches and patch records, the \
         token log joins case-insensitively and wins over the fault log, \
         and every absent source leaves its field off the wire"
    );
}

/// A single-attempt unit honestly answers one attempt with
/// `comparable: false` — the detail panel's "nothing to compare" state —
/// and an unknown unit is a 404, the same contract the other
/// `/api/units/{id}/…` reads keep.
#[tokio::test]
async fn test_unit_attempts_single_attempt_and_unknown_unit() {
    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let base = format!("http://127.0.0.1:{}", fixture.port());
    let (status, body) = get_json(&format!(
        "{base}/api/units/game_logic.dll%2FUpdateScene%2Fv1/attempts"
    ))
    .await;
    assert_eq!(status, 200);
    assert_eq!(body["attempts"].as_array().expect("attempts").len(), 1);
    assert!(
        !body["comparable"].as_bool().expect("comparable"),
        "a single attempt is not comparable"
    );

    let (status, _) = get_json(&format!("{base}/api/units/nope.dll%2FGhost%2Fv1/attempts")).await;
    assert_eq!(status, 404, "an unknown unit is a 404, not an empty list");
}

/// Corrupt logs are no logs at all: strategy, tier, tokens, and success
/// stay absent while the patch-record fields survive untouched — the
/// join degrades honestly instead of failing or zeroing.
#[tokio::test]
async fn test_unit_attempts_corrupt_logs_degrade_honestly() {
    let fixture = TestFixture::new();
    let analysis = fixture.repo_path().join("re").join("analysis");
    std::fs::create_dir_all(&analysis).expect("analysis dir");
    std::fs::write(analysis.join("token_usage.json"), "{ not json").expect("corrupt token log");
    std::fs::write(analysis.join("fault_log.json"), "nope").expect("corrupt fault log");

    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let base = format!("http://127.0.0.1:{}", fixture.port());
    let (status, body) = get_json(&format!(
        "{base}/api/units/game_logic.dll%2FDrawPrimitive%2Fv2/attempts"
    ))
    .await;
    assert_eq!(status, 200, "corrupt logs never fail the request");
    let attempts = body["attempts"].as_array().expect("attempts");
    assert_eq!(
        attempts.len(),
        2,
        "the attempt set survives the corrupt logs"
    );
    for attempt in attempts {
        assert!(attempt.get("strategy").is_none());
        assert!(attempt.get("context_tier").is_none());
        assert!(attempt.get("tokens_used").is_none());
        assert!(attempt.get("success").is_none());
        assert!(
            attempt["commit_hash"].is_string(),
            "patch-record fields survive the corrupt logs"
        );
    }
}

// ── Unit attempt diff API (issue #135, W4.6) ───────────────────────────

/// Issue #135 router contract: `/api/units/{id}/attempts/diff` is
/// registered in the shared routes — it reads only persisted branches —
/// so both the plain and the live router answer it. The fixture's
/// DrawPrimitive v1 and v2 branches carry distinct commits, so the diff
/// is real text, not an empty shell.
#[tokio::test]
async fn test_unit_attempt_diff_registered_in_plain_and_live_routers() {
    for kind in ["plain", "live"] {
        let fixture = TestFixture::new();
        let state = ServerState::new(fixture.repo_path());
        let router = if kind == "plain" {
            build_router(state)
        } else {
            let events = TranslationEvents::new(128);
            let manager = SessionManager::new_with_broadcast(events.subscribe());
            build_router_with_ws(state, manager, ProgressState::new(), ws_actions(&fixture))
        };
        let _server = spawn_server(router, fixture.port()).await;

        tokio::time::sleep(Duration::from_millis(200)).await;

        let base = format!("http://127.0.0.1:{}", fixture.port());
        let (status, body) = get_json(&format!(
            "{base}/api/units/game_logic.dll%2FDrawPrimitive%2Fv2/attempts/diff?from=1&to=2"
        ))
        .await;
        assert_eq!(
            status, 200,
            "{kind} router serves /api/units/{{id}}/attempts/diff"
        );
        assert_eq!(body["from"].as_u64().expect("from"), 1);
        assert_eq!(body["to"].as_u64().expect("to"), 2);
        let diff = body["diff"].as_str().expect("diff text");
        assert!(
            diff.contains("src/draw_primitive_v2.rs"),
            "{kind} router: the v2 branch's distinct commit shows in the diff"
        );
    }
}

/// The exact-JSON pin against fixture branches with distinct commits:
/// v1's tree lacks the v2 attempt's file, so the tree-to-tree diff is
/// exactly that one added file — verbatim unified text plus its stats.
#[tokio::test]
async fn test_unit_attempt_diff_api_exact_json_from_fixture() {
    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let base = format!("http://127.0.0.1:{}", fixture.port());
    let (status, body) = get_json(&format!(
        "{base}/api/units/game_logic.dll%2FDrawPrimitive%2Fv2/attempts/diff?from=1&to=2"
    ))
    .await;
    assert_eq!(status, 200);
    assert_eq!(
        body,
        serde_json::json!({
            "unit_id": "game_logic.dll/DrawPrimitive/v2",
            "from": 1,
            "to": 2,
            "from_branch": "re/game_logic.dll/DrawPrimitivev1",
            "to_branch": "re/game_logic.dll/DrawPrimitivev2",
            "files_changed": 1,
            "insertions": 4,
            "deletions": 0,
            "diff": "diff --git a/src/draw_primitive_v2.rs b/src/draw_primitive_v2.rs\n\
                     new file mode 100644\n\
                     index 0000000..1d34caf\n\
                     --- /dev/null\n\
                     +++ b/src/draw_primitive_v2.rs\n\
                     @@ -0,0 +1,4 @@\n\
                     +/// Attempt 2 — wrong shader constant mapping\n\
                     +pub fn draw_primitive_v2(_encoder: &mut wgpu::CommandEncoder) {\n\
                     +    // buggy implementation\n\
                     +}\n",
        }),
        "the diff is the git2 tree-to-tree patch between the two attempt \
         branches' trees, verbatim"
    );
}

/// A missing branch on either side answers an honest error payload —
/// never an empty fabricated diff — and a non-numeric attempt number is
/// a 400 naming the accepted shape.
#[tokio::test]
async fn test_unit_attempt_diff_missing_branch_and_bad_params() {
    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let base = format!("http://127.0.0.1:{}", fixture.port());

    // Attempt 3 never left a branch or record in the fixture.
    let (status, body) = get_json(&format!(
        "{base}/api/units/game_logic.dll%2FDrawPrimitive%2Fv2/attempts/diff?from=1&to=3"
    ))
    .await;
    assert_eq!(status, 404, "a missing attempt branch is an honest 404");
    assert!(
        body["error"].as_bool().unwrap_or(false)
            && body["message"].as_str().unwrap_or("").contains("Attempt 3"),
        "the error payload names the attempt that has no branch, got: {body}"
    );
    assert!(
        body.get("diff").is_none(),
        "the error payload never carries a fabricated diff"
    );

    // The `to` side missing is just as honest as the `from` side.
    let (status, body) = get_json(&format!(
        "{base}/api/units/game_logic.dll%2FDrawPrimitive%2Fv2/attempts/diff?from=9&to=2"
    ))
    .await;
    assert_eq!(status, 404);
    assert!(
        body["message"].as_str().unwrap_or("").contains("Attempt 9"),
        "the from side is named too, got: {body}"
    );

    // An attempt the join *does* find — a patch record naming a branch
    // the repository no longer holds — is the same honest 404, never a
    // 500 and never an empty diff.
    let patch_dir = fixture
        .repo_path()
        .join("re")
        .join("patches")
        .join("game_logic.dll")
        .join("DrawPrimitive");
    std::fs::write(
        patch_dir.join("v4.json"),
        serde_json::json!({
            "binary": "game_logic.dll",
            "function": "DrawPrimitive",
            "attempt": 4,
            "branch_name": "re/game_logic.dll/DrawPrimitivev4",
            "committed_at": "2025-09-29T09:00:00Z",
            "error_message": "",
            "compilation_errors": [],
            "test_failures": [],
            "commit_hash": "ghi789"
        })
        .to_string(),
    )
    .expect("record naming a branch the repo lacks");
    let (status, body) = get_json(&format!(
        "{base}/api/units/game_logic.dll%2FDrawPrimitive%2Fv2/attempts/diff?from=1&to=4"
    ))
    .await;
    assert_eq!(
        status, 404,
        "a branch the join names but the repo lacks is an honest 404"
    );
    assert!(
        body["message"].as_str().unwrap_or("").contains("Attempt 4"),
        "the error names the attempt whose branch is gone, got: {body}"
    );

    // A non-numeric attempt number answers 400 naming the accepted shape.
    let (status, body) = get_json(&format!(
        "{base}/api/units/game_logic.dll%2FDrawPrimitive%2Fv2/attempts/diff?from=one&to=2"
    ))
    .await;
    assert_eq!(status, 400, "a non-numeric attempt is a 400");
    assert!(
        body["message"]
            .as_str()
            .unwrap_or("")
            .contains("?from=1&to=2"),
        "the 400 names the accepted shape, got: {body}"
    );
}

// ── Headless browser test: Faults view (issue #125) ────────────────────

/// The Faults tab renders the fixture log honestly: summary cards,
/// per-binary bars, a trend line, the table — and the category filter
/// narrows everything. The CSV builder (exposed as
/// `window.calxglossFaultsCsv`) is pinned against the same fixture.
///
/// Run with: `cargo test --features server --test e2e headless -- --ignored`
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Chromium/Chrome installed; run with --ignored"]
async fn test_headless_faults_view_renders_filters_and_exports() {
    let fixture = TestFixture::new();
    write_fault_log_fixture(&fixture.repo_path(), &sample_fault_entries());
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let browser = launch_headless_browser();
    let tab = open_dashboard_tab(&browser, fixture.port());

    // Switch to the Faults tab.
    tab.evaluate(
        "document.querySelector('.nav-tab[data-view=\"faults\"]')?.click() === undefined",
        false,
    )
    .expect("click faults tab");

    // The fixture log renders: 6 rows in the table.
    let mut loaded = false;
    for _ in 0..25 {
        if eval_count(
            &tab,
            "document.querySelectorAll('#faults-table-body tr').length",
        ) == 6
        {
            loaded = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(loaded, "faults view should render the 6 fixture entries");

    // Summary cards, per-binary bars, and the trend line all render.
    assert_eq!(
        eval_count(
            &tab,
            "document.querySelectorAll('#faults-summary-cards .status-card').length"
        ),
        9,
        "fixture log should render total + 5 category + 3 severity cards"
    );
    assert_eq!(
        eval_count(
            &tab,
            "document.querySelectorAll('#faults-binary-bars .fault-bar-row').length"
        ),
        2,
        "fixture log should render 2 per-binary bars"
    );
    assert_eq!(
        eval_count(
            &tab,
            "document.querySelectorAll('#faults-trend polyline').length"
        ),
        2,
        "trend should render a count line and a moving-average line"
    );
    assert_eq!(
        eval_count(
            &tab,
            "document.querySelector('#faults-trend polyline').getAttribute('points').split(' ').length"
        ),
        4,
        "trend should span the 4 day buckets from 10-01 to 10-04"
    );

    // The CSV builder (the export button's data source) is pinned against
    // the fixture: header + 6 rows, with the recovery verbatim.
    let csv = eval_text(&tab, "window.calxglossFaultsCsv()");
    let lines: Vec<&str> = csv.lines().collect();
    assert_eq!(
        lines.first().copied().unwrap_or(""),
        "category,severity,binary,function,attempt,strategy,timestamp,recovery",
        "CSV header should name every fault field"
    );
    assert_eq!(lines.len(), 7, "CSV should carry header + 6 fault rows");
    assert!(
        lines.iter().any(|l| l.contains("hallucination")
            && l.contains("1790812920")
            && l.contains("recovery guidance for DrawSprite")),
        "a CSV row should carry the attempt identity and recovery verbatim: {lines:?}"
    );

    // The category filter narrows the table to the two hallucinations.
    tab.evaluate(
        r#"(() => {
            const select = document.getElementById('faults-filter-category');
            select.value = 'hallucination';
            select.dispatchEvent(new Event('change'));
        })()"#,
        false,
    )
    .expect("set category filter");
    let mut filtered = false;
    for _ in 0..25 {
        if eval_count(
            &tab,
            "document.querySelectorAll('#faults-table-body tr').length",
        ) == 2
        {
            filtered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        filtered,
        "the category filter should narrow the table to the hallucinations"
    );
}

/// With no fault log at all, the Faults tab says so plainly — no wall of
/// zeros, no error.
///
/// Run with: `cargo test --features server --test e2e headless -- --ignored`
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Chromium/Chrome installed; run with --ignored"]
async fn test_headless_faults_view_honest_empty_state() {
    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let browser = launch_headless_browser();
    let tab = open_dashboard_tab(&browser, fixture.port());

    // Switch to the Faults tab.
    tab.evaluate(
        "document.querySelector('.nav-tab[data-view=\"faults\"]')?.click() === undefined",
        false,
    )
    .expect("click faults tab");

    let mut empty_visible = false;
    for _ in 0..25 {
        if tab
            .evaluate(
                "document.getElementById('faults-empty').style.display === 'flex'",
                false,
            )
            .ok()
            .and_then(|r| r.value)
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            empty_visible = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        empty_visible,
        "a missing fault log should show the honest empty state"
    );

    assert!(
        tab.evaluate(
            "document.getElementById('faults-body').style.display === 'none'",
            false
        )
        .ok()
        .and_then(|r| r.value)
        .and_then(|v| v.as_bool())
        .unwrap_or(false),
        "the empty state should hide the body — no wall of zeros"
    );
}

// ── Headless browser tests: Token Usage view (issue #126) ──────────────

/// The Token Usage tab renders the fixture log honestly: summary split
/// cards, per-binary bars with shares, per-tier bars, the per-strategy
/// table with success rates — and the time-range selector re-renders in
/// place. The cost panel computes from the operator-typed price, persists
/// it in localStorage, and survives a reload.
///
/// The fixture timestamps are relative to now so the 7-day window keeps
/// holding exactly one attempt whenever the test runs.
///
/// Run with: `cargo test --features server --test e2e headless -- --ignored`
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Chromium/Chrome installed; run with --ignored"]
async fn test_headless_token_usage_view_renders_cost_and_time_range() {
    let fixture = TestFixture::new();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock after epoch")
        .as_secs();
    write_token_usage_fixture(
        &fixture.repo_path(),
        &[
            token_usage_entry(
                "game_logic.dll",
                "DrawSprite",
                1,
                "initial",
                4_000,
                true,
                "stub",
                now - 3_600,
            ),
            token_usage_entry(
                "d3d9.dll",
                "UpdateScene",
                1,
                "stale_strategy",
                6_000,
                false,
                "module_context",
                now - 40 * 86_400,
            ),
        ],
    );
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let browser = launch_headless_browser();
    let tab = open_dashboard_tab(&browser, fixture.port());

    // Switch to the Token Usage tab.
    tab.evaluate(
        "document.querySelector('.nav-tab[data-view=\"token-usage\"]')?.click() === undefined",
        false,
    )
    .expect("click token usage tab");

    // The fixture log renders: both attempts in the strategy table.
    let mut loaded = false;
    for _ in 0..25 {
        if eval_count(
            &tab,
            "document.querySelectorAll('#token-usage-strategy-body tr').length",
        ) == 2
        {
            loaded = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        loaded,
        "token usage view should render both fixture attempts"
    );

    // Summary split, per-binary bars, per-tier bars all render.
    assert_eq!(
        eval_count(
            &tab,
            "document.querySelectorAll('#token-usage-summary-cards .status-card').length"
        ),
        3,
        "fixture log should render total + successful + failed cards"
    );
    assert_eq!(
        eval_count(
            &tab,
            "document.querySelectorAll('#token-usage-binary-bars .token-bar-row').length"
        ),
        2,
        "fixture log should render 2 per-binary bars"
    );
    assert_eq!(
        eval_count(
            &tab,
            "document.querySelectorAll('#token-usage-tier-bars .token-bar-row').length"
        ),
        2,
        "fixture log should render 2 per-tier bars"
    );
    assert!(
        eval_text(
            &tab,
            "document.querySelector('#token-usage-binary-bars .token-bar-share').textContent"
        )
        .contains('%'),
        "per-binary bars should carry percentage shares"
    );

    // The cost panel: typing a price computes the estimate client-side
    // from the fetched totals — 10 000 tokens at $100/1M is $1.00.
    tab.evaluate(
        r#"(() => {
            const input = document.getElementById('token-usage-cost-price');
            input.value = '100';
            input.dispatchEvent(new Event('input'));
        })()"#,
        false,
    )
    .expect("type pricing");
    assert_eq!(
        eval_text(
            &tab,
            "document.getElementById('token-usage-cost-total').textContent"
        ),
        "$1.00",
        "the cost panel should compute the estimate from the typed price"
    );

    // The pricing persists in localStorage and survives a reload.
    assert_eq!(
        eval_text(&tab, "localStorage.getItem('calxgloss_token_pricing')"),
        "100",
        "the typed price should persist in localStorage"
    );
    tab.reload(false, None).expect("reload dashboard");
    tab.evaluate(
        "document.querySelector('.nav-tab[data-view=\"token-usage\"]')?.click() === undefined",
        false,
    )
    .expect("click token usage tab after reload");
    let mut cost_restored = false;
    for _ in 0..25 {
        if eval_text(
            &tab,
            "document.getElementById('token-usage-cost-total')?.textContent",
        ) == "$1.00"
        {
            cost_restored = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        cost_restored,
        "the persisted price should re-estimate the cost after a reload"
    );

    // The time-range filter re-renders in place: 7 days keeps only the
    // recent attempt.
    tab.evaluate(
        r#"(() => {
            const select = document.getElementById('token-usage-filter-range');
            select.value = '7d';
            select.dispatchEvent(new Event('change'));
        })()"#,
        false,
    )
    .expect("set time range filter");
    let mut narrowed = false;
    for _ in 0..25 {
        if eval_count(
            &tab,
            "document.querySelectorAll('#token-usage-strategy-body tr').length",
        ) == 1
        {
            narrowed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        narrowed,
        "the 7-day range should narrow the view to the recent attempt"
    );
    assert_eq!(
        eval_text(
            &tab,
            "document.getElementById('token-usage-cost-total').textContent"
        ),
        "$0.40",
        "the cost estimate should follow the filtered totals without a reload"
    );
}

/// With no token usage log at all — or a corrupt one — the Token Usage tab
/// says so plainly: no wall of zeros, no error.
///
/// Run with: `cargo test --features server --test e2e headless -- --ignored`
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Chromium/Chrome installed; run with --ignored"]
async fn test_headless_token_usage_view_honest_empty_state() {
    for kind in ["missing", "corrupt"] {
        let fixture = TestFixture::new();
        if kind == "corrupt" {
            let dir = fixture.repo_path().join("re").join("analysis");
            std::fs::create_dir_all(&dir).expect("analysis dir exists");
            std::fs::write(dir.join("token_usage.json"), "{ not json")
                .expect("corrupt log written");
        }
        let state = ServerState::new(fixture.repo_path());
        let router = build_router(state);
        let _server = spawn_server(router, fixture.port()).await;

        tokio::time::sleep(Duration::from_millis(200)).await;

        let browser = launch_headless_browser();
        let tab = open_dashboard_tab(&browser, fixture.port());

        // Switch to the Token Usage tab.
        tab.evaluate(
            "document.querySelector('.nav-tab[data-view=\"token-usage\"]')?.click() === undefined",
            false,
        )
        .expect("click token usage tab");

        let mut empty_visible = false;
        for _ in 0..25 {
            if tab
                .evaluate(
                    "document.getElementById('token-usage-empty').style.display === 'flex'",
                    false,
                )
                .ok()
                .and_then(|r| r.value)
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
            {
                empty_visible = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        assert!(
            empty_visible,
            "a {kind} token usage log should show the honest empty state"
        );

        assert!(
            tab.evaluate(
                "document.getElementById('token-usage-body').style.display === 'none'",
                false
            )
            .ok()
            .and_then(|r| r.value)
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
            "the empty state should hide the body — no wall of zeros"
        );
    }
}

// ── Headless browser test: Strategy Analytics view (issue #127) ─────────

/// The Strategy Analytics tab renders the fixture log honestly: the
/// per-strategy table with attempts, successes, failures, and pass rate,
/// and the per-category pass-rate bars — and the time-range selector
/// re-renders in place. The CSV builder (exposed as
/// `window.calxglossStrategyCsv`) is pinned against the same fixture.
///
/// The fixture timestamps are relative to now so the 7-day window keeps
/// holding exactly the two recent attempts whenever the test runs.
///
/// Run with: `cargo test --features server --test e2e headless -- --ignored`
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Chromium/Chrome installed; run with --ignored"]
async fn test_headless_strategy_analytics_view_renders_filter_and_exports() {
    let fixture = TestFixture::new();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock after epoch")
        .as_secs();
    write_strategy_fixture(
        &fixture.repo_path(),
        &[
            strategy_entry(
                "game_logic.dll",
                "ProjectSpecific",
                "initial",
                false,
                1,
                now - 3_600,
            ),
            strategy_entry(
                "game_logic.dll",
                "ProjectSpecific",
                "compile_fix",
                true,
                2,
                now - 3_540,
            ),
            strategy_entry(
                "d3d9.dll",
                "KnownThirdParty",
                "stale_strategy",
                false,
                1,
                now - 40 * 86_400,
            ),
        ],
    );
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let browser = launch_headless_browser();
    let tab = open_dashboard_tab(&browser, fixture.port());

    // Switch to the Strategy Analytics tab.
    tab.evaluate(
        "document.querySelector('.nav-tab[data-view=\"strategy-analytics\"]')?.click() === undefined",
        false,
    )
    .expect("click strategy analytics tab");

    // The fixture log renders: all three attempts across three strategies.
    let mut loaded = false;
    for _ in 0..25 {
        if eval_count(
            &tab,
            "document.querySelectorAll('#strategy-analytics-strategy-body tr').length",
        ) == 3
        {
            loaded = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        loaded,
        "strategy analytics view should render all three fixture attempts"
    );

    // The per-category bars render — one per binary category the log names.
    assert_eq!(
        eval_count(
            &tab,
            "document.querySelectorAll('#strategy-analytics-category-bars .token-bar-row').length"
        ),
        2,
        "fixture log should render 2 per-category bars"
    );
    assert!(
        eval_text(&tab, "document.querySelector('#strategy-analytics-category-bars .token-bar-share').textContent")
            .contains('%'),
        "per-category bars should carry pass rates"
    );

    // The CSV export: exact rows from the fetched JSON — the per-strategy
    // breakdown (all three strategies tie at one attempt, so they sort
    // alphabetically), then the per-category breakdown.
    let csv = eval_text(&tab, "window.calxglossStrategyCsv()");
    assert_eq!(
        csv,
        "strategy,attempts,successes,failures,pass_rate\n\
         compile_fix,1,1,0,100\n\
         initial,1,0,1,0\n\
         stale_strategy,1,0,1,0\n\
         \n\
         category,attempts,successes,failures,pass_rate\n\
         ProjectSpecific,2,1,1,50\n\
         KnownThirdParty,1,0,1,0",
        "the CSV should carry both filtered breakdowns verbatim"
    );

    // The time-range filter re-renders in place: 7 days drops the stale
    // attempt from both the table and the bars.
    tab.evaluate(
        r#"(() => {
            const select = document.getElementById('strategy-analytics-filter-range');
            select.value = '7d';
            select.dispatchEvent(new Event('change'));
        })()"#,
        false,
    )
    .expect("set time range filter");
    let mut narrowed = false;
    for _ in 0..25 {
        if eval_count(
            &tab,
            "document.querySelectorAll('#strategy-analytics-strategy-body tr').length",
        ) == 2
        {
            narrowed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        narrowed,
        "the 7-day range should narrow the view to the recent attempts"
    );
    assert_eq!(
        eval_count(
            &tab,
            "document.querySelectorAll('#strategy-analytics-category-bars .token-bar-row').length"
        ),
        1,
        "the 7-day range should drop the out-of-range category bar"
    );
}

/// With no prompt-strategy log at all — or a corrupt one — the Strategy
/// Analytics tab says so plainly: no wall of zeros, no error.
///
/// Run with: `cargo test --features server --test e2e headless -- --ignored`
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Chromium/Chrome installed; run with --ignored"]
async fn test_headless_strategy_analytics_view_honest_empty_state() {
    for kind in ["missing", "corrupt"] {
        let fixture = TestFixture::new();
        if kind == "corrupt" {
            let dir = fixture.repo_path().join("re").join("analysis");
            std::fs::create_dir_all(&dir).expect("analysis dir exists");
            std::fs::write(dir.join("prompt_strategy_log.json"), "{ not json")
                .expect("corrupt log written");
        }
        let state = ServerState::new(fixture.repo_path());
        let router = build_router(state);
        let _server = spawn_server(router, fixture.port()).await;

        tokio::time::sleep(Duration::from_millis(200)).await;

        let browser = launch_headless_browser();
        let tab = open_dashboard_tab(&browser, fixture.port());

        // Switch to the Strategy Analytics tab.
        tab.evaluate(
            "document.querySelector('.nav-tab[data-view=\"strategy-analytics\"]')?.click() === undefined",
            false,
        )
        .expect("click strategy analytics tab");

        let mut empty_visible = false;
        for _ in 0..25 {
            if tab
                .evaluate(
                    "document.getElementById('strategy-analytics-empty').style.display === 'flex'",
                    false,
                )
                .ok()
                .and_then(|r| r.value)
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
            {
                empty_visible = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        assert!(
            empty_visible,
            "a {kind} prompt-strategy log should show the honest empty state"
        );

        assert!(
            tab.evaluate(
                "document.getElementById('strategy-analytics-body').style.display === 'none'",
                false
            )
            .ok()
            .and_then(|r| r.value)
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
            "the empty state should hide the body — no wall of zeros"
        );
    }
}

/// The LLM Metrics tab renders the fixture logs honestly: percentile
/// cards labeled as attempt wall-clock, the timeout trend, and the
/// per-tier table — with an unmeasured tier rendering an em dash, never
/// a fabricated number. The time-range filter re-renders in place.
///
/// Run with: `cargo test --features server --test e2e headless -- --ignored`
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Chromium/Chrome installed; run with --ignored"]
async fn test_headless_llm_metrics_view_renders_percentiles_and_filter() {
    let fixture = TestFixture::new();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock after epoch")
        .as_secs();
    write_token_usage_fixture(
        &fixture.repo_path(),
        &[
            llm_metrics_token_entry(
                "game_logic.dll",
                "DrawSprite",
                1,
                "initial",
                4000,
                false,
                "stub",
                now - 3_600,
                Some(10),
            ),
            llm_metrics_token_entry(
                "game_logic.dll",
                "DrawSprite",
                2,
                "compile_fix",
                3000,
                true,
                "stub",
                now - 3_540,
                Some(30),
            ),
            llm_metrics_token_entry(
                "game_logic.dll",
                "DrawSprite",
                3,
                "escalate",
                8000,
                false,
                "unmeasured_tier",
                now - 3_500,
                None,
            ),
            llm_metrics_token_entry(
                "d3d9.dll",
                "UpdateScene",
                1,
                "initial",
                2000,
                true,
                "stale_tier",
                now - 40 * 86_400,
                Some(90),
            ),
        ],
    );
    write_fault_log_fixture(
        &fixture.repo_path(),
        &[resource_exhaustion_fault_entry(
            "game_logic.dll",
            "DrawSprite",
            3,
            "escalate",
            "timeout",
            now - 3_600,
        )],
    );
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let browser = launch_headless_browser();
    let tab = open_dashboard_tab(&browser, fixture.port());

    // Switch to the LLM Metrics tab.
    tab.evaluate(
        "document.querySelector('.nav-tab[data-view=\"llm-metrics\"]')?.click() === undefined",
        false,
    )
    .expect("click llm metrics tab");

    // The fixture renders: four cards (P50/P95/P99 + timeouts).
    let mut loaded = false;
    for _ in 0..25 {
        if eval_count(
            &tab,
            "document.querySelectorAll('#llm-metrics-summary-cards .status-card').length",
        ) == 4
        {
            loaded = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        loaded,
        "llm metrics view should render the percentile cards — last P50 read: {}",
        eval_text(
            &tab,
            "document.querySelector('#llm-metrics-summary-cards .status-card .status-card-value')?.textContent || ''"
        )
    );

    // All-time percentiles over the measured durations 10/30/90:
    // nearest-rank P50 is 30 — the unmeasured attempt never joins the math.
    assert_eq!(
        eval_text(
            &tab,
            "document.querySelector('#llm-metrics-summary-cards .status-card .status-card-value').textContent"
        ),
        "30s",
        "the P50 card should pin the nearest-rank percentile of the measured durations"
    );

    // Honest labeling: the note spells out that durations are attempt
    // wall-clock (compile and tests included), never per-call latency.
    assert!(
        eval_text(&tab, "document.querySelector('#view-llm-metrics .llm-metrics-note:last-of-type')?.textContent || ''")
            .contains("compile and tests included"),
        "the view must label durations as attempt-level wall-clock"
    );

    // The timeout trend renders its SVG from the server's buckets.
    assert_eq!(
        eval_count(
            &tab,
            "document.querySelectorAll('#llm-metrics-timeout-trend svg').length"
        ),
        1,
        "the timeout trend should render from the fixture fault"
    );

    // The per-tier table: stub (2), stale_tier (1), unmeasured_tier (1) —
    // and the unmeasured tier's percentiles are em dashes, never numbers.
    let mut tiers_rendered = false;
    for _ in 0..25 {
        if eval_count(
            &tab,
            "document.querySelectorAll('#llm-metrics-tier-body tr').length",
        ) == 3
        {
            tiers_rendered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(tiers_rendered, "the tier table should render three tiers");
    assert_eq!(
        eval_text(
            &tab,
            "document.querySelector('#llm-metrics-tier-body tr:last-child td:last-child').textContent"
        ),
        "—",
        "an unmeasured tier renders an em dash, never a fabricated number"
    );

    // The time-range filter re-renders in place: 7 days drops the stale
    // attempt — the P50 recomputes to 10s and the stale tier row is gone.
    tab.evaluate(
        r#"(() => {
            const select = document.getElementById('llm-metrics-filter-range');
            select.value = '7d';
            select.dispatchEvent(new Event('change'));
        })()"#,
        false,
    )
    .expect("set time range filter");
    let mut narrowed = false;
    for _ in 0..25 {
        if eval_count(
            &tab,
            "document.querySelectorAll('#llm-metrics-tier-body tr').length",
        ) == 2
        {
            narrowed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        narrowed,
        "the 7-day range should narrow the tier table to the recent attempts"
    );
    assert_eq!(
        eval_text(
            &tab,
            "document.querySelector('#llm-metrics-summary-cards .status-card .status-card-value').textContent"
        ),
        "10s",
        "the 7-day range should recompute the P50 in place"
    );
}

/// With no token usage log at all — or a corrupt one — the LLM Metrics
/// tab says so plainly: no wall of zeros, no error.
///
/// Run with: `cargo test --features server --test e2e headless -- --ignored`
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Chromium/Chrome installed; run with --ignored"]
async fn test_headless_llm_metrics_view_honest_empty_state() {
    for kind in ["missing", "corrupt"] {
        let fixture = TestFixture::new();
        if kind == "corrupt" {
            let dir = fixture.repo_path().join("re").join("analysis");
            std::fs::create_dir_all(&dir).expect("analysis dir exists");
            std::fs::write(dir.join("token_usage.json"), "{ not json")
                .expect("corrupt log written");
        }
        let state = ServerState::new(fixture.repo_path());
        let router = build_router(state);
        let _server = spawn_server(router, fixture.port()).await;

        tokio::time::sleep(Duration::from_millis(200)).await;

        let browser = launch_headless_browser();
        let tab = open_dashboard_tab(&browser, fixture.port());

        // Switch to the LLM Metrics tab.
        tab.evaluate(
            "document.querySelector('.nav-tab[data-view=\"llm-metrics\"]')?.click() === undefined",
            false,
        )
        .expect("click llm metrics tab");

        let mut empty_visible = false;
        for _ in 0..25 {
            if tab
                .evaluate(
                    "document.getElementById('llm-metrics-empty').style.display === 'flex'",
                    false,
                )
                .ok()
                .and_then(|r| r.value)
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
            {
                empty_visible = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        assert!(
            empty_visible,
            "a {kind} token usage log should show the honest empty state"
        );

        assert!(
            tab.evaluate(
                "document.getElementById('llm-metrics-body').style.display === 'none'",
                false
            )
            .ok()
            .and_then(|r| r.value)
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
            "the empty state should hide the body — no wall of zeros"
        );
    }
}

/// The Binaries tab renders the fixture's classified binaries as rows:
/// the override chip on the overridden row, the function counts, and the
/// token totals — all read straight from the persisted history.
///
/// Run with: `cargo test --features server --test e2e headless -- --ignored`
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Chromium/Chrome installed; run with --ignored"]
async fn test_headless_binaries_view_renders_rows() {
    let fixture = TestFixture::new();
    write_binaries_list_fixtures(&fixture);
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let browser = launch_headless_browser();
    let tab = open_dashboard_tab(&browser, fixture.port());

    // Switch to the Binaries tab.
    tab.evaluate(
        "document.querySelector('.nav-tab[data-view=\"binaries\"]')?.click() === undefined",
        false,
    )
    .expect("click binaries tab");

    // Two rows — the corrupt classification record never becomes one.
    let mut rows_rendered = false;
    for _ in 0..25 {
        if eval_count(
            &tab,
            "document.querySelectorAll('#binaries-table-body tr').length",
        ) == 2
        {
            rows_rendered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        rows_rendered,
        "both classified binaries should render as rows"
    );

    // Alphabetical: d3d9.dll first, carrying the override chip.
    assert_eq!(
        eval_text(
            &tab,
            "document.querySelector('#binaries-table-body tr td').textContent"
        ),
        "d3d9.dll",
        "rows sort alphabetically by binary name"
    );
    assert!(
        eval_bool(
            &tab,
            "document.querySelector('#binaries-table-body tr').textContent.includes('overridden')"
        ),
        "the overridden row carries the override chip"
    );

    // The token total renders with its thousands separator, and the
    // function counts land in the game_logic.dll row.
    assert!(
        eval_bool(
            &tab,
            "document.querySelector('#binaries-table-body').textContent.includes('175')"
        ),
        "the case-insensitive token join shows game_logic.dll's 175 tokens"
    );
}

/// With no readable classification records — the fixture's own minimal
/// ones carry no `binary` field — the Binaries tab says so plainly: no
/// empty table shell, no wall of zeros, no error.
///
/// Run with: `cargo test --features server --test e2e headless -- --ignored`
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Chromium/Chrome installed; run with --ignored"]
async fn test_headless_binaries_view_honest_empty_state() {
    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let browser = launch_headless_browser();
    let tab = open_dashboard_tab(&browser, fixture.port());

    // Switch to the Binaries tab.
    tab.evaluate(
        "document.querySelector('.nav-tab[data-view=\"binaries\"]')?.click() === undefined",
        false,
    )
    .expect("click binaries tab");

    let mut empty_visible = false;
    for _ in 0..25 {
        if eval_bool(
            &tab,
            "document.getElementById('binaries-empty').style.display === 'flex'",
        ) {
            empty_visible = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        empty_visible,
        "no readable classification records should show the honest empty state"
    );

    assert!(
        eval_bool(
            &tab,
            "document.getElementById('binaries-body').style.display === 'none'"
        ),
        "the empty state should hide the table — no wall of zeros"
    );
}

/// Issue #132: clicking a fixture row expands the detail panel beneath it
/// — the classification decision in force (override applied) with its
/// reasoning and symbol counts, the per-function list with each
/// unit's review status, and the shortcut to the existing
/// classification-override flow.
///
/// Run with: `cargo test --features server --test e2e headless -- --ignored`
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Chromium/Chrome installed; run with --ignored"]
async fn test_headless_binaries_detail_panel_expands() {
    let fixture = TestFixture::new();
    write_binaries_list_fixtures(&fixture);
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let browser = launch_headless_browser();
    let tab = open_dashboard_tab(&browser, fixture.port());

    // Switch to the Binaries tab and wait for the rows.
    tab.evaluate(
        "document.querySelector('.nav-tab[data-view=\"binaries\"]')?.click() === undefined",
        false,
    )
    .expect("click binaries tab");
    let mut rows_rendered = false;
    for _ in 0..25 {
        if eval_count(
            &tab,
            "document.querySelectorAll('#binaries-table-body tr.binaries-row').length",
        ) == 2
        {
            rows_rendered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        rows_rendered,
        "both classified binaries should render as rows"
    );

    // Click the first row — the overridden d3d9.dll.
    tab.evaluate(
        "document.querySelector('#binaries-table-body tr.binaries-row').click() === undefined",
        false,
    )
    .expect("click first binaries row");

    // The panel expands with the fetched detail (the spinner is replaced).
    let mut detail_rendered = false;
    for _ in 0..25 {
        if eval_bool(
            &tab,
            "document.querySelector('#binaries-table-body tr.binaries-detail-row')?.textContent.includes('KnownThirdParty') === true",
        ) {
            detail_rendered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        detail_rendered,
        "the expanded panel should show the override-in-force category"
    );

    let detail_text = eval_text(
        &tab,
        "document.querySelector('#binaries-table-body tr.binaries-detail-row').textContent",
    );
    for expected in [
        "operator override — KnownThirdParty", // the in-force reason, as the analyzer spells it
        "Exports: 100",
        "Imports: 5",
        "wgpu",                    // the binary's one function unit
        "Accepted",                // its review status
        "Override classification", // the shortcut to the existing flow
    ] {
        assert!(
            detail_text.contains(expected),
            "the detail panel should show {expected:?} — got: {detail_text}"
        );
    }

    // Exactly one function row, carrying its review status.
    assert_eq!(
        eval_count(
            &tab,
            "document.querySelectorAll('#binaries-table-body .binaries-detail-functions tbody tr').length",
        ),
        1,
        "d3d9.dll's one dashboard unit appears in the function list"
    );

    // The shortcut opens the existing classification-override panel —
    // anchored inside this view. Its endpoints are live-only, so under
    // plain `serve` it honestly reports itself unavailable rather than
    // rendering a blank or a fake form.
    tab.evaluate(
        "document.querySelector('#binaries-table-body .binaries-detail-override')?.click() === undefined",
        false,
    )
    .expect("click override shortcut");
    let mut override_panel = false;
    for _ in 0..25 {
        if eval_bool(
            &tab,
            "document.getElementById('classification-override-panel')?.textContent.includes('unavailable') === true",
        ) {
            override_panel = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        override_panel,
        "the shortcut should open the existing override panel, honestly \
         reporting unavailability under plain serve"
    );
}

/// Wait for the panel's shim tracker to finish its own read and render.
async fn wait_for_shim_tracker(tab: &headless_chrome::Tab, needle: &str) -> bool {
    let expr = format!(
        "document.querySelector('#binaries-table-body .binaries-detail-shim .binaries-shim-tracker')?.textContent.includes({needle:?}) === true"
    );
    for _ in 0..25 {
        if eval_bool(tab, &expr) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    false
}

/// Run with: `cargo test --features server --test e2e headless -- --ignored`
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Chromium/Chrome installed; run with --ignored"]
async fn test_headless_binaries_detail_shim_tracker() {
    let fixture = TestFixture::new();
    write_binaries_list_fixtures(&fixture);
    write_shim_tracker_fixtures(&fixture);
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let browser = launch_headless_browser();
    let tab = open_dashboard_tab(&browser, fixture.port());

    tab.evaluate(
        "document.querySelector('.nav-tab[data-view=\"binaries\"]')?.click() === undefined",
        false,
    )
    .expect("click binaries tab");
    let mut rows_rendered = false;
    for _ in 0..25 {
        if eval_count(
            &tab,
            "document.querySelectorAll('#binaries-table-body tr.binaries-row').length",
        ) == 3
        {
            rows_rendered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        rows_rendered,
        "all three classified binaries render as rows"
    );

    // Click the crate-replacement binary with artifacts — d3d9.dll.
    tab.evaluate(
        "document.querySelector('#binaries-table-body tr.binaries-row[data-binary=\"d3d9.dll\"]').click() === undefined",
        false,
    )
    .expect("click d3d9.dll row");

    assert!(
        wait_for_shim_tracker(&tab, "Mappings: 2").await,
        "the shim tracker should render from the persisted shim artifacts"
    );
    let tracker_text = eval_text(
        &tab,
        "document.querySelector('#binaries-table-body .binaries-detail-shim .binaries-shim-tracker').textContent",
    );
    for expected in [
        "Shim layer",
        "wgpu-rs",         // the crate the override in force names
        "Mappings: 2",     // from mappings.json
        "Compiled: yes",   // from verification.json
        "7/8",             // mapping test pass counts
        "2/2",             // edge test pass counts
        "re/shim/wgpu-rs", // the branch the dependency model names
        "merged",          // its acceptance state in the branch model
    ] {
        assert!(
            tracker_text.contains(expected),
            "the shim tracker should show {expected:?} — got: {tracker_text}"
        );
    }
}

/// Run with: `cargo test --features server --test e2e headless -- --ignored`
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Chromium/Chrome installed; run with --ignored"]
async fn test_headless_binaries_detail_shim_tracker_honest_states() {
    let fixture = TestFixture::new();
    write_binaries_list_fixtures(&fixture);
    write_shim_tracker_fixtures(&fixture);
    // A fourth binary: a crate replacement with no shim artifacts at all —
    // the honest "shim not generated" empty state.
    std::fs::write(
        fixture
            .repo_path()
            .join("re")
            .join("classify")
            .join("ogg.dll.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "binary": "ogg.dll",
            "category": "KnownThirdParty",
            "strategy": "CrateReplacement",
            "exports_count": 10,
            "imports_count": 1,
            "crate_replacement": "ogg-rs",
            "known_runtime": false,
            "reason": "audio codec — replaced with ogg-rs behind a shim layer"
        }))
        .unwrap(),
    )
    .expect("ogg classification written");
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let browser = launch_headless_browser();
    let tab = open_dashboard_tab(&browser, fixture.port());

    tab.evaluate(
        "document.querySelector('.nav-tab[data-view=\"binaries\"]')?.click() === undefined",
        false,
    )
    .expect("click binaries tab");
    let mut rows_rendered = false;
    for _ in 0..25 {
        if eval_count(
            &tab,
            "document.querySelectorAll('#binaries-table-body tr.binaries-row').length",
        ) == 4
        {
            rows_rendered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(rows_rendered, "all four classified binaries render as rows");

    // The reverse-engineered binary: honestly no shim expected.
    tab.evaluate(
        "document.querySelector('#binaries-table-body tr.binaries-row[data-binary=\"game_logic.dll\"]').click() === undefined",
        false,
    )
    .expect("click game_logic.dll row");
    assert!(
        wait_for_shim_tracker(&tab, "No shim expected").await,
        "a reverse-engineered binary's tracker honestly says no shim is expected"
    );

    // The crate-replacement binary whose shim was generated but whose
    // branch the reviewer sent back: both answers show side by side.
    tab.evaluate(
        "document.querySelector('#binaries-table-body tr.binaries-row[data-binary=\"fmod.dll\"]').click() === undefined",
        false,
    )
    .expect("click fmod.dll row");
    assert!(
        wait_for_shim_tracker(&tab, "Mappings: 2").await,
        "a crate-replacement binary with shim artifacts reports the generated mappings"
    );
    let tracker_text = eval_text(
        &tab,
        "document.querySelector('#binaries-table-body .binaries-detail-shim .binaries-shim-tracker').textContent",
    );
    assert!(
        tracker_text.contains("sent back"),
        "the mapping count and the sent-back branch verdict both show — got: {tracker_text}"
    );

    // The crate-replacement binary with no shim artifacts: the honest
    // empty state — not generated, no invented counts.
    tab.evaluate(
        "document.querySelector('#binaries-table-body tr.binaries-row[data-binary=\"ogg.dll\"]').click() === undefined",
        false,
    )
    .expect("click ogg.dll row");
    assert!(
        wait_for_shim_tracker(&tab, "Shim not generated").await,
        "a crate-replacement binary without shim artifacts honestly \
         reports shim not generated"
    );
    let tracker_text = eval_text(
        &tab,
        "document.querySelector('#binaries-table-body .binaries-detail-shim .binaries-shim-tracker').textContent",
    );
    assert!(
        !tracker_text.contains("Mappings:") && !tracker_text.contains("Branch re/"),
        "the empty state invents no mappings and no branch — got: {tracker_text}"
    );
}

/// Wait for the panel's PAL tracker to finish its own read and render.
async fn wait_for_pal_tracker(tab: &headless_chrome::Tab, needle: &str) -> bool {
    let expr = format!(
        "document.querySelector('#binaries-table-body .binaries-detail-pal .binaries-pal-tracker')?.textContent.includes({needle:?}) === true"
    );
    for _ in 0..25 {
        if eval_bool(tab, &expr) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    false
}

/// Issue #134: the fixture binary's detail panel shows its needed PAL
/// traits with at least one existing marker (GraphicsDevice — the
/// generated scratch PAL crate defines it) and one missing marker
/// (PlatformCore — nothing defines it).
///
/// Run with: `cargo test --features server --test e2e headless -- --ignored`
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Chromium/Chrome installed; run with --ignored"]
async fn test_headless_binaries_detail_pal_tracker() {
    let fixture = TestFixture::new();
    write_binaries_list_fixtures(&fixture);
    write_pal_tracker_fixtures(&fixture);
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let browser = launch_headless_browser();
    let tab = open_dashboard_tab(&browser, fixture.port());

    tab.evaluate(
        "document.querySelector('.nav-tab[data-view=\"binaries\"]')?.click() === undefined",
        false,
    )
    .expect("click binaries tab");
    let mut rows_rendered = false;
    for _ in 0..25 {
        if eval_count(
            &tab,
            "document.querySelectorAll('#binaries-table-body tr.binaries-row').length",
        ) == 2
        {
            rows_rendered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(rows_rendered, "both classified binaries render as rows");

    // Click the binary with API-call artifacts — d3d9.dll.
    tab.evaluate(
        "document.querySelector('#binaries-table-body tr.binaries-row[data-binary=\"d3d9.dll\"]').click() === undefined",
        false,
    )
    .expect("click d3d9.dll row");

    assert!(
        wait_for_pal_tracker(&tab, "GraphicsDevice").await,
        "the PAL tracker should render the traits derived from the \
         persisted API-call categories"
    );
    let tracker_text = eval_text(
        &tab,
        "document.querySelector('#binaries-table-body .binaries-detail-pal .binaries-pal-tracker').textContent",
    );
    for expected in [
        "PAL traits",
        "GraphicsDevice", // derived from the DirectX and DirectX11 categories
        "exists",         // the scratch PAL crate defines it
        "PlatformCore",   // derived from the Win32Core category
        "missing",        // nothing in the workspace defines it
        "DirectX",        // the categories that demanded the trait
        "Win32Core",
    ] {
        assert!(
            tracker_text.contains(expected),
            "the PAL tracker should show {expected:?} — got: {tracker_text}"
        );
    }

    // The markers are the two traits' own states, not one global flag:
    // exactly one exists chip and one missing chip render.
    assert_eq!(
        eval_count(
            &tab,
            "document.querySelectorAll('#binaries-table-body .binaries-pal-trait[data-state=\"exists\"]').length",
        ),
        1,
        "one needed trait exists in the generated PAL source"
    );
    assert_eq!(
        eval_count(
            &tab,
            "document.querySelectorAll('#binaries-table-body .binaries-pal-trait[data-state=\"missing\"]').length",
        ),
        1,
        "one needed trait is visibly missing"
    );
}

/// Issue #134: a binary with no persisted API-call artifacts shows the
/// honest empty state — no fabricated trait list.
///
/// Run with: `cargo test --features server --test e2e headless -- --ignored`
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Chromium/Chrome installed; run with --ignored"]
async fn test_headless_binaries_detail_pal_tracker_honest_empty_state() {
    let fixture = TestFixture::new();
    write_binaries_list_fixtures(&fixture);
    write_pal_tracker_fixtures(&fixture);
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let browser = launch_headless_browser();
    let tab = open_dashboard_tab(&browser, fixture.port());

    tab.evaluate(
        "document.querySelector('.nav-tab[data-view=\"binaries\"]')?.click() === undefined",
        false,
    )
    .expect("click binaries tab");
    let mut rows_rendered = false;
    for _ in 0..25 {
        if eval_count(
            &tab,
            "document.querySelectorAll('#binaries-table-body tr.binaries-row').length",
        ) == 2
        {
            rows_rendered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(rows_rendered, "both classified binaries render as rows");

    // The reverse-engineered binary has no per-function analysis artifacts.
    tab.evaluate(
        "document.querySelector('#binaries-table-body tr.binaries-row[data-binary=\"game_logic.dll\"]').click() === undefined",
        false,
    )
    .expect("click game_logic.dll row");

    assert!(
        wait_for_pal_tracker(&tab, "No PAL traits derived").await,
        "a binary without API-call artifacts honestly says no traits \
         were derived"
    );
    assert_eq!(
        eval_count(
            &tab,
            "document.querySelectorAll('#binaries-table-body .binaries-pal-trait').length",
        ),
        0,
        "the empty state fabricates no trait rows"
    );
}

/// Issue #327 AC1/AC5: with the settings-backed actions backend wired in,
/// `POST /api/units/{id}/patch` drives the real assembled request — the
/// review UI's double-click creates the next-attempt branch and patch record
/// for real, and the retry task is assembled from the description (its LLM
/// endpoint here is a dead port, so the background retry fails on its own;
/// the response and the on-disk artifacts prove the request ran the real
/// path, not the retired canned response).
#[tokio::test]
async fn test_patch_request_with_actions_backend_creates_branch_and_record() {
    let fixture = TestFixture::new();

    // A target dir holding the Kuna-loadable fixture binary under the unit's
    // name, so the request's engine load succeeds.
    let target = tempfile::tempdir().expect("target dir");
    let fixture_bin = calxgloss_testfixtures::fixture_target_path().expect("fixture target path");
    std::fs::copy(fixture_bin, target.path().join("game_logic.dll"))
        .expect("copy fixture binary under the unit's name");

    let state = ServerState::new(fixture.repo_path());
    let spec = PipelineSpec {
        llm: Some(calxgloss_translator::assembly::LlmSelection::Description(
            calxgloss_translator::assembly::LlmDescription {
                endpoint: "http://127.0.0.1:1/v1/chat/completions".to_string(),
                model: "fixture-model".to_string(),
                api_key: None,
                context_window: Some(128_000),
                temperature: None,
                timeout_secs: Some(2),
            },
        )),
        ..PipelineSpec::default()
    };
    let actions =
        ActionsState::new(fixture.repo_path(), spec).with_target_dir(target.path().to_path_buf());
    let router = build_router_with_actions(state, actions);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let unit_id = "game_logic.dll/DrawPrimitive/v2";
    let encoded_id = urlencoding::encode(unit_id);
    let resp = reqwest::Client::new()
        .post(format!(
            "http://127.0.0.1:{}/api/units/{}/patch",
            fixture.port(),
            encoded_id
        ))
        .json(&serde_json::json!({"issue": "off-by-one in loop bound"}))
        .send()
        .await
        .expect("patch request reaches server");

    assert_eq!(resp.status(), 200, "the assembled request succeeds");
    let body: serde_json::Value = resp.json().await.expect("patch body is JSON");
    assert_eq!(body["action"], "patch_requested");
    assert_eq!(
        body["branch_name"], "re/game_logic.dll/DrawPrimitivev3",
        "the next-attempt branch is named in the response"
    );

    // The branch really exists and the patch record really landed — the
    // request walked the real create-and-record path.
    let repo_path = fixture.repo_path();
    let git = GitManager::open(&repo_path).expect("open git");
    let branches = git.list_translation_branches().expect("list branches");
    assert!(
        branches.contains(&"re/game_logic.dll/DrawPrimitivev3".to_string()),
        "the v3 branch exists: {branches:?}"
    );
    let record_path = fixture
        .repo_path()
        .join("re")
        .join("patches")
        .join("game_logic.dll")
        .join("DrawPrimitive")
        .join("v3.json");
    let record: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(record_path).expect("v3 patch record"))
            .expect("v3 record json");
    assert_eq!(record["patch_request"], "off-by-one in loop bound");
}

/// Issue #327 AC1: the canned "patch requested" response is gone. A router
/// built without the settings-backed actions backend honestly refuses a patch
/// request instead of pretending a retry started.
#[tokio::test]
async fn test_patch_without_actions_backend_refuses_instead_of_fabricating() {
    let fixture = TestFixture::new();
    let router = build_router(ServerState::new(fixture.repo_path()));
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let unit_id = "game_logic.dll/DrawPrimitive/v2";
    let encoded_id = urlencoding::encode(unit_id);
    let resp = reqwest::Client::new()
        .post(format!(
            "http://127.0.0.1:{}/api/units/{}/patch",
            fixture.port(),
            encoded_id
        ))
        .json(&serde_json::json!({"issue": "off-by-one in loop bound"}))
        .send()
        .await
        .expect("patch request reaches server");

    assert_eq!(
        resp.status(),
        500,
        "no actions backend means an honest refusal, not a fabricated 200"
    );
    let body = resp.text().await.expect("error body");
    assert!(
        body.contains("actions backend"),
        "the refusal names the missing backend: {body}"
    );
}

/// Issue #327 AC6: a server started with no LLM settings carries an
/// actions backend whose description has no LLM selection, so a patch
/// request fails with the assembly seam's clear error at request time —
/// not a canned success and not a half-configured retry.
#[tokio::test]
async fn test_patch_without_llm_settings_reports_assembly_error() {
    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path());
    // Target dir configured, so the failing knob is specifically the missing
    // LLM selection: the seam builds the LLM before it ever touches a binary.
    let actions = ActionsState::new(fixture.repo_path(), PipelineSpec::default())
        .with_target_dir(fixture.repo_path());
    let router = build_router_with_actions(state, actions);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let unit_id = "game_logic.dll/DrawPrimitive/v2";
    let encoded_id = urlencoding::encode(unit_id);
    let resp = reqwest::Client::new()
        .post(format!(
            "http://127.0.0.1:{}/api/units/{}/patch",
            fixture.port(),
            encoded_id
        ))
        .json(&serde_json::json!({"issue": "off-by-one in loop bound"}))
        .send()
        .await
        .expect("patch request reaches server");

    assert_eq!(
        resp.status(),
        500,
        "a description with no LLM selection fails assembly, not the retry"
    );
    let body = resp.text().await.expect("error body");
    assert!(
        body.contains("cannot assemble a pass without an LLM"),
        "the response carries the seam's assembly error: {body}"
    );

    // Nothing half-created behind the failed request: no v3 attempt branch.
    let repo_path = fixture.repo_path();
    let git = GitManager::open(&repo_path).expect("open git");
    let v3_branches: Vec<_> = git
        .list_translation_branches()
        .expect("list branches")
        .into_iter()
        .filter(|b| b.ends_with("v3"))
        .collect();
    assert!(
        v3_branches.is_empty(),
        "a failed assembly must not leave a next-attempt branch: {v3_branches:?}"
    );
}

/// Integration test verifying that the full router with actions
/// can serve the dashboard.
#[tokio::test]
async fn test_actions_router_dashboard() {
    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path());
    let actions = ActionsState::new(fixture.repo_path(), PipelineSpec::default());
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
    let actions = ActionsState::new(fixture.repo_path(), PipelineSpec::default());
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
    let router = build_router_with_ws(state.clone(), manager, progress, ws_actions(&fixture));
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

/// Test the decompiler context endpoint returns not-found for units without analysis artifacts.
/// (Our fixture doesn't create engine data, so this should return not-found gracefully.)
#[tokio::test]
async fn test_unit_decomp_missing_artifacts() {
    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let unit_id = "game_logic.dll/DrawPrimitive/v2";
    let encoded_id = urlencoding::encode(unit_id);
    let resp = reqwest::get(format!(
        "http://127.0.0.1:{}/api/units/{}/decomp",
        fixture.port(),
        encoded_id
    ))
    .await
    .expect("decomp request succeeds");

    // Returns success:true with an empty context when no analysis artifacts exist.
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("decomp body is JSON");
    assert_eq!(body["success"], true);
}
// ─────────────────────────────────────────────────────────────
// Unit process detail tests (issue #62)
// ─────────────────────────────────────────────────────────────

/// Writes canned run-telemetry artifacts for game_logic.dll/DrawPrimitive:
/// a token-usage log (2 attempts, escalated tiers), a fault log (2 faults),
/// and an analysis artifact (for the tier rationale).
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
    let decomp_artifact = serde_json::json!({
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
        serde_json::to_string_pretty(&decomp_artifact).expect("serialize decomp artifact"),
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

    // Rationale: recomputed from the analysis artifact.
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
        .expect("write corrupt decomp artifact");

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

/// Evaluate a JS expression on the dashboard tab and read the result as a
/// boolean, shared by every headless test so none redefines the coercion.
///
/// An evaluation error or a non-boolean result reads as `false`, which keeps
/// render-polling loops honest until the dashboard actually shows the thing.
fn eval_bool(tab: &headless_chrome::Tab, expr: &str) -> bool {
    tab.evaluate(expr, false)
        .ok()
        .and_then(|r| r.value)
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

/// Like [`eval_bool`], but reads the result as text; errors and non-string
/// results read as the empty string.
fn eval_text(tab: &headless_chrome::Tab, expr: &str) -> String {
    tab.evaluate(expr, false)
        .ok()
        .and_then(|r| r.value)
        .and_then(|v| v.as_str().map(String::from))
        .unwrap_or_default()
}

/// Like [`eval_bool`], but reads the result as a whole number; errors and
/// non-number results read as `-1`, a count no real element set can match.
fn eval_count(tab: &headless_chrome::Tab, expr: &str) -> i64 {
    tab.evaluate(expr, false)
        .ok()
        .and_then(|r| r.value)
        .and_then(|v| v.as_i64())
        .unwrap_or(-1)
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

    assert!(
        eval_bool(&tab, "!!document.getElementById('server-shutdown-btn')"),
        "control panel should have a shutdown button"
    );
    assert!(
        eval_bool(&tab, "!!document.getElementById('server-restart-btn')"),
        "control panel should have a restart button"
    );

    // The log-level select must offer the levels the server accepts.
    assert!(
        eval_bool(
            &tab,
            "['off','error','warn','info','debug','trace'].every(\
                l => [...document.getElementById('server-loglevel-select').options]\
                    .some(o => o.value === l))"
        ),
        "log-level select should offer off/error/warn/info/debug/trace"
    );
    // And pre-select the level the server reports.
    assert!(
        eval_bool(
            &tab,
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
    let router = build_router_with_ws(state, manager, progress, ws_actions(&fixture));
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    // A little live data so the pipeline panel is visible.
    events.emit(ProgressEvent::ClassificationComplete {
        binary: "d3d9.dll".into(),
        category: "WindowsOs".into(),
        classification_strategy: "PalMapping".into(),
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

    // The bar renders asynchronously once the pipeline fetch settles;
    // poll until all 8 segments appear (up to ~5 seconds).
    let mut rendered = false;
    for _ in 0..25 {
        if eval_count(
            &tab,
            "document.querySelectorAll('#pipeline-phase-bar .phase-segment').length",
        ) == 8
        {
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
            &tab,
            "!!document.querySelector('#pipeline-phase-bar .phase-segment[data-phase=\"pal_design\"]')"
        ),
        "PAL Design must be its own segment"
    );

    // Restitching & Documentation render honestly as no-data-source.
    for phase in ["restitching", "documentation"] {
        assert!(
            eval_bool(
                &tab,
                &format!(
                    "document.querySelector('#pipeline-phase-bar .phase-segment[data-phase=\"{phase}\"]')\
                    ?.classList.contains('state-no_data_source') === true"
                )
            ),
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
/// buttons are real controls (issue #94): each row carries one translation
/// toggle (issue #285) plus Configure and Classify, clicking the toggle
/// drives its per-binary endpoint, and on a router with no scope handle
/// attached the server's honest 503 reason surfaces as an error toast.
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
    let router = build_router_with_ws(state, manager, progress, ws_actions(&fixture));
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
        classification_strategy: "PalMapping".into(),
        crate_replacement: None,
        exported_symbols: 25,
        imported_symbols: 6,
    });
    events.emit(ProgressEvent::ClassificationComplete {
        binary: "dinput8.dll".into(),
        category: "WindowsOs".into(),
        classification_strategy: "CrateReplacement".into(),
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
        classification_strategy: "ReverseEngineer".into(),
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

    // Rows render asynchronously once the pipeline fetch settles;
    // poll until all four appear (up to ~5 seconds).
    let mut rendered = false;
    for _ in 0..25 {
        if eval_count(
            &tab,
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
            eval_bool(
                &tab,
                &format!(
                    "!!document.querySelector('#pipeline-binaries [data-binary=\"{binary}\"]')"
                )
            ),
            "row for {binary} should exist"
        );
    }

    let cell_text = |binary: &str, selector: &str| -> String {
        eval_text(
            &tab,
            &format!(
                "document.querySelector('#pipeline-binaries [data-binary=\"{binary}\"] {selector}')?.textContent || ''"
            ),
        )
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
            &tab,
            "document.querySelectorAll('#pipeline-binaries .pipeline-binary-head .pipeline-binary-status').length === 0"
        ),
        "no status badge next to the binary name"
    );
    // d3d9 is PAL-mapped — its compact row (issue #244) suppresses the
    // tokens/success cell and the translation counts entirely.
    assert!(
        eval_bool(
            &tab,
            "!document.querySelector('#pipeline-binaries [data-binary=\"d3d9.dll\"] [data-metric=\"success-rate\"]') \
                 && !document.querySelector('#pipeline-binaries [data-binary=\"d3d9.dll\"] [data-count=\"total\"]')"
        ),
        "a PAL row renders no tokens/success cell and no translation counts"
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
            &tab,
            "[...document.querySelectorAll('#pipeline-binaries .pipeline-binary-status')].every(e => !e.textContent.includes('Classified'))"
        ),
        "no Classified badge — the state column already carries the classification state"
    );
    assert!(
        eval_bool(
            &tab,
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
            &tab,
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
    // (engine.dll: classified and working, but no batch summary has landed.
    // success-rate is absent here too: with no terminal outcomes the cell
    // shows the status placeholder instead of a rate, never a zero)
    for (binary, selector) in [
        ("engine.dll", "[data-metric=\"tokens\"]"),
        ("engine.dll", "[data-count=\"total\"]"),
    ] {
        let text = cell_text(binary, selector);
        assert!(
            text.contains('—') && !text.contains('0'),
            "{binary} {selector} must render unknown as —, not a fabricated zero, got: {text}"
        );
    }

    // ── Quick-action buttons: one translation toggle plus Configure and
    // Classify (issue #285) — never two translation buttons on one row ──
    assert!(
        eval_bool(
            &tab,
            "[...document.querySelectorAll('#pipeline-binaries [data-binary=\"game_logic.dll\"] .pipeline-binary-actions button')].length === 3"
        ),
        "each row should offer its translation toggle, Configure, and Classify"
    );
    // The toggle's state follows the row honestly (issue #285): engine.dll's
    // batch pass is in flight — its button reads Pause; game_logic.dll's
    // pass has finished — its button reads Start Translation.
    assert_eq!(
        eval_text(
            &tab,
            "document.querySelector('#pipeline-binaries [data-binary=\"engine.dll\"] [data-action=\"pause\"]')?.textContent || ''"
        ),
        "Pause",
        "the working row's toggle reads Pause"
    );
    assert_eq!(
        eval_text(
            &tab,
            "document.querySelector('#pipeline-binaries [data-binary=\"game_logic.dll\"] [data-action=\"start\"]')?.textContent || ''"
        ),
        "Start Translation",
        "the finished row's toggle reads Start Translation"
    );
    assert!(
        eval_bool(
            &tab,
            "document.querySelector('#pipeline-binaries [data-binary=\"engine.dll\"] [data-action=\"start\"]') === null \
                 && document.querySelector('#pipeline-binaries [data-binary=\"game_logic.dll\"] [data-action=\"pause\"]') === null \
                 && ![...document.querySelectorAll('#pipeline-binaries .pipeline-action-btn')].some(b => b.dataset.action === 'resume')"
        ),
        "one translation button per row — never Pause and Start together, and no row-level Resume"
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
    .expect("click the start-translation quick action");

    // The click is a real control: it fires a POST to the row's per-binary
    // start endpoint…
    let mut fired = false;
    for _ in 0..25 {
        if eval_count(&tab, "window.__nonGetFetches") >= 1 {
            fired = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        fired,
        "the quick action must drive POST /api/pipeline/binaries/{{name}}/start, not just announce"
    );

    // …and this plain router has no scope handle attached — the swap steers
    // through the handle, so the server's own honest 503 reason surfaces as
    // an error toast — never a silent no-op, never a locally-faked state
    // change.
    let mut surfaced = false;
    for _ in 0..25 {
        if eval_bool(
            &tab,
            "[...document.querySelectorAll('#toast-container .toast')].some(t => t.textContent.includes('no scope control'))",
        ) {
            surfaced = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        surfaced,
        "the server's 503 reason must surface as an error toast, got: {}",
        eval_text(
            &tab,
            "[...document.querySelectorAll('#toast-container .toast')].map(t => t.textContent).join(' | ')"
        )
    );

    tab.close_target().ok();
    drop(browser);
}

/// Headless-browser test for the compact PAL row (issue #244, part of #223):
/// a PAL-classified binary renders the compact variant — trait names with
/// defined/missing markers in the state cell, an "N/M defined" readiness
/// count in the counts area, an empty cost placeholder keeping the grid
/// aligned, and Classify alone in the actions cell. A PAL row whose poll
/// carried no summary shows an em-dash, never a fabricated 0/0. A non-PAL
/// neighbour keeps its counts, its success-column placeholder, and its three
/// buttons. A live reclassification to a translation strategy restores the
/// full row and moves it up into table order on the next refresh.
///
/// Run with: `cargo test --features server --test e2e headless -- --ignored`
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Chromium/Chrome installed; run with --ignored"]
async fn test_headless_pipeline_pal_rows_compact() {
    let fixture = TestFixture::new();
    // d3d9.dll: classified PalMapping on disk, with function artifacts
    // recording DirectX/Win32Core API-call categories and a generated PAL
    // crate defining GraphicsDevice but not PlatformCore. game_logic.dll:
    // ReverseEngineer — the full-row neighbour.
    write_pipeline_pal_readiness_fixtures(&fixture);

    let state = ServerState::new(fixture.repo_path());
    let events = TranslationEvents::new(128);
    let manager = SessionManager::new_with_broadcast(events.subscribe());
    let progress = ProgressState::new();
    let router = build_router_with_ws(state, manager, progress, ws_actions(&fixture));
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    // A second PAL binary classified live with no analysis artifacts — the
    // poll carries no summary for it, and the row must answer honestly.
    events.emit(ProgressEvent::ClassificationComplete {
        binary: "audio.dll".into(),
        category: "WindowsOs".into(),
        classification_strategy: "PalMapping".into(),
        crate_replacement: None,
        exported_symbols: 3,
        imported_symbols: 2,
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    let browser = launch_headless_browser();
    let tab = open_dashboard_tab(&browser, fixture.port());

    // game_logic.dll (full row) plus audio.dll and d3d9.dll (compact —
    // PAL rows sort last, issue #242); poll until all three appear.
    let mut rendered = false;
    for _ in 0..25 {
        if eval_count(
            &tab,
            "document.querySelectorAll('#pipeline-binaries .pipeline-binary-row[data-binary]').length",
        ) == 3
        {
            rendered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        rendered,
        "one full row and two compact PAL rows should render"
    );

    let cell_text = |binary: &str, selector: &str| -> String {
        eval_text(
            &tab,
            &format!(
                "document.querySelector('#pipeline-binaries [data-binary=\"{binary}\"] {selector}')?.textContent || ''"
            ),
        )
    };

    // ── State cell: PAL → the summary's trait names ─────────────────────
    let state_cell = cell_text("d3d9.dll", ".pipeline-binary-state");
    assert!(
        state_cell.contains("PAL →")
            && state_cell.contains("GraphicsDevice")
            && state_cell.contains("PlatformCore"),
        "the state cell lists the traits the poll's summary names, got: {state_cell}"
    );
    assert!(
        eval_bool(
            &tab,
            r#"(() => {
                const row = document.querySelector('#pipeline-binaries [data-binary="d3d9.dll"]');
                const defined = row?.querySelector('.pal-trait[data-state="defined"]');
                const missing = row?.querySelector('.pal-trait[data-state="missing"]');
                return defined?.textContent === 'GraphicsDevice'
                    && missing?.textContent === 'PlatformCore';
            })()"#
        ),
        "defined and missing traits carry distinguishable markers"
    );

    // ── Readiness count in the counts area, never a fabricated 0/0 ──────
    assert_eq!(
        cell_text("d3d9.dll", "[data-count=\"pal-readiness\"]").trim(),
        "1/2 defined",
        "the counts area shows the trait readiness count"
    );
    let audio_readiness = cell_text("audio.dll", "[data-count=\"pal-readiness\"]");
    assert_eq!(
        audio_readiness.trim(),
        "—",
        "a PAL row whose poll carried no summary shows an em-dash, got: {audio_readiness}"
    );
    assert!(
        !audio_readiness.contains('0'),
        "no fabricated zero for a summary-less PAL row, got: {audio_readiness}"
    );
    assert!(
        cell_text("audio.dll", ".pipeline-binary-state").contains("PAL trait"),
        "a summary-less PAL row keeps the plain PAL trait state text"
    );

    // ── Suppressed cells and controls on both compact rows ──────────────
    for binary in ["d3d9.dll", "audio.dll"] {
        assert!(
            eval_bool(
                &tab,
                &format!(
                    r#"(() => {{
                        const row = document.querySelector('#pipeline-binaries [data-binary="{binary}"]');
                        if (!row) return false;
                        const btns = [...row.querySelectorAll('.pipeline-action-btn')];
                        return row.querySelector('[data-count="total"]') === null
                            && row.querySelector('[data-metric="tokens"]') === null
                            && row.querySelector('[data-metric="success-rate"]') === null
                            && row.querySelector('.pipeline-binary-activity') === null
                            && !!row.querySelector('.pipeline-binary-cost')
                            && row.querySelector('.pipeline-binary-cost').childElementCount === 0
                            && btns.length === 1
                            && btns[0].dataset.action === 'classify';
                    }})()"#
                )
            ),
            "{binary} renders no counts, no cost content, no activity line, and Classify only"
        );
    }

    // ── The non-PAL neighbour keeps its full row ─────────────────────────
    assert!(
        eval_bool(
            &tab,
            r#"(() => {
                const row = document.querySelector('#pipeline-binaries [data-binary="game_logic.dll"]');
                if (!row) return false;
                return row.querySelectorAll('.pipeline-action-btn').length === 3
                    && !!row.querySelector('[data-count="total"]')
                    && !!row.querySelector('[data-metric="tokens"]');
            })()"#
        ),
        "the non-PAL neighbour keeps its counts and its three buttons"
    );
    assert!(
        cell_text("game_logic.dll", "[data-metric=\"success-rate\"]").contains("In pipeline"),
        "the full neighbour still shows its status placeholder in the Success column, got: {}",
        cell_text("game_logic.dll", "[data-metric=\"success-rate\"]")
    );

    // Switch to the Pipeline view so the cells have real layout boxes —
    // hidden elements report zero rects and would pass vacuously.
    tab.evaluate(
        "document.querySelector('.nav-tab[data-view=\"pipeline\"]').click()",
        false,
    )
    .expect("switch to pipeline view");
    tokio::time::sleep(Duration::from_millis(300)).await;

    // The empty cost placeholder keeps the compact row's grid aligned
    // with the header's cost column.
    assert!(
        eval_bool(
            &tab,
            r#"(() => {
                const h = document.querySelector('#pipeline-binaries .pipeline-binary-header .pipeline-binary-cost');
                const r = document.querySelector('#pipeline-binaries [data-binary="d3d9.dll"] .pipeline-binary-cost');
                if (!h || !r) return false;
                const hb = h.getBoundingClientRect(), rb = r.getBoundingClientRect();
                return hb.width >= 100 && rb.width >= 100
                    && Math.abs(hb.left - rb.left) <= 2 && Math.abs(hb.width - rb.width) <= 2;
            })()"#
        ),
        "the compact row's placeholder cells keep the grid aligned with the header"
    );

    // ── Overriding to a translation strategy restores the full row ───────
    // The classification-override panel's live event is what re-renders
    // rows (app.js reloads the pipeline on classification_complete) —
    // emitting it here is the same path the panel's success takes.
    events.emit(ProgressEvent::ClassificationComplete {
        binary: "d3d9.dll".into(),
        category: "ProjectSpecific".into(),
        classification_strategy: "ReverseEngineer".into(),
        crate_replacement: None,
        exported_symbols: 25,
        imported_symbols: 6,
    });
    let mut restored = false;
    for _ in 0..25 {
        if eval_bool(
            &tab,
            "!!document.querySelector('#pipeline-binaries [data-binary=\"d3d9.dll\"] [data-action=\"start\"]')",
        ) {
            restored = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        restored,
        "overriding a PAL-classified binary to a translation strategy restores its full row on the next refresh"
    );
    assert!(
        eval_bool(
            &tab,
            r#"(() => {
                const rows = [...document.querySelectorAll('#pipeline-binaries .pipeline-binary-row[data-binary]')];
                const row = rows.find(r => r.dataset.binary === 'd3d9.dll');
                if (!row) return false;
                const palIdx = rows.findIndex(r => r.dataset.binary === 'audio.dll');
                return row.querySelectorAll('.pipeline-action-btn').length === 3
                    && !!row.querySelector('[data-count="total"]')
                    && row.querySelector('[data-count="pal-readiness"]') === null
                    && rows.indexOf(row) < palIdx;
            })()"#
        ),
        "the restored row has full counts and buttons, no readiness span, and has moved up out of the PAL tail"
    );

    tab.close_target().ok();
    drop(browser);
}

/// Headless-browser test for the controls header (issue #94, W2.4): the
/// state badge follows the pipeline's state machine — first from the
/// server-status snapshot, then over the WebSocket as *another* client
/// drives the lifecycle endpoints — and the buttons gate by the server's
/// own transition table at every step.
///
/// Run with: `cargo test --features server --test e2e headless -- --ignored`
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Chromium/Chrome installed; run with --ignored"]
async fn test_headless_controls_header_tracks_live_state() {
    let fixture = TestFixture::new();
    let events = TranslationEvents::new(128);
    let control = PipelineControl::new().with_events(events.clone());
    let run_requests = RunRequestSignal::new();
    let state = ServerState::new(fixture.repo_path())
        .with_pipeline_control(control.clone())
        .with_run_requests(run_requests.clone());
    let manager = SessionManager::new_with_broadcast(events.subscribe());
    let progress = ProgressState::new();
    let router = build_router_with_ws(state, manager, progress, ws_actions(&fixture));
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let browser = launch_headless_browser();
    let tab = open_dashboard_tab(&browser, fixture.port());

    let header_state = || {
        eval_text(
            &tab,
            "document.getElementById('pipeline-state')?.dataset.state || ''",
        )
    };
    let btn_disabled = |id: &str| {
        eval_bool(
            &tab,
            &format!("document.getElementById('{id}')?.disabled === true"),
        )
    };
    let wait_for_state = |want: &'static str| async move {
        for _ in 0..25 {
            if header_state() == want {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        false
    };

    // The first server-status snapshot points the header at the machine's
    // real state — idle, with only Start (and Shut Down Server) available.
    assert!(
        wait_for_state("idle").await,
        "the header must follow the server-status snapshot to idle, got: {}",
        header_state()
    );
    assert!(!btn_disabled("ctl-start"), "Start is available from idle");
    for id in [
        "ctl-pause",
        "ctl-resume",
        "ctl-stop",
        "ctl-cancel",
        "ctl-restart",
    ] {
        assert!(btn_disabled(id), "{id} must be disabled in idle");
    }
    assert!(
        !btn_disabled("ctl-shutdown"),
        "Shut Down Server is always available"
    );

    // Another client (the reqwest "other tab") drives the lifecycle — the
    // header follows over the WebSocket with no interaction in this tab.
    let (status, _) = post_lifecycle(fixture.port(), "/api/pipeline/start").await;
    assert_eq!(status, 200, "start from idle should succeed");
    assert!(
        wait_for_state("running").await,
        "the header must follow the WS pipeline_state_changed event to running"
    );
    assert!(
        btn_disabled("ctl-start"),
        "a running run cannot start again"
    );
    assert!(
        !btn_disabled("ctl-pause"),
        "Pause is available while running"
    );
    assert!(!btn_disabled("ctl-stop"), "Stop is available while running");
    assert!(
        !btn_disabled("ctl-cancel"),
        "Cancel current is available while running"
    );

    // A stale button — force one enabled, as another tab's earlier state
    // would have left it — issuing an operation the machine forbids: the
    // server's own 409 reason surfaces as an error toast, and the header
    // stays truthful rather than corrupting itself.
    tab.evaluate(
        "document.getElementById('ctl-start').disabled = false; \
             document.getElementById('ctl-start').click() === undefined",
        false,
    )
    .expect("force a stale start click");
    let mut rejected = false;
    for _ in 0..25 {
        if eval_bool(
            &tab,
            "[...document.querySelectorAll('#toast-container .toast')].some(t => t.textContent.includes('cannot start a pipeline that is running'))",
        ) {
            rejected = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        rejected,
        "a stale click must surface the server's 409 reason, got: {}",
        eval_text(
            &tab,
            "[...document.querySelectorAll('#toast-container .toast')].map(t => t.textContent).join(' | ')"
        )
    );
    assert_eq!(
        header_state(),
        "running",
        "the rejected click must not corrupt the header's state"
    );

    let (status, _) = post_lifecycle(fixture.port(), "/api/pipeline/pause").await;
    assert_eq!(status, 200);
    assert!(
        wait_for_state("paused").await,
        "the header must follow the pause over the WebSocket"
    );
    assert!(btn_disabled("ctl-pause"), "a paused run cannot pause again");
    assert!(
        !btn_disabled("ctl-resume"),
        "Resume is available while paused"
    );

    let (status, _) = post_lifecycle(fixture.port(), "/api/pipeline/resume").await;
    assert_eq!(status, 200);
    assert!(
        wait_for_state("running").await,
        "the header must follow the resume"
    );

    let (status, _) = post_lifecycle(fixture.port(), "/api/pipeline/stop").await;
    assert_eq!(status, 200);
    assert!(
        wait_for_state("stopping").await,
        "the header must follow the stop over the WebSocket"
    );
    for id in [
        "ctl-start",
        "ctl-pause",
        "ctl-resume",
        "ctl-stop",
        "ctl-restart",
    ] {
        assert!(btn_disabled(id), "{id} must be disabled while stopping");
    }

    // The run finishes (the live loop would do this) — Restart becomes the
    // only lifecycle operation available.
    control.complete().expect("stopping -> complete");
    assert!(
        wait_for_state("complete").await,
        "the header must follow the completion over the WebSocket"
    );
    assert!(
        !btn_disabled("ctl-restart"),
        "Restart is available once the run is complete"
    );

    tab.close_target().ok();
    drop(browser);
}

/// Headless-browser test for the restart dialog (issue #94, W2.4): from a
/// complete run the Restart button opens a dialog with phase / target /
/// scope selectors and a safety explanation; confirming drives
/// POST /api/pipeline/restart with the chosen selectors — the header moves
/// back to running and the live loop's request slot carries the choices.
///
/// Run with: `cargo test --features server --test e2e headless -- --ignored`
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Chromium/Chrome installed; run with --ignored"]
async fn test_headless_restart_dialog_drives_endpoint() {
    let fixture = TestFixture::new();
    let events = TranslationEvents::new(128);
    let control = PipelineControl::new().with_events(events.clone());
    // A finished run — restart is only legal from Complete or Error.
    control.start().expect("idle -> running");
    control.stop().expect("running -> stopping");
    control.complete().expect("stopping -> complete");
    let run_requests = RunRequestSignal::new();
    let mut run_rx = run_requests.subscribe();
    let state = ServerState::new(fixture.repo_path())
        .with_pipeline_control(control.clone())
        .with_run_requests(run_requests.clone());
    let manager = SessionManager::new_with_broadcast(events.subscribe());
    let progress = ProgressState::new();
    let router = build_router_with_ws(state, manager, progress, ws_actions(&fixture));
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let browser = launch_headless_browser();
    let tab = open_dashboard_tab(&browser, fixture.port());

    // The header settles on complete, which unlocks Restart.
    let mut settled = false;
    for _ in 0..25 {
        if eval_bool(
            &tab,
            "document.getElementById('pipeline-state')?.dataset.state === 'complete' \
                 && document.getElementById('ctl-restart')?.disabled === false",
        ) {
            settled = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        settled,
        "the header must show complete and enable Restart, got: {}",
        eval_text(
            &tab,
            "document.getElementById('pipeline-state')?.dataset.state || ''"
        )
    );

    tab.evaluate(
        "document.getElementById('ctl-restart').click() === undefined",
        false,
    )
    .expect("click Restart");

    // The dialog opens with the three selectors and the safety explanation.
    let mut opened = false;
    for _ in 0..25 {
        if eval_bool(&tab, "!!document.getElementById('restart-dialog')") {
            opened = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(opened, "Restart must open the options dialog");
    assert!(
        eval_bool(
            &tab,
            "[...document.querySelectorAll('#restart-phase option')].map(o => o.value).join(',') === 'translate,classify'"
        ),
        "phase selector offers translate and classify"
    );
    assert!(
        eval_bool(
            &tab,
            "[...document.querySelectorAll('#restart-target option')].some(o => o.value === 'all')"
        ),
        "target selector offers all binaries"
    );
    assert!(
        eval_bool(
            &tab,
            "[...document.querySelectorAll('#restart-scope option')].map(o => o.value).join(',') === 'all_functions,only_queued,only_failed'"
        ),
        "scope selector offers all_functions, only_queued, and only_failed"
    );
    assert!(
        eval_text(
            &tab,
            "document.querySelector('#restart-dialog .dialog-safety')?.textContent || ''"
        )
        .contains("nothing in flight is discarded"),
        "the dialog must explain the safety of restarting"
    );

    // Pick fresh classification of only the failed functions, then confirm.
    tab.evaluate(
        "document.getElementById('restart-phase').value = 'classify'; \
             document.getElementById('restart-scope').value = 'only_failed'; true",
        false,
    )
    .expect("choose restart selectors");
    tab.evaluate(
        "document.getElementById('restart-confirm').click() === undefined",
        false,
    )
    .expect("confirm restart");

    // The header follows the machine back to running…
    let mut restarted = false;
    for _ in 0..25 {
        if eval_bool(
            &tab,
            "document.getElementById('pipeline-state')?.dataset.state === 'running'",
        ) {
            restarted = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        restarted,
        "confirming the dialog must drive POST /api/pipeline/restart and move the header to running"
    );

    // …and the live loop's request slot carries the chosen selectors.
    run_rx
        .changed()
        .await
        .expect("a restart request was queued");
    let request = run_rx.borrow_and_update().clone();
    let request = request.expect("the dialog's restart request is stored");
    assert_eq!(
        request.phase,
        RunPhase::Classify,
        "the dialog's phase reached the endpoint"
    );
    assert_eq!(
        request.scope,
        RunScope::OnlyFailed,
        "the dialog's scope reached the endpoint"
    );
    assert_eq!(
        request.target,
        RunTarget::All,
        "the default target is all binaries"
    );

    // The success toast names the selectors it sent.
    assert!(
        eval_bool(
            &tab,
            "[...document.querySelectorAll('#toast-container .toast')].some(t => t.textContent.includes('phase classify') && t.textContent.includes('only failed functions'))"
        ),
        "the toast must report the restart the server actually queued, got: {}",
        eval_text(
            &tab,
            "[...document.querySelectorAll('#toast-container .toast')].map(t => t.textContent).join(' | ')"
        )
    );

    tab.close_target().ok();
    drop(browser);
}

/// Headless-browser test for a pipeline row's single translation toggle
/// (issue #285): while the pipeline works a binary its one button reads
/// Pause — clicking it drives the per-binary pause endpoint, not the
/// run-wide POST /api/pipeline/pause, and the WS binary_pause_changed
/// event re-renders the row as Paused (the paused flag wins over working)
/// with the same button slot relabeled Start Translation. Pressing that
/// drives the per-binary start endpoint — which resumes the held binary
/// and focuses it — and the row re-renders Working with Pause back in the
/// slot. The run-level machine never moves in either direction. Mirrors
/// the restart-dialog endpoint test.
///
/// Run with: `cargo test --features server --test e2e headless -- --ignored`
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Chromium/Chrome installed; run with --ignored"]
async fn test_headless_binary_translation_toggle_matrix() {
    let fixture = TestFixture::new();
    let events = TranslationEvents::new(128);
    let scope =
        calxgloss_types::ScopeControl::open(fixture.repo_path()).with_events(events.clone());
    // A running run: if the row's button drove the run-wide endpoints,
    // the machine would move — it must stay running throughout.
    let control = PipelineControl::new().with_events(events.clone());
    control.start().expect("idle -> running");
    let run_requests = RunRequestSignal::new();
    let state = ServerState::new(fixture.repo_path())
        .with_scope_control(scope)
        .with_pipeline_control(control.clone())
        .with_run_requests(run_requests);
    let manager = SessionManager::new_with_broadcast(events.subscribe());
    let progress = ProgressState::new();
    let router = build_router_with_ws(state, manager, progress, ws_actions(&fixture));
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    // One planned binary whose batch pass is in flight — the honest
    // Pause state of the toggle.
    events.emit(ProgressEvent::QueuePlanned {
        binaries: vec!["game_logic.dll".to_string()],
    });
    events.emit(ProgressEvent::BatchStarted {
        binary: "game_logic.dll".into(),
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    let browser = launch_headless_browser();
    let tab = open_dashboard_tab(&browser, fixture.port());

    // Rows render asynchronously once the pipeline fetch settles; poll
    // until the row and its Pause button appear (up to ~5 seconds).
    let mut rendered = false;
    for _ in 0..25 {
        if eval_bool(
            &tab,
            "!!document.querySelector('#pipeline-binaries [data-binary=\"game_logic.dll\"] [data-action=\"pause\"]')",
        ) {
            rendered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(rendered, "the working row must render with a Pause button");
    assert_eq!(
        eval_text(
            &tab,
            "document.querySelector('#pipeline-binaries [data-binary=\"game_logic.dll\"] [data-action=\"pause\"]')?.textContent || ''"
        ),
        "Pause",
        "an unpaused working row's button reads Pause"
    );

    // Click Pause on the row.
    tab.evaluate(
        "document.querySelector('#pipeline-binaries [data-binary=\"game_logic.dll\"] [data-action=\"pause\"]').click() === undefined",
        false,
    )
    .expect("click the row's Pause button");

    // The row re-renders as Paused — over the WS binary_pause_changed
    // event, with no reload — and its single button slot relabels to
    // Start Translation: the paused flag wins over the working flag, so
    // the held-out row never still reads Pause.
    let mut paused = false;
    for _ in 0..25 {
        if eval_bool(
            &tab,
            "document.querySelector('#pipeline-binaries [data-binary=\"game_logic.dll\"]')?.dataset.status === 'paused' \
                 && document.querySelector('#pipeline-binaries [data-binary=\"game_logic.dll\"] [data-action=\"start\"]')?.textContent === 'Start Translation' \
                 && !document.querySelector('#pipeline-binaries [data-binary=\"game_logic.dll\"] [data-action=\"pause\"]')",
        ) {
            paused = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        paused,
        "the row must re-render as Paused with a Start Translation button, got: {}",
        eval_text(
            &tab,
            "document.querySelector('#pipeline-binaries [data-binary=\"game_logic.dll\"]')?.outerHTML || ''"
        )
    );
    // The badge reads Paused ahead of Working, the single honest state.
    assert!(
        eval_text(
            &tab,
            "document.querySelector('#pipeline-binaries [data-binary=\"game_logic.dll\"] [data-metric=\"success-rate\"]')?.textContent || ''"
        )
        .contains("Paused"),
        "the paused row's status badge reads Paused"
    );

    // The success toast carries the server's own reason.
    assert!(
        eval_bool(
            &tab,
            "[...document.querySelectorAll('#toast-container .toast')].some(t => t.textContent.includes('held out of the queue'))"
        ),
        "the toast reports the pause the server made, got: {}",
        eval_text(
            &tab,
            "[...document.querySelectorAll('#toast-container .toast')].map(t => t.textContent).join(' | ')"
        )
    );

    // The per-binary endpoint was driven, not the run-wide one: the
    // lifecycle machine never moved, in the server's truth and in the
    // header's badge.
    assert_eq!(
        control.state(),
        PipelineState::Running,
        "a row pause must not touch the run-level lifecycle machine"
    );
    assert_eq!(
        eval_text(
            &tab,
            "document.getElementById('pipeline-state')?.dataset.state || ''"
        ),
        "running",
        "the header badge never moved"
    );
    // The click reached the endpoint — the pause rode the persisted scope
    // record, matched on the #107 case-insensitive rule.
    assert!(
        calxgloss_types::ScopeControl::open(fixture.repo_path()).is_paused("GAME_LOGIC.DLL"),
        "the click drove POST /api/pipeline/binaries/game_logic.dll/pause"
    );

    // Press Start Translation in the same slot — the swap press on the
    // still-in-flight binary resumes it and focuses it, and the row falls
    // back to its Working state with Pause in the slot.
    tab.evaluate(
        "document.querySelector('#pipeline-binaries [data-binary=\"game_logic.dll\"] [data-action=\"start\"]').click() === undefined",
        false,
    )
    .expect("click the row's Start Translation button");

    let mut resumed = false;
    for _ in 0..25 {
        if eval_bool(
            &tab,
            "document.querySelector('#pipeline-binaries [data-binary=\"game_logic.dll\"]')?.dataset.status !== 'paused' \
                 && !!document.querySelector('#pipeline-binaries [data-binary=\"game_logic.dll\"] [data-action=\"pause\"]')",
        ) {
            resumed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        resumed,
        "the row must re-render working with a Pause button, got: {}",
        eval_text(
            &tab,
            "document.querySelector('#pipeline-binaries [data-binary=\"game_logic.dll\"]')?.outerHTML || ''"
        )
    );
    assert!(
        !calxgloss_types::ScopeControl::open(fixture.repo_path()).is_paused("game_logic.dll"),
        "the start click resumed the held binary through POST /api/pipeline/binaries/game_logic.dll/start"
    );
    assert!(
        calxgloss_types::ScopeControl::open(fixture.repo_path()).is_focus("game_logic.dll"),
        "the start click also parked the binary in the focus slot"
    );
    // The swap toast names what the server actually did.
    assert!(
        eval_bool(
            &tab,
            "[...document.querySelectorAll('#toast-container .toast')].some(t => t.textContent.includes('Started game_logic.dll'))"
        ),
        "the toast reports the start the server made, got: {}",
        eval_text(
            &tab,
            "[...document.querySelectorAll('#toast-container .toast')].map(t => t.textContent).join(' | ')"
        )
    );
    assert_eq!(
        control.state(),
        PipelineState::Running,
        "a row start must not touch the run-level lifecycle machine either"
    );

    tab.close_target().ok();
    drop(browser);
}

/// Headless-browser test for the "translate this next" focus end to end
/// (issue #284): with a plan of three rows rendered, an operator focus on
/// the last binary — the bare endpoint, not the row's Start Translation
/// button, which composes the swap on top of this focus (issue #285,
/// tested just below) — makes the re-served pipeline state put that binary
/// at the front of the plan order. Entering the Pipeline view refetches
/// the rows, and the fetched order already honors the pending focus: the
/// dashboard shows what the live run will do at its next binary boundary.
///
/// Run with: `cargo test --features server --test e2e headless -- --ignored`
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Chromium/Chrome installed; run with --ignored"]
async fn test_headless_focus_reorders_served_pipeline_rows() {
    let fixture = TestFixture::new();
    let events = TranslationEvents::new(128);
    let scope =
        calxgloss_types::ScopeControl::open(fixture.repo_path()).with_events(events.clone());
    let state = ServerState::new(fixture.repo_path()).with_scope_control(scope);
    let manager = SessionManager::new_with_broadcast(events.subscribe());
    let progress = ProgressState::new();
    let router = build_router_with_ws(state, manager, progress, ws_actions(&fixture));
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    // The run's plan renders three rows in plan order before anything starts.
    events.emit(ProgressEvent::QueuePlanned {
        binaries: vec![
            "a.dll".to_string(),
            "b.dll".to_string(),
            "c.dll".to_string(),
        ],
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    let browser = launch_headless_browser();
    let tab = open_dashboard_tab(&browser, fixture.port());

    let row_order = || {
        eval_text(
            &tab,
            "[...document.querySelectorAll('#pipeline-binaries .pipeline-binary-row[data-binary]')].map(e => e.dataset.binary).join(',')",
        )
    };

    // Rows render asynchronously once the boot pipeline fetch settles; poll
    // until all three appear in plan order (up to ~5 seconds).
    let mut rendered = false;
    for _ in 0..25 {
        if row_order() == "a.dll,b.dll,c.dll" {
            rendered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        rendered,
        "the plan's three rows must render in plan order, got: {}",
        row_order()
    );

    // The operator focuses c.dll — the endpoint's 200, not a row button.
    let (status, body) = post_lifecycle(fixture.port(), "/api/pipeline/binaries/c.dll/focus").await;
    assert_eq!(status, 200, "the focus call should succeed, got: {body}");

    // Entering the Pipeline view refetches the rows; the re-served state
    // puts the focused binary at the front of the plan.
    tab.evaluate(
        "document.querySelector('.nav-tab[data-view=\"pipeline\"]').click() === undefined",
        false,
    )
    .expect("click the Pipeline tab");

    let mut hoisted = false;
    for _ in 0..25 {
        if row_order() == "c.dll,a.dll,b.dll" {
            hoisted = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        hoisted,
        "the re-served rows must show the focused binary first, got: {}",
        row_order()
    );

    // The focus rode the persisted scope record — the same slot the live
    // worklist will consume at the next boundary.
    assert!(
        calxgloss_types::ScopeControl::open(fixture.repo_path()).is_focus("C.DLL"),
        "the focus is in the persisted scope record"
    );

    tab.close_target().ok();
    drop(browser);
}

/// Headless-browser test for the row's Start Translation press driving the
/// per-binary start swap (issue #285): with a three-binary plan rendered
/// and a.dll in flight, one click on c.dll's button swaps the run — the
/// WS binary_pause_changed events re-render the dashboard with no reload,
/// the served plan now leads with c.dll, the previous leader re-renders
/// Paused, and the success toast names both halves of the swap. The
/// run-level machine never moves: the row button steers, never walks.
///
/// Run with: `cargo test --features server --test e2e headless -- --ignored`
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Chromium/Chrome installed; run with --ignored"]
async fn test_headless_binary_start_swaps_the_rows() {
    let fixture = TestFixture::new();
    let events = TranslationEvents::new(128);
    let scope =
        calxgloss_types::ScopeControl::open(fixture.repo_path()).with_events(events.clone());
    let control = PipelineControl::new().with_events(events.clone());
    control.start().expect("idle -> running");
    let run_requests = RunRequestSignal::new();
    let state = ServerState::new(fixture.repo_path())
        .with_scope_control(scope)
        .with_pipeline_control(control.clone())
        .with_run_requests(run_requests);
    let manager = SessionManager::new_with_broadcast(events.subscribe());
    let progress = ProgressState::new();
    let router = build_router_with_ws(state, manager, progress, ws_actions(&fixture));
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    // The plan's three rows, with a.dll's pass in flight: a.dll reads
    // Pause, c.dll reads Start Translation.
    events.emit(ProgressEvent::QueuePlanned {
        binaries: vec![
            "a.dll".to_string(),
            "b.dll".to_string(),
            "c.dll".to_string(),
        ],
    });
    events.emit(ProgressEvent::BatchStarted {
        binary: "a.dll".into(),
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    let browser = launch_headless_browser();
    let tab = open_dashboard_tab(&browser, fixture.port());

    let row_order = || {
        eval_text(
            &tab,
            "[...document.querySelectorAll('#pipeline-binaries .pipeline-binary-row[data-binary]')].map(e => e.dataset.binary).join(',')",
        )
    };

    // Poll until the rows render in plan order and c.dll's row carries its
    // Start Translation button (up to ~5 seconds).
    let mut rendered = false;
    for _ in 0..25 {
        if row_order() == "a.dll,b.dll,c.dll"
            && eval_bool(
                &tab,
                "!!document.querySelector('#pipeline-binaries [data-binary=\"c.dll\"] [data-action=\"start\"]')",
            )
        {
            rendered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        rendered,
        "the plan's rows must render with c.dll offering Start Translation, got: {}",
        row_order()
    );

    // Press Start Translation on c.dll — one click, the whole swap.
    tab.evaluate(
        "document.querySelector('#pipeline-binaries [data-binary=\"c.dll\"] [data-action=\"start\"]').click() === undefined",
        false,
    )
    .expect("click c.dll's Start Translation button");

    // The WS pause events drive the dashboard to show both halves of the
    // swap with no reload: the served plan leads with the target now, and
    // the previous leader re-renders Paused — held out to make way.
    let mut swapped = false;
    for _ in 0..25 {
        if row_order() == "c.dll,a.dll,b.dll"
            && eval_bool(
                &tab,
                "document.querySelector('#pipeline-binaries [data-binary=\"a.dll\"]')?.dataset.status === 'paused'",
            )
        {
            swapped = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        swapped,
        "the swap must re-render the plan led by c.dll with a.dll Paused, got: {}",
        row_order()
    );

    // The toast is honest about the side effect: it names both binaries.
    assert!(
        eval_bool(
            &tab,
            "[...document.querySelectorAll('#toast-container .toast')].some(t => t.textContent.includes('Started c.dll') && t.textContent.includes('paused a.dll'))"
        ),
        "the toast names the swap the server made, got: {}",
        eval_text(
            &tab,
            "[...document.querySelectorAll('#toast-container .toast')].map(t => t.textContent).join(' | ')"
        )
    );

    // The server's truth behind the re-render: the swap rode the persisted
    // scope record, and the run-level machine and header badge never moved.
    let reopened = calxgloss_types::ScopeControl::open(fixture.repo_path());
    assert!(reopened.is_paused("A.DLL"), "the previous leader is paused");
    assert!(
        !reopened.is_paused("C.DLL"),
        "the target row's press admitted c.dll"
    );
    assert!(reopened.is_focus("C.DLL"), "c.dll holds the focus slot");
    assert_eq!(
        control.state(),
        PipelineState::Running,
        "the swap never walks the run-level lifecycle machine"
    );
    assert_eq!(
        eval_text(
            &tab,
            "document.getElementById('pipeline-state')?.dataset.state || ''"
        ),
        "running",
        "the header badge never moved"
    );

    tab.close_target().ok();
    drop(browser);
}

/// Headless-browser test for the shutdown dialog (issue #94, W2.4): Shut
/// Down Server opens a confirmation listing exactly what it does — honest
/// to the live mode — and confirming drives the existing
/// POST /api/server/shutdown, taking the accept loop down.
///
/// Run with: `cargo test --features server --test e2e headless -- --ignored`
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Chromium/Chrome installed; run with --ignored"]
async fn test_headless_shutdown_dialog_drives_endpoint() {
    let fixture = TestFixture::new();
    let events = TranslationEvents::new(128);
    let control = PipelineControl::new().with_events(events.clone());
    let state = ServerState::new(fixture.repo_path()).with_pipeline_control(control.clone());
    let manager = SessionManager::new_with_broadcast(events.subscribe());
    let progress = ProgressState::new();
    let router = build_router_with_ws(state.clone(), manager, progress, ws_actions(&fixture));
    // The accept loop watches the state's shutdown flag — the production
    // graceful-shutdown path, so the dialog visibly stops the server.
    let server = spawn_server_with_shutdown(&state, router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let browser = launch_headless_browser();
    let tab = open_dashboard_tab(&browser, fixture.port());

    // Shut Down Server is available from the very first snapshot.
    let mut ready = false;
    for _ in 0..25 {
        if eval_bool(
            &tab,
            "document.getElementById('ctl-shutdown')?.disabled === false",
        ) {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        ready,
        "Shut Down Server must be enabled once the status snapshot lands"
    );

    tab.evaluate(
        "document.getElementById('ctl-shutdown').click() === undefined",
        false,
    )
    .expect("click Shut Down Server");

    let mut opened = false;
    for _ in 0..25 {
        if eval_bool(&tab, "!!document.getElementById('shutdown-dialog')") {
            opened = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(opened, "Shut Down Server must open the confirmation dialog");

    // The dialog lists exactly what the shutdown does — honest to the live
    // router: unit boundary, the in-flight unit is saved, then the process stops.
    let listed = eval_text(
        &tab,
        "document.querySelector('#shutdown-dialog .dialog-list')?.textContent || ''",
    );
    assert!(
        listed.contains("unit boundary")
            && listed.contains("save its state")
            && listed.contains("Stop the server"),
        "the confirmation must list the shutdown's actions, got: {listed}"
    );

    tab.evaluate(
        "document.getElementById('shutdown-confirm').click() === undefined",
        false,
    )
    .expect("confirm shutdown");

    // The accept loop exits gracefully — the production shutdown path ran.
    server
        .await
        .expect("the dialog's POST takes the server down");
    let after = reqwest::get(format!(
        "http://127.0.0.1:{}/api/server/status",
        fixture.port()
    ))
    .await;
    assert!(
        after.is_err(),
        "the server must refuse connections after the dialog's shutdown"
    );

    drop(browser);
}

/// Headless-browser test for the translation scope controls panel
/// (issue #95, W2.6): the panel renders the current scope and constraints
/// from the status endpoint on load, and every control — category
/// checkboxes, priority add/remove, constraint inputs — drives its scope
/// endpoint end to end, with the rendered state following the server's
/// answer rather than a local guess.
///
/// Run with: `cargo test --features server --test e2e headless -- --ignored`
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Chromium/Chrome installed; run with --ignored"]
async fn test_headless_scope_controls_panel() {
    let fixture = TestFixture::new();
    // The run is already steered: one priority function and constraints in
    // force — the panel must render exactly this on load, not defaults.
    let scope = calxgloss_types::ScopeControl::open(fixture.repo_path());
    scope
        .prioritize_function("engine.dll", "DrawPrimitive")
        .expect("seeded priority persists");
    scope
        .set_constraints(calxgloss_types::TranslationConstraints {
            max_attempts: Some(2),
            max_context_tier: Some(calxgloss_types::ContextTier::Disassembly),
            token_budget: Some(50_000),
        })
        .expect("seeded constraints persist");
    scope.record_tokens(12_345);
    let state = ServerState::new(fixture.repo_path()).with_scope_control(scope);
    let events = TranslationEvents::new(128);
    let manager = SessionManager::new_with_broadcast(events.subscribe());
    let progress = ProgressState::new();
    let router = build_router_with_ws(state, manager, progress, ws_actions(&fixture));
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    // One binary per category the checkboxes speak about, so each checkbox
    // has a real category to read.
    for (binary, category) in [
        ("engine.dll", "ProjectSpecific"),
        ("zlib.dll", "KnownThirdParty"),
        ("mystery.dll", "UnknownThirdParty"),
        ("msvcrt.dll", "RuntimeLibrary"),
        ("d3d9.dll", "WindowsOs"),
    ] {
        events.emit(ProgressEvent::ClassificationComplete {
            binary: binary.into(),
            category: category.into(),
            classification_strategy: "ReverseEngineer".into(),
            crate_replacement: None,
            exported_symbols: 1,
            imported_symbols: 0,
        });
    }
    tokio::time::sleep(Duration::from_millis(300)).await;

    let browser = launch_headless_browser();
    let tab = open_dashboard_tab(&browser, fixture.port());

    let checked = |id: &str| {
        eval_bool(
            &tab,
            &format!("document.getElementById('{id}')?.checked === true"),
        )
    };
    let chip_count = |fn_name: &str| {
        eval_count(
            &tab,
            &format!(
                "document.querySelectorAll('#scope-priority-list .scope-priority-chip[data-function=\"{fn_name}\"]').length"
            ),
        )
    };
    let get_scope = || async {
        reqwest::get(format!("http://127.0.0.1:{}/api/scope", fixture.port()))
            .await
            .expect("scope status reachable")
            .json::<serde_json::Value>()
            .await
            .expect("scope status is JSON")
    };
    let scope_binaries = || async {
        let mut list: Vec<String> = get_scope().await["scope"]["binaries"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        list.sort();
        list
    };
    let priority_count = || async {
        get_scope().await["scope"]["priority_functions"]
            .as_array()
            .map(Vec::len)
    };

    // On load the panel renders the server's scope: the seeded priority
    // chip is present and the checkboxes read the unsteered allow-list —
    // every discovered binary is in scope, so translate boxes are on and
    // skip boxes are off.
    let mut chip_rendered = false;
    for _ in 0..25 {
        if chip_count("DrawPrimitive") == 1 {
            chip_rendered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        chip_rendered,
        "the seeded priority chip must render on load"
    );
    assert!(
        checked("scope-translate-project-specific"),
        "project-specific binaries are in scope — the box reads checked"
    );
    assert!(
        checked("scope-translate-known-third-party"),
        "known third-party binaries are in scope — the box reads checked"
    );
    assert!(
        !checked("scope-skip-runtime"),
        "runtime binaries are in scope — the skip box reads unchecked"
    );
    assert!(
        !checked("scope-skip-unknown-third-party"),
        "unknown third-party binaries are in scope — the skip box reads unchecked"
    );

    // Constraints render from the status endpoint, and the token display
    // carries the budget minus the run's spend.
    assert_eq!(
        eval_text(
            &tab,
            "document.getElementById('scope-max-attempts')?.value || ''"
        ),
        "2"
    );
    assert_eq!(
        eval_text(
            &tab,
            "document.getElementById('scope-max-tier')?.value || ''"
        ),
        "Disassembly"
    );
    // The tier select's values come from the status response's
    // context_tiers, not from markup — every cap the server accepts is
    // an option, and only those (issue #109).
    assert_eq!(
        eval_text(
            &tab,
            "[...document.querySelectorAll('#scope-max-tier option')].map(o => o.value).join(',')"
        ),
        ",Signature,Disassembly,WithTests,ModuleContext,FullModule",
        "the tier select must offer exactly the tiers the status response names"
    );
    assert_eq!(
        eval_text(
            &tab,
            "document.getElementById('scope-token-budget')?.value || ''"
        ),
        "50000"
    );
    assert!(
        eval_text(
            &tab,
            "document.getElementById('scope-token-remaining')?.textContent || ''"
        )
        .contains("37655"),
        "the remaining-budget display follows the server's spend"
    );

    // Toggling "skip runtime functions" drives POST /api/scope/binaries —
    // the exclusion lands server-side, and the panel keeps the box checked
    // because it re-rendered from the server's answer.
    tab.evaluate(
        "document.getElementById('scope-skip-runtime').click() === undefined",
        false,
    )
    .expect("toggle skip-runtime");
    let mut binaries_landed = false;
    for _ in 0..25 {
        if scope_binaries().await
            == vec![
                "d3d9.dll".to_string(),
                "engine.dll".to_string(),
                "mystery.dll".to_string(),
                "zlib.dll".to_string(),
            ]
        {
            binaries_landed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        binaries_landed,
        "the checkbox must drive POST /api/scope/binaries with the runtime binary excluded"
    );
    assert!(
        checked("scope-skip-runtime"),
        "the checkbox follows the server's answer, not a reverted local guess"
    );

    // Unchecking a translate-mode checkbox excludes that category: zlib's
    // box off drops it from the allow-list, while the WindowsOs binary no
    // checkbox speaks for keeps its place from the server's current list.
    tab.evaluate(
        "document.getElementById('scope-translate-known-third-party').click() === undefined",
        false,
    )
    .expect("toggle translate-known-third-party");
    let mut exclusion_landed = false;
    for _ in 0..25 {
        if scope_binaries().await
            == vec![
                "d3d9.dll".to_string(),
                "engine.dll".to_string(),
                "mystery.dll".to_string(),
            ]
        {
            exclusion_landed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        exclusion_landed,
        "unchecking a translate checkbox must drop that category from the allow-list"
    );
    assert!(
        !checked("scope-translate-known-third-party"),
        "the unchecked box follows the server's answer"
    );

    // Round-trip back: re-checking known third-party and un-checking the
    // runtime skip covers every known binary again — sent as the empty
    // unsteered list, and the checkboxes render from that echo.
    tab.evaluate(
        "document.getElementById('scope-translate-known-third-party').click() === undefined; \
             document.getElementById('scope-skip-runtime').click() === undefined",
        false,
    )
    .expect("restore both checkboxes");
    let mut unsteered_restored = false;
    for _ in 0..25 {
        if scope_binaries().await.is_empty() {
            unsteered_restored = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        unsteered_restored,
        "covering every known binary again must return the scope to the unsteered empty list"
    );
    assert!(
        !checked("scope-skip-runtime") && checked("scope-translate-known-third-party"),
        "after the round-trip the checkboxes render the unsteered state honestly"
    );

    // Adding a priority function through the form drives the priority
    // endpoint; the chip appears and the server agrees.
    tab.evaluate(
        "document.getElementById('scope-priority-binary').value = 'zlib.dll'; \
             document.getElementById('scope-priority-function').value = 'InitZlib'; \
             document.getElementById('scope-priority-add-btn').click() === undefined",
        false,
    )
    .expect("add a priority function");
    let mut chip_added = false;
    for _ in 0..25 {
        if chip_count("InitZlib") == 1 {
            chip_added = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(chip_added, "the added priority chip must render");
    assert_eq!(
        priority_count().await,
        Some(2),
        "the added priority reached the server"
    );

    // Removing it drives the removal endpoint; the chip disappears and the
    // server's list shrinks.
    tab.evaluate(
        "document.querySelector('#scope-priority-list .scope-priority-chip[data-function=\"InitZlib\"] .scope-priority-remove').click() === undefined",
        false,
    )
    .expect("remove the priority function");
    let mut chip_removed = false;
    for _ in 0..25 {
        if chip_count("InitZlib") == 0 {
            chip_removed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(chip_removed, "the removed priority chip must disappear");
    assert_eq!(
        priority_count().await,
        Some(1),
        "the removal reached the server"
    );
    assert_eq!(
        chip_count("DrawPrimitive"),
        1,
        "the untouched priority entry stays rendered"
    );

    // Applying new constraints replaces them wholesale; the display and
    // the server both follow.
    tab.evaluate(
        "document.getElementById('scope-max-attempts').value = '3'; \
             document.getElementById('scope-max-tier').value = ''; \
             document.getElementById('scope-token-budget').value = '90000'; \
             document.getElementById('scope-constraints-apply').click() === undefined",
        false,
    )
    .expect("apply constraints");
    let mut constraints_landed = false;
    for _ in 0..25 {
        let body = get_scope().await;
        if body["constraints"]["max_attempts"] == serde_json::json!(3)
            && body["constraints"]["max_context_tier"].is_null()
            && body["constraints"]["token_budget"] == serde_json::json!(90000)
        {
            constraints_landed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        constraints_landed,
        "the constraint inputs must drive POST /api/scope/constraints wholesale"
    );
    assert!(
        eval_text(
            &tab,
            "document.getElementById('scope-token-remaining')?.textContent || ''"
        )
        .contains("77655"),
        "the remaining-budget display follows the new budget"
    );

    tab.close_target().ok();
    drop(browser);
}

/// The scope panel on a plain `serve` router (no scope control attached)
/// says so honestly and disables itself — the controls header's honesty
/// rule, same shape (issue #95, W2.6).
///
/// Run with: `cargo test --features server --test e2e headless -- --ignored`
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Chromium/Chrome installed; run with --ignored"]
async fn test_headless_scope_controls_honest_without_control() {
    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let browser = launch_headless_browser();
    let tab = open_dashboard_tab(&browser, fixture.port());

    let mut honest = false;
    for _ in 0..25 {
        if eval_bool(
            &tab,
            "!!document.getElementById('scope-unavailable') && \
                 document.getElementById('scope-unavailable').style.display !== 'none' && \
                 document.getElementById('scope-body').style.display === 'none'",
        ) {
            honest = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        honest,
        "without a scope control the panel must show its honest unavailable state"
    );
    assert!(
        eval_text(
            &tab,
            "document.getElementById('scope-unavailable-message')?.textContent || ''"
        )
        .contains("calxgloss live"),
        "the message names what the panel needs"
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
            &tab,
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
        if eval_bool(&tab, all_sections) {
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
    let tier_text = eval_text(
        &tab,
        "document.getElementById('process-tier-section')?.textContent || ''",
    );
    assert!(
        tier_text.contains("with_tests"),
        "tier section should show the final tier label, got: {tier_text}"
    );
    assert!(
        tier_text.contains("escalated"),
        "tier section should flag escalation, got: {tier_text}"
    );

    // The fault section lists the canned fault categories.
    let fault_text = eval_text(
        &tab,
        "document.getElementById('process-faults-section')?.textContent || ''",
    );
    assert!(
        fault_text.contains("context_window_exceeded") && fault_text.contains("hallucination"),
        "fault section should list both canned faults, got: {fault_text}"
    );

    // The strategy section shows the retry strategies used.
    let strategy_text = eval_text(
        &tab,
        "document.getElementById('process-strategies-section')?.textContent || ''",
    );
    assert!(
        strategy_text.contains("initial") && strategy_text.contains("compile_fix"),
        "strategy section should list both strategies, got: {strategy_text}"
    );

    tab.close_target().ok();
    drop(browser);
}

/// Headless-browser test for the unit detail panel's attempt list
/// (issue #131, W4.5): clicking the two-attempt DrawPrimitive unit renders
/// one entry per persisted attempt with the joined metadata — strategies,
/// tiers, token counts, and commit identities from the seeded logs and
/// patch records — and no "nothing to compare" note.
///
/// Run with: `cargo test --features server --test e2e headless -- --ignored`
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Chromium/Chrome installed; run with --ignored"]
async fn test_headless_unit_attempts_list_metadata() {
    let fixture = TestFixture::new();
    write_token_usage_fixture(
        &fixture.repo_path(),
        &[
            token_usage_entry(
                "game_logic.dll",
                "DrawPrimitive",
                1,
                "initial",
                4000,
                false,
                "stub",
                1759053600,
            ),
            token_usage_entry(
                "GAME_LOGIC.DLL",
                "DrawPrimitive",
                2,
                "escalate",
                2500,
                true,
                "with_tests",
                1759059000,
            ),
        ],
    );
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(500)).await;

    let browser = launch_headless_browser();
    let tab = open_dashboard_tab(&browser, fixture.port());

    tab.evaluate(
        "document.querySelector('.nav-tab[data-view=\"queue\"]')?.click() === undefined",
        false,
    )
    .expect("click queue tab");

    tab.evaluate(
        "document.querySelector('#full-queue-list [data-unit-id=\"game_logic.dll/DrawPrimitive/v2\"]').click() === undefined",
        false,
    )
    .expect("click queue item");

    // The attempts section fills asynchronously; poll until both attempt
    // entries are rendered (up to ~5 seconds).
    let two_attempts =
        "document.querySelectorAll('#unit-attempts-section .unit-attempt-item').length === 2";
    let mut rendered = false;
    for _ in 0..25 {
        if eval_bool(&tab, two_attempts) {
            rendered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(rendered, "attempts section should render both attempts");

    let section = eval_text(
        &tab,
        "document.getElementById('unit-attempts-section')?.textContent || ''",
    );
    for expected in [
        "Attempt 1",
        "Attempt 2",
        "initial",
        "escalate",
        "stub",
        "with_tests",
        "4,000",
        "2,500",
        "abc123",
        "def456",
    ] {
        assert!(
            section.contains(expected),
            "attempts section should show {expected}, got: {section}"
        );
    }
    assert!(
        !section.contains("nothing to compare"),
        "a two-attempt unit never shows the single-attempt note, got: {section}"
    );

    tab.close_target().ok();
    drop(browser);
}

/// Headless-browser honest state for issue #131: a single-attempt unit
/// shows exactly one attempt entry and the "nothing to compare" note —
/// the panel never pretends a diff is possible.
///
/// Run with: `cargo test --features server --test e2e headless -- --ignored`
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Chromium/Chrome installed; run with --ignored"]
async fn test_headless_unit_attempts_single_attempt_note() {
    let fixture = TestFixture::new();
    // A queued unit with one branch and no patch records or logs.
    add_pending_translation(&fixture, "RenderHUD");
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(500)).await;

    let browser = launch_headless_browser();
    let tab = open_dashboard_tab(&browser, fixture.port());

    tab.evaluate(
        "document.querySelector('.nav-tab[data-view=\"queue\"]')?.click() === undefined",
        false,
    )
    .expect("click queue tab");

    tab.evaluate(
        "document.querySelector('#full-queue-list [data-unit-id=\"game_logic.dll/RenderHUD/v1\"]').click() === undefined",
        false,
    )
    .expect("click queue item");

    let one_attempt =
        "document.querySelectorAll('#unit-attempts-section .unit-attempt-item').length === 1";
    let mut rendered = false;
    for _ in 0..25 {
        if eval_bool(&tab, one_attempt) {
            rendered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        rendered,
        "attempts section should render the single attempt"
    );

    let section = eval_text(
        &tab,
        "document.getElementById('unit-attempts-section')?.textContent || ''",
    );
    assert!(
        section.contains("nothing to compare"),
        "a single-attempt unit honestly says there is nothing to compare, got: {section}"
    );
    assert!(
        section.contains("Attempt 1"),
        "the one attempt is still listed, got: {section}"
    );

    tab.close_target().ok();
    drop(browser);
}

/// Adds a DrawPrimitive attempt branch with its own commit, so the
/// fixture unit gains another comparable attempt whose tree differs —
/// a pair the side-by-side diff can visibly switch between.
fn add_attempt_branch_with_commit(fixture: &TestFixture, attempt: u32, file_stem: &str) {
    let git = GitManager::open(&fixture.repo_path()).expect("open fixture repo");
    let branch = GitBranch::new("game_logic.dll", "DrawPrimitive", attempt).expect("branch name");
    git.create_branch("game_logic.dll", "DrawPrimitive", attempt, None)
        .expect("create branch");

    let src_file = format!("src/{file_stem}.rs");
    std::fs::create_dir_all(fixture.repo_path().join("src")).expect("create src dir");
    std::fs::write(
        fixture.repo_path().join(&src_file),
        format!(
            "/// {file_stem} — retry translation\npub fn {file_stem}(_encoder: &mut wgpu::CommandEncoder) {{}}\n"
        ),
    )
    .expect("write translation file");
    git.commit(
        &branch,
        &format!("Retry DrawPrimitive — attempt {attempt}"),
        &[src_file.as_str()],
    )
    .expect("commit branch");
}

/// Headless-browser test for the unit detail panel's attempt comparison
/// (issue #135, W4.6): a three-attempt unit renders pickers defaulting to
/// the last two attempts and a side-by-side diff of their branches with
/// additions and deletions styled per the dark theme — and picking a
/// different pair changes the rendered diff.
///
/// Run with: `cargo test --features server --test e2e headless -- --ignored`
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Chromium/Chrome installed; run with --ignored"]
async fn test_headless_unit_attempt_diff_side_by_side() {
    let fixture = TestFixture::new();
    add_attempt_branch_with_commit(&fixture, 3, "draw_primitive_v3");
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(500)).await;

    let browser = launch_headless_browser();
    let tab = open_dashboard_tab(&browser, fixture.port());

    tab.evaluate(
        "document.querySelector('.nav-tab[data-view=\"queue\"]')?.click() === undefined",
        false,
    )
    .expect("click queue tab");

    tab.evaluate(
        "document.querySelector('#full-queue-list [data-unit-id=\"game_logic.dll/DrawPrimitive/v2\"]').click() === undefined",
        false,
    )
    .expect("click queue item");

    // The attempts section fills asynchronously; poll until all three
    // attempt entries are rendered (up to ~5 seconds).
    let three_attempts =
        "document.querySelectorAll('#unit-attempts-section .unit-attempt-item').length === 3";
    let mut rendered = false;
    for _ in 0..25 {
        if eval_bool(&tab, three_attempts) {
            rendered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        rendered,
        "attempts section should render all three attempts"
    );

    // The pickers default to the last two attempts.
    let default_from = eval_text(
        &tab,
        "document.getElementById('attempt-diff-from')?.value || ''",
    );
    let default_to = eval_text(
        &tab,
        "document.getElementById('attempt-diff-to')?.value || ''",
    );
    assert_eq!(
        default_from, "2",
        "the from picker defaults to the second-to-last attempt"
    );
    assert_eq!(
        default_to, "3",
        "the to picker defaults to the last attempt"
    );

    // The default pair (2 → 3) shows the v2 file removed and the v3 file
    // added, styled as deletions and additions.
    let styled = "document.querySelectorAll('#attempt-diff-body .diff-line.deletion').length > 0 \
                  && document.querySelectorAll('#attempt-diff-body .diff-line.addition').length > 0";
    let mut diff_rendered = false;
    for _ in 0..25 {
        if eval_bool(&tab, styled) {
            diff_rendered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        diff_rendered,
        "the attempt diff renders styled additions and deletions"
    );

    let diff_text = eval_text(
        &tab,
        "document.getElementById('attempt-diff-body')?.textContent || ''",
    );
    assert!(
        diff_text.contains("src/draw_primitive_v3.rs"),
        "the default diff shows the v3 attempt's file, got: {diff_text}"
    );
    assert!(
        diff_text.contains("src/draw_primitive_v2.rs"),
        "the default diff shows the v2 attempt's file removed, got: {diff_text}"
    );

    // The reviewer picks a different pair (1 → 2): the rendered diff
    // changes to the v2 file appearing, with no v3 file anywhere.
    tab.evaluate(
        "(() => { const f = document.getElementById('attempt-diff-from'); f.value = '1'; f.dispatchEvent(new Event('change')); const t = document.getElementById('attempt-diff-to'); t.value = '2'; t.dispatchEvent(new Event('change')); return true; })()",
        false,
    )
    .expect("switch the pickers to the pair 1 → 2");

    let switched = "(document.getElementById('attempt-diff-body')?.textContent || '').includes('draw_primitive_v2.rs') \
         && !(document.getElementById('attempt-diff-body')?.textContent || '').includes('draw_primitive_v3')";
    let mut changed = false;
    for _ in 0..25 {
        if eval_bool(&tab, switched) {
            changed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        changed,
        "picking a different attempt pair re-renders the diff, got: {}",
        eval_text(
            &tab,
            "document.getElementById('attempt-diff-body')?.textContent || ''"
        )
    );

    tab.close_target().ok();
    drop(browser);
}

/// Headless-browser test for the Overrides tab in the unit detail panel
/// (issue #96, W2.7): the tab renders the override seeded on the shared
/// handle — summary rows, pre-filled form controls, and reviewer notes
/// injected into the overview — and toggling skip and clicking Apply
/// drives the endpoint end to end, with the rendered state following the
/// record the server echoes back.
///
/// Run with: `cargo test --features server --test e2e headless -- --ignored`
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Chromium/Chrome installed; run with --ignored"]
async fn test_headless_unit_overrides_tab() {
    let fixture = TestFixture::new();
    write_canned_run_telemetry(&fixture);
    // The unit is already steered — the tab must render exactly this on
    // load, not defaults.
    let overrides = calxgloss_types::OverrideControl::open(fixture.repo_path());
    overrides
        .set(
            "game_logic.dll",
            "DrawPrimitive",
            calxgloss_types::FunctionOverride {
                tier_override: Some(calxgloss_types::ContextTier::FullModule),
                retry_strategy_override: Some(calxgloss_types::RetryStrategy::Escalate),
                custom_hints: vec!["blitter routine".into()],
                skip: false,
                reviewer_notes: "looks like a blitter".into(),
            },
        )
        .expect("seeded override persists");
    let state = ServerState::new(fixture.repo_path()).with_override_control(overrides);
    let events = TranslationEvents::new(128);
    let manager = SessionManager::new_with_broadcast(events.subscribe());
    let progress = ProgressState::new();
    let router = build_router_with_ws(state, manager, progress, ws_actions(&fixture));
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(500)).await;

    let browser = launch_headless_browser();
    let tab = open_dashboard_tab(&browser, fixture.port());

    // Switch to the queue view and open the telemetry-backed unit's detail.
    tab.evaluate(
        "document.querySelector('.nav-tab[data-view=\"queue\"]')?.click() === undefined",
        false,
    )
    .expect("click queue tab");
    let mut listed = false;
    for _ in 0..25 {
        if eval_bool(
            &tab,
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
    tab.evaluate(
        "document.querySelector('#full-queue-list [data-unit-id=\"game_logic.dll/DrawPrimitive/v2\"]').click() === undefined",
        false,
    )
    .expect("click queue item");

    // Click the Overrides tab in the detail's tab bar.
    tab.evaluate(
        "document.querySelector('[data-diff-tab=\"overrides\"]')?.click() === undefined",
        false,
    )
    .expect("click overrides tab");

    // The tab renders the seeded record: the summary spells out the forced
    // tier and strategy, and the form controls come back pre-filled.
    let mut rendered = false;
    for _ in 0..25 {
        if eval_bool(
            &tab,
            "document.getElementById('overrides-body')?.textContent?.includes('forced to FullModule') === true",
        ) {
            rendered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let summary = eval_text(
        &tab,
        "document.getElementById('override-summary')?.textContent || ''",
    );
    assert!(
        rendered,
        "overrides tab should render the seeded summary, got: {summary}"
    );
    assert!(
        summary.contains("forced to escalate") && summary.contains("1 appended to the prompt"),
        "summary should name the forced strategy and hint count, got: {summary}"
    );
    assert_eq!(
        eval_text(
            &tab,
            "document.getElementById('override-tier')?.value || ''"
        ),
        "FullModule",
        "the tier select should come back pre-filled"
    );
    assert_eq!(
        eval_text(
            &tab,
            "document.getElementById('override-strategy')?.value || ''"
        ),
        "escalate",
        "the strategy select should come back pre-filled"
    );
    assert!(
        eval_text(
            &tab,
            "document.getElementById('override-hints')?.value || ''"
        )
        .contains("blitter routine"),
        "the hints textarea should come back pre-filled"
    );

    // Reviewer notes display in the overview too, not only inside the tab.
    let notes_text = eval_text(
        &tab,
        "document.getElementById('reviewer-notes-section')?.textContent || ''",
    );
    assert!(
        notes_text.contains("looks like a blitter"),
        "the overview should show the reviewer notes, got: {notes_text}"
    );

    // Toggling skip and clicking Apply drives the endpoint; the summary
    // follows the record the server echoes back.
    tab.evaluate(
        "document.getElementById('override-skip')?.click() === undefined",
        false,
    )
    .expect("toggle skip checkbox");
    tab.evaluate(
        "document.getElementById('override-apply')?.click() === undefined",
        false,
    )
    .expect("click apply");
    let mut skip_applied = false;
    for _ in 0..25 {
        if eval_bool(
            &tab,
            "document.getElementById('override-summary')?.textContent?.includes('skipped') === true",
        ) {
            skip_applied = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        skip_applied,
        "the summary should show the skip after Apply, got: {}",
        eval_text(
            &tab,
            "document.getElementById('override-summary')?.textContent || ''"
        )
    );
    let body = reqwest::get(format!(
        "http://127.0.0.1:{}/api/units/game_logic.dll%2FDrawPrimitive%2Fv2/override",
        fixture.port()
    ))
    .await
    .expect("override endpoint reachable")
    .json::<serde_json::Value>()
    .await
    .expect("override body is JSON");
    assert_eq!(
        body["override"]["skip"], true,
        "the skip flag landed on the server, got: {body}"
    );

    tab.close_target().ok();
    drop(browser);
}

/// Headless-browser test for the binary classification override panel
/// (issue #97, W2.8): clicking Classify on a pipeline row renders the
/// recorded classification with its reasoning, and choosing a category and
/// crate and clicking Apply drives the endpoint end to end — the panel
/// adopts the override the server echoes back, and the record persists in
/// the workspace for the next run.
///
/// Run with: `cargo test --features server --test e2e headless -- --ignored`
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Chromium/Chrome installed; run with --ignored"]
async fn test_headless_classification_override_panel() {
    let fixture = TestFixture::new();
    write_canned_classification_record(&fixture, "fmod.dll", "UnknownThirdParty");
    let overrides = calxgloss_types::ClassificationOverrideControl::open(fixture.repo_path());
    let state =
        ServerState::new(fixture.repo_path()).with_classification_override_control(overrides);
    let events = TranslationEvents::new(128);
    let manager = SessionManager::new_with_broadcast(events.subscribe());
    let progress = ProgressState::new();
    let router = build_router_with_ws(state, manager, progress, ws_actions(&fixture));
    let _server = spawn_server(router, fixture.port()).await;

    // One classified binary so the row exists to click.
    events.emit(ProgressEvent::ClassificationComplete {
        binary: "fmod.dll".into(),
        category: "UnknownThirdParty".into(),
        classification_strategy: "ReverseEngineer".into(),
        crate_replacement: None,
        exported_symbols: 10,
        imported_symbols: 4,
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    let browser = launch_headless_browser();
    let tab = open_dashboard_tab(&browser, fixture.port());

    // Wait for the row, then click its Classify button.
    let mut listed = false;
    for _ in 0..25 {
        if eval_bool(
            &tab,
            "!!document.querySelector('#pipeline-binaries [data-binary=\"fmod.dll\"]')",
        ) {
            listed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(listed, "pipeline row for fmod.dll should exist");
    tab.evaluate(
        "document.querySelector('#pipeline-binaries [data-binary=\"fmod.dll\"] [data-action=\"classify\"]').click() === undefined",
        false,
    )
    .expect("click classify button");

    // The panel renders the recorded classification with its reasoning.
    let mut rendered = false;
    for _ in 0..25 {
        if eval_bool(
            &tab,
            "document.getElementById('classification-override-panel')?.textContent?.includes('no known library') === true",
        ) {
            rendered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let panel_text = eval_text(
        &tab,
        "document.getElementById('classification-override-panel')?.textContent || ''",
    );
    assert!(
        rendered,
        "panel should render the recorded classification with reasoning, got: {panel_text}"
    );
    assert!(
        panel_text.contains("UnknownThirdParty"),
        "the current category should show, got: {panel_text}"
    );
    assert!(
        panel_text.contains("No override in force"),
        "the absence of an override should be stated, got: {panel_text}"
    );

    // Steer it: a known third-party crate replacement, then Apply.
    tab.evaluate(
        "document.getElementById('clf-category').value = 'KnownThirdParty'",
        false,
    )
    .expect("select category");
    tab.evaluate(
        "document.getElementById('clf-crate').value = 'fmod-rs'",
        false,
    )
    .expect("fill crate");
    tab.evaluate(
        "document.getElementById('clf-apply').click() === undefined",
        false,
    )
    .expect("click apply");

    // The panel adopts the override the server echoes back.
    let mut applied = false;
    for _ in 0..25 {
        if eval_bool(
            &tab,
            "document.getElementById('classification-override-panel')?.textContent?.includes('Override in force: KnownThirdParty') === true",
        ) {
            applied = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        applied,
        "the panel should show the override after Apply, got: {}",
        eval_text(
            &tab,
            "document.getElementById('classification-override-panel')?.textContent || ''"
        )
    );

    // The record landed in the workspace — a restarted run honors it.
    let reopened = calxgloss_types::ClassificationOverrideControl::open(fixture.repo_path());
    let record = reopened
        .get("fmod.dll")
        .expect("the override persists in the workspace");
    assert_eq!(
        record.category,
        calxgloss_types::DllCategory::KnownThirdParty
    );
    assert_eq!(
        record.crate_replacement.as_deref(),
        Some("fmod-rs"),
        "the crate replacement rides along"
    );

    tab.close_target().ok();
    drop(browser);
}

/// Headless-browser counterpart of the 503 contract: on a live router with
/// no classification-override control attached, the panel renders the
/// server's honest refusal instead of controls (issue #97).
///
/// Run with: `cargo test --features server --test e2e headless -- --ignored`
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Chromium/Chrome installed; run with --ignored"]
async fn test_headless_classification_override_honest_without_control() {
    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path());
    let events = TranslationEvents::new(128);
    let manager = SessionManager::new_with_broadcast(events.subscribe());
    let progress = ProgressState::new();
    let router = build_router_with_ws(state, manager, progress, ws_actions(&fixture));
    let _server = spawn_server(router, fixture.port()).await;

    events.emit(ProgressEvent::ClassificationComplete {
        binary: "fmod.dll".into(),
        category: "UnknownThirdParty".into(),
        classification_strategy: "ReverseEngineer".into(),
        crate_replacement: None,
        exported_symbols: 10,
        imported_symbols: 4,
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    let browser = launch_headless_browser();
    let tab = open_dashboard_tab(&browser, fixture.port());

    let mut listed = false;
    for _ in 0..25 {
        if eval_bool(
            &tab,
            "!!document.querySelector('#pipeline-binaries [data-binary=\"fmod.dll\"]')",
        ) {
            listed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(listed, "pipeline row for fmod.dll should exist");
    tab.evaluate(
        "document.querySelector('#pipeline-binaries [data-binary=\"fmod.dll\"] [data-action=\"classify\"]').click() === undefined",
        false,
    )
    .expect("click classify button");

    // The server's own reason renders — no controls, no fabricated state.
    let mut honest = false;
    for _ in 0..25 {
        if eval_bool(
            &tab,
            "document.getElementById('classification-override-panel')?.textContent?.includes('no classification override control') === true",
        ) {
            honest = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        honest,
        "the panel should render the server's honest 503 reason"
    );
    assert!(
        !eval_bool(&tab, "!!document.getElementById('clf-apply')"),
        "no form controls when the endpoints are unavailable"
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
            &tab,
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
        if eval_bool(&tab, all_sections) {
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
    let api_text = eval_text(
        &tab,
        "document.getElementById('api-mappings-section')?.textContent || ''",
    );
    assert!(
        api_text.contains("Present")
            && api_text.contains("DirectX")
            && api_text.contains("wgpu::Surface::present"),
        "API mappings section should show name, category, and PAL mapping, got: {api_text}"
    );

    // The call graph section lists resolved caller and callee names.
    let cg_text = eval_text(
        &tab,
        "document.getElementById('call-graph-section')?.textContent || ''",
    );
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
    let router = build_router_with_ws(state, manager, progress, ws_actions(&fixture));
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;
    emit_canned_batch_summary(&events);
    tokio::time::sleep(Duration::from_millis(300)).await;

    let browser = launch_headless_browser();
    let tab = open_dashboard_tab(&browser, fixture.port());

    // The pipeline panel renders asynchronously; poll until the time
    // estimate is visible (up to ~5 seconds).
    let mut estimate_visible = false;
    for _ in 0..25 {
        if eval_bool(
            &tab,
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
            &tab,
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
        &tab,
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
            &tab,
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
            &tab,
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
            &tab,
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
        if eval_bool(
            &tab,
            &format!(
                "(() => {{ const el = document.querySelector('{row_sel} .qi-skip-check'); \
                    return !!el && el.checked === false; }})()"
            ),
        ) {
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
        if eval_bool(
            &tab,
            &format!(
                "(() => {{ const row = document.querySelector('{row_sel}'); \
                    const cb = row?.querySelector('.qi-skip-check'); \
                    const st = row?.querySelector('.qi-status'); \
                    return !!cb && cb.checked === true \
                        && !!st && st.textContent.includes('Skipped'); }})()"
            ),
        ) {
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
        if eval_bool(
            &tab,
            &format!(
                "(() => {{ const el = document.querySelector('{row_sel} .qi-skip-check'); \
                    return !!el && el.checked === false; }})()"
            ),
        ) {
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
        if eval_bool(
            &tab,
            &format!(
                "(() => {{ const a = document.querySelector('{draw_sel} .qi-select'); \
                    const b = document.querySelector('{hud_sel} .qi-select'); \
                    return !!a && !a.checked && !!b && !b.checked; }})()"
            ),
        ) {
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
            &tab,
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
        eval_bool(
            &tab,
            &format!(
                "(() => {{ const a = document.querySelector('{draw_sel} .qi-select'); \
                    const b = document.querySelector('{hud_sel} .qi-select'); \
                    return !!a && a.checked && !!b && b.checked; }})()"
            )
        ),
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
        if eval_bool(
            &tab,
            &format!(
                "(() => {{ const a = document.querySelector('{draw_sel} .qi-select'); \
                    const b = document.querySelector('{hud_sel} .qi-select'); \
                    const sa = document.querySelector('{draw_sel} .qi-skip-check'); \
                    const sb = document.querySelector('{hud_sel} .qi-skip-check'); \
                    return !!a && !a.checked && !!b && !b.checked \
                        && !!sa && sa.checked && !!sb && sb.checked; }})()"
            ),
        ) {
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
        if eval_bool(
            &tab,
            "!!window.calxglossGraph && window.calxglossGraph.totalNodeCount >= 5",
        ) {
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
            &tab,
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
        &tab,
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
            &tab,
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
            &tab,
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

    let eval_str = |expr: &str| -> Option<String> {
        tab.evaluate(expr, false)
            .ok()
            .and_then(|r| r.value)
            .and_then(|v| v.as_str().map(|s| s.to_string()))
    };

    // Wait for the graph renderer to load the fixture's units.
    let mut loaded = false;
    for _ in 0..25 {
        if eval_bool(
            &tab,
            "!!window.calxglossGraph && window.calxglossGraph.totalNodeCount >= 5",
        ) {
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
        if eval_bool(
            &tab,
            "!!window.calxglossGraph && window.calxglossGraph.visibleNodeCount === 2",
        ) {
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
    let router = build_router_with_ws(state, manager, progress, ws_actions(&fixture));
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    // History from a "previous run": persisted before the page opens, so
    // the view must load it from the server rather than a memory buffer.
    let log = LlmIoLog::new(fixture.repo_path());
    log.record(&ProgressEvent::LlmRequest {
        binary: "game_logic.dll".into(),
        function: "DrawPrimitive".into(),
        attempt: 1,
        retry_strategy: "direct".into(),
        prompt: "translate DrawPrimitive from the decompile".into(),
    });
    log.record(&ProgressEvent::LlmResponse {
        binary: "game_logic.dll".into(),
        function: "DrawPrimitive".into(),
        attempt: 1,
        retry_strategy: "direct".into(),
        content: "fn draw_primitive() {}".into(),
        tokens_used: Some(4321),
    });
    log.record(&ProgressEvent::LlmRequest {
        binary: "d3d9.dll".into(),
        function: "UpdateScene".into(),
        attempt: 2,
        retry_strategy: "compile_fix".into(),
        prompt: "fix the compile errors in UpdateScene".into(),
    });

    let browser = launch_headless_browser();
    let tab = open_dashboard_tab(&browser, fixture.port());

    let visible_count = || {
        eval_count(
            &tab,
            "document.querySelectorAll('#llm-log-entries .llm-log-entry').length",
        )
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
        &tab,
        "document.querySelector('#llm-log-entries .llm-log-entry:nth-child(2) .meta').textContent",
    );
    assert!(
        response_meta.contains("4321 tokens"),
        "response entry should show its token count, got: {response_meta}"
    );
    let request_meta = eval_text(
        &tab,
        "document.querySelector('#llm-log-entries .llm-log-entry:nth-child(1) .meta').textContent",
    );
    assert!(
        request_meta.contains('—'),
        "request entry should show an em dash for the unmeasured token count, got: {request_meta}"
    );

    // Entries start collapsed: the body is hidden until the header is clicked.
    assert!(
        eval_bool(
            &tab,
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
            &tab,
            "document.querySelector('#llm-log-entries .llm-log-entry .llm-log-entry-body').offsetHeight > 0"
        ),
        "header click should expand the entry"
    );

    // One-click copy: every entry carries a copy button.
    assert!(
        eval_bool(
            &tab,
            "document.querySelectorAll('#llm-log-entries .llm-log-copy').length === 3"
        ),
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
    let searched_meta = eval_text(
        &tab,
        "document.querySelector('#llm-log-entries .llm-log-entry .meta').textContent",
    );
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
        retry_strategy: "direct".into(),
        prompt: "translate UpdateScene".into(),
    });
    events.emit(ProgressEvent::LlmCallFailed {
        binary: "d3d9.dll".into(),
        function: "UpdateScene".into(),
        attempt: 4,
        retry_strategy: "retry".into(),
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
    let router = build_router_with_ws(state, manager, progress, ws_actions(&fixture));
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
            retry_strategy: "decompose".into(),
        },
    ] {
        events.emit(event);
    }
    tokio::time::sleep(Duration::from_millis(300)).await;

    let browser = launch_headless_browser();
    let tab = open_dashboard_tab(&browser, fixture.port());

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
        if eval_count(
            &tab,
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
        eval_count(
            &tab,
            "document.querySelectorAll('#live-units .live-unit').length"
        )
    );

    // The row carries the phase label and the evidence the stream reported.
    let row = "#live-units .live-unit[data-function=\"DrawPrimitive\"]";
    let row_text = |suffix: &str| -> String {
        eval_text(
            &tab,
            &format!("document.querySelector('{row}')?{suffix} || ''"),
        )
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
        retry_strategy: "decompose".into(),
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
        if eval_bool(
            &tab,
            &format!(
                "(() => {{ const r = document.querySelector('{row}'); \
                return !!r && r.classList.contains('finished-ok') && \
                    r.querySelector('.live-phase')?.textContent === 'Review'; }})()"
            ),
        ) {
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
        history.contains("Scan Fetch")
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

    tab.evaluate(
        "document.querySelector('.nav-tab[data-view=\"live\"]')?.click() === undefined",
        false,
    )
    .expect("click live tab");

    // The honest empty state must appear (poll up to ~5 seconds).
    let mut announced = false;
    for _ in 0..25 {
        if eval_bool(
            &tab,
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
        !eval_bool(
            &tab,
            "document.querySelector('#live-units .live-unit') !== null"
        ),
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

    // Category cards: one per DllCategory, with the fixture's counts.
    let mut cards_rendered = false;
    for _ in 0..25 {
        if eval_bool(
            &tab,
            "(() => { const cards = document.querySelectorAll('#category-cards .category-card'); \
                if (cards.length !== 7) return false; \
                const ps = document.querySelector('#category-cards [data-category=\"ProjectSpecific\"]'); \
                const sdk = document.querySelector('#category-cards [data-category=\"MicrosoftSdk\"]'); \
                const dotnet = document.querySelector('#category-cards [data-category=\"DotNetManaged\"]'); \
                return !!ps && !!sdk && ps.textContent.includes('1') && sdk.textContent.includes('1') && \
                    !!dotnet && \
                    dotnet.querySelector('.category-card-label')?.textContent === '.NET Managed' && \
                    dotnet.querySelector('.category-card-value')?.textContent === '0'; })()",
        ) {
            cards_rendered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        cards_rendered,
        "category cards should render 7 categories with fixture counts, with the DotNetManaged card present at an honest zero"
    );

    // Quality summary: avg confidence 73% (0.725 rounded), and honest
    // em-dashes for the baseline/verification rates with no data behind them.
    let mut quality_rendered = false;
    for _ in 0..25 {
        if eval_bool(
            &tab,
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
        eval_text(
            &tab,
            "document.getElementById('quality-summary')?.textContent || ''"
        )
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
            &tab,
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
        eval_text(
            &tab,
            "document.getElementById('token-budget')?.textContent || ''"
        )
    );

    tab.close_target().ok();
    drop(browser);
}

/// Headless-browser test: a browser reload keeps the tab the operator was
/// on — clicking the pipeline tab and reloading must land back on the
/// pipeline view, not the dashboard.
///
/// Run with: `cargo test --features server --test e2e headless -- --ignored`
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Chromium/Chrome installed; run with --ignored"]
async fn test_headless_reload_keeps_current_tab() {
    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let browser = launch_headless_browser();
    let tab = open_dashboard_tab(&browser, fixture.port());

    // Switch to the pipeline tab.
    tab.evaluate(
        "(() => { document.querySelector('.nav-tab[data-view=\"pipeline\"]').click(); })()",
        false,
    )
    .expect("click pipeline tab");

    let mut pipeline_active = false;
    for _ in 0..25 {
        if eval_bool(
            &tab,
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
        "pipeline view should be active after the tab click"
    );

    // Reload: the pipeline view must still be the active one.
    tab.reload(false, None).expect("reload");
    tab.wait_until_navigated().expect("wait for reload");

    pipeline_active = false;
    for _ in 0..25 {
        if eval_bool(
            &tab,
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
        "reload should stay on the pipeline tab, not fall back to the dashboard"
    );

    tab.close_target().ok();
    drop(browser);
}
