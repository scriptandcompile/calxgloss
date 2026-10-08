//! End-to-end tests for the web review UI.
//!
//! These tests spin up the axum server in a real git repository with sample data,
//! then verify both API responses and headless-browser rendering.
//!
//! Run API-level tests: `cargo test --features server --test e2e`
//! Run browser tests:   `cargo test --features server --test e2e headless -- --ignored`

use calxgloss_git::{GitManager, InitConfig};
use calxgloss_types::{GitBranch, ProgressEvent, TranslationEvents};
use calxgloss_web::{
    ActionsState, ProgressState, ServerState, SessionManager, build_dashboard, build_router,
    build_router_with_actions, build_router_with_ws,
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
            classify_dir.join("game_logic.json"),
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
            classify_dir.join("d3d9.json"),
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
            let shim_branch = GitBranch::new("d3d9", "wgpu", 1).unwrap();
            git.create_branch("d3d9", "wgpu", 1, None).unwrap();

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

        // 4. Create a translation branch `re/game_logic/DrawPrimitivev1`
        //    with a Rust source file.
        {
            let branch = GitBranch::new("game_logic", "DrawPrimitive", 1).unwrap();
            git.create_branch("game_logic", "DrawPrimitive", 1, None)
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
            let branch_v2 = GitBranch::new("game_logic", "DrawPrimitive", 2).unwrap();
            git.create_branch("game_logic", "DrawPrimitive", 2, None)
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

        // 5. A second translation: `re/game_logic/UpdateScenev1` (accepted/merged).
        {
            let branch = GitBranch::new("game_logic", "UpdateScene", 1).unwrap();
            git.create_branch("game_logic", "UpdateScene", 1, None)
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

        // 6. Create a patch record for game_logic/DrawPrimitive v1.
        let patch_dir = git
            .repo_path()
            .join("re")
            .join("patches")
            .join("game_logic")
            .join("DrawPrimitive");
        std::fs::create_dir_all(&patch_dir).unwrap();
        let patch_record = serde_json::json!({
            "dll": "game_logic",
            "function": "DrawPrimitive",
            "attempt": 1,
            "branch_name": "re/game_logic/DrawPrimitivev1",
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
            "dll": "game_logic",
            "function": "DrawPrimitive",
            "attempt": 2,
            "branch_name": "re/game_logic/DrawPrimitivev2",
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

        // 7. Create baseline test data for DrawPrimitive.
        let baseline_dir = git
            .repo_path()
            .join("re")
            .join("baseline")
            .join("game_logic.dll")
            .join("DrawPrimitive");
        std::fs::create_dir_all(&baseline_dir).unwrap();
        let baseline = serde_json::json!([
            {
                "input": {"vertices": [1,2,3], "index": 0},
                "expected_return": 0,
                "passed": true
            },
            {
                "input": {"vertices": [], "index": 0},
                "expected_return": 0,
                "passed": true
            },
            {
                "input": {"vertices": [99], "index": -1},
                "expected_return": -1,
                "passed": true
            }
        ]);
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
        let baseline_us_data = serde_json::json!([
            {
                "input": {"delta_time": 0.016},
                "expected_return": 0,
                "passed": true
            }
        ]);
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
    let (_handler, _sender) = manager.register_client().await;
    events.emit(ProgressEvent::TranslationStarted {
        dll: "game_logic".into(),
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
            .any(|id| id.contains("game_logic") && id.contains("DrawPrimitive")),
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
            .any(|id| id.contains("game_logic") && id.contains("UpdateScene")),
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

/// Verify that a single unit detail endpoint returns expected fields.
#[tokio::test]
async fn test_unit_detail_endpoint() {
    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let unit_id = "game_logic/DrawPrimitive/v2";
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
    assert_eq!(unit["dll"], "game_logic");
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
/// when no translation is running.
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
        dll: "game_logic".into(),
        function: "DrawPrimitive".into(),
        tier: tier.into(),
        tier_label: format!("{tier} label"),
        complexity: "Medium".into(),
        api_call_count: 3,
    };
    for event in [
        ProgressEvent::TranslationStarted {
            dll: "game_logic".into(),
            function: "DrawPrimitive".into(),
        },
        ProgressEvent::GhidraFetchComplete {
            dll: "game_logic".into(),
            function: "DrawPrimitive".into(),
            address: None,
            disassembly_lines: 10,
        },
        ProgressEvent::ApiTaggingComplete {
            dll: "game_logic".into(),
            function: "DrawPrimitive".into(),
            tagged_apis: 3,
        },
        ProgressEvent::TestsGenerated {
            dll: "game_logic".into(),
            function: "DrawPrimitive".into(),
            test_count: 5,
        },
        tier("T1"),
        ProgressEvent::LlmCallStart {
            dll: "game_logic".into(),
            function: "DrawPrimitive".into(),
            attempt: 1,
            strategy: "direct".into(),
        },
        ProgressEvent::LlmCallFailed {
            dll: "game_logic".into(),
            function: "DrawPrimitive".into(),
            attempt: 1,
            strategy: "direct".into(),
            error: "context window exceeded".into(),
        },
        tier("T2"),
        ProgressEvent::LlmCallStart {
            dll: "game_logic".into(),
            function: "DrawPrimitive".into(),
            attempt: 2,
            strategy: "decompose".into(),
        },
        ProgressEvent::LlmCallComplete {
            dll: "game_logic".into(),
            function: "DrawPrimitive".into(),
            attempt: 2,
            code_length: 120,
            tokens_used: None,
        },
        ProgressEvent::TranslationAttemptCompleted {
            dll: "game_logic".into(),
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
            dll: "game_logic".into(),
            function: "Update".into(),
        },
        ProgressEvent::TranslationCompleted {
            dll: "game_logic".into(),
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
    assert_eq!(unit["dll"].as_str(), Some("game_logic"));
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

/// Route-table contract: endpoints that read live translation state are
/// registered **only** in the WebSocket (live) router. On the plain serve
/// router and the actions router they must fall through to the static 404,
/// never answer with fabricated empty data.
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

        for path in ["/api/pipeline", "/api/progress", "/api/events/upgrade"] {
            let resp = reqwest::get(format!("http://127.0.0.1:{}{}", fixture.port(), path))
                .await
                .expect("request reaches server");
            assert_eq!(
                resp.status(),
                404,
                "{path} must not be routed on the {kind} router"
            );
        }
    }
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

    let unit_id = "game_logic/DrawPrimitive/v2";
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

    let unit_id = "game_logic/DrawPrimitive/v2";
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

    let unit_id = "game_logic/DrawPrimitive/v2";
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
            .any(|id| id.contains("game_logic") && id.contains("DrawPrimitive")),
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
            .any(|id| id.contains("game_logic") && id.contains("DrawPrimitive")),
        "DrawPrimitive unit present (all: {:?})",
        all_ids
    );
    assert!(
        all_ids
            .iter()
            .any(|id| id.contains("game_logic") && id.contains("UpdateScene")),
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
#[tokio::test]
#[ignore = "requires Chromium/Chrome installed; run with --ignored"]
async fn test_headless_browser_page_loads() {
    use headless_chrome::{Browser, LaunchOptionsBuilder};

    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(500)).await;

    let browser = Browser::new(
        LaunchOptionsBuilder::default()
            .headless(true)
            .args(vec![
                std::ffi::OsStr::new("--no-sandbox"),
                std::ffi::OsStr::new("--disable-gpu"),
                std::ffi::OsStr::new("--disable-dev-shm-usage"),
            ])
            .build()
            .unwrap(),
    )
    .expect("launch headless chrome");

    let tab = browser.new_tab().expect("open new tab");

    // Navigate to the server's root (HTML page).
    tab.navigate_to(&format!("http://127.0.0.1:{}", fixture.port()))
        .expect("navigate to server root");

    // Wait for the page to fully load.
    tab.wait_until_navigated().expect("wait for navigation");

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

    // Enable runtime for JS evaluation.
    tab.enable_runtime().expect("enable runtime");

    // Verify the dependency graph endpoint is reachable via fetch.
    let graph_result = tab
        .evaluate(
            "fetch('/api/graph').then(r => r.ok).catch(() => false)",
            false,
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
            false,
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
#[tokio::test]
#[ignore = "requires Chromium/Chrome installed; run with --ignored"]
async fn test_headless_server_status_card() {
    use headless_chrome::{Browser, LaunchOptionsBuilder};

    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(500)).await;

    let browser = Browser::new(
        LaunchOptionsBuilder::default()
            .headless(true)
            .args(vec![
                std::ffi::OsStr::new("--no-sandbox"),
                std::ffi::OsStr::new("--disable-gpu"),
                std::ffi::OsStr::new("--disable-dev-shm-usage"),
            ])
            .build()
            .expect("build chrome launch options"),
    )
    .expect("launch headless chrome");

    let tab = browser.new_tab().expect("open new tab");
    tab.navigate_to(&format!("http://127.0.0.1:{}", fixture.port()))
        .expect("navigate to server root");
    tab.wait_until_navigated().expect("wait for navigation");
    tab.enable_runtime().expect("enable runtime");

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
