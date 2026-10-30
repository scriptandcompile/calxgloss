//! End-to-end tests for the web review UI.
//!
//! These tests spin up the axum server in a real git repository with sample data,
//! then verify both API responses and headless-browser rendering.
//!
//! Run everything, API and browser tests alike:
//! `cargo test --features server --test e2e`
//! Browser tests skip themselves at runtime when no Chrome/Chromium is
//! installed; set `$CHROME` to name a browser binary outside the usual search.

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

// Scenario tests split out of this file; they see the helpers below through
// `use super::*;`.
#[path = "e2e/analysis_artifact_contract.rs"]
mod analysis_artifact_contract;
#[path = "e2e/analytics_api.rs"]
mod analytics_api;
#[path = "e2e/attempts_api_and_analytics_views.rs"]
mod attempts_api_and_analytics_views;
#[path = "e2e/control_endpoints.rs"]
mod control_endpoints;
#[path = "e2e/dashboard_api.rs"]
mod dashboard_api;
#[path = "e2e/headless_binary_and_unit_views.rs"]
mod headless_binary_and_unit_views;
#[path = "e2e/headless_queue_graph_live.rs"]
mod headless_queue_graph_live;
#[path = "e2e/pipeline_progress_and_llm_log.rs"]
mod pipeline_progress_and_llm_log;
#[path = "e2e/unit_detail_and_server_basics.rs"]
mod unit_detail_and_server_basics;

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

    /// Creates sample data the DashboardBuilder can read:
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
            expected_api_calls: Vec::new(),
        },
        actual_return: expected,
        actual_side_effects: Vec::new(),
        actual_api_calls: Vec::new(),
        passed,
        error: None,
    }
}

/// Start the axum server in a background task.
/// The live (ws) routers get a settings-backed actions backend (issue
/// #327). The web review surface under test never posts a patch, so the
/// default — LLM-less — description is enough here; a patch request
/// against these routers would fail assembly, exactly what issue #327
/// specifies for a server started without LLM settings.
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

/// Like `write_canned_run_telemetry` but the token-usage entries include
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

// ─────────────────────────────────────────────────────────────
// Token usage analytics (issue #126, W3.2)
// ─────────────────────────────────────────────────────────────

/// One token-usage entry with every field spelled out — the fixture's
/// exact values are what the endpoint assertions pin. An empty tier omits
/// `context_tier` entirely, the shape entries written before tier tracking
/// (and by older versions) have on disk.
// One parameter per fixture field — the whole point is spelling every
// field out, so grouping them into a struct would only hide the values.
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

// ─────────────────────────────────────────────────────────────
// LLM performance metrics (issue #128, W3.4)
// ─────────────────────────────────────────────────────────────

/// One token-usage entry with a recorded attempt duration — the same
/// shape as `token_usage_entry` plus `duration_secs`. `duration: None`
/// writes the pre-duration-tracking shape (the field omitted entirely),
/// which the percentile math must exclude rather than count as zero.
// One parameter per fixture field — the whole point is spelling every
// field out, so grouping them into a struct would only hide the values.
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

/// One resource-exhaustion fault with the `metadata.reason` the
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
/// excluded from the percentiles, never counted as zero. The faults hold exactly
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

    // The persisted override layer: it sets d3d9.dll to KnownThirdParty
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
    // A corrupt function artifact is no artifact: it gives no category.
    std::fs::write(analysis.join("broken.json"), "{ not json").expect("corrupt artifact written");

    // The generated shared PAL crate that the verifier writes under
    // `scratch/pal/`: it defines GraphicsDevice (and AudioDevice) but not
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
// ─────────────────────────────────────────────────────────────
// Unit process detail tests (issue #62)
// ─────────────────────────────────────────────────────────────

/// Writes canned run-telemetry artifacts for game_logic.dll/DrawPrimitive:
/// a token-usage log (2 attempts, escalated tiers), a fault log (2 faults),
/// and an analysis artifact (its tier rationale is read from there).
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

/// Fetches the unit detail body for `unit_id` from a plain `serve` router.
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

// ─────────────────────────────────────────────────────────────
// Unit analysis context tests (issue #73)
// ─────────────────────────────────────────────────────────────

/// Writes canned analysis artifacts for game_logic.dll/DrawPrimitive: a
/// function analysis artifact naming two Windows APIs, and a per-binary
/// call-graph record. In that record DrawPrimitive is called by GameLoop
/// (the caller is stored as an address) and calls BlitSurface (an edge with
/// a name) and InternalFlush (an edge with no name, matched by address).
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

// ─────────────────────────────────────────────────────────────
// Headless browser test (requires Chromium/Chrome installed)
// ─────────────────────────────────────────────────────────────

/// Launch headless Chrome with the flags that work inside containers and CI,
/// or return `None` — printing a skip note — when no browser is installed.
/// `default_executable` looks at `$CHROME`, then `google-chrome-stable`,
/// `chromium`, and the other standard names on PATH, so the browser tests run
/// wherever a browser exists and are skipped with a printed note where none is.
///
/// Chrome's CDP calls are **blocking**, so every browser test must run on a
/// multi-thread runtime (`#[tokio::test(flavor = "multi_thread")]`). On the
/// default current-thread runtime the blocking calls starve the axum server
/// task that the same test spawns, so the page is never served and navigation
/// times out with "The event waited for never came".
fn launch_headless_browser() -> Option<headless_chrome::Browser> {
    use headless_chrome::{Browser, LaunchOptionsBuilder};

    if headless_chrome::browser::default_executable().is_err() {
        eprintln!("skipping browser test: no Chrome/Chromium found (set $CHROME to name one)");
        return None;
    }
    Some(
        Browser::new(
            LaunchOptionsBuilder::default()
                .headless(true)
                .args(vec![
                    std::ffi::OsStr::new("--no-sandbox"),
                    std::ffi::OsStr::new("--disable-gpu"),
                    std::ffi::OsStr::new("--disable-dev-shm-usage"),
                    // Wide viewport: a narrow window pins the pipeline row's
                    // head track to its minimum size and hides column-alignment
                    // bugs that only show up once the tracks grow with content.
                    std::ffi::OsStr::new("--window-size=1400,900"),
                ])
                .build()
                .expect("build chrome launch options"),
        )
        .expect("launch headless chrome"),
    )
}

/// Open a tab on the fixture's server and wait for the page to load.
///
/// `navigate_to` waits for Chrome's `networkAlmostIdle` lifecycle event, which
/// only arrives after the dashboard's own fetches finish. That is generous on
/// purpose, so a slow machine still passes.
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
/// boolean. Every headless test uses this, so none repeats the conversion.
///
/// An evaluation error or a non-boolean result reads as `false`. That keeps
/// the render-polling loops honest until the dashboard really shows the thing.
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

/// Like [`eval_bool`], but reads the result as a whole number. Errors and
/// non-number results read as `-1`, a number no real element count can be.
fn eval_count(tab: &headless_chrome::Tab, expr: &str) -> i64 {
    tab.evaluate(expr, false)
        .ok()
        .and_then(|r| r.value)
        .and_then(|v| v.as_i64())
        .unwrap_or(-1)
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
