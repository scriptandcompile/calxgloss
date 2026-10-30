//! Scenario tests split from `tests/e2e.rs`.

use super::*;

/// Issue #327 AC6: a server started with no LLM settings gets an actions
/// backend whose description has no LLM selection. So a patch request fails
/// at request time with the assembly seam's clear error — not a canned
/// success, and not a half-configured retry.
#[tokio::test]
async fn test_patch_without_llm_settings_reports_assembly_error() {
    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path());
    // Target dir configured, so the one thing missing is the LLM selection:
    // the seam builds the LLM before it ever reads a binary.
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

/// Checks that the full router, with the actions backend attached, can
/// still serve the dashboard.
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

    // The server management endpoints are in all three routers: the
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

    // The enhanced /health is routed here too (issue #59: all three routers).
    let health_resp = reqwest::get(format!("http://127.0.0.1:{}/health", fixture.port()))
        .await
        .expect("health request succeeds");
    assert_eq!(health_resp.status(), 200);
    let health_body: serde_json::Value = health_resp.json().await.expect("health is JSON");
    assert_eq!(health_body["status"], "ok");
    assert!(health_body["uptime_secs"].as_u64().is_some());
    assert_eq!(health_body["version"], env!("CARGO_PKG_VERSION"));
}

/// A send-back verdict survives a dashboard rebuild (issue #9). POST
/// /send-back writes a send-back record, and a dashboard rebuilt from disk
/// reports the unit as `send_back` — not `queued`/`pending_review`. That
/// gives the review state machine (SendBack → Blocked cascade → re-review)
/// a failed root unit to cascade from.
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

    // Files under js/ must be served too: the page loads them natively
    // through `import`, so nested paths have to resolve.
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

/// Checks that the WebSocket upgrade route exists (basic sanity). A full
/// WebSocket test would need a WS client; this only checks the route works.
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

    // Not 404 — the WS upgrade fails here in a different way.
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
    // An empty diff is allowed here (the diff between main and v2 can be
    // empty depending on how the fixture is set up).
    // Each file should have a path and hunks
    for file in files {
        assert!(file["path"].as_str().is_some());
        assert!(file["hunks"].as_array().is_some());
    }
}

/// The decompiler context endpoint answers honestly when a unit has no analysis artifact.
/// (This fixture writes none, so the answer is the honest payload: HTTP 200, no context.)
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

    // Answers success:true with no context when the analysis artifact is missing.
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("decomp body is JSON");
    assert_eq!(body["success"], true);
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

    // --- Tier section: read from the last attempt in the token-usage log ---
    let tier = &process["tier"];
    assert_eq!(tier["tier"], 2, "tier number should be 2 (with_tests)");
    assert_eq!(tier["label"], "with_tests");
    assert!(tier["description"].is_string());
    assert_eq!(
        tier["escalated"], true,
        "tier should be flagged as escalated"
    );

    // Rationale: computed again from the analysis artifact.
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

    // This unit has no telemetry artifacts: every section must be present
    // but empty, and the response must still report success.
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

    // Call graph context: caller addresses are matched to names, and callee
    // edges with no recorded name are matched through the function list.
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

    // No analysis artifacts here: both sections must be present but empty,
    // and the response must still report success.
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

/// Checks that the build_dashboard API (exposed at the crate root) builds correctly from the fixture.
#[tokio::test]
async fn test_build_dashboard_api() {
    let fixture = TestFixture::new();
    let dashboard = build_dashboard(&fixture.repo_path()).expect("build dashboard should succeed");

    assert!(
        !dashboard.review_queue.is_empty(),
        "dashboard should have units"
    );

    // The expected units are all found by id.
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

    // Collect every unit id from review_queue and recent_activity.
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

    // Check the status counts.
    let counts = &dashboard.status_counts;
    assert!(counts.accepted >= 1); // UpdateScene is merged
    assert!(counts.total() >= 3); // classify + 2 func translations
}

/// Checks that a headless browser can open the server and that the HTML
/// page loads without JavaScript errors.
///
/// The data rendering itself is checked by the API-level tests above, which
/// are faster and need no browser installed.
///
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_headless_browser_page_loads() {
    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(500)).await;

    let Some(browser) = launch_headless_browser() else {
        return;
    };
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

    // The dependency graph endpoint is reachable through fetch.
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

    // The dashboard endpoint is reachable through fetch.
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

/// Headless-browser test for the dashboard server status card (issue #59).
/// The card must show the values from `GET /api/server/status`: version,
/// uptime, and the pipeline state.
///
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_headless_server_status_card() {
    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(500)).await;

    let Some(browser) = launch_headless_browser() else {
        return;
    };
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

    // Plain `serve` has no live pipeline: the card must say so honestly.
    assert_eq!(
        text_of("server-status-pipeline"),
        "no pipeline",
        "plain serve status card should report 'no pipeline'"
    );

    tab.close_target().ok();
    drop(browser);
}

/// Headless-browser test for the dashboard server control panel (issue #60).
/// The panel must show shutdown and restart buttons and a log-level selector
/// listing every level the server accepts.
///
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_headless_server_control_panel() {
    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(500)).await;

    let Some(browser) = launch_headless_browser() else {
        return;
    };
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
    // It also pre-selects the level the server reports.
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

/// Headless-browser test for the dashboard pipeline phase bar (issue #61).
/// In live mode the bar must show one segment per master-plan phase: 8 in
/// total, including Phase 2.5 (PAL Design). Restitching and Documentation
/// must read as no data source, never as zero progress.
///
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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

    let Some(browser) = launch_headless_browser() else {
        return;
    };
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

    // Restitching and Documentation honestly read as no data source.
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

/// Headless-browser test for the per-binary progress panel (issue #63). In
/// live mode the pipeline panel must show one row per target binary with its
/// classification strategy, function counts (total, translated, in-progress,
/// queued, failed), token use, and success rate. Values it does not know
/// render as em-dashes, never as invented zeros. The quick-action buttons are
/// real controls (issue #94): each row has one translation toggle (issue
/// #285) plus Configure and Classify. Pressing the toggle calls its
/// per-binary endpoint, and on a router with no scope handle attached the
/// server's own honest 503 reason shows up as an error toast.
///
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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
    // d3d9.dll through PAL mapping (classified only), dinput8.dll through
    // crate replacement with one unit in flight, engine.dll through full RE
    // (classified only), and game_logic.dll discovered unclassified. Its batch
    // summary is the count source of record: 2 of 5 translated, 1 failed,
    // 5000 tokens → 2 queued, 67% success rate.
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
    // engine.dll's batch pass is in flight: the row must show it working even
    // though no unit event exists yet.
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

    let Some(browser) = launch_headless_browser() else {
        return;
    };
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

    // ── The status badge sits in the Success column, not beside the name ──
    assert!(
        eval_bool(
            &tab,
            "document.querySelectorAll('#pipeline-binaries .pipeline-binary-head .pipeline-binary-status').length === 0"
        ),
        "no status badge next to the binary name"
    );
    // d3d9.dll is PAL-mapped: its compact row (issue #244) leaves out the
    // tokens/success cell and the translation counts completely.
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
    // Switch to the Pipeline view so the rows have real layout boxes: a
    // hidden element reports a zero rect and would pass without checking.
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
    // (engine.dll is classified and working, but no batch summary has
    // arrived yet. Its success rate is absent too: with no finished
    // outcomes the cell shows the status placeholder, never a zero.)
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
    // The toggle shows the row's state honestly (issue #285): engine.dll's
    // batch pass is in flight, so its button reads Pause; game_logic.dll's
    // pass has finished, so its button reads Start Translation.
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

    // Replace fetch so any request that changes state can be counted.
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

    // The click is a real control: it sends a POST to the row's per-binary
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

    // …and this plain router has no scope handle attached. The swap works
    // through that handle, so the server's own honest 503 reason shows up as
    // an error toast — not a silent no-op, and not a state change faked in
    // the page.
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

/// Headless-browser test for the compact PAL row (issue #244, part of #223).
/// A PAL-classified binary gets the compact row: trait names with
/// defined/missing markers in the state cell, an "N/M defined" readiness
/// count in the counts area, an empty cost placeholder that keeps the grid
/// aligned, and Classify alone in the actions cell. If the poll brought no
/// summary for a PAL row, it shows an em-dash, never an invented 0/0. A
/// non-PAL neighbour keeps its counts, its success-column placeholder, and
/// its three buttons. Reclassifying live to a translation strategy brings
/// the full row back and puts the binary in table order on the next refresh.
///
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_headless_pipeline_pal_rows_compact() {
    let fixture = TestFixture::new();
    // d3d9.dll is classified PalMapping on disk, with function artifacts
    // recording the DirectX/Win32Core API-call categories and a generated PAL
    // crate that defines GraphicsDevice but not PlatformCore. game_logic.dll
    // is ReverseEngineer: the full-row neighbour.
    write_pipeline_pal_readiness_fixtures(&fixture);

    let state = ServerState::new(fixture.repo_path());
    let events = TranslationEvents::new(128);
    let manager = SessionManager::new_with_broadcast(events.subscribe());
    let progress = ProgressState::new();
    let router = build_router_with_ws(state, manager, progress, ws_actions(&fixture));
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    // A second PAL binary classified live with no analysis artifacts: the
    // poll has no summary for it, and the row must answer honestly.
    events.emit(ProgressEvent::ClassificationComplete {
        binary: "audio.dll".into(),
        category: "WindowsOs".into(),
        classification_strategy: "PalMapping".into(),
        crate_replacement: None,
        exported_symbols: 3,
        imported_symbols: 2,
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    let Some(browser) = launch_headless_browser() else {
        return;
    };
    let tab = open_dashboard_tab(&browser, fixture.port());

    // game_logic.dll (full row) plus audio.dll and d3d9.dll (compact: PAL
    // rows sort last, issue #242); poll until all three show up.
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

    // Switch to the Pipeline view so the cells have real layout boxes: a
    // hidden element reports a zero rect and would pass without checking.
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
    // The classification-override panel's live event is what redraws the
    // rows (app.js reloads the pipeline on classification_complete), so
    // sending that event here is the same path the panel takes on success.
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

/// Headless-browser test for the controls header (issue #94, W2.4). The
/// state badge follows the pipeline's state machine: first from the
/// server-status snapshot, then over the WebSocket while *another* client
/// calls the lifecycle endpoints. The buttons are gated by the server's own
/// transition table at every step.
///
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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

    let Some(browser) = launch_headless_browser() else {
        return;
    };
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

    // The first server-status snapshot puts the header on the machine's real
    // state: idle, with only Start (and Shut Down Server) available.
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

    // Another client (the reqwest "other tab") runs the lifecycle: the header
    // follows over the WebSocket, with no interaction in this tab.
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

    // A stale button — force one enabled, the way an earlier state in another
    // tab would have left it — then use it for an operation the machine
    // forbids: the server's own 409 reason shows up as an error toast, and the
    // header keeps telling the truth instead of corrupting its own state.
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

    // The run finishes, which the live loop would normally do: Restart is
    // now the only lifecycle operation available.
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

/// Headless-browser test for the restart dialog (issue #94, W2.4). From a
/// finished run the Restart button opens a dialog with phase / target / scope
/// selectors and a safety explanation. Confirming sends those selectors to
/// POST /api/pipeline/restart: the header moves back to running, and the live
/// loop's request slot holds the choices that were made.
///
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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

    let Some(browser) = launch_headless_browser() else {
        return;
    };
    let tab = open_dashboard_tab(&browser, fixture.port());

    // The header settles on complete, which makes Restart available.
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

    // …and the live loop's request slot holds the chosen selectors.
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

    // The success toast lists the selectors that were sent.
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
