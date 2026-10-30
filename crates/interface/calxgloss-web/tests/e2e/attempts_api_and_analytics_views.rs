//! Scenario tests split from `tests/e2e.rs`.

use super::*;

/// A unit with one attempt honestly answers with that one attempt and
/// `comparable: false` — the detail panel's "nothing to compare" state. An
/// unknown unit id gets a 404, the same contract the other
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
/// stay absent while the patch-record fields are untouched. The lookup
/// degrades honestly instead of failing the request or showing zero.
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

/// Issue #135 router contract: `/api/units/{id}/attempts/diff` is in the
/// shared routes, so both the plain `serve` router and the live router
/// answer it. It reads only saved branches. The fixture's DrawPrimitive v1
/// and v2 branches have distinct commits, so the diff is real text, not an
/// empty placeholder.
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

/// The exact-JSON pin against fixture branches with distinct commits: v1's
/// tree does not have the file the v2 attempt added, so the tree-to-tree
/// diff is exactly that one file — verbatim unified text plus its stats.
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

/// A missing branch on either side answers with an honest error payload,
/// never an invented empty diff. A non-numeric attempt number gets a 400
/// that names the accepted shape.
#[tokio::test]
async fn test_unit_attempt_diff_missing_branch_and_bad_params() {
    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let base = format!("http://127.0.0.1:{}", fixture.port());

    // Attempt 3 has no branch and no record in the fixture.
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

    // A missing `to` branch is answered just as honestly as a missing `from`.
    let (status, body) = get_json(&format!(
        "{base}/api/units/game_logic.dll%2FDrawPrimitive%2Fv2/attempts/diff?from=9&to=2"
    ))
    .await;
    assert_eq!(status, 404);
    assert!(
        body["message"].as_str().unwrap_or("").contains("Attempt 9"),
        "the from side is named too, got: {body}"
    );

    // An attempt the lookup *does* find — a patch record that points at a
    // branch the repository no longer has — gets the same honest 404, never
    // a 500 and never an empty diff.
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

    // A non-numeric attempt number gets a 400 that names the accepted shape.
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

/// The Faults tab shows the fixture log honestly: summary cards, per-binary
/// bars, a trend line, and the table. The category filter narrows all of
/// them. The CSV builder (exposed as
/// `window.calxglossFaultsCsv`) is pinned against the same fixture.
///
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_headless_faults_view_renders_filters_and_exports() {
    let fixture = TestFixture::new();
    write_fault_log_fixture(&fixture.repo_path(), &sample_fault_entries());
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let Some(browser) = launch_headless_browser() else {
        return;
    };
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
    // the fixture: header + 6 rows, with the recovery text verbatim.
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
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_headless_faults_view_honest_empty_state() {
    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let Some(browser) = launch_headless_browser() else {
        return;
    };
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

/// The Token Usage tab shows the fixture log honestly: the summary split
/// cards, per-binary bars with shares, per-tier bars, and the per-strategy
/// table with success rates. The time-range selector re-renders the tab in
/// place. The cost panel works out the estimate from the price the operator
/// types, saves it in localStorage, and survives a page reload.
///
/// The fixture timestamps are relative to now so the 7-day window keeps
/// holding exactly one attempt whenever the test runs.
///
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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

    let Some(browser) = launch_headless_browser() else {
        return;
    };
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
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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

        let Some(browser) = launch_headless_browser() else {
            return;
        };
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

/// The Strategy Analytics tab shows the fixture log honestly: the
/// per-strategy table with attempts, successes, failures, and pass rate,
/// plus the per-category pass-rate bars. The time-range selector
/// re-renders the tab in place. The CSV builder (exposed as
/// `window.calxglossStrategyCsv`) is pinned against the same fixture.
///
/// The fixture timestamps are relative to now so the 7-day window keeps
/// holding exactly the two recent attempts whenever the test runs.
///
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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

    let Some(browser) = launch_headless_browser() else {
        return;
    };
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

    // The CSV export: exact rows built from the fetched JSON — first the
    // per-strategy breakdown (all three strategies have one attempt each,
    // so they sort alphabetically), then the per-category breakdown.
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
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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

        let Some(browser) = launch_headless_browser() else {
            return;
        };
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

/// The LLM Metrics tab shows the fixture logs honestly: percentile cards
/// labeled as attempt wall-clock, the timeout trend, and the per-tier
/// table. A tier with no measurement renders an em dash, never an invented
/// number. The time-range filter re-renders the tab in place.
///
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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

    let Some(browser) = launch_headless_browser() else {
        return;
    };
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

    // All-time percentiles over the measured durations 10/30/90: the
    // nearest-rank P50 is 30 — the unmeasured attempt is not in the math.
    assert_eq!(
        eval_text(
            &tab,
            "document.querySelector('#llm-metrics-summary-cards .status-card .status-card-value').textContent"
        ),
        "30s",
        "the P50 card should pin the nearest-rank percentile of the measured durations"
    );

    // Honest labeling: the note says plainly that the durations are attempt
    // wall-clock (compile and tests included), never the latency of a call.
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
    // and the unmeasured tier's percentiles show em dashes, never numbers.
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
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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

        let Some(browser) = launch_headless_browser() else {
            return;
        };
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

/// The Binaries tab shows the fixture's classified binaries as rows: the
/// override chip on the overridden row, the function counts, and the token
/// totals — all read straight from the saved history.
///
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_headless_binaries_view_renders_rows() {
    let fixture = TestFixture::new();
    write_binaries_list_fixtures(&fixture);
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let Some(browser) = launch_headless_browser() else {
        return;
    };
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

    // Alphabetical: d3d9.dll first, with the override chip on it.
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
    // function counts appear in the game_logic.dll row.
    assert!(
        eval_bool(
            &tab,
            "document.querySelector('#binaries-table-body').textContent.includes('175')"
        ),
        "the case-insensitive token join shows game_logic.dll's 175 tokens"
    );
}

/// With no readable classification records — the fixture's own minimal
/// ones have no `binary` field — the Binaries tab says so plainly: no
/// empty table shell, no wall of zeros, no error.
///
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_headless_binaries_view_honest_empty_state() {
    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let Some(browser) = launch_headless_browser() else {
        return;
    };
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

/// Issue #132: clicking a fixture row opens the detail panel below it. It
/// shows the classification decision in force (override applied) with its
/// reasoning and symbol counts, the per-function list with each unit's
/// review status, and the shortcut to the existing classification-override
/// flow.
///
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_headless_binaries_detail_panel_expands() {
    let fixture = TestFixture::new();
    write_binaries_list_fixtures(&fixture);
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let Some(browser) = launch_headless_browser() else {
        return;
    };
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

    // Exactly one function row, with its review status.
    assert_eq!(
        eval_count(
            &tab,
            "document.querySelectorAll('#binaries-table-body .binaries-detail-functions tbody tr').length",
        ),
        1,
        "d3d9.dll's one dashboard unit appears in the function list"
    );

    // The shortcut opens the existing classification-override panel, placed
    // inside this view. Its endpoints exist only in live mode, so under
    // plain `serve` it honestly reports itself unavailable instead of
    // showing a blank panel or a fake form.
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_headless_binaries_detail_shim_tracker() {
    let fixture = TestFixture::new();
    write_binaries_list_fixtures(&fixture);
    write_shim_tracker_fixtures(&fixture);
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let Some(browser) = launch_headless_browser() else {
        return;
    };
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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

    let Some(browser) = launch_headless_browser() else {
        return;
    };
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
    // branch the reviewer sent back: both answers appear side by side.
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

/// Issue #134: the fixture binary's detail panel shows its needed PAL
/// traits with at least one existing marker (GraphicsDevice — the
/// generated scratch PAL crate defines it) and one missing marker
/// (PlatformCore — nothing defines it).
///
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_headless_binaries_detail_pal_tracker() {
    let fixture = TestFixture::new();
    write_binaries_list_fixtures(&fixture);
    write_pal_tracker_fixtures(&fixture);
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let Some(browser) = launch_headless_browser() else {
        return;
    };
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
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_headless_binaries_detail_pal_tracker_honest_empty_state() {
    let fixture = TestFixture::new();
    write_binaries_list_fixtures(&fixture);
    write_pal_tracker_fixtures(&fixture);
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let Some(browser) = launch_headless_browser() else {
        return;
    };
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

/// Issue #327 AC1/AC5: with the settings-backed actions backend attached,
/// `POST /api/units/{id}/patch` drives the real assembled request. It
/// creates the next-attempt branch and the patch record for real, and the
/// retry task is assembled from the pass description. The LLM endpoint here
/// points at a dead port, so the background retry fails on its own; the
/// response and the on-disk artifacts show the request ran the real path,
/// not the canned reply that issue #327 removed.
#[tokio::test]
async fn test_patch_request_with_actions_backend_creates_branch_and_record() {
    let fixture = TestFixture::new();

    // A target dir holding the Kuna-loadable fixture binary under the unit's
    // name, so the pass's analysis engine load succeeds.
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

    // The branch really exists and the patch record really landed: the
    // request took the real create-and-record path.
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
/// built without the settings-backed actions backend honestly refuses a
/// patch request instead of pretending that a retry started.
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
