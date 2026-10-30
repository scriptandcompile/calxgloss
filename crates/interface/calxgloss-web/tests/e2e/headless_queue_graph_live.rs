//! Scenario tests split from `tests/e2e.rs`.

use super::*;

/// Headless-browser test for issue #64: with measured attempt durations in
/// the token-usage log, the pipeline panel must show a time estimate and the
/// review queue must render a per-unit effort column.
///
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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

    let Some(browser) = launch_headless_browser() else {
        return;
    };
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
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_headless_queue_priority_and_reorder() {
    let fixture = TestFixture::new();
    add_pending_translation(&fixture, "RenderHUD");

    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let Some(browser) = launch_headless_browser() else {
        return;
    };
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
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_headless_queue_skip_checkbox() {
    let fixture = TestFixture::new();

    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let Some(browser) = launch_headless_browser() else {
        return;
    };
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

/// Headless-browser test for issue #78: queue rows have a multi-select
/// checkbox, the list header has a select-all that marks every visible row,
/// and the batch dropdown applies the chosen action (Skip All here) to all
/// selected units — persisted through the per-unit skip logic, after which
/// the selection clears.
///
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_headless_queue_multiselect_batch_actions() {
    let fixture = TestFixture::new();
    add_pending_translation(&fixture, "RenderHUD");

    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let Some(browser) = launch_headless_browser() else {
        return;
    };
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
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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

    let Some(browser) = launch_headless_browser() else {
        return;
    };
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
/// `toSVG()` serializes the filtered view (visible nodes only, each including
/// its unit id), the PNG export runs the same SVG through rasterization, the
/// share URL encodes the active filters and the zoom/pan camera, and opening
/// that URL in a fresh tab restores the same filters and viewport.
///
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_headless_graph_export_and_share_url() {
    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let Some(browser) = launch_headless_browser() else {
        return;
    };
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

    // SVG export matches the filtered view: the d3d9 nodes are in (their
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
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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

    let Some(browser) = launch_headless_browser() else {
        return;
    };
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

    // Token count per entry: the response reports its count, the request
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

    // One-click copy: every entry has a copy button.
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
    let reloaded = visible_count();
    assert!(
        reloaded == 5,
        "history reload must not duplicate the live entries — got {reloaded} entries"
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
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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

    let Some(browser) = launch_headless_browser() else {
        return;
    };
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

    // The row shows the phase label and the evidence the stream reported.
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

    // The pushed records include the phase history — the phase chip's tooltip
    // shows the path the unit took, escalations and retries included.
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
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_headless_live_view_honest_without_live_mode() {
    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(500)).await;

    let Some(browser) = launch_headless_browser() else {
        return;
    };
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
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_headless_dashboard_summary_sections() {
    let fixture = TestFixture::new();
    write_token_usage_log(&fixture, false);

    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let Some(browser) = launch_headless_browser() else {
        return;
    };
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
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_headless_reload_keeps_current_tab() {
    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let Some(browser) = launch_headless_browser() else {
        return;
    };
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
