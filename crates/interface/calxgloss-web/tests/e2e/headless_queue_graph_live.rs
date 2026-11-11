//! Scenario tests split from `tests/e2e.rs`.
//!
//! Every test here boots one world through the review-world adapter (issue
//! #476). A test files its record fixtures through the record writers,
//! emits progress events through the typed emitter and waits for the
//! server to apply them, and reads the browser's DOM through the world's
//! bounded waits. The queue, graph, and live-view pins wait on the
//! seam's applied waits before reading the DOM — a live reading is
//! never slept through.

use super::*;

use super::support::*;
use calxgloss_types::ProgressEvent;
use calxgloss_web::LlmIoLog;
use std::time::Duration;

/// Headless-browser test for issue #64: with measured attempt durations in
/// the token-usage log, the pipeline panel must show a time estimate and the
/// review queue must render a per-unit effort column.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_headless_pipeline_estimate_and_queue_effort() {
    let fixture = TestFixture::new();
    write_token_usage_log(&fixture, true);

    let world = support::ReviewWorld::boot_ws_on(&fixture).await;

    // The minimal live events that give one binary a known function total
    // with work remaining (5 total, 2 translated, 1 failed → 2 remain).
    let summary = ProgressEvent::BatchSummary {
        binary: "game_logic.dll".into(),
        total_functions: 5,
        success_count: 2,
        failure_count: 1,
        total_attempts: 4,
        total_tokens: 5000,
    };
    world.emitter().emit(summary.clone());
    world
        .wait_until_applied(&summary, |body| {
            body["binaries"].as_array().is_some_and(|binaries| {
                binaries
                    .iter()
                    .any(|b| b["binary"] == "game_logic.dll" && b["functions_total"] == 5)
            })
        })
        .await;

    let Some(tab) = world.open_dashboard_tab() else {
        return;
    };

    // The pipeline panel renders asynchronously; wait until the time
    // estimate is visible.
    assert!(
        tab.wait_for_bool(
            "document.getElementById('pipeline-time-estimate')?.style.display !== 'none' \
                && document.getElementById('pipeline-time-estimate')?.textContent.includes('remaining')"
        )
        .await,
        "pipeline time estimate should be visible when durations exist"
    );

    // Switch to the queue view so the full queue list renders.
    tab.click(r#".nav-tab[data-view="queue"]"#);

    // The DrawPrimitive unit has its own measured attempts → its effort
    // column shows a real duration, not the em-dash placeholder.
    let effort_rendered = tab
        .wait_for_bool(
            "(() => { const el = document.querySelector('#full-queue-list \
                [data-unit-id=\"game_logic.dll/DrawPrimitive/v2\"] .qi-effort'); \
                return !!el && el.textContent !== '—'; })()",
        )
        .await;
    let effort_text = tab.eval_text(
        "document.querySelector('#full-queue-list \
            [data-unit-id=\"game_logic.dll/DrawPrimitive/v2\"] .qi-effort')?.textContent || ''",
    );
    assert!(
        effort_rendered,
        "queue effort column should show an estimate for the unit, got: {effort_text:?}"
    );
}

/// Headless-browser test for issue #74: the queue view renders a priority
/// column (default NORMAL), a synthetic drag through the real drag handlers
/// reorders and persists the manual order, and clicking the chip cycles and
/// persists the priority — both landing in `re/review/queue_overlay.json`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_headless_queue_priority_and_reorder() {
    let fixture = TestFixture::new();
    add_pending_translation(&fixture, "RenderHUD");

    let world = support::ReviewWorld::boot_plain_on(&fixture).await;

    let Some(tab) = world.open_dashboard_tab() else {
        return;
    };

    // Switch to the queue view so the full queue list renders.
    tab.click(r#".nav-tab[data-view="queue"]"#);

    let draw = "game_logic.dll/DrawPrimitive/v2";
    let hud = "game_logic.dll/RenderHUD/v1";

    // The priority column renders with the default NORMAL for both units.
    assert!(
        tab.wait_for_bool(
            "(() => { const el = document.querySelector('#full-queue-list \
                [data-unit-id=\"game_logic.dll/DrawPrimitive/v2\"] .qi-priority'); \
                return !!el && el.textContent === 'NORMAL'; })()"
        )
        .await,
        "queue priority column should render NORMAL for the unit"
    );

    // Drag reordering through the real handlers: a synthetic drag of
    // RenderHUD onto the top half of DrawPrimitive's row drops it above.
    tab.run(
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
        "synthetic drag reorder",
    );

    assert!(
        tab.wait_for_bool(
            "(() => { const first = document.querySelector('#full-queue-list .queue-item-full'); \
                return !!first && first.dataset.unitId === 'game_logic.dll/RenderHUD/v1'; })()"
        )
        .await,
        "manual reorder should put RenderHUD first in the rendered queue"
    );

    // The drop fires the PUT without awaiting it, so the applied wait
    // reads the persisted overlay file until the new order lands.
    let overlay_file = calxgloss_types::queue_overlay_path(world.repo_path());
    let wanted = serde_json::json!([hud, draw]);
    let persisted = wait_for_persisted(&overlay_file, |value| value["order"] == wanted).await;
    assert_eq!(
        persisted["order"], wanted,
        "reorder persists to the overlay file"
    );

    // Clicking the chip cycles NORMAL → HIGH and persists it.
    tab.click(r#"#full-queue-list [data-unit-id="game_logic.dll/DrawPrimitive/v2"] .qi-priority"#);

    assert!(
        tab.wait_for_bool(
            "(() => { const el = document.querySelector('#full-queue-list \
                [data-unit-id=\"game_logic.dll/DrawPrimitive/v2\"] .qi-priority'); \
                return !!el && el.textContent === 'HIGH'; })()"
        )
        .await,
        "clicking the chip should cycle to HIGH"
    );

    let persisted = wait_for_persisted(&overlay_file, |value| {
        value["priorities"][draw].as_str() == Some("high")
    })
    .await;
    assert_eq!(
        persisted["priorities"][draw].as_str(),
        Some("high"),
        "priority click persists to the overlay file"
    );
}

/// Headless-browser test for issue #75: the queue view renders a skip
/// checkbox per unit, clicking it marks the unit `Skipped` — the row
/// re-renders checked with a Skipped badge — and the skip persists to
/// `re/review/skips.json`; unchecking restores the unit.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_headless_queue_skip_checkbox() {
    let world = support::ReviewWorld::boot_plain().await;

    let Some(tab) = world.open_dashboard_tab() else {
        return;
    };

    // Switch to the queue view so the full queue list renders.
    tab.click(r#".nav-tab[data-view="queue"]"#);

    let draw = "game_logic.dll/DrawPrimitive/v2";
    let row_sel = format!("#full-queue-list [data-unit-id=\"{draw}\"]");

    // The skip checkbox column renders, unchecked for an active unit.
    assert!(
        tab.wait_for_bool(&format!(
            "(() => {{ const el = document.querySelector('{row_sel} .qi-skip-check'); \
                return !!el && el.checked === false; }})()"
        ))
        .await,
        "queue skip checkbox should render unchecked for the unit"
    );

    // Clicking the checkbox skips the unit.
    tab.click(&format!("{row_sel} .qi-skip-check"));

    // The skip lands in the repo's skip set — the applied wait on the
    // persisted file, since the POST is not awaited.
    let skips_file = calxgloss_types::ReviewSkips::path_in(world.repo_path().as_path());
    let wanted = serde_json::json!([draw]);
    let persisted = wait_for_persisted(&skips_file, |value| value["skipped"] == wanted).await;
    assert_eq!(
        persisted["skipped"], wanted,
        "skip click persists to re/review/skips.json"
    );

    // After the dashboard reload the row renders checked with a Skipped
    // badge — the checkbox reflects persisted state, not just the click.
    assert!(
        tab.wait_for_bool(&format!(
            "(() => {{ const row = document.querySelector('{row_sel}'); \
                const cb = row?.querySelector('.qi-skip-check'); \
                const st = row?.querySelector('.qi-status'); \
                return !!cb && cb.checked === true \
                    && !!st && st.textContent.includes('Skipped'); }})()"
        ))
        .await,
        "skipped unit should re-render checked with a Skipped badge"
    );

    // Unchecking unskips: the skip set empties and the row comes back.
    tab.click(&format!("{row_sel} .qi-skip-check"));

    let persisted = wait_for_persisted(&skips_file, |value| {
        value["skipped"].as_array().is_some_and(|a| a.is_empty())
    })
    .await;
    assert!(
        persisted["skipped"]
            .as_array()
            .is_some_and(|a| a.is_empty()),
        "unchecking empties the persisted skip set"
    );

    assert!(
        tab.wait_for_bool(&format!(
            "(() => {{ const el = document.querySelector('{row_sel} .qi-skip-check'); \
                return !!el && el.checked === false; }})()"
        ))
        .await,
        "unskipped unit should re-render unchecked"
    );
}

/// Headless-browser test for issue #78: queue rows have a multi-select
/// checkbox, the list header has a select-all that marks every visible row,
/// and the batch dropdown applies the chosen action (Skip All here) to all
/// selected units — persisted through the per-unit skip logic, after which
/// the selection clears.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_headless_queue_multiselect_batch_actions() {
    let fixture = TestFixture::new();
    add_pending_translation(&fixture, "RenderHUD");

    let world = support::ReviewWorld::boot_plain_on(&fixture).await;

    let Some(tab) = world.open_dashboard_tab() else {
        return;
    };

    // Switch to the queue view so the full queue list renders.
    tab.click(r#".nav-tab[data-view="queue"]"#);

    let draw = "game_logic.dll/DrawPrimitive/v2";
    let hud = "game_logic.dll/RenderHUD/v1";
    let draw_sel = format!("#full-queue-list [data-unit-id=\"{draw}\"]");
    let hud_sel = format!("#full-queue-list [data-unit-id=\"{hud}\"]");

    // Each row renders an (unchecked) select checkbox beside the skip one.
    assert!(
        tab.wait_for_bool(&format!(
            "(() => {{ const a = document.querySelector('{draw_sel} .qi-select'); \
                const b = document.querySelector('{hud_sel} .qi-select'); \
                return !!a && !a.checked && !!b && !b.checked; }})()"
        ))
        .await,
        "queue rows should render unchecked select checkboxes"
    );

    // The batch dropdown offers the three batch actions.
    assert!(
        tab.eval_bool(
            "(() => {{ const sel = document.getElementById('batch-action'); \
                    const values = [...sel.options].map(o => o.value); \
                    return values.includes('accept') && values.includes('skip') \
                        && values.includes('send-back'); }})()"
        ),
        "batch dropdown should offer Accept All, Skip All, and Send Back All"
    );

    // Select-all marks every visible row.
    tab.click("#queue-select-all");
    assert!(
        tab.eval_bool(&format!(
            "(() => {{ const a = document.querySelector('{draw_sel} .qi-select'); \
                    const b = document.querySelector('{hud_sel} .qi-select'); \
                    return !!a && a.checked && !!b && b.checked; }})()"
        )),
        "select-all should check every visible row"
    );

    // Choose Skip All from the dropdown: both units land in the persisted
    // skip set through the per-unit skip logic.
    tab.run(
        "(() => { const sel = document.getElementById('batch-action'); \
                sel.value = 'skip'; \
                sel.dispatchEvent(new Event('change')); })() === undefined",
        "trigger batch skip",
    );

    let skips_file = calxgloss_types::ReviewSkips::path_in(world.repo_path().as_path());
    let persisted = wait_for_persisted(&skips_file, |value| {
        let skipped = value["skipped"].as_array().cloned().unwrap_or_default();
        skipped.iter().any(|id| id == draw) && skipped.iter().any(|id| id == hud)
    })
    .await;
    let skipped = persisted["skipped"].as_array().cloned().unwrap_or_default();
    assert!(
        skipped.iter().any(|id| id == draw) && skipped.iter().any(|id| id == hud),
        "batch skip persists both selected units, got {skipped:?}"
    );

    // After the dashboard reload the selection is cleared — rows come back
    // with unchecked select checkboxes (and checked skip checkboxes).
    assert!(
        tab.wait_for_bool(&format!(
            "(() => {{ const a = document.querySelector('{draw_sel} .qi-select'); \
                    const b = document.querySelector('{hud_sel} .qi-select'); \
                    const sa = document.querySelector('{draw_sel} .qi-skip-check'); \
                    const sb = document.querySelector('{hud_sel} .qi-skip-check'); \
                    return !!a && !a.checked && !!b && !b.checked \
                        && !!sa && sa.checked && !!sb && sb.checked; }})()"
        ))
        .await,
        "selection should clear after the batch lands, with skips rendered"
    );
}

/// Headless-browser test for issue #76: the graph view loads enriched nodes
/// into the canvas renderer, node height encodes token usage, confidence
/// maps to a red→green hue (null stays neutral), and the kind/status/binary
/// selects combine with AND — the summary reports how many nodes survive.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_headless_graph_filters_and_encoding() {
    let fixture = TestFixture::new();

    // Canned usage through the record writer so DrawPrimitive renders
    // taller than units with none.
    write_token_usage_log(&fixture, false);

    let world = support::ReviewWorld::boot_plain_on(&fixture).await;

    let Some(tab) = world.open_dashboard_tab() else {
        return;
    };

    // Switch to the graph view.
    tab.click(r#".nav-tab[data-view="graph"]"#);

    // The renderer loads the fixture's five units.
    assert!(
        tab.wait_for_bool("!!window.calxglossGraph && window.calxglossGraph.totalNodeCount >= 5")
            .await,
        "graph renderer should load the fixture nodes"
    );

    // Size encoding: DrawPrimitive (7168 tokens) is taller than UpdateScene
    // (no recorded usage — base size, never zero).
    assert!(
        tab.wait_for_bool(
            "(() => { const g = window.calxglossGraph; if (!g) return false; \
                const draw = g._allNodes.find(n => n.id === 'game_logic.dll/DrawPrimitive/v2'); \
                const update = g._allNodes.find(n => n.id === 'game_logic.dll/UpdateScene/v1'); \
                return !!draw && draw.token_usage === 7168 && !!update \
                    && update.token_usage == null && draw._h > update._h; })()"
        )
        .await,
        "node height should encode token usage (DrawPrimitive taller, UpdateScene base)"
    );

    // Color encoding: real nodes stay honest (null confidence → neutral),
    // and the 0.0→1.0 range maps to hues 0→140 (red→green).
    assert!(
        tab.eval_bool(
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
                return honest && mapped; })()"
        ),
        "confidence should map to hues 0..140 with null staying neutral"
    );

    // Filters combine with AND: binary=d3d9.dll leaves the shim node…
    tab.run(
        "(() => { const sel = document.getElementById('graph-filter-binary'); \
            sel.value = 'd3d9.dll'; \
            sel.dispatchEvent(new Event('change')); })()",
        "set binary filter",
    );

    assert!(
        tab.wait_for_bool(
            "(() => { const g = window.calxglossGraph; \
                const sum = document.getElementById('graph-filter-summary'); \
                return !!g && g.visibleNodeCount === 2 && g.totalNodeCount >= 7 \
                    && sum.textContent.includes('2 of'); })()"
        )
        .await,
        "binary filter should leave only the d3d9.dll nodes"
    );

    // …and adding kind=shim_layer empties the view (AND, not OR — the two
    // d3d9.dll nodes are a classification and a function translation).
    tab.run(
        "(() => { const sel = document.getElementById('graph-filter-kind'); \
            sel.value = 'shim_layer'; \
            sel.dispatchEvent(new Event('change')); })()",
        "set kind filter",
    );

    assert!(
        tab.wait_for_bool(
            "(() => { const g = window.calxglossGraph; \
                return !!g && g.visibleNodeCount === 0; })()"
        )
        .await,
        "kind × binary filters must combine with AND"
    );

    // Resetting both selects restores every node, and the summary follows.
    tab.run(
        "(() => { for (const id of ['graph-filter-binary', 'graph-filter-kind']) { \
                const sel = document.getElementById(id); \
                sel.value = 'all'; \
                sel.dispatchEvent(new Event('change')); } })()",
        "reset filters",
    );

    let summary = tab.eval_text(
        "(() => { const g = window.calxglossGraph; \
            const sum = document.getElementById('graph-filter-summary'); \
            return (g && g.visibleNodeCount === g.totalNodeCount) ? sum.textContent : ''; })()",
    );
    let restored = !summary.is_empty() && summary.contains("nodes") && !summary.contains(" of ");
    assert!(
        restored,
        "reset filters should restore all nodes, summary reads 'N nodes': {summary:?}"
    );
}

/// Headless-browser test for graph export + shareable URLs (issue #79):
/// `toSVG()` serializes the filtered view (visible nodes only, each including
/// its unit id), the PNG export runs the same SVG through rasterization, the
/// share URL encodes the active filters and the zoom/pan camera, and opening
/// that URL in a fresh tab restores the same filters and viewport.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_headless_graph_export_and_share_url() {
    let world = support::ReviewWorld::boot_plain().await;

    let Some(tab) = world.open_dashboard_tab() else {
        return;
    };

    // Wait for the graph renderer to load the fixture's units.
    assert!(
        tab.wait_for_bool("!!window.calxglossGraph && window.calxglossGraph.totalNodeCount >= 5")
            .await,
        "graph renderer should load the fixture nodes"
    );

    // Narrow to one binary — export and share must both follow the
    // filtered view, not the full graph.
    tab.run(
        "(() => { const sel = document.getElementById('graph-filter-binary'); \
            sel.value = 'd3d9.dll'; \
            sel.dispatchEvent(new Event('change')); })()",
        "set binary filter",
    );

    assert!(
        tab.wait_for_bool(
            "!!window.calxglossGraph && window.calxglossGraph.visibleNodeCount === 2"
        )
        .await,
        "binary filter should leave the two d3d9.dll nodes"
    );

    // SVG export matches the filtered view: the d3d9 nodes are in (their
    // unit ids appear as data-id attributes), game_logic nodes are out.
    let svg = tab.eval_text("window.calxglossGraph.toSVG()");
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
    let png_ok = tab.eval_promise_bool("window.calxglossExportPNG()");
    assert!(
        png_ok,
        "PNG export should rasterize the SVG and produce a blob"
    );

    // Move the camera, then build the share URL — it must encode the
    // active filter and the viewport state.
    tab.run(
        "(() => { const g = window.calxglossGraph; \
            g.scale = 1.5; g.offsetX = 120; g.offsetY = -40; g.draw(); })()",
        "move camera",
    );

    let share_url = tab.eval_text("window.calxglossShareUrl()");
    for fragment in ["view=graph", "gb=d3d9.dll", "gz=1.5", "gx=120", "gy=-40"] {
        assert!(
            share_url.contains(fragment),
            "share URL {share_url} should encode {fragment}"
        );
    }

    // Opening the shared URL in a fresh tab restores the filter (select and
    // visible node count) and the exact camera.
    let shared_tab = tab.open_tab_at(&share_url);

    assert!(
        support::wait_for_bool_on(
            &shared_tab,
            "(() => { const g = window.calxglossGraph; if (!g) return false; \
                    const sel = document.getElementById('graph-filter-binary'); \
                    return sel.value === 'd3d9.dll' && g.visibleNodeCount === 2 \
                        && Math.abs(g.scale - 1.5) < 0.001 \
                        && Math.abs(g.offsetX - 120) < 0.001 \
                        && Math.abs(g.offsetY + 40) < 0.001; })()"
        )
        .await,
        "opening the shared URL should restore the encoded filters and viewport"
    );

    shared_tab.close_target().ok();
}

/// Headless-browser test for the LLM I/O log browser (issue #80): the view
/// loads its history from `GET /api/llm-io` (so it survives a reload),
/// shows a token count per entry, starts entries collapsed and expands
/// them on header click, offers one-click copy per entry, narrows the list
/// through the binary filter and full-text search, and still appends live
/// WebSocket entries on top of the history — without duplicating them when
/// the history reloads on the next view entry.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_headless_llm_log_browser() {
    let fixture = TestFixture::new();

    // History from a "previous run": filed through the log writer before
    // the world boots, so the view must load it from the server rather
    // than a memory buffer.
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

    let world = support::ReviewWorld::boot_ws_on(&fixture).await;

    let Some(tab) = world.open_dashboard_tab() else {
        return;
    };

    let visible_count =
        || tab.eval_count("document.querySelectorAll('#llm-log-entries .llm-log-entry').length");

    // Switch to the LLM I/O tab.
    tab.click(r#".nav-tab[data-view="llm-log"]"#);

    // The persisted history renders — loaded over HTTP, not from a buffer.
    assert!(
        tab.wait_for_bool(
            "document.querySelectorAll('#llm-log-entries .llm-log-entry').length === 3"
        )
        .await,
        "log view should load the persisted history"
    );

    // Token count per entry: the response reports its count, the request
    // shows an honest em dash rather than a fabricated zero.
    let response_meta = tab.eval_text(
        "document.querySelector('#llm-log-entries .llm-log-entry:nth-child(2) .meta').textContent",
    );
    assert!(
        response_meta.contains("4321 tokens"),
        "response entry should show its token count, got: {response_meta}"
    );
    let request_meta = tab.eval_text(
        "document.querySelector('#llm-log-entries .llm-log-entry:nth-child(1) .meta').textContent",
    );
    assert!(
        request_meta.contains('—'),
        "request entry should show an em dash for the unmeasured token count, got: {request_meta}"
    );

    // Entries start collapsed: the body is hidden until the header is clicked.
    assert!(
        tab.eval_bool(
            "document.querySelector('#llm-log-entries .llm-log-entry .llm-log-entry-body').offsetHeight === 0"
        ),
        "entries should start collapsed"
    );
    tab.click("#llm-log-entries .llm-log-entry .llm-log-entry-header");
    assert!(
        tab.eval_bool(
            "document.querySelector('#llm-log-entries .llm-log-entry .llm-log-entry-body').offsetHeight > 0"
        ),
        "header click should expand the entry"
    );

    // One-click copy: every entry has a copy button.
    assert!(
        tab.eval_bool("document.querySelectorAll('#llm-log-entries .llm-log-copy').length === 3"),
        "every entry should have a copy button"
    );

    // Binary filter narrows to one binary.
    tab.run(
        "(() => { const sel = document.getElementById('llm-log-filter-binary'); \
            sel.value = 'd3d9.dll'; \
            sel.dispatchEvent(new Event('change')); })()",
        "set binary filter",
    );
    assert!(
        visible_count() == 1,
        "binary filter should leave only the d3d9.dll entry"
    );

    // Full-text search through prompt content (filter reset first).
    tab.run(
        "(() => { const sel = document.getElementById('llm-log-filter-binary'); \
            sel.value = ''; \
            sel.dispatchEvent(new Event('change')); \
            const inp = document.getElementById('llm-log-search'); \
            inp.value = 'compile errors'; \
            inp.dispatchEvent(new Event('input')); })()",
        "set search",
    );
    assert!(
        visible_count() == 1,
        "search should match exactly the entry whose content mentions it"
    );
    let searched_meta = tab
        .eval_text("document.querySelector('#llm-log-entries .llm-log-entry .meta').textContent");
    assert!(
        searched_meta.contains("UpdateScene"),
        "the searched entry should be the UpdateScene prompt, got: {searched_meta}"
    );

    // Reset the search — back to the full history.
    tab.run(
        "(() => { const inp = document.getElementById('llm-log-search'); \
            inp.value = ''; \
            inp.dispatchEvent(new Event('input')); })()",
        "clear search",
    );
    assert!(
        visible_count() == 3,
        "clearing the search should show all history"
    );

    // Live WebSocket entries still append on top of the history — including
    // a failed call, whose content must match the server log's raw error.
    world.emitter().emit(ProgressEvent::LlmRequest {
        binary: "game_logic.dll".into(),
        function: "UpdateScene".into(),
        attempt: 3,
        retry_strategy: "direct".into(),
        prompt: "translate UpdateScene".into(),
    });
    let failed_call = ProgressEvent::LlmCallFailed {
        binary: "d3d9.dll".into(),
        function: "UpdateScene".into(),
        attempt: 4,
        retry_strategy: "retry".into(),
        error: "connection reset".into(),
    };
    world.emitter().emit(failed_call.clone());

    // The consumer appends each log entry before applying the event to the
    // store, so the failure's unit record standing in the store proves
    // both live entries are already persisted server-side.
    world
        .wait_until_unit_applied(&failed_call, "d3d9.dll", "UpdateScene", |_| true)
        .await;

    assert!(
        tab.wait_for_bool(
            "document.querySelectorAll('#llm-log-entries .llm-log-entry').length === 5"
        )
        .await,
        "live WS entries should append on top of the history"
    );

    // Re-entering the view reloads the history — the live entries were also
    // persisted server-side, and dedup must keep them from showing twice
    // (the error entry's content is the raw error on both sides). Arm the
    // page's own re-render sentinel first. The page rewrites the entries
    // container only after its fresh history load lands, so waiting on that
    // rewrite proves the reload re-rendered — no fixed sleep.
    tab.run(
        "(() => { window.__llmLogRerender = false; \
            new MutationObserver(() => { window.__llmLogRerender = true; }) \
                .observe(document.getElementById('llm-log-entries'), { childList: true }); })()",
        "arm the re-render sentinel",
    );
    tab.run(
        "document.querySelector('.nav-tab[data-view=\"dashboard\"]').click(); \
         document.querySelector('.nav-tab[data-view=\"llm-log\"]').click();",
        "re-enter llm-log view",
    );
    assert!(
        tab.wait_for_bool("window.__llmLogRerender === true").await,
        "the re-entered view never re-rendered from a fresh history load"
    );
    let reloaded = visible_count();
    assert!(
        reloaded == 5,
        "history reload must not duplicate the live entries — got {reloaded} entries"
    );
}

/// Headless-browser test for the live translation view (issue #65): in live
/// mode the Live tab must render one progress bar per in-flight unit, labeled
/// with its current phase and the evidence the live stream reported — tier,
/// strategy, attempt, baseline/verification status, confidence — and must
/// update the row when a later event lands over the WebSocket.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_headless_live_view_renders_and_updates() {
    let world = support::ReviewWorld::boot().await;

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
    ] {
        world.emitter().emit(event);
    }
    let in_flight = ProgressEvent::LlmCallStart {
        binary: "game_logic.dll".into(),
        function: "DrawPrimitive".into(),
        attempt: 2,
        retry_strategy: "decompose".into(),
    };
    world.emitter().emit(in_flight.clone());
    world
        .wait_until_unit_applied(&in_flight, "game_logic.dll", "DrawPrimitive", |record| {
            record.phase == calxgloss_types::TranslationPhase::LlmCall && record.attempt == 2
        })
        .await;

    let Some(tab) = world.open_dashboard_tab() else {
        return;
    };

    // Switch to the Live tab.
    tab.click(r#".nav-tab[data-view="live"]"#);

    // The row renders asynchronously once the enhanced-progress fetch settles;
    // wait until the unit appears.
    assert!(
        tab.wait_for_bool(
            "document.querySelectorAll('#live-units .live-unit[data-function=\"DrawPrimitive\"]').length === 1"
        )
        .await,
        "live view should render one row for the in-flight unit, rows: {}",
        tab.eval_count("document.querySelectorAll('#live-units .live-unit').length")
    );

    // The row shows the phase label and the evidence the stream reported.
    let row = "#live-units .live-unit[data-function=\"DrawPrimitive\"]";
    let row_text = |suffix: &str| -> String {
        tab.eval_text(&format!("document.querySelector('{row}')?{suffix} || ''"))
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
    world
        .emitter()
        .emit(ProgressEvent::TranslationAttemptCompleted {
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
    let completed = ProgressEvent::TranslationCompleted {
        binary: "game_logic.dll".into(),
        function: "DrawPrimitive".into(),
        total_attempts: 2,
        success_strategy: Some("decompose".into()),
    };
    world.emitter().emit(completed.clone());
    world
        .wait_until_unit_applied(&completed, "game_logic.dll", "DrawPrimitive", |record| {
            record.finished
        })
        .await;

    assert!(
        tab.wait_for_bool(&format!(
            "(() => {{ const r = document.querySelector('{row}'); \
            return !!r && r.classList.contains('finished-ok') && \
                r.querySelector('.live-phase')?.textContent === 'Review'; }})()"
        ))
        .await,
        "row should update to Review/finished over the WS"
    );
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
}

/// Headless-browser test for issue #431 (P53.4): the queue row marks the unit
/// in flight with its live reading — the current pipeline phase — and updates
/// that marker in place when the existing `unit_phase` WebSocket push arrives,
/// with no page reload. A unit the run never touched carries no live marker
/// at all, and the live marker rides as its own element beside the row's
/// persisted status chip, never inside it. A unit the run fails reads Failed,
/// never Awaiting Review — the push's own `succeeded` field decides.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_headless_queue_row_shows_live_reading_and_updates_in_place() {
    let fixture = TestFixture::new();
    add_pending_translation(&fixture, "RenderHUD");
    add_pending_translation(&fixture, "PauseGame");
    let world = support::ReviewWorld::boot_ws_on(&fixture).await;

    // One unit in flight at the LLM call before the browser even opens.
    world.emitter().emit(ProgressEvent::TranslationStarted {
        binary: "game_logic.dll".into(),
        function: "DrawPrimitive".into(),
    });
    let in_flight = ProgressEvent::LlmCallStart {
        binary: "game_logic.dll".into(),
        function: "DrawPrimitive".into(),
        attempt: 1,
        retry_strategy: "direct".into(),
    };
    world.emitter().emit(in_flight.clone());
    world
        .wait_until_unit_applied(&in_flight, "game_logic.dll", "DrawPrimitive", |record| {
            record.phase == calxgloss_types::TranslationPhase::LlmCall
        })
        .await;

    let Some(tab) = world.open_dashboard_tab() else {
        return;
    };

    tab.click(r#".nav-tab[data-view="queue"]"#);

    let draw_row = "#full-queue-list [data-unit-id=\\\"game_logic.dll/DrawPrimitive/v2\\\"]";
    let hud_row = "#full-queue-list [data-unit-id=\\\"game_logic.dll/RenderHUD/v1\\\"]";

    // The in-flight unit's row carries a live marker naming its phase.
    assert!(
        tab.wait_for_bool(&format!(
            "(() => {{ const el = document.querySelector('{draw_row} .qi-live'); \
                return !!el && el.textContent === 'LLM Call'; }})()"
        ))
        .await,
        "queue row should carry a live marker naming the unit's phase"
    );

    // The marker rides beside the persisted status chip as its own element —
    // two fields, never one.
    assert!(
        tab.eval_bool(&format!(
            "(() => {{ const row = document.querySelector('{draw_row}'); \
            return !!row && row.querySelector('.qi-live') !== null \
                && row.querySelector('.qi-status') !== null; }})()"
        )),
        "the live marker and the persisted status chip are separate elements"
    );

    // A unit the run never touched carries no live marker at all.
    assert!(
        tab.eval_bool(&format!(
            "(() => {{ const row = document.querySelector('{hud_row}'); \
            return !!row && row.querySelector('.qi-live') === null; }})()"
        )),
        "an untouched unit's row carries no live marker — a blank never reads as a state"
    );

    // The run completes the unit. The existing unit_phase push must switch
    // the marker to awaiting-review in place — the test never navigates or
    // reloads the page.
    let completed = ProgressEvent::TranslationCompleted {
        binary: "game_logic.dll".into(),
        function: "DrawPrimitive".into(),
        total_attempts: 1,
        success_strategy: Some("direct".into()),
    };
    world.emitter().emit(completed.clone());
    world
        .wait_until_unit_applied(&completed, "game_logic.dll", "DrawPrimitive", |record| {
            record.finished
        })
        .await;

    assert!(
        tab.wait_for_bool(&format!(
            "(() => {{ const el = document.querySelector('{draw_row} .qi-live'); \
                return !!el && el.textContent === 'Awaiting Review'; }})()"
        ))
        .await,
        "the queue row's live marker should update in place off the WS push, no reload"
    );

    // The run then fails another unit. That unit's row must read Failed,
    // never Awaiting Review — a failed unit moved no closer to review. The
    // same push path updates this row in place too.
    world.emitter().emit(ProgressEvent::TranslationStarted {
        binary: "game_logic.dll".into(),
        function: "PauseGame".into(),
    });
    let failed = ProgressEvent::TranslationFailed {
        binary: "game_logic.dll".into(),
        function: "PauseGame".into(),
        total_attempts: 1,
    };
    world.emitter().emit(failed.clone());
    world
        .wait_until_unit_applied(&failed, "game_logic.dll", "PauseGame", |record| {
            record.finished && record.succeeded == Some(false)
        })
        .await;
    let pause_row = "#full-queue-list [data-unit-id=\\\"game_logic.dll/PauseGame/v1\\\"]";
    assert!(
        tab.wait_for_bool(&format!(
            "(() => {{ const el = document.querySelector('{pause_row} .qi-live'); \
                return !!el && el.textContent === 'Failed'; }})()"
        ))
        .await,
        "a failed unit's row reads Failed — never Awaiting Review"
    );
}

/// Headless-browser honesty test for the live translation view (issue #65):
/// outside `calxgloss live` the enhanced endpoint is not routed, so the Live
/// tab must say the live view needs a running pipeline — never render an
/// empty list that masquerades as an idle run.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_headless_live_view_honest_without_live_mode() {
    let world = support::ReviewWorld::boot_plain().await;

    let Some(tab) = world.open_dashboard_tab() else {
        return;
    };

    tab.click(r#".nav-tab[data-view="live"]"#);

    // The honest empty state must appear.
    assert!(
        tab.wait_for_bool(
            "(() => { const e = document.getElementById('live-empty'); \
                return !!e && e.style.display !== 'none' && \
                    e.textContent.includes('calxgloss live'); })()"
        )
        .await,
        "plain serve must announce that the live view needs calxgloss live"
    );
    assert!(
        !tab.eval_bool("document.querySelector('#live-units .live-unit') !== null"),
        "no fabricated unit rows outside live mode"
    );
}

/// Headless-browser test for issue #66: the dashboard must render category
/// cards sourced from the classification data, a quality summary computed
/// from the dashboard units, and a token budget visual driven by the
/// token-usage log and a user-set budget.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_headless_dashboard_summary_sections() {
    let fixture = TestFixture::new();
    write_token_usage_log(&fixture, false);

    let world = support::ReviewWorld::boot_plain_on(&fixture).await;

    let Some(tab) = world.open_dashboard_tab() else {
        return;
    };

    // Category cards: one per DllCategory, with the fixture's counts.
    assert!(
        tab.wait_for_bool(
            "(() => { const cards = document.querySelectorAll('#category-cards .category-card'); \
                if (cards.length !== 7) return false; \
                const ps = document.querySelector('#category-cards [data-category=\"ProjectSpecific\"]'); \
                const sdk = document.querySelector('#category-cards [data-category=\"MicrosoftSdk\"]'); \
                const dotnet = document.querySelector('#category-cards [data-category=\"DotNetManaged\"]'); \
                return !!ps && !!sdk && ps.textContent.includes('1') && sdk.textContent.includes('1') && \
                    !!dotnet && \
                    dotnet.querySelector('.category-card-label')?.textContent === '.NET Managed' && \
                    dotnet.querySelector('.category-card-value')?.textContent === '0'; })()"
        )
        .await,
        "category cards should render 7 categories with fixture counts, with the DotNetManaged card present at an honest zero"
    );

    // Quality summary: avg confidence 73% (0.725 rounded), and honest
    // em-dashes for the baseline/verification rates with no data behind them.
    assert!(
        tab.wait_for_bool(
            "(() => { const el = document.getElementById('quality-summary'); \
                if (!el) return false; const t = el.textContent; \
                return t.includes('73%') && t.includes('—'); })()"
        )
        .await,
        "quality summary should show the 73% average confidence and em-dashes for the rates with no data behind them, got: {:?}",
        tab.eval_text("document.getElementById('quality-summary')?.textContent || ''")
    );

    // Token budget: consumed tokens come from the log; the budget itself is
    // a user preference in localStorage. Set it, reload, and check the bar.
    tab.run(
        "localStorage.setItem('calxgloss_token_budget', '10000') === undefined",
        "set token budget",
    );
    tab.reload();

    assert!(
        tab.wait_for_bool(
            "(() => { const el = document.getElementById('token-budget'); \
                if (!el) return false; \
                const tokens = el.querySelector('[data-total-tokens]'); \
                if (!tokens || tokens.getAttribute('data-total-tokens') !== '7168') return false; \
                const fill = el.querySelector('.token-budget-fill'); \
                return !!fill && fill.style.width === '71.68%'; })()"
        )
        .await,
        "token budget bar should show 7,168 consumed against the 10,000 budget (71.68%), got: {:?}",
        tab.eval_text("document.getElementById('token-budget')?.textContent || ''")
    );
}

/// Headless-browser test: a browser reload keeps the tab the operator was
/// on — clicking the pipeline tab and reloading must land back on the
/// pipeline view, not the dashboard.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_headless_reload_keeps_current_tab() {
    let world = support::ReviewWorld::boot_plain().await;

    let Some(tab) = world.open_dashboard_tab() else {
        return;
    };

    // Switch to the pipeline tab.
    tab.run(
        "(() => { document.querySelector('.nav-tab[data-view=\"pipeline\"]').click(); })()",
        "click pipeline tab",
    );

    let pipeline_active = "document.getElementById('view-pipeline')?.classList.contains('view-active') === true \
        && document.getElementById('view-dashboard')?.classList.contains('view-active') !== true";
    assert!(
        tab.wait_for_bool(pipeline_active).await,
        "pipeline view should be active after the tab click"
    );

    // Reload: the pipeline view must still be the active one.
    tab.reload();

    assert!(
        tab.wait_for_bool(pipeline_active).await,
        "reload should stay on the pipeline tab, not fall back to the dashboard"
    );
}

/// Headless-browser pin for the live view's evidence-scan panel (issue #428):
/// pushed scan events render named rows without a reload. A running row shows
/// its name and a ticking clock. A finished row shows its elapsed seconds and
/// the finding count the evidence engine reported. A finished scan that filed
/// no single count shows the words `findings: unknown` instead of a number.
/// A failed scan renders distinctly as failed, with its error text visible
/// and no count (issue #429). A batch for the next binary clears the pass's
/// rows.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_headless_live_view_shows_scan_rows() {
    let world = support::ReviewWorld::boot().await;

    let Some(tab) = world.open_dashboard_tab() else {
        eprintln!("skipping scan-panel test: no headless browser found");
        return;
    };
    tab.click(r#".nav-tab[data-view="live"]"#);

    // Before the first started event the panel says the scan phase has not
    // started — it must not imply that a count of scans ran.
    assert!(
        tab.wait_for_bool("document.getElementById('live-scans-empty').style.display === ''")
            .await,
        "the not-started message should show before the first scan event"
    );
    let before = tab.eval_text("document.getElementById('live-scans')?.textContent || ''");
    assert!(
        !before.contains("0 scan") && !before.contains("scan"),
        "no scan rows and no implied scan count before the first event, got {before:?}"
    );

    // One pass over one binary: a finished scan with a count, one still
    // running, one finished whose evidence engine files no single
    // count, one finished failed with its error and no count, and one
    // failed whose error words are blank (issue #429).
    world.emitter().emit(ProgressEvent::BatchStarted {
        binary: "scan_hd.dll".into(),
    });
    let scan_events = [
        ProgressEvent::EvidenceScanStarted {
            binary: "scan_hd.dll".into(),
            scan: "control-flow".into(),
        },
        ProgressEvent::EvidenceScanCompleted {
            binary: "scan_hd.dll".into(),
            scan: "control-flow".into(),
            elapsed_secs: 2.5,
            findings: Some(9),
            error: None,
        },
        ProgressEvent::EvidenceScanStarted {
            binary: "scan_hd.dll".into(),
            scan: "callback-detection".into(),
        },
        ProgressEvent::EvidenceScanStarted {
            binary: "scan_hd.dll".into(),
            scan: "type-database".into(),
        },
        ProgressEvent::EvidenceScanCompleted {
            binary: "scan_hd.dll".into(),
            scan: "type-database".into(),
            elapsed_secs: 4.0,
            findings: None,
            error: None,
        },
        ProgressEvent::EvidenceScanStarted {
            binary: "scan_hd.dll".into(),
            scan: "sync".into(),
        },
        ProgressEvent::EvidenceScanCompleted {
            binary: "scan_hd.dll".into(),
            scan: "sync".into(),
            elapsed_secs: 3.0,
            findings: None,
            error: Some("the sync evidence engine refused the scan".into()),
        },
        ProgressEvent::EvidenceScanStarted {
            binary: "scan_hd.dll".into(),
            scan: "blank-error".into(),
        },
        ProgressEvent::EvidenceScanCompleted {
            binary: "scan_hd.dll".into(),
            scan: "blank-error".into(),
            elapsed_secs: 1.0,
            findings: None,
            error: Some(String::new()),
        },
    ];
    let last_scan = scan_events
        .last()
        .cloned()
        .expect("the pass ends with a completed scan");
    for event in scan_events {
        world.emitter().emit(event);
    }

    // The applied wait first: the live view serves all five scan records.
    world
        .wait_until_enhanced_progress_applied(&last_scan, |body| {
            body["scans"].as_array().is_some_and(|scans| {
                scans.len() == 5
                    && scans
                        .iter()
                        .any(|s| s["scan"] == "blank-error" && s["finished"] == true)
            })
        })
        .await;

    // The pushed events re-render the panel on their own: five named
    // rows, no reload.
    assert!(
        tab.wait_for_bool("document.querySelectorAll('#live-scans .live-scan').length === 5")
            .await,
        "the pushed scan events should produce five rows without a reload, rows: {}",
        tab.eval_count("document.querySelectorAll('#live-scans .live-scan').length")
    );
    let row_text = |name: &str| -> String {
        tab.eval_text(&format!(
            "document.querySelector('#live-scans [data-scan=\"{name}\"]')?.textContent || ''"
        ))
    };

    // Finished rows: elapsed seconds with the finding count where the
    // scan files one, and the words `findings: unknown` where it does
    // not — an unreported count never shows a number (issue #429).
    let counted = row_text("control-flow");
    assert!(
        counted.contains("2.5s") && counted.contains("9 findings"),
        "the finished row should show elapsed seconds and the finding count, got {counted:?}"
    );
    let uncounted = row_text("type-database");
    assert!(
        uncounted.contains("4s") && uncounted.contains("findings: unknown"),
        "a finished scan without one reported count must not show a number, got {uncounted:?}"
    );
    assert!(
        !uncounted.contains("0 finding"),
        "a row must not invent a zero count, got {uncounted:?}"
    );

    // The failed scan reads as failed at a glance, with its error text
    // visible in the browser, and never with a zero count (issue #429).
    let failed = row_text("sync");
    assert!(
        failed.contains("failed") && failed.contains("the sync evidence engine refused the scan"),
        "the failed scan should read as failed with its error text, got {failed:?}"
    );
    assert!(
        !failed.contains("0 finding"),
        "a failed scan must not show a zero count, got {failed:?}"
    );
    assert!(
        tab.eval_bool(
            "document.querySelector('#live-scans [data-scan=\"sync\"]')?.classList.contains('scan-failed') === true"
        ),
        "the failed row should carry the scan-failed class, distinct from the finished rows"
    );
    assert!(
        tab.eval_bool(
            "document.querySelector('#live-scans [data-scan=\"control-flow\"]')?.classList.contains('scan-failed') === false"
        ),
        "a completed row should not carry the failed class"
    );

    // A failure whose error words are blank still reads as failed: the
    // row looks at whether the error is there, not at how long its words
    // are (issue #429).
    let blank_failure = row_text("blank-error");
    assert!(
        blank_failure.contains("failed") && !blank_failure.contains("running"),
        "a failed scan with blank error words must still render as failed, got {blank_failure:?}"
    );
    assert!(
        tab.eval_bool(
            "document.querySelector('#live-scans [data-scan=\"blank-error\"]')?.classList.contains('scan-failed') === true"
        ),
        "the blank-error row should carry the scan-failed class, not read as completed"
    );

    // The in-flight scan stays a running row, its clock advancing on the
    // ticker while its completed event is still out.
    let running = row_text("callback-detection");
    assert!(
        running.contains("running"),
        "the in-flight scan should render as running, got {running:?}"
    );
    let clock = || -> String {
        tab.eval_text(
            "document.querySelector('#live-scans [data-scan=\"callback-detection\"] .live-elapsed')?.textContent || ''",
        )
    };
    let first = clock();
    assert!(
        first.ends_with('s') && first != "s",
        "the running row should show a seconds clock, got {first:?}"
    );
    // This delay is the subject under test, not a settle: the clock must
    // advance because real time passed while the completed event stayed out.
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let second = clock();
    assert_ne!(
        first, second,
        "the running scan's clock must advance without a reload (was {first:?}, now {second:?})"
    );

    // A batch for the next binary clears this pass's scan rows, and the panel
    // falls back to the not-started message.
    let next_pass = ProgressEvent::BatchStarted {
        binary: "next_scan_hd.dll".into(),
    };
    world.emitter().emit(next_pass.clone());
    world
        .wait_until_enhanced_progress_applied(&next_pass, |body| {
            body["scans"]
                .as_array()
                .is_some_and(|scans| scans.is_empty())
        })
        .await;
    assert!(
        tab.wait_for_bool("document.querySelectorAll('#live-scans .live-scan').length === 0")
            .await,
        "a batch for the next binary should clear the previous pass's scan rows"
    );
    assert!(
        tab.eval_bool("document.getElementById('live-scans-empty').style.display === ''"),
        "the cleared panel should say the scan phase has not started"
    );
}

/// Headless-browser pin for the worklist tick line in the live view's scan
/// panel (issue #430): the pipeline's existing `BatchProgress` heartbeat
/// renders beside the scan rows as pass name · function · position. The
/// position advances as later heartbeats arrive, with no page reload. A
/// heartbeat under the call-graph pass name renders the same line under
/// that name — no new event. A pass with no per-item granularity renders
/// its name alone, never a fabricated position.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_headless_live_view_shows_worklist_tick_line() {
    let world = support::ReviewWorld::boot().await;

    let Some(tab) = world.open_dashboard_tab() else {
        eprintln!("skipping worklist-tick test: no headless browser found");
        return;
    };
    tab.click(r#".nav-tab[data-view="live"]"#);

    let tick_text = || -> String {
        tab.eval_text("document.getElementById('live-worklist-tick')?.textContent || ''")
    };

    // Before the pass's first heartbeat there is no tick line to show.
    assert!(
        tick_text().is_empty(),
        "no heartbeat has landed, so the tick line should be empty, got {:?}",
        tick_text()
    );

    // A scan running with the pass's heartbeat beside it: the line names
    // the pass, the function Kuna is on, and the position in the work list.
    world.emitter().emit(ProgressEvent::BatchStarted {
        binary: "tick_hd.dll".into(),
    });
    world.emitter().emit(ProgressEvent::EvidenceScanStarted {
        binary: "tick_hd.dll".into(),
        scan: "sync".into(),
    });
    let beat = ProgressEvent::BatchProgress {
        binary: "tick_hd.dll".into(),
        pass: "evidence scans".into(),
        function: "FUN_1800412a0".into(),
        index: 1200,
        total: 7267,
    };
    world.emitter().emit(beat.clone());
    world
        .wait_until_enhanced_progress_applied(&beat, |body| {
            body["activity"]["function"] == "FUN_1800412a0"
        })
        .await;

    // The heartbeat re-renders the panel on its own — the tick line shows
    // while the scan row is still running, no reload.
    assert!(
        tab.wait_for_text(
            "document.getElementById('live-worklist-tick')?.textContent || ''",
            |text| {
                text.contains("evidence scans")
                    && text.contains("FUN_1800412a0")
                    && text.contains("1,200/7,267")
            }
        )
        .await,
        "the heartbeat should render pass · function · position without a reload, got {:?}",
        tick_text()
    );
    assert_eq!(
        tab.eval_count("document.querySelectorAll('#live-scans .live-scan').length"),
        1,
        "the running scan row stands beside the tick line"
    );

    // The next unique function sends its heartbeat and moves the counter
    // forward. Same line, position moved, still no reload.
    let next_beat = ProgressEvent::BatchProgress {
        binary: "tick_hd.dll".into(),
        pass: "evidence scans".into(),
        function: "FUN_180057900".into(),
        index: 1201,
        total: 7267,
    };
    world.emitter().emit(next_beat.clone());
    world
        .wait_until_enhanced_progress_applied(&next_beat, |body| {
            body["activity"]["function"] == "FUN_180057900"
        })
        .await;
    assert!(
        tab.wait_for_text(
            "document.getElementById('live-worklist-tick')?.textContent || ''",
            |text| text.contains("FUN_180057900") && text.contains("1,201/7,267")
        )
        .await,
        "the tick line's position should advance as heartbeats arrive, got {:?}",
        tick_text()
    );

    // The cold call-graph build sends its heartbeat under its own pass
    // name. The same line; no new event variant.
    let graph_beat = ProgressEvent::BatchProgress {
        binary: "tick_hd.dll".into(),
        pass: "call graph".into(),
        function: "FUN_180060000".into(),
        index: 41,
        total: 7267,
    };
    world.emitter().emit(graph_beat.clone());
    world
        .wait_until_enhanced_progress_applied(&graph_beat, |body| {
            body["activity"]["function"] == "FUN_180060000"
        })
        .await;
    assert!(
        tab.wait_for_text(
            "document.getElementById('live-worklist-tick')?.textContent || ''",
            |text| {
                text.contains("call graph")
                    && text.contains("FUN_180060000")
                    && text.contains("41/7,267")
            }
        )
        .await,
        "the call-graph heartbeat should render the same line under its own pass name, got {:?}",
        tick_text()
    );

    // A pass with no per-item granularity shows its name alone — never a
    // fabricated position or a zero.
    let name_only_beat = ProgressEvent::BatchProgress {
        binary: "tick_hd.dll".into(),
        pass: "xref index".into(),
        function: String::new(),
        index: 0,
        total: 0,
    };
    world.emitter().emit(name_only_beat.clone());
    world
        .wait_until_enhanced_progress_applied(&name_only_beat, |body| {
            body["activity"]["pass"] == "xref index"
        })
        .await;
    assert!(
        tab.wait_for_text(
            "document.getElementById('live-worklist-tick')?.textContent || ''",
            |text| text.contains("xref index") && !text.contains('/') && !text.contains('0')
        )
        .await,
        "a pass without per-item granularity should show its name alone, got {:?}",
        tick_text()
    );

    // A batch for the next binary clears the heartbeat record with the
    // scan rows. The line empties rather than outliving the pass it
    // showed.
    let next_pass = ProgressEvent::BatchStarted {
        binary: "next_tick_hd.dll".into(),
    };
    world.emitter().emit(next_pass.clone());
    world
        .wait_until_enhanced_progress_applied(&next_pass, |body| {
            body.get("activity").is_none()
                && body
                    .get("scans")
                    .is_some_and(|scans| scans.as_array().is_some_and(|s| s.is_empty()))
        })
        .await;
    assert!(
        tab.wait_for_bool("document.getElementById('live-worklist-tick')?.textContent === ''")
            .await,
        "the next binary's pass should clear the previous pass's tick line, got {:?}",
        tick_text()
    );
}

/// Poll a persisted record file until `settled` accepts its JSON — the
/// applied wait for the queue panel's endpoint calls, which the page fires
/// without awaiting. It returns the record that satisfied the predicate,
/// or the last one seen when the deadline passes, so the caller's own
/// assertion names the change that never landed. Shares the adapter's
/// wait bounds (issue #476).
async fn wait_for_persisted(
    path: &std::path::Path,
    settled: impl Fn(&serde_json::Value) -> bool,
) -> serde_json::Value {
    let deadline = tokio::time::Instant::now() + support::APPLIED_WAIT_DEADLINE;
    loop {
        let value = std::fs::read_to_string(path)
            .ok()
            .and_then(|raw| serde_json::from_str(&raw).ok())
            .unwrap_or_default();
        if settled(&value) || tokio::time::Instant::now() >= deadline {
            return value;
        }
        tokio::time::sleep(support::APPLIED_WAIT_POLL).await;
    }
}
