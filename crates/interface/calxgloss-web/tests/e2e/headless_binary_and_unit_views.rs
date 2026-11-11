//! Scenario tests split from `tests/e2e.rs`.
//!
//! Every test here boots one world through the review-world adapter (issue
//! #475). A test files its record fixtures through the record writers,
//! emits progress events through the typed emitter and waits for the
//! server to apply them, and reads the browser's DOM through the world's
//! bounded waits. A live reading is never slept through.

use super::*;

/// Headless-browser test for a pipeline row's single translation toggle
/// (issue #285). While the pipeline works a binary, that row's one button
/// reads Pause. Clicking it calls the per-binary pause endpoint, not the
/// run-wide POST /api/pipeline/pause. The WS binary_pause_changed event
/// redraws the row as Paused — the paused flag wins over the working flag —
/// and the same button slot becomes Start Translation. Pressing that calls
/// the per-binary start endpoint, which resumes the held binary and moves it
/// to the front of the run, and the row shows Working again with Pause in
/// its slot. Either way the run-level machine never moves. Same shape as the
/// restart-dialog endpoint test.
///
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_headless_binary_translation_toggle_matrix() {
    // A running run: if the row's button called the run-wide endpoints, the
    // machine would move — it has to stay running the whole time.
    let world = support::ReviewWorld::boot_ws_wired().await;
    world.pipeline_control().start().expect("idle -> running");

    // One planned binary whose batch pass is in flight: the honest Pause
    // state of the toggle.
    let planned = ProgressEvent::QueuePlanned {
        binaries: vec!["game_logic.dll".to_string()],
    };
    world.emitter().emit(planned.clone());
    world
        .wait_until_applied(&planned, |view| {
            support::row_named(view, "game_logic.dll").is_some()
        })
        .await;
    let working = ProgressEvent::BatchStarted {
        binary: "game_logic.dll".into(),
    };
    world.emitter().emit(working.clone());
    world
        .wait_until_applied(&working, |view| {
            support::row_named(view, "game_logic.dll").is_some_and(|b| b["processing"] == true)
        })
        .await;

    let Some(tab) = world.open_dashboard_tab() else {
        return;
    };

    // Rows render asynchronously once the pipeline fetch settles; wait
    // until the row and its Pause button appear.
    assert!(
        tab.wait_for_bool(
            "!!document.querySelector('#pipeline-binaries [data-binary=\"game_logic.dll\"] [data-action=\"pause\"]')"
        )
        .await,
        "the working row must render with a Pause button"
    );
    assert_eq!(
        tab.eval_text(
            "document.querySelector('#pipeline-binaries [data-binary=\"game_logic.dll\"] [data-action=\"pause\"]')?.textContent || ''"
        ),
        "Pause",
        "an unpaused working row's button reads Pause"
    );

    // Click Pause on the row.
    tab.click(r#"#pipeline-binaries [data-binary="game_logic.dll"] [data-action="pause"]"#);

    // The row redraws as Paused through the WS binary_pause_changed event,
    // with no reload, and its single button slot becomes Start Translation.
    // The paused flag wins over the working flag, so a row that is held out
    // never keeps reading Pause.
    assert!(
        tab.wait_for_bool(
            "document.querySelector('#pipeline-binaries [data-binary=\"game_logic.dll\"]')?.dataset.status === 'paused' \
                 && document.querySelector('#pipeline-binaries [data-binary=\"game_logic.dll\"] [data-action=\"start\"]')?.textContent === 'Start Translation' \
                 && !document.querySelector('#pipeline-binaries [data-binary=\"game_logic.dll\"] [data-action=\"pause\"]')"
        )
        .await,
        "the row must re-render as Paused with a Start Translation button, got: {}",
        tab.eval_text(
            "document.querySelector('#pipeline-binaries [data-binary=\"game_logic.dll\"]')?.outerHTML || ''"
        )
    );
    // The badge reads Paused rather than Working: one honest state.
    assert!(
        tab.eval_text(
            "document.querySelector('#pipeline-binaries [data-binary=\"game_logic.dll\"] [data-metric=\"success-rate\"]')?.textContent || ''"
        )
        .contains("Paused"),
        "the paused row's status badge reads Paused"
    );

    // The success toast shows the server's own reason.
    assert!(
        tab.wait_for_bool(
            "[...document.querySelectorAll('#toast-container .toast')].some(t => t.textContent.includes('held out of the queue'))"
        )
        .await,
        "the toast reports the pause the server made, got: {}",
        tab.eval_text(
            "[...document.querySelectorAll('#toast-container .toast')].map(t => t.textContent).join(' | ')"
        )
    );

    // The per-binary endpoint was called, not the run-wide one: the
    // lifecycle machine never moved, neither in the server's state nor in
    // the header's badge.
    assert_eq!(
        world.pipeline_control().state(),
        PipelineState::Running,
        "a row pause must not touch the run-level lifecycle machine"
    );
    assert_eq!(
        tab.eval_text("document.getElementById('pipeline-state')?.dataset.state || ''"),
        "running",
        "the header badge never moved"
    );
    // The click reached the endpoint: the pause was saved in the persisted
    // scope record, matched by the case-insensitive rule from issue #107.
    assert!(
        calxgloss_types::ScopeControl::open(world.repo_path()).is_paused("GAME_LOGIC.DLL"),
        "the click drove POST /api/pipeline/binaries/game_logic.dll/pause"
    );

    // Press Start Translation in the same slot. Pressing it swaps the run:
    // the still-in-flight binary is resumed and moved to the front, and the
    // row goes back to its Working state with Pause in the slot.
    tab.click(r#"#pipeline-binaries [data-binary="game_logic.dll"] [data-action="start"]"#);

    assert!(
        tab.wait_for_bool(
            "document.querySelector('#pipeline-binaries [data-binary=\"game_logic.dll\"]')?.dataset.status !== 'paused' \
                 && !!document.querySelector('#pipeline-binaries [data-binary=\"game_logic.dll\"] [data-action=\"pause\"]')"
        )
        .await,
        "the row must re-render working with a Pause button, got: {}",
        tab.eval_text(
            "document.querySelector('#pipeline-binaries [data-binary=\"game_logic.dll\"]')?.outerHTML || ''"
        )
    );
    assert!(
        !calxgloss_types::ScopeControl::open(world.repo_path()).is_paused("game_logic.dll"),
        "the start click resumed the held binary through POST /api/pipeline/binaries/game_logic.dll/start"
    );
    assert!(
        calxgloss_types::ScopeControl::open(world.repo_path()).is_focus("game_logic.dll"),
        "the start click also gave the binary the focus slot"
    );
    // The swap toast says what the server actually did.
    assert!(
        tab.wait_for_bool(
            "[...document.querySelectorAll('#toast-container .toast')].some(t => t.textContent.includes('Started game_logic.dll'))"
        )
        .await,
        "the toast reports the start the server made, got: {}",
        tab.eval_text(
            "[...document.querySelectorAll('#toast-container .toast')].map(t => t.textContent).join(' | ')"
        )
    );
    assert_eq!(
        world.pipeline_control().state(),
        PipelineState::Running,
        "a row start must not touch the run-level lifecycle machine either"
    );
}

/// Headless-browser test for the "translate this next" focus, end to end
/// (issue #284). Three plan rows are rendered. The operator puts the last
/// binary first by calling the bare endpoint — not the row's Start
/// Translation button, which adds the swap on top of this focus (issue #285,
/// tested just below). The pipeline state served afterwards puts that binary
/// at the front of the plan order. Opening the Pipeline view fetches the rows
/// again, and the order already honors the focus that is waiting: the
/// dashboard shows what the live run will do at its next binary boundary.
///
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_headless_focus_reorders_served_pipeline_rows() {
    let world = support::ReviewWorld::boot_ws_wired().await;

    // The run's plan shows three rows in plan order before anything starts.
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
            served_row_names(view) == ["a.dll", "b.dll", "c.dll"]
        })
        .await;

    let Some(tab) = world.open_dashboard_tab() else {
        return;
    };

    let rows_order = "[...document.querySelectorAll('#pipeline-binaries .pipeline-binary-row[data-binary]')].map(e => e.dataset.binary).join(',')";

    // Rows render asynchronously once the boot pipeline fetch settles; wait
    // until all three appear in plan order.
    assert!(
        tab.wait_for_text(rows_order, |order| order == "a.dll,b.dll,c.dll")
            .await,
        "the plan's three rows must render in plan order, got: {}",
        tab.eval_text(rows_order)
    );

    // The operator puts c.dll first — the endpoint's 200, not a row button.
    let (status, body) = world
        .client()
        .post_lifecycle("/api/pipeline/binaries/c.dll/focus")
        .await;
    assert_eq!(status, 200, "the focus call should succeed, got: {body}");

    // Opening the Pipeline view fetches the rows again; the state served now
    // puts that binary at the front of the plan.
    tab.click(r#".nav-tab[data-view="pipeline"]"#);

    assert!(
        tab.wait_for_text(rows_order, |order| order == "c.dll,a.dll,b.dll")
            .await,
        "the re-served rows must show the focused binary first, got: {}",
        tab.eval_text(rows_order)
    );

    // The focus was saved in the persisted scope record — the same slot the
    // live worklist reads at the next binary boundary.
    assert!(
        calxgloss_types::ScopeControl::open(world.repo_path()).is_focus("C.DLL"),
        "the focus is in the persisted scope record"
    );
}

/// Headless-browser test for pressing a row's Start Translation button,
/// which calls the per-binary start swap (issue #285). A three-binary plan is
/// rendered with a.dll in flight. One click on c.dll's button swaps the
/// run: the WS binary_pause_changed events redraw the dashboard with no
/// reload, the plan served now leads with c.dll, the previous leader shows
/// Paused, and the success toast names both halves of the swap. The run-level
/// machine never moves: the row button only chooses which binary runs next.
///
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_headless_binary_start_swaps_the_rows() {
    let world = support::ReviewWorld::boot_ws_wired().await;
    world.pipeline_control().start().expect("idle -> running");

    // The plan's three rows, with a.dll's pass in flight: a.dll reads
    // Pause, c.dll reads Start Translation.
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
            served_row_names(view) == ["a.dll", "b.dll", "c.dll"]
        })
        .await;
    let working = ProgressEvent::BatchStarted {
        binary: "a.dll".into(),
    };
    world.emitter().emit(working.clone());
    world
        .wait_until_applied(&working, |view| {
            support::row_named(view, "a.dll").is_some_and(|b| b["processing"] == true)
        })
        .await;

    let Some(tab) = world.open_dashboard_tab() else {
        return;
    };

    let rows_order = "[...document.querySelectorAll('#pipeline-binaries .pipeline-binary-row[data-binary]')].map(e => e.dataset.binary).join(',')";

    // Wait until the rows show in plan order and c.dll's row has its Start
    // Translation button.
    assert!(
        tab.wait_for_bool(&format!(
            "{rows_order} === 'a.dll,b.dll,c.dll' \
                 && !!document.querySelector('#pipeline-binaries [data-binary=\"c.dll\"] [data-action=\"start\"]')"
        ))
        .await,
        "the plan's rows must render with c.dll offering Start Translation, got: {}",
        tab.eval_text(rows_order)
    );

    // Press Start Translation on c.dll — one click, the whole swap.
    tab.click(r#"#pipeline-binaries [data-binary="c.dll"] [data-action="start"]"#);

    // The WS pause events make the dashboard show both halves of the swap
    // with no reload: the plan served now leads with the target binary, and
    // the previous leader shows Paused — held out to make way for it.
    assert!(
        tab.wait_for_bool(&format!(
            "{rows_order} === 'c.dll,a.dll,b.dll' \
                 && document.querySelector('#pipeline-binaries [data-binary=\"a.dll\"]')?.dataset.status === 'paused'"
        ))
        .await,
        "the swap must re-render the plan led by c.dll with a.dll Paused, got: {}",
        tab.eval_text(rows_order)
    );

    // The toast is honest about the side effect: it mentions both binaries.
    assert!(
        tab.wait_for_bool(
            "[...document.querySelectorAll('#toast-container .toast')].some(t => t.textContent.includes('Started c.dll') && t.textContent.includes('paused a.dll'))"
        )
        .await,
        "the toast names the swap the server made, got: {}",
        tab.eval_text(
            "[...document.querySelectorAll('#toast-container .toast')].map(t => t.textContent).join(' | ')"
        )
    );

    // The server's state behind the redraw: the swap was saved in the
    // persisted scope record, and the run machine and header badge never moved.
    let reopened = calxgloss_types::ScopeControl::open(world.repo_path());
    assert!(reopened.is_paused("A.DLL"), "the previous leader is paused");
    assert!(
        !reopened.is_paused("C.DLL"),
        "the target row's press admitted c.dll"
    );
    assert!(reopened.is_focus("C.DLL"), "c.dll holds the focus slot");
    assert_eq!(
        world.pipeline_control().state(),
        PipelineState::Running,
        "the swap never walks the run-level lifecycle machine"
    );
    assert_eq!(
        tab.eval_text("document.getElementById('pipeline-state')?.dataset.state || ''"),
        "running",
        "the header badge never moved"
    );
}

/// Headless-browser test for the shutdown dialog (issue #94, W2.4). Shut
/// Down Server opens a confirmation that lists exactly what happens, honest
/// about live mode. Confirming sends the existing
/// POST /api/server/shutdown, which stops the accept loop.
///
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_headless_shutdown_dialog_drives_endpoint() {
    // The accept loop watches the state's shutdown flag: that is the real
    // graceful-shutdown path, so the dialog visibly stops the server.
    let mut world = support::ReviewWorld::boot_graceful().await;

    let Some(tab) = world.open_dashboard_tab() else {
        return;
    };

    // Shut Down Server is available from the very first snapshot.
    assert!(
        tab.wait_for_bool("document.getElementById('ctl-shutdown')?.disabled === false")
            .await,
        "Shut Down Server must be enabled once the status snapshot lands"
    );

    tab.click("#ctl-shutdown");

    assert!(
        tab.wait_for_bool("!!document.getElementById('shutdown-dialog')")
            .await,
        "Shut Down Server must open the confirmation dialog"
    );

    // The dialog lists exactly what the shutdown does, honest about the live
    // router: the unit boundary, saving the in-flight unit, then the stop.
    let listed =
        tab.eval_text("document.querySelector('#shutdown-dialog .dialog-list')?.textContent || ''");
    assert!(
        listed.contains("unit boundary")
            && listed.contains("save its state")
            && listed.contains("Stop the server"),
        "the confirmation must list the shutdown's actions, got: {listed}"
    );

    tab.click("#shutdown-confirm");

    // The accept loop exits in order: the real shutdown path ran.
    world.wait_for_server_shutdown().await;
    let after = reqwest::get(world.client().url("/api/server/status")).await;
    assert!(
        after.is_err(),
        "the server must refuse connections after the dialog's shutdown"
    );
}

/// Headless-browser test for the translation scope controls panel
/// (issue #95, W2.6): the panel renders the current scope and constraints
/// from the status endpoint on load, and every control — category
/// checkboxes, priority add/remove, constraint inputs — posts to its scope
/// endpoint end to end, with the rendered state following the server's
/// answer rather than a local guess.
///
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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
    let world = support::ReviewWorld::boot_ws_wired_on(&fixture).await;
    // The run has already spent 12,345 tokens. That spend lives on the
    // live scope handle, not in the persisted record. The old preamble
    // handed the server the seeded handle itself; now the test records
    // the spend on the world's own scope control before the browser
    // opens (issue #475).
    world.scope_control().record_tokens(12_345);

    // One binary per category the checkboxes control, so each checkbox
    // has a real category to read.
    let mut last_classified: Option<ProgressEvent> = None;
    for (binary, category) in [
        ("engine.dll", "ProjectSpecific"),
        ("zlib.dll", "KnownThirdParty"),
        ("mystery.dll", "UnknownThirdParty"),
        ("msvcrt.dll", "RuntimeLibrary"),
        ("d3d9.dll", "WindowsOs"),
    ] {
        let classified = ProgressEvent::ClassificationComplete {
            binary: binary.into(),
            category: category.into(),
            classification_strategy: "ReverseEngineer".into(),
            crate_replacement: None,
            exported_symbols: 1,
            imported_symbols: 0,
        };
        world.emitter().emit(classified.clone());
        last_classified = Some(classified);
    }
    world
        .wait_until_applied(
            last_classified
                .as_ref()
                .expect("five classification events were emitted"),
            |view| {
                [
                    "engine.dll",
                    "zlib.dll",
                    "mystery.dll",
                    "msvcrt.dll",
                    "d3d9.dll",
                ]
                .iter()
                .all(|name| support::row_named(view, name).is_some())
            },
        )
        .await;

    let Some(tab) = world.open_dashboard_tab() else {
        return;
    };

    let checked = |id: &str| {
        tab.eval_bool(&format!(
            "document.getElementById('{id}')?.checked === true"
        ))
    };
    let chip_count = |fn_name: &str| {
        tab.eval_count(&format!(
            "document.querySelectorAll('#scope-priority-list .scope-priority-chip[data-function=\"{fn_name}\"]').length"
        ))
    };
    let get_scope = || async {
        let (status, body) = world.client().get_json("/api/scope").await;
        assert_eq!(status, 200, "scope status reachable");
        body
    };
    let scope_binaries = |body: &serde_json::Value| -> Vec<String> {
        let mut list: Vec<String> = body["scope"]["binaries"]
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
    assert!(
        tab.wait_for_bool(
            "document.querySelectorAll('#scope-priority-list .scope-priority-chip[data-function=\"DrawPrimitive\"]').length === 1"
        )
        .await,
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
    // shows the budget minus the run's spend.
    assert_eq!(
        tab.eval_text("document.getElementById('scope-max-attempts')?.value || ''"),
        "2"
    );
    assert_eq!(
        tab.eval_text("document.getElementById('scope-max-tier')?.value || ''"),
        "Disassembly"
    );
    // The tier select's values come from the status response's
    // context_tiers, not from markup — every cap the server accepts is
    // an option, and only those (issue #109).
    assert_eq!(
        tab.eval_text(
            "[...document.querySelectorAll('#scope-max-tier option')].map(o => o.value).join(',')"
        ),
        ",Signature,Disassembly,WithTests,ModuleContext,FullModule",
        "the tier select must offer exactly the tiers the status response names"
    );
    assert_eq!(
        tab.eval_text("document.getElementById('scope-token-budget')?.value || ''"),
        "50000"
    );
    assert!(
        tab.eval_text("document.getElementById('scope-token-remaining')?.textContent || ''")
            .contains("37655"),
        "the remaining-budget display follows the server's spend"
    );

    // Toggling "skip runtime functions" sends POST /api/scope/binaries —
    // the exclusion lands server-side, and the panel keeps the box checked
    // because it re-rendered from the server's answer.
    tab.click("#scope-skip-runtime");
    let body = wait_for_scope_state(world.client(), |body| {
        scope_binaries(body)
            == vec![
                "d3d9.dll".to_string(),
                "engine.dll".to_string(),
                "mystery.dll".to_string(),
                "zlib.dll".to_string(),
            ]
    })
    .await;
    assert!(
        scope_binaries(&body)
            == vec![
                "d3d9.dll".to_string(),
                "engine.dll".to_string(),
                "mystery.dll".to_string(),
                "zlib.dll".to_string(),
            ],
        "the checkbox must drive POST /api/scope/binaries with the runtime binary excluded"
    );
    assert!(
        tab.wait_for_bool("document.getElementById('scope-skip-runtime')?.checked === true")
            .await,
        "the checkbox follows the server's answer, not a reverted local guess"
    );

    // Unchecking a translate-mode checkbox excludes that category: zlib's
    // box off drops it from the allow-list, while WindowsOs — which no
    // checkbox excludes — keeps its place in the server's current list.
    tab.click("#scope-translate-known-third-party");
    let body = wait_for_scope_state(world.client(), |body| {
        scope_binaries(body)
            == vec![
                "d3d9.dll".to_string(),
                "engine.dll".to_string(),
                "mystery.dll".to_string(),
            ]
    })
    .await;
    assert!(
        scope_binaries(&body)
            == vec![
                "d3d9.dll".to_string(),
                "engine.dll".to_string(),
                "mystery.dll".to_string(),
            ],
        "unchecking a translate checkbox must drop that category from the allow-list"
    );
    assert!(
        tab.wait_for_bool(
            "document.getElementById('scope-translate-known-third-party')?.checked === false"
        )
        .await,
        "the unchecked box follows the server's answer"
    );

    // Round-trip back: re-checking known third-party and un-checking the
    // runtime skip covers every known binary again — sent as the empty
    // unsteered list, and the checkboxes render from that echo.
    tab.run(
        "document.getElementById('scope-translate-known-third-party').click(); \
             document.getElementById('scope-skip-runtime').click()",
        "restore both checkboxes",
    );
    let body = wait_for_scope_state(world.client(), |body| scope_binaries(body).is_empty()).await;
    assert!(
        scope_binaries(&body).is_empty(),
        "covering every known binary again must return the scope to the unsteered empty list"
    );
    assert!(
        tab.wait_for_bool(
            "document.getElementById('scope-skip-runtime')?.checked === false \
                 && document.getElementById('scope-translate-known-third-party')?.checked === true"
        )
        .await,
        "after the round-trip the checkboxes render the unsteered state honestly"
    );

    // Adding a priority function through the form sends the priority
    // endpoint; the chip appears and the server agrees.
    tab.run(
        "document.getElementById('scope-priority-binary').value = 'zlib.dll'; \
             document.getElementById('scope-priority-function').value = 'InitZlib'; \
             document.getElementById('scope-priority-add-btn').click()",
        "add a priority function",
    );
    assert!(
        tab.wait_for_bool(
            "document.querySelectorAll('#scope-priority-list .scope-priority-chip[data-function=\"InitZlib\"]').length === 1"
        )
        .await,
        "the added priority chip must render"
    );
    assert_eq!(
        priority_count().await,
        Some(2),
        "the added priority reached the server"
    );

    // Removing it sends the removal request; the chip disappears and the
    // server's list shrinks.
    tab.click(
        r#"#scope-priority-list .scope-priority-chip[data-function="InitZlib"] .scope-priority-remove"#,
    );
    assert!(
        tab.wait_for_bool(
            "document.querySelectorAll('#scope-priority-list .scope-priority-chip[data-function=\"InitZlib\"]').length === 0"
        )
        .await,
        "the removed priority chip must disappear"
    );
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
    tab.run(
        "document.getElementById('scope-max-attempts').value = '3'; \
             document.getElementById('scope-max-tier').value = ''; \
             document.getElementById('scope-token-budget').value = '90000'; \
             document.getElementById('scope-constraints-apply').click()",
        "apply constraints",
    );
    let body = wait_for_scope_state(world.client(), |body| {
        body["constraints"]["max_attempts"] == serde_json::json!(3)
            && body["constraints"]["max_context_tier"].is_null()
            && body["constraints"]["token_budget"] == serde_json::json!(90000)
    })
    .await;
    assert!(
        body["constraints"]["max_attempts"] == serde_json::json!(3)
            && body["constraints"]["max_context_tier"].is_null()
            && body["constraints"]["token_budget"] == serde_json::json!(90000),
        "the constraint inputs must drive POST /api/scope/constraints wholesale"
    );
    assert!(
        tab.eval_text("document.getElementById('scope-token-remaining')?.textContent || ''")
            .contains("77655"),
        "the remaining-budget display follows the new budget"
    );
}

/// The scope panel on a plain `serve` router (no scope control attached)
/// says so honestly and disables itself — the controls header's honesty
/// rule, same shape (issue #95, W2.6).
///
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_headless_scope_controls_honest_without_control() {
    let world = support::ReviewWorld::boot_plain().await;

    let Some(tab) = world.open_dashboard_tab() else {
        return;
    };

    assert!(
        tab.wait_for_bool(
            "!!document.getElementById('scope-unavailable') && \
                 document.getElementById('scope-unavailable').style.display !== 'none' && \
                 document.getElementById('scope-body').style.display === 'none'"
        )
        .await,
        "without a scope control the panel must show its honest unavailable state"
    );
    assert!(
        tab.eval_text("document.getElementById('scope-unavailable-message')?.textContent || ''")
            .contains("calxgloss live"),
        "the message names what the panel needs"
    );
}

/// Headless-browser test for the unit process detail panel (issue #62):
/// clicking a unit backed by filed token-usage and fault-log artifacts
/// must render the four process sections — tier, faults, tokens, strategies.
///
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_headless_unit_process_sections() {
    let fixture = TestFixture::new();
    write_canned_run_telemetry(&fixture);
    let world = support::ReviewWorld::boot_plain_on(&fixture).await;

    let Some(tab) = world.open_dashboard_tab() else {
        return;
    };

    // Switch to the queue view so the full queue list renders.
    tab.click(r#".nav-tab[data-view="queue"]"#);

    // Wait for the telemetry-backed unit to appear in the queue list.
    assert!(
        tab.wait_for_bool(
            "!!document.querySelector('#full-queue-list [data-unit-id=\"game_logic.dll/DrawPrimitive/v2\"]')"
        )
        .await,
        "queue list should contain the DrawPrimitive v2 unit"
    );

    // Click the unit to render its inline detail panel.
    tab.click(r#"#full-queue-list [data-unit-id="game_logic.dll/DrawPrimitive/v2"]"#);

    // The four process sections render asynchronously once the unit fetch
    // settles; wait until all are present.
    let all_sections = "!!document.getElementById('process-tier-section') && \
         !!document.getElementById('process-faults-section') && \
         !!document.getElementById('process-tokens-section') && \
         !!document.getElementById('process-strategies-section')";
    assert!(
        tab.wait_for_bool(all_sections).await,
        "detail panel should render the four process sections"
    );

    // The tier section shows the escalated tier from the filed telemetry.
    let tier_text =
        tab.eval_text("document.getElementById('process-tier-section')?.textContent || ''");
    assert!(
        tier_text.contains("with_tests"),
        "tier section should show the final tier label, got: {tier_text}"
    );
    assert!(
        tier_text.contains("escalated"),
        "tier section should flag escalation, got: {tier_text}"
    );

    // The fault section lists the filed fault categories.
    let fault_text =
        tab.eval_text("document.getElementById('process-faults-section')?.textContent || ''");
    assert!(
        fault_text.contains("context_window_exceeded") && fault_text.contains("hallucination"),
        "fault section should list both filed faults, got: {fault_text}"
    );

    // The strategy section shows the retry strategies used.
    let strategy_text =
        tab.eval_text("document.getElementById('process-strategies-section')?.textContent || ''");
    assert!(
        strategy_text.contains("initial") && strategy_text.contains("compile_fix"),
        "strategy section should list both strategies, got: {strategy_text}"
    );
}

/// Headless-browser test for the unit detail panel's attempt list
/// (issue #131, W4.5): clicking the two-attempt DrawPrimitive unit renders
/// one entry per persisted attempt with the joined metadata — strategies,
/// tiers, token counts, and commit identities from the seeded logs and
/// patch records — and no "nothing to compare" note.
///
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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
    let world = support::ReviewWorld::boot_plain_on(&fixture).await;

    let Some(tab) = world.open_dashboard_tab() else {
        return;
    };

    tab.click(r#".nav-tab[data-view="queue"]"#);
    tab.click(r#"#full-queue-list [data-unit-id="game_logic.dll/DrawPrimitive/v2"]"#);

    // The attempts section fills asynchronously; wait until both attempt
    // entries are rendered.
    let two_attempts =
        "document.querySelectorAll('#unit-attempts-section .unit-attempt-item').length === 2";
    assert!(
        tab.wait_for_bool(two_attempts).await,
        "attempts section should render both attempts"
    );

    let section =
        tab.eval_text("document.getElementById('unit-attempts-section')?.textContent || ''");
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
}

/// Headless-browser honest state for issue #131: a single-attempt unit
/// shows exactly one attempt entry and the "nothing to compare" note —
/// the panel never pretends a diff is possible.
///
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_headless_unit_attempts_single_attempt_note() {
    let fixture = TestFixture::new();
    // A queued unit with one branch and no patch records or logs.
    add_pending_translation(&fixture, "RenderHUD");
    let world = support::ReviewWorld::boot_plain_on(&fixture).await;

    let Some(tab) = world.open_dashboard_tab() else {
        return;
    };

    tab.click(r#".nav-tab[data-view="queue"]"#);
    tab.click(r#"#full-queue-list [data-unit-id="game_logic.dll/RenderHUD/v1"]"#);

    let one_attempt =
        "document.querySelectorAll('#unit-attempts-section .unit-attempt-item').length === 1";
    assert!(
        tab.wait_for_bool(one_attempt).await,
        "attempts section should render the single attempt"
    );

    let section =
        tab.eval_text("document.getElementById('unit-attempts-section')?.textContent || ''");
    assert!(
        section.contains("nothing to compare"),
        "a single-attempt unit honestly says there is nothing to compare, got: {section}"
    );
    assert!(
        section.contains("Attempt 1"),
        "the one attempt is still listed, got: {section}"
    );
}

/// Headless-browser test for the unit detail panel's attempt comparison
/// (issue #135, W4.6): a three-attempt unit renders pickers defaulting to
/// the last two attempts and a side-by-side diff of their branches with
/// additions and deletions styled per the dark theme — and picking a
/// different pair changes the rendered diff.
///
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_headless_unit_attempt_diff_side_by_side() {
    let fixture = TestFixture::new();
    add_attempt_branch_with_commit(&fixture, 3, "draw_primitive_v3");
    let world = support::ReviewWorld::boot_plain_on(&fixture).await;

    let Some(tab) = world.open_dashboard_tab() else {
        return;
    };

    tab.click(r#".nav-tab[data-view="queue"]"#);
    tab.click(r#"#full-queue-list [data-unit-id="game_logic.dll/DrawPrimitive/v2"]"#);

    // The attempts section fills asynchronously; the world's bounded DOM
    // wait replaces this pin's hand-written deadline poll (issue #475).
    let three_attempts =
        "document.querySelectorAll('#unit-attempts-section .unit-attempt-item').length === 3";
    assert!(
        tab.wait_for_bool(three_attempts).await,
        "attempts section should render all three attempts"
    );

    // The pickers default to the last two attempts.
    let default_from = tab.eval_text("document.getElementById('attempt-diff-from')?.value || ''");
    let default_to = tab.eval_text("document.getElementById('attempt-diff-to')?.value || ''");
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
    assert!(
        tab.wait_for_bool(styled).await,
        "the attempt diff renders styled additions and deletions"
    );

    let diff_text =
        tab.eval_text("document.getElementById('attempt-diff-body')?.textContent || ''");
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
    tab.run(
        "(() => { const f = document.getElementById('attempt-diff-from'); f.value = '1'; f.dispatchEvent(new Event('change')); const t = document.getElementById('attempt-diff-to'); t.value = '2'; t.dispatchEvent(new Event('change')); return true; })()",
        "switch the pickers to the pair 1 → 2",
    );

    let switched = "(document.getElementById('attempt-diff-body')?.textContent || '').includes('draw_primitive_v2.rs') \
         && !(document.getElementById('attempt-diff-body')?.textContent || '').includes('draw_primitive_v3')";
    assert!(
        tab.wait_for_bool(switched).await,
        "picking a different attempt pair re-renders the diff, got: {}",
        tab.eval_text("document.getElementById('attempt-diff-body')?.textContent || ''")
    );
}

/// Headless-browser test for the Overrides tab in the unit detail panel
/// (issue #96, W2.7): the tab renders the override seeded on the shared
/// handle — summary rows, pre-filled form controls, and reviewer notes
/// injected into the overview — and toggling skip and clicking Apply
/// runs the endpoint end to end, with the rendered state following the
/// record the server echoes back.
///
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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
    let world = support::ReviewWorld::boot_ws_wired_on(&fixture).await;

    let Some(tab) = world.open_dashboard_tab() else {
        return;
    };

    // Switch to the queue view and open the telemetry-backed unit's detail.
    tab.click(r#".nav-tab[data-view="queue"]"#);
    assert!(
        tab.wait_for_bool(
            "!!document.querySelector('#full-queue-list [data-unit-id=\"game_logic.dll/DrawPrimitive/v2\"]')"
        )
        .await,
        "queue list should contain the DrawPrimitive v2 unit"
    );
    tab.click(r#"#full-queue-list [data-unit-id="game_logic.dll/DrawPrimitive/v2"]"#);

    // Click the Overrides tab in the detail's tab bar.
    tab.click(r#"[data-diff-tab="overrides"]"#);

    // The tab renders the seeded record: the summary spells out the forced
    // tier and strategy, and the form controls come back pre-filled.
    assert!(
        tab.wait_for_bool(
            "document.getElementById('overrides-body')?.textContent?.includes('forced to FullModule') === true"
        )
        .await,
        "overrides tab should render the seeded summary, got: {}",
        tab.eval_text("document.getElementById('override-summary')?.textContent || ''")
    );
    let summary = tab.eval_text("document.getElementById('override-summary')?.textContent || ''");
    assert!(
        summary.contains("forced to escalate") && summary.contains("1 appended to the prompt"),
        "summary should name the forced strategy and hint count, got: {summary}"
    );
    assert_eq!(
        tab.eval_text("document.getElementById('override-tier')?.value || ''"),
        "FullModule",
        "the tier select should come back pre-filled"
    );
    assert_eq!(
        tab.eval_text("document.getElementById('override-strategy')?.value || ''"),
        "escalate",
        "the strategy select should come back pre-filled"
    );
    assert!(
        tab.eval_text("document.getElementById('override-hints')?.value || ''")
            .contains("blitter routine"),
        "the hints textarea should come back pre-filled"
    );

    // Reviewer notes display in the overview too, not only inside the tab.
    let notes_text =
        tab.eval_text("document.getElementById('reviewer-notes-section')?.textContent || ''");
    assert!(
        notes_text.contains("looks like a blitter"),
        "the overview should show the reviewer notes, got: {notes_text}"
    );

    // Toggling skip and clicking Apply sends the save request; the summary
    // follows the record the server echoes back.
    tab.click("#override-skip");
    tab.click("#override-apply");
    assert!(
        tab.wait_for_bool(
            "document.getElementById('override-summary')?.textContent?.includes('skipped') === true"
        )
        .await,
        "the summary should show the skip after Apply, got: {}",
        tab.eval_text("document.getElementById('override-summary')?.textContent || ''")
    );
    let (_, body) = world
        .client()
        .get_json("/api/units/game_logic.dll%2FDrawPrimitive%2Fv2/override")
        .await;
    assert_eq!(
        body["override"]["skip"], true,
        "the skip flag landed on the server, got: {body}"
    );
}

/// Headless-browser test for the binary classification override panel
/// (issue #97, W2.8): clicking Classify on a pipeline row renders the
/// recorded classification with its reasoning, and choosing a category and
/// crate and clicking Apply runs the endpoint end to end — the panel
/// adopts the override the server echoes back, and the record persists in
/// the workspace for the next run.
///
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_headless_classification_override_panel() {
    let fixture = TestFixture::new();
    write_canned_classification_record(
        &fixture.repo_path(),
        "fmod.dll",
        DllCategory::UnknownThirdParty,
    );
    let world = support::ReviewWorld::boot_ws_wired_on(&fixture).await;

    // One classified binary so the row exists to click.
    let classified = ProgressEvent::ClassificationComplete {
        binary: "fmod.dll".into(),
        category: "UnknownThirdParty".into(),
        classification_strategy: "ReverseEngineer".into(),
        crate_replacement: None,
        exported_symbols: 10,
        imported_symbols: 4,
    };
    world.emitter().emit(classified.clone());
    world
        .wait_until_applied(&classified, |view| {
            support::row_named(view, "fmod.dll").is_some()
        })
        .await;

    let Some(tab) = world.open_dashboard_tab() else {
        return;
    };

    // Wait for the row, then click its Classify button.
    assert!(
        tab.wait_for_bool(
            "!!document.querySelector('#pipeline-binaries [data-binary=\"fmod.dll\"]')"
        )
        .await,
        "pipeline row for fmod.dll should exist"
    );
    tab.click(r#"#pipeline-binaries [data-binary="fmod.dll"] [data-action="classify"]"#);

    // The panel renders the recorded classification with its reasoning.
    assert!(
        tab.wait_for_bool(
            "document.getElementById('classification-override-panel')?.textContent?.includes('no known library') === true"
        )
        .await,
        "panel should render the recorded classification with reasoning, got: {}",
        tab.eval_text("document.getElementById('classification-override-panel')?.textContent || ''")
    );
    let panel_text = tab
        .eval_text("document.getElementById('classification-override-panel')?.textContent || ''");
    assert!(
        panel_text.contains("UnknownThirdParty"),
        "the current category should show, got: {panel_text}"
    );
    assert!(
        panel_text.contains("No override in force"),
        "the absence of an override should be stated, got: {panel_text}"
    );

    // Steer it: a known third-party crate replacement, then Apply.
    tab.run(
        "document.getElementById('clf-category').value = 'KnownThirdParty'",
        "select category",
    );
    tab.run(
        "document.getElementById('clf-crate').value = 'fmod-rs'",
        "fill crate",
    );
    tab.click("#clf-apply");

    // The panel adopts the override the server echoes back.
    assert!(
        tab.wait_for_bool(
            "document.getElementById('classification-override-panel')?.textContent?.includes('Override in force: KnownThirdParty') === true"
        )
        .await,
        "the panel should show the override after Apply, got: {}",
        tab.eval_text("document.getElementById('classification-override-panel')?.textContent || ''")
    );

    // The record landed in the workspace — a restarted run will use it.
    let reopened = calxgloss_types::ClassificationOverrideControl::open(world.repo_path());
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
        "the crate replacement comes through"
    );
}

/// Headless-browser counterpart of the 503 contract: on a live router with
/// no classification-override control attached, the panel renders the
/// server's honest refusal instead of controls (issue #97).
///
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_headless_classification_override_honest_without_control() {
    let world = support::ReviewWorld::boot().await;

    let classified = ProgressEvent::ClassificationComplete {
        binary: "fmod.dll".into(),
        category: "UnknownThirdParty".into(),
        classification_strategy: "ReverseEngineer".into(),
        crate_replacement: None,
        exported_symbols: 10,
        imported_symbols: 4,
    };
    world.emitter().emit(classified.clone());
    world
        .wait_until_applied(&classified, |view| {
            support::row_named(view, "fmod.dll").is_some()
        })
        .await;

    let Some(tab) = world.open_dashboard_tab() else {
        return;
    };

    assert!(
        tab.wait_for_bool(
            "!!document.querySelector('#pipeline-binaries [data-binary=\"fmod.dll\"]')"
        )
        .await,
        "pipeline row for fmod.dll should exist"
    );
    tab.click(r#"#pipeline-binaries [data-binary="fmod.dll"] [data-action="classify"]"#);

    // The server's own reason renders — no controls, no fabricated state.
    assert!(
        tab.wait_for_bool(
            "document.getElementById('classification-override-panel')?.textContent?.includes('no classification override control') === true"
        )
        .await,
        "the panel should render the server's honest 503 reason"
    );
    assert!(
        !tab.eval_bool("!!document.getElementById('clf-apply')"),
        "no form controls when the endpoints are unavailable"
    );
}

/// Headless-browser test for the unit analysis detail sections (issue #73):
/// clicking a unit backed by a filed function analysis artifact and a
/// filed per-binary call-graph record must render the Windows API mappings
/// and call graph context sections with the artifact's names.
///
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_headless_unit_analysis_sections() {
    let fixture = TestFixture::new();
    write_canned_analysis_context(&fixture);
    let world = support::ReviewWorld::boot_plain_on(&fixture).await;

    let Some(tab) = world.open_dashboard_tab() else {
        return;
    };

    // Switch to the queue view so the full queue list renders.
    tab.click(r#".nav-tab[data-view="queue"]"#);

    // Wait for the artifact-backed unit to appear in the queue list.
    assert!(
        tab.wait_for_bool(
            "!!document.querySelector('#full-queue-list [data-unit-id=\"game_logic.dll/DrawPrimitive/v2\"]')"
        )
        .await,
        "queue list should contain the DrawPrimitive v2 unit"
    );

    // Click the unit to render its inline detail panel.
    tab.click(r#"#full-queue-list [data-unit-id="game_logic.dll/DrawPrimitive/v2"]"#);

    // The two analysis sections render asynchronously once the unit fetch
    // settles; wait until both are present.
    let all_sections = "!!document.getElementById('api-mappings-section') && \
         !!document.getElementById('call-graph-section')";
    assert!(
        tab.wait_for_bool(all_sections).await,
        "detail panel should render the API mappings and call graph sections"
    );

    // The API mappings section lists the filed APIs with category and PAL mapping.
    let api_text =
        tab.eval_text("document.getElementById('api-mappings-section')?.textContent || ''");
    assert!(
        api_text.contains("Present")
            && api_text.contains("DirectX")
            && api_text.contains("wgpu::Surface::present"),
        "API mappings section should show name, category, and PAL mapping, got: {api_text}"
    );

    // The call graph section lists resolved caller and callee names.
    let cg_text = tab.eval_text("document.getElementById('call-graph-section')?.textContent || ''");
    assert!(
        cg_text.contains("GameLoop") && cg_text.contains("BlitSurface"),
        "call graph section should list caller and callee names, got: {cg_text}"
    );
}

// ─────────────────────────────────────────────────────────────
// Applied-wait helpers for this submodule (issue #475)
// ─────────────────────────────────────────────────────────────

/// The served `/api/pipeline` rows' binary names, in served display order —
/// the applied state for a queue plan's row order.
fn served_row_names(view: &serde_json::Value) -> Vec<String> {
    view["binaries"]
        .as_array()
        .expect("binaries is an array")
        .iter()
        .map(|b| b["binary"].as_str().unwrap_or_default().to_string())
        .collect()
}

/// Poll `GET /api/scope` until `settled` accepts its body — the applied
/// wait for the scope endpoint calls behind the scope panel's controls.
/// It returns the body that satisfied the predicate, or the last one seen
/// when the deadline passes, so the caller's own assertion names the
/// posted change that never landed.
async fn wait_for_scope_state(
    client: &support::Client,
    settled: impl Fn(&serde_json::Value) -> bool,
) -> serde_json::Value {
    let deadline = tokio::time::Instant::now() + support::APPLIED_WAIT_DEADLINE;
    loop {
        let (status, body) = client.get_json("/api/scope").await;
        assert_eq!(status, 200, "the scope endpoint answers during a wait");
        if settled(&body) || tokio::time::Instant::now() >= deadline {
            return body;
        }
        tokio::time::sleep(support::APPLIED_WAIT_POLL).await;
    }
}
