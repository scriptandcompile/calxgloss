//! Scenario tests split from `tests/e2e.rs`.

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
    let fixture = TestFixture::new();
    let events = TranslationEvents::new(128);
    let scope =
        calxgloss_types::ScopeControl::open(fixture.repo_path()).with_events(events.clone());
    // A running run: if the row's button called the run-wide endpoints, the
    // machine would move — it has to stay running the whole time.
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

    // One planned binary whose batch pass is in flight: the honest Pause
    // state of the toggle.
    events.emit(ProgressEvent::QueuePlanned {
        binaries: vec!["game_logic.dll".to_string()],
    });
    events.emit(ProgressEvent::BatchStarted {
        binary: "game_logic.dll".into(),
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    let Some(browser) = launch_headless_browser() else {
        return;
    };
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

    // The row redraws as Paused through the WS binary_pause_changed event,
    // with no reload, and its single button slot becomes Start Translation.
    // The paused flag wins over the working flag, so a row that is held out
    // never keeps reading Pause.
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
    // The badge reads Paused rather than Working: one honest state.
    assert!(
        eval_text(
            &tab,
            "document.querySelector('#pipeline-binaries [data-binary=\"game_logic.dll\"] [data-metric=\"success-rate\"]')?.textContent || ''"
        )
        .contains("Paused"),
        "the paused row's status badge reads Paused"
    );

    // The success toast shows the server's own reason.
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

    // The per-binary endpoint was called, not the run-wide one: the
    // lifecycle machine never moved, neither in the server's state nor in
    // the header's badge.
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
    // The click reached the endpoint: the pause was saved in the persisted
    // scope record, matched by the case-insensitive rule from issue #107.
    assert!(
        calxgloss_types::ScopeControl::open(fixture.repo_path()).is_paused("GAME_LOGIC.DLL"),
        "the click drove POST /api/pipeline/binaries/game_logic.dll/pause"
    );

    // Press Start Translation in the same slot. Pressing it swaps the run:
    // the still-in-flight binary is resumed and moved to the front, and the
    // row goes back to its Working state with Pause in the slot.
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
        "the start click also gave the binary the focus slot"
    );
    // The swap toast says what the server actually did.
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

    // The run's plan shows three rows in plan order before anything starts.
    events.emit(ProgressEvent::QueuePlanned {
        binaries: vec![
            "a.dll".to_string(),
            "b.dll".to_string(),
            "c.dll".to_string(),
        ],
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    let Some(browser) = launch_headless_browser() else {
        return;
    };
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

    // The operator puts c.dll first — the endpoint's 200, not a row button.
    let (status, body) = post_lifecycle(fixture.port(), "/api/pipeline/binaries/c.dll/focus").await;
    assert_eq!(status, 200, "the focus call should succeed, got: {body}");

    // Opening the Pipeline view fetches the rows again; the state served now
    // puts that binary at the front of the plan.
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

    // The focus was saved in the persisted scope record — the same slot the
    // live worklist reads at the next binary boundary.
    assert!(
        calxgloss_types::ScopeControl::open(fixture.repo_path()).is_focus("C.DLL"),
        "the focus is in the persisted scope record"
    );

    tab.close_target().ok();
    drop(browser);
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

    let Some(browser) = launch_headless_browser() else {
        return;
    };
    let tab = open_dashboard_tab(&browser, fixture.port());

    let row_order = || {
        eval_text(
            &tab,
            "[...document.querySelectorAll('#pipeline-binaries .pipeline-binary-row[data-binary]')].map(e => e.dataset.binary).join(',')",
        )
    };

    // Poll until the rows show in plan order and c.dll's row has its Start
    // Translation button (up to ~5 seconds).
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

    // The WS pause events make the dashboard show both halves of the swap
    // with no reload: the plan served now leads with the target binary, and
    // the previous leader shows Paused — held out to make way for it.
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

    // The toast is honest about the side effect: it mentions both binaries.
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

    // The server's state behind the redraw: the swap was saved in the
    // persisted scope record, and the run machine and header badge never moved.
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

/// Headless-browser test for the shutdown dialog (issue #94, W2.4). Shut
/// Down Server opens a confirmation that lists exactly what happens, honest
/// about live mode. Confirming sends the existing
/// POST /api/server/shutdown, which stops the accept loop.
///
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_headless_shutdown_dialog_drives_endpoint() {
    let fixture = TestFixture::new();
    let events = TranslationEvents::new(128);
    let control = PipelineControl::new().with_events(events.clone());
    let state = ServerState::new(fixture.repo_path()).with_pipeline_control(control.clone());
    let manager = SessionManager::new_with_broadcast(events.subscribe());
    let progress = ProgressState::new();
    let router = build_router_with_ws(state.clone(), manager, progress, ws_actions(&fixture));
    // The accept loop watches the state's shutdown flag: that is the real
    // graceful-shutdown path, so the dialog visibly stops the server.
    let server = spawn_server_with_shutdown(&state, router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let Some(browser) = launch_headless_browser() else {
        return;
    };
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

    // The dialog lists exactly what the shutdown does, honest about the live
    // router: the unit boundary, saving the in-flight unit, then the stop.
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

    // The accept loop exits in order: the real shutdown path ran.
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
    scope.record_tokens(12_345);
    let state = ServerState::new(fixture.repo_path()).with_scope_control(scope);
    let events = TranslationEvents::new(128);
    let manager = SessionManager::new_with_broadcast(events.subscribe());
    let progress = ProgressState::new();
    let router = build_router_with_ws(state, manager, progress, ws_actions(&fixture));
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    // One binary per category the checkboxes control, so each checkbox
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

    let Some(browser) = launch_headless_browser() else {
        return;
    };
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
    // shows the budget minus the run's spend.
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

    // Toggling "skip runtime functions" sends POST /api/scope/binaries —
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
    // box off drops it from the allow-list, while WindowsOs — which no
    // checkbox excludes — keeps its place in the server's current list.
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

    // Adding a priority function through the form sends the priority
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

    // Removing it sends the removal request; the chip disappears and the
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
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_headless_scope_controls_honest_without_control() {
    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let Some(browser) = launch_headless_browser() else {
        return;
    };
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
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_headless_unit_process_sections() {
    let fixture = TestFixture::new();
    write_canned_run_telemetry(&fixture);
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(500)).await;

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
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(500)).await;

    let Some(browser) = launch_headless_browser() else {
        return;
    };
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
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_headless_unit_attempts_single_attempt_note() {
    let fixture = TestFixture::new();
    // A queued unit with one branch and no patch records or logs.
    add_pending_translation(&fixture, "RenderHUD");
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(500)).await;

    let Some(browser) = launch_headless_browser() else {
        return;
    };
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
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(500)).await;

    let Some(browser) = launch_headless_browser() else {
        return;
    };
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
    let state = ServerState::new(fixture.repo_path()).with_override_control(overrides);
    let events = TranslationEvents::new(128);
    let manager = SessionManager::new_with_broadcast(events.subscribe());
    let progress = ProgressState::new();
    let router = build_router_with_ws(state, manager, progress, ws_actions(&fixture));
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(500)).await;

    let Some(browser) = launch_headless_browser() else {
        return;
    };
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

    // Toggling skip and clicking Apply sends the save request; the summary
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
/// crate and clicking Apply runs the endpoint end to end — the panel
/// adopts the override the server echoes back, and the record persists in
/// the workspace for the next run.
///
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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

    let Some(browser) = launch_headless_browser() else {
        return;
    };
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

    // The record landed in the workspace — a restarted run will use it.
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
        "the crate replacement comes through"
    );

    tab.close_target().ok();
    drop(browser);
}

/// Headless-browser counterpart of the 503 contract: on a live router with
/// no classification-override control attached, the panel renders the
/// server's honest refusal instead of controls (issue #97).
///
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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

    let Some(browser) = launch_headless_browser() else {
        return;
    };
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
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_headless_unit_analysis_sections() {
    let fixture = TestFixture::new();
    write_canned_analysis_context(&fixture);
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(500)).await;

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
