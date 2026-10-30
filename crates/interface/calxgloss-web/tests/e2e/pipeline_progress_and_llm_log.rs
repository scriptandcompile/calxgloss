//! Scenario tests split from `tests/e2e.rs`.

use super::*;

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

    // A tagged-object strategy reads back as its variant name — not an
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

/// The pre-batch scan phase sends one heartbeat for its whole group, under
/// the phase name (issue #239), and the call-graph pass sends one heartbeat
/// per function as it processes its work list. `/api/pipeline` reports the
/// latest heartbeat as `activity` on the row of the binary being worked on
/// — and a heartbeat with no per-item detail reports only its name.
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

    // A heartbeat before its first listing has no per-item
    // detail: only the name is honest.
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

/// Issue #242: classification changes move rows automatically. The order
/// is recomputed per poll from the merged live-over-disk classifications:
/// re-classifying into PAL mapping moves the row to the bottom and out of
/// PAL mapping back up again — on the very next request, with no restart.
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

/// Issue #243: a PalMapping row includes the PAL-readiness summary — the
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

/// Issue #64: when the token-usage log records measured attempt durations
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

/// Issue #64: `/api/dashboard` includes a `queue_effort` map giving each
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

/// Feed canned `ProgressEvent`s through the live event path (broadcast channel →
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

    // The fault list: every entry verbatim, oldest first, with the three
    // attempt-identity fields and the attached recovery guidance.
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
