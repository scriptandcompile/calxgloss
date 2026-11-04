use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use serde_json::json;

use super::*;
use crate::wine::proxy::REFERENCE_APP_CAPTURE_PREFIX;

/// A run dir laid from a real target: the target copy sits beside
/// nothing — the proxy has not been placed yet, and the operator's
/// target file is untouched.
#[test]
fn scaffolding_places_the_real_target_under_its_real_module_name() {
    let root = tempfile::tempdir().expect("tempdir");
    let target = root.path().join("game_logic.dll");
    std::fs::write(&target, b"real bytes").expect("fixture target");
    let run = root.path().join("run");

    scaffold_run_dir(&run, "game_logic.dll", &target).expect("scaffold runs");

    assert_eq!(
        std::fs::read(run.join(px_real_name("game_logic.dll"))).expect("real copy"),
        b"real bytes",
        "the run dir holds the real module under the name the proxy resolves through"
    );
    assert!(!run.join("game_logic.dll").exists());
    assert_eq!(
        std::fs::read(&target).expect("the operator's target"),
        b"real bytes",
        "the operator's file is never touched by scaffolding"
    );
}

/// A finished capture leaves no proxy in front of the real target:
/// the module stands back under its own binary identity.
#[test]
fn finalizing_a_finished_run_restores_the_identity_and_drops_the_proxy() {
    let root = tempfile::tempdir().expect("tempdir");
    let target = root.path().join("game_logic.dll");
    std::fs::write(&target, b"real bytes").expect("fixture target");
    let run = root.path().join("run");
    scaffold_run_dir(&run, "game_logic.dll", &target).expect("scaffold runs");
    std::fs::write(run.join("game_logic.dll"), b"proxy bytes").expect("proxy placed");

    finalize_run_dir(&run, "game_logic.dll").expect("finalize runs");

    assert_eq!(
        std::fs::read(run.join("game_logic.dll")).expect("restored identity"),
        b"real bytes",
        "the application tree resolves the real module, never the recorder"
    );
    assert!(
        !run.join(px_real_name("game_logic.dll")).exists(),
        "the real name the proxy resolved through is gone: nothing points at a copy"
    );
}

/// An interrupted run — proxy placed, run dir never completed — still
/// ends with no recorder standing over the target.
#[test]
fn finalizing_an_interrupted_run_leaves_no_proxy_standing() {
    let root = tempfile::tempdir().expect("tempdir");
    let target = root.path().join("game_logic.dll");
    std::fs::write(&target, b"real bytes").expect("fixture target");
    let run = root.path().join("run");
    scaffold_run_dir(&run, "game_logic.dll", &target).expect("scaffold runs");
    std::fs::write(run.join("game_logic.dll"), b"proxy bytes").expect("proxy placed");

    finalize_run_dir(&run, "game_logic.dll").expect("finalize after an interrupted run");
    finalize_run_dir(&run, "game_logic.dll").expect("finalizing twice is honest, not an error");

    assert_eq!(
        std::fs::read(run.join("game_logic.dll")).expect("restored identity"),
        b"real bytes",
        "an interrupted capture cannot leave the tree running through a recorder"
    );
}

/// The slot table records every export whose whole parameter vector the
/// recorder can carry — and forwards the rest with its name intact.
#[test]
fn the_slot_table_records_what_fits_and_forwards_the_rest() {
    let exports = [
        ("fixture_tick", "int __stdcall fixture_tick(void)"),
        (
            "fixture_status",
            "int __stdcall fixture_status(int code, DWORD flags, char* buf, void* out)",
        ),
        ("fixture_gain", "int __stdcall fixture_gain(float level)"),
        (
            "fixture_wide",
            "int __stdcall fixture_wide(int a, int b, int c, int d, int e)",
        ),
        (
            "fixture_unparsed",
            "int __stdcall fixture_unparsed(int code",
        ),
        ("fixture_void_sig", ""),
    ]
    .map(|(name, signature)| calxgloss_types::Export {
        name: name.to_string(),
        address: 0x1000,
        signature: signature.to_string(),
    });

    let slots = derive_proxy_slots(&exports, Machine::X86_64);

    let shape: Vec<(&str, Option<usize>)> = slots
        .iter()
        .map(|slot| {
            (
                slot.export.as_str(),
                slot.recorded.as_ref().map(|r| r.arg_kinds.len()),
            )
        })
        .collect();
    assert_eq!(
        shape,
        vec![
            ("fixture_tick", Some(0)),
            ("fixture_status", Some(4)),
            ("fixture_gain", None),
            ("fixture_wide", None),
            ("fixture_unparsed", None),
            ("fixture_void_sig", None),
        ],
        "a float, a fifth argument, an unparseable prototype, and a missing \
         signature all keep the export forwarding — recording nothing beats recording wrong"
    );
}

// ------------------------------------------------------------- launcher

/// A fake Wine standing in for the real thing — hermetic launcher and
/// budget pins live here; the real Wine + proxy proof is the gated e2e
/// at the bottom of this file and in `tests/baseline.rs`.
fn fake_wine(dir: &Path, body: &str) -> PathBuf {
    let path = dir.join("fake-wine.sh");
    std::fs::write(
        &path,
        format!(
            "#!/usr/bin/env bash\nif [ \"$1\" = \"--version\" ]; then echo 'wine-9.0 (fake)'; \
             exit 0; fi\n{body}\n"
        ),
    )
    .expect("fake wine script");
    let mut perms = std::fs::metadata(&path).expect("metadata").permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&path, perms).expect("chmod +x");
    path
}

/// A fixture operator tree: the target DLL, a fake application exe,
/// and an armed (scaffolded + proxy-placed) run dir.
struct LaunchFixture {
    runner: WineRunner,
    run: PathBuf,
    app: PathBuf,
}

fn launch_fixture(root: &Path, wine_body: &str) -> LaunchFixture {
    let wine = fake_wine(root, wine_body);
    let app = root.join("game.exe");
    std::fs::write(&app, b"MZ fake app").expect("fixture app");
    let target = root.join("game_logic.dll");
    std::fs::write(&target, b"real bytes").expect("fixture target");
    let run = root.join("run");
    scaffold_run_dir(&run, "game_logic.dll", &target).expect("scaffold runs");
    std::fs::write(run.join("game_logic.dll"), b"proxy bytes").expect("proxy placed");
    LaunchFixture {
        runner: WineRunner::new(&root.join("work")).with_wine_bin(wine.display().to_string()),
        run,
        app,
    }
}

/// The launcher puts the run dir on the DLL search path and hands Wine
/// the application; the recorder's wire events become the log's entries.
#[test]
fn a_launched_run_records_events_and_resolves_through_the_run_dir() {
    let root = tempfile::tempdir().expect("tempdir");
    let fixture = launch_fixture(
        root.path(),
        r#"echo "WINEPATH=$WINEPATH APP=$1" > "$(dirname "$0")/env-dump.txt"
printf 'EVENT\t{"export":"GameLogic_Run","args":[{"kind":"scalar","tag":"i","value":7}]}\n'
printf '%s\n' 'not an event line'
printf 'proxy: cannot record event: SetFilePointerEx returns no value shape\n' >&2
printf 'EVENT\t{"export":"GameLogic_Tick","args":[]}\n'"#,
    );

    let launch = fixture
        .runner
        .launch_reference_app(
            "game_logic.dll",
            &fixture.run,
            &fixture.app,
            &CaptureBudgets::new(),
        )
        .expect("the fake-wine run completes");

    assert_eq!(
        launch.events.len(),
        2,
        "both EVENT lines parsed; the noise line did not"
    );
    assert_eq!(launch.events_seen, 2);
    assert_eq!(launch.events_dropped, 0);
    assert!(launch.stop.is_none(), "the application ended on its own");
    assert_eq!(
        launch.proxy_notes,
        vec!["proxy: cannot record event: SetFilePointerEx returns no value shape".to_string()],
        "the proxy's honest refusals ride along"
    );

    // The run dir restored to the real module under its own identity —
    // the launch's exit path, not the orchestrator's, did it.
    assert_eq!(
        std::fs::read(fixture.run.join("game_logic.dll")).expect("restored identity"),
        b"real bytes"
    );
    assert!(!fixture.run.join(px_real_name("game_logic.dll")).exists());

    let dump = std::fs::read_to_string(root.path().join("env-dump.txt")).expect("env dump");
    let expected_path = fixture
        .runner
        .to_wine_path(&fixture.run)
        .expect("wine path of the run dir");
    let expected_app = fixture
        .runner
        .to_wine_path(&fixture.app)
        .expect("wine path of the app");
    assert!(
        dump.contains(&format!("WINEPATH={expected_path}")),
        "the run dir is on the DLL search path: {dump}"
    );
    assert!(
        dump.contains(&format!("APP={expected_app}")),
        "Wine receives the application as its first argument: {dump}"
    );
}

/// The event budget stops the run, truncates, and says so — the events
/// that arrived past the budget are counted as dropped, never silent.
#[test]
fn the_event_budget_stops_the_run_and_states_its_truncation() {
    let root = tempfile::tempdir().expect("tempdir");
    fixture_with_ten_events(root.path());

    let budgets = CaptureBudgets::new().with_max_events(3);
    let launch = fixture_runner(root.path())
        .launch_reference_app(
            "game_logic.dll",
            &run_of(root.path()),
            &app_of(root.path()),
            &budgets,
        )
        .expect("budgeted run completes");

    assert_eq!(
        launch.events.len(),
        3,
        "the budget is the number of kept events"
    );
    assert_eq!(launch.events_seen, 10, "every event on the wire is seen");
    assert_eq!(
        launch.events_dropped, 7,
        "the events past the budget are counted"
    );
    assert_eq!(launch.stop, Some(BudgetStop::MaxEvents));
}

fn fixture_with_ten_events(root: &Path) {
    // The events ride to the pipe in one flush, before the pump can act
    // on the first of them: otherwise the stop fired at the third event
    // races the emitter and the fixture, not the pump, loses the rest.
    let events = root.join("ten-events.txt");
    let mut body = String::new();
    for i in 1..=10 {
        body.push_str(&format!(
            "EVENT\t{{\"export\":\"GameLogic_Step_{i}\",\"args\":[]}}\n"
        ));
    }
    std::fs::write(&events, body).expect("ten events staged");
    let wine = fake_wine(
        root,
        r#"cat "$(dirname "$0")/ten-events.txt"
sleep 30"#,
    );
    let app = root.join("game.exe");
    std::fs::write(&app, b"MZ fake app").expect("fixture app");
    let target = root.join("game_logic.dll");
    std::fs::write(&target, b"real bytes").expect("fixture target");
    let run = root.join("run");
    scaffold_run_dir(&run, "game_logic.dll", &target).expect("scaffold runs");
    std::fs::write(run.join("game_logic.dll"), b"proxy bytes").expect("proxy placed");
    std::fs::write(root.join("fake-wine-used"), wine.display().to_string())
        .expect("record the wine script path");
}

fn fixture_runner(root: &Path) -> WineRunner {
    let wine = std::fs::read_to_string(root.join("fake-wine-used")).expect("wine path");
    WineRunner::new(&root.join("work")).with_wine_bin(wine)
}

fn run_of(root: &Path) -> PathBuf {
    root.join("run")
}

fn app_of(root: &Path) -> PathBuf {
    root.join("game.exe")
}

/// The duration budget stops a run that never ends on its own — the
/// whole call returns bounded, and the truncation is stated.
#[test]
fn the_duration_budget_stops_a_run_that_outlives_its_budget() {
    let root = tempfile::tempdir().expect("tempdir");
    let fixture = launch_fixture(
        root.path(),
        r#"printf 'EVENT\t{"export":"GameLogic_Run","args":[]}\n'
sleep 30"#,
    );

    let started = std::time::Instant::now();
    let budgets = CaptureBudgets::new().with_max_duration_secs(1);
    let launch = fixture
        .runner
        .launch_reference_app("game_logic.dll", &fixture.run, &fixture.app, &budgets)
        .expect("the duration budget returns, bounded");
    let elapsed = started.elapsed();

    assert!(
        elapsed < std::time::Duration::from_secs(10),
        "the budget stopped the run after {elapsed:?}; it should not wait for the sleep"
    );
    assert_eq!(launch.stop, Some(BudgetStop::Duration));
    assert_eq!(launch.events.len(), 1);
    assert_eq!(
        std::fs::read(fixture.run.join("game_logic.dll")).expect("restored identity"),
        b"real bytes",
        "the budget-stopped run dir stands clean too"
    );
}

/// The event-log size budget stops the run past the byte cap and holds
/// the assembled log under the budget, counting every trim as a drop.
#[test]
fn the_size_budget_stops_past_the_cap_and_holds_the_log_under_it() {
    let root = tempfile::tempdir().expect("tempdir");
    let filler = "x".repeat(120);
    let body = (1..=5)
        .map(|i| {
            format!(
                "printf 'EVENT\\t{{\"export\":\"GameLogic_Bulk_{i}\",\"args\":[],\"\
                 pad\":\"{filler}\"}}\\n'"
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let fixture = launch_fixture(root.path(), &body);

    let budgets = CaptureBudgets::new().with_max_log_bytes(500);
    let launch = fixture
        .runner
        .launch_reference_app("game_logic.dll", &fixture.run, &fixture.app, &budgets)
        .expect("size-budgeted run completes");

    assert_eq!(launch.stop, Some(BudgetStop::LogSize));
    assert!(
        launch.events_dropped >= 1,
        "events past the cap are counted"
    );

    let (log, dropped) =
        fixture
            .runner
            .assemble_capture_log_value("game_logic.dll", &launch, &budgets);
    let text = serde_json::to_string(&log).expect("serialization");
    assert!(
        text.len() as u64 <= 500,
        "the written log fits its budget: {} bytes",
        text.len()
    );
    assert!(dropped >= launch.events_dropped);
    let notes = log["notes"].as_array().expect("notes array");
    assert!(
        notes.iter().any(|n| n
            .as_str()
            .is_some_and(|n| n.contains("event-log size budget"))),
        "the truncation is stated in the log: {notes:?}"
    );
}

/// A size budget with no run-stop trims trailing entries when the
/// assembled document would not fit — every trim stated as a drop.
#[test]
fn assembly_trims_trailing_entries_to_hold_the_document_under_its_budget() {
    let work = tempfile::tempdir().expect("tempdir");
    let runner = WineRunner::new(work.path());
    let run = LaunchedCapture {
        events: vec![
            json!({"export": "GameLogic_Fat", "args": []}),
            json!({"export": "GameLogic_Fat", "args": []}),
        ],
        events_seen: 2,
        events_dropped: 0,
        stop: None,
        proxy_notes: Vec::new(),
        exit_note: None,
        stream_unclosed: false,
    };

    // Measure what two untrimmed entries cost, then budget the document
    // under it: one trailing entry must fall, and the trim must state.
    let (full, full_dropped) =
        runner.assemble_capture_log_value("g.dll", &run, &CaptureBudgets::new());
    assert_eq!(full_dropped, 0);
    let two = serde_json::to_string(&full).expect("serialization").len();

    // Budget just under the pair: trimming one trailing entry (with its
    // stated drop and note) must fit, the pair must not.
    let budgets = CaptureBudgets::new().with_max_log_bytes((two - 1) as u64);
    let (log, dropped) = runner.assemble_capture_log_value("g.dll", &run, &budgets);

    let text = serde_json::to_string(&log).expect("serialization");
    assert!(
        text.len() as u64 <= (two - 1) as u64,
        "the log holds its budget: {} bytes",
        text.len()
    );
    assert_eq!(dropped, 1, "one trailing entry trimmed, counted as a drop");
    assert_eq!(
        log["events_dropped"],
        json!(1),
        "the trim states itself in the log"
    );
    assert_eq!(
        log["entries"].as_array().expect("entries").len(),
        1,
        "exactly the trailing entry fell"
    );
    let notes = log["notes"].as_array().expect("notes");
    assert!(
        notes
            .iter()
            .any(|n| n.as_str().is_some_and(|n| n.contains("trimmed 1 trailing"))),
        "the trim says so: {notes:?}"
    );
}

/// A launch that cannot start still leaves the run dir clean — the
/// guard's finalize runs on the error path too.
#[test]
fn a_launch_that_cannot_start_leaves_no_proxy_standing() {
    let root = tempfile::tempdir().expect("tempdir");
    let app = root.path().join("game.exe");
    std::fs::write(&app, b"MZ fake app").expect("fixture app");
    let target = root.path().join("game_logic.dll");
    std::fs::write(&target, b"real bytes").expect("fixture target");
    let run = root.path().join("run");
    scaffold_run_dir(&run, "game_logic.dll", &target).expect("scaffold runs");
    std::fs::write(run.join("game_logic.dll"), b"proxy bytes").expect("proxy placed");

    let runner = WineRunner::new(&root.path().join("work")).with_wine_bin("/nonexistent-wine");
    runner
        .launch_reference_app("game_logic.dll", &run, &app, &CaptureBudgets::new())
        .expect_err("the broken Wine path fails the launch");

    assert_eq!(
        std::fs::read(run.join("game_logic.dll")).expect("restored identity"),
        b"real bytes",
        "the failed launch leaves the operator's tree exactly as it stands at rest"
    );
    assert!(!run.join(px_real_name("game_logic.dll")).exists());
}

// --------------------------------------------------------- orchestrator

/// The whole capture command machinery, hermetically: fake Wine, real
/// generated proxy, scaffolded run dir, budget stop, log written,
/// identity restored — AC-4 end to end against the mingw-built fixture
/// target, the same one the gated live tests stand on.
#[test]
fn a_complete_capture_run_records_and_restores_the_real_module() {
    let Ok(target) = calxgloss_testfixtures::fixture_target_path() else {
        eprintln!("skipping: needs the mingw-built fixture target");
        return;
    };
    let real_bytes = std::fs::read(&target).expect("fixture target bytes");
    let root = tempfile::tempdir().expect("tempdir");
    let wine = fake_wine(
        root.path(),
        r#"printf 'EVENT\t{"export":"fixture_tick","args":[]}\n'
sleep 30"#,
    );
    let app = root.path().join("game.exe");
    std::fs::write(&app, b"MZ fake app").expect("fixture app");

    let runner =
        WineRunner::new(&root.path().join("work")).with_wine_bin(wine.display().to_string());
    let run = root.path().join("capture");
    let budgets = CaptureBudgets::new().with_max_duration_secs(2);
    let outcome = runner
        .capture_reference_app_run(
            &[ProxySlot::forwarding("fixture_tick")],
            &target,
            &app,
            &run,
            &budgets,
        )
        .expect("the complete capture run completes");

    assert_eq!(outcome.events_seen, 1);
    assert_eq!(outcome.stop, Some(BudgetStop::Duration));

    let log_text = std::fs::read_to_string(&outcome.log_path).expect("the log was written");
    let log: serde_json::Value = serde_json::from_str(&log_text).expect("valid JSON");
    assert_eq!(log["entries"].as_array().expect("entries").len(), 1);
    assert!(
        log_text.contains("duration budget"),
        "the truncation states itself in the written log"
    );

    assert_eq!(
        outcome.log["capture_id"].as_str().expect("capture id"),
        format!("{}fixture_target.dll", REFERENCE_APP_CAPTURE_PREFIX),
        "the log is identified with the target the run resolved through"
    );

    assert_eq!(
        std::fs::read(run.join("fixture_target.dll")).expect("restored identity"),
        real_bytes,
        "after the run, the application tree resolves the real module — never the recorder"
    );
    assert!(
        !run.join(px_real_name("fixture_target.dll")).exists(),
        "nothing left pointing at the real-named copy"
    );
    assert!(
        run.join(CAPTURE_LOG_NAME).is_file(),
        "the event log stays beside the restored module"
    );
}
