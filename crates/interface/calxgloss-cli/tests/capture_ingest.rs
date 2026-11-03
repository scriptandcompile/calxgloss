//! Process-level e2e for the `capture --ingest` command (P23.2, issue
//! #396): the built CLI folds a capture event log over the fixture target,
//! prints the count report with every refusal named, and files the named
//! records in the binary's unknown ledger — no Wine in sight, because an
//! all-refused log replays nothing at all.

use std::path::Path;
use std::process::Command;

/// Run the built CLI isolated from the ambient config, as every engine
/// test does.
fn cli(dir: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_calxgloss-cli"));
    let empty = dir.join("empty-config.toml");
    std::fs::write(&empty, "# empty: every setting falls back to its default")
        .expect("empty config written");
    cmd.env("CALXGLOSS_CONFIG", &empty);
    for key in ["CALXGLOSS_TARGET_DIR", "CALXGLOSS_WORKSPACE"] {
        cmd.env_remove(key);
    }
    cmd
}

fn run(cmd: &mut Command, dir: &Path) -> (bool, String, String) {
    let out = cmd.current_dir(dir).output().expect("the CLI ran");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn capture_ingest_reports_named_refusals_and_replays_nothing() {
    let fixture = calxgloss_testfixtures::fixture_target_path().expect("fixture target");
    let dir = tempfile::tempdir().expect("temp dir");
    let ws = dir.path();
    std::fs::copy(&fixture, ws.join("fixture-target")).expect("copy fixture into workspace");

    // An all-refused log: a float tag, a pointer-bearing vector, an
    // export the listing does not carry, and a stated truncation. Nothing
    // survives to the replay seam, so no Wine is ever asked for.
    std::fs::write(
        ws.join("capture-log.json"),
        r#"{
            "capture_id": "cap-cli",
            "events_dropped": 2,
            "entries": [
                {"binary": "fixture-target", "export": "fixture_status", "lane": "baseline_hook",
                 "evidence": {"run_event": {"capture_id": "cap-cli", "event_sequence": 1}},
                 "arguments": [{"scalar": {"tag": "f64", "value": 1.5}}]},
                {"binary": "fixture-target", "export": "fixture_ordered", "lane": "baseline_hook",
                 "evidence": {"run_event": {"capture_id": "cap-cli", "event_sequence": 2}},
                 "arguments": [
                     {"pointer": {"bytes": [1, 2, 3, 4], "captured_size": 4, "truncated": false}}
                 ]},
                {"binary": "fixture-target", "export": "ghost_export", "lane": "baseline_hook",
                 "evidence": {"run_event": {"capture_id": "cap-cli", "event_sequence": 3}},
                 "arguments": [{"scalar": {"tag": "i32", "value": 7}}]}
            ]
        }"#,
    )
    .expect("capture log written");

    let (ok, stdout, stderr) = run(
        cli(ws).args([
            "--target-dir",
            ".",
            "capture",
            "--binary",
            "fixture-target",
            "--ingest",
            "capture-log.json",
        ]),
        ws,
    );
    assert!(ok, "capture --ingest failed:\n{stdout}\n{stderr}");

    // The count report the command owes: every dimension named, every
    // refusal with its reason.
    assert!(stdout.contains("3 events seen"), "{stdout}");
    assert!(stdout.contains("0 cases mined"), "{stdout}");
    assert!(stdout.contains("4 refusals named"), "{stdout}");
    assert!(stdout.contains("1 truncation stated"), "{stdout}");
    for reason in [
        "float-argument",
        "pointer-bearing-vector",
        "no-parseable-signature",
        "truncated-capture",
    ] {
        assert!(stdout.contains(reason), "{stdout} lacks {reason:?}");
    }
    assert!(
        stdout.contains("capture truncated: 2 events dropped"),
        "{stdout}"
    );

    // The named records land in the binary's unknown ledger, origin-bound
    // to the capture.
    let ledger = std::fs::read_to_string(ws.join("re/unknowns/fixture-target.json"))
        .expect("the fold files its named records in the unknown ledger");
    for slot in ["cap-cli#1", "cap-cli#2", "cap-cli#3", "cap-cli#capture"] {
        assert!(ledger.contains(slot), "ledger lacks {slot:?}: {ledger}");
    }
    assert!(
        ledger.contains("capture_refused"),
        "the ledger names the kind"
    );

    // Nothing was replayed: no baseline document was filed anywhere.
    assert!(
        !ws.join("re/baseline").exists(),
        "an all-refused log files no baseline suite"
    );
}

#[test]
fn capture_ingest_fails_naming_a_malformed_log() {
    let fixture = calxgloss_testfixtures::fixture_target_path().expect("fixture target");
    let dir = tempfile::tempdir().expect("temp dir");
    let ws = dir.path();
    std::fs::copy(&fixture, ws.join("fixture-target")).expect("copy fixture into workspace");
    std::fs::write(ws.join("capture-log.json"), "not json at all").expect("log written");

    let (ok, _stdout, stderr) = run(
        cli(ws).args([
            "--target-dir",
            ".",
            "capture",
            "--binary",
            "fixture-target",
            "--ingest",
            "capture-log.json",
        ]),
        ws,
    );
    assert!(!ok, "a malformed log must fail the run");
    assert!(
        stderr.contains("not valid JSON") || stderr.contains("capture-log-v1"),
        "the failure names the log's shape: {stderr}"
    );
}
