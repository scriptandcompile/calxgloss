//! Process-level e2e for the `scenario compare` command (P24.6, issue
//! #407): two *scenario captures* plus the filed *scenario contract* in,
//! one digest-bearing *scenario verdict* filed at
//! `re/scenarios/verdicts/{binary}-{scenario}.json`.
//!
//! Every pin here is ungated and Wine-free: the comparator is pure record
//! logic, so these pins hand it capture documents built by hand at
//! arbitrary paths — that is itself the proof the compare command
//! launches nothing. The verdict's digest is re-derived from the filed
//! bytes alone, `--json` prints the machine-readable document, and every
//! refusal (no contract yet, no capture at the named path, an unstamped
//! pairing) names what it refused and files nothing.

use std::path::{Path, PathBuf};
use std::process::Command;

use calxgloss_types::ScenarioVerdictDocument;

/// Run the built CLI isolated from the ambient config, as every engine
/// test does.
fn cli(dir: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_calxgloss-cli"));
    let empty = dir.join("empty-config.toml");
    std::fs::write(&empty, "# empty: every setting falls back to its default")
        .expect("empty config written");
    cmd.env("CALXGLOSS_CONFIG", &empty);
    for key in [
        "CALXGLOSS_TARGET_DIR",
        "CALXGLOSS_WORKSPACE",
        "CALXGLOSS_WINE",
    ] {
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

const BINARY: &str = "fixture_console.exe";
const SCENARIO: &str = "boot-and-exit";

fn workspace() -> tempfile::TempDir {
    tempfile::tempdir().expect("a scratch workspace")
}

/// Declare the scenario the hand-built captures speak — the default
/// normalization version (`norm-v1`) is the stamp the captures carry too.
fn declare(ws: &Path) {
    let mut cmd = cli(ws);
    cmd.args(["scenario", "declare"])
        .args(["--binary", BINARY, "--scenario", SCENARIO])
        .args(["--observe", "new.dat", "--observe", "old.dat"])
        .args(["--input-at", "1000:echo hello-scene"]);
    let (ok, stdout, stderr) = run(&mut cmd, ws);
    assert!(ok, "the scenario declares: {stdout}{stderr}");
}

/// A hand-built *scenario capture* document that observed everything:
/// all five dimension blocks stand filled, pairing stamped under
/// norm-v1. `chunk` is the first terminal segment, so a pair can be made
/// to diverge in exactly one place.
fn capture_json(chunk: &str) -> serde_json::Value {
    serde_json::json!({
        "scenario": SCENARIO,
        "filed_at": 1,
        "pairing": {
            "program_sha256": "sha256:bytes-under-test",
            "wine_version": "wine-9.0",
            "normalization_version": "norm-v1",
        },
        "terminal": {
            "chunks": [chunk, "goodbye"],
            "output_capped": false,
            "geometry": { "cols": 80, "rows": 24 },
            "rendered_states": [],
        },
        "interaction": { "acknowledged_at_ms": [1000, 2000] },
        "exit": { "disposition": "exited", "exit_code": 7 },
        "filesystem": {
            "entries": [
                {
                    "path": "new.dat",
                    "change": "created",
                    "size_bytes": 12,
                    "sha256": "sha256-new",
                    "block_hashes": ["sha256-new"],
                },
                {
                    "path": "old.dat",
                    "change": "deleted",
                    "size_bytes": 9,
                    "sha256": "sha256-old",
                    "block_hashes": ["sha256-old"],
                },
            ],
        },
        "process": {
            "samples": [
                { "pid": 100, "name": "fixture_console.exe" },
                { "pid": 110, "name": "child_helper.exe" },
            ],
        },
    })
}

/// File one hand-built capture document as its own loose JSON file and
/// return its path — compare reads captures wherever they stand.
fn stage_capture(dir: &Path, name: &str, document: &serde_json::Value) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(
        &path,
        serde_json::to_vec_pretty(document).expect("the capture serializes"),
    )
    .expect("the capture stages");
    path
}

fn compare(ws: &Path, left: &Path, right: &Path, extra: &[&str]) -> (bool, String, String) {
    let mut cmd = cli(ws);
    cmd.args(["scenario", "compare"])
        .args(["--binary", BINARY, "--scenario", SCENARIO])
        .args(["--left", &left.display().to_string()])
        .args(["--right", &right.display().to_string()])
        .args(extra);
    run(&mut cmd, ws)
}

fn filed_verdict(ws: &Path) -> PathBuf {
    ws.join("re")
        .join("scenarios")
        .join("verdicts")
        .join(format!("{BINARY}-{SCENARIO}.json"))
}

#[test]
fn compare_before_any_contract_names_the_declare_step_and_files_nothing() {
    let ws = workspace();
    let left = stage_capture(ws.path(), "left.json", &capture_json("hello-scene"));
    let right = stage_capture(ws.path(), "right.json", &capture_json("hello-scene"));
    let (ok, stdout, stderr) = compare(ws.path(), &left, &right, &[]);
    assert!(!ok, "a compare with no contract is refused");
    let message = format!("{stdout}{stderr}");
    assert!(
        message.contains("declare"),
        "the refusal points at the declare step: {message}"
    );
    assert!(
        !filed_verdict(ws.path()).exists(),
        "a refused compare files nothing"
    );
}

#[test]
fn an_agreeing_pair_files_the_digest_bearing_verdict_where_the_record_tree_documents_it() {
    let ws = workspace();
    declare(ws.path());
    let left = stage_capture(ws.path(), "left.json", &capture_json("hello-scene"));
    let right = stage_capture(ws.path(), "right.json", &capture_json("hello-scene"));
    let (ok, stdout, stderr) = compare(ws.path(), &left, &right, &[]);
    assert!(ok, "the compare runs: {stdout}{stderr}");

    let path = filed_verdict(ws.path());
    let filed = std::fs::read_to_string(&path).expect("the verdict files at the documented path");
    let document: ScenarioVerdictDocument =
        serde_json::from_str(&filed).expect("the filed document is a verdict");
    assert_eq!(document.binary.to_string(), BINARY);
    assert_eq!(document.scenario, SCENARIO);
    assert_eq!(
        document.normalization_version, "norm-v1",
        "the version in force is stated"
    );
    for (dimension, state) in [
        ("terminal", &document.verdict.terminal),
        ("interaction", &document.verdict.interaction),
        ("exit", &document.verdict.exit),
        ("filesystem", &document.verdict.filesystem),
        ("process", &document.verdict.process),
    ] {
        assert_eq!(
            state,
            &calxgloss_types::DimensionVerdict::AssessedPass,
            "{dimension} weighed assessed pass"
        );
    }
    assert!(
        document.digest.starts_with("sha256:"),
        "the verdict carries its content digest: {:?}",
        document.digest
    );
    assert_eq!(
        document.digest,
        document.content_digest().expect("the digest re-derives"),
        "a reader of the filed bytes alone re-derives the same digest"
    );
    // The honesty line: a bounded filesystem always states its path-
    // outside unknowns, so a fully-passing pair still claims nothing
    // complete — and the statements ride the filed document.
    assert!(
        !document.claims_complete_equivalence,
        "a bounded pair states its unknowns and claims nothing complete"
    );
    assert!(
        document
            .residual_unknowns
            .iter()
            .any(|unknown| unknown.contains("new.dat") && unknown.contains("old.dat")),
        "the observation paths are named in the unknowns: {:?}",
        document.residual_unknowns
    );
    // The captures it judged are cited by digest, so the verdict can
    // never be read without the pair it speaks for.
    assert!(
        document.left_capture_sha256.starts_with("sha256:")
            && document.right_capture_sha256.starts_with("sha256:")
    );
}

#[test]
fn the_json_flag_prints_the_machine_readable_verdict_document() {
    let ws = workspace();
    declare(ws.path());
    let left = stage_capture(ws.path(), "left.json", &capture_json("hello-scene"));
    let right = stage_capture(ws.path(), "right.json", &capture_json("hello-scene"));
    let (ok, stdout, stderr) = compare(ws.path(), &left, &right, &["--json"]);
    assert!(ok, "the compare runs: {stdout}{stderr}");

    let printed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("--json prints one machine-readable document");
    let filed: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(filed_verdict(ws.path())).expect("the verdict filed"),
    )
    .expect("the filed document parses");
    assert_eq!(printed, filed, "--json prints exactly the filed document");
    assert_eq!(printed["verdict"]["terminal"], "assessed_pass");
}

#[test]
fn a_diverging_pair_files_an_assessed_fail_naming_the_segment_with_both_sides_beside_it() {
    let ws = workspace();
    declare(ws.path());
    let left = stage_capture(ws.path(), "left.json", &capture_json("hello-scene"));
    let right = stage_capture(ws.path(), "right.json", &capture_json("hello-different"));
    let (ok, stdout, stderr) = compare(ws.path(), &left, &right, &[]);
    assert!(
        ok,
        "an assessed fail is a verdict, not a command failure: {stdout}{stderr}"
    );
    for side in ["hello-scene", "hello-different"] {
        assert!(
            stdout.contains(side),
            "the human verdict names the divergent segment text {side}: {stdout}"
        );
    }

    let document: ScenarioVerdictDocument = serde_json::from_str(
        &std::fs::read_to_string(filed_verdict(ws.path())).expect("the verdict filed"),
    )
    .expect("the filed document parses");
    assert_eq!(
        document.verdict.terminal,
        calxgloss_types::DimensionVerdict::AssessedFail
    );
    assert_eq!(
        document.verdict.exit,
        calxgloss_types::DimensionVerdict::AssessedPass
    );
    assert_eq!(document.divergences.len(), 1, "one named divergence");
    let divergence = &document.divergences[0];
    match divergence {
        calxgloss_types::DimensionDivergence::TerminalSegment { index, left, right } => {
            assert_eq!(*index, 0, "the divergence names its segment index");
            assert_eq!(left.as_deref(), Some("hello-scene"));
            assert_eq!(right.as_deref(), Some("hello-different"));
        }
        other => panic!("expected a named terminal segment, got {other:?}"),
    }
}

#[test]
fn an_unstamped_pairing_refuses_the_pair_naming_the_side_that_cannot_prove_its_version() {
    let ws = workspace();
    declare(ws.path());
    let left = stage_capture(ws.path(), "left.json", &capture_json("hello-scene"));
    let mut unstamped = capture_json("hello-scene");
    unstamped["pairing"]
        .as_object_mut()
        .expect("the pairing stands")
        .remove("normalization_version");
    let right = stage_capture(ws.path(), "right.json", &unstamped);
    let (ok, stdout, stderr) = compare(ws.path(), &left, &right, &[]);
    assert!(
        !ok,
        "a pair across unproven normalization versions is refused"
    );
    let message = format!("{stdout}{stderr}");
    assert!(
        message.contains("right") && message.contains("not proven"),
        "the refusal names the unstamped side: {message}"
    );
    assert!(
        !filed_verdict(ws.path()).exists(),
        "a refused compare files nothing"
    );
}

#[test]
fn a_capture_document_that_is_not_there_is_refused_naming_its_path() {
    let ws = workspace();
    declare(ws.path());
    let left = ws.path().join("never-staged.json");
    let right = stage_capture(ws.path(), "right.json", &capture_json("hello-scene"));
    let (ok, stdout, stderr) = compare(ws.path(), &left, &right, &[]);
    assert!(!ok, "a missing capture document is refused");
    let message = format!("{stdout}{stderr}");
    assert!(
        message.contains("never-staged.json"),
        "the refusal names the path it could not read: {message}"
    );
    assert!(
        !filed_verdict(ws.path()).exists(),
        "a refused compare files nothing"
    );
}
