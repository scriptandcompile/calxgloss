//! Behavior tests for the unknown audit ledger at the terminal dashboard
//! seam (issue #377). The built CLI renders the dashboard over a temp git
//! repository whose branches, filed ledgers, and reviewer resolutions are
//! staged on disk, and the assertions read only the printed section: each
//! target binary's ledger line, its open records named one bounded line
//! each, the reviewer's settled rides counted beside open — and a binary
//! whose ledger was never filed (or never spoke) printed as *unknown*,
//! never as a clean run. The run close prints the same lines through the
//! same derivation, so these pins cover the wording both readers share.

use std::path::Path;
use std::process::Command;

use calxgloss_types::{
    BinaryIdentity, UnknownKind, UnknownLedger, UnknownOrigin, UnknownRecord, UnknownResolutions,
    UnknownSeverity, save_json, unknown_ledger_path, unknown_resolutions_path,
};

/// Run the built CLI isolated from the ambient config, like the scan
/// process tests do: an empty config file and no ambient target or
/// workspace variables.
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

/// Run `cmd` in `dir` and return (success, stdout, stderr).
fn run(cmd: &mut Command, dir: &Path) -> (bool, String, String) {
    let out = cmd.current_dir(dir).output().expect("the CLI ran");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn git(dir: &Path, args: &[&str]) {
    let out = Command::new("git")
        .args([
            "-c",
            "user.name=calxgloss-test",
            "-c",
            "user.email=test@calxgloss.local",
        ])
        .args(args)
        .current_dir(dir)
        .output()
        .expect("git ran");
    assert!(
        out.status.success(),
        "git {args:?} failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// A git workspace with one translation branch per named binary.
fn workspace_with_branches(binaries: &[(&str, &str)]) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("temp workspace");
    git(dir.path(), &["init", "-b", "main"]);
    git(dir.path(), &["commit", "--allow-empty", "-m", "baseline"]);
    for (binary, function) in binaries {
        git(
            dir.path(),
            &["branch", &format!("re/{binary}/{function}/v1")],
        );
    }
    dir
}

fn record(
    binary: &str,
    function: &str,
    id: &str,
    severity: UnknownSeverity,
    question: &str,
) -> UnknownRecord {
    UnknownRecord::derive(
        binary,
        Some(function.to_string()),
        UnknownKind::CoverageFacet,
        severity,
        question,
        "call-site survey",
        UnknownOrigin::CaseSet {
            case_set: format!("cs-{id}"),
        },
        1_700_000_000,
    )
}

fn file_ledger(workspace: &Path, binary: &str, records: &[UnknownRecord]) {
    save_json(
        &unknown_ledger_path(workspace, &BinaryIdentity::from(binary)),
        &UnknownLedger {
            binary: BinaryIdentity::from(binary),
            filed_at: 1_700_000_000,
            records: Some(records.to_vec()),
        },
    )
    .expect("file ledger");
}

#[test]
fn the_dashboard_prints_each_targets_ledger_with_settles_counted_apart() {
    let ws = workspace_with_branches(&[("game_logic.dll", "DrawPrimitive")]);
    let open = record(
        "game_logic.dll",
        "DrawPrimitive",
        "u-open",
        UnknownSeverity::Blocking,
        "Which side owns the buffer?",
    );
    let settled = record(
        "game_logic.dll",
        "DrawPrimitive",
        "u-settled",
        UnknownSeverity::Material,
        "Answered by review.",
    );
    let dismissed = record(
        "game_logic.dll",
        "DrawPrimitive",
        "u-dismissed",
        UnknownSeverity::Notable,
        "Ruled out of scope.",
    );
    file_ledger(
        ws.path(),
        "game_logic.dll",
        &[open.clone(), settled.clone(), dismissed.clone()],
    );
    let mut resolutions = UnknownResolutions::default();
    resolutions
        .resolve(
            &settled,
            "the answer landed in the type database",
            1,
            1_700_000_500,
        )
        .expect("resolve");
    resolutions
        .dismiss(
            &dismissed,
            "the reviewer ruled it out of scope",
            1,
            1_700_000_500,
        )
        .expect("dismiss");
    save_json(&unknown_resolutions_path(ws.path()), &resolutions).expect("file resolutions");

    let (ok, stdout, stderr) = run(
        cli(ws.path()).args(["--target-dir", ".", "dashboard"]),
        ws.path(),
    );
    assert!(ok, "the dashboard run failed:\n{stdout}\n{stderr}");

    assert!(stdout.contains("Unknown audit ledger"), "{stdout}");
    assert!(
        stdout.contains("game_logic.dll — 1 open (1 blocking)"),
        "the open severity counts: {stdout}"
    );
    assert!(
        stdout.contains("• [blocking] Which side owns the buffer? — needs: call-site survey"),
        "the open record prints its question and required evidence: {stdout}"
    );
    assert!(
        stdout.contains("1 resolved, 1 dismissed"),
        "the settled rides count beside open, never folded: {stdout}"
    );
    // A settled record counts in the ledger but never prints as open and
    // never reads as established.
    assert!(!stdout.contains("Answered by review."), "{stdout}");
    assert!(!stdout.contains("Ruled out of scope."), "{stdout}");

    // The existing report rows keep their place: the audit section rides
    // the same dashboard, footer and all.
    assert!(stdout.contains("branches found in re/*"), "{stdout}");
}

#[test]
fn an_unfiled_or_silent_ledger_prints_unknown_never_a_clean_run() {
    let ws = workspace_with_branches(&[("render_core.dll", "Blit"), ("keyless_engine.dll", "Go")]);

    // render_core.dll: nobody ever filed a ledger. keyless_engine.dll: the
    // document exists but carries no `records` key — the absent key never
    // means the list is empty (ADR-0053).
    save_json(
        &unknown_ledger_path(ws.path(), &BinaryIdentity::from("keyless_engine.dll")),
        &UnknownLedger {
            binary: BinaryIdentity::from("keyless_engine.dll"),
            filed_at: 1_700_000_000,
            records: None,
        },
    )
    .expect("file keyless ledger");

    let (ok, stdout, stderr) = run(
        cli(ws.path()).args(["--target-dir", ".", "dashboard"]),
        ws.path(),
    );
    assert!(ok, "the dashboard run failed:\n{stdout}\n{stderr}");

    assert!(
        stdout.contains("render_core.dll — unknown"),
        "an unfiled ledger prints as unknown: {stdout}"
    );
    assert!(
        stdout.contains("keyless_engine.dll — unknown"),
        "a document whose records key is absent prints as unknown: {stdout}"
    );
    assert!(
        !stdout.contains("none open"),
        "neither reading launders into a clean run: {stdout}"
    );
    assert!(stdout.contains("branches found in re/*"), "{stdout}");
}

#[test]
fn a_filed_empty_ledger_prints_the_honest_empty_line() {
    let ws = workspace_with_branches(&[("engine_helpers.dll", "Alloc")]);
    file_ledger(ws.path(), "engine_helpers.dll", &[]);

    let (ok, stdout, stderr) = run(
        cli(ws.path()).args(["--target-dir", ".", "dashboard"]),
        ws.path(),
    );
    assert!(ok, "the dashboard run failed:\n{stdout}\n{stderr}");

    assert!(
        stdout.contains("engine_helpers.dll — none open (ledger filed)"),
        "the only honest clean line is a filed, explicitly empty ledger: {stdout}"
    );
}
