//! Behavior tests over the generic scan command at the process seam
//! (issue #339, spec #337): the built CLI runs the `typesdb` ride over
//! the fixture target in a temp workspace, and only outward results are
//! asserted — process success/failure, the document filed at the row's
//! own path, the printed report, and the failure/remediation wording.
//! The run's report and a later `--show` report must be the same read
//! of the same document.

use std::path::Path;
use std::process::Command;

/// Run the built CLI isolated from the ambient config: the user's global
/// file may hold anything, so each test points `CALXGLOSS_CONFIG` at an
/// empty file in its own temp dir and strips the target/workspace vars.
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

/// Run `cmd` in `dir` so no ambient `calxgloss.toml` is picked up, and
/// return (success, stdout, stderr).
fn run(cmd: &mut Command, dir: &Path) -> (bool, String, String) {
    let out = cmd.current_dir(dir).output().expect("the CLI ran");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// A workspace holding a copy of the fixture target at its root, which
/// doubles as the target dir: the persistor files `{binary}.json`
/// literally, and a path-shaped key would land the document outside the
/// workspace — the same layout the control-flow process test uses.
fn fixture_workspace() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("temp workspace");
    let fixture = calxgloss_testfixtures::fixture_target_path().expect("fixture target");
    std::fs::copy(&fixture, dir.path().join("fixture-target"))
        .expect("copy fixture into workspace");
    dir
}

#[test]
fn the_typesdb_run_files_the_documents_and_prints_what_a_later_show_prints() {
    let ws = fixture_workspace();

    let (ok, stdout, stderr) = run(
        cli(ws.path()).args(["--target-dir", ".", "typesdb", "--binary", "fixture-target"]),
        ws.path(),
    );
    assert!(ok, "the typesdb ride failed:\n{stdout}\n{stderr}");

    // The document sits at the row's own path and the declarations file
    // — the entry's one side effect — beside it.
    let document = ws.path().join("re/analysis/typesdb/fixture-target.json");
    assert!(document.is_file(), "the document is filed at {document:?}");
    let decls = ws.path().join("re/analysis/typesdb/fixture-target.rs");
    assert!(
        decls.is_file(),
        "the Rust declarations are written at {decls:?}"
    );

    // The run's report names the database and points at both files.
    assert!(stdout.contains("Type Database"), "{stdout}");
    assert!(stdout.contains("Rust decls:"), "{stdout}");

    // Run-print and show-print equality: the same read of the same
    // document must produce byte-identical output.
    let (ok, show_stdout, stderr) = run(
        cli(ws.path()).args([
            "--target-dir",
            ".",
            "typesdb",
            "--binary",
            "fixture-target",
            "--show",
        ]),
        ws.path(),
    );
    assert!(ok, "the typesdb show failed:\n{show_stdout}\n{stderr}");
    assert_eq!(
        stdout, show_stdout,
        "the run's report and a later --show report are the same read of the same document"
    );
}

#[test]
fn show_with_no_filed_document_fails_naming_the_producing_command() {
    // Remediation wording at the process seam: a fresh workspace, no
    // scan ever run, and the failure tells the operator the exact
    // command that would produce the document.
    let ws = fixture_workspace();
    let (ok, stdout, stderr) = run(
        cli(ws.path()).args([
            "--target-dir",
            ".",
            "typesdb",
            "--binary",
            "fixture-target",
            "--show",
        ]),
        ws.path(),
    );
    assert!(!ok, "an unscanned --show must fail");
    assert!(
        stderr.contains("run `calxgloss typesdb --binary fixture-target`"),
        "the failure names the exact producing command:\n{stdout}\n{stderr}"
    );
}

#[test]
fn a_ridden_flag_free_command_prints_the_same_report_run_and_show() {
    // One of the eleven commands folded into the generic handler (issue
    // #340) at the process seam: `controlflow` scans the fixture, files
    // its document at the row's own path, and the run's report and a
    // later `--show` report are byte-identical — the same read of the
    // same document, with no entry-side engine composition left behind.
    let ws = fixture_workspace();

    let (ok, stdout, stderr) = run(
        cli(ws.path()).args([
            "--target-dir",
            ".",
            "controlflow",
            "--binary",
            "fixture-target",
        ]),
        ws.path(),
    );
    assert!(ok, "the controlflow ride failed:\n{stdout}\n{stderr}");
    let document = ws.path().join("re/analysis/controlflow/fixture-target.json");
    assert!(
        document.is_file(),
        "the document is filed at {document:?}"
    );
    assert!(stdout.contains("Control flow"), "{stdout}");

    let (ok, show_stdout, stderr) = run(
        cli(ws.path()).args([
            "--target-dir",
            ".",
            "controlflow",
            "--binary",
            "fixture-target",
            "--show",
        ]),
        ws.path(),
    );
    assert!(ok, "the controlflow show failed:\n{show_stdout}\n{stderr}");
    assert_eq!(
        stdout, show_stdout,
        "the run's report and a later --show report are the same read of the same document"
    );
}
