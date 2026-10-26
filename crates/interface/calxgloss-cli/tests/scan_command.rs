//! Behavior tests over the generic scan command at the process seam
//! (issues #339–#341, spec #337): the built CLI runs a ride over the
//! fixture target in a temp workspace, and only outward results are
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
    let document = ws
        .path()
        .join("re/analysis/controlflow/fixture-target.json");
    assert!(document.is_file(), "the document is filed at {document:?}");
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

#[test]
fn the_apidetect_report_prints_the_scans_admission_run_and_show_alike() {
    // The apidetect admission line at the process seam (issue #346):
    // the scan stamps its coverage into the document it files, and both
    // the run's report and a later `--show` report print the document's
    // one bounded admission line beside the counts — byte-identically,
    // because both are the same read of the same document.
    let ws = fixture_workspace();

    let (ok, stdout, stderr) = run(
        cli(ws.path()).args([
            "--target-dir",
            ".",
            "apidetect",
            "--binary",
            "fixture-target",
        ]),
        ws.path(),
    );
    assert!(ok, "the apidetect ride failed:\n{stdout}\n{stderr}");
    let document = ws.path().join("re/analysis/apidetect/fixture-target.json");
    assert!(document.is_file(), "the document is filed at {document:?}");

    // The limitation line rides beside the counts, and it names the
    // facet the engine never examines — the admission the scan owes.
    // Label and admission print in different styles, so the assertion
    // quotes each piece as printed, never their join across the codes.
    assert!(stdout.contains("Identified:"), "{stdout}");
    assert!(
        stdout.contains("Coverage:") && stdout.contains("partial — delay imports unexamined"),
        "the report prints the document's admission line beside the counts:\n{stdout}"
    );

    let (ok, show_stdout, stderr) = run(
        cli(ws.path()).args([
            "--target-dir",
            ".",
            "apidetect",
            "--binary",
            "fixture-target",
            "--show",
        ]),
        ws.path(),
    );
    assert!(ok, "the apidetect show failed:\n{show_stdout}\n{stderr}");
    assert!(
        show_stdout.contains("Coverage:")
            && show_stdout.contains("partial — delay imports unexamined"),
        "the show report prints the same admission:\n{show_stdout}"
    );
    assert_eq!(
        stdout, show_stdout,
        "the run's report and a later --show report are the same read of the same document"
    );
}

#[test]
fn the_typeinfer_write_back_rides_the_scan_and_show_paths_and_prints_its_report() {
    // The type-inference follow-on at the process seam (issue #341):
    // `--write-back --confidence-floor 0` applies through the typeinfer
    // crate's own write-back API and prints its report after the main
    // report; `--show --write-back` prints the same section from the
    // filed document; and without the flag no write-back section
    // appears at all — run or show.
    let ws = fixture_workspace();

    let (ok, stdout, stderr) = run(
        cli(ws.path()).args([
            "--target-dir",
            ".",
            "typeinfer",
            "--binary",
            "fixture-target",
            "--write-back",
            "--confidence-floor",
            "0",
        ]),
        ws.path(),
    );
    assert!(
        ok,
        "the typeinfer write-back ride failed:\n{stdout}\n{stderr}"
    );
    let document = ws.path().join("re/analysis/typeinfer/fixture-target.json");
    assert!(document.is_file(), "the document is filed at {document:?}");
    assert!(stdout.contains("Type Inference"), "{stdout}");
    assert!(stdout.contains("Type Write-Back — floor 0"), "{stdout}");
    assert!(
        stdout.find("Type Inference").expect("main report")
            < stdout
                .find("Type Write-Back")
                .expect("write-back report follows"),
        "the write-back section prints after the main report:\n{stdout}"
    );

    let (ok, show_stdout, stderr) = run(
        cli(ws.path()).args([
            "--target-dir",
            ".",
            "typeinfer",
            "--binary",
            "fixture-target",
            "--show",
            "--write-back",
            "--confidence-floor",
            "0",
        ]),
        ws.path(),
    );
    assert!(
        ok,
        "the typeinfer --show --write-back failed:\n{show_stdout}\n{stderr}"
    );
    assert!(
        show_stdout.contains("Type Write-Back — floor 0"),
        "--show --write-back prints the write-back report too:\n{show_stdout}"
    );

    // Without the flag, neither path prints a write-back section.
    let (ok, stdout, stderr) = run(
        cli(ws.path()).args([
            "--target-dir",
            ".",
            "typeinfer",
            "--binary",
            "fixture-target",
        ]),
        ws.path(),
    );
    assert!(ok, "the plain typeinfer ride failed:\n{stdout}\n{stderr}");
    assert!(
        !stdout.contains("Type Write-Back"),
        "--write-back off prints no write-back section:\n{stdout}"
    );
    let (ok, show_stdout, stderr) = run(
        cli(ws.path()).args([
            "--target-dir",
            ".",
            "typeinfer",
            "--binary",
            "fixture-target",
            "--show",
        ]),
        ws.path(),
    );
    assert!(
        ok,
        "the plain typeinfer show failed:\n{show_stdout}\n{stderr}"
    );
    assert_eq!(
        stdout, show_stdout,
        "the run's report and a later --show report are the same read of the same document"
    );
}

#[test]
fn a_malformed_set_override_file_fails_naming_its_path() {
    // The set-override flags at the process seam (issue #341): a broken
    // JSON document fails the run, and stderr names both the file's
    // path and the database that could not be read — the row's own
    // warning wording, never a silent fallback to the built-in set.
    for (command, flag, wording) in [
        ("algorithm", "--patterns", "could not read pattern database"),
        (
            "libmatch",
            "--signatures",
            "could not read signature database",
        ),
    ] {
        let ws = fixture_workspace();
        std::fs::write(
            ws.path().join("broken-database.json"),
            "{ this is not a database document",
        )
        .expect("malformed override file written");
        let (ok, stdout, stderr) = run(
            cli(ws.path()).args([
                "--target-dir",
                ".",
                command,
                "--binary",
                "fixture-target",
                flag,
                "broken-database.json",
            ]),
            ws.path(),
        );
        assert!(
            !ok,
            "the {command} run with a malformed override must fail:\n{stdout}\n{stderr}"
        );
        // The row's own warning carries the database error naming the
        // file's path, and it rides the tracing stream (stdout); the
        // handler's bail rides stderr. Assert over the process's whole
        // diagnostic output rather than pinning one stream.
        let diagnostics = format!("{stdout}{stderr}");
        assert!(
            diagnostics.contains(wording) && diagnostics.contains("broken-database.json"),
            "the failure names the unreadable database and its path:\n{stdout}\n{stderr}"
        );
    }
}
