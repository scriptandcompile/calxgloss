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
fn the_libmatch_report_prints_the_documents_admission_line_only_when_there_is_one() {
    // The libmatch admission line at the process seam (issue #347): a
    // filed document's coverage record — however it got stamped — prints
    // its one bounded admission line beside the counts through `--show`,
    // and a complete record prints nothing. The documents here are filed
    // by the engine's own persistor with hand-stamped coverage, so the
    // pin does not depend on which bodies the fixture's real decompile
    // happens to produce.
    let ws = fixture_workspace();
    let file_document = |coverage: calxgloss_types::ScanCoverage| {
        let mut metadata = calxgloss_types::ScanMetadata::new("fixture-target");
        metadata.coverage = Some(coverage);
        let result = calxgloss_libmatch::types::LibmatchResult::new(metadata);
        calxgloss_libmatch::persist::LibmatchPersistor::new(ws.path())
            .save(&result)
            .expect("the hand-stamped libmatch document should be filed");
    };

    file_document(calxgloss_types::ScanCoverage {
        status: calxgloss_types::CoverageStatus::Partial,
        facets: vec![calxgloss_types::FacetCoverage {
            id: "function-bodies".to_string(),
            status: calxgloss_types::CoverageStatus::Partial,
            limitation: Some("1 function body unreached: FUN_180099000".to_string()),
        }],
    });
    let (ok, stdout, stderr) = run(
        cli(ws.path()).args([
            "--target-dir",
            ".",
            "libmatch",
            "--binary",
            "fixture-target",
            "--show",
        ]),
        ws.path(),
    );
    assert!(ok, "the libmatch show failed:\n{stdout}\n{stderr}");
    assert!(
        stdout.contains("Coverage:") && stdout.contains("1 function body unreached: FUN_180099000"),
        "the report prints the document's admission line beside the counts:\n{stdout}"
    );

    // A complete record is nothing to admit: no line at all.
    file_document(calxgloss_types::ScanCoverage {
        status: calxgloss_types::CoverageStatus::Complete,
        facets: vec![calxgloss_types::FacetCoverage {
            id: "function-bodies".to_string(),
            status: calxgloss_types::CoverageStatus::Complete,
            limitation: None,
        }],
    });
    let (ok, stdout, stderr) = run(
        cli(ws.path()).args([
            "--target-dir",
            ".",
            "libmatch",
            "--binary",
            "fixture-target",
            "--show",
        ]),
        ws.path(),
    );
    assert!(ok, "the libmatch show failed:\n{stdout}\n{stderr}");
    assert!(
        !stdout.contains("Coverage:"),
        "a complete record has nothing to admit:\n{stdout}"
    );
}

#[test]
fn the_floatsimd_report_prints_the_documents_admission_line_only_when_there_is_one() {
    // The floatsimd admission line at the process seam (issue #347),
    // pinned the same way as libmatch's: the `--show` report prints the
    // filed document's one bounded line, naming the never-reached
    // bodies, and prints nothing under a complete record — so the
    // flagless rows beside a complete count mean examined-and-clean.
    let ws = fixture_workspace();
    let file_document = |coverage: calxgloss_types::ScanCoverage| {
        let mut metadata = calxgloss_types::ScanMetadata::new("fixture-target");
        metadata.coverage = Some(coverage);
        let result = calxgloss_floatsimd::types::FloatsimdResult::new(metadata);
        calxgloss_floatsimd::persist::FloatsimdPersistor::new(ws.path())
            .save(&result)
            .expect("the hand-stamped float/SIMD document should be filed");
    };

    file_document(calxgloss_types::ScanCoverage {
        status: calxgloss_types::CoverageStatus::Partial,
        facets: vec![calxgloss_types::FacetCoverage {
            id: "function-bodies".to_string(),
            status: calxgloss_types::CoverageStatus::Partial,
            limitation: Some("2 function bodies unreached: FUN_99000, FUN_99100".to_string()),
        }],
    });
    let (ok, stdout, stderr) = run(
        cli(ws.path()).args([
            "--target-dir",
            ".",
            "floatsimd",
            "--binary",
            "fixture-target",
            "--show",
        ]),
        ws.path(),
    );
    assert!(ok, "the floatsimd show failed:\n{stdout}\n{stderr}");
    assert!(
        stdout.contains("Coverage:")
            && stdout.contains("2 function bodies unreached: FUN_99000, FUN_99100"),
        "the report prints the document's admission line beside the counts:\n{stdout}"
    );

    // A complete record is nothing to admit: no line at all.
    file_document(calxgloss_types::ScanCoverage {
        status: calxgloss_types::CoverageStatus::Complete,
        facets: vec![calxgloss_types::FacetCoverage {
            id: "function-bodies".to_string(),
            status: calxgloss_types::CoverageStatus::Complete,
            limitation: None,
        }],
    });
    let (ok, stdout, stderr) = run(
        cli(ws.path()).args([
            "--target-dir",
            ".",
            "floatsimd",
            "--binary",
            "fixture-target",
            "--show",
        ]),
        ws.path(),
    );
    assert!(ok, "the floatsimd show failed:\n{stdout}\n{stderr}");
    assert!(
        !stdout.contains("Coverage:"),
        "a complete record has nothing to admit:\n{stdout}"
    );
}

#[test]
fn the_typesdb_report_prints_the_documents_admission_line_only_when_there_is_one() {
    // The typesdb admission line at the process seam (issue #348): a
    // filed document's coverage record — however it got stamped — prints
    // its one bounded admission line beside the counts through `--show`,
    // and a complete record prints nothing. The documents here are filed
    // by the engine's own persistor with hand-stamped coverage, so the
    // pin does not depend on whether the fixture target carries RTTI.
    let ws = fixture_workspace();
    let file_document = |coverage: calxgloss_types::ScanCoverage| {
        let mut metadata = calxgloss_types::ScanMetadata::new("fixture-target");
        metadata.coverage = Some(coverage);
        let db = calxgloss_typesdb::types::TypeDatabase::new(metadata);
        calxgloss_typesdb::persist::TypeDatabasePersistor::new(ws.path())
            .save(&db)
            .expect("the hand-stamped type database should be filed");
    };

    file_document(calxgloss_types::ScanCoverage {
        status: calxgloss_types::CoverageStatus::Unavailable,
        facets: vec![calxgloss_types::FacetCoverage {
            id: "vtables".to_string(),
            status: calxgloss_types::CoverageStatus::Unavailable,
            limitation: Some("no vtable evidence on this target".to_string()),
        }],
    });
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
    assert!(ok, "the typesdb show failed:\n{stdout}\n{stderr}");
    assert!(
        stdout.contains("Inferred:"),
        "the counts still print as they always did:\n{stdout}"
    );
    assert!(
        stdout.contains("Coverage:")
            && stdout.contains("unavailable — no vtable evidence on this target"),
        "the report prints the document's admission line beside the counts:\n{stdout}"
    );

    // A complete record is nothing to admit: no line at all.
    file_document(calxgloss_types::ScanCoverage {
        status: calxgloss_types::CoverageStatus::Complete,
        facets: vec![calxgloss_types::FacetCoverage {
            id: "vtables".to_string(),
            status: calxgloss_types::CoverageStatus::Complete,
            limitation: None,
        }],
    });
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
    assert!(ok, "the typesdb show failed:\n{stdout}\n{stderr}");
    assert!(
        !stdout.contains("Coverage:"),
        "a complete record has nothing to admit:\n{stdout}"
    );
}

#[test]
fn the_consts_report_prints_the_documents_admission_line_only_when_there_is_one() {
    // The consts admission line at the process seam (issue #348), pinned
    // the same way: the `--show` report prints the filed document's one
    // bounded line — the whole picture's admission, naming both regions
    // the scan could not read — and prints nothing under a complete
    // record, so an empty findings list beside a complete count means
    // examined-and-clean.
    let ws = fixture_workspace();
    let file_document = |coverage: calxgloss_types::ScanCoverage| {
        let mut metadata = calxgloss_types::ScanMetadata::new("fixture-target");
        metadata.coverage = Some(coverage);
        let result = calxgloss_consts::types::ConstResult::new(metadata);
        calxgloss_consts::persist::ConstPersistor::new(ws.path())
            .save(&result)
            .expect("the hand-stamped constant result should be filed");
    };

    file_document(calxgloss_types::ScanCoverage {
        status: calxgloss_types::CoverageStatus::Partial,
        facets: vec![
            calxgloss_types::FacetCoverage {
                id: "function-bodies".to_string(),
                status: calxgloss_types::CoverageStatus::Partial,
                limitation: Some("2 function bodies unreached: FUN_99000, FUN_99100".to_string()),
            },
            calxgloss_types::FacetCoverage {
                id: "data-objects".to_string(),
                status: calxgloss_types::CoverageStatus::Partial,
                limitation: Some(
                    "1 data-object memory window unreadable: DAT_1400a1c00".to_string(),
                ),
            },
        ],
    });
    let (ok, stdout, stderr) = run(
        cli(ws.path()).args([
            "--target-dir",
            ".",
            "consts",
            "--binary",
            "fixture-target",
            "--show",
        ]),
        ws.path(),
    );
    assert!(ok, "the consts show failed:\n{stdout}\n{stderr}");
    assert!(
        stdout.contains("Findings:"),
        "the counts still print as they always did:\n{stdout}"
    );
    assert!(
        stdout.contains("Coverage:")
            && stdout.contains("2 function bodies unreached: FUN_99000, FUN_99100")
            && stdout.contains("1 data-object memory window unreadable: DAT_1400a1c00"),
        "the report prints the document's one admission line, both regions in it:\n{stdout}"
    );

    // A complete record is nothing to admit: no line at all.
    file_document(calxgloss_types::ScanCoverage {
        status: calxgloss_types::CoverageStatus::Complete,
        facets: vec![
            calxgloss_types::FacetCoverage {
                id: "function-bodies".to_string(),
                status: calxgloss_types::CoverageStatus::Complete,
                limitation: None,
            },
            calxgloss_types::FacetCoverage {
                id: "data-objects".to_string(),
                status: calxgloss_types::CoverageStatus::Complete,
                limitation: None,
            },
        ],
    });
    let (ok, stdout, stderr) = run(
        cli(ws.path()).args([
            "--target-dir",
            ".",
            "consts",
            "--binary",
            "fixture-target",
            "--show",
        ]),
        ws.path(),
    );
    assert!(ok, "the consts show failed:\n{stdout}\n{stderr}");
    assert!(
        !stdout.contains("Coverage:"),
        "a complete record has nothing to admit:\n{stdout}"
    );
}

#[test]
fn the_controlflow_report_prints_the_documents_admission_line_only_when_there_is_one() {
    // The control-flow admission line at the process seam (issue #349):
    // the `--show` report prints the filed document's one bounded line,
    // naming the never-reached bodies, and prints nothing under a
    // complete record — pinned through the engine's own persistor so it
    // does not depend on which bodies the fixture happens to decompile.
    let ws = fixture_workspace();
    let file_document = |coverage: calxgloss_types::ScanCoverage| {
        let mut metadata = calxgloss_types::ScanMetadata::new("fixture-target");
        metadata.coverage = Some(coverage);
        let result = calxgloss_controlflow::types::ControlFlowResult::new(metadata);
        calxgloss_controlflow::persist::ControlFlowPersistor::new(ws.path())
            .save(&result)
            .expect("the hand-stamped control-flow document should be filed");
    };

    file_document(calxgloss_types::ScanCoverage {
        status: calxgloss_types::CoverageStatus::Partial,
        facets: vec![calxgloss_types::FacetCoverage {
            id: "function-bodies".to_string(),
            status: calxgloss_types::CoverageStatus::Partial,
            limitation: Some("1 function body unreached: FUN_1800412a0".to_string()),
        }],
    });
    let (ok, stdout, stderr) = run(
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
    assert!(ok, "the controlflow show failed:\n{stdout}\n{stderr}");
    assert!(
        stdout.contains("Coverage:") && stdout.contains("1 function body unreached: FUN_1800412a0"),
        "the report prints the document's admission line beside the counts:\n{stdout}"
    );

    // A complete record is nothing to admit: no line at all.
    file_document(calxgloss_types::ScanCoverage {
        status: calxgloss_types::CoverageStatus::Complete,
        facets: vec![calxgloss_types::FacetCoverage {
            id: "function-bodies".to_string(),
            status: calxgloss_types::CoverageStatus::Complete,
            limitation: None,
        }],
    });
    let (ok, stdout, stderr) = run(
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
    assert!(ok, "the controlflow show failed:\n{stdout}\n{stderr}");
    assert!(
        !stdout.contains("Coverage:"),
        "a complete record has nothing to admit:\n{stdout}"
    );
}

#[test]
fn the_memory_report_prints_the_documents_admission_line_only_when_there_is_one() {
    // The memory-lifecycle admission line at the process seam (issue
    // #349), pinned the same way as control-flow's: the `--show` report
    // prints the filed document's one bounded line naming the skipped
    // bodies, and prints nothing under a complete record.
    let ws = fixture_workspace();
    let file_document = |coverage: calxgloss_types::ScanCoverage| {
        let mut metadata = calxgloss_types::ScanMetadata::new("fixture-target");
        metadata.coverage = Some(coverage);
        let result = calxgloss_memory::types::MemoryResult::new(metadata);
        calxgloss_memory::persist::MemoryPersistor::new(ws.path())
            .save(&result)
            .expect("the hand-stamped memory document should be filed");
    };

    file_document(calxgloss_types::ScanCoverage {
        status: calxgloss_types::CoverageStatus::Partial,
        facets: vec![calxgloss_types::FacetCoverage {
            id: "function-bodies".to_string(),
            status: calxgloss_types::CoverageStatus::Partial,
            limitation: Some("2 function bodies unreached: FUN_180049abc, FUN_18004def0".to_string()),
        }],
    });
    let (ok, stdout, stderr) = run(
        cli(ws.path()).args([
            "--target-dir",
            ".",
            "memory",
            "--binary",
            "fixture-target",
            "--show",
        ]),
        ws.path(),
    );
    assert!(ok, "the memory show failed:\n{stdout}\n{stderr}");
    assert!(
        stdout.contains("Coverage:")
            && stdout.contains("2 function bodies unreached: FUN_180049abc, FUN_18004def0"),
        "the report prints the document's admission line beside the counts:\n{stdout}"
    );

    // A complete record is nothing to admit: no line at all.
    file_document(calxgloss_types::ScanCoverage {
        status: calxgloss_types::CoverageStatus::Complete,
        facets: vec![calxgloss_types::FacetCoverage {
            id: "function-bodies".to_string(),
            status: calxgloss_types::CoverageStatus::Complete,
            limitation: None,
        }],
    });
    let (ok, stdout, stderr) = run(
        cli(ws.path()).args([
            "--target-dir",
            ".",
            "memory",
            "--binary",
            "fixture-target",
            "--show",
        ]),
        ws.path(),
    );
    assert!(ok, "the memory show failed:\n{stdout}\n{stderr}");
    assert!(
        !stdout.contains("Coverage:"),
        "a complete record has nothing to admit:\n{stdout}"
    );
}

#[test]
fn the_sync_report_prints_the_documents_admission_line_only_when_there_is_one() {
    // The concurrency admission line at the process seam (issue #349),
    // pinned the same way: the `--show` report prints the filed
    // document's one bounded line, and prints nothing under a complete
    // record — so the flagless rows beside a complete count mean
    // examined-and-clean.
    let ws = fixture_workspace();
    let file_document = |coverage: calxgloss_types::ScanCoverage| {
        let mut metadata = calxgloss_types::ScanMetadata::new("fixture-target");
        metadata.coverage = Some(coverage);
        let result = calxgloss_sync::types::SyncResult::new(metadata);
        calxgloss_sync::persist::SyncPersistor::new(ws.path())
            .save(&result)
            .expect("the hand-stamped sync document should be filed");
    };

    file_document(calxgloss_types::ScanCoverage {
        status: calxgloss_types::CoverageStatus::Partial,
        facets: vec![calxgloss_types::FacetCoverage {
            id: "function-bodies".to_string(),
            status: calxgloss_types::CoverageStatus::Partial,
            limitation: Some("1 function body unreached: FUN_18003e999".to_string()),
        }],
    });
    let (ok, stdout, stderr) = run(
        cli(ws.path()).args([
            "--target-dir",
            ".",
            "sync",
            "--binary",
            "fixture-target",
            "--show",
        ]),
        ws.path(),
    );
    assert!(ok, "the sync show failed:\n{stdout}\n{stderr}");
    assert!(
        stdout.contains("Coverage:") && stdout.contains("1 function body unreached: FUN_18003e999"),
        "the report prints the document's admission line beside the counts:\n{stdout}"
    );

    // A complete record is nothing to admit: no line at all.
    file_document(calxgloss_types::ScanCoverage {
        status: calxgloss_types::CoverageStatus::Complete,
        facets: vec![calxgloss_types::FacetCoverage {
            id: "function-bodies".to_string(),
            status: calxgloss_types::CoverageStatus::Complete,
            limitation: None,
        }],
    });
    let (ok, stdout, stderr) = run(
        cli(ws.path()).args([
            "--target-dir",
            ".",
            "sync",
            "--binary",
            "fixture-target",
            "--show",
        ]),
        ws.path(),
    );
    assert!(ok, "the sync show failed:\n{stdout}\n{stderr}");
    assert!(
        !stdout.contains("Coverage:"),
        "a complete record has nothing to admit:\n{stdout}"
    );
}

#[test]
fn the_globalstate_report_prints_the_documents_admission_line_only_when_there_is_one() {
    // The global-state admission line at the process seam (issue #350):
    // the `--show` report prints the filed document's one bounded line,
    // naming the never-reached bodies, and prints nothing under a
    // complete record — pinned through the engine's own persistor so it
    // does not depend on which bodies the fixture happens to decompile.
    let ws = fixture_workspace();
    let file_document = |coverage: calxgloss_types::ScanCoverage| {
        let mut metadata = calxgloss_types::ScanMetadata::new("fixture-target");
        metadata.coverage = Some(coverage);
        let result = calxgloss_globalstate::types::GlobalStateResult::new(metadata);
        calxgloss_globalstate::persist::GlobalStatePersistor::new(ws.path())
            .save(&result)
            .expect("the hand-stamped global-state document should be filed");
    };

    file_document(calxgloss_types::ScanCoverage {
        status: calxgloss_types::CoverageStatus::Partial,
        facets: vec![calxgloss_types::FacetCoverage {
            id: "function-bodies".to_string(),
            status: calxgloss_types::CoverageStatus::Partial,
            limitation: Some("1 function body unreached: FUN_180045670".to_string()),
        }],
    });
    let (ok, stdout, stderr) = run(
        cli(ws.path()).args([
            "--target-dir",
            ".",
            "global-state",
            "--binary",
            "fixture-target",
            "--show",
        ]),
        ws.path(),
    );
    assert!(ok, "the global-state show failed:\n{stdout}\n{stderr}");
    assert!(
        stdout.contains("Coverage:") && stdout.contains("1 function body unreached: FUN_180045670"),
        "the report prints the document's admission line beside the counts:\n{stdout}"
    );

    // A complete record is nothing to admit: no line at all.
    file_document(calxgloss_types::ScanCoverage {
        status: calxgloss_types::CoverageStatus::Complete,
        facets: vec![calxgloss_types::FacetCoverage {
            id: "function-bodies".to_string(),
            status: calxgloss_types::CoverageStatus::Complete,
            limitation: None,
        }],
    });
    let (ok, stdout, stderr) = run(
        cli(ws.path()).args([
            "--target-dir",
            ".",
            "global-state",
            "--binary",
            "fixture-target",
            "--show",
        ]),
        ws.path(),
    );
    assert!(ok, "the global-state show failed:\n{stdout}\n{stderr}");
    assert!(
        !stdout.contains("Coverage:"),
        "a complete record has nothing to admit:\n{stdout}"
    );
}

#[test]
fn the_errhandling_report_prints_the_documents_admission_line_only_when_there_is_one() {
    // The error-handling admission line at the process seam (issue
    // #350), pinned the same way as global-state's: the `--show` report
    // prints the filed document's one bounded line naming the skipped
    // bodies, and prints nothing under a complete record.
    let ws = fixture_workspace();
    let file_document = |coverage: calxgloss_types::ScanCoverage| {
        let mut metadata = calxgloss_types::ScanMetadata::new("fixture-target");
        metadata.coverage = Some(coverage);
        let result = calxgloss_errhandling::types::ErrhandlingResult::new(metadata);
        calxgloss_errhandling::persist::ErrhandlingPersistor::new(ws.path())
            .save(&result)
            .expect("the hand-stamped error-handling document should be filed");
    };

    file_document(calxgloss_types::ScanCoverage {
        status: calxgloss_types::CoverageStatus::Partial,
        facets: vec![calxgloss_types::FacetCoverage {
            id: "function-bodies".to_string(),
            status: calxgloss_types::CoverageStatus::Partial,
            limitation: Some(
                "2 function bodies unreached: FUN_18004abcd, FUN_18006beef".to_string(),
            ),
        }],
    });
    let (ok, stdout, stderr) = run(
        cli(ws.path()).args([
            "--target-dir",
            ".",
            "errhandling",
            "--binary",
            "fixture-target",
            "--show",
        ]),
        ws.path(),
    );
    assert!(ok, "the errhandling show failed:\n{stdout}\n{stderr}");
    assert!(
        stdout.contains("Coverage:")
            && stdout.contains("2 function bodies unreached: FUN_18004abcd, FUN_18006beef"),
        "the report prints the document's admission line beside the counts:\n{stdout}"
    );

    // A complete record is nothing to admit: no line at all.
    file_document(calxgloss_types::ScanCoverage {
        status: calxgloss_types::CoverageStatus::Complete,
        facets: vec![calxgloss_types::FacetCoverage {
            id: "function-bodies".to_string(),
            status: calxgloss_types::CoverageStatus::Complete,
            limitation: None,
        }],
    });
    let (ok, stdout, stderr) = run(
        cli(ws.path()).args([
            "--target-dir",
            ".",
            "errhandling",
            "--binary",
            "fixture-target",
            "--show",
        ]),
        ws.path(),
    );
    assert!(ok, "the errhandling show failed:\n{stdout}\n{stderr}");
    assert!(
        !stdout.contains("Coverage:"),
        "a complete record has nothing to admit:\n{stdout}"
    );
}

#[test]
fn the_callback_report_prints_the_documents_admission_line_only_when_there_is_one() {
    // The callback-detection admission line at the process seam (issue
    // #350), pinned the same way: the `--show` report prints the filed
    // document's one bounded line, and prints nothing under a complete
    // record — so the flagless counts beside a complete record mean
    // examined-and-clean.
    let ws = fixture_workspace();
    let file_document = |coverage: calxgloss_types::ScanCoverage| {
        let mut metadata = calxgloss_types::ScanMetadata::new("fixture-target");
        metadata.coverage = Some(coverage);
        let result = calxgloss_callback::types::CallbackResult::new(metadata);
        calxgloss_callback::persist::CallbackPersistor::new(ws.path())
            .save(&result)
            .expect("the hand-stamped callback document should be filed");
    };

    file_document(calxgloss_types::ScanCoverage {
        status: calxgloss_types::CoverageStatus::Partial,
        facets: vec![calxgloss_types::FacetCoverage {
            id: "function-bodies".to_string(),
            status: calxgloss_types::CoverageStatus::Partial,
            limitation: Some("1 function body unreached: FUN_180050001".to_string()),
        }],
    });
    let (ok, stdout, stderr) = run(
        cli(ws.path()).args([
            "--target-dir",
            ".",
            "callback",
            "--binary",
            "fixture-target",
            "--show",
        ]),
        ws.path(),
    );
    assert!(ok, "the callback show failed:\n{stdout}\n{stderr}");
    assert!(
        stdout.contains("Coverage:") && stdout.contains("1 function body unreached: FUN_180050001"),
        "the report prints the document's admission line beside the counts:\n{stdout}"
    );

    // A complete record is nothing to admit: no line at all.
    file_document(calxgloss_types::ScanCoverage {
        status: calxgloss_types::CoverageStatus::Complete,
        facets: vec![calxgloss_types::FacetCoverage {
            id: "function-bodies".to_string(),
            status: calxgloss_types::CoverageStatus::Complete,
            limitation: None,
        }],
    });
    let (ok, stdout, stderr) = run(
        cli(ws.path()).args([
            "--target-dir",
            ".",
            "callback",
            "--binary",
            "fixture-target",
            "--show",
        ]),
        ws.path(),
    );
    assert!(ok, "the callback show failed:\n{stdout}\n{stderr}");
    assert!(
        !stdout.contains("Coverage:"),
        "a complete record has nothing to admit:\n{stdout}"
    );
}

#[test]
fn the_typesdb_and_consts_reports_read_their_own_scans_coverage_run_and_show_alike() {
    // The two rides' own stamps at the process seam (issue #348): each
    // scan files the record it stamped, and the run's report and a later
    // `--show` report stay the byte-identical same read — admission line
    // when the scan owes one, silence when it does not.
    for command in ["typesdb", "consts"] {
        let ws = fixture_workspace();
        let (ok, stdout, stderr) = run(
            cli(ws.path()).args(["--target-dir", ".", command, "--binary", "fixture-target"]),
            ws.path(),
        );
        assert!(ok, "the {command} ride failed:\n{stdout}\n{stderr}");
        let (ok, show_stdout, stderr) = run(
            cli(ws.path()).args([
                "--target-dir",
                ".",
                command,
                "--binary",
                "fixture-target",
                "--show",
            ]),
            ws.path(),
        );
        assert!(ok, "the {command} show failed:\n{show_stdout}\n{stderr}");
        assert_eq!(
            stdout, show_stdout,
            "the {command} run's report and a later --show report are the same \
             read of the same document, coverage included"
        );
    }
}

#[test]
fn the_libmatch_and_floatsimd_rides_report_run_and_show_identically() {
    // The run-equals-show doctrine holds for both engines' new stamps
    // (issue #347): whatever coverage the fixture's real scans stamp,
    // the run's report and a later `--show` report are the same read of
    // the same document — admission line and all, or its absence.
    for command in ["libmatch", "floatsimd"] {
        let ws = fixture_workspace();
        let (ok, stdout, stderr) = run(
            cli(ws.path()).args(["--target-dir", ".", command, "--binary", "fixture-target"]),
            ws.path(),
        );
        assert!(ok, "the {command} ride failed:\n{stdout}\n{stderr}");

        let (ok, show_stdout, stderr) = run(
            cli(ws.path()).args([
                "--target-dir",
                ".",
                command,
                "--binary",
                "fixture-target",
                "--show",
            ]),
            ws.path(),
        );
        assert!(ok, "the {command} show failed:\n{show_stdout}\n{stderr}");
        assert_eq!(
            stdout, show_stdout,
            "the {command} run's report and a later --show report are the same \
             read of the same document"
        );
    }
}

#[test]
fn the_controlflow_memory_and_sync_rides_report_run_and_show_identically() {
    // The run-equals-show doctrine holds for the fan-out trio's own
    // stamps (issue #349): whatever coverage the fixture's real scans
    // stamp, the run's report and a later `--show` report are the same
    // read of the same document — admission line and all, or its
    // absence.
    for command in ["controlflow", "memory", "sync"] {
        let ws = fixture_workspace();
        let (ok, stdout, stderr) = run(
            cli(ws.path()).args(["--target-dir", ".", command, "--binary", "fixture-target"]),
            ws.path(),
        );
        assert!(ok, "the {command} ride failed:\n{stdout}\n{stderr}");

        let (ok, show_stdout, stderr) = run(
            cli(ws.path()).args([
                "--target-dir",
                ".",
                command,
                "--binary",
                "fixture-target",
                "--show",
            ]),
            ws.path(),
        );
        assert!(ok, "the {command} show failed:\n{show_stdout}\n{stderr}");
        assert_eq!(
            stdout, show_stdout,
            "the {command} run's report and a later --show report are the same \
             read of the same document, coverage included"
        );
    }
}

#[test]
fn the_globalstate_errhandling_and_callback_rides_report_run_and_show_identically() {
    // The run-equals-show doctrine holds for the fan-out B trio's own
    // stamps (issue #350): whatever coverage the fixture's real scans
    // stamp, the run's report and a later `--show` report are the same
    // read of the same document — admission line and all, or its
    // absence.
    for command in ["global-state", "errhandling", "callback"] {
        let ws = fixture_workspace();
        if command == "callback" {
            // The callback ride's pre-scan hook reads the type-inference
            // document for signature enrichment and warns when it is
            // absent — scan-side log noise on the tracing stream, not
            // report bytes. Filing the empty document through its own
            // persistor keeps the run's stdout to just the report, so
            // run and --show compare byte for byte.
            let result = calxgloss_typeinfer::types::TypeInferenceResult::new(
                calxgloss_types::ScanMetadata::new("fixture-target"),
            );
            calxgloss_typeinfer::persist::TypeInferPersistor::new(ws.path())
                .save(&result)
                .expect("the empty type-inference document should be filed");
        }
        let (ok, stdout, stderr) = run(
            cli(ws.path()).args(["--target-dir", ".", command, "--binary", "fixture-target"]),
            ws.path(),
        );
        assert!(ok, "the {command} ride failed:\n{stdout}\n{stderr}");

        let (ok, show_stdout, stderr) = run(
            cli(ws.path()).args([
                "--target-dir",
                ".",
                command,
                "--binary",
                "fixture-target",
                "--show",
            ]),
            ws.path(),
        );
        assert!(ok, "the {command} show failed:\n{show_stdout}\n{stderr}");
        assert_eq!(
            stdout, show_stdout,
            "the {command} run's report and a later --show report are the same \
             read of the same document, coverage included"
        );
    }
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
