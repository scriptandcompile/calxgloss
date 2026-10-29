//! Behavior tests over the generic scan command at the process seam
//! (issues #339–#341, spec #337). The built CLI runs each scan through its
//! fixture target in a temp workspace, and the tests assert only outward
//! results: whether the process succeeded or failed, the document filed
//! at the row's own path, the printed report, and the failure and
//! remediation wording. The run's report and a later `--show` report must
//! be the same read of the same document.

use std::path::Path;
use std::process::Command;

/// Run the built CLI isolated from the ambient config. The user's global
/// config file may hold anything, so each test points `CALXGLOSS_CONFIG`
/// at an empty file in its own temp dir and removes the target and
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

/// A workspace with a copy of the fixture target at its root, which also
/// serves as the target dir. The persistor names its file
/// `{binary}.json` literally, so a path-shaped name would file the
/// document outside the workspace. This is the same layout the control-flow
/// process test uses.
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
    assert!(ok, "the typesdb scan failed:\n{stdout}\n{stderr}");

    // The document sits at the row's own path, and beside it is the
    // declarations file — the entry's only side effect.
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
    // The remediation wording at the process seam. The workspace is fresh,
    // no scan has ever run, and the failure tells the operator the exact
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
    // One of the eleven flag-free commands moved onto the generic handler
    // (issue #340), seen here at the process seam: `controlflow` scans the
    // fixture and files its document at the row's own path, and the run's
    // report and a later `--show` report are byte-identical — the same read
    // of the same document. The command's entry builds no evidence engine
    // of its own: that build stays the descriptor row's.
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
    assert!(ok, "the controlflow scan failed:\n{stdout}\n{stderr}");
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
    // The apidetect admission line at the process seam (issue #346). The
    // scan records its coverage in the document it files. Both the run's
    // report and a later `--show` report print that document's one bounded
    // admission line beside the counts, byte-identically, because both are
    // the same read of the same document.
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
    assert!(ok, "the apidetect scan failed:\n{stdout}\n{stderr}");
    let document = ws.path().join("re/analysis/apidetect/fixture-target.json");
    assert!(document.is_file(), "the document is filed at {document:?}");

    // The limitation line prints beside the counts, and it names the facet
    // the scan never examines — the admission the scan owes. The label and
    // the admission text print in different styles, so the assertion checks
    // each piece as printed, never the two joined across the styling codes.
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
    // The libmatch admission line at the process seam (issue #347). Whatever
    // a filed document's coverage record says, `--show` prints its one
    // bounded admission line beside the counts. A complete record prints
    // nothing. Here the test files each document through the evidence engine's
    // own persistor, with the coverage written by hand, so the pin does not
    // depend on which function bodies the fixture's real decompile happens to
    // produce.
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
    // The floatsimd admission line at the process seam (issue #347), pinned
    // the same way as libmatch's: the `--show` report prints the filed
    // document's one bounded line, which names the function bodies the scan
    // never reached, and prints nothing under a complete record. So rows
    // without a limitation line beside a complete count mean the scan looked
    // at them and found nothing to admit.
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
    // The typesdb admission line at the process seam (issue #348). Whatever
    // a filed document's coverage record says, `--show` prints its one
    // bounded admission line beside the counts. A complete record prints
    // nothing. Here the test files each document through the evidence engine's
    // own persistor, with the coverage written by hand, so the pin does not
    // depend on whether the fixture target has RTTI.
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
    // the same way. The `--show` report prints the filed document's one
    // bounded line: it is the whole scan's admission, and it names both
    // regions the scan could not read. Under a complete record it prints
    // nothing, so an empty findings list beside a complete count means
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
    // The control-flow admission line at the process seam (issue #349). The
    // `--show` report prints the filed document's one bounded line, which
    // names the function bodies the scan never reached, and it prints
    // nothing under a complete record. The test files the document through
    // the evidence engine's own persistor, so the pin does not depend on
    // which bodies the fixture happens to decompile.
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
    // The memory-lifecycle admission line at the process seam (issue #349),
    // pinned the same way as control-flow's. The `--show` report prints the
    // filed document's one bounded line naming the function bodies the scan
    // never reached, and it prints nothing under a complete record.
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
            limitation: Some(
                "2 function bodies unreached: FUN_180049abc, FUN_18004def0".to_string(),
            ),
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
    // pinned the same way. The `--show` report prints the filed document's
    // one bounded line, and it prints nothing under a complete record — so
    // rows without a limitation line beside a complete count mean the scan
    // looked at them and found nothing to admit.
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
    // The global-state admission line at the process seam (issue #350). The
    // `--show` report prints the filed document's one bounded line, which
    // names the function bodies the scan never reached, and it prints
    // nothing under a complete record. The test files the document through
    // the evidence engine's own persistor, so the pin does not depend on
    // which bodies the fixture happens to decompile.
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
    // The error-handling admission line at the process seam (issue #350),
    // pinned the same way as global-state's. The `--show` report prints the
    // filed document's one bounded line naming the function bodies the scan
    // never reached, and it prints nothing under a complete record.
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
    // #350), pinned the same way. The `--show` report prints the filed
    // document's one bounded line and prints nothing under a complete
    // record, so counts without a limitation line beside a complete record
    // mean the scan looked at everything and found nothing to admit.
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
fn the_algorithm_report_prints_the_documents_admission_line_only_when_there_is_one() {
    // The algorithm-recognition admission line at the process seam (issue
    // #351). The `--show` report prints the filed document's one bounded
    // line, which names the function bodies the scan never reached and the
    // caller edges it could not read, and it prints nothing under a complete
    // record. The test files the document through the evidence engine's own
    // persistor, so the pin does not depend on which bodies the fixture
    // happens to decompile.
    let ws = fixture_workspace();
    let file_document = |coverage: calxgloss_types::ScanCoverage| {
        let mut metadata = calxgloss_types::ScanMetadata::new("fixture-target");
        metadata.coverage = Some(coverage);
        let result = calxgloss_algorithm::types::AlgorithmRecognitionResult::new(metadata);
        calxgloss_algorithm::persist::AlgorithmPersistor::new(ws.path())
            .save(&result)
            .expect("the hand-stamped algorithm document should be filed");
    };

    file_document(calxgloss_types::ScanCoverage {
        status: calxgloss_types::CoverageStatus::Partial,
        facets: vec![
            calxgloss_types::FacetCoverage {
                id: "function-bodies".to_string(),
                status: calxgloss_types::CoverageStatus::Partial,
                limitation: Some("1 function body unreached: FUN_180070010".to_string()),
            },
            calxgloss_types::FacetCoverage {
                id: "caller-edges".to_string(),
                status: calxgloss_types::CoverageStatus::Unavailable,
                limitation: Some("1 caller edge unreadable: FUN_180070020".to_string()),
            },
        ],
    });
    let (ok, stdout, stderr) = run(
        cli(ws.path()).args([
            "--target-dir",
            ".",
            "algorithm",
            "--binary",
            "fixture-target",
            "--show",
        ]),
        ws.path(),
    );
    assert!(ok, "the algorithm show failed:\n{stdout}\n{stderr}");
    assert!(
        stdout.contains("Coverage:")
            && stdout.contains("1 function body unreached: FUN_180070010")
            && stdout.contains("1 caller edge unreadable: FUN_180070020"),
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
            "algorithm",
            "--binary",
            "fixture-target",
            "--show",
        ]),
        ws.path(),
    );
    assert!(ok, "the algorithm show failed:\n{stdout}\n{stderr}");
    assert!(
        !stdout.contains("Coverage:"),
        "a complete record has nothing to admit:\n{stdout}"
    );
}

#[test]
fn the_stringctx_report_prints_the_documents_admission_line_only_when_there_is_one() {
    // The string-context admission line at the process seam (issue #351).
    // Its three-facet record prints beside the counts: function bodies the
    // scan never read, a program string listing the scan could not read, and
    // string cross-references that could not be read. A complete record
    // prints nothing. It files the document through the evidence engine's own
    // persistor, as every pin in this family does.
    let ws = fixture_workspace();
    let file_document = |coverage: calxgloss_types::ScanCoverage| {
        let mut metadata = calxgloss_types::ScanMetadata::new("fixture-target");
        metadata.coverage = Some(coverage);
        let result = calxgloss_stringctx::types::StringContextResult::new(metadata);
        calxgloss_stringctx::persist::StringContextPersistor::new(ws.path())
            .save(&result)
            .expect("the hand-stamped string-context document should be filed");
    };

    file_document(calxgloss_types::ScanCoverage {
        status: calxgloss_types::CoverageStatus::Partial,
        facets: vec![
            calxgloss_types::FacetCoverage {
                id: "function-bodies".to_string(),
                status: calxgloss_types::CoverageStatus::Partial,
                limitation: Some("1 function body unreached: FUN_180061000".to_string()),
            },
            calxgloss_types::FacetCoverage {
                id: "program-strings".to_string(),
                status: calxgloss_types::CoverageStatus::Unavailable,
                limitation: Some("program string listing unreadable".to_string()),
            },
            calxgloss_types::FacetCoverage {
                id: "string-xrefs".to_string(),
                status: calxgloss_types::CoverageStatus::Unavailable,
                limitation: Some("no string cross-reference could be read".to_string()),
            },
        ],
    });
    let (ok, stdout, stderr) = run(
        cli(ws.path()).args([
            "--target-dir",
            ".",
            "stringctx",
            "--binary",
            "fixture-target",
            "--show",
        ]),
        ws.path(),
    );
    assert!(ok, "the stringctx show failed:\n{stdout}\n{stderr}");
    assert!(
        stdout.contains("Coverage:")
            && stdout.contains("1 function body unreached: FUN_180061000")
            && stdout.contains("program string listing unreadable")
            && stdout.contains("no string cross-reference could be read"),
        "the report prints the document's admission line beside the counts:\n{stdout}"
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
                id: "program-strings".to_string(),
                status: calxgloss_types::CoverageStatus::Complete,
                limitation: None,
            },
            calxgloss_types::FacetCoverage {
                id: "string-xrefs".to_string(),
                status: calxgloss_types::CoverageStatus::Complete,
                limitation: None,
            },
        ],
    });
    let (ok, stdout, stderr) = run(
        cli(ws.path()).args([
            "--target-dir",
            ".",
            "stringctx",
            "--binary",
            "fixture-target",
            "--show",
        ]),
        ws.path(),
    );
    assert!(ok, "the stringctx show failed:\n{stdout}\n{stderr}");
    assert!(
        !stdout.contains("Coverage:"),
        "a complete record has nothing to admit:\n{stdout}"
    );
}

#[test]
fn the_serialize_report_prints_the_documents_admission_line_only_when_there_is_one() {
    // The serialization-pattern admission line at the process seam (issue
    // #351). The test files the document through the evidence engine's own
    // persistor.
    let ws = fixture_workspace();
    let file_document = |coverage: calxgloss_types::ScanCoverage| {
        let mut metadata = calxgloss_types::ScanMetadata::new("fixture-target");
        metadata.coverage = Some(coverage);
        let result = calxgloss_serialize::types::SerializeResult::new(metadata);
        calxgloss_serialize::persist::SerializePersistor::new(ws.path())
            .save(&result)
            .expect("the hand-stamped serialization document should be filed");
    };

    file_document(calxgloss_types::ScanCoverage {
        status: calxgloss_types::CoverageStatus::Partial,
        facets: vec![calxgloss_types::FacetCoverage {
            id: "function-bodies".to_string(),
            status: calxgloss_types::CoverageStatus::Partial,
            limitation: Some("1 function body unreached: FUN_180099900".to_string()),
        }],
    });
    let (ok, stdout, stderr) = run(
        cli(ws.path()).args([
            "--target-dir",
            ".",
            "serialize",
            "--binary",
            "fixture-target",
            "--show",
        ]),
        ws.path(),
    );
    assert!(ok, "the serialize show failed:\n{stdout}\n{stderr}");
    assert!(
        stdout.contains("Coverage:") && stdout.contains("1 function body unreached: FUN_180099900"),
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
            "serialize",
            "--binary",
            "fixture-target",
            "--show",
        ]),
        ws.path(),
    );
    assert!(ok, "the serialize show failed:\n{stdout}\n{stderr}");
    assert!(
        !stdout.contains("Coverage:"),
        "a complete record has nothing to admit:\n{stdout}"
    );
}

#[test]
fn the_typeinfer_report_prints_the_documents_admission_line_only_when_there_is_one() {
    // The type-inference admission line at the process seam (issue #351). The
    // four-facet record prints, and its complete `function-bodies` facet adds
    // nothing to admit; a complete record prints no line at all. This test
    // runs along the scan-and-show path the write-back ticket's own test
    // already pins. This pin only shows that the admission line prints beside
    // the counts when the filed document has one to admit.
    let ws = fixture_workspace();
    let file_document = |coverage: calxgloss_types::ScanCoverage| {
        let mut metadata = calxgloss_types::ScanMetadata::new("fixture-target");
        metadata.coverage = Some(coverage);
        let result = calxgloss_typeinfer::types::TypeInferenceResult::new(metadata);
        calxgloss_typeinfer::persist::TypeInferPersistor::new(ws.path())
            .save(&result)
            .expect("the hand-stamped type-inference document should be filed");
    };

    file_document(calxgloss_types::ScanCoverage {
        status: calxgloss_types::CoverageStatus::Partial,
        facets: vec![
            calxgloss_types::FacetCoverage {
                id: "function-bodies".to_string(),
                status: calxgloss_types::CoverageStatus::Complete,
                limitation: None,
            },
            calxgloss_types::FacetCoverage {
                id: "machine-listings".to_string(),
                status: calxgloss_types::CoverageStatus::Partial,
                limitation: Some("1 machine listing unreadable: FUN_180088000".to_string()),
            },
            calxgloss_types::FacetCoverage {
                id: "import-names".to_string(),
                status: calxgloss_types::CoverageStatus::Unavailable,
                limitation: Some("import listing unreadable".to_string()),
            },
            calxgloss_types::FacetCoverage {
                id: "caller-edges".to_string(),
                status: calxgloss_types::CoverageStatus::Unavailable,
                limitation: Some("1 caller edge unreadable: FUN_180088010".to_string()),
            },
        ],
    });
    let (ok, stdout, stderr) = run(
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
    assert!(ok, "the typeinfer show failed:\n{stdout}\n{stderr}");
    assert!(
        stdout.contains("Coverage:")
            && stdout.contains("1 machine listing unreadable: FUN_180088000")
            && stdout.contains("import listing unreadable")
            && stdout.contains("1 caller edge unreadable: FUN_180088010"),
        "the report prints the document's admission line beside the counts:\n{stdout}"
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
                id: "machine-listings".to_string(),
                status: calxgloss_types::CoverageStatus::Complete,
                limitation: None,
            },
            calxgloss_types::FacetCoverage {
                id: "import-names".to_string(),
                status: calxgloss_types::CoverageStatus::Complete,
                limitation: None,
            },
            calxgloss_types::FacetCoverage {
                id: "caller-edges".to_string(),
                status: calxgloss_types::CoverageStatus::Complete,
                limitation: None,
            },
        ],
    });
    let (ok, stdout, stderr) = run(
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
    assert!(ok, "the typeinfer show failed:\n{stdout}\n{stderr}");
    assert!(
        !stdout.contains("Coverage:"),
        "a complete record has nothing to admit:\n{stdout}"
    );
}

#[test]
fn the_typesdb_and_consts_reports_read_their_own_scans_coverage_run_and_show_alike() {
    // The typesdb and consts scans' own coverage stamps at the process seam
    // (issue #348).
    // Each scan files the coverage record it wrote. The run's report and a
    // later `--show` report stay byte-identical, because both are the same
    // read: the admission line when the scan owes one, silence when it does
    // not.
    for command in ["typesdb", "consts"] {
        let ws = fixture_workspace();
        let (ok, stdout, stderr) = run(
            cli(ws.path()).args(["--target-dir", ".", command, "--binary", "fixture-target"]),
            ws.path(),
        );
        assert!(ok, "the {command} scan failed:\n{stdout}\n{stderr}");
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
fn libmatch_and_floatsimd_coverage_reports_run_and_show_identically() {
    // The run-equals-show rule holds for both evidence engines' new coverage
    // stamps (issue #347). Whatever coverage the fixture's real scans record,
    // the run's report and a later `--show` report are the same read of the
    // same document — the admission line and all, or its absence.
    for command in ["libmatch", "floatsimd"] {
        let ws = fixture_workspace();
        let (ok, stdout, stderr) = run(
            cli(ws.path()).args(["--target-dir", ".", command, "--binary", "fixture-target"]),
            ws.path(),
        );
        assert!(ok, "the {command} scan failed:\n{stdout}\n{stderr}");

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
fn controlflow_memory_and_sync_coverage_reports_run_and_show_identically() {
    // The run-equals-show rule holds for the controlflow / memory / sync
    // scans' own coverage stamps (issue #349). Whatever coverage the fixture's real scans record,
    // the run's report and a later `--show` report are the same read of the
    // same document — the admission line and all, or its absence.
    for command in ["controlflow", "memory", "sync"] {
        let ws = fixture_workspace();
        let (ok, stdout, stderr) = run(
            cli(ws.path()).args(["--target-dir", ".", command, "--binary", "fixture-target"]),
            ws.path(),
        );
        assert!(ok, "the {command} scan failed:\n{stdout}\n{stderr}");

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
fn globalstate_errhandling_and_callback_coverage_reports_run_and_show_identically() {
    // The run-equals-show rule holds for the global-state / errhandling /
    // callback scans' own coverage stamps (issue #350). Whatever coverage the fixture's real scans record,
    // the run's report and a later `--show` report are the same read of the
    // same document — the admission line and all, or its absence.
    for command in ["global-state", "errhandling", "callback"] {
        let ws = fixture_workspace();
        if command == "callback" {
            // The callback command's pre-scan hook reads the type-inference
            // document to enrich signatures, and it warns when that document
            // is absent. The warning is scan-side log noise on the tracing
            // stream, not report bytes. Filing the empty document through its
            // own persistor first keeps the run's stdout to just the report,
            // so the run output and the --show output compare byte for byte.
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
        assert!(ok, "the {command} scan failed:\n{stdout}\n{stderr}");

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
fn algorithm_stringctx_serialize_typeinfer_coverage_reports_run_and_show_identically() {
    // The run-equals-show rule holds for the algorithm / stringctx /
    // serialize / typeinfer scans' own coverage stamps (issue #351). Whatever coverage the fixture's real
    // scans record, the run's report and a later `--show` report are the
    // same read of the same document — the admission line and all, or its
    // absence.
    for command in ["algorithm", "stringctx", "serialize", "typeinfer"] {
        let ws = fixture_workspace();
        let (ok, stdout, stderr) = run(
            cli(ws.path()).args(["--target-dir", ".", command, "--binary", "fixture-target"]),
            ws.path(),
        );
        assert!(ok, "the {command} scan failed:\n{stdout}\n{stderr}");

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
fn the_typeinfer_write_back_walks_the_scan_and_show_paths_and_prints_its_report() {
    // The type-inference follow-on at the process seam (issue #341).
    // `--write-back --confidence-floor 0` runs through the typeinfer crate's
    // own write-back API, and its report prints after the main report.
    // `--show --write-back` prints the same section from the filed document.
    // Without the flag, no write-back section prints at all, on the run path
    // or on the show path.
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
        "the typeinfer write-back scan failed:\n{stdout}\n{stderr}"
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
    assert!(ok, "the plain typeinfer scan failed:\n{stdout}\n{stderr}");
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
    // The set-override flags at the process seam (issue #341). A malformed
    // JSON document fails the run, and the process's whole diagnostic output
    // names both the file's path and the database that could not be read —
    // the row's own warning wording, never a silent fallback to the built-in
    // set.
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
        // The row's own warning holds the database error, which names the
        // file's path. That warning goes out on the tracing stream (stdout),
        // while the handler's failure message goes to stderr. So the
        // assertion reads the process's whole diagnostic output rather than
        // pinning one stream.
        let diagnostics = format!("{stdout}{stderr}");
        assert!(
            diagnostics.contains(wording) && diagnostics.contains("broken-database.json"),
            "the failure names the unreadable database and its path:\n{stdout}\n{stderr}"
        );
    }
}

// ── #355: seam capability admission prints in the scan run report ─────────

#[test]
fn the_run_report_stays_silent_of_seam_admissions_when_the_seam_declares_answerable() {
    // Issue #355's rule at the process seam. The Kuna seam declares every
    // query family answerable, so the scan run report prints no seam
    // admission line at all — total silence. The run-equals-`--show`
    // contract still stands unchanged, alongside the seam line's recorded
    // exemption (ADR-0054).
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
    assert!(ok, "the controlflow scan failed:\n{stdout}\n{stderr}");
    assert!(
        !stdout.contains("Seam:"),
        "the seam declares every family answerable — the run report admits \
         nothing about seam capability:\n{stdout}"
    );

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
        "the seam line sits at the same point on both paths — the run == \
         --show equality contract stands under the all-answerable seam"
    );
}
