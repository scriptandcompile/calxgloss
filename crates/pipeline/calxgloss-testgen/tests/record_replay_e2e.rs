//! Record-and-replay fold end-to-end (P23.2, issue #396): a captured event
//! log, folded with a fake replay seam, lands a filed baseline suite at
//! `re/baseline/{binary}/{function}/baseline.json` and files its named
//! refusals and replay faults in the binary's unknown ledger.
//!
//! No Wine in sight: the replay seam is the fold's closed fake, deciding
//! each outcome per case — the filed-baseline seam and the ledger seam are
//! the real writers.

use calxgloss_testgen::{
    Replay, ReplayOutcome, TestGenerator, file_capture_records, fold_capture_event_log,
};
use calxgloss_types::{
    BinaryIdentity, Export, SideEffect, SideEffectKind, TestCase, UnknownKind, UnknownLedger,
    load_json, unknown_ledger_path,
};
use serde_json::{Value, json};

fn exports() -> Vec<Export> {
    vec![
        Export {
            name: "fixture_check".to_string(),
            address: 0x100,
            signature: "int __stdcall fixture_check(int code)".to_string(),
        },
        Export {
            name: "fixture_status".to_string(),
            address: 0x200,
            signature: "int __stdcall fixture_status(int code)".to_string(),
        },
    ]
}

/// One capture log: two mined-hook events for `fixture_check` (one twin of a
/// pre-filed generated case, one fresh), a float entry, a pointer entry, an
/// event for an unlisted export, and a faulting entry on `fixture_status`.
fn capture_log() -> Value {
    json!({
        "capture_id": "cap-e2e",
        "events_dropped": 3,
        "entries": [
            {
                "binary": "game.dll",
                "export": "fixture_check",
                "lane": "baseline_hook",
                "evidence": {"run_event": {"capture_id": "cap-e2e", "event_sequence": 1}},
                "arguments": [{"scalar": {"tag": "i32", "value": 9}}]
            },
            {
                "binary": "game.dll",
                "export": "fixture_check",
                "lane": "baseline_hook",
                "evidence": {"run_event": {"capture_id": "cap-e2e", "event_sequence": 2}},
                "arguments": [{"scalar": {"tag": "i32", "value": 12}}]
            },
            {
                "binary": "game.dll",
                "export": "fixture_check",
                "lane": "baseline_hook",
                "evidence": {"run_event": {"capture_id": "cap-e2e", "event_sequence": 3}},
                "arguments": [{"scalar": {"tag": "f64", "value": 1.5}}]
            },
            {
                "binary": "game.dll",
                "export": "fixture_check",
                "lane": "baseline_hook",
                "evidence": {"run_event": {"capture_id": "cap-e2e", "event_sequence": 4}},
                "arguments": [
                    {"pointer": {"bytes": [1, 2, 3, 4], "captured_size": 4, "truncated": false}}
                ]
            },
            {
                "binary": "game.dll",
                "export": "ghost_export",
                "lane": "baseline_hook",
                "evidence": {"run_event": {"capture_id": "cap-e2e", "event_sequence": 5}},
                "arguments": [{"scalar": {"tag": "i32", "value": 7}}]
            },
            {
                "binary": "game.dll",
                "export": "fixture_status",
                "lane": "baseline_hook",
                "evidence": {"run_event": {"capture_id": "cap-e2e", "event_sequence": 6}},
                "arguments": [{"scalar": {"tag": "i32", "value": 11}}]
            }
        ]
    })
}

#[tokio::test]
async fn a_captured_log_fills_the_filed_baseline_suite_and_the_unknown_ledger() {
    let dir = tempfile::tempdir().unwrap();
    let generator = TestGenerator::new(dir.path());

    // A generated suite row already on disk for the twin's input vector.
    generator
        .save_baseline(
            "game.dll",
            "fixture_check",
            &[calxgloss_types::TestResult {
                test_case: TestCase {
                    inputs: json!({"param_0": 9}),
                    expected_return: Value::Null,
                    expected_side_effects: Vec::new(),
                    expected_api_calls: Vec::new(),
                    origin: calxgloss_types::CaseOrigin::Generated,
                },
                actual_return: json!(9),
                actual_side_effects: Vec::new(),
                actual_api_calls: Vec::new(),
                passed: true,
                error: None,
            }],
        )
        .unwrap();

    // Event 1 (the twin's vector) is never replayed; event 6 faults.
    let seam = |function: &str, case: &TestCase| match function {
        "fixture_status" => ReplayOutcome::Faulted {
            detail: format!("access violation reading {}", case.inputs),
        },
        _ => ReplayOutcome::Observed {
            returned: json!(42),
            side_effects: vec![SideEffect {
                kind: SideEffectKind::WindowUpdate,
                detail: "redrew the status panel".to_string(),
            }],
            api_calls: vec!["GetLastError".to_string()],
        },
    };
    let folded = fold_capture_event_log(
        &generator,
        "game.dll",
        &exports(),
        &capture_log(),
        &Replay::Fake(&seam),
    )
    .await
    .unwrap();

    // The count report: six events seen, one case mined, the twin
    // deduplicated, three refusals named, the truncation stated.
    assert_eq!(folded.report.events_seen, 6);
    assert_eq!(folded.report.cases_mined, 1);
    assert_eq!(folded.report.cases_deduplicated, 1);
    assert_eq!(folded.report.refusals.len(), 4);
    assert_eq!(folded.report.events_dropped, Some(3));
    let summary = folded.report.summary();
    for fact in [
        "6 events seen",
        "1 cases mined",
        "1 twin deduplicated",
        "4 refusals named",
        "1 truncation stated",
    ] {
        assert!(summary.contains(fact), "{summary} lacks {fact:?}");
    }

    // The filed baseline document, on disk at the real seam: the generated
    // row first with its origin upgraded to the mined twin, then the mined
    // row carrying what the replay observed.
    let baseline = dir
        .path()
        .join("re/baseline/game.dll/fixture_check/baseline.json");
    assert!(baseline.is_file());
    let filed: Vec<calxgloss_types::TestResult> =
        serde_json::from_str(&std::fs::read_to_string(&baseline).unwrap()).unwrap();
    assert_eq!(filed.len(), 2);
    assert_eq!(
        filed[0].test_case.origin,
        calxgloss_types::CaseOrigin::MinedHook {
            capture_id: "cap-e2e".to_string(),
            event_sequence: 1,
        },
        "the twin upgrades the filed row's origin to the mined one"
    );
    assert_eq!(
        filed[1].test_case.origin,
        calxgloss_types::CaseOrigin::MinedHook {
            capture_id: "cap-e2e".to_string(),
            event_sequence: 2,
        }
    );
    assert_eq!(filed[1].test_case.inputs, json!({"code": 12}));
    // Mined in capture order: event 2 was the first fresh vector (event 1's
    // vector twin-collided with the generated row and files no new row).
    let raw: Value = serde_json::from_str(&std::fs::read_to_string(&baseline).unwrap()).unwrap();
    assert_eq!(
        raw[0]["test_case"]["origin"]["mined_hook"]["event_sequence"],
        json!(1)
    );
    assert_eq!(
        raw[1]["test_case"]["origin"]["mined_hook"]["event_sequence"],
        json!(2)
    );
    assert_eq!(raw[1]["actual_return"], json!(42));
    assert_eq!(
        raw[1]["test_case"]["expected_api_calls"],
        json!(["GetLastError"])
    );
    // The side effect the replay observed at the original is the filed
    // case's expectation — observed, never promised by the capture.
    assert_eq!(
        filed[1].test_case.expected_side_effects,
        vec![SideEffect {
            kind: SideEffectKind::WindowUpdate,
            detail: "redrew the status panel".to_string(),
        }]
    );
    assert_eq!(
        raw[1]["test_case"]["expected_side_effects"],
        raw[1]["actual_side_effects"]
    );

    // A faulting replay files no suite for its export.
    assert!(
        !dir.path()
            .join("re/baseline/game.dll/fixture_status/baseline.json")
            .is_file()
    );

    // The named refusals and the fault land in the unknown ledger.
    let landed = file_capture_records(dir.path(), "game.dll", &folded.unknown_records).unwrap();
    assert_eq!(landed, 5); // 3 refusals + 1 truncation + 1 crash reproduction
    let ledger = load_json::<UnknownLedger>(&unknown_ledger_path(
        dir.path(),
        &BinaryIdentity::new("game.dll"),
    ))
    .unwrap();
    let records = ledger.records.unwrap();
    assert_eq!(records.len(), 5);
    assert_eq!(
        records
            .iter()
            .filter(|r| r.kind == UnknownKind::CaptureRefused)
            .count(),
        4,
        "three entry refusals plus the stated truncation"
    );
    let crash = records
        .iter()
        .find(|r| r.kind == UnknownKind::CrashReproduction)
        .expect("the faulting replay names a crash_reproduction record");
    assert_eq!(crash.function.as_deref(), Some("fixture_status"));
    assert!(crash.question.contains("#6"), "{}", crash.question);
    assert!(crash.id.ends_with("crash_reproduction/cap-e2e#6"));
    let questions: Vec<&str> = records
        .iter()
        .filter(|r| r.kind == UnknownKind::CaptureRefused)
        .map(|r| r.question.as_str())
        .collect();
    for reason in [
        "float-argument",
        "pointer-bearing-vector",
        "no-parseable-signature",
        "truncated-capture",
    ] {
        assert!(
            questions.iter().any(|q| q.contains(reason)),
            "no refusal names {reason:?}: {questions:?}"
        );
    }

    // A re-ingest of the same log is byte-stable: no new filed rows, no new
    // ledger records, no re-numbered revisions.
    let before = std::fs::read(&baseline).unwrap();
    let again = fold_capture_event_log(
        &generator,
        "game.dll",
        &exports(),
        &capture_log(),
        &Replay::Fake(&seam),
    )
    .await
    .unwrap();
    assert_eq!(again.report.cases_mined, 0);
    assert_eq!(again.report.cases_deduplicated, 2);
    let _ = TestCase {
        inputs: Value::Null,
        expected_return: Value::Null,
        expected_side_effects: Vec::new(),
        expected_api_calls: Vec::new(),
        origin: calxgloss_types::CaseOrigin::Generated,
    };
    assert!(again.filed.is_empty());
    assert_eq!(std::fs::read(&baseline).unwrap(), before);
    let landed_again =
        file_capture_records(dir.path(), "game.dll", &again.unknown_records).unwrap();
    assert_eq!(landed_again, 5);
    let ledger = load_json::<UnknownLedger>(&unknown_ledger_path(
        dir.path(),
        &BinaryIdentity::new("game.dll"),
    ))
    .unwrap();
    for record in ledger.records.unwrap() {
        assert_eq!(record.revision, 1, "a re-ingest never re-numbers the diff");
    }
}
