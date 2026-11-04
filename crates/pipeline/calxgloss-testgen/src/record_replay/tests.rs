//! The fold's pins (issue #396): every refusal names its reason, twins
//! dedup on exact input vectors, filed order and cap exemption hold, and
//! the crash record names its event — all through the fake replay seam,
//! with no Wine in sight.

use std::cell::Cell;

use calxgloss_types::{CaseOrigin, Export, UnknownKind, UnknownOrigin};
use serde_json::json;

use super::*;

fn export(name: &str, signature: &str) -> Export {
    Export {
        name: name.to_string(),
        address: 0x1000,
        signature: signature.to_string(),
    }
}

/// One captured call entry as a capture lane writes it: the shared
/// captured-entry wire shape, run-event evidence naming the capture and
/// the event's position, scalar arguments with the harness's encode tags.
fn captured(sequence: u64, name: &str, args: Vec<Value>) -> Value {
    json!({
        "binary": "game.dll",
        "export": name,
        "lane": "baseline_hook",
        "evidence": {"run_event": {"capture_id": "cap-a", "event_sequence": sequence}},
        "arguments": args
    })
}

fn scalar(tag: &str, value: Value) -> Value {
    json!({"scalar": {"tag": tag, "value": value}})
}

fn pointer(bytes: Vec<u8>, captured_size: u64, truncated: bool) -> Value {
    json!({"pointer": {"bytes": bytes, "captured_size": captured_size, "truncated": truncated}})
}

fn log(capture_id: &str, entries: Vec<Value>) -> Value {
    json!({"capture_id": capture_id, "entries": entries})
}

fn observed(returned: Value, api_calls: Vec<&str>) -> ReplayOutcome {
    ReplayOutcome::Observed {
        returned,
        api_calls: api_calls.into_iter().map(String::from).collect(),
        side_effects: Vec::new(),
    }
}

fn exports() -> Vec<Export> {
    vec![
        export("fixture_check", "int __stdcall fixture_check(int code)"),
        export("fixture_tick", "int __stdcall fixture_tick(void)"),
    ]
}

#[tokio::test]
async fn a_captured_hook_event_mines_a_filed_case() {
    let dir = tempfile::tempdir().unwrap();
    let generator = TestGenerator::new(dir.path());
    let seam = |_: &str, _: &TestCase| observed(json!(7), vec!["GetLastError"]);
    let folded = fold_capture_event_log(
        &generator,
        "game.dll",
        &exports(),
        &log(
            "cap-a",
            vec![captured(1, "fixture_check", vec![scalar("i32", json!(9))])],
        ),
        &Replay::Fake(&seam),
    )
    .await
    .unwrap();

    assert_eq!(folded.report.events_seen, 1);
    assert_eq!(folded.report.cases_mined, 1);
    assert!(folded.report.refusals.is_empty());
    assert!(folded.unknown_records.is_empty());

    let rows = generator
        .load_baseline("game.dll", "fixture_check")
        .unwrap();
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_eq!(
        row.test_case.origin,
        CaseOrigin::MinedHook {
            capture_id: "cap-a".to_string(),
            event_sequence: 1,
        }
    );
    assert_eq!(row.test_case.inputs, json!({"code": 9}));
    assert_eq!(row.actual_return, json!(7));
    assert_eq!(row.actual_api_calls, ["GetLastError"]);
    // The replay observation is the filed expectation; the capture never
    // promised a return value on its own.
    assert!(row.test_case.expected_api_calls == vec!["GetLastError".to_string()]);
    assert_eq!(row.test_case.expected_return, Value::Null);
    assert!(row.passed);
    assert!(
        dir.path()
            .join("re/baseline/game.dll/fixture_check/baseline.json")
            .is_file()
    );
}

#[tokio::test]
async fn a_replay_observed_side_effect_files_as_the_case_expectation() {
    let dir = tempfile::tempdir().unwrap();
    let generator = TestGenerator::new(dir.path());
    let seam = |_: &str, _: &TestCase| ReplayOutcome::Observed {
        returned: json!(7),
        side_effects: vec![calxgloss_types::SideEffect {
            kind: calxgloss_types::SideEffectKind::FileWrite,
            detail: "wrote-config".to_string(),
        }],
        api_calls: Vec::new(),
    };
    fold_capture_event_log(
        &generator,
        "game.dll",
        &exports(),
        &log(
            "cap-a",
            vec![captured(1, "fixture_check", vec![scalar("i32", json!(9))])],
        ),
        &Replay::Fake(&seam),
    )
    .await
    .unwrap();
    let rows = generator
        .load_baseline("game.dll", "fixture_check")
        .unwrap();
    // What the replay observed is what the case expects — side effects
    // included, observed at the original, never from the capture.
    assert_eq!(
        rows[0].actual_side_effects,
        vec![calxgloss_types::SideEffect {
            kind: calxgloss_types::SideEffectKind::FileWrite,
            detail: "wrote-config".to_string(),
        }]
    );
    assert_eq!(
        rows[0].test_case.expected_side_effects,
        rows[0].actual_side_effects
    );
}

#[tokio::test]
async fn an_input_free_event_mines_against_a_void_export() {
    let dir = tempfile::tempdir().unwrap();
    let generator = TestGenerator::new(dir.path());
    let seam = |_: &str, _: &TestCase| observed(json!(3), vec![]);
    let folded = fold_capture_event_log(
        &generator,
        "game.dll",
        &exports(),
        &log("cap-a", vec![captured(2, "fixture_tick", vec![])]),
        &Replay::Fake(&seam),
    )
    .await
    .unwrap();
    assert_eq!(folded.report.cases_mined, 1);
    let rows = generator.load_baseline("game.dll", "fixture_tick").unwrap();
    assert_eq!(rows[0].test_case.inputs, json!({}));
}

#[tokio::test]
async fn an_entry_naming_another_binary_is_out_of_this_folds_scope() {
    let dir = tempfile::tempdir().unwrap();
    let generator = TestGenerator::new(dir.path());
    let seam = |_: &str, _: &TestCase| observed(json!(7), vec![]);
    let mut entry = captured(1, "fixture_check", vec![scalar("i32", json!(9))]);
    entry["binary"] = json!("other.dll");
    let folded = fold_capture_event_log(
        &generator,
        "game.dll",
        &exports(),
        &log("cap-a", vec![entry]),
        &Replay::Fake(&seam),
    )
    .await
    .unwrap();
    // Not this binary's call: not mined, not refused, not recorded — it
    // belongs to the other binary's own ingest.
    assert_eq!(folded.report.cases_mined, 0);
    assert!(folded.report.refusals.is_empty());
    assert!(folded.unknown_records.is_empty());
    assert!(
        generator
            .load_baseline("game.dll", "fixture_check")
            .is_err()
    );
}

#[tokio::test]
async fn every_refusal_names_its_reason_and_files_a_capture_refused_record() {
    let dir = tempfile::tempdir().unwrap();
    let generator = TestGenerator::new(dir.path());
    let seam = |f: &str, c: &TestCase| panic!("replayed {f} {}", c.inputs);
    let entries = vec![
        // A float tag, caught at the raw level before any typed parse.
        captured(
            1,
            "fixture_check",
            vec![json!({"scalar": {"tag": "f64", "value": 1.5}})],
        ),
        // A truncated capture flag on a pointer descriptor.
        captured(2, "fixture_check", vec![pointer(vec![7], 512, true)]),
        // A materializable pointer fed to a parameter that is not one.
        captured(
            3,
            "fixture_check",
            vec![pointer(vec![1, 2, 3, 4], 4, false)],
        ),
        // An export the listing does not carry.
        captured(4, "ghost_export", vec![scalar("i32", json!(1))]),
        // A signature that does not parse.
        captured(5, "fixture_unparsed", vec![scalar("i32", json!(1))]),
        // Wrong arity against the declared signature.
        captured(
            6,
            "fixture_check",
            vec![scalar("i32", json!(1)), scalar("i32", json!(2))],
        ),
        // A bool tag: outside the closed scalar vocabulary, the entry
        // never decodes as a shaped vector at all.
        captured(
            7,
            "fixture_check",
            vec![json!({"scalar": {"tag": "bool", "value": true}})],
        ),
        // An integer outside the declared parameter's range.
        captured(
            8,
            "fixture_check",
            vec![scalar("i32", json!(5_000_000_000i64))],
        ),
        // An entry that is not a shaped vector at all — and names no
        // evidence, so it is nameable only against the capture as a whole.
        json!({"export": "fixture_check", "not_arguments": []}),
    ];
    // Entry 5 needs an export whose signature does not parse.
    let mut exports = exports();
    exports.push(export(
        "fixture_unparsed",
        "int __stdcall fixture_unparsed(int code",
    ));

    let folded = fold_capture_event_log(
        &generator,
        "game.dll",
        &exports,
        &log("cap-a", entries),
        &Replay::Fake(&seam),
    )
    .await
    .unwrap();

    let reasons: Vec<&str> = folded
        .report
        .refusals
        .iter()
        .map(|r| r.reason.as_str())
        .collect();
    assert_eq!(
        reasons,
        [
            "float-argument",
            "truncated-capture",
            // The captured bytes are materializable, but a pointer
            // descriptor cannot feed a plain int parameter.
            "argument-shape-not-in-signature",
            "no-parseable-signature",
            "no-parseable-signature",
            "argument-shape-not-in-signature",
            "argument-shape-not-in-signature",
            "argument-shape-not-in-signature",
            "argument-shape-not-in-signature",
        ]
    );
    // Each named refusal also names its record, origin-bound to the event.
    assert_eq!(folded.unknown_records.len(), 9);
    for record in &folded.unknown_records {
        assert_eq!(record.kind, UnknownKind::CaptureRefused);
        assert!(matches!(record.origin, UnknownOrigin::Capture { .. }));
    }
    assert_eq!(
        folded.unknown_records[0].id,
        "game.dll/fixture_check/capture_refused/cap-a#1"
    );
    // Nothing was filed — a refused entry files no case.
    assert!(
        generator
            .load_baseline("game.dll", "fixture_check")
            .is_err()
    );
    assert_eq!(folded.report.cases_mined, 0);
}

#[tokio::test]
async fn a_replay_fault_files_a_crash_record_naming_the_event() {
    let dir = tempfile::tempdir().unwrap();
    let generator = TestGenerator::new(dir.path());
    let seam = |_: &str, _: &TestCase| ReplayOutcome::Faulted {
        detail: "access violation at 0x1000".to_string(),
    };
    let folded = fold_capture_event_log(
        &generator,
        "game.dll",
        &exports(),
        &log(
            "cap-a",
            vec![captured(3, "fixture_check", vec![scalar("i32", json!(9))])],
        ),
        &Replay::Fake(&seam),
    )
    .await
    .unwrap();

    assert_eq!(folded.report.cases_mined, 0);
    assert_eq!(folded.unknown_records.len(), 1);
    let record = &folded.unknown_records[0];
    assert_eq!(record.kind, UnknownKind::CrashReproduction);
    assert_eq!(
        record.origin,
        UnknownOrigin::Capture {
            capture_id: "cap-a".to_string(),
            event_sequence: Some(3),
        }
    );
    assert!(record.question.contains("access violation at 0x1000"));
    assert!(record.question.contains("#3"));
    // A faulting replay files no baseline case.
    assert!(
        generator
            .load_baseline("game.dll", "fixture_check")
            .is_err()
    );
}

#[tokio::test]
async fn a_twin_deduplicates_upgrades_the_origin_and_is_never_replayed() {
    let dir = tempfile::tempdir().unwrap();
    let generator = TestGenerator::new(dir.path());
    // A generated suite row already filed for the same input vector,
    // keyed the generation's 0-based way.
    let generated = TestCase {
        inputs: json!({"param_0": 9}),
        expected_return: Value::Null,
        expected_side_effects: Vec::new(),
        expected_api_calls: Vec::new(),
        origin: CaseOrigin::Generated,
    };
    generator
        .save_baseline(
            "game.dll",
            "fixture_check",
            &[TestResult {
                test_case: generated,
                actual_return: json!(9),
                actual_side_effects: Vec::new(),
                actual_api_calls: Vec::new(),
                passed: true,
                error: None,
            }],
        )
        .unwrap();

    let replays = Cell::new(0usize);
    let seam = |_: &str, _: &TestCase| {
        replays.set(replays.get() + 1);
        observed(json!(9), vec![])
    };
    let folded = fold_capture_event_log(
        &generator,
        "game.dll",
        &exports(),
        &log(
            "cap-a",
            vec![captured(4, "fixture_check", vec![scalar("i32", json!(9))])],
        ),
        &Replay::Fake(&seam),
    )
    .await
    .unwrap();

    assert_eq!(replays.get(), 0, "a twin is not replayed again");
    assert_eq!(folded.report.cases_deduplicated, 1);
    assert_eq!(folded.report.cases_mined, 0);
    let rows = generator
        .load_baseline("game.dll", "fixture_check")
        .unwrap();
    assert_eq!(rows.len(), 1);
    // The collision keeps the stronger origin: the mined one.
    assert_eq!(
        rows[0].test_case.origin,
        CaseOrigin::MinedHook {
            capture_id: "cap-a".to_string(),
            event_sequence: 4,
        }
    );
}

#[tokio::test]
async fn mined_rows_file_generated_first_then_in_capture_order() {
    let dir = tempfile::tempdir().unwrap();
    let generator = TestGenerator::new(dir.path());
    generator
        .save_baseline(
            "game.dll",
            "fixture_check",
            &[TestResult {
                test_case: TestCase {
                    inputs: json!({"param_0": 1}),
                    expected_return: Value::Null,
                    expected_side_effects: Vec::new(),
                    expected_api_calls: Vec::new(),
                    origin: CaseOrigin::Generated,
                },
                actual_return: json!(1),
                actual_side_effects: Vec::new(),
                actual_api_calls: Vec::new(),
                passed: true,
                error: None,
            }],
        )
        .unwrap();
    let seam = |_: &str, _: &TestCase| observed(json!(0), vec![]);
    let entries = vec![
        captured(10, "fixture_check", vec![scalar("i32", json!(11))]),
        captured(20, "fixture_check", vec![scalar("i32", json!(22))]),
        captured(30, "fixture_check", vec![scalar("i32", json!(11))]), // twin of #10
    ];
    let folded = fold_capture_event_log(
        &generator,
        "game.dll",
        &exports(),
        &log("cap-a", entries),
        &Replay::Fake(&seam),
    )
    .await
    .unwrap();
    assert_eq!(folded.report.cases_mined, 2);
    assert_eq!(folded.report.cases_deduplicated, 1);
    let rows = generator
        .load_baseline("game.dll", "fixture_check")
        .unwrap();
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[0].test_case.origin, CaseOrigin::Generated);
    assert!(
        rows[1].test_case.inputs[&rows[1]
            .test_case
            .inputs
            .as_object()
            .unwrap()
            .keys()
            .next()
            .unwrap()
            .clone()]
            == json!(11)
    );
    match &rows[1].test_case.origin {
        CaseOrigin::MinedHook { event_sequence, .. } => assert_eq!(*event_sequence, 10),
        other => panic!("expected a mined row, got {other:?}"),
    }
    match &rows[2].test_case.origin {
        CaseOrigin::MinedHook { event_sequence, .. } => assert_eq!(*event_sequence, 20),
        other => panic!("expected a mined row, got {other:?}"),
    }
}

#[tokio::test]
async fn mined_rows_are_exempt_from_the_generation_cap() {
    let dir = tempfile::tempdir().unwrap();
    let generator = TestGenerator::new(dir.path());
    // A suite already at the cap of 40 generated rows.
    let rows: Vec<TestResult> = (0..40u64)
        .map(|i| TestResult {
            test_case: TestCase {
                inputs: json!({"param_0": i}),
                expected_return: Value::Null,
                expected_side_effects: Vec::new(),
                expected_api_calls: Vec::new(),
                origin: CaseOrigin::Generated,
            },
            actual_return: json!(i),
            actual_side_effects: Vec::new(),
            actual_api_calls: Vec::new(),
            passed: true,
            error: None,
        })
        .collect();
    generator
        .save_baseline("game.dll", "fixture_check", &rows)
        .unwrap();
    let seam = |_: &str, _: &TestCase| observed(json!(0), vec![]);
    let folded = fold_capture_event_log(
        &generator,
        "game.dll",
        &exports(),
        &log(
            "cap-a",
            vec![captured(1, "fixture_check", vec![scalar("i32", json!(41))])],
        ),
        &Replay::Fake(&seam),
    )
    .await
    .unwrap();
    assert_eq!(folded.report.cases_mined, 1, "{:?}", folded.report);
    assert_eq!(
        generator
            .load_baseline("game.dll", "fixture_check")
            .unwrap()
            .len(),
        41
    );
}

#[tokio::test]
async fn a_repeated_ingest_files_byte_stable_baseline_and_report() {
    let dir = tempfile::tempdir().unwrap();
    let generator = TestGenerator::new(dir.path());
    let seam = |_: &str, _: &TestCase| observed(json!(5), vec!["WriteFile"]);
    let log = log(
        "cap-a",
        vec![
            captured(1, "fixture_check", vec![scalar("i32", json!(9))]),
            json!({
                "binary": "game.dll",
                "export": "ghost",
                "lane": "baseline_hook",
                "evidence": {"run_event": {"capture_id": "cap-a", "event_sequence": 2}},
                "arguments": [scalar("i32", json!(1))]
            }),
        ],
    );
    let first = fold_capture_event_log(
        &generator,
        "game.dll",
        &exports(),
        &log,
        &Replay::Fake(&seam),
    )
    .await
    .unwrap();
    let path = generator.baseline_path("game.dll", "fixture_check");
    let first_bytes = std::fs::read(&path).unwrap();
    let second = fold_capture_event_log(
        &generator,
        "game.dll",
        &exports(),
        &log,
        &Replay::Fake(&seam),
    )
    .await
    .unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), first_bytes);
    assert_eq!(first.report.cases_mined, 1);
    assert_eq!(first.report.refusals.len(), 1);
    assert_eq!(second.report.cases_mined, 0);
    assert_eq!(second.report.cases_deduplicated, 1);
    assert_eq!(second.report.refusals.len(), 1);
    assert!(!first.filed.is_empty());
    assert!(
        second.filed.is_empty(),
        "nothing changed, nothing rewritten"
    );
}

#[tokio::test]
async fn a_stated_truncation_names_one_capture_level_refusal() {
    let dir = tempfile::tempdir().unwrap();
    let generator = TestGenerator::new(dir.path());
    let seam = |_: &str, _: &TestCase| observed(json!(1), vec![]);
    let mut log = log("cap-a", vec![]);
    log["events_dropped"] = json!(7);
    let folded = fold_capture_event_log(
        &generator,
        "game.dll",
        &exports(),
        &log,
        &Replay::Fake(&seam),
    )
    .await
    .unwrap();
    assert_eq!(folded.report.refusals.len(), 1);
    assert_eq!(
        folded.report.refusals[0].reason,
        RefusalReason::TruncatedCapture
    );
    assert_eq!(folded.report.refusals[0].sequence, None);
    let record = &folded.unknown_records[0];
    assert_eq!(record.function, None);
    assert_eq!(
        record.origin,
        UnknownOrigin::Capture {
            capture_id: "cap-a".to_string(),
            event_sequence: None,
        }
    );
    assert!(record.id.ends_with("capture_refused/cap-a#capture"));
    let summary = folded.report.summary();
    assert!(summary.contains("1 truncation stated"), "{summary}");
    assert!(folded.report.to_string().contains("7 events dropped"));
}

#[tokio::test]
async fn a_dump_thread_entry_files_a_mined_minidump_origin_from_its_own_evidence() {
    let dir = tempfile::tempdir().unwrap();
    let generator = TestGenerator::new(dir.path());
    let seam = |_: &str, _: &TestCase| observed(json!(2), vec![]);
    let entry = json!({
        "binary": "game.dll",
        "export": "fixture_check",
        "lane": "minidump",
        "evidence": {"dump_thread": {"dump_digest": "sha256:2f2a9c", "thread_id": 3812}},
        "arguments": [scalar("i32", json!(9))],
    });
    fold_capture_event_log(
        &generator,
        "game.dll",
        &exports(),
        &log("dump-7f", vec![entry]),
        &Replay::Fake(&seam),
    )
    .await
    .unwrap();
    let rows = generator
        .load_baseline("game.dll", "fixture_check")
        .unwrap();
    // Every origin field is one the capture really recorded: the dump's
    // digest and the faulting thread's id, never a repurposed stand-in.
    assert_eq!(
        rows[0].test_case.origin,
        CaseOrigin::MinedMinidump {
            dump_digest: "sha256:2f2a9c".to_string(),
            thread_id: 3812,
            fault_address: 0,
        }
    );
}

#[tokio::test]
async fn a_captured_pointer_buffer_replays_as_a_fresh_allocation_holding_the_captured_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let generator = TestGenerator::new(dir.path());
    // The replay seam receives the vector with the pointer spelled as a
    // harness-allocated buffer carrying exactly the captured bytes — the
    // replay materializes the target, it never points at a captured address.
    let seam = |_: &str, case: &TestCase| {
        assert_eq!(
            case.inputs,
            json!({"buffer": {"__alloc": {"size": 5, "bytes": "48656c6c6f"}}}),
            "a captured pointer replays as a fresh allocation holding the captured bytes"
        );
        observed(json!(7), vec![])
    };
    let mut exports = exports();
    exports.push(export(
        "fixture_buffer",
        "int __stdcall fixture_buffer(char* buffer)",
    ));
    let folded = fold_capture_event_log(
        &generator,
        "game.dll",
        &exports,
        &log(
            "cap-a",
            vec![captured(
                1,
                "fixture_buffer",
                vec![pointer(vec![72, 101, 108, 108, 111], 5, false)],
            )],
        ),
        &Replay::Fake(&seam),
    )
    .await
    .unwrap();

    assert_eq!(folded.report.cases_mined, 1);
    assert!(folded.report.refusals.is_empty());
    assert!(folded.unknown_records.is_empty());
    let rows = generator
        .load_baseline("game.dll", "fixture_buffer")
        .unwrap();
    assert_eq!(
        rows[0].test_case.inputs,
        json!({"buffer": {"__alloc": {"size": 5, "bytes": "48656c6c6f"}}})
    );
    match &rows[0].test_case.origin {
        CaseOrigin::MinedHook { event_sequence, .. } => assert_eq!(*event_sequence, 1),
        other => panic!("a mined pointer row keeps its mined origin: {other:?}"),
    }
}

#[tokio::test]
async fn a_pointer_with_no_captured_bytes_refuses_as_unmaterializable() {
    let dir = tempfile::tempdir().unwrap();
    let generator = TestGenerator::new(dir.path());
    let seam = |f: &str, c: &TestCase| panic!("replayed {f} {}", c.inputs);
    let folded = fold_capture_event_log(
        &generator,
        "game.dll",
        &exports(),
        &log(
            "cap-a",
            vec![captured(
                1,
                "fixture_check",
                vec![pointer(Vec::new(), 0, false)],
            )],
        ),
        &Replay::Fake(&seam),
    )
    .await
    .unwrap();
    // The earlier slice's refusal still fires: a pointer the replay has no
    // bytes to materialize is refused-and-recorded, never pointed at an
    // address the harness cannot honor.
    assert_eq!(folded.report.refusals.len(), 1);
    assert_eq!(
        folded.report.refusals[0].reason.as_str(),
        "unmaterializable-pointer"
    );
    assert_eq!(folded.unknown_records.len(), 1);
    assert!(
        folded.unknown_records[0]
            .question
            .contains("no captured bytes")
    );
    assert!(
        generator
            .load_baseline("game.dll", "fixture_check")
            .is_err()
    );
}

#[tokio::test]
async fn a_descriptor_over_the_capture_bound_refuses_naming_the_bound() {
    let dir = tempfile::tempdir().unwrap();
    let generator = TestGenerator::new(dir.path());
    let seam = |f: &str, c: &TestCase| panic!("replayed {f} {}", c.inputs);
    // A record-time capture can never carry more than the bound: a
    // descriptor that does states a truncation it never stamped, so the
    // fold refuses it rather than reconstruct an over-bound buffer.
    let over = vec![7u8; calxgloss_types::POINTER_CAPTURE_BOUND as usize + 1];
    let folded = fold_capture_event_log(
        &generator,
        "game.dll",
        &exports(),
        &log(
            "cap-a",
            vec![captured(
                1,
                "fixture_check",
                vec![pointer(over.clone(), over.len() as u64, false)],
            )],
        ),
        &Replay::Fake(&seam),
    )
    .await
    .unwrap();
    assert_eq!(folded.report.refusals.len(), 1);
    assert_eq!(
        folded.report.refusals[0].reason.as_str(),
        "truncated-capture"
    );
    let record = &folded.unknown_records[0];
    assert!(
        record.question.contains("capture bound"),
        "{}",
        record.question
    );
    assert!(record.question.contains("65537"), "{}", record.question);
}

#[tokio::test]
async fn an_unstated_short_capture_refuses_naming_the_sizes() {
    let dir = tempfile::tempdir().unwrap();
    let generator = TestGenerator::new(dir.path());
    let seam = |f: &str, c: &TestCase| panic!("replayed {f} {}", c.inputs);
    // bytes under the bound but short of the observed size with
    // truncated=false: the record claims a full capture it never made.
    let folded = fold_capture_event_log(
        &generator,
        "game.dll",
        &exports(),
        &log(
            "cap-a",
            vec![captured(
                1,
                "fixture_check",
                vec![pointer(vec![1, 2], 4, false)],
            )],
        ),
        &Replay::Fake(&seam),
    )
    .await
    .unwrap();
    assert_eq!(folded.report.refusals.len(), 1);
    assert_eq!(
        folded.report.refusals[0].reason.as_str(),
        "truncated-capture"
    );
    let record = &folded.unknown_records[0];
    assert!(record.question.contains("truncated"), "{}", record.question);
    assert!(record.question.contains("4"), "{}", record.question);
    assert!(record.question.contains("2"), "{}", record.question);
}

#[test]
fn capture_records_merge_into_the_ledger_without_clobbering_batched_records() {
    let dir = tempfile::tempdir().unwrap();
    // A batch-filed record already in the ledger.
    let batch = UnknownRecord::derive(
        "game.dll",
        Some("fixture_ordered".to_string()),
        UnknownKind::ExportUncovered,
        UnknownSeverity::Material,
        "why",
        "evidence",
        UnknownOrigin::CaseSet {
            case_set: "fixture_ordered".to_string(),
        },
        100,
    );
    let ledger = UnknownLedger::file(
        "game.dll",
        None,
        std::slice::from_ref(&batch),
        &Default::default(),
        100,
    );
    calxgloss_types::save_json(
        &calxgloss_types::unknown_ledger_path(
            dir.path(),
            &calxgloss_types::BinaryIdentity::new("game.dll"),
        ),
        &ledger,
    )
    .unwrap();

    let refused = refusal_record(
        "game.dll",
        "cap-a",
        Some(1),
        Some("fixture_check"),
        RefusalReason::FloatArgument,
        "detail",
    );
    assert_eq!(
        file_capture_records(dir.path(), "game.dll", std::slice::from_ref(&refused)).unwrap(),
        2
    );
    // A re-ingest of the same capture re-derives the same id — no new
    // revision, no duplicate, the batch record survives.
    assert_eq!(
        file_capture_records(dir.path(), "game.dll", &[refused]).unwrap(),
        2
    );
    let filed = calxgloss_types::load_json::<UnknownLedger>(&calxgloss_types::unknown_ledger_path(
        dir.path(),
        &calxgloss_types::BinaryIdentity::new("game.dll"),
    ))
    .unwrap();
    let records = filed.records.unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(records.iter().filter(|r| r.id == batch.id).count(), 1);
    let capture = records
        .iter()
        .find(|r| r.kind == UnknownKind::CaptureRefused)
        .unwrap();
    assert_eq!(capture.revision, 1, "a re-ingest never re-numbers the diff");
}
