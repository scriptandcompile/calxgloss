//! End-to-end baseline execution against a real DLL.
//!
//! These tests need three things that are not guaranteed on every machine:
//!
//! * a real Windows DLL, named by `CALXGLOSS_TEST_DLL`
//! * Wine, to run the cross-compiled harness
//! * the `x86_64-pc-windows-gnu` Rust target
//!
//! They are therefore `#[ignore]`d by default. To run them:
//!
//! ```text
//! rustup target add x86_64-pc-windows-gnu
//! CALXGLOSS_TEST_DLL="/path/to/eqmain.dll" \
//!     cargo test -p calxgloss-testgen --test baseline -- --ignored --nocapture
//! ```
//!
//! `eqmain.dll` from EverQuest is the reference target: it is a Delphi binary
//! whose interesting functions are internal, so it exercises the whole
//! `VA -> RVA -> module_base + RVA` path rather than the export table.

use std::path::{Path, PathBuf};

use calxgloss_testgen::{
    BaselineRunner, FunctionLocator, HarnessSpec, LoadMode, PeImage, WineRunner, generate_harness,
    parse_signature,
};
use calxgloss_types::TestCase;
use serde_json::{Value, json};

/// The RVA of `FUN_18008ed50`, whose decompiled body is
/// `return param_1 + ((longlong)param_2 + 4) * 8;`.
const TARGET_RVA: u32 = 0x8ed50;

/// The signature the decompiler reports for that function.
const TARGET_SIGNATURE: &str = "longlong FUN_18008ed50(longlong param_1,int param_2)";

/// RVA of `FUN_1800470a0`, which reads a `u32` at `[param_1 + 0x120]`.
const GETTER_RVA: u32 = 0x470a0;

/// RVA of `FUN_180081be0`, which writes `0` to `[param_1 + 0xe5]`.
const SETTER_RVA: u32 = 0x81be0;

fn real_dll() -> Option<PathBuf> {
    let path = std::env::var("CALXGLOSS_TEST_DLL").ok()?;
    let path = Path::new(&path);
    path.exists().then(|| path.to_path_buf())
}

/// An independent model of the target function, used as the oracle.
///
/// The real function performs wrapping 64-bit arithmetic, so the model must too
/// or the boundary cases will disagree for the wrong reason.
fn model(p1: i64, p2: i32) -> i64 {
    p1.wrapping_add((p2 as i64).wrapping_add(4).wrapping_mul(8))
}

fn test_case(p1: i64, p2: i32) -> TestCase {
    TestCase {
        inputs: json!({ "param_1": p1, "param_2": p2 }),
        expected_return: Value::Null,
        expected_side_effects: Vec::new(),
        expected_api_calls: Vec::new(),
        origin: calxgloss_types::CaseOrigin::Generated,
        case_kind: None,
    }
}

/// The boundary cases the MVP criteria call for, including both ends of the
/// 32-bit range and a value past 4GB.
fn cases() -> Vec<TestCase> {
    vec![
        test_case(0, 0),
        test_case(0x1000, 0),
        test_case(0, -4),
        test_case(0, -5),
        test_case(0, 1),
        test_case(0x1000, -1),
        test_case(0xdead_beef, 7),
        test_case(0, i32::MAX),
        test_case(0, i32::MIN),
        test_case(0x1_0000_0000, 1),
    ]
}

fn runner(work_dir: &Path) -> WineRunner {
    WineRunner::new(work_dir)
}

/// Build a spec for a Ghidra-style internal function.
fn spec(signature: &str, rva: u32) -> HarnessSpec {
    let sig = parse_signature(signature).expect("signature should parse");
    let image = PeImage::parse(&real_dll().expect("CALXGLOSS_TEST_DLL")).expect("PE should parse");
    HarnessSpec::new(
        &format!("FUN_1800{rva:x}"),
        FunctionLocator::Rva(rva),
        &sig,
        image.machine(),
    )
    .expect("spec should build")
}

#[test]
#[ignore = "needs Wine, a real DLL, and the windows-gnu Rust target"]
fn baseline_return_values_match_the_model() {
    let Some(binary) = real_dll() else {
        eprintln!("CALXGLOSS_TEST_DLL not set; skipping");
        return;
    };
    let image = PeImage::parse(&binary).expect("PE should parse");
    let work = tempfile::tempdir().expect("tempdir");

    let spec = spec(TARGET_SIGNATURE, TARGET_RVA);
    let test_cases = cases();
    let report = runner(work.path())
        .run(&spec, &binary, &test_cases, image.machine())
        .expect("harness should run");

    // Every case must be accounted for, and none may have crashed the process.
    assert_eq!(
        report.results.len(),
        test_cases.len(),
        "expected a result per case; stderr: {}",
        report.stderr
    );

    // Compare each result against the model, reading the inputs from that case's
    // own entry so the expectation cannot drift from the input it describes.
    let mut mismatches = Vec::new();
    for result in &report.results {
        assert!(
            !result.crashed,
            "case {} crashed the harness: {:?}",
            result.index, result.error
        );
        let case = &test_cases[result.index];
        let p1 = case.inputs["param_1"].as_i64().expect("p1");
        let p2 = case.inputs["param_2"].as_i64().expect("p2") as i32;
        let want = model(p1, p2);
        let got = result.returned.as_i64();
        println!("p1={p1:#x} p2={p2}: got {got:?}, want {want}");
        if got != Some(want) {
            mismatches.push((result.index, got, want, result.error.clone()));
        }
    }

    assert!(
        mismatches.is_empty(),
        "{}/{} cases disagree with the model: {mismatches:#?}",
        mismatches.len(),
        test_cases.len()
    );
}

#[test]
#[ignore = "needs Wine, a real DLL, and the windows-gnu Rust target"]
fn baseline_reaches_memory_accessing_functions() {
    let Some(binary) = real_dll() else {
        eprintln!("CALXGLOSS_TEST_DLL not set; skipping");
        return;
    };
    let image = PeImage::parse(&binary).expect("PE should parse");
    let work = tempfile::tempdir().expect("tempdir");
    let r = runner(work.path());

    // FUN_1800470a0 returns the u32 at [param_1 + 0x120]. A uniform 0xff fill
    // makes the read observable: whatever it returns must be 0xffffffff, since
    // every byte in the buffer is 0xff.
    let getter_sig = parse_signature("uint FUN_1800470a0(undefined *param_1)").unwrap();
    let getter = HarnessSpec::new(
        "FUN_1800470a0",
        FunctionLocator::Rva(GETTER_RVA),
        &getter_sig,
        image.machine(),
    )
    .unwrap();
    let buffer = json!({ "param_1": { "__alloc": { "size": "0x400", "fill": "0xff" } } });
    let getter_case = TestCase {
        inputs: buffer,
        expected_return: Value::Null,
        expected_side_effects: Vec::new(),
        expected_api_calls: Vec::new(),
        origin: calxgloss_types::CaseOrigin::Generated,
        case_kind: None,
    };
    let report = r
        .run(
            &getter,
            &binary,
            std::slice::from_ref(&getter_case),
            image.machine(),
        )
        .expect("getter should run");
    let result = &report.results[0];
    assert!(!result.crashed, "getter crashed: {:?}", result.error);
    assert!(result.ok, "getter failed: {:?}", result.error);
    assert_eq!(
        result.returned.as_u64(),
        Some(0xffff_ffff),
        "getter should read back the 0xff fill"
    );

    // FUN_180081be0 returns void and writes 0 to [param_1 + 0xe5]. There is no
    // return value to check, so this asserts the call completes and writes to a
    // live buffer instead of faulting the way it would if the harness passed a
    // raw unmapped address.
    let setter_sig = parse_signature("void FUN_180081be0(undefined *param_1)").unwrap();
    let setter = HarnessSpec::new(
        "FUN_180081be0",
        FunctionLocator::Rva(SETTER_RVA),
        &setter_sig,
        image.machine(),
    )
    .unwrap();
    let report = r
        .run(&setter, &binary, &[getter_case], image.machine())
        .expect("setter should run");
    let result = &report.results[0];
    assert!(!result.crashed, "setter crashed: {:?}", result.error);
    assert!(result.ok, "setter failed: {:?}", result.error);
    // A void call sends no payload.
    assert_eq!(result.returned, Value::Null);
}

#[test]
#[ignore = "needs Wine, a real DLL, and the windows-gnu Rust target"]
fn baseline_reports_a_faulting_function_instead_of_hanging() {
    let Some(binary) = real_dll() else {
        eprintln!("CALXGLOSS_TEST_DLL not set; skipping");
        return;
    };
    let image = PeImage::parse(&binary).expect("PE should parse");
    let work = tempfile::tempdir().expect("tempdir");

    // Calling through a null pointer must fault. The runner has to come back
    // with a failed result rather than losing the whole batch, which is the
    // job of the per-case isolation retry.
    let sig = parse_signature("uint FUN_1800470a0(undefined *param_1)").unwrap();
    let spec = HarnessSpec::new(
        "FUN_1800470a0",
        FunctionLocator::Rva(GETTER_RVA),
        &sig,
        image.machine(),
    )
    .unwrap();

    let cases: Vec<TestCase> = vec![
        // Valid: an allocated buffer.
        TestCase {
            inputs: json!({ "param_1": { "__alloc": { "size": "0x400", "fill": "0xff" } } }),
            expected_return: Value::Null,
            expected_side_effects: Vec::new(),
            expected_api_calls: Vec::new(),
            origin: calxgloss_types::CaseOrigin::Generated,
            case_kind: None,
        },
        // Faults: a null pointer.
        TestCase {
            inputs: json!({ "param_1": null }),
            expected_return: Value::Null,
            expected_side_effects: Vec::new(),
            expected_api_calls: Vec::new(),
            origin: calxgloss_types::CaseOrigin::Generated,
            case_kind: None,
        },
        // Valid again, to prove the batch continued past the fault.
        TestCase {
            inputs: json!({ "param_1": { "__alloc": { "size": "0x400", "fill": 0 } } }),
            expected_return: Value::Null,
            expected_side_effects: Vec::new(),
            expected_api_calls: Vec::new(),
            origin: calxgloss_types::CaseOrigin::Generated,
            case_kind: None,
        },
    ];

    let report = runner(work.path())
        .run(&spec, &binary, &cases, image.machine())
        .expect("harness should run");

    assert_eq!(
        report.results.len(),
        3,
        "every case should be accounted for"
    );

    // The first and third cases are buffer reads and should succeed.
    assert!(
        report.results[0].ok,
        "case 0: {:?}",
        report.results[0].error
    );
    assert_eq!(report.results[0].returned.as_u64(), Some(0xffff_ffff));
    assert!(
        report.results[2].ok,
        "case 2: {:?}",
        report.results[2].error
    );
    assert_eq!(report.results[2].returned.as_u64(), Some(0));

    // The middle case dereferenced null, so it must be reported as a failure
    // rather than silently passing.
    assert!(
        !report.results[1].ok,
        "a null dereference must not report success"
    );
}

#[test]
#[ignore = "needs Wine, a real DLL, and the windows-gnu Rust target"]
fn baseline_resolves_a_va_through_the_image_base() {
    let Some(binary) = real_dll() else {
        eprintln!("CALXGLOSS_TEST_DLL not set; skipping");
        return;
    };
    let image = PeImage::parse(&binary).expect("PE should parse");

    // This is the step the whole design depends on: a decompiler virtual
    // address becomes a call target through the image base.
    let decomp_va = image.va_from_rva(TARGET_RVA);
    let locator = calxgloss_testgen::locator_for_va(&image, decomp_va).expect("locator");
    assert_eq!(locator, FunctionLocator::Rva(TARGET_RVA));

    // The same lookup driven by the decompiler's function name.
    let by_name =
        calxgloss_testgen::locator_for_function(&image, "FUN_18008ed50").expect("locator");
    assert_eq!(by_name, FunctionLocator::Rva(TARGET_RVA));
}

#[test]
#[ignore = "needs Wine, a real DLL, and the windows-gnu Rust target"]
fn full_load_mode_still_produces_a_baseline() {
    let Some(binary) = real_dll() else {
        eprintln!("CALXGLOSS_TEST_DLL not set; skipping");
        return;
    };
    let image = PeImage::parse(&binary).expect("PE should parse");
    let work = tempfile::tempdir().expect("tempdir");

    let mut spec = spec(TARGET_SIGNATURE, TARGET_RVA);
    // Runs Delphi's DllMain, which a function needing runtime state requires.
    spec.load_mode = LoadMode::Full;

    let test_cases = cases();
    let report = runner(work.path())
        .run(&spec, &binary, &test_cases, image.machine())
        .expect("harness should run");

    assert_eq!(report.results.len(), test_cases.len());
    for result in &report.results {
        assert!(
            result.ok,
            "case {} failed: {:?}",
            result.index, result.error
        );
        let case = &test_cases[result.index];
        let p1 = case.inputs["param_1"].as_i64().unwrap();
        let p2 = case.inputs["param_2"].as_i64().unwrap() as i32;
        assert_eq!(
            result.returned.as_i64(),
            Some(model(p1, p2)),
            "case {} disagreed after full load",
            result.index
        );
    }
}

#[test]
#[ignore = "needs Wine, a real DLL, and the windows-gnu Rust target"]
fn generated_harness_has_no_dependencies() {
    // The generated project must stay dependency-free so cross-compiling it
    // does not need a registry fetch. That keeps the harness build fast and
    // self-contained.
    let spec = HarnessSpec::new(
        "FUN_18008ed50",
        FunctionLocator::Rva(TARGET_RVA),
        &parse_signature(TARGET_SIGNATURE).unwrap(),
        calxgloss_testgen::Machine::X86_64,
    )
    .unwrap();
    let src = generate_harness(&spec).unwrap();
    assert!(!src.contains("serde"), "harness must not depend on serde");
    assert!(
        !src.contains("extern crate"),
        "harness must not declare crates"
    );
}

/// The public entry point end to end: a DLL path, a decompiler function name, a
/// signature, and test cases in — ground truth out.
///
/// This is the path the rest of the pipeline actually calls, so it is the one
/// that has to be shown to work, not just the runner underneath it.
#[tokio::test]
#[ignore = "needs Wine, a real DLL, and the windows-gnu Rust target"]
async fn baseline_runner_returns_ground_truth_for_a_ghidra_function() {
    let Some(binary) = real_dll() else {
        eprintln!("CALXGLOSS_TEST_DLL not set; skipping");
        return;
    };
    let work = tempfile::tempdir().expect("tempdir");
    let runner = BaselineRunner::new(work.path());

    // Expectations are stated here so the comparison is tested, not just the
    // capture: the model below is derived from the decompiled body.
    let expected: Vec<Value> = cases()
        .iter()
        .map(|c| {
            let p1 = c.inputs["param_1"].as_i64().unwrap();
            let p2 = c.inputs["param_2"].as_i64().unwrap() as i32;
            json!(model(p1, p2))
        })
        .collect();
    let test_cases: Vec<TestCase> = cases()
        .into_iter()
        .zip(expected)
        .map(|(mut c, want)| {
            c.expected_return = want;
            c
        })
        .collect();

    let results = runner
        .run(
            "eqmain.dll",
            "FUN_18008ed50",
            TARGET_SIGNATURE,
            &test_cases,
            &binary,
        )
        .await
        .expect("baseline should run");

    assert_eq!(results.len(), test_cases.len());
    for result in &results {
        assert!(result.passed, "case failed: {:?}", result.error);
        assert_eq!(
            result.actual_return, result.test_case.expected_return,
            "the captured value must equal what the model predicted"
        );
    }
}

/// A case whose expectation is wrong has to come back as a failure.
///
/// Without this, a runner that returned `passed: true` unconditionally would
/// pass the test above while having checked nothing.
#[tokio::test]
#[ignore = "needs Wine, a real DLL, and the windows-gnu Rust target"]
async fn baseline_runner_reports_a_mismatch_against_the_expectation() {
    let Some(binary) = real_dll() else {
        eprintln!("CALXGLOSS_TEST_DLL not set; skipping");
        return;
    };
    let work = tempfile::tempdir().expect("tempdir");
    let runner = BaselineRunner::new(work.path());

    // `FUN_18008ed50(0, 0)` returns 32, so 33 is deliberately wrong.
    let test_cases = vec![TestCase {
        inputs: json!({ "param_1": 0, "param_2": 0 }),
        expected_return: json!(33),
        expected_side_effects: Vec::new(),
        expected_api_calls: Vec::new(),
        origin: calxgloss_types::CaseOrigin::Generated,
        case_kind: None,
    }];

    let results = runner
        .run(
            "eqmain.dll",
            "FUN_18008ed50",
            TARGET_SIGNATURE,
            &test_cases,
            &binary,
        )
        .await
        .expect("baseline should run");

    assert_eq!(results.len(), 1);
    assert!(
        !results[0].passed,
        "a wrong expectation must not report a pass"
    );
    assert_eq!(results[0].actual_return, json!(32));
    let error = results[0].error.as_deref().unwrap_or_default();
    assert!(
        error.contains("expected 33") && error.contains("returned 32"),
        "{error}"
    );
}

// ---------------------------------------------------------------------------
// The shared-fixture targets (`calxgloss-testfixtures`), which need only Wine
// and the windows-gnu target — no external DLL. These pin the ordered
// API-call trace end to end: the harness interposes the import address table,
// records every scoped call in execution order, and the report carries the
// trace from the wire all the way into a saved baseline.
// ---------------------------------------------------------------------------

/// Build and run a harness for one fixture export and return the per-case
/// results. `WineRunner::run` compiles the harness itself and retries a batch
/// that dies partway case by case, which is exactly the isolation path the
/// trace tests need.
fn run_one(
    work: &Path,
    dll: &Path,
    export: &str,
    signature: &str,
    inputs_json: &[Value],
    scope: &[&str],
) -> Vec<calxgloss_testgen::HarnessTestResult> {
    let image = PeImage::parse(dll).expect("fixture target should parse as a PE image");
    let signature = parse_signature(signature).expect("signature should parse");
    let spec = HarnessSpec::new(
        export,
        FunctionLocator::ExportName(export.to_string()),
        &signature,
        image.machine(),
    )
    .expect("spec should build")
    .with_trace_scope(scope.iter().copied());

    let cases: Vec<TestCase> = inputs_json
        .iter()
        .map(|inputs| TestCase {
            inputs: inputs.clone(),
            expected_return: Value::Null,
            expected_side_effects: Vec::new(),
            expected_api_calls: Vec::new(),
            origin: calxgloss_types::CaseOrigin::Generated,
            case_kind: None,
        })
        .collect();

    let runner = WineRunner::new(work);
    runner
        .preflight_wine()
        .expect("wine should be installed to run these tests");
    let report = runner
        .run(&spec, dll, &cases, image.machine())
        .expect("the fixture harness should run");
    assert_eq!(
        report.results.len(),
        cases.len(),
        "every case must come back; stderr: {}",
        report.stderr
    );
    report.results
}

/// `fixture_tick` calls `puts` and then `GetTickCount`, in that statement
/// order; the report must carry exactly that ordered trace — not a sorted or
/// deduplicated set.
#[test]
#[ignore = "needs Wine and the windows-gnu Rust target"]
fn fixture_tick_reports_its_ordered_api_trace() {
    let work = tempfile::tempdir().expect("tempdir");
    let target =
        calxgloss_testfixtures::fixture_target_path().expect("fixture target should be built");
    let results = run_one(
        work.path(),
        &target,
        "fixture_tick",
        "unsigned int fixture_tick(void)",
        &[json!({})],
        &["puts", "GetTickCount"],
    );
    assert_eq!(results.len(), 1);
    let r = &results[0];
    assert!(!r.crashed, "fixture_tick crashed: {:?}", r.error);
    assert!(r.ok, "fixture_tick failed: {:?}", r.error);
    assert_eq!(
        r.trace,
        vec!["puts".to_string(), "GetTickCount".to_string()],
        "the trace must be the ordered sequence of interposed calls"
    );
}

/// `fixture_ordered`'s imports are data-dependent — `OutputDebugStringA`'s
/// buffer is built from `GetTickCount`'s return — so the recorded order can
/// only come from the call sites, not from the import table's layout.
#[test]
#[ignore = "needs Wine and the windows-gnu Rust target"]
fn fixture_ordered_records_a_data_dependent_trace_in_call_order() {
    let work = tempfile::tempdir().expect("tempdir");
    let target =
        calxgloss_testfixtures::fixture_target_path().expect("fixture target should be built");
    let results = run_one(
        work.path(),
        &target,
        "fixture_ordered",
        "unsigned int fixture_ordered(int *param_1)",
        &[
            json!({ "param_1": { "__alloc": { "size": 4, "fill": 1 } } }),
            // A captured buffer materialises as a fresh allocation holding
            // exactly the captured bytes (P23.3): the bytes the record saw,
            // not a fill pattern.
            json!({ "param_1": { "__alloc": { "size": 4, "bytes": "deadbeef" } } }),
        ],
        &["GetTickCount", "OutputDebugStringA"],
    );
    assert_eq!(results.len(), 2);
    let r = &results[0];
    assert!(!r.crashed, "fixture_ordered crashed: {:?}", r.error);
    assert!(r.ok, "fixture_ordered failed: {:?}", r.error);
    assert_eq!(
        r.trace,
        vec!["GetTickCount".to_string(), "OutputDebugStringA".to_string()],
        "the trace must follow call-site order, not the import table's order"
    );
    // The exact-content allocation reached the target intact: the u32 read
    // back from the fresh buffer is the captured bytes little-endian.
    let captured = &results[1];
    assert!(
        !captured.crashed,
        "captured-bytes case crashed: {:?}",
        captured.error
    );
    assert!(
        captured.ok,
        "captured-bytes case failed: {:?}",
        captured.error
    );
    assert_eq!(
        captured.returned.as_u64(),
        Some(0xefbe_adde),
        "the fresh allocation must hold the captured bytes"
    );
}

/// A batch with one faulting case retries each case in its own process run;
/// every result must carry *its own* trace, never an earlier case's — and the
/// faulting case must still come back (an empty trace is *unassessed*, never
/// a claim that the target called nothing).
#[test]
#[ignore = "needs Wine and the windows-gnu Rust target"]
fn fixture_isolation_scopes_the_trace_per_case() {
    let work = tempfile::tempdir().expect("tempdir");
    let target =
        calxgloss_testfixtures::fixture_target_path().expect("fixture target should be built");
    let buffer = json!({ "param_1": { "__alloc": { "size": 4, "fill": 1 } } });
    let results = run_one(
        work.path(),
        &target,
        "fixture_ordered",
        "unsigned int fixture_ordered(int *param_1)",
        &[buffer.clone(), json!({ "param_1": null }), buffer.clone()],
        &["GetTickCount", "OutputDebugStringA"],
    );
    assert_eq!(results.len(), 3, "every case must come back");
    let expected = vec!["GetTickCount".to_string(), "OutputDebugStringA".to_string()];
    assert_eq!(results[0].index, 0);
    assert_eq!(results[1].index, 1);
    assert_eq!(results[2].index, 2);
    assert!(
        results[0].ok && results[2].ok,
        "the good cases must pass: {:?} {:?}",
        results[0].error,
        results[2].error
    );
    assert!(
        results[1].crashed || !results[1].ok,
        "the null-deref case must be reported as a fault, got {:?}",
        results[1]
    );
    assert_eq!(results[0].trace, expected, "case 0's trace");
    assert!(
        results[1].trace.is_empty(),
        "the faulting case's trace must not leak a previous case's: {:?}",
        results[1].trace
    );
    assert_eq!(
        results[2].trace, expected,
        "case 2 must re-record its own trace"
    );
}

/// A target with exports but no import directory is not an error: the
/// interposer degrades, the call still runs, and the trace stays empty —
/// which the pipeline must read as *unassessed*, never as "called nothing".
#[test]
#[ignore = "needs Wine and the windows-gnu Rust target"]
fn fixture_without_imports_yields_an_empty_trace_and_completes() {
    let work = tempfile::tempdir().expect("tempdir");
    let plain =
        calxgloss_testfixtures::plain_target_path().expect("plain fixture target should be built");
    let results = run_one(
        work.path(),
        &plain,
        "plain_add",
        "int plain_add(int a, int b)",
        &[json!({ "a": 1, "b": 2 })],
        &["GetTickCount"],
    );
    assert_eq!(results.len(), 1);
    let r = &results[0];
    assert!(!r.crashed, "plain_add crashed: {:?}", r.error);
    assert!(r.ok, "plain_add failed: {:?}", r.error);
    assert!(
        r.trace.is_empty(),
        "a target with no import table records no trace, got {:?}",
        r.trace
    );
}

/// `BaselineRunner::run` derives the trace scope from the target's own
/// imports, so the caller never passes a scope, and the trace lands in the
/// report (capture + case expectation) that the pipeline saves as the
/// baseline.
#[tokio::test]
#[ignore = "needs Wine and the windows-gnu Rust target"]
async fn baseline_runner_records_fixture_tick_trace_into_the_report() {
    let work = tempfile::tempdir().expect("tempdir");
    let target =
        calxgloss_testfixtures::fixture_target_path().expect("fixture target should be built");
    let runner = BaselineRunner::new(work.path());
    let inputs = json!({});
    let results = runner
        .run(
            "fixture_target.dll",
            "fixture_tick",
            "unsigned int fixture_tick(void)",
            &[TestCase {
                inputs: inputs.clone(),
                expected_return: Value::Null,
                expected_side_effects: Vec::new(),
                expected_api_calls: Vec::new(),
                origin: calxgloss_types::CaseOrigin::Generated,
                case_kind: None,
            }],
            &target,
        )
        .await
        .expect("the fixture harness should run");
    let r = &results[0];
    assert!(r.passed, "fixture_tick failed: {:?}", r.error);
    assert_eq!(
        r.actual_api_calls,
        vec!["puts".to_string(), "GetTickCount".to_string()],
        "the runner must derive the trace scope from the target's imports"
    );
    assert_eq!(r.test_case.inputs, inputs);
    assert_eq!(
        r.test_case.expected_api_calls, r.actual_api_calls,
        "the saved baseline's expected trace must carry the capture"
    );
}

/// A missing DLL is a reportable condition, not a panic or a silent pass.
#[tokio::test]
async fn baseline_runner_reports_a_missing_dll_without_touching_wine() {
    let work = tempfile::tempdir().expect("tempdir");
    let runner = BaselineRunner::new(work.path());
    let missing = work.path().join("no-such-library.dll");
    let test_cases = vec![TestCase {
        inputs: json!({ "param_1": 0, "param_2": 0 }),
        expected_return: Value::Null,
        expected_side_effects: Vec::new(),
        expected_api_calls: Vec::new(),
        origin: calxgloss_types::CaseOrigin::Generated,
        case_kind: None,
    }];

    let results = runner
        .run(
            "no-such-library.dll",
            "FUN_18008ed50",
            TARGET_SIGNATURE,
            &test_cases,
            &missing,
        )
        .await
        .expect("a missing DLL should be reported, not raised");

    assert_eq!(results.len(), 1);
    assert!(!results[0].passed);
    assert!(
        results[0]
            .error
            .as_deref()
            .is_some_and(|e| e.contains("not found")),
        "{:?}",
        results[0].error
    );
}
// --- armed entry recording (P23.4, issue #398) ------------------------------

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod live_entry_hook {
    //! Arm a recording trampoline on a real fixture export, run it under
    //! Wine, and fold what was recorded through the existing `--ingest`
    //! path. What only this Wine-gated run can prove: the patched export
    //! address table really redirects every `GetProcAddress` — including
    //! the harness's own locator — into a recorded call that still reaches
    //! the real entry, and the folded events replay through the baseline
    //! harness into a filed case.

    use super::*;
    use calxgloss_testgen::{EntryHook, Replay, ScalarKind, TestGenerator, fold_capture_event_log};
    use calxgloss_types::CaseOrigin;

    /// The armed run of `fixture_status(int code)` records the call as it
    /// arrived at the export entry, the armed run's own result is unchanged
    /// from the uninstrumented run, and folding the recorded log through
    /// the harness replay path files one mined-hook case.
    #[tokio::test]
    #[ignore = "needs Wine and the windows-gnu Rust target"]
    async fn an_entry_hooked_run_records_the_call_and_its_replay_files_a_case() {
        let work = tempfile::tempdir().expect("tempdir");
        let store = tempfile::tempdir().expect("tempdir");
        let dll =
            calxgloss_testfixtures::fixture_target_path().expect("fixture target should be built");
        let image = PeImage::parse(&dll).expect("fixture target should parse as a PE image");
        let signature = parse_signature("int fixture_status(int code)")
            .expect("fixture signature should parse");

        let cases = [TestCase {
            inputs: json!({ "code": 7 }),
            expected_return: Value::Null,
            expected_side_effects: Vec::new(),
            expected_api_calls: Vec::new(),
            origin: CaseOrigin::Generated,
            case_kind: None,
        }];

        let plain_spec = HarnessSpec::new(
            "fixture_status",
            FunctionLocator::ExportName("fixture_status".to_string()),
            &signature,
            image.machine(),
        )
        .expect("spec should build");

        let runner = WineRunner::new(work.path());
        runner
            .preflight_wine()
            .expect("wine should be installed to run these tests");

        // The uninstrumented run first: today's suite is the standard.
        let plain = runner
            .run(&plain_spec, &dll, &cases, image.machine())
            .expect("the un-armed fixture harness should run");
        assert_eq!(plain.results.len(), 1);
        assert!(plain.results[0].ok, "{:?}", plain.results[0].error);

        // Armed: the run's own export entry gets the recording trampoline.
        let armed_spec = plain_spec.clone().with_entry_hooks([EntryHook {
            name: "fixture_status".to_string(),
            arg_kinds: vec![ScalarKind::I32],
        }]);
        let armed = runner
            .run(&armed_spec, &dll, &cases, image.machine())
            .expect("the entry-hooked fixture harness should run");
        assert!(
            !armed.results[0].crashed,
            "the hooked call crashed: {:?}; stderr: {}",
            armed.results[0].error, armed.stderr
        );
        assert_eq!(
            armed.results[0].returned, plain.results[0].returned,
            "the hook records the call, it does not change it"
        );

        // The run recorded the entry it made: the argument vector as it
        // arrived, numbered under this run's capture id.
        let log = armed
            .capture_log
            .as_ref()
            .expect("an armed run leaves a capture log");
        let entries = log["entries"].as_array().expect("entries array");
        assert!(
            !entries.is_empty(),
            "the entry-hooked run recorded at least one entry event; stderr: {}",
            armed.stderr
        );
        let entry = &entries[0];
        assert_eq!(entry["export"], "fixture_status");
        assert_eq!(entry["binary"], "fixture_target.dll");
        assert_eq!(
            entry["arguments"][0],
            json!({"scalar": {"tag": "i32", "value": 7}}),
            "the scalar argument is recorded as it arrived"
        );

        // The recorded events replay through the baseline harness and file
        // a case — the existing `capture --ingest` fold, unchanged.
        let generator = TestGenerator::new(store.path());
        let exports = [calxgloss_types::Export {
            name: "fixture_status".to_string(),
            address: 0,
            signature: "int fixture_status(int code)".to_string(),
        }];
        let folded = fold_capture_event_log(
            &generator,
            "fixture_target.dll",
            &exports,
            log,
            &Replay::Harness { dll_path: &dll },
        )
        .await
        .expect("the fold should run");
        assert_eq!(folded.report.events_seen, entries.len());
        assert!(
            folded.report.cases_mined >= 1,
            "a replayed entry event files a case; refusals: {:?}",
            folded.report.refusals
        );
        let rows = generator
            .load_baseline("fixture_target.dll", "fixture_status")
            .expect("a filed baseline suite");
        assert!(
            rows.iter().any(|row| matches!(
                &row.test_case.origin,
                CaseOrigin::MinedHook { capture_id, event_sequence }
                    if capture_id == "baseline-hook:fixture_target.dll:fixture_status"
                        && *event_sequence >= 1
            )),
            "the filed case's evidence names the baseline hook run: {:?}",
            rows.iter()
                .map(|row| row.test_case.origin.clone())
                .collect::<Vec<_>>()
        );
    }

    /// A pointer argument is recorded as bytes read out of the running
    /// process — only from VirtualQuery-verified committed memory, so the
    /// recorder never faults — and the recorded buffer starts with exactly
    /// what the harness had written there.
    #[test]
    #[ignore = "needs Wine and the windows-gnu Rust target"]
    fn a_hooked_run_reads_a_pointer_argument_out_of_the_target_process() {
        let work = tempfile::tempdir().expect("tempdir");
        let dll =
            calxgloss_testfixtures::fixture_target_path().expect("fixture target should be built");
        let image = PeImage::parse(&dll).expect("fixture target should parse as a PE image");
        let signature = parse_signature("unsigned int fixture_ordered(int *probe)")
            .expect("fixture signature should parse");

        let cases = [TestCase {
            inputs: json!({ "probe": { "__alloc": { "size": 4, "bytes": "44556677" } } }),
            expected_return: Value::Null,
            expected_side_effects: Vec::new(),
            expected_api_calls: Vec::new(),
            origin: CaseOrigin::Generated,
            case_kind: None,
        }];

        let spec = HarnessSpec::new(
            "fixture_ordered",
            FunctionLocator::ExportName("fixture_ordered".to_string()),
            &signature,
            image.machine(),
        )
        .expect("spec should build")
        .with_entry_hooks([EntryHook {
            name: "fixture_ordered".to_string(),
            arg_kinds: vec![ScalarKind::Ptr],
        }]);

        let runner = WineRunner::new(work.path());
        runner
            .preflight_wine()
            .expect("wine should be installed to run these tests");
        let report = runner
            .run(&spec, &dll, &cases, image.machine())
            .expect("the entry-hooked fixture harness should run");

        // The hooked call still returns what the real entry returns: the
        // captured bytes read back little-endian.
        assert_eq!(
            report.results[0].returned.as_u64(),
            Some(0x7766_5544),
            "the hook records the call, it does not change it; stderr: {}\n\
             result: ok={} error={:?} crashed={}",
            report.stderr,
            report.results[0].ok,
            report.results[0].error,
            report.results[0].crashed,
        );

        let log = report
            .capture_log
            .expect("an armed run leaves a capture log");
        let entries = log["entries"].as_array().expect("entries array");
        assert!(
            !entries.is_empty(),
            "the entry-hooked run recorded at least one entry event; stderr: {}",
            report.stderr
        );
        // The recorded arguments speak the fold's wire vocabulary: one
        // externally tagged descriptor per argument. The probe's pointer
        // descriptor carries the captured bytes read out of committed
        // memory inside the target process.
        let pointer = entries
            .iter()
            .flat_map(|entry| entry["arguments"].as_array().cloned().unwrap_or_default())
            .find_map(|argument| argument.get("pointer").cloned())
            .expect("the hooked run recorded a pointer capture argument");
        let bytes = pointer["bytes"].as_array().expect("bytes array");
        assert!(
            bytes.len() >= 4,
            "the probe read the buffer it was pointed at"
        );
        assert_eq!(
            bytes[..4],
            [json!(0x44), json!(0x55), json!(0x66), json!(0x77)],
            "the recorded bytes are what the harness had written there"
        );
        assert!(
            pointer["captured_size"].is_number() && pointer["truncated"].is_boolean(),
            "the capture states its observed size and truncation stamp"
        );
        // Whether the region extent runs past the capture bound is the
        // target's business; either way the record states it, and the
        // fold's refusal vocabulary for a truncation is pinned by fold's
        // own tests. What this proves is the probe's honesty: bytes only
        // from verified committed memory, never a fault, never an invention.
    }
}
// --- recording proxy (P23.5, issue #399) ------------------------------------

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod live_recording_proxy {
    //! Point a generated caller harness at a recording proxy wearing a
    //! real DLL's binary identity, and show the reference-app run records
    //! the calls that really arrive at the proxy and folds them through
    //! the `--ingest` fold into filed cases. What only this Wine-gated run
    //! can prove: the caller really lands on the proxy's exports, a
    //! recorded call still reaches the real entry — the return value says
    //! so — and live memory is captured under the capture bound.

    use super::*;
    use calxgloss_testgen::{
        ProxySlot, Replay, ScalarKind, TestGenerator, fold_capture_event_log,
        generate_recording_proxy, px_real_name, px_stderr_notes,
    };
    use calxgloss_types::{CaseOrigin, Export};
    use std::fs;

    /// Generate and cargo-build the proxy under the fixture's binary
    /// identity, laid out as the caller run needs it: the proxy owns the
    /// identity, the real DLL sits beside it under its real name.
    fn lay_proxy(
        runner: &WineRunner,
        dll: &Path,
        build: &Path,
        run_dir: &Path,
        recorded: &str,
        kinds: &[ScalarKind],
    ) -> PathBuf {
        std::fs::create_dir_all(run_dir).expect("run dir");
        let image = PeImage::parse(dll).expect("fixture target should parse as a PE image");
        let slots: Vec<ProxySlot> = image
            .exports()
            .iter()
            .filter(|e| !e.name.is_empty() && !e.is_forwarder)
            .map(|e| {
                if e.name == recorded {
                    ProxySlot::recorded(&e.name, kinds.to_vec())
                } else {
                    ProxySlot::forwarding(&e.name)
                }
            })
            .collect();
        let generation =
            generate_recording_proxy("fixture_target.dll", &slots, Some(image.machine()))
                .expect("the proxy should generate for an x86-64 target");
        fs::create_dir_all(build.join(".cargo")).expect("cargo dir");
        let def = build.join("px_fixture_target.def");
        fs::write(&def, &generation.def).expect("def file");
        fs::write(
            build.join(".cargo/config.toml"),
            format!(
                "[build]\nrustflags = [\"-C\", \"link-arg=-Wl,{}\"]\n",
                def.display()
            ),
        )
        .expect("cargo config");
        let proxy_path = runner
            .build_recording_proxy("fixture_target.dll", &generation, image.machine(), run_dir)
            .expect("the proxy should cargo-build under wine");
        assert_eq!(
            proxy_path,
            run_dir.join("fixture_target.dll"),
            "the proxy wears the identity it was generated for"
        );
        fs::copy(dll, run_dir.join(px_real_name("fixture_target.dll")))
            .expect("the real dll sits beside the proxy");
        proxy_path
    }

    /// The fixture built as a caller: the harness's own calls are the
    /// arriving calls the proxy must record and forward. The run loads
    /// full, not `DONT_RESOLVE_DLL_REFERENCES`: the proxy is a real module
    /// whose `DllMain` and TLS must attach for its capture machinery to
    /// work, exactly like the real target's full-load mode.
    fn caller_spec(dll: &Path, function: &str, signature: &str) -> HarnessSpec {
        let image = PeImage::parse(dll).expect("fixture target should parse as a PE image");
        let signature = parse_signature(signature).expect("fixture signature should parse");
        let mut spec = HarnessSpec::new(
            function,
            FunctionLocator::ExportName(function.to_string()),
            &signature,
            image.machine(),
        )
        .expect("spec should build");
        spec.load_mode = LoadMode::Full;
        spec
    }

    /// A caller run through the proxy records its arriving calls, forwards
    /// them transparently, and the recording folds into filed cases under
    /// the reference-app capture id.
    #[tokio::test]
    #[ignore = "needs Wine and the windows-gnu Rust target"]
    async fn a_reference_app_run_through_the_proxy_folds_into_filed_cases() {
        let work = tempfile::tempdir().expect("tempdir");
        let store = tempfile::tempdir().expect("tempdir");
        let build = work.path().join("px_build");
        let run = work.path().join("px_run");
        fs::create_dir_all(&run).expect("run dir");
        let dll =
            calxgloss_testfixtures::fixture_target_path().expect("fixture target should be built");
        let image = PeImage::parse(&dll).expect("fixture target should parse as a PE image");
        let runner = WineRunner::new(work.path());
        runner
            .preflight_wine()
            .expect("wine should be installed to run these tests");

        // The uninstrumented caller first: the plain fixture run is the
        // standard the transparent proxy has to answer to.
        let plain_spec = caller_spec(&dll, "fixture_status", "int fixture_status(int code)");
        let cases = [TestCase {
            inputs: json!({ "code": 7 }),
            expected_return: Value::Null,
            expected_side_effects: Vec::new(),
            expected_api_calls: Vec::new(),
            origin: CaseOrigin::Generated,
            case_kind: None,
        }];
        let plain = runner
            .run(&plain_spec, &dll, &cases, image.machine())
            .expect("the plain caller run should complete");
        assert!(plain.results[0].ok, "{:?}", plain.results[0].error);

        let proxy_dll = lay_proxy(
            &runner,
            &dll,
            &build,
            &run,
            "fixture_status",
            &[ScalarKind::I32],
        );
        assert_ne!(
            fs::read(&proxy_dll).expect("proxy bytes"),
            fs::read(&dll).expect("real dll bytes"),
            "the proxy is its own module, not a copy of the real one"
        );

        let caller = runner
            .run(&plain_spec, &proxy_dll, &cases, image.machine())
            .expect("the caller run against the proxy should complete");
        assert!(
            !caller.results[0].crashed,
            "the caller should survive the proxy: {:?}; stderr: {}",
            caller.results[0].error, caller.stderr
        );
        let notes = px_stderr_notes(&caller.stderr);
        assert!(
            notes.is_empty(),
            "the proxy should run clean, noted: {notes:?}"
        );
        assert_eq!(
            caller.results[0].returned, plain.results[0].returned,
            "the proxy forwards transparently: the recorded call reaches the real entry"
        );

        // The proxy's entry events ride the harness's own event protocol;
        // they assemble into a capture event log under the reference-app
        // capture id.
        let log = runner.px_capture_log("fixture_target.dll", &caller.entry_events, &notes);
        assert_eq!(log["schema"], json!("capture-log-v1"));
        assert_eq!(log["capture_id"], json!("reference-app:fixture_target.dll"));
        let entries = log["entries"].as_array().expect("entries array");
        assert!(
            !entries.is_empty(),
            "the proxy records the call that arrived; stderr: {}\nrun: (results: {:?}, \
             reported: {})\nentries: {:#?}",
            caller.stderr,
            caller.results,
            caller.reported,
            log
        );
        let entry = entries
            .iter()
            .find(|entry| entry["export"] == json!("fixture_status"))
            .expect("the armed export's arriving call is recorded");
        assert_eq!(entry["binary"], json!("fixture_target.dll"));
        assert_eq!(
            entry["arguments"][0],
            json!({"scalar": {"tag": "i32", "value": 7}}),
            "the argument vector is recorded as it arrived"
        );

        // The fold: the proxy's capture log files cases through the very
        // `capture --ingest` fold, under the reference-app capture id.
        let exports = vec![Export {
            name: "fixture_status".to_string(),
            address: 0,
            signature: "int fixture_status(int code)".to_string(),
        }];
        let generator = TestGenerator::new(store.path());
        let folded = fold_capture_event_log(
            &generator,
            "fixture_target.dll",
            &exports,
            &log,
            &Replay::Harness { dll_path: &dll },
        )
        .await
        .expect("the proxy capture log should fold");
        assert_eq!(folded.report.events_seen, entries.len());
        assert!(
            folded.report.cases_mined >= 1,
            "a recorded proxy call files a case; refusals: {:?}",
            folded.report.refusals
        );
        let rows = generator
            .load_baseline("fixture_target.dll", "fixture_status")
            .expect("a filed baseline suite");
        assert!(
            rows.iter().any(|row| matches!(
                &row.test_case.origin,
                CaseOrigin::MinedHook { capture_id, event_sequence }
                    if capture_id == "reference-app:fixture_target.dll" && *event_sequence >= 1
            )),
            "the filed case's evidence names the reference-app run: {:?}",
            rows.iter()
                .map(|row| row.test_case.origin.clone())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            entries
                .iter()
                .find(|entry| entry["export"] == json!("fixture_status"))
                .expect("the armed export's entry")["lane"],
            json!("reference_app"),
            "the recorded calls are stamped as arriving on the reference-app lane"
        );
    }

    /// The capture bound applies to what a proxy really records: a pointer
    /// argument becomes a pointer capture out of live memory, and the call
    /// still reaches the real entry.
    #[test]
    #[ignore = "needs Wine and the windows-gnu Rust target"]
    fn the_proxy_records_a_live_pointer_capture_and_still_forwards() {
        let work = tempfile::tempdir().expect("tempdir");
        let build = work.path().join("px_build");
        let run = work.path().join("px_run");
        fs::create_dir_all(&run).expect("run dir");
        let dll =
            calxgloss_testfixtures::fixture_target_path().expect("fixture target should be built");
        let image = PeImage::parse(&dll).expect("fixture target should parse as a PE image");
        let runner = WineRunner::new(work.path());
        runner
            .preflight_wine()
            .expect("wine should be installed to run these tests");

        let proxy_dll = lay_proxy(
            &runner,
            &dll,
            &build,
            &run,
            "fixture_ordered",
            &[ScalarKind::Ptr],
        );

        let spec = caller_spec(
            &dll,
            "fixture_ordered",
            "unsigned int fixture_ordered(int *probe)",
        );
        let cases = [TestCase {
            inputs: json!({ "probe": { "__alloc": { "size": 4, "bytes": "44556677" } } }),
            expected_return: Value::Null,
            expected_side_effects: Vec::new(),
            expected_api_calls: Vec::new(),
            origin: CaseOrigin::Generated,
            case_kind: None,
        }];
        let caller = runner
            .run(&spec, &proxy_dll, &cases, image.machine())
            .expect("the caller run against the proxy should complete");
        assert!(
            !caller.results[0].crashed,
            "the caller should survive the proxy: {:?}",
            caller.results[0].error
        );
        assert_eq!(
            caller.results[0].returned.as_u64(),
            Some(0x7766_5544),
            "the recorded call reaches the real entry — it reads the caller's \
             own buffer back little-endian; stderr: {}",
            caller.stderr
        );
        let log = runner.px_capture_log("fixture_target.dll", &caller.entry_events, &[]);
        let entries = log["entries"].as_array().expect("entries array");
        let pointer = entries
            .iter()
            .flat_map(|entry| entry["arguments"].as_array().cloned().unwrap_or_default())
            .find_map(|argument| argument.get("pointer").cloned())
            .expect("the proxy recorded a pointer capture; log: {log}");
        let bytes = pointer["bytes"].as_array().expect("bytes array");
        assert!(
            bytes.len() >= 4,
            "the pointer capture reaches into the caller's buffer"
        );
        assert_eq!(
            bytes[..4],
            [json!(0x44), json!(0x55), json!(0x66), json!(0x77)],
            "the recorded bytes are a faithful copy of the caller's live memory"
        );
        assert!(
            pointer["captured_size"].is_number() && pointer["truncated"].is_boolean(),
            "the capture states its observed size and truncation stamp"
        );
    }
}
