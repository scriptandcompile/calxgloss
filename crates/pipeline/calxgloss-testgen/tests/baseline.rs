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

/// The signature Ghidra reports for that function.
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
    let Some(dll) = real_dll() else {
        eprintln!("CALXGLOSS_TEST_DLL not set; skipping");
        return;
    };
    let image = PeImage::parse(&dll).expect("PE should parse");
    let work = tempfile::tempdir().expect("tempdir");

    let spec = spec(TARGET_SIGNATURE, TARGET_RVA);
    let test_cases = cases();
    let report = runner(work.path())
        .run(&spec, &dll, &test_cases, image.machine())
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
    let Some(dll) = real_dll() else {
        eprintln!("CALXGLOSS_TEST_DLL not set; skipping");
        return;
    };
    let image = PeImage::parse(&dll).expect("PE should parse");
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
    };
    let report = r
        .run(
            &getter,
            &dll,
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
    // live buffer rather than faulting — which is what a raw unmapped address
    // would have done.
    let setter_sig = parse_signature("void FUN_180081be0(undefined *param_1)").unwrap();
    let setter = HarnessSpec::new(
        "FUN_180081be0",
        FunctionLocator::Rva(SETTER_RVA),
        &setter_sig,
        image.machine(),
    )
    .unwrap();
    let report = r
        .run(&setter, &dll, &[getter_case], image.machine())
        .expect("setter should run");
    let result = &report.results[0];
    assert!(!result.crashed, "setter crashed: {:?}", result.error);
    assert!(result.ok, "setter failed: {:?}", result.error);
    // A void call carries no payload.
    assert_eq!(result.returned, Value::Null);
}

#[test]
#[ignore = "needs Wine, a real DLL, and the windows-gnu Rust target"]
fn baseline_reports_a_faulting_function_instead_of_hanging() {
    let Some(dll) = real_dll() else {
        eprintln!("CALXGLOSS_TEST_DLL not set; skipping");
        return;
    };
    let image = PeImage::parse(&dll).expect("PE should parse");
    let work = tempfile::tempdir().expect("tempdir");

    // Calling through a null pointer must fault. The runner has to come back with
    // a failed result rather than losing the whole batch, which is what the
    // per-case isolation pass exists for.
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
        },
        // Faults: a null pointer.
        TestCase {
            inputs: json!({ "param_1": null }),
            expected_return: Value::Null,
            expected_side_effects: Vec::new(),
        },
        // Valid again, to prove the batch continued past the fault.
        TestCase {
            inputs: json!({ "param_1": { "__alloc": { "size": "0x400", "fill": 0 } } }),
            expected_return: Value::Null,
            expected_side_effects: Vec::new(),
        },
    ];

    let report = runner(work.path())
        .run(&spec, &dll, &cases, image.machine())
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
    let Some(dll) = real_dll() else {
        eprintln!("CALXGLOSS_TEST_DLL not set; skipping");
        return;
    };
    let image = PeImage::parse(&dll).expect("PE should parse");

    // This is the step the whole design rests on: a Ghidra virtual address
    // becomes a call target via the image base.
    let ghidra_va = image.va_from_rva(TARGET_RVA);
    let locator = calxgloss_testgen::locator_for_va(&image, ghidra_va).expect("locator");
    assert_eq!(locator, FunctionLocator::Rva(TARGET_RVA));

    // And the same thing driven by Ghidra's function naming.
    let by_name =
        calxgloss_testgen::locator_for_function(&image, "FUN_18008ed50").expect("locator");
    assert_eq!(by_name, FunctionLocator::Rva(TARGET_RVA));
}

#[test]
#[ignore = "needs Wine, a real DLL, and the windows-gnu Rust target"]
fn full_load_mode_still_produces_a_baseline() {
    let Some(dll) = real_dll() else {
        eprintln!("CALXGLOSS_TEST_DLL not set; skipping");
        return;
    };
    let image = PeImage::parse(&dll).expect("PE should parse");
    let work = tempfile::tempdir().expect("tempdir");

    let mut spec = spec(TARGET_SIGNATURE, TARGET_RVA);
    // Runs Delphi's DllMain, which is what a function needing runtime state needs.
    spec.load_mode = LoadMode::Full;

    let test_cases = cases();
    let report = runner(work.path())
        .run(&spec, &dll, &test_cases, image.machine())
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
    // The generated project must stay dependency-free so cross-compiling it does
    // not need a registry fetch. This is what keeps the harness build fast and
    // hermetic.
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

/// The public entry point end to end: a DLL path, a Ghidra function name, a
/// signature, and test cases in — ground truth out.
///
/// This is the path the rest of the pipeline actually calls, so it is the one
/// that has to be shown to work, not just the runner underneath it.
#[tokio::test]
#[ignore = "needs Wine, a real DLL, and the windows-gnu Rust target"]
async fn baseline_runner_returns_ground_truth_for_a_ghidra_function() {
    let Some(dll) = real_dll() else {
        eprintln!("CALXGLOSS_TEST_DLL not set; skipping");
        return;
    };
    let work = tempfile::tempdir().expect("tempdir");
    let runner = BaselineRunner::new(work.path());

    // Expectations are stated here so the comparison is exercised, not just the
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
            &dll,
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
    let Some(dll) = real_dll() else {
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
    }];

    let results = runner
        .run(
            "eqmain.dll",
            "FUN_18008ed50",
            TARGET_SIGNATURE,
            &test_cases,
            &dll,
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
