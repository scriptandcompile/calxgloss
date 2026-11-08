//! The harness calls the unit it is given (issue #416).
//!
//! testgen files each generated case's inputs as a positional value —
//! null for a unit with no parameters, a JSON array of arguments
//! otherwise — and the generated runner dispatches that shape to the
//! function named by the verify request. These pins drive that contract
//! through a real scaffolded project and a real `cargo run`. A
//! pipeline-driven suite can honestly earn a `passed`. An arity the
//! unit never had breaks the harness's own build — the verifier's
//! failure, never the unit's verdict (issue #440 amended #416's stance
//! that it surfaced as the unit's own compile failure). A new test pins
//! that outcome end to end for the everquest workspace's own shape: a
//! zero-argument `extern "system"` unit and a one-element array case
//! (issue #442). A panicking unit fails its case instead of the harness.
//! And when a suite names no expected returns, the values dimension says
//! it assessed nothing rather than claiming a match. Like this crate's
//! other compile-backed tests, they hide behind `#[ignore]`:
//!
//! ```text
//! cargo test -p calxgloss-verify --test positional_dispatch -- --ignored
//! ```

use calxgloss_types::{BinaryIdentity, TestCase, VerifierCommand};
use calxgloss_types::{VerificationReceipt, VerificationVerdict, persist, verification_receipt_path};
use calxgloss_verify::{Verifier, VerifyContext};
use serde_json::json;

/// Drive one body + suite through the real gate, keeping the receipt
/// beside the result for the dimension assertions.
async fn gate(
    function: &str,
    body: &str,
    cases: &[TestCase],
) -> (calxgloss_types::VerificationResult, VerificationReceipt) {
    let work = tempfile::tempdir().expect("temp work dir");
    let verifier = Verifier::new(work.path()).expect("verifier");
    let run = verifier
        .verify(
            "positional_dispatch.dll",
            function,
            body,
            cases,
            &VerifyContext::default(),
        )
        .await
        .expect("verification runs");
    (run.result, run.receipt)
}

/// A generated case as testgen files it: positional inputs, no expected
/// return yet — the suite a pipeline-driven attempt actually carries.
fn generated_case(inputs: serde_json::Value) -> TestCase {
    TestCase {
        inputs,
        expected_return: json!(null),
        expected_side_effects: Vec::new(),
        expected_api_calls: Vec::new(),
        origin: calxgloss_types::CaseOrigin::Generated,
        case_kind: None,
    }
}

/// A pipeline-driven attempt whose unit matches its signature earns a
/// real `passed` from the real runner — and the receipt says the values
/// dimension assessed nothing, because no generated case named an
/// expected return (ADR-0057: a pass that compared no values must say
/// so, not look like a values match).
#[tokio::test]
#[ignore = "scaffolds and cargo-runs a real scratch project + runner"]
async fn a_pipeline_shaped_suite_honestly_passes_the_generated_unit() {
    let body = "pub fn fixture_gate() -> u32 { let mut d = GraphicsDeviceStub::default(); d.create_texture(2, 2); d.present(); 7 }";
    let (result, receipt) = gate("fixture_gate", body, &[generated_case(json!(null))]).await;

    assert!(result.compiled, "the generated unit compiles");
    assert_eq!(
        result.tests_total, 1,
        "the null case ran through the runner"
    );
    assert_eq!(result.tests_passed, 1, "and the harness called the unit");
    assert_eq!(
        result.value_assessed_tests, 0,
        "no case named an expected return"
    );
    assert_eq!(receipt.verdict, VerificationVerdict::Passed);
    assert_eq!(
        receipt.verifier_command,
        VerifierCommand::CompileAndBaselineTest,
        "a case ran — the full gate, not a compile-only stand-in"
    );
    let values = &receipt.dimensions["values"];
    assert_eq!(
        (values.assessed, values.passed),
        (0, 0),
        "the pass compared no values, and the receipt records 0 assessed — never a 6/6 values match it did not earn"
    );
}

/// An arity the unit never defined is the harness's own build failure,
/// not the unit's (issue #440, amending #416): the unit passes the
/// compile leg, the null-input arm's zero-argument call is rejected
/// inside the scratch test project — in the generated runner, the
/// harness's own file — and the run hands back an `Err` carrying the
/// mismatch text, never a `VerificationResult`. The pair it files is
/// verdicted `harness_error`; no `compile_failed` pair stands under
/// the run's key.
#[tokio::test]
#[ignore = "scaffolds and cargo-runs a real scratch project + runner"]
async fn an_arity_the_unit_never_defined_is_a_harness_error_not_a_compile_failure() {
    let body = "pub fn fixture_gate(code: u32) -> u32 { code }";
    let work = tempfile::tempdir().expect("temp work dir");
    let verifier = Verifier::new(work.path()).expect("verifier");
    let error = verifier
        .verify(
            "positional_dispatch.dll",
            "fixture_gate",
            body,
            &[generated_case(json!(null))],
            &VerifyContext::default(),
        )
        .await
        .expect_err("a test project that never built is the verifier's error, never a unit verdict");

    // The build-error text still rides the hand-back, so a human can
    // read whose code broke — and whose did not.
    let handed_back = error.to_string();
    assert!(
        handed_back.contains("this function takes 1 argument but 0 arguments were supplied"),
        "the reason names the mismatch: {handed_back}"
    );

    // What travels under the run's key: a harness-error pair, and never
    // a compile-failed one — the compile leg logged success.
    let pair = verification_receipt_path(
        work.path(),
        &BinaryIdentity::new("positional_dispatch.dll"),
        "fixture_gate",
        1,
    );
    let filed: VerificationReceipt = persist::load_json(&pair).expect("the filed authority reads");
    assert_eq!(filed.verdict, VerificationVerdict::HarnessError);
}

/// Pin the everquest workspace's shape end to end (issue #442).
///
/// All three units of the 2026-11-07 live run hit this shape. A
/// zero-argument `extern "system"` unit meets a mined case carrying a
/// one-element positional argument array. The mismatch breaks the
/// generated runner's build inside the scratch test project. The real
/// gate answers with an error naming the mismatch. It files a
/// `harness_error` pair, and the pair's reason quotes the build error.
/// No `compile_failed` pair stands under the run's key.
#[tokio::test]
#[ignore = "scaffolds and cargo-runs a real scratch project + runner"]
async fn the_everquest_workspace_shape_answers_with_a_harness_error_pair() {
    let body = "#[no_mangle]\npub extern \"system\" fn sub_401033() -> core::ffi::c_int { 0 }";
    let mut mined_case = generated_case(json!([0]));
    mined_case.case_kind = Some(calxgloss_types::CaseKind::Positive);
    let work = tempfile::tempdir().expect("temp work dir");
    let verifier = Verifier::new(work.path()).expect("verifier");
    let error = verifier
        .verify(
            "LaunchPad.exe",
            "sub_401033",
            body,
            &[mined_case],
            &VerifyContext::default(),
        )
        .await
        .expect_err("the workspace's broken-gate shape answers with an error, never a verdict");

    // The hand-back quotes the build error in the generated runner —
    // the harness's own file — naming whose code did not build.
    let handed_back = error.to_string();
    assert!(
        handed_back.contains("this function takes 0 arguments but 1 argument was supplied"),
        "the reason names the mismatch: {handed_back}"
    );

    let pair = verification_receipt_path(
        work.path(),
        &BinaryIdentity::new("LaunchPad.exe"),
        "sub_401033",
        1,
    );
    let filed: VerificationReceipt = persist::load_json(&pair).expect("the filed authority reads");
    assert_eq!(filed.verdict, VerificationVerdict::HarnessError);
    let reason = filed
        .harness_error_reason
        .as_deref()
        .expect("the pair names which arm of the gate broke");
    assert!(
        reason.contains("this function takes 0 arguments but 1 argument was supplied"),
        "the filed reason quotes the build error: {reason}"
    );

    // Nothing else stands under this (binary, function) key: the compile
    // leg logged success, so no pair may claim the unit did not compile.
    let unit_key = pair
        .parent()
        .expect("the pair files under a unit directory");
    let filed_verdicts: Vec<VerificationVerdict> = std::fs::read_dir(unit_key)
        .expect("the unit's receipt directory")
        .filter_map(|entry| {
            let path = entry.expect("directory entry").path();
            (path.extension() == Some(std::ffi::OsStr::new("json"))).then(|| {
                persist::load_json::<VerificationReceipt>(&path)
                    .expect("a filed pair reads")
                    .verdict
            })
        })
        .collect();
    assert_eq!(
        filed_verdicts,
        vec![VerificationVerdict::HarnessError],
        "exactly one pair stands under the run's key, and it is never `compile_failed`"
    );
}

/// A suite whose generated case carries arguments dispatches them
/// positionally, coercing to the unit's own parameter types.
#[tokio::test]
#[ignore = "scaffolds and cargo-runs a real scratch project + runner"]
async fn a_positional_case_calls_the_unit_with_its_arguments() {
    let body = "pub fn fixture_sum(a: u32, b: i32) -> i64 { a as i64 + b as i64 }";
    let mut case = generated_case(json!([40, 2]));
    case.expected_return = json!(42);
    let (result, receipt) = gate("fixture_sum", body, &[case]).await;

    assert_eq!(
        result.tests_passed, 1,
        "the harness called fixture_sum(40, 2)"
    );
    assert_eq!(result.value_assessed_tests, 1);
    assert_eq!(result.values_matched_tests, 1);
    let values = &receipt.dimensions["values"];
    assert_eq!((values.assessed, values.passed), (1, 1));
    assert_eq!(receipt.verdict, VerificationVerdict::Passed);
}

/// A unit that panics on an input fails that case — with the panic named
/// in the failure — while the harness itself survives to report every
/// other case. tests_failed, never harness-error.
#[tokio::test]
#[ignore = "scaffolds and cargo-runs a real scratch project + runner"]
async fn a_panicking_unit_fails_its_case_not_the_harness() {
    let body = r#"pub fn fixture_gate() -> u32 { panic!("off-by-one in the loop bound") }"#;
    let (result, receipt) = gate(
        "fixture_gate",
        body,
        &[generated_case(json!(null)), generated_case(json!(null))],
    )
    .await;

    assert!(
        result.compiled,
        "the body compiles — it just panics when called"
    );
    assert_eq!(
        result.failed_tests.len(),
        2,
        "both cases ran and both failed"
    );
    assert!(
        result.failed_tests[0]
            .error
            .contains("the unit panicked: off-by-one in the loop bound"),
        "the panic message rides the failure: {:?}",
        result.failed_tests[0].error
    );
    assert_eq!(
        result.value_assessed_tests, 0,
        "an uncalled return assesses nothing"
    );
    assert_eq!(receipt.verdict, VerificationVerdict::TestsFailed);
}

/// A named-object input — the shape the harness used to refuse with a
/// sentinel string while calling nothing — now fails its own case by
/// name, honestly, instead of pretending the suite was judged.
#[tokio::test]
#[ignore = "scaffolds and cargo-runs a real scratch project + runner"]
async fn an_uncallable_named_object_input_fails_its_case() {
    let body = "pub fn fixture_gate() -> u32 { let mut d = GraphicsDeviceStub::default(); d.create_texture(2, 2); d.present(); 7 }";
    let (result, _receipt) = gate(
        "fixture_gate",
        body,
        &[generated_case(json!({"param_0": 1}))],
    )
    .await;

    assert_eq!(result.failed_tests.len(), 1);
    assert!(
        result.failed_tests[0]
            .error
            .contains("gives fixture_gate no callable arguments"),
        "the failure names the unit and the uncallable input: {:?}",
        result.failed_tests[0].error
    );
    assert_eq!(result.value_assessed_tests, 0);
}
