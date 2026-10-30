//! The API-call trace verdict at the gate (the P22 trace dimension).
//!
//! The restitch gate proves a unit returns the right values; the trace
//! dimension proves it gets there by the right route. These tests scaffold
//! a real scratch project, run the real generated test runner, and read the
//! verdict back from the verification record — the same path the retry
//! ladder reads. Like this crate's other compile-backed tests, they hide
//! behind `#[ignore]`:
//!
//! ```text
//! cargo test -p calxgloss-verify --test api_trace_verdict -- --ignored
//! ```

use calxgloss_types::{TestCase, VerificationResult};
use calxgloss_verify::Verifier;
use serde_json::json;

/// The translated body under verification: it reaches the value 7 through
/// the verify PAL surface in one known order — `create_texture`,
/// `create_render_target`, `blit`, `present`.
const PAL_BODY: &str = r#"
pub fn call_no_params() -> serde_json::Value {
    let mut device = GraphicsDeviceStub::default();
    let texture = device.create_texture(2, 2);
    let mut target = device.create_render_target(2, 2);
    device.blit(&texture, &mut target);
    device.present();
    serde_json::Value::from(7)
}
"#;

/// The body's own call order, as the recorder must report it.
const BODY_TRACE: [&str; 4] = [
    "create_texture",
    "create_render_target",
    "blit",
    "present",
];

/// One baseline case demanding value 7 with the given expected trace.
fn case_with_trace(expected_trace: &[&str]) -> TestCase {
    TestCase {
        inputs: json!(null),
        expected_return: json!(7),
        expected_side_effects: Vec::new(),
        expected_api_calls: expected_trace.iter().map(|name| (*name).to_string()).collect(),
    }
}

/// Scaffold, compile, and run one translation through the real runner.
async fn scratch_verify(body: &str, cases: &[TestCase]) -> VerificationResult {
    let work = tempfile::tempdir().expect("temp work dir");
    let verifier = Verifier::new(work.path()).expect("verifier");
    verifier
        .verify("fixture_target.dll", "restitched_trace", body, cases)
        .await
        .expect("verification runs")
}

/// A translation whose value matches but whose PAL-surface call order
/// diverges from the expected trace fails the test, names the divergence
/// as a trace divergence, and carries both sequences side by side as
/// typed data with the first divergence position.
#[tokio::test]
#[ignore = "scaffolds and cargo-runs a real scratch project + runner"]
async fn a_permuted_call_order_fails_as_a_named_trace_divergence() {
    // Same calls, wrong order: present and blit swapped relative to the body.
    let permuted: Vec<&str> = vec![
        "create_texture",
        "create_render_target",
        "present",
        "blit",
    ];
    let result = scratch_verify(PAL_BODY, &[case_with_trace(&permuted)]).await;

    assert!(result.compiled, "the body itself compiles");
    assert_eq!(
        result.tests_total, 1,
        "the runner ran the one baseline case"
    );
    assert_eq!(result.tests_passed, 0, "the wrong path does not pass");

    assert_eq!(result.failed_tests.len(), 1);
    let failure = &result.failed_tests[0];
    assert_eq!(
        failure.error,
        "API-call trace divergence at position 2: \
         expected [create_texture, create_render_target, present, blit], \
         got [create_texture, create_render_target, blit, present]",
        "the failure names the trace divergence with both sequences beside the position"
    );
    assert_eq!(failure.expected_api_calls, permuted);
    assert_eq!(failure.actual_api_calls, BODY_TRACE);
    assert_eq!(failure.trace_divergence_index, Some(2));
    assert_eq!(
        failure.expected, failure.actual,
        "the value verdict stood intact — only the path diverged"
    );
    assert_eq!(
        result.trace_assessed_tests, 1,
        "the trace dimension was assessed for this pass attempt"
    );
}

/// The matching-order twin: the same body demanded through the order it
/// actually executes passes, and the pass is marked trace-assessed — the
/// trace-assessed pass is distinguishable from an unassessed one.
#[tokio::test]
#[ignore = "scaffolds and cargo-runs a real scratch project + runner"]
async fn a_matching_call_order_passes_and_is_marked_assessed() {
    let result = scratch_verify(PAL_BODY, &[case_with_trace(&BODY_TRACE)]).await;

    assert!(result.compiled, "the body itself compiles");
    assert_eq!(result.tests_total, 1);
    assert_eq!(result.tests_passed, 1, "right value, right route: pass");
    assert!(result.failed_tests.is_empty(), "a pass carries no failure record");
    assert_eq!(
        result.trace_assessed_tests, 1,
        "this pass was assessed on the trace dimension"
    );
}

/// A case with no recorded expected trace keeps its value verdict but is
/// never counted as trace-assessed: silence never becomes a trace pass, and
/// the unassessed pass is distinguishable from the assessed one.
#[tokio::test]
#[ignore = "scaffolds and cargo-runs a real scratch project + runner"]
async fn an_empty_expected_trace_leaves_the_value_verdict_unassessed_on_trace() {
    let result = scratch_verify(PAL_BODY, &[case_with_trace(&[])]).await;

    assert!(result.compiled, "the body itself compiles");
    assert_eq!(result.tests_total, 1);
    assert_eq!(result.tests_passed, 1, "the value verdict stands on its own");
    assert!(result.failed_tests.is_empty());
    assert_eq!(
        result.trace_assessed_tests, 0,
        "an unassessed trace never counts as assessed — pass or otherwise"
    );
}

/// Comparison is sequence equality, not pairwise-over-the-shorter-prefix:
/// an expected trace missing one call the body made fails, and the failure
/// names the position where the sequences first part company — the inserted
/// call — not merely a length mismatch.
#[tokio::test]
#[ignore = "scaffolds and cargo-runs a real scratch project + runner"]
async fn an_extra_call_the_expected_trace_never_demanded_diverges_where_it_appears() {
    // The body's route with create_render_target dropped from the demand:
    // equality fails at position 1, where the extra call sits.
    let missing_one: [&str; 3] = ["create_texture", "blit", "present"];
    let result = scratch_verify(PAL_BODY, &[case_with_trace(&missing_one)]).await;

    assert!(result.compiled);
    assert_eq!(result.tests_passed, 0, "a length mismatch is a sequence mismatch");
    assert_eq!(result.failed_tests.len(), 1);
    let failure = &result.failed_tests[0];
    assert_eq!(
        failure.trace_divergence_index,
        Some(1),
        "the divergence is named where the sequences first part company"
    );
    assert_eq!(
        failure.error,
        "API-call trace divergence at position 1: \
         expected [create_texture, blit, present], \
         got [create_texture, create_render_target, blit, present]"
    );
    assert_eq!(result.trace_assessed_tests, 1);
}
