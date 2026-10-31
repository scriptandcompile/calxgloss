//! The API-call trace verdict at the gate (the P22 trace dimension).
//!
//! The restitch gate proves a unit returns the right values; the trace
//! dimension proves it honours the observed route, in order, as a
//! containment inside the full verify-PAL-surface route — extra surface
//! entries the capture vocabulary cannot speak never fail a case. These
//! tests scaffold a real scratch project, run the real generated test
//! runner, and read the verdict back from the verification record — the
//! same path the retry ladder reads. Like this crate's other
//! compile-backed tests, they hide behind `#[ignore]`:
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
const BODY_TRACE: [&str; 4] = ["create_texture", "create_render_target", "blit", "present"];

/// One baseline case demanding value 7 with the given expected trace.
fn case_with_trace(expected_trace: &[&str]) -> TestCase {
    TestCase {
        inputs: json!(null),
        expected_return: json!(7),
        expected_side_effects: Vec::new(),
        expected_api_calls: expected_trace
            .iter()
            .map(|name| (*name).to_string())
            .collect(),
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

/// A permuted expected trace is still a containment failure: the matcher
/// honours the prefix it can, then gives up hunting the first unhonoured
/// expected call. The named position is where in the actual route that
/// search gave up — here the end of the route, after the matcher spent
/// the real `present` on the expected `present` out of order and could
/// no longer find `blit` after it.
#[tokio::test]
#[ignore = "scaffolds and cargo-runs a real scratch project + runner"]
async fn a_permuted_call_order_fails_as_a_named_trace_divergence() {
    // Same calls, wrong order: present and blit swapped relative to the body.
    let permuted: Vec<&str> = vec!["create_texture", "create_render_target", "present", "blit"];
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
        "API-call trace divergence at position 4: \
         expected [create_texture, create_render_target, present, blit], \
         got [create_texture, create_render_target, blit, present]",
        "the failure names the trace divergence with both sequences beside the position"
    );
    assert_eq!(failure.expected_api_calls, permuted);
    assert_eq!(failure.actual_api_calls, BODY_TRACE);
    assert_eq!(
        failure.trace_divergence_index,
        Some(4),
        "the position names where the containment search gave up its hunt for `blit`"
    );
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
    assert!(
        result.failed_tests.is_empty(),
        "a pass carries no failure record"
    );
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
    assert_eq!(
        result.tests_passed, 1,
        "the value verdict stands on its own"
    );
    assert!(result.failed_tests.is_empty());
    assert_eq!(
        result.trace_assessed_tests, 0,
        "an unassessed trace never counts as assessed — pass or otherwise"
    );
}

/// The trace dimension is judged by containment, not sequence equality: an
/// extra surface entry the capture vocabulary can never speak — device
/// housekeeping the IAT interposer was structurally blind to — never fails
/// a case. This pin used to demand exactly such an extra call diverge; its
/// inversion is the change of mind (#388): the capture proves presence and
/// order, never absence, so a folded expectation honoured in order passes
/// even when the route carries more.
#[tokio::test]
#[ignore = "scaffolds and cargo-runs a real scratch project + runner"]
async fn an_extra_surface_call_the_capture_cannot_speak_is_tolerated() {
    // The body's route with create_render_target dropped from the demand —
    // an unspellable housekeeping entry. The fold's expectation
    // [create_texture, blit, present] still rides inside the route, in order.
    let folded: [&str; 3] = ["create_texture", "blit", "present"];
    let result = scratch_verify(PAL_BODY, &[case_with_trace(&folded)]).await;

    assert!(result.compiled);
    assert_eq!(result.tests_total, 1);
    assert_eq!(
        result.tests_passed, 1,
        "the extras never fail — the route honours the folded expectation in order"
    );
    assert!(
        result.failed_tests.is_empty(),
        "a pass carries no failure record"
    );
    assert_eq!(
        result.trace_assessed_tests, 1,
        "the dimension was still assessed against the fold's expectation"
    );
}

/// Containment is no free pass: an expected call the body never makes
/// still fails, named at the position in the actual route where the
/// search gave up hunting it — 0 when the very first expected call was
/// never found, and just past the last honoured call for a later miss.
#[tokio::test]
#[ignore = "scaffolds and cargo-runs a real scratch project + runner"]
async fn an_expected_call_the_body_never_makes_fails_at_the_give_up_position() {
    // Case 0: `set_title` heads the fold's expectation but the body never
    // touches the window surface — the search gives up at the route's
    // start. Case 1: `create_texture` is honoured, then the hunt for
    // `set_title` gives up just past it.
    let result = scratch_verify(
        PAL_BODY,
        &[
            case_with_trace(&["set_title", "blit"]),
            case_with_trace(&["create_texture", "set_title", "blit"]),
        ],
    )
    .await;

    assert!(result.compiled, "the body itself compiles");
    assert_eq!(result.tests_total, 2);
    assert_eq!(
        result.tests_passed, 0,
        "containment never excuses an expected call the body never made"
    );
    assert_eq!(result.failed_tests.len(), 2);
    assert_eq!(
        result.failed_tests[0].trace_divergence_index,
        Some(0),
        "the first expected call was never found — the search gave up at the route's start"
    );
    assert_eq!(
        result.failed_tests[0].error,
        "API-call trace divergence at position 0: \
         expected [set_title, blit], \
         got [create_texture, create_render_target, blit, present]"
    );
    assert_eq!(
        result.failed_tests[1].trace_divergence_index,
        Some(1),
        "the miss follows an honoured call — the search gave up just past it"
    );
    assert_eq!(result.trace_assessed_tests, 2);
}

/// A fold with a repeated captured call demands that repetition: a body
/// that blits once where the fold saw it twice fails, the give-up
/// position naming where the second hunt ran out of route.
#[tokio::test]
#[ignore = "scaffolds and cargo-runs a real scratch project + runner"]
async fn a_repeated_expected_call_honoured_only_once_fails() {
    // The body blits once; the fold demands it twice. The first blit
    // is honoured at position 2, so the second hunt starts at 3 and gives
    // up there — `present` is all the route has left.
    let result = scratch_verify(PAL_BODY, &[case_with_trace(&["blit", "blit"])]).await;

    assert!(result.compiled, "the body itself compiles");
    assert_eq!(result.tests_total, 1);
    assert_eq!(
        result.tests_passed, 0,
        "one blit where the fold saw two is a divergence"
    );
    assert_eq!(result.failed_tests.len(), 1);
    let failure = &result.failed_tests[0];
    assert_eq!(
        failure.trace_divergence_index,
        Some(3),
        "the second hunt gave up just past the single honoured blit"
    );
    assert_eq!(
        failure.error,
        "API-call trace divergence at position 3: \
         expected [blit, blit], \
         got [create_texture, create_render_target, blit, present]"
    );
    assert_eq!(result.trace_assessed_tests, 1);
}

/// Extras after the whole fold has been honoured are tolerated like extras
/// inside it: once the expectation has ridden the route in order, trailing
/// surface entries the capture cannot speak never fail the case.
#[tokio::test]
#[ignore = "scaffolds and cargo-runs a real scratch project + runner"]
async fn trailing_extras_after_a_honoured_expectation_pass() {
    // The fold ends at `blit`; the body still presents afterwards — an
    // entry the drawing capture could never demand.
    let folded: [&str; 3] = ["create_texture", "create_render_target", "blit"];
    let result = scratch_verify(PAL_BODY, &[case_with_trace(&folded)]).await;

    assert!(result.compiled, "the body itself compiles");
    assert_eq!(result.tests_total, 1);
    assert_eq!(
        result.tests_passed, 1,
        "the honoured fold rides the route despite trailing extras"
    );
    assert!(
        result.failed_tests.is_empty(),
        "a pass carries no failure record"
    );
    assert_eq!(
        result.trace_assessed_tests, 1,
        "the dimension was assessed against the fold's expectation"
    );
}

/// The storage shapes that paired cleanly under exact equality keep
/// passing: an exact route is trivially contained in itself, so the
/// change of mind never regresses a unit whose capture was complete.
#[tokio::test]
#[ignore = "scaffolds and cargo-runs a real scratch project + runner"]
async fn a_storage_shaped_exact_route_still_passes_and_is_assessed() {
    // A body that reaches 7 through open/read/close on the file surface,
    // demanded through exactly that route.
    const STORAGE_BODY: &str = r#"
pub fn call_no_params() -> serde_json::Value {
    let fs = FileSystemStub::default();
    let handle = fs
        .open("pin_storage.bin", FileMode::Read)
        .expect("the stub open always works");
    let mut buf = [0u8; 8];
    let _ = fs.read(&handle, &mut buf);
    fs.close(handle).expect("the stub close always works");
    serde_json::Value::from(7)
}
"#;
    let result = scratch_verify(STORAGE_BODY, &[case_with_trace(&["open", "read", "close"])]).await;

    assert!(result.compiled, "the body itself compiles");
    assert_eq!(result.tests_total, 1);
    assert_eq!(
        result.tests_passed, 1,
        "the exact route pairs exactly as before"
    );
    assert!(
        result.failed_tests.is_empty(),
        "a pass carries no failure record"
    );
    assert_eq!(
        result.trace_assessed_tests, 1,
        "this pass was assessed on the trace dimension"
    );
}

/// Thread shapes pair cleanly too: the sleep/spawn/join route that matched
/// exactly under equality still passes under containment, assessed —
/// surface entries recorded only on the main thread, so the route is
/// exactly what the body ran, in order.
#[tokio::test]
#[ignore = "scaffolds and cargo-runs a real scratch project + runner"]
async fn a_thread_shaped_exact_route_still_passes_and_is_assessed() {
    // A body that reaches 7 through sleep, spawn, and join on the thread
    // surface, demanded through exactly that route. The spawned closure
    // touches no surface entry, keeping the recorded route deterministic.
    const THREAD_BODY: &str = r#"
pub fn call_no_params() -> serde_json::Value {
    ThreadStub::sleep(0);
    let worker = ThreadStub::spawn(|| serde_json::Value::from(1))
        .expect("the stub spawn always works");
    ThreadStub::join(worker).expect("the spawned wrapper always joins");
    serde_json::Value::from(7)
}
"#;
    let result = scratch_verify(THREAD_BODY, &[case_with_trace(&["sleep", "spawn", "join"])]).await;

    assert!(result.compiled, "the body itself compiles");
    assert_eq!(result.tests_total, 1);
    assert_eq!(
        result.tests_passed, 1,
        "the exact route pairs exactly as before"
    );
    assert!(
        result.failed_tests.is_empty(),
        "a pass carries no failure record"
    );
    assert_eq!(
        result.trace_assessed_tests, 1,
        "this pass was assessed on the trace dimension"
    );
}
