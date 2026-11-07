//! A mined-origin case rides the existing gate untouched (the P23.1
//! verify-untouched contract pin).
//!
//! The verify side replays whatever the filed baseline document contains;
//! the case-origin field is `#[serde(default)]`, so a hand-stamped mined
//! case rides the current generated suite reader with no verify change at
//! all. These tests scaffold a real scratch project, run the real
//! generated test runner over a suite carrying a mined origin, and read
//! the verdict back — the same path the retry ladder reads. Like this
//! crate's other compile-backed tests, they hide behind `#[ignore]`:
//!
//! ```text
//! cargo test -p calxgloss-verify --test mined_case_rides_the_gate -- --ignored
//! ```

use calxgloss_types::{CaseOrigin, TestCase};
use calxgloss_verify::{Verifier, VerifyContext};
use serde_json::json;

/// The translated body under verification: it always returns 7.
const BODY: &str = r#"
pub fn restitched_mined() -> serde_json::Value {
    serde_json::Value::from(7)
}
"#;

/// A hand-stamped mined-hook case: the expectations of a case whose input
/// vector a real caller once passed, carrying its capture evidence.
fn mined_case() -> TestCase {
    TestCase {
        inputs: json!(null),
        expected_return: json!(7),
        expected_side_effects: Vec::new(),
        expected_api_calls: Vec::new(),
        origin: CaseOrigin::MinedHook {
            capture_id: "cap-pin-1".to_string(),
            event_sequence: 4,
        },
        case_kind: None,
    }
}

/// The gate runs a hand-stamped mined-origin case exactly like a generated
/// one: the suite reader never saw the origin field, the value verdict
/// lands unchanged, and verify's own source stayed zero-diff.
#[tokio::test]
#[ignore = "scaffolds and cargo-runs a real scratch project + runner"]
async fn a_hand_stamped_mined_case_passes_the_gate_unchanged() {
    let work = tempfile::tempdir().expect("temp work dir");
    let verifier = Verifier::new(work.path()).expect("verifier");
    let result = verifier
        .verify(
            "fixture_target.dll",
            "restitched_mined",
            BODY,
            &[mined_case()],
            &VerifyContext::default(),
        )
        .await
        .expect("verification runs")
        .result;

    assert!(result.compiled, "the body itself compiles");
    assert_eq!(
        result.tests_total, 1,
        "the runner ran the one mined-origin case"
    );
    assert_eq!(
        result.tests_passed, 1,
        "the hand-stamped origin rode the existing suite reader — pass unchanged"
    );
    assert!(
        result.failed_tests.is_empty(),
        "a pass carries no failure record"
    );
}
