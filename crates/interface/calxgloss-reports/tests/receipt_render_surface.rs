//! The review surface renders *verification receipts* (P25.2, issue
//! #411).
//!
//! The receipt Markdown renderer lives with the record in
//! `calxgloss-types` — the document owns its own human twin, and the
//! verify crate cannot call into reports (reports depend on the
//! translator, which depends on verify) — but the spec names reports as
//! the review surface, so the rendering is re-exported here. This pin
//! holds that contract: the report surface exposes the same renderer,
//! and it renders from the JSON authority's own facts alone.

use calxgloss_reports::verification_receipt_markdown;
use calxgloss_types::{
    BinaryIdentity, DimensionCounts, VerificationReceipt, VerificationVerdict, VerifierCommand,
};
use std::collections::BTreeMap;

/// One real-shaped, digest-folded receipt for the rendering pin to hold up.
fn sample_receipt() -> VerificationReceipt {
    let mut dimensions = BTreeMap::new();
    dimensions.insert(
        "values".to_string(),
        DimensionCounts {
            assessed: 3,
            passed: 2,
        },
    );
    let mut receipt = VerificationReceipt {
        binary: BinaryIdentity::new("game_logic.dll"),
        function: "DrawSprite".to_string(),
        attempt: 2,
        retry_strategy: "compile_fix".to_string(),
        attempt_path: "compile_fix".to_string(),
        verifier_command: VerifierCommand::CompileAndBaselineTest,
        baseline_suite_digest: "sha256:aaa0".to_string(),
        covered_case_kinds: calxgloss_types::CaseKind::ALL.iter().copied().collect(),
        dimensions,
        compile_ms: 4200,
        test_run_ms: 1300,
        total_ms: 6100,
        verdict: VerificationVerdict::TestsFailed,
        failed_cases: vec![1],
        harness_error_reason: None,
        digest: String::new(),
    };
    receipt.digest = receipt.content_digest().expect("the fold");
    receipt
}

#[test]
fn the_report_surface_renders_a_receipt_from_its_json_authority_s_facts() {
    let receipt = sample_receipt();

    let rendered = verification_receipt_markdown(&receipt);
    assert!(rendered.contains(&receipt.digest), "the pair proves itself");
    assert!(rendered.contains("tests_failed"), "the JSON's verdict");
    assert!(
        rendered.contains("assessed 3, passed 2"),
        "the JSON's counts"
    );
    assert!(rendered.contains("case 1"), "the JSON's named failure");
}
