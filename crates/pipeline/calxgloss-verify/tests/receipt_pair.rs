//! The *verification receipt* pair a verify run files (P25.2, issue #411).
//!
//! Every verify run — pass, tests-failed, or compile-failed — files a pair
//! under the record convention beside `re/baseline/`: the JSON authority
//! plus its Markdown twin, **paired by content digest**. A reader holding
//! only the pair re-derives the JSON's own digest and finds it named again
//! in the rendering, so neither file can be edited apart from its twin
//! unnoticed. The receipt mirrors the returned [`VerificationResult`]'s
//! facts, names the baseline suite digest it was earned against, and
//! stands keyed on its place in the retry sequence — filed pairs are never
//! edited in place. Like this crate's other compile-backed tests, these
//! pins hide behind `#[ignore]`:
//!
//! ```text
//! cargo test -p calxgloss-verify --test receipt_pair -- --ignored
//! ```

use std::path::{Path, PathBuf};

use calxgloss_types::{
    BinaryIdentity, TestCase, VerificationReceipt, VerificationVerdict, VerifierCommand,
    baseline_suite_digest, persist, verification_receipt_path,
};
use calxgloss_verify::{VerificationRun, Verifier, VerifyContext};
use serde_json::json;

const BINARY: &str = "receipt_fixture.dll";
const FUNCTION: &str = "receipt_gate";

/// A body that always returns 7, with no surface calls.
const BODY: &str = "pub fn call_no_params() -> serde_json::Value { serde_json::Value::from(7) }";

/// The failing twin: the same unit never compiles.
const BROKEN_BODY: &str = "pub fn call_no_params() -> serde_json::Value { \"not an int\" }";

/// One baseline case demanding value `want` through no params.
fn case(want: i64) -> TestCase {
    TestCase {
        inputs: json!(null),
        expected_return: json!(want),
        expected_side_effects: Vec::new(),
        expected_api_calls: Vec::new(),
        origin: calxgloss_types::CaseOrigin::Generated,
    }
}

/// One real run through the real engine; the scratch dir lives until the
/// caller is done reading what the run filed.
async fn scratch_run(
    context: &VerifyContext<'_>,
    body: &str,
    cases: &[TestCase],
) -> (VerificationRun, tempfile::TempDir) {
    let work = tempfile::tempdir().expect("temp work dir");
    let verifier = Verifier::new(work.path()).expect("verifier");
    let run = verifier
        .verify(BINARY, FUNCTION, body, cases, context)
        .await
        .expect("verification runs");
    (run, work)
}

fn unit_dir(work: &Path) -> PathBuf {
    verification_receipt_path(work, &BinaryIdentity::new(BINARY), FUNCTION, 1)
}

/// The reader's check, from the pair's contents alone: the JSON names its
/// own digest over its canonical body, and the Markdown twin carries that
/// same digest.
fn pair_verifies(json_path: &Path) -> VerificationReceipt {
    let filed: VerificationReceipt =
        persist::load_json(json_path).expect("the filed JSON authority reads");
    assert_eq!(
        filed.content_digest().expect("the fold"),
        filed.digest,
        "the JSON names itself: {}",
        filed.digest
    );
    let md_path = json_path.with_extension("md");
    let md = std::fs::read_to_string(&md_path).expect("the Markdown twin stands beside it");
    assert!(
        md.contains(&filed.digest),
        "the Markdown carries the same digest:\n{md}"
    );
    filed
}

/// A passing run files its pair under the record convention, paired by
/// digest, with dimension counts mirroring the returned result and the
/// handed-back receipt identical to the filed one.
#[tokio::test]
#[ignore = "scaffolds and cargo-runs a real scratch project + runner"]
async fn a_passing_verify_run_files_its_digest_paired_pair_beside_the_baseline() {
    let (run, work) = scratch_run(&VerifyContext::default(), BODY, &[case(7)]).await;
    let json_path = unit_dir(work.path());
    assert_eq!(
        json_path,
        work.path()
            .join("re/verification/receipt_fixture.dll/receipt_gate/attempt-1.json"),
        "under the record convention beside re/baseline/"
    );

    let filed = pair_verifies(&json_path);
    assert_eq!(filed.verdict, VerificationVerdict::Passed);
    assert_eq!(filed.binary.as_str(), BINARY);
    assert_eq!(filed.function, FUNCTION);
    assert_eq!(filed.attempt, 1);
    // The dimension map mirrors the returned result's facts.
    assert_eq!(
        (
            filed.dimensions["values"].assessed,
            filed.dimensions["values"].passed
        ),
        (run.result.tests_total, run.result.tests_passed),
        "values counts mirror the returned result"
    );
    assert_eq!(
        filed.dimensions["api_trace"].assessed, run.result.trace_assessed_tests,
        "the trace dimension mirrors the returned result too"
    );
    // Timings are present: the real cargo build and runner both took time.
    assert!(filed.compile_ms > 0, "compile timing present");
    assert!(filed.test_run_ms > 0, "test-run timing present");
    assert!(filed.total_ms > 0, "total timing present");

    // The verifier owns its receipt: the handed-back document is the filed one.
    assert_eq!(
        run.receipt, filed,
        "the receipt travels to the caller intact"
    );
    assert_eq!(run.receipt.digest, filed.digest);
}

/// Drift never hides: a reader who recomputes over an edited JSON finds a
/// digest that no longer matches its twin.
#[tokio::test]
#[ignore = "scaffolds and cargo-runs a real scratch project + runner"]
async fn an_edited_authority_fails_the_reader_s_pairing_recomputation() {
    let (_run, work) = scratch_run(&VerifyContext::default(), BODY, &[case(8)]).await;
    let json_path = unit_dir(work.path());
    let filed = pair_verifies(&json_path);
    assert_eq!(filed.verdict, VerificationVerdict::TestsFailed);

    // Someone edits the filed verdict to claim a pass the run never earned.
    let edited = {
        let mut document: serde_json::Value = persist::load_json(&json_path).expect("reads");
        document["verdict"] = json!("passed");
        document["digest"] = json!(&filed.digest);
        serde_json::to_string(&document).expect("re-serializes")
    };
    std::fs::write(&json_path, &edited).expect("the tampering lands");
    let tampered: VerificationReceipt =
        persist::load_json(&json_path).expect("the edited document still parses");
    assert_ne!(
        tampered.content_digest().expect("the fold"),
        tampered.digest,
        "the edited authority no longer names itself — the pairing catches the drift"
    );
}

/// A tests-failed run files a pair too, with the matching verdict and the
/// failed cases named on the human side.
#[tokio::test]
#[ignore = "scaffolds and cargo-runs a real scratch project + runner"]
async fn a_tests_failed_run_files_its_pair_naming_the_failed_cases() {
    let (run, work) = scratch_run(&VerifyContext::default(), BODY, &[case(8)]).await;
    let json_path = unit_dir(work.path());
    let filed = pair_verifies(&json_path);

    assert_eq!(filed.verdict, VerificationVerdict::TestsFailed);
    assert_eq!(filed.failed_cases, vec![0], "the diverged case is named");
    let md = std::fs::read_to_string(json_path.with_extension("md")).expect("twin reads");
    assert!(
        md.contains("case 0"),
        "and named on the rendering too:\n{md}"
    );
    assert_eq!(filed.verdict, VerificationVerdict::TestsFailed);
    assert_eq!(run.result.failed_tests.len(), 1);
}

/// A compile-failed run files its pair, names the compile-failed verdict,
/// and assesses nothing — nothing ran to be assessed.
#[tokio::test]
#[ignore = "scaffolds and cargo-runs a real scratch project + runner"]
async fn a_compile_failed_run_files_a_pair_that_assesses_nothing() {
    let (_run, work) = scratch_run(&VerifyContext::default(), BROKEN_BODY, &[case(7)]).await;
    let json_path = unit_dir(work.path());
    let filed = pair_verifies(&json_path);

    assert_eq!(filed.verdict, VerificationVerdict::CompileFailed);
    assert_eq!(
        filed.verifier_command,
        VerifierCommand::CompileOnly,
        "no baseline case ever ran through a runner — the gate was compile-only as invoked"
    );
    assert_eq!(filed.dimensions["values"].assessed, 0, "nothing ran");
    assert_eq!(filed.dimensions["values"].passed, 0);
    assert_eq!(filed.dimensions["api_trace"].assessed, 0);
    assert_eq!(filed.test_run_ms, 0, "no test leg ever ran");
}

/// A value that matched while the observed route did not: the pair says
/// the values dimension passed and the trace dimension did not — each
/// dimension counts only what it was qualified to assess (ADR-0057).
#[tokio::test]
#[ignore = "scaffolds and cargo-runs a real scratch project + runner"]
async fn a_trace_divergence_with_a_matching_value_splits_the_dimension_counts() {
    let mut diverging = case(7); // the body returns 7, so the value leg passes
    diverging.expected_api_calls = vec!["create_texture".to_string(), "present".to_string()];
    let (run, work) = scratch_run(&VerifyContext::default(), BODY, &[diverging]).await;
    let filed = pair_verifies(&unit_dir(work.path()));

    assert_eq!(
        filed.verdict,
        VerificationVerdict::TestsFailed,
        "the case still failed — on the route, not the value"
    );
    assert_eq!(filed.failed_cases, vec![0], "and the failed case is named");
    assert_eq!(
        (
            filed.dimensions["values"].assessed,
            filed.dimensions["values"].passed
        ),
        (1, 1),
        "the value leg was assessed and passed"
    );
    assert_eq!(
        (
            filed.dimensions["api_trace"].assessed,
            filed.dimensions["api_trace"].passed
        ),
        (1, 0),
        "the trace leg was assessed and diverged"
    );
    assert_eq!(
        filed.dimensions["values"],
        calxgloss_types::DimensionCounts {
            assessed: run.result.tests_total,
            passed: run.result.tests_passed + 1,
        },
        "the map mirrors the returned result's facts exactly"
    );
}

/// A run with no cases still files: an explicit empty-suite digest, never
/// a missing field, and the compile-only gate reads off the receipt.
#[tokio::test]
#[ignore = "scaffolds and cargo-runs a real scratch project + runner"]
async fn an_empty_suite_run_files_an_explicit_empty_suite_digest() {
    let (_run, work) = scratch_run(&VerifyContext::default(), BODY, &[]).await;
    let json_path = unit_dir(work.path());
    let filed = pair_verifies(&json_path);

    assert_eq!(
        filed.baseline_suite_digest,
        baseline_suite_digest(&[], None).expect("the empty suite folds"),
        "an empty suite files its explicit digest"
    );
    assert_eq!(
        filed.verifier_command,
        VerifierCommand::CompileOnly,
        "no baseline case ran — the gate was compile-only"
    );
    assert_eq!(filed.verdict, VerificationVerdict::Passed);
}

/// A suite read from a filed baseline document carries that location in
/// its digest fold, so two attempts judged against suites from different
/// files never read as judged against the same one.
#[tokio::test]
#[ignore = "scaffolds and cargo-runs a real scratch project + runner"]
async fn a_filed_baseline_file_location_rides_the_suite_digest() {
    let work = tempfile::tempdir().expect("temp work dir");
    let baseline = work
        .path()
        .join("re/baseline/game_logic.dll/DrawSprite/baseline.json");
    std::fs::create_dir_all(baseline.parent().expect("parent")).expect("suite dir");
    std::fs::write(&baseline, "[]").expect("the suite files");

    let verifier = Verifier::new(work.path()).expect("verifier");
    let context = VerifyContext {
        baseline_file: Some(&baseline),
        ..VerifyContext::default()
    };
    let run = verifier
        .verify(BINARY, FUNCTION, BODY, &[case(7)], &context)
        .await
        .expect("verification runs");
    let filed = pair_verifies(&unit_dir(work.path()));

    assert_eq!(
        filed.baseline_suite_digest,
        baseline_suite_digest(
            &[case(7)],
            Some("re/baseline/game_logic.dll/DrawSprite/baseline.json"),
        )
        .expect("the located suite folds"),
        "the fold names the baseline file's location relative to the record tree"
    );
    assert_eq!(
        filed.verifier_command,
        VerifierCommand::CompileAndBaselineTest,
        "a case ran — the gate was the full one"
    );
    assert_eq!(run.receipt, filed);
}

/// The retry sequence's places stand one name apart in one unit directory:
/// the next attempt writes its own pair, and a filed pair is never edited
/// in place — the earlier bytes stand untouched beside the newer verdict.
#[tokio::test]
#[ignore = "scaffolds and cargo-runs a real scratch project + runner"]
async fn each_attempt_writes_its_own_pair_and_a_filed_pair_is_never_edited() {
    let work = tempfile::tempdir().expect("temp work dir");
    let verifier = Verifier::new(work.path()).expect("verifier");

    let first = verifier
        .verify(
            BINARY,
            FUNCTION,
            BODY,
            &[case(7)],
            &VerifyContext {
                attempt: 1,
                ..VerifyContext::default()
            },
        )
        .await
        .expect("the first attempt verifies");
    let first_pair = std::fs::read(unit_dir(work.path())).expect("the first pair's JSON");
    let first_md =
        std::fs::read(unit_dir(work.path()).with_extension("md")).expect("the first twin");

    let second = verifier
        .verify(
            BINARY,
            FUNCTION,
            BROKEN_BODY,
            &[case(7)],
            &VerifyContext {
                attempt: 2,
                retry_strategy: "compile_fix",
                ..VerifyContext::default()
            },
        )
        .await
        .expect("the fix attempt verifies");

    // The first pair stands byte-for-byte untouched beside the new one.
    assert_eq!(
        std::fs::read(unit_dir(work.path())).expect("still there"),
        first_pair,
        "the filed pair was never edited in place"
    );
    assert_eq!(
        std::fs::read(unit_dir(work.path()).with_extension("md")).expect("still there"),
        first_md,
        "nor was its twin"
    );

    // The second attempt filed its own pair — same unit directory, one name apart.
    let second_json =
        verification_receipt_path(work.path(), &BinaryIdentity::new(BINARY), FUNCTION, 2);
    let second_pair = pair_verifies(&second_json);
    assert_eq!(second_pair.attempt, 2);
    assert_eq!(second_pair.verdict, VerificationVerdict::CompileFailed);
    assert_eq!(second_pair.retry_strategy, "compile_fix");
    assert_eq!(second.receipt, second_pair);
    assert_ne!(
        second_pair.digest, first.receipt.digest,
        "a different run is a different digest"
    );
}
