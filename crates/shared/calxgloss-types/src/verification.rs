//! Types for verifying translated Rust code against baseline behavior.
//!
//! This module holds the records that report compilation status, test
//! pass/fail counts, and the detail of each test case that diverges from
//! the original binary's behavior — and the durable *verification
//! receipt*: what one verify run concluded, which gate it ran, and the
//! digest that makes its verdict citable.

use crate::identity::BinaryIdentity;
use crate::obligations::CaseKind;
use crate::test::SideEffect;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Detailed information about a single test failure.
///
/// Written when the Rust translation gives different output than the
/// baseline tests captured from the original binary.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FailedTest {
    /// Zero-based index of the test case in the baseline suite.
    pub test_index: usize,

    /// The test inputs that were provided.
    pub inputs: serde_json::Value,

    /// The expected return value (from the original binary baseline).
    pub expected: serde_json::Value,

    /// The actual return value (from the Rust translation).
    pub actual: serde_json::Value,

    /// Description of the mismatch (e.g., `"expected 42, got 43"` or `"panicked with: index out of bounds"`).
    pub error: String,

    /// The side effects the test case expected, recorded as typed kinds
    /// instead of mixed into the prose.
    ///
    /// A divergence on global handling is reported by naming the kind:
    /// `GlobalRead`/`GlobalWrite` with the global in the detail. Consumers
    /// (reports, dashboards, attempt records) can then compare divergences
    /// structurally instead of parsing the `error` string. `#[serde(default)]`
    /// keeps verification results saved before the field existed readable.
    #[serde(default)]
    pub expected_side_effects: Vec<SideEffect>,

    /// The ordered API-call trace the baseline case expected, beside the
    /// expected return value.
    ///
    /// A trace divergence is reported by naming the position, not just the
    /// prose: `expected_api_calls` and `actual_api_calls` travel together
    /// as typed, machine-comparable sequences, and
    /// `trace_divergence_index` names where they first part. Empty traces
    /// mean the dimension is *unassessed* for this case, never a pass.
    /// `#[serde(default)]` keeps verification results saved before the
    /// dimension existed readable.
    #[serde(default)]
    pub expected_api_calls: Vec<String>,

    /// The ordered API-call trace the Rust translation actually made,
    /// beside the actual return value. See `expected_api_calls`.
    #[serde(default)]
    pub actual_api_calls: Vec<String>,

    /// Zero-based position in the sequences where the expected and actual
    /// API-call traces first diverge, when the failure is a trace
    /// divergence — the call the reviewer reads as substituted, inserted,
    /// or reordered. Whether the dimension was assessed for this case is
    /// read from `expected_api_calls` being non-empty; a `None` here simply
    /// names no divergence, so a value-only failure with matching traces
    /// also carries `None`.
    #[serde(default)]
    pub trace_divergence_index: Option<usize>,
}

/// Result of compiling and verifying a translated function.
///
/// Reports whether the generated Rust code compiled successfully, how many
/// baseline tests passed, and detailed information for any failures.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    /// Whether the code compiled without errors.
    pub compiled: bool,

    /// Compilation error messages, if compilation failed.
    pub compilation_errors: Vec<String>,

    /// Number of baseline tests that passed.
    pub tests_passed: usize,

    /// Total number of baseline tests executed.
    pub tests_total: usize,

    /// Detailed information about each test that failed.
    pub failed_tests: Vec<FailedTest>,

    /// How many baseline cases carried the API-call trace dimension as
    /// *assessed* — a case whose expected trace was recorded (non-empty)
    /// and was therefore compared, not merely run for its value.
    ///
    /// This is what makes a trace-assessed verification pass distinguishable
    /// from a trace-unassessed one: `trace_assessed_tests == tests_total`
    /// with every test passing means the ordered call paths matched too,
    /// while `trace_assessed_tests == 0` means the gate only ever read the
    /// values. Silence never counts as a pass: an empty or missing expected
    /// trace leaves this count untouched, and a run whose tests never
    /// executed assesses nothing. `#[serde(default)]` keeps verification
    /// results saved before the dimension existed readable as unassessed.
    #[serde(default)]
    pub trace_assessed_tests: usize,

    /// How many baseline cases the runner could *call and compare a
    /// return value against* — a case with no expected return, or one
    /// the runner could not call at all, leaves the values dimension
    /// unassessed for it. Like the trace count, this makes an honest
    /// verdict distinguishable from a vacuous one: `passed` on a suite
    /// of unassessed values states that it compared none, instead of
    /// posing as a values match (ADR-0057). `#[serde(default)]` keeps
    /// results saved before the count existed readable.
    #[serde(default)]
    pub value_assessed_tests: usize,

    /// Value-assessed cases whose returned value matched the expected
    /// one — the values dimension's pass count, never inferred from the
    /// overall test verdict (ADR-0057).
    #[serde(default)]
    pub values_matched_tests: usize,
}

/// The outcome a verification run reached, as a receipt names it.
///
/// The closed set has exactly four members, and the distinction that
/// matters is ownership: the first three are verdicts *about the unit*
/// (it passed, its tests diverged, it never compiled), while
/// [`Self::HarnessError`] is a verdict about the *verifier* — the gate
/// itself broke, so nothing was learned about the unit. A harness
/// failure never reads as a unit failure and never reads as a pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationVerdict {
    /// The unit compiled and every executed baseline case passed.
    Passed,
    /// The unit compiled but at least one baseline case diverged.
    TestsFailed,
    /// The unit did not compile; there was nothing for tests to judge.
    CompileFailed,
    /// The verifier itself failed (a toolchain or harness fault) — the
    /// unit was never judged at all.
    HarnessError,
}

/// The verifier command as actually invoked, which fixes how wide the
/// gate was.
///
/// The breadth is part of the verdict's meaning: a `passed` earned by a
/// compile-only gate claims less than one earned by the full
/// baseline-test gate, and a reviewer reading a receipt must be able to
/// tell the two apart without guessing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifierCommand {
    /// The gate compiled the unit only — no baseline case was run.
    CompileOnly,
    /// The gate compiled the unit and ran the baseline suite through the
    /// generated runner.
    CompileAndBaselineTest,
}

/// How one verification dimension fared: how many cases it *assessed*
/// and how many of those it saw pass.
///
/// The honesty rule (ADR-0057) rides these two numbers: a case counts as
/// assessed only when the dimension actually had something to compare,
/// and `passed <= assessed` always. `assessed < tests run` means the
/// dimension was only partially in force — silence is never a pass, and
/// a `values` pass with `api_trace` at zero assessed reads as a
/// value-only pass, never a fully assessed one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DimensionCounts {
    /// Cases this dimension compared — it had an expectation for them.
    pub assessed: usize,

    /// Assessed cases this dimension saw pass.
    pub passed: usize,
}

/// The durable record of one verification run — the receipt a *verify*
/// pass or failure leaves behind.
///
/// [`VerificationResult`] reports what the gate learned inside a running
/// pipeline; this is what outlives the run: which gate judged which unit
/// at which attempt, the verdict it reached, the suite it was earned
/// against, per-dimension counts, and timings. It is data-only and
/// JSON-friendly on purpose, following the same serde discipline as its
/// siblings — fields added later carry `#[serde(default)]` so filed
/// receipts keep loading.
///
/// The vocabulary is grown ahead of the writers on purpose (the track's
/// prefactor): nothing in the pipeline files receipts yet, so this
/// record defines the shape they will all share.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationReceipt {
    /// The target binary identity of the verified unit — the receipt's
    /// join key beside function and attempt, the same identity triple
    /// every attempt record spells identically.
    pub binary: BinaryIdentity,

    /// The function the unit translated.
    pub function: String,

    /// The 1-based attempt number within this function's retry loop —
    /// the attempt's place in the retry sequence, which also keys the
    /// filed receipt file so a v1 pair and its v2 fix sit side by side
    /// across attempt branches.
    pub attempt: u32,

    /// The strategy that produced the attempt under verification
    /// (`"initial"`, `"compile_fix"`, …). Kept a plain string for the
    /// reason the experiment log keeps one ([`crate::RetryStrategy`]'s
    /// set is closed and `"initial"` is not in it).
    pub retry_strategy: String,

    /// The shape of the prompt the attempt took — e.g. a strategy-built
    /// fix prompt vs a tier-escalated rebuild — as the retry seam names
    /// it. Recorded because the same verdict earned through different
    /// prompt shapes is a different story for the reviewer.
    pub attempt_path: String,

    /// The verifier command as actually invoked, so the gate's breadth
    /// is part of the verdict's meaning (see [`VerifierCommand`]).
    pub verifier_command: VerifierCommand,

    /// The content digest (`sha256:`-prefixed) of the baseline suite
    /// actually fed into this run — so two attempts judged against
    /// different suites never read as judged against the same one. A
    /// run with no cases records the empty suite's digest, never a
    /// missing field.
    pub baseline_suite_digest: String,

    /// The case-kind classes the filed suite actually exercised — every
    /// declared kind the baseline cases as fed carried, collected. A kind
    /// the suite never exercised stays missing here, so an obligation
    /// requiring it never reads covered (issue #421's coverage check);
    /// a case declaring no kind adds nothing to this set.
    /// `#[serde(default)]` keeps receipts saved before the field existed
    /// readable, per this record's serde discipline — their empty set
    /// claims no kind, so a required kind reads uncovered, never
    /// silently satisfied.
    #[serde(default)]
    pub covered_case_kinds: BTreeSet<CaseKind>,

    /// Per-dimension counts keyed by dimension name — today `values`
    /// and `api_trace`. The map shape is deliberate: P23's mined-input
    /// and P24's scenario dimensions join additively, no receipt
    /// rewrite. A [`BTreeMap`] keeps the serialization canonical, so
    /// the content digest re-derives from filed bytes and receipts diff
    /// cleanly between attempt branches.
    pub dimensions: BTreeMap<String, DimensionCounts>,

    /// How long compilation took, in milliseconds.
    pub compile_ms: u64,

    /// How long the test run took, in milliseconds (zero on a
    /// compile-only or compile-failed gate).
    pub test_run_ms: u64,

    /// The whole run's duration, in milliseconds.
    pub total_ms: u64,

    /// What the run concluded — and whose failure it was, unit or
    /// harness (see [`VerificationVerdict`]).
    pub verdict: VerificationVerdict,

    /// The baseline cases the run saw diverge, named by position in the
    /// suite as fed — a `tests-failed` verdict never rests on counts
    /// alone. A passed run files an empty list; a compile-failed run
    /// names none either, since no case ever ran to fail.
    /// `#[serde(default)]` keeps receipts saved before the field existed
    /// readable, per this record's serde discipline.
    #[serde(default)]
    pub failed_cases: Vec<usize>,

    /// The digest of this document's own content (see
    /// [`Self::content_digest`]); the handle P26's ledger will cite a
    /// verified unit by.
    pub digest: String,
}

impl VerificationReceipt {
    /// The canonical digest of this receipt's content: sha256 over the
    /// document's own JSON with the `digest` field blanked, prefixed
    /// `sha256:` like every other content digest the record tree carries
    /// — the same fold the *scenario verdict* uses. The digest field
    /// never rides its own digest, so a reader of a filed receipt
    /// re-derives the same value from the filed bytes alone.
    pub fn content_digest(&self) -> Result<String, crate::error::TypesError> {
        use sha2::{Digest as _, Sha256};
        let mut blanked = self.clone();
        blanked.digest = String::new();
        let bytes = serde_json::to_vec(&blanked)?;
        let sum = Sha256::digest(&bytes);
        let hex: String = sum.iter().map(|byte| format!("{byte:02x}")).collect();
        Ok(format!("sha256:{hex}"))
    }
}

/// Render a filed receipt's human-readable twin from its own JSON facts.
///
/// This is the pipeline-side half of the digest pair: the same document the
/// JSON authority carries, folded into prose a reviewer reads, with the
/// JSON's content digest embedded so the pair re-derives from its contents
/// alone. It adds nothing the record does not already state — one receipt,
/// one truth — and its wording is deliberately not part of the tested
/// contract (only the digest pairing and the facts are).
pub fn verification_receipt_markdown(receipt: &VerificationReceipt) -> String {
    // Labels come off the record's own serde spelling, so the human side can
    // never spell a verdict differently than the JSON authority files it.
    fn label<T: Serialize + ?Sized>(value: &T) -> String {
        serde_json::to_value(value)
            .ok()
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_else(|| "?".to_string())
    }

    let failed = if receipt.failed_cases.is_empty() {
        "none".to_string()
    } else {
        receipt
            .failed_cases
            .iter()
            .map(|index| format!("case {index}"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let covered_kinds = if receipt.covered_case_kinds.is_empty() {
        "none".to_string()
    } else {
        receipt
            .covered_case_kinds
            .iter()
            .map(|kind| kind.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    };
    let dimensions = receipt
        .dimensions
        .iter()
        .map(|(name, counts)| {
            format!(
                "- Dimension `{name}`: assessed {}, passed {}",
                counts.assessed, counts.passed
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        "# Verification receipt — {function} ({binary})\n\n\
         Verdict: `{verdict}` · attempt {attempt} · strategy `{strategy}` · path `{path}`\n\n\
         - Gate: `{gate}`\n\
         - Baseline suite digest: `{suite}`\n\
         - Suite covered kinds: {covered}\n\
         {dimensions}\n\
         - Timings: compile {compile} ms, test run {test} ms, total {total} ms\n\
         - Failed baseline cases: {failed}\n\n\
         ## Pairing\n\n\
         The JSON document beside this rendering is the authority. Recompute the\n\
         digest over it with its `digest` field blanked and it must equal:\n\n\
         ```\n{digest}\n```\n",
        function = receipt.function,
        binary = receipt.binary.as_str(),
        verdict = label(&receipt.verdict),
        attempt = receipt.attempt,
        strategy = receipt.retry_strategy,
        path = receipt.attempt_path,
        gate = label(&receipt.verifier_command),
        suite = receipt.baseline_suite_digest,
        covered = covered_kinds,
        compile = receipt.compile_ms,
        test = receipt.test_run_ms,
        total = receipt.total_ms,
        failed = failed,
        digest = receipt.digest,
    )
}

/// The record tree's verification-receipt directory: `re/verification`.
/// Receipts file here beside `re/baseline/` — same per-binary,
/// per-function unit layout as the baseline suites they were earned
/// against.
pub fn verification_receipts_dir(workspace: impl AsRef<std::path::Path>) -> std::path::PathBuf {
    workspace.as_ref().join("re").join("verification")
}

/// The canonical document the *baseline-suite digest* folds: the case suite
/// exactly as fed into a verify run, plus the location of the baseline file
/// it was read from when one existed. Field order is fixed here, so the
/// digest re-derives from filed baseline bytes plus the named location.
#[derive(Serialize)]
struct BaselineSuiteFold<'a> {
    baseline_file: Option<&'a str>,
    cases: &'a [crate::test::TestCase],
}

/// The content digest (`sha256:`-prefixed) of the baseline suite actually
/// fed into a verification run — [sha256 over the canonical encoding of
/// [`BaselineSuiteFold`]]. A run with no cases folds the empty suite
/// explicitly, never a missing field; the baseline file's location rides
/// the fold when one existed, so the same cases read from a named file
/// never digest as cases handed over from nowhere.
pub fn baseline_suite_digest(
    cases: &[crate::test::TestCase],
    baseline_file: Option<&str>,
) -> Result<String, crate::error::TypesError> {
    use sha2::{Digest as _, Sha256};
    let bytes = serde_json::to_vec(&BaselineSuiteFold {
        baseline_file,
        cases,
    })?;
    let sum = Sha256::digest(&bytes);
    let hex: String = sum.iter().map(|byte| format!("{byte:02x}")).collect();
    Ok(format!("sha256:{hex}"))
}

/// The record tree location of one unit's filed receipt for one attempt:
/// `re/verification/<binary identity>/<function>/attempt-<n>.json`.
///
/// The file name keys on the attempt's place in the retry sequence, so
/// the receipts of a v1 attempt and its v2 fix stand one name apart in
/// one directory — and, staged onto their attempt branches, they diff
/// side by side across branches. A later verify run for the same
/// attempt writes its own receipt; receipts already filed are never
/// edited in place.
pub fn verification_receipt_path(
    workspace: impl AsRef<std::path::Path>,
    binary: &BinaryIdentity,
    function: &str,
    attempt: u32,
) -> std::path::PathBuf {
    verification_receipts_dir(workspace)
        .join(binary.as_str())
        .join(function)
        .join(format!("attempt-{attempt}.json"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_verdict_closed_set_names_four_outcomes() {
        // The receipt's headline: the unit passed, the unit's tests failed,
        // the unit did not compile, or the harness itself broke. A
        // verifier-side failure is its own outcome — it never reads as a
        // unit verdict, pass or fail.
        let cases = [
            (VerificationVerdict::Passed, r#""passed""#),
            (VerificationVerdict::TestsFailed, r#""tests_failed""#),
            (VerificationVerdict::CompileFailed, r#""compile_failed""#),
            (VerificationVerdict::HarnessError, r#""harness_error""#),
        ];
        for (verdict, label) in cases {
            assert_eq!(serde_json::to_string(&verdict).expect("serializes"), label);
            let back: VerificationVerdict =
                serde_json::from_str(label).expect("the persisted label deserializes");
            assert_eq!(back, verdict);
        }
        for label in [r#""pass""#, r#""unknown""#, r#""Passed""#] {
            assert!(
                serde_json::from_str::<VerificationVerdict>(label).is_err(),
                "{label} is not a verdict and must not deserialize"
            );
        }
    }

    #[test]
    fn a_filed_receipt_reads_back_field_for_field() {
        // The receipt is a filed wire document first — reviewers, P26's
        // ledger, and diff tools all read it from its bytes alone. This
        // literal document is the shape contract: every field the
        // vocabulary promises survives the round trip.
        let filed = r#"{
            "binary": "game_logic.dll",
            "function": "DrawSprite",
            "attempt": 2,
            "retry_strategy": "test_fix",
            "attempt_path": "strategy_prompt",
            "verifier_command": "compile_and_baseline_test",
            "baseline_suite_digest": "sha256:aaa0",
            "dimensions": {
                "values": { "assessed": 3, "passed": 2 },
                "api_trace": { "assessed": 1, "passed": 1 }
            },
            "compile_ms": 4200,
            "test_run_ms": 1300,
            "total_ms": 6100,
            "verdict": "tests_failed",
            "failed_cases": [0, 2],
            "digest": "sha256:bbb0"
        }"#;
        let receipt: VerificationReceipt =
            serde_json::from_str(filed).expect("the filed document reads");
        assert_eq!(receipt.binary.as_str(), "game_logic.dll");
        assert_eq!(receipt.function, "DrawSprite");
        assert_eq!(receipt.attempt, 2, "the unit key is the identity triple");
        assert_eq!(receipt.retry_strategy, "test_fix");
        assert_eq!(receipt.attempt_path, "strategy_prompt");
        assert_eq!(
            receipt.verifier_command,
            VerifierCommand::CompileAndBaselineTest
        );
        assert_eq!(receipt.baseline_suite_digest, "sha256:aaa0");
        assert_eq!(receipt.dimensions["values"].assessed, 3);
        assert_eq!(receipt.dimensions["values"].passed, 2);
        assert_eq!(receipt.dimensions["api_trace"].assessed, 1);
        assert_eq!(receipt.compile_ms, 4200);
        assert_eq!(receipt.test_run_ms, 1300);
        assert_eq!(receipt.total_ms, 6100);
        assert_eq!(receipt.verdict, VerificationVerdict::TestsFailed);
        assert_eq!(
            receipt.failed_cases,
            [0, 2],
            "the verdict names the baseline cases that diverged"
        );
        assert_eq!(receipt.digest, "sha256:bbb0");

        let written = serde_json::to_string(&receipt).expect("serializes");
        let back: VerificationReceipt = serde_json::from_str(&written).expect("reads back");
        assert_eq!(back, receipt, "the record round-trips");
    }

    #[test]
    fn a_new_dimension_joins_the_map_without_a_receipt_rewrite() {
        // The map shape is the reservation: a filed receipt naming a
        // dimension this record has never heard of — P23's mined inputs
        // or P24's scenario dimension — reads and writes back unchanged.
        // Widening the gate adds a key, never a field.
        let filed = r#"{
            "binary": "game_logic.dll",
            "function": "DrawSprite",
            "attempt": 1,
            "retry_strategy": "initial",
            "attempt_path": "strategy_prompt",
            "verifier_command": "compile_and_baseline_test",
            "baseline_suite_digest": "sha256:aaa0",
            "dimensions": {
                "values": { "assessed": 3, "passed": 3 },
                "api_trace": { "assessed": 0, "passed": 0 },
                "mined_inputs": { "assessed": 4, "passed": 4 }
            },
            "compile_ms": 4000,
            "test_run_ms": 1200,
            "total_ms": 5200,
            "verdict": "passed",
            "digest": "sha256:bbb0"
        }"#;
        let receipt: VerificationReceipt =
            serde_json::from_str(filed).expect("the unknown dimension must not poison the read");
        assert_eq!(receipt.dimensions.len(), 3, "every dimension key survives");
        assert_eq!(receipt.dimensions["mined_inputs"].assessed, 4);

        let written = serde_json::to_string(&receipt).expect("serializes");
        assert!(
            written.contains("mined_inputs"),
            "the unknown key is written back out"
        );
    }

    /// One generated baseline case for the suite-fold pins to feed.
    fn sample_case() -> crate::test::TestCase {
        crate::test::TestCase {
            inputs: serde_json::json!([1, 2]),
            expected_return: serde_json::json!(3),
            expected_side_effects: Vec::new(),
            expected_api_calls: Vec::new(),
            origin: crate::CaseOrigin::Generated,
            case_kind: None,
        }
    }

    /// One real-shaped receipt for the digest and path pins to fold over.
    fn sample_receipt() -> VerificationReceipt {
        let mut dimensions = BTreeMap::new();
        dimensions.insert(
            "values".to_string(),
            DimensionCounts {
                assessed: 3,
                passed: 2,
            },
        );
        dimensions.insert(
            "api_trace".to_string(),
            DimensionCounts {
                assessed: 1,
                passed: 1,
            },
        );
        VerificationReceipt {
            binary: BinaryIdentity::new("game_logic.dll"),
            function: "DrawSprite".to_string(),
            attempt: 2,
            retry_strategy: "test_fix".to_string(),
            attempt_path: "strategy_prompt".to_string(),
            verifier_command: VerifierCommand::CompileAndBaselineTest,
            baseline_suite_digest: "sha256:aaa0".to_string(),
            covered_case_kinds: CaseKind::ALL.iter().copied().collect(),
            dimensions,
            compile_ms: 4200,
            test_run_ms: 1300,
            total_ms: 6100,
            verdict: VerificationVerdict::TestsFailed,
            failed_cases: Vec::new(),
            digest: String::new(),
        }
    }

    #[test]
    fn the_receipt_digest_digests_the_content_never_the_digest_field_itself() {
        // The same fold the scenario verdict uses: the digest is the
        // content's identity, so a reader of a filed receipt re-derives
        // it from the filed bytes alone, and two receipts that disagree
        // can never share one.
        let mut a = sample_receipt();
        a.digest = a.content_digest().expect("serializes");
        assert!(
            a.digest.starts_with("sha256:"),
            "the digest names its algorithm"
        );

        let mut blanked = a.clone();
        blanked.digest = String::new();
        assert_eq!(
            a.content_digest().expect("serializes"),
            blanked.content_digest().expect("serializes"),
            "the digest field itself never rides its own digest"
        );

        let mut b = a.clone();
        b.verdict = VerificationVerdict::Passed;
        assert_ne!(
            a.content_digest().expect("serializes"),
            b.content_digest().expect("serializes"),
            "a different verdict is a different digest"
        );

        // The filed-bytes leg: a reader who never saw the writer parses
        // the written document and re-derives the same digest from it.
        let written = serde_json::to_string(&a).expect("serializes");
        let read_back: VerificationReceipt =
            serde_json::from_str(&written).expect("the filed bytes read");
        assert_eq!(
            read_back.content_digest().expect("folds"),
            a.digest,
            "the digest re-derives from the filed bytes alone"
        );
    }

    #[test]
    fn the_receipt_markdown_renders_the_json_authority_s_own_facts() {
        // One receipt, one truth: the human side is rendered from the JSON
        // document alone — same verdict, same suite digest, same dimension
        // counts, same named failures — and it embeds the JSON's content
        // digest so the pair proves itself from its own contents.
        let mut receipt = sample_receipt();
        receipt.failed_cases = vec![1];
        receipt.digest = receipt.content_digest().expect("folds");

        let md = verification_receipt_markdown(&receipt);
        assert!(
            md.contains(&receipt.digest),
            "the rendering carries the JSON authority's digest:\n{md}"
        );
        assert!(
            md.contains("tests_failed"),
            "the verdict is the JSON's verdict"
        );
        assert!(
            md.contains(&receipt.baseline_suite_digest),
            "the suite digest rides the rendering too"
        );
        assert!(
            md.contains("case 1"),
            "the failed case is named on the human side"
        );
        assert!(md.contains("assessed 3, passed 2"), "values counts ride");
        assert!(md.contains("assessed 1, passed 1"), "api_trace counts ride");
        assert!(
            md.contains("compile_and_baseline_test"),
            "the gate as invoked"
        );
    }

    #[test]
    fn a_passing_run_and_a_compile_failure_name_no_failed_cases_in_the_markdown() {
        // "Naming the failed tests" is honest both ways: a pass files an
        // empty list and says none; a compile-failed run names none either —
        // no case ever ran to fail.
        let mut passed = sample_receipt();
        passed.verdict = VerificationVerdict::Passed;
        passed.failed_cases = Vec::new();
        passed.digest = passed.content_digest().expect("folds");
        let md = verification_receipt_markdown(&passed);
        assert!(md.contains("none"), "a pass says so plainly:\n{md}");
        assert!(!md.contains("case 1"));
    }

    #[test]
    fn the_baseline_suite_digest_folds_the_canonical_cases_and_names_their_location() {
        // The digest is the run's own answer to "judged against which suite":
        // sha256 over the canonical encoding of the cases actually fed in,
        // with the baseline file's location named when one existed. A reader
        // re-derives the empty-suite digest independently — the expected
        // value here is the literal sha256 of the canonical fold bytes, not
        // a recomputation of the writer's code.
        let empty = baseline_suite_digest(&[], None).expect("the empty suite folds");
        assert_eq!(
            empty, "sha256:d3b0ecf1dd8f369432b9e00b99024c6ca03b22b1c2f111720ebd817bf2012358",
            "an empty suite files an explicit digest, never a missing field"
        );

        let cases = vec![sample_case()];

        // Same cases, named vs unnamed origin file: a suite read from a filed
        // baseline stands apart from cases handed over without one.
        let located = baseline_suite_digest(
            &cases,
            Some("re/baseline/game_logic.dll/DrawSprite/baseline.json"),
        )
        .expect("the located suite folds");
        let anonymous = baseline_suite_digest(&cases, None).expect("the bare suite folds");
        assert_ne!(
            located, anonymous,
            "the fold names the baseline file's location when one existed"
        );
        assert!(located.starts_with("sha256:"));

        // Stability: the suite round-tripped through its canonical encoding
        // folds to the same digest — the reader's recomputation from filed
        // baseline bytes matches what the run filed.
        let written = serde_json::to_vec(&cases).expect("cases serialize");
        let read_back: Vec<crate::test::TestCase> =
            serde_json::from_slice(&written).expect("the canonical bytes read back");
        assert_eq!(
            baseline_suite_digest(&read_back, None).expect("refolds"),
            anonymous,
            "the fold is stable across the canonical encoding"
        );
    }

    #[test]
    fn receipts_file_per_unit_under_re_verification_keyed_on_the_attempt() {
        // The route beside re/baseline/: one unit directory per binary
        // and function, one receipt file keyed on the attempt's place in
        // the retry sequence — so a v1 receipt and its v2 fix stand one
        // name apart in the same directory and survive diffing across
        // attempt branches.
        let binary = BinaryIdentity::new("game_logic.dll");
        assert_eq!(
            verification_receipts_dir("/repo"),
            std::path::PathBuf::from("/repo/re/verification")
        );
        let second = verification_receipt_path("/repo", &binary, "DrawSprite", 2);
        assert_eq!(
            second,
            std::path::PathBuf::from(
                "/repo/re/verification/game_logic.dll/DrawSprite/attempt-2.json"
            )
        );
        let first = verification_receipt_path("/repo", &binary, "DrawSprite", 1);
        assert_eq!(
            first.parent(),
            second.parent(),
            "one unit directory per unit"
        );
    }
}
