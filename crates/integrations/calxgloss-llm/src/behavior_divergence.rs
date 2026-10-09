//! Behavior-divergence detector for the translation pipeline.
//!
//! This module provides [`BehaviorDivergenceDetector`] which identifies when a
//! Rust implementation passes all baseline tests but diverges on unseen inputs.
//! This is a critical fault mode because the implementation *appears* correct
//! (all baseline tests pass) while silently producing wrong behavior on real
//! inputs not covered by the baseline suite.
//!
//! # How it works
//!
//! The detector compares two sets of test results:
//!
//! 1. **Baseline tests** — the tests that originally captured the binary's
//!    behavior. These were used for the initial verification pass.
//! 2. **Edge-case tests** — additional inputs derived from Ghidra analysis
//!    (boundary values from `cmp` instructions, null checks, overflow
//!    conditions, etc.). These are NOT in the baseline set.
//!
//! When all baseline tests pass but one or more edge-case tests fail, the
//! detector fires a [`BehaviorDivergenceSignal`] indicating that the test
//! suite is insufficient to verify behavioral equivalence.  The signal
//! includes suggestions for new baseline test cases that should be added.
//!
//! # Example
//!
//! ```
//! use calxgloss_llm::behavior_divergence::{BehaviorDivergenceDetector, EdgeCaseTest};
//!
//! let mut detector = BehaviorDivergenceDetector::new();
//!
//! // All baseline tests passed.
//! let baseline_results = vec![true, true, true, true];
//!
//! // Edge-case tests reveal divergence.
//! let edge_tests = vec![
//!     EdgeCaseTest::new("zero_input", serde_json::json!([0, 0]), serde_json::json!(0)),
//!     EdgeCaseTest::new("negative_input", serde_json::json!([-1, -1]), serde_json::json!(-2)),
//! ];
//! let edge_results = vec![false, true];
//!
//! let signal = detector.detect_divergence(
//!     "game_logic.dll",
//!     "AddTwo",
//!     3,
//!     "test_fix",
//!     &baseline_results,
//!     &edge_tests,
//!     &edge_results,
//! );
//!
//! assert!(signal.is_some());
//! let s = signal.unwrap();
//! assert_eq!(s.failing_edge_cases.len(), 1);
//! assert_eq!(s.suggested_new_baseline_tests.len(), 1);
//! ```

use serde_json::Value;
use std::collections::HashSet;

// ============================================================
// Public types
// ============================================================

/// An edge-case test used for divergence detection.
///
/// Unlike baseline tests, edge-case tests target specific inputs that
/// a Ghidra analysis might reveal: boundary values, null checks,
/// overflow conditions, and other inputs not naturally covered by
/// the original binary's test suite.
#[derive(Debug, Clone)]
pub struct EdgeCaseTest {
    /// A human-readable label for this test (e.g., `"zero_input"`,
    /// `"negative_overflow"`).
    pub label: String,

    /// The input to the translated function.
    pub inputs: Value,

    /// The expected return value from the original binary.
    pub expected: Value,
}

impl EdgeCaseTest {
    /// Create a new edge-case test.
    pub fn new(label: impl Into<String>, inputs: Value, expected: Value) -> Self {
        Self {
            label: label.into(),
            inputs,
            expected,
        }
    }
}

/// A signal that behavior divergence has been detected.
///
/// Returned by [`BehaviorDivergenceDetector::detect_divergence`] when the
/// Rust implementation passes all baseline tests but fails on one or more
/// edge-case tests. This indicates insufficient test coverage — the baseline
/// suite does not exercise all the paths the original binary exercises.
#[derive(Debug, Clone)]
pub struct BehaviorDivergenceSignal {
    /// How many baseline tests passed.
    pub baseline_passed: usize,

    /// Total number of baseline tests (should equal `baseline_passed` since
    /// divergence detection only fires when baseline is fully green).
    pub baseline_total: usize,

    /// How many edge-case tests passed.
    pub edge_tests_passed: usize,

    /// Total edge-case tests that were run.
    pub edge_tests_total: usize,

    /// Edge-case tests that failed, revealing the divergence.
    pub failing_edge_cases: Vec<EdgeCaseTest>,

    /// New baseline test cases suggested to close the coverage gap.
    /// Each entry is an edge-case test that should be added to the baseline
    /// suite for future verification passes.
    pub suggested_new_baseline_tests: Vec<EdgeCaseTest>,

    /// The DLL where the divergence was found.
    pub binary: String,

    /// The function where the divergence was found.
    pub function: String,

    /// The translation attempt where divergence was detected.
    pub attempt: u32,

    /// The strategy that was active.
    pub strategy: String,
}

/// Detects behavior divergence between the Rust implementation and the
/// original binary.
///
/// The detector works by comparing baseline test results against edge-case
/// test results. When baseline tests all pass but edge-case tests fail,
/// the implementation is likely diverging on inputs not covered by the
/// baseline suite.
///
/// # Configuration
///
/// The detector has a single configurable parameter:
///
/// - `require_all_baseline_pass` — Whether ALL baseline tests must pass
///   before edge-case results are considered. Default is `true` because
///   if baseline tests already fail, the divergence is obvious and does
///   not require special handling.
#[derive(Debug, Clone)]
pub struct BehaviorDivergenceDetector {
    /// Whether all baseline tests must pass for divergence detection to
    /// fire. When `false`, edge-case failures are reported regardless of
    /// baseline status (useful for mixed diagnostics).
    require_all_baseline_pass: bool,

    /// The minimum number of edge-case tests that must be provided for
    /// detection to be meaningful. If fewer edge-case tests are provided,
    /// the detector returns `None` (insufficient data).
    min_edge_cases: usize,

    /// Whether to suggest new baseline tests for failing edge cases.
    suggest_new_baseline: bool,
}

// ============================================================
// Implementation
// ============================================================

impl BehaviorDivergenceDetector {
    /// Create a new detector with default settings.
    ///
    /// Defaults:
    /// - All baseline tests must pass before checking edge cases.
    /// - At least 2 edge-case tests must be provided.
    /// - Suggest new baseline tests for failing edge cases.
    pub fn new() -> Self {
        Self {
            require_all_baseline_pass: true,
            min_edge_cases: 2,
            suggest_new_baseline: true,
        }
    }

    /// Require all baseline tests to pass before checking edge cases.
    pub fn with_require_all_baseline_pass(mut self, require: bool) -> Self {
        self.require_all_baseline_pass = require;
        self
    }

    /// Set the minimum number of edge-case tests for detection.
    pub fn with_min_edge_cases(mut self, min: usize) -> Self {
        self.min_edge_cases = min;
        self
    }

    /// Configure whether to suggest new baseline tests for failures.
    pub fn with_suggest_new_baseline(mut self, suggest: bool) -> Self {
        self.suggest_new_baseline = suggest;
        self
    }

    /// Detect behavior divergence between baseline and edge-case tests.
    ///
    /// # Arguments
    ///
    /// * `binary` — The DLL name.
    /// * `function` — The function name.
    /// * `attempt` — The 1-based attempt number.
    /// * `strategy` — The retry strategy label.
    /// * `baseline_passed` — Boolean results for each baseline test
    ///   (true = passed). **All must be `true`** for divergence to be
    ///   reported.
    /// * `edge_tests` — Edge-case tests that were run.
    /// * `edge_results` — Boolean results for each edge-case test.
    ///
    /// # Returns
    ///
    /// [`Some`](`BehaviorDivergenceSignal`) when all baseline tests pass
    /// but one or more edge-case tests fail. [`None`] otherwise.
    ///
    /// The signal includes suggestions for new baseline test cases to
    /// close the coverage gap.
    #[allow(clippy::too_many_arguments)]
    pub fn detect_divergence(
        &self,
        binary: &str,
        function: &str,
        attempt: u32,
        strategy: &str,
        baseline_passed: &[bool],
        edge_tests: &[EdgeCaseTest],
        edge_results: &[bool],
    ) -> Option<BehaviorDivergenceSignal> {
        // Need matching counts for edge results and tests.
        if edge_results.len() != edge_tests.len() {
            tracing::warn!(
                edge_tests = edge_tests.len(),
                edge_results = edge_results.len(),
                "Edge test and result counts mismatch — skipping divergence check"
            );
            return None;
        }

        // Need enough edge-case tests to make the check meaningful.
        if edge_results.len() < self.min_edge_cases {
            return None;
        }

        // Check baseline: all must pass for divergence to be reported.
        // If baseline tests already fail, that's a different fault mode
        // (straightforward test failure) and does not require divergence
        // handling.
        if self.require_all_baseline_pass && baseline_passed.iter().any(|&passed| !passed) {
            return None;
        }

        // Collect failing edge-case tests.
        let failing: Vec<EdgeCaseTest> = edge_tests
            .iter()
            .zip(edge_results.iter())
            .filter(|&(_, result)| !result)
            .map(|(test, _)| test.clone())
            .collect();

        if failing.is_empty() {
            // All edge cases passed too — no divergence detected.
            return None;
        }

        // Count passing edge cases.
        let edge_passed = edge_results.iter().filter(|&&r| r).count();

        // Generate suggestions for new baseline tests.
        let suggested = if self.suggest_new_baseline {
            failing
                .iter()
                .map(|test| {
                    EdgeCaseTest::new(
                        test.label.clone(),
                        test.inputs.clone(),
                        test.expected.clone(),
                    )
                })
                .collect()
        } else {
            Vec::new()
        };

        Some(BehaviorDivergenceSignal {
            baseline_passed: baseline_passed.len(),
            baseline_total: baseline_passed.len(),
            edge_tests_passed: edge_passed,
            edge_tests_total: edge_results.len(),
            failing_edge_cases: failing,
            suggested_new_baseline_tests: suggested,
            binary: binary.to_string(),
            function: function.to_string(),
            attempt,
            strategy: strategy.to_string(),
        })
    }

    /// Generate a Ghidra-derived edge-case test suite from disassembly hints.
    ///
    /// This is a heuristic generator that produces edge-case inputs based
    /// on patterns commonly found in disassembled code. It is a starting
    /// point — the LLM can further refine these based on the full
    /// disassembly and decompiler output.
    ///
    /// # Arguments
    ///
    /// * `num_params` — The number of parameters the function takes.
    /// * `disassembly_hints` — A set of observed patterns in the
    ///   disassembly, such as `"zero_check"`, `"null_check"`,
    ///   `"overflow"`, `"negative"` (derived from Ghidra analysis).
    ///
    /// # Returns
    ///
    /// A vector of edge-case tests targeting the indicated patterns.
    pub fn generate_edge_cases(
        &self,
        num_params: usize,
        disassembly_hints: &HashSet<String>,
    ) -> Vec<EdgeCaseTest> {
        let mut tests = Vec::new();

        // Always generate zero-input edge case (most common check).
        if disassembly_hints.contains("zero_check") || disassembly_hints.contains("boundary") {
            let zero_inputs = gen_params(num_params, |i| match i {
                0 => serde_json::json!(0),
                _ => serde_json::json!(0u32),
            });
            tests.push(EdgeCaseTest::new(
                "zero_input",
                serde_json::Value::Array(zero_inputs),
                serde_json::json!(0),
            ));
        }

        // Null-pointer edge case (for pointer/option parameters).
        if disassembly_hints.contains("null_check") {
            let null_inputs = gen_params(num_params, |i| match i {
                0 => serde_json::json!(null),
                _ => serde_json::json!(0u32),
            });
            tests.push(EdgeCaseTest::new(
                "null_pointer",
                serde_json::Value::Array(null_inputs),
                serde_json::json!(null),
            ));
        }

        // Negative value edge case.
        if disassembly_hints.contains("negative") {
            let neg_inputs = gen_params(num_params, |i| match i {
                0 => serde_json::json!(-1),
                _ => serde_json::json!(0i32),
            });
            tests.push(EdgeCaseTest::new(
                "negative_input",
                serde_json::Value::Array(neg_inputs),
                serde_json::json!(-1),
            ));
        }

        // Maximum-value edge case (overflow detection).
        if disassembly_hints.contains("overflow") || disassembly_hints.contains("max_value") {
            let max_inputs = gen_params(num_params, |_| serde_json::json!(i32::MAX));
            tests.push(EdgeCaseTest::new(
                "max_value_input",
                serde_json::Value::Array(max_inputs),
                serde_json::json!(i32::MAX),
            ));
        }

        // Minimum-value edge case (underflow detection).
        if disassembly_hints.contains("min_value") {
            let min_inputs = gen_params(num_params, |_| serde_json::json!(i32::MIN));
            tests.push(EdgeCaseTest::new(
                "min_value_input",
                serde_json::Value::Array(min_inputs),
                serde_json::json!(i32::MIN),
            ));
        }

        tests
    }

    /// Check whether the detected divergence is likely caused by missing
    /// boundary-condition handling.
    ///
    /// Returns `true` if the failing edge cases all involve boundary values
    /// (zero, max, min, negative).
    pub fn is_boundary_divergence(&self, signal: &BehaviorDivergenceSignal) -> bool {
        signal
            .failing_edge_cases
            .iter()
            .all(|test| is_boundary_value(&test.inputs))
    }

    /// Get a confidence score for the divergence diagnosis.
    ///
    /// Higher scores indicate greater confidence that the test suite,
    /// not the implementation, is the root cause.
    ///
    /// Scoring:
    /// - +1 for each baseline test passed (up to +5)
    /// - +2 if more than half the edge cases fail (suggests systematic
    ///   coverage gap, not an implementation bug)
    /// - +3 if failing edge cases are boundary values
    pub fn divergence_confidence(&self, signal: &BehaviorDivergenceSignal) -> u8 {
        let mut score: u8 = 0;

        // Baseline pass rate contributes confidence.
        score += (signal.baseline_passed.min(5)) as u8;

        // If most edge cases fail, it's likely a coverage gap.
        if signal.edge_tests_total > 0
            && signal.failing_edge_cases.len() * 2 >= signal.edge_tests_total
        {
            score += 2;
        }

        // Boundary divergence is more likely a coverage issue.
        if self.is_boundary_divergence(signal) {
            score += 3;
        }

        score.min(10)
    }

    /// Build a human-readable recommendation for fixing the divergence.
    pub fn divergence_recommendation(&self, signal: &BehaviorDivergenceSignal) -> String {
        let confidence = self.divergence_confidence(signal);
        let boundary = self.is_boundary_divergence(signal);

        let mut parts = Vec::new();

        parts.push(format!(
            "Behavior divergence detected: {} baseline test(s) pass, but {} of {} edge-case test(s) fail.",
            signal.baseline_passed,
            signal.failing_edge_cases.len(),
            signal.edge_tests_total
        ));

        if boundary {
            parts.push(
                "All failing edge cases involve boundary values (zero, negative, overflow, underflow). \
                 The test suite likely does not exercise these code paths."
                    .to_string(),
            );
        }

        match confidence {
            0..=3 => parts.push(
                "Low confidence: this may be an implementation bug rather than a coverage gap. Manual review recommended."
                    .to_string(),
            ),
            4..=6 => parts.push(
                "Moderate confidence: likely a coverage gap, but verify the implementation against disassembly."
                    .to_string(),
            ),
            7..=10 => parts.push(
                "High confidence: the baseline test suite is insufficient. Adding the suggested edge cases as new baseline tests should resolve this."
                    .to_string(),
            ),
            _ => unreachable!(),
        }

        if !signal.suggested_new_baseline_tests.is_empty() {
            let names: Vec<&str> = signal
                .suggested_new_baseline_tests
                .iter()
                .map(|t| &t.label)
                .map(|s| s.as_str())
                .collect();
            parts.push(format!(
                "Suggested new baseline test(s): {}. Add these to the baseline suite and re-verify.",
                names.join(", ")
            ));
        }

        parts.join(" ")
    }
}

impl Default for BehaviorDivergenceDetector {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================
// Helpers
// ============================================================

/// Generate an array of parameter values for edge-case testing.
fn gen_params<F>(count: usize, generator: F) -> Vec<Value>
where
    F: Fn(usize) -> Value,
{
    (0..count).map(generator).collect()
}

/// Check whether a JSON value represents a boundary condition.
///
/// Boundary values include: zero, null, i32::MIN/MAX, u32::MAX, negative numbers,
/// empty strings, and empty arrays.
fn is_boundary_value(inputs: &Value) -> bool {
    match inputs {
        Value::Array(arr) => arr.is_empty() || arr.iter().any(is_boundary_scalar),
        _ => is_boundary_scalar(inputs),
    }
}

/// Check whether a single scalar value is a boundary condition.
fn is_boundary_scalar(v: &Value) -> bool {
    match v {
        Value::Number(n) => {
            // Check unsigned first for values that might overflow i64.
            if let Some(u) = n.as_u64()
                && (u == 0 || u == u32::MAX as u64 || u == u64::MAX)
            {
                return true;
            }

            // Then check signed values.
            if let Some(i) = n.as_i64() {
                return i == 0
                    || i == i32::MIN as i64
                    || i == i32::MAX as i64
                    || i == i64::MIN
                    || i == i64::MAX
                    || i < 0;
            }
            false
        }
        Value::Null => true,
        Value::String(s) => s.is_empty(),
        Value::Array(arr) => arr.is_empty(),
        _ => false,
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================
    // Construction
    // =========================================================

    #[test]
    fn test_detector_new() {
        let detector = BehaviorDivergenceDetector::new();
        assert!(detector.require_all_baseline_pass);
        assert_eq!(detector.min_edge_cases, 2);
        assert!(detector.suggest_new_baseline);
    }

    #[test]
    fn test_detector_with_options() {
        let detector = BehaviorDivergenceDetector::new()
            .with_require_all_baseline_pass(false)
            .with_min_edge_cases(5)
            .with_suggest_new_baseline(false);

        assert!(!detector.require_all_baseline_pass);
        assert_eq!(detector.min_edge_cases, 5);
        assert!(!detector.suggest_new_baseline);
    }

    // =========================================================
    // No divergence — all baseline pass, all edge cases pass
    // =========================================================

    #[test]
    fn test_no_divergence_all_pass() {
        let detector = BehaviorDivergenceDetector::new();

        let baseline = vec![true, true, true];
        let edge_tests = vec![
            EdgeCaseTest::new("edge1", serde_json::json!([1, 2]), serde_json::json!(3)),
            EdgeCaseTest::new("edge2", serde_json::json!([10, 20]), serde_json::json!(30)),
        ];
        let edge_results = vec![true, true];

        assert!(
            detector
                .detect_divergence(
                    "test.dll",
                    "Add",
                    1,
                    "initial",
                    &baseline,
                    &edge_tests,
                    &edge_results,
                )
                .is_none()
        );
    }

    #[test]
    fn test_no_divergence_baseline_fails() {
        let detector = BehaviorDivergenceDetector::new();

        // Baseline has a failure — divergence should NOT be reported
        // (baseline failure is handled separately).
        let baseline = vec![true, false, true];
        let edge_tests = vec![
            EdgeCaseTest::new("edge1", serde_json::json!([0, 0]), serde_json::json!(0)),
            EdgeCaseTest::new("edge2", serde_json::json!([-1, -1]), serde_json::json!(-2)),
        ];
        let edge_results = vec![false, true];

        assert!(
            detector
                .detect_divergence(
                    "test.dll",
                    "Add",
                    1,
                    "test_fix",
                    &baseline,
                    &edge_tests,
                    &edge_results,
                )
                .is_none()
        );
    }

    #[test]
    fn test_no_divergence_too_few_edge_cases() {
        let detector = BehaviorDivergenceDetector::new();

        let baseline = vec![true, true];
        let edge_tests = vec![EdgeCaseTest::new(
            "only_one",
            serde_json::json!([0]),
            serde_json::json!(0),
        )];
        let edge_results = vec![false]; // Fails, but only 1 edge case

        // Below min_edge_cases (2), so no detection.
        assert!(
            detector
                .detect_divergence(
                    "test.dll",
                    "Func",
                    1,
                    "initial",
                    &baseline,
                    &edge_tests,
                    &edge_results,
                )
                .is_none()
        );
    }

    // =========================================================
    // Divergence detected — baseline passes, edge cases fail
    // =========================================================

    #[test]
    fn test_divergence_one_failing_edge_case() {
        let detector = BehaviorDivergenceDetector::new();

        let baseline = vec![true, true, true];
        let edge_tests = vec![
            EdgeCaseTest::new("zero", serde_json::json!([0, 0]), serde_json::json!(0)),
            EdgeCaseTest::new("positive", serde_json::json!([1, 2]), serde_json::json!(3)),
        ];
        let edge_results = vec![false, true]; // Zero input fails

        let signal = detector.detect_divergence(
            "game_logic.dll",
            "AddTwo",
            3,
            "test_fix",
            &baseline,
            &edge_tests,
            &edge_results,
        );

        assert!(signal.is_some());
        let s = signal.unwrap();
        assert_eq!(s.baseline_passed, 3);
        assert_eq!(s.edge_tests_passed, 1);
        assert_eq!(s.edge_tests_total, 2);
        assert_eq!(s.failing_edge_cases.len(), 1);
        assert_eq!(s.failing_edge_cases[0].label, "zero");
        assert_eq!(s.suggested_new_baseline_tests.len(), 1);
        assert_eq!(s.binary, "game_logic.dll");
        assert_eq!(s.function, "AddTwo");
    }

    #[test]
    fn test_divergence_multiple_failing_edge_cases() {
        let detector = BehaviorDivergenceDetector::new();

        let baseline = vec![true, true];
        let edge_tests = vec![
            EdgeCaseTest::new("zero", serde_json::json!([0, 0]), serde_json::json!(0)),
            EdgeCaseTest::new(
                "negative",
                serde_json::json!([-1, -1]),
                serde_json::json!(-2),
            ),
            EdgeCaseTest::new(
                "max",
                serde_json::json!([2147483647u32, 1u32]),
                serde_json::json!(2147483648u64),
            ),
        ];
        let edge_results = vec![false, false, true];

        let signal = detector.detect_divergence(
            "a.dll",
            "func",
            5,
            "escalate",
            &baseline,
            &edge_tests,
            &edge_results,
        );

        assert!(signal.is_some());
        let s = signal.unwrap();
        assert_eq!(s.failing_edge_cases.len(), 2);
        assert_eq!(s.suggested_new_baseline_tests.len(), 2);
    }

    #[test]
    fn test_divergence_no_suggestions_when_disabled() {
        let detector = BehaviorDivergenceDetector::new().with_suggest_new_baseline(false);

        let baseline = vec![true];
        let edge_tests = vec![
            EdgeCaseTest::new("zero", serde_json::json!([0]), serde_json::json!(0)),
            EdgeCaseTest::new("neg", serde_json::json!([-1]), serde_json::json!(-1)),
        ];
        let edge_results = vec![false, true];

        let signal = detector.detect_divergence(
            "test.dll",
            "X",
            1,
            "initial",
            &baseline,
            &edge_tests,
            &edge_results,
        );

        assert!(signal.is_some());
        let s = signal.unwrap();
        assert_eq!(s.suggested_new_baseline_tests.len(), 0);
    }

    #[test]
    fn test_divergence_mismatched_counts_returns_none() {
        let detector = BehaviorDivergenceDetector::new();

        let baseline = vec![true, true];
        let edge_tests = vec![
            EdgeCaseTest::new("a", serde_json::json!(0), serde_json::json!(0)),
            EdgeCaseTest::new("b", serde_json::json!(1), serde_json::json!(1)),
        ];
        // Only one result for two tests.
        let edge_results = vec![false];

        assert!(
            detector
                .detect_divergence(
                    "test.dll",
                    "X",
                    1,
                    "initial",
                    &baseline,
                    &edge_tests,
                    &edge_results,
                )
                .is_none()
        );
    }

    #[test]
    fn test_divergence_empty_edge_cases_returns_none() {
        let detector = BehaviorDivergenceDetector::new();

        let baseline = vec![true];
        let edge_tests: Vec<EdgeCaseTest> = vec![];
        let edge_results: Vec<bool> = vec![];

        assert!(
            detector
                .detect_divergence(
                    "test.dll",
                    "X",
                    1,
                    "initial",
                    &baseline,
                    &edge_tests,
                    &edge_results,
                )
                .is_none()
        );
    }

    // =========================================================
    // require_all_baseline_pass = false
    // =========================================================

    #[test]
    fn test_detect_with_partial_baseline_passes() {
        let detector = BehaviorDivergenceDetector::new().with_require_all_baseline_pass(false);

        // Baseline has one failure, but we still want to see edge-case
        // failures (mixed diagnostics mode).
        let baseline = vec![true, false, true];
        let edge_tests = vec![
            EdgeCaseTest::new("zero", serde_json::json!([0]), serde_json::json!(0)),
            EdgeCaseTest::new("neg", serde_json::json!([-1]), serde_json::json!(-1)),
        ];
        let edge_results = vec![false, true];

        let signal = detector.detect_divergence(
            "test.dll",
            "X",
            1,
            "initial",
            &baseline,
            &edge_tests,
            &edge_results,
        );

        assert!(signal.is_some());
        let s = signal.unwrap();
        assert_eq!(s.failing_edge_cases.len(), 1);
    }

    // =========================================================
    // Edge-case generation
    // =========================================================

    #[test]
    fn test_generate_edge_cases_zero_check() {
        let detector = BehaviorDivergenceDetector::new();
        let mut hints = HashSet::new();
        hints.insert("zero_check".to_string());

        let tests = detector.generate_edge_cases(2, &hints);

        assert!(!tests.is_empty());
        assert!(tests[0].label.contains("zero"));
        assert_eq!(tests[0].inputs, serde_json::json!([0, 0]));
    }

    #[test]
    fn test_generate_edge_cases_multiple_hints() {
        let detector = BehaviorDivergenceDetector::new();
        let mut hints = HashSet::new();
        hints.insert("zero_check".to_string());
        hints.insert("negative".to_string());
        hints.insert("overflow".to_string());

        let tests = detector.generate_edge_cases(1, &hints);

        assert!(tests.len() >= 3);
        let labels: Vec<&str> = tests.iter().map(|t| t.label.as_str()).collect();
        assert!(labels.iter().any(|l| l.contains("zero")));
        assert!(labels.iter().any(|l| l.contains("negative")));
        assert!(labels.iter().any(|l| l.contains("max")));
    }

    #[test]
    fn test_generate_edge_cases_no_hints() {
        let detector = BehaviorDivergenceDetector::new();
        let hints = HashSet::new();

        let tests = detector.generate_edge_cases(2, &hints);

        // No hints → no edge cases generated.
        assert!(tests.is_empty());
    }

    #[test]
    fn test_generate_edge_cases_null_check() {
        let detector = BehaviorDivergenceDetector::new();
        let mut hints = HashSet::new();
        hints.insert("null_check".to_string());

        let tests = detector.generate_edge_cases(2, &hints);

        assert!(!tests.is_empty());
        assert!(tests[0].inputs.get(0).unwrap().is_null());
    }

    #[test]
    fn test_generate_edge_cases_overflow() {
        let detector = BehaviorDivergenceDetector::new();
        let mut hints = HashSet::new();
        hints.insert("overflow".to_string());

        let tests = detector.generate_edge_cases(1, &hints);

        assert!(!tests.is_empty());
        let val = tests[0].inputs.as_array().unwrap()[0].as_i64().unwrap();
        // The generator produces i32::MAX as the overflow boundary.
        assert_eq!(val, i32::MAX as i64);
    }

    #[test]
    fn test_generate_edge_cases_min_value() {
        let detector = BehaviorDivergenceDetector::new();
        let mut hints = HashSet::new();
        hints.insert("min_value".to_string());

        let tests = detector.generate_edge_cases(1, &hints);

        assert!(!tests.is_empty());
        let val = tests[0].inputs.as_array().unwrap()[0].as_i64().unwrap();
        assert_eq!(val, i32::MIN as i64);
    }

    // =========================================================
    // Boundary divergence detection
    // =========================================================

    #[test]
    fn test_is_boundary_divergence_all_boundary() {
        let detector = BehaviorDivergenceDetector::new();

        let signal = BehaviorDivergenceSignal {
            baseline_passed: 3,
            baseline_total: 3,
            edge_tests_passed: 1,
            edge_tests_total: 3,
            failing_edge_cases: vec![
                EdgeCaseTest::new("zero", serde_json::json!([0]), serde_json::json!(0)),
                EdgeCaseTest::new("negative", serde_json::json!([-1]), serde_json::json!(-1)),
            ],
            suggested_new_baseline_tests: Vec::new(),
            binary: "t".into(),
            function: "f".into(),
            attempt: 1,
            strategy: "initial".into(),
        };

        assert!(detector.is_boundary_divergence(&signal));
    }

    #[test]
    fn test_is_boundary_divergence_mixed() {
        let detector = BehaviorDivergenceDetector::new();

        let signal = BehaviorDivergenceSignal {
            baseline_passed: 3,
            baseline_total: 3,
            edge_tests_passed: 0,
            edge_tests_total: 3,
            failing_edge_cases: vec![
                EdgeCaseTest::new("zero", serde_json::json!([0]), serde_json::json!(0)),
                EdgeCaseTest::new(
                    "wrong_logic",
                    serde_json::json!([10, 20]),
                    serde_json::json!(600),
                ),
            ],
            suggested_new_baseline_tests: Vec::new(),
            binary: "t".into(),
            function: "f".into(),
            attempt: 1,
            strategy: "initial".into(),
        };

        // Not all failing cases are boundary — one is a logic error.
        assert!(!detector.is_boundary_divergence(&signal));
    }

    // =========================================================
    // Confidence scoring
    // =========================================================

    #[test]
    fn test_confidence_high_score() {
        let detector = BehaviorDivergenceDetector::new();

        let signal = BehaviorDivergenceSignal {
            baseline_passed: 10,
            baseline_total: 10,
            edge_tests_passed: 0,
            edge_tests_total: 4,
            failing_edge_cases: vec![
                EdgeCaseTest::new("zero", serde_json::json!([0]), serde_json::json!(0)),
                EdgeCaseTest::new("negative", serde_json::json!([-1]), serde_json::json!(-1)),
                EdgeCaseTest::new(
                    "max",
                    serde_json::json!([2147483647]),
                    serde_json::json!(2147483647),
                ),
                EdgeCaseTest::new(
                    "min",
                    serde_json::json!([i32::MIN]),
                    serde_json::json!(i32::MIN),
                ),
            ],
            suggested_new_baseline_tests: Vec::new(),
            binary: "t".into(),
            function: "f".into(),
            attempt: 1,
            strategy: "initial".into(),
        };

        // All boundary + high baseline pass + all edge fail = high confidence.
        let confidence = detector.divergence_confidence(&signal);
        assert!(confidence >= 7);
    }

    #[test]
    fn test_confidence_low_score() {
        let detector = BehaviorDivergenceDetector::new();

        let signal = BehaviorDivergenceSignal {
            baseline_passed: 0,
            baseline_total: 3,
            edge_tests_passed: 0,
            edge_tests_total: 2,
            failing_edge_cases: vec![EdgeCaseTest::new(
                "random",
                serde_json::json!([100]),
                serde_json::json!(200),
            )],
            suggested_new_baseline_tests: Vec::new(),
            binary: "t".into(),
            function: "f".into(),
            attempt: 1,
            strategy: "initial".into(),
        };

        // Zero baseline + non-boundary = low confidence.
        let confidence = detector.divergence_confidence(&signal);
        assert!(confidence <= 3);
    }

    #[test]
    fn test_confidence_capped_at_10() {
        let detector = BehaviorDivergenceDetector::new();

        let signal = BehaviorDivergenceSignal {
            baseline_passed: 100,
            baseline_total: 100,
            edge_tests_passed: 0,
            edge_tests_total: 10,
            failing_edge_cases: vec![
                EdgeCaseTest::new("a", serde_json::json!([0]), serde_json::json!(0)),
                EdgeCaseTest::new("b", serde_json::json!([-1]), serde_json::json!(-1)),
                EdgeCaseTest::new(
                    "c",
                    serde_json::json!([2147483647]),
                    serde_json::json!(2147483647),
                ),
                EdgeCaseTest::new(
                    "d",
                    serde_json::json!([i32::MIN]),
                    serde_json::json!(i32::MIN),
                ),
                EdgeCaseTest::new("e", serde_json::json!([0u32]), serde_json::json!(0u32)),
                EdgeCaseTest::new(
                    "f",
                    serde_json::json!([i64::MAX]),
                    serde_json::json!(i64::MAX),
                ),
                EdgeCaseTest::new("g", serde_json::json!([null]), serde_json::json!(null)),
                EdgeCaseTest::new(
                    "h",
                    serde_json::json!([i64::MIN]),
                    serde_json::json!(i64::MIN),
                ),
                EdgeCaseTest::new("i", serde_json::json!([-100]), serde_json::json!(-100)),
                EdgeCaseTest::new("j", serde_json::json!([0i64]), serde_json::json!(0i64)),
            ],
            suggested_new_baseline_tests: Vec::new(),
            binary: "t".into(),
            function: "f".into(),
            attempt: 1,
            strategy: "initial".into(),
        };

        let confidence = detector.divergence_confidence(&signal);
        assert_eq!(confidence, 10);
    }

    // =========================================================
    // Recommendation text
    // =========================================================

    #[test]
    fn test_recommendation_includes_failing_count() {
        let detector = BehaviorDivergenceDetector::new();

        let signal = BehaviorDivergenceSignal {
            baseline_passed: 5,
            baseline_total: 5,
            edge_tests_passed: 2,
            edge_tests_total: 5,
            failing_edge_cases: vec![EdgeCaseTest::new(
                "zero",
                serde_json::json!([0]),
                serde_json::json!(0),
            )],
            suggested_new_baseline_tests: vec![EdgeCaseTest::new(
                "zero",
                serde_json::json!([0]),
                serde_json::json!(0),
            )],
            binary: "game.dll".into(),
            function: "Compute".into(),
            attempt: 3,
            strategy: "test_fix".into(),
        };

        let rec = detector.divergence_recommendation(&signal);
        assert!(rec.contains("5 baseline"));
        assert!(rec.contains("1 of 5 edge"));
        assert!(rec.contains("zero"));
    }

    #[test]
    fn test_recommendation_boundary_label() {
        let detector = BehaviorDivergenceDetector::new();

        let signal = BehaviorDivergenceSignal {
            baseline_passed: 3,
            baseline_total: 3,
            edge_tests_passed: 1,
            edge_tests_total: 3,
            failing_edge_cases: vec![
                EdgeCaseTest::new("zero", serde_json::json!([0]), serde_json::json!(0)),
                EdgeCaseTest::new("negative", serde_json::json!([-5]), serde_json::json!(-5)),
            ],
            suggested_new_baseline_tests: Vec::new(),
            binary: "t".into(),
            function: "f".into(),
            attempt: 1,
            strategy: "initial".into(),
        };

        let rec = detector.divergence_recommendation(&signal);
        assert!(rec.contains("boundary values"));
    }

    // =========================================================
    // Edge-case value helpers
    // =========================================================

    #[test]
    fn test_is_boundary_value_zero() {
        assert!(is_boundary_value(&serde_json::json!([0])));
    }

    #[test]
    fn test_is_boundary_value_negative() {
        assert!(is_boundary_value(&serde_json::json!([-1])));
    }

    #[test]
    fn test_is_boundary_value_max() {
        assert!(is_boundary_value(&serde_json::json!([u32::MAX as u64])));
    }

    #[test]
    fn test_is_boundary_value_min() {
        assert!(is_boundary_value(&serde_json::json!([i32::MIN as i64])));
    }

    #[test]
    fn test_is_boundary_value_null() {
        assert!(is_boundary_value(&serde_json::json!(null)));
    }

    #[test]
    fn test_is_boundary_value_normal() {
        assert!(!is_boundary_value(&serde_json::json!([42])));
        assert!(!is_boundary_value(&serde_json::json!([100])));
    }

    #[test]
    fn test_is_boundary_value_empty_string() {
        assert!(is_boundary_value(&serde_json::json!("")));
    }

    #[test]
    fn test_is_boundary_value_empty_array() {
        assert!(is_boundary_value(&serde_json::json!([])));
    }

    #[test]
    fn test_is_boundary_value_mixed_array() {
        assert!(is_boundary_value(&serde_json::json!([42, 0]))); // zero is boundary
        assert!(!is_boundary_value(&serde_json::json!([42, 100]))); // neither is boundary
    }

    // =========================================================
    // EdgeCaseTest construction
    // =========================================================

    #[test]
    fn test_edge_case_test_new() {
        let test = EdgeCaseTest::new(
            "test_label",
            serde_json::json!([1, 2]),
            serde_json::json!(3),
        );
        assert_eq!(test.label, "test_label");
        assert_eq!(test.inputs, serde_json::json!([1, 2]));
        assert_eq!(test.expected, serde_json::json!(3));
    }

    // =========================================================
    // Default trait
    // =========================================================

    #[test]
    fn test_detector_default() {
        let a = BehaviorDivergenceDetector::new();
        let b = BehaviorDivergenceDetector::default();
        assert_eq!(a.require_all_baseline_pass, b.require_all_baseline_pass);
        assert_eq!(a.min_edge_cases, b.min_edge_cases);
        assert_eq!(a.suggest_new_baseline, b.suggest_new_baseline);
    }

    // =========================================================
    // Clone / Debug derivations
    // =========================================================

    #[test]
    fn test_signal_clone() {
        let detector = BehaviorDivergenceDetector::new();
        let baseline = vec![true, true];
        let edge_tests = vec![
            EdgeCaseTest::new("a", serde_json::json!([0]), serde_json::json!(0)),
            EdgeCaseTest::new("b", serde_json::json!([-1]), serde_json::json!(-1)),
        ];
        let edge_results = vec![false, true];

        let signal = detector
            .detect_divergence("d", "f", 1, "s", &baseline, &edge_tests, &edge_results)
            .unwrap();

        let cloned = signal.clone();
        assert_eq!(cloned.binary, signal.binary);
        assert_eq!(cloned.function, signal.function);
        assert_eq!(
            cloned.failing_edge_cases.len(),
            signal.failing_edge_cases.len()
        );
    }
}
