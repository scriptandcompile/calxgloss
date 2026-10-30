//! Types for verifying translated Rust code against baseline behavior.
//!
//! This module holds the records that report compilation status, test
//! pass/fail counts, and the detail of each test case that diverges from
//! the original binary's behavior.

use crate::test::SideEffect;
use serde::{Deserialize, Serialize};

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
}
