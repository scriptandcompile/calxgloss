//! Types for verifying translated Rust code against baseline behavior.
//!
//! This module defines the data structures used to report compilation
//! status, test pass/fail counts, and detailed failure information for
//! each test case that diverges from the original binary's behavior.

use serde::{Deserialize, Serialize};

/// Detailed information about a single test failure.
///
/// Produced when the Rust translation produces different output than
/// the baseline tests captured from the original binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
}
