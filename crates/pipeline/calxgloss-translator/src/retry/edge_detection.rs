//! Detect whether test failures are concentrated on boundary values.

/// Detect whether test failures are concentrated on boundary values.
///
/// Returns `true` if the failing tests are likely edge cases (zero, max, negative,
/// null, empty, overflow). This is used to decide whether `EdgeCaseFix` is
/// appropriate.
pub fn is_edge_case_failure(
    failed_tests: &[String],
    _tests_passed: usize,
    _tests_total: usize,
) -> bool {
    // Need some failures to matter
    if failed_tests.is_empty() {
        return false;
    }

    // Check if failures are all in boundary-value territory.
    // Word-boundary indicators avoid matching "0" inside "100".
    let boundary_indicators = [
        "zero",
        "null",
        "max",
        "overflow",
        "underflow",
        "negative",
        "empty",
        "min",
        "boundary",
        "i32::",
        "u32::",
        "i16::",
        "u16::",
        "i64::",
        "u64::",
        "i8::",
        "u8::",
    ];

    let total_failing = failed_tests.len();
    let mut boundary_matches = 0u32;

    for test_desc in failed_tests {
        let lower = test_desc.to_lowercase();
        for indicator in &boundary_indicators {
            if lower.contains(indicator) {
                boundary_matches += 1;
                break;
            }
        }
    }

    // If the majority of failing tests mention boundary indicators,
    // treat as edge case failure.
    boundary_matches as f64 >= (total_failing as f64 * 0.5)
}
