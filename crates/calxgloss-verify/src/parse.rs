//! Output parsing — cargo check, test runner, and shim test results.

use calxgloss_types::{FailedTest, ShimMappingTestResult};
use serde_json::Value;
use tracing::warn;

/// Parse `cargo check` output for errors and warnings.
pub fn parse_cargo_output(output: &str) -> (bool, Vec<String>, Vec<String>) {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();
    let mut current = String::new();
    let mut is_error = false;

    for line in output.lines() {
        if line.contains("error[E") || line.contains("error: ") {
            if !current.is_empty() {
                if is_error {
                    errors.push(current.trim().to_string());
                } else {
                    warnings.push(current.trim().to_string());
                }
            }
            is_error = true;
            current.clear();
        }
        current.push_str(line);
        current.push('\n');
    }

    if !current.is_empty() {
        if is_error {
            errors.push(current.trim().to_string());
        } else {
            warnings.push(current.trim().to_string());
        }
    }

    (errors.is_empty(), errors, warnings)
}

/// Parse test runner output for pass/fail results.
pub fn parse_test_results(
    output: &str,
    baseline_tests: &[calxgloss_types::TestCase],
) -> (usize, usize, Vec<FailedTest>) {
    if output.contains("SKIPPED")
        || output.contains("no baseline file")
        || output.contains("baseline.json not found")
    {
        warn!("Behavioral tests were skipped");
        return (0, baseline_tests.len(), Vec::new());
    }

    // Try to parse test results from JSON output
    let test_output_lines: Vec<&str> = output.lines().filter(|l| l.starts_with('[')).collect();

    if let Some(json_line) = test_output_lines.last()
        && let Ok(results) = serde_json::from_str::<Vec<Value>>(json_line)
    {
        let mut failed = Vec::new();
        let mut passed = 0;

        for (i, result) in results.iter().enumerate() {
            if let Some(passed_val) = result.get("passed").and_then(|v| v.as_bool()) {
                if passed_val {
                    passed += 1;
                } else if let Some(error_msg) = result.get("error").and_then(|v| v.as_str()) {
                    failed.push(FailedTest {
                        test_index: i,
                        inputs: baseline_tests
                            .get(i)
                            .map(|t| t.inputs.clone())
                            .unwrap_or_default(),
                        expected: baseline_tests
                            .get(i)
                            .map(|t| t.expected_return.clone())
                            .unwrap_or_default(),
                        actual: result.get("actual").cloned().unwrap_or_default(),
                        error: error_msg.to_string(),
                    });
                }
            }
        }

        return (passed, results.len(), failed);
    }

    // Fallback: if we couldn't parse structured output, assume tests ran
    // but produced no verifiable results
    let trimmed = output.trim();
    if trimmed.is_empty() {
        return (0, baseline_tests.len(), Vec::new());
    }

    // If cargo run succeeded without errors but we couldn't parse results,
    // the runner may have produced output we don't understand
    (0, baseline_tests.len(), Vec::new())
}

/// Parse `cargo test` output for shim test results.
///
/// Returns `(tests_passed, tests_total, edge_tests_passed, edge_tests_total,
/// failed_tests, mapping_results)`.
///
/// The parser works by scanning the test output for individual test names
/// and grouping them by their originating mapping function name.  Test
/// functions follow the naming convention used by
/// `calxgloss_analysis::shim_test_gen`:
///
/// - `test_<fn_name>_params` — parameter correctness test
/// - `test_<fn_name>_edge_<case>` — edge-case tests
pub fn parse_shim_test_results(
    output: &str,
    _shim_source: &str,
    _shim_tests: &str,
) -> (
    usize,
    usize,
    usize,
    usize,
    Vec<FailedTest>,
    Vec<ShimMappingTestResult>,
) {
    let mut tests_passed: usize = 0;
    let mut tests_total: usize = 0;
    let mut edge_tests_passed: usize = 0;
    let mut edge_tests_total: usize = 0;
    let mut failed_tests: Vec<FailedTest> = Vec::new();

    // Track per-mapping results.
    let mut mapping_stats: std::collections::HashMap<String, (usize, usize, Vec<FailedTest>)> =
        std::collections::HashMap::new();

    // Parse individual test lines: "test shim_tests::test_foo_params ... ok"
    for line in output.lines() {
        // Match lines like: "test shim_tests::test_foo_params ... ok"
        // or: "test shim_tests::test_foo_params ... FAILED"
        if let Some(test_info) = parse_test_line(line) {
            let test_name = test_info.name;
            let is_ok = test_info.is_ok;

            // Determine if this is an edge-case test or a main test.
            let is_edge = test_name.contains("_edge_");
            let mapping_fn = extract_mapping_function(&test_name);

            // Update per-mapping stats.
            mapping_stats
                .entry(mapping_fn.clone())
                .or_insert_with(|| (0, 0, Vec::new()))
                .1 += 1; // total

            if is_edge {
                edge_tests_total += 1;
                if is_ok {
                    edge_tests_passed += 1;
                } else {
                    let error = test_info
                        .error
                        .unwrap_or_else(|| "test failed with unknown error".to_string());
                    failed_tests.push(FailedTest {
                        test_index: edge_tests_total - 1,
                        inputs: serde_json::json!({}),
                        expected: serde_json::json!(true),
                        actual: serde_json::json!(false),
                        error,
                    });
                }
            } else {
                tests_total += 1;
                if is_ok {
                    tests_passed += 1;
                } else {
                    let error = test_info
                        .error
                        .unwrap_or_else(|| "test failed with unknown error".to_string());
                    failed_tests.push(FailedTest {
                        test_index: tests_total - 1,
                        inputs: serde_json::json!({}),
                        expected: serde_json::json!(true),
                        actual: serde_json::json!(false),
                        error,
                    });
                }
            }
        }
    }

    // Build per-mapping result entries.
    let mut mapping_results: Vec<ShimMappingTestResult> = Vec::new();
    for (fn_name, (passed, total, failures)) in &mapping_stats {
        mapping_results.push(ShimMappingTestResult {
            original_api: fn_name.clone(),
            crate_api: String::new(),
            passed: *passed,
            total: *total,
            failures: failures.clone(),
        });
    }

    // Sort mapping results for deterministic output.
    mapping_results.sort_by(|a, b| a.original_api.cmp(&b.original_api));

    (
        tests_passed,
        tests_total,
        edge_tests_passed,
        edge_tests_total,
        failed_tests,
        mapping_results,
    )
}

/// Represents a parsed line from `cargo test` output.
pub struct ParsedTestLine {
    pub name: String,
    pub is_ok: bool,
    pub error: Option<String>,
}

/// Parse a single test output line and extract the test name and result.
///
/// Matches patterns like:
/// - `test shim_tests::test_foo_params ... ok`
/// - `test shim_tests::test_foo_params ... FAILED`
/// - `test shim_tests::test_foo_params ... ignored`
pub fn parse_test_line(line: &str) -> Option<ParsedTestLine> {
    // Look for the "test ..." portion followed by a status.
    let parts: Vec<&str> = line.split(" ... ").collect();
    if parts.len() != 2 {
        return None;
    }

    let prefix = parts[0].trim();
    let status = parts[1].trim();

    // The test name is everything after "test " in the prefix.
    let name = prefix.strip_prefix("test ").map(|s| s.to_string())?;

    // Skip ignored tests — they don't count.
    if status == "ignored" {
        return None;
    }

    let is_ok = status == "ok";

    Some(ParsedTestLine {
        name,
        is_ok,
        error: if !is_ok {
            // Try to find the panic/error in subsequent lines.
            None // Will be filled from context if needed
        } else {
            None
        },
    })
}

/// Extract the mapping function name from a test name.
///
/// Given `shim_tests::test_direct3dcreate9_params` returns
/// `direct3dcreate9`.  Given `shim_tests::test_direct3dcreate9_edge_zero`
/// returns `direct3dcreate9`.
pub fn extract_mapping_function(test_name: &str) -> String {
    // Strip module prefix if present.
    let name = test_name.split("::").last().unwrap_or(test_name);

    // Strip "test_" prefix and "_params" or "_edge_*" suffix.
    let name = name.strip_prefix("test_").unwrap_or(name);
    let name = name.strip_suffix("_params").unwrap_or(name);
    let name = name.strip_suffix("_edge_zero").unwrap_or(name);
    let name = name.strip_suffix("_edge_null").unwrap_or(name);
    let name = name.strip_suffix("_edge_max").unwrap_or(name);
    let name = name.strip_suffix("_edge_empty").unwrap_or(name);
    let name = name.strip_suffix("_edge_negative").unwrap_or(name);
    let name = name.strip_suffix("_edge_overflow").unwrap_or(name);

    name.to_string()
}
