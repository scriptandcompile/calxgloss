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

/// What one run's runner rows say the gate learned, per dimension.
#[derive(Debug, Clone, Default)]
pub struct TestRunReport {
    /// Cases the runner reported as passed.
    pub passed: usize,

    /// Rows the runner produced (or, with no rows, the suite size it
    /// never got through).
    pub total: usize,

    /// Rows the runner reported as failed.
    pub failed: Vec<FailedTest>,

    /// Cases whose expected API-call trace was compared.
    pub trace_assessed: usize,

    /// Cases whose return value the runner could call and compare —
    /// uncallable inputs and expected-null cases leave this count alone.
    pub value_assessed: usize,

    /// Value-assessed cases whose returned value matched the expectation.
    pub values_matched: usize,

    /// Whether the runner produced any per-case result rows at all.
    /// A non-empty baseline with no rows means the test project (unit
    /// plus runner) never built or the runner broke before printing —
    /// counts alone must never read as a verdict over an unjudged suite.
    pub produced_results: bool,

    /// Whether the runner stopped before finishing the suite: the rows it
    /// printed cover fewer cases than the suite holds and its last word is
    /// a fatal signal, so the unit itself crashed on the next case.
    pub incomplete: bool,
}

/// How many raw output lines, and how many characters all told, a
/// parse-failure warning quotes. Enough of a chatty runner's first word
/// to spot a format mismatch; small enough that no runner floods the log.
const MAX_EXCERPT_LINES: usize = 20;
const MAX_EXCERPT_CHARS: usize = 2_000;

/// The raw runner output a parse failure quotes, cut to the line and
/// character budgets above. An ellipsis admits when the quote was cut.
fn bounded_runner_excerpt(output: &str) -> String {
    let lines = output.lines().collect::<Vec<_>>();
    let mut excerpt = lines
        .iter()
        .take(MAX_EXCERPT_LINES)
        .copied()
        .collect::<Vec<_>>()
        .join("\n");
    let chars_cut = excerpt.chars().count() > MAX_EXCERPT_CHARS;
    if chars_cut {
        excerpt = excerpt.chars().take(MAX_EXCERPT_CHARS).collect();
    }
    if lines.len() > MAX_EXCERPT_LINES || chars_cut {
        excerpt.push('…');
    }
    excerpt
}

/// Parse test runner output for pass/fail results.
///
/// Counts each dimension honestly: `trace_assessed` counts the cases
/// whose expected API-call trace was recorded and therefore compared,
/// and `value_assessed` counts the cases the runner could actually call
/// and hold against an expected return (the new runner rows name this;
/// older row shapes that always compared a value read as assessed).
pub fn parse_test_results(
    output: &str,
    baseline_tests: &[calxgloss_types::TestCase],
) -> TestRunReport {
    if output.contains("SKIPPED")
        || output.contains("no baseline file")
        || output.contains("baseline.json not found")
    {
        warn!("Behavioral tests were skipped");
        return TestRunReport {
            total: baseline_tests.len(),
            ..Default::default()
        };
    }

    // Try to parse test results from JSON output
    let test_output_lines: Vec<&str> = output.lines().filter(|l| l.starts_with('[')).collect();

    if let Some(json_line) = test_output_lines.last()
        && let Ok(results) = serde_json::from_str::<Vec<Value>>(json_line)
    {
        let mut failed = Vec::new();
        let mut report = TestRunReport {
            total: results.len(),
            produced_results: !results.is_empty(),
            ..Default::default()
        };

        for (i, result) in results.iter().enumerate() {
            // The runner assessed the trace dimension for this case exactly
            // when it carried a non-empty expected trace; the count rides
            // even on passing cases, where no failure record exists.
            if result
                .get("trace_assessed")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
            {
                report.trace_assessed += 1;
            }
            // The runner assessed the values dimension for this case when
            // it could call the unit AND the baseline case carried an
            // expected return. A row that predates the flag compared a
            // value unconditionally, so it reads as assessed.
            let value_assessed = result
                .get("value_assessed")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);
            if value_assessed {
                report.value_assessed += 1;
                let expected = baseline_tests
                    .get(i)
                    .map(|t| t.expected_return.clone())
                    .unwrap_or_else(|| result.get("expected").cloned().unwrap_or_default());
                if result.get("actual").cloned().unwrap_or_default() == expected {
                    report.values_matched += 1;
                }
            }
            if let Some(passed_val) = result.get("passed").and_then(|v| v.as_bool()) {
                if passed_val {
                    report.passed += 1;
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
                        // The expected side effects travel with the failure
                        // as typed kinds, so a divergence on global handling
                        // is reported by name — machine-comparable — and not
                        // only inside the prose error string.
                        expected_side_effects: baseline_tests
                            .get(i)
                            .map(|t| t.expected_side_effects.clone())
                            .unwrap_or_default(),
                        // The expected and actual API-call traces travel
                        // side by side as typed sequences, and a trace
                        // divergence names its first position — so a reviewer
                        // reads "wrong path" apart from "wrong value" without
                        // parsing prose. The runner reports both; the expected
                        // also rides the baseline case for redundancy.
                        expected_api_calls: baseline_tests
                            .get(i)
                            .map(|t| t.expected_api_calls.clone())
                            .unwrap_or_default(),
                        actual_api_calls: result
                            .get("actual_api_calls")
                            .and_then(|v| v.as_array())
                            .map(|arr| {
                                arr.iter()
                                    .filter_map(|v| v.as_str().map(String::from))
                                    .collect()
                            })
                            .unwrap_or_default(),
                        trace_divergence_index: result
                            .get("trace_divergence_index")
                            .and_then(|v| v.as_u64())
                            .map(|v| v as usize),
                    });
                }
            }
        }

        report.failed = failed;
        // The runner stopped mid-suite when its last word is a fatal
        // signal and the rows it printed cover fewer cases than the suite
        // holds: the unit crashed on the next case, and that case's return
        // was never observed.
        report.incomplete = !results.is_empty()
            && results.len() < baseline_tests.len()
            && runner_death_signal(output);
        return report;
    }

    // No JSON rows at all. The caller (`Verifier::verify`) decides whose
    // failure this is — a test project that never built, or a runner
    // that broke without printing — and `produced_results: false` is
    // what lets that routing stay honest instead of filing an unjudged
    // run as a zero-test pass.
    let trimmed = output.trim();
    if trimmed.is_empty() {
        warn!("Test runner produced no output");
    } else {
        // The warning line quotes what the runner printed (issue #441), so
        // a format mismatch is diagnosable from the run log alone. The
        // quote is bounded, so a chatty or huge runner can never flood the
        // log; tracing keeps a &str field on the warning's own line.
        let excerpt = bounded_runner_excerpt(trimmed);
        warn!(
            runner_output = excerpt.as_str(),
            "Could not parse test results from runner output"
        );
    }
    TestRunReport {
        total: baseline_tests.len(),
        ..Default::default()
    }
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
                        expected_side_effects: Vec::new(),
                        expected_api_calls: Vec::new(),
                        actual_api_calls: Vec::new(),
                        trace_divergence_index: None,
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
                        expected_side_effects: Vec::new(),
                        expected_api_calls: Vec::new(),
                        actual_api_calls: Vec::new(),
                        trace_divergence_index: None,
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

/// True when a test runner's captured output reports that the runner
/// process itself died on a fatal signal — a segfault or abort from the
/// code under test, not a compile or test failure. A harness that calls a
/// unit with a raw address (a null pointer the JSON `null` coerced to)
/// sees this when the unit dereferences it; cargo words the death as
/// `(signal: 11, SIGSEGV: invalid memory reference)` on its failure line.
pub fn runner_death_signal(output: &str) -> bool {
    output.lines().any(|line| {
        let line = line.trim();
        line.contains("(signal:")
            && (line.contains("SIGILL")
                || line.contains("SIGABRT")
                || line.contains("SIGBUS")
                || line.contains("SIGFPE")
                || line.contains("SIGSEGV"))
    })
}

/// Failure record for a suite the runner died part-way through: the crash
/// names itself, and no return is claimed for it — nothing was assessed.
pub fn crashed_suite_failure(test_index: usize, inputs: &serde_json::Value) -> FailedTest {
    FailedTest {
        test_index,
        inputs: inputs.clone(),
        expected: serde_json::Value::Null,
        actual: serde_json::Value::String("runner died on a fatal signal".to_string()),
        error: "the code under test crashed the runner (segfault or abort), so its return \
             was never observed"
            .to_string(),
        expected_side_effects: Vec::new(),
        expected_api_calls: Vec::new(),
        actual_api_calls: Vec::new(),
        trace_divergence_index: None,
    }
}

/// Failure record for a suite whose runner died on a fatal signal before
/// printing any row: nothing printed means nothing attributes the death
/// to a case, so the record names the crash, admits the crashed case is
/// unknown, and claims no inputs and no return.
pub fn runner_died_before_first_row() -> FailedTest {
    FailedTest {
        test_index: 0,
        inputs: serde_json::Value::Null,
        expected: serde_json::Value::Null,
        actual: serde_json::Value::String("runner died on a fatal signal".to_string()),
        error: "the code under test crashed the runner (segfault or abort) before it printed \
             any result row; the crashed case is unknown, so no case is blamed and no \
             return was observed"
            .to_string(),
        expected_side_effects: Vec::new(),
        expected_api_calls: Vec::new(),
        actual_api_calls: Vec::new(),
        trace_divergence_index: None,
    }
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
