//! Baseline test execution infrastructure.
//!
//! Runs test cases against the *original* DLL to establish what the real
//! function does, which is the reference the translated model is later judged
//! against.
//!
//! # Execution Model
//!
//! Calling an arbitrary internal function of a Windows DLL needs the module to
//! be mapped and the target to be called by address, so each function gets its
//! own generated harness rather than a link-time stub:
//!
//! 1. The DLL is parsed to find its image base, architecture, and exports.
//! 2. The function is located — a Ghidra `FUN_<hex>` name becomes an RVA via
//!    the image base, anything else is resolved through the export table.
//! 3. A dependency-free harness is generated: it maps the DLL with
//!    `LoadLibraryExW`, calls the target once per input line, and writes one
//!    result line per case.
//! 4. The harness is cross-compiled for the DLL's own architecture and run
//!    under Wine.
//! 5. A fault in the target is caught by the harness's own crash handler, so a
//!    single bad input costs one case rather than the whole batch.
//!
//! # Temporary Project Structure
//!
//! ```text
//! ~/.cache/calxgloss/baseline/{function_label}/
//! ├── Cargo.toml
//! ├── src/main.rs         # generated harness
//! └── target/             # cross-compiled output
//! ```

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use calxgloss_types::{TestCase, TestResult};
use serde_json::Value;
use tracing::{info, instrument, warn};

use crate::pe::PeImage;
use crate::wine::{HarnessSpec, WineRunner, locator_for_function};
use crate::{FfiStub, parse_signature};

/// Context data passed during test execution.
///
/// Carries information about the function being tested, the test
/// inputs, and expected behavior.
#[derive(Debug, Clone)]
pub struct TestContext {
    /// The DLL being tested.
    pub dll: String,

    /// The function being tested.
    pub function: String,

    /// The test case being executed.
    pub test: TestCase,

    /// The test case index (0-based).
    pub test_index: usize,

    /// The FFI stub for the function.
    pub ffi_stub: FfiStub,
}

/// Runner for baseline tests.
///
/// Manages the creation of temporary Cargo projects, compilation,
/// execution, and result collection for baseline test cases.
#[derive(Debug, Clone)]
pub struct BaselineRunner {
    /// Base directory for temporary test projects.
    work_dir: PathBuf,
}

impl BaselineRunner {
    /// Create a new baseline runner with the given work directory.
    ///
    /// Test projects are created under `{work_dir}/calxgloss_baseline/`.
    pub fn new(work_dir: &Path) -> Self {
        let base = work_dir.join("calxgloss_baseline");
        Self { work_dir: base }
    }

    /// Run baseline tests for a function.
    ///
    /// # Arguments
    ///
    /// * `dll` — The DLL filename.
    /// * `function` — The function name.
    /// * `signature` — The function signature string.
    /// * `tests` — The test cases to execute.
    /// * `dll_path` — Path to the original DLL on the current system.
    ///
    /// # Returns
    ///
    /// A vector of [`TestResult`] structs with actual return values populated.
    /// If the DLL path doesn't exist, returns a vector of failed test results.
    #[instrument(skip(self, tests, dll_path), fields(dll, function, test_count = tests.len()))]
    pub async fn run(
        &self,
        dll: &str,
        function: &str,
        signature: &str,
        tests: &[TestCase],
        dll_path: &Path,
    ) -> Result<Vec<TestResult>> {
        // Check if DLL exists
        if !dll_path.exists() {
            warn!(
                dll_path = %dll_path.display(),
                "Original DLL not found — returning failed test results"
            );
            return self.create_stub_failures(dll, function, tests);
        }

        let image = PeImage::parse(dll_path)
            .with_context(|| format!("Could not read '{}' as a PE image", dll_path.display()))?;
        let machine = image.machine();

        let locator = locator_for_function(&image, function).with_context(|| {
            format!("Could not locate '{function}' in '{}'", dll_path.display())
        })?;
        let parsed = parse_signature(signature)
            .with_context(|| format!("Could not parse the signature of '{function}'"))?;
        let spec = HarnessSpec::new(function, locator, &parsed, machine)
            .with_context(|| format!("Could not build a harness for '{function}'"))?;

        let runner = WineRunner::new(&self.work_dir);
        runner.preflight_wine()?;

        let report = runner
            .run(&spec, dll_path, tests, machine)
            .with_context(|| format!("Baseline execution failed for '{function}'"))?;

        let results = collect_results(&report.results, tests);

        info!(
            dll,
            function,
            count = results.len(),
            passed = results.iter().filter(|r| r.passed).count(),
            "Baseline execution complete"
        );

        Ok(results)
    }

    /// Create stub failure results when the DLL is not available.
    fn create_stub_failures(
        &self,
        dll: &str,
        _function: &str,
        tests: &[TestCase],
    ) -> Result<Vec<TestResult>> {
        let results: Vec<TestResult> = tests
            .iter()
            .map(|test| TestResult {
                test_case: test.clone(),
                actual_return: Value::Null,
                actual_side_effects: Vec::new(),
                passed: false,
                error: Some(format!(
                    "Original DLL '{dll}' not found — baseline cannot be executed. DLL path must be provided to run_baseline_tests.",
                )),
            })
            .collect();

        Ok(results)
    }
}

/// Whether an observed return value agrees with what the test case expected.
///
/// JSON carries no integer widths, so the two sides are compared as they are
/// rather than re-interpreted. The harness already reports a value at the exact
/// width the signature declares, so an expectation derived from that same
/// signature agrees without any coercion — and guessing at a width here could
/// either hide a genuine divergence or invent a false one.
fn values_match(expected: &Value, actual: &Value) -> bool {
    match (expected, actual) {
        // Beyond i64, JSON can only hold the value as a float; that is the
        // closest available reading, and it is exact for anything under 2^53.
        (Value::Number(e), Value::Number(a)) => match (e.as_i64(), a.as_i64()) {
            (Some(e), Some(a)) => e == a,
            _ => e.as_f64() == a.as_f64(),
        },
        _ => expected == actual,
    }
}

/// Turn harness outcomes into [`TestResult`]s, one per test case.
///
/// `passed` means the call completed and, where the test case states an
/// expectation, that the observed return value matched it. A test case with no
/// expectation (`expected_return` is `null`) records what the function did
/// without asserting anything about it — the baseline's job is to establish
/// ground truth, so an unremarked-upon result is not a failure.
///
/// Cases the harness never reported are surfaced as failures rather than
/// dropped: a missing result means the function did something the harness could
/// not account for, and silently omitting it would hide that.
fn collect_results(
    outcomes: &[crate::wine::HarnessTestResult],
    tests: &[TestCase],
) -> Vec<TestResult> {
    tests
        .iter()
        .enumerate()
        .map(|(index, test)| {
            let Some(outcome) = outcomes.iter().find(|o| o.index == index) else {
                return TestResult {
                    test_case: test.clone(),
                    actual_return: Value::Null,
                    actual_side_effects: Vec::new(),
                    passed: false,
                    error: Some("the harness produced no result for this test case".to_string()),
                };
            };

            let expected = &test.expected_return;
            let expectation_stated = !expected.is_null();
            let agrees = !expectation_stated || values_match(expected, &outcome.returned);
            let mismatch = if agrees {
                None
            } else {
                Some(format!(
                    "expected {expected} but the original returned {}",
                    outcome.returned
                ))
            };

            TestResult {
                test_case: test.clone(),
                actual_return: outcome.returned.clone(),
                // Side effects are not observed: the harness calls the target
                // and reports its return value, and reading back whatever the
                // call mutated would need a per-type view of the arguments.
                actual_side_effects: Vec::new(),
                passed: outcome.ok && agrees,
                error: outcome.error.clone().or(mismatch),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wine::HarnessTestResult;
    use serde_json::json;

    fn outcome(index: usize, returned: Value) -> HarnessTestResult {
        HarnessTestResult {
            index,
            ok: true,
            returned,
            error: None,
            crashed: false,
        }
    }

    fn case(inputs: Value, expected: Value) -> TestCase {
        TestCase {
            inputs,
            expected_return: expected,
            expected_side_effects: Vec::new(),
        }
    }

    #[test]
    fn test_values_match_across_json_representations() {
        assert!(values_match(&json!(7), &json!(7)));
        assert!(values_match(&json!(-2147483648), &json!(-2147483648)));
        assert!(values_match(&json!(4294967295u64), &json!(4294967295u64)));
        assert!(values_match(
            &json!("FUN_18008ed50"),
            &json!("FUN_18008ed50")
        ));
        // Signedness is never guessed at: without the declared width these are
        // not comparable, and reading one as the other would hide a divergence.
        assert!(!values_match(&json!(-1), &json!(4294967295u64)));
        assert!(!values_match(&json!(0), &json!(1)));
        assert!(!values_match(&Value::Null, &json!(0)));
    }

    #[test]
    fn test_collect_results_matches_expectations_per_case() {
        let tests = vec![
            case(json!({ "a": 1 }), json!(8)),
            case(json!({ "a": 2 }), json!(99)),
        ];
        let outcomes = vec![outcome(0, json!(8)), outcome(1, json!(7))];

        let results = collect_results(&outcomes, &tests);
        assert_eq!(results.len(), 2);
        assert!(results[0].passed, "{:?}", results[0].error);
        assert!(!results[1].passed);
        assert_eq!(results[1].actual_return, json!(7));
        assert!(
            results[1]
                .error
                .as_deref()
                .is_some_and(|e| e.contains("expected 99") && e.contains("returned 7")),
            "a mismatch should say what was wanted and what happened: {:?}",
            results[1].error
        );
    }

    #[test]
    fn test_case_without_an_expectation_records_ground_truth() {
        // The baseline's job is to establish what the original function does, so
        // a case that states no expectation passes when the call returned.
        let tests = vec![case(json!({ "a": 1 }), Value::Null)];
        let results = collect_results(&[outcome(0, json!(4294967295u64))], &tests);
        assert!(results[0].passed);
        assert_eq!(results[0].actual_return, json!(4294967295u64));
    }

    #[test]
    fn test_a_crashed_case_fails_even_against_a_matching_expectation() {
        let tests = vec![case(json!({ "a": 1 }), json!(8))];
        let outcomes = vec![HarnessTestResult {
            index: 0,
            ok: false,
            returned: Value::Null,
            error: Some("the function under test faulted".to_string()),
            crashed: true,
        }];

        let results = collect_results(&outcomes, &tests);
        assert!(!results[0].passed, "a fault must not be reported as a pass");
        assert_eq!(
            results[0].error.as_deref(),
            Some("the function under test faulted")
        );
    }

    #[test]
    fn test_a_missing_outcome_is_surfaced_rather_than_dropped() {
        // Cases 0 and 2 exist but the harness never reported them; silently
        // returning one result would hide that from the caller.
        let tests = vec![
            case(json!({ "a": 1 }), Value::Null),
            case(json!({ "a": 2 }), Value::Null),
            case(json!({ "a": 3 }), Value::Null),
        ];
        let results = collect_results(&[outcome(1, json!(4))], &tests);
        assert_eq!(results.len(), 3);
        assert!(!results[0].passed && !results[2].passed);
        assert!(results[1].passed);
    }
}
