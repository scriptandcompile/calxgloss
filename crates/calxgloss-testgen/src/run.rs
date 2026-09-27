//! Baseline test execution infrastructure.
//!
//! This module provides the ability to compile a temporary Cargo project
//! containing FFI stubs and test harnesses, link against the original DLL,
//! execute test cases, and capture results.
//!
//! # Execution Model
//!
//! For each function under test:
//!
//! 1. A temporary Cargo project is created with:
//!    - The FFI stub for calling the original DLL function
//!    - A test harness that invokes the function with controlled inputs
//!    - Dependencies needed for the FFI (link flags for the target DLL)
//! 2. The project is compiled using `cargo build`
//! 3. The compiled binary is executed, running each test case
//! 4. Return values and side effects are captured and reported
//!
//! # Temporary Project Structure
//!
//! ```text
//! ~/.cache/calxgloss/baseline/{dll_hash}/{function_hash}/
//! ├── Cargo.toml
//! ├── src/
//! │   ├── main.rs          # Test harness
//! │   └── ffi.rs           # FFI stub
//! └── target/              # Build output
//! ```

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};
use calxgloss_types::{SideEffect, TestCase, TestResult};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, instrument, warn};

use crate::FfiStub;

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
        debug!(dll, function, "Starting baseline test execution");

        // Check if DLL exists
        if !dll_path.exists() {
            warn!(
                dll_path = %dll_path.display(),
                "Original DLL not found — returning failed test results"
            );
            return self.create_stub_failures(dll, function, tests);
        }

        // Generate FFI stub
        let ffi_stub = crate::generate_ffi_stub(dll, function, signature)
            .context("Failed to generate FFI stub for baseline execution")?;

        // Create test project directory
        let project_dir = self.create_project(dll, function, &ffi_stub)?;

        // Compile the test project
        self.compile(&project_dir)?;

        // Execute the test binary and collect results
        let results = self.execute(&project_dir, tests)?;

        // Cleanup test project
        self.cleanup(&project_dir)?;

        info!(
            dll,
            function,
            count = results.len(),
            "Baseline execution complete"
        );

        Ok(results)
    }

    /// Create a temporary Cargo project for testing.
    fn create_project(&self, dll: &str, function: &str, ffi_stub: &FfiStub) -> Result<PathBuf> {
        debug!(dll, function, "Creating test project");

        // Create a unique directory for this test
        let project_name = format!("baseline_{}_{}", dll.replace('.', "_"), function);
        let project_dir = self.work_dir.join(&project_name);

        // Create directory structure
        fs::create_dir_all(project_dir.join("src"))
            .context("Failed to create test project directories")?;

        // Write Cargo.toml
        let cargo_toml = self.generate_cargo_toml(dll, &project_name);
        fs::write(project_dir.join("Cargo.toml"), cargo_toml)
            .context("Failed to write Cargo.toml")?;

        // Write FFI stub
        fs::write(project_dir.join("src").join("ffi.rs"), &ffi_stub.code)
            .context("Failed to write FFI stub")?;

        // Write test harness
        // The harness reads test cases from stdin (JSON array) and outputs results (JSON array)
        let harness = self.generate_test_harness(dll, function);
        fs::write(project_dir.join("src").join("main.rs"), harness)
            .context("Failed to write test harness")?;

        info!(
            path = %project_dir.display(),
            "Test project created"
        );

        Ok(project_dir)
    }

    /// Generate a Cargo.toml for the test project.
    fn generate_cargo_toml(&self, _dll: &str, project_name: &str) -> String {
        format!(
            r#"[package]
name = "{project_name}"
version = "0.1.0"
edition = "2021"

[[bin]]
name = "test_runner"
path = "src/main.rs"

[dependencies]
serde = {{ version = "1.0", features = ["derive"] }}
serde_json = "1.0"
"#
        )
    }

    /// Generate a test harness that reads test cases from stdin and outputs results.
    fn generate_test_harness(&self, dll: &str, function: &str) -> String {
        // The harness dynamically includes the FFI stub and runs tests.
        // Since we can't easily include the FFI at compile time for arbitrary functions,
        // the harness generates the FFI code and compiles it as a module.
        //
        // For MVP, we use a simpler approach: the harness is a template that
        // gets customized with the specific function call.
        format!(
            r#"// Auto-generated test harness for {dll}::{function}
// Note: This is a skeleton for MVP. Full execution requires
// linking against the original DLL at runtime.

use serde::{{Deserialize, Serialize}};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Debug, Clone)]
struct TestInput {{
    inputs: HashMap<String, serde_json::Value>,
}}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct TestOutput {{
    test_index: usize,
    inputs: HashMap<String, serde_json::Value>,
    actual_return: serde_json::Value,
    passed: bool,
    error: Option<String>,
}}

// The FFI module is included from ffi.rs
include!("{ffi_stub_path}");

fn main() {{
    // Read test cases from stdin
    let input_data: String = std::io::stdin().read_line(&mut Vec::new()).unwrap_or_default();
    let test_cases: Vec<TestInput> = serde_json::from_str(&input_data).expect("Failed to parse test cases");

    let mut results: Vec<TestOutput> = Vec::new();

    for (i, test) in test_cases.iter().enumerate() {{
        // TODO: Implement actual FFI call
        // For MVP, we output placeholder results
        results.push(TestOutput {{
            test_index: i,
            inputs: test.inputs.clone(),
            actual_return: serde_json::Value::Null,
            passed: false,
            error: Some("FFI execution not yet implemented in MVP".to_string()),
        }});
    }}

    // Output results as JSON to stdout
    let output = serde_json::to_string_pretty(&results).expect("Failed to serialize results");
    println!("{{}}", output);
}}
"#,
            ffi_stub_path = "../src/ffi.rs",
        )
    }

    /// Compile the test project.
    fn compile(&self, project_dir: &Path) -> Result<()> {
        debug!(path = %project_dir.display(), "Compiling test project");

        let status = Command::new("cargo")
            .arg("build")
            .arg("--release")
            .current_dir(project_dir)
            .status()
            .context("Failed to run cargo build")?;

        if !status.success() {
            return Err(anyhow::anyhow!(
                "Test project compilation failed (exit code: {:?})",
                status.code()
            ));
        }

        debug!("Test project compiled successfully");
        Ok(())
    }

    /// Execute the test binary and collect results.
    fn execute(&self, project_dir: &Path, tests: &[TestCase]) -> Result<Vec<TestResult>> {
        debug!("Executing test binary");

        let _binary_path = project_dir
            .join("target")
            .join("release")
            .join("test_runner");

        // Convert test cases to JSON input
        let test_inputs: Vec<HashMap<String, serde_json::Value>> = tests
            .iter()
            .map(|t| {
                let mut map = HashMap::new();
                if let serde_json::Value::Object(obj) = &t.inputs {
                    for (k, v) in obj.iter() {
                        map.insert(k.clone(), v.clone());
                    }
                }
                map
            })
            .collect();

        let _input_json =
            serde_json::to_string(&test_inputs).context("Failed to serialize test inputs")?;

        // In the future, this would spawn the test_runner binary and
        // pipe the test inputs to its stdin, then parse JSON results from stdout.
        // For MVP, we return placeholder results since the FFI link step
        // is not yet fully implemented.
        warn!("MVP: FFI execution is not yet fully implemented. Returning placeholder results.");

        // Build the same wire format the compiled test_runner emits, then convert
        // it to `TestResult`s through the real deserialization path.
        let outputs: Vec<ExecutionOutput> = test_inputs
            .iter()
            .enumerate()
            .map(|(i, inputs)| ExecutionOutput {
                test_index: i,
                inputs: serde_json::Value::Object(inputs.clone().into_iter().collect()),
                actual_return: serde_json::Value::Null,
                actual_side_effects: Vec::new(),
                passed: false,
                error: Some(
                    "FFI execution requires the original DLL to be present at runtime".to_string(),
                ),
            })
            .collect();

        Ok(outputs_to_results(&outputs, tests))
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
                actual_return: serde_json::Value::Null,
                actual_side_effects: Vec::new(),
                passed: false,
                error: Some(format!(
                    "Original DLL '{}' not found — baseline cannot be executed. DLL path must be provided to run_baseline_tests.",
                    dll
                )),
            })
            .collect();

        Ok(results)
    }

    /// Cleanup temporary test project.
    fn cleanup(&self, project_dir: &Path) -> Result<()> {
        // Optionally keep test projects for debugging.
        // For now, we skip cleanup to allow inspection of generated code.
        debug!(path = %project_dir.display(), "Keeping test project for inspection");
        Ok(())
    }
}

/// A single test execution output from the baseline runner.
///
/// This type is used to communicate results between the compiled test
/// binary and the harness.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionOutput {
    /// The test case index (0-based).
    pub test_index: usize,

    /// The inputs that were tested.
    pub inputs: serde_json::Value,

    /// The actual return value observed from the original function.
    pub actual_return: serde_json::Value,

    /// Side effects observed during execution.
    pub actual_side_effects: Vec<SideEffect>,

    /// Whether the test passed (actual matches expected).
    pub passed: bool,

    /// Error message if the test failed or an error occurred.
    pub error: Option<String>,
}

/// Convert execution outputs to [`TestResult`] structs.
pub fn outputs_to_results(outputs: &[ExecutionOutput], tests: &[TestCase]) -> Vec<TestResult> {
    outputs
        .iter()
        .filter_map(|output| {
            tests.get(output.test_index).map(|test| TestResult {
                test_case: test.clone(),
                actual_return: output.actual_return.clone(),
                actual_side_effects: output.actual_side_effects.clone(),
                passed: output.passed,
                error: output.error.clone(),
            })
        })
        .collect()
}
