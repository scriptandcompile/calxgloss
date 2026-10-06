//! The [`Verifier`] engine and [`CompileResult`] — core verification types.

use anyhow::{Context, Result};
use calxgloss_types::{ShimVerificationResult, TestCase, VerificationResult};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tracing::{debug, error, info, instrument, warn};

use crate::cargo;
use crate::helpers::{sanitize_crate_name, sanitize_identifier};
use crate::parse;

/// Shared PAL stub content, embedded at compile time from `src/pal/src/stub_content.rs`.
///
/// This file is kept in sync with `stubs.rs` by the build script.  The constant
/// is written to `scratch/pal/src/stub_content.rs` when the first scratch project
/// is created, so the scratch project can `include!` it.
pub const PAL_STUB_CONTENT: &str = include_str!("pal/src/stub_content.rs");

// ============================================================
// Public API
// ============================================================

/// Verification engine for translated Rust code.
///
/// Takes Rust source code and baseline test cases, creates a sandboxed
/// compilation environment, and verifies that the translated code compiles
/// and produces behavior matching the original binary.
#[derive(Debug, Clone)]
pub struct Verifier {
    /// Working directory for scratch Cargo projects.
    work_dir: PathBuf,
}

/// Result of the compilation step.
#[derive(Debug, Clone)]
pub struct CompileResult {
    /// Whether the code compiled without errors.
    pub success: bool,

    /// Compilation error messages, if any.
    pub errors: Vec<String>,

    /// Compilation warnings, if any.
    pub warnings: Vec<String>,

    /// Raw compiler output for debugging.
    pub output: String,
}

impl Verifier {
    /// Create a new verifier with the given working directory.
    ///
    /// The working directory is used to store scratch Cargo projects
    /// created during verification. The directory is created if it
    /// does not exist.
    #[instrument(skip(work_dir))]
    pub fn new(work_dir: &Path) -> Result<Self> {
        let work_dir = work_dir.to_path_buf();
        std::fs::create_dir_all(&work_dir)
            .context("Failed to create verifier working directory")?;
        info!(work_dir = %work_dir.display(), "Created verifier");
        Ok(Self { work_dir })
    }

    /// Compile the translated Rust code.
    ///
    /// Scaffolds a minimal Cargo project, writes the translated code
    /// as a library module with stub implementations for external
    /// dependencies, and runs `cargo check`.
    ///
    /// # Arguments
    ///
    /// * `dll` — The DLL name (used for project identification).
    /// * `function` — The function name (used for module naming).
    /// * `rust_code` — The translated Rust source code.
    ///
    /// # Returns
    ///
    /// A [`CompileResult`] with compilation status and error details.
    #[instrument(skip(self, rust_code), fields(dll, function))]
    pub async fn compile(
        &self,
        dll: &str,
        function: &str,
        rust_code: &str,
    ) -> Result<CompileResult> {
        debug!(dll, function, "Starting compilation check");

        let project = self.scaffold_project(dll, function, rust_code)?;
        let output = cargo::run_cargo_check(&project)
            .await
            .context("cargo check failed")?;
        let (success, errors, warnings) = parse::parse_cargo_output(&output);

        if success {
            info!(dll, function, "Compilation successful");
        } else {
            error!(
                dll,
                function,
                error_count = errors.len(),
                "Compilation failed"
            );
        }

        Ok(CompileResult {
            success,
            errors,
            warnings,
            output,
        })
    }

    /// Verify the translated Rust code against baseline tests.
    ///
    /// Full verification flow:
    /// 1. Compile the code via `cargo check`
    /// 2. If compilation succeeds, run behavioral tests against baseline inputs
    /// 3. Compare outputs against baseline expected values
    ///
    /// # Arguments
    ///
    /// * `dll` — The DLL name.
    /// * `function` — The function name.
    /// * `rust_code` — The translated Rust source code.
    /// * `baseline_tests` — Baseline test cases with expected return values.
    ///
    /// # Returns
    ///
    /// A [`VerificationResult`] with compilation status, test pass/fail counts,
    /// and detailed failure information.
    #[instrument(skip(self, rust_code, baseline_tests), fields(dll, function, test_count = baseline_tests.len()))]
    pub async fn verify(
        &self,
        dll: &str,
        function: &str,
        rust_code: &str,
        baseline_tests: &[TestCase],
    ) -> Result<VerificationResult> {
        debug!(dll, function, "Starting verification");

        let compile_result = self.compile(dll, function, rust_code).await?;

        if !compile_result.success {
            info!(dll, function, "Skipping tests — compilation failed");
            return Ok(VerificationResult {
                compiled: false,
                compilation_errors: compile_result.errors,
                tests_passed: 0,
                tests_total: baseline_tests.len(),
                failed_tests: Vec::new(),
            });
        }

        info!(
            dll,
            function, "Compilation passed, running behavioral tests"
        );

        let project = self.scaffold_test_project(dll, function, rust_code, baseline_tests)?;
        let test_output = cargo::run_test_runner(&project)
            .await
            .unwrap_or_else(|e| format!("Test execution failed: {}", e));

        let (tests_passed, tests_total, failed_tests) =
            parse::parse_test_results(&test_output, baseline_tests);

        info!(
            dll,
            function,
            passed = tests_passed,
            total = tests_total,
            "Verification complete"
        );

        Ok(VerificationResult {
            compiled: true,
            compilation_errors: Vec::new(),
            tests_passed,
            tests_total,
            failed_tests,
        })
    }

    // ---- Internal helpers ----

    /// Ensure the shared PAL crate exists at `{work_dir}/scratch/pal/`.
    ///
    /// The PAL crate is created once per workspace.  All scratch projects
    /// depend on it, so this only needs to run once before any scaffold.
    fn ensure_pal_crate(&self) {
        let pal_dir = self.work_dir.join("scratch").join("pal");
        if pal_dir.join("src").join("stub_content.rs").is_file() {
            return;
        }

        debug!(path = %pal_dir.display(), "Creating shared PAL crate");
        let _ = std::fs::create_dir_all(pal_dir.join("src"));

        // Cargo.toml for the shared PAL crate
        let cargo_toml = r#"[package]
name = "calxgloss-verify-pal"
version = "0.1.0"
edition = "2021"

[dependencies]
"#;
        std::fs::write(pal_dir.join("Cargo.toml"), cargo_toml).ok();

        // lib.rs that includes the embedded stub content
        let lib_rs = r#"// Stub content from stubs.rs.
include!("stub_content.rs");
"#;
        std::fs::write(pal_dir.join("src").join("lib.rs"), lib_rs).ok();

        // Copy stub content (embedded at compile time via include_str!)
        let content_path = pal_dir.join("src").join("stub_content.rs");
        let existing = std::fs::read_to_string(&content_path).ok();
        if existing != Some(PAL_STUB_CONTENT.to_string()) {
            let _ = std::fs::write(&content_path, PAL_STUB_CONTENT);
        }
    }

    /// Scaffold a minimal Cargo project for compilation verification.
    fn scaffold_project(&self, dll: &str, function: &str, rust_code: &str) -> Result<PathBuf> {
        self.ensure_pal_crate();
        let project_dir = self.create_scratch_dir(dll, function);

        let cargo_toml = format!(
            "[package]\nname = \"{}_verify\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\npal = {{ path = \"../pal\", package = \"calxgloss-verify-pal\" }}\n\n[lib]\nname = \"{}_lib\"\npath = \"src/lib.rs\"\n",
            sanitize_crate_name(dll),
            sanitize_identifier(function),
        );
        std::fs::write(project_dir.join("Cargo.toml"), cargo_toml)
            .context("Failed to write Cargo.toml")?;

        std::fs::create_dir_all(project_dir.join("src"))
            .context("Failed to create src directory")?;

        let mut lib_rs = String::new();
        lib_rs.push_str("#![allow(dead_code, unused_imports, unused_variables, clippy::new_without_default, clippy::default_trait_access, clippy::missing_errors_doc)]\n\n");
        lib_rs.push_str("use pal::*;\n\n");
        lib_rs.push_str("// ===== Translated function =====\n\n");
        lib_rs.push_str(rust_code);

        std::fs::write(project_dir.join("src").join("lib.rs"), lib_rs)
            .context("Failed to write lib.rs")?;

        debug!(project = %project_dir.display(), "Scaffolded scratch project");
        Ok(project_dir)
    }

    /// Scaffold a Cargo project with behavioral test runner.
    fn scaffold_test_project(
        &self,
        dll: &str,
        function: &str,
        rust_code: &str,
        baseline_tests: &[TestCase],
    ) -> Result<PathBuf> {
        self.ensure_pal_crate();
        let project_dir = self.create_scratch_dir(dll, function);

        let cargo_toml = format!(
            "[package]\nname = \"{}_verify\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\npal = {{ path = \"../pal\", package = \"calxgloss-verify-pal\" }}\nserde_json = \"1\"\n\n[lib]\nname = \"{}_lib\"\npath = \"src/lib.rs\"\n\n[[bin]]\nname = \"{}_runner\"\npath = \"src/main.rs\"\n",
            sanitize_crate_name(dll),
            sanitize_identifier(function),
            sanitize_identifier(function),
        );
        std::fs::write(project_dir.join("Cargo.toml"), cargo_toml)
            .context("Failed to write Cargo.toml")?;

        std::fs::create_dir_all(project_dir.join("src"))
            .context("Failed to create src directory")?;

        // Write stubs (from pal crate) + translated code for lib.rs
        let mut lib_rs = String::new();
        lib_rs.push_str("#![allow(dead_code, unused_imports, unused_variables, clippy::new_without_default, clippy::default_trait_access, clippy::missing_errors_doc)]\n\n");
        lib_rs.push_str("use pal::*;\n\n");
        lib_rs.push_str("// ===== Translated function =====\n\n");
        lib_rs.push_str(rust_code);
        std::fs::write(project_dir.join("src").join("lib.rs"), lib_rs)
            .context("Failed to write lib.rs")?;

        // Write test runner binary
        let test_harness = self.generate_test_harness(function, baseline_tests);
        std::fs::write(project_dir.join("src").join("main.rs"), test_harness)
            .context("Failed to write test runner")?;

        // Save baseline JSON for the runner
        let baseline_json = serde_json::to_string_pretty(baseline_tests)
            .context("Failed to serialize baseline tests")?;
        std::fs::write(project_dir.join("baseline.json"), baseline_json)
            .context("Failed to write baseline.json")?;

        debug!(project = %project_dir.display(), test_count = baseline_tests.len(), "Scaffolded test project");
        Ok(project_dir)
    }

    /// Create a scratch subdirectory in the working directory.
    fn create_scratch_dir(&self, dll: &str, function: &str) -> PathBuf {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_micros())
            .unwrap_or(0);

        let dir_name = format!(
            "{}_{}_{}",
            sanitize_identifier(dll),
            sanitize_identifier(function),
            timestamp
        );

        let project_dir = self.work_dir.join("scratch").join(dir_name);
        let _ = std::fs::create_dir_all(&project_dir);
        project_dir
    }

    /// Generate a test runner that invokes the translated function with baseline inputs.
    fn generate_test_harness(&self, function: &str, baseline_tests: &[TestCase]) -> String {
        let mut code = String::new();

        // Import the translated library and shared PAL types
        let lib_name = sanitize_crate_name(function);
        code.push_str(&format!("use {}_lib::*;\n", lib_name));
        code.push_str("use pal::*;\n");
        code.push_str("use serde_json::Value;\n\n");

        code.push_str(
            r#"// Test runner for behavioral verification

fn main() {
    let baseline_raw = std::fs::read_to_string("baseline.json")
        .expect("baseline.json not found");
    let tests: Vec<TestCaseInput> = serde_json::from_str(&baseline_raw)
        .expect("Failed to parse baseline.json");

    let results: Vec<TestResult> = tests.iter().enumerate().map(|(i, t)| {
        let output = call_function(&t.inputs);
        TestResult {
            test_index: i,
            expected: t.expected_return.clone(),
            actual: output.clone(),
            passed: t.expected_return == output,
            error: if t.expected_return == output { None } else { Some(format!("expected {}, got {}", t.expected_return, output)) },
        }
    }).collect();

    println!("{}", serde_json::to_string(&results).unwrap());
}

fn call_function(inputs: &Value) -> Value {
"#,
        );

        // Generate input pattern match arms
        code.push_str(&self.generate_input_patterns(baseline_tests));

        code.push_str(
            r#"        _ => {
            // Could not match input pattern
            Value::Object(serde_json::Map::from_iter([
                ("error".into(), Value::String("input pattern not matched for this function signature".into())),
            ]))
        }
    }
}
"#,
        );

        code
    }

    /// Generate input pattern match arms for all test cases.
    fn generate_input_patterns(&self, baseline_tests: &[TestCase]) -> String {
        let mut code = String::new();
        code.push_str("    match inputs {\n");

        for test in baseline_tests {
            let inputs = &test.inputs;

            // Try to extract typed literals from the JSON
            match inputs {
                serde_json::Value::Null => {
                    code.push_str("        Null => call_no_params(),\n");
                }
                serde_json::Value::Number(n) => {
                    if let Some(v) = n.as_i64() {
                        code.push_str(&format!(
                            "        Number(n) if n.as_i64() == Some({}) => call_single_int({}),\n",
                            v, v
                        ));
                    } else if let Some(v) = n.as_u64() {
                        code.push_str(&format!("        Number(n) if n.as_u64() == Some({}) => call_single_uint({}),\n", v, v));
                    } else if let Some(v) = n.as_f64() {
                        code.push_str(&format!("        Number(n) if n.as_f64() == Some({}) => call_single_float({}),\n", v, v));
                    } else {
                        code.push_str("        Number(_) => call_single_int(0),\n");
                    }
                }
                serde_json::Value::Array(arr) if arr.len() == 2 => {
                    code.push_str("        Array(arr) if arr.len() == 2 && arr.iter().all(|v| v.is_number()) => {\n");
                    code.push_str("            if let (Some(a), Some(b)) = (arr[0].as_i64(), arr[1].as_i64()) {\n");
                    code.push_str("                call_two_ints(a as i32, b as i32)\n");
                    code.push_str("            } else {\n");
                    code.push_str("                Value::String(\"type mismatch for 2-int pattern\".into())\n");
                    code.push_str("            }\n        }\n");
                }
                serde_json::Value::Array(arr) if arr.len() == 3 => {
                    code.push_str("        Array(arr) if arr.len() == 3 && arr.iter().all(|v| v.is_number()) => {\n");
                    code.push_str("            if let (Some(a), Some(b), Some(c)) = (arr[0].as_i64(), arr[1].as_i64(), arr[2].as_u64()) {\n");
                    code.push_str(
                        "                call_three_ints(a as i32, b as i32, c as u32)\n",
                    );
                    code.push_str("            } else {\n");
                    code.push_str("                Value::String(\"type mismatch for 3-int pattern\".into())\n");
                    code.push_str("            }\n        }\n");
                }
                serde_json::Value::Array(arr) => {
                    code.push_str(&format!(
                        "        Array(_) if arr.len() == {} => {{",
                        arr.len()
                    ));
                    code.push_str(" Value::String(format!(\"array of length {} not supported\", arr.len()))\n        }}\n");
                }
                serde_json::Value::Object(_) => {
                    code.push_str("        Object(_) => {\n");
                    code.push_str("            Value::String(\"named parameters not supported in MVP\".into())\n");
                    code.push_str("        }\n");
                }
                _ => {
                    code.push_str(
                        "        _ => Value::String(\"unrecognized input pattern\".into()),\n",
                    );
                }
            }
        }

        // Fallback for unmatched patterns
        code.push_str(
            "        _ => Value::String(\"could not match input to function signature\".into()),\n",
        );
        code.push_str("    }\n");

        code
    }

    // ---- Shim layer verification ----

    /// Verify a shim layer by compiling its generated code and running its tests.
    ///
    /// This is the shim-layer equivalent of [`Self::verify`].  It takes raw
    /// shim source and test code (as produced by `calxgloss-analysis::shim_gen`
    /// and `calxgloss-analysis::shim_test_gen`), scaffolds a sandboxed Cargo
    /// project, compiles it, runs `cargo test`, and returns a
    /// [`ShimVerificationResult`] describing the outcome.
    ///
    /// # Arguments
    ///
    /// * `shim_source` — The generated shim module source code.
    /// * `shim_tests` — The generated test module source code.
    /// * `target_crate` — The Rust crate name for the dependency
    ///   (e.g. `"wgpu"`, `"cpal"`).  The dependency is added under the same
    ///   name in the scaffolded `Cargo.toml`.
    /// * `dll_name` — The original DLL name, used for project identification
    ///   and to derive the module name.
    ///
    /// # Example
    ///
    /// ```no_run,ignore
    /// use calxgloss_verify::Verifier;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let shim_source = r#"pub unsafe fn set_texture(stage: u32, texture: *mut c_void) { }"#;
    /// let shim_tests = r#"#[cfg(test)] mod shim_tests { #[test] fn test_placeholder() {} }"#;
    ///
    /// let verifier = Verifier::new(std::path::Path::new("/tmp/calxgloss-work"))?;
    /// let result = verifier.verify_shim(shim_source, shim_tests, "wgpu", "d3d9.dll").await?;
    ///
    /// assert!(result.compiled);
    /// # Ok(())
    /// # }
    /// ```
    #[instrument(skip(self, shim_source, shim_tests), fields(dll, target_crate))]
    pub async fn verify_shim(
        &self,
        shim_source: &str,
        shim_tests: &str,
        target_crate: &str,
        dll_name: &str,
    ) -> Result<ShimVerificationResult> {
        debug!(dll = dll_name, "Starting shim verification");

        // Scaffold a shim project and compile it.
        let project =
            self.scaffold_shim_project(dll_name, shim_source, shim_tests, target_crate)?;
        let compile_output = cargo::run_cargo_check(&project)
            .await
            .context("cargo check failed for shim")?;
        let (compiled, compilation_errors, compilation_warnings) =
            parse::parse_cargo_output(&compile_output);

        if !compiled {
            info!(
                dll = dll_name,
                error_count = compilation_errors.len(),
                "Shim verification failed at compilation"
            );
            return Ok(ShimVerificationResult {
                compiled: false,
                compilation_errors,
                compilation_warnings,
                tests_passed: 0,
                tests_total: 0,
                edge_tests_passed: 0,
                edge_tests_total: 0,
                failed_tests: Vec::new(),
                mapping_results: Vec::new(),
            });
        }

        info!(dll = dll_name, "Shim compiled successfully, running tests");

        // Run the shim's tests.
        let test_output = Self::run_cargo_test(&project)
            .await
            .unwrap_or_else(|e| format!("Test execution failed: {}", e));

        // Parse test results from the test output.
        let (
            tests_passed,
            tests_total,
            edge_tests_passed,
            edge_tests_total,
            failed_tests,
            mapping_results,
        ) = parse::parse_shim_test_results(&test_output, shim_source, shim_tests);

        info!(
            dll = dll_name,
            tests_passed, tests_total, "Shim verification complete"
        );

        Ok(ShimVerificationResult {
            compiled: true,
            compilation_errors: Vec::new(),
            compilation_warnings,
            tests_passed,
            tests_total,
            edge_tests_passed,
            edge_tests_total,
            failed_tests,
            mapping_results,
        })
    }

    /// Scaffold a Cargo project containing shim source and shim tests.
    ///
    /// Creates a minimal project with the shim as a library module, the
    /// target crate as a dependency, and the test module included via an
    /// `include!` so the tests run alongside the code.
    fn scaffold_shim_project(
        &self,
        dll_name: &str,
        shim_source: &str,
        shim_tests: &str,
        target_crate: &str,
    ) -> Result<PathBuf> {
        let project_dir = self.create_scratch_dir(dll_name, "shim");

        // Determine the crate root mapping for Cargo.toml.
        let dep_crate = Self::shim_crate_root_for_cargo(target_crate);

        let cargo_toml = format!(
            "[package]\nname = \"{}_shim\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\n{dep_crate} = {{ version = \"*\", optional = true }}\n\n[features]\ndefault = []\n\n[lib]\nname = \"{}_shim_lib\"\npath = \"src/lib.rs\"\n",
            sanitize_crate_name(dll_name),
            sanitize_identifier(dll_name),
        );
        std::fs::write(project_dir.join("Cargo.toml"), cargo_toml)
            .context("Failed to write shim Cargo.toml")?;

        std::fs::create_dir_all(project_dir.join("src"))
            .context("Failed to create shim src directory")?;

        // Build the lib.rs: shim source + include the test module so cargo test picks it up.
        let mut lib_rs = String::new();
        lib_rs.push_str("#![allow(dead_code, unused_imports, unused_variables, clippy::new_without_default, clippy::default_trait_access, clippy::missing_errors_doc)]\n\n");
        lib_rs.push_str(shim_source);
        lib_rs.push('\n');

        // Write the tests to a separate file and include them.
        let tests_path = "shim_tests.rs";
        let tests_dir = project_dir.join("src");
        std::fs::write(tests_dir.join(tests_path), shim_tests)
            .context("Failed to write shim test file")?;

        // Add include! at the end of lib.rs to bring tests into scope.
        // If the test module already has #[cfg(test)], the include! brings it in.
        lib_rs.push_str(&format!(
            "#[path = \"{tests_path}\"]\nmod shim_tests;\n",
            tests_path = tests_path,
        ));

        std::fs::write(project_dir.join("src").join("lib.rs"), lib_rs)
            .context("Failed to write shim lib.rs")?;

        debug!(
            project = %project_dir.display(),
            "Scaffolded shim scratch project"
        );
        Ok(project_dir)
    }

    /// Resolve a crate name to its Cargo dependency name.
    fn shim_crate_root_for_cargo(crate_name: &str) -> String {
        match crate_name {
            "wgpu" => "wgpu = \"*\"".to_string(),
            "tiny-skia" => "tiny_skia = \"*\"".to_string(),
            "cpal" => "cpal = \"*\"".to_string(),
            "fmod-rs" => "fmod_rs = \"*\"".to_string(),
            "vb6runtime" => "vb6runtime = \"*\"".to_string(),
            _ => format!("{crate_crate} = \"*\"", crate_crate = crate_name),
        }
    }

    /// Run `cargo test` in the given project directory.
    async fn run_cargo_test(project: &Path) -> Result<String> {
        debug!(project = %project.display(), "Running cargo test");

        let output = tokio::process::Command::new("cargo")
            .arg("test")
            .current_dir(project)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .context("Failed to spawn cargo test")?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let combined = format!("{}\n{}", stderr, stdout);

        if output.status.success() {
            debug!("cargo test succeeded");
        } else {
            debug!(
                output = &combined[..combined.len().min(500)],
                "cargo test failed"
            );
        }

        Ok(combined.to_owned())
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Stubs;
    use crate::{parse_cargo_output, parse_test_line, parse_test_results};
    use std::fs;

    #[test]
    fn test_verifier_creation() {
        let dir = std::env::temp_dir().join("calxgloss_verify_test_creation");
        let _ = fs::remove_dir_all(&dir);
        let verifier = Verifier::new(&dir).unwrap();
        assert!(dir.exists());
        let _ = fs::remove_dir_all(&dir);
        let _ = verifier;
    }

    #[test]
    fn test_sanitize_crate_name() {
        assert_eq!(sanitize_crate_name("game_logic.dll"), "game_logic_dll");
        assert_eq!(sanitize_crate_name("my-app"), "my-app");
        assert_eq!(sanitize_crate_name("test_app"), "test_app");
    }

    #[test]
    fn test_sanitize_identifier() {
        assert_eq!(sanitize_identifier("DrawSprite"), "DrawSprite");
        assert_eq!(sanitize_identifier("123test"), "_123test");
        assert_eq!(sanitize_identifier("my_func"), "my_func");
        assert_eq!(sanitize_identifier("hello-world"), "hello_world");
    }

    #[test]
    fn test_parse_cargo_output_empty() {
        let (success, errors, warnings) = parse_cargo_output("");
        assert!(success);
        assert!(errors.is_empty());
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_parse_cargo_output_with_error() {
        let output = r#"error[E0308]: mismatched types
  --> src/lib.rs:5:12
   |
5  |     return "hello";
   |             ^^^^^^^ expected `i32`, found `&str`

error: could not compile (exit status: 1)
"#;
        let (success, errors, _warnings) = parse_cargo_output(output);
        assert!(!success);
        assert!(!errors.is_empty());
    }

    #[test]
    fn test_parse_cargo_output_with_warnings() {
        let output = r#"warning: unused variable: `x`
  --> src/lib.rs:3:9
   |
3  |     let x = 42;
   |         ^ help: if this is intentional, prefix it with an underscore: `_x`

warning: 1 warning emitted
"#;
        let (success, errors, warnings) = parse_cargo_output(output);
        assert!(success);
        assert!(errors.is_empty());
        assert!(!warnings.is_empty());
    }

    #[test]
    fn test_parse_cargo_output_mixed() {
        let output = r#"warning: unused variable
  --> src/lib.rs:1:5
error[E0308]: mismatched types
  --> src/lib.rs:5:12
"#;
        let (success, errors, warnings) = parse_cargo_output(output);
        assert!(!success);
        assert!(!errors.is_empty());
        assert!(!warnings.is_empty());
    }

    #[test]
    fn test_parse_test_results_empty() {
        let baseline = vec![TestCase {
            inputs: serde_json::json!({}),
            expected_return: serde_json::json!(0),
            expected_side_effects: vec![],
        }];
        let (passed, total, failed) = parse_test_results("", &baseline);
        assert_eq!(passed, 0);
        assert_eq!(total, 1);
        assert!(failed.is_empty());
    }

    #[test]
    fn test_parse_test_results_skipped() {
        let baseline = vec![TestCase {
            inputs: serde_json::json!({}),
            expected_return: serde_json::json!(0),
            expected_side_effects: vec![],
        }];
        let (passed, total, failed) = parse_test_results("SKIPPED: no baseline file", &baseline);
        assert_eq!(passed, 0);
        assert_eq!(total, 1);
        assert!(failed.is_empty());
    }

    #[test]
    fn test_parse_test_results_json() {
        let json = r#"[{"expected": 42, "actual": 42, "passed": true, "error": null}, {"expected": 100, "actual": 99, "passed": false, "error": "expected 100, got 99"}]"#;

        let baseline = vec![
            TestCase {
                inputs: serde_json::json!({"x": 10}),
                expected_return: serde_json::json!(42),
                expected_side_effects: vec![],
            },
            TestCase {
                inputs: serde_json::json!({"x": 20}),
                expected_return: serde_json::json!(100),
                expected_side_effects: vec![],
            },
        ];

        let (passed, total, failed) = parse_test_results(json, &baseline);
        assert_eq!(passed, 1);
        assert_eq!(total, 2);
        assert_eq!(failed.len(), 1);
        assert_eq!(failed[0].test_index, 1);
        assert_eq!(failed[0].error, "expected 100, got 99");
    }

    #[test]
    fn test_stubs_all_produces_valid_rust() {
        let stubs = Stubs::all();
        assert!(!stubs.is_empty());
        assert!(stubs.contains("pub trait"));
    }

    #[test]
    fn test_generate_test_harness_structure() {
        let dir = std::env::temp_dir().join("calxgloss_verify_harness");
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::create_dir_all(&dir);

        let verifier = Verifier::new(&dir).unwrap();

        let tests = vec![
            TestCase {
                inputs: serde_json::json!([10, 20]),
                expected_return: serde_json::json!(30),
                expected_side_effects: vec![],
            },
            TestCase {
                inputs: serde_json::json!([0, 0]),
                expected_return: serde_json::json!(0),
                expected_side_effects: vec![],
            },
        ];

        let harness = verifier.generate_test_harness("MyFunc", &tests);
        assert!(harness.contains("fn main()"));
        assert!(harness.contains("fn call_function"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_generate_input_patterns_array() {
        let dir = std::env::temp_dir().join("calxgloss_verify_patterns");
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::create_dir_all(&dir);

        let verifier = Verifier::new(&dir).unwrap();

        let tests = vec![TestCase {
            inputs: serde_json::json!([1, 2, 3]),
            expected_return: serde_json::json!(6),
            expected_side_effects: vec![],
        }];

        let patterns = verifier.generate_input_patterns(&tests);
        assert!(patterns.contains("Array(arr) if arr.len() == 3"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_generate_input_patterns_null() {
        let dir = std::env::temp_dir().join("calxgloss_verify_patterns_null");
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::create_dir_all(&dir);

        let verifier = Verifier::new(&dir).unwrap();

        let tests = vec![TestCase {
            inputs: serde_json::Value::Null,
            expected_return: serde_json::json!(0),
            expected_side_effects: vec![],
        }];

        let patterns = verifier.generate_input_patterns(&tests);
        assert!(patterns.contains("Null => call_no_params()"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_generate_input_patterns_number() {
        let dir = std::env::temp_dir().join("calxgloss_verify_patterns_num");
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::create_dir_all(&dir);

        let verifier = Verifier::new(&dir).unwrap();

        let tests = vec![TestCase {
            inputs: serde_json::json!(42),
            expected_return: serde_json::json!(42),
            expected_side_effects: vec![],
        }];

        let patterns = verifier.generate_input_patterns(&tests);
        assert!(patterns.contains("Number(n) if n.as_i64() == Some(42)"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    #[ignore = "requires cargo binary"]
    async fn test_compilation_result_from_simple_code() {
        let dir = std::env::temp_dir().join("calxgloss_verify_simple");
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::create_dir_all(&dir);
        let verifier = Verifier::new(&dir).unwrap();

        let result = verifier
            .compile(
                "test.dll",
                "SimpleFunc",
                "pub fn simple_func(x: i32) -> i32 { x * 2 }",
            )
            .await;

        if let Ok(cr) = result {
            assert!(cr.success, "Simple function should compile successfully");
            assert!(cr.errors.is_empty());
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    #[ignore = "requires cargo binary"]
    async fn test_compilation_result_from_code_with_errors() {
        let dir = std::env::temp_dir().join("calxgloss_verify_errors");
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::create_dir_all(&dir);
        let verifier = Verifier::new(&dir).unwrap();

        let result = verifier
            .compile(
                "test.dll",
                "BadFunc",
                "pub fn bad_func() -> i32 { \"not an int\" }",
            )
            .await;

        if let Ok(cr) = result {
            assert!(
                !cr.success,
                "Function with type mismatch should not compile"
            );
            assert!(!cr.errors.is_empty());
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_scaffold_project_creates_files() {
        let dir = std::env::temp_dir().join("calxgloss_verify_test_scaffold");
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::create_dir_all(&dir);

        let project_dir = dir.join("test_scaffold_project");

        let verifier = Verifier::new(&project_dir).unwrap();

        let project = verifier
            .scaffold_project(
                "test.dll",
                "MyFunc",
                "pub fn my_func(x: i32) -> i32 { x + 1 }",
            )
            .unwrap();

        assert!(project.exists());
        assert!(project.join("Cargo.toml").exists());
        assert!(project.join("src").join("lib.rs").exists());

        let lib_rs = std::fs::read_to_string(project.join("src").join("lib.rs")).unwrap();
        // Traits are now in the pal module, not directly in lib.rs
        assert!(lib_rs.contains("use pal::*") || lib_rs.contains("pub trait"));
        assert!(lib_rs.contains("pub fn my_func"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_scaffold_test_project_creates_files() {
        let dir = std::env::temp_dir().join("calxgloss_verify_scaffold_test");
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::create_dir_all(&dir);

        let verifier = Verifier::new(&dir).unwrap();

        let tests = vec![TestCase {
            inputs: serde_json::json!([1, 2]),
            expected_return: serde_json::json!(3),
            expected_side_effects: vec![],
        }];

        let project = verifier
            .scaffold_test_project(
                "test.dll",
                "MyFunc",
                "pub fn my_func(x: i32, y: i32) -> i32 { x + y }",
                &tests,
            )
            .unwrap();

        assert!(project.exists());
        assert!(project.join("Cargo.toml").exists());
        assert!(project.join("src").join("lib.rs").exists());
        assert!(project.join("src").join("main.rs").exists());
        assert!(project.join("baseline.json").exists());

        let _ = fs::remove_dir_all(&dir);
    }

    // ---- Shim verification tests ----

    #[test]
    fn test_parse_test_line_ok() {
        let line = "test shim_tests::test_direct3dcreate9_params ... ok";
        let parsed = parse_test_line(line).unwrap();
        assert_eq!(parsed.name, "shim_tests::test_direct3dcreate9_params");
        assert!(parsed.is_ok);
    }

    #[test]
    fn test_parse_test_line_failed() {
        let line = "test shim_tests::test_present_params ... FAILED";
        let parsed = parse_test_line(line).unwrap();
        assert_eq!(parsed.name, "shim_tests::test_present_params");
        assert!(!parsed.is_ok);
    }

    #[test]
    fn test_parse_test_line_ignored() {
        let line = "test shim_tests::test_ignored ... ignored";
        let parsed = parse_test_line(line);
        assert!(parsed.is_none());
    }

    #[test]
    fn test_parse_test_line_non_test() {
        let line = "this is not a test output";
        let parsed = parse_test_line(line);
        assert!(parsed.is_none());
    }
}
