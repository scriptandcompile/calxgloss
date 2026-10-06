//! The [`TestGenerator`] — orchestrator for FFI bindings, test inputs, and baseline execution.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use calxgloss_types::{Export, FunctionInfo, TestCase, TestResult};
use tracing::{debug, info, instrument, warn};

use crate::run::BaselineRunner;

pub use crate::ffi::{FfiBinding, generate_ffi_binding};
pub use crate::inputs::generate_test_inputs;

// ============================================================
// Test Generator (orchestrator)
// ============================================================

/// Main entry point for test generation.
///
/// Manages the generation of FFI bindings, test inputs, and baseline execution
/// for functions extracted from DLLs. The generator stores baseline results
/// in a structured directory layout under `re/baseline/{dll}/{function}.json`.
///
/// # Directory Layout
///
/// ```text
/// re/baseline/
/// └── game_logic.dll/
///     ├── DrawSprite/
///     │   └── baseline.json
///     └── CalculateHash/
///         └── baseline.json
/// ```
#[derive(Debug, Clone)]
pub struct TestGenerator {
    /// Base directory for storing baseline data.
    /// Baselines are written to `{target_dir}/re/baseline/{dll}/{function}.json`.
    target_dir: PathBuf,

    /// Optional Ghidra client for exporting function signatures.
    ghidra: Option<calxgloss_ghidra::GhidraClient>,
}

impl TestGenerator {
    /// Create a new test generator with the given base directory.
    ///
    /// # Arguments
    ///
    /// * `target_dir` - Base directory where baseline data will be stored.
    ///   Baselines are written to `{target_dir}/re/baseline/`.
    pub fn new(target_dir: &Path) -> Self {
        Self {
            target_dir: target_dir.to_path_buf(),
            ghidra: None,
        }
    }

    /// Create a new test generator with an optional Ghidra client.
    ///
    /// The Ghidra client is used to automatically extract function signatures
    /// from the export table when available.
    pub fn new_with_ghidra(target_dir: &Path, ghidra: calxgloss_ghidra::GhidraClient) -> Self {
        Self {
            target_dir: target_dir.to_path_buf(),
            ghidra: Some(ghidra),
        }
    }

    /// Set the Ghidra client for this generator.
    pub fn with_ghidra(mut self, ghidra: calxgloss_ghidra::GhidraClient) -> Self {
        self.ghidra = Some(ghidra);
        self
    }

    /// Generate an FFI binding for a function.
    ///
    /// Takes the function's exported signature (e.g., `"int __stdcall DrawSprite(int x, int y, unsigned int texture_index)"`)
    /// and generates a Rust `extern "C"` block with appropriate type mappings.
    ///
    /// # Arguments
    ///
    /// * `dll` - The DLL filename this function belongs to.
    /// * `function` - The function name.
    /// * `signature` - The function signature as provided by Ghidra.
    ///
    /// # Returns
    ///
    /// A [`FfiBinding`] containing the generated FFI code and parsed type information.
    pub fn generate_ffi_binding(&self, dll: &str, function: &str, signature: &str) -> Result<FfiBinding> {
        debug!(dll, function, signature, "Generating FFI binding");
        let binding = generate_ffi_binding(dll, function, signature)?;
        info!(dll, function, "Generated FFI binding");
        Ok(binding)
    }

    /// Generate test inputs for a function based on its signature and disassembly.
    ///
    /// Generates 10-20 test input cases covering:
    /// - Boundary values (zero, min/max, null pointers)
    /// - Typical values (small positive integers, common strings)
    /// - Edge cases identified from disassembly (comparisons, boundary checks)
    ///
    /// # Arguments
    ///
    /// * `signature` - The function signature with parameter types.
    /// * `disassembly` - Raw disassembly for edge case detection.
    ///
    /// # Returns
    ///
    /// A vector of [`TestCase`] structs with populated inputs. The `expected_return`
    /// and `expected_side_effects` fields are empty and must be filled by
    /// baseline execution.
    pub async fn generate_test_inputs(
        &self,
        signature: &str,
        disassembly: &str,
    ) -> Result<Vec<TestCase>> {
        debug!(
            signature,
            disassembly_len = disassembly.len(),
            "Generating test inputs"
        );
        let test_cases = generate_test_inputs(signature, disassembly)?;
        info!(count = test_cases.len(), "Generated test inputs");
        Ok(test_cases)
    }

    /// Generate test inputs from a [`FunctionInfo`] struct.
    ///
    /// Convenience method that extracts the disassembly from the function info
    /// and calls [`generate_test_inputs`](Self::generate_test_inputs).
    pub async fn generate_test_inputs_from_function(
        &self,
        function_info: &FunctionInfo,
    ) -> Result<Vec<TestCase>> {
        debug!(
            dll = function_info.dll,
            function = function_info.name,
            "Generating test inputs from function"
        );
        self.generate_test_inputs("", &function_info.disassembly)
            .await
    }

    /// Run baseline tests for a function by compiling and executing against the original DLL.
    ///
    /// This method:
    /// 1. Generates an FFI binding for the function
    /// 2. Creates a temporary Cargo project with the binding and a test harness
    /// 3. Compiles and links against the original DLL
    /// 4. Executes each test case, capturing return values and side effects
    /// 5. Returns the test results
    ///
    /// # Arguments
    ///
    /// * `dll` - The DLL filename.
    /// * `function` - The function name.
    /// * `signature` - The function signature.
    /// * `tests` - The test cases to execute.
    /// * `dll_path` - Path to the original DLL on the current system.
    ///
    /// # Returns
    ///
    /// A vector of [`TestResult`] structs with actual return values and side effects populated.
    #[instrument(skip(self, tests, dll_path), fields(dll, function, test_count = tests.len()))]
    pub async fn run_baseline_tests(
        &self,
        dll: &str,
        function: &str,
        signature: &str,
        tests: &[TestCase],
        dll_path: &Path,
    ) -> Result<Vec<TestResult>> {
        debug!(dll, function, "Running baseline tests");

        let runner = BaselineRunner::new(&self.target_dir);
        let results = runner
            .run(dll, function, signature, tests, dll_path)
            .await?;

        info!(
            dll,
            function,
            passed = results.iter().filter(|r| r.passed).count(),
            failed = results.iter().filter(|r| !r.passed).count(),
            "Baseline tests completed"
        );

        Ok(results)
    }

    /// Run baseline tests using exports to extract signatures.
    ///
    /// Convenience method that looks up the function in the exports list,
    /// extracts its signature, and runs the baseline tests.
    pub async fn run_baseline_tests_from_exports(
        &self,
        dll: &str,
        function: &str,
        exports: &[Export],
        tests: &[TestCase],
        dll_path: &Path,
    ) -> Result<Vec<TestResult>> {
        let signature = exports
            .iter()
            .find(|e| e.name == function)
            .map(|e| e.signature.clone())
            .ok_or_else(|| anyhow::anyhow!("Function '{}' not found in exports", function))?;

        self.run_baseline_tests(dll, function, &signature, tests, dll_path)
            .await
    }

    /// Run baseline tests from a [`FunctionInfo`] using Ghidra exports.
    pub async fn run_baseline_from_function(
        &self,
        function_info: &FunctionInfo,
        exports: &[Export],
        tests: &[TestCase],
        dll_path: &Path,
    ) -> Result<Vec<TestResult>> {
        let signature = exports
            .iter()
            .find(|e| e.name == function_info.name)
            .map(|e| e.signature.clone());

        match signature {
            Some(sig) => {
                self.run_baseline_tests(
                    &function_info.dll,
                    &function_info.name,
                    &sig,
                    tests,
                    dll_path,
                )
                .await
            }
            None => {
                warn!(
                    dll = function_info.dll,
                    function = function_info.name,
                    "No signature found in exports, skipping baseline"
                );
                Ok(Vec::new())
            }
        }
    }

    /// Save baseline test results to disk.
    ///
    /// Writes the test results to `re/baseline/{dll}/{function}.json` under
    /// the generator's target directory. Creates parent directories as needed.
    ///
    /// # Arguments
    ///
    /// * `dll` - The DLL filename.
    /// * `function` - The function name.
    /// * `results` - The test results to save.
    pub fn save_baseline(&self, dll: &str, function: &str, results: &[TestResult]) -> Result<()> {
        debug!(dll, function, "Saving baseline");

        let baseline_dir = self
            .target_dir
            .join("re")
            .join("baseline")
            .join(dll)
            .join(function);
        std::fs::create_dir_all(&baseline_dir).context("Failed to create baseline directory")?;

        let baseline_path = baseline_dir.join("baseline.json");
        let json = serde_json::to_string_pretty(results)
            .context("Failed to serialize baseline results")?;

        std::fs::write(&baseline_path, json)
            .with_context(|| format!("Failed to write baseline to {}", baseline_path.display()))?;

        info!(
            path = %baseline_path.display(),
            count = results.len(),
            "Baseline saved"
        );

        Ok(())
    }

    /// Load a previously saved baseline from disk.
    ///
    /// # Arguments
    ///
    /// * `dll` - The DLL filename.
    /// * `function` - The function name.
    ///
    /// # Returns
    ///
    /// A vector of [`TestResult`] structs, or an error if the baseline file
    /// does not exist or cannot be parsed.
    pub fn load_baseline(&self, dll: &str, function: &str) -> Result<Vec<TestResult>> {
        let baseline_path = self
            .target_dir
            .join("re")
            .join("baseline")
            .join(dll)
            .join(function)
            .join("baseline.json");

        if !baseline_path.exists() {
            return Err(anyhow::anyhow!(
                "Baseline not found at {}",
                baseline_path.display()
            ));
        }

        let json = std::fs::read_to_string(&baseline_path)
            .with_context(|| format!("Failed to read baseline from {}", baseline_path.display()))?;

        let results: Vec<TestResult> = serde_json::from_str(&json).with_context(|| {
            format!("Failed to parse baseline from {}", baseline_path.display())
        })?;

        info!(
            path = %baseline_path.display(),
            count = results.len(),
            "Baseline loaded"
        );

        Ok(results)
    }

    /// Get the path where a baseline would be saved for a function.
    pub fn baseline_path(&self, dll: &str, function: &str) -> PathBuf {
        self.target_dir
            .join("re")
            .join("baseline")
            .join(dll)
            .join(function)
            .join("baseline.json")
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        DisassemblyEdgeCases, EdgeCaseSource, FfiBindingBuilder, ParameterTypeInfo, parse_signature,
    };

    #[test]
    fn test_parse_signature_simple() {
        let sig = "int __stdcall DrawSprite(int x, int y, unsigned int texture_index)";
        let info = parse_signature(sig).unwrap();

        assert_eq!(info.return_type, "int");
        assert_eq!(info.calling_convention, Some("__stdcall".to_string()));
        assert_eq!(info.parameters.len(), 3);
        assert_eq!(info.parameters[0].r#type, "int");
        assert_eq!(info.parameters[0].name.as_deref(), Some("x"));
        assert_eq!(info.parameters[1].r#type, "int");
        assert_eq!(info.parameters[1].name.as_deref(), Some("y"));
        assert_eq!(info.parameters[2].r#type, "unsigned int");
        assert_eq!(info.parameters[2].name.as_deref(), Some("texture_index"));
    }

    #[test]
    fn test_parse_signature_no_params() {
        let sig = "void __cdecl Initialize()";
        let info = parse_signature(sig).unwrap();

        assert_eq!(info.return_type, "void");
        assert_eq!(info.calling_convention, Some("__cdecl".to_string()));
        assert_eq!(info.parameters.len(), 0);
    }

    #[test]
    fn test_parse_signature_no_convention() {
        let sig = "int foo(int a, char* b)";
        let info = parse_signature(sig).unwrap();

        assert_eq!(info.return_type, "int");
        assert_eq!(info.calling_convention, None);
        assert_eq!(info.parameters.len(), 2);
    }

    #[test]
    fn test_parse_signature_null_pointer() {
        let sig = "int __stdcall ReadFile(char* buffer, int length)";
        let info = parse_signature(sig).unwrap();

        assert_eq!(info.parameters[0].r#type, "char*");
        assert_eq!(info.parameters[1].r#type, "int");
    }

    #[test]
    fn test_generate_ffi_binding_simple() {
        let sig = "int __stdcall DrawSprite(int x, int y, unsigned int texture_index)";
        let binding = generate_ffi_binding("game_logic.dll", "DrawSprite", sig).unwrap();

        assert!(binding.code.contains("extern \"C\""));
        assert!(binding.code.contains("DrawSprite"));
        assert!(binding.code.contains("x"));
        assert!(binding.code.contains("y"));
        assert!(binding.code.contains("texture_index"));
        assert!(binding.code.contains("i32"));
        assert!(binding.code.contains("u32"));
    }

    #[test]
    fn test_generate_ffi_binding_void_return() {
        let sig = "void __stdcall Initialize()";
        let binding = generate_ffi_binding("init.dll", "Initialize", sig).unwrap();

        assert!(binding.code.contains("fn Initialize"));
        assert!(binding.code.contains("()"));
    }

    #[test]
    fn test_generate_ffi_binding_string_param() {
        let sig = "int __stdcall LoadTexture(const char* path)";
        let binding = generate_ffi_binding("tex.dll", "LoadTexture", sig).unwrap();

        assert!(binding.code.contains("LoadTexture"));
        assert!(binding.code.contains("path"));
        assert!(binding.code.contains("i8"));
    }

    #[test]
    fn test_generate_test_inputs_from_signature() {
        let sig = "int __stdcall DrawSprite(int x, int y, unsigned int texture_index)";
        let tests = generate_test_inputs(sig, "").unwrap();

        assert!(!tests.is_empty());
        assert!(tests.len() >= 10);

        // Check that tests have inputs but empty expected values
        for test in &tests {
            assert!(!test.inputs.is_null());
            assert!(test.expected_return.is_null());
            assert!(test.expected_side_effects.is_empty());
        }
    }

    #[test]
    fn test_generate_test_inputs_with_disassembly() {
        let sig = "int __stdcall DrawSprite(int x, int y, unsigned int texture_index)";
        let disassembly = "cmp eax, 0\nje null_handler\ncmp ecx, 256\nja out_of_bounds";
        let tests = generate_test_inputs(sig, disassembly).unwrap();

        // Should have more tests due to edge cases from disassembly
        assert!(tests.len() >= 10);

        // Check for zero and boundary value inputs
        let inputs_json = serde_json::to_value(&tests).unwrap();
        let inputs_str = inputs_json.to_string();
        assert!(inputs_str.contains("0"));
        assert!(inputs_str.contains("256"));
    }

    #[test]
    fn test_ffi_binding_builder() {
        let binding = FfiBindingBuilder::new("test.dll", "TestFunc")
            .return_type("int")
            .calling_convention("__stdcall")
            .param("x", "i32")
            .param("y", "i32")
            .build();

        assert!(binding.code.contains("TestFunc"));
        assert!(binding.code.contains("extern \"C\""));
        assert!(binding.code.contains("x: i32"));
        assert!(binding.code.contains("y: i32"));
    }

    #[test]
    fn test_test_generator_creation() {
        let generator = TestGenerator::new(Path::new("/tmp/test_baseline"));
        assert_eq!(generator.target_dir, PathBuf::from("/tmp/test_baseline"));
        assert!(generator.ghidra.is_none());
    }

    #[test]
    fn test_test_generator_with_ghidra() {
        let client = calxgloss_ghidra::GhidraClient::new("http://localhost:8080").unwrap();
        let generator = TestGenerator::new_with_ghidra(Path::new("/tmp/test_baseline"), client);
        assert!(generator.ghidra.is_some());
    }

    #[test]
    fn test_save_and_load_baseline() {
        let temp_dir = tempfile::tempdir().unwrap();
        let generator = TestGenerator::new(temp_dir.path());

        let test_case = TestCase {
            inputs: serde_json::json!({"x": 10, "y": 20}),
            expected_return: serde_json::json!(100),
            expected_side_effects: Vec::new(),
        };

        let result = TestResult {
            test_case,
            actual_return: serde_json::json!(100),
            actual_side_effects: Vec::new(),
            passed: true,
            error: None,
        };

        generator
            .save_baseline("test.dll", "TestFunc", &[result])
            .unwrap();

        let loaded = generator.load_baseline("test.dll", "TestFunc").unwrap();
        assert_eq!(loaded.len(), 1);
        assert!(loaded[0].passed);
    }

    #[test]
    fn test_baseline_path() {
        let generator = TestGenerator::new(Path::new("/tmp/test"));
        let expected = PathBuf::from("/tmp/test/re/baseline/test.dll/MyFunc/baseline.json");
        assert_eq!(generator.baseline_path("test.dll", "MyFunc"), expected);
    }

    #[test]
    fn test_edge_case_source_all_variants() {
        //use calxgloss_types::SideEffectKind;

        let sources = vec![
            EdgeCaseSource::Zero,
            EdgeCaseSource::NegativeOne,
            EdgeCaseSource::MinI32,
            EdgeCaseSource::MaxI32,
            EdgeCaseSource::MinU32,
            EdgeCaseSource::MaxU32,
            EdgeCaseSource::NullPointer,
            EdgeCaseSource::EmptyString,
            EdgeCaseSource::MaxStringLength,
            EdgeCaseSource::MinFloat,
            EdgeCaseSource::MaxFloat,
            EdgeCaseSource::NaN,
            EdgeCaseSource::DisassemblyPattern("cmp eax, 100".to_string()),
        ];

        for source in sources {
            let _ = format!("{:?}", source);
        }
    }

    #[test]
    fn test_parameter_type_info() {
        let info = ParameterTypeInfo {
            name: None,
            r#type: "int".to_string(),
            is_pointer: false,
            is_signed: true,
            bit_width: Some(32),
        };

        assert_eq!(info.r#type, "int");
        assert!(info.is_signed);
        assert!(!info.is_pointer);
        assert_eq!(info.bit_width, Some(32));
    }

    #[test]
    fn test_disassembly_edge_cases_empty() {
        let cases = DisassemblyEdgeCases::from_disassembly("");
        assert!(cases.boundary_checks.is_empty());
        assert!(cases.negative_checks.is_empty());
        assert!(cases.zero_checks.is_empty());
        assert!(cases.max_value_checks.is_empty());
    }

    #[test]
    fn test_disassembly_edge_cases_detection() {
        let disassembly = r#"
            cmp eax, 0
            je zero_handler
            cmp ecx, 256
            ja out_of_bounds
            cmp edx, -1
            jl negative_range
            mov eax, 100
            test eax, eax
            jz is_zero
        "#;

        let cases = DisassemblyEdgeCases::from_disassembly(disassembly);
        assert!(!cases.zero_checks.is_empty() || !cases.boundary_checks.is_empty());
    }
}
