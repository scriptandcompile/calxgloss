//! Prompt templates — Askama template structs for LLM prompt generation.
//!
//! This module contains all the Askama [`Template`](askama::Template) structs
//! used to render translation, fix, and escalation prompts.
//!
//! - [`MinimalTemplate`] — Tier 0: function name, signature, call graph
//! - [`TranslateTemplate`] — Standard translation (disassembly + decompiler + tests)
//! - [`FixTemplate`] — Retry after verification failure
//! - [`EscalateTemplate`] — Retry with additional Ghidra context
//! - [`EdgeCaseTemplate`] — Boundary-value test failure fix
//! - [`RichTemplate`] — Complex functions (101-300 instructions)
//! - [`DetailedTemplate`] — Very complex functions (>300 instructions)
//! - [`SignatureTemplate`] — Tier 0: name and signature only
//! - [`WithTestsTemplate`] — Tier 2: disassembly + decompiler + tests
//! - [`ModuleContextTemplate`] — Tier 3: module context with neighbors + data structures
//! - [`FullModuleTemplate`] — Tier 4: full module with shim layer + PAL traits

use askama::Template;
use calxgloss_types::{ApiCategoryMapping, FailureHint, TranslationRequest};
use serde_json::json;

// ============================================================
// Helper structs (non-template)
// ============================================================

/// A formatted test case for template rendering.
#[derive(serde::Serialize, Clone, Debug)]
pub struct TestCaseFormatted {
    /// Test case index (1-based).
    pub index: usize,
    /// The test inputs as JSON.
    pub inputs: serde_json::Value,
    /// Expected return value as JSON.
    pub expected_return: serde_json::Value,
    /// Expected side effects as JSON.
    pub side_effects: serde_json::Value,
}

/// A failing edge case test with context.
#[derive(Debug, Clone, serde::Serialize)]
pub struct EdgeCaseTest {
    /// Test index (1-based).
    pub index: usize,
    /// Test inputs as JSON.
    pub inputs: serde_json::Value,
    /// Expected output.
    pub expected: serde_json::Value,
    /// Actual output.
    pub actual: serde_json::Value,
    /// Error message from the test harness.
    pub error: String,
    /// Disassembly hints from Ghidra that explain this branch.
    pub disassembly_hints: String,
}

/// A boundary value check identified in the disassembly.
#[derive(Debug, Clone, serde::Serialize)]
pub struct BoundaryValue {
    /// Human-readable description.
    pub description: String,
    /// The condition being checked (e.g., "x <= 0").
    pub condition: String,
    /// Address of the branch instruction.
    pub branch_address: u64,
}

/// A function that is a direct caller or callee of the target function.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CallGraphNeighbor {
    /// The neighbor function's name.
    pub name: String,
    /// Virtual address of the neighbor.
    pub address: u64,
    /// Signature as seen by Ghidra.
    pub signature: String,
    /// Whether this neighbor calls or is called by the target.
    pub role: String,
}

/// A neighboring function with shared context.
#[derive(Debug, Clone, serde::Serialize)]
pub struct NeighborFunction {
    /// The function name.
    pub name: String,
    /// The DLL containing the function.
    pub dll: String,
    /// Virtual address.
    pub address: u64,
    /// Disassembly listing.
    pub disassembly: String,
    /// Pseudo-C decompiler output.
    pub decompiler_output: String,
}

/// A data structure referenced near the target function.
#[derive(Debug, Clone, serde::Serialize)]
pub struct StructuredData {
    /// Name or type tag.
    pub name: String,
    /// Size in bytes, or 0 if unknown.
    pub size: usize,
    /// Struct fields.
    pub fields: Vec<StructField>,
}

/// A single field within a data structure.
#[derive(Debug, Clone, serde::Serialize)]
pub struct StructField {
    /// Field name.
    pub name: String,
    /// Field type as inferred by Ghidra.
    pub type_: String,
    /// Byte offset from struct start, or -1 if unknown.
    pub offset: i64,
}

/// Type information inferred by Ghidra's type database.
#[derive(Debug, Clone, serde::Serialize)]
pub struct TypeInfo {
    /// Type name or signature.
    pub name: String,
    /// Human-readable description, or empty string when none available.
    pub description: String,
}

/// An algorithm recognized in the target function by the analysis pipeline.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AlgorithmInfo {
    /// The recognized algorithm, e.g. `comparison_sort`.
    pub algorithm: String,
    /// The family the algorithm belongs to, e.g. `sorting`.
    pub category: String,
    /// The detector that recognized it, e.g. `cfg_pattern`.
    pub method: String,
    /// Confidence that the recognition is right, 0–100.
    pub confidence: u8,
    /// The decompiled line or string that supports the recognition.
    pub evidence: String,
}

/// A memory lifecycle finding about the target function, made by the
/// analysis pipeline.
///
/// One finding whichever detector made it — the kind names the detector
/// behind the claim (`allocation`, `handle`, `ref_count`) so the prompt
/// can weigh the hypothesis beside the evidence without knowing the
/// record shape that produced it.
#[derive(Debug, Clone, serde::Serialize)]
pub struct MemoryInfo {
    /// The function the finding is about, e.g. `FUN_18003ab00`.
    pub function: String,
    /// The kind of finding, e.g. `allocation`, `handle`, `ref_count`.
    pub kind: String,
    /// The Rust pattern the pairing suggests, e.g. `Box<T>`.
    pub suggestion: String,
    /// Confidence that the finding is right, 0–100.
    pub confidence: u8,
    /// The decompiled lines that support the finding.
    pub evidence: String,
}

/// A formatted test result for template rendering.
///
/// Carries the test case data alongside the pass/fail outcome observed
/// during verification, plus the error message for any failed test.
#[derive(serde::Serialize, Clone, Debug)]
pub struct FormattedTestResult {
    /// Test index (1-based).
    pub index: usize,
    /// The test inputs as JSON.
    pub inputs: serde_json::Value,
    /// Expected return value as JSON.
    pub expected: serde_json::Value,
    /// Actual return value observed during verification.
    pub actual: serde_json::Value,
    /// Whether this test passed verification.
    pub passed: bool,
    /// Error message from the test harness, if the test failed.
    pub error: String,
    /// Expected side effects as JSON.
    pub side_effects: serde_json::Value,
}

impl FormattedTestResult {
    /// Build a `FormattedTestResult` from a baseline [`calxgloss_types::TestCase`].
    pub fn from_baseline(test: &calxgloss_types::TestCase, index: usize) -> Self {
        Self {
            index,
            inputs: test.inputs.clone(),
            expected: test.expected_return.clone(),
            actual: test.expected_return.clone(),
            passed: false,
            error: String::new(),
            side_effects: serde_json::to_value(&test.expected_side_effects)
                .unwrap_or_else(|_| serde_json::json!([])),
        }
    }

    /// Build a `FormattedTestResult` from a baseline + [`calxgloss_types::FailedTest`].
    pub fn from_baseline_with_failure(
        baseline: &calxgloss_types::TestCase,
        failed: &calxgloss_types::FailedTest,
        index: usize,
    ) -> Self {
        Self {
            index,
            inputs: failed.inputs.clone(),
            expected: failed.expected.clone(),
            actual: failed.actual.clone(),
            passed: false,
            error: failed.error.clone(),
            side_effects: serde_json::to_value(&baseline.expected_side_effects)
                .unwrap_or_else(|_| serde_json::json!([])),
        }
    }

    /// Build a `FormattedTestResult` for a passing test from baseline.
    pub fn from_baseline_passing(baseline: &calxgloss_types::TestCase, index: usize) -> Self {
        Self {
            index,
            inputs: baseline.inputs.clone(),
            expected: baseline.expected_return.clone(),
            actual: baseline.expected_return.clone(),
            passed: true,
            error: String::new(),
            side_effects: serde_json::to_value(&baseline.expected_side_effects)
                .unwrap_or_else(|_| serde_json::json!([])),
        }
    }
}

// ============================================================
// Minimal template — Tier 0: function name, signature, call graph
// ============================================================

/// Template for minimal translation prompts.
///
/// Used for simple functions (≤30 instructions). Contains disassembly,
/// decompiler output, baseline tests, and optionally API-category-specific
/// mapping table rows when API-aware augmentation is enabled.
#[derive(Template)]
#[template(path = "minimal_translate.j2")]
pub struct MinimalTemplate {
    /// The function name to translate.
    pub function_name: String,
    /// The DLL containing the function.
    pub dll_name: String,
    /// The virtual address of the function entry point.
    pub address: u64,
    /// Raw disassembly listing from Ghidra.
    pub disassembly: String,
    /// Pseudo-C decompiler output from Ghidra.
    pub decompiler_output: String,
    /// Windows API calls identified in the disassembly.
    pub windows_apis: Vec<calxgloss_types::WindowsApiCall>,
    /// Baseline test cases the translated Rust code must pass.
    pub test_cases: Vec<TestCaseFormatted>,
    /// Whether there are no Windows API calls (for conditional rendering).
    pub no_windows_apis: bool,
    /// API-category-specific mapping rows.
    pub api_category_mappings: Vec<calxgloss_types::ApiCategoryMapping>,
}

impl MinimalTemplate {
    /// Create a new minimal template from a translation request.
    pub fn from_request(req: &TranslationRequest) -> Self {
        let test_cases: Vec<TestCaseFormatted> = req
            .baseline_tests
            .iter()
            .enumerate()
            .map(|(i, test)| TestCaseFormatted {
                index: i + 1,
                inputs: test.inputs.clone(),
                expected_return: test.expected_return.clone(),
                side_effects: serde_json::to_value(&test.expected_side_effects)
                    .unwrap_or_else(|_| json!([])),
            })
            .collect();

        MinimalTemplate {
            function_name: req.function.clone(),
            dll_name: req.dll.clone(),
            address: 0,
            disassembly: req.disassembly.clone(),
            decompiler_output: req.decompiler_output.clone(),
            windows_apis: req.windows_apis.clone(),
            test_cases,
            no_windows_apis: req.windows_apis.is_empty(),
            api_category_mappings: Vec::new(),
        }
    }
}

// ============================================================
// Translate template — standard translation prompt
// ============================================================

/// Template for function translation prompts.
///
/// Rendered via Askama from the embedded `templates/translate.j2` file.
#[derive(Template)]
#[template(path = "translate.j2")]
pub struct TranslateTemplate {
    /// The function name to translate.
    pub function_name: String,
    /// The DLL containing the function.
    pub dll_name: String,
    /// The virtual address of the function entry point.
    pub address: u64,
    /// Raw disassembly listing from Ghidra.
    pub disassembly: String,
    /// Pseudo-C decompiler output from Ghidra.
    pub decompiler_output: String,
    /// Windows API calls identified in the disassembly.
    pub windows_apis: Vec<calxgloss_types::WindowsApiCall>,
    /// Baseline test cases the translated Rust code must pass.
    pub test_cases: Vec<TestCaseFormatted>,
    /// Whether there are no Windows API calls (for conditional rendering).
    pub no_windows_apis: bool,
    /// API-category-specific mapping rows.
    pub api_category_mappings: Vec<calxgloss_types::ApiCategoryMapping>,
}

impl TranslateTemplate {
    /// Create a new translate template from a translation request.
    pub fn from_request(req: &TranslationRequest) -> Self {
        let test_cases: Vec<TestCaseFormatted> = req
            .baseline_tests
            .iter()
            .enumerate()
            .map(|(i, test)| TestCaseFormatted {
                index: i + 1,
                inputs: test.inputs.clone(),
                expected_return: test.expected_return.clone(),
                side_effects: serde_json::to_value(&test.expected_side_effects)
                    .unwrap_or_else(|_| json!([])),
            })
            .collect();

        TranslateTemplate {
            function_name: req.function.clone(),
            dll_name: req.dll.clone(),
            address: 0,
            disassembly: req.disassembly.clone(),
            decompiler_output: req.decompiler_output.clone(),
            windows_apis: req.windows_apis.clone(),
            test_cases,
            no_windows_apis: req.windows_apis.is_empty(),
            api_category_mappings: Vec::new(),
        }
    }
}

// ============================================================
// Fix template — for retrying after verification failure
// ============================================================

/// Template for "fix the compilation errors" or "fix the failing tests" prompts.
///
/// Rendered via Askama from the embedded `templates/failure_fix.j2` file.
#[derive(Template)]
#[template(path = "failure_fix.j2")]
pub struct FixTemplate {
    /// The function name being fixed.
    pub function_name: String,
    /// The DLL containing the function.
    pub dll_name: String,
    /// The previously generated (failing) Rust code.
    pub original_rust_code: String,
    /// A description of what went wrong during verification.
    pub failure_description: String,
    /// Previous attempt failures to reference in the prompt.
    pub failure_history: Vec<FailureHint>,
}

impl FixTemplate {
    /// Create a new fix template without failure history.
    pub fn new(
        function_name: String,
        dll_name: String,
        original_rust_code: String,
        failure_description: String,
    ) -> Self {
        Self {
            function_name,
            dll_name,
            original_rust_code,
            failure_description,
            failure_history: Vec::new(),
        }
    }

    /// Create a new fix template with failure history for informed prompting.
    pub fn with_history(
        function_name: String,
        dll_name: String,
        original_rust_code: String,
        failure_description: String,
        failure_history: Vec<FailureHint>,
    ) -> Self {
        Self {
            function_name,
            dll_name,
            original_rust_code,
            failure_description,
            failure_history,
        }
    }
}

// ============================================================
// Escalate template — for retrying with additional Ghidra context
// ============================================================

/// Template for "add more context and retry" prompts.
///
/// Used when previous attempts failed with compile_fix or test_fix strategies.
#[derive(Template)]
#[template(path = "escalate.j2")]
pub struct EscalateTemplate {
    /// The function name being fixed.
    pub function_name: String,
    /// The DLL containing the function.
    pub dll_name: String,
    /// The previously generated (failing) Rust code.
    pub original_rust_code: String,
    /// A description of what went wrong during verification.
    pub failure_description: String,
    /// Functions directly called by or calling this function.
    pub call_graph_neighbors: Vec<CallGraphNeighbor>,
    /// Other functions sharing context with this function.
    pub neighboring_functions: Vec<NeighborFunction>,
    /// Data structures referenced near this function.
    pub data_structures: Vec<StructuredData>,
    /// Type information inferred by Ghidra.
    pub type_info: Vec<TypeInfo>,
    /// Algorithms recognized in this function by the analysis pipeline.
    pub recognized_algorithms: Vec<AlgorithmInfo>,
    /// Memory lifecycle findings about this function made by the analysis
    /// pipeline.
    pub memory_findings: Vec<MemoryInfo>,
    /// Previous attempt failures to reference in the prompt.
    pub failure_history: Vec<FailureHint>,
    /// Enriched call graph context with caller/callee/leaf-API details.
    pub call_graph_context: Vec<calxgloss_callgraph::FunctionContext>,
}

impl EscalateTemplate {
    /// Create a new escalate template without failure history.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        function_name: String,
        dll_name: String,
        original_rust_code: String,
        failure_description: String,
        call_graph_neighbors: Vec<CallGraphNeighbor>,
        neighboring_functions: Vec<NeighborFunction>,
        data_structures: Vec<StructuredData>,
        type_info: Vec<TypeInfo>,
        recognized_algorithms: Vec<AlgorithmInfo>,
        memory_findings: Vec<MemoryInfo>,
    ) -> Self {
        Self {
            function_name,
            dll_name,
            original_rust_code,
            failure_description,
            call_graph_neighbors,
            neighboring_functions,
            data_structures,
            type_info,
            recognized_algorithms,
            memory_findings,
            failure_history: Vec::new(),
            call_graph_context: Vec::new(),
        }
    }

    /// Create a new escalate template with failure history.
    #[allow(clippy::too_many_arguments)]
    pub fn with_history(
        function_name: String,
        dll_name: String,
        original_rust_code: String,
        failure_description: String,
        call_graph_neighbors: Vec<CallGraphNeighbor>,
        neighboring_functions: Vec<NeighborFunction>,
        data_structures: Vec<StructuredData>,
        type_info: Vec<TypeInfo>,
        recognized_algorithms: Vec<AlgorithmInfo>,
        memory_findings: Vec<MemoryInfo>,
        failure_history: Vec<FailureHint>,
    ) -> Self {
        Self {
            function_name,
            dll_name,
            original_rust_code,
            failure_description,
            call_graph_neighbors,
            neighboring_functions,
            data_structures,
            type_info,
            recognized_algorithms,
            memory_findings,
            failure_history,
            call_graph_context: Vec::new(),
        }
    }

    /// Create a new escalate template with enriched call graph context.
    #[allow(clippy::too_many_arguments)]
    pub fn with_context(
        function_name: String,
        dll_name: String,
        original_rust_code: String,
        failure_description: String,
        call_graph_neighbors: Vec<CallGraphNeighbor>,
        neighboring_functions: Vec<NeighborFunction>,
        data_structures: Vec<StructuredData>,
        type_info: Vec<TypeInfo>,
        recognized_algorithms: Vec<AlgorithmInfo>,
        memory_findings: Vec<MemoryInfo>,
        failure_history: Vec<FailureHint>,
        call_graph_context: Vec<calxgloss_callgraph::FunctionContext>,
    ) -> Self {
        Self {
            function_name,
            dll_name,
            original_rust_code,
            failure_description,
            call_graph_neighbors,
            neighboring_functions,
            data_structures,
            type_info,
            recognized_algorithms,
            memory_findings,
            failure_history,
            call_graph_context,
        }
    }
}

// ============================================================
// Edge case template — for boundary-value test failures
// ============================================================

/// Template for "fix edge cases" prompts.
///
/// Used when tests fail specifically on boundary values (zero, max, negative).
#[derive(Template)]
#[template(path = "edge_case.j2")]
pub struct EdgeCaseTemplate {
    /// The function name being fixed.
    pub function_name: String,
    /// The DLL containing the function.
    pub dll_name: String,
    /// The previously generated (failing) Rust code.
    pub original_rust_code: String,
    /// Failing edge case test details.
    pub failed_tests: Vec<EdgeCaseTest>,
    /// Boundary checks identified from the disassembly.
    pub boundary_values: Vec<BoundaryValue>,
    /// Previous attempt failures to reference in the prompt.
    pub failure_history: Vec<FailureHint>,
}

impl EdgeCaseTemplate {
    /// Create a new edge case template without failure history.
    pub fn new(
        function_name: String,
        dll_name: String,
        original_rust_code: String,
        failed_tests: Vec<EdgeCaseTest>,
        boundary_values: Vec<BoundaryValue>,
    ) -> Self {
        Self {
            function_name,
            dll_name,
            original_rust_code,
            failed_tests,
            boundary_values,
            failure_history: Vec::new(),
        }
    }

    /// Create a new edge case template with failure history.
    pub fn with_history(
        function_name: String,
        dll_name: String,
        original_rust_code: String,
        failed_tests: Vec<EdgeCaseTest>,
        boundary_values: Vec<BoundaryValue>,
        failure_history: Vec<FailureHint>,
    ) -> Self {
        Self {
            function_name,
            dll_name,
            original_rust_code,
            failed_tests,
            boundary_values,
            failure_history,
        }
    }
}

// ============================================================
// Rich template — for complex functions (101-300 instructions)
// ============================================================

/// Template for "rich context" translation prompts.
///
/// Used when a function has 101–300 instructions, multiple API categories,
/// or high branch density.
#[derive(Template)]
#[template(path = "rich_translate.j2")]
pub struct RichTemplate {
    /// The function name to translate.
    pub function_name: String,
    /// The DLL containing the function.
    pub dll_name: String,
    /// The virtual address of the function entry point.
    pub address: u64,
    /// Raw disassembly listing from Ghidra.
    pub disassembly: String,
    /// Pseudo-C decompiler output from Ghidra.
    pub decompiler_output: String,
    /// Windows API calls identified in the disassembly.
    pub windows_apis: Vec<calxgloss_types::WindowsApiCall>,
    /// Whether there are no Windows API calls.
    pub no_windows_apis: bool,
    /// Baseline test cases.
    pub test_cases: Vec<TestCaseFormatted>,
    /// API-category-specific mapping rows.
    pub api_category_mappings: Vec<ApiCategoryMapping>,
}

impl RichTemplate {
    /// Create a new rich template from a translation request.
    pub fn from_request(req: &TranslationRequest) -> Self {
        let test_cases: Vec<TestCaseFormatted> = req
            .baseline_tests
            .iter()
            .enumerate()
            .map(|(i, test)| TestCaseFormatted {
                index: i + 1,
                inputs: test.inputs.clone(),
                expected_return: test.expected_return.clone(),
                side_effects: serde_json::to_value(&test.expected_side_effects)
                    .unwrap_or_else(|_| json!([])),
            })
            .collect();

        RichTemplate {
            function_name: req.function.clone(),
            dll_name: req.dll.clone(),
            address: 0,
            disassembly: req.disassembly.clone(),
            decompiler_output: req.decompiler_output.clone(),
            windows_apis: req.windows_apis.clone(),
            no_windows_apis: req.windows_apis.is_empty(),
            test_cases,
            api_category_mappings: Vec::new(),
        }
    }
}

// ============================================================
// Detailed template — for very complex functions (>300 instructions)
// ============================================================

/// Template for "detailed context" translation prompts.
///
/// Used when a function exceeds 300 instructions or has extreme complexity.
#[derive(Template)]
#[template(path = "detailed_translate.j2")]
pub struct DetailedTemplate {
    /// The function name to translate.
    pub function_name: String,
    /// The DLL containing the function.
    pub dll_name: String,
    /// The virtual address of the function entry point.
    pub address: u64,
    /// Raw disassembly listing from Ghidra.
    pub disassembly: String,
    /// Pseudo-C decompiler output from Ghidra.
    pub decompiler_output: String,
    /// Windows API calls identified in the disassembly.
    pub windows_apis: Vec<calxgloss_types::WindowsApiCall>,
    /// Whether there are no Windows API calls.
    pub no_windows_apis: bool,
    /// Baseline test cases.
    pub test_cases: Vec<TestCaseFormatted>,
    /// API-category-specific mapping rows.
    pub api_category_mappings: Vec<ApiCategoryMapping>,
    /// Functions directly called by or calling this function.
    pub call_graph_neighbors: Vec<CallGraphNeighbor>,
    /// Other functions sharing context with this function.
    pub neighboring_functions: Vec<NeighborFunction>,
    /// Data structures referenced near this function.
    pub data_structures: Vec<StructuredData>,
    /// Type information inferred by Ghidra.
    pub type_info: Vec<TypeInfo>,
}

impl DetailedTemplate {
    /// Create a new detailed template from a translation request.
    pub fn from_request(req: &TranslationRequest) -> Self {
        let test_cases: Vec<TestCaseFormatted> = req
            .baseline_tests
            .iter()
            .enumerate()
            .map(|(i, test)| TestCaseFormatted {
                index: i + 1,
                inputs: test.inputs.clone(),
                expected_return: test.expected_return.clone(),
                side_effects: serde_json::to_value(&test.expected_side_effects)
                    .unwrap_or_else(|_| json!([])),
            })
            .collect();

        DetailedTemplate {
            function_name: req.function.clone(),
            dll_name: req.dll.clone(),
            address: 0,
            disassembly: req.disassembly.clone(),
            decompiler_output: req.decompiler_output.clone(),
            windows_apis: req.windows_apis.clone(),
            no_windows_apis: req.windows_apis.is_empty(),
            test_cases,
            api_category_mappings: Vec::new(),
            call_graph_neighbors: Vec::new(),
            neighboring_functions: Vec::new(),
            data_structures: Vec::new(),
            type_info: Vec::new(),
        }
    }
}

// ============================================================
// Signature template — Tier 0: function name, signature, call graph
// ============================================================

/// Template for Tier 0 translation prompts (name and signature only).
///
/// Contains only the function name, signature, and call graph neighbors.
#[derive(Template)]
#[template(path = "signature_translate.j2")]
pub struct SignatureTemplate {
    /// The function name to translate.
    pub function_name: String,
    /// The DLL containing the function.
    pub dll_name: String,
    /// Virtual address as a hex string.
    pub address_hex: String,
    /// The inferred C signature from Ghidra's decompiler.
    pub signature: String,
    /// Functions directly called by or calling this function.
    pub call_graph_neighbors: Vec<CallGraphNeighbor>,
}

impl SignatureTemplate {
    /// Create a new signature template from tier-0 data.
    pub fn from_data(data: &super::context::SignaturePromptData) -> Self {
        SignatureTemplate {
            function_name: data.function_name.clone(),
            dll_name: data.dll_name.clone(),
            address_hex: data.address_hex.clone(),
            signature: data.signature.clone(),
            call_graph_neighbors: data.call_graph_neighbors.clone(),
        }
    }
}

// ============================================================
// With-tests template — Tier 2: disassembly + decompiler + tests
// ============================================================

/// Template for Tier 2 translation prompts (disassembly + decompiler + baseline tests).
///
/// Contains full disassembly, Ghidra pseudo-C, tagged Windows API calls,
/// call graph neighbors, and baseline test results with pass/fail status.
#[derive(Template)]
#[template(path = "with_tests_translate.j2")]
pub struct WithTestsTemplate {
    /// The function name to translate.
    pub function_name: String,
    /// The DLL containing the function.
    pub dll_name: String,
    /// Virtual address of the function entry point.
    pub address: u64,
    /// Raw disassembly listing from Ghidra.
    pub disassembly: String,
    /// Pseudo-C decompiler output from Ghidra.
    pub decompiler_output: String,
    /// Windows API calls identified in the disassembly.
    pub windows_apis: Vec<calxgloss_types::WindowsApiCall>,
    /// Whether there are no Windows API calls.
    pub no_windows_apis: bool,
    /// Functions directly called by or calling this function.
    pub call_graph_neighbors: Vec<CallGraphNeighbor>,
    /// Baseline test results with pass/fail status and error details.
    pub test_results: Vec<FormattedTestResult>,
    /// Enriched call graph context with caller/callee/leaf-API details.
    pub call_graph_context: Vec<calxgloss_callgraph::FunctionContext>,
}

impl WithTestsTemplate {
    /// Create a new with-tests template from tier-2 data.
    pub fn from_data(data: &super::context::WithTestsPromptData) -> Self {
        WithTestsTemplate {
            function_name: data.function_name.clone(),
            dll_name: data.dll_name.clone(),
            address: data.address,
            disassembly: data.disassembly.clone(),
            decompiler_output: data.decompiler_output.clone(),
            windows_apis: data.windows_apis.clone(),
            no_windows_apis: data.no_windows_apis,
            call_graph_neighbors: data.call_graph_neighbors.clone(),
            test_results: data.test_results.clone(),
            call_graph_context: data.call_graph_context.clone(),
        }
    }
}

// ============================================================
// Module context template — Tier 3: disassembly + tests + neighbors
// ============================================================

/// Template for Tier 3 translation prompts (disassembly + decompiler + tests
/// + neighboring function context + shared data structures).
///
/// Contains full disassembly, Ghidra pseudo-C, tagged Windows API calls,
/// call graph neighbors, baseline test results, neighboring function code
/// and decompiler output, and shared data structure definitions.
#[derive(Template)]
#[template(path = "module_context_translate.j2")]
pub struct ModuleContextTemplate {
    /// The function name to translate.
    pub function_name: String,
    /// The DLL containing the function.
    pub dll_name: String,
    /// Virtual address of the function entry point.
    pub address: u64,
    /// Raw disassembly listing from Ghidra.
    pub disassembly: String,
    /// Pseudo-C decompiler output from Ghidra.
    pub decompiler_output: String,
    /// Windows API calls identified in the disassembly.
    pub windows_apis: Vec<calxgloss_types::WindowsApiCall>,
    /// Whether there are no Windows API calls.
    pub no_windows_apis: bool,
    /// Functions directly called by or calling this function.
    pub call_graph_neighbors: Vec<CallGraphNeighbor>,
    /// Baseline test results with pass/fail status and error details.
    pub test_results: Vec<FormattedTestResult>,
    /// Neighboring functions with full disassembly and decompiler output.
    pub neighboring_functions: Vec<NeighborFunction>,
    /// Data structures referenced near the target function.
    pub data_structures: Vec<StructuredData>,
    /// Enriched call graph context with caller/callee/leaf-API details.
    pub call_graph_context: Vec<calxgloss_callgraph::FunctionContext>,
}

impl ModuleContextTemplate {
    /// Create a new module context template from tier-3 data.
    pub fn from_data(data: &super::context::ModuleContextPromptData) -> Self {
        ModuleContextTemplate {
            function_name: data.function_name.clone(),
            dll_name: data.dll_name.clone(),
            address: data.address,
            disassembly: data.disassembly.clone(),
            decompiler_output: data.decompiler_output.clone(),
            windows_apis: data.windows_apis.clone(),
            no_windows_apis: data.no_windows_apis,
            call_graph_neighbors: data.call_graph_neighbors.clone(),
            test_results: data.test_results.clone(),
            neighboring_functions: data.neighboring_functions.clone(),
            data_structures: data.data_structures.clone(),
            call_graph_context: data.call_graph_context.clone(),
        }
    }
}

// ============================================================
// Helper structs for Tier 4 — shim layer code + PAL traits
// ============================================================

/// A shim layer code block for a crate-replacement DLL.
///
/// Contains the generated Rust shim source code that bridges
/// the original Windows DLL's API surface to a target Rust crate.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ShimCode {
    /// The original DLL filename (e.g., `"d3d9.dll"`).
    pub source_dll: String,
    /// The target Rust crate name (e.g., `"wgpu"`).
    pub target_crate: String,
    /// Number of API mappings in this shim layer.
    pub mapping_count: usize,
    /// The full generated Rust source code of the shim layer.
    pub source: String,
}

/// A Platform Abstraction Layer (PAL) trait definition.
///
/// Represents a PAL trait with its methods, used to abstract
/// platform-specific APIs (DirectX → wgpu, GDI → tiny-skia, etc.)
/// so the LLM knows the exact trait interface to call.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PalTraitDef {
    /// The trait name (e.g., `"GraphicsDevice"`).
    pub trait_name: String,
    /// The crate or module this trait belongs to (e.g., `"pal"`).
    pub module: String,
    /// A one-line description of what this trait abstracts.
    pub description: String,
    /// The list of methods in this trait.
    pub methods: Vec<PalTraitMethod>,
}

/// A single method within a PAL trait definition.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PalTraitMethod {
    /// The method name.
    pub name: String,
    /// The full method signature (e.g., `"fn create_texture(&mut self, width: u32, height: u32) -> Self::Texture"`).
    pub signature: String,
    /// A one-line description of what the method does.
    pub description: String,
}

// ============================================================
// Full module template — Tier 4: module context + shims + PAL
// ============================================================

/// Template for Tier 4 translation prompts (full module context).
///
/// Contains everything from Tier 3 (disassembly, decompiler, tests,
/// neighboring functions, data structures) plus shim layer code for
/// crate-replacement DLLs and PAL trait definitions for platform
/// abstraction. This tier is used when translating functions that
/// call through shim layers and need the full translation-layer
/// context to map correctly.
#[derive(Template)]
#[template(path = "full_module_translate.j2")]
pub struct FullModuleTemplate {
    /// The function name to translate.
    pub function_name: String,
    /// The DLL containing the function.
    pub dll_name: String,
    /// Virtual address of the function entry point.
    pub address: u64,
    /// Raw disassembly listing from Ghidra.
    pub disassembly: String,
    /// Pseudo-C decompiler output from Ghidra.
    pub decompiler_output: String,
    /// Windows API calls identified in the disassembly.
    pub windows_apis: Vec<calxgloss_types::WindowsApiCall>,
    /// Whether there are no Windows API calls.
    pub no_windows_apis: bool,
    /// Functions directly called by or calling this function.
    pub call_graph_neighbors: Vec<CallGraphNeighbor>,
    /// Baseline test results with pass/fail status and error details.
    pub test_results: Vec<FormattedTestResult>,
    /// Neighboring functions with full disassembly and decompiler output.
    pub neighboring_functions: Vec<NeighborFunction>,
    /// Data structures referenced near the target function.
    pub data_structures: Vec<StructuredData>,
    /// Shim layer code for crate-replacement DLLs (e.g., d3d9 → wgpu).
    pub shim_layers: Vec<ShimCode>,
    /// PAL trait definitions for platform abstraction.
    pub pal_traits: Vec<PalTraitDef>,
    /// Enriched call graph context with caller/callee/leaf-API details.
    pub call_graph_context: Vec<calxgloss_callgraph::FunctionContext>,
}

impl FullModuleTemplate {
    /// Create a new full module template from tier-4 data.
    pub fn from_data(data: &super::context::FullModulePromptData) -> Self {
        FullModuleTemplate {
            function_name: data.function_name.clone(),
            dll_name: data.dll_name.clone(),
            address: data.address,
            disassembly: data.disassembly.clone(),
            decompiler_output: data.decompiler_output.clone(),
            windows_apis: data.windows_apis.clone(),
            no_windows_apis: data.no_windows_apis,
            call_graph_neighbors: data.call_graph_neighbors.clone(),
            test_results: data.test_results.clone(),
            neighboring_functions: data.neighboring_functions.clone(),
            data_structures: data.data_structures.clone(),
            shim_layers: data.shim_layers.clone(),
            pal_traits: data.pal_traits.clone(),
            call_graph_context: data.call_graph_context.clone(),
        }
    }
}
