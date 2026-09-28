//! Prompt templates and rendering for the Calxgloss LLM translation pipeline.
//!
//! This crate provides a lightweight template engine for building prompts
//! sent to the local LLM. Templates are embedded at compile time via
//! `include_str!` and rendered with structured data from the translation
//! pipeline.
//!
//! # Architecture
//!
//! - [`PromptLibrary`] — a collection of named templates (e.g. `"translate"`)
//!   that can be looked up and rendered in one call.
//! - [`build_translate_prompt`] — convenience function that assembles all
//!   context from a [`TranslationRequest`](calxgloss_types::TranslationRequest)
//!   into a rendered prompt string.
//!
//! # Template Syntax
//!
//! Uses [Askama](https://docs.rs/askama) templating syntax (Jinja2-inspired):
//!
//! | Syntax | Meaning |
//! |---|---|
//! | `{{var}}` | Substitute variable as string |
//! | `{{#items}}...{{/items}}` | Iterate over JSON array (via `iter()`) |
//! | `{% if var %}...{% endif %}` | Conditional (truthy) |
//! | `{% unless var %}...{% endif %}` | Conditional (falsy, via `!var`) |

pub mod error;

pub use error::PromptError;

use askama::Template;
use calxgloss_types::TranslationRequest;
use serde_json::json;

// ============================================================
// Prompt templates (Askama structs)
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
    pub windows_apis: Vec<calxgloss_types::translation::WindowsApiCall>,

    /// Baseline test cases the translated Rust code must pass.
    pub test_cases: Vec<TestCaseFormatted>,

    /// Whether there are no Windows API calls (for conditional rendering).
    pub no_windows_apis: bool,
}

/// A formatted test case for template rendering.
#[derive(serde::Serialize)]
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
            address: 0, // Not provided in TranslationRequest
            disassembly: req.disassembly.clone(),
            decompiler_output: req.decompiler_output.clone(),
            windows_apis: req.windows_apis.clone(),
            test_cases,
            no_windows_apis: req.windows_apis.is_empty(),
        }
    }
}

// ============================================================
// Convenience functions
// ============================================================

/// Build and render a translation prompt from a [`TranslationRequest`].
///
/// This is the main convenience function for the translation pipeline.
/// It extracts all relevant fields from the request and renders the
/// `"translate"` template.
pub fn build_translate_prompt(req: &TranslationRequest) -> Result<String, PromptError> {
    let template = TranslateTemplate::from_request(req);
    let rendered = template
        .render()
        .map_err(|e| PromptError::Render(e.to_string()))?;
    if rendered.trim().is_empty() {
        return Err(PromptError::EmptyPrompt);
    }
    Ok(rendered)
}

// ============================================================
// Fix template — for retrying after verification failure
// ============================================================

/// Template for "fix the compilation errors" or "fix the failing tests" prompts.
///
/// Rendered via Askama from the embedded `templates/fix.j2` file.
#[derive(Template)]
#[template(path = "fix.j2")]
pub struct FixTemplate {
    /// The function name being fixed.
    pub function_name: String,

    /// The DLL containing the function.
    pub dll_name: String,

    /// The previously generated (failing) Rust code.
    pub original_rust_code: String,

    /// A description of what went wrong during verification.
    pub failure_description: String,
}

impl FixTemplate {
    /// Create a new fix template.
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
        }
    }
}

// ============================================================
// Escalate template — for retrying with additional Ghidra context
// ============================================================

/// Template for "add more context and retry" prompts.
///
/// Used when previous attempts failed with compile_fix or test_fix strategies.
/// Injects call graph neighbors, neighboring functions, data structures, and type info.
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

/// Build an escalated prompt that injects additional Ghidra context.
pub fn build_escalate_prompt(
    function_name: String,
    dll_name: String,
    original_rust_code: String,
    failure_description: String,
    call_graph_neighbors: Vec<CallGraphNeighbor>,
    neighboring_functions: Vec<NeighborFunction>,
    data_structures: Vec<StructuredData>,
    type_info: Vec<TypeInfo>,
) -> Result<String, PromptError> {
    let template = EscalateTemplate {
        function_name,
        dll_name,
        original_rust_code,
        failure_description,
        call_graph_neighbors,
        neighboring_functions,
        data_structures,
        type_info,
    };
    let rendered = template
        .render()
        .map_err(|e| PromptError::Render(e.to_string()))?;
    if rendered.trim().is_empty() {
        return Err(PromptError::EmptyPrompt);
    }
    Ok(rendered)
}

/// Build an edge-case prompt focused on boundary value handling.
pub fn build_edge_case_prompt(
    function_name: String,
    dll_name: String,
    original_rust_code: String,
    failed_tests: Vec<EdgeCaseTest>,
    boundary_values: Vec<BoundaryValue>,
) -> Result<String, PromptError> {
    let template = EdgeCaseTemplate {
        function_name,
        dll_name,
        original_rust_code,
        failed_tests,
        boundary_values,
    };
    let rendered = template
        .render()
        .map_err(|e| PromptError::Render(e.to_string()))?;
    if rendered.trim().is_empty() {
        return Err(PromptError::EmptyPrompt);
    }
    Ok(rendered)
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use calxgloss_types::{ApiCategory, TestCase};
    use serde_json::json;

    fn sample_request() -> TranslationRequest {
        TranslationRequest {
            dll: "game_logic.dll".to_string(),
            function: "DrawSprite".to_string(),
            disassembly: "mov eax, [esp+4]\nadd eax, ebx\nret".to_string(),
            decompiler_output: "int DrawSprite(int x, int y) { return x + y; }".to_string(),
            windows_apis: vec![
                calxgloss_types::translation::WindowsApiCall {
                    name: "GetTickCount".to_string(),
                    category: ApiCategory::Win32Core,
                    pal_mapping: "std::time::Instant::now()".to_string(),
                },
                calxgloss_types::translation::WindowsApiCall {
                    name: "CreateFileA".to_string(),
                    category: ApiCategory::Win32Core,
                    pal_mapping: "std::fs::File::open".to_string(),
                },
            ],
            baseline_tests: vec![
                TestCase {
                    inputs: json!({"x": 10, "y": 20}),
                    expected_return: json!(30),
                    expected_side_effects: vec![],
                },
                TestCase {
                    inputs: json!({"x": 0, "y": 0}),
                    expected_return: json!(0),
                    expected_side_effects: vec![],
                },
            ],
        }
    }

    #[test]
    fn test_build_translate_variables() {
        let req = sample_request();
        let template = TranslateTemplate::from_request(&req);

        assert_eq!(template.function_name, "DrawSprite");
        assert_eq!(template.dll_name, "game_logic.dll");
        assert!(!template.no_windows_apis);
        assert_eq!(template.windows_apis.len(), 2);
        assert_eq!(template.test_cases.len(), 2);
    }

    #[test]
    fn test_build_translate_prompt_basic() {
        let req = sample_request();
        let prompt = build_translate_prompt(&req).unwrap();

        // Check that key sections are present
        assert!(prompt.contains("DrawSprite"));
        assert!(prompt.contains("game_logic.dll"));
        assert!(prompt.contains("GetTickCount"));
        assert!(prompt.contains("std::time::Instant::now()"));
        assert!(prompt.contains("CreateFileA"));
        assert!(prompt.contains("std::fs::File::open"));
        assert!(prompt.contains("DISASSEMBLY"));
        assert!(prompt.contains("DECOMPILER OUTPUT"));
        assert!(prompt.contains("WINDOWS API CALLS IDENTIFIED"));
        assert!(prompt.contains("BASELINE TESTS"));
        assert!(prompt.contains("TRANSLATION REQUIREMENTS"));
    }

    #[test]
    fn test_prompt_with_no_apis() {
        let mut req = sample_request();
        req.windows_apis = vec![];
        let prompt = build_translate_prompt(&req).unwrap();
        assert!(prompt.contains("No Windows API calls were identified"));
    }

    #[test]
    fn test_prompt_with_no_tests() {
        let mut req = sample_request();
        req.baseline_tests = vec![];
        let template = TranslateTemplate::from_request(&req);
        assert_eq!(template.test_cases.len(), 0);
    }

    #[test]
    fn test_escalate_prompt_basic() {
        let prompt = build_escalate_prompt(
            "DrawSprite".to_string(),
            "game_logic.dll".to_string(),
            "fn draw_sprite(x: i32) -> i32 { x }".to_string(),
            "Tests failed: boundary case x=0 produced wrong result".to_string(),
            Vec::new(), // empty neighbors — should render "No call graph neighbors"
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
        .unwrap();

        assert!(prompt.contains("DrawSprite"));
        assert!(prompt.contains("game_logic.dll"));
        assert!(prompt.contains("No call graph neighbors identified"));
        assert!(prompt.contains("No neighboring function context available"));
        assert!(prompt.contains("No data structure context available"));
        assert!(prompt.contains("No additional type information available"));
    }

    #[test]
    fn test_escalate_prompt_with_neighbors() {
        let neighbors = vec![CallGraphNeighbor {
            name: "helper_compute".to_string(),
            address: 0x1000,
            signature: "int __stdcall helper_compute(int x, int y)".to_string(),
            role: "callee".to_string(),
        }];

        let prompt = build_escalate_prompt(
            "DrawSprite".to_string(),
            "game_logic.dll".to_string(),
            "fn draw_sprite(x: i32) -> i32 { x }".to_string(),
            "Wrong result".to_string(),
            neighbors,
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
        .unwrap();

        assert!(prompt.contains("helper_compute"));
        assert!(prompt.contains("int __stdcall helper_compute(int x, int y)"));
    }

    #[test]
    fn test_edge_case_prompt_basic() {
        let failed_tests = vec![EdgeCaseTest {
            index: 1,
            inputs: json!({"x": 0}),
            expected: json!(0),
            actual: json!(1),
            error: "Expected 0, got 1".to_string(),
            disassembly_hints: "cmp eax, 0\nje .zero_branch".to_string(),
        }];

        let prompt = build_edge_case_prompt(
            "DrawSprite".to_string(),
            "game_logic.dll".to_string(),
            "fn draw_sprite(x: i32) -> i32 { x + 1 }".to_string(),
            failed_tests,
            Vec::new(),
        )
        .unwrap();

        assert!(prompt.contains("DrawSprite"));
        assert!(prompt.contains("x + 1"));
        assert!(prompt.contains("Expected 0, got 1"));
        assert!(prompt.contains("cmp eax, 0"));
    }

    #[test]
    fn test_edge_case_prompt_with_boundary_values() {
        let bvs = vec![BoundaryValue {
            description: "Zero check for input index".to_string(),
            condition: "x <= 0".to_string(),
            branch_address: 0x2000,
        }];

        let prompt = build_edge_case_prompt(
            "DrawSprite".to_string(),
            "game_logic.dll".to_string(),
            "fn draw_sprite(x: i32) -> i32 { x }".to_string(),
            Vec::new(),
            bvs,
        )
        .unwrap();

        assert!(prompt.contains("Zero check for input index"));
        assert!(prompt.contains("x <= 0"));
        assert!(prompt.contains("0x2000"));
    }
}
