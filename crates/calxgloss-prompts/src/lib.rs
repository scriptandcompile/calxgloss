//! Prompt templates and rendering for the Calxgloss LLM translation pipeline.
//!
//! This crate provides a lightweight template engine for building prompts
//! sent to the local LLM. Templates are embedded at compile time via
//! `include_str!` and rendered with structured data from the translation
//! pipeline.
//!
//! # Architecture
//!
//! - [`TranslateTemplate`] — renders `translate.j2` (standard prompt)
//! - [`MinimalTemplate`] — renders `minimal_translate.j2` (simple functions)
//! - [`RichTemplate`] — renders `rich_translate.j2` (complex functions)
//! - [`DetailedTemplate`] — renders `detailed_translate.j2` (very complex functions)
//! - [`build_translate_prompt`] — builds a standard translation prompt
//! - [`build_complexity_prompt`] — Phase 2, step 2.1: selects template by complexity
//! - [`ComplexityPromptData::api_categories`] — Phase 2, step 2.2: extracts API categories
//!
//! # Phase 2, Step 2.2 — API-Aware Prompt Augmentation
//!
//! When a function calls Windows APIs, the prompt builder automatically
//! injects the full mapping table rows for each API category the function touches.
//! This gives the LLM detailed context about how to translate specific APIs
//! (e.g., every Win32 Core mapping, every DirectX mapping, every GDI mapping)
//! rather than just the one-liner `api.name → api.pal_mapping` shown in the
//! "WINDOWS API CALLS IDENTIFIED" section.
//!
//! The augmentation is applied to all complexity tiers:
//! - **Minimal** functions (≤30 instructions) get the reference tables
//! - **Standard** functions (31–100) get the reference tables
//! - **Rich** functions (101–300) get the reference tables + advanced guidelines
//! - **Detailed** functions (>300) get the reference tables + full Ghidra context
//!
//! # Template Syntax
//!
//! Uses [Askama](https://docs.rs/askama) templating syntax (Jinja2-inspired):
//!
//! | Syntax | Meaning |
//! |---|---|
//! | `{{var}}` | Substitute variable as string |
//! | `{% if var %}...{% endif %}` | Conditional (truthy) |
//! | `{% for item in list %}...{% endfor %}` | Loop |

pub mod error;

pub use error::PromptError;

use askama::Template;
use calxgloss_types::{ApiCategoryMapping, FunctionComplexity, TranslationRequest};
use serde_json::json;

// ============================================================
// Prompt templates (Askama structs)
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
    pub windows_apis: Vec<calxgloss_types::translation::WindowsApiCall>,

    /// Baseline test cases the translated Rust code must pass.
    pub test_cases: Vec<TestCaseFormatted>,

    /// Whether there are no Windows API calls (for conditional rendering).
    pub no_windows_apis: bool,

    /// API-category-specific mapping rows providing detailed context
    /// for the APIs used in this function (Phase 2, step 2.2).
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

/// Template for function translation prompts.
///
/// Rendered via Askama from the embedded `templates/translate.j2` file.
/// When API-aware augmentation is enabled, this includes the full mapping
/// table rows for the API categories the function touches.
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

    /// API-category-specific mapping rows providing detailed context
    /// for the APIs used in this function (Phase 2, step 2.2).
    pub api_category_mappings: Vec<calxgloss_types::ApiCategoryMapping>,
}

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
            api_category_mappings: Vec::new(),
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
// Rich template — for functions with complex control flow (101-300 instructions)
// ============================================================

/// Template for "rich context" translation prompts.
///
/// Used when a function has 101–300 instructions, multiple API categories,
/// or high branch density. Adds detailed API category mapping rows and
/// advanced translation guidelines to the standard prompt.
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
    pub windows_apis: Vec<calxgloss_types::translation::WindowsApiCall>,

    /// Whether there are no Windows API calls (for conditional rendering).
    pub no_windows_apis: bool,

    /// Baseline test cases the translated Rust code must pass.
    pub test_cases: Vec<TestCaseFormatted>,

    /// API-category-specific mapping rows providing detailed context
    /// for the APIs used in this function.
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
/// Adds all the context from `RichTemplate` plus call graph neighbors,
/// neighboring function disassembly, data structures, and type information.
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
    pub windows_apis: Vec<calxgloss_types::translation::WindowsApiCall>,

    /// Whether there are no Windows API calls (for conditional rendering).
    pub no_windows_apis: bool,

    /// Baseline test cases the translated Rust code must pass.
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
// Complexity-aware prompt builder (Phase 2, step 2.1)
// ============================================================

/// Context data needed to build a complexity-aware prompt.
///
/// This aggregates all the pieces the translation pipeline collects
/// during function analysis, ready to be rendered into whichever
/// template matches the function's complexity level.
#[derive(Debug)]
pub struct ComplexityPromptData {
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
    pub windows_apis: Vec<calxgloss_types::translation::WindowsApiCall>,
    /// Baseline test cases.
    pub test_cases: Vec<TestCaseFormatted>,
    /// API-category-specific mapping rows.
    pub api_category_mappings: Vec<ApiCategoryMapping>,
    /// Call graph neighbors (for detailed template).
    pub call_graph_neighbors: Vec<CallGraphNeighbor>,
    /// Neighboring function context (for detailed template).
    pub neighboring_functions: Vec<NeighborFunction>,
    /// Data structures (for detailed template).
    pub data_structures: Vec<StructuredData>,
    /// Type information (for detailed template).
    pub type_info: Vec<TypeInfo>,
}

impl ComplexityPromptData {
    /// Build [`ComplexityPromptData`] from a [`TranslationRequest`].
    ///
    /// This is a convenience constructor that extracts all data from
    /// a request without the extra analysis fields (call graph, data
    /// structures, type info). For full analysis data, construct the
    /// struct directly.
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

        Self {
            function_name: req.function.clone(),
            dll_name: req.dll.clone(),
            address: 0,
            disassembly: req.disassembly.clone(),
            decompiler_output: req.decompiler_output.clone(),
            windows_apis: req.windows_apis.clone(),
            test_cases,
            api_category_mappings: Vec::new(),
            call_graph_neighbors: Vec::new(),
            neighboring_functions: Vec::new(),
            data_structures: Vec::new(),
            type_info: Vec::new(),
        }
    }

    /// Returns true if this data has no Windows API calls.
    pub fn has_no_windows_apis(&self) -> bool {
        self.windows_apis.is_empty()
    }

    /// Returns the set of unique API categories used by this function's
    /// tagged Windows API calls.
    pub fn api_categories(&self) -> Vec<calxgloss_types::ApiCategory> {
        let mut seen = std::collections::HashSet::new();
        self.windows_apis
            .iter()
            .filter_map(|api| {
                if seen.insert(api.category.clone()) {
                    Some(api.category.clone())
                } else {
                    None
                }
            })
            .collect()
    }
}

/// Build and render a translation prompt, selecting the template
/// based on the function's complexity level.
///
/// This is the main entry point for complexity-based prompt selection.
/// It creates the appropriate template struct, renders it, and returns
/// the rendered prompt string.
///
/// # Arguments
///
/// * `complexity` — The detected complexity level of the function.
/// * `data` — All context data needed to render the selected template.
///
/// # Returns
///
/// The rendered prompt string, or an error if rendering fails.
///
/// # Complexity-based selection
///
/// | Complexity | Template | Context |
/// |------------|----------|---------|
/// | `Minimal` (≤30 instructions) | `minimal_translate.j2` | Disassembly + decompiler only |
/// | `Standard` (31–100 instructions) | `translate.j2` | Disassembly + decompiler + API mappings + tests |
/// | `Rich` (101–300 instructions) | `rich_translate.j2` | Standard + API category context + advanced guidelines |
/// | `Detailed` (>300 instructions) | `detailed_translate.j2` | Rich + call graph + neighbors + data structures + type info |
pub fn build_complexity_prompt(
    complexity: &FunctionComplexity,
    data: &ComplexityPromptData,
) -> Result<String, PromptError> {
    // Phase 2, step 2.2: API-aware prompt augmentation — populate
    // api_category_mappings from the function's tagged Windows APIs.
    let categories = data.api_categories();
    let api_mappings = calxgloss_pal::ApiMappings::default();
    let api_category_mappings = api_mappings.for_categories(&categories);

    let rendered = match complexity {
        FunctionComplexity::Minimal => {
            let mut template = MinimalTemplate {
                function_name: data.function_name.clone(),
                dll_name: data.dll_name.clone(),
                address: data.address,
                disassembly: data.disassembly.clone(),
                decompiler_output: data.decompiler_output.clone(),
                windows_apis: data.windows_apis.clone(),
                test_cases: data.test_cases.clone(),
                no_windows_apis: data.windows_apis.is_empty(),
                api_category_mappings: Vec::new(),
            };
            // API-aware augmentation: inject full mapping table rows
            if !api_category_mappings.is_empty() {
                template.api_category_mappings = api_category_mappings;
            }
            template
                .render()
                .map_err(|e| PromptError::Render(e.to_string()))?
        }
        FunctionComplexity::Standard => {
            let req = build_std_request(data);
            let mut template = TranslateTemplate::from_request(&req);
            // API-aware augmentation: inject full mapping table rows
            if !api_category_mappings.is_empty() {
                template.api_category_mappings = api_category_mappings;
            }
            template
                .render()
                .map_err(|e| PromptError::Render(e.to_string()))?
        }
        FunctionComplexity::Rich => {
            let req = build_std_request(data);
            let mut template = RichTemplate::from_request(&req);
            // API-aware augmentation: inject full mapping table rows
            if !api_category_mappings.is_empty() {
                template.api_category_mappings = api_category_mappings;
            }
            template
                .render()
                .map_err(|e| PromptError::Render(e.to_string()))?
        }
        FunctionComplexity::Detailed => {
            let req = build_std_request(data);
            let mut template = DetailedTemplate::from_request(&req);
            // API-aware augmentation: inject full mapping table rows
            if !api_category_mappings.is_empty() {
                template.api_category_mappings = api_category_mappings;
            }
            template
                .render()
                .map_err(|e| PromptError::Render(e.to_string()))?
        }
    };

    if rendered.trim().is_empty() {
        return Err(PromptError::EmptyPrompt);
    }
    Ok(rendered)
}

/// Helper to build a minimal TranslationRequest from ComplexityPromptData
/// so we can reuse the existing template constructors.
fn build_std_request(data: &ComplexityPromptData) -> TranslationRequest {
    use calxgloss_types::TestCase;
    let baseline_tests: Vec<TestCase> = data
        .test_cases
        .iter()
        .map(|tc| TestCase {
            inputs: tc.inputs.clone(),
            expected_return: tc.expected_return.clone(),
            expected_side_effects: serde_json::from_value(tc.side_effects.clone())
                .unwrap_or_default(),
        })
        .collect();

    TranslationRequest {
        dll: data.dll_name.clone(),
        function: data.function_name.clone(),
        disassembly: data.disassembly.clone(),
        decompiler_output: data.decompiler_output.clone(),
        windows_apis: data.windows_apis.clone(),
        baseline_tests,
    }
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

    #[test]
    fn test_complexity_prompt_selects_minimal_template() {
        let data = ComplexityPromptData {
            function_name: "SimpleFunc".to_string(),
            dll_name: "test.dll".to_string(),
            address: 0x1000,
            disassembly: "mov eax, 0\nret".to_string(),
            decompiler_output: "int SimpleFunc() { return 0; }".to_string(),
            windows_apis: Vec::new(),
            test_cases: Vec::new(),
            api_category_mappings: Vec::new(),
            call_graph_neighbors: Vec::new(),
            neighboring_functions: Vec::new(),
            data_structures: Vec::new(),
            type_info: Vec::new(),
        };

        let prompt = build_complexity_prompt(&FunctionComplexity::Minimal, &data).unwrap();
        assert!(prompt.contains("SimpleFunc"));
        assert!(prompt.contains("test.dll"));
        assert!(prompt.contains("DISASSEMBLY"));
    }

    #[test]
    fn test_complexity_prompt_selects_standard_template() {
        let data = ComplexityPromptData {
            function_name: "StdFunc".to_string(),
            dll_name: "game.dll".to_string(),
            address: 0x2000,
            disassembly: "mov eax, [esp+4]\nadd eax, ebx\nret".to_string(),
            decompiler_output: "int StdFunc(int x, int y) { return x + y; }".to_string(),
            windows_apis: vec![calxgloss_types::translation::WindowsApiCall {
                name: "GetTickCount".to_string(),
                category: ApiCategory::Win32Core,
                pal_mapping: "std::time::Instant::now()".to_string(),
            }],
            test_cases: Vec::new(),
            api_category_mappings: Vec::new(),
            call_graph_neighbors: Vec::new(),
            neighboring_functions: Vec::new(),
            data_structures: Vec::new(),
            type_info: Vec::new(),
        };

        let prompt = build_complexity_prompt(&FunctionComplexity::Standard, &data).unwrap();
        assert!(prompt.contains("StdFunc"));
        assert!(prompt.contains("game.dll"));
        assert!(prompt.contains("WINDOWS API CALLS IDENTIFIED"));
    }

    // ============================================================
    // Phase 2, step 2.2 — API-aware prompt augmentation tests
    // ============================================================

    #[test]
    fn test_api_categories_extracted_from_windows_apis() {
        let data = ComplexityPromptData {
            function_name: "TestFunc".to_string(),
            dll_name: "test.dll".to_string(),
            address: 0x1000,
            disassembly: "mov eax, 0\nret".to_string(),
            decompiler_output: "int TestFunc() { return 0; }".to_string(),
            windows_apis: vec![
                calxgloss_types::translation::WindowsApiCall {
                    name: "CreateFileA".to_string(),
                    category: ApiCategory::Win32Core,
                    pal_mapping: "std::fs::File::open".to_string(),
                },
                calxgloss_types::translation::WindowsApiCall {
                    name: "Direct3DCreate9".to_string(),
                    category: ApiCategory::DirectX,
                    pal_mapping: "wgpu::Instance::new [PAL placeholder]".to_string(),
                },
            ],
            test_cases: Vec::new(),
            api_category_mappings: Vec::new(),
            call_graph_neighbors: Vec::new(),
            neighboring_functions: Vec::new(),
            data_structures: Vec::new(),
            type_info: Vec::new(),
        };

        let categories = data.api_categories();
        assert_eq!(categories.len(), 2);
        assert!(categories.contains(&ApiCategory::Win32Core));
        assert!(categories.contains(&ApiCategory::DirectX));
    }

    #[test]
    fn test_api_categories_deduplicates() {
        let data = ComplexityPromptData {
            function_name: "TestFunc".to_string(),
            dll_name: "test.dll".to_string(),
            address: 0x1000,
            disassembly: "mov eax, 0\nret".to_string(),
            decompiler_output: "int TestFunc() { return 0; }".to_string(),
            windows_apis: vec![
                calxgloss_types::translation::WindowsApiCall {
                    name: "CreateFileA".to_string(),
                    category: ApiCategory::Win32Core,
                    pal_mapping: "std::fs::File::open".to_string(),
                },
                calxgloss_types::translation::WindowsApiCall {
                    name: "ReadFile".to_string(),
                    category: ApiCategory::Win32Core,
                    pal_mapping: "std::fs::read".to_string(),
                },
            ],
            test_cases: Vec::new(),
            api_category_mappings: Vec::new(),
            call_graph_neighbors: Vec::new(),
            neighboring_functions: Vec::new(),
            data_structures: Vec::new(),
            type_info: Vec::new(),
        };

        let categories = data.api_categories();
        // Both APIs are Win32Core, so only one unique category
        assert_eq!(categories.len(), 1);
        assert_eq!(categories[0], ApiCategory::Win32Core);
    }

    #[test]
    fn test_api_categories_empty_when_no_apis() {
        let data = ComplexityPromptData {
            function_name: "TestFunc".to_string(),
            dll_name: "test.dll".to_string(),
            address: 0x1000,
            disassembly: "mov eax, 0\nret".to_string(),
            decompiler_output: "int TestFunc() { return 0; }".to_string(),
            windows_apis: Vec::new(),
            test_cases: Vec::new(),
            api_category_mappings: Vec::new(),
            call_graph_neighbors: Vec::new(),
            neighboring_functions: Vec::new(),
            data_structures: Vec::new(),
            type_info: Vec::new(),
        };

        let categories = data.api_categories();
        assert!(categories.is_empty());
    }

    #[test]
    fn test_standard_prompt_includes_api_mapping_reference() {
        let data = ComplexityPromptData {
            function_name: "TestFunc".to_string(),
            dll_name: "game.dll".to_string(),
            address: 0x2000,
            disassembly: "mov eax, [esp+4]\nret".to_string(),
            decompiler_output: "int TestFunc(int x) { return x; }".to_string(),
            windows_apis: vec![calxgloss_types::translation::WindowsApiCall {
                name: "CreateFileA".to_string(),
                category: ApiCategory::Win32Core,
                pal_mapping: "std::fs::File::open".to_string(),
            }],
            test_cases: Vec::new(),
            api_category_mappings: Vec::new(),
            call_graph_neighbors: Vec::new(),
            neighboring_functions: Vec::new(),
            data_structures: Vec::new(),
            type_info: Vec::new(),
        };

        let prompt = build_complexity_prompt(&FunctionComplexity::Standard, &data).unwrap();

        // The API mapping reference section should be present
        assert!(prompt.contains("API MAPPING REFERENCE"));
        // Win32Core category table should be present
        assert!(prompt.contains("Win32Core Category"));
        // Should contain a mapping row
        assert!(prompt.contains("CreateFileA"));
        assert!(prompt.contains("std::fs::File::open"));
    }

    #[test]
    fn test_minimal_prompt_includes_api_mapping_reference() {
        let data = ComplexityPromptData {
            function_name: "SimpleFunc".to_string(),
            dll_name: "test.dll".to_string(),
            address: 0x1000,
            disassembly: "mov eax, 0\nret".to_string(),
            decompiler_output: "int SimpleFunc() { return 0; }".to_string(),
            windows_apis: vec![calxgloss_types::translation::WindowsApiCall {
                name: "BitBlt".to_string(),
                category: ApiCategory::Gdi,
                pal_mapping: "tiny_skia::Pixmap::blit_rect [PAL placeholder]".to_string(),
            }],
            test_cases: Vec::new(),
            api_category_mappings: Vec::new(),
            call_graph_neighbors: Vec::new(),
            neighboring_functions: Vec::new(),
            data_structures: Vec::new(),
            type_info: Vec::new(),
        };

        let prompt = build_complexity_prompt(&FunctionComplexity::Minimal, &data).unwrap();

        // The API mapping reference section should be present even for minimal prompts
        assert!(prompt.contains("API MAPPING REFERENCE"));
        assert!(prompt.contains("GDI Category"));
        assert!(prompt.contains("BitBlt"));
        assert!(prompt.contains("tiny_skia"));
    }

    #[test]
    fn test_rich_prompt_includes_api_mapping_reference() {
        let data = ComplexityPromptData {
            function_name: "ComplexFunc".to_string(),
            dll_name: "render.dll".to_string(),
            address: 0x3000,
            disassembly: (0..200)
                .map(|i| format!("0x{:08X}: nop", 0x3000 + i * 4))
                .collect::<Vec<_>>()
                .join("\n"),
            decompiler_output: "int ComplexFunc() { return 0; }".to_string(),
            windows_apis: vec![
                calxgloss_types::translation::WindowsApiCall {
                    name: "Direct3DCreate9".to_string(),
                    category: ApiCategory::DirectX,
                    pal_mapping: "wgpu::Instance::new [PAL placeholder]".to_string(),
                },
                calxgloss_types::translation::WindowsApiCall {
                    name: "GetDC".to_string(),
                    category: ApiCategory::Gdi,
                    pal_mapping: "tiny_skia::Pixmap::new [PAL placeholder]".to_string(),
                },
            ],
            test_cases: Vec::new(),
            api_category_mappings: Vec::new(),
            call_graph_neighbors: Vec::new(),
            neighboring_functions: Vec::new(),
            data_structures: Vec::new(),
            type_info: Vec::new(),
        };

        let prompt = build_complexity_prompt(&FunctionComplexity::Rich, &data).unwrap();

        assert!(prompt.contains("API MAPPING REFERENCE"));
        assert!(prompt.contains("DirectX Category"));
        assert!(prompt.contains("GDI Category"));
        assert!(prompt.contains("Direct3DCreate9"));
        assert!(prompt.contains("wgpu::Instance::new"));
        assert!(prompt.contains("GetDC"));
        assert!(prompt.contains("tiny_skia"));
    }

    #[test]
    fn test_prompt_has_no_api_mapping_reference_when_no_apis() {
        let data = ComplexityPromptData {
            function_name: "NoApiFunc".to_string(),
            dll_name: "test.dll".to_string(),
            address: 0x1000,
            disassembly: "mov eax, 0\nret".to_string(),
            decompiler_output: "int NoApiFunc() { return 0; }".to_string(),
            windows_apis: Vec::new(),
            test_cases: Vec::new(),
            api_category_mappings: Vec::new(),
            call_graph_neighbors: Vec::new(),
            neighboring_functions: Vec::new(),
            data_structures: Vec::new(),
            type_info: Vec::new(),
        };

        let prompt = build_complexity_prompt(&FunctionComplexity::Standard, &data).unwrap();

        // When there are no Windows APIs, the section should be absent
        assert!(!prompt.contains("Win32Core Category"));
        assert!(!prompt.contains("DirectX Category"));
    }
}
