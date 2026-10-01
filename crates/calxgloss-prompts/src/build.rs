//! Prompt builders — functions that construct rendered prompts from data structs.
//!
//! This module provides all the `build_*` functions that the translation
//! pipeline calls to produce ready-to-send prompts:
//!
//! - [`build_translate_prompt`] — standard translation prompt
//! - [`build_escalate_prompt`] — escalate with additional context
//! - [`build_edge_case_prompt`] — fix boundary-value failures
//! - [`build_stub_prompt`] — Tier 0 stub generation
//! - [`build_disassembly_prompt`] — Tier 1 disassembly-only prompt
//! - [`build_with_tests_prompt`] — Tier 2 full context with tests
//! - [`build_module_context_prompt`] — Tier 3 module context with neighbors
//! - [`build_complexity_prompt`] — complexity-aware prompt selection
//! - [`extract_signature_from_decompiler`] — extract function signature

use askama::Template;
use calxgloss_types::{FunctionComplexity, TranslationRequest};

use super::context::{
    ComplexityPromptData, DisassemblyPromptData, ModuleContextPromptData, StubPromptData,
    WithTestsPromptData,
};
use super::error::PromptError;
use super::templates::{
    BoundaryValue, CallGraphNeighbor, EdgeCaseTemplate, EdgeCaseTest, EscalateTemplate,
    MinimalTemplate, ModuleContextTemplate, RichTemplate, StubTemplate, TranslateTemplate,
    WithTestsTemplate,
};

// ============================================================
// Standard translation prompt builder
// ============================================================

/// Builds a standard translation prompt from a [`TranslationRequest`].
///
/// This is the most common path — it renders the [`TranslateTemplate`]
/// with the request's disassembly, decompiler output, Windows API calls,
/// and baseline tests.
///
/// When API-aware augmentation is enabled (default), the prompt includes
/// full mapping table rows for each API category the function touches.
pub fn build_translate_prompt(req: &TranslationRequest) -> Result<String, PromptError> {
    let mut template = TranslateTemplate::from_request(req);

    // API-aware augmentation: inject full mapping table rows for each
    // API category the function touches.
    let categories: Vec<calxgloss_types::ApiCategory> = req
        .windows_apis
        .iter()
        .map(|api| api.category.clone())
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();
    let api_mappings = calxgloss_pal::ApiMappings::default();
    let api_category_mappings = api_mappings.for_categories(&categories);
    if !api_category_mappings.is_empty() {
        template.api_category_mappings = api_category_mappings;
    }

    template
        .render()
        .map_err(|e| PromptError::Render(e.to_string()))
}

// ============================================================
// Escalation prompt builder
// ============================================================

/// Builds an escalation prompt with additional Ghidra context.
///
/// Used when previous attempts failed with compile_fix or test_fix strategies.
/// Adds call graph neighbors, neighboring functions, data structures,
/// and type information to help the LLM understand the broader context.
#[allow(clippy::too_many_arguments)]
pub fn build_escalate_prompt(
    function_name: String,
    dll_name: String,
    original_rust_code: String,
    failure_description: String,
    call_graph_neighbors: Vec<CallGraphNeighbor>,
    neighboring_functions: Vec<super::templates::NeighborFunction>,
    data_structures: Vec<super::templates::StructuredData>,
    type_info: Vec<super::templates::TypeInfo>,
    failure_history: Vec<calxgloss_types::FailureHint>,
) -> Result<String, PromptError> {
    let template = EscalateTemplate::with_history(
        function_name,
        dll_name,
        original_rust_code,
        failure_description,
        call_graph_neighbors,
        neighboring_functions,
        data_structures,
        type_info,
        failure_history,
    );

    template
        .render()
        .map_err(|e| PromptError::Render(e.to_string()))
}

// ============================================================
// Edge case prompt builder
// ============================================================

/// Builds an edge case fix prompt for boundary-value test failures.
///
/// Includes failing test details, disassembly hints, and boundary
/// value analysis to help the LLM fix off-by-one and boundary conditions.
#[allow(clippy::too_many_arguments)]
pub fn build_edge_case_prompt(
    function_name: String,
    dll_name: String,
    original_rust_code: String,
    failed_tests: Vec<EdgeCaseTest>,
    boundary_values: Vec<BoundaryValue>,
    failure_history: Vec<calxgloss_types::FailureHint>,
) -> Result<String, PromptError> {
    let template = EdgeCaseTemplate::with_history(
        function_name,
        dll_name,
        original_rust_code,
        failed_tests,
        boundary_values,
        failure_history,
    );

    template
        .render()
        .map_err(|e| PromptError::Render(e.to_string()))
}

// ============================================================
// Stub prompt builder (Tier 0)
// ============================================================

/// Builds a Tier 0 stub prompt for function stub generation.
///
/// Contains only the function name, signature, and call graph neighbors.
/// Used when the function's disassembly is too large or irrelevant
/// for the initial stub generation phase.
pub fn build_stub_prompt(data: &StubPromptData) -> Result<String, PromptError> {
    let template = StubTemplate::from_data(data);

    template
        .render()
        .map_err(|e| PromptError::Render(e.to_string()))
}

// ============================================================
// Disassembly prompt builder (Tier 1)
// ============================================================

/// Builds a Tier 1 disassembly + decompiler prompt.
///
/// Contains raw disassembly and pseudo-C output, but no baseline tests.
/// Used for functions where test generation is not feasible.
pub fn build_disassembly_prompt(data: &DisassemblyPromptData) -> Result<String, PromptError> {
    let req = TranslationRequest {
        dll: data.dll_name.clone(),
        function: data.function_name.clone(),
        disassembly: data.disassembly.clone(),
        decompiler_output: data.decompiler_output.clone(),
        windows_apis: data.windows_apis.clone(),
        baseline_tests: data.test_cases.clone(),
    };

    let mut template = TranslateTemplate::from_request(&req);
    template.no_windows_apis = data.no_windows_apis;

    template
        .render()
        .map_err(|e| PromptError::Render(e.to_string()))
}

// ============================================================
// With-tests prompt builder (Tier 2)
// ============================================================

/// Builds a Tier 2 full context prompt with baseline test results.
///
/// Contains full disassembly, decompiler output, tagged Windows API calls,
/// call graph neighbors, and baseline test results with pass/fail status.
pub fn build_with_tests_prompt(data: &WithTestsPromptData) -> Result<String, PromptError> {
    let template = WithTestsTemplate::from_data(data);

    template
        .render()
        .map_err(|e| PromptError::Render(e.to_string()))
}

// ============================================================
// Module context prompt builder (Tier 3)
// ============================================================

/// Builds a Tier 3 module context prompt with neighboring function code
/// and shared data structures.
///
/// Contains full disassembly, decompiler output, tagged Windows API calls,
/// call graph neighbors, baseline test results with pass/fail status, and
/// full context from neighboring functions (disassembly + decompiler output)
/// plus any data structures referenced near the target function.
///
/// This tier is used for complex functions whose translation requires
/// understanding shared calling conventions, data layouts, or helper
/// patterns from adjacent functions in the same module.
pub fn build_module_context_prompt(data: &ModuleContextPromptData) -> Result<String, PromptError> {
    let template = ModuleContextTemplate::from_data(data);

    template
        .render()
        .map_err(|e| PromptError::Render(e.to_string()))
}

// ============================================================
// Complexity-aware prompt builder (Tier 3+)
// ============================================================

/// Builds a complexity-aware prompt, selecting the appropriate template
/// based on the function's [`FunctionComplexity`].
///
/// Complexity tiers and their templates:
///
/// | Complexity | Template | Context |
/// |------------|----------|---------|
/// | `Minimal` (≤30 instructions) | `TranslateTemplate` | Disassembly + decompiler + API mappings + tests |
/// | `Standard` (31–100 instructions) | `TranslateTemplate` | Disassembly + decompiler + API mappings + tests |
/// | `Rich` (101–300 instructions) | `RichTemplate` | Standard + API category context + advanced guidelines |
/// | `Detailed` (>300 instructions) | `DetailedTemplate` | Rich + call graph + neighbors + data structures + type info |
pub fn build_complexity_prompt(
    complexity: &FunctionComplexity,
    data: &ComplexityPromptData,
) -> Result<String, PromptError> {
    // API-aware prompt augmentation — populate
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
            let mut template = super::templates::DetailedTemplate::from_request(&req);
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
// Signature extraction helpers
// ============================================================

/// Extracts the function signature from Ghidra's decompiler output.
///
/// The decompiler's first line is a real signature carrying real parameter
/// types, so it is preferred. Returns an empty string if the output is
/// empty or contains no recognizable signature pattern.
///
/// Recognized patterns:
/// - `int __stdcall FuncName(int x, int y)` — standard signature
/// - `longlong FUN_18008ed50(longlong param_1,int param_2)` — Ghidra-generated names
pub fn extract_signature_from_decompiler(decompiler_output: &str) -> &str {
    let trimmed = decompiler_output.trim();
    if trimmed.is_empty() {
        return "";
    }

    // Get the first line — this is typically the signature
    let first_line = trimmed.lines().next().unwrap_or("");

    // If the first line contains "(", it's likely a signature
    if first_line.contains('(') && first_line.contains(')') {
        // Strip trailing " {" or "{" from the signature line
        return first_line
            .trim_end()
            .strip_suffix('{')
            .unwrap_or(first_line)
            .trim_end();
    }

    // Fallback: return empty
    ""
}
