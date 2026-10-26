//! Prompt builders — functions that construct rendered prompts from data structs.
//!
//! This module provides all the `build_*` functions that the translation
//! pipeline calls to produce ready-to-send prompts:
//!
//! - [`build_translate_prompt`] — standard translation prompt
//! - [`build_escalate_prompt`] — escalate with additional context
//! - [`build_edge_case_prompt`] — fix boundary-value failures
//! - [`build_signature_prompt`] — Tier 0 signature-prompt generation
//! - [`build_disassembly_prompt`] — Tier 1 disassembly-only prompt
//! - [`build_with_tests_prompt`] — Tier 2 full context with tests
//! - [`build_module_context_prompt`] — Tier 3 module context with neighbors
//! - [`build_complexity_prompt`] — complexity-aware prompt selection
//! - [`extract_signature_from_decompiler`] — extract function signature

use askama::Template;
use calxgloss_types::{FunctionComplexity, TranslationRequest};

use super::context::{
    ComplexityPromptData, DisassemblyPromptData, SignaturePromptData, WithTestsPromptData,
};
use super::error::PromptError;
use super::templates::{
    BoundaryValue, EdgeCaseTemplate, EdgeCaseTest, EscalateTemplate, EvidenceBundle,
    FullModuleTemplate, MinimalTemplate, ModuleContextTemplate, PalTraitDef, RichTemplate,
    ShimCode, SignatureTemplate, TranslateTemplate, WithTestsTemplate,
};

// ============================================================
// Render helper
// ============================================================

/// Renders a template and normalizes the blank lines its block tags leave
/// behind, so sections always sit exactly one blank line apart and an
/// omitted conditional section leaves no trace.
fn render_prompt<T: Template>(template: &T) -> Result<String, PromptError> {
    let rendered = template
        .render()
        .map_err(|e| PromptError::Render(e.to_string()))?;
    Ok(collapse_blank_lines(&rendered))
}

/// Collapses runs of blank lines to a single blank line and trims the ends.
fn collapse_blank_lines(rendered: &str) -> String {
    let mut out = String::with_capacity(rendered.len());
    let mut blanks = 0usize;
    for line in rendered.lines() {
        if line.trim().is_empty() {
            blanks += 1;
            continue;
        }
        if !out.is_empty() {
            out.push('\n');
            if blanks > 0 {
                out.push('\n');
            }
        }
        out.push_str(line);
        blanks = 0;
    }
    out
}

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
///
/// TODO: Add `call_graph_context` enrichment when a call graph is available.
/// Use `WithTestsPromptData::from_request_with_call_graph` or construct
/// `FunctionContext` directly via `ContextEnricher::enrich()`.
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

    render_prompt(&template)
}

// ============================================================
// Escalation prompt builder
// ============================================================

/// Builds an escalation prompt with additional decompiler context.
///
/// Used when previous attempts failed with compile_fix or test_fix strategies.
/// The decompiler-derived finding lists ride in as an [`EvidenceBundle`];
/// the function identity and failure history stay as separate parameters.
pub fn build_escalate_prompt(
    function_name: String,
    dll_name: String,
    original_rust_code: String,
    failure_description: String,
    evidence: EvidenceBundle,
    failure_history: Vec<calxgloss_types::FailureHint>,
) -> Result<String, PromptError> {
    build_escalate_prompt_with_context(
        function_name,
        dll_name,
        original_rust_code,
        failure_description,
        evidence,
        failure_history,
    )
}

/// Builds an escalation prompt with additional decompiler context and enriched
/// call graph data.
///
/// Used when previous attempts failed with compile_fix or test_fix strategies.
/// The bundle carries call graph neighbors, neighboring functions, data
/// structures, type information, recognized algorithms, memory lifecycle
/// findings, concurrency findings, callback findings, control-flow findings,
/// calling-convention readings, global-state access records, string
/// context findings, library/API findings, constant/enum findings,
/// serialization findings, and enriched call graph context (caller/callee
/// details and leaf API suggestions) to help the LLM understand the
/// broader context.
pub fn build_escalate_prompt_with_context(
    function_name: String,
    dll_name: String,
    original_rust_code: String,
    failure_description: String,
    evidence: EvidenceBundle,
    failure_history: Vec<calxgloss_types::FailureHint>,
) -> Result<String, PromptError> {
    let template = EscalateTemplate::with_history(
        function_name,
        dll_name,
        original_rust_code,
        failure_description,
        evidence,
        failure_history,
    );

    render_prompt(&template)
}

// ============================================================
// Edge case prompt builder
// ============================================================

/// Builds an edge case fix prompt for boundary-value test failures.
///
/// Includes failing test details, disassembly hints, and boundary
/// value analysis to help the LLM fix off-by-one and boundary conditions.
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

    render_prompt(&template)
}

// ============================================================
// Signature prompt builder (Tier 0)
// ============================================================

/// Builds a Tier 0 signature prompt (name, signature, call graph neighbors).
///
/// Contains only the function name, signature, and call graph neighbors.
/// Used when the function's disassembly is too large or irrelevant
/// for the initial signature-only phase.
pub fn build_signature_prompt(data: &SignaturePromptData) -> Result<String, PromptError> {
    let template = SignatureTemplate::from_data(data);

    render_prompt(&template)
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
        binary: data.dll_name.clone().into(),
        function: data.function_name.clone(),
        disassembly: data.disassembly.clone(),
        decompiler_output: data.decompiler_output.clone(),
        windows_apis: data.windows_apis.clone(),
        baseline_tests: data.test_cases.clone(),
    };

    let mut template = TranslateTemplate::from_request(&req);
    template.no_windows_apis = data.no_windows_apis;

    render_prompt(&template)
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

    render_prompt(&template)
}

// ============================================================
// Module context prompt builder (Tier 3)
// ============================================================

/// Builds a Tier 3 module context prompt with neighboring function code
/// and shared data structures.
///
/// Contains full disassembly, decompiler output, tagged Windows API calls,
/// baseline test results with pass/fail status, and — through the one
/// [`EvidenceBundle`] the gathered finding lists ride in as (issue #320) —
/// full context from neighboring functions (disassembly + decompiler
/// output), any data structures referenced near the target function, and
/// the shared evidence sections the template includes. Callers with no
/// gathered context pass [`EvidenceBundle::default()`].
///
/// This tier is used for complex functions whose translation requires
/// understanding shared calling conventions, data layouts, or helper
/// patterns from adjacent functions in the same module.
pub fn build_module_context_prompt(
    req: &TranslationRequest,
    evidence: EvidenceBundle,
) -> Result<String, PromptError> {
    let template = ModuleContextTemplate::from_request(req, evidence);

    render_prompt(&template)
}

// ============================================================
// Full module prompt builder (Tier 4)
// ============================================================

/// Builds a Tier 4 full module prompt with shim layer code and PAL trait
/// definitions on top of module context.
///
/// Contains full disassembly, decompiler output, tagged Windows API calls,
/// baseline test results with pass/fail status, generated shim layer code
/// for crate-replacement DLLs, and PAL trait definitions — plus the full
/// gathered context, which rides in as one [`EvidenceBundle`] exactly as
/// the module-context builder takes it (issue #320). Callers with no
/// gathered context pass [`EvidenceBundle::default()`].
///
/// This tier is used when translating functions that call through shim
/// layers (e.g., DirectX → wgpu) and need the full translation-layer
/// context — including the shim source code and PAL trait interfaces —
/// to map correctly to the cross-platform Rust equivalents.
pub fn build_full_module_prompt(
    req: &TranslationRequest,
    evidence: EvidenceBundle,
    shim_layers: Vec<ShimCode>,
    pal_traits: Vec<PalTraitDef>,
) -> Result<String, PromptError> {
    let template = FullModuleTemplate::from_request(req, evidence, shim_layers, pal_traits);

    render_prompt(&template)
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
            render_prompt(&template)?
        }
        FunctionComplexity::Standard => {
            let req = build_std_request(data);
            let mut template = TranslateTemplate::from_request(&req);
            // API-aware augmentation: inject full mapping table rows
            if !api_category_mappings.is_empty() {
                template.api_category_mappings = api_category_mappings;
            }
            render_prompt(&template)?
        }
        FunctionComplexity::Rich => {
            let req = build_std_request(data);
            let mut template = RichTemplate::from_request(&req);
            // API-aware augmentation: inject full mapping table rows
            if !api_category_mappings.is_empty() {
                template.api_category_mappings = api_category_mappings;
            }
            // Type-info rows (issue #276): the persisted type-inference
            // artifact's readings, direction records included, ride the
            // template's existing type-info section — no new section.
            template.type_info = data.type_info.clone();
            template.control_flow_findings = data.control_flow_findings.clone();
            // Coverage fan-out (issue #351): the type-inference engine's one
            // record qualifies this tier's type-information section too.
            template.type_inference_coverage = data.type_inference_coverage.clone();
            render_prompt(&template)?
        }
        FunctionComplexity::Detailed => {
            let req = build_std_request(data);
            let mut template = super::templates::DetailedTemplate::from_request(&req);
            // API-aware augmentation: inject full mapping table rows
            if !api_category_mappings.is_empty() {
                template.api_category_mappings = api_category_mappings;
            }
            // Type-info rows (issue #276): same riding as the rich arm —
            // the artifact's readings render through the existing
            // type-info section, no new section.
            template.type_info = data.type_info.clone();
            template.control_flow_findings = data.control_flow_findings.clone();
            // Coverage fan-out (issue #351): the type-inference engine's one
            // record also qualifies this tier's type-information section and
            // its parameter-direction section.
            template.type_inference_coverage = data.type_inference_coverage.clone();
            render_prompt(&template)?
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
        binary: data.dll_name.clone().into(),
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

/// Extracts the function signature from the decompiler output.
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
