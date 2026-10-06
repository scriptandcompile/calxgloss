//! Prompt data structures — input types for the prompt builder functions.
//!
//! This module defines the data structs used as input to the prompt build
//! functions (`build_*`). Each struct corresponds to a specific translation
//! tier:
//!
//! - [`SignaturePromptData`] — Tier 0: name and signature only (plus call graph)
//! - [`DisassemblyPromptData`] — Tier 1: disassembly + decompiler output
//! - [`WithTestsPromptData`] — Tier 2: full context with baseline test results
//! - [`ModuleContextPromptData`] — Tier 3: module context with neighbors + data structures
//! - [`ComplexityPromptData`] — Tier 3+: complexity-aware rich context
//! - [`FullModulePromptData`] — Tier 4: full module with shim layer + PAL traits

use super::templates::{
    CallGraphNeighbor, ControlFlowInfo, FormattedTestResult, NeighborFunction, PalTraitDef,
    ShimCode, StructuredData,
};
use calxgloss_callgraph::FunctionContext;
use calxgloss_types::{ApiCategory, TestCase, TranslationRequest};
use serde::Serialize;

// ============================================================
// Tier 0 — Signature prompt data
// ============================================================

/// Prompt data for a Tier 0 (name-and-signature-only) translation request.
#[derive(Debug, Clone, Serialize)]
pub struct SignaturePromptData {
    pub function_name: String,
    pub dll_name: String,
    pub address_hex: String,
    pub signature: String,
    pub call_graph_neighbors: Vec<CallGraphNeighbor>,
}

impl SignaturePromptData {
    pub fn from_function_info(info: &calxgloss_types::FunctionInfo) -> Self {
        Self {
            function_name: info.name.clone(),
            dll_name: info.dll.clone(),
            address_hex: format!("{:#x}", info.address),
            signature: String::new(),
            call_graph_neighbors: info
                .call_graph
                .iter()
                .map(|name| CallGraphNeighbor {
                    name: name.clone(),
                    address: 0,
                    signature: String::new(),
                    role: String::new(),
                })
                .collect(),
        }
    }
}

// ============================================================
// Tier 1 — Disassembly prompt data
// ============================================================

/// Prompt data for a Tier 1 (disassembly + decompiler) translation request.
#[derive(Debug, Clone, Serialize)]
pub struct DisassemblyPromptData {
    pub function_name: String,
    pub dll_name: String,
    pub address: u64,
    pub disassembly: String,
    pub decompiler_output: String,
    pub windows_apis: Vec<calxgloss_types::WindowsApiCall>,
    pub no_windows_apis: bool,
    pub test_cases: Vec<TestCase>,
}

impl DisassemblyPromptData {
    pub fn from_function_info(info: &calxgloss_types::FunctionInfo) -> Self {
        Self {
            function_name: info.name.clone(),
            dll_name: info.dll.clone(),
            address: info.address,
            disassembly: info.disassembly.clone(),
            decompiler_output: info.decompiler_output.clone(),
            windows_apis: info.windows_apis.clone(),
            no_windows_apis: info.windows_apis.is_empty(),
            test_cases: Vec::new(),
        }
    }
}

// ============================================================
// Tier 2 — With-tests prompt data
// ============================================================

/// Prompt data for a Tier 2 (full context with tests) translation request.
#[derive(Debug, Clone, Serialize)]
pub struct WithTestsPromptData {
    pub function_name: String,
    pub dll_name: String,
    pub address: u64,
    pub disassembly: String,
    pub decompiler_output: String,
    pub windows_apis: Vec<calxgloss_types::WindowsApiCall>,
    pub no_windows_apis: bool,
    pub call_graph_neighbors: Vec<CallGraphNeighbor>,
    pub test_results: Vec<FormattedTestResult>,
    /// Enriched call graph context from [`calxgloss_callgraph::ContextEnricher`].
    ///
    /// When present, the prompt includes caller/callee details and leaf API
    /// suggestions alongside the simpler neighbor list.
    pub call_graph_context: Vec<calxgloss_callgraph::FunctionContext>,
}

impl WithTestsPromptData {
    pub fn from_request(req: &TranslationRequest) -> Self {
        let test_results: Vec<FormattedTestResult> = req
            .baseline_tests
            .iter()
            .enumerate()
            .map(|(i, test)| FormattedTestResult::from_baseline(test, i + 1))
            .collect();

        let windows_apis = req.windows_apis.clone();

        Self {
            function_name: req.function.clone(),
            dll_name: req.dll.clone(),
            address: 0,
            disassembly: req.disassembly.clone(),
            decompiler_output: req.decompiler_output.clone(),
            windows_apis,
            no_windows_apis: req.windows_apis.is_empty(),
            call_graph_neighbors: Vec::new(),
            test_results,
            call_graph_context: Vec::new(),
        }
    }

    /// Build with-tests prompt data with enriched call graph context.
    ///
    /// Use this constructor when a [`calxgloss_callgraph::CallGraph`] is available
    /// and you want to produce enriched caller/callee context for the prompt.
    pub fn from_request_with_call_graph(
        req: &TranslationRequest,
        graph: &calxgloss_callgraph::CallGraph,
    ) -> Self {
        let mut data = Self::from_request(req);
        let enricher = calxgloss_callgraph::ContextEnricher::new();
        let contexts = enricher.enrich(graph);
        data.call_graph_context = contexts;
        data
    }
}

// ============================================================
// Tier 3 — Module context prompt data
// ============================================================

/// Prompt data for a Tier 3 (module context) translation request.
///
/// Extends Tier 2 with neighboring function context and shared data
/// structures. This tier is used when a function's translation requires
/// understanding its neighbors — shared data layouts, calling conventions,
/// or helper function patterns.
#[derive(Debug, Clone, Serialize)]
pub struct ModuleContextPromptData {
    pub function_name: String,
    pub dll_name: String,
    pub address: u64,
    pub disassembly: String,
    pub decompiler_output: String,
    pub windows_apis: Vec<calxgloss_types::WindowsApiCall>,
    pub no_windows_apis: bool,
    pub call_graph_neighbors: Vec<CallGraphNeighbor>,
    pub test_results: Vec<FormattedTestResult>,
    pub neighboring_functions: Vec<NeighborFunction>,
    pub data_structures: Vec<StructuredData>,
    /// Enriched call graph context from [`calxgloss_callgraph::ContextEnricher`].
    ///
    /// When present, the prompt includes caller/callee details and leaf API
    /// suggestions alongside the simpler neighbor list.
    pub call_graph_context: Vec<calxgloss_callgraph::FunctionContext>,
    /// Control-flow findings about the target function made by the
    /// `calxgloss-controlflow` detectors.
    pub control_flow_findings: Vec<ControlFlowInfo>,
}

impl ModuleContextPromptData {
    /// Build module context prompt data from a [`TranslationRequest`].
    ///
    /// Only the request's core fields are populated. Neighboring functions,
    /// data structures, and call graph neighbors are left empty — call
    /// [`from_request_with_context`] instead when that extra context is
    /// available from Ghidra.
    pub fn from_request(req: &TranslationRequest) -> Self {
        let test_results: Vec<FormattedTestResult> = req
            .baseline_tests
            .iter()
            .enumerate()
            .map(|(i, test)| FormattedTestResult::from_baseline(test, i + 1))
            .collect();

        let windows_apis = req.windows_apis.clone();

        Self {
            function_name: req.function.clone(),
            dll_name: req.dll.clone(),
            address: 0,
            disassembly: req.disassembly.clone(),
            decompiler_output: req.decompiler_output.clone(),
            windows_apis,
            no_windows_apis: req.windows_apis.is_empty(),
            call_graph_neighbors: Vec::new(),
            test_results,
            neighboring_functions: Vec::new(),
            data_structures: Vec::new(),
            call_graph_context: Vec::new(),
            control_flow_findings: Vec::new(),
        }
    }

    /// Build module context prompt data from a [`TranslationRequest`] with
    /// additional Ghidra-derived context.
    ///
    /// Use this constructor when neighboring function code and data structure
    /// information have been fetched from Ghidra.
    #[allow(clippy::too_many_arguments)]
    pub fn from_request_with_context(
        req: &TranslationRequest,
        call_graph_neighbors: Vec<CallGraphNeighbor>,
        neighboring_functions: Vec<NeighborFunction>,
        data_structures: Vec<StructuredData>,
        call_graph_context: Vec<FunctionContext>,
        control_flow_findings: Vec<ControlFlowInfo>,
    ) -> Self {
        let test_results: Vec<FormattedTestResult> = req
            .baseline_tests
            .iter()
            .enumerate()
            .map(|(i, test)| FormattedTestResult::from_baseline(test, i + 1))
            .collect();

        let windows_apis = req.windows_apis.clone();

        Self {
            function_name: req.function.clone(),
            dll_name: req.dll.clone(),
            address: 0,
            disassembly: req.disassembly.clone(),
            decompiler_output: req.decompiler_output.clone(),
            windows_apis,
            no_windows_apis: req.windows_apis.is_empty(),
            call_graph_neighbors,
            test_results,
            neighboring_functions,
            data_structures,
            call_graph_context,
            control_flow_findings,
        }
    }
}

// ============================================================
// Tier 3+ — Complexity-aware prompt data
// ============================================================

/// Prompt data for a complexity-aware translation request.
#[derive(Debug, Clone, Serialize)]
pub struct ComplexityPromptData {
    pub function_name: String,
    pub dll_name: String,
    pub address: u64,
    pub disassembly: String,
    pub decompiler_output: String,
    pub windows_apis: Vec<calxgloss_types::WindowsApiCall>,
    pub test_cases: Vec<super::templates::TestCaseFormatted>,
    pub api_category_mappings: Vec<calxgloss_types::ApiCategoryMapping>,
    pub call_graph_neighbors: Vec<CallGraphNeighbor>,
    pub neighboring_functions: Vec<super::templates::NeighborFunction>,
    pub data_structures: Vec<super::templates::StructuredData>,
    pub type_info: Vec<super::templates::TypeInfo>,
    /// Control-flow findings about the target function made by the
    /// `calxgloss-controlflow` detectors.
    pub control_flow_findings: Vec<ControlFlowInfo>,
}

impl ComplexityPromptData {
    pub fn from_request(req: &TranslationRequest) -> Self {
        let test_cases: Vec<super::templates::TestCaseFormatted> = req
            .baseline_tests
            .iter()
            .enumerate()
            .map(|(i, test)| super::templates::TestCaseFormatted {
                index: i + 1,
                inputs: test.inputs.clone(),
                expected_return: test.expected_return.clone(),
                side_effects: serde_json::to_value(&test.expected_side_effects)
                    .unwrap_or_else(|_| serde_json::json!([])),
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
            control_flow_findings: Vec::new(),
        }
    }

    /// Extract the unique API categories this function touches.
    pub fn api_categories(&self) -> Vec<ApiCategory> {
        let mut categories: Vec<ApiCategory> = self
            .windows_apis
            .iter()
            .map(|api| api.category.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        // ApiCategory doesn't implement Ord, so sort by display name
        categories.sort_by_key(|c| format!("{:?}", c));
        categories
    }
}

// ============================================================
// Tier 4 — Full module prompt data (module context + shims + PAL)
// ============================================================

/// Prompt data for a Tier 4 (full module) translation request.
///
/// Extends Tier 3 with shim layer code and PAL trait definitions.
/// This tier is used when translating functions that call through
/// shim layers (e.g., DirectX → wgpu) and need the full translation-
/// layer context to map correctly.
#[derive(Debug, Clone, Serialize)]
pub struct FullModulePromptData {
    pub function_name: String,
    pub dll_name: String,
    pub address: u64,
    pub disassembly: String,
    pub decompiler_output: String,
    pub windows_apis: Vec<calxgloss_types::WindowsApiCall>,
    pub no_windows_apis: bool,
    pub call_graph_neighbors: Vec<CallGraphNeighbor>,
    pub test_results: Vec<FormattedTestResult>,
    pub neighboring_functions: Vec<NeighborFunction>,
    pub data_structures: Vec<StructuredData>,
    pub shim_layers: Vec<ShimCode>,
    pub pal_traits: Vec<PalTraitDef>,
    /// Enriched call graph context from [`calxgloss_callgraph::ContextEnricher`].
    ///
    /// When present, the prompt includes caller/callee details and leaf API
    /// suggestions alongside the simpler neighbor list.
    pub call_graph_context: Vec<calxgloss_callgraph::FunctionContext>,
    /// Control-flow findings about the target function made by the
    /// `calxgloss-controlflow` detectors.
    pub control_flow_findings: Vec<ControlFlowInfo>,
}

impl FullModulePromptData {
    /// Build full module prompt data from a [`TranslationRequest`].
    ///
    /// Only the request's core fields are populated. Shim layers, PAL
    /// traits, and other Tier 3+ fields are left empty — call
    /// [`from_request_with_full_context`] instead when that extra context
    /// is available from Ghidra and the workspace.
    pub fn from_request(req: &TranslationRequest) -> Self {
        let test_results: Vec<FormattedTestResult> = req
            .baseline_tests
            .iter()
            .enumerate()
            .map(|(i, test)| FormattedTestResult::from_baseline(test, i + 1))
            .collect();

        let windows_apis = req.windows_apis.clone();

        Self {
            function_name: req.function.clone(),
            dll_name: req.dll.clone(),
            address: 0,
            disassembly: req.disassembly.clone(),
            decompiler_output: req.decompiler_output.clone(),
            windows_apis,
            no_windows_apis: req.windows_apis.is_empty(),
            call_graph_neighbors: Vec::new(),
            test_results,
            neighboring_functions: Vec::new(),
            data_structures: Vec::new(),
            shim_layers: Vec::new(),
            pal_traits: Vec::new(),
            call_graph_context: Vec::new(),
            control_flow_findings: Vec::new(),
        }
    }

    /// Build full module prompt data from a [`TranslationRequest`] with
    /// complete Ghidra-derived context and workspace shim/PAL data.
    ///
    /// Use this constructor when all context — call graph neighbors,
    /// neighboring function code, data structures, shim layer code,
    /// and PAL trait definitions — is available.
    #[allow(clippy::too_many_arguments)]
    pub fn from_request_with_full_context(
        req: &TranslationRequest,
        call_graph_neighbors: Vec<CallGraphNeighbor>,
        neighboring_functions: Vec<NeighborFunction>,
        data_structures: Vec<StructuredData>,
        shim_layers: Vec<ShimCode>,
        pal_traits: Vec<PalTraitDef>,
        call_graph_context: Vec<FunctionContext>,
        control_flow_findings: Vec<ControlFlowInfo>,
    ) -> Self {
        let test_results: Vec<FormattedTestResult> = req
            .baseline_tests
            .iter()
            .enumerate()
            .map(|(i, test)| FormattedTestResult::from_baseline(test, i + 1))
            .collect();

        let windows_apis = req.windows_apis.clone();

        Self {
            function_name: req.function.clone(),
            dll_name: req.dll.clone(),
            address: 0,
            disassembly: req.disassembly.clone(),
            decompiler_output: req.decompiler_output.clone(),
            windows_apis,
            no_windows_apis: req.windows_apis.is_empty(),
            call_graph_neighbors,
            test_results,
            neighboring_functions,
            data_structures,
            shim_layers,
            pal_traits,
            call_graph_context,
            control_flow_findings,
        }
    }
}
