//! Prompt data structures — input types for the prompt builder functions.
//!
//! This module defines the data structs used as input to the prompt build
//! functions (`build_*`). Each struct corresponds to a specific translation
//! tier:
//!
//! - [`StubPromptData`] — Tier 0: function stub only (name, signature, call graph)
//! - [`DisassemblyPromptData`] — Tier 1: disassembly + decompiler output
//! - [`WithTestsPromptData`] — Tier 2: full context with baseline test results
//! - [`ComplexityPromptData`] — Tier 3+: complexity-aware rich context

use super::templates::{CallGraphNeighbor, FormattedTestResult};
use calxgloss_types::{ApiCategory, TestCase, TranslationRequest};
use serde::Serialize;

// ============================================================
// Tier 0 — Stub prompt data
// ============================================================

/// Prompt data for a Tier 0 (stub-only) translation request.
#[derive(Debug, Clone, Serialize)]
pub struct StubPromptData {
    pub function_name: String,
    pub dll_name: String,
    pub address_hex: String,
    pub signature: String,
    pub call_graph_neighbors: Vec<CallGraphNeighbor>,
}

impl StubPromptData {
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
    pub windows_apis: Vec<calxgloss_types::translation::WindowsApiCall>,
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
            windows_apis: info
                .windows_apis
                .iter()
                .map(|api| calxgloss_types::translation::WindowsApiCall {
                    name: api.name.clone(),
                    category: api.category.clone(),
                    pal_mapping: api.pal_mapping.clone(),
                })
                .collect(),
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
}

impl WithTestsPromptData {
    pub fn from_request(req: &TranslationRequest) -> Self {
        let test_results: Vec<FormattedTestResult> = req
            .baseline_tests
            .iter()
            .enumerate()
            .map(|(i, test)| FormattedTestResult::from_baseline(test, i + 1))
            .collect();

        // Convert from translation::WindowsApiCall to calxgloss_types::WindowsApiCall
        let windows_apis: Vec<calxgloss_types::WindowsApiCall> = req
            .windows_apis
            .iter()
            .map(|api| calxgloss_types::WindowsApiCall {
                name: api.name.clone(),
                category: api.category.clone(),
                pal_mapping: api.pal_mapping.clone(),
            })
            .collect();

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
    pub windows_apis: Vec<calxgloss_types::translation::WindowsApiCall>,
    pub test_cases: Vec<super::templates::TestCaseFormatted>,
    pub api_category_mappings: Vec<calxgloss_types::ApiCategoryMapping>,
    pub call_graph_neighbors: Vec<CallGraphNeighbor>,
    pub neighboring_functions: Vec<super::templates::NeighborFunction>,
    pub data_structures: Vec<super::templates::StructuredData>,
    pub type_info: Vec<super::templates::TypeInfo>,
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
