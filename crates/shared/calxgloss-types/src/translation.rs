//! Types for the translation request/response cycle.
//!
//! This module defines the data structures used to request a function
//! translation from the LLM pipeline and to capture the result.

use serde::{Deserialize, Serialize};

use crate::identity::BinaryIdentity;
use crate::{TestCase, WindowsApiCall};

/// A request to translate a single function from disassembly to Rust.
///
/// The request bundles all context the LLM needs: the function's
/// disassembly, decompiler output, identified Windows API calls with
/// their PAL mappings, and baseline tests the output must pass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TranslationRequest {
    /// The DLL containing the function to translate.
    pub binary: BinaryIdentity,

    /// The function name to translate.
    pub function: String,

    /// Raw disassembly listing from Ghidra.
    pub disassembly: String,

    /// Pseudo-C decompiler output from Ghidra.
    pub decompiler_output: String,

    /// Windows API calls identified in the disassembly, with their PAL mappings.
    pub windows_apis: Vec<WindowsApiCall>,

    /// Baseline test cases the translated Rust code must pass.
    pub baseline_tests: Vec<TestCase>,
}

/// The result produced by a successful LLM translation.
///
/// Includes the generated Rust code, the prompt that produced it, the
/// model used, and optional token usage information for cost tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TranslationResult {
    /// The generated Rust source code for the function.
    pub rust_code: String,

    /// The full prompt sent to the LLM (for reproducibility and debugging).
    pub prompt_used: String,

    /// The LLM model name and version used for this translation.
    pub model: String,

    /// Number of tokens used, if reported by the LLM.
    pub tokens_used: Option<usize>,
}

/// A Windows API mapping grouped by category, used in rich/detailed
/// translation prompts to give the LLM extra reference context for
/// the specific API categories a function touches.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiCategoryMapping {
    /// The API category name (e.g. `"Win32Core"`, `"DirectX"`).
    pub category: String,
    /// The individual API mappings for this category.
    pub mappings: Vec<ApiMappingItem>,
}

/// A single Windows API → Rust equivalent mapping.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiMappingItem {
    /// The Windows API name.
    pub windows_api: String,
    /// The cross-platform Rust equivalent.
    pub rust_equivalent: String,
    /// Human-readable notes about the mapping.
    pub notes: String,
}
