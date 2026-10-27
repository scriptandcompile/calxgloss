//! Types for the translation request/response cycle.
//!
//! This module holds the records used to ask the LLM pipeline for a function
//! translation and to capture the result.

use serde::{Deserialize, Serialize};

use crate::identity::BinaryIdentity;
use crate::{TestCase, WindowsApiCall};

/// A request to translate a single function from disassembly to Rust.
///
/// The request includes all the context the LLM needs: the function's
/// disassembly, decompiler output, identified Windows API calls with
/// their PAL mappings, and baseline tests the output must pass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TranslationRequest {
    /// The DLL containing the function to translate.
    pub binary: BinaryIdentity,

    /// The function name to translate.
    pub function: String,

    /// Raw disassembly listing from the decompiler.
    pub disassembly: String,

    /// Pseudo-C decompiler output.
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

/// Windows API mappings grouped by category. Rich and detailed translation
/// prompts include this record so the LLM gets reference material for the
/// API categories the function uses.
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
