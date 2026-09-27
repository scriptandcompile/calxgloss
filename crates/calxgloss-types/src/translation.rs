//! Types for the translation request/response cycle.
//!
//! This module defines the data structures used to request a function
//! translation from the LLM pipeline and to capture the result.

use serde::{Deserialize, Serialize};

use crate::{ApiCategory, TestCase};

/// A request to translate a single function from disassembly to Rust.
///
/// The request bundles all context the LLM needs: the function's
/// disassembly, decompiler output, identified Windows API calls with
/// their PAL mappings, and baseline tests the output must pass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TranslationRequest {
    /// The DLL containing the function to translate.
    pub dll: String,

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

/// A single Windows API call identified within a function's disassembly.
///
/// When Ghidra analysis finds a call to a known Windows API, this struct
/// records the API name, its category, and the PAL mapping target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowsApiCall {
    /// The Windows API function name (e.g., `CreateFileA`).
    pub name: String,

    /// The platform API category this call belongs to.
    pub category: ApiCategory,

    /// The cross-platform Rust equivalent (e.g., `std::fs::File::open`).
    pub pal_mapping: String,
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
