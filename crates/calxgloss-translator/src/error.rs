//! Error types for the translation pipeline.

use thiserror::Error;

/// Unified error type for the translation pipeline.
#[derive(Debug, Error)]
pub enum TranslatorError {
    /// Failed to fetch function information from Ghidra.
    #[error("failed to get function '{function}' from DLL '{dll}': {source}")]
    GhidraFetch {
        dll: String,
        function: String,
        source: calxgloss_ghidra::GhidraError,
    },

    /// Failed to call the LLM.
    #[error("LLM request failed: {0}")]
    Llm(#[from] calxgloss_llm::LlmError),

    /// Failed to build a prompt from the translation request.
    #[error("failed to build prompt: {0}")]
    Prompt(#[from] calxgloss_prompts::PromptError),

    /// Failed to generate or run baseline tests.
    #[error("test generation failed: {0}")]
    TestGen(anyhow::Error),

    /// The LLM returned empty or invalid Rust code.
    #[error("LLM returned empty or invalid code ({} chars)", .code_len)]
    EmptyCode { code_len: usize },

    /// The translation request had insufficient context (no disassembly, no tests).
    #[error("translation request missing required context: {0}")]
    MissingContext(String),

    /// Failed to plan translation order from the call graph.
    #[error("call graph planning failed: {0}")]
    CallGraph(String),
}

pub type Result<T> = std::result::Result<T, TranslatorError>;
