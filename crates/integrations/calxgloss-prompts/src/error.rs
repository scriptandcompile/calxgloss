//! Prompt-specific error types.
//!
//! This module defines `PromptError`, the unified error type for the
//! calxgloss-prompts crate, covering template rendering failures
//! and empty prompt generation.

use thiserror::Error;

/// Unified error type for prompt template operations.
///
/// Covers template rendering failures and empty prompt generation.
#[derive(Debug, Error)]
pub enum PromptError {
    /// Template rendering failed (askama reported an error).
    #[error("render error: {0}")]
    Render(String),

    /// The rendered prompt is empty.
    #[error("rendered prompt is empty")]
    EmptyPrompt,
}
