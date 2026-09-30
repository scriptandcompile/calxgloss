//! Error types for the calxgloss-analysis crate.
//!
//! This module defines `AnalysisError`, the unified error type used throughout
//! the analysis crate for DLL classification, function analysis, and API tagging.

use thiserror::Error;

/// Errors that can occur during analysis operations.
#[derive(Debug, Error)]
pub enum AnalysisError {
    /// A GhidraMCP request failed.
    #[error("GhidraMCP error: {0}")]
    Ghidra(#[from] calxgloss_ghidra::GhidraError),

    /// An I/O or general error occurred.
    #[error("{0}")]
    Io(#[from] anyhow::Error),

    /// A DLL name was empty or unparseable.
    #[error("empty DLL name")]
    EmptyDllName,

    /// A function name was empty or unparseable.
    #[error("empty function name")]
    EmptyFunctionName,

    /// No exports or imports found for the DLL.
    #[error("no symbols found in DLL: {0}")]
    NoSymbols(String),

    /// The DLL could not be classified.
    #[error("classification failed for '{dll}': {reason}")]
    ClassificationFailed { dll: String, reason: String },

    /// Function analysis failed.
    #[error("function analysis failed for '{function}' in '{dll}': {reason}")]
    FunctionAnalysisFailed {
        dll: String,
        function: String,
        reason: String,
    },
}

pub type Result<T> = std::result::Result<T, AnalysisError>;
