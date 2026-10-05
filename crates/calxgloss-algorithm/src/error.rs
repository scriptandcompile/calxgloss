//! Error types for the calxgloss-algorithm crate.
//!
//! This module defines `AlgorithmError`, the unified error type used
//! throughout the algorithm recognition crate for decompiler and string
//! fetches, detector runs, and JSON persistence.

use thiserror::Error;

/// Errors that can occur during algorithm recognition operations.
#[derive(Debug, Error)]
pub enum AlgorithmError {
    /// A GhidraMCP request failed.
    #[error("GhidraMCP error: {0}")]
    Ghidra(#[from] calxgloss_ghidra::GhidraError),

    /// An I/O error occurred while reading or writing recognition results.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// A JSON serialization or deserialization error occurred.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// A function name was empty or unparseable.
    #[error("empty function name")]
    EmptyFunctionName,

    /// An algorithm recognition scan failed for a DLL.
    #[error("algorithm recognition scan failed for '{dll}': {reason}")]
    ScanFailed { dll: String, reason: String },
}

pub type Result<T> = std::result::Result<T, AlgorithmError>;
