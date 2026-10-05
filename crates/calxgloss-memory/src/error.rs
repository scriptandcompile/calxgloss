//! Error types for the calxgloss-memory crate.
//!
//! This module defines `MemoryError`, the unified error type used
//! throughout the memory lifecycle detection crate for decompiler
//! fetches, detector runs, and JSON persistence.

use thiserror::Error;

/// Errors that can occur during memory lifecycle detection operations.
#[derive(Debug, Error)]
pub enum MemoryError {
    /// A GhidraMCP request failed.
    #[error("GhidraMCP error: {0}")]
    Ghidra(#[from] calxgloss_ghidra::GhidraError),

    /// An I/O error occurred while reading or writing detection results.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// A JSON serialization or deserialization error occurred.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// A function name was empty or unparseable.
    #[error("empty function name")]
    EmptyFunctionName,

    /// A memory lifecycle scan failed for a DLL.
    #[error("memory lifecycle scan failed for '{dll}': {reason}")]
    ScanFailed { dll: String, reason: String },
}

pub type Result<T> = std::result::Result<T, MemoryError>;
