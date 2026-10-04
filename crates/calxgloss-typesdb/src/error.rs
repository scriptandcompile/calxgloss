//! Error types for the calxgloss-typesdb crate.
//!
//! This module defines `TypesDbError`, the unified error type used throughout
//! the type database crate for Ghidra type-library scanning, vtable detection,
//! string-guided inference, and JSON persistence.

use thiserror::Error;

/// Errors that can occur during type database operations.
#[derive(Debug, Error)]
pub enum TypesDbError {
    /// A GhidraMCP request failed.
    #[error("GhidraMCP error: {0}")]
    Ghidra(#[from] calxgloss_ghidra::GhidraError),

    /// An I/O error occurred while reading or writing the type database.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// A JSON serialization or deserialization error occurred.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// A type name was empty or unparseable.
    #[error("empty type name")]
    EmptyTypeName,

    /// A type database scan failed for a DLL.
    #[error("type database scan failed for '{dll}': {reason}")]
    ScanFailed { dll: String, reason: String },
}

pub type Result<T> = std::result::Result<T, TypesDbError>;
