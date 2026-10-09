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

    /// No persisted type database exists at the requested path.
    #[error("type database not found: {}", .path.display())]
    NotFound { path: std::path::PathBuf },

    /// A type name was empty or unparseable.
    #[error("empty type name")]
    EmptyTypeName,

    /// A type database scan failed for a DLL.
    #[error("type database scan failed for '{binary}': {reason}")]
    ScanFailed { binary: String, reason: String },
}

/// Maps the shared JSON store's errors onto this crate's error type: the
/// store's not-found becomes [`TypesDbError::NotFound`], and its I/O and
/// JSON errors fold into the existing pass-through variants.
impl From<calxgloss_types::persist::PersistError> for TypesDbError {
    fn from(error: calxgloss_types::persist::PersistError) -> Self {
        use calxgloss_types::persist::PersistError;
        match error {
            PersistError::NotFound { path } => Self::NotFound { path },
            PersistError::Io { source, .. } => Self::Io(source),
            PersistError::Json { source, .. } => Self::Json(source),
        }
    }
}

pub type Result<T> = std::result::Result<T, TypesDbError>;
