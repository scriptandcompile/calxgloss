//! Error types for the calxgloss-typesdb crate.
//!
//! This module defines `TypesDbError`, the one error type the whole crate
//! uses. It covers scanning the decompiler's type library, vtable detection,
//! string-guided inference, and JSON persistence.

use thiserror::Error;

/// Errors that can occur during type database operations.
#[derive(Debug, Error)]
pub enum TypesDbError {
    /// A read through the analysis seam failed.
    #[error("engine error: {0}")]
    Engine(#[from] calxgloss_decomp::EngineError),

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

    /// The type database scan failed for one target binary.
    #[error("type database scan failed for '{binary}': {reason}")]
    ScanFailed { binary: String, reason: String },
}

/// Maps the shared JSON store's errors onto this crate's error type.
/// The store's not-found error becomes [`TypesDbError::NotFound`]; its I/O
/// and JSON errors become the existing pass-through variants.
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
