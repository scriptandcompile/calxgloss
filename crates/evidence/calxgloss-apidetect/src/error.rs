//! Error types for the calxgloss-apidetect crate.
//!
//! This module defines `ApiError`, the unified error type used
//! throughout the API-identification crate for import listings,
//! call-graph fetches, and JSON persistence.

use thiserror::Error;

/// Errors that can occur during API identification operations.
#[derive(Debug, Error)]
pub enum ApiError {
    /// A GhidraMCP request failed.
    #[error("GhidraMCP error: {0}")]
    Ghidra(#[from] calxgloss_ghidra::GhidraError),

    /// The call graph the per-function summary traverses could not be built.
    #[error("call graph build failed: {reason}")]
    CallGraph { reason: String },

    /// An I/O error occurred while reading or writing API results.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// A JSON serialization or deserialization error occurred.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// No persisted API result exists at the requested path.
    #[error("API result not found: {}", .path.display())]
    NotFound { path: std::path::PathBuf },
}

/// Maps the shared JSON store's errors onto this crate's error type: the
/// store's not-found becomes [`ApiError::NotFound`], and its I/O and
/// JSON errors fold into the existing pass-through variants.
impl From<calxgloss_types::persist::PersistError> for ApiError {
    fn from(error: calxgloss_types::persist::PersistError) -> Self {
        use calxgloss_types::persist::PersistError;
        match error {
            PersistError::NotFound { path } => Self::NotFound { path },
            PersistError::Io { source, .. } => Self::Io(source),
            PersistError::Json { source, .. } => Self::Json(source),
        }
    }
}

pub type Result<T> = std::result::Result<T, ApiError>;
