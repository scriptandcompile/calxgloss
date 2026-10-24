//! Error types for the calxgloss-bdiff crate.
//!
//! This module defines `BdiffError`, the unified error type used
//! throughout the binary-version pairing crate for the pairing pass
//! itself and JSON persistence of the pairing document.

use thiserror::Error;

/// Errors that can occur while pairing binary versions or persisting
/// the pairing document.
#[derive(Debug, Error)]
pub enum BdiffError {
    /// An I/O error occurred while reading or writing the pairing document.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// A JSON serialization or deserialization error occurred while
    /// reading or writing the pairing document.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// No persisted pairing document exists at the requested path.
    #[error("pairing document not found: {}", .path.display())]
    NotFound { path: std::path::PathBuf },
}

/// Maps the shared JSON store's errors onto this crate's error type: the
/// store's not-found becomes [`BdiffError::NotFound`], and its I/O and
/// JSON errors fold into the existing pass-through variants.
impl From<calxgloss_types::persist::PersistError> for BdiffError {
    fn from(error: calxgloss_types::persist::PersistError) -> Self {
        use calxgloss_types::persist::PersistError;
        match error {
            PersistError::NotFound { path } => Self::NotFound { path },
            PersistError::Io { source, .. } => Self::Io(source),
            PersistError::Json { source, .. } => Self::Json(source),
        }
    }
}

pub type Result<T> = std::result::Result<T, BdiffError>;
