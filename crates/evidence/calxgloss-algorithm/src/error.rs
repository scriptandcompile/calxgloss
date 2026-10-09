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

    /// No persisted recognition result exists at the requested path.
    #[error("algorithm recognition result not found: {}", .path.display())]
    NotFound { path: std::path::PathBuf },

    /// A function name was empty or unparseable.
    #[error("empty function name")]
    EmptyFunctionName,

    /// An algorithm recognition scan failed for a DLL.
    #[error("algorithm recognition scan failed for '{binary}': {reason}")]
    ScanFailed { binary: String, reason: String },
}

/// Maps the shared JSON store's errors onto this crate's error type: the
/// store's not-found becomes [`AlgorithmError::NotFound`], and its I/O and
/// JSON errors fold into the existing pass-through variants.
impl From<calxgloss_types::persist::PersistError> for AlgorithmError {
    fn from(error: calxgloss_types::persist::PersistError) -> Self {
        use calxgloss_types::persist::PersistError;
        match error {
            PersistError::NotFound { path } => Self::NotFound { path },
            PersistError::Io { source, .. } => Self::Io(source),
            PersistError::Json { source, .. } => Self::Json(source),
        }
    }
}

pub type Result<T> = std::result::Result<T, AlgorithmError>;
