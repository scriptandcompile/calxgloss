//! Error types for the calxgloss-globalstate crate.
//!
//! This module defines `GlobalStateError`, the one error type the whole
//! global-state reference-set crate uses — for decompiler fetches, the
//! access reading, and JSON persistence.

use thiserror::Error;

/// Errors that can occur during global-state scanning.
#[derive(Debug, Error)]
pub enum GlobalStateError {
    /// A read through the analysis engine seam failed.
    #[error("engine error: {0}")]
    Engine(#[from] calxgloss_decomp::EngineError),

    /// An I/O error occurred while reading or writing the reference-set
    /// document.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// A JSON serialization or deserialization error occurred.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// No persisted reference-set document exists at the requested path.
    #[error("global-state result not found: {}", .path.display())]
    NotFound { path: std::path::PathBuf },

    /// Too many of the program's functions failed to decompile for the
    /// scan to be trusted. A high skip rate is the signature of the bridge
    /// answering from the wrong program. The skip-rate breaker aborts the
    /// scan instead of persisting a document that looks clean but is not.
    #[error("the engine failed to decompile {failed} of {total} functions")]
    DecompileBreaker { failed: usize, total: usize },
}

/// Maps the shared JSON store's errors onto this crate's error type. The
/// store's not-found becomes [`GlobalStateError::NotFound`], and its I/O
/// and JSON errors become the matching pass-through variants.
impl From<calxgloss_types::persist::PersistError> for GlobalStateError {
    fn from(error: calxgloss_types::persist::PersistError) -> Self {
        use calxgloss_types::persist::PersistError;
        match error {
            PersistError::NotFound { path } => Self::NotFound { path },
            PersistError::Io { source, .. } => Self::Io(source),
            PersistError::Json { source, .. } => Self::Json(source),
        }
    }
}

pub type Result<T> = std::result::Result<T, GlobalStateError>;
