//! Error types for the calxgloss-sync crate.
//!
//! This module defines `SyncError`, the one error type this crate
//! uses everywhere. It covers decompiler reads, detector runs, and
//! JSON persistence.

use thiserror::Error;

/// Errors that can occur during concurrency detection operations.
#[derive(Debug, Error)]
pub enum SyncError {
    /// A read from the analysis engine at the seam failed.
    #[error("engine error: {0}")]
    Engine(#[from] calxgloss_decomp::EngineError),

    /// An I/O error occurred while reading or writing detection results.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// A JSON serialization or deserialization error occurred.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// No persisted concurrency result exists at the requested path.
    #[error("concurrency result not found: {}", .path.display())]
    NotFound { path: std::path::PathBuf },

    /// A function name was empty or unparseable.
    #[error("empty function name")]
    EmptyFunctionName,

    /// Too many of the program's functions failed to decompile to
    /// trust the scan's answer. A high skip rate is the signature of
    /// a seam letting the scan answer about the wrong program. The
    /// skip-rate breaker is a fuse: it aborts the scan rather than
    /// persisting a record that looks clean but is not.
    #[error("the engine failed to decompile {failed} of {total} functions")]
    DecompileBreaker { failed: usize, total: usize },

    /// A concurrency scan failed for one target binary.
    #[error("concurrency scan failed for '{binary}': {reason}")]
    ScanFailed { binary: String, reason: String },
}

/// Maps the shared JSON store's errors onto this crate's error type.
/// The store's not-found becomes [`SyncError::NotFound`], and its I/O
/// and JSON errors become the existing pass-through variants.
impl From<calxgloss_types::persist::PersistError> for SyncError {
    fn from(error: calxgloss_types::persist::PersistError) -> Self {
        use calxgloss_types::persist::PersistError;
        match error {
            PersistError::NotFound { path } => Self::NotFound { path },
            PersistError::Io { source, .. } => Self::Io(source),
            PersistError::Json { source, .. } => Self::Json(source),
        }
    }
}

pub type Result<T> = std::result::Result<T, SyncError>;
