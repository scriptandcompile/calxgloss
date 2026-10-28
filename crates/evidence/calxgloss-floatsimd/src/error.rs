//! Error types for the calxgloss-floatsimd crate.
//!
//! This module defines `FloatsimdError`, the one error type the
//! float/SIMD usage-flagging crate uses everywhere: for decompiler
//! reads, the per-body reading, and JSON persistence.

use thiserror::Error;

/// Errors that can occur during float/SIMD usage scanning.
#[derive(Debug, Error)]
pub enum FloatsimdError {
    /// An engine read through the analysis seam failed.
    #[error("engine error: {0}")]
    Engine(#[from] calxgloss_decomp::EngineError),

    /// An I/O error occurred while reading or writing the flag document.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// A JSON serialization or deserialization error occurred.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// No persisted flag document exists at the requested path.
    #[error("float/SIMD result not found: {}", .path.display())]
    NotFound { path: std::path::PathBuf },

    /// Too many of the program's functions failed to decompile for
    /// the scan to be trusted. A high skip rate is the signature of
    /// the seam answering about the wrong program, so the skip-rate
    /// breaker aborts the scan instead of letting it persist a record
    /// that looks clean but is not.
    #[error("the engine failed to decompile {failed} of {total} functions")]
    DecompileBreaker { failed: usize, total: usize },
}

/// Maps the shared JSON store's errors onto this crate's error type:
/// the store's not-found becomes [`FloatsimdError::NotFound`], and its
/// I/O and JSON errors become the matching pass-through variants here.
impl From<calxgloss_types::persist::PersistError> for FloatsimdError {
    fn from(error: calxgloss_types::persist::PersistError) -> Self {
        use calxgloss_types::persist::PersistError;
        match error {
            PersistError::NotFound { path } => Self::NotFound { path },
            PersistError::Io { source, .. } => Self::Io(source),
            PersistError::Json { source, .. } => Self::Json(source),
        }
    }
}

pub type Result<T> = std::result::Result<T, FloatsimdError>;
