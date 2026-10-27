//! Error types for the calxgloss-consts crate.
//!
//! This module defines `ConstError`, the one error type the constant
//! detection crate uses everywhere: for decompiler fetches, detector
//! runs, and JSON persistence.

use thiserror::Error;

/// Errors that can occur during constant detection operations.
#[derive(Debug, Error)]
pub enum ConstError {
    /// A read by the analysis engine through the seam failed.
    #[error("engine error: {0}")]
    Engine(#[from] calxgloss_decomp::EngineError),

    /// An I/O error occurred while reading or writing detection results.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// A JSON serialization or deserialization error occurred.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// No persisted constant result exists at the requested path.
    #[error("constant result not found: {}", .path.display())]
    NotFound { path: std::path::PathBuf },

    /// A function name was empty or unparseable.
    #[error("empty function name")]
    EmptyFunctionName,

    /// Too many of the program's functions failed to decompile, so the
    /// scan's result cannot be trusted. A high failure rate is the
    /// signature of the seam answering about the wrong program. The
    /// skip-rate breaker aborts the scan instead of persisting a
    /// record that looks clean but is not.
    #[error("the engine failed to decompile {failed} of {total} functions")]
    DecompileBreaker { failed: usize, total: usize },

    /// A constant scan failed for a DLL.
    #[error("constant scan failed for '{binary}': {reason}")]
    ScanFailed { binary: String, reason: String },
}

/// Converts the shared JSON store's errors into this crate's error
/// type. The store's not-found error becomes [`ConstError::NotFound`];
/// its I/O and JSON errors become the matching pass-through variants
/// above.
impl From<calxgloss_types::persist::PersistError> for ConstError {
    fn from(error: calxgloss_types::persist::PersistError) -> Self {
        use calxgloss_types::persist::PersistError;
        match error {
            PersistError::NotFound { path } => Self::NotFound { path },
            PersistError::Io { source, .. } => Self::Io(source),
            PersistError::Json { source, .. } => Self::Json(source),
        }
    }
}

pub type Result<T> = std::result::Result<T, ConstError>;
