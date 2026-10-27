//! Error types for the calxgloss-controlflow crate.
//!
//! This module defines `ControlFlowError`, the unified error type used
//! throughout the control-flow detection crate for decompiler fetches,
//! detector runs, and JSON persistence.

use thiserror::Error;

/// Errors that can occur during control-flow detection operations.
#[derive(Debug, Error)]
pub enum ControlFlowError {
    /// A read from the analysis engine, through the analysis seam, failed.
    #[error("engine error: {0}")]
    Engine(#[from] calxgloss_decomp::EngineError),

    /// An I/O error occurred while reading or writing detection results.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// A JSON serialization or deserialization error occurred.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// No persisted control-flow result exists at the requested path.
    #[error("control-flow result not found: {}", .path.display())]
    NotFound { path: std::path::PathBuf },

    /// A function name was empty or unparseable.
    #[error("empty function name")]
    EmptyFunctionName,

    /// Too many of the program's functions failed to decompile for the
    /// scan to be trusted. A high skip rate is the signature of the seam
    /// answering about the wrong program. The skip-rate breaker is a
    /// fuse, not a post-mortem: it aborts the scan rather than letting
    /// it persist a record that looks clean but is not.
    #[error("the engine failed to decompile {failed} of {total} functions")]
    DecompileBreaker { failed: usize, total: usize },

    /// The control-flow scan of one target binary failed.
    #[error("control-flow scan failed for '{binary}': {reason}")]
    ScanFailed { binary: String, reason: String },
}

/// Maps the shared JSON store's errors onto this crate's error type: the
/// store's not-found becomes [`ControlFlowError::NotFound`], and its I/O and
/// JSON errors become the existing I/O and JSON variants.
impl From<calxgloss_types::persist::PersistError> for ControlFlowError {
    fn from(error: calxgloss_types::persist::PersistError) -> Self {
        use calxgloss_types::persist::PersistError;
        match error {
            PersistError::NotFound { path } => Self::NotFound { path },
            PersistError::Io { source, .. } => Self::Io(source),
            PersistError::Json { source, .. } => Self::Json(source),
        }
    }
}

pub type Result<T> = std::result::Result<T, ControlFlowError>;
