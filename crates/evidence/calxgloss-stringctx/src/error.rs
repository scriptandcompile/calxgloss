//! Error types for the calxgloss-stringctx crate.
//!
//! This module defines `StringCtxError`, the one error type the whole
//! string-context crate uses. It covers fetches of decompiler output and
//! the string listing, classification and mapping work, and JSON
//! persistence.

use thiserror::Error;

/// Errors that can occur during string-context operations.
#[derive(Debug, Error)]
pub enum StringCtxError {
    /// A read through the seam from the analysis engine failed.
    #[error("engine error: {0}")]
    Engine(#[from] calxgloss_decomp::EngineError),

    /// An I/O error occurred while reading or writing string-context results.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// A JSON serialization or deserialization error occurred.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// No persisted string-context result exists at the requested path.
    #[error("string context result not found: {}", .path.display())]
    NotFound { path: std::path::PathBuf },

    /// A function name was empty or unparseable.
    #[error("empty function name")]
    EmptyFunctionName,

    /// More than half of the program's functions failed to
    /// decompile. A high skip rate is the signature of the seam
    /// answering about the wrong program. The skip-rate breaker is a
    /// fuse, not a post-mortem: it aborts the scan rather than let it
    /// persist a record that looks clean but is not.
    #[error("the engine failed to decompile {failed} of {total} functions")]
    DecompileBreaker { failed: usize, total: usize },

    /// A string-context scan failed for a DLL.
    #[error("string context scan failed for '{binary}': {reason}")]
    ScanFailed { binary: String, reason: String },
}

/// Maps the shared JSON store's errors onto this crate's error type: the
/// store's not-found error becomes [`StringCtxError::NotFound`], and its
/// I/O and JSON errors become the existing pass-through variants.
impl From<calxgloss_types::persist::PersistError> for StringCtxError {
    fn from(error: calxgloss_types::persist::PersistError) -> Self {
        use calxgloss_types::persist::PersistError;
        match error {
            PersistError::NotFound { path } => Self::NotFound { path },
            PersistError::Io { source, .. } => Self::Io(source),
            PersistError::Json { source, .. } => Self::Json(source),
        }
    }
}

pub type Result<T> = std::result::Result<T, StringCtxError>;
