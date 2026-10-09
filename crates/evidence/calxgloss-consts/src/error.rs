//! Error types for the calxgloss-consts crate.
//!
//! This module defines `ConstError`, the unified error type used
//! throughout the constant detection crate for decompiler fetches,
//! detector runs, and JSON persistence.

use thiserror::Error;

/// Errors that can occur during constant detection operations.
#[derive(Debug, Error)]
pub enum ConstError {
    /// A GhidraMCP request failed.
    #[error("GhidraMCP error: {0}")]
    Ghidra(#[from] calxgloss_ghidra::GhidraError),

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

    /// Too many of the program's functions failed to decompile for the
    /// scan to be trusted — the signature of the bridge answering from
    /// the wrong program. The skip-rate breaker aborts the scan rather
    /// than letting it persist a phantom-clean record.
    #[error(
        "Ghidra failed to decompile {failed} of {total} functions — is the right program open?"
    )]
    DecompileBreaker { failed: usize, total: usize },

    /// A constant scan failed for a DLL.
    #[error("constant scan failed for '{binary}': {reason}")]
    ScanFailed { binary: String, reason: String },
}

/// Maps the shared JSON store's errors onto this crate's error type: the
/// store's not-found becomes [`ConstError::NotFound`], and its I/O and
/// JSON errors fold into the existing pass-through variants.
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
