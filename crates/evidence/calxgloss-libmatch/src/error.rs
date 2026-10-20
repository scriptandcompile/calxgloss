//! Error types for the calxgloss-libmatch crate.
//!
//! This module defines `LibmatchError`, the unified error type used
//! throughout the known-library identification crate for decompiler
//! fetches and JSON persistence.

use thiserror::Error;

/// Errors that can occur during known-library identification operations.
#[derive(Debug, Error)]
pub enum LibmatchError {
    /// An engine read through the analysis seam failed.
    #[error("engine error: {0}")]
    Engine(#[from] calxgloss_decomp::EngineError),

    /// An I/O error occurred while reading or writing libmatch results.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// A JSON serialization or deserialization error occurred.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// No persisted libmatch result exists at the requested path.
    #[error("libmatch result not found: {}", .path.display())]
    NotFound { path: std::path::PathBuf },

    /// Too many of the program's functions failed to decompile for the
    /// scan to be trusted — the signature of the engine answering from
    /// the wrong program. The skip-rate breaker aborts the scan rather
    /// than letting it persist a phantom-clean record.
    #[error("the engine failed to decompile {failed} of {total} functions")]
    DecompileBreaker { failed: usize, total: usize },

    /// A `--signatures` signature database file could not be read: it
    /// is missing, unreadable, or not a valid signature document. The
    /// path is named so the operator knows which file to fix — a
    /// malformed database fails the run loudly rather than silently
    /// degrading recognition to a partial set.
    #[error("could not read signature database {}: {source}", .path.display())]
    SignatureDatabase {
        path: std::path::PathBuf,
        #[source]
        source: calxgloss_types::persist::PersistError,
    },
}

/// Maps the shared JSON store's errors onto this crate's error type: the
/// store's not-found becomes [`LibmatchError::NotFound`], and its I/O and
/// JSON errors fold into the existing pass-through variants.
impl From<calxgloss_types::persist::PersistError> for LibmatchError {
    fn from(error: calxgloss_types::persist::PersistError) -> Self {
        use calxgloss_types::persist::PersistError;
        match error {
            PersistError::NotFound { path } => Self::NotFound { path },
            PersistError::Io { source, .. } => Self::Io(source),
            PersistError::Json { source, .. } => Self::Json(source),
        }
    }
}

pub type Result<T> = std::result::Result<T, LibmatchError>;
