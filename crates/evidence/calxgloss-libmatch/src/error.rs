//! The failure surface of the known-library identification scan.
//!
//! This module defines `LibmatchError`, the one error type the
//! known-library identification crate reports. It covers a failed
//! read through the seam to the analysis engine, failed reading and
//! writing of the persisted document, the skip-rate breaker, and a
//! supplied signature database that cannot be read.

use thiserror::Error;

/// Errors that can occur during known-library identification operations.
#[derive(Debug, Error)]
pub enum LibmatchError {
    /// A read through the seam to the analysis engine failed.
    #[error("engine error: {0}")]
    Engine(#[from] calxgloss_decomp::EngineError),

    /// An I/O error occurred while reading or writing the scan's document.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// A JSON serialization or deserialization error occurred.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// No persisted known-library document exists at the requested path.
    #[error("libmatch result not found: {}", .path.display())]
    NotFound { path: std::path::PathBuf },

    /// More than half of the program's functions failed to
    /// decompile. A high skip rate is the signature of the seam
    /// answering about the wrong program. The skip-rate breaker is a
    /// fuse, not a post-mortem: it aborts the scan rather than let it
    /// persist a record that looks clean but is not.
    #[error("the engine failed to decompile {failed} of {total} functions")]
    DecompileBreaker { failed: usize, total: usize },

    /// A `--signatures` signature database file could not be read: it
    /// is missing, unreadable, or not a valid signature document. The
    /// error names the path so the operator knows which file to fix.
    /// A malformed database fails the run loudly rather than quietly
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
/// JSON errors become the pass-through variants above.
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
