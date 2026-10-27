//! Error types for the calxgloss-algorithm crate.
//!
//! This module defines `AlgorithmError`, the one error type used
//! throughout the algorithm recognition crate — for decompiler and
//! string fetches, detector runs, and JSON persistence.

use thiserror::Error;

/// Errors that can occur during algorithm recognition.
#[derive(Debug, Error)]
pub enum AlgorithmError {
    /// A read from the analysis engine through the seam failed.
    #[error("engine error: {0}")]
    Engine(#[from] calxgloss_decomp::EngineError),

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

    /// Too many of the program's functions failed to decompile for the
    /// scan to be trusted — a high skip rate is the signature of reading
    /// the wrong program. The skip-rate breaker aborts the scan instead
    /// of persisting a record that looks clean but is not.
    #[error("the engine failed to decompile {failed} of {total} functions")]
    DecompileBreaker { failed: usize, total: usize },

    /// An algorithm recognition scan failed for one target binary.
    #[error("algorithm recognition scan failed for '{binary}': {reason}")]
    ScanFailed { binary: String, reason: String },

    /// A `--patterns` pattern database file could not be read: it is
    /// missing, unreadable, or not a valid pattern document. The error
    /// names the path so the operator knows which file to fix: a
    /// malformed database fails the run loudly instead of quietly
    /// reducing recognition to a partial set.
    #[error("could not read pattern database {}: {source}", .path.display())]
    PatternDatabase {
        path: std::path::PathBuf,
        #[source]
        source: calxgloss_types::persist::PersistError,
    },
}

/// Maps the shared JSON store's errors onto this crate's error type. The
/// store's not-found becomes [`AlgorithmError::NotFound`], and its I/O
/// and JSON errors become the existing pass-through variants. Pattern
/// database loading deliberately does not use this conversion — it maps
/// to [`AlgorithmError::PatternDatabase`] instead, so the failure names
/// the file the operator passed.
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
