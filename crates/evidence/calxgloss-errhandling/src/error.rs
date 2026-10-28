//! The failure surface of the error-handling evidence scan.
//!
//! The scan fails in exactly two ways of its own. The listing could
//! not be read at all, or more than half of the listing's functions
//! failed to decompile, which trips the skip-rate breaker. Everything
//! else the scan touches is already an
//! [`EngineError`](calxgloss_decomp::EngineError) — the analysis
//! engine, for example, cannot find what a read asked for. A
//! decompile that failed for one function is skipped and counted, not
//! surfaced as a failure. The persistor adds the shared store's three
//! error kinds; the conversion below maps them so a missing document
//! stays distinct from a corrupt one.

use thiserror::Error;

/// Errors that can occur during error-handling evidence scanning and
/// persistence.
#[derive(Debug, Error)]
pub enum ErrhandlingError {
    /// A read through the seam to the analysis engine failed: the
    /// listing could not be read, or the analysis engine answered
    /// wrongly. The scan says no more about why the seam failed than
    /// the seam itself reported.
    #[error("engine error: {0}")]
    Engine(#[from] calxgloss_decomp::EngineError),

    /// An I/O error occurred while reading or writing the evidence
    /// document.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// A JSON serialization or deserialization error occurred.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// No persisted evidence document exists at the requested path.
    #[error("error-handling result not found: {}", .path.display())]
    NotFound { path: std::path::PathBuf },

    /// More than half of the listing's functions failed to
    /// decompile. That is the signature of the seam answering about
    /// the wrong program. A scan that skipped its way through the
    /// whole listing would otherwise persist a record that looks
    /// clean but is not: no findings looks exactly like a binary
    /// without the idiom. The scan aborts with the counts instead
    /// (issue #71) and tells the operator to verify the open program
    /// before trusting anything this artifact claims.
    #[error("the engine failed to decompile {failed} of {total} functions")]
    DecompileBreaker {
        /// How many decompiles failed before the scan gave up.
        failed: usize,
        /// How many functions the listing holds.
        total: usize,
    },
}

/// Maps the shared JSON store's errors onto this crate's error type:
/// the store's not-found becomes [`ErrhandlingError::NotFound`], and
/// its I/O and JSON errors become the pass-through variants above.
impl From<calxgloss_types::persist::PersistError> for ErrhandlingError {
    fn from(value: calxgloss_types::persist::PersistError) -> Self {
        use calxgloss_types::persist::PersistError;
        match value {
            PersistError::NotFound { path } => Self::NotFound { path },
            PersistError::Io { source, .. } => Self::Io(source),
            PersistError::Json { source, .. } => Self::Json(source),
        }
    }
}

/// Convenience alias for results in this crate.
pub type Result<T> = std::result::Result<T, ErrhandlingError>;
