//! Failure surface for the error-handling evidence crate.
//!
//! The scan fails in exactly two ways of its own: the listing could
//! not be read at all, or more than half of the listing's functions
//! failed to decompile — a skip-rate trip. Everything else the scan
//! touches is already an [`EngineError`] (an engine not found, a
//! decompile that failed for one function is skipped and counted, not
//! surfaced as a failure); the persistor adds the shared store's
//! three kinds, mapped below to keep a missing document distinct from
//! a corrupt one.

use thiserror::Error;

/// Errors that can occur during error-handling evidence scanning and
/// persistence.
#[derive(Debug, Error)]
pub enum ErrhandlingError {
    /// An engine read through the decompiler seam failed: the listing
    /// could not be read, or the engine answered wrongly. The scan
    /// makes no claim about why the seam failed beyond what the seam
    /// itself reported.
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

    /// More than half of the listing's functions failed to decompile.
    /// That is the signature of the bridge answering from the wrong
    /// program, and a scan that skipped its way through the whole
    /// listing would persist a phantom-clean record: no findings is
    /// indistinguishable from a binary without the idiom. The scan
    /// aborts with the counts instead (issue #71), telling the
    /// operator to verify the open program before trusting anything
    /// this artifact claims.
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
/// its I/O and JSON errors fold into the existing pass-through
/// variants.
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
