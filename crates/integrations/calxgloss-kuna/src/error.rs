//! Named failures for the Kuna engine integration.

/// Why a Kuna engine operation failed.
///
/// Every variant names what broke and, where the fallback matters, points at
/// it: a Kuna failure under `--engine kuna` has to say that `--engine ghidra`
/// is the working path, rather than surfacing an upstream backtrace.
#[derive(Debug, thiserror::Error)]
pub enum KunaError {
    /// A target binary could not be loaded by the Kuna engine.
    #[error(
        "the Kuna engine could not load {path}: {reason}\n\
         the Kuna engine is a skeleton in this release; re-run with --engine ghidra \
         for the full pipeline"
    )]
    LoadFailed {
        /// The target that failed to load.
        path: String,
        /// Kuna's own explanation for the failure.
        reason: String,
    },

    /// The embedded SLEIGH spec tree could not be unpacked to a writable
    /// cache directory, so no engine load can resolve a language.
    #[error(
        "the Kuna engine could not unpack its embedded SLEIGH specs: {reason}\n\
         the Kuna engine is a skeleton in this release; re-run with --engine ghidra \
         for the full pipeline"
    )]
    SpecsUnavailable {
        /// Why every cache location was rejected.
        reason: String,
    },
}

/// The crate-wide result alias every Kuna entry point returns.
pub type Result<T> = std::result::Result<T, KunaError>;
