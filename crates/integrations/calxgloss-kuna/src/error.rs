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

    /// The engine thread is gone, so no further request can be answered.
    ///
    /// The thread exits when the last [`KunaSource`](crate::source::KunaSource)
    /// handle drops, or after a fatal load failure; either way the caller
    /// holds a handle to a program that is no longer running.
    #[error(
        "the Kuna engine is no longer answering requests; its program thread has exited\n\
         re-run with --engine ghidra for the full pipeline"
    )]
    EngineUnavailable,

    /// No function in the loaded program carries the requested name.
    #[error("the Kuna engine has no function named '{name}'")]
    FunctionNotFound {
        /// The name that was asked for.
        name: String,
    },

    /// The engine panicked inside one call, and the seam caught it.
    ///
    /// Kuna is a young engine; an upstream `unwrap` inside a listing or
    /// decompile must cost this process nothing. The engine thread runs
    /// every call inside `catch_unwind`, and the panic arrives here as a
    /// named failure — never a process abort (issue #206).
    #[error(
        "the Kuna engine panicked in `{call}`: {panic}\n\
         the panic was caught at the engine seam; re-run with --engine ghidra \
         for the full pipeline"
    )]
    EngineFault {
        /// The engine call that panicked.
        call: String,
        /// The panic payload, as far as it could be read.
        panic: String,
    },

    /// The target's import/export tables or image base could not be read.
    ///
    /// The Kuna source answers these seam reads from the same file the
    /// engine loaded, through the `object` crate; a file the engine parsed
    /// but these tables cannot is named here rather than answered empty.
    #[error(
        "the Kuna engine could not read the container tables of {path}: {reason}\n\
         re-run with --engine ghidra for the full pipeline"
    )]
    TablesUnreadable {
        /// The target whose tables were read.
        path: String,
        /// Why the read failed.
        reason: String,
    },

    /// The engine refused to decompile one function it knows exists.
    #[error(
        "the Kuna engine could not decompile '{name}': {reason}\n\
         re-run with --engine ghidra for the full pipeline"
    )]
    DecompileFailed {
        /// The function the decompile named.
        name: String,
        /// Kuna's own per-function explanation.
        reason: String,
    },
}

/// The crate-wide result alias every Kuna entry point returns.
pub type Result<T> = std::result::Result<T, KunaError>;
