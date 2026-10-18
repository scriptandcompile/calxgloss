//! Named failures for the Kuna engine integration.

/// Why a Kuna engine operation failed.
///
/// Every variant names what broke and, where the operator can act, says what
/// to do — raise a budget, repair a directive file — rather than surfacing an
/// upstream backtrace. Kuna is the only analysis engine (issue #214), so no
/// variant points at another one.
#[derive(Debug, thiserror::Error)]
pub enum KunaError {
    /// A target binary could not be loaded by the Kuna engine.
    #[error("the Kuna engine could not load {path}: {reason}")]
    LoadFailed {
        /// The target that failed to load.
        path: String,
        /// Kuna's own explanation for the failure.
        reason: String,
    },

    /// The embedded SLEIGH spec tree could not be unpacked to a writable
    /// cache directory, so no engine load can resolve a language.
    #[error("the Kuna engine could not unpack its embedded SLEIGH specs: {reason}")]
    SpecsUnavailable {
        /// Why every cache location was rejected.
        reason: String,
    },

    /// The engine thread is gone, so no further request can be answered.
    ///
    /// The thread exits when the last [`KunaSource`](crate::source::KunaSource)
    /// handle drops, or after a fatal load failure; either way the caller
    /// holds a handle to a program that is no longer running.
    #[error("the Kuna engine is no longer answering requests; its program thread has exited")]
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
         the panic was caught at the engine seam"
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
    #[error("the Kuna engine could not read the container tables of {path}: {reason}")]
    TablesUnreadable {
        /// The target whose tables were read.
        path: String,
        /// Why the read failed.
        reason: String,
    },

    /// The engine refused to decompile one function it knows exists.
    #[error("the Kuna engine could not decompile '{name}': {reason}")]
    DecompileFailed {
        /// The function the decompile named.
        name: String,
        /// Kuna's own per-function explanation.
        reason: String,
    },

    /// The engine stopped decompiling one function because a per-function
    /// budget tripped (issue #211).
    ///
    /// Kuna's watchdogs fail one function, not the run: the seam names
    /// which budget stopped it so the scan records the function as a
    /// per-function failure and keeps walking, and the operator can raise
    /// the budget in the `[analysis]` config block instead of losing the
    /// run to one obfuscated body.
    #[error(
        "the Kuna engine stopped decompiling '{name}': the {budget} budget tripped ({reason})\n\
         raise the budget in the [analysis] config block"
    )]
    DecompileBudgetExceeded {
        /// The function the decompile named.
        name: String,
        /// Which watchdog stopped it: `instruction`, `time`, or `memory`.
        budget: &'static str,
        /// Kuna's own explanation for the trip.
        reason: String,
    },

    /// A budget knob the platform cannot enforce, refused at load.
    ///
    /// The memory watchdog decides by watching the process's resident set;
    /// where that cannot be read the limit could never fire, so the knob
    /// is refused by name rather than armed as a silent no-op — the same
    /// refusal Kuna's CLI makes for `--max-fn-memory`.
    #[error(
        "the Kuna engine cannot enforce the {knob} budget on this platform: {reason}\n\
         drop the setting"
    )]
    BudgetUnsupported {
        /// The config knob that could not be armed.
        knob: &'static str,
        /// Why the platform cannot enforce it.
        reason: String,
    },

    /// No type in the engine's type manager carries the requested name.
    ///
    /// The seam maps this to the same `NotFound` a Ghidra miss becomes, so
    /// layout probes branch on one fact whichever engine answers.
    #[error("the Kuna engine's type manager has no type named '{name}'")]
    TypeNotFound {
        /// The type name that was asked for.
        name: String,
    },

    /// A named type exists but is not a structure, so no layout answers.
    #[error("the Kuna engine's type manager has no structure named '{name}'")]
    NotAStruct {
        /// The name that resolved to some other kind of type.
        name: String,
    },

    /// A named type exists but is not an enumeration, so no members answer.
    #[error("the Kuna engine's type manager has no enumeration named '{name}'")]
    NotAnEnum {
        /// The name that resolved to some other kind of type.
        name: String,
    },

    /// The requested byte range is not mapped in the loaded program.
    #[error("the Kuna engine has no mapped bytes at {address:#x} for {length} bytes")]
    MemoryUnmapped {
        /// The address the read started at.
        address: u64,
        /// The length the read asked for.
        length: usize,
    },

    /// A write-seam declaration the engine's own grammar refused to parse.
    ///
    /// The declaration never reached the directive plane: a write calxgloss
    /// can name but Kuna cannot parse is refused at the seam, where the
    /// caller still holds the text, rather than poisoning the replay file.
    #[error("the Kuna engine could not parse `{directive}`: {reason}")]
    DirectiveRejected {
        /// The declaration or type text the seam was given.
        directive: String,
        /// Kuna's own explanation for the refusal.
        reason: String,
    },

    /// A directive file on disk holds a line the directive grammar refuses.
    ///
    /// A half-understood directive file must never load as a quiet partial
    /// replay; the offending line is named so the file can be repaired.
    #[error("the directive file {path} is not readable at line {line}: {reason}")]
    DirectiveFileInvalid {
        /// The directive file that failed to parse.
        path: String,
        /// The 1-based line the grammar refused.
        line: usize,
        /// Why the line was refused.
        reason: String,
    },

    /// A struct record the directive plane cannot honestly regenerate.
    ///
    /// `add_struct_field` re-bodies the owning `typedef struct` record from
    /// its own text; a record carrying a shape that text cannot re-render —
    /// a bitfield — is named here rather than rewritten lossy.
    #[error("the directive plane cannot regenerate the record for type '{name}': {reason}")]
    DirectiveRegenerationFailed {
        /// The structure whose record could not be regenerated.
        name: String,
        /// Why the record could not be re-rendered.
        reason: String,
    },

    /// A directive file could not be read or written.
    #[error("the Kuna directive plane could not use {path}: {reason}")]
    Io {
        /// The path the file operation named.
        path: String,
        /// Why the operation failed.
        reason: String,
    },
}

/// The crate-wide result alias every Kuna entry point returns.
pub type Result<T> = std::result::Result<T, KunaError>;
