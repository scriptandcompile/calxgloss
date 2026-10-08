//! Runtime server lifecycle controls.
//!
//! Holds the reload handle for the process's tracing `EnvFilter` so the
//! `PATCH /api/server/log-level` endpoint can change verbosity while the
//! server runs. The handle is created by the CLI's logging init and shared
//! into server state at startup.

use tracing_subscriber::EnvFilter;
use tracing_subscriber::Registry;
use tracing_subscriber::reload::Handle;

/// The log levels the runtime endpoint accepts — the same vocabulary the
/// CLI verbosity flags map to.
pub(crate) const VALID_LOG_LEVELS: [&str; 6] = ["off", "error", "warn", "info", "debug", "trace"];

/// Errors from the runtime lifecycle controls.
#[derive(Debug, thiserror::Error)]
pub enum LifecycleError {
    /// The reloadable filter layer is gone — the global subscriber it was
    /// installed into no longer exists.
    #[error("failed to reload log filter: {0}")]
    FilterReload(#[from] tracing_subscriber::reload::Error),
}

/// Handle for changing the process's tracing verbosity at runtime.
///
/// Wraps the `reload` handle of the `EnvFilter` installed as the process's
/// global tracing filter. Changes are **process-lifetime only**: nothing is
/// written to disk, and the next start re-reads the CLI verbosity flags.
#[derive(Clone)]
pub struct LogLevelControl {
    handle: Handle<EnvFilter, Registry>,
}

impl LogLevelControl {
    /// Wrap the reload handle of the `EnvFilter` the CLI's logging init
    /// installed as the global subscriber's filter layer.
    pub fn new(handle: Handle<EnvFilter, Registry>) -> Self {
        Self { handle }
    }

    /// Normalize and validate a level name against the accepted vocabulary.
    ///
    /// Returns the lowercase level name on success, `None` for anything
    /// outside `off`/`error`/`warn`/`info`/`debug`/`trace`.
    pub fn validate(level: &str) -> Option<String> {
        let normalized = level.trim().to_ascii_lowercase();
        VALID_LOG_LEVELS
            .contains(&normalized.as_str())
            .then_some(normalized)
    }

    /// Reload the global filter so only records at `level` and above are
    /// emitted. `level` must already be validated.
    pub fn apply(&self, level: &str) -> Result<(), LifecycleError> {
        self.handle
            .modify(|filter| *filter = EnvFilter::new(level))
            .map_err(LifecycleError::FilterReload)
    }
}
