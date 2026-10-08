//! Runtime server lifecycle controls.
//!
//! Holds the reload handle for the process's tracing `EnvFilter` so the
//! `PATCH /api/server/log-level` endpoint can change verbosity while the
//! server runs. The handle is created by the CLI's logging init and shared
//! into server state at startup.

use tracing_subscriber::EnvFilter;
use tracing_subscriber::Registry;
use tracing_subscriber::reload::Handle;

/// Errors from the runtime lifecycle controls.
#[derive(Debug, thiserror::Error)]
pub enum LifecycleError {
    /// The reloadable filter layer is gone — the global subscriber it was
    /// installed into no longer exists.
    #[error("failed to reload log filter: {0}")]
    FilterReload(#[from] tracing_subscriber::reload::Error),
}

/// A tracing verbosity level the runtime endpoint accepts — the same
/// vocabulary the CLI verbosity flags map to.
///
/// A closed set on purpose: the endpoint rejects a name outside it with 400
/// instead of handing a typo to `EnvFilter`, which would silently install a
/// permissive filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    /// No records are emitted.
    Off,
    /// `error` and above.
    Error,
    /// `warn` and above — what the CLI installs with no verbosity flags.
    Warn,
    /// `info` and above.
    Info,
    /// `debug` and above.
    Debug,
    /// Everything, including `trace`.
    Trace,
}

impl LogLevel {
    /// Every accepted level, quietest first — the order the UI lists them in.
    pub const ALL: [LogLevel; 6] = [
        LogLevel::Off,
        LogLevel::Error,
        LogLevel::Warn,
        LogLevel::Info,
        LogLevel::Debug,
        LogLevel::Trace,
    ];

    /// The name this level is accepted and reported as.
    pub fn as_str(self) -> &'static str {
        match self {
            LogLevel::Off => "off",
            LogLevel::Error => "error",
            LogLevel::Warn => "warn",
            LogLevel::Info => "info",
            LogLevel::Debug => "debug",
            LogLevel::Trace => "trace",
        }
    }

    /// Parse a level name, case-insensitively and tolerating surrounding
    /// whitespace. `None` for anything outside the closed set.
    pub fn parse(name: &str) -> Option<LogLevel> {
        let normalized = name.trim().to_ascii_lowercase();
        Self::ALL
            .iter()
            .copied()
            .find(|level| level.as_str() == normalized)
    }

    /// The accepted names, quietest first — for error messages that must
    /// tell the operator what is valid.
    pub fn names() -> [&'static str; 6] {
        Self::ALL.map(|level| level.as_str())
    }
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
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

    /// Reload the global filter so only records at `level` and above are
    /// emitted.
    pub fn apply(&self, level: LogLevel) -> Result<(), LifecycleError> {
        self.handle
            .modify(|filter| *filter = EnvFilter::new(level.as_str()))
            .map_err(LifecycleError::FilterReload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parsing is case-insensitive and whitespace-tolerant, and anything
    /// outside the closed set is rejected rather than passed to the filter.
    #[test]
    fn level_names_round_trip_and_reject_unknown() {
        assert_eq!(LogLevel::parse("DEBUG"), Some(LogLevel::Debug));
        assert_eq!(LogLevel::parse("  warn "), Some(LogLevel::Warn));
        for bad in ["verbose", "everything", "", "warn error"] {
            assert_eq!(LogLevel::parse(bad), None, "'{bad}' is not a level");
        }
        for level in LogLevel::ALL {
            assert_eq!(LogLevel::parse(level.as_str()), Some(level));
            assert_eq!(level.to_string(), level.as_str());
        }
    }

    /// Applying a level reloads the filter; the handle stays usable for
    /// further changes for the rest of the process's life.
    #[test]
    fn applying_a_level_reloads_the_filter_repeatedly() {
        let (_filter, handle) = tracing_subscriber::reload::Layer::new(EnvFilter::new("warn"));
        let control = LogLevelControl::new(handle);
        control.apply(LogLevel::Debug).expect("apply debug");
        control.apply(LogLevel::Trace).expect("apply trace");
        control.apply(LogLevel::Off).expect("apply off");
    }
}
