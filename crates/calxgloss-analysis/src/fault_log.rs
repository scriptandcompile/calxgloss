//! Fault event logger for persisting detected faults to disk.
//!
//! This module provides [`FaultLogger`] for persisting translation fault events
//! to `re/analysis/fault_log.json`.
//!
//! # Purpose
//!
//! Track all detected faults during translation — including context-window
//! exceeded, hallucination, infinite loops, behavior divergence, and resource
//! exhaustion.  The log file can be analyzed for patterns: which DLLs/functions
//! are most prone to which faults, average time to recovery, etc.
//!
//! # File Format
//!
//! The file is a JSON object matching [`calxgloss_types::FaultLog`]:
//!
//! ```json
//! {
//!   "entries": [
//!     {
//!       "dll": "game_logic.dll",
//!       "function": "DrawSprite",
//!       "attempt": 3,
//!       "strategy": "compile_fix",
//!       "category": "context_window_exceeded",
//!       "severity": "error",
//!       "description": "LLM response (150000 chars) exceeded model limit (131072 chars) by 18928 chars",
//!       "recovery": "Split function into 7 basic-block chunks and retry with focused context",
//!       "timestamp": 1725000000,
//!       "metadata": {
//!         "response_size": 150000,
//!         "limit": 131072,
//!         "overflow_chars": 18928,
//!         "has_truncation_signal": false,
//!         "disassembly_lines": 200,
//!         "suggested_chunks": null
//!       }
//!     }
//!   ]
//! }
//! ```
//!
//! # Example
//!
//! ```no_run
//! use calxgloss_analysis::FaultLogger;
//! use calxgloss_types::{ContextWindowFault, FaultEvent};
//!
//! let logger = FaultLogger::new("/path/to/workspace");
//!
//! let fault = ContextWindowFault::response_exceeds_limit(150_000, 131_072, 200);
//! let event = FaultEvent::context_window_exceeded(
//!     "game_logic.dll",
//!     "DrawSprite",
//!     3,
//!     "compile_fix",
//!     &fault,
//! );
//! logger.record(event);
//! ```

use calxgloss_types::FaultEvent;
use tracing::{debug, warn};

/// Logger for fault events.
///
/// Each call to [`record`](Self::record) appends a fault event to the
/// in-memory log and flushes it to the JSON file on disk.
///
/// The file path is `<workspace>/re/analysis/fault_log.json`.
/// The directory structure is created automatically if it does not exist.
#[derive(Debug, Clone)]
pub struct FaultLogger {
    /// Base workspace path where `re/analysis/` resides.
    workspace: std::path::PathBuf,
}

impl FaultLogger {
    /// Create a new logger targeting the given workspace directory.
    ///
    /// # Arguments
    ///
    /// * `workspace` — The workspace root path. The log file will be written
    ///   to `<workspace>/re/analysis/fault_log.json`.
    pub fn new(workspace: impl Into<std::path::PathBuf>) -> Self {
        Self {
            workspace: workspace.into(),
        }
    }

    /// Record a single fault event.
    ///
    /// This appends the event to the in-memory log and persists the entire
    /// log to disk. If persistence fails, the event is still kept in memory
    /// and a warning is emitted.
    pub fn record(&self, event: FaultEvent) {
        let log_path = self.log_path();

        // Try to read existing log
        let mut log = match std::fs::read_to_string(&log_path) {
            Ok(contents) => match serde_json::from_str(&contents) {
                Ok(existing) => existing,
                Err(e) => {
                    warn!(
                        path = ?log_path,
                        error = %e,
                        "Failed to parse existing fault log, starting fresh"
                    );
                    calxgloss_types::FaultLog::new()
                }
            },
            Err(_) => calxgloss_types::FaultLog::new(),
        };

        // Add the event
        log.add_entry(event);

        // Persist
        if let Err(e) = self.persist(&log) {
            warn!(error = %e, "Failed to persist fault log to disk");
        } else {
            debug!(
                dll = %log.entries.last().map(|e| &e.dll).unwrap_or(&"".to_string()),
                function = %log.entries.last().map(|e| &e.function).unwrap_or(&"".to_string()),
                category = ?log.entries.last().map(|e| &e.category).unwrap_or(&calxgloss_types::FaultCategory::ContextWindowExceeded),
                "Recorded fault event"
            );
        }
    }

    /// Load the current log from disk without adding new events.
    ///
    /// Returns [`None`] if the file does not exist or cannot be parsed.
    pub fn load(&self) -> Option<calxgloss_types::FaultLog> {
        let log_path = self.log_path();
        std::fs::read_to_string(&log_path)
            .ok()
            .and_then(|contents| serde_json::from_str(&contents).ok())
    }

    /// Persist the in-memory log to the JSON file.
    fn persist(&self, log: &calxgloss_types::FaultLog) -> std::io::Result<()> {
        let log_path = self.log_path();

        // Ensure the directory exists
        if let Some(parent) = log_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Serialize with indentation for readability
        let contents = serde_json::to_string_pretty(log)?;
        std::fs::write(&log_path, contents)?;

        Ok(())
    }

    /// Compute aggregated statistics from the current log.
    ///
    /// This is a convenience method that loads the log and calls
    /// [`compute_stats`](calxgloss_types::FaultLog::compute_stats).
    pub fn compute_stats(&self) -> Option<calxgloss_types::FaultStats> {
        let log = self.load()?;
        Some(log.compute_stats())
    }

    /// Get the path to the fault log JSON file.
    fn log_path(&self) -> std::path::PathBuf {
        self.workspace
            .join("re")
            .join("analysis")
            .join("fault_log.json")
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_workspace(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("calxgloss-test-faults-{}", name));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_logger_create() {
        let ws = temp_workspace("create");
        let logger = FaultLogger::new(&ws);
        assert_eq!(logger.workspace, ws);
    }

    #[test]
    fn test_logger_record_and_load() {
        let ws = temp_workspace("record_and_load");
        let logger = FaultLogger::new(&ws);

        let fault = calxgloss_types::ContextWindowFault::response_exceeds_limit(
            150_000, 131_072, 200,
        );
        let event = FaultEvent::context_window_exceeded(
            "test.dll",
            "entry",
            1,
            "initial",
            &fault,
        );
        logger.record(event);

        let log = logger.load().expect("log should exist");
        assert_eq!(log.entries.len(), 1);
        assert_eq!(log.entries[0].dll, "test.dll");
        assert_eq!(log.entries[0].function, "entry");
    }

    #[test]
    fn test_logger_multiple_entries() {
        let ws = temp_workspace("multiple_entries");
        let logger = FaultLogger::new(&ws);

        for i in 1..=5 {
            let fault = calxgloss_types::ContextWindowFault::response_exceeds_limit(
                150_000 + i * 10_000,
                131_072,
                200,
            );
            logger.record(FaultEvent::context_window_exceeded(
                "game_logic.dll",
                "func",
                i as u32,
                "compile_fix",
                &fault,
            ));
        }

        let log = logger.load().expect("log should exist");
        assert_eq!(log.entries.len(), 5);
    }

    #[test]
    fn test_logger_stats_computation() {
        let ws = temp_workspace("stats");
        let logger = FaultLogger::new(&ws);

        logger.record(FaultEvent::context_window_exceeded(
            "a.dll",
            "func_a",
            1,
            "initial",
            &calxgloss_types::ContextWindowFault::response_exceeds_limit(200_000, 131_072, 100),
        ));
        logger.record(FaultEvent::context_window_exceeded(
            "b.dll",
            "func_b",
            1,
            "initial",
            &calxgloss_types::ContextWindowFault::response_exceeds_limit(150_000, 131_072, 80),
        ));

        let stats = logger.compute_stats().expect("stats should exist");
        assert_eq!(stats.total_entries, 2);
        assert_eq!(stats.by_dll.len(), 2);
        assert_eq!(stats.total_errors, 2);
    }

    #[test]
    fn test_logger_load_nonexistent() {
        let ws = temp_workspace("nonexistent").join("nonexistent_subdir");
        let logger = FaultLogger::new(&ws);
        assert!(logger.load().is_none());
    }

    #[test]
    fn test_logger_persists_across_instances() {
        let ws = temp_workspace("persist");
        let logger1 = FaultLogger::new(&ws);
        logger1.record(FaultEvent::context_window_exceeded(
            "persist_test.dll",
            "entry",
            1,
            "initial",
            &calxgloss_types::ContextWindowFault::response_exceeds_limit(
                150_000, 131_072, 100,
            ),
        ));

        let logger2 = FaultLogger::new(&ws);
        let log = logger2.load().expect("should load from disk");
        assert_eq!(log.entries.len(), 1);
    }

    #[test]
    fn test_log_path_construction() {
        let ws = std::path::PathBuf::from("/workspace");
        let logger = FaultLogger::new(ws.clone());
        let log_path = logger.log_path();
        assert_eq!(
            log_path,
            ws.join("re").join("analysis").join("fault_log.json")
        );
    }

    #[test]
    fn test_load_corrupted_file() {
        let ws = temp_workspace("corrupted");
        let logger = FaultLogger::new(&ws);

        let log_path = logger.log_path();
        std::fs::create_dir_all(log_path.parent().unwrap()).unwrap();
        std::fs::write(&log_path, "not valid json {{{").unwrap();

        assert!(logger.load().is_none());

        logger.record(FaultEvent::context_window_exceeded(
            "recovery.dll",
            "entry",
            1,
            "recovery",
            &calxgloss_types::ContextWindowFault::response_exceeds_limit(512, 256, 10),
        ));

        let log = logger.load().expect("should load after recovery");
        assert_eq!(log.entries.len(), 1);
    }
}
