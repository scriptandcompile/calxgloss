//! Prompt strategy benchmark logger.
//!
//! This module provides [`PromptStrategyLogger`] for persisting translation
//! attempt benchmarks to `re/analysis/prompt_strategy_log.json`.
//!
//! # Purpose
//!
//! tracking pass rates per retry strategy
//! per DLL category. This logger records every attempt outcome and
//! stores it in a JSON file that can be read back to compute aggregate
//! statistics (pass rate, fail rate, etc.) for analysis.
//!
//! # File Format
//!
//! The file is a JSON object matching [`calxgloss_types::PromptStrategyLog`]:
//!
//! ```json
//! {
//!   "entries": [
//!     {
//!       "dll": "game_logic.dll",
//!       "dll_category": "ProjectSpecific",
//!       "strategy": "compile_fix",
//!       "success": false,
//!       "attempt": 1,
//!       "timestamp": 1725000000
//!     }
//!   ]
//! }
//! ```
//!
//! # Example
//!
//! ```no_run
//! use calxgloss_analysis::PromptStrategyLogger;
//! use calxgloss_types::{PromptStrategyEntry, DllCategory};
//!
//! let logger = PromptStrategyLogger::new("/path/to/workspace");
//!
//! let entry = PromptStrategyEntry::new(
//!     "game_logic.dll",
//!     DllCategory::ProjectSpecific,
//!     "compile_fix",
//!     true,
//!     1,
//! );
//! logger.record(entry);
//! ```

use calxgloss_types::PromptStrategyEntry;
use tracing::{debug, warn};

/// Logger for prompt strategy benchmark entries.
///
/// Each call to [`record`](Self::record) appends a benchmark entry to the
/// in-memory log and flushes it to the JSON file on disk.
///
/// The file path is `<workspace>/re/analysis/prompt_strategy_log.json`.
/// The directory structure is created automatically if it does not exist.
#[derive(Debug, Clone)]
pub struct PromptStrategyLogger {
    /// Base workspace path where `re/analysis/` resides.
    workspace: std::path::PathBuf,
}

impl PromptStrategyLogger {
    /// Create a new logger targeting the given workspace directory.
    ///
    /// # Arguments
    ///
    /// * `workspace` — The workspace root path. The log file will be written
    ///   to `<workspace>/re/analysis/prompt_strategy_log.json`.
    pub fn new(workspace: impl Into<std::path::PathBuf>) -> Self {
        Self {
            workspace: workspace.into(),
        }
    }

    /// Record a single benchmark entry.
    ///
    /// This appends the entry to the in-memory log and persists the entire
    /// log to disk. If persistence fails, the entry is still kept in memory
    /// and a warning is emitted.
    pub fn record(&self, entry: PromptStrategyEntry) {
        let log_path = self.log_path();

        // Try to read existing log
        let mut log = match std::fs::read_to_string(&log_path) {
            Ok(contents) => match serde_json::from_str(&contents) {
                Ok(existing) => existing,
                Err(e) => {
                    warn!(
                        path = ?log_path,
                        error = %e,
                        "Failed to parse existing benchmark log, starting fresh"
                    );
                    calxgloss_types::PromptStrategyLog::new()
                }
            },
            Err(_) => calxgloss_types::PromptStrategyLog::new(),
        };

        // Add the entry
        log.add_entry(entry);

        // Persist
        if let Err(e) = self.persist(&log) {
            warn!(error = %e, "Failed to persist benchmark log to disk");
        } else {
            debug!(
                dll = %log.entries.last().map(|e| &e.dll).unwrap_or(&"".to_string()),
                strategy = %log.entries.last().map(|e| &e.strategy).unwrap_or(&"".to_string()),
                success = log.entries.last().map(|e| e.success).unwrap_or(false),
                "Recorded benchmark entry"
            );
        }
    }

    /// Load the current log from disk without adding new entries.
    ///
    /// Returns [`None`] if the file does not exist or cannot be parsed.
    pub fn load(&self) -> Option<calxgloss_types::PromptStrategyLog> {
        let log_path = self.log_path();
        std::fs::read_to_string(&log_path)
            .ok()
            .and_then(|contents| serde_json::from_str(&contents).ok())
    }

    /// Persist the in-memory log to the JSON file.
    fn persist(&self, log: &calxgloss_types::PromptStrategyLog) -> std::io::Result<()> {
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
    /// [`compute_stats`](calxgloss_types::PromptStrategyLog::compute_stats).
    pub fn compute_stats(&self) -> Option<calxgloss_types::PromptStrategyStats> {
        let log = self.load()?;
        Some(log.compute_stats())
    }

    /// Get the path to the benchmark log JSON file.
    fn log_path(&self) -> std::path::PathBuf {
        self.workspace
            .join("re")
            .join("analysis")
            .join("prompt_strategy_log.json")
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_workspace(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("calxgloss-test-benchmark-{}", name));
        // Clean up any previous test artifacts
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_logger_create() {
        let ws = temp_workspace("create");
        let logger = PromptStrategyLogger::new(&ws);
        assert_eq!(logger.workspace, ws);
    }

    #[test]
    fn test_logger_record_and_load() {
        let ws = temp_workspace("record_and_load");
        let logger = PromptStrategyLogger::new(&ws);

        let entry = PromptStrategyEntry::new(
            "test.dll",
            calxgloss_types::DllCategory::ProjectSpecific,
            "compile_fix",
            true,
            1,
        );
        logger.record(entry);

        let log = logger.load().expect("log should exist");
        assert_eq!(log.entries.len(), 1);
        assert!(log.entries[0].success);
    }

    #[test]
    fn test_logger_multiple_entries() {
        let ws = temp_workspace("multiple_entries");
        let logger = PromptStrategyLogger::new(&ws);

        for i in 1..=5 {
            logger.record(PromptStrategyEntry::new(
                "game_logic.dll",
                calxgloss_types::DllCategory::ProjectSpecific,
                "compile_fix",
                i % 2 == 0, // alternate success
                i,
            ));
        }

        let log = logger.load().expect("log should exist");
        assert_eq!(log.entries.len(), 5);

        let stats = log.compute_stats();
        assert_eq!(stats.total_entries, 5);
        assert_eq!(stats.total_successes, 2); // attempts 2 and 4
        assert_eq!(stats.total_failures, 3);
    }

    #[test]
    fn test_logger_stats_computation() {
        let ws = temp_workspace("stats");
        let logger = PromptStrategyLogger::new(&ws);

        // Mixed strategies and categories
        logger.record(PromptStrategyEntry::new(
            "a.dll",
            calxgloss_types::DllCategory::ProjectSpecific,
            "compile_fix",
            true,
            1,
        ));
        logger.record(PromptStrategyEntry::new(
            "a.dll",
            calxgloss_types::DllCategory::ProjectSpecific,
            "test_fix",
            false,
            2,
        ));
        logger.record(PromptStrategyEntry::new(
            "b.dll",
            calxgloss_types::DllCategory::MicrosoftSdk,
            "compile_fix",
            true,
            1,
        ));

        let stats = logger.compute_stats().expect("stats should exist");
        assert_eq!(stats.total_entries, 3);
        assert_eq!(stats.total_successes, 2);
        assert_eq!(stats.by_category.len(), 2);
        assert_eq!(stats.by_strategy.len(), 2);
    }

    #[test]
    fn test_logger_load_nonexistent() {
        let ws = temp_workspace("nonexistent").join("nonexistent_subdir");
        let logger = PromptStrategyLogger::new(&ws);
        assert!(logger.load().is_none());
    }

    #[test]
    fn test_logger_persists_across_instances() {
        let ws = temp_workspace("persist");
        let logger1 = PromptStrategyLogger::new(&ws);
        logger1.record(PromptStrategyEntry::new(
            "persist_test.dll",
            calxgloss_types::DllCategory::ProjectSpecific,
            "initial",
            true,
            1,
        ));

        // A new logger instance should read the same file
        let logger2 = PromptStrategyLogger::new(&ws);
        let log = logger2.load().expect("should load from disk");
        assert_eq!(log.entries.len(), 1);
        assert_eq!(log.entries[0].dll, "persist_test.dll");
    }

    #[test]
    fn test_log_path_construction() {
        let ws = std::path::PathBuf::from("/workspace");
        let logger = PromptStrategyLogger::new(ws.clone());
        let log_path = logger.log_path();
        assert_eq!(
            log_path,
            ws.join("re")
                .join("analysis")
                .join("prompt_strategy_log.json")
        );
    }

    #[test]
    fn test_load_corrupted_file() {
        let ws = temp_workspace("corrupted");
        let logger = PromptStrategyLogger::new(&ws);

        // Write invalid JSON
        let log_path = logger.log_path();
        std::fs::create_dir_all(log_path.parent().unwrap()).unwrap();
        std::fs::write(&log_path, "not valid json {{{").unwrap();

        // Loading should return None (corrupted file)
        assert!(logger.load().is_none());

        // Recording should start fresh
        logger.record(PromptStrategyEntry::new(
            "recovery.dll",
            calxgloss_types::DllCategory::ProjectSpecific,
            "recovery",
            true,
            1,
        ));

        let log = logger.load().expect("should load after recovery");
        assert_eq!(log.entries.len(), 1);
        assert_eq!(log.entries[0].dll, "recovery.dll");
    }
}
