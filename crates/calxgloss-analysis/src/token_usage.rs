//! Token usage logger for persisting per-attempt token counts.
//!
//! This module provides [`TokenUsageLogger`] for persisting translation
//! attempt token usage data to `re/analysis/token_usage.json`.
//!
//! # Purpose
//!
//! Track LLM token consumption across translation runs. This logger records
//! every attempt's token count and stores it in a JSON file that can be
//! analyzed for cost estimation, efficiency tracking, and context window
//! utilization analysis.
//!
//! # File Format
//!
//! The file is a JSON object matching [`calxgloss_types::TokenUsageLog`]:
//!
//! ```json
//! {
//!   "entries": [
//!     {
//!       "dll": "game_logic.dll",
//!       "function": "DrawSprite",
//!       "attempt": 1,
//!       "strategy": "initial",
//!       "tokens_used": 4096,
//!       "success": true,
//!       "timestamp": 1725000000
//!     }
//!   ]
//! }
//! ```
//!
//! # Example
//!
//! ```no_run
//! use calxgloss_analysis::TokenUsageLogger;
//! use calxgloss_types::TokenUsageEntry;
//!
//! let logger = TokenUsageLogger::new("/path/to/workspace");
//!
//! let entry = TokenUsageEntry::new(
//!     "game_logic.dll",
//!     "DrawSprite",
//!     1,
//!     "initial",
//!     4096,
//!     true,
//! );
//! logger.record(entry);
//! ```

use calxgloss_types::TokenUsageEntry;
use tracing::{debug, warn};

/// Logger for token usage entries.
///
/// Each call to [`record`](Self::record) appends a token usage entry to the
/// in-memory log and flushes it to the JSON file on disk.
///
/// The file path is `<workspace>/re/analysis/token_usage.json`.
/// The directory structure is created automatically if it does not exist.
#[derive(Debug, Clone)]
pub struct TokenUsageLogger {
    /// Base workspace path where `re/analysis/` resides.
    workspace: std::path::PathBuf,
}

impl TokenUsageLogger {
    /// Create a new logger targeting the given workspace directory.
    ///
    /// # Arguments
    ///
    /// * `workspace` — The workspace root path. The log file will be written
    ///   to `<workspace>/re/analysis/token_usage.json`.
    pub fn new(workspace: impl Into<std::path::PathBuf>) -> Self {
        Self {
            workspace: workspace.into(),
        }
    }

    /// Record a single token usage entry.
    ///
    /// This appends the entry to the in-memory log and persists the entire
    /// log to disk. If persistence fails, the entry is still kept in memory
    /// and a warning is emitted.
    pub fn record(&self, entry: TokenUsageEntry) {
        let log_path = self.log_path();

        // Try to read existing log
        let mut log = match std::fs::read_to_string(&log_path) {
            Ok(contents) => match serde_json::from_str(&contents) {
                Ok(existing) => existing,
                Err(e) => {
                    warn!(
                        path = ?log_path,
                        error = %e,
                        "Failed to parse existing token usage log, starting fresh"
                    );
                    calxgloss_types::TokenUsageLog::new()
                }
            },
            Err(_) => calxgloss_types::TokenUsageLog::new(),
        };

        // Add the entry
        log.add_entry(entry);

        // Persist
        if let Err(e) = self.persist(&log) {
            warn!(error = %e, "Failed to persist token usage log to disk");
        } else {
            debug!(
                dll = %log.entries.last().map(|e| &e.dll).unwrap_or(&"".to_string()),
                function = %log.entries.last().map(|e| &e.function).unwrap_or(&"".to_string()),
                tokens = log.entries.last().map(|e| e.tokens_used).unwrap_or(0),
                "Recorded token usage entry"
            );
        }
    }

    /// Load the current log from disk without adding new entries.
    ///
    /// Returns [`None`] if the file does not exist or cannot be parsed.
    pub fn load(&self) -> Option<calxgloss_types::TokenUsageLog> {
        let log_path = self.log_path();
        std::fs::read_to_string(&log_path)
            .ok()
            .and_then(|contents| serde_json::from_str(&contents).ok())
    }

    /// Persist the in-memory log to the JSON file.
    fn persist(&self, log: &calxgloss_types::TokenUsageLog) -> std::io::Result<()> {
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
    /// [`compute_stats`](calxgloss_types::TokenUsageLog::compute_stats).
    pub fn compute_stats(&self) -> Option<calxgloss_types::TokenUsageStats> {
        let log = self.load()?;
        Some(log.compute_stats())
    }

    /// Get the path to the token usage log JSON file.
    fn log_path(&self) -> std::path::PathBuf {
        self.workspace
            .join("re")
            .join("analysis")
            .join("token_usage.json")
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_workspace(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("calxgloss-test-tokens-{}", name));
        // Clean up any previous test artifacts
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_logger_create() {
        let ws = temp_workspace("create");
        let logger = TokenUsageLogger::new(&ws);
        assert_eq!(logger.workspace, ws);
    }

    #[test]
    fn test_logger_record_and_load() {
        let ws = temp_workspace("record_and_load");
        let logger = TokenUsageLogger::new(&ws);

        let entry = TokenUsageEntry::new(
            "test.dll",
            "entry",
            1,
            "initial",
            2048,
            true,
        );
        logger.record(entry);

        let log = logger.load().expect("log should exist");
        assert_eq!(log.entries.len(), 1);
        assert_eq!(log.entries[0].tokens_used, 2048);
        assert!(log.entries[0].success);
    }

    #[test]
    fn test_logger_multiple_entries() {
        let ws = temp_workspace("multiple_entries");
        let logger = TokenUsageLogger::new(&ws);

        for i in 1..=5 {
            logger.record(TokenUsageEntry::new(
                "game_logic.dll",
                "func",
                i,
                "initial",
                1024,
                i % 2 == 0,
            ));
        }

        let log = logger.load().expect("log should exist");
        assert_eq!(log.entries.len(), 5);

        let stats = log.compute_stats();
        assert_eq!(stats.total_entries, 5);
        assert_eq!(stats.total_tokens, 5 * 1024);
        assert_eq!(stats.successful_tokens, 2 * 1024);
        assert_eq!(stats.failed_tokens, 3 * 1024);
    }

    #[test]
    fn test_logger_stats_computation() {
        let ws = temp_workspace("stats");
        let logger = TokenUsageLogger::new(&ws);

        // Mixed tokens and success/failure
        logger.record(TokenUsageEntry::new(
            "a.dll",
            "func_a",
            1,
            "initial",
            4096,
            false,
        ));
        logger.record(TokenUsageEntry::new(
            "a.dll",
            "func_a",
            2,
            "compile_fix",
            3072,
            true,
        ));
        logger.record(TokenUsageEntry::new(
            "b.dll",
            "func_b",
            1,
            "initial",
            2048,
            true,
        ));

        let stats = logger.compute_stats().expect("stats should exist");
        assert_eq!(stats.total_entries, 3);
        assert_eq!(stats.total_tokens, 4096 + 3072 + 2048);
        assert_eq!(stats.successful_tokens, 3072 + 2048);
        assert_eq!(stats.by_dll.len(), 2);
    }

    #[test]
    fn test_logger_load_nonexistent() {
        let ws = temp_workspace("nonexistent").join("nonexistent_subdir");
        let logger = TokenUsageLogger::new(&ws);
        assert!(logger.load().is_none());
    }

    #[test]
    fn test_logger_persists_across_instances() {
        let ws = temp_workspace("persist");
        let logger1 = TokenUsageLogger::new(&ws);
        logger1.record(TokenUsageEntry::new(
            "persist_test.dll",
            "entry",
            1,
            "initial",
            1024,
            true,
        ));

        // A new logger instance should read the same file
        let logger2 = TokenUsageLogger::new(&ws);
        let log = logger2.load().expect("should load from disk");
        assert_eq!(log.entries.len(), 1);
        assert_eq!(log.entries[0].tokens_used, 1024);
    }

    #[test]
    fn test_log_path_construction() {
        let ws = std::path::PathBuf::from("/workspace");
        let logger = TokenUsageLogger::new(ws.clone());
        let log_path = logger.log_path();
        assert_eq!(
            log_path,
            ws.join("re").join("analysis").join("token_usage.json")
        );
    }

    #[test]
    fn test_load_corrupted_file() {
        let ws = temp_workspace("corrupted");
        let logger = TokenUsageLogger::new(&ws);

        // Write invalid JSON
        let log_path = logger.log_path();
        std::fs::create_dir_all(log_path.parent().unwrap()).unwrap();
        std::fs::write(&log_path, "not valid json {{{").unwrap();

        // Loading should return None (corrupted file)
        assert!(logger.load().is_none());

        // Recording should start fresh
        logger.record(TokenUsageEntry::new(
            "recovery.dll",
            "entry",
            1,
            "recovery",
            512,
            true,
        ));

        let log = logger.load().expect("should load after recovery");
        assert_eq!(log.entries.len(), 1);
        assert_eq!(log.entries[0].tokens_used, 512);
    }
}
