//! Per-attempt token usage tracking.
//!
//! This module provides types and utility functions for logging and
//! persisting LLM token usage data across translation runs.
//!
//! # Overview
//!
//! Every translation attempt is recorded as a [`TokenUsageEntry`] containing:
//! - The DLL name and function it belongs to
//! - The attempt number (1-based)
//! - The retry strategy used (initial, compile_fix, test_fix, etc.)
//! - Number of tokens consumed by that attempt
//! - Whether the attempt ultimately succeeded
//! - A timestamp for when the entry was recorded
//!
//! These entries are collected into a [`TokenUsageLog`] which can compute
//! aggregate statistics (total tokens, per-DLL breakdown, etc.).
//!
//! The [`crate::analysis::TokenUsageLogger`](crate::analysis::TokenUsageLogger)
//! handles persistence to `re/analysis/token_usage.json`.
//!
//! # Example
//!
//! ```
//! use calxgloss_types::TokenUsageEntry;
//!
//! let entry = TokenUsageEntry {
//!     dll: "game_logic.dll".to_string(),
//!     function: "DrawSprite".to_string(),
//!     attempt: 1,
//!     strategy: "initial".to_string(),
//!     tokens_used: 4096,
//!     success: true,
//!     timestamp: 0, // set by logger
//! };
//! ```

use serde::{Deserialize, Serialize};

/// A single token usage entry recording the token count for one translation attempt.
///
/// Each entry captures which function and DLL it belongs to, the attempt number,
/// which retry strategy was used, how many tokens the LLM consumed, and whether
/// the attempt succeeded.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TokenUsageEntry {
    /// The DLL filename (e.g., `"game_logic.dll"`).
    pub dll: String,

    /// The function name that was translated.
    pub function: String,

    /// The 1-based attempt number within this function's retry loop.
    pub attempt: u32,

    /// The retry strategy label (e.g., `"initial"`, `"compile_fix"`, `"test_fix"`, `"escalate"`).
    pub strategy: String,

    /// Number of tokens the LLM used for this attempt.
    pub tokens_used: usize,

    /// Whether this attempt ultimately produced passing code.
    pub success: bool,

    /// Unix timestamp in seconds when this entry was recorded.
    pub timestamp: u64,
}

impl TokenUsageEntry {
    /// Create a new token usage entry with the current timestamp.
    pub fn new(
        dll: impl Into<String>,
        function: impl Into<String>,
        attempt: u32,
        strategy: impl Into<String>,
        tokens_used: usize,
        success: bool,
    ) -> Self {
        Self {
            dll: dll.into(),
            function: function.into(),
            attempt,
            strategy: strategy.into(),
            tokens_used,
            success,
            timestamp: current_timestamp(),
        }
    }
}

/// An aggregated view of token usage data across entries.
///
/// This struct is produced by [`TokenUsageLog::compute_stats`] and
/// contains per-DLL and overall token consumption summaries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenUsageStats {
    /// Total entries in the log.
    pub total_entries: usize,

    /// Total tokens consumed across all entries.
    pub total_tokens: usize,

    /// Tokens consumed only by successful attempts.
    pub successful_tokens: usize,

    /// Tokens consumed by failed attempts.
    pub failed_tokens: usize,

    /// Per-DLL token totals.
    pub by_dll: Vec<DllTokenStats>,
}

/// Token consumption statistics for a single DLL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DllTokenStats {
    /// The DLL filename.
    pub dll: String,
    /// Total attempts for this DLL.
    pub total_attempts: usize,
    /// Total tokens consumed.
    pub total_tokens: usize,
}

/// A complete token usage log collecting entries across all translation runs.
///
/// This struct is the in-memory representation that the logger serializes
/// to `re/analysis/token_usage.json`. It can also compute aggregate
/// statistics via [`compute_stats`](Self::compute_stats).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TokenUsageLog {
    /// All recorded entries.
    pub entries: Vec<TokenUsageEntry>,
}

impl TokenUsageLog {
    /// Create an empty log.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Append an entry to the log.
    pub fn add_entry(&mut self, entry: TokenUsageEntry) {
        self.entries.push(entry);
    }

    /// Compute aggregated token usage statistics across all entries.
    pub fn compute_stats(&self) -> TokenUsageStats {
        let total = self.entries.len();
        let total_tokens: usize = self.entries.iter().map(|e| e.tokens_used).sum();
        let successful_tokens: usize = self
            .entries
            .iter()
            .filter(|e| e.success)
            .map(|e| e.tokens_used)
            .sum();
        let failed_tokens = total_tokens.saturating_sub(successful_tokens);

        // Group by DLL
        let mut dll_map: std::collections::HashMap<String, (usize, usize)> =
            std::collections::HashMap::new();
        for entry in &self.entries {
            let (attempts, tokens) = dll_map.entry(entry.dll.clone()).or_insert((0, 0));
            *attempts += 1;
            *tokens += entry.tokens_used;
        }

        let by_dll: Vec<DllTokenStats> = dll_map
            .into_iter()
            .map(|(dll, (attempts, tokens))| DllTokenStats {
                dll,
                total_attempts: attempts,
                total_tokens: tokens,
            })
            .collect();

        TokenUsageStats {
            total_entries: total,
            total_tokens,
            successful_tokens,
            failed_tokens,
            by_dll,
        }
    }
}

/// Returns the current Unix timestamp in seconds.
fn current_timestamp() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entry_creation() {
        let entry = TokenUsageEntry::new("game_logic.dll", "DrawSprite", 1, "initial", 4096, true);
        assert_eq!(entry.dll, "game_logic.dll");
        assert_eq!(entry.function, "DrawSprite");
        assert_eq!(entry.attempt, 1);
        assert_eq!(entry.strategy, "initial");
        assert_eq!(entry.tokens_used, 4096);
        assert!(entry.success);
        assert!(entry.timestamp > 0);
    }

    #[test]
    fn test_log_empty_stats() {
        let log = TokenUsageLog::new();
        let stats = log.compute_stats();
        assert_eq!(stats.total_entries, 0);
        assert_eq!(stats.total_tokens, 0);
        assert_eq!(stats.successful_tokens, 0);
        assert_eq!(stats.failed_tokens, 0);
        assert!(stats.by_dll.is_empty());
    }

    #[test]
    fn test_log_single_entry() {
        let mut log = TokenUsageLog::new();
        log.add_entry(TokenUsageEntry::new(
            "test.dll", "entry", 1, "initial", 2048, true,
        ));

        let stats = log.compute_stats();
        assert_eq!(stats.total_entries, 1);
        assert_eq!(stats.total_tokens, 2048);
        assert_eq!(stats.successful_tokens, 2048);
        assert_eq!(stats.failed_tokens, 0);
        assert_eq!(stats.by_dll.len(), 1);
        assert_eq!(stats.by_dll[0].total_tokens, 2048);
    }

    #[test]
    fn test_log_mixed_results() {
        let mut log = TokenUsageLog::new();

        // Multiple attempts across two DLLs
        log.add_entry(TokenUsageEntry::new(
            "game_logic.dll",
            "DrawSprite",
            1,
            "initial",
            4096,
            false,
        ));
        log.add_entry(TokenUsageEntry::new(
            "game_logic.dll",
            "DrawSprite",
            2,
            "compile_fix",
            3072,
            true,
        ));
        log.add_entry(TokenUsageEntry::new(
            "audio.dll",
            "PlaySample",
            1,
            "initial",
            2048,
            true,
        ));

        let stats = log.compute_stats();
        assert_eq!(stats.total_entries, 3);
        assert_eq!(stats.total_tokens, 4096 + 3072 + 2048);
        assert_eq!(stats.successful_tokens, 3072 + 2048);
        assert_eq!(stats.failed_tokens, 4096);
        assert_eq!(stats.by_dll.len(), 2);

        let gl = stats
            .by_dll
            .iter()
            .find(|d| d.dll == "game_logic.dll")
            .unwrap();
        assert_eq!(gl.total_attempts, 2);
        assert_eq!(gl.total_tokens, 4096 + 3072);
    }

    #[test]
    fn test_log_serialization_roundtrip() {
        let mut log = TokenUsageLog::new();
        log.add_entry(TokenUsageEntry::new(
            "game_logic.dll",
            "DrawSprite",
            1,
            "initial",
            4096,
            false,
        ));

        let json = serde_json::to_string(&log).expect("should serialize");
        let deserialized: TokenUsageLog = serde_json::from_str(&json).expect("should deserialize");

        assert_eq!(deserialized.entries.len(), 1);
        assert_eq!(deserialized.entries[0].dll, "game_logic.dll");
        assert_eq!(deserialized.entries[0].function, "DrawSprite");
        assert_eq!(deserialized.entries[0].tokens_used, 4096);
        assert!(!deserialized.entries[0].success);
    }

    #[test]
    fn test_stats_serialization_roundtrip() {
        let mut log = TokenUsageLog::new();
        log.add_entry(TokenUsageEntry::new(
            "game_logic.dll",
            "DrawSprite",
            1,
            "initial",
            1024,
            true,
        ));

        let stats = log.compute_stats();
        let json = serde_json::to_string(&stats).expect("should serialize");
        let deserialized: TokenUsageStats =
            serde_json::from_str(&json).expect("should deserialize");

        assert_eq!(deserialized.total_entries, 1);
        assert_eq!(deserialized.total_tokens, 1024);
        assert_eq!(deserialized.by_dll.len(), 1);
    }
}
