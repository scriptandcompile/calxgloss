//! Token usage recorded for each translation attempt.
//!
//! This module holds the types that record and save LLM token usage across
//! translation runs.
//!
//! # Overview
//!
//! Every translation attempt is recorded as a [`TokenUsageEntry`] containing:
//! - The DLL name and function the attempt belongs to
//! - The attempt number (1-based)
//! - The retry strategy used (initial, compile_fix, test_fix, etc.)
//! - The number of tokens the attempt used
//! - Whether the attempt ultimately succeeded
//! - The time the entry was recorded
//! - How long the attempt took, in whole seconds (issue #64; entries
//!   written by older versions have no duration field)
//!
//! The entries accumulate in a [`TokenUsageLog`], which computes aggregate
//! statistics (total tokens, a per-DLL breakdown, and more).
//!
//! The [`crate::analysis::TokenUsageLogger`](crate::analysis::TokenUsageLogger)
//! saves the log to `re/analysis/token_usage.json`.
//!
//! # Example
//!
//! ```
//! use calxgloss_types::TokenUsageEntry;
//!
//! let entry = TokenUsageEntry::new(
//!     "game_logic.dll",
//!     "DrawSprite",
//!     1,
//!     "initial",
//!     4096,
//!     true,
//! );
//! ```

use serde::{Deserialize, Serialize};

use crate::identity::BinaryIdentity;

/// One record of the token count for a single translation attempt.
///
/// Each entry records which function and DLL the attempt belongs to, the
/// attempt number, the retry strategy used, how many tokens the LLM used,
/// and whether the attempt succeeded.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TokenUsageEntry {
    /// The DLL filename (e.g., `"game_logic.dll"`).
    pub binary: BinaryIdentity,

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

    /// The context tier label for this attempt (e.g., `"stub"`, `"disassembly"`,
    /// `"with_tests"`, `"module_context"`, `"full_module"`).  It is empty when
    /// context tier tracking is not turned on.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub context_tier: String,

    /// How long the attempt took, in whole seconds. The translator's retry
    /// loop records it (issue #64).  It is `None` on entries written before
    /// durations were tracked, so time estimates average only real
    /// measurements.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_secs: Option<u64>,
}

impl TokenUsageEntry {
    /// Create a new token usage entry with the current timestamp.
    pub fn new(
        binary: impl Into<BinaryIdentity>,
        function: impl Into<String>,
        attempt: u32,
        strategy: impl Into<String>,
        tokens_used: usize,
        success: bool,
    ) -> Self {
        Self {
            binary: binary.into(),
            function: function.into(),
            attempt,
            strategy: strategy.into(),
            tokens_used,
            success,
            timestamp: current_timestamp(),
            context_tier: String::new(),
            duration_secs: None,
        }
    }

    /// Create a new token usage entry with the current timestamp and a context tier label.
    pub fn new_with_tier(
        binary: impl Into<BinaryIdentity>,
        function: impl Into<String>,
        attempt: u32,
        strategy: impl Into<String>,
        tokens_used: usize,
        success: bool,
        context_tier: impl Into<String>,
    ) -> Self {
        Self {
            binary: binary.into(),
            function: function.into(),
            attempt,
            strategy: strategy.into(),
            tokens_used,
            success,
            timestamp: current_timestamp(),
            context_tier: context_tier.into(),
            duration_secs: None,
        }
    }

    /// Record how long the attempt took, in whole seconds.
    ///
    /// The translator's retry loop calls this around each attempt. Entries
    /// without a duration count as unmeasured to [`TokenUsageLog::
    /// average_attempt_duration_secs`].
    pub fn with_duration_secs(mut self, duration_secs: u64) -> Self {
        self.duration_secs = Some(duration_secs);
        self
    }
}

/// Aggregated token usage across entries.
///
/// [`TokenUsageLog::compute_stats`] produces this struct. It summarizes
/// token use overall and per DLL.
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
    pub by_binary: Vec<BinaryTokenStats>,
}

/// Token consumption statistics for a single DLL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryTokenStats {
    /// The DLL filename.
    pub binary: BinaryIdentity,
    /// Total attempts for this DLL.
    pub total_attempts: usize,
    /// Total tokens consumed.
    pub total_tokens: usize,
}

/// The saved totals of the entries dropped by the [`MAX_LOG_ENTRIES`]
/// cap (issue #82).
///
/// [`TokenUsageLog::add_entry`] adds each dropped entry into these totals.
/// So [`TokenUsageLog::compute_stats`] and
/// [`TokenUsageLog::average_attempt_duration_secs`] still cover the whole
/// run's history, even though the file no longer holds those entries.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TokenUsageTrim {
    /// How many entries were trimmed away.
    #[serde(default)]
    pub entries: usize,

    /// Total tokens consumed by trimmed entries.
    #[serde(default)]
    pub total_tokens: usize,

    /// Tokens consumed by trimmed entries whose attempt succeeded.
    #[serde(default)]
    pub successful_tokens: usize,

    /// Per-DLL totals for trimmed entries, sorted by binary.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub by_binary: Vec<BinaryTokenStats>,

    /// Sum of recorded attempt durations across trimmed entries, in seconds.
    #[serde(default)]
    pub duration_secs_sum: u64,

    /// How many trimmed entries recorded a duration.
    #[serde(default)]
    pub duration_count: usize,
}

impl TokenUsageTrim {
    /// True when nothing has ever been trimmed. Every fresh log starts in
    /// this state, which is why the JSON can leave this field out.
    fn is_empty(&self) -> bool {
        self.entries == 0
    }

    /// Add one dropped entry into the running totals.
    fn absorb(&mut self, entry: &TokenUsageEntry) {
        self.entries += 1;
        self.total_tokens += entry.tokens_used;
        if entry.success {
            self.successful_tokens += entry.tokens_used;
        }
        let idx = self.by_binary.partition_point(|b| b.binary < entry.binary);
        match self.by_binary.get_mut(idx) {
            Some(b) if b.binary == entry.binary => {
                b.total_attempts += 1;
                b.total_tokens += entry.tokens_used;
            }
            _ => self.by_binary.insert(
                idx,
                BinaryTokenStats {
                    binary: entry.binary.clone(),
                    total_attempts: 1,
                    total_tokens: entry.tokens_used,
                },
            ),
        }
        if let Some(secs) = entry.duration_secs {
            self.duration_secs_sum += secs;
            self.duration_count += 1;
        }
    }
}

/// The complete token usage log: every entry recorded across all
/// translation runs.
///
/// This struct is the in-memory form the logger saves to
/// `re/analysis/token_usage.json`. It can also compute aggregate
/// statistics via [`compute_stats`](Self::compute_stats).
///
/// The log is bounded. [`add_entry`](Self::add_entry) keeps at most
/// [`MAX_LOG_ENTRIES`] of the newest entries and moves the totals of the
/// dropped ones into [`trimmed`](Self::trimmed), so the aggregates still
/// cover the whole run.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TokenUsageLog {
    /// The retained entries — the newest window of at most
    /// [`MAX_LOG_ENTRIES`] entries.
    pub entries: Vec<TokenUsageEntry>,

    /// Aggregate totals for entries trimmed away by the cap.
    #[serde(default, skip_serializing_if = "TokenUsageTrim::is_empty")]
    pub trimmed: TokenUsageTrim,
}

impl TokenUsageLog {
    /// Create an empty log.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append an entry to the log.
    ///
    /// The log keeps at most [`MAX_LOG_ENTRIES`] entries. Once full, each
    /// new entry drops the oldest one, which bounds the file's size and
    /// the cost of rewriting it (issue #82). The dropped entry's totals
    /// move into [`trimmed`](Self::trimmed), so the aggregates stay
    /// accurate.
    pub fn add_entry(&mut self, entry: TokenUsageEntry) {
        self.entries.push(entry);
        if self.entries.len() > crate::MAX_LOG_ENTRIES {
            let dropped = self.entries.remove(0);
            self.trimmed.absorb(&dropped);
        }
    }

    /// Compute aggregated token usage statistics across the whole run.
    ///
    /// Covers both the retained entries and the trimmed-away history in
    /// [`trimmed`](Self::trimmed).
    pub fn compute_stats(&self) -> TokenUsageStats {
        let total = self.entries.len() + self.trimmed.entries;
        let retained_tokens: usize = self.entries.iter().map(|e| e.tokens_used).sum();
        let total_tokens = retained_tokens + self.trimmed.total_tokens;
        let retained_successful: usize = self
            .entries
            .iter()
            .filter(|e| e.success)
            .map(|e| e.tokens_used)
            .sum();
        let successful_tokens = retained_successful + self.trimmed.successful_tokens;
        let failed_tokens = total_tokens.saturating_sub(successful_tokens);

        // Group by DLL, combining the retained entries with the trimmed totals.
        let mut binary_map: std::collections::HashMap<BinaryIdentity, (usize, usize)> =
            std::collections::HashMap::new();
        for entry in &self.entries {
            let (attempts, tokens) = binary_map.entry(entry.binary.clone()).or_insert((0, 0));
            *attempts += 1;
            *tokens += entry.tokens_used;
        }
        for trimmed in &self.trimmed.by_binary {
            let (attempts, tokens) = binary_map.entry(trimmed.binary.clone()).or_insert((0, 0));
            *attempts += trimmed.total_attempts;
            *tokens += trimmed.total_tokens;
        }

        let mut by_binary: Vec<BinaryTokenStats> = binary_map
            .into_iter()
            .map(|(binary, (attempts, tokens))| BinaryTokenStats {
                binary,
                total_attempts: attempts,
                total_tokens: tokens,
            })
            .collect();
        by_binary.sort_by(|a, b| a.binary.cmp(&b.binary));

        TokenUsageStats {
            total_entries: total,
            total_tokens,
            successful_tokens,
            failed_tokens,
            by_binary,
        }
    }

    /// The mean attempt duration, in seconds, over the entries that
    /// recorded one (issue #64).
    ///
    /// Returns `None` when no entry has a duration. That is the honest
    /// answer when nothing has been measured yet, so callers hide time
    /// estimates instead of making them up. Entries written by older
    /// versions have no `duration_secs` field; they are skipped, never
    /// counted as zero. Entries dropped by the cap (issue #82) still count,
    /// through their totals in [`trimmed`](Self::trimmed).
    pub fn average_attempt_duration_secs(&self) -> Option<f64> {
        let mut total_secs = self.trimmed.duration_secs_sum;
        let mut measured = self.trimmed.duration_count;
        for entry in &self.entries {
            if let Some(secs) = entry.duration_secs {
                total_secs += secs;
                measured += 1;
            }
        }
        if measured == 0 {
            return None;
        }
        Some(total_secs as f64 / measured as f64)
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
        assert_eq!(entry.binary, "game_logic.dll");
        assert_eq!(entry.function, "DrawSprite");
        assert_eq!(entry.attempt, 1);
        assert_eq!(entry.strategy, "initial");
        assert_eq!(entry.tokens_used, 4096);
        assert!(entry.success);
        assert!(entry.timestamp > 0);
        assert!(entry.context_tier.is_empty());
    }

    #[test]
    fn test_entry_creation_with_tier() {
        let entry = TokenUsageEntry::new_with_tier(
            "game_logic.dll",
            "DrawSprite",
            1,
            "initial",
            4096,
            true,
            "with_tests",
        );
        assert_eq!(entry.binary, "game_logic.dll");
        assert_eq!(entry.function, "DrawSprite");
        assert_eq!(entry.attempt, 1);
        assert_eq!(entry.strategy, "initial");
        assert_eq!(entry.tokens_used, 4096);
        assert!(entry.success);
        assert!(entry.timestamp > 0);
        assert_eq!(entry.context_tier, "with_tests");
    }

    #[test]
    fn test_log_empty_stats() {
        let log = TokenUsageLog::new();
        let stats = log.compute_stats();
        assert_eq!(stats.total_entries, 0);
        assert_eq!(stats.total_tokens, 0);
        assert_eq!(stats.successful_tokens, 0);
        assert_eq!(stats.failed_tokens, 0);
        assert!(stats.by_binary.is_empty());
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
        assert_eq!(stats.by_binary.len(), 1);
        assert_eq!(stats.by_binary[0].total_tokens, 2048);
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
        assert_eq!(stats.by_binary.len(), 2);

        let gl = stats
            .by_binary
            .iter()
            .find(|d| d.binary == "game_logic.dll")
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
        assert_eq!(deserialized.entries[0].binary, "game_logic.dll");
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
        assert_eq!(deserialized.by_binary.len(), 1);
    }

    #[test]
    fn test_entry_with_tier_serialization() {
        let entry = TokenUsageEntry::new_with_tier(
            "game_logic.dll",
            "DrawSprite",
            2,
            "escalate",
            8192,
            false,
            "module_context",
        );

        // Serialize — context_tier should be included
        let json = serde_json::to_string(&entry).expect("should serialize");
        let deserialized: TokenUsageEntry =
            serde_json::from_str(&json).expect("should deserialize");
        assert_eq!(deserialized.context_tier, "module_context");

        // Entry without tier — context_tier should be omitted from JSON
        let entry_no_tier =
            TokenUsageEntry::new("game_logic.dll", "Entry", 1, "initial", 2048, true);
        let json = serde_json::to_string(&entry_no_tier).expect("should serialize");
        assert!(!json.contains("\"context_tier\""));
    }

    #[test]
    fn test_entry_with_duration() {
        let entry = TokenUsageEntry::new("game_logic.dll", "DrawSprite", 1, "initial", 4096, true)
            .with_duration_secs(42);
        assert_eq!(entry.duration_secs, Some(42));

        // Duration survives a JSON round trip.
        let json = serde_json::to_string(&entry).expect("should serialize");
        let deserialized: TokenUsageEntry =
            serde_json::from_str(&json).expect("should deserialize");
        assert_eq!(deserialized.duration_secs, Some(42));
    }

    #[test]
    fn test_entry_without_duration_omits_field_and_stays_compatible() {
        // New entries without a duration omit the field from JSON…
        let entry = TokenUsageEntry::new("game_logic.dll", "DrawSprite", 1, "initial", 2048, true);
        assert_eq!(entry.duration_secs, None);
        let json = serde_json::to_string(&entry).expect("should serialize");
        assert!(!json.contains("\"duration_secs\""));

        // …and logs written before durations existed still deserialize,
        // with the field reading as unmeasured rather than zero.
        let legacy = r#"{"binary":"game_logic.dll","function":"DrawSprite","attempt":1,
            "strategy":"initial","tokens_used":2048,"success":true,"timestamp":1767225600}"#;
        let legacy_entry: TokenUsageEntry =
            serde_json::from_str(legacy).expect("legacy entry should deserialize");
        assert_eq!(legacy_entry.duration_secs, None);
    }

    #[test]
    fn test_average_attempt_duration_none_without_measurements() {
        let log = TokenUsageLog::new();
        assert_eq!(log.average_attempt_duration_secs(), None);

        // Entries without durations never count as zero.
        let mut log = TokenUsageLog::new();
        log.add_entry(TokenUsageEntry::new(
            "game_logic.dll",
            "DrawSprite",
            1,
            "initial",
            4096,
            false,
        ));
        assert_eq!(log.average_attempt_duration_secs(), None);
    }

    #[test]
    fn test_average_attempt_duration_averages_only_measured_entries() {
        let mut log = TokenUsageLog::new();
        log.add_entry(
            TokenUsageEntry::new("game_logic.dll", "DrawSprite", 1, "initial", 4096, false)
                .with_duration_secs(100),
        );
        log.add_entry(TokenUsageEntry::new(
            "audio.dll",
            "PlaySample",
            1,
            "initial",
            2048,
            true,
        ));
        log.add_entry(
            TokenUsageEntry::new("game_logic.dll", "DrawSprite", 2, "compile_fix", 3072, true)
                .with_duration_secs(200),
        );

        let avg = log
            .average_attempt_duration_secs()
            .expect("two measured entries should yield an average");
        assert_eq!(avg, 150.0);
    }

    #[test]
    fn test_add_entry_caps_retained_entries_at_the_documented_max() {
        let mut log = TokenUsageLog::new();
        for i in 0..crate::MAX_LOG_ENTRIES {
            log.add_entry(TokenUsageEntry::new(
                "test.dll",
                "entry",
                i as u32 + 1,
                "initial",
                10,
                true,
            ));
        }
        // Exactly at the cap: nothing trimmed yet.
        assert_eq!(log.entries.len(), crate::MAX_LOG_ENTRIES);
        assert_eq!(log.entries[0].attempt, 1);

        // One past the cap: oldest entry dropped, newest kept.
        log.add_entry(TokenUsageEntry::new(
            "test.dll",
            "entry",
            crate::MAX_LOG_ENTRIES as u32 + 1,
            "initial",
            10,
            true,
        ));
        assert_eq!(log.entries.len(), crate::MAX_LOG_ENTRIES);
        assert_eq!(log.entries[0].attempt, 2);
    }

    /// Build a varied entry for cap tests — binary, strategy, success and
    /// token count all cycle so aggregates can't match by accident.
    fn make_token_usage_entry(i: usize) -> TokenUsageEntry {
        TokenUsageEntry::new(
            if i.is_multiple_of(2) {
                "a.dll"
            } else {
                "b.dll"
            },
            "entry",
            i as u32 + 1,
            if i.is_multiple_of(3) {
                "initial"
            } else {
                "compile_fix"
            },
            i % 7 + 1,
            !i.is_multiple_of(4),
        )
    }

    #[test]
    fn test_compute_stats_cover_trimmed_entries() {
        let history = crate::MAX_LOG_ENTRIES + 25;

        // Reference: the same history with no cap applied, built by
        // pushing entries directly past `add_entry`.
        let mut reference = TokenUsageLog::new();
        reference.entries = (0..history).map(make_token_usage_entry).collect();

        // Capped: same history through `add_entry`, oldest entries trimmed.
        let mut capped = TokenUsageLog::new();
        for i in 0..history {
            capped.add_entry(make_token_usage_entry(i));
        }
        assert_eq!(capped.entries.len(), crate::MAX_LOG_ENTRIES);

        assert_eq!(
            serde_json::to_value(capped.compute_stats()).expect("serialize capped stats"),
            serde_json::to_value(reference.compute_stats()).expect("serialize reference stats"),
            "stats must cover the whole run's history, not just the retained window"
        );
    }

    #[test]
    fn test_average_attempt_duration_covers_trimmed_entries() {
        let mut log = TokenUsageLog::new();
        // The first 10 entries (all trimmed away) took 1000s each; the
        // retained window is all 100s attempts.
        for i in 0..crate::MAX_LOG_ENTRIES + 10 {
            let duration = if i < 10 { 1000 } else { 100 };
            log.add_entry(make_token_usage_entry(i).with_duration_secs(duration));
        }
        let avg = log
            .average_attempt_duration_secs()
            .expect("measured entries should yield an average");
        // Whole-run average: (10 * 1000 + 10_000 * 100) / 10_010.
        let expected = 1_010_000.0 / 10_010.0;
        assert!(
            (avg - expected).abs() < 1e-9,
            "average must cover trimmed entries: got {avg}, expected {expected}"
        );
    }

    #[test]
    fn test_trimmed_log_round_trips_through_json() {
        let mut log = TokenUsageLog::new();
        for i in 0..crate::MAX_LOG_ENTRIES + 5 {
            log.add_entry(make_token_usage_entry(i));
        }

        let json = serde_json::to_string(&log).expect("serialize trimmed log");
        let back: TokenUsageLog = serde_json::from_str(&json).expect("deserialize trimmed log");

        assert_eq!(back.entries.len(), crate::MAX_LOG_ENTRIES);
        assert_eq!(back.trimmed.entries, 5);
        assert_eq!(
            serde_json::to_value(back.compute_stats()).expect("serialize restored stats"),
            serde_json::to_value(log.compute_stats()).expect("serialize original stats"),
            "a trimmed log must round-trip with its aggregates intact"
        );
    }

    #[test]
    fn test_log_without_trimmed_field_stays_compatible() {
        // Logs written before the cap (issue #82) have no `trimmed` field.
        let json = r#"{"entries":[{"binary":"test.dll","function":"entry","attempt":1,"strategy":"initial","tokens_used":2048,"success":true,"timestamp":1700000000}]}"#;
        let log: TokenUsageLog = serde_json::from_str(json).expect("old logs must still load");
        assert_eq!(log.entries.len(), 1);
        assert_eq!(log.trimmed.entries, 0);
    }
}
