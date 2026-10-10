//! Prompt variant experiment data types.
//!
//! This module provides types for tracking and analyzing prompt strategy
//! performance across DLL categories.
//!
//! # Overview
//!
//! Every translation attempt is recorded as a [`PromptStrategyEntry`] containing:
//! - The DLL name and its classification category
//! - The retry strategy used (`compile_fix`, `test_fix`, `escalate`, etc.)
//! - Whether the attempt succeeded or failed
//! - The attempt number (1-based)
//! - A timestamp for when the entry was recorded
//!
//! These entries are collected into a [`PromptStrategyLog`] which can compute:
//! - Pass rate per strategy per DLL category
//! - Total attempts, successes, and failures
//! - Per-category and per-strategy aggregates
//!
//! The [`crate::analysis::PromptStrategyLogger`] handles persistence to
//! `re/analysis/prompt_strategy_log.json`.
//!
//! # Example
//!
//! ```
//! use calxgloss_types::PromptStrategyEntry;
//! use calxgloss_types::DllCategory;
//!
//! let entry = PromptStrategyEntry {
//!     binary: "game_logic.dll".into(),
//!     dll_category: DllCategory::ProjectSpecific,
//!     strategy: "compile_fix".to_string(),
//!     success: false,
//!     attempt: 1,
//!     timestamp: 0, // set by logger
//! };
//! ```

use serde::{Deserialize, Serialize};

use crate::DllCategory;
use crate::identity::BinaryIdentity;

/// A single experiment entry recording the outcome of one translation attempt.
///
/// Each entry captures which strategy was used, whether it succeeded, and
/// which DLL category it operated on. The logger fills in the timestamp.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PromptStrategyEntry {
    /// The DLL filename (e.g., `"game_logic.dll"`).
    pub binary: BinaryIdentity,

    /// The DLL classification category.
    pub dll_category: DllCategory,

    /// The retry strategy label (e.g., `"compile_fix"`, `"test_fix"`, `"escalate"`).
    pub strategy: String,

    /// Whether this attempt ultimately produced passing code.
    pub success: bool,

    /// The 1-based attempt number within this function's retry loop.
    pub attempt: u32,

    /// Unix timestamp in seconds when this entry was recorded.
    pub timestamp: u64,
}

impl PromptStrategyEntry {
    /// Create a new experiment entry with the current timestamp.
    pub fn new(
        binary: impl Into<BinaryIdentity>,
        dll_category: DllCategory,
        strategy: impl Into<String>,
        success: bool,
        attempt: u32,
    ) -> Self {
        Self {
            binary: binary.into(),
            dll_category,
            strategy: strategy.into(),
            success,
            attempt,
            timestamp: current_timestamp(),
        }
    }
}

/// An aggregated view of experiment data across entries.
///
/// This struct is produced by [`PromptStrategyLog::compute_stats`] and
/// contains pass rates broken down by category and strategy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptStrategyStats {
    /// Total entries in the log.
    pub total_entries: usize,

    /// Total successful attempts.
    pub total_successes: usize,

    /// Total failed attempts.
    pub total_failures: usize,

    /// Per-category aggregates.
    pub by_category: Vec<CategoryStats>,

    /// Per-strategy aggregates.
    pub by_strategy: Vec<StrategyStats>,
}

/// Pass rate statistics for a single DLL category.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategoryStats {
    /// The DLL category name.
    pub category: String,
    /// Total attempts for this category.
    pub total: usize,
    /// Successful attempts for this category.
    pub successes: usize,
    /// Failure rate (0.0–1.0).
    pub fail_rate: f64,
    /// Pass rate (0.0–1.0).
    pub pass_rate: f64,
}

/// Pass rate statistics for a single retry strategy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrategyStats {
    /// The strategy label.
    pub strategy: String,
    /// Total attempts using this strategy.
    pub total: usize,
    /// Successful attempts using this strategy.
    pub successes: usize,
    /// Failure rate (0.0–1.0).
    pub fail_rate: f64,
    /// Pass rate (0.0–1.0).
    pub pass_rate: f64,
}

/// Aggregate contribution of entries trimmed away by the [`MAX_LOG_ENTRIES`]
/// cap (issue #82).
///
/// [`PromptStrategyLog::add_entry`] folds each dropped entry into this
/// accumulator so [`PromptStrategyLog::compute_stats`] keeps covering the
/// whole run's history even though the entries themselves are gone.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PromptStrategyTrim {
    /// How many entries were trimmed away.
    #[serde(default)]
    pub entries: usize,

    /// Trimmed entries whose attempt succeeded.
    #[serde(default)]
    pub successes: usize,

    /// Trimmed (total, successes) per DLL category.
    #[serde(default)]
    pub by_category: std::collections::HashMap<String, (usize, usize)>,

    /// Trimmed (total, successes) per retry strategy.
    #[serde(default)]
    pub by_strategy: std::collections::HashMap<String, (usize, usize)>,
}

impl PromptStrategyTrim {
    /// True when nothing has ever been trimmed — the state every fresh log
    /// starts in, and the reason the accumulator can be skipped in JSON.
    fn is_empty(&self) -> bool {
        self.entries == 0
    }

    /// Fold one dropped entry into the running totals.
    fn absorb(&mut self, entry: &PromptStrategyEntry) {
        self.entries += 1;
        if entry.success {
            self.successes += 1;
        }
        let category = format!("{:?}", entry.dll_category);
        let (tot, suc) = self.by_category.entry(category).or_insert((0, 0));
        *tot += 1;
        if entry.success {
            *suc += 1;
        }
        let (tot, suc) = self
            .by_strategy
            .entry(entry.strategy.clone())
            .or_insert((0, 0));
        *tot += 1;
        if entry.success {
            *suc += 1;
        }
    }
}

/// A complete experiment log collecting entries across all translation runs.
///
/// This struct is the in-memory representation that the logger serializes
/// to `re/analysis/prompt_strategy_log.json`. It can also compute aggregate
/// statistics via [`compute_stats`](Self::compute_stats).
///
/// The log is bounded: [`add_entry`](Self::add_entry) keeps at most
/// [`MAX_LOG_ENTRIES`] newest entries and folds the trimmed-away ones into
/// [`trimmed`](Self::trimmed), so aggregates still cover the whole run.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PromptStrategyLog {
    /// The retained entries — the newest window of at most
    /// [`MAX_LOG_ENTRIES`] entries.
    pub entries: Vec<PromptStrategyEntry>,

    /// Aggregate totals for entries trimmed away by the cap.
    #[serde(default, skip_serializing_if = "PromptStrategyTrim::is_empty")]
    pub trimmed: PromptStrategyTrim,
}

impl PromptStrategyLog {
    /// Create an empty log.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append an entry to the log.
    ///
    /// The log retains at most [`MAX_LOG_ENTRIES`] entries: once full, each
    /// new entry drops the oldest one, keeping the file's size and the
    /// per-entry rewrite cost bounded (issue #82). The dropped entry is
    /// folded into [`trimmed`](Self::trimmed) so aggregates stay honest.
    pub fn add_entry(&mut self, entry: PromptStrategyEntry) {
        self.entries.push(entry);
        if self.entries.len() > crate::MAX_LOG_ENTRIES {
            let dropped = self.entries.remove(0);
            self.trimmed.absorb(&dropped);
        }
    }

    /// Compute aggregated pass-rate statistics across the whole run.
    ///
    /// Covers both the retained entries and the trimmed-away history in
    /// [`trimmed`](Self::trimmed).
    pub fn compute_stats(&self) -> PromptStrategyStats {
        let total = self.entries.len() + self.trimmed.entries;
        let successes = self.entries.iter().filter(|e| e.success).count() + self.trimmed.successes;
        let failures = total - successes;

        // Group by category, merging the retained entries with the trimmed totals.
        let mut category_map: std::collections::HashMap<String, (usize, usize)> =
            std::collections::HashMap::new();
        for entry in &self.entries {
            let cat = format!("{:?}", entry.dll_category);
            let (tot, suc) = category_map.entry(cat).or_insert((0, 0));
            *tot += 1;
            if entry.success {
                *suc += 1;
            }
        }
        for (cat, (tot, suc)) in &self.trimmed.by_category {
            let (acc_tot, acc_suc) = category_map.entry(cat.clone()).or_insert((0, 0));
            *acc_tot += tot;
            *acc_suc += suc;
        }

        let by_category: Vec<CategoryStats> = category_map
            .into_iter()
            .map(|(category, (tot, suc))| {
                let pass_rate = suc as f64 / tot as f64;
                CategoryStats {
                    category,
                    total: tot,
                    successes: suc,
                    fail_rate: 1.0 - pass_rate,
                    pass_rate,
                }
            })
            .collect();

        // Group by strategy, merging the retained entries with the trimmed totals.
        let mut strategy_map: std::collections::HashMap<String, (usize, usize)> =
            std::collections::HashMap::new();
        for entry in &self.entries {
            let (tot, suc) = strategy_map.entry(entry.strategy.clone()).or_insert((0, 0));
            *tot += 1;
            if entry.success {
                *suc += 1;
            }
        }
        for (strategy, (tot, suc)) in &self.trimmed.by_strategy {
            let (acc_tot, acc_suc) = strategy_map.entry(strategy.clone()).or_insert((0, 0));
            *acc_tot += tot;
            *acc_suc += suc;
        }

        let by_strategy: Vec<StrategyStats> = strategy_map
            .into_iter()
            .map(|(strategy, (tot, suc))| {
                let pass_rate = suc as f64 / tot as f64;
                StrategyStats {
                    strategy,
                    total: tot,
                    successes: suc,
                    fail_rate: 1.0 - pass_rate,
                    pass_rate,
                }
            })
            .collect();

        PromptStrategyStats {
            total_entries: total,
            total_successes: successes,
            total_failures: failures,
            by_category,
            by_strategy,
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
        let entry = PromptStrategyEntry::new(
            "game_logic.dll",
            DllCategory::ProjectSpecific,
            "compile_fix",
            false,
            1,
        );
        assert_eq!(entry.binary, "game_logic.dll");
        assert_eq!(entry.dll_category, DllCategory::ProjectSpecific);
        assert_eq!(entry.strategy, "compile_fix");
        assert!(!entry.success);
        assert_eq!(entry.attempt, 1);
        assert!(entry.timestamp > 0);
    }

    #[test]
    fn test_log_empty_stats() {
        let log = PromptStrategyLog::new();
        let stats = log.compute_stats();
        assert_eq!(stats.total_entries, 0);
        assert_eq!(stats.total_successes, 0);
        assert_eq!(stats.total_failures, 0);
        assert!(stats.by_category.is_empty());
        assert!(stats.by_strategy.is_empty());
    }

    #[test]
    fn test_log_single_success() {
        let mut log = PromptStrategyLog::new();
        log.add_entry(PromptStrategyEntry::new(
            "test.dll",
            DllCategory::ProjectSpecific,
            "initial",
            true,
            1,
        ));

        let stats = log.compute_stats();
        assert_eq!(stats.total_entries, 1);
        assert_eq!(stats.total_successes, 1);
        assert_eq!(stats.total_failures, 0);
        assert_eq!(stats.by_category.len(), 1);
        assert_eq!(stats.by_strategy.len(), 1);
        assert_eq!(stats.by_category[0].pass_rate, 1.0);
        assert_eq!(stats.by_strategy[0].pass_rate, 1.0);
    }

    #[test]
    fn test_log_mixed_results() {
        let mut log = PromptStrategyLog::new();

        // 3 compile_fix, 1 test_fix, 1 escalate
        log.add_entry(PromptStrategyEntry::new(
            "a.dll",
            DllCategory::ProjectSpecific,
            "compile_fix",
            false,
            1,
        ));
        log.add_entry(PromptStrategyEntry::new(
            "a.dll",
            DllCategory::ProjectSpecific,
            "compile_fix",
            true,
            2,
        ));
        log.add_entry(PromptStrategyEntry::new(
            "a.dll",
            DllCategory::ProjectSpecific,
            "test_fix",
            true,
            3,
        ));
        log.add_entry(PromptStrategyEntry::new(
            "b.dll",
            DllCategory::MicrosoftSdk,
            "compile_fix",
            false,
            1,
        ));
        log.add_entry(PromptStrategyEntry::new(
            "b.dll",
            DllCategory::MicrosoftSdk,
            "test_fix",
            false,
            2,
        ));
        log.add_entry(PromptStrategyEntry::new(
            "b.dll",
            DllCategory::MicrosoftSdk,
            "escalate",
            true,
            3,
        ));

        let stats = log.compute_stats();
        assert_eq!(stats.total_entries, 6);
        assert_eq!(stats.total_successes, 3);
        assert_eq!(stats.total_failures, 3);

        // compile_fix: 1/3 = 0.333...
        let cf = stats
            .by_strategy
            .iter()
            .find(|s| s.strategy == "compile_fix")
            .unwrap();
        assert_eq!(cf.total, 3);
        assert_eq!(cf.successes, 1);
        assert!((cf.pass_rate - 1.0 / 3.0).abs() < 0.001);

        // test_fix: 1/2 = 0.5
        let tf = stats
            .by_strategy
            .iter()
            .find(|s| s.strategy == "test_fix")
            .unwrap();
        assert_eq!(tf.total, 2);
        assert_eq!(tf.successes, 1);
        assert_eq!(tf.pass_rate, 0.5);

        // escalate: 1/1 = 1.0
        let es = stats
            .by_strategy
            .iter()
            .find(|s| s.strategy == "escalate")
            .unwrap();
        assert_eq!(es.total, 1);
        assert_eq!(es.successes, 1);
        assert_eq!(es.pass_rate, 1.0);
    }

    #[test]
    fn test_log_serialization_roundtrip() {
        let mut log = PromptStrategyLog::new();
        log.add_entry(PromptStrategyEntry::new(
            "game_logic.dll",
            DllCategory::ProjectSpecific,
            "compile_fix",
            false,
            1,
        ));

        let json = serde_json::to_string(&log).expect("should serialize");
        let deserialized: PromptStrategyLog =
            serde_json::from_str(&json).expect("should deserialize");

        assert_eq!(deserialized.entries.len(), 1);
        assert_eq!(deserialized.entries[0].binary, "game_logic.dll");
        assert_eq!(deserialized.entries[0].strategy, "compile_fix");
        assert!(!deserialized.entries[0].success);
        assert_eq!(deserialized.entries[0].attempt, 1);
    }

    #[test]
    fn test_stats_serialization_roundtrip() {
        let mut log = PromptStrategyLog::new();
        log.add_entry(PromptStrategyEntry::new(
            "game_logic.dll",
            DllCategory::ProjectSpecific,
            "compile_fix",
            true,
            1,
        ));

        let stats = log.compute_stats();
        let json = serde_json::to_string(&stats).expect("should serialize");
        let deserialized: PromptStrategyStats =
            serde_json::from_str(&json).expect("should deserialize");

        assert_eq!(deserialized.total_entries, 1);
        assert_eq!(deserialized.total_successes, 1);
        assert_eq!(deserialized.by_category.len(), 1);
        assert_eq!(deserialized.by_strategy.len(), 1);
    }

    /// Build a varied entry for cap tests — binary, category, strategy and
    /// success all cycle so aggregates can't match by accident.
    fn make_strategy_entry(i: usize) -> PromptStrategyEntry {
        PromptStrategyEntry::new(
            if i.is_multiple_of(2) {
                "a.dll"
            } else {
                "b.dll"
            },
            match i % 3 {
                0 => DllCategory::MicrosoftSdk,
                1 => DllCategory::KnownThirdParty,
                _ => DllCategory::UnknownThirdParty,
            },
            if i.is_multiple_of(2) {
                "initial"
            } else {
                "compile_fix"
            },
            !i.is_multiple_of(4),
            i as u32 + 1,
        )
    }

    /// Serialize stats with the HashMap-derived breakdowns sorted by name,
    /// so two equal aggregates compare equal regardless of map order.
    fn sorted_stats_value(stats: PromptStrategyStats) -> serde_json::Value {
        let mut value = serde_json::to_value(stats).expect("serialize stats");
        for (array_key, name_key) in [("by_category", "category"), ("by_strategy", "strategy")] {
            value[array_key]
                .as_array_mut()
                .expect("breakdown is an array")
                .sort_by(|a, b| {
                    a[name_key]
                        .as_str()
                        .unwrap_or_default()
                        .cmp(b[name_key].as_str().unwrap_or_default())
                });
        }
        value
    }

    #[test]
    fn test_add_entry_caps_retained_entries_at_the_documented_max() {
        let mut log = PromptStrategyLog::new();
        for i in 0..crate::MAX_LOG_ENTRIES {
            log.add_entry(make_strategy_entry(i));
        }
        assert_eq!(log.entries.len(), crate::MAX_LOG_ENTRIES);
        assert_eq!(log.entries[0].attempt, 1);

        log.add_entry(make_strategy_entry(crate::MAX_LOG_ENTRIES));
        assert_eq!(log.entries.len(), crate::MAX_LOG_ENTRIES);
        assert_eq!(log.entries[0].attempt, 2);
    }

    #[test]
    fn test_compute_stats_cover_trimmed_entries() {
        let history = crate::MAX_LOG_ENTRIES + 25;

        // Reference: the same history with no cap applied, built by
        // assigning entries directly past `add_entry`.
        let mut reference = PromptStrategyLog::new();
        reference.entries = (0..history).map(make_strategy_entry).collect();

        // Capped: same history through `add_entry`, oldest entries trimmed.
        let mut capped = PromptStrategyLog::new();
        for i in 0..history {
            capped.add_entry(make_strategy_entry(i));
        }
        assert_eq!(capped.entries.len(), crate::MAX_LOG_ENTRIES);

        assert_eq!(
            sorted_stats_value(capped.compute_stats()),
            sorted_stats_value(reference.compute_stats()),
            "strategy stats must cover the whole run's history, not just the retained window"
        );
    }

    #[test]
    fn test_trimmed_log_round_trips_through_json() {
        let mut log = PromptStrategyLog::new();
        for i in 0..crate::MAX_LOG_ENTRIES + 5 {
            log.add_entry(make_strategy_entry(i));
        }

        let json = serde_json::to_string(&log).expect("serialize trimmed log");
        let back: PromptStrategyLog = serde_json::from_str(&json).expect("deserialize trimmed log");

        assert_eq!(back.entries.len(), crate::MAX_LOG_ENTRIES);
        assert_eq!(back.trimmed.entries, 5);
        assert_eq!(
            sorted_stats_value(back.compute_stats()),
            sorted_stats_value(log.compute_stats()),
            "a trimmed experiment log must round-trip with its aggregates intact"
        );
    }

    #[test]
    fn test_log_without_trimmed_field_stays_compatible() {
        // Experiment logs written before the cap (issue #82) carry no `trimmed` field.
        let json = r#"{"entries":[{"binary":"test.dll","dll_category":"ProjectSpecific","strategy":"initial","success":true,"attempt":1,"timestamp":1700000000}]}"#;
        let log: PromptStrategyLog =
            serde_json::from_str(json).expect("old experiment logs must still load");
        assert_eq!(log.entries.len(), 1);
        assert_eq!(log.trimmed.entries, 0);
    }
}
