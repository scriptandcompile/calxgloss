//! Unit process telemetry (issue #62): context tier, fault history, token
//! usage, and retry-strategy history for the unit detail panel.
//!
//! All data is derived from artifacts the pipeline already writes under
//! `re/analysis/` — the token-usage log, the fault log, and the per-function
//! Ghidra analysis artifact. No new persistence is introduced. Missing or
//! corrupt artifacts degrade to empty sections rather than errors.

use std::path::Path;

use calxgloss_types::{ContextTier, FaultLog, TokenUsageEntry, TokenUsageLog, detect_complexity};

use super::super::types::{
    FaultRecord, StrategyRecord, TierAttemptRecord, TierRationale, TierSection, TokenAttemptRecord,
    TokenSection, UnitProcess,
};

/// Builds the process-telemetry section for a unit of work.
///
/// Reads `re/analysis/token_usage.json`, `re/analysis/fault_log.json`, and
/// the Ghidra artifact at `re/analysis/{binary}/{function}.json`, filtering the
/// shared logs down to entries belonging to this unit. Every read failure
/// (missing file, corrupt JSON) degrades that section to its empty value.
pub(crate) fn build_unit_process(
    repo_path: &Path,
    unit: &calxgloss_types::UnitOfWork,
) -> UnitProcess {
    let function = unit.function.clone().unwrap_or_default();

    let entries = load_json_or_default::<TokenUsageLog>(
        &repo_path
            .join("re")
            .join("analysis")
            .join("token_usage.json"),
    )
    .entries
    .into_iter()
    .filter(|e| binary_matches(&e.binary, &unit.binary) && e.function == function)
    .collect::<Vec<_>>();

    let faults = load_json_or_default::<FaultLog>(
        &repo_path.join("re").join("analysis").join("fault_log.json"),
    )
    .entries
    .iter()
    .filter(|e| binary_matches(&e.binary, &unit.binary) && e.function == function)
    .map(FaultRecord::from)
    .collect();

    UnitProcess {
        tier: build_tier_section(unit, &entries, repo_path),
        faults,
        tokens: build_token_section(&entries),
        strategies: build_strategy_section(&entries),
    }
}

// ─── Tier section ────────────────────────────────────────────────────

/// Builds the tier section: the tier the unit ended up at, whether the
/// pipeline escalated, the rationale from the Ghidra artifact, and the
/// per-attempt tier/strategy history.
fn build_tier_section(
    unit: &calxgloss_types::UnitOfWork,
    entries: &[TokenUsageEntry],
    repo_path: &Path,
) -> TierSection {
    let sorted = sorted_entries(entries);

    let attempts: Vec<TierAttemptRecord> = sorted
        .iter()
        .copied()
        .map(TierAttemptRecord::from)
        .collect();

    // Prefer the tier recorded on the unit itself; function units carry it
    // on their token-usage entries instead, so fall back to the last
    // attempt that actually recorded a tier.
    let (tier, label, description) = match unit.context_tier {
        Some(number) => {
            let tier = ContextTier::from_number(number as u32);
            (
                Some(number),
                tier.map(|t| t.label().to_string()),
                tier.map(|t| t.description().to_string()),
            )
        }
        None => sorted
            .iter()
            .rev()
            .find_map(|e| ContextTier::from_label(&e.context_tier))
            .map(|t| {
                (
                    Some(t.number() as usize),
                    Some(t.label().to_string()),
                    Some(t.description().to_string()),
                )
            })
            .unwrap_or((None, None, None)),
    };

    let distinct_tiers = entries
        .iter()
        .map(|e| e.context_tier.as_str())
        .filter(|t| !t.is_empty())
        .collect::<std::collections::HashSet<_>>();

    TierSection {
        tier,
        label,
        description,
        escalated: distinct_tiers.len() > 1,
        rationale: load_tier_rationale(
            repo_path,
            &unit.binary,
            &unit.function.clone().unwrap_or_default(),
        ),
        attempts,
    }
}

/// Recomputes the tier rationale from the Ghidra analysis artifact,
/// mirroring the signals the pipeline feeds to `select_context_tier`
/// (complexity and Windows API call-site count).
/// Returns `None` when the artifact is missing or unreadable.
fn load_tier_rationale(repo_path: &Path, binary: &str, function: &str) -> Option<TierRationale> {
    if function.is_empty() {
        return None;
    }
    let artifact_path = repo_path
        .join("re")
        .join("analysis")
        .join(binary)
        .join(format!("{function}.json"));

    #[derive(serde::Deserialize)]
    struct RawApiCall {
        #[serde(default)]
        category: String,
    }

    #[derive(serde::Deserialize)]
    struct RawFunctionArtifact {
        #[serde(default)]
        disassembly: String,
        #[serde(default)]
        windows_apis: Vec<RawApiCall>,
    }

    let artifact: RawFunctionArtifact = std::fs::read_to_string(&artifact_path)
        .ok()
        .and_then(|content| serde_json::from_str(&content).ok())?;

    let categories: Vec<String> = artifact
        .windows_apis
        .iter()
        .map(|api| api.category.clone())
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();
    let api_call_count = artifact.windows_apis.len();
    let complexity = detect_complexity(&artifact.disassembly, &categories);

    Some(TierRationale {
        complexity: complexity.label().to_string(),
        api_call_count,
    })
}

// ─── Token and strategy sections ─────────────────────────────────────

/// Builds the token totals and per-attempt breakdown for this unit.
fn build_token_section(entries: &[TokenUsageEntry]) -> TokenSection {
    let total_tokens: usize = entries.iter().map(|e| e.tokens_used).sum();
    let successful_tokens: usize = entries
        .iter()
        .filter(|e| e.success)
        .map(|e| e.tokens_used)
        .sum();

    let per_attempt = sorted_entries(entries)
        .iter()
        .copied()
        .map(TokenAttemptRecord::from)
        .collect();

    TokenSection {
        total_tokens,
        successful_tokens,
        failed_tokens: total_tokens.saturating_sub(successful_tokens),
        attempts: entries.len(),
        per_attempt,
    }
}

/// Groups this unit's attempts by retry strategy, in first-use order,
/// with per-strategy success rates.
fn build_strategy_section(entries: &[TokenUsageEntry]) -> Vec<StrategyRecord> {
    let mut order: Vec<String> = Vec::new();
    let mut counts: std::collections::HashMap<String, (usize, usize)> =
        std::collections::HashMap::new();

    for entry in sorted_entries(entries) {
        let counts = counts.entry(entry.strategy.clone()).or_insert((0, 0));
        counts.0 += 1;
        if entry.success {
            counts.1 += 1;
        }
        if !order.contains(&entry.strategy) {
            order.push(entry.strategy.clone());
        }
    }

    order
        .into_iter()
        .map(|strategy| {
            let (attempts, successes) = counts.get(&strategy).copied().unwrap_or((0, 0));
            let success_rate = if attempts == 0 {
                0.0
            } else {
                successes as f64 / attempts as f64
            };
            StrategyRecord {
                strategy,
                attempts,
                successes,
                success_rate,
            }
        })
        .collect()
}

// ─── Artifact loading helpers ────────────────────────────────────────

/// Reads and parses a JSON artifact, degrading to the type's default value
/// when the file is missing or corrupt.
pub(crate) fn load_json_or_default<T>(path: &Path) -> T
where
    T: serde::de::DeserializeOwned + Default,
{
    std::fs::read_to_string(path)
        .ok()
        .and_then(|content| serde_json::from_str(&content).ok())
        .unwrap_or_default()
}

// ─── Queue effort estimates (issue #64) ──────────────────────────────

/// Path of the token-usage log artifact inside the repo — the single place
/// the layout is spelled out, shared by every handler that reads it.
pub(crate) fn token_usage_log_path(repo_path: &Path) -> std::path::PathBuf {
    repo_path
        .join("re")
        .join("analysis")
        .join("token_usage.json")
}

/// Estimates the effort per queued unit from the token-usage log's recorded
/// attempt durations: unit_id → average seconds per attempt.
///
/// Only function-level units get estimates. A unit with its own measured
/// attempts uses their average; a unit without its own history falls back
/// to the global average across all measured attempts. When the log has no
/// durations at all the map is empty, so the frontend renders `—` instead
/// of a fabricated number.
pub(crate) fn build_queue_effort(
    repo_path: &Path,
    queue: &[calxgloss_types::UnitOfWork],
) -> std::collections::HashMap<String, u64> {
    let log = load_json_or_default::<TokenUsageLog>(&token_usage_log_path(repo_path));
    let global_avg = match log.average_attempt_duration_secs() {
        Some(avg) => avg,
        None => return std::collections::HashMap::new(),
    };

    let mut effort = std::collections::HashMap::new();
    for unit in queue {
        if unit.kind != calxgloss_types::WorkKind::FunctionTranslation {
            continue;
        }
        let function = match unit.function.as_deref() {
            Some(f) if !f.is_empty() => f,
            _ => continue,
        };
        let durations: Vec<u64> = log
            .entries
            .iter()
            .filter(|e| binary_matches(&e.binary, &unit.binary) && e.function == function)
            .filter_map(|e| e.duration_secs)
            .collect();
        let avg = match durations.len() {
            0 => global_avg,
            n => durations.iter().sum::<u64>() as f64 / n as f64,
        };
        effort.insert(unit.id.clone(), avg.round() as u64);
    }
    effort
}

/// Returns entries sorted by attempt number (stable, so entries with the
/// same attempt keep their file order).
fn sorted_entries(entries: &[TokenUsageEntry]) -> Vec<&TokenUsageEntry> {
    let mut sorted: Vec<&TokenUsageEntry> = entries.iter().collect();
    sorted.sort_by_key(|e| e.attempt);
    sorted
}

/// True when a log-entry DLL name refers to the same binary as a unit's
/// DLL name. Both spell the binary identity verbatim, extension included
/// (issue #68); the comparison only folds case.
pub(crate) fn binary_matches(entry_binary: &str, unit_binary: &str) -> bool {
    entry_binary.eq_ignore_ascii_case(unit_binary)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dll_matches_compares_verbatim() {
        assert!(binary_matches("game_logic.dll", "game_logic.dll"));
        assert!(binary_matches("GAME_LOGIC.DLL", "game_logic.dll"));
        assert!(!binary_matches("game_logic.dll", "game_logic"));
        assert!(!binary_matches("audio.dll", "game_logic.dll"));
    }

    #[test]
    fn test_unit_process_renders_retained_window_after_trim() {
        let ws = tempfile::tempdir().expect("temp workspace");
        write_trimmed_token_log(ws.path());

        let unit = calxgloss_types::UnitOfWork {
            id: "game_logic.dll/DrawSprite".to_string(),
            name: "game_logic.dll!DrawSprite".to_string(),
            kind: calxgloss_types::WorkKind::FunctionTranslation,
            binary: "game_logic.dll".into(),
            function: Some("DrawSprite".to_string()),
            attempt: 5,
            status: calxgloss_types::ReviewStatus::Queued,
            accepted: false,
            unit_confidence: None,
            baseline_tests_passed: None,
            baseline_tests_total: None,
            verification_tests_passed: None,
            verification_tests_total: None,
            llm_model: None,
            context_tier: None,
            dependencies: Vec::new(),
            known_gaps: Vec::new(),
            stale: calxgloss_types::dashboard::Staleness::Fresh,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };

        let process = build_unit_process(ws.path(), &unit);

        // Per-attempt detail honestly covers the retained window only.
        assert_eq!(process.tokens.attempts, 2);
        assert_eq!(process.tokens.per_attempt.len(), 2);
        assert_eq!(process.tokens.total_tokens, 700);
        // Missing fault and Ghidra artifacts degrade to empty sections, never errors.
        assert!(process.faults.is_empty());
    }

    /// Write a trimmed token-usage log: two retained attempts for
    /// `game_logic.dll!DrawSprite`, three older attempts folded into the
    /// trimmed accumulator.
    fn write_trimmed_token_log(repo_path: &std::path::Path) {
        use calxgloss_types::{TokenUsageEntry, TokenUsageLog, TokenUsageTrim};

        let log_path = token_usage_log_path(repo_path);
        std::fs::create_dir_all(log_path.parent().expect("log has a parent"))
            .expect("create re/analysis");
        let mut log = TokenUsageLog::new();
        log.add_entry(TokenUsageEntry::new(
            "game_logic.dll",
            "DrawSprite",
            4,
            "test_fix",
            300,
            true,
        ));
        log.add_entry(TokenUsageEntry::new(
            "game_logic.dll",
            "DrawSprite",
            5,
            "escalate",
            400,
            true,
        ));
        log.trimmed = TokenUsageTrim {
            entries: 3,
            total_tokens: 900,
            successful_tokens: 600,
            by_binary: Vec::new(),
            duration_secs_sum: 0,
            duration_count: 0,
        };
        std::fs::write(
            &log_path,
            serde_json::to_string(&log).expect("serialize log"),
        )
        .expect("write token usage log");
    }
}
