//! Analytics handlers — the historical views over the persisted logs in
//! `re/analysis/` (issues #125/#126/#127/#128, W3.1–W3.4): fault
//! analytics, token usage analytics, strategy analytics, and LLM
//! performance metrics, plus the scaffolding the later analytics tickets
//! reuse: this module, its registration on the shared router, and the
//! analytics wire types in `types.rs`.
//!
//! Registered in the shared routes: the data is the persisted logs, never
//! live pipeline state, so every router answers it. Aggregation is computed
//! on demand — the log file is the only source of truth, nothing is
//! maintained incrementally (the established `compute_stats` pattern).
//!
//! Every endpoint honors its optional filters — faults: `category`,
//! `binary`, and the `from`/`to` UTC date range (inclusive); token usage
//! and strategy analytics: the same `from`/`to` range — so a view's cards,
//! bars, trend, and table always describe the same set. A malformed filter
//! value is refused with 400 and the accepted shape, never silently
//! ignored: an operator who typed a filter must never be shown unfiltered
//! data.
//!
//! Counts cover the logs' *retained* windows. The trim accumulators keep
//! whole-run totals for `compute_stats`, but trimmed events carry no
//! timestamp, so they cannot take part in the date filter or the trend
//! buckets — folding them into the cards would make the cards disagree
//! with the tables underneath them.

use std::collections::HashMap;

use axum::{
    Json,
    extract::{Query, State},
};
use chrono::{DateTime, NaiveDate};
use std::collections::BTreeMap;

use calxgloss_types::{
    FaultCategory, FaultEvent, FaultLog, FaultSeverity, PromptStrategyEntry, PromptStrategyLog,
    TokenUsageEntry, TokenUsageLog,
};

use super::super::types::{
    FaultAnalytics, FaultAnalyticsEntry, FaultBinaryCount, FaultByBinaryResponse, FaultCount,
    FaultSummaryResponse, FaultTrendPoint, FaultTrendResponse, LlmMetricsByTierResponse,
    LlmMetricsSummaryResponse, LlmMetricsTierStats, LlmMetricsTimeoutPoint,
    StrategyAnalyticsByCategoryResponse, StrategyAnalyticsByStrategyResponse,
    StrategyAnalyticsCategoryStats, StrategyAnalyticsStrategyStats, TokenUsageBinaryShare,
    TokenUsageByBinaryResponse, TokenUsageByStrategyResponse, TokenUsageByTierResponse,
    TokenUsageStrategyStats, TokenUsageSummaryResponse, TokenUsageTierStats,
};
use super::super::{ServerError, ServerState};
use super::process::{
    fault_log_path, load_json_or_default, prompt_strategy_log_path, token_usage_log_path,
};

// ─── Filtering ─────────────────────────────────────────────────────────

/// The optional filters every faults analytics endpoint honors. Empty or
/// absent query parameters mean "no constraint on that axis".
struct FaultFilters {
    category: Option<FaultCategory>,
    binary: Option<String>,
    from: Option<NaiveDate>,
    to: Option<NaiveDate>,
}

impl FaultFilters {
    /// Parses the query parameters, refusing malformed values with a 400
    /// that names the accepted shape.
    fn from_params(params: &HashMap<String, String>) -> Result<Self, ServerError> {
        let category = match params.get("category").filter(|s| !s.is_empty()) {
            Some(raw) => Some(
                serde_json::from_value::<FaultCategory>(serde_json::Value::String(raw.clone()))
                    .map_err(|_| {
                        ServerError::BadRequest(format!(
                            "unknown fault category '{raw}' — expected one of: {}",
                            known_categories()
                        ))
                    })?,
            ),
            None => None,
        };
        let binary = params.get("binary").filter(|s| !s.is_empty()).cloned();
        let from = parse_day(params, "from")?;
        let to = parse_day(params, "to")?;
        Ok(Self {
            category,
            binary,
            from,
            to,
        })
    }

    /// True when the event falls inside every active filter. The binary
    /// axis matches case-insensitively, like every other binary
    /// comparison the server makes.
    fn matches(&self, event: &FaultEvent) -> bool {
        if let Some(category) = &self.category
            && &event.category != category
        {
            return false;
        }
        if let Some(binary) = &self.binary
            && !event.binary.eq_ignore_ascii_case(binary)
        {
            return false;
        }
        in_date_range(self.from, self.to, event.timestamp)
    }
}

/// Parses a `YYYY-MM-DD` query parameter into a UTC day, refusing a
/// malformed value with a 400.
fn parse_day(
    params: &HashMap<String, String>,
    key: &str,
) -> Result<Option<NaiveDate>, ServerError> {
    match params.get(key).filter(|s| !s.is_empty()) {
        Some(raw) => raw.parse::<NaiveDate>().map(Some).map_err(|_| {
            ServerError::BadRequest(format!(
                "invalid '{key}' date '{raw}' — expected YYYY-MM-DD"
            ))
        }),
        None => Ok(None),
    }
}

/// The category vocabulary, quoted for the 400 message.
fn known_categories() -> String {
    [
        FaultCategory::ContextWindowExceeded,
        FaultCategory::Hallucination,
        FaultCategory::InfiniteLoop,
        FaultCategory::BehaviorDivergence,
        FaultCategory::ResourceExhaustion,
        FaultCategory::SlowResponse,
        FaultCategory::PromptCorruption,
    ]
    .iter()
    .map(|c| c.to_string())
    .collect::<Vec<_>>()
    .join(", ")
}

/// The UTC calendar day a Unix-seconds timestamp falls on, `None` when the
/// timestamp is outside the representable range.
fn day_of(timestamp: u64) -> Option<NaiveDate> {
    DateTime::from_timestamp(timestamp as i64, 0).map(|dt| dt.date_naive())
}

/// True when the timestamp falls inside the inclusive `from`/`to` UTC date
/// range. A timestamp outside the representable range cannot be placed in
/// the range — it only survives when no date filter is active.
fn in_date_range(from: Option<NaiveDate>, to: Option<NaiveDate>, timestamp: u64) -> bool {
    if from.is_none() && to.is_none() {
        return true;
    }
    let Some(day) = day_of(timestamp) else {
        return false;
    };
    from.is_none_or(|from| day >= from) && to.is_none_or(|to| day <= to)
}

// ─── Shared read ───────────────────────────────────────────────────────

/// Loads the persisted fault log and applies the filters.
///
/// Returns the matching entries oldest first (append order preserved for
/// equal timestamps) alongside the total the log holds *before* filtering.
/// A missing or corrupt log loads as empty — the honest "no faults yet"
/// shape, never an error.
fn filtered_faults(
    state: &ServerState,
    params: &HashMap<String, String>,
) -> Result<(Vec<FaultAnalyticsEntry>, usize), ServerError> {
    let filters = FaultFilters::from_params(params)?;
    let log: FaultLog = load_json_or_default(&fault_log_path(state.repo_path()));

    let mut entries: Vec<FaultAnalyticsEntry> = log
        .entries
        .iter()
        .filter(|event| filters.matches(event))
        .map(FaultAnalyticsEntry::from)
        .collect();
    entries.sort_by_key(|entry| entry.timestamp);
    Ok((entries, log.entries.len()))
}

impl From<&FaultEvent> for FaultAnalyticsEntry {
    /// Projects a shared fault-log event onto the analytics wire format —
    /// every field verbatim, including the attached recovery guidance.
    fn from(event: &FaultEvent) -> Self {
        Self {
            binary: event.binary.clone(),
            function: event.function.clone(),
            attempt: event.attempt,
            strategy: event.strategy.clone(),
            category: event.category.clone(),
            severity: event.severity.clone(),
            description: event.description.clone(),
            recovery: event.recovery.clone(),
            timestamp: event.timestamp,
        }
    }
}

// ─── GET /api/faults ───────────────────────────────────────────────────

/// Serves the fault list with the full attempt identity triple and the
/// attached recovery guidance, honoring the category / binary / date-range
/// filters.
pub async fn api_get_faults(
    State(state): State<ServerState>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<FaultAnalytics>, ServerError> {
    let (entries, total_in_log) = filtered_faults(&state, &params)?;
    Ok(Json(FaultAnalytics {
        entries,
        total_in_log,
    }))
}

// ─── GET /api/faults/summary ───────────────────────────────────────────

/// Serves the summary-card counts: total faults broken down by category
/// and severity, over the same filtered set the table shows.
pub async fn api_get_faults_summary(
    State(state): State<ServerState>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<FaultSummaryResponse>, ServerError> {
    let (entries, _) = filtered_faults(&state, &params)?;

    let mut by_category: HashMap<&FaultCategory, usize> = HashMap::new();
    let mut warnings = 0usize;
    let mut errors = 0usize;
    let mut critical = 0usize;
    for entry in &entries {
        *by_category.entry(&entry.category).or_default() += 1;
        match entry.severity {
            FaultSeverity::Warning => warnings += 1,
            FaultSeverity::Error => errors += 1,
            FaultSeverity::Critical => critical += 1,
        }
    }

    let mut categories: Vec<FaultCount> = by_category
        .iter()
        .map(|(category, count)| FaultCount {
            name: category.to_string(),
            count: *count,
        })
        .collect();
    // Highest first; ties alphabetical so the cards keep a stable order.
    categories.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.name.cmp(&b.name)));

    // Severity is a closed vocabulary — always all three, in the fixed
    // warning → error → critical order, so the cards never shift shape.
    let severities = vec![
        FaultCount {
            name: FaultSeverity::Warning.to_string(),
            count: warnings,
        },
        FaultCount {
            name: FaultSeverity::Error.to_string(),
            count: errors,
        },
        FaultCount {
            name: FaultSeverity::Critical.to_string(),
            count: critical,
        },
    ];

    Ok(Json(FaultSummaryResponse {
        total: entries.len(),
        by_category: categories,
        by_severity: severities,
    }))
}

// ─── GET /api/faults/by-binary ─────────────────────────────────────────

/// Serves the per-target-binary fault counts for the bar chart.
pub async fn api_get_faults_by_binary(
    State(state): State<ServerState>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<FaultByBinaryResponse>, ServerError> {
    let (entries, _) = filtered_faults(&state, &params)?;

    let mut counts: HashMap<&str, usize> = HashMap::new();
    for entry in &entries {
        *counts.entry(entry.binary.as_str()).or_default() += 1;
    }

    let mut binaries: Vec<FaultBinaryCount> = counts
        .iter()
        .map(|(binary, count)| FaultBinaryCount {
            binary: (*binary).into(),
            count: *count,
        })
        .collect();
    // Highest first; ties alphabetical so the bars keep a stable order.
    binaries.sort_by(|a, b| {
        b.count
            .cmp(&a.count)
            .then_with(|| a.binary.as_str().cmp(b.binary.as_str()))
    });

    Ok(Json(FaultByBinaryResponse { binaries }))
}

// ─── GET /api/faults/trend ─────────────────────────────────────────────

/// Serves the faults-per-day series with the 3-day moving average,
/// bucketed server-side so the chart and the API agree on the numbers.
pub async fn api_get_faults_trend(
    State(state): State<ServerState>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<FaultTrendResponse>, ServerError> {
    let (entries, _) = filtered_faults(&state, &params)?;

    // Count per UTC day, keyed by day so gap days can be filled in.
    let mut per_day: BTreeMap<NaiveDate, usize> = BTreeMap::new();
    for entry in &entries {
        if let Some(day) = day_of(entry.timestamp) {
            *per_day.entry(day).or_default() += 1;
        }
    }

    let mut days: Vec<FaultTrendPoint> = Vec::new();
    for (day, count) in gap_filled_days(&per_day) {
        // Trailing 3-day window clipped to the bucketed range —
        // the first points average the days that actually exist.
        let window_sum: usize = days.iter().rev().take(2).map(|p| p.count).sum::<usize>() + count;
        let window_days = days.len().min(2) + 1;
        days.push(FaultTrendPoint {
            date: day.format("%Y-%m-%d").to_string(),
            count,
            moving_average: window_sum as f64 / window_days as f64,
        });
    }

    Ok(Json(FaultTrendResponse { days }))
}

// ─── Token usage analytics (issue #126, W3.2) ──────────────────────────

/// Loads the persisted token usage log and applies the date-range filter.
///
/// Returns the matching retained entries alongside the total the log holds
/// *before* filtering. A missing or corrupt log loads as empty — the
/// honest "no usage yet" shape, never an error.
fn filtered_token_usage(
    state: &ServerState,
    params: &HashMap<String, String>,
) -> Result<(Vec<TokenUsageEntry>, usize), ServerError> {
    let from = parse_day(params, "from")?;
    let to = parse_day(params, "to")?;
    let log: TokenUsageLog = load_json_or_default(&token_usage_log_path(state.repo_path()));

    let entries: Vec<TokenUsageEntry> = log
        .entries
        .iter()
        .filter(|entry| in_date_range(from, to, entry.timestamp))
        .cloned()
        .collect();
    Ok((entries, log.entries.len()))
}

// ─── GET /api/token-usage/summary ──────────────────────────────────────

/// Serves the summary split: total tokens consumed, broken into successful
/// and failed attempts, over the filtered set. Measured totals only — the
/// token-budget indicator waits on the constraints concept.
pub async fn api_get_token_usage_summary(
    State(state): State<ServerState>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<TokenUsageSummaryResponse>, ServerError> {
    let (entries, total_in_log) = filtered_token_usage(&state, &params)?;

    let total_tokens: usize = entries.iter().map(|e| e.tokens_used).sum();
    let successful_tokens: usize = entries
        .iter()
        .filter(|e| e.success)
        .map(|e| e.tokens_used)
        .sum();
    Ok(Json(TokenUsageSummaryResponse {
        total_tokens,
        successful_tokens,
        failed_tokens: total_tokens - successful_tokens,
        total_attempts: entries.len(),
        total_in_log,
    }))
}

// ─── GET /api/token-usage/by-binary ────────────────────────────────────

/// Serves the per-target-binary token totals with percentage shares of
/// the filtered total, for the bar chart.
pub async fn api_get_token_usage_by_binary(
    State(state): State<ServerState>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<TokenUsageByBinaryResponse>, ServerError> {
    let (entries, _) = filtered_token_usage(&state, &params)?;

    let mut totals: HashMap<&str, usize> = HashMap::new();
    for entry in &entries {
        *totals.entry(entry.binary.as_str()).or_default() += entry.tokens_used;
    }

    let total_tokens: usize = totals.values().sum();
    let mut binaries: Vec<TokenUsageBinaryShare> = totals
        .iter()
        .map(|(binary, tokens)| TokenUsageBinaryShare {
            binary: (*binary).into(),
            tokens: *tokens,
            share_percent: share_percent(*tokens, total_tokens),
        })
        .collect();
    // Highest first; ties alphabetical so the bars keep a stable order.
    binaries.sort_by(|a, b| {
        b.tokens
            .cmp(&a.tokens)
            .then_with(|| a.binary.as_str().cmp(b.binary.as_str()))
    });

    Ok(Json(TokenUsageByBinaryResponse { binaries }))
}

// ─── GET /api/token-usage/by-tier ──────────────────────────────────────

/// Serves the per-context-tier token totals — the breakdown for judging
/// whether tier escalation pays for itself. Entries written before tier
/// tracking carry an empty label and form their own honest bucket.
pub async fn api_get_token_usage_by_tier(
    State(state): State<ServerState>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<TokenUsageByTierResponse>, ServerError> {
    let (entries, _) = filtered_token_usage(&state, &params)?;

    let mut totals: HashMap<&str, (usize, usize)> = HashMap::new();
    for entry in &entries {
        let bucket = totals.entry(&entry.context_tier).or_default();
        bucket.0 += entry.tokens_used;
        bucket.1 += 1;
    }

    let mut tiers: Vec<TokenUsageTierStats> = totals
        .iter()
        .map(|(tier, (tokens, attempts))| TokenUsageTierStats {
            tier: (*tier).into(),
            tokens: *tokens,
            attempts: *attempts,
        })
        .collect();
    // Highest first; ties alphabetical so the bars keep a stable order.
    tiers.sort_by(|a, b| b.tokens.cmp(&a.tokens).then_with(|| a.tier.cmp(&b.tier)));

    Ok(Json(TokenUsageByTierResponse { tiers }))
}

// ─── GET /api/token-usage/by-strategy ──────────────────────────────────

/// Serves the per-retry-strategy token totals with a success rate per
/// strategy — which recovery paths burn tokens and which ones work.
pub async fn api_get_token_usage_by_strategy(
    State(state): State<ServerState>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<TokenUsageByStrategyResponse>, ServerError> {
    let (entries, _) = filtered_token_usage(&state, &params)?;

    let mut totals: HashMap<&str, (usize, usize, usize)> = HashMap::new();
    for entry in &entries {
        let bucket = totals.entry(&entry.strategy).or_default();
        bucket.0 += entry.tokens_used;
        bucket.1 += 1;
        if entry.success {
            bucket.2 += 1;
        }
    }

    let mut strategies: Vec<TokenUsageStrategyStats> = totals
        .iter()
        .map(
            |(strategy, (tokens, attempts, successes))| TokenUsageStrategyStats {
                strategy: (*strategy).into(),
                tokens: *tokens,
                attempts: *attempts,
                successes: *successes,
                // Every bucket holds at least one attempt, so the rate is
                // always defined — never a fabricated zero over zero attempts.
                success_rate: *successes as f64 * 100.0 / *attempts as f64,
            },
        )
        .collect();
    // Highest first; ties alphabetical so the rows keep a stable order.
    strategies.sort_by(|a, b| {
        b.tokens
            .cmp(&a.tokens)
            .then_with(|| a.strategy.cmp(&b.strategy))
    });

    Ok(Json(TokenUsageByStrategyResponse { strategies }))
}

// ─── Strategy analytics (issue #127, W3.3) ─────────────────────────────

/// Loads the persisted prompt-strategy log and applies the date-range
/// filter.
///
/// Returns the matching retained entries alongside the total the log holds
/// *before* filtering. A missing or corrupt log loads as empty — the
/// honest "no attempts yet" shape, never an error.
fn filtered_prompt_strategy(
    state: &ServerState,
    params: &HashMap<String, String>,
) -> Result<(Vec<PromptStrategyEntry>, usize), ServerError> {
    let from = parse_day(params, "from")?;
    let to = parse_day(params, "to")?;
    let log: PromptStrategyLog = load_json_or_default(&prompt_strategy_log_path(state.repo_path()));

    let entries: Vec<PromptStrategyEntry> = log
        .entries
        .iter()
        .filter(|entry| in_date_range(from, to, entry.timestamp))
        .cloned()
        .collect();
    Ok((entries, log.entries.len()))
}

// ─── GET /api/strategy-analytics/by-strategy ───────────────────────────

/// Serves attempts, successes, failures, and pass rate per retry strategy
/// — the evidence for improving retry-strategy selection.
pub async fn api_get_strategy_analytics_by_strategy(
    State(state): State<ServerState>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<StrategyAnalyticsByStrategyResponse>, ServerError> {
    let (entries, total_in_log) = filtered_prompt_strategy(&state, &params)?;

    let mut totals: HashMap<&str, (usize, usize)> = HashMap::new();
    for entry in &entries {
        let bucket = totals.entry(entry.retry_strategy.as_str()).or_default();
        bucket.0 += 1;
        if entry.success {
            bucket.1 += 1;
        }
    }

    let mut strategies: Vec<StrategyAnalyticsStrategyStats> = totals
        .iter()
        .map(
            |(strategy, (attempts, successes))| StrategyAnalyticsStrategyStats {
                strategy: (*strategy).into(),
                attempts: *attempts,
                successes: *successes,
                failures: attempts - successes,
                // Every bucket holds at least one attempt, so the rate is
                // always defined — never a fabricated zero over zero attempts.
                pass_rate: *successes as f64 * 100.0 / *attempts as f64,
            },
        )
        .collect();
    // Most attempts first; ties alphabetical so the rows keep a stable order.
    strategies.sort_by(|a, b| {
        b.attempts
            .cmp(&a.attempts)
            .then_with(|| a.strategy.cmp(&b.strategy))
    });

    Ok(Json(StrategyAnalyticsByStrategyResponse {
        strategies,
        total_in_log,
    }))
}

// ─── GET /api/strategy-analytics/by-category ───────────────────────────

/// Serves pass rates broken down by binary category — whether one class of
/// binary systematically defeats the current strategies. The category
/// label is the `DllCategory` debug name, the same vocabulary the log's
/// own aggregates use.
pub async fn api_get_strategy_analytics_by_category(
    State(state): State<ServerState>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<StrategyAnalyticsByCategoryResponse>, ServerError> {
    let (entries, total_in_log) = filtered_prompt_strategy(&state, &params)?;

    let mut totals: HashMap<String, (usize, usize)> = HashMap::new();
    for entry in &entries {
        let bucket = totals
            .entry(format!("{:?}", entry.dll_category))
            .or_default();
        bucket.0 += 1;
        if entry.success {
            bucket.1 += 1;
        }
    }

    let mut categories: Vec<StrategyAnalyticsCategoryStats> = totals
        .iter()
        .map(
            |(category, (attempts, successes))| StrategyAnalyticsCategoryStats {
                category: category.clone(),
                attempts: *attempts,
                successes: *successes,
                failures: attempts - successes,
                pass_rate: *successes as f64 * 100.0 / *attempts as f64,
            },
        )
        .collect();
    // Most attempts first; ties alphabetical so the bars keep a stable order.
    categories.sort_by(|a, b| {
        b.attempts
            .cmp(&a.attempts)
            .then_with(|| a.category.cmp(&b.category))
    });

    Ok(Json(StrategyAnalyticsByCategoryResponse {
        categories,
        total_in_log,
    }))
}

// ─── LLM performance metrics (issue #128, W3.4) ────────────────────────

/// True when the fault is a resource-exhaustion fault of the *timeout*
/// kind — the vocabulary the pipeline's `ResourceExhaustionFault` writes
/// into the event's `metadata.reason`. Overloaded faults and every other
/// category stay out of the timeout count.
fn is_timeout_fault(event: &FaultEvent) -> bool {
    event.category == FaultCategory::ResourceExhaustion
        && event
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("reason"))
            .and_then(|reason| reason.as_str())
            == Some("timeout")
}

/// Nearest-rank percentile over ascending-sorted durations, in whole
/// seconds: the smallest observed value at or above `percent`% of the
/// measurements. Always an actually recorded duration — never interpolated
/// from a value no attempt ever took — and `None` over an empty set, so
/// unmeasured history renders as an em dash rather than a fabricated zero.
fn percentile_secs(sorted: &[u64], percent: f64) -> Option<u64> {
    if sorted.is_empty() {
        return None;
    }
    let rank = (percent / 100.0 * sorted.len() as f64).ceil() as usize;
    Some(sorted[(rank - 1).min(sorted.len() - 1)])
}

/// Serves the attempt-duration percentiles and the timeout frequency:
/// P50/P95/P99 over the token log's *recorded* attempt durations (entries
/// written before duration tracking existed are excluded, never imputed),
/// and timeouts counted from resource-exhaustion faults of the timeout
/// kind, bucketed per UTC day server-side. Both logs honor the same
/// `from`/`to` range so the cards and the trend describe the same window.
pub async fn api_get_llm_metrics_summary(
    State(state): State<ServerState>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<LlmMetricsSummaryResponse>, ServerError> {
    let (entries, total_in_log) = filtered_token_usage(&state, &params)?;

    let mut durations: Vec<u64> = entries
        .iter()
        .filter_map(|entry| entry.duration_secs)
        .collect();
    durations.sort_unstable();

    let from = parse_day(&params, "from")?;
    let to = parse_day(&params, "to")?;
    let fault_log: FaultLog = load_json_or_default(&fault_log_path(state.repo_path()));
    let timeouts: Vec<&FaultEvent> = fault_log
        .entries
        .iter()
        .filter(|event| is_timeout_fault(event) && in_date_range(from, to, event.timestamp))
        .collect();

    // Count per UTC day, keyed by day so gap days can be filled in — the
    // same honest gap-fill the faults trend uses: zeros only between days
    // that actually hold a timeout, never a fabricated run outside them.
    let mut per_day: BTreeMap<NaiveDate, usize> = BTreeMap::new();
    for event in &timeouts {
        if let Some(day) = day_of(event.timestamp) {
            *per_day.entry(day).or_default() += 1;
        }
    }
    let timeout_trend = gap_filled_days(&per_day)
        .into_iter()
        .map(|(day, count)| LlmMetricsTimeoutPoint {
            date: day.format("%Y-%m-%d").to_string(),
            count,
        })
        .collect();

    Ok(Json(LlmMetricsSummaryResponse {
        total_attempts: entries.len(),
        measured_attempts: durations.len(),
        p50_secs: percentile_secs(&durations, 50.0),
        p95_secs: percentile_secs(&durations, 95.0),
        p99_secs: percentile_secs(&durations, 99.0),
        timeouts: timeouts.len(),
        timeout_trend,
        total_in_log,
    }))
}

/// Serves attempt duration correlated by context tier — whether the
/// heavier tiers pay for themselves in wall-clock time as well as tokens.
/// The issue asked for a breakdown by *model* tier; no model name or tier
/// is persisted per attempt, so the honest axis is the context tier the
/// logs do record — the same axis the token usage view breaks down by.
/// Entries written before tier tracking carry an empty label and form
/// their own honest bucket; a tier whose attempts recorded no durations
/// answers with `None` percentiles, never an imputed zero.
pub async fn api_get_llm_metrics_by_tier(
    State(state): State<ServerState>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<LlmMetricsByTierResponse>, ServerError> {
    let (entries, total_in_log) = filtered_token_usage(&state, &params)?;

    // (attempts, measured durations ascending) per tier — durations are
    // pushed in entry order, so each bucket sorts before taking its
    // percentile.
    let mut buckets: HashMap<&str, (usize, Vec<u64>)> = HashMap::new();
    for entry in &entries {
        let bucket = buckets.entry(entry.context_tier.as_str()).or_default();
        bucket.0 += 1;
        if let Some(secs) = entry.duration_secs {
            bucket.1.push(secs);
        }
    }

    let mut tiers: Vec<LlmMetricsTierStats> = buckets
        .into_iter()
        .map(|(tier, (attempts, mut durations))| {
            durations.sort_unstable();
            LlmMetricsTierStats {
                tier: tier.into(),
                attempts,
                measured_attempts: durations.len(),
                p50_secs: percentile_secs(&durations, 50.0),
                p95_secs: percentile_secs(&durations, 95.0),
            }
        })
        .collect();
    // Most attempts first; ties alphabetical so the rows keep a stable
    // order (the untracked empty label sorts first, honestly).
    tiers.sort_by(|a, b| {
        b.attempts
            .cmp(&a.attempts)
            .then_with(|| a.tier.cmp(&b.tier))
    });

    Ok(Json(LlmMetricsByTierResponse {
        tiers,
        total_in_log,
    }))
}

/// One breakdown row's percentage share of the filtered total (0.0–100.0).
fn share_percent(part: usize, whole: usize) -> f64 {
    if whole == 0 {
        // No matching attempts means no rows — a share is never asked for
        // over an empty total; guard anyway so nothing divides by zero.
        return 0.0;
    }
    part as f64 * 100.0 / whole as f64
}

/// Gap-filled per-day buckets: one entry per UTC day from the first day
/// that holds an event to the last, zero-count days filled in between —
/// zeros only between days that actually hold events, never a fabricated
/// run outside them. An empty input answers an empty series.
fn gap_filled_days(per_day: &BTreeMap<NaiveDate, usize>) -> Vec<(NaiveDate, usize)> {
    let (Some(first), Some(last)) = (
        per_day.keys().next().copied(),
        per_day.keys().next_back().copied(),
    ) else {
        return Vec::new();
    };
    let mut days = Vec::new();
    let mut day = first;
    while day <= last {
        days.push((day, per_day.get(&day).copied().unwrap_or(0)));
        day += chrono::Duration::days(1);
    }
    days
}
