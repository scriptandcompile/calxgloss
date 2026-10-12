//! Fault analytics handlers (issue #125, W3.1) — the first slice of the W3
//! historical views, and the scaffolding the later analytics tickets reuse:
//! this module, its registration on the shared router, and the analytics
//! wire types in `types.rs`.
//!
//! Registered in the shared routes: the data is the persisted fault log at
//! `re/analysis/fault_log.json`, never live pipeline state, so every router
//! answers it. Aggregation is computed on demand — the log file is the only
//! source of truth, nothing is maintained incrementally (the established
//! `compute_stats` pattern).
//!
//! Every endpoint honors the same optional filters — `category`, `binary`,
//! and the `from`/`to` UTC date range (inclusive) — so the view's summary
//! cards, bars, trend, and table always describe the same set of faults.
//! A malformed filter value is refused with 400 and the accepted shape,
//! never silently ignored: an operator who typed a filter must never be
//! shown unfiltered data.
//!
//! Counts cover the log's *retained* window. The log's trim accumulator
//! keeps whole-run totals for `compute_stats`, but trimmed events carry no
//! timestamp, so they cannot take part in the date filter or the trend
//! buckets — folding them into the cards would make the cards disagree with
//! the table underneath them.

use std::collections::HashMap;

use axum::{
    Json,
    extract::{Query, State},
};
use chrono::{DateTime, NaiveDate};
use std::collections::BTreeMap;

use calxgloss_types::{FaultCategory, FaultEvent, FaultLog, FaultSeverity};

use super::super::types::{
    FaultAnalytics, FaultAnalyticsEntry, FaultBinaryCount, FaultByBinaryResponse, FaultCount,
    FaultSummaryResponse, FaultTrendPoint, FaultTrendResponse,
};
use super::super::{ServerError, ServerState};
use super::process::{fault_log_path, load_json_or_default};

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
        if self.from.is_some() || self.to.is_some() {
            // A timestamp outside the representable range cannot be placed
            // in the range — it only survives when no date filter is active.
            let Some(day) = day_of(event.timestamp) else {
                return false;
            };
            if let Some(from) = self.from
                && day < from
            {
                return false;
            }
            if let Some(to) = self.to
                && day > to
            {
                return false;
            }
        }
        true
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

    let days = match (
        per_day.keys().next().copied(),
        per_day.keys().next_back().copied(),
    ) {
        (Some(first), Some(last)) => {
            let mut points: Vec<FaultTrendPoint> = Vec::new();
            let mut day = first;
            while day <= last {
                let count = per_day.get(&day).copied().unwrap_or(0);
                // Trailing 3-day window clipped to the bucketed range —
                // the first points average the days that actually exist.
                let window_sum: usize =
                    points.iter().rev().take(2).map(|p| p.count).sum::<usize>() + count;
                let window_days = points.len().min(2) + 1;
                points.push(FaultTrendPoint {
                    date: day.format("%Y-%m-%d").to_string(),
                    count,
                    moving_average: window_sum as f64 / window_days as f64,
                });
                day += chrono::Duration::days(1);
            }
            points
        }
        // Nothing matches: an honest empty series, not a fabricated run
        // of zeros.
        _ => Vec::new(),
    };

    Ok(Json(FaultTrendResponse { days }))
}
