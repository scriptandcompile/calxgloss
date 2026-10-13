//! Binaries view handlers — the whole-effort read over every classified
//! target binary (issue #130, W4.1).
//!
//! Registered in the shared routes: every read is persisted history, never
//! live pipeline state, so plain `serve` and `live` answer identically.
//! This module is the pattern the follow-up W4 binaries tickets copy —
//! one handler module owning the `/api/binaries/*` read paths and their
//! wire types in `types.rs`.
//!
//! The row set is the workspace's classification records (`re/classify/`,
//! read through the pipeline handler's one `disk_classifications` shape);
//! a record that is missing, corrupt, or name/category-less is no record
//! at all, so a workspace with none honestly answers an empty list rather
//! than a wall of zero rows. Category and strategy carry the decision
//! actually in force: the persisted classification-override layer
//! (`re/analysis/classification_overrides.json`) is applied on top, keyed
//! by binary identity verbatim — the same exact-match rule the override
//! endpoints and the analyzer use.
//!
//! Function counts come from all the review dashboard's units — the queue
//! plus recent activity, where the accepted ones live — counting only
//! function-translation work (classification, shim, and PAL units are not
//! functions). The status fold guarantees `total = done + queued + failed`
//! so no unit hides in an unshown bucket: `Accepted` is done,
//! `SendBack`/`PatchRequested` are the failing verdicts, and everything
//! else — queued, pending review, in progress, blocked, skipped — is
//! still waiting. Token totals come from the token-usage log with the
//! same case-insensitive binary join every other server comparison makes;
//! a missing or corrupt log means no recorded spend, not a failure.

use std::collections::HashMap;
use std::path::Path;

use axum::{Json, extract::State};

use calxgloss_types::{
    ClassificationOverrides, ReviewStatus, TokenUsageLog, WorkKind,
    classification_override_records_path,
};

use super::super::types::{BinariesListResponse, BinarySummaryRow};
use super::super::{ServerError, ServerState};
use super::pipeline::disk_classifications;
use super::process::{load_json_or_default, token_usage_log_path};

/// Per-binary function tallies folded from the dashboard's units.
#[derive(Debug, Default, Clone, Copy)]
struct FunctionCounts {
    total: usize,
    done: usize,
    failed: usize,
}

impl FunctionCounts {
    /// The waiting remainder — everything the binary owns that is neither
    /// done nor failing. Spelled once so the row's three counts always
    /// add up to the total.
    fn queued(&self) -> usize {
        self.total.saturating_sub(self.done + self.failed)
    }
}

/// Whether a unit's status counts as a failing verdict — the same two
/// roots the dashboard's auto-blocking cascade treats as failing. A
/// `Blocked` unit is a dependent of a failure, not a failure itself, so
/// it stays in the waiting bucket.
fn is_failing(status: &ReviewStatus) -> bool {
    matches!(
        status,
        ReviewStatus::SendBack | ReviewStatus::PatchRequested
    )
}

/// Tally function-translation units per binary, keyed by the lowercased
/// binary name so the join is case-insensitive like every other binary
/// comparison the server makes. The caller supplies all the dashboard's
/// units — accepted ones live in `recent_activity`, not the queue. A
/// dashboard that cannot be built is the caller's error, not this fold's.
fn function_counts_by_binary<'a>(
    units: impl IntoIterator<Item = &'a calxgloss_types::UnitOfWork>,
) -> HashMap<String, FunctionCounts> {
    let mut counts: HashMap<String, FunctionCounts> = HashMap::new();
    for unit in units {
        if unit.kind != WorkKind::FunctionTranslation {
            continue;
        }
        let entry = counts
            .entry(unit.binary.as_str().to_ascii_lowercase())
            .or_default();
        entry.total += 1;
        if unit.status == ReviewStatus::Accepted {
            entry.done += 1;
        } else if is_failing(&unit.status) {
            entry.failed += 1;
        }
    }
    counts
}

/// Sum token-usage-log entries per binary, keyed by the lowercased binary
/// name — the same retained-window aggregation the token-usage analytics
/// view does.
fn tokens_by_binary(repo_path: &Path) -> HashMap<String, usize> {
    let log = load_json_or_default::<TokenUsageLog>(&token_usage_log_path(repo_path));
    let mut totals: HashMap<String, usize> = HashMap::new();
    for entry in &log.entries {
        *totals
            .entry(entry.binary.as_str().to_ascii_lowercase())
            .or_default() += entry.tokens_used;
    }
    totals
}

/// Build the full binaries list payload from the workspace's persisted
/// history. Split from the handler so the aggregation is testable and the
/// follow-up W4 tickets grow the same shape.
fn binaries_list(repo_path: &Path) -> Result<BinariesListResponse, ServerError> {
    // The classification records decide which binaries exist at all; with
    // none readable, nothing downstream is worth reading either.
    let classifications = disk_classifications(repo_path);
    if classifications.is_empty() {
        return Ok(BinariesListResponse {
            binaries: Vec::new(),
        });
    }

    // The override layer in force, keyed by binary identity verbatim —
    // exact match, the same rule the override endpoints and the analyzer
    // hold. A missing or corrupt override document is no overrides.
    let overrides = load_json_or_default::<ClassificationOverrides>(
        &classification_override_records_path(repo_path),
    )
    .overrides;

    let dashboard = super::super::build_dashboard(repo_path)
        .map_err(|e| ServerError::internal(&e.to_string()))?;
    // All the dashboard's units, not just the queue: accepted ones live
    // in `recent_activity`, and a summary that never counted them would
    // always show zero done.
    let counts = function_counts_by_binary(
        dashboard
            .review_queue
            .iter()
            .chain(dashboard.recent_activity.iter()),
    );
    let tokens = tokens_by_binary(repo_path);

    let mut binaries: Vec<BinarySummaryRow> = classifications
        .values()
        .map(|record| {
            let name = record.binary.as_str();
            let r#override = overrides.get(name);
            let tally = counts
                .get(&name.to_ascii_lowercase())
                .copied()
                .unwrap_or_default();
            BinarySummaryRow {
                binary: record.binary.clone(),
                category: r#override
                    .as_ref()
                    .map(|o| serde_json::to_value(&o.category).ok())
                    .and_then(|v| v.and_then(|v| v.as_str().map(str::to_string)))
                    .unwrap_or_else(|| record.category.clone()),
                strategy: r#override
                    .as_ref()
                    .map(|o| o.strategy_label().to_string())
                    .unwrap_or_else(|| record.strategy.clone()),
                crate_replacement: match r#override.as_ref() {
                    Some(o) => o.crate_replacement.clone(),
                    None => record.crate_replacement.clone(),
                },
                overridden: r#override.is_some(),
                functions_total: tally.total,
                functions_done: tally.done,
                functions_queued: tally.queued(),
                functions_failed: tally.failed,
                tokens_used: tokens.get(&name.to_ascii_lowercase()).copied().unwrap_or(0),
            }
        })
        .collect();
    // Alphabetical by binary name — persisted history carries no run-plan
    // order, so the one stable order is the identity itself.
    binaries.sort_by(|a, b| a.binary.as_str().cmp(b.binary.as_str()));
    Ok(BinariesListResponse { binaries })
}

/// Handle `GET /api/binaries/list` — every classified target binary with
/// the summary the Binaries view renders: category and strategy in force
/// (override layer applied), function counts from the review dashboard's
/// units, and token totals from the token-usage log. Shared router: both
/// `serve` and `live` answer it, and a workspace with no readable
/// classification records honestly answers an empty list.
pub async fn api_get_binaries_list(
    State(state): State<ServerState>,
) -> Result<Json<BinariesListResponse>, ServerError> {
    Ok(Json(binaries_list(state.repo_path())?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use calxgloss_types::{BinaryIdentity, UnitOfWork};

    fn make_unit(binary: &str, kind: WorkKind, status: ReviewStatus) -> UnitOfWork {
        let accepted = status == ReviewStatus::Accepted;
        UnitOfWork {
            id: format!("{binary}/Func/v1"),
            name: format!("{binary}!Func"),
            kind,
            binary: BinaryIdentity::new(binary),
            function: Some("Func".to_string()),
            attempt: 1,
            status,
            accepted,
            unit_confidence: None,
            baseline_tests_passed: None,
            baseline_tests_total: None,
            verification_tests_passed: None,
            verification_tests_total: None,
            llm_model: None,
            context_tier: None,
            dependencies: Vec::new(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            known_gaps: Vec::new(),
            stale: calxgloss_types::dashboard::Staleness::Fresh,
        }
    }

    #[test]
    fn counts_fold_only_function_translation_units() {
        // Classification, shim, and PAL units are work, not functions —
        // the row's counts stay function counts.
        let counts = function_counts_by_binary(&[
            make_unit(
                "game_logic.dll",
                WorkKind::FunctionTranslation,
                ReviewStatus::Accepted,
            ),
            make_unit(
                "game_logic.dll",
                WorkKind::FunctionTranslation,
                ReviewStatus::SendBack,
            ),
            make_unit(
                "game_logic.dll",
                WorkKind::DllClassification,
                ReviewStatus::Accepted,
            ),
            make_unit(
                "game_logic.dll",
                WorkKind::ShimLayer,
                ReviewStatus::Accepted,
            ),
            make_unit("game_logic.dll", WorkKind::PalTrait, ReviewStatus::Queued),
        ]);
        let tally = counts
            .get("game_logic.dll")
            .expect("the binary's tally exists");
        assert_eq!(tally.total, 2, "only function units count");
        assert_eq!(tally.done, 1);
        assert_eq!(tally.failed, 1);
        assert_eq!(tally.queued(), 0);
    }

    #[test]
    fn failing_verdicts_are_send_back_and_patch_requested_only() {
        // Blocked is a dependent of a failure, and a reviewer skip is a
        // decision, not a verdict — both stay in the waiting bucket.
        let counts = function_counts_by_binary(&[
            make_unit(
                "a.dll",
                WorkKind::FunctionTranslation,
                ReviewStatus::SendBack,
            ),
            make_unit(
                "a.dll",
                WorkKind::FunctionTranslation,
                ReviewStatus::PatchRequested,
            ),
            make_unit(
                "a.dll",
                WorkKind::FunctionTranslation,
                ReviewStatus::Blocked,
            ),
            make_unit(
                "a.dll",
                WorkKind::FunctionTranslation,
                ReviewStatus::Skipped,
            ),
            make_unit("a.dll", WorkKind::FunctionTranslation, ReviewStatus::Queued),
            make_unit(
                "a.dll",
                WorkKind::FunctionTranslation,
                ReviewStatus::PendingReview,
            ),
            make_unit(
                "a.dll",
                WorkKind::FunctionTranslation,
                ReviewStatus::InProgress,
            ),
        ]);
        let tally = counts.get("a.dll").expect("the binary's tally exists");
        assert_eq!(tally.total, 7);
        assert_eq!(tally.done, 0);
        assert_eq!(
            tally.failed, 2,
            "only the two failing verdicts fold to failed"
        );
        assert_eq!(
            tally.queued(),
            5,
            "total = done + queued + failed always holds"
        );
    }

    #[test]
    fn unit_join_is_case_insensitive() {
        // The same binary spelled differently lands in one tally — the
        // case-insensitive join every server-side binary comparison uses.
        let counts = function_counts_by_binary(&[
            make_unit(
                "Game_Logic.dll",
                WorkKind::FunctionTranslation,
                ReviewStatus::Accepted,
            ),
            make_unit(
                "game_logic.dll",
                WorkKind::FunctionTranslation,
                ReviewStatus::Queued,
            ),
        ]);
        assert_eq!(counts.len(), 1, "one binary, one tally");
        let tally = counts.get("game_logic.dll").expect("lowercased key");
        assert_eq!(tally.total, 2);
    }
}
