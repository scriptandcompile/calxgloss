//! Binaries view handlers — the whole-effort read over every classified
//! target binary (issue #130, W4.1) and the per-binary detail behind an
//! expanded row (issue #132, W4.2).
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

use axum::{Json, extract::Path as PathExtractor, extract::State};

use calxgloss_types::{
    BinaryClassificationOverride, ClassificationOverrides, ReviewStatus, TokenUsageLog, WorkKind,
    classification_override_records_path,
};

use super::super::types::{
    BinariesListResponse, BinaryDetailResponse, BinaryFunctionRow, BinarySummaryRow,
    ClassificationInfo,
};
use super::super::{ServerError, ServerState};
use super::classification::classification_record_path;
use super::pipeline::disk_classifications;
use super::process::{binary_matches, load_json_or_default, token_usage_log_path};

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

/// The classification decision actually in force for one record: the
/// recorded classification with the persisted override layer applied on
/// top. Spelled once so the summary rows and the detail panel can never
/// disagree about what the analyzer would act on.
struct InForceDecision {
    category: String,
    strategy: String,
    crate_replacement: Option<String>,
    reason: Option<String>,
    overridden: bool,
}

/// Fold one record with its override (exact-key match, the same rule the
/// override endpoints and the analyzer hold). `recorded_reason` is the
/// raw record's stored reason, used only when no override is in force;
/// under one, the decision matches what the analyzer would act on — its
/// synthesized override reason, and a crate named only in
/// crate-replacement mode, where the recorded crate stands in for the
/// analyzer's table fallback (the web crate does not link the
/// classification table).
fn in_force_decision(
    record: &ClassificationInfo,
    r#override: Option<&BinaryClassificationOverride>,
    recorded_reason: Option<&str>,
) -> InForceDecision {
    match r#override {
        Some(o) => InForceDecision {
            category: serde_json::to_value(&o.category)
                .ok()
                .and_then(|v| v.as_str().map(str::to_string))
                .unwrap_or_else(|| record.category.clone()),
            strategy: o.strategy_label().to_string(),
            crate_replacement: if o.is_crate_replacement() {
                o.crate_replacement
                    .clone()
                    .or_else(|| record.crate_replacement.clone())
            } else {
                None
            },
            reason: Some(o.override_reason()),
            overridden: true,
        },
        None => InForceDecision {
            category: record.category.clone(),
            strategy: record.strategy.clone(),
            crate_replacement: record.crate_replacement.clone(),
            reason: recorded_reason.map(str::to_string),
            overridden: false,
        },
    }
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
            let decision = in_force_decision(record, overrides.get(name), None);
            let tally = counts
                .get(&name.to_ascii_lowercase())
                .copied()
                .unwrap_or_default();
            BinarySummaryRow {
                binary: record.binary.clone(),
                category: decision.category,
                strategy: decision.strategy,
                crate_replacement: decision.crate_replacement,
                overridden: decision.overridden,
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

/// Tally the binary's function-translation units into the detail panel's
/// function list — the same dashboard units the summary row's counts
/// fold, so the list's length is always that row's `functions_total`.
/// Alphabetical by function, then attempt: the same function can appear
/// once per attempt, each with its own review status.
fn functions_for_binary(
    units: impl IntoIterator<Item = calxgloss_types::UnitOfWork>,
    name: &str,
) -> Vec<BinaryFunctionRow> {
    let mut rows: Vec<BinaryFunctionRow> = units
        .into_iter()
        .filter(|unit| {
            unit.kind == WorkKind::FunctionTranslation && binary_matches(unit.binary.as_str(), name)
        })
        .map(|unit| BinaryFunctionRow {
            function: unit.function.unwrap_or_else(|| unit.name.clone()),
            attempt: unit.attempt,
            status: unit.status,
        })
        .collect();
    rows.sort_by(|a, b| a.function.cmp(&b.function).then(a.attempt.cmp(&b.attempt)));
    rows
}

/// Build the full detail payload for one binary from persisted history.
/// The requested spelling resolves to the record's verbatim identity
/// through the case-insensitive binary rule every other server
/// comparison makes; no readable classification record under any
/// spelling is an honest 404, never an empty shell.
fn binary_detail(repo_path: &Path, name: &str) -> Result<BinaryDetailResponse, ServerError> {
    let classifications = disk_classifications(repo_path);
    // Deterministic when several spellings of one name each hold a
    // record: the alphabetically first verbatim identity wins.
    let record = classifications
        .values()
        .filter(|c| binary_matches(c.binary.as_str(), name))
        .min_by_key(|c| c.binary.as_str())
        .ok_or_else(|| {
            ServerError::not_found(&format!(
                "no readable classification record for binary: {name}"
            ))
        })?;
    let name = record.binary.as_str();

    let overrides = load_json_or_default::<ClassificationOverrides>(
        &classification_override_records_path(repo_path),
    )
    .overrides;
    let r#override = overrides.get(name);

    // The recorded reasoning and the runtime flag live only in the raw
    // record — `disk_classifications` keeps the shape the pipeline rows
    // need. A record the reader already accepted cannot realistically
    // fail to re-read; if it does, those fields honestly stay
    // absent/false.
    let raw = std::fs::read_to_string(classification_record_path(repo_path, name))
        .ok()
        .and_then(|content| serde_json::from_str::<serde_json::Value>(&content).ok());
    let recorded_reason = raw
        .as_ref()
        .and_then(|v| v.get("reason"))
        .and_then(|v| v.as_str());
    let recorded_runtime = raw
        .as_ref()
        .and_then(|v| v.get("known_runtime"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let decision = in_force_decision(record, r#override, recorded_reason);

    // The glossary rule as the analyzer applies it: an override answers
    // through `is_runtime`, and a `RuntimeLibrary` category always
    // implies the flag.
    let known_runtime = match r#override {
        Some(o) => o.is_runtime(),
        None => recorded_runtime || decision.category == "RuntimeLibrary",
    };

    let dashboard = super::super::build_dashboard(repo_path)
        .map_err(|e| ServerError::internal(&e.to_string()))?;
    let functions = functions_for_binary(
        dashboard
            .review_queue
            .into_iter()
            .chain(dashboard.recent_activity),
        name,
    );

    Ok(BinaryDetailResponse {
        binary: record.binary.clone(),
        category: decision.category,
        strategy: decision.strategy,
        crate_replacement: decision.crate_replacement,
        overridden: decision.overridden,
        known_runtime,
        reason: decision.reason,
        exports_count: record.exported_symbols,
        imports_count: record.imported_symbols,
        functions,
    })
}

/// Handle `GET /api/binaries/{name}` — one binary's full detail: the
/// classification decision in force (override layer applied, with its
/// recorded reasoning and symbol counts) and the per-function list with
/// each unit's review status. Shared router: both `serve` and `live`
/// answer it from persisted history only. An unknown binary name — or
/// one whose only record is corrupt — honestly 404s.
pub async fn api_get_binary_detail(
    State(state): State<ServerState>,
    PathExtractor(name): PathExtractor<String>,
) -> Result<Json<BinaryDetailResponse>, ServerError> {
    Ok(Json(binary_detail(state.repo_path(), &name)?))
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

    #[test]
    fn detail_function_list_is_every_matching_unit_sorted() {
        // Both attempts of one function appear, each with its own status;
        // other binaries' and non-function units never join. The list's
        // length is always the summary row's functions_total.
        let mut units = vec![
            make_unit(
                "game_logic.dll",
                WorkKind::FunctionTranslation,
                ReviewStatus::Accepted,
            ),
            {
                let mut v2 = make_unit(
                    "game_logic.dll",
                    WorkKind::FunctionTranslation,
                    ReviewStatus::PendingReview,
                );
                v2.attempt = 2;
                v2
            },
            make_unit(
                "other.dll",
                WorkKind::FunctionTranslation,
                ReviewStatus::Accepted,
            ),
            make_unit(
                "game_logic.dll",
                WorkKind::DllClassification,
                ReviewStatus::Accepted,
            ),
        ];
        units[0].function = Some("DrawPrimitive".into());
        units[1].function = Some("DrawPrimitive".into());
        units[2].function = Some("DrawPrimitive".into());
        units[3].function = Some("Classify".into());

        let rows = functions_for_binary(units, "game_logic.dll");
        assert_eq!(rows.len(), 2, "only this binary's function units");
        assert_eq!(rows[0].function, "DrawPrimitive");
        assert_eq!(rows[0].attempt, 1);
        assert_eq!(rows[0].status, ReviewStatus::Accepted);
        assert_eq!(rows[1].attempt, 2);
        assert_eq!(rows[1].status, ReviewStatus::PendingReview);
    }

    #[test]
    fn detail_function_list_join_is_case_insensitive() {
        let rows = functions_for_binary(
            vec![make_unit(
                "Game_Logic.DLL",
                WorkKind::FunctionTranslation,
                ReviewStatus::Queued,
            )],
            "game_logic.dll",
        );
        assert_eq!(rows.len(), 1, "the requested spelling folds case");
    }

    #[test]
    fn in_force_decision_prefers_the_override_layer() {
        // The same fold the summary rows and the analyzer honor: category,
        // strategy label, crate, and reason come from the override;
        // without one, the record answers verbatim.
        let record = ClassificationInfo {
            binary: "d3d9.dll".into(),
            category: "MicrosoftSdk".into(),
            strategy: "CrateReplacement".into(),
            crate_replacement: Some("wgpu".into()),
            exported_symbols: 100,
            imported_symbols: 5,
        };
        let plain = in_force_decision(&record, None, Some("heuristic reason"));
        assert_eq!(plain.category, "MicrosoftSdk");
        assert_eq!(plain.strategy, "CrateReplacement");
        assert_eq!(plain.crate_replacement.as_deref(), Some("wgpu"));
        assert_eq!(plain.reason.as_deref(), Some("heuristic reason"));
        assert!(!plain.overridden);

        let r#override = calxgloss_types::BinaryClassificationOverride {
            category: calxgloss_types::DllCategory::KnownThirdParty,
            crate_replacement: Some("wgpu-rs".into()),
            known_runtime: false,
        };
        let steered = in_force_decision(&record, Some(&r#override), Some("heuristic reason"));
        assert_eq!(steered.category, "KnownThirdParty");
        assert_eq!(steered.strategy, "CrateReplacement");
        assert_eq!(steered.crate_replacement.as_deref(), Some("wgpu-rs"));
        // The reason is the analyzer's own account of an overridden
        // decision — the recorded heuristic reason does not carry over.
        assert_eq!(
            steered.reason.as_deref(),
            Some("operator override — KnownThirdParty (category set from the dashboard)")
        );
        assert!(steered.overridden);
    }

    #[test]
    fn override_crate_follows_the_analyzers_category_rule() {
        // A crate name means something only in crate-replacement modes:
        // elsewhere the analyzer drops it, and in those modes an override
        // naming no crate falls back to the recorded one (the web stand-in
        // for the analyzer's table lookup).
        let record = ClassificationInfo {
            binary: "game_logic.dll".into(),
            category: "ProjectSpecific".into(),
            strategy: "ReverseEngineer".into(),
            crate_replacement: Some("recorded-crate".into()),
            exported_symbols: 1,
            imported_symbols: 1,
        };
        let steered = in_force_decision(
            &record,
            Some(&calxgloss_types::BinaryClassificationOverride {
                category: calxgloss_types::DllCategory::ProjectSpecific,
                crate_replacement: Some("ignored-crate".into()),
                known_runtime: false,
            }),
            None,
        );
        assert_eq!(
            steered.crate_replacement, None,
            "a non-crate-replacement category drops the crate, as the analyzer does"
        );

        let steered = in_force_decision(
            &record,
            Some(&calxgloss_types::BinaryClassificationOverride {
                category: calxgloss_types::DllCategory::KnownThirdParty,
                crate_replacement: None,
                known_runtime: false,
            }),
            None,
        );
        assert_eq!(
            steered.crate_replacement.as_deref(),
            Some("recorded-crate"),
            "a crate-replacement override naming no crate keeps the recorded one"
        );
    }
}
