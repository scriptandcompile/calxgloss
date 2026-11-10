//! Binaries view handlers — the whole-effort read over every classified
//! target binary (issue #130, W4.1), the per-binary detail behind an
//! expanded row (issue #132, W4.2), the shim-layer tracker inside
//! that panel (issue #133, W4.3), and the PAL-trait tracker beside it
//! (issue #134, W4.4).
//!
//! Registered in the shared routes: every read is persisted history, never
//! live pipeline state, so plain `serve` and `live` answer identically.
//! This module is the pattern the follow-up W4 binaries tickets copy —
//! one handler module owning the `/api/binaries/*` read paths and their
//! wire types in `types.rs`.
//!
//! The row set is the workspace's classification records (`re/classify/`,
//! read through the review-surface reader, issue #461); a record that is
//! missing, corrupt, or has no name or category is no
//! record at all, so a workspace with none honestly answers an empty list
//! rather than a wall of zero rows. Category and strategy show the decision
//! actually in force: the persisted classification-override layer
//! (`re/analysis/classification_overrides.json`) is applied on top, keyed
//! by binary identity verbatim — the same exact-match rule the override
//! endpoints and the analyzer use.
//!
//! Function counts come from all the review dashboard's units — the queue
//! plus recent activity, where the accepted ones live — counting only
//! function-translation work (classification, shim, and PAL units are not
//! functions). The status grouping guarantees `total = done + queued + failed`
//! so no unit hides in an unshown bucket: `Accepted` is done,
//! `SendBack`/`PatchRequested` are the failing verdicts, and everything
//! else — queued, pending review, in progress, blocked, skipped — is
//! still waiting. Token totals come from the token-usage log with the
//! same case-insensitive binary join every other server comparison makes;
//! a missing or corrupt log means no recorded spend, not a failure.
//!
//! The PAL tracker (issue #134, W4.4) derives a binary's *needed* traits
//! on demand from the persisted per-function analysis artifacts — the
//! `windows_apis` categories recorded under `re/analysis/{binary}/` —
//! mapped category→trait with the translator's Tier-4 extraction shape
//! (`PAL_TRAIT_CATEGORIES` below, a web-side mirror; the pipeline is
//! never touched). *Existence* is detected from the workspace's
//! generated PAL/shim source artifacts — the shared PAL crate under
//! `scratch/pal/src/` and the generated `re/shims/{binary}/shim.rs` —
//! introducing no new persisted "defined traits" record. Missing or
//! corrupt artifacts on either side honestly answer an empty trait list
//! or missing markers, never a fabricated trait list.

use std::collections::HashMap;
use std::path::Path;

use axum::{Json, extract::Path as PathExtractor, extract::State};

use calxgloss_types::{BinaryIdentity, ReviewStatus, TokenUsageLog, WorkKind};

use super::super::ServerError;
use super::super::review_reader::ReviewSurfaceReader;
use super::super::types::{
    BinariesListResponse, BinaryDetailResponse, BinaryFunctionRow, BinarySummaryRow,
    PalStatusResponse, PalTraitStatus, ShimBranchInfo, ShimStatusResponse, ShimVerificationInfo,
};
use super::process::{binary_matches, load_json_or_default, token_usage_log_path};

/// Per-binary function tallies built from the dashboard's units.
#[derive(Debug, Default, Clone, Copy)]
struct FunctionCounts {
    total: usize,
    done: usize,
    failed: usize,
    /// Open unknown records across this binary's units — `None` when any
    /// unit's ledger state is unknown, never a collapsed zero (issue
    /// #376).
    unknowns_open: Option<usize>,
}

impl FunctionCounts {
    /// The waiting remainder — everything the binary owns that is neither
    /// done nor failing. Defined once so the row's three counts always
    /// add up to the total.
    fn queued(&self) -> usize {
        self.total.saturating_sub(self.done + self.failed)
    }
}

/// Whether a unit's status counts as a failing verdict — the same two
/// verdicts the dashboard's auto-blocking cascade treats as failing. A
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
/// dashboard that cannot be built is the caller's error, not this
/// function's.
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
        // Open unknowns fold like the tallies do, with one honesty rule
        // (issue #376): any unit whose ledger state is unknown leaves the
        // binary's open count unknown — never summed past, never shown as
        // zero. The first unit of a binary seeds the reading; from then on
        // an unknown in either hand poisons the sum for good.
        entry.unknowns_open = if entry.total == 1 {
            unit.unknowns.open_count()
        } else {
            match (entry.unknowns_open, unit.unknowns.open_count()) {
                (Some(sum), Some(open)) => Some(sum + open),
                _ => None,
            }
        };
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
/// follow-up W4 tickets extend the same shape.
fn binaries_list(reader: &ReviewSurfaceReader) -> Result<BinariesListResponse, ServerError> {
    let repo_path = reader.repo_path();
    // The classification records decide which binaries exist at all; with
    // none readable, nothing downstream is worth reading either.
    let classifications = reader.binary_classifications()?;
    if classifications.count() == 0 {
        return Ok(BinariesListResponse {
            binaries: Vec::new(),
        });
    }

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
        .filter_map(|record| {
            // The reader's kept records all name their binary — unpacking,
            // not a second policy. The decision in force comes from the
            // reader's single record-and-override fold.
            let name = record.binary.as_deref()?;
            let decision = classifications.in_force(record);
            let tally = counts
                .get(&name.to_ascii_lowercase())
                .copied()
                .unwrap_or_default();
            Some(BinarySummaryRow {
                binary: BinaryIdentity::new(name),
                category: decision.category,
                strategy: decision.strategy,
                crate_replacement: decision.crate_replacement,
                overridden: decision.overridden,
                functions_total: tally.total,
                functions_done: tally.done,
                functions_queued: tally.queued(),
                functions_failed: tally.failed,
                unknowns_open: tally.unknowns_open,
                tokens_used: tokens.get(&name.to_ascii_lowercase()).copied().unwrap_or(0),
            })
        })
        .collect();
    // Alphabetical by binary name — persisted history has no run-plan
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
    State(reader): State<ReviewSurfaceReader>,
) -> Result<Json<BinariesListResponse>, ServerError> {
    Ok(Json(binaries_list(&reader)?))
}

/// Tally the binary's function-translation units into the detail panel's
/// function list — the same dashboard units the summary row's counts are
/// built from, so the list's length is always that row's `functions_total`.
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
            unknowns_open: unit.unknowns.open_count(),
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
fn binary_detail(
    reader: &ReviewSurfaceReader,
    name: &str,
) -> Result<BinaryDetailResponse, ServerError> {
    let repo_path = reader.repo_path();
    let classifications = reader.binary_classifications()?;
    let record = classifications.find(name)?;
    let name = record.binary.as_deref().unwrap_or(name);
    let decision = classifications.in_force(record);

    // The glossary rule as the analyzer applies it: an override answers
    // through `is_runtime`, and a `RuntimeLibrary` category always
    // implies the flag.
    let known_runtime = match classifications.override_for(record) {
        Some(o) => o.is_runtime(),
        None => record.known_runtime || decision.category == "RuntimeLibrary",
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
        binary: BinaryIdentity::new(name),
        category: decision.category,
        strategy: decision.strategy,
        crate_replacement: decision.crate_replacement,
        overridden: decision.overridden,
        known_runtime,
        reason: decision.reason,
        exports_count: record.exports_count,
        imports_count: record.imports_count,
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
    State(reader): State<ReviewSurfaceReader>,
    PathExtractor(name): PathExtractor<String>,
) -> Result<Json<BinaryDetailResponse>, ServerError> {
    Ok(Json(binary_detail(&reader, &name)?))
}

/// Read the dashboard's shim unit for one crate into the tracker's
/// branch state. The join is the same exact-crate-name rule the
/// dashboard's own dependency wiring holds (shim units keyed by their
/// function, the crate name); when the crate has no shim unit the result
/// is `None` — honestly "no shim branch", never a guessed verdict.
fn shim_branch_state(
    units: impl IntoIterator<Item = calxgloss_types::UnitOfWork>,
    krate: &str,
) -> Option<ShimBranchInfo> {
    let unit = units
        .into_iter()
        .find(|unit| unit.kind == WorkKind::ShimLayer && unit.function.as_deref() == Some(krate))?;
    Some(ShimBranchInfo {
        name: format!("re/shim/{krate}"),
        merged: unit.status == ReviewStatus::Accepted,
        sent_back: unit.status == ReviewStatus::SendBack,
    })
}

/// Build the full shim tracker payload for one binary from persisted
/// artifacts only: the shim files under `re/shims/{binary}/` (mappings
/// and verification result) and the shim branch's acceptance state in
/// the dashboard's branch model. Whether a shim is expected at all
/// follows the decision in force — the override layer applied — so an
/// overridden binary is tracked against the crate the analyzer would
/// actually build on. A crate-replacement binary with no readable
/// artifacts honestly reports not generated; when the decision in force
/// names no crate replacement, the binary honestly reports no shim
/// expected.
fn shim_status(
    reader: &ReviewSurfaceReader,
    name: &str,
) -> Result<ShimStatusResponse, ServerError> {
    let repo_path = reader.repo_path();
    let classifications = reader.binary_classifications()?;
    let record = classifications.find(name)?;
    let name = record.binary.as_deref().unwrap_or(name);
    let decision = classifications.in_force(record);

    // The reader walks the shim artifact directory (issue #464) — each
    // filed document as its own reading.
    let readout = reader.shim_readout(name);
    let mappings = readout.mappings;
    let verification = readout.verification;

    // Only a decision in force that names a crate has a shim branch to
    // look for; the branch model is the same dashboard the rest of this
    // module reads, so merged/sent-back come from its persisted verdicts.
    let branch = match decision.crate_replacement.as_deref() {
        Some(krate) => {
            let dashboard = super::super::build_dashboard(repo_path)
                .map_err(|e| ServerError::internal(&e.to_string()))?;
            shim_branch_state(
                dashboard
                    .review_queue
                    .into_iter()
                    .chain(dashboard.recent_activity),
                krate,
            )
        }
        None => None,
    };

    Ok(ShimStatusResponse {
        binary: BinaryIdentity::new(name),
        shim_expected: decision.crate_replacement.is_some(),
        crate_replacement: decision.crate_replacement,
        generated: mappings.is_some(),
        mapping_count: mappings.as_ref().map(|shim| shim.mappings.len()),
        verification: verification.map(|v| ShimVerificationInfo {
            compiled: v.compiled,
            tests_passed: v.tests_passed,
            tests_total: v.tests_total,
            edge_tests_passed: v.edge_tests_passed,
            edge_tests_total: v.edge_tests_total,
        }),
        branch,
    })
}

/// Handle `GET /api/binaries/{name}/shim-status` — the shim-layer
/// tracker for one binary: whether a shim exists (from the shim
/// artifacts the shim pipeline persists under `re/shims/{binary}/`),
/// its mapping count, its verification outcome, and whether the shim
/// branch was merged or sent back (from the dashboard's branch model).
/// Shared router: both `serve` and `live` answer it from persisted
/// artifacts only. Missing or corrupt artifacts honestly answer "not
/// generated" with the derived fields absent; an unknown binary name
/// honestly 404s like every other binaries read.
pub async fn api_get_binary_shim_status(
    State(reader): State<ReviewSurfaceReader>,
    PathExtractor(name): PathExtractor<String>,
) -> Result<Json<ShimStatusResponse>, ServerError> {
    Ok(Json(shim_status(&reader, &name)?))
}

// ─── PAL tracker (issue #134, W4.4) ────────────────────────────────────

/// The category→trait mapping the PAL tracker uses, mirroring
/// the translator's Tier-4 PAL extraction (`extract_pal_traits` in
/// `calxgloss-translator::retry::helpers`): the same categories demand
/// the same traits. Kept as a web-side derivation on purpose — W4
/// observes the pipeline's outputs, never touches it. Categories are
/// matched case-insensitively like every other server comparison; a
/// category the Tier-4 extraction maps to no trait contributes nothing.
const PAL_TRAIT_CATEGORIES: &[(&str, &[&str])] = &[
    (
        "GraphicsDevice",
        &["DirectX", "DirectX10", "DirectX11", "DirectX12"],
    ),
    ("Graphics2D", &["Gdi", "GdiPlus", "Direct2D"]),
    ("AudioDevice", &["Audio"]),
    ("WindowManager", &["Win32Gui"]),
    ("PlatformCore", &["Win32Core"]),
    ("ComObject", &["Com"]),
];

/// The trait one recorded API-call category demands, per the Tier-4
/// shape. `None` is the Tier-4 catch-all: the category needs no PAL
/// trait.
fn pal_trait_for_category(category: &str) -> Option<&'static str> {
    PAL_TRAIT_CATEGORIES
        .iter()
        .find(|(_, categories)| categories.iter().any(|c| category.eq_ignore_ascii_case(c)))
        .map(|(trait_name, _)| *trait_name)
}

/// Group recorded categories into the traits they demand, sorted by
/// trait name with each trait's verbatim categories sorted — the
/// deterministic order the exact-JSON contract pins. Categories that map
/// to no trait are dropped, so the trait list is never fabricated from
/// them. Also drives the pipeline poll's PAL-readiness summary
/// (issue #243) — the same derivation, not a second implementation.
pub(crate) fn needed_pal_traits(categories: &[String]) -> Vec<PalTraitStatus> {
    let mut by_trait: std::collections::BTreeMap<&'static str, Vec<String>> =
        std::collections::BTreeMap::new();
    for category in categories {
        if let Some(trait_name) = pal_trait_for_category(category) {
            by_trait
                .entry(trait_name)
                .or_default()
                .push(category.clone());
        }
    }
    by_trait
        .into_iter()
        .map(|(name, mut categories)| {
            // Verbatim spellings, but deterministic: sorted and deduped so
            // the same workspace always yields the same payload.
            categories.sort();
            categories.dedup();
            PalTraitStatus {
                name: name.to_string(),
                categories,
                exists: false,
            }
        })
        .collect()
}

/// Whether a source text defines `trait {name}` — the `trait` keyword
/// immediately followed by the exact trait name, with a word boundary on
/// each side, so `trait GraphicsDevice2` never marks `GraphicsDevice` and
/// a mention of the trait in any other position never counts.
pub(crate) fn defines_trait(source: &str, name: &str) -> bool {
    let needle = format!("trait {name}");
    let ident_byte = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    source.match_indices(&needle).any(|(start, matched)| {
        let before_ok = start
            .checked_sub(1)
            .is_none_or(|i| !ident_byte(source.as_bytes()[i]));
        let after_ok = source
            .as_bytes()
            .get(start + matched.len())
            .is_none_or(|b| !ident_byte(*b));
        before_ok && after_ok
    })
}

/// Build the full PAL tracker payload for one binary from persisted
/// artifacts only: needed traits derived from the per-function analysis
/// artifacts' API-call categories, existence detected against the
/// workspace's generated PAL/shim source artifacts. No classification
/// or override decision is involved — the traits a binary needs are what
/// its functions' recorded API calls demand, whatever the decision in
/// force says. A binary with no readable API-call artifacts honestly
/// answers an empty trait list.
fn pal_status(reader: &ReviewSurfaceReader, name: &str) -> Result<PalStatusResponse, ServerError> {
    let classifications = reader.binary_classifications()?;
    let record = classifications.find(name)?;
    let name = record.binary.as_deref().unwrap_or(name);

    // Both sides of the tracker read through the review-surface reader
    // (issue #464): the recorded API-call categories from the binaries
    // readable analysis artifacts, and the generated PAL/shim sources.
    let categories = reader.api_call_categories(name);
    let mut traits = needed_pal_traits(&categories);
    if !traits.is_empty() {
        let sources = reader.pal_source_texts();
        for trait_status in &mut traits {
            trait_status.exists = sources
                .iter()
                .any(|source| defines_trait(source, &trait_status.name));
        }
    }

    Ok(PalStatusResponse {
        binary: BinaryIdentity::new(name),
        traits,
    })
}

/// Handle `GET /api/binaries/{name}/pal-status` — the PAL-trait tracker
/// for one binary: the traits its functions' persisted API-call
/// categories demand, each marked existing or missing against the
/// workspace's generated PAL/shim source artifacts. Shared router: both
/// `serve` and `live` answer it from persisted artifacts only. Missing
/// or corrupt artifacts on either side honestly answer an empty trait
/// list or missing markers — never a fabricated trait list; an unknown
/// binary name honestly 404s like every other binaries read.
pub async fn api_get_binary_pal_status(
    State(reader): State<ReviewSurfaceReader>,
    PathExtractor(name): PathExtractor<String>,
) -> Result<Json<PalStatusResponse>, ServerError> {
    Ok(Json(pal_status(&reader, &name)?))
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
            unknowns: calxgloss_types::UnitUnknowns::unknown(),
            obligation: calxgloss_types::UnitObligation::unknown(),
        }
    }

    #[test]
    fn unknowns_fold_sums_known_units_and_unknown_poisons_the_total() {
        // Issue #376: the binary's open count sums its units' open counts —
        // but any unit whose ledger reading is unknown leaves the whole
        // binary unknown. The fold never sums past an unknown, and the row
        // never renders an unknown as 0.
        let mut open_one = make_unit(
            "game_logic.dll",
            WorkKind::FunctionTranslation,
            ReviewStatus::Queued,
        );
        open_one.unknowns = calxgloss_types::UnitUnknowns {
            open: Some(vec![calxgloss_types::UnitUnknown {
                id: "u-a".to_string(),
                kind: calxgloss_types::UnknownKind::CoverageFacet,
                severity: calxgloss_types::UnknownSeverity::Blocking,
                question: "What does it really do?".to_string(),
                required_evidence: "call-site survey".to_string(),
                revision: 1,
            }]),
            ..calxgloss_types::UnitUnknowns::unknown()
        };
        let mut known_none = make_unit(
            "game_logic.dll",
            WorkKind::FunctionTranslation,
            ReviewStatus::Accepted,
        );
        known_none.unknowns = calxgloss_types::UnitUnknowns {
            open: Some(vec![]),
            ..calxgloss_types::UnitUnknowns::unknown()
        };
        let unknown = make_unit(
            "game_logic.dll",
            WorkKind::FunctionTranslation,
            ReviewStatus::PendingReview,
        );

        let counts = function_counts_by_binary(&[open_one.clone(), known_none]);
        assert_eq!(
            counts["game_logic.dll"].unknowns_open,
            Some(1),
            "known readings sum"
        );

        let counts = function_counts_by_binary(&[open_one, unknown]);
        assert_eq!(
            counts["game_logic.dll"].unknowns_open, None,
            "any unknown unit flips the binary total to unknown, never a partial sum"
        );
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
        // One binary with two spellings ends up in one tally — the
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
    fn shim_branch_state_folds_the_dashboard_verdicts() {
        // The shim unit's review status is the acceptance state: the
        // builder sets merged for an Accepted unit and sent_back for a
        // SendBack unit; anything else is neither. Only shim-layer units
        // join, keyed by the crate name exactly as the dashboard's own
        // dependency wiring keys it.
        let mut shim_unit = make_unit("shim", WorkKind::ShimLayer, ReviewStatus::Accepted);
        shim_unit.function = Some("wgpu".into());
        let mut other = make_unit("shim", WorkKind::PalTrait, ReviewStatus::Accepted);
        other.function = Some("wgpu".into());

        let merged = shim_branch_state(vec![shim_unit, other], "wgpu")
            .expect("the shim unit joins on the crate name");
        assert_eq!(merged.name, "re/shim/wgpu");
        assert!(merged.merged);
        assert!(!merged.sent_back);

        let sent_back = shim_branch_state(
            vec![{
                let mut u = make_unit("shim", WorkKind::ShimLayer, ReviewStatus::SendBack);
                u.function = Some("wgpu".into());
                u
            }],
            "wgpu",
        )
        .expect("the sent-back shim unit joins");
        assert!(!sent_back.merged);
        assert!(sent_back.sent_back);

        assert!(
            shim_branch_state(
                vec![{
                    let mut u = make_unit("shim", WorkKind::ShimLayer, ReviewStatus::Queued);
                    u.function = Some("wgpu".into());
                    u
                }],
                "wgpu-rs",
            )
            .is_none(),
            "no shim unit for the crate in force is honestly no branch"
        );
    }

    #[test]
    fn category_trait_mapping_mirrors_the_tier_four_shape() {
        // Every category the translator's Tier-4 extraction maps, maps
        // to the same trait here — and the categories it leaves
        // unmapped (its catch-all) stay unmapped.
        for category in ["DirectX", "DirectX10", "DirectX11", "DirectX12"] {
            assert_eq!(
                pal_trait_for_category(category),
                Some("GraphicsDevice"),
                "{category} demands GraphicsDevice"
            );
        }
        for category in ["Gdi", "GdiPlus", "Direct2D"] {
            assert_eq!(
                pal_trait_for_category(category),
                Some("Graphics2D"),
                "{category} demands Graphics2D"
            );
        }
        assert_eq!(pal_trait_for_category("Audio"), Some("AudioDevice"));
        assert_eq!(pal_trait_for_category("Win32Gui"), Some("WindowManager"));
        assert_eq!(pal_trait_for_category("Win32Core"), Some("PlatformCore"));
        assert_eq!(pal_trait_for_category("Com"), Some("ComObject"));
        for category in [
            "DirectWrite",
            "Win32Networking",
            "Win32Registry",
            "Vb6Runtime",
            "SomethingElse",
            "",
        ] {
            assert_eq!(
                pal_trait_for_category(category),
                None,
                "{category} maps to no PAL trait"
            );
        }
        // Case-insensitive like every other server comparison.
        assert_eq!(pal_trait_for_category("directx11"), Some("GraphicsDevice"));
    }

    #[test]
    fn needed_pal_traits_groups_categories_and_sorts() {
        // DirectX and DirectX11 group into one GraphicsDevice; unmapped
        // categories contribute nothing; traits sort by name with each
        // trait's verbatim categories sorted.
        let categories: Vec<String> = ["Win32Core", "DirectX11", "DirectX", "Gdi", "Com"]
            .iter()
            .map(|c| c.to_string())
            .collect();
        let traits = needed_pal_traits(&categories);
        let spelled: Vec<(&str, &[&str])> = vec![
            ("ComObject", &["Com"]),
            ("Graphics2D", &["Gdi"]),
            ("GraphicsDevice", &["DirectX", "DirectX11"]),
            ("PlatformCore", &["Win32Core"]),
        ];
        let got: Vec<(&str, Vec<&str>)> = traits
            .iter()
            .map(|t| {
                (
                    t.name.as_str(),
                    t.categories.iter().map(String::as_str).collect(),
                )
            })
            .collect();
        assert_eq!(got.len(), spelled.len(), "one row per demanded trait");
        for (name, cats) in spelled {
            let row = got
                .iter()
                .find(|(n, _)| *n == name)
                .unwrap_or_else(|| panic!("{name} is needed"));
            assert_eq!(row.1, cats, "{name} carries its verbatim categories");
        }
        assert!(
            traits.iter().all(|t| !t.exists),
            "existence is filled by the source scan, not the derivation"
        );
    }

    #[test]
    fn trait_definition_scan_requires_word_boundaries() {
        assert!(defines_trait(
            "pub trait GraphicsDevice {",
            "GraphicsDevice"
        ));
        assert!(defines_trait(
            "pub unsafe trait GraphicsDevice: Send {",
            "GraphicsDevice"
        ));
        assert!(
            !defines_trait("pub trait GraphicsDevice2 {", "GraphicsDevice"),
            "a longer trait name is not the shorter one"
        );
        assert!(
            !defines_trait("// GraphicsDevice PAL trait", "GraphicsDevice"),
            "a comment naming the trait is not a definition"
        );
        assert!(
            !defines_trait("use pal::GraphicsDevice;", "GraphicsDevice"),
            "a reference to the trait is not a definition"
        );
    }

    // The record-directory walks these reads used to do now live in the
    // review reader, beside its own seam tests (issue #464).
}
