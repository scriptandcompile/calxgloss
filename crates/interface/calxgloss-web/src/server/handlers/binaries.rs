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
//! read through the pipeline handler's one `disk_classifications` shape);
//! a record that is missing, corrupt, or has no name or category is no
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
use std::path::{Path, PathBuf};

use axum::{Json, extract::Path as PathExtractor, extract::State};

use calxgloss_types::{
    BinaryClassificationOverride, ClassificationOverrides, ReviewStatus, TokenUsageLog, WorkKind,
    classification_override_records_path,
};

use super::super::types::{
    BinariesListResponse, BinaryDetailResponse, BinaryFunctionRow, BinarySummaryRow,
    ClassificationInfo, PalStatusResponse, PalTraitStatus, ShimBranchInfo, ShimStatusResponse,
    ShimVerificationInfo,
};
use super::super::{ServerError, ServerState};
use super::classification::classification_record_path;
use super::pipeline::disk_classifications;
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

/// The classification decision actually in force for one record: the
/// recorded classification with the persisted override layer applied on
/// top. Computed in one place so the summary rows and the detail panel
/// can never disagree about what the analyzer would act on.
struct InForceDecision {
    category: String,
    strategy: String,
    crate_replacement: Option<String>,
    reason: Option<String>,
    overridden: bool,
}

/// Combine one record with its override (exact-key match — the same rule
/// the override endpoints and the analyzer hold). `recorded_reason` is the
/// raw record's stored reason, used only when no override is in force.
/// Under an override, the result matches what the analyzer would act on:
/// it uses the override's synthesized reason, and it names a crate only in
/// crate-replacement mode. There the recorded crate stands in for the
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
            strategy: record.classification_strategy.clone(),
            crate_replacement: record.crate_replacement.clone(),
            reason: recorded_reason.map(str::to_string),
            overridden: false,
        },
    }
}

/// Build the full binaries list payload from the workspace's persisted
/// history. Split from the handler so the aggregation is testable and the
/// follow-up W4 tickets extend the same shape.
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
                unknowns_open: tally.unknowns_open,
                tokens_used: tokens.get(&name.to_ascii_lowercase()).copied().unwrap_or(0),
            }
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
    State(state): State<ServerState>,
) -> Result<Json<BinariesListResponse>, ServerError> {
    Ok(Json(binaries_list(state.repo_path())?))
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

/// Resolve the requested spelling to one readable classification record
/// through the case-insensitive binary rule every other server
/// comparison makes; no readable record under any spelling is an honest
/// 404, never an empty shell. Deterministic when several spellings of
/// one name each hold a record: the alphabetically first verbatim
/// identity wins.
fn find_classification_record<'a>(
    classifications: &'a HashMap<calxgloss_types::BinaryIdentity, ClassificationInfo>,
    name: &str,
) -> Result<&'a ClassificationInfo, ServerError> {
    classifications
        .values()
        .filter(|c| binary_matches(c.binary.as_str(), name))
        .min_by_key(|c| c.binary.as_str())
        .ok_or_else(|| {
            ServerError::not_found(&format!(
                "no readable classification record for binary: {name}"
            ))
        })
}

/// Build the full detail payload for one binary from persisted history.
/// The requested spelling resolves to the record's verbatim identity
/// through the case-insensitive binary rule every other server
/// comparison makes; no readable classification record under any
/// spelling is an honest 404, never an empty shell.
fn binary_detail(repo_path: &Path, name: &str) -> Result<BinaryDetailResponse, ServerError> {
    let classifications = disk_classifications(repo_path);
    let record = find_classification_record(&classifications, name)?;
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

/// The workspace's shim artifact directory for one binary — the layout
/// the shim pipeline persists (`calxgloss-analysis::shim_pipeline`):
/// `re/shims/{binary}/` holding `mappings.json`, `shim.rs`,
/// `shim_tests.rs`, and `verification.json`.
fn shim_artifact_dir(repo_path: &Path, name: &str) -> Option<PathBuf> {
    binary_artifact_dir(repo_path, "shims", name)
}

/// The per-binary artifact directory under `re/{root}/` whose directory
/// name is the binary's — matched case-insensitively like every other
/// server binary join; when several spellings match, the alphabetically
/// first wins. If no directory matches, the result is `None` — the
/// honest "no artifacts" answer.
fn binary_artifact_dir(repo_path: &Path, root: &str, name: &str) -> Option<PathBuf> {
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(repo_path.join("re").join(root))
        .ok()?
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .filter(|path| {
            path.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|dir_name| binary_matches(dir_name, name))
        })
        .collect();
    dirs.sort();
    dirs.into_iter().next()
}

/// Reads one shim artifact, honestly `None` when the file is missing or
/// corrupt — a corrupt artifact is no artifact, never a zeroed one.
fn read_shim_artifact<T: serde::de::DeserializeOwned>(dir: &Path, file: &str) -> Option<T> {
    std::fs::read_to_string(dir.join(file))
        .ok()
        .and_then(|content| serde_json::from_str(&content).ok())
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
fn shim_status(repo_path: &Path, name: &str) -> Result<ShimStatusResponse, ServerError> {
    let classifications = disk_classifications(repo_path);
    let record = find_classification_record(&classifications, name)?;
    let name = record.binary.as_str();

    let overrides = load_json_or_default::<ClassificationOverrides>(
        &classification_override_records_path(repo_path),
    )
    .overrides;
    let decision = in_force_decision(record, overrides.get(name), None);

    let artifacts = shim_artifact_dir(repo_path, name);
    let mappings: Option<calxgloss_types::ShimLayer> = artifacts
        .as_ref()
        .and_then(|dir| read_shim_artifact(dir, "mappings.json"));
    let verification: Option<calxgloss_types::ShimVerificationResult> = artifacts
        .as_ref()
        .and_then(|dir| read_shim_artifact(dir, "verification.json"));

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
        binary: record.binary.clone(),
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
    State(state): State<ServerState>,
    PathExtractor(name): PathExtractor<String>,
) -> Result<Json<ShimStatusResponse>, ServerError> {
    Ok(Json(shim_status(state.repo_path(), &name)?))
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

/// The workspace's per-function analysis artifact directory for one
/// binary — the layout the web's analysis readers read:
/// `re/analysis/{binary}/` holding one `{function}.json` per analyzed
/// function. No shipped command files these today (see the
/// `handlers::analysis` module note), so a missing directory here is
/// the normal case, not a fault.
fn analysis_artifact_dir(repo_path: &Path, name: &str) -> Option<PathBuf> {
    binary_artifact_dir(repo_path, "analysis", name)
}

/// The API-call categories the binary's persisted per-function analysis
/// artifacts actually record — the honest input to the needed-trait
/// derivation. A missing or unreadable directory is no categories; a
/// corrupt function artifact is no artifact, contributing nothing while
/// the readable ones still answer. Sorted and deduplicated verbatim.
/// Read per binary only by the binaries tracker and by the pipeline
/// poll's PalMapping rows (issue #243) — never for non-PAL rows.
pub(crate) fn recorded_api_categories(repo_path: &Path, name: &str) -> Vec<String> {
    // The shape the analysis pipeline persists per function — only the
    // API-call categories matter here; everything else is ignored.
    #[derive(serde::Deserialize)]
    struct FunctionArtifact {
        #[serde(default)]
        windows_apis: Option<Vec<ApiCallRecord>>,
    }
    #[derive(serde::Deserialize)]
    struct ApiCallRecord {
        #[serde(default)]
        category: String,
    }

    let Some(dir) = analysis_artifact_dir(repo_path, name) else {
        return Vec::new();
    };
    let mut categories: Vec<String> = std::fs::read_dir(&dir)
        .ok()
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.is_file() && path.extension().is_some_and(|ext| ext == "json"))
        .filter_map(|path| std::fs::read_to_string(path).ok())
        .filter_map(|content| serde_json::from_str::<FunctionArtifact>(&content).ok())
        .filter_map(|artifact| artifact.windows_apis)
        .flatten()
        .map(|api| api.category)
        .filter(|category| !category.is_empty())
        .collect();
    categories.sort();
    categories.dedup();
    categories
}

/// The workspace's generated PAL/shim source texts — the honest input for
/// trait existence, adding no new persistence format. The shared PAL crate
/// verifier generates under `scratch/pal/src/` (every `.rs` in it) plus
/// every binary's generated shim source (`re/shims/{binary}/shim.rs`,
/// the layout `shim_pipeline` persists — test sources reference traits
/// without defining them, so only `shim.rs` counts). Unreadable files
/// are skipped; no sources is the honest empty answer. The pipeline poll
/// scans once per request and shares the result across all PAL rows
/// (issue #243) — the scan never runs per row.
pub(crate) fn generated_pal_source_texts(repo_path: &Path) -> Vec<String> {
    let mut pal_files: Vec<PathBuf> =
        std::fs::read_dir(repo_path.join("scratch").join("pal").join("src"))
            .ok()
            .into_iter()
            .flatten()
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| path.is_file() && path.extension().is_some_and(|ext| ext == "rs"))
            .collect();
    pal_files.sort();

    let mut shim_files: Vec<PathBuf> = std::fs::read_dir(repo_path.join("re").join("shims"))
        .ok()
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .map(|dir| dir.join("shim.rs"))
        .filter(|path| path.is_file())
        .collect();
    shim_files.sort();

    pal_files
        .into_iter()
        .chain(shim_files)
        .filter_map(|path| std::fs::read_to_string(path).ok())
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
fn pal_status(repo_path: &Path, name: &str) -> Result<PalStatusResponse, ServerError> {
    let classifications = disk_classifications(repo_path);
    let record = find_classification_record(&classifications, name)?;
    let name = record.binary.as_str();

    let categories = recorded_api_categories(repo_path, name);
    let mut traits = needed_pal_traits(&categories);
    if !traits.is_empty() {
        let sources = generated_pal_source_texts(repo_path);
        for trait_status in &mut traits {
            trait_status.exists = sources
                .iter()
                .any(|source| defines_trait(source, &trait_status.name));
        }
    }

    Ok(PalStatusResponse {
        binary: record.binary.clone(),
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
    State(state): State<ServerState>,
    PathExtractor(name): PathExtractor<String>,
) -> Result<Json<PalStatusResponse>, ServerError> {
    Ok(Json(pal_status(state.repo_path(), &name)?))
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
    fn in_force_decision_prefers_the_override_layer() {
        // The same combination the summary rows and the analyzer honor: category,
        // strategy label, crate, and reason come from the override;
        // without one, the record answers verbatim.
        let record = ClassificationInfo {
            binary: "d3d9.dll".into(),
            category: "MicrosoftSdk".into(),
            classification_strategy: "CrateReplacement".into(),
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
            classification_strategy: "ReverseEngineer".into(),
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
    fn shim_artifact_dir_join_is_case_insensitive() {
        // The shim directory is named with the binary name the pipeline
        // wrote;
        // the lookup matches case-insensitively like every other server
        // binary join, and deterministically the alphabetically first
        // spelling wins.
        let workspace = tempfile::tempdir().expect("temp workspace");
        let shims = workspace.path().join("re").join("shims");
        std::fs::create_dir_all(shims.join("D3D9.dll")).expect("shim dir");
        std::fs::create_dir_all(shims.join("d3d9.dll")).expect("shim dir");

        let dir = shim_artifact_dir(workspace.path(), "d3d9.dll").expect("a matching dir");
        assert_eq!(
            dir.file_name().and_then(|n| n.to_str()),
            Some("D3D9.dll"),
            "alphabetically first spelling wins"
        );
        assert!(
            shim_artifact_dir(workspace.path(), "other.dll").is_none(),
            "no matching directory is honestly no artifacts"
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

    #[test]
    fn analysis_artifact_dir_join_is_case_insensitive() {
        // The analysis directory carries the binary name the pipeline
        // wrote; the lookup matches case-insensitively like every other
        // server binary join, and deterministically the alphabetically
        // first spelling wins.
        let workspace = tempfile::tempdir().expect("temp workspace");
        let analysis = workspace.path().join("re").join("analysis");
        std::fs::create_dir_all(analysis.join("D3D9.dll")).expect("analysis dir");
        std::fs::create_dir_all(analysis.join("d3d9.dll")).expect("analysis dir");

        let dir = analysis_artifact_dir(workspace.path(), "d3d9.dll").expect("a matching dir");
        assert_eq!(
            dir.file_name().and_then(|n| n.to_str()),
            Some("D3D9.dll"),
            "alphabetically first spelling wins"
        );
        assert!(
            analysis_artifact_dir(workspace.path(), "other.dll").is_none(),
            "no matching directory is honestly no artifacts"
        );
    }

    #[test]
    fn generated_sources_cover_scratch_pal_and_shim_sources_only() {
        // The scratch PAL crate contributes every .rs; a shim directory
        // only its generated shim.rs — a trait defined in shim_tests.rs
        // is a reference, not a generated definition.
        let workspace = tempfile::tempdir().expect("temp workspace");
        let pal_src = workspace.path().join("scratch").join("pal").join("src");
        std::fs::create_dir_all(&pal_src).expect("pal src dir");
        std::fs::write(pal_src.join("stub_content.rs"), "pub trait WindowManager {")
            .expect("stub content");
        std::fs::write(pal_src.join("lib.rs"), "include!(\"stub_content.rs\");").expect("lib rs");
        let shim_dir = workspace.path().join("re").join("shims").join("d3d9.dll");
        std::fs::create_dir_all(&shim_dir).expect("shim dir");
        std::fs::write(shim_dir.join("shim.rs"), "unsafe fn present() {}").expect("shim source");
        std::fs::write(shim_dir.join("shim_tests.rs"), "pub trait ComObject {")
            .expect("shim tests");

        let sources = generated_pal_source_texts(workspace.path());
        let joined = sources.join("\n");
        assert!(
            defines_trait(&joined, "WindowManager"),
            "the generated PAL crate counts"
        );
        assert!(
            !defines_trait(&joined, "ComObject"),
            "a shim test source is not a generated trait definition"
        );
    }
}
