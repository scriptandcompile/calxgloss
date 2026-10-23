//! Live translation progress and pipeline progress endpoints.

use super::super::{
    BatchInfo, BinaryFocusResponse, BinaryPauseResponse, ClassificationInfo, CombinedState,
    PipelineControl,
    PipelineDllProgress, PipelineLifecycleResponse, PipelineProgressResponse, PipelineTimeEstimate,
    ProgressEntry, ProgressInfo, ProgressResponse, ServerError, UnitCancelResponse,
};

use super::process::binary_matches;
use super::scope::{persist_error, scope_handle};

use axum::{
    Json,
    extract::{Path as PathExtractor, State},
};
use calxgloss_types::{
    BinaryIdentity, BinaryProgress, LiveTranslationState, LiveUnitProgress, PalReadiness,
    PalTraitReadiness, PassStatus, PhaseProgress, PhaseState, PipelinePhase, PipelineRunRequest,
    RunRequestSignal, ScopeControl, TokenUsageLog, TranslationPhase, derive_unit_confidence,
};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use tracing::info;

/// Handle GET /api/progress — return in-flight translation units.
pub async fn api_get_progress(State(combined): State<CombinedState>) -> Json<ProgressResponse> {
    let progress = match &combined.progress {
        Some(p) => p,
        None => return ProgressResponse::empty().into(),
    };

    let entries = progress.read().await.snapshot().await;

    let in_progress: Vec<ProgressInfo> = entries
        .values()
        .map(|e| {
            let elapsed = e.started_at.elapsed().as_secs_f64();
            ProgressInfo {
                binary: e.binary.clone(),
                function: e.function.clone(),
                attempt: e.attempt,
                strategy: e.strategy.clone(),
                phase: e.phase,
                phase_history: e.phase_history.clone(),
                finished: e.finished,
                elapsed_secs: (elapsed * 1000.0).round() / 1000.0,
            }
        })
        .collect();

    let count = in_progress.len();
    Json(ProgressResponse { in_progress, count })
}

/// Handle GET /api/progress/enhanced — the live view's per-unit records.
///
/// Where `/api/progress` answers "which units are in flight and what phase are
/// they in", this answers what the live view needs to show the pipeline
/// working: per-unit phase and elapsed time plus context tier, retry strategy,
/// attempt, baseline/verification pass status, and unit confidence. The records
/// are the shared [`LiveTranslationState`] ones, so W2/W3 can consume them
/// without depending on the web crate.
///
/// Registered in the **live router only** (see [`super::super::live_only_routes`]):
/// outside `calxgloss live` there is no live translation state, and an empty
/// payload here would be indistinguishable from an idle run.
pub async fn api_get_progress_enhanced(
    State(combined): State<CombinedState>,
) -> Json<LiveTranslationState> {
    let progress = match &combined.progress {
        Some(p) => p,
        None => return LiveTranslationState::empty().into(),
    };

    let entries = progress.read().await.snapshot().await;
    let mut units: Vec<LiveUnitProgress> = entries.values().map(live_unit_progress).collect();

    // Stable order so the live view doesn't shuffle rows between refreshes.
    units.sort_by(|a, b| {
        a.binary
            .cmp(&b.binary)
            .then_with(|| a.function.cmp(&b.function))
    });

    let count = units.len();
    let in_flight = units.iter().filter(|u| !u.finished).count();
    Json(LiveTranslationState {
        units,
        count,
        in_flight,
    })
}

/// Project one live [`ProgressEntry`] into the shared [`LiveUnitProgress`]
/// record the live view consumes.
///
/// Shared by `GET /api/progress/enhanced` and the WebSocket `unit_phase` push
/// so both surfaces report the same honest shape: unmeasured test classes stay
/// [`PassState::NotRun`](calxgloss_types::PassState::NotRun), an unnamed retry
/// strategy is `None` rather than a blank, and confidence is derived from
/// evidence rather than guessed.
pub(crate) fn live_unit_progress(e: &ProgressEntry) -> LiveUnitProgress {
    let elapsed = e.started_at.elapsed().as_secs_f64();
    let baseline =
        PassStatus::from_optional_counts(e.baseline_tests_passed, e.baseline_tests_total);
    let verification =
        PassStatus::from_optional_counts(e.verification_tests_passed, e.verification_tests_total);
    LiveUnitProgress {
        binary: e.binary.clone(),
        function: e.function.clone(),
        phase: e.phase,
        phase_history: e.phase_history.clone(),
        elapsed_secs: (elapsed * 1000.0).round() / 1000.0,
        attempt: e.attempt,
        // An entry starts with an empty strategy; no strategy named yet
        // means none to report, not a blank one.
        retry_strategy: (!e.strategy.is_empty()).then(|| e.strategy.clone()),
        context_tier: e.context_tier.clone(),
        tier_label: e.tier_label.clone(),
        baseline: baseline.clone(),
        verification,
        compiled: e.compiled,
        unit_confidence: derive_unit_confidence(e.compiled, &baseline),
        finished: e.finished,
        succeeded: e.succeeded,
    }
}

/// Handle GET /api/pipeline — return overall pipeline progress.
///
/// This endpoint aggregates classification results, batch summaries,
/// and live translation state to give a high-level view of the
/// pipeline's current status. Since issue #61 it also derives one
/// [`PhaseProgress`] per master-plan phase (1–7 plus Phase 2.5 PAL Design)
/// and one [`BinaryProgress`] per discovered binary. Every derived record
/// is honest: phases with no backing data source (Restitching, Documentation)
/// report `NoDataSource`, and unknown counts stay `None` rather than being
/// fabricated as zeros.
pub async fn api_get_pipeline(
    State(combined): State<CombinedState>,
) -> Json<PipelineProgressResponse> {
    let progress = match &combined.progress {
        Some(p) => p,
        None => return PipelineProgressResponse::empty(0).into(),
    };

    let entries = progress.read().await.snapshot().await;
    let classifications_raw = progress.read().await.classifications().await;
    let batch_summaries_raw = progress.read().await.batch_summaries().await;
    let processing = progress.read().await.processing_binary().await;
    let activity = progress.read().await.activity().await;
    let queue = progress.read().await.queue().await;
    let ingestion = progress.read().await.ingestion().await;

    // Convert to owned HashMaps for O(1) lookups by binary identity
    let mut classifications: HashMap<BinaryIdentity, ClassificationInfo> = classifications_raw
        .into_iter()
        .map(|c| (c.binary.clone(), c))
        .collect();
    let batch_summaries: HashMap<BinaryIdentity, BatchInfo> = batch_summaries_raw
        .into_iter()
        .map(|b| (b.binary.clone(), b))
        .collect();

    // A restarted run re-classifies nothing, so the persisted records are
    // the only account of what the workspace already knows; this run's own
    // events supersede them wherever both exist.
    for (binary, info) in disk_classifications(combined.server.repo_path()) {
        classifications.entry(binary).or_insert(info);
    }

    // Snapshot entries before dropping the lock to avoid nested borrows
    let entries_snapshot: HashMap<String, ProgressEntry> = entries.clone();

    // Collect all binary identities from all three sources
    let mut dll_names: HashSet<BinaryIdentity> = HashSet::new();

    // From live translation entries (group by DLL)
    for entry in entries_snapshot.values() {
        dll_names.insert(entry.binary.clone());
    }
    // From classification results
    for binary in classifications.keys() {
        dll_names.insert(binary.clone());
    }
    // From batch summaries
    for binary in batch_summaries.keys() {
        dll_names.insert(binary.clone());
    }
    // The binary whose batch pass has begun is discovered even when no
    // unit, classification, or summary event has named it yet — otherwise
    // a restarted run shows nothing until its first function event.
    if let Some(binary) = &processing {
        dll_names.insert(binary.clone());
    }
    // A beating pass names its binary too — the beat can only be honest
    // about a binary the table actually shows.
    if let Some((binary, _)) = &activity {
        dll_names.insert(binary.clone());
    }
    // The run's queue plan names every binary it will process — the
    // table shows the whole plan, not just what has started.
    dll_names.extend(queue.iter().map(|q| BinaryIdentity::new(q.as_str())));
    // A binary whose engine auto-analysis landed is being ingested —
    // the table shows it before any unit, classification, or plan event
    // names it (issue #124).
    dll_names.extend(ingestion.analyzed.iter().cloned());

    let total_dlls = dll_names.len();
    let dll_names_vec: Vec<BinaryIdentity> = {
        let mut v: Vec<BinaryIdentity> = dll_names.into_iter().collect();
        // Three-tier order (issue #242): queue-planned non-PAL rows in
        // queue-plan order — the order the live loop will process them —
        // then unplanned non-PAL rows alphabetical, then PAL-mapped rows
        // alphabetical. A PAL binary the plan happens to name still sorts
        // last: display order reflects translation intent, not a queue
        // accident. Read from the merged live-over-disk classifications —
        // exactly the classification the row renders — and recomputed per
        // poll, so a classification change relocates the row for free.
        let is_pal = |d: &BinaryIdentity| {
            classifications
                .get(d)
                .is_some_and(|c| is_pal_strategy(&c.strategy))
        };
        // Issue #284: a pending focus reads as the front of the plan — the
        // live loop hoists it at the next binary boundary, and the served
        // table shows that intent ahead of time. Only a focus the current
        // plan names is hoisted; one it does not name waits, exactly as the
        // worklist waits. PAL rows stay last: focus reorders intent, never
        // overrides it. Names match case-insensitively (issue #107).
        let plan: Vec<String> = {
            let mut plan = queue.clone();
            if let Some(focus) = combined
                .server
                .scope_control()
                .and_then(|sc| sc.focused_binary().map(|f| f.as_str().to_owned()))
            {
                if let Some(idx) = plan.iter().position(|b| b.eq_ignore_ascii_case(&focus)) {
                    if idx != 0 {
                        let hoisted = plan.remove(idx);
                        plan.insert(0, hoisted);
                    }
                }
            }
            plan
        };
        let pos = |d: &BinaryIdentity| plan.iter().position(|q| q == d.as_str());
        v.sort_by(|a, b| match (is_pal(a), is_pal(b)) {
            (true, true) => a.cmp(b),
            (true, false) => std::cmp::Ordering::Greater,
            (false, true) => std::cmp::Ordering::Less,
            (false, false) => match (pos(a), pos(b)) {
                (Some(i), Some(j)) => i.cmp(&j),
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => a.cmp(b),
            },
        });
        v
    };

    // Find DLLs currently being translated (have entries not yet finished)
    let currently_translating: Vec<BinaryIdentity> = entries_snapshot
        .values()
        .filter(|e| !e.finished)
        .map(|e| e.binary.clone())
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();

    // Build per-DLL progress
    let mut dlls = Vec::new();
    for (order, binary) in dll_names_vec.iter().enumerate() {
        let classification = classifications.get(binary).cloned();

        let batch = batch_summaries.get(binary).cloned();

        // Check if this DLL is currently being translated
        let current_translating = currently_translating
            .iter()
            .find(|d| **d == *binary)
            .map(|d| {
                let dll_entries: Vec<_> = entries_snapshot
                    .values()
                    .filter(|e| e.binary == **d)
                    .collect();
                let completed = dll_entries.iter().filter(|e| e.finished).count();
                super::super::CurrentDllStatus {
                    binary: d.clone(),
                    total_entries: dll_entries.len(),
                    completed_entries: completed,
                }
            });

        dlls.push(PipelineDllProgress {
            binary: binary.clone(),
            classification,
            batch,
            in_progress: current_translating,
            order,
        });
    }

    // PAL trait-readiness summary (issue #243): it rides this single
    // bulk poll, so the frontend never fetches per row. The generated
    // PAL/shim source scan runs once per poll and is shared across all
    // PAL rows; when no row is PAL-mapped the scan never happens and no
    // per-binary artifact reads follow. Recomputed per poll, so trait
    // design progress and classification overrides land on the next
    // refresh with no special handling.
    let has_pal_row = dll_names_vec.iter().any(|d| {
        classifications
            .get(d)
            .is_some_and(|c| is_pal_strategy(&c.strategy))
    });
    let pal_sources = has_pal_row
        .then(|| super::binaries::generated_pal_source_texts(combined.server.repo_path()));

    let mut binaries = derive_binaries(
        &dll_names_vec,
        &classifications,
        &batch_summaries,
        &entries_snapshot,
        processing.as_ref(),
        activity.as_ref(),
        combined.server.scope_control().as_ref(),
    );
    if let Some(sources) = pal_sources {
        for row in &mut binaries {
            // The summary rides only PalMapping rows; the per-binary
            // artifact reads stay bounded to those rows. No derived
            // trait means no summary — never a fabricated empty one.
            if row.strategy.as_deref().is_some_and(is_pal_strategy) {
                let categories = super::binaries::recorded_api_categories(
                    combined.server.repo_path(),
                    row.binary.as_str(),
                );
                let traits: Vec<PalTraitReadiness> =
                    super::binaries::needed_pal_traits(&categories)
                        .into_iter()
                        .map(|t| {
                            let defined = sources
                                .iter()
                                .any(|s| super::binaries::defines_trait(s, &t.name));
                            PalTraitReadiness {
                                name: t.name,
                                defined,
                            }
                        })
                        .collect();
                row.pal = (!traits.is_empty()).then_some(PalReadiness { traits });
            }
        }
    }
    let phases = derive_phases(
        total_dlls,
        &classifications,
        &batch_summaries,
        &entries_snapshot,
        ingestion.started,
        &ingestion.analyzed,
    );

    let time_estimate = compute_time_estimate(combined.server.repo_path(), &binaries);

    Json(PipelineProgressResponse {
        total_dlls,
        classified_count: classifications.len(),
        batch_complete_count: batch_summaries.len(),
        currently_translating,
        dlls,
        phases,
        binaries,
        time_estimate,
    })
}

/// Classification records persisted by earlier runs (`re/classify/*.json`).
/// A restarted pipeline re-classifies nothing, so these artifacts are the
/// only account of what the workspace already knows — the pipeline table
/// hydrates its rows from them until this run's own events supersede them.
/// Records missing a name or category are skipped rather than guessed at.
/// The binaries view (issue #130) reads the same records through this one
/// shape — one reader of the artifact format, not two.
pub(crate) fn disk_classifications(
    repo_path: &Path,
) -> HashMap<BinaryIdentity, ClassificationInfo> {
    let mut found = HashMap::new();
    let classify_dir = repo_path.join("re").join("classify");
    let Ok(entries) = std::fs::read_dir(&classify_dir) else {
        return found;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&content) else {
            continue;
        };
        let binary = value.get("binary").and_then(|v| v.as_str()).unwrap_or("");
        let category = value.get("category").and_then(|v| v.as_str()).unwrap_or("");
        if binary.is_empty() || category.is_empty() {
            continue;
        }
        // Strategy is serialized from `calxgloss_analysis::Strategy`:
        // unit variants land as bare strings ("PalMapping"), struct
        // variants as tagged objects ({"CrateReplacement": {…}}). The
        // variant name is the strategy either way.
        let strategy = match value.get("strategy") {
            Some(serde_json::Value::String(s)) => s.clone(),
            Some(serde_json::Value::Object(obj)) => obj.keys().next().cloned().unwrap_or_default(),
            _ => String::new(),
        };
        found.insert(
            binary.into(),
            ClassificationInfo {
                binary: binary.to_string().into(),
                category: category.to_string(),
                strategy,
                crate_replacement: value
                    .get("crate_replacement")
                    .and_then(|v| v.as_str())
                    .map(str::to_string),
                exported_symbols: value
                    .get("exports_count")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as usize,
                imported_symbols: value
                    .get("imports_count")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as usize,
            },
        );
    }
    found
}

// ============================================================
// Time estimate (issue #64)
// ============================================================
/// Derive the pipeline time estimate from the token-usage log's recorded
/// attempt durations and the remaining work in `binaries`. Returns `None`
/// when no attempt has a measured duration or no work remains — the
/// estimate is never fabricated.
fn compute_time_estimate(
    repo_path: &Path,
    binaries: &[BinaryProgress],
) -> Option<PipelineTimeEstimate> {
    let log = super::process::load_json_or_default::<TokenUsageLog>(
        &super::process::token_usage_log_path(repo_path),
    );
    let avg_attempt_secs = log.average_attempt_duration_secs()?;
    let remaining_units: usize = binaries
        .iter()
        .map(|b| {
            b.functions_total
                .map(|total| total.saturating_sub(b.functions_translated + b.functions_failed))
                .unwrap_or(0)
        })
        .sum();
    if remaining_units == 0 {
        return None;
    }
    Some(PipelineTimeEstimate {
        avg_attempt_secs,
        remaining_units,
        estimated_secs: avg_attempt_secs * remaining_units as f64,
    })
}

// ============================================================
// Phase & binary derivation (issue #61)
// ============================================================

/// The furthest phase a unit reached, across its whole phase history (retry
/// escalations re-enter phases, so the latest phase alone understates
/// progress). `TranslationPhase`'s declaration order is the pipeline order,
/// which is why it derives `Ord`.
fn furthest_phase(entry: &ProgressEntry) -> TranslationPhase {
    entry
        .phase_history
        .iter()
        .map(|r| r.phase)
        .max()
        .unwrap_or(entry.phase)
        .max(entry.phase)
}

/// Whether a classification strategy string names the PAL mapping strategy.
/// Events carry the strategy as a `{:?}`-formatted string (e.g. "PalMapping").
/// One match rule, shared by the phase counts and the row sort (issue #242) —
/// the same containment the frontend's "PAL trait" state cell uses.
fn is_pal_strategy(strategy: &str) -> bool {
    strategy.contains("PalMapping")
}

/// Build a counted phase record, deriving the honest state from the counts.
fn counted_phase(phase: PipelinePhase, completed: usize, total: usize) -> PhaseProgress {
    let state = if total == 0 || completed == 0 {
        PhaseState::NotStarted
    } else if completed >= total {
        PhaseState::Complete
    } else {
        PhaseState::InProgress
    };
    PhaseProgress {
        phase,
        state,
        completed: Some(completed),
        total: Some(total),
    }
}

/// Count binaries that have completed the unit-level phase at `threshold`:
/// those with at least one unit that reached it, plus — when `batch_counts`
/// — those whose batch summary landed, which means the pipeline ran that
/// phase over the whole binary. `batch_counts` is `false` for verification:
/// a batch summary alone doesn't prove anything verified successfully, only
/// units that reached review do. Unknown binaries (no units, no summary)
/// never count as done.
fn dll_done_count(
    total_dlls: usize,
    entries: &HashMap<String, ProgressEntry>,
    batch_summaries: &HashMap<BinaryIdentity, BatchInfo>,
    threshold: TranslationPhase,
    batch_counts: bool,
) -> usize {
    let mut done: HashSet<&str> = HashSet::new();
    for entry in entries.values() {
        if furthest_phase(entry) >= threshold {
            done.insert(entry.binary.as_str());
        }
    }
    if batch_counts {
        for binary in batch_summaries.keys() {
            done.insert(binary.as_str());
        }
    }
    // Only count binaries the pipeline actually knows about.
    done.len().min(total_dlls)
}

/// Derive one record per master-plan phase, in bar order, from the live
/// progress data. A binary counts as having completed a unit-level phase
/// when at least one of its functions reached that phase (or its batch
/// summary landed) — the counts are per binary, matching `total_dlls`.
///
/// `ingestion_started` and `analyzed` come from the startup preflight
/// scan (issue #124): they light up `project_ingestion` while the run is
/// still ingesting binaries, before any classification exists.
fn derive_phases(
    total_dlls: usize,
    classifications: &HashMap<BinaryIdentity, ClassificationInfo>,
    batch_summaries: &HashMap<BinaryIdentity, BatchInfo>,
    entries: &HashMap<String, ProgressEntry>,
    ingestion_started: bool,
    analyzed: &[BinaryIdentity],
) -> Vec<PhaseProgress> {
    // Phase 2.5 only covers binaries classified with the PAL strategy.
    let pal_binaries: Vec<&BinaryIdentity> = classifications
        .keys()
        .filter(|binary| {
            classifications
                .get(*binary)
                .is_some_and(|c| is_pal_strategy(&c.strategy))
        })
        .collect();

    PipelinePhase::ALL
        .iter()
        .map(|&phase| match phase {
            PipelinePhase::ProjectIngestion => {
                let completed = classifications.len();
                if completed == 0 && !analyzed.is_empty() {
                    // Binaries are already ingested but none classified
                    // yet — ingestion is underway, and
                    // the analyzed binaries give an honest denominator.
                    PhaseProgress {
                        phase,
                        state: PhaseState::InProgress,
                        completed: Some(0),
                        total: Some(total_dlls),
                    }
                } else if completed == 0 && ingestion_started {
                    // Preflight has begun but no binary is named yet —
                    // in progress with no honest count (the bar renders —).
                    PhaseProgress {
                        phase,
                        state: PhaseState::InProgress,
                        completed: None,
                        total: None,
                    }
                } else {
                    counted_phase(phase, completed, total_dlls)
                }
            }
            PipelinePhase::DisassemblyTagging => counted_phase(
                phase,
                dll_done_count(
                    total_dlls,
                    entries,
                    batch_summaries,
                    TranslationPhase::TestGen,
                    true,
                ),
                total_dlls,
            ),
            PipelinePhase::PalDesign => counted_phase(
                phase,
                pal_binaries
                    .iter()
                    .filter(|binary| batch_summaries.contains_key(*binary))
                    .count(),
                pal_binaries.len(),
            ),
            PipelinePhase::TestGeneration => counted_phase(
                phase,
                dll_done_count(
                    total_dlls,
                    entries,
                    batch_summaries,
                    TranslationPhase::ContextTier,
                    true,
                ),
                total_dlls,
            ),
            PipelinePhase::RustCodeGeneration => counted_phase(
                phase,
                dll_done_count(
                    total_dlls,
                    entries,
                    batch_summaries,
                    TranslationPhase::Compiling,
                    true,
                ),
                total_dlls,
            ),
            PipelinePhase::BehaviorVerification => counted_phase(
                phase,
                dll_done_count(
                    total_dlls,
                    entries,
                    batch_summaries,
                    TranslationPhase::Review,
                    false,
                ),
                total_dlls,
            ),
            // No backing data source — never a fabricated count.
            PipelinePhase::Restitching | PipelinePhase::Documentation => {
                PhaseProgress::no_data_source(phase)
            }
        })
        .collect()
}

/// Derive per-binary progress records in the order `dll_names` gives them
/// (the handler's three-tier display order, issue #242). Batch summaries are
/// the authoritative function counts when present; otherwise the counts come
/// from per-unit terminal events, and unknown totals stay `None`. The
/// PAL-readiness summary (issue #243) is attached by the handler after this,
/// where the poll's one shared generated-source scan lives.
fn derive_binaries(
    dll_names: &[BinaryIdentity],
    classifications: &HashMap<BinaryIdentity, ClassificationInfo>,
    batch_summaries: &HashMap<BinaryIdentity, BatchInfo>,
    entries: &HashMap<String, ProgressEntry>,
    processing: Option<&BinaryIdentity>,
    activity: Option<&(BinaryIdentity, calxgloss_types::BinaryActivity)>,
    scope: Option<&ScopeControl>,
) -> Vec<BinaryProgress> {
    dll_names
        .iter()
        .map(|binary| {
            let classification = classifications.get(binary);
            let batch = batch_summaries.get(binary);

            let units: Vec<&ProgressEntry> =
                entries.values().filter(|e| e.binary == *binary).collect();

            let (functions_translated, functions_failed, functions_total, tokens_used) = match batch
            {
                Some(b) => (
                    b.success_count,
                    b.failure_count,
                    Some(b.total_functions),
                    Some(b.total_tokens),
                ),
                None => (
                    units.iter().filter(|e| e.succeeded == Some(true)).count(),
                    units.iter().filter(|e| e.succeeded == Some(false)).count(),
                    None,
                    None,
                ),
            };

            BinaryProgress {
                binary: binary.clone(),
                category: classification.map(|c| c.category.clone()),
                strategy: classification.map(|c| c.strategy.clone()),
                crate_replacement: classification.and_then(|c| c.crate_replacement.clone()),
                functions_total,
                functions_translated,
                functions_in_progress: units.iter().filter(|e| !e.finished).count(),
                functions_failed,
                tokens_used,
                processing: processing == Some(binary),
                activity: activity
                    .filter(|(d, _)| d == binary)
                    .map(|(_, a)| a.clone()),
                // The paused set is operator steering, not run telemetry —
                // the scope handle is its source of truth (issue #218), so
                // the row reads it directly and a plain GET is honest
                // without waiting for a BinaryPauseChanged event (issue #221).
                paused: scope.is_some_and(|s| s.is_paused(binary.as_str())),
                // Attached per poll by the handler for PalMapping rows
                // (issue #243) — no scan exists at this point to check against.
                pal: None,
            }
        })
        .collect()
}

// ─── POST /api/pipeline/{pause,resume,stop} ──────────────────────────

/// The three lifecycle control endpoints (issue #90, W2.1) share this:
/// take the control handle attached to the server state (503 when this
/// live router was built without one — honest rather than pretending an
/// idle pipeline can be paused), run the transition, and report the
/// state it moved from and to. A transition the state machine forbids
/// (double pause, resuming a running run) is a 409 with the machine's
/// own message, never a silent no-op.
fn control_pipeline(
    combined: &CombinedState,
    op: &str,
    apply: impl FnOnce(&PipelineControl) -> Result<(), calxgloss_types::PipelineTransitionError>,
) -> Result<Json<PipelineLifecycleResponse>, ServerError> {
    let control = combined.server.pipeline_control().ok_or_else(|| {
        ServerError::unavailable("this server has no live pipeline control attached")
    })?;
    let previous = control.state();
    apply(&control).map_err(|e| ServerError::conflict(&e.to_string()))?;
    let state = control.state();
    info!("pipeline {op}: {previous} -> {state} requested via API");
    Ok(Json(PipelineLifecycleResponse {
        previous,
        state,
        message: format!("Pipeline {op} requested."),
    }))
}

/// Pause the live run (issue #90): the pipeline notices at the next **unit
/// boundary** — the unit in flight is never interrupted mid-LLM-call — and
/// parks there until resumed or stopped. Live router only.
pub async fn api_pause_pipeline(
    State(combined): State<CombinedState>,
) -> Result<Json<PipelineLifecycleResponse>, ServerError> {
    control_pipeline(&combined, "pause", |c| c.pause())
}

/// Resume a paused run exactly where the pause stopped it. Live router only.
pub async fn api_resume_pipeline(
    State(combined): State<CombinedState>,
) -> Result<Json<PipelineLifecycleResponse>, ServerError> {
    control_pipeline(&combined, "resume", |c| c.resume())
}

/// Stop the live run (issue #90): the current unit finishes and is saved,
/// then the run halts in a consistent state. Distinct from
/// `POST /api/server/shutdown`, which also takes the server down. Live
/// router only.
pub async fn api_stop_pipeline(
    State(combined): State<CombinedState>,
) -> Result<Json<PipelineLifecycleResponse>, ServerError> {
    control_pipeline(&combined, "stop", |c| c.stop())
}

// ─── POST /api/pipeline/binaries/{binary}/{pause,resume} ─────────────

/// The binaries the workspace has discovered — the same set `GET
/// /api/pipeline` builds its rows from: live progress (entries,
/// classifications, batch summaries, the binary in flight, a beating pass,
/// the queue plan, ingested analysis) plus the persisted classification
/// records, plus the persisted paused set. A binary paused in an earlier run
/// is known to the workspace even before this run rediscovers it, and
/// resume must never lock the operator out of clearing that pause.
async fn discovered_binaries(
    combined: &CombinedState,
    scope: &ScopeControl,
) -> std::collections::HashSet<BinaryIdentity> {
    let mut names: std::collections::HashSet<BinaryIdentity> =
        scope.paused_binaries().into_iter().collect();
    if let Some(progress) = &combined.progress {
        for entry in progress.read().await.snapshot().await.values() {
            names.insert(entry.binary.clone());
        }
        for classification in progress.read().await.classifications().await {
            names.insert(classification.binary);
        }
        for summary in progress.read().await.batch_summaries().await {
            names.insert(summary.binary);
        }
        if let Some(binary) = progress.read().await.processing_binary().await {
            names.insert(binary);
        }
        if let Some((binary, _)) = progress.read().await.activity().await {
            names.insert(binary);
        }
        for binary in progress.read().await.queue().await {
            names.insert(BinaryIdentity::new(binary.as_str()));
        }
        names.extend(progress.read().await.ingestion().await.analyzed);
    }
    for (binary, _) in disk_classifications(combined.server.repo_path()) {
        names.insert(binary);
    }
    names
}

/// The two per-binary pause endpoints (issue #221, X6) share this: the
/// scope handle must be attached — 503 otherwise, the lifecycle endpoints'
/// honesty rule — and the binary must be one the workspace has discovered.
/// A request naming an undiscovered binary is a 409 carrying the server's
/// own reason, so a stale click is never a silent no-op. A successful call
/// re-persists the scope record (the pause survives a restart, issue #218)
/// and, on a handle built `with_events`, fans a `BinaryPauseChanged` out to
/// WS clients. Pausing one binary never touches the run-level machine —
/// steering, not lifecycle.
async fn control_binary_pause(
    combined: &CombinedState,
    binary: &str,
    pause: bool,
) -> Result<Json<BinaryPauseResponse>, ServerError> {
    let scope = scope_handle(combined)?;
    let discovered = discovered_binaries(combined, &scope).await;
    if !discovered
        .iter()
        .any(|b| binary_matches(b.as_str(), binary))
    {
        return Err(ServerError::conflict(&format!(
            "this workspace has not discovered the binary '{binary}' — nothing to {}",
            if pause { "pause" } else { "resume" }
        )));
    }
    if pause {
        scope.pause_binary(binary).map_err(persist_error)?;
    } else {
        scope.resume_binary(binary).map_err(persist_error)?;
    }
    let paused = scope.is_paused(binary);
    info!(binary, paused, "scope: binary pause state changed via API");
    Ok(Json(BinaryPauseResponse {
        binary: binary.to_string(),
        paused,
        message: if paused {
            format!("Binary {binary} paused — held out of the queue until resumed.")
        } else {
            format!("Binary {binary} resumed — admitted to the queue again.")
        },
    }))
}

/// Hold one target binary out of the run's queue while the run keeps going
/// (issue #221, X6): a pass in flight ends at the next unit boundary, a
/// pass not yet started never begins. Distinct from `POST /api/pipeline/pause`,
/// which pauses the whole run. Live router only.
pub async fn api_pause_binary(
    State(combined): State<CombinedState>,
    PathExtractor(binary): PathExtractor<String>,
) -> Result<Json<BinaryPauseResponse>, ServerError> {
    control_binary_pause(&combined, &binary, true).await
}

/// Re-admit a paused target binary to the run's queue (issue #221, X6): the
/// pass that comes back around translates it, or the next run does. Live
/// router only.
pub async fn api_resume_binary(
    State(combined): State<CombinedState>,
    PathExtractor(binary): PathExtractor<String>,
) -> Result<Json<BinaryPauseResponse>, ServerError> {
    control_binary_pause(&combined, &binary, false).await
}

// ─── POST /api/pipeline/binaries/{binary}/focus ──────────────────────

/// Put one target binary at the front of the run's queue (issue #284): the
/// scope handle's single focus slot is set here, the running worklist
/// consults it at each binary boundary, hoists the focused binary to the
/// front, re-publishes the plan with it there, and consumes the slot —
/// honored once, never again. The same honesty rules as the pause pair:
/// 503 without a scope handle, 409 for a binary the workspace has not
/// discovered. A second press simply replaces the first (last press wins).
/// Live router only.
pub async fn api_focus_binary(
    State(combined): State<CombinedState>,
    PathExtractor(binary): PathExtractor<String>,
) -> Result<Json<BinaryFocusResponse>, ServerError> {
    let scope = scope_handle(&combined)?;
    let discovered = discovered_binaries(&combined, &scope).await;
    if !discovered
        .iter()
        .any(|b| binary_matches(b.as_str(), &binary))
    {
        return Err(ServerError::conflict(&format!(
            "this workspace has not discovered the binary '{binary}' — nothing to focus"
        )));
    }
    scope.set_focus(&binary).map_err(persist_error)?;
    info!(binary, "scope: binary focus set via API");
    Ok(Json(BinaryFocusResponse {
        binary: binary.to_string(),
        message: format!("Binary {binary} focused — the run works it at the next boundary."),
    }))
}

// ─── POST /api/pipeline/{start,restart} ──────────────────────────────

/// The control handle plus the run-request channel the start/restart
/// endpoints (issue #92, W2.3) both need: 503 when this live router was
/// built without them — honest rather than pretending a run can begin
/// with no loop to run it.
fn run_handles(
    combined: &CombinedState,
) -> Result<(PipelineControl, RunRequestSignal), ServerError> {
    let control = combined.server.pipeline_control().ok_or_else(|| {
        ServerError::unavailable("this server has no live pipeline control attached")
    })?;
    let run_requests = combined.server.run_requests().ok_or_else(|| {
        ServerError::unavailable("this server has no live pipeline control attached")
    })?;
    Ok((control, run_requests))
}

/// Begin the translation phase of a live session that has not translated
/// yet (issue #92, W2.3) — e.g. one launched `--classify-only`. The
/// transition is driven first: a run already in flight is refused with
/// 409 and no request is queued (a finished run restarts — that is the
/// verb for it). Then the default full-scope request lands on the shared
/// channel and the live loop starts translating. Live router only.
pub async fn api_start_pipeline(
    State(combined): State<CombinedState>,
) -> Result<Json<PipelineLifecycleResponse>, ServerError> {
    let (control, run_requests) = run_handles(&combined)?;
    let previous = control.state();
    control
        .start()
        .map_err(|e| ServerError::conflict(&e.to_string()))?;
    run_requests.request(PipelineRunRequest::default());
    let state = control.state();
    info!("pipeline start: {previous} -> {state} requested via API");
    Ok(Json(PipelineLifecycleResponse {
        previous,
        state,
        message: "Pipeline start requested — translation begins.".to_string(),
    }))
}

/// Re-run a stopped pipeline inside the live process (issue #92, W2.3):
/// the body carries the phase, target, and scope selectors — all
/// optional, and a missing or empty body re-runs everything. The
/// transition is driven first, so a run that is not in a terminal state
/// is refused with 409 and nothing is queued; only then does the request
/// land on the shared channel for the live loop to re-run the pipeline
/// with. Live router only.
pub async fn api_restart_pipeline(
    State(combined): State<CombinedState>,
    body: Option<Json<PipelineRunRequest>>,
) -> Result<Json<PipelineLifecycleResponse>, ServerError> {
    let Json(request) = body.unwrap_or_default();
    let (control, run_requests) = run_handles(&combined)?;
    let previous = control.state();
    control
        .restart()
        .map_err(|e| ServerError::conflict(&e.to_string()))?;
    run_requests.request(request.clone());
    let state = control.state();
    info!(
        "pipeline restart: {previous} -> {state} requested via API \
         (phase {}, target {}, scope {})",
        request.phase, request.target, request.scope
    );
    Ok(Json(PipelineLifecycleResponse {
        previous,
        state,
        message: format!(
            "Pipeline restart requested — phase {}, target {}, scope {}.",
            request.phase, request.target, request.scope
        ),
    }))
}

/// Cancel the unit currently in flight (issue #91, W2.2): the pipeline
/// aborts it at the earliest safe point — mid-LLM-call included — records
/// the attempt as cancelled/failed, and continues with the next unit.
/// With no unit in flight (idle, paused, or between units) the request is
/// rejected with a 409 rather than silently doing nothing, so a stale
/// dashboard button cannot drive the run inconsistent. Live router only.
pub async fn api_cancel_current_unit(
    State(combined): State<CombinedState>,
) -> Result<Json<UnitCancelResponse>, ServerError> {
    let cancellation = combined.server.unit_cancellation().ok_or_else(|| {
        ServerError::unavailable("this server has no live pipeline control attached")
    })?;
    let unit = cancellation
        .cancel_current()
        .map_err(|e| ServerError::conflict(&e.to_string()))?;
    info!(
        binary = %unit.binary(),
        function = %unit.function(),
        "unit cancelled via API — run continues with the next unit"
    );
    Ok(Json(UnitCancelResponse {
        binary: unit.binary().to_string(),
        function: unit.function().to_string(),
        message: format!(
            "Cancelled the in-flight unit {unit}; the run continues with the next unit."
        ),
    }))
}
