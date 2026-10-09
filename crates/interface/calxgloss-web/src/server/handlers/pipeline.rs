//! Live translation progress and pipeline progress endpoints.

use super::super::{
    BatchInfo, ClassificationInfo, CombinedState, PipelineDllProgress, PipelineProgressResponse,
    PipelineTimeEstimate, ProgressEntry, ProgressInfo, ProgressResponse,
};

use axum::{Json, extract::State};
use calxgloss_types::{
    BinaryProgress, LiveTranslationState, LiveUnitProgress, PassStatus, PhaseProgress, PhaseState,
    PipelinePhase, TokenUsageLog, TranslationPhase, derive_unit_confidence,
};
use std::collections::{HashMap, HashSet};
use std::path::Path;

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
                dll: e.dll.clone(),
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
    let mut units: Vec<LiveUnitProgress> = entries
        .values()
        .map(|e| {
            let elapsed = e.started_at.elapsed().as_secs_f64();
            let baseline =
                PassStatus::from_optional_counts(e.baseline_tests_passed, e.baseline_tests_total);
            let verification = PassStatus::from_optional_counts(
                e.verification_tests_passed,
                e.verification_tests_total,
            );
            LiveUnitProgress {
                dll: e.dll.clone(),
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
        })
        .collect();

    // Stable order so the live view doesn't shuffle rows between refreshes.
    units.sort_by(|a, b| a.dll.cmp(&b.dll).then_with(|| a.function.cmp(&b.function)));

    let count = units.len();
    let in_flight = units.iter().filter(|u| !u.finished).count();
    Json(LiveTranslationState {
        units,
        count,
        in_flight,
    })
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
    let processing = progress.read().await.processing_dll().await;
    let activity = progress.read().await.activity().await;
    let queue = progress.read().await.queue().await;

    // Convert to owned HashMaps for O(1) lookups by DLL name
    let mut classifications: HashMap<String, ClassificationInfo> = classifications_raw
        .into_iter()
        .map(|c| (c.dll.clone(), c))
        .collect();
    let batch_summaries: HashMap<String, BatchInfo> = batch_summaries_raw
        .into_iter()
        .map(|b| (b.dll.clone(), b))
        .collect();

    // A restarted run re-classifies nothing, so the persisted records are
    // the only account of what the workspace already knows; this run's own
    // events supersede them wherever both exist.
    for (dll, info) in disk_classifications(combined.server.repo_path()) {
        classifications.entry(dll).or_insert(info);
    }

    // Snapshot entries before dropping the lock to avoid nested borrows
    let entries_snapshot: HashMap<String, ProgressEntry> = entries.clone();

    // Collect all DLL names from all three sources
    let mut dll_names: HashSet<String> = HashSet::new();

    // From live translation entries (group by DLL)
    for entry in entries_snapshot.values() {
        dll_names.insert(entry.dll.clone());
    }
    // From classification results
    for dll in classifications.keys() {
        dll_names.insert(dll.clone());
    }
    // From batch summaries
    for dll in batch_summaries.keys() {
        dll_names.insert(dll.clone());
    }
    // The binary whose batch pass has begun is discovered even when no
    // unit, classification, or summary event has named it yet — otherwise
    // a restarted run shows nothing until its first function event.
    if let Some(dll) = &processing {
        dll_names.insert(dll.clone());
    }
    // A beating pass names its binary too — the beat can only be honest
    // about a binary the table actually shows.
    if let Some((dll, _)) = &activity {
        dll_names.insert(dll.clone());
    }
    // The run's queue plan names every binary it will process — the
    // table shows the whole plan, not just what has started.
    dll_names.extend(queue.iter().cloned());

    let total_dlls = dll_names.len();
    let dll_names_vec: Vec<String> = {
        let mut v: Vec<String> = dll_names.into_iter().collect();
        // Rows follow the run's queue plan — the order the live loop
        // will process them — with unplanned binaries after, alphabetical.
        let pos = |d: &String| queue.iter().position(|q| q == d);
        v.sort_by(|a, b| match (pos(a), pos(b)) {
            (Some(i), Some(j)) => i.cmp(&j),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => a.cmp(b),
        });
        v
    };

    // Find DLLs currently being translated (have entries not yet finished)
    let currently_translating: Vec<String> = entries_snapshot
        .values()
        .filter(|e| !e.finished)
        .map(|e| e.dll.clone())
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();

    // Build per-DLL progress
    let mut dlls = Vec::new();
    for (order, dll) in dll_names_vec.iter().enumerate() {
        let classification = classifications.get(dll).cloned();

        let batch = batch_summaries.get(dll).cloned();

        // Check if this DLL is currently being translated
        let current_translating = currently_translating.iter().find(|d| **d == *dll).map(|d| {
            let dll_entries: Vec<_> = entries_snapshot.values().filter(|e| e.dll == **d).collect();
            let completed = dll_entries.iter().filter(|e| e.finished).count();
            super::super::CurrentDllStatus {
                dll: d.clone(),
                total_entries: dll_entries.len(),
                completed_entries: completed,
            }
        });

        dlls.push(PipelineDllProgress {
            dll: dll.clone(),
            classification,
            batch,
            in_progress: current_translating,
            order,
        });
    }

    let binaries = derive_binaries(
        &dll_names_vec,
        &classifications,
        &batch_summaries,
        &entries_snapshot,
        processing.as_deref(),
        activity.as_ref(),
    );
    let phases = derive_phases(
        total_dlls,
        &classifications,
        &batch_summaries,
        &entries_snapshot,
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
fn disk_classifications(repo_path: &Path) -> HashMap<String, ClassificationInfo> {
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
        let dll = value.get("dll").and_then(|v| v.as_str()).unwrap_or("");
        let category = value.get("category").and_then(|v| v.as_str()).unwrap_or("");
        if dll.is_empty() || category.is_empty() {
            continue;
        }
        found.insert(
            dll.to_string(),
            ClassificationInfo {
                dll: dll.to_string(),
                category: category.to_string(),
                strategy: value
                    .get("strategy")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
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
    batch_summaries: &HashMap<String, BatchInfo>,
    threshold: TranslationPhase,
    batch_counts: bool,
) -> usize {
    let mut done: HashSet<&str> = HashSet::new();
    for entry in entries.values() {
        if furthest_phase(entry) >= threshold {
            done.insert(entry.dll.as_str());
        }
    }
    if batch_counts {
        for dll in batch_summaries.keys() {
            done.insert(dll.as_str());
        }
    }
    // Only count binaries the pipeline actually knows about.
    done.len().min(total_dlls)
}

/// Derive one record per master-plan phase, in bar order, from the live
/// progress data. A binary counts as having completed a unit-level phase
/// when at least one of its functions reached that phase (or its batch
/// summary landed) — the counts are per binary, matching `total_dlls`.
fn derive_phases(
    total_dlls: usize,
    classifications: &HashMap<String, ClassificationInfo>,
    batch_summaries: &HashMap<String, BatchInfo>,
    entries: &HashMap<String, ProgressEntry>,
) -> Vec<PhaseProgress> {
    // Phase 2.5 only covers binaries classified with the PAL strategy.
    let pal_binaries: Vec<&String> = classifications
        .keys()
        .filter(|dll| {
            classifications
                .get(*dll)
                .is_some_and(|c| is_pal_strategy(&c.strategy))
        })
        .collect();

    PipelinePhase::ALL
        .iter()
        .map(|&phase| match phase {
            PipelinePhase::ProjectIngestion => {
                counted_phase(phase, classifications.len(), total_dlls)
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
                    .filter(|dll| batch_summaries.contains_key(dll.as_str()))
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

/// Derive per-binary progress records, sorted by name. Batch summaries are
/// the authoritative function counts when present; otherwise the counts come
/// from per-unit terminal events, and unknown totals stay `None`.
fn derive_binaries(
    dll_names: &[String],
    classifications: &HashMap<String, ClassificationInfo>,
    batch_summaries: &HashMap<String, BatchInfo>,
    entries: &HashMap<String, ProgressEntry>,
    processing_dll: Option<&str>,
    activity: Option<&(String, calxgloss_types::BinaryActivity)>,
) -> Vec<BinaryProgress> {
    dll_names
        .iter()
        .map(|dll| {
            let classification = classifications.get(dll);
            let batch = batch_summaries.get(dll);

            let units: Vec<&ProgressEntry> = entries.values().filter(|e| e.dll == *dll).collect();

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
                dll: dll.clone(),
                category: classification.map(|c| c.category.clone()),
                strategy: classification.map(|c| c.strategy.clone()),
                crate_replacement: classification.and_then(|c| c.crate_replacement.clone()),
                functions_total,
                functions_translated,
                functions_in_progress: units.iter().filter(|e| !e.finished).count(),
                functions_failed,
                tokens_used,
                processing: processing_dll == Some(dll.as_str()),
                activity: activity.filter(|(d, _)| d == dll).map(|(_, a)| a.clone()),
            }
        })
        .collect()
}
