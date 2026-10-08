//! Live translation progress and pipeline progress endpoints.

use super::super::{
    BatchInfo, ClassificationInfo, CombinedState, PipelineDllProgress, PipelineProgressResponse,
    PipelineTimeEstimate, ProgressEntry, ProgressInfo, ProgressResponse,
};

use axum::{Json, extract::State};
use calxgloss_types::{
    BinaryProgress, PhaseProgress, PhaseState, PipelinePhase, TokenUsageLog, TranslationPhase,
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

    // Convert to owned HashMaps for O(1) lookups by DLL name
    let classifications: HashMap<String, ClassificationInfo> = classifications_raw
        .into_iter()
        .map(|c| (c.dll.clone(), c))
        .collect();
    let batch_summaries: HashMap<String, BatchInfo> = batch_summaries_raw
        .into_iter()
        .map(|b| (b.dll.clone(), b))
        .collect();

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

    let total_dlls = dll_names.len();
    let dll_names_vec: Vec<String> = {
        let mut v: Vec<String> = dll_names.into_iter().collect();
        v.sort();
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
            }
        })
        .collect()
}
