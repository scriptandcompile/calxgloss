//! Live translation progress and pipeline progress endpoints.

use super::super::{
    CombinedState, PipelineDllProgress, PipelineProgressResponse, ProgressInfo, ProgressResponse,
    ProgressUnitStatus,
};

use axum::{Json, extract::State};

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
                status: format!("{:?}", e.status).to_lowercase().replace('_', " "),
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
/// pipeline's current status.
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
    let classifications: std::collections::HashMap<String, super::super::ClassificationInfo> =
        classifications_raw
            .into_iter()
            .map(|c| (c.dll.clone(), c))
            .collect();
    let batch_summaries: std::collections::HashMap<String, super::super::BatchInfo> =
        batch_summaries_raw
            .into_iter()
            .map(|b| (b.dll.clone(), b))
            .collect();

    // Snapshot entries before dropping the lock to avoid nested borrows
    let entries_snapshot: std::collections::HashMap<String, super::super::ProgressEntry> =
        entries.clone();

    // Collect all DLL names from all three sources
    let mut dll_names: std::collections::HashSet<String> = std::collections::HashSet::new();

    // From live translation entries (group by DLL)
    for entry in entries_snapshot.values() {
        dll_names.insert(entry.dll.clone());
    }

    let total_dlls = dll_names.len();
    let dll_names_vec: Vec<String> = {
        let mut v: Vec<String> = dll_names.into_iter().collect();
        v.sort();
        v
    };

    // Find DLLs currently being translated (have entries with non-Complete status)
    let currently_translating: Vec<String> = entries_snapshot
        .values()
        .filter(|e| !matches!(e.status, ProgressUnitStatus::Complete))
        .map(|e| e.dll.clone())
        .collect::<std::collections::HashSet<_>>()
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
            let completed = dll_entries
                .iter()
                .filter(|e| matches!(e.status, ProgressUnitStatus::Complete))
                .count();
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

    Json(PipelineProgressResponse {
        total_dlls,
        classified_count: classifications.len(),
        batch_complete_count: batch_summaries.len(),
        currently_translating,
        dlls,
    })
}
