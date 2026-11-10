//! The live-merge seam: the reader's one fold that patches the live
//! store's in-flight units into a freshly built review dashboard
//! (issue #460).

use super::*;

impl ReviewSurfaceReader {
    /// Builds the workspace's review dashboard and merges the live store's
    /// in-flight readings into it — the single fold both the dashboard and
    /// the unit-detail endpoint serve through.
    pub async fn review_dashboard(&self) -> Result<ReviewDashboard, ServerError> {
        let mut dashboard = super::super::build_dashboard(&self.repo_path)
            .map_err(|e| ServerError::internal(&e.to_string()))?;
        if let Some(progress) = &self.progress {
            // The store answers each read as one consistent snapshot
            // (P58's seam, kept as shipped).
            let entries = progress.read().await.snapshot().await;
            merge_live_progress(&mut dashboard, &entries);
        }
        Ok(dashboard)
    }
}

/// The single *live-merge fold*: it patches the live store's in-flight
/// readings into a freshly built dashboard. Every review row whose
/// `binary/function` pair the store names reads `in_progress`; every
/// in-flight unit the dashboard does not list yet arrives as exactly one
/// synthetic `live/{key}/v{attempt}` row, named the way the live view
/// names it. An accepted row keeps the timestamp its acceptance recorded.
pub(super) fn merge_live_progress(
    dashboard: &mut ReviewDashboard,
    entries: &HashMap<String, LiveUnitProgress>,
) {
    let mut matched_keys: std::collections::HashSet<String> = std::collections::HashSet::new();

    // One rule for every review row, in either list: a row the live store
    // names reads in flight. Re-stamping is for rows whose status is a
    // review state the run has now overtaken — an accepted row keeps the
    // timestamp its acceptance recorded.
    let mut patch = |units: &mut Vec<calxgloss_types::UnitOfWork>| {
        for unit in units {
            let key = format!("{}/{}", unit.binary, unit.function.as_deref().unwrap_or(""));
            if entries.contains_key(key.as_str()) {
                let old =
                    std::mem::replace(&mut unit.status, calxgloss_types::ReviewStatus::InProgress);
                if !matches!(old, calxgloss_types::ReviewStatus::Accepted) {
                    unit.updated_at = chrono::Utc::now();
                }
                matched_keys.insert(key);
            }
        }
    };
    patch(&mut dashboard.review_queue);
    patch(&mut dashboard.recent_activity);

    // An in-flight unit the dashboard does not list yet still shows as one
    // synthetic row, keyed and named the way the live view names it.
    for (key, entry) in entries {
        if matched_keys.contains(key.as_str()) {
            continue;
        }
        let name = if entry.function.is_empty() {
            format!("Classify {}", entry.binary)
        } else {
            format!("{}!{}", entry.binary, entry.function)
        };
        dashboard.review_queue.push(calxgloss_types::UnitOfWork {
            id: format!("live/{}/v{}", key, entry.attempt),
            name,
            kind: calxgloss_types::WorkKind::FunctionTranslation,
            binary: entry.binary.clone(),
            function: if entry.function.is_empty() {
                None
            } else {
                Some(entry.function.clone())
            },
            attempt: entry.attempt,
            status: calxgloss_types::ReviewStatus::InProgress,
            accepted: false,
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
            unknowns: calxgloss_types::UnitUnknowns::unknown(),
            obligation: calxgloss_types::UnitObligation::unknown(),
            stale: calxgloss_types::dashboard::Staleness::Fresh,
        });
    }
}
