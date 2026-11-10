//! The web server has one review-surface reader (issue #460, P59). The
//! reader is built from the workspace path plus the live store, and every
//! review payload is served from it. It owns the single *live-merge fold*
//! — the code that patches in-flight units into the review rows — which
//! the dashboard and unit-detail endpoints each pasted by hand. Later P59
//! tickets route more record reads through this reader.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use calxgloss_types::LiveUnitProgress;
use calxgloss_types::dashboard::ReviewDashboard;
use tokio::sync::RwLock;

use super::ServerError;
use super::live_store::ProgressState;

/// One reader over the record tree and the live store, serving every
/// review payload. Handlers receive it through [`super::CombinedState`]
/// and never walk the record tree or the live store's internals
/// themselves.
#[derive(Clone)]
pub struct ReviewSurfaceReader {
    repo_path: PathBuf,
    progress: Option<Arc<RwLock<ProgressState>>>,
}

impl ReviewSurfaceReader {
    /// Creates the reader for a workspace, with the live store attached
    /// when the server runs a live pipeline (`None` for plain `serve`).
    pub fn new(repo_path: PathBuf, progress: Option<Arc<RwLock<ProgressState>>>) -> Self {
        Self {
            repo_path,
            progress,
        }
    }

    /// Builds the workspace's review dashboard and merges the live store's
    /// in-flight readings into it — the single fold both the dashboard and
    /// the unit-detail endpoint serve through.
    pub async fn review_dashboard(&self) -> Result<ReviewDashboard, ServerError> {
        let mut dashboard = super::build_dashboard(&self.repo_path)
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
fn merge_live_progress(
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

#[cfg(test)]
mod tests {
    use super::*;
    use calxgloss_types::{BinaryIdentity, ReviewStatus, UnitOfWork, WorkKind};

    fn unit(binary: &str, function: &str, status: ReviewStatus) -> UnitOfWork {
        UnitOfWork {
            id: format!("{binary}/{function}/v1"),
            name: format!("{binary}!{function}"),
            kind: WorkKind::FunctionTranslation,
            binary: BinaryIdentity::new(binary),
            function: Some(function.to_string()),
            attempt: 1,
            status,
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
        }
    }

    /// The store read the fold consumes: apply events to a real live store
    /// and take its snapshot, exactly as the reader will.
    async fn store_entries(
        events: Vec<calxgloss_types::ProgressEvent>,
    ) -> HashMap<String, LiveUnitProgress> {
        let store = super::super::ProgressState::new();
        for event in events {
            store.apply(&event).await;
        }
        store.snapshot().await
    }

    fn started(binary: &str, function: &str) -> calxgloss_types::ProgressEvent {
        calxgloss_types::ProgressEvent::TranslationStarted {
            binary: binary.into(),
            function: function.to_string(),
        }
    }

    #[tokio::test]
    async fn a_matching_review_row_is_patched_to_in_progress() {
        let mut dashboard = ReviewDashboard::new(vec![unit(
            "game_logic.dll",
            "DrawPrimitive",
            ReviewStatus::PendingReview,
        )]);
        let entries = store_entries(vec![started("game_logic.dll", "DrawPrimitive")]).await;

        merge_live_progress(&mut dashboard, &entries);

        assert_eq!(
            dashboard.review_queue[0].status,
            ReviewStatus::InProgress,
            "a unit the live store names reads as in flight"
        );
    }

    #[tokio::test]
    async fn an_in_flight_unit_the_dashboard_does_not_list_is_added_once() {
        let mut dashboard = ReviewDashboard::new(vec![unit(
            "game_logic.dll",
            "DrawPrimitive",
            ReviewStatus::PendingReview,
        )]);
        let entries = store_entries(vec![
            started("game_logic.dll", "DrawPrimitive"),
            started("kernel32.dll", "CreateFile"),
        ])
        .await;

        merge_live_progress(&mut dashboard, &entries);

        let added: Vec<&UnitOfWork> = dashboard
            .review_queue
            .iter()
            .filter(|u| u.id == "live/kernel32.dll/CreateFile/v1")
            .collect();
        assert_eq!(
            added.len(),
            1,
            "the in-flight unit the dashboard lacks arrives as exactly one synthetic row"
        );
        assert_eq!(added[0].status, ReviewStatus::InProgress);
        assert_eq!(
            dashboard.review_queue.len(),
            2,
            "no other row is fabricated"
        );
    }

    #[tokio::test]
    async fn an_accepted_unit_patched_in_place_keeps_its_recorded_timestamp() {
        let mut accepted = unit("game_logic.dll", "Update", ReviewStatus::Accepted);
        accepted.accepted = true;
        let filed_at = chrono::Utc::now() - chrono::Duration::days(3);
        accepted.updated_at = filed_at;
        let pending = unit(
            "game_logic.dll",
            "DrawPrimitive",
            ReviewStatus::PendingReview,
        );
        let pending_before = pending.updated_at;
        // ReviewDashboard::new files accepted rows in recent_activity.
        let mut dashboard = ReviewDashboard::new(vec![accepted, pending]);
        let entries = store_entries(vec![
            started("game_logic.dll", "Update"),
            started("game_logic.dll", "DrawPrimitive"),
        ])
        .await;

        merge_live_progress(&mut dashboard, &entries);

        assert_eq!(
            dashboard.recent_activity[0].status,
            ReviewStatus::InProgress,
            "a running translation reads in flight wherever its row sits"
        );
        assert_eq!(
            dashboard.recent_activity[0].updated_at, filed_at,
            "patching an accepted row's status is a live reading, not a new review event"
        );
        assert!(
            dashboard.review_queue[0].updated_at > pending_before,
            "an unaccepted patched row is re-stamped, as today"
        );
    }

    #[tokio::test]
    async fn a_unit_matched_in_recent_activity_is_not_added_again_as_synthetic() {
        let mut accepted = unit("kernel32.dll", "CreateFile", ReviewStatus::Accepted);
        accepted.accepted = true;
        let mut dashboard = ReviewDashboard::new(vec![accepted]);
        let entries = store_entries(vec![started("kernel32.dll", "CreateFile")]).await;

        merge_live_progress(&mut dashboard, &entries);

        assert!(
            dashboard
                .review_queue
                .iter()
                .all(|u| !u.id.starts_with("live/")),
            "the accepted row in recent_activity already shows the unit — no second row"
        );
        assert_eq!(
            dashboard.recent_activity[0].status,
            ReviewStatus::InProgress
        );
    }

    /// A repo with one review unit — branch `re/game_logic.dll/DrawSpritev1`
    /// with one translated commit, the shape the `actions.rs` tests use —
    /// so the dashboard really lists `game_logic.dll/DrawSprite/v1`.
    fn make_repo_with_unit() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("temp dir");
        let git = calxgloss_git::GitManager::init_repo(dir.path(), None).expect("init git repo");
        git.create_branch("game_logic.dll", "DrawSprite", 1, None)
            .expect("create v1 branch");

        let branch = calxgloss_types::GitBranch::new("game_logic.dll", "DrawSprite", 1)
            .expect("branch name");
        std::fs::create_dir_all(dir.path().join("src").join("modules")).expect("src dir");
        std::fs::write(
            dir.path().join("src").join("modules").join("game_logic.rs"),
            "pub fn draw_sprite() {}\n",
        )
        .expect("write translation");
        git.commit(
            &branch,
            "Translate DrawSprite",
            &["src/modules/game_logic.rs"],
        )
        .expect("commit translation");
        dir
    }

    #[tokio::test]
    async fn the_reader_serves_the_workspaces_dashboard_with_the_live_store_folded_in() {
        let dir = make_repo_with_unit();
        let store = super::super::ProgressState::new();
        store.apply(&started("game_logic.dll", "DrawSprite")).await;
        store
            .apply(&started("game_logic.dll", "LateFunction"))
            .await;
        let reader = super::super::ReviewSurfaceReader::new(
            dir.path().to_path_buf(),
            Some(std::sync::Arc::new(tokio::sync::RwLock::new(store))),
        );

        let dashboard = reader
            .review_dashboard()
            .await
            .expect("the workspace dashboard builds");

        let listed = dashboard
            .review_queue
            .iter()
            .find(|u| u.id == "game_logic.dll/DrawSprite/v1")
            .expect("the workspace's unit is listed");
        assert_eq!(
            listed.status,
            ReviewStatus::InProgress,
            "the store's in-flight reading reaches the built dashboard"
        );
        let synthetic: Vec<&UnitOfWork> = dashboard
            .review_queue
            .iter()
            .filter(|u| u.function.as_deref() == Some("LateFunction"))
            .collect();
        assert_eq!(
            synthetic.len(),
            1,
            "the unit only the store names arrives exactly once"
        );
        assert_eq!(synthetic[0].id, "live/game_logic.dll/LateFunction/v1");
    }
}
