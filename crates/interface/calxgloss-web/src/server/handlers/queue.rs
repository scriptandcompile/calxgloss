//! Queue management: listing units, computing dependency order, and the
//! persisted manual overlay (order + priority) on top of it.

use std::collections::HashMap;

use super::super::{
    QueueEntry, QueueOverlay, QueueOverlayResponse, QueueOverlayUpdate, QueuePosition,
    QueuePriority, QueueResponse, ServerError, ServerState,
};
use calxgloss_types::{DependencyGraph, ReviewStatus};

use axum::{Json, extract::State};

// ─── GET /api/queue ──────────────────────────────────────────────────

/// Returns the full review queue sorted by dependency order, with the
/// persisted queue overlay breaking ties (issue #74).
pub async fn api_get_queue(
    State(state): State<ServerState>,
) -> Result<Json<QueueResponse>, ServerError> {
    let dashboard = super::super::build_dashboard(state.repo_path())
        .map_err(|e| ServerError::internal(&e.to_string()))?;
    let overlay = load_queue_overlay(state.repo_path());
    let ordered = queue_order(&dashboard, &overlay);
    Ok(Json(QueueResponse::from_ordered(&dashboard, &ordered)))
}

// ─── GET /api/queue/next ─────────────────────────────────────────────

/// Returns the next unit in the review queue: dependency order with the
/// persisted queue overlay breaking ties, matching what the queue view
/// shows (issue #74).
pub async fn api_get_next_unit(
    State(state): State<ServerState>,
) -> Result<Json<Option<QueueEntry>>, ServerError> {
    let dashboard = super::super::build_dashboard(state.repo_path())
        .map_err(|e| ServerError::internal(&e.to_string()))?;
    let overlay = load_queue_overlay(state.repo_path());
    // queue_order puts the active (Queued + PendingReview) section first.
    let next = queue_order(&dashboard, &overlay)
        .into_iter()
        .find(|u| matches!(u.status, ReviewStatus::Queued | ReviewStatus::PendingReview));
    Ok(Json(next.map(|u| QueueEntry {
        id: u.id.clone(),
        name: u.name.clone(),
        kind: u.kind.to_string(),
        binary: u.binary.clone(),
        function: u.function.clone(),
        status: u.status.to_string(),
        stale: u.stale.to_string(),
        blocked: matches!(u.status, ReviewStatus::Blocked),
    })))
}

// ─── /api/queue/overlay (issue #74) ──────────────────────────────────

/// Returns the persisted queue overlay plus the effective queue order it
/// produces. Degrades to an empty overlay (pure dependency order) when
/// nothing has been recorded yet. Registered in every router — it reads a
/// persisted file, not live pipeline state.
pub async fn api_get_queue_overlay(
    State(state): State<ServerState>,
) -> Result<Json<QueueOverlayResponse>, ServerError> {
    let dashboard = super::super::build_dashboard(state.repo_path())
        .map_err(|e| ServerError::internal(&e.to_string()))?;
    let overlay = load_queue_overlay(state.repo_path());
    Ok(Json(overlay_response(&dashboard, &overlay)))
}

/// Replaces the manual order and/or the priority map of the persisted queue
/// overlay and returns the new overlay with the effective order. An omitted
/// body field keeps its persisted value. Registered in every router — the
/// overlay is review state the plain `serve` mode owns.
pub async fn api_update_queue_overlay(
    State(state): State<ServerState>,
    Json(update): Json<QueueOverlayUpdate>,
) -> Result<Json<QueueOverlayResponse>, ServerError> {
    let dashboard = super::super::build_dashboard(state.repo_path())
        .map_err(|e| ServerError::internal(&e.to_string()))?;
    let mut overlay = load_queue_overlay(state.repo_path());
    if let Some(order) = update.order {
        overlay.order = order;
    }
    if let Some(priorities) = update.priorities {
        overlay.priorities = priorities;
    }
    save_queue_overlay(state.repo_path(), &overlay)?;
    Ok(Json(overlay_response(&dashboard, &overlay)))
}

/// Builds the overlay endpoint response: the overlay as persisted plus the
/// effective order it produces over this dashboard.
fn overlay_response(
    dashboard: &calxgloss_types::ReviewDashboard,
    overlay: &QueueOverlay,
) -> QueueOverlayResponse {
    let queue_order = queue_order(dashboard, overlay)
        .into_iter()
        .map(|u| u.id.clone())
        .collect();
    QueueOverlayResponse {
        success: true,
        overlay: overlay.clone(),
        queue_order,
    }
}

// ─── Helper functions ─────────────────────────────────────────────────

/// Find a unit by ID using the repository's review dashboard.
pub(crate) fn find_unit(
    state: &ServerState,
    unit_id: &str,
) -> Result<calxgloss_types::UnitOfWork, ServerError> {
    let dashboard = super::super::build_dashboard(state.repo_path())
        .map_err(|e| ServerError::internal(&e.to_string()))?;
    dashboard
        .review_queue
        .iter()
        .chain(dashboard.recent_activity.iter())
        .find(|u| u.id == unit_id)
        .cloned()
        .ok_or_else(|| ServerError::not_found(&format!("Unit not found: {unit_id}")))
}

/// Compute the position of a unit in the effective queue order — dependency
/// order with the persisted overlay breaking ties (issue #74).
pub(crate) fn compute_queue_position(
    dashboard: &calxgloss_types::ReviewDashboard,
    unit: &calxgloss_types::UnitOfWork,
    overlay: &QueueOverlay,
) -> QueuePosition {
    let sorted = queue_order(dashboard, overlay);
    let total = sorted.len();
    let index = sorted.iter().position(|u| u.id == unit.id);
    QueuePosition { index, total }
}

/// Path of the persisted queue overlay inside the repo — review-UI state,
/// filed beside the other review records rather than under `re/analysis`
/// (which holds pipeline artifacts).
pub(crate) fn queue_overlay_path(repo_path: &std::path::Path) -> std::path::PathBuf {
    repo_path
        .join("re")
        .join("review")
        .join("queue_overlay.json")
}

/// Loads the persisted queue overlay, degrading to the empty overlay
/// (pure dependency order) when the file is missing or corrupt.
pub(crate) fn load_queue_overlay(repo_path: &std::path::Path) -> QueueOverlay {
    super::process::load_json_or_default(&queue_overlay_path(repo_path))
}

/// Writes the queue overlay atomically so a manual order or priority set in
/// the UI survives a server restart.
pub(crate) fn save_queue_overlay(
    repo_path: &std::path::Path,
    overlay: &QueueOverlay,
) -> Result<(), ServerError> {
    calxgloss_types::save_json(&queue_overlay_path(repo_path), overlay)
        .map_err(|e| ServerError::internal(&format!("Failed to save queue overlay: {e}")))
}

/// Orders the review queue: dependency order governs, and the persisted
/// overlay breaks ties (issue #74).
///
/// The active section (Queued + PendingReview) of [`sorted_queue`] is
/// re-sorted by (dependency depth, priority, manual order). Depth is the
/// longest dependency chain to a unit: if A depends on B then A's depth is
/// strictly greater, so units sharing a depth are incomparable in the graph
/// and reordering among them can never violate a dependency edge. Within a
/// depth group, HIGH sorts before NORMAL before LOW, then the reviewer's
/// manual order; units with no overlay entry keep their dependency-order
/// position. Accepted and other non-active units stay in their
/// [`sorted_queue`] tail, untouched by the overlay.
pub(crate) fn queue_order<'a>(
    dashboard: &'a calxgloss_types::ReviewDashboard,
    overlay: &QueueOverlay,
) -> Vec<&'a calxgloss_types::UnitOfWork> {
    let sorted = dashboard.sorted_queue();
    let depths = dependency_depths(&dashboard.dependency_graph);
    let manual_index = overlay_manual_index(overlay);

    // sorted_queue puts the active (Queued + PendingReview) units first;
    // only that section takes part in the tie-break.
    let split = sorted
        .iter()
        .position(|u| !matches!(u.status, ReviewStatus::Queued | ReviewStatus::PendingReview))
        .unwrap_or(sorted.len());
    let (active, rest) = sorted.split_at(split);

    let mut active: Vec<&calxgloss_types::UnitOfWork> = active.to_vec();
    active.sort_by_key(|u| {
        (
            // Units outside the graph sort after every graph unit, matching
            // sorted_queue's own placement of them.
            depths.get(u.id.as_str()).copied().unwrap_or(usize::MAX),
            priority_rank(overlay.priorities.get(u.id.as_str()).copied()),
            manual_index(u.id.as_str()),
        )
    });

    active.extend(rest.iter().copied());
    active
}

/// Sort rank of a priority: HIGH first, LOW last; absent means NORMAL.
fn priority_rank(priority: Option<QueuePriority>) -> u8 {
    match priority.unwrap_or_default() {
        QueuePriority::High => 0,
        QueuePriority::Normal => 1,
        QueuePriority::Low => 2,
    }
}

/// Maps each unit id to its position in the overlay's manual order; ids
/// absent from the order sort last (they keep dependency order).
fn overlay_manual_index(overlay: &QueueOverlay) -> impl Fn(&str) -> usize + '_ {
    |id| {
        overlay
            .order
            .iter()
            .position(|unit| unit == id)
            .unwrap_or(usize::MAX)
    }
}

/// Longest-dependency-chain depth per unit id: a unit's depth is one more
/// than the deepest unit it depends on, and zero when it depends on nothing.
/// Because a dependency edge always points to a strictly smaller depth,
/// units at equal depth are incomparable — the tie groups the overlay may
/// reorder. Graph cycles (which `topological_order` already warns about)
/// contribute no depth rather than looping.
fn dependency_depths(graph: &DependencyGraph) -> HashMap<&str, usize> {
    let mut deps: HashMap<&str, Vec<&str>> = HashMap::new();
    for edge in &graph.edges {
        deps.entry(edge.from.as_str())
            .or_default()
            .push(edge.to.as_str());
    }

    let mut depths: HashMap<&str, usize> = HashMap::new();
    let mut visiting: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for node in &graph.nodes {
        depth_of(node.unit_id.as_str(), &deps, &mut depths, &mut visiting);
    }
    depths
}

/// Depth of one unit, memoized in `depths`. A unit already on the current
/// DFS path (a cycle) contributes zero, so cyclic graphs terminate.
fn depth_of<'a>(
    id: &'a str,
    deps: &HashMap<&'a str, Vec<&'a str>>,
    depths: &mut HashMap<&'a str, usize>,
    visiting: &mut std::collections::HashSet<&'a str>,
) -> usize {
    if let Some(&d) = depths.get(id) {
        return d;
    }
    if !visiting.insert(id) {
        return 0;
    }
    let mut max_dep = 0;
    if let Some(unit_deps) = deps.get(id) {
        for &dep in unit_deps {
            max_dep = max_dep.max(depth_of(dep, deps, depths, visiting));
        }
    }
    visiting.remove(id);
    let depth = max_dep + 1;
    depths.insert(id, depth);
    depth
}

// ─── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use calxgloss_types::{
        DependencyEdge, DependencyGraph, DependencyNode, ReviewDashboard, UnitOfWork, WorkKind,
    };

    fn make_unit(id: &str, kind: WorkKind, status: ReviewStatus) -> UnitOfWork {
        UnitOfWork {
            id: id.into(),
            name: id.into(),
            kind,
            binary: "game_logic.dll".into(),
            function: Some(id.into()),
            attempt: 1,
            accepted: matches!(&status, ReviewStatus::Accepted),
            status,
            unit_confidence: None,
            baseline_tests_passed: None,
            baseline_tests_total: None,
            verification_tests_passed: None,
            verification_tests_total: None,
            llm_model: None,
            context_tier: None,
            dependencies: vec![],
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            known_gaps: vec![],
            stale: calxgloss_types::dashboard::Staleness::Fresh,
        }
    }

    fn make_graph(nodes: &[(&str, WorkKind)], edges: &[(&str, &str)]) -> DependencyGraph {
        DependencyGraph {
            nodes: nodes
                .iter()
                .map(|(id, kind)| {
                    DependencyNode::with_level(*id, *id, ReviewStatus::Queued, kind.level())
                })
                .collect(),
            edges: edges
                .iter()
                .map(|(from, to)| DependencyEdge {
                    from: (*from).into(),
                    to: (*to).into(),
                })
                .collect(),
        }
    }

    fn make_dashboard(units: Vec<UnitOfWork>, graph: DependencyGraph) -> ReviewDashboard {
        let mut dashboard = ReviewDashboard::new(units);
        dashboard.dependency_graph = graph;
        dashboard
    }

    fn ids(order: &[&UnitOfWork]) -> Vec<String> {
        order.iter().map(|u| u.id.clone()).collect()
    }

    #[test]
    fn queue_order_never_puts_a_dependent_before_its_dependency() {
        // func_B depends on func_A; the overlay tries to invert them.
        let dashboard = make_dashboard(
            vec![
                make_unit(
                    "func_A",
                    WorkKind::FunctionTranslation,
                    ReviewStatus::Queued,
                ),
                make_unit(
                    "func_B",
                    WorkKind::FunctionTranslation,
                    ReviewStatus::Queued,
                ),
            ],
            make_graph(
                &[
                    ("func_A", WorkKind::FunctionTranslation),
                    ("func_B", WorkKind::FunctionTranslation),
                ],
                &[("func_B", "func_A")],
            ),
        );
        let overlay = QueueOverlay {
            order: vec!["func_B".into(), "func_A".into()],
            priorities: HashMap::from([("func_B".into(), QueuePriority::High)]),
        };

        let order = ids(&queue_order(&dashboard, &overlay));
        let a = order
            .iter()
            .position(|id| id == "func_A")
            .expect("A ordered");
        let b = order
            .iter()
            .position(|id| id == "func_B")
            .expect("B ordered");
        assert!(
            a < b,
            "dependency must precede its dependent, got {order:?}"
        );
    }

    #[test]
    fn queue_order_breaks_same_depth_ties_by_priority_then_manual_order() {
        // Three queued functions at the same depth (all depend on the
        // classification unit, which is accepted and sits in the tail).
        let dashboard = make_dashboard(
            vec![
                make_unit(
                    "func_A",
                    WorkKind::FunctionTranslation,
                    ReviewStatus::Queued,
                ),
                make_unit(
                    "func_B",
                    WorkKind::FunctionTranslation,
                    ReviewStatus::Queued,
                ),
                make_unit(
                    "func_C",
                    WorkKind::FunctionTranslation,
                    ReviewStatus::Queued,
                ),
                make_unit(
                    "dll_classify",
                    WorkKind::DllClassification,
                    ReviewStatus::Accepted,
                ),
            ],
            make_graph(
                &[
                    ("func_A", WorkKind::FunctionTranslation),
                    ("func_B", WorkKind::FunctionTranslation),
                    ("func_C", WorkKind::FunctionTranslation),
                    ("dll_classify", WorkKind::DllClassification),
                ],
                &[
                    ("func_A", "dll_classify"),
                    ("func_B", "dll_classify"),
                    ("func_C", "dll_classify"),
                ],
            ),
        );
        let overlay = QueueOverlay {
            order: vec!["func_C".into(), "func_B".into()],
            priorities: HashMap::from([("func_B".into(), QueuePriority::High)]),
        };

        let order = ids(&queue_order(&dashboard, &overlay));
        // HIGH wins over manual order; manual order wins over default. The
        // accepted classification unit drops out of sorted_queue entirely
        // (it is in the graph and no longer active), so it is not listed.
        assert_eq!(order, vec!["func_B", "func_C", "func_A"]);
    }

    #[test]
    fn queue_order_without_overlay_is_dependency_order() {
        let dashboard = make_dashboard(
            vec![
                make_unit(
                    "func_A",
                    WorkKind::FunctionTranslation,
                    ReviewStatus::Queued,
                ),
                make_unit(
                    "func_B",
                    WorkKind::FunctionTranslation,
                    ReviewStatus::Queued,
                ),
            ],
            make_graph(
                &[
                    ("func_A", WorkKind::FunctionTranslation),
                    ("func_B", WorkKind::FunctionTranslation),
                ],
                &[("func_B", "func_A")],
            ),
        );

        let order = ids(&queue_order(&dashboard, &QueueOverlay::default()));
        assert_eq!(order, vec!["func_A", "func_B"]);
    }

    #[test]
    fn queue_order_terminates_on_cyclic_graphs() {
        let dashboard = make_dashboard(
            vec![
                make_unit(
                    "func_A",
                    WorkKind::FunctionTranslation,
                    ReviewStatus::Queued,
                ),
                make_unit(
                    "func_B",
                    WorkKind::FunctionTranslation,
                    ReviewStatus::Queued,
                ),
            ],
            make_graph(
                &[
                    ("func_A", WorkKind::FunctionTranslation),
                    ("func_B", WorkKind::FunctionTranslation),
                ],
                &[("func_A", "func_B"), ("func_B", "func_A")],
            ),
        );

        let order = ids(&queue_order(&dashboard, &QueueOverlay::default()));
        assert_eq!(order.len(), 2, "both units still ordered despite the cycle");
    }

    #[test]
    fn queue_overlay_round_trips_through_disk() {
        let dir = tempfile::tempdir().expect("temp workspace");
        let overlay = QueueOverlay {
            order: vec!["func_B".into(), "func_A".into()],
            priorities: HashMap::from([("func_A".into(), QueuePriority::Low)]),
        };

        save_queue_overlay(dir.path(), &overlay).expect("overlay saves");
        let loaded = load_queue_overlay(dir.path());
        assert_eq!(loaded.order, overlay.order);
        assert_eq!(loaded.priorities, overlay.priorities);
    }

    #[test]
    fn load_queue_overlay_degrades_to_empty_when_missing_or_corrupt() {
        let dir = tempfile::tempdir().expect("temp workspace");
        let missing = load_queue_overlay(dir.path());
        assert!(missing.order.is_empty() && missing.priorities.is_empty());

        let path = queue_overlay_path(dir.path());
        std::fs::create_dir_all(path.parent().expect("overlay dir")).expect("create re/review");
        std::fs::write(&path, "not json").expect("write corrupt overlay");
        let corrupt = load_queue_overlay(dir.path());
        assert!(corrupt.order.is_empty() && corrupt.priorities.is_empty());
    }
}
