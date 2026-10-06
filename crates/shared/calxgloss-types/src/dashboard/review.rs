//! ReviewDashboard — the main dashboard type.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::graph::DependencyGraph;
use super::status::StatusCounts;
use super::types::{ReviewStatus, WorkLevel};
use super::work_unit::UnitOfWork;

/// A dashboard view showing all units of work and their status.
///
/// Assembled from a list of [`UnitOfWork`] instances, this type provides:
/// - A dependency-sorted review queue
/// - Aggregated status counts
/// - A dependency graph for visualization
/// - Recent activity (accepted/merged units)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewDashboard {
    /// The dependency graph for this review session.
    pub dependency_graph: DependencyGraph,
    /// Units of work ordered for review (dependency-sorted).
    pub review_queue: Vec<UnitOfWork>,
    /// Recently accepted units.
    pub recent_activity: Vec<UnitOfWork>,
    /// Total counts by status.
    pub status_counts: StatusCounts,
}

impl ReviewDashboard {
    /// Creates a new dashboard with the given units of work.
    ///
    /// Builds the dependency graph from units' `dependencies` fields,
    /// sorts the review queue by dependency order (fewer deps first),
    /// computes status counts, and separates accepted units into
    /// `recent_activity`.
    pub fn new(units: Vec<UnitOfWork>) -> Self {
        let mut graph = DependencyGraph {
            nodes: Vec::new(),
            edges: Vec::new(),
        };
        let mut queue = Vec::new();
        let mut recent = Vec::new();
        let mut counts = StatusCounts::default();

        for unit in units {
            let is_accepted = matches!(unit.status, ReviewStatus::Accepted);
            let is_pending = matches!(
                unit.status,
                ReviewStatus::PendingReview | ReviewStatus::SendBack | ReviewStatus::PatchRequested
            );

            if is_accepted {
                recent.push(unit.clone());
            } else if is_pending || unit.status == ReviewStatus::Queued {
                queue.push(unit.clone());
            }

            // Count statuses
            match unit.status {
                ReviewStatus::Queued => counts.queued += 1,
                ReviewStatus::PendingReview => counts.pending_review += 1,
                ReviewStatus::InProgress => counts.in_progress += 1,
                ReviewStatus::Accepted => counts.accepted += 1,
                ReviewStatus::SendBack => counts.send_back += 1,
                ReviewStatus::PatchRequested => counts.patch_requested += 1,
                ReviewStatus::Blocked => counts.blocked += 1,
            }

            // Add node to dependency graph with the correct processing level
            graph.nodes.push(super::graph::DependencyNode::with_level(
                unit.id.clone(),
                unit.name.clone(),
                unit.status.clone(),
                unit.kind.level(),
            ));

            // Add edges for dependencies
            for dep in &unit.dependencies {
                graph.edges.push(super::graph::DependencyEdge {
                    from: unit.id.clone(),
                    to: dep.clone(),
                });
            }
        }

        // Sort queue by dependency order (fewer deps first)
        queue.sort_by_key(|a| a.dependencies.len());

        Self {
            dependency_graph: graph,
            review_queue: queue,
            recent_activity: recent,
            status_counts: counts,
        }
    }

    /// Returns the next unit to review in proper dependency-then-level order.
    ///
    /// This method uses the full topological sort with level-aware tie-breaking
    /// to determine the correct next unit. The ordering respects:
    /// 1. **Dependencies first** — a unit's dependencies must come before it
    /// 2. **Level priority** — within the same depth: shim < PAL trait < function < integration
    ///
    /// Only units with status `Queued` or `PendingReview` are considered.
    /// Already-accepted units and blocked units are excluded.
    pub fn next_in_dependency_order(&self) -> Option<&UnitOfWork> {
        let sorted = self.sorted_queue();
        sorted.first().copied()
    }

    /// Returns all non-accepted units sorted in proper dependency-then-level order.
    ///
    /// Uses the full topological sort from [`DependencyGraph::topological_order`]
    /// with level-aware tie-breaking. This is the canonical ordering for
    /// batch operations like accept-all.
    pub fn sorted_queue(&self) -> Vec<&UnitOfWork> {
        let (ordered, cycle_nodes) = self.dependency_graph.topological_order();
        if !cycle_nodes.is_empty() {
            // Log cycle detection to stderr (tracing is not a dependency of calxgloss-types)
            eprintln!(
                "WARNING: Cycle detected in dependency graph: {:?}. {} nodes excluded from order.",
                cycle_nodes,
                cycle_nodes.len()
            );
        }

        let id_set: std::collections::HashSet<&str> =
            ordered.iter().map(|n| n.unit_id.as_str()).collect();
        let mut result: Vec<&UnitOfWork> = self
            .review_queue
            .iter()
            .chain(self.recent_activity.iter())
            .filter(|u| {
                !id_set.contains(u.id.as_str())
                    || matches!(u.status, ReviewStatus::Queued | ReviewStatus::PendingReview)
            })
            .collect();

        // Separate: accepted units go last (they're already merged)
        let mut accepted: Vec<&UnitOfWork> = Vec::new();
        let mut pending: Vec<&UnitOfWork> = Vec::new();
        for u in &result {
            if matches!(u.status, ReviewStatus::Queued | ReviewStatus::PendingReview) {
                pending.push(*u);
            } else {
                accepted.push(*u);
            }
        }

        // Re-sort pending in topological + level order
        pending.sort_by(|a, b| {
            let ai = ordered.iter().position(|n| n.unit_id == a.id);
            let bi = ordered.iter().position(|n| n.unit_id == b.id);
            match (ai, bi) {
                (Some(i), Some(j)) => i.cmp(&j),
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => a
                    .kind
                    .level()
                    .cmp(&b.kind.level())
                    .then_with(|| a.id.cmp(&b.id)),
            }
        });

        result.clear();
        result.extend(pending);
        result.extend(accepted);
        result
    }

    /// Returns the next unit to review (first in dependency order).
    ///
    /// Deprecated: use [`next_in_dependency_order`](Self::next_in_dependency_order) instead.
    #[deprecated(since = "0.2.0", note = "Use next_in_dependency_order() instead")]
    pub fn next_to_review(&self) -> Option<&UnitOfWork> {
        self.review_queue.first()
    }

    /// Returns units that are blocked by unmet dependencies.
    pub fn blocked_units(&self) -> Vec<&UnitOfWork> {
        self.review_queue
            .iter()
            .filter(|u| matches!(u.status, ReviewStatus::Blocked))
            .collect()
    }

    /// Auto-mark units as blocked when their dependencies are not in a passing state.
    ///
    /// This implements Phase 4 / Step 4.4: **auto-queue unmet units**. When a
    /// dependency unit (e.g. a shim layer or DLL classification) is in a
    /// failing status (`SendBack`, `PatchRequested`), all units that transitively
    /// depend on it are automatically marked as [`Blocked`].
    ///
    /// # Failing statuses
    ///
    /// A unit is considered to be in a failing status if its status is any of:
    /// - [`ReviewStatus::SendBack`] — sent back for fixes
    /// - [`ReviewStatus::PatchRequested`] — patch requested for a specific issue
    ///
    /// These statuses indicate the unit is *not yet complete* and therefore
    /// cannot serve as a valid dependency for downstream units.
    ///
    /// # Propagation
    ///
    /// Blocking propagates transitively. If A depends on B and B depends on C,
    /// and C fails:
    ///
    /// 1. C is failing → mark B as [`Blocked`]
    /// 2. B is now failing (blocked) → mark A as [`Blocked`]
    ///
    /// Units already in a terminal status (`Accepted`, `Blocked`) are left
    /// unchanged — the method is idempotent. Each status rewrite also moves
    /// the unit's tally in [`StatusCounts`] to `blocked`, so the summary
    /// reflects the cascade.
    ///
    /// # Returns
    ///
    /// The number of units that were changed to [`Blocked`].
    pub fn auto_block_units(&mut self) -> usize {
        // Phase 1: identify all failing units (SendBack, PatchRequested)
        // These are the roots of the blocking cascade.
        let mut failing: HashMap<String, bool> = HashMap::new();
        let unit_ids: Vec<String> = self.review_queue.iter().map(|u| u.id.clone()).collect();

        for id in &unit_ids {
            let unit = self.review_queue.iter().find(|u| &u.id == id).unwrap();
            let is_failing = matches!(
                unit.status,
                ReviewStatus::SendBack | ReviewStatus::PatchRequested
            );
            failing.insert(id.clone(), is_failing);
        }

        // Phase 2: propagate blocking transitively.
        //
        // Build a reverse lookup: for each unit ID, which other units depend on it?
        let mut depended_on_by: HashMap<String, Vec<String>> = HashMap::new();
        for unit in &self.review_queue {
            for dep in &unit.dependencies {
                depended_on_by
                    .entry(dep.clone())
                    .or_default()
                    .push(unit.id.clone());
            }
        }

        // BFS from failing units through the depended-on-by graph.
        // If a dependency fails, all dependents become blocked.
        // A blocked unit then counts as failing for further propagation.
        let mut queue: Vec<String> = failing
            .iter()
            .filter(|&(_, &is_failing)| is_failing)
            .map(|(id, _)| id.clone())
            .collect();

        while let Some(failing_id) = queue.pop() {
            // Find all units that depend on this failing unit
            if let Some(dependents) = depended_on_by.get(&failing_id) {
                for dependent_id in dependents {
                    // Only propagate if this dependent isn't already blocked/failing
                    if let Some(was_failing) = failing.get(dependent_id)
                        && !*was_failing
                    {
                        // Mark as blocked and update state
                        failing.insert(dependent_id.clone(), true);
                        queue.push(dependent_id.clone());
                    }
                }
            }
        }

        // Phase 3: apply the blocking changes to the review queue
        let mut blocked_count = 0usize;
        for unit in &mut self.review_queue {
            // Skip units that are already in a terminal status or already blocked.
            // Also skip units that *are* the failing dependency itself — those
            // should keep their original status (SendBack/PatchRequested) since
            // the whole point of auto-blocking is about *dependents* of failing
            // units, not the failing units themselves.
            if matches!(
                unit.status,
                ReviewStatus::Blocked
                    | ReviewStatus::Accepted
                    | ReviewStatus::SendBack
                    | ReviewStatus::PatchRequested
            ) {
                continue;
            }
            if failing.get(&unit.id) == Some(&true) {
                let old_status = std::mem::replace(&mut unit.status, ReviewStatus::Blocked);
                if old_status != ReviewStatus::Blocked {
                    blocked_count += 1;
                    move_count_to_blocked(&mut self.status_counts, &old_status);
                }
            }
        }

        // Also apply blocking to recent_activity (e.g. units that were just
        // accepted but now have an unmet dependency due to another unit failing)
        for unit in &mut self.recent_activity {
            if matches!(
                unit.status,
                ReviewStatus::Blocked
                    | ReviewStatus::Accepted
                    | ReviewStatus::SendBack
                    | ReviewStatus::PatchRequested
            ) {
                continue;
            }
            if failing.get(&unit.id) == Some(&true) {
                let old_status = std::mem::replace(&mut unit.status, ReviewStatus::Blocked);
                if old_status != ReviewStatus::Blocked {
                    blocked_count += 1;
                    move_count_to_blocked(&mut self.status_counts, &old_status);
                }
            }
        }

        blocked_count
    }

    /// Returns units sorted in dependency order, excluding already-accepted ones.
    ///
    /// Only units with status `Queued` or `PendingReview` are included.
    /// Units with dependencies that are already accepted appear after those
    /// dependencies in the returned order.
    pub fn pending_in_dependency_order(&self) -> Vec<&UnitOfWork> {
        // Build a temporary graph from the review queue
        let mut nodes: Vec<&str> = self
            .review_queue
            .iter()
            .filter(|u| matches!(u.status, ReviewStatus::Queued | ReviewStatus::PendingReview))
            .map(|u| u.id.as_str())
            .collect();
        nodes.sort(); // stable ordering

        let edges: Vec<(&str, &str)> = self
            .review_queue
            .iter()
            .filter(|u| matches!(u.status, ReviewStatus::Queued | ReviewStatus::PendingReview))
            .flat_map(|u| u.dependencies.iter().map(|d| (u.id.as_str(), d.as_str())))
            .collect();

        let graph = DependencyGraph {
            nodes: nodes
                .iter()
                .map(|id| {
                    let name = self
                        .review_queue
                        .iter()
                        .find(|u| u.id == *id)
                        .map(|u| u.name.clone())
                        .unwrap_or_default();
                    let status = self
                        .review_queue
                        .iter()
                        .find(|u| u.id == *id)
                        .map(|u| u.status.clone())
                        .unwrap_or(ReviewStatus::Queued);

                    // Look up the WorkKind to get the correct level
                    let level = self
                        .review_queue
                        .iter()
                        .find(|u| u.id == *id)
                        .map(|u| u.kind.level())
                        .unwrap_or(WorkLevel::FunctionTranslation);

                    super::graph::DependencyNode::with_level(id.to_string(), name, status, level)
                })
                .collect(),
            edges: edges
                .into_iter()
                .map(|(from, to)| super::graph::DependencyEdge {
                    from: from.to_string(),
                    to: to.to_string(),
                })
                .collect(),
        };

        let (ordered_ids, _cycle_nodes) = graph.topological_order();
        let ordered_ids: Vec<&str> = ordered_ids.iter().map(|n| n.unit_id.as_str()).collect();

        // Return units in topological order, preserving original fields
        let id_set: std::collections::HashSet<&str> = ordered_ids.iter().copied().collect();
        self.review_queue
            .iter()
            .filter(|u| {
                matches!(u.status, ReviewStatus::Queued | ReviewStatus::PendingReview)
                    && id_set.contains(u.id.as_str())
            })
            .collect()
    }
}

/// Moves one unit's tally from `old_status` to `blocked` so [`StatusCounts`]
/// stays in sync with the queue after [`ReviewDashboard::auto_block_units`]
/// rewrites a status.
fn move_count_to_blocked(counts: &mut StatusCounts, old_status: &ReviewStatus) {
    match old_status {
        ReviewStatus::Queued => counts.queued = counts.queued.saturating_sub(1),
        ReviewStatus::PendingReview => {
            counts.pending_review = counts.pending_review.saturating_sub(1)
        }
        ReviewStatus::InProgress => counts.in_progress = counts.in_progress.saturating_sub(1),
        ReviewStatus::Accepted => counts.accepted = counts.accepted.saturating_sub(1),
        ReviewStatus::SendBack => counts.send_back = counts.send_back.saturating_sub(1),
        ReviewStatus::PatchRequested => {
            counts.patch_requested = counts.patch_requested.saturating_sub(1)
        }
        ReviewStatus::Blocked => {}
    }
    counts.blocked += 1;
}
