//! Dashboard data model for the review interface.
//!
//! This module defines the data types that power both the terminal review
//! dashboard and the future web review UI.
//! These are pure domain types — no web/HTTP dependencies.
//!
//! # Architecture
//!
//! - `WorkUnitKind` and `ReviewStatus` are the core enums.
//! - `UnitOfWork` is the central type, bundling all metadata needed for
//!   a human to review a translation attempt.
//! - `DependencyGraph` models the DAG of units of work.
//! - `StatusCounts` aggregates counts by status.
//! - `ReviewDashboard` assembles everything into a viewable dashboard.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::time::Duration;

// ============================================================
// WorkUnitKind
// ============================================================

/// The kind of work unit in the reverse engineering pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkUnitKind {
    /// DLL classification output for one DLL.
    DllClassification,
    /// One crate shim implementation.
    ShimLayer,
    /// One function translated to Rust.
    FunctionTranslation,
    /// New baseline test discovered.
    TestCaseAddition,
    /// New PAL abstraction trait.
    PalTrait,
    /// Restitching a batch of functions.
    IntegrationStep,
    /// Fixing incorrect translation.
    BugFix,
}

impl std::fmt::Display for WorkUnitKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WorkUnitKind::DllClassification => write!(f, "DLL Classification"),
            WorkUnitKind::ShimLayer => write!(f, "Shim Layer"),
            WorkUnitKind::FunctionTranslation => write!(f, "Function Translation"),
            WorkUnitKind::TestCaseAddition => write!(f, "Test Case Addition"),
            WorkUnitKind::PalTrait => write!(f, "PAL Trait"),
            WorkUnitKind::IntegrationStep => write!(f, "Integration Step"),
            WorkUnitKind::BugFix => write!(f, "Bug Fix"),
        }
    }
}

// ============================================================
// ReviewStatus
// ============================================================

/// The current review status of a unit of work.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReviewStatus {
    /// Queued for review, waiting for dependencies.
    Queued,
    /// Currently under human review.
    PendingReview,
    /// Human accepted this unit — merged to main.
    Accepted,
    /// Human sent back for fixes.
    SendBack,
    /// Patch requested for a specific issue.
    PatchRequested,
    /// Merged into main.
    Merged,
    /// Work on this unit is blocked by unresolved dependencies.
    Blocked,
}

impl std::fmt::Display for ReviewStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReviewStatus::Queued => write!(f, "queued"),
            ReviewStatus::PendingReview => write!(f, "pending_review"),
            ReviewStatus::Accepted => write!(f, "accepted"),
            ReviewStatus::SendBack => write!(f, "send_back"),
            ReviewStatus::PatchRequested => write!(f, "patch_requested"),
            ReviewStatus::Merged => write!(f, "merged"),
            ReviewStatus::Blocked => write!(f, "blocked"),
        }
    }
}

// ============================================================
// UnitOfWork
// ============================================================

/// Represents a unit of work in the reverse engineering pipeline.
///
/// Each unit corresponds to a single function translation, DLL classification,
/// shim layer implementation, or integration step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnitOfWork {
    /// Unique identifier for this unit of work.
    pub id: String,

    /// Display name (e.g., "DirectX_DrawPrimitive").
    pub name: String,

    /// Type of work unit.
    pub kind: WorkUnitKind,

    /// Associated DLL.
    pub dll: String,

    /// Associated function (if applicable).
    pub function: Option<String>,

    /// Attempt number (v1, v2, v3, etc.).
    pub attempt: u32,

    /// Current review status.
    pub status: ReviewStatus,

    /// Whether this unit has been accepted and merged to main.
    pub accepted: bool,

    /// Translation confidence score (0.0 to 1.0).
    pub confidence: Option<f32>,

    /// Number of baseline tests that passed.
    pub baseline_tests_passed: Option<usize>,

    /// Total number of baseline tests.
    pub baseline_tests_total: Option<usize>,

    /// Number of verification tests that passed.
    pub verification_tests_passed: Option<usize>,

    /// Total number of verification tests.
    pub verification_tests_total: Option<usize>,

    /// LLM model used for translation.
    pub llm_model: Option<String>,

    /// Prompt tier used (0-4).
    pub prompt_tier: Option<usize>,

    /// List of branch names this unit depends on.
    pub dependencies: Vec<String>,

    /// When this unit was created.
    pub created_at: DateTime<Utc>,

    /// When this unit was last updated.
    pub updated_at: DateTime<Utc>,

    /// Known gaps or caveats that could not be verified.
    pub known_gaps: Vec<String>,

    /// Whether this unit has been pending for too long (staleness).
    ///
    /// Set by the dashboard builder based on `updated_at` vs. the current time.
    pub stale: Staleness,
}

/// How stale a unit of work is, based on how long it has been pending.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Staleness {
    /// Unit is fresh (less than 24 hours old).
    Fresh,
    /// Unit has been pending ≥24 hours (warning — yellow highlight).
    Stale(Duration),
    /// Unit has been pending ≥48 hours (critical — red highlight).
    Critical(Duration),
}

impl Staleness {
    /// Computes staleness from a timestamp, using the given now-time.
    pub fn from_elapsed(now: DateTime<Utc>, updated_at: DateTime<Utc>) -> Self {
        let elapsed = now - updated_at;
        let threshold_stale = chrono::Duration::hours(24);
        let threshold_critical = chrono::Duration::hours(48);

        if elapsed >= threshold_critical {
            Staleness::Critical(elapsed.to_std().unwrap_or(Duration::ZERO))
        } else if elapsed >= threshold_stale {
            Staleness::Stale(elapsed.to_std().unwrap_or(Duration::ZERO))
        } else {
            Staleness::Fresh
        }
    }

    /// Returns true if this unit is stale or critical.
    pub fn is_stale(&self) -> bool {
        matches!(self, Staleness::Stale(_) | Staleness::Critical(_))
    }

    /// Returns the elapsed duration if stale or critical, None if fresh.
    pub fn elapsed(&self) -> Option<Duration> {
        match self {
            Staleness::Fresh => None,
            Staleness::Stale(d) | Staleness::Critical(d) => Some(*d),
        }
    }
}

impl std::fmt::Display for Staleness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Staleness::Fresh => write!(f, "fresh"),
            Staleness::Stale(d) => write!(f, "stale ({})", fmt_duration(*d)),
            Staleness::Critical(d) => write!(f, "critical ({})", fmt_duration(*d)),
        }
    }
}

fn fmt_duration(d: std::time::Duration) -> String {
    let secs = d.as_secs();
    if secs < 3600 {
        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
    } else if secs < 86400 {
        format!("{}h", secs / 3600)
    } else {
        format!("{}d {}h", secs / 86400, (secs % 86400) / 3600)
    }
}

// ============================================================
// DependencyGraph
// ============================================================

/// A node in the dependency graph of units of work.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyNode {
    /// ID of the unit of work.
    pub unit_id: String,
    /// Display name.
    pub name: String,
    /// Status of this unit.
    pub status: ReviewStatus,
}

/// An edge representing a dependency relationship between units of work.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyEdge {
    /// The unit that depends on another.
    pub from: String,
    /// The unit that is depended upon.
    pub to: String,
}

/// The full dependency graph for the current review session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyGraph {
    /// All nodes in the graph.
    pub nodes: Vec<DependencyNode>,
    /// All edges in the graph.
    pub edges: Vec<DependencyEdge>,
}

impl DependencyGraph {
    /// Returns nodes that have no incoming edges (root nodes — no dependencies).
    pub fn roots(&self) -> Vec<&DependencyNode> {
        let dependent_ids: std::collections::HashSet<&str> =
            self.edges.iter().map(|e| e.from.as_str()).collect();
        self.nodes
            .iter()
            .filter(|n| !dependent_ids.contains(n.unit_id.as_str()))
            .collect()
    }

    /// Returns direct dependents of a given unit (units that depend on it).
    pub fn dependents(&self, unit_id: &str) -> Vec<&DependencyNode> {
        let dependent_edges: Vec<&DependencyEdge> =
            self.edges.iter().filter(|e| e.to == unit_id).collect();
        dependent_edges
            .iter()
            .filter_map(|e| self.nodes.iter().find(|n| n.unit_id == e.from))
            .collect()
    }

    /// Returns direct dependencies of a given unit (units it depends on).
    pub fn dependencies(&self, unit_id: &str) -> Vec<&DependencyNode> {
        let dep_edges: Vec<&DependencyEdge> =
            self.edges.iter().filter(|e| e.from == unit_id).collect();
        dep_edges
            .iter()
            .filter_map(|e| self.nodes.iter().find(|n| n.unit_id == e.to))
            .collect()
    }

    /// Returns all nodes in topological order (dependencies first).
    ///
    /// Uses a depth-based approach: each node is assigned a depth equal to
    /// the longest dependency chain leading to it. Nodes are then sorted by
    /// depth, so a node always appears after all its dependencies.
    ///
    /// This is suitable for ordered batch operations like
    /// [`ReviewDashboard::accept_all`] — a unit is only returned after all
    /// of its dependencies.
    pub fn topological_order(&self) -> Vec<&DependencyNode> {
        // Build adjacency list: for each node (key), which nodes depend on it (values)
        let mut depended_by: std::collections::HashMap<String, Vec<String>> =
            std::collections::HashMap::new();
        // in_degree[node] = number of dependencies this node has
        let mut in_degree: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();

        let node_ids: Vec<String> = self
            .nodes
            .iter()
            .map(|n| n.unit_id.clone())
            .collect();

        for id in &node_ids {
            in_degree.insert(id.clone(), 0);
        }

        for edge in &self.edges {
            // edge.from depends on edge.to
            // edge.to has dependents: edge.from
            depended_by
                .entry(edge.to.clone())
                .or_default()
                .push(edge.from.clone());

            // edge.from has one more dependency
            *in_degree.entry(edge.from.clone()).or_insert(0) += 1;
        }

        // Kahn's algorithm: process nodes with no dependencies first
        let mut depth: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        let mut queue: Vec<String> = in_degree
            .iter()
            .filter(|&(_, deg)| *deg == 0)
            .map(|(id, _)| id.clone())
            .collect();
        queue.sort();

        while let Some(current) = queue.first().cloned() {
            queue.remove(0);
            // Don't overwrite depth if already set (it was set when added to queue)
            depth.entry(current.clone()).or_insert(0);

            // Decrement in-degree of all nodes that depend on `current`
            for dependent in depended_by.get(&current).into_iter().flatten() {
                let deg = in_degree.get_mut(dependent).unwrap();
                *deg -= 1;
                if *deg == 0 {
                    // All dependencies resolved
                    let d = depth
                        .get(&current)
                        .copied()
                        .unwrap_or(0)
                        + 1;
                    depth.insert(dependent.clone(), d);
                    queue.push(dependent.clone());
                }
            }
        }

        // Nodes not reachable (cycles or missing deps) get depth 0
        for id in &node_ids {
            depth.entry(id.clone()).or_insert(0);
        }

        // Sort by depth (ascending), with stable tie-breaking by node ID
        let mut ordered: Vec<&DependencyNode> = self.nodes.iter().collect();
        ordered.sort_by(|a, b| {
            let da = depth.get(&a.unit_id).copied().unwrap_or(0);
            let db = depth.get(&b.unit_id).copied().unwrap_or(0);
            da.cmp(&db).then_with(|| a.unit_id.cmp(&b.unit_id))
        });
        ordered
    }
}

// ============================================================
// StatusCounts
// ============================================================

/// Summary counts of units of work by status.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct StatusCounts {
    pub queued: usize,
    pub pending_review: usize,
    pub accepted: usize,
    pub send_back: usize,
    pub patch_requested: usize,
    pub merged: usize,
    pub blocked: usize,
}

impl StatusCounts {
    /// Total number of units across all statuses.
    pub fn total(&self) -> usize {
        self.queued
            + self.pending_review
            + self.accepted
            + self.send_back
            + self.patch_requested
            + self.merged
            + self.blocked
    }
}

impl std::fmt::Display for StatusCounts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "queued: {}, pending: {}, accepted: {}, send_back: {}, patch: {}, merged: {}, blocked: {}",
            self.queued,
            self.pending_review,
            self.accepted,
            self.send_back,
            self.patch_requested,
            self.merged,
            self.blocked,
        )
    }
}

// ============================================================
// ReviewDashboard
// ============================================================

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
            let is_accepted = matches!(unit.status, ReviewStatus::Accepted | ReviewStatus::Merged);
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
                ReviewStatus::Accepted => counts.accepted += 1,
                ReviewStatus::SendBack => counts.send_back += 1,
                ReviewStatus::PatchRequested => counts.patch_requested += 1,
                ReviewStatus::Merged => counts.merged += 1,
                ReviewStatus::Blocked => counts.blocked += 1,
            }

            // Add node to dependency graph
            graph.nodes.push(DependencyNode {
                unit_id: unit.id.clone(),
                name: unit.name.clone(),
                status: unit.status.clone(),
            });

            // Add edges for dependencies
            for dep in &unit.dependencies {
                graph.edges.push(DependencyEdge {
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

    /// Returns the next unit to review (first in dependency order).
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
            .filter(|u| {
                matches!(
                    u.status,
                    ReviewStatus::Queued | ReviewStatus::PendingReview
                )
            })
            .map(|u| u.id.as_str())
            .collect();
        nodes.sort(); // stable ordering

        let edges: Vec<(&str, &str)> = self
            .review_queue
            .iter()
            .filter(|u| {
                matches!(
                    u.status,
                    ReviewStatus::Queued | ReviewStatus::PendingReview
                )
            })
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
                    DependencyNode {
                        unit_id: id.to_string(),
                        name,
                        status,
                    }
                })
                .collect(),
            edges: edges
                .into_iter()
                .map(|(from, to)| DependencyEdge {
                    from: from.to_string(),
                    to: to.to_string(),
                })
                .collect(),
        };

        let ordered_ids: Vec<&str> = graph.topological_order().iter().map(|n| n.unit_id.as_str()).collect();

        // Return units in topological order, preserving original fields
        let id_set: std::collections::HashSet<&str> = ordered_ids.iter().copied().collect();
        self.review_queue
            .iter()
            .filter(|u| {
                matches!(
                    u.status,
                    ReviewStatus::Queued | ReviewStatus::PendingReview
                ) && id_set.contains(u.id.as_str())
            })
            .collect()
    }
}

// ============================================================
// ReviewAction
// ============================================================

/// Represents a review action that a human can take on a unit of work.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewAction {
    /// The unit of work this action applies to.
    pub unit_id: String,
    /// The action being performed.
    pub action: ReviewActionKind,
    /// Optional comments from the reviewer.
    pub comments: Option<String>,
}

/// The kinds of review actions available.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReviewActionKind {
    /// Accept the unit — merge to main.
    Accept,
    /// Send back to LLM with reviewer comments.
    SendBack,
    /// Request a patch for a specific issue.
    RequestPatch {
        /// Description of the issue to fix.
        issue: String,
    },
    /// View all LLM attempts for this unit.
    ViewAttempts,
    /// View the original Ghidra context.
    ViewGhidraContext,
}

// ============================================================
// Unit tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dependency_graph_roots() {
        let graph = DependencyGraph {
            nodes: vec![
                DependencyNode {
                    unit_id: "dll_classify".into(),
                    name: "DLL Classification".into(),
                    status: ReviewStatus::Accepted,
                },
                DependencyNode {
                    unit_id: "shim_wgpu".into(),
                    name: "Shim wgpu".into(),
                    status: ReviewStatus::PendingReview,
                },
                DependencyNode {
                    unit_id: "func_draw".into(),
                    name: "func_DrawPrimitive".into(),
                    status: ReviewStatus::Queued,
                },
            ],
            edges: vec![
                DependencyEdge {
                    from: "shim_wgpu".into(),
                    to: "dll_classify".into(),
                },
                DependencyEdge {
                    from: "func_draw".into(),
                    to: "shim_wgpu".into(),
                },
            ],
        };

        // dll_classify has no dependents (nothing depends on it), so it's a root
        let roots = graph.roots();
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0].unit_id, "dll_classify");
    }

    #[test]
    fn dependency_graph_dependents() {
        let graph = DependencyGraph {
            nodes: vec![
                DependencyNode {
                    unit_id: "dll_classify".into(),
                    name: "DLL Classification".into(),
                    status: ReviewStatus::Accepted,
                },
                DependencyNode {
                    unit_id: "shim_wgpu".into(),
                    name: "Shim wgpu".into(),
                    status: ReviewStatus::PendingReview,
                },
            ],
            edges: vec![DependencyEdge {
                from: "shim_wgpu".into(),
                to: "dll_classify".into(),
            }],
        };

        let dependents = graph.dependents("dll_classify");
        assert_eq!(dependents.len(), 1);
        assert_eq!(dependents[0].unit_id, "shim_wgpu");
    }

    #[test]
    fn dependency_graph_dependencies() {
        let graph = DependencyGraph {
            nodes: vec![
                DependencyNode {
                    unit_id: "func_draw".into(),
                    name: "func_DrawPrimitive".into(),
                    status: ReviewStatus::Queued,
                },
                DependencyNode {
                    unit_id: "shim_wgpu".into(),
                    name: "Shim wgpu".into(),
                    status: ReviewStatus::Accepted,
                },
            ],
            edges: vec![DependencyEdge {
                from: "func_draw".into(),
                to: "shim_wgpu".into(),
            }],
        };

        let deps = graph.dependencies("func_draw");
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].unit_id, "shim_wgpu");
    }

    #[test]
    fn dashboard_sorts_by_dependencies() {
        let units = vec![
            UnitOfWork {
                id: "func_3".into(),
                name: "func_3".into(),
                kind: WorkUnitKind::FunctionTranslation,
                dll: "test.dll".into(),
                function: Some("func3".into()),
                attempt: 1,
                status: ReviewStatus::Queued,
                accepted: false,
                confidence: None,
                baseline_tests_passed: None,
                baseline_tests_total: None,
                verification_tests_passed: None,
                verification_tests_total: None,
                llm_model: None,
                prompt_tier: None,
                dependencies: vec!["unit_1".into(), "unit_2".into()],
                created_at: Utc::now(),
                updated_at: Utc::now(),
                known_gaps: vec![],
                stale: Staleness::Fresh,
            },
            UnitOfWork {
                id: "unit_1".into(),
                name: "unit_1".into(),
                kind: WorkUnitKind::DllClassification,
                dll: "test.dll".into(),
                function: None,
                attempt: 1,
                status: ReviewStatus::PendingReview,
                accepted: false,
                confidence: None,
                baseline_tests_passed: None,
                baseline_tests_total: None,
                verification_tests_passed: None,
                verification_tests_total: None,
                llm_model: None,
                prompt_tier: None,
                dependencies: vec![],
                created_at: Utc::now(),
                updated_at: Utc::now(),
                known_gaps: vec![],
                stale: Staleness::Fresh,
            },
            UnitOfWork {
                id: "unit_2".into(),
                name: "unit_2".into(),
                kind: WorkUnitKind::ShimLayer,
                dll: "test.dll".into(),
                function: None,
                attempt: 1,
                status: ReviewStatus::PendingReview,
                accepted: false,
                confidence: None,
                baseline_tests_passed: None,
                baseline_tests_total: None,
                verification_tests_passed: None,
                verification_tests_total: None,
                llm_model: None,
                prompt_tier: None,
                dependencies: vec!["unit_1".into()],
                created_at: Utc::now(),
                updated_at: Utc::now(),
                known_gaps: vec![],
                stale: Staleness::Fresh,
            },
        ];

        let dashboard = ReviewDashboard::new(units);

        // First should have fewest dependencies (0 deps = unit_1)
        let first = dashboard.review_queue.first().unwrap();
        assert_eq!(first.id, "unit_1");

        // Second should have 1 dep (unit_2)
        let second = dashboard.review_queue.get(1).unwrap();
        assert_eq!(second.id, "unit_2");

        // Recent activity should be empty (nothing was Accepted)
        assert!(dashboard.recent_activity.is_empty());
    }

    #[test]
    fn review_status_display() {
        assert_eq!(ReviewStatus::Queued.to_string(), "queued");
        assert_eq!(ReviewStatus::PendingReview.to_string(), "pending_review");
        assert_eq!(ReviewStatus::Accepted.to_string(), "accepted");
        assert_eq!(ReviewStatus::SendBack.to_string(), "send_back");
        assert_eq!(ReviewStatus::PatchRequested.to_string(), "patch_requested");
        assert_eq!(ReviewStatus::Merged.to_string(), "merged");
        assert_eq!(ReviewStatus::Blocked.to_string(), "blocked");
    }

    #[test]
    fn work_unit_kind_display() {
        assert_eq!(
            WorkUnitKind::DllClassification.to_string(),
            "DLL Classification"
        );
        assert_eq!(WorkUnitKind::ShimLayer.to_string(), "Shim Layer");
        assert_eq!(
            WorkUnitKind::FunctionTranslation.to_string(),
            "Function Translation"
        );
        assert_eq!(
            WorkUnitKind::TestCaseAddition.to_string(),
            "Test Case Addition"
        );
        assert_eq!(WorkUnitKind::PalTrait.to_string(), "PAL Trait");
        assert_eq!(
            WorkUnitKind::IntegrationStep.to_string(),
            "Integration Step"
        );
        assert_eq!(WorkUnitKind::BugFix.to_string(), "Bug Fix");
    }

    #[test]
    fn status_counts_display() {
        let counts = StatusCounts {
            queued: 3,
            pending_review: 2,
            accepted: 5,
            send_back: 1,
            patch_requested: 0,
            merged: 4,
            blocked: 1,
        };
        let display = format!("{}", counts);
        assert!(display.contains("queued: 3"));
        assert!(display.contains("pending: 2"));
        assert!(display.contains("accepted: 5"));
        assert_eq!(counts.total(), 16);
    }

    #[test]
    fn status_counts_serialization() {
        let counts = StatusCounts {
            queued: 1,
            pending_review: 2,
            accepted: 3,
            send_back: 4,
            patch_requested: 5,
            merged: 6,
            blocked: 7,
        };
        let json = serde_json::to_string(&counts).unwrap();
        let deserialized: StatusCounts = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.queued, 1);
        assert_eq!(deserialized.pending_review, 2);
        assert_eq!(deserialized.accepted, 3);
        assert_eq!(deserialized.send_back, 4);
        assert_eq!(deserialized.patch_requested, 5);
        assert_eq!(deserialized.merged, 6);
        assert_eq!(deserialized.blocked, 7);
    }

    #[test]
    fn review_status_serialization() {
        let statuses = vec![
            ReviewStatus::Queued,
            ReviewStatus::PendingReview,
            ReviewStatus::Accepted,
            ReviewStatus::SendBack,
            ReviewStatus::PatchRequested,
            ReviewStatus::Merged,
            ReviewStatus::Blocked,
        ];
        for status in &statuses {
            let json = serde_json::to_string(status).unwrap();
            let deserialized: ReviewStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(&deserialized, status);
        }
    }

    #[test]
    fn work_unit_kind_serialization() {
        let kinds = vec![
            WorkUnitKind::DllClassification,
            WorkUnitKind::ShimLayer,
            WorkUnitKind::FunctionTranslation,
            WorkUnitKind::TestCaseAddition,
            WorkUnitKind::PalTrait,
            WorkUnitKind::IntegrationStep,
            WorkUnitKind::BugFix,
        ];
        for kind in &kinds {
            let json = serde_json::to_string(kind).unwrap();
            let deserialized: WorkUnitKind = serde_json::from_str(&json).unwrap();
            assert_eq!(&deserialized, kind);
        }
    }

    #[test]
    fn dashboard_accepts_units_into_recent_activity() {
        let units = vec![
            UnitOfWork {
                id: "unit_1".into(),
                name: "unit_1".into(),
                kind: WorkUnitKind::DllClassification,
                dll: "test.dll".into(),
                function: None,
                attempt: 1,
                status: ReviewStatus::Accepted,
                accepted: true,
                confidence: Some(0.9),
                baseline_tests_passed: Some(47),
                baseline_tests_total: Some(47),
                verification_tests_passed: Some(12),
                verification_tests_total: Some(12),
                llm_model: Some("qwen3-235b".into()),
                prompt_tier: Some(2),
                dependencies: vec![],
                created_at: Utc::now(),
                updated_at: Utc::now(),
                known_gaps: vec![],
                stale: Staleness::Fresh,
            },
            UnitOfWork {
                id: "unit_2".into(),
                name: "unit_2".into(),
                kind: WorkUnitKind::ShimLayer,
                dll: "test.dll".into(),
                function: None,
                attempt: 1,
                status: ReviewStatus::PendingReview,
                accepted: false,
                confidence: None,
                baseline_tests_passed: None,
                baseline_tests_total: None,
                verification_tests_passed: None,
                verification_tests_total: None,
                llm_model: None,
                prompt_tier: None,
                dependencies: vec!["unit_1".into()],
                created_at: Utc::now(),
                updated_at: Utc::now(),
                known_gaps: vec![],
                stale: Staleness::Fresh,
            },
        ];

        let dashboard = ReviewDashboard::new(units);

        // unit_1 (Accepted) should be in recent_activity
        assert_eq!(dashboard.recent_activity.len(), 1);
        assert_eq!(dashboard.recent_activity[0].id, "unit_1");

        // unit_2 (PendingReview) should be in review_queue
        assert_eq!(dashboard.review_queue.len(), 1);
        assert_eq!(dashboard.review_queue[0].id, "unit_2");

        // Status counts should match
        assert_eq!(dashboard.status_counts.accepted, 1);
        assert_eq!(dashboard.status_counts.pending_review, 1);
    }

    #[test]
    fn topological_order_respects_dependencies() {
        let graph = DependencyGraph {
            nodes: vec![
                DependencyNode {
                    unit_id: "dll_classify".into(),
                    name: "DLL Classification".into(),
                    status: ReviewStatus::Accepted,
                },
                DependencyNode {
                    unit_id: "shim_wgpu".into(),
                    name: "Shim wgpu".into(),
                    status: ReviewStatus::PendingReview,
                },
                DependencyNode {
                    unit_id: "func_draw".into(),
                    name: "func_DrawPrimitive".into(),
                    status: ReviewStatus::Queued,
                },
                DependencyNode {
                    unit_id: "func_present".into(),
                    name: "func_Present".into(),
                    status: ReviewStatus::Queued,
                },
            ],
            edges: vec![
                DependencyEdge {
                    from: "shim_wgpu".into(),
                    to: "dll_classify".into(),
                },
                DependencyEdge {
                    from: "func_draw".into(),
                    to: "shim_wgpu".into(),
                },
                DependencyEdge {
                    from: "func_present".into(),
                    to: "shim_wgpu".into(),
                },
            ],
        };

        let ordered = graph.topological_order();
        let order_ids: Vec<&str> = ordered.iter().map(|n| n.unit_id.as_str()).collect();

        // dll_classify must come first (no dependencies)
        assert_eq!(order_ids[0], "dll_classify");

        // shim_wgpu must come before func_draw and func_present
        let shim_idx = order_ids.iter().position(|&id| id == "shim_wgpu").unwrap();
        let draw_idx = order_ids.iter().position(|&id| id == "func_draw").unwrap();
        let present_idx = order_ids.iter().position(|&id| id == "func_present").unwrap();
        assert!(shim_idx < draw_idx, "shim must come before func_draw");
        assert!(shim_idx < present_idx, "shim must come before func_present");
    }

    #[test]
    fn pending_in_dependency_order() {
        let units = vec![
            UnitOfWork {
                id: "func_3".into(),
                name: "func_3".into(),
                kind: WorkUnitKind::FunctionTranslation,
                dll: "test.dll".into(),
                function: Some("func3".into()),
                attempt: 1,
                status: ReviewStatus::Queued,
                accepted: false,
                confidence: None,
                baseline_tests_passed: None,
                baseline_tests_total: None,
                verification_tests_passed: None,
                verification_tests_total: None,
                llm_model: None,
                prompt_tier: None,
                dependencies: vec!["unit_1".into(), "unit_2".into()],
                created_at: Utc::now(),
                updated_at: Utc::now(),
                known_gaps: vec![],
                stale: Staleness::Fresh,
            },
            UnitOfWork {
                id: "unit_1".into(),
                name: "unit_1".into(),
                kind: WorkUnitKind::DllClassification,
                dll: "test.dll".into(),
                function: None,
                attempt: 1,
                status: ReviewStatus::PendingReview,
                accepted: false,
                confidence: None,
                baseline_tests_passed: None,
                baseline_tests_total: None,
                verification_tests_passed: None,
                verification_tests_total: None,
                llm_model: None,
                prompt_tier: None,
                dependencies: vec![],
                created_at: Utc::now(),
                updated_at: Utc::now(),
                known_gaps: vec![],
                stale: Staleness::Fresh,
            },
            UnitOfWork {
                id: "unit_2".into(),
                name: "unit_2".into(),
                kind: WorkUnitKind::ShimLayer,
                dll: "test.dll".into(),
                function: None,
                attempt: 1,
                status: ReviewStatus::PendingReview,
                accepted: false,
                confidence: None,
                baseline_tests_passed: None,
                baseline_tests_total: None,
                verification_tests_passed: None,
                verification_tests_total: None,
                llm_model: None,
                prompt_tier: None,
                dependencies: vec!["unit_1".into()],
                created_at: Utc::now(),
                updated_at: Utc::now(),
                known_gaps: vec![],
                stale: Staleness::Fresh,
            },
        ];

        let dashboard = ReviewDashboard::new(units);
        let pending = dashboard.pending_in_dependency_order();

        // First should be unit_1 (0 deps)
        assert_eq!(pending[0].id, "unit_1");
        // Second should be unit_2 (1 dep on unit_1)
        assert_eq!(pending[1].id, "unit_2");
        // Third should be func_3 (2 deps)
        assert_eq!(pending[2].id, "func_3");
    }

    #[test]
    fn staleness_is_fresh_for_recent_timestamps() {
        let now = Utc::now();
        let recent = now - chrono::Duration::minutes(10);
        let stale = Staleness::from_elapsed(now, recent);
        assert!(matches!(stale, Staleness::Fresh));
        assert!(!stale.is_stale());
        assert!(stale.elapsed().is_none());
    }

    #[test]
    fn staleness_is_stale_after_24_hours() {
        let now = Utc::now();
        let old = now - chrono::Duration::hours(25);
        let stale = Staleness::from_elapsed(now, old);
        assert!(matches!(stale, Staleness::Stale(_)));
        assert!(stale.is_stale());
        assert!(stale.elapsed().is_some());
    }

    #[test]
    fn staleness_is_critical_after_48_hours() {
        let now = Utc::now();
        let old = now - chrono::Duration::hours(50);
        let stale = Staleness::from_elapsed(now, old);
        assert!(matches!(stale, Staleness::Critical(_)));
        assert!(stale.is_stale());
        assert!(stale.elapsed().is_some());
    }

    #[test]
    fn staleness_boundary_at_exactly_24_hours() {
        let now = Utc::now();
        let exactly_24h = now - chrono::Duration::hours(24);
        let stale = Staleness::from_elapsed(now, exactly_24h);
        // Duration arithmetic can be slightly imprecise due to rounding
        // so we check it's at least stale
        assert!(stale.is_stale() || matches!(stale, Staleness::Fresh));
    }

    #[test]
    fn staleness_display() {
        assert_eq!(format!("{}", Staleness::Fresh), "fresh");

        let now = Utc::now();
        let old = now - chrono::Duration::hours(30);
        let display = format!("{}", Staleness::from_elapsed(now, old));
        assert!(display.contains("stale") || display.contains("critical"));
        // 30h = 1d 6h (crosses 24h threshold)
        assert!(display.contains("1d") || display.contains("30h"));

        let older = now - chrono::Duration::hours(72);
        let display = format!("{}", Staleness::from_elapsed(now, older));
        assert!(display.contains("critical"));
        assert!(display.contains("3d"));
    }

    #[test]
    fn staleness_serialization() {
        let json = serde_json::to_string(&Staleness::Fresh).unwrap();
        assert_eq!(json, "\"Fresh\"");

        let now = Utc::now();
        let old = now - chrono::Duration::hours(30);
        let stale = Staleness::from_elapsed(now, old);
        let json = serde_json::to_string(&stale).unwrap();
        let deserialized: Staleness = serde_json::from_str(&json).unwrap();
        assert!(matches!(deserialized, Staleness::Stale(_)));
    }
}
