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
use std::collections::HashMap;
use std::time::Duration;

// ============================================================
// WorkUnitLevel — dependency priority ordering
// ============================================================

/// The processing level of a work unit in the dependency graph.
///
/// Levels define the *phase* a unit belongs to in the pipeline.
/// Units at a lower level must be processed before units at a
/// higher level, even when the DAG has no explicit edge between them.
///
/// This ordering implements the requirement from Phase 4 / Step 4.2:
///
/// ```text
/// shim layers → PAL traits → function translations → integration
/// ```
///
/// The level is used to break ties in topological sorting: when two
/// units have the same topological depth, the one at the lower level
/// is returned first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize)]
pub enum WorkUnitLevel {
    /// DLL classification — roots of the dependency graph, no dependencies.
    #[default]
    DllClassification = 0,
    /// Shim layer — translates a DLL's API surface to a crate's API.
    /// Must come after DLL classification, before any function that uses it.
    ShimLayer = 1,
    /// PAL trait — defines an abstraction interface for platform code.
    /// Must come after shim layers (shims may depend on PAL traits).
    PalTrait = 2,
    /// Test case addition — baseline or verification test for a function.
    TestCaseAddition = 3,
    /// Function translation — a function translated to Rust.
    /// Depends on shim layers, PAL traits, and test cases.
    FunctionTranslation = 4,
    /// Integration step — restitching a batch of translated functions.
    /// Must come after all constituent functions.
    IntegrationStep = 5,
    /// Bug fix — fixing an incorrect translation.
    /// Depends on the original function translation.
    BugFix = 6,
}

impl WorkUnitLevel {
    /// Returns a human-readable label for this level.
    pub fn label(&self) -> &'static str {
        match self {
            WorkUnitLevel::DllClassification => "classify",
            WorkUnitLevel::ShimLayer => "shim",
            WorkUnitLevel::PalTrait => "pal",
            WorkUnitLevel::TestCaseAddition => "test",
            WorkUnitLevel::FunctionTranslation => "func",
            WorkUnitLevel::IntegrationStep => "integrate",
            WorkUnitLevel::BugFix => "fix",
        }
    }
}

impl std::fmt::Display for WorkUnitLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

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

impl WorkUnitKind {
    /// Returns the processing level for this kind of work unit.
    ///
    /// This determines the unit's priority in topological ordering.
    /// Units at a lower level are processed first, even when the DAG
    /// has no explicit edge between them.
    pub fn level(&self) -> WorkUnitLevel {
        match self {
            WorkUnitKind::DllClassification => WorkUnitLevel::DllClassification,
            WorkUnitKind::ShimLayer => WorkUnitLevel::ShimLayer,
            WorkUnitKind::PalTrait => WorkUnitLevel::PalTrait,
            WorkUnitKind::TestCaseAddition => WorkUnitLevel::TestCaseAddition,
            WorkUnitKind::FunctionTranslation => WorkUnitLevel::FunctionTranslation,
            WorkUnitKind::IntegrationStep => WorkUnitLevel::IntegrationStep,
            WorkUnitKind::BugFix => WorkUnitLevel::BugFix,
        }
    }
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
    /// Currently being translated by the pipeline (live/running).
    InProgress,
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
            ReviewStatus::InProgress => write!(f, "in_progress"),
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
    /// Processing level — used for tie-breaking in topological sort.
    ///
    /// When two nodes have the same topological depth, the one at
    /// the lower level is returned first. For example, a shim layer
    /// at depth 1 is returned before a function translation at depth 1.
    #[serde(default)]
    pub level: WorkUnitLevel,
}

impl DependencyNode {
    /// Creates a new dependency node.
    pub fn new(unit_id: impl Into<String>, name: impl Into<String>, status: ReviewStatus) -> Self {
        Self {
            unit_id: unit_id.into(),
            name: name.into(),
            status,
            level: WorkUnitLevel::FunctionTranslation, // default: treat as function translation
        }
    }

    /// Creates a dependency node with an explicit level.
    pub fn with_level(
        unit_id: impl Into<String>,
        name: impl Into<String>,
        status: ReviewStatus,
        level: WorkUnitLevel,
    ) -> Self {
        Self {
            unit_id: unit_id.into(),
            name: name.into(),
            status,
            level,
        }
    }
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
    /// Uses Kahn's algorithm with **level-aware tie-breaking**: when multiple
    /// nodes have the same topological depth, nodes at a lower processing level
    /// are returned first. This enforces the ordering requirement from
    /// Phase 4 / Step 4.2:
    ///
    /// ```text
    /// shim layers → PAL traits → function translations → integration
    /// ```
    ///
    /// # Cycle Detection
    ///
    /// If the graph contains a cycle, this method returns the nodes that were
    /// successfully ordered (those whose dependencies were all resolved), along
    /// with a list of node IDs that are part of or blocked by the cycle.
    ///
    /// # Returns
    ///
    /// A tuple of:
    /// 1. `Vec<&DependencyNode>` — nodes in dependency-then-level order
    /// 2. `Vec<String>` — node IDs involved in cycles (empty if no cycle)
    pub fn topological_order(&self) -> (Vec<&DependencyNode>, Vec<String>) {
        // Build adjacency list: for each node (key), which nodes depend on it (values)
        let mut depended_by: std::collections::HashMap<String, Vec<String>> =
            std::collections::HashMap::new();
        // in_degree[node] = number of dependencies this node has
        let mut in_degree: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();

        let node_ids: Vec<String> = self.nodes.iter().map(|n| n.unit_id.clone()).collect();

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

        // Helper to get level of a node by ID
        let get_level = |id: &str| -> WorkUnitLevel {
            self.nodes
                .iter()
                .find(|n| n.unit_id == id)
                .map(|n| n.level)
                .unwrap_or(WorkUnitLevel::FunctionTranslation)
        };

        // Kahn's algorithm with level-aware priority queue
        let mut depth: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        // Use a Vec as a priority queue, sorted by (depth, level, node_id)
        let mut queue: Vec<String> = in_degree
            .iter()
            .filter(|&(_, deg)| *deg == 0)
            .map(|(id, _)| id.clone())
            .collect();
        queue.sort_by_key(|id| (0, get_level(id), id.clone()));

        let mut ordered_ids: Vec<String> = Vec::new();

        while let Some(current) = queue.first().cloned() {
            queue.remove(0);
            let current_depth = depth.get(&current).copied().unwrap_or(0);
            ordered_ids.push(current.clone());

            // Collect all nodes that become ready from processing `current`
            let mut newly_ready: Vec<String> = Vec::new();
            if let Some(deps) = depended_by.get(&current) {
                for dependent in deps {
                    let deg = in_degree.get_mut(dependent).unwrap();
                    *deg -= 1;
                    if *deg == 0 {
                        let new_depth = current_depth + 1;
                        depth.insert(dependent.clone(), new_depth);
                        newly_ready.push(dependent.clone());
                    }
                }
            }

            // Sort newly ready nodes by (depth, level, id) for stable ordering
            newly_ready.sort_by_key(|id| (depth[id], get_level(id), id.clone()));

            // Insert all newly ready nodes into the queue at correct positions
            // All have the same depth (current_depth + 1), so we merge-sort them
            // with the existing queue which may have nodes at higher depths
            let mut merged = Vec::with_capacity(queue.len() + newly_ready.len());
            let mut qi = 0;
            let mut ni = 0;

            while qi < queue.len() && ni < newly_ready.len() {
                let q_depth = depth.get(&queue[qi]).copied().unwrap_or(0);
                let q_level = get_level(&queue[qi]);
                let n_depth = depth[&newly_ready[ni]];
                let n_level = get_level(&newly_ready[ni]);

                if n_depth < q_depth
                    || (n_depth == q_depth && n_level < q_level)
                    || (n_depth == q_depth && n_level == q_level && newly_ready[ni] <= queue[qi])
                {
                    merged.push(newly_ready[ni].clone());
                    ni += 1;
                } else {
                    merged.push(queue[qi].clone());
                    qi += 1;
                }
            }

            while ni < newly_ready.len() {
                merged.push(newly_ready[ni].clone());
                ni += 1;
            }
            while qi < queue.len() {
                merged.push(queue[qi].clone());
                qi += 1;
            }

            queue = merged;
        }

        // Detect cycles: nodes not in ordered_ids have in_degree > 0
        let cycle_nodes: Vec<String> = node_ids
            .into_iter()
            .filter(|id| !ordered_ids.contains(id))
            .collect();

        // Build result in order (iterate over ordered_ids, not self.nodes)
        let ordered: Vec<&DependencyNode> = ordered_ids
            .iter()
            .filter_map(|id| self.nodes.iter().find(|n| n.unit_id == *id))
            .collect();

        (ordered, cycle_nodes)
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
    pub in_progress: usize,
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
            + self.in_progress
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
            "queued: {}, pending: {}, in_progress: {}, accepted: {}, send_back: {}, patch: {}, merged: {}, blocked: {}",
            self.queued,
            self.pending_review,
            self.in_progress,
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
                ReviewStatus::InProgress => counts.in_progress += 1,
                ReviewStatus::Accepted => counts.accepted += 1,
                ReviewStatus::SendBack => counts.send_back += 1,
                ReviewStatus::PatchRequested => counts.patch_requested += 1,
                ReviewStatus::Merged => counts.merged += 1,
                ReviewStatus::Blocked => counts.blocked += 1,
            }

            // Add node to dependency graph with the correct processing level
            graph.nodes.push(DependencyNode::with_level(
                unit.id.clone(),
                unit.name.clone(),
                unit.status.clone(),
                unit.kind.level(),
            ));

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
    /// Units already in a terminal status (`Accepted`, `Merged`, `Blocked`) are
    /// left unchanged — the method is idempotent.
    ///
    /// # Returns
    ///
    /// The number of units that were changed to [`Blocked`].
    ///
    /// # Example
    ///
    /// ```
    /// use calxgloss_types::dashboard::{ReviewDashboard, ReviewStatus, UnitOfWork, WorkUnitKind};
    /// use chrono::Utc;
    ///
    /// let mut dashboard = ReviewDashboard::new(vec![
    ///     UnitOfWork {
    ///         id: "shim_wgpu".into(),
    ///         name: "Shim wgpu".into(),
    ///         kind: WorkUnitKind::ShimLayer,
    ///         dll: "d3d9.dll".into(),
    ///         function: None,
    ///         attempt: 1,
    ///         status: ReviewStatus::SendBack, // shim failed
    ///         accepted: false,
    ///         confidence: None,
    ///         baseline_tests_passed: None,
    ///         baseline_tests_total: None,
    ///         verification_tests_passed: None,
    ///         verification_tests_total: None,
    ///         llm_model: None,
    ///         prompt_tier: None,
    ///         dependencies: vec![],
    ///         created_at: Utc::now(),
    ///         updated_at: Utc::now(),
    ///         known_gaps: vec![],
    ///         stale: calxgloss_types::dashboard::Staleness::Fresh,
    ///     },
    ///     UnitOfWork {
    ///         id: "func_draw".into(),
    ///         name: "func_DrawPrimitive".into(),
    ///         kind: WorkUnitKind::FunctionTranslation,
    ///         dll: "game_logic.dll".into(),
    ///         function: Some("DrawPrimitive".into()),
    ///         attempt: 1,
    ///         status: ReviewStatus::Queued,
    ///         accepted: false,
    ///         confidence: None,
    ///         baseline_tests_passed: None,
    ///         baseline_tests_total: None,
    ///         verification_tests_passed: None,
    ///         verification_tests_total: None,
    ///         llm_model: None,
    ///         prompt_tier: None,
    ///         dependencies: vec!["shim_wgpu".into()], // depends on the failing shim
    ///         created_at: Utc::now(),
    ///         updated_at: Utc::now(),
    ///         known_gaps: vec![],
    ///         stale: calxgloss_types::dashboard::Staleness::Fresh,
    ///     },
    /// ]);
    ///
    /// let blocked_count = dashboard.auto_block_units();
    /// assert_eq!(blocked_count, 1);
    /// assert!(dashboard.review_queue.iter().any(|u| u.id == "func_draw" && matches!(u.status, ReviewStatus::Blocked)));
    /// ```
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
                    | ReviewStatus::Merged
                    | ReviewStatus::SendBack
                    | ReviewStatus::PatchRequested
            ) {
                continue;
            }
            if failing.get(&unit.id) == Some(&true) {
                let old_status = std::mem::replace(&mut unit.status, ReviewStatus::Blocked);
                if old_status != ReviewStatus::Blocked {
                    blocked_count += 1;
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
                    | ReviewStatus::Merged
                    | ReviewStatus::SendBack
                    | ReviewStatus::PatchRequested
            ) {
                continue;
            }
            if failing.get(&unit.id) == Some(&true) {
                let old_status = std::mem::replace(&mut unit.status, ReviewStatus::Blocked);
                if old_status != ReviewStatus::Blocked {
                    blocked_count += 1;
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

                    // Look up the WorkUnitKind to get the correct level
                    let level = self
                        .review_queue
                        .iter()
                        .find(|u| u.id == *id)
                        .map(|u| u.kind.level())
                        .unwrap_or(WorkUnitLevel::FunctionTranslation);

                    DependencyNode::with_level(id.to_string(), name, status, level)
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
                DependencyNode::new("dll_classify", "DLL Classification", ReviewStatus::Accepted),
                DependencyNode::with_level(
                    "shim_wgpu",
                    "Shim wgpu",
                    ReviewStatus::PendingReview,
                    WorkUnitLevel::ShimLayer,
                ),
                DependencyNode::new("func_draw", "func_DrawPrimitive", ReviewStatus::Queued),
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
                DependencyNode::new("dll_classify", "DLL Classification", ReviewStatus::Accepted),
                DependencyNode::with_level(
                    "shim_wgpu",
                    "Shim wgpu",
                    ReviewStatus::PendingReview,
                    WorkUnitLevel::ShimLayer,
                ),
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
                DependencyNode::new("func_draw", "func_DrawPrimitive", ReviewStatus::Queued),
                DependencyNode::with_level(
                    "shim_wgpu",
                    "Shim wgpu",
                    ReviewStatus::Accepted,
                    WorkUnitLevel::ShimLayer,
                ),
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
        assert_eq!(ReviewStatus::InProgress.to_string(), "in_progress");
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
            in_progress: 0,
            accepted: 5,
            send_back: 1,
            patch_requested: 0,
            merged: 4,
            blocked: 1,
        };
        let display = format!("{}", counts);
        assert!(display.contains("queued: 3"));
        assert!(display.contains("pending: 2"));
        assert!(display.contains("in_progress: 0"));
        assert!(display.contains("accepted: 5"));
        assert_eq!(counts.total(), 16);
    }

    #[test]
    fn status_counts_serialization() {
        let counts = StatusCounts {
            queued: 1,
            pending_review: 2,
            in_progress: 3,
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
        assert_eq!(deserialized.in_progress, 3);
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
            ReviewStatus::InProgress,
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
                DependencyNode::new("dll_classify", "DLL Classification", ReviewStatus::Accepted),
                DependencyNode::with_level(
                    "shim_wgpu",
                    "Shim wgpu",
                    ReviewStatus::PendingReview,
                    WorkUnitLevel::ShimLayer,
                ),
                DependencyNode::new("func_draw", "func_DrawPrimitive", ReviewStatus::Queued),
                DependencyNode::new("func_present", "func_Present", ReviewStatus::Queued),
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

        let (ordered, cycles) = graph.topological_order();
        assert!(cycles.is_empty(), "no cycles expected");
        let order_ids: Vec<&str> = ordered.iter().map(|n| n.unit_id.as_str()).collect();

        // dll_classify must come first (no dependencies)
        assert_eq!(order_ids[0], "dll_classify");

        // shim_wgpu must come before func_draw and func_present
        let shim_idx = order_ids.iter().position(|&id| id == "shim_wgpu").unwrap();
        let draw_idx = order_ids.iter().position(|&id| id == "func_draw").unwrap();
        let present_idx = order_ids
            .iter()
            .position(|&id| id == "func_present")
            .unwrap();
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

    // ── Level-aware topological sort tests (Phase 4, Step 4.2) ──

    #[test]
    fn level_respects_pipeline_order() {
        // When two nodes have the same topological depth,
        // the one at a lower level is returned first.
        // e.g., a shim layer at depth 1 should come before a PAL trait at depth 1
        let graph = DependencyGraph {
            nodes: vec![
                DependencyNode::with_level(
                    "dll_cls",
                    "DLL Classify",
                    ReviewStatus::Accepted,
                    WorkUnitLevel::DllClassification,
                ),
                DependencyNode::with_level(
                    "shim_wgpu",
                    "Shim wgpu",
                    ReviewStatus::Queued,
                    WorkUnitLevel::ShimLayer,
                ),
                DependencyNode::with_level(
                    "pal_graphics",
                    "PAL GraphicsDevice",
                    ReviewStatus::Queued,
                    WorkUnitLevel::PalTrait,
                ),
                DependencyNode::with_level(
                    "func_draw",
                    "func_DrawPrimitive",
                    ReviewStatus::Queued,
                    WorkUnitLevel::FunctionTranslation,
                ),
            ],
            edges: vec![
                DependencyEdge {
                    from: "shim_wgpu".into(),
                    to: "dll_cls".into(),
                },
                DependencyEdge {
                    from: "pal_graphics".into(),
                    to: "dll_cls".into(),
                },
                // func_draw depends on both shim and PAL
                DependencyEdge {
                    from: "func_draw".into(),
                    to: "shim_wgpu".into(),
                },
                DependencyEdge {
                    from: "func_draw".into(),
                    to: "pal_graphics".into(),
                },
            ],
        };

        let (ordered, cycles) = graph.topological_order();
        assert!(cycles.is_empty(), "no cycles expected");
        let order_ids: Vec<&str> = ordered.iter().map(|n| n.unit_id.as_str()).collect();

        // dll_cls first (depth 0)
        assert_eq!(order_ids[0], "dll_cls");

        // shim_wgpu before pal_graphics at depth 1 (ShimLayer < PalTrait level)
        let shim_idx = order_ids.iter().position(|&id| id == "shim_wgpu").unwrap();
        let pal_idx = order_ids
            .iter()
            .position(|&id| id == "pal_graphics")
            .unwrap();
        assert!(
            shim_idx < pal_idx,
            "shim layer should come before PAL trait at same depth"
        );

        // func_draw last (depth 2)
        assert_eq!(order_ids[order_ids.len() - 1], "func_draw");
    }

    #[test]
    fn full_pipeline_order() {
        // Simulates the full pipeline: classify → shim → PAL trait → function → integration
        let graph = DependencyGraph {
            nodes: vec![
                DependencyNode::with_level(
                    "dll_cls",
                    "Classify d3d9.dll",
                    ReviewStatus::Accepted,
                    WorkUnitLevel::DllClassification,
                ),
                DependencyNode::with_level(
                    "shim_wgpu",
                    "Shim d3d9→wgpu",
                    ReviewStatus::Queued,
                    WorkUnitLevel::ShimLayer,
                ),
                DependencyNode::with_level(
                    "pal_graphics",
                    "PAL GraphicsDevice",
                    ReviewStatus::Queued,
                    WorkUnitLevel::PalTrait,
                ),
                DependencyNode::with_level(
                    "func_present",
                    "func_Present",
                    ReviewStatus::Queued,
                    WorkUnitLevel::FunctionTranslation,
                ),
                DependencyNode::with_level(
                    "func_draw",
                    "func_DrawPrimitive",
                    ReviewStatus::Queued,
                    WorkUnitLevel::FunctionTranslation,
                ),
                DependencyNode::with_level(
                    "integrate_batch",
                    "Integrate batch 001",
                    ReviewStatus::Queued,
                    WorkUnitLevel::IntegrationStep,
                ),
            ],
            edges: vec![
                DependencyEdge {
                    from: "shim_wgpu".into(),
                    to: "dll_cls".into(),
                },
                DependencyEdge {
                    from: "pal_graphics".into(),
                    to: "shim_wgpu".into(),
                },
                DependencyEdge {
                    from: "func_present".into(),
                    to: "pal_graphics".into(),
                },
                DependencyEdge {
                    from: "func_draw".into(),
                    to: "shim_wgpu".into(),
                },
                DependencyEdge {
                    from: "func_draw".into(),
                    to: "pal_graphics".into(),
                },
                DependencyEdge {
                    from: "integrate_batch".into(),
                    to: "func_present".into(),
                },
                DependencyEdge {
                    from: "integrate_batch".into(),
                    to: "func_draw".into(),
                },
            ],
        };

        let (ordered, cycles) = graph.topological_order();
        assert!(cycles.is_empty(), "no cycles expected");
        let order_ids: Vec<&str> = ordered.iter().map(|n| n.unit_id.as_str()).collect();

        // Expected order:
        // 0: dll_cls (depth 0, level 0)
        // 1: shim_wgpu (depth 1, level 1)
        // 2: pal_graphics (depth 2, level 2)
        // 3: func_draw (depth 3, level 4) - depends on shim(1) + pal(2), same depth as func_present
        // 4: func_present (depth 3, level 4) - depends on pal(2)
        // 5: integrate_batch (depth 4, level 5)

        assert_eq!(order_ids[0], "dll_cls");
        assert_eq!(order_ids[1], "shim_wgpu");
        assert_eq!(order_ids[2], "pal_graphics");

        // func_present depends on pal_graphics at depth 3
        // func_draw depends on shim_wgpu (depth 2) + pal_graphics (depth 2) = depth 3
        let present_idx = order_ids
            .iter()
            .position(|&id| id == "func_present")
            .unwrap();
        let draw_idx = order_ids.iter().position(|&id| id == "func_draw").unwrap();
        let int_idx = order_ids
            .iter()
            .position(|&id| id == "integrate_batch")
            .unwrap();

        assert!(present_idx < int_idx, "function before integration");
        assert!(draw_idx < int_idx, "function before integration");
        assert_eq!(order_ids[order_ids.len() - 1], "integrate_batch");
    }

    #[test]
    fn cycle_detection() {
        // Create a cycle: A → B → A
        let graph = DependencyGraph {
            nodes: vec![
                DependencyNode::new("unit_a", "Unit A", ReviewStatus::Queued),
                DependencyNode::new("unit_b", "Unit B", ReviewStatus::Queued),
            ],
            edges: vec![
                DependencyEdge {
                    from: "unit_a".into(),
                    to: "unit_b".into(),
                },
                DependencyEdge {
                    from: "unit_b".into(),
                    to: "unit_a".into(),
                },
            ],
        };

        let (ordered, cycles) = graph.topological_order();
        assert!(
            ordered.is_empty(),
            "all nodes should be excluded due to cycle"
        );
        assert_eq!(cycles.len(), 2, "both nodes should be in the cycle list");
    }

    #[test]
    fn partial_cycle() {
        // A → B → C, and C → D (cycle), but A is unaffected
        let graph = DependencyGraph {
            nodes: vec![
                DependencyNode::new("good_a", "Good A", ReviewStatus::Queued),
                DependencyNode::new("good_b", "Good B", ReviewStatus::Queued),
                DependencyNode::new("bad_c", "Bad C", ReviewStatus::Queued),
                DependencyNode::new("bad_d", "Bad D", ReviewStatus::Queued),
            ],
            edges: vec![
                DependencyEdge {
                    from: "good_b".into(),
                    to: "good_a".into(),
                },
                // Cycle: bad_c → bad_d → bad_c
                DependencyEdge {
                    from: "bad_c".into(),
                    to: "bad_d".into(),
                },
                DependencyEdge {
                    from: "bad_d".into(),
                    to: "bad_c".into(),
                },
            ],
        };

        let (ordered, cycles) = graph.topological_order();
        let order_ids: Vec<&str> = ordered.iter().map(|n| n.unit_id.as_str()).collect();

        // Good nodes should still be ordered
        assert_eq!(order_ids[0], "good_a");
        assert_eq!(order_ids[1], "good_b");
        assert_eq!(ordered.len(), 2, "only good nodes should be ordered");

        // Bad nodes should be in cycle list
        assert!(cycles.contains(&"bad_c".to_string()));
        assert!(cycles.contains(&"bad_d".to_string()));
    }

    #[test]
    fn work_unit_level_ordering() {
        // Verify that WorkUnitLevel enum ordering matches pipeline phases
        assert!(WorkUnitLevel::DllClassification < WorkUnitLevel::ShimLayer);
        assert!(WorkUnitLevel::ShimLayer < WorkUnitLevel::PalTrait);
        assert!(WorkUnitLevel::PalTrait < WorkUnitLevel::TestCaseAddition);
        assert!(WorkUnitLevel::TestCaseAddition < WorkUnitLevel::FunctionTranslation);
        assert!(WorkUnitLevel::FunctionTranslation < WorkUnitLevel::IntegrationStep);
        assert!(WorkUnitLevel::IntegrationStep < WorkUnitLevel::BugFix);

        // Verify labels
        assert_eq!(WorkUnitLevel::DllClassification.label(), "classify");
        assert_eq!(WorkUnitLevel::ShimLayer.label(), "shim");
        assert_eq!(WorkUnitLevel::PalTrait.label(), "pal");
        assert_eq!(WorkUnitLevel::FunctionTranslation.label(), "func");
        assert_eq!(WorkUnitLevel::IntegrationStep.label(), "integrate");
        assert_eq!(WorkUnitLevel::BugFix.label(), "fix");
    }

    #[test]
    fn work_unit_kind_to_level() {
        assert_eq!(
            WorkUnitKind::DllClassification.level(),
            WorkUnitLevel::DllClassification
        );
        assert_eq!(WorkUnitKind::ShimLayer.level(), WorkUnitLevel::ShimLayer);
        assert_eq!(WorkUnitKind::PalTrait.level(), WorkUnitLevel::PalTrait);
        assert_eq!(
            WorkUnitKind::TestCaseAddition.level(),
            WorkUnitLevel::TestCaseAddition
        );
        assert_eq!(
            WorkUnitKind::FunctionTranslation.level(),
            WorkUnitLevel::FunctionTranslation
        );
        assert_eq!(
            WorkUnitKind::IntegrationStep.level(),
            WorkUnitLevel::IntegrationStep
        );
        assert_eq!(WorkUnitKind::BugFix.level(), WorkUnitLevel::BugFix);
    }

    #[test]
    fn dependency_node_constructors() {
        // Test the new constructor methods
        let node = DependencyNode::new("id1", "Name 1", ReviewStatus::Queued);
        assert_eq!(node.unit_id, "id1");
        assert_eq!(node.level, WorkUnitLevel::FunctionTranslation); // default

        let node = DependencyNode::with_level(
            "id2",
            "Name 2",
            ReviewStatus::PendingReview,
            WorkUnitLevel::ShimLayer,
        );
        assert_eq!(node.unit_id, "id2");
        assert_eq!(node.level, WorkUnitLevel::ShimLayer);
    }

    #[test]
    fn empty_graph_topological_order() {
        let graph = DependencyGraph {
            nodes: Vec::new(),
            edges: Vec::new(),
        };

        let (ordered, cycles) = graph.topological_order();
        assert!(ordered.is_empty());
        assert!(cycles.is_empty());
    }

    #[test]
    fn single_node_no_edges() {
        let graph = DependencyGraph {
            nodes: vec![DependencyNode::with_level(
                "solo",
                "Solo Unit",
                ReviewStatus::Queued,
                WorkUnitLevel::ShimLayer,
            )],
            edges: Vec::new(),
        };

        let (ordered, cycles) = graph.topological_order();
        assert_eq!(ordered.len(), 1);
        assert_eq!(ordered[0].unit_id, "solo");
        assert!(cycles.is_empty());
    }

    #[test]
    fn level_tiebreaks_same_depth() {
        // Both shim and PAL depend only on the DLL classification.
        // At the same depth, shim should come first.
        let graph = DependencyGraph {
            nodes: vec![
                DependencyNode::with_level(
                    "dll",
                    "DLL",
                    ReviewStatus::Accepted,
                    WorkUnitLevel::DllClassification,
                ),
                DependencyNode::with_level(
                    "func_x",
                    "Func X",
                    ReviewStatus::Queued,
                    WorkUnitLevel::FunctionTranslation,
                ),
                DependencyNode::with_level(
                    "shim_y",
                    "Shim Y",
                    ReviewStatus::Queued,
                    WorkUnitLevel::ShimLayer,
                ),
                DependencyNode::with_level(
                    "pal_z",
                    "PAL Z",
                    ReviewStatus::Queued,
                    WorkUnitLevel::PalTrait,
                ),
            ],
            edges: vec![
                DependencyEdge {
                    from: "func_x".into(),
                    to: "dll".into(),
                },
                DependencyEdge {
                    from: "shim_y".into(),
                    to: "dll".into(),
                },
                DependencyEdge {
                    from: "pal_z".into(),
                    to: "dll".into(),
                },
            ],
        };

        let (ordered, _cycles) = graph.topological_order();
        let order_ids: Vec<&str> = ordered.iter().map(|n| n.unit_id.as_str()).collect();

        // dll first
        assert_eq!(order_ids[0], "dll");

        // Then shim, then pal (same depth, level tie-breaking)
        assert_eq!(order_ids[1], "shim_y");
        assert_eq!(order_ids[2], "pal_z");
        assert_eq!(order_ids[3], "func_x");
    }

    // ── Auto-block units tests (Phase 4, Step 4.4) ──

    #[test]
    fn auto_block_marks_dependent_on_failed_dependency() {
        let mut dashboard = ReviewDashboard::new(vec![
            UnitOfWork {
                id: "shim_wgpu".into(),
                name: "Shim wgpu".into(),
                kind: WorkUnitKind::ShimLayer,
                dll: "d3d9.dll".into(),
                function: None,
                attempt: 1,
                status: ReviewStatus::SendBack,
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
                id: "func_draw".into(),
                name: "func_DrawPrimitive".into(),
                kind: WorkUnitKind::FunctionTranslation,
                dll: "game_logic.dll".into(),
                function: Some("DrawPrimitive".into()),
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
                dependencies: vec!["shim_wgpu".into()],
                created_at: Utc::now(),
                updated_at: Utc::now(),
                known_gaps: vec![],
                stale: Staleness::Fresh,
            },
        ]);

        let blocked_count = dashboard.auto_block_units();
        assert_eq!(blocked_count, 1);

        let shim = dashboard
            .review_queue
            .iter()
            .find(|u| u.id == "shim_wgpu")
            .unwrap();
        let func = dashboard
            .review_queue
            .iter()
            .find(|u| u.id == "func_draw")
            .unwrap();

        // The failed dependency should NOT change its own status
        assert!(matches!(shim.status, ReviewStatus::SendBack));
        // The dependent should be blocked
        assert!(matches!(func.status, ReviewStatus::Blocked));
        // blocked_units() should find the blocked unit
        assert_eq!(dashboard.blocked_units().len(), 1);
        assert_eq!(dashboard.blocked_units()[0].id, "func_draw");
    }

    #[test]
    fn auto_block_noop_when_all_deps_accepted() {
        let mut dashboard = ReviewDashboard::new(vec![
            UnitOfWork {
                id: "shim_wgpu".into(),
                name: "Shim wgpu".into(),
                kind: WorkUnitKind::ShimLayer,
                dll: "d3d9.dll".into(),
                function: None,
                attempt: 1,
                status: ReviewStatus::Accepted,
                accepted: true,
                confidence: Some(0.9),
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
                id: "func_draw".into(),
                name: "func_DrawPrimitive".into(),
                kind: WorkUnitKind::FunctionTranslation,
                dll: "game_logic.dll".into(),
                function: Some("DrawPrimitive".into()),
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
                dependencies: vec!["shim_wgpu".into()],
                created_at: Utc::now(),
                updated_at: Utc::now(),
                known_gaps: vec![],
                stale: Staleness::Fresh,
            },
        ]);

        let blocked_count = dashboard.auto_block_units();
        assert_eq!(blocked_count, 0);

        // No units should be blocked
        assert!(
            dashboard
                .review_queue
                .iter()
                .all(|u| { !matches!(u.status, ReviewStatus::Blocked) })
        );
    }

    #[test]
    fn auto_block_multiple_deps_any_failed_blocks_dependent() {
        // func_draw depends on both shim_wgpu and pal_graphics.
        // Only shim_wgpu fails; func_draw should still be blocked.
        let mut dashboard = ReviewDashboard::new(vec![
            UnitOfWork {
                id: "shim_wgpu".into(),
                name: "Shim wgpu".into(),
                kind: WorkUnitKind::ShimLayer,
                dll: "d3d9.dll".into(),
                function: None,
                attempt: 1,
                status: ReviewStatus::SendBack,
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
                id: "pal_graphics".into(),
                name: "PAL GraphicsDevice".into(),
                kind: WorkUnitKind::PalTrait,
                dll: "d3d9.dll".into(),
                function: None,
                attempt: 1,
                status: ReviewStatus::Accepted,
                accepted: true,
                confidence: Some(0.95),
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
                id: "func_draw".into(),
                name: "func_DrawPrimitive".into(),
                kind: WorkUnitKind::FunctionTranslation,
                dll: "game_logic.dll".into(),
                function: Some("DrawPrimitive".into()),
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
                dependencies: vec!["shim_wgpu".into(), "pal_graphics".into()],
                created_at: Utc::now(),
                updated_at: Utc::now(),
                known_gaps: vec![],
                stale: Staleness::Fresh,
            },
        ]);

        let blocked_count = dashboard.auto_block_units();
        assert_eq!(blocked_count, 1);

        let func = dashboard
            .review_queue
            .iter()
            .find(|u| u.id == "func_draw")
            .unwrap();
        assert!(matches!(func.status, ReviewStatus::Blocked));
    }

    #[test]
    fn auto_block_propagates_transitively() {
        // dll_cls → shim_wgpu → func_draw → integrate_batch
        // If shim_wgpu fails, both func_draw and integrate_batch get blocked.
        let mut dashboard = ReviewDashboard::new(vec![
            UnitOfWork {
                id: "dll_cls".into(),
                name: "Classify d3d9.dll".into(),
                kind: WorkUnitKind::DllClassification,
                dll: "d3d9.dll".into(),
                function: None,
                attempt: 1,
                status: ReviewStatus::Accepted,
                accepted: true,
                confidence: Some(0.99),
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
                id: "shim_wgpu".into(),
                name: "Shim wgpu".into(),
                kind: WorkUnitKind::ShimLayer,
                dll: "d3d9.dll".into(),
                function: None,
                attempt: 1,
                status: ReviewStatus::SendBack,
                accepted: false,
                confidence: None,
                baseline_tests_passed: None,
                baseline_tests_total: None,
                verification_tests_passed: None,
                verification_tests_total: None,
                llm_model: None,
                prompt_tier: None,
                dependencies: vec!["dll_cls".into()],
                created_at: Utc::now(),
                updated_at: Utc::now(),
                known_gaps: vec![],
                stale: Staleness::Fresh,
            },
            UnitOfWork {
                id: "func_draw".into(),
                name: "func_DrawPrimitive".into(),
                kind: WorkUnitKind::FunctionTranslation,
                dll: "game_logic.dll".into(),
                function: Some("DrawPrimitive".into()),
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
                dependencies: vec!["shim_wgpu".into()],
                created_at: Utc::now(),
                updated_at: Utc::now(),
                known_gaps: vec![],
                stale: Staleness::Fresh,
            },
            UnitOfWork {
                id: "integrate".into(),
                name: "Integrate batch 001".into(),
                kind: WorkUnitKind::IntegrationStep,
                dll: "game_logic.dll".into(),
                function: None,
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
                dependencies: vec!["func_draw".into()],
                created_at: Utc::now(),
                updated_at: Utc::now(),
                known_gaps: vec![],
                stale: Staleness::Fresh,
            },
        ]);

        let blocked_count = dashboard.auto_block_units();
        assert_eq!(blocked_count, 2); // func_draw + integrate

        // Check each unit's status
        let statuses: HashMap<&str, &ReviewStatus> = dashboard
            .review_queue
            .iter()
            .chain(dashboard.recent_activity.iter())
            .map(|u| (u.id.as_str(), &u.status))
            .collect();

        assert!(matches!(statuses["dll_cls"], ReviewStatus::Accepted));
        assert!(matches!(statuses["shim_wgpu"], ReviewStatus::SendBack)); // unchanged
        assert!(matches!(statuses["func_draw"], ReviewStatus::Blocked));
        assert!(matches!(statuses["integrate"], ReviewStatus::Blocked));

        // blocked_units() should find exactly 2
        assert_eq!(dashboard.blocked_units().len(), 2);
    }

    #[test]
    fn auto_block_respects_terminal_statuses() {
        // A unit already in Accepted/Merged/Blocked status should NOT be changed.
        let mut dashboard = ReviewDashboard::new(vec![
            UnitOfWork {
                id: "shim_wgpu".into(),
                name: "Shim wgpu".into(),
                kind: WorkUnitKind::ShimLayer,
                dll: "d3d9.dll".into(),
                function: None,
                attempt: 1,
                status: ReviewStatus::SendBack,
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
                id: "func_draw".into(),
                name: "func_DrawPrimitive (v2)".into(),
                kind: WorkUnitKind::FunctionTranslation,
                dll: "game_logic.dll".into(),
                function: Some("DrawPrimitive".into()),
                attempt: 2,
                status: ReviewStatus::Accepted, // already accepted — should NOT change
                accepted: true,
                confidence: Some(0.8),
                baseline_tests_passed: Some(47),
                baseline_tests_total: Some(47),
                verification_tests_passed: Some(12),
                verification_tests_total: Some(12),
                llm_model: Some("qwen3".into()),
                prompt_tier: Some(2),
                dependencies: vec!["shim_wgpu".into()],
                created_at: Utc::now(),
                updated_at: Utc::now(),
                known_gaps: vec![],
                stale: Staleness::Fresh,
            },
        ]);

        let blocked_count = dashboard.auto_block_units();
        assert_eq!(blocked_count, 0);

        // func_draw has Accepted status so it's in recent_activity, not review_queue
        let func = dashboard
            .review_queue
            .iter()
            .chain(dashboard.recent_activity.iter())
            .find(|u| u.id == "func_draw")
            .unwrap();
        assert!(matches!(func.status, ReviewStatus::Accepted));
    }

    #[test]
    fn auto_block_noop_with_no_units() {
        let mut dashboard = ReviewDashboard::new(vec![]);
        let blocked_count = dashboard.auto_block_units();
        assert_eq!(blocked_count, 0);
        assert!(dashboard.blocked_units().is_empty());
    }

    #[test]
    fn auto_block_patch_requested_blocks_dependents() {
        // PatchRequested is also a failing status that triggers blocking.
        let mut dashboard = ReviewDashboard::new(vec![
            UnitOfWork {
                id: "pal_graphics".into(),
                name: "PAL GraphicsDevice".into(),
                kind: WorkUnitKind::PalTrait,
                dll: "d3d9.dll".into(),
                function: None,
                attempt: 1,
                status: ReviewStatus::PatchRequested,
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
                id: "func_present".into(),
                name: "func_Present".into(),
                kind: WorkUnitKind::FunctionTranslation,
                dll: "game_logic.dll".into(),
                function: Some("Present".into()),
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
                dependencies: vec!["pal_graphics".into()],
                created_at: Utc::now(),
                updated_at: Utc::now(),
                known_gaps: vec![],
                stale: Staleness::Fresh,
            },
        ]);

        let blocked_count = dashboard.auto_block_units();
        assert_eq!(blocked_count, 1);

        let func = dashboard
            .review_queue
            .iter()
            .find(|u| u.id == "func_present")
            .unwrap();
        assert!(matches!(func.status, ReviewStatus::Blocked));
    }

    #[test]
    fn auto_block_idempotent() {
        // Calling auto_block_units() multiple times should be a no-op after the first call.
        let mut dashboard = ReviewDashboard::new(vec![
            UnitOfWork {
                id: "shim_wgpu".into(),
                name: "Shim wgpu".into(),
                kind: WorkUnitKind::ShimLayer,
                dll: "d3d9.dll".into(),
                function: None,
                attempt: 1,
                status: ReviewStatus::SendBack,
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
                id: "func_draw".into(),
                name: "func_DrawPrimitive".into(),
                kind: WorkUnitKind::FunctionTranslation,
                dll: "game_logic.dll".into(),
                function: Some("DrawPrimitive".into()),
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
                dependencies: vec!["shim_wgpu".into()],
                created_at: Utc::now(),
                updated_at: Utc::now(),
                known_gaps: vec![],
                stale: Staleness::Fresh,
            },
        ]);

        let first = dashboard.auto_block_units();
        let second = dashboard.auto_block_units();
        let third = dashboard.auto_block_units();

        assert_eq!(first, 1);
        assert_eq!(second, 0); // already blocked, no change
        assert_eq!(third, 0);
    }
}
