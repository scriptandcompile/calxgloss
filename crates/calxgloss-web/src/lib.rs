//! Calxgloss Web — Web Review UI (scaffolded for post-MVP implementation)
//!
//! This crate will house the review UI for the Calxgloss reverse engineering harness.
//! It will use **axum** + **leptos** for a reactive server-side rendered web interface.
//!
//! ## MVP Status
//!
//! In the MVP, review happens via terminal output from `calxgloss-reports`.
//! The web UI is not implemented yet — these structs are scaffolds for future work.
//!
//! ## Future Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────────┐
//! │  Web Review UI                                                   │
//! │                                                                  │
//! │  ┌─────────────────┐  ┌──────────────────────────────────────┐   │
//! │  │  Dependency     │  │  Unit of Work Details                │   │
//! │  │  Graph          │  │                                      │   │
//! │  │  ● DLL Classify │  │  Function: DrawPrimitive             │   │
//! │  │    │            │  │  Branch: re/game_logic/DrawPrimitive │   │
//! │  │    ├─ shim/wgpu │  │  Status: ✅ Accepted                 │   │
//! │  │    └─ shim/cpal │  │                                      │   │
//! │  │                 │  │  [Justification] [Diff View]         │   │
//! │  │  [Queue]        │  │  [Test Results] [Actions]            │   │
//! │  └─────────────────┘  └──────────────────────────────────────┘   │
//! └──────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Feature Flags
//!
//! - `server` — enables the axum HTTP server (default: off)
//!
//! Run with a feature flag:
//! ```bash
//! cargo build --features server
//! ```
//!
//! ## Post-MVP Implementation Plan
//!
//! 1. Set up axum router with `/api/*` endpoints for review data
//! 2. Add leptos and implement components for review dashboard, diff view, dependency graph
//! 3. Wire endpoints to `calxgloss-types` and `calxgloss-git` data sources
//! 4. Add WebSocket support for real-time translation progress streaming

// ============================================================
// Core structs — future web UI data models
// ============================================================

use chrono::{DateTime, Utc};

/// Represents a unit of work in the reverse engineering pipeline.
/// Each unit corresponds to a single function translation, DLL classification,
/// shim layer implementation, or integration step.
#[derive(Debug, Clone)]
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
}

/// The kind of work unit.
#[derive(Debug, Clone, PartialEq)]
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

/// The current review status of a unit of work.
#[derive(Debug, Clone, PartialEq)]
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

/// A node in the dependency graph of units of work.
#[derive(Debug, Clone)]
pub struct DependencyNode {
    /// ID of the unit of work.
    pub unit_id: String,
    /// Display name.
    pub name: String,
    /// Status of this unit.
    pub status: ReviewStatus,
}

/// An edge representing a dependency relationship between units of work.
#[derive(Debug, Clone)]
pub struct DependencyEdge {
    /// The unit that depends on another.
    pub from: String,
    /// The unit that is depended upon.
    pub to: String,
}

/// The full dependency graph for the current review session.
#[derive(Debug, Clone)]
pub struct DependencyGraph {
    /// All nodes in the graph.
    pub nodes: Vec<DependencyNode>,
    /// All edges in the graph.
    pub edges: Vec<DependencyEdge>,
}

impl DependencyGraph {
    /// Returns nodes that have no incoming edges (root nodes — no dependencies).
    pub fn roots(&self) -> Vec<&DependencyNode> {
        let dependent_ids: std::collections::HashSet<&str> = self
            .edges
            .iter()
            .map(|e| &e.from)
            .map(|s| s.as_str())
            .collect();
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
}

/// Represents a review action that a human can take on a unit of work.
#[derive(Debug, Clone)]
pub struct ReviewAction {
    /// The unit of work this action applies to.
    pub unit_id: String,
    /// The action being performed.
    pub action: ReviewActionKind,
    /// Optional comments from the reviewer.
    pub comments: Option<String>,
}

/// The kinds of review actions available.
#[derive(Debug, Clone)]
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

/// A dashboard view showing all units of work and their status.
#[derive(Debug, Clone)]
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
    pub fn new(units: Vec<UnitOfWork>) -> Self {
        let mut graph = DependencyGraph {
            nodes: Vec::new(),
            edges: Vec::new(),
        };
        let mut queue = Vec::new();
        let mut recent = Vec::new();
        let mut counts = StatusCounts::default();

        for unit in units {
            let is_accepted =
                unit.status == ReviewStatus::Accepted || unit.status == ReviewStatus::Merged;
            let is_pending = unit.status == ReviewStatus::PendingReview
                || unit.status == ReviewStatus::SendBack
                || unit.status == ReviewStatus::PatchRequested;

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

        // Sort queue by dependency order (roots first)
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
            .filter(|u| u.status == ReviewStatus::Blocked)
            .collect()
    }
}

/// Summary counts of units of work by status.
#[derive(Debug, Default, Clone)]
pub struct StatusCounts {
    pub queued: usize,
    pub pending_review: usize,
    pub accepted: usize,
    pub send_back: usize,
    pub patch_requested: usize,
    pub merged: usize,
    pub blocked: usize,
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
// Axum API scaffolding (behind feature flag)
// ============================================================

#[cfg(feature = "server")]
pub mod server {
    //! Axum HTTP server for the review dashboard API.
    //!
    //! This module is only compiled when the `server` feature is enabled.

    use axum::{
        Router,
        routing::{get, post},
    };

    /// Build the axum router with all API endpoints.
    pub fn build_router() -> Router {
        Router::new()
            .route("/api/dashboard", get(api_get_dashboard))
            .route("/api/units/{id}", get(api_get_unit))
            .route("/api/units/{id}/accept", post(api_accept_unit))
            .route("/api/units/{id}/send-back", post(api_send_back_unit))
            .route("/api/units/{id}/patch", post(api_request_patch))
            .route("/api/graph", get(api_get_dependency_graph))
            .route("/health", get(api_health))
    }

    // --- API endpoint handlers (scaffolded) ---

    async fn api_get_dashboard() -> &'static str {
        "{}"
        // TODO: Query units of work, return dashboard data
    }

    async fn api_get_unit(axum::extract::Path(_id): axum::extract::Path<String>) -> &'static str {
        "{}"
        // TODO: Query single unit of work by ID
    }

    async fn api_accept_unit(
        axum::extract::Path(_id): axum::extract::Path<String>,
    ) -> &'static str {
        "{}"
        // TODO: Accept unit — merge branch to main
    }

    async fn api_send_back_unit(
        axum::extract::Path(_id): axum::extract::Path<String>,
    ) -> &'static str {
        "{}"
        // TODO: Send back unit with reviewer comments
    }

    async fn api_request_patch(
        axum::extract::Path(_id): axum::extract::Path<String>,
    ) -> &'static str {
        "{}"
        // TODO: Request patch for specific issue
    }

    async fn api_get_dependency_graph() -> &'static str {
        "{}"
        // TODO: Build and return dependency graph
    }

    async fn api_health() -> &'static str {
        "ok"
    }
}

// ============================================================
// Leptos component scaffolding (planned, post-MVP)
// ============================================================
//
// The `leptos` dependency and feature are not wired up yet — re-add them
// alongside the real implementation. The planned components are:
//
// - DashboardView: main review dashboard page
// - DependencyGraphView: visual dependency graph
// - UnitOfWorkCard: individual unit card with diff/tests/actions
// - ReviewQueue: queue of pending units
// - RecentActivity: recent accept/send-back events
//
// Each would live in a `#[cfg(feature = "leptos")] pub mod components` block.

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
    }
}
