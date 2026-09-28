//! Calxgloss Web — Web Review UI (API layer for the review dashboard)
//!
//! This crate houses the review UI for the Calxgloss reverse engineering harness.
//! The domain data types (`UnitOfWork`, `ReviewDashboard`, `DependencyGraph`, etc.)
//! live in `calxgloss-types` and are re-exported from this crate for convenience.
//!
//! ## MVP Status
//!
//! The MVP used terminal output from `calxgloss-reports` for review.
//! The web UI's API layer is implemented behind the `server` feature flag.
//!
//! ## Architecture
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
//! Re-export the dashboard data types from `calxgloss-types` so downstream
//! consumers can import everything from a single place.

// ============================================================
// Re-exports from calxgloss-types
// ============================================================

pub use calxgloss_types::{
    DependencyEdge, DependencyGraph, DependencyNode, ReviewAction, ReviewActionKind,
    ReviewDashboard, ReviewStatus, StatusCounts, UnitOfWork, WorkUnitKind,
};

// ============================================================
// Axum API layer (behind feature flag)
// ============================================================

#[cfg(feature = "server")]
pub mod server {
    //! Axum HTTP server for the review dashboard API.
    //!
    //! This module is only compiled when the `server` feature is enabled.
    //!
    //! ## API Endpoints
    //!
    //! | Method | Path | Handler | Description |
    //! |--------|------|---------|-------------|
    //! | `GET` | `/api/dashboard` | `api_get_dashboard` | Full review dashboard with queue, graph, and counts |
    //! | `GET` | `/api/units/:id` | `api_get_unit` | Detail view for a single unit of work |
    //! | `POST` | `/api/units/:id/accept` | `api_accept_unit` | Accept unit — merge branch to main |
    //! | `POST` | `/api/units/:id/send-back` | `api_send_back_unit` | Send back unit with reviewer comments |
    //! | `POST` | `/api/units/:id/patch` | `api_request_patch` | Request patch for specific issue |
    //! | `GET` | `/api/graph` | `api_get_dependency_graph` | Dependency graph for visualization |
    //! | `GET` | `/health` | `api_health` | Health check |
    //!
    //! ## Usage
    //!
    //! ```no_run
    //! use calxgloss_web::server::{ServerState, serve};
    //! use std::path::PathBuf;
    //!
    //! #[tokio::main]
    //! async fn main() -> anyhow::Result<()> {
    //!     let state = ServerState::new(PathBuf::from("/path/to/repo"));
    //!     serve(state, 3000).await?;
    //!     Ok(())
    //! }
    //! ```
    //!
    //! The server builds the dashboard on every request by reading Git branches,
    //! patch records, and baseline files from the repository. This means the
    //! dashboard always reflects the current state of the repository.
    //!
    //! For high-traffic deployments, consider adding a caching layer (e.g.,
    //! Redis) or using `axum::cache` to avoid rebuilding the dashboard on
    //! every request.
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
    use calxgloss_types::{
        DependencyEdge, DependencyGraph, DependencyNode, ReviewDashboard, ReviewStatus,
        StatusCounts, UnitOfWork, WorkUnitKind,
    };
    use calxgloss_types::dashboard::Staleness;
    use chrono::Utc;

    #[test]
    fn dependency_graph_roots() {
        let graph = DependencyGraph {
            nodes: vec![
                DependencyNode::new("dll_classify", "DLL Classification", ReviewStatus::Accepted),
                DependencyNode::with_level("shim_wgpu", "Shim wgpu", ReviewStatus::PendingReview, WorkUnitKind::ShimLayer.level()),
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
                DependencyNode::with_level("shim_wgpu", "Shim wgpu", ReviewStatus::PendingReview, WorkUnitKind::ShimLayer.level()),
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
                DependencyNode::with_level("shim_wgpu", "Shim wgpu", ReviewStatus::Accepted, WorkUnitKind::ShimLayer.level()),
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
    }
}
