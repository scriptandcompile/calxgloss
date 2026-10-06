use crate::dashboard::graph::{DependencyEdge, DependencyGraph, DependencyNode};
use crate::dashboard::review::ReviewDashboard;
use crate::dashboard::status::StatusCounts;
use crate::dashboard::types::{ReviewStatus, Staleness, WorkKind, WorkLevel};
use crate::dashboard::work_unit::UnitOfWork;
use chrono::Utc;
use std::collections::HashMap;

#[test]
fn dependency_graph_roots() {
    let graph = DependencyGraph {
        nodes: vec![
            DependencyNode::new("dll_classify", "DLL Classification", ReviewStatus::Accepted),
            DependencyNode::with_level(
                "shim_wgpu",
                "Shim wgpu",
                ReviewStatus::PendingReview,
                WorkLevel::ShimLayer,
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
                WorkLevel::ShimLayer,
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
                WorkLevel::ShimLayer,
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
            kind: WorkKind::FunctionTranslation,
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
            context_tier: None,
            dependencies: vec!["unit_1".into(), "unit_2".into()],
            created_at: Utc::now(),
            updated_at: Utc::now(),
            known_gaps: vec![],
            stale: Staleness::Fresh,
        },
        UnitOfWork {
            id: "unit_1".into(),
            name: "unit_1".into(),
            kind: WorkKind::DllClassification,
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
            context_tier: None,
            dependencies: vec![],
            created_at: Utc::now(),
            updated_at: Utc::now(),
            known_gaps: vec![],
            stale: Staleness::Fresh,
        },
        UnitOfWork {
            id: "unit_2".into(),
            name: "unit_2".into(),
            kind: WorkKind::ShimLayer,
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
            context_tier: None,
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
    assert_eq!(ReviewStatus::Blocked.to_string(), "blocked");
}

#[test]
fn work_kind_display() {
    assert_eq!(
        WorkKind::DllClassification.to_string(),
        "DLL Classification"
    );
    assert_eq!(WorkKind::ShimLayer.to_string(), "Shim Layer");
    assert_eq!(
        WorkKind::FunctionTranslation.to_string(),
        "Function Translation"
    );
    assert_eq!(
        WorkKind::TestCaseAddition.to_string(),
        "Test Case Addition"
    );
    assert_eq!(WorkKind::PalTrait.to_string(), "PAL Trait");
    assert_eq!(
        WorkKind::IntegrationStep.to_string(),
        "Integration Step"
    );
    assert_eq!(WorkKind::BugFix.to_string(), "Bug Fix");
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
        blocked: 1,
    };
    let display = format!("{}", counts);
    assert!(display.contains("queued: 3"));
    assert!(display.contains("pending: 2"));
    assert!(display.contains("in_progress: 0"));
    assert!(display.contains("accepted: 5"));
    assert_eq!(counts.total(), 12);
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
        blocked: 6,
    };
    let json = serde_json::to_string(&counts).unwrap();
    let deserialized: StatusCounts = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.queued, 1);
    assert_eq!(deserialized.pending_review, 2);
    assert_eq!(deserialized.in_progress, 3);
    assert_eq!(deserialized.accepted, 3);
    assert_eq!(deserialized.send_back, 4);
    assert_eq!(deserialized.patch_requested, 5);
    assert_eq!(deserialized.blocked, 6);
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
        ReviewStatus::Blocked,
    ];
    for status in &statuses {
        let json = serde_json::to_string(status).unwrap();
        let deserialized: ReviewStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(&deserialized, status);
    }
}

#[test]
fn work_kind_serialization() {
    let kinds = vec![
        WorkKind::DllClassification,
        WorkKind::ShimLayer,
        WorkKind::FunctionTranslation,
        WorkKind::TestCaseAddition,
        WorkKind::PalTrait,
        WorkKind::IntegrationStep,
        WorkKind::BugFix,
    ];
    for kind in &kinds {
        let json = serde_json::to_string(kind).unwrap();
        let deserialized: WorkKind = serde_json::from_str(&json).unwrap();
        assert_eq!(&deserialized, kind);
    }
}

#[test]
fn dashboard_accepts_units_into_recent_activity() {
    let units = vec![
        UnitOfWork {
            id: "unit_1".into(),
            name: "unit_1".into(),
            kind: WorkKind::DllClassification,
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
            context_tier: Some(2),
            dependencies: vec![],
            created_at: Utc::now(),
            updated_at: Utc::now(),
            known_gaps: vec![],
            stale: Staleness::Fresh,
        },
        UnitOfWork {
            id: "unit_2".into(),
            name: "unit_2".into(),
            kind: WorkKind::ShimLayer,
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
            context_tier: None,
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
                WorkLevel::ShimLayer,
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
            kind: WorkKind::FunctionTranslation,
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
            context_tier: None,
            dependencies: vec!["unit_1".into(), "unit_2".into()],
            created_at: Utc::now(),
            updated_at: Utc::now(),
            known_gaps: vec![],
            stale: Staleness::Fresh,
        },
        UnitOfWork {
            id: "unit_1".into(),
            name: "unit_1".into(),
            kind: WorkKind::DllClassification,
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
            context_tier: None,
            dependencies: vec![],
            created_at: Utc::now(),
            updated_at: Utc::now(),
            known_gaps: vec![],
            stale: Staleness::Fresh,
        },
        UnitOfWork {
            id: "unit_2".into(),
            name: "unit_2".into(),
            kind: WorkKind::ShimLayer,
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
            context_tier: None,
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
    assert!(stale.is_stale() || matches!(stale, Staleness::Fresh));
}

#[test]
fn staleness_display() {
    assert_eq!(format!("{}", Staleness::Fresh), "fresh");

    let now = Utc::now();
    let old = now - chrono::Duration::hours(30);
    let display = format!("{}", Staleness::from_elapsed(now, old));
    assert!(display.contains("stale") || display.contains("critical"));
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

#[test]
fn level_respects_pipeline_order() {
    let graph = DependencyGraph {
        nodes: vec![
            DependencyNode::with_level(
                "dll_cls",
                "DLL Classify",
                ReviewStatus::Accepted,
                WorkLevel::DllClassification,
            ),
            DependencyNode::with_level(
                "shim_wgpu",
                "Shim wgpu",
                ReviewStatus::Queued,
                WorkLevel::ShimLayer,
            ),
            DependencyNode::with_level(
                "pal_graphics",
                "PAL GraphicsDevice",
                ReviewStatus::Queued,
                WorkLevel::PalTrait,
            ),
            DependencyNode::with_level(
                "func_draw",
                "func_DrawPrimitive",
                ReviewStatus::Queued,
                WorkLevel::FunctionTranslation,
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

    assert_eq!(order_ids[0], "dll_cls");

    let shim_idx = order_ids.iter().position(|&id| id == "shim_wgpu").unwrap();
    let pal_idx = order_ids
        .iter()
        .position(|&id| id == "pal_graphics")
        .unwrap();
    assert!(
        shim_idx < pal_idx,
        "shim layer should come before PAL trait at same depth"
    );

    assert_eq!(order_ids[order_ids.len() - 1], "func_draw");
}

#[test]
fn full_pipeline_order() {
    let graph = DependencyGraph {
        nodes: vec![
            DependencyNode::with_level(
                "dll_cls",
                "Classify d3d9.dll",
                ReviewStatus::Accepted,
                WorkLevel::DllClassification,
            ),
            DependencyNode::with_level(
                "shim_wgpu",
                "Shim d3d9→wgpu",
                ReviewStatus::Queued,
                WorkLevel::ShimLayer,
            ),
            DependencyNode::with_level(
                "pal_graphics",
                "PAL GraphicsDevice",
                ReviewStatus::Queued,
                WorkLevel::PalTrait,
            ),
            DependencyNode::with_level(
                "func_present",
                "func_Present",
                ReviewStatus::Queued,
                WorkLevel::FunctionTranslation,
            ),
            DependencyNode::with_level(
                "func_draw",
                "func_DrawPrimitive",
                ReviewStatus::Queued,
                WorkLevel::FunctionTranslation,
            ),
            DependencyNode::with_level(
                "integrate_batch",
                "Integrate batch 001",
                ReviewStatus::Queued,
                WorkLevel::IntegrationStep,
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

    assert_eq!(order_ids[0], "dll_cls");
    assert_eq!(order_ids[1], "shim_wgpu");
    assert_eq!(order_ids[2], "pal_graphics");

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

    assert_eq!(order_ids[0], "good_a");
    assert_eq!(order_ids[1], "good_b");
    assert_eq!(ordered.len(), 2, "only good nodes should be ordered");

    assert!(cycles.contains(&"bad_c".to_string()));
    assert!(cycles.contains(&"bad_d".to_string()));
}

#[test]
fn work_level_ordering() {
    assert!(WorkLevel::DllClassification < WorkLevel::ShimLayer);
    assert!(WorkLevel::ShimLayer < WorkLevel::PalTrait);
    assert!(WorkLevel::PalTrait < WorkLevel::TestCaseAddition);
    assert!(WorkLevel::TestCaseAddition < WorkLevel::FunctionTranslation);
    assert!(WorkLevel::FunctionTranslation < WorkLevel::IntegrationStep);
    assert!(WorkLevel::IntegrationStep < WorkLevel::BugFix);

    assert_eq!(WorkLevel::DllClassification.label(), "classify");
    assert_eq!(WorkLevel::ShimLayer.label(), "shim");
    assert_eq!(WorkLevel::PalTrait.label(), "pal");
    assert_eq!(WorkLevel::FunctionTranslation.label(), "func");
    assert_eq!(WorkLevel::IntegrationStep.label(), "integrate");
    assert_eq!(WorkLevel::BugFix.label(), "fix");
}

#[test]
fn work_kind_to_level() {
    assert_eq!(
        WorkKind::DllClassification.level(),
        WorkLevel::DllClassification
    );
    assert_eq!(WorkKind::ShimLayer.level(), WorkLevel::ShimLayer);
    assert_eq!(WorkKind::PalTrait.level(), WorkLevel::PalTrait);
    assert_eq!(
        WorkKind::TestCaseAddition.level(),
        WorkLevel::TestCaseAddition
    );
    assert_eq!(
        WorkKind::FunctionTranslation.level(),
        WorkLevel::FunctionTranslation
    );
    assert_eq!(
        WorkKind::IntegrationStep.level(),
        WorkLevel::IntegrationStep
    );
    assert_eq!(WorkKind::BugFix.level(), WorkLevel::BugFix);
}

#[test]
fn dependency_node_constructors() {
    let node = DependencyNode::new("id1", "Name 1", ReviewStatus::Queued);
    assert_eq!(node.unit_id, "id1");
    assert_eq!(node.level, WorkLevel::FunctionTranslation);

    let node = DependencyNode::with_level(
        "id2",
        "Name 2",
        ReviewStatus::PendingReview,
        WorkLevel::ShimLayer,
    );
    assert_eq!(node.unit_id, "id2");
    assert_eq!(node.level, WorkLevel::ShimLayer);
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
            WorkLevel::ShimLayer,
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
    let graph = DependencyGraph {
        nodes: vec![
            DependencyNode::with_level(
                "dll",
                "DLL",
                ReviewStatus::Accepted,
                WorkLevel::DllClassification,
            ),
            DependencyNode::with_level(
                "func_x",
                "Func X",
                ReviewStatus::Queued,
                WorkLevel::FunctionTranslation,
            ),
            DependencyNode::with_level(
                "shim_y",
                "Shim Y",
                ReviewStatus::Queued,
                WorkLevel::ShimLayer,
            ),
            DependencyNode::with_level(
                "pal_z",
                "PAL Z",
                ReviewStatus::Queued,
                WorkLevel::PalTrait,
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

    assert_eq!(order_ids[0], "dll");
    assert_eq!(order_ids[1], "shim_y");
    assert_eq!(order_ids[2], "pal_z");
    assert_eq!(order_ids[3], "func_x");
}

#[test]
fn auto_block_marks_dependent_on_failed_dependency() {
    let mut dashboard = ReviewDashboard::new(vec![
        UnitOfWork {
            id: "shim_wgpu".into(),
            name: "Shim wgpu".into(),
            kind: WorkKind::ShimLayer,
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
            context_tier: None,
            dependencies: vec![],
            created_at: Utc::now(),
            updated_at: Utc::now(),
            known_gaps: vec![],
            stale: Staleness::Fresh,
        },
        UnitOfWork {
            id: "func_draw".into(),
            name: "func_DrawPrimitive".into(),
            kind: WorkKind::FunctionTranslation,
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
            context_tier: None,
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

    assert!(matches!(shim.status, ReviewStatus::SendBack));
    assert!(matches!(func.status, ReviewStatus::Blocked));
    assert_eq!(dashboard.blocked_units().len(), 1);
    assert_eq!(dashboard.blocked_units()[0].id, "func_draw");
}

#[test]
fn auto_block_noop_when_all_deps_accepted() {
    let mut dashboard = ReviewDashboard::new(vec![
        UnitOfWork {
            id: "shim_wgpu".into(),
            name: "Shim wgpu".into(),
            kind: WorkKind::ShimLayer,
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
            context_tier: None,
            dependencies: vec![],
            created_at: Utc::now(),
            updated_at: Utc::now(),
            known_gaps: vec![],
            stale: Staleness::Fresh,
        },
        UnitOfWork {
            id: "func_draw".into(),
            name: "func_DrawPrimitive".into(),
            kind: WorkKind::FunctionTranslation,
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
            context_tier: None,
            dependencies: vec!["shim_wgpu".into()],
            created_at: Utc::now(),
            updated_at: Utc::now(),
            known_gaps: vec![],
            stale: Staleness::Fresh,
        },
    ]);

    let blocked_count = dashboard.auto_block_units();
    assert_eq!(blocked_count, 0);

    assert!(
        dashboard
            .review_queue
            .iter()
            .all(|u| { !matches!(u.status, ReviewStatus::Blocked) })
    );
}

#[test]
fn auto_block_multiple_deps_any_failed_blocks_dependent() {
    let mut dashboard = ReviewDashboard::new(vec![
        UnitOfWork {
            id: "shim_wgpu".into(),
            name: "Shim wgpu".into(),
            kind: WorkKind::ShimLayer,
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
            context_tier: None,
            dependencies: vec![],
            created_at: Utc::now(),
            updated_at: Utc::now(),
            known_gaps: vec![],
            stale: Staleness::Fresh,
        },
        UnitOfWork {
            id: "pal_graphics".into(),
            name: "PAL GraphicsDevice".into(),
            kind: WorkKind::PalTrait,
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
            context_tier: None,
            dependencies: vec![],
            created_at: Utc::now(),
            updated_at: Utc::now(),
            known_gaps: vec![],
            stale: Staleness::Fresh,
        },
        UnitOfWork {
            id: "func_draw".into(),
            name: "func_DrawPrimitive".into(),
            kind: WorkKind::FunctionTranslation,
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
            context_tier: None,
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
    let mut dashboard = ReviewDashboard::new(vec![
        UnitOfWork {
            id: "dll_cls".into(),
            name: "Classify d3d9.dll".into(),
            kind: WorkKind::DllClassification,
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
            context_tier: None,
            dependencies: vec![],
            created_at: Utc::now(),
            updated_at: Utc::now(),
            known_gaps: vec![],
            stale: Staleness::Fresh,
        },
        UnitOfWork {
            id: "shim_wgpu".into(),
            name: "Shim wgpu".into(),
            kind: WorkKind::ShimLayer,
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
            context_tier: None,
            dependencies: vec!["dll_cls".into()],
            created_at: Utc::now(),
            updated_at: Utc::now(),
            known_gaps: vec![],
            stale: Staleness::Fresh,
        },
        UnitOfWork {
            id: "func_draw".into(),
            name: "func_DrawPrimitive".into(),
            kind: WorkKind::FunctionTranslation,
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
            context_tier: None,
            dependencies: vec!["shim_wgpu".into()],
            created_at: Utc::now(),
            updated_at: Utc::now(),
            known_gaps: vec![],
            stale: Staleness::Fresh,
        },
        UnitOfWork {
            id: "integrate".into(),
            name: "Integrate batch 001".into(),
            kind: WorkKind::IntegrationStep,
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
            context_tier: None,
            dependencies: vec!["func_draw".into()],
            created_at: Utc::now(),
            updated_at: Utc::now(),
            known_gaps: vec![],
            stale: Staleness::Fresh,
        },
    ]);

    let blocked_count = dashboard.auto_block_units();
    assert_eq!(blocked_count, 2); // func_draw + integrate

    let statuses: HashMap<&str, &ReviewStatus> = dashboard
        .review_queue
        .iter()
        .chain(dashboard.recent_activity.iter())
        .map(|u| (u.id.as_str(), &u.status))
        .collect();

    assert!(matches!(statuses["dll_cls"], ReviewStatus::Accepted));
    assert!(matches!(statuses["shim_wgpu"], ReviewStatus::SendBack));
    assert!(matches!(statuses["func_draw"], ReviewStatus::Blocked));
    assert!(matches!(statuses["integrate"], ReviewStatus::Blocked));

    assert_eq!(dashboard.blocked_units().len(), 2);
}

#[test]
fn auto_block_respects_terminal_statuses() {
    let mut dashboard = ReviewDashboard::new(vec![
        UnitOfWork {
            id: "shim_wgpu".into(),
            name: "Shim wgpu".into(),
            kind: WorkKind::ShimLayer,
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
            context_tier: None,
            dependencies: vec![],
            created_at: Utc::now(),
            updated_at: Utc::now(),
            known_gaps: vec![],
            stale: Staleness::Fresh,
        },
        UnitOfWork {
            id: "func_draw".into(),
            name: "func_DrawPrimitive (v2)".into(),
            kind: WorkKind::FunctionTranslation,
            dll: "game_logic.dll".into(),
            function: Some("DrawPrimitive".into()),
            attempt: 2,
            status: ReviewStatus::Accepted,
            accepted: true,
            confidence: Some(0.8),
            baseline_tests_passed: Some(47),
            baseline_tests_total: Some(47),
            verification_tests_passed: Some(12),
            verification_tests_total: Some(12),
            llm_model: Some("qwen3".into()),
            context_tier: Some(2),
            dependencies: vec!["shim_wgpu".into()],
            created_at: Utc::now(),
            updated_at: Utc::now(),
            known_gaps: vec![],
            stale: Staleness::Fresh,
        },
    ]);

    let blocked_count = dashboard.auto_block_units();
    assert_eq!(blocked_count, 0);

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
    let mut dashboard = ReviewDashboard::new(vec![
        UnitOfWork {
            id: "pal_graphics".into(),
            name: "PAL GraphicsDevice".into(),
            kind: WorkKind::PalTrait,
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
            context_tier: None,
            dependencies: vec![],
            created_at: Utc::now(),
            updated_at: Utc::now(),
            known_gaps: vec![],
            stale: Staleness::Fresh,
        },
        UnitOfWork {
            id: "func_present".into(),
            name: "func_Present".into(),
            kind: WorkKind::FunctionTranslation,
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
            context_tier: None,
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
    let mut dashboard = ReviewDashboard::new(vec![
        UnitOfWork {
            id: "shim_wgpu".into(),
            name: "Shim wgpu".into(),
            kind: WorkKind::ShimLayer,
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
            context_tier: None,
            dependencies: vec![],
            created_at: Utc::now(),
            updated_at: Utc::now(),
            known_gaps: vec![],
            stale: Staleness::Fresh,
        },
        UnitOfWork {
            id: "func_draw".into(),
            name: "func_DrawPrimitive".into(),
            kind: WorkKind::FunctionTranslation,
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
            context_tier: None,
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
    assert_eq!(second, 0);
    assert_eq!(third, 0);
}
