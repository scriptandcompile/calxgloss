//! Integration tests for the calxgloss-callgraph crate.
//!
//! These tests exercise multi-module workflows that unit tests cannot cover
//! on their own:
//!
//! - **Persistence round-trip** — build a graph in memory, save to disk,
//!   load it back, and re-classify with root/leaf detectors.
//! - **Full pipeline (ignored)** — requires a running GhidraMCP server
//!   and is skipped by default.

use std::collections::HashMap;

use calxgloss_callgraph::{
    CallGraph, CallGraphEdge, CallGraphPersistor, CallType, FunctionCallGraph, LeafCategory,
    LeafDetector, NodeCategory, RootDetector,
};

/// ---------------------------------------------------------------------------
/// Helpers
/// ---------------------------------------------------------------------------
/// Build a small synthetic call graph (no Ghidra required).
///
/// ```text
/// main (Root) ──► helper (Middle) ──► Direct3DCreate9 (Leaf)
///                            └──► MessageBox (Leaf)
/// ```
fn synthetic_graph() -> CallGraph {
    CallGraph {
        dll: "test.dll".to_string(),
        functions: vec![
            FunctionCallGraph {
                name: "main".to_string(),
                address: 0x401000,
                callers: vec![],
                callees: vec![CallGraphEdge {
                    source: 0x401000,
                    target: 0x402000,
                    call_site: 0x401010,
                    call_type: CallType::Direct,
                    callee_name: "helper".to_string(),
                }],
                node_category: NodeCategory::Middle,
            },
            FunctionCallGraph {
                name: "helper".to_string(),
                address: 0x402000,
                callers: vec![0x401000],
                callees: vec![
                    CallGraphEdge {
                        source: 0x402000,
                        target: 0x700000,
                        call_site: 0x402008,
                        call_type: CallType::Direct,
                        callee_name: "Direct3DCreate9".to_string(),
                    },
                    CallGraphEdge {
                        source: 0x402000,
                        target: 0x701000,
                        call_site: 0x402010,
                        call_type: CallType::Direct,
                        callee_name: "MessageBox".to_string(),
                    },
                ],
                node_category: NodeCategory::Middle,
            },
            FunctionCallGraph {
                name: "Direct3DCreate9".to_string(),
                address: 0x700000,
                callers: vec![0x402000],
                callees: vec![],
                node_category: NodeCategory::Middle,
            },
            FunctionCallGraph {
                name: "MessageBox".to_string(),
                address: 0x701000,
                callers: vec![0x402000],
                callees: vec![],
                node_category: NodeCategory::Middle,
            },
        ],
    }
}

/// Run root + leaf classification on a call graph (mutates in place).
fn classify_graph(graph: &mut CallGraph) {
    let root_detector = RootDetector::new();
    let leaf_detector = LeafDetector::new();

    for func in &mut graph.functions {
        func.node_category = if root_detector.is_root(func) {
            NodeCategory::Root
        } else if leaf_detector.has_leaf_call(func) {
            NodeCategory::Leaf
        } else {
            NodeCategory::Middle
        };
    }
}

/// ---------------------------------------------------------------------------
//  Persistence round-trip
/// ---------------------------------------------------------------------------

#[test]
fn test_persistence_build_save_load_classify() {
    let temp_dir = std::env::temp_dir().join("calxgloss_integration_persist");
    let _ = std::fs::remove_dir_all(&temp_dir);
    std::fs::create_dir_all(&temp_dir).unwrap();

    let persistor = CallGraphPersistor::new(&temp_dir);

    // 1. Build graph (in memory).
    let graph = synthetic_graph();

    // 2. Save to disk.
    persistor.save(&graph).unwrap();

    // 3. Load from disk.
    let mut loaded = persistor.load("test.dll").unwrap();

    // 4. Classify the loaded graph.
    classify_graph(&mut loaded);

    // 5. Verify that the "main" function is still Middle (it calls helper,
    //    which is a leaf caller, but main itself does NOT directly call a
    //    known API).
    let main_func = loaded
        .functions
        .iter()
        .find(|f| f.name == "main")
        .expect("main should exist");
    assert_eq!(main_func.node_category, NodeCategory::Middle);

    // 6. "helper" directly calls Direct3DCreate9 and MessageBox, so it
    //    should be classified as Leaf.
    let helper_func = loaded
        .functions
        .iter()
        .find(|f| f.name == "helper")
        .expect("helper should exist");
    assert_eq!(helper_func.node_category, NodeCategory::Leaf);

    // 7. Verify leaf APIs for helper.
    let leaf_det = LeafDetector::new();
    let apis = leaf_det.classify(helper_func).expect("helper is a leaf");
    let api_names: Vec<_> = apis.iter().map(|s| &s.api_name).collect();
    assert!(api_names.contains(&&"Direct3DCreate9".to_string()));
    assert!(api_names.contains(&&"MessageBox".to_string()));

    // Cleanup.
    let _ = std::fs::remove_dir_all(&temp_dir);
}

/// ---------------------------------------------------------------------------
//  Root detection integration
/// ---------------------------------------------------------------------------

#[test]
fn test_root_detection_classifies_dllmain() {
    let temp_dir = std::env::temp_dir().join("calxgloss_integration_root");
    let _ = std::fs::remove_dir_all(&temp_dir);
    std::fs::create_dir_all(&temp_dir).unwrap();

    let persistor = CallGraphPersistor::new(&temp_dir);

    // Build a graph with a DllMain entry point.
    let graph = CallGraph {
        dll: "plugin.dll".to_string(),
        functions: vec![
            FunctionCallGraph {
                name: "DllMain".to_string(),
                address: 0x400000,
                callers: vec![],
                callees: vec![CallGraphEdge {
                    source: 0x400000,
                    target: 0x401000,
                    call_site: 0,
                    call_type: CallType::Direct,
                    callee_name: "plugin_init".to_string(),
                }],
                node_category: NodeCategory::Middle,
            },
            FunctionCallGraph {
                name: "plugin_init".to_string(),
                address: 0x401000,
                callers: vec![0x400000],
                callees: vec![],
                node_category: NodeCategory::Middle,
            },
        ],
    };

    persistor.save(&graph).unwrap();
    let mut loaded = persistor.load("plugin.dll").unwrap();
    classify_graph(&mut loaded);

    let dllmain = loaded
        .functions
        .iter()
        .find(|f| f.name == "DllMain")
        .expect("DllMain should exist");
    assert_eq!(dllmain.node_category, NodeCategory::Root);

    let _ = std::fs::remove_dir_all(&temp_dir);
}

/// ---------------------------------------------------------------------------
/// Full pipeline (requires Ghidra)
/// ---------------------------------------------------------------------------
/// End-to-end test: fetch functions from Ghidra, build graph, classify, persist.
///
/// Ignored by default because it requires a live GhidraMCP server with a
/// program open.  Run with:
///
/// ```text
/// CALXGLOSS_GHIDRA_URL=http://127.0.0.1:8080 \
///     cargo test -p calxgloss-callgraph --test integration_tests full_pipeline -- --ignored --nocapture
/// ```
#[tokio::test]
#[ignore = "needs a running GhidraMCP server with a program open"]
async fn test_full_pipeline_ghidra_to_persist() {
    let url = std::env::var("CALXGLOSS_GHIDRA_URL").expect("CALXGLOSS_GHIDRA_URL");
    let ghidra = calxgloss_ghidra::GhidraClient::new(&url).expect("connect to Ghidra");

    let functions = ghidra
        .list_functions()
        .await
        .expect("list_functions should succeed");
    assert!(
        !functions.is_empty(),
        "expected at least one function in the open program"
    );

    // Build the graph.
    let builder = calxgloss_callgraph::CallGraphBuilder::new(ghidra, "test.dll");
    let mut graph = builder.build().await.expect("build should succeed");

    // All functions should be present.
    assert_eq!(graph.functions.len(), functions.len());

    // Classify.
    classify_graph(&mut graph);

    // Verify no function is unclassified.
    for func in &graph.functions {
        assert!(
            matches!(
                func.node_category,
                NodeCategory::Root | NodeCategory::Leaf | NodeCategory::Middle
            ),
            "function {} has unclassified category",
            func.name
        );
    }

    // Persist and reload.
    let temp_dir = std::env::temp_dir().join("calxgloss_integration_pipeline");
    let _ = std::fs::remove_dir_all(&temp_dir);
    std::fs::create_dir_all(&temp_dir).unwrap();

    let persistor = CallGraphPersistor::new(&temp_dir);
    persistor.save(&graph).unwrap();
    let loaded = persistor.load("test.dll").unwrap();

    assert_eq!(loaded.functions.len(), graph.functions.len());
    assert_eq!(loaded.dll, graph.dll);

    let _ = std::fs::remove_dir_all(&temp_dir);
}

/// ---------------------------------------------------------------------------
//  Classifier round-trip consistency
/// ---------------------------------------------------------------------------

#[test]
fn test_classify_preserves_node_categories() {
    let temp_dir = std::env::temp_dir().join("calxgloss_integration_classify");
    let _ = std::fs::remove_dir_all(&temp_dir);
    std::fs::create_dir_all(&temp_dir).unwrap();

    let _persistor = CallGraphPersistor::new(&temp_dir);

    // Build a graph where every function should get a specific category.
    let mut graph = CallGraph {
        dll: "categories.dll".to_string(),
        functions: vec![
            // root: DllMain
            FunctionCallGraph {
                name: "DllMain".to_string(),
                address: 0x1000,
                callers: vec![],
                callees: vec![CallGraphEdge {
                    source: 0x1000,
                    target: 0x2000,
                    call_site: 0,
                    call_type: CallType::Direct,
                    callee_name: "app_init".to_string(),
                }],
                node_category: NodeCategory::Middle,
            },
            // leaf: calls MessageBox + CreateFile
            FunctionCallGraph {
                name: "app_init".to_string(),
                address: 0x2000,
                callers: vec![0x1000],
                callees: vec![
                    CallGraphEdge {
                        source: 0x2000,
                        target: 0x3000,
                        call_site: 0,
                        call_type: CallType::Direct,
                        callee_name: "MessageBox".to_string(),
                    },
                    CallGraphEdge {
                        source: 0x2000,
                        target: 0x3001,
                        call_site: 0,
                        call_type: CallType::Direct,
                        callee_name: "CreateFile".to_string(),
                    },
                ],
                node_category: NodeCategory::Middle,
            },
            // middle: calls nothing known
            FunctionCallGraph {
                name: "compute_hash".to_string(),
                address: 0x4000,
                callers: vec![0x2000],
                callees: vec![CallGraphEdge {
                    source: 0x4000,
                    target: 0x4010,
                    call_site: 0,
                    call_type: CallType::Direct,
                    callee_name: "rotate_left".to_string(),
                }],
                node_category: NodeCategory::Middle,
            },
            // middle: pure logic, no API calls
            FunctionCallGraph {
                name: "rotate_left".to_string(),
                address: 0x4010,
                callers: vec![0x4000],
                callees: vec![],
                node_category: NodeCategory::Middle,
            },
        ],
    };

    classify_graph(&mut graph);

    // Verify classifications.
    let mut by_name: HashMap<_, _> = graph
        .functions
        .into_iter()
        .map(|f| (f.name.clone(), f.node_category))
        .collect();

    assert_eq!(by_name.remove("DllMain"), Some(NodeCategory::Root));
    assert_eq!(by_name.remove("app_init"), Some(NodeCategory::Leaf));
    assert_eq!(by_name.remove("compute_hash"), Some(NodeCategory::Middle));
    assert_eq!(by_name.remove("rotate_left"), Some(NodeCategory::Middle));
    assert!(
        by_name.is_empty(),
        "all functions should be classified: remaining = {:?}",
        by_name
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

/// ---------------------------------------------------------------------------
//  Leaf detector multi-API classification
/// ---------------------------------------------------------------------------

#[test]
fn test_leaf_classify_returns_all_matched_categories() {
    let detector = LeafDetector::new();

    // Build a function that crosses multiple API categories.
    let func = FunctionCallGraph {
        name: "full_init".to_string(),
        address: 0x1000,
        callers: vec![],
        callees: vec![
            CallGraphEdge {
                source: 0x1000,
                target: 0,
                call_site: 0,
                call_type: CallType::Direct,
                callee_name: "CoInitialize".to_string(),
            },
            CallGraphEdge {
                source: 0x1000,
                target: 0,
                call_site: 0,
                call_type: CallType::Direct,
                callee_name: "WSAStartup".to_string(),
            },
            CallGraphEdge {
                source: 0x1000,
                target: 0,
                call_site: 0,
                call_type: CallType::Direct,
                callee_name: "CryptAcquireContext".to_string(),
            },
            CallGraphEdge {
                source: 0x1000,
                target: 0,
                call_site: 0,
                call_type: CallType::Direct,
                callee_name: "internal_init".to_string(),
            },
        ],
        node_category: NodeCategory::Middle,
    };

    let apis = detector.classify(&func).expect("should match 3 APIs");
    assert_eq!(apis.len(), 3);

    let categories: Vec<_> = apis.iter().map(|a| &a.category).collect();
    assert!(categories.contains(&&LeafCategory::Com));
    assert!(categories.contains(&&LeafCategory::Network));
    assert!(categories.contains(&&LeafCategory::Crypto));

    // The internal function should not be in the results.
    let names: Vec<_> = apis.iter().map(|a| a.api_name.as_str()).collect();
    assert!(!names.contains(&"internal_init"));
}
