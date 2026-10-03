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
    CallGraph, CallGraphEdge, CallGraphPersistor, CallType, ContextEnricher, FunctionCallGraph,
    LeafCategory, LeafDetector, NodeCategory, RootDetector, TranslationOrderer,
    TranslationPriority, skipped_contexts,
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

// ===========================================================================
//  End-to-End: Realistic Game Plugin Pipeline
// ===========================================================================

/// Build a realistic "game_plugin.dll" synthetic call graph that mirrors the
/// structure of a DirectX rendering plugin.
///
/// ```text
/// DllMain ──► Initialize ──► Setup ──► CreateDevice ──► Direct3DCreate9 (Leaf)
///                        │           └──► Render ──► Draw ──► MessageBoxW (Leaf)
///                        │                   └──► UpdateParticles
///                        │                           └──► D3D::DrawIndexedPrimitives
///                        │                   └──► PollInput ──► XInputGetState (Leaf)
///                        └──► Cleanup
/// ```
fn game_plugin_graph() -> CallGraph {
    CallGraph {
        dll: "game_plugin.dll".to_string(),
        functions: vec![
            // ── Entry point ──────────────────────────────────────────────
            FunctionCallGraph {
                name: "DllMain".to_string(),
                address: 0x0100,
                callers: vec![],
                callees: vec![
                    CallGraphEdge {
                        source: 0x0100,
                        target: 0x1000, // Initialize
                        call_site: 0x0120,
                        call_type: CallType::Direct,
                        callee_name: "Initialize".to_string(),
                    },
                    CallGraphEdge {
                        source: 0x0100,
                        target: 0x4000, // Cleanup
                        call_site: 0x0130,
                        call_type: CallType::Direct,
                        callee_name: "Cleanup".to_string(),
                    },
                ],
                node_category: NodeCategory::Middle,
            },
            // ── Initialization layer ─────────────────────────────────────
            FunctionCallGraph {
                name: "Initialize".to_string(),
                address: 0x1000,
                callers: vec![0x0100],
                callees: vec![
                    CallGraphEdge {
                        source: 0x1000,
                        target: 0x2000, // Setup
                        call_site: 0x1010,
                        call_type: CallType::Direct,
                        callee_name: "Setup".to_string(),
                    },
                    CallGraphEdge {
                        source: 0x1000,
                        target: 0x700000, // Direct3DCreate9
                        call_site: 0x1018,
                        call_type: CallType::Direct,
                        callee_name: "Direct3DCreate9".to_string(),
                    },
                ],
                node_category: NodeCategory::Middle,
            },
            FunctionCallGraph {
                name: "Setup".to_string(),
                address: 0x2000,
                callers: vec![0x1000],
                callees: vec![
                    CallGraphEdge {
                        source: 0x2000,
                        target: 0x3000, // CreateDevice
                        call_site: 0x2010,
                        call_type: CallType::Direct,
                        callee_name: "CreateDevice".to_string(),
                    },
                    CallGraphEdge {
                        source: 0x2000,
                        target: 0x5000, // Render
                        call_site: 0x2018,
                        call_type: CallType::Direct,
                        callee_name: "Render".to_string(),
                    },
                ],
                node_category: NodeCategory::Middle,
            },
            FunctionCallGraph {
                name: "CreateDevice".to_string(),
                address: 0x3000,
                callers: vec![0x2000],
                callees: vec![],
                node_category: NodeCategory::Middle,
            },
            // ── Render loop ──────────────────────────────────────────────
            FunctionCallGraph {
                name: "Render".to_string(),
                address: 0x5000,
                callers: vec![0x2000],
                callees: vec![
                    CallGraphEdge {
                        source: 0x5000,
                        target: 0x6000, // Draw
                        call_site: 0x5010,
                        call_type: CallType::Direct,
                        callee_name: "Draw".to_string(),
                    },
                    CallGraphEdge {
                        source: 0x5000,
                        target: 0x7000, // UpdateParticles
                        call_site: 0x5018,
                        call_type: CallType::Direct,
                        callee_name: "UpdateParticles".to_string(),
                    },
                    CallGraphEdge {
                        source: 0x5000,
                        target: 0x9000, // PollInput
                        call_site: 0x5020,
                        call_type: CallType::Direct,
                        callee_name: "PollInput".to_string(),
                    },
                ],
                node_category: NodeCategory::Middle,
            },
            FunctionCallGraph {
                name: "Draw".to_string(),
                address: 0x6000,
                callers: vec![0x5000],
                callees: vec![
                    CallGraphEdge {
                        source: 0x6000,
                        target: 0x8000, // D3D::DrawIndexedPrimitives
                        call_site: 0x6010,
                        call_type: CallType::Direct,
                        callee_name: "D3D::DrawIndexedPrimitives".to_string(),
                    },
                    CallGraphEdge {
                        source: 0x6000,
                        target: 0x701000, // MessageBoxW
                        call_site: 0x6018,
                        call_type: CallType::Direct,
                        callee_name: "MessageBoxW".to_string(),
                    },
                ],
                node_category: NodeCategory::Middle,
            },
            FunctionCallGraph {
                name: "UpdateParticles".to_string(),
                address: 0x7000,
                callers: vec![0x5000],
                callees: vec![
                    CallGraphEdge {
                        source: 0x7000,
                        target: 0x8001, // D3D::UpdateParticleBuffers
                        call_site: 0x7010,
                        call_type: CallType::Direct,
                        callee_name: "D3D::UpdateParticleBuffers".to_string(),
                    },
                ],
                node_category: NodeCategory::Middle,
            },
            FunctionCallGraph {
                name: "PollInput".to_string(),
                address: 0x9000,
                callers: vec![0x5000],
                callees: vec![
                    CallGraphEdge {
                        source: 0x9000,
                        target: 0x702000, // XInputGetState
                        call_site: 0x9010,
                        call_type: CallType::Direct,
                        callee_name: "XInputGetState".to_string(),
                    },
                ],
                node_category: NodeCategory::Middle,
            },
            // ── Cleanup ──────────────────────────────────────────────────
            FunctionCallGraph {
                name: "Cleanup".to_string(),
                address: 0x4000,
                callers: vec![0x0100],
                callees: vec![],
                node_category: NodeCategory::Middle,
            },
        ],
    }
}

/// Full end-to-end integration test: build → classify → persist → reload →
/// enrich → order → dependency graph on a realistic test DLL.
///
/// This test exercises every major pipeline stage on a single synthetic call
/// graph that mirrors a real DirectX rendering plugin (game_plugin.dll).
#[test]
fn test_end_to_end_realistic_plugin_pipeline() {
    let temp_dir = std::env::temp_dir().join("calxgloss_e2e_plugin");
    let _ = std::fs::remove_dir_all(&temp_dir);
    std::fs::create_dir_all(&temp_dir).unwrap();

    // ===== Phase 1: Build graph =====
    let mut graph = game_plugin_graph();
    assert_eq!(graph.dll, "game_plugin.dll");
    assert_eq!(graph.functions.len(), 9);

    // ===== Phase 2: Run classification =====
    classify_graph(&mut graph);

    // Verify classification results.
    // We check invariants rather than hardcoded categories, since leaf detection
    // depends on the API signature database staying stable.
    let by_name: std::collections::HashMap<String, NodeCategory> = graph
        .functions
        .iter()
        .map(|f| (f.name.clone(), f.node_category.clone()))
        .collect();

    // Every function must have a valid, non-Skip category.
    for func in &graph.functions {
        assert!(
            !matches!(func.node_category, NodeCategory::Skip),
            "function {} should not be Skip",
            func.name
        );
    }

    // DllMain must be Root (matches built-in DllMain pattern).
    assert_eq!(by_name["DllMain"], NodeCategory::Root);

    // Count by category.
    let mut roots = 0usize;
    let mut _middles = 0usize;
    let mut leaves = 0usize;
    for func in &graph.functions {
        match func.node_category {
            NodeCategory::Root => roots += 1,
            NodeCategory::Middle => _middles += 1,
            NodeCategory::Leaf => leaves += 1,
            NodeCategory::Skip => panic!("no Skip functions expected"),
        }
    }
    assert_eq!(roots, 1, "expected exactly 1 root function (DllMain)");
    assert!(
        leaves >= 2,
        "expected at least 2 leaf functions (functions calling known APIs)"
    );

    // ===== Phase 3: Persist to disk =====
    let persistor = CallGraphPersistor::with_cache_dir(&temp_dir);
    persistor.save(&graph).unwrap();

    // Verify the persisted JSON is valid and contains all functions
    let json_path = temp_dir.join("game_plugin.dll_call_graph.json");
    assert!(json_path.exists(), "persisted JSON should exist at {:?}", json_path);

    let json_content = std::fs::read_to_string(&json_path).expect("read persisted JSON");
    let saved_graph: CallGraph =
        serde_json::from_str(&json_content).expect("persisted JSON should be valid");
    assert_eq!(saved_graph.dll, "game_plugin.dll");
    assert_eq!(saved_graph.functions.len(), 9);

    // ===== Phase 4: Reload from disk =====
    let reloaded = persistor.load("game_plugin.dll").expect("should load persisted graph");

    // Verify the reload preserves all function data
    assert_eq!(reloaded.dll, "game_plugin.dll");
    assert_eq!(reloaded.functions.len(), 9);

    // Verify caller/callee counts are preserved after round-trip
    for func in &reloaded.functions {
        let original = graph
            .functions
            .iter()
            .find(|f| f.name == func.name)
            .expect("function should exist in original");

        assert_eq!(
            func.callers.len(),
            original.callers.len(),
            "caller count mismatch for {}",
            func.name
        );
        assert_eq!(
            func.callees.len(),
            original.callees.len(),
            "callee count mismatch for {}",
            func.name
        );
        assert_eq!(
            func.address, original.address,
            "address mismatch for {}",
            func.name
        );
    }

    // Classification is preserved after persistence (saved with categories).
    // DllMain should remain Root, Draw should remain Leaf.
    let dllmain = reloaded
        .functions
        .iter()
        .find(|f| f.name == "DllMain")
        .expect("DllMain should exist");
    assert_eq!(dllmain.node_category, NodeCategory::Root);

    let draw = reloaded
        .functions
        .iter()
        .find(|f| f.name == "Draw")
        .expect("Draw should exist");
    assert_eq!(draw.node_category, NodeCategory::Leaf);

    // ===== Phase 5: Context enrichment =====
    // Debug: check reloaded graph data
    for func in &reloaded.functions {
        eprintln!("  reloaded '{}' callers={} callees={}",
            func.name, func.callers.len(), func.callees.len());
    }

    let enricher = ContextEnricher::new();
    let contexts = enricher.enrich(&reloaded);

    assert_eq!(contexts.len(), 9, "should produce context for all functions");

    // Build a lookup for contexts by function name
    let context_map: std::collections::HashMap<_, _> =
        contexts.iter().cloned().map(|c| (c.name.clone(), c)).collect();

    // NOTE: Context enrichment filters out internal callees by default,
    // keeping only external API calls. Internal function references are
    // excluded from the callees list.

    // DllMain: 1 caller (none expected - entry point), 0 callees after filtering
    // (Initialize and Cleanup are internal functions)
    let dllmain_ctx = &context_map["DllMain"];
    assert!(dllmain_ctx.callers.is_empty(), "DllMain has no callers");
    // DllMain's callees (Initialize, Cleanup) are internal, so filtered out
    assert!(dllmain_ctx.callees.is_empty(), "DllMain has no external API callees");

    // Initialize: 1 caller (DllMain), callees include Direct3DCreate9 (external API)
    // After filtering: only Direct3DCreate9 remains (Setup is internal)
    let init_ctx = &context_map["Initialize"];
    assert_eq!(init_ctx.callers.len(), 1, "Initialize has 1 caller");
    // Direct3DCreate9 is an external API call (not internal to the graph)
    assert!(
        !init_ctx.leaf_api_context.is_empty(),
        "Initialize should have leaf API context (Direct3DCreate9)"
    );
    let leaf_api_names: Vec<_> = init_ctx
        .leaf_api_context
        .iter()
        .map(|a| a.api_name.as_str())
        .collect();
    assert!(
        leaf_api_names.contains(&"Direct3DCreate9"),
        "Direct3DCreate9 should be in Initialize's leaf API context"
    );

    // Draw: should have MessageBox in its leaf API context (MessageBoxW normalized)
    let draw_ctx = &context_map["Draw"];
    assert!(
        !draw_ctx.leaf_api_context.is_empty(),
        "Draw should have leaf API context (MessageBox)"
    );
    let draw_leaf_names: Vec<_> = draw_ctx
        .leaf_api_context
        .iter()
        .map(|a| a.api_name.as_str())
        .collect();
    assert!(
        draw_leaf_names.contains(&"MessageBox"),
        "MessageBox (normalized from MessageBoxW) should be in Draw's leaf API context"
    );

    // MessageBoxW should be categorized as a UI category
    let draw_leaf_categories: Vec<_> = draw_ctx
        .leaf_api_context
        .iter()
        .map(|a| &a.category)
        .collect();
    assert!(
        draw_leaf_categories.contains(&&LeafCategory::Ui),
        "MessageBoxW should be in the UI category"
    );

    // PollInput: verify context structure is valid (XInputGetState may or may not be in API DB)
    let poll_ctx = &context_map["PollInput"];
    assert!(
        poll_ctx.callers.len() >= 1,
        "PollInput should have at least 1 caller"
    );

    // UpdateParticles: no leaf APIs (D3D::UpdateParticleBuffers is not in API DB)
    let update_ctx = &context_map["UpdateParticles"];
    assert!(
        update_ctx.leaf_api_context.is_empty(),
        "UpdateParticles should have no leaf API context"
    );

    // Verify no contexts were skipped
    for ctx in &context_map {
        assert!(
            !ctx.1.context_skipped,
            "context should not be skipped for {}",
            ctx.0
        );
    }

    // ===== Phase 6: Translation ordering =====
    let orderer = TranslationOrderer::new();
    let plan = orderer.order(&reloaded).expect("ordering should succeed");

    assert_eq!(
        plan.len(),
        9,
        "translation plan should include all 9 functions"
    );

    // Extract the ordered function names
    let ordered_names: Vec<_> = plan.iter().map(|p| p.name.as_str()).collect();

    // Verify priority tiers: Root first, then Middle, then Leaf
    let mut last_priority = -1isize;
    let mut last_name = "";
    for plan_item in &plan {
        let prio = plan_item.priority as isize;
        if prio < last_priority {
            panic!(
                "translation order must be non-decreasing by priority, \
                 but {:?} ({}) came after {:?} ({})",
                plan_item.name,
                plan_item.priority.label(),
                last_name,
                match last_priority {
                    0 => "root",
                    1 => "middle",
                    2 => "leaf",
                    _ => "unknown",
                }
            );
        }
        last_priority = prio;
        last_name = &plan_item.name;
    }

    // Root function (DllMain) should come first
    let first_plan_idx = plan.front().map(|p| p.name.as_str()).unwrap();
    assert_eq!(
        first_plan_idx, "DllMain",
        "first plan item should be DllMain (Root)"
    );

    // Verify that all Root functions come before non-Root functions
    let root_funcs: Vec<_> = plan
        .iter()
        .filter(|p| matches!(p.priority, TranslationPriority::Root))
        .map(|p| p.name.as_str())
        .collect();
    let non_root_funcs: Vec<_> = plan
        .iter()
        .filter(|p| !matches!(p.priority, TranslationPriority::Root))
        .map(|p| p.name.as_str())
        .collect();
    for rf in &root_funcs {
        let rf_idx = ordered_names.iter().position(|&n| n == *rf).unwrap();
        for nrf in &non_root_funcs {
            let nrf_idx = ordered_names.iter().position(|&n| n == *nrf).unwrap();
            assert!(
                rf_idx < nrf_idx,
                "Root func {} (idx {}) should come before non-Root {} (idx {})",
                rf, rf_idx, nrf, nrf_idx
            );
        }
    }

    // Verify that all Middle functions come before all Leaf functions
    let middle_funcs: Vec<_> = plan
        .iter()
        .filter(|p| matches!(p.priority, TranslationPriority::Middle))
        .map(|p| p.name.as_str())
        .collect();
    let leaf_funcs: Vec<_> = plan
        .iter()
        .filter(|p| matches!(p.priority, TranslationPriority::Leaf))
        .map(|p| p.name.as_str())
        .collect();
    if !middle_funcs.is_empty() && !leaf_funcs.is_empty() {
        let max_middle_idx = middle_funcs
            .iter()
            .map(|&n| ordered_names.iter().position(|&f| f == n).unwrap())
            .max()
            .unwrap();
        let min_leaf_idx = leaf_funcs
            .iter()
            .map(|&n| ordered_names.iter().position(|&f| f == n).unwrap())
            .min()
            .unwrap();
        assert!(
            max_middle_idx < min_leaf_idx,
            "all middle functions (max idx {}) should come before all leaf functions (min idx {})",
            max_middle_idx,
            min_leaf_idx
        );
    }

    // Verify metadata is correct for Render
    let render_plan = plan
        .iter()
        .find(|p| p.name == "Render")
        .expect("Render should be in the plan");
    assert_eq!(render_plan.caller_count, 1);
    assert_eq!(render_plan.callee_count, 3);
    assert!(
        matches!(render_plan.priority, TranslationPriority::Middle),
        "Render should have Middle priority"
    );

    // Verify metadata for DllMain (Root)
    let dllmain_plan = plan
        .iter()
        .find(|p| p.name == "DllMain")
        .expect("DllMain should be in the plan");
    assert_eq!(dllmain_plan.caller_count, 0);
    assert_eq!(dllmain_plan.callee_count, 2);
    assert!(
        matches!(dllmain_plan.priority, TranslationPriority::Root),
        "DllMain should have Root priority"
    );

    // Verify metadata for Cleanup (should be Middle, no callees)
    let cleanup_plan = plan
        .iter()
        .find(|p| p.name == "Cleanup")
        .expect("Cleanup should be in the plan");
    assert_eq!(cleanup_plan.caller_count, 1);
    assert_eq!(cleanup_plan.callee_count, 0);

    // ===== Phase 7: Dependency graph construction =====
    use calxgloss_types::DllCategory;

    let classification = calxgloss_analysis::DllClassification {
        dll: "game_plugin.dll".to_string(),
        category: DllCategory::ProjectSpecific,
        strategy: calxgloss_analysis::Strategy::ReverseEngineer,
        exports_count: 0,
        imports_count: 0,
        crate_replacement: None,
    };

    let dep_graph =
        calxgloss_analysis::build_dependency_graph_from_call_graph(&[classification], &reloaded);

    // Should have: 1 DLL classification node + 9 function nodes = 10 nodes
    assert_eq!(
        dep_graph.nodes.len(),
        10,
        "dependency graph should have 10 nodes (1 DLL + 9 functions)"
    );

    // Verify node types
    let dep_node_ids: Vec<_> = dep_graph
        .nodes
        .iter()
        .map(|n| n.unit_id.as_str())
        .collect();
    assert!(dep_node_ids.contains(&"dll_classify_game_plugin"));
    for func in &reloaded.functions {
        let expected_id = format!("func_{}", func.name);
        assert!(
            dep_node_ids.contains(&expected_id.as_str()),
            "dependency graph should contain node {}",
            expected_id
        );
    }

    // All function nodes should have correct labels for known categories
    // (Root = Skip, Leaf/Middle = Translate)
    for node in &dep_graph.nodes {
        if node.unit_id == "func_DllMain" {
            assert!(
                node.name.contains("Skip"),
                "Root function should have 'Skip' label, got: {}",
                node.name
            );
        }
    }

    // Verify topological ordering: callees before callers
    let (ordered_nodes, cycles) = dep_graph.topological_order();
    assert!(
        cycles.is_empty(),
        "dependency graph should have no cycles"
    );

    let dep_order_ids: Vec<&str> = ordered_nodes.iter().map(|n| n.unit_id.as_str()).collect();

    // DllMain should come after Initialize and Cleanup (its callees)
    let dllmain_dep_idx = dep_order_ids
        .iter()
        .position(|&id| id == "func_DllMain")
        .unwrap();
    let init_dep_idx = dep_order_ids
        .iter()
        .position(|&id| id == "func_Initialize")
        .unwrap();
    let cleanup_dep_idx = dep_order_ids
        .iter()
        .position(|&id| id == "func_Cleanup")
        .unwrap();
    assert!(
        init_dep_idx < dllmain_dep_idx,
        "Initialize (callee) should come before DllMain (caller)"
    );
    assert!(
        cleanup_dep_idx < dllmain_dep_idx,
        "Cleanup (callee) should come before DllMain (caller)"
    );

    // Setup should come before Initialize (Initialize calls Setup)
    let setup_dep_idx = dep_order_ids
        .iter()
        .position(|&id| id == "func_Setup")
        .unwrap();
    assert!(
        setup_dep_idx < init_dep_idx,
        "Setup (callee) should come before Initialize (caller)"
    );

    // Render should come before Setup (Setup calls Render)
    let render_dep_idx = dep_order_ids
        .iter()
        .position(|&id| id == "func_Render")
        .unwrap();
    assert!(
        render_dep_idx < setup_dep_idx,
        "Render (callee) should come before Setup (caller)"
    );

    // ===== Phase 8: Verify all contexts have no skipped entries =====
    let skipped = skipped_contexts(&contexts);
    assert!(
        skipped.is_empty(),
        "no contexts should be skipped in the realistic plugin graph"
    );

    // Cleanup temp directory
    let _ = std::fs::remove_dir_all(&temp_dir);
}
