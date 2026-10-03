//! Call graph enrichment and dependency graph construction.
//!
//! This module bridges [`calxgloss_callgraph`] and the analysis pipeline:
//!
//! 1. **Enrichment** — builds a call graph from Ghidra data, classifies each
//!    function as [`Root`](calxgloss_types::NodeCategory::Root),
//!    [`Leaf`](calxgloss_types::NodeCategory::Leaf), or
//!    [`Middle`](calxgloss_types::NodeCategory::Middle), and persists it to
//!    JSON.
//!
//! 2. **Dependency graph construction** — converts the persisted call graph
//!    into a [`DependencyGraph`](calxgloss_types::DependencyGraph) for the
//!    translation work queue.
//!
//! # Example
//!
//! ```no_run
//! use calxgloss_analysis::build_enriched_call_graph;
//! use calxgloss_ghidra::GhidraClient;
//! use std::path::Path;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let ghidra = GhidraClient::new("http://localhost:8080")?;
//!
//! let graph = build_enriched_call_graph(&ghidra, "eqmain.dll", Path::new("/workspace")).await?;
//!
//! for func in &graph.functions {
//!     println!("{}: {:?}", func.name, func.node_category);
//! }
//! # Ok(())
//! # }
//! ```

use calxgloss_callgraph::{
    CallGraphBuilder, CallGraphPersistor, LeafDetector, RootDetector,
};
use calxgloss_ghidra::GhidraClient;
use calxgloss_types::{
    DependencyEdge, DependencyGraph, DependencyNode, NodeCategory, ReviewStatus,
    dashboard::WorkUnitLevel,
};
use tracing::info;

// ============================================================
// Call graph enrichment
// ============================================================

/// Builds, classifies, and persists a call graph for a single DLL.
///
/// This is the primary integration point between the call graph analysis
/// pipeline and the rest of the system. It:
///
/// 1. Fetches all function metadata from Ghidra via [`CallGraphBuilder`].
/// 2. Classifies each function using [`RootDetector`] and [`LeafDetector`].
/// 3. Updates each function's [`NodeCategory`].
/// 4. Persists the enriched graph to `re/analysis/{dll}_call_graph.json`.
///
/// # Arguments
///
/// * `ghidra` — The Ghidra client used to fetch function data.
/// * `dll_name` — The DLL filename (e.g., `"eqmain.dll"`).
/// * `workspace_root` — The workspace root directory for persistence.
///
/// # Returns
///
/// A fully classified [`calxgloss_callgraph::CallGraph`], or an error if
/// Ghidra data cannot be fetched or the graph cannot be persisted.
///
/// # Graceful degradation
///
/// If a single function's decompilation fails, it is included with an empty
/// callee list. If all decompilations fail, the graph still completes with
/// empty callee lists for every function.
///
/// # TODOs
///
/// ```text
/// TODO: Cache CallGraphBuilder results to avoid rebuilding on every analysis run
/// TODO: Add call graph analysis as a separate pipeline phase (Phase 1.5)
/// TODO: Make call graph analysis optional via config flag
/// TODO: Integrate with dependency tracker: use NodeCategory for translation ordering
/// TODO: Add call graph data to `FunctionAnalysis` struct (callers, callees with metadata)
/// ```
pub async fn build_enriched_call_graph(
    ghidra: &GhidraClient,
    dll_name: &str,
    workspace_root: &std::path::Path,
) -> anyhow::Result<calxgloss_callgraph::CallGraph> {
    info!(%dll_name, "Building enriched call graph");

    // 1. Build the call graph from Ghidra data.
    let builder = CallGraphBuilder::new(ghidra.clone(), dll_name);
    let mut graph = builder.build().await?;

    // 2. Classify each function.
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

    let func_count = graph.functions.len();
    let root_count = graph
        .functions
        .iter()
        .filter(|f| matches!(f.node_category, NodeCategory::Root))
        .count();
    let leaf_count = graph
        .functions
        .iter()
        .filter(|f| matches!(f.node_category, NodeCategory::Leaf))
        .count();

    info!(
        %dll_name,
        func_count,
        root_count,
        leaf_count,
        middle_count = func_count - root_count - leaf_count,
        "Classified call graph"
    );

    // 3. Persist to disk.
    let persistor = CallGraphPersistor::new(workspace_root);
    persistor.save(&graph)?;

    info!(%dll_name, "Saved enriched call graph");

    Ok(graph)
}

/// Loads a persisted call graph from the workspace.
///
/// Returns `None` if the graph file does not exist or fails to parse.
/// This allows callers to decide whether a missing graph is acceptable.
pub fn load_call_graph(
    workspace_root: &std::path::Path,
    dll_name: &str,
) -> Option<calxgloss_callgraph::CallGraph> {
    let persistor = CallGraphPersistor::new(workspace_root);
    persistor.load(dll_name).ok()
}

// ============================================================
// Dependency graph construction from call graph
// ============================================================

/// Builds a [`DependencyGraph`] from DLL classifications and a call graph.
///
/// This is the dependency tracker integration point: it converts the structured
/// call graph (with node categories, callers, and callees) into a flat DAG
/// suitable for the translation work queue.
///
/// # Arguments
///
/// * `classifications` — DLL classifications from the analysis pipeline.
/// * `call_graph` — A structured call graph with node categories.
///
/// # Returns
///
/// A [`DependencyGraph`] where:
/// - DLL classification nodes are roots
/// - Shim layer nodes depend on their DLL
/// - Function nodes depend on their shim (if crate-replacement) or DLL
///   classification, plus their call graph neighbors
///
/// Root and leaf functions are included in the graph with their category
/// attached to the node metadata.
///
/// # TODOs
///
/// ```text
/// TODO: Add priority weighting: functions with more callers get higher priority within tier
/// TODO: Add cycle detection and resolution (break cycles by picking lowest-address function)
/// TODO: Add streaming: emit plans as functions are classified, don't wait for full graph
/// TODO: Add batch ordering: group functions by DLL for batch translation
/// TODO: Add configurable priority inversion (user can override via config)
/// ```
pub fn build_dependency_graph_from_call_graph(
    classifications: &[crate::DllClassification],
    call_graph: &calxgloss_callgraph::CallGraph,
) -> DependencyGraph {
    let mut graph = DependencyGraph {
        nodes: Vec::new(),
        edges: Vec::new(),
    };

    // ── Phase 1: Build a map of DLL classifications for quick lookup ──

    let mut dll_node_ids: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();

    for cls in classifications {
        if cls.dll == call_graph.dll {
            let node_id = helpers::dll_node_id(&cls.dll);
            graph.nodes.push(DependencyNode::with_level(
                node_id.clone(),
                format!("Classify {}", cls.dll),
                ReviewStatus::Queued,
                WorkUnitLevel::DllClassification,
            ));
            dll_node_ids.insert(cls.dll.clone(), node_id);
        }
    }

    // If no classification exists for this DLL, create a default one
    if !dll_node_ids.contains_key(&call_graph.dll) {
        let node_id = helpers::dll_node_id(&call_graph.dll);
        graph.nodes.push(DependencyNode::with_level(
            node_id.clone(),
            format!("Classify {}", call_graph.dll),
            ReviewStatus::Queued,
            WorkUnitLevel::DllClassification,
        ));
        dll_node_ids.insert(call_graph.dll.clone(), node_id);
    }

    // ── Phase 2: Add shim layer node if applicable ──

    let mut shim_node_id: Option<String> = None;

    for cls in classifications {
        if cls.dll == call_graph.dll {
            if let crate::Strategy::CrateReplacement { crate_name } = &cls.strategy {
                let shim_id = helpers::shim_node_id(&cls.dll, crate_name);
                graph.nodes.push(DependencyNode::with_level(
                    shim_id.clone(),
                    format!("Shim {} → {}", cls.dll, crate_name),
                    ReviewStatus::Queued,
                    WorkUnitLevel::ShimLayer,
                ));
                graph.edges.push(DependencyEdge {
                    from: shim_id.clone(),
                    to: dll_node_ids[&cls.dll].clone(),
                });
                shim_node_id = Some(shim_id);
            }
            break;
        }
    }

    // ── Phase 3: Add function nodes and edges ──

    let mut function_node_ids: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();

    for func in &call_graph.functions {
        let func_id = helpers::func_node_id(&func.name);
        let label = match func.node_category {
            NodeCategory::Root => format!("Skip {}", func.name),
            NodeCategory::Leaf => format!("Translate {}", func.name),
            NodeCategory::Middle => format!("Translate {}", func.name),
            NodeCategory::Skip => format!("Skip {}", func.name),
        };
        graph.nodes.push(DependencyNode::new(
            func_id.clone(),
            label,
            ReviewStatus::Queued,
        ));
        function_node_ids.insert(func.name.clone(), func_id);
    }

    // ── Phase 4: Add function dependency edges ──

    // Depend on shim layer or DLL classification
    if let Some(ref shim_id) = shim_node_id {
        for func_id in function_node_ids.values() {
            graph.edges.push(DependencyEdge {
                from: func_id.clone(),
                to: shim_id.clone(),
            });
        }
    } else {
        let dll_id = &dll_node_ids[&call_graph.dll];
        for func_id in function_node_ids.values() {
            graph.edges.push(DependencyEdge {
                from: func_id.clone(),
                to: dll_id.clone(),
            });
        }
    }

    // Depend on call graph neighbors (callees only — caller edges would create
    // cycles since they go in the opposite direction of the callee edges)
    for func in &call_graph.functions {
        let func_id = &function_node_ids[&func.name];

        // Edges to callees
        for edge in &func.callees {
            // Try to find the callee's function node by address
            if let Some(callee_name) =
                helpers::find_function_by_address(call_graph, edge.target)
                && let Some(callee_id) = function_node_ids.get(callee_name)
            {
                graph.edges.push(DependencyEdge {
                    from: func_id.clone(),
                    to: callee_id.clone(),
                });
            }
        }
    }

    graph
}

/// Helper utilities for dependency graph construction from call graph data.
mod helpers {
    /// Returns the node ID for a DLL classification unit.
    pub fn dll_node_id(dll: &str) -> String {
        format!("dll_classify_{}", base_name(dll))
    }

    /// Returns the node ID for a shim layer unit.
    pub fn shim_node_id(dll: &str, crate_name: &str) -> String {
        format!(
            "shim_{}_{}",
            base_name(dll),
            crate_name.replace(['-', '.', '/'], "_")
        )
    }

    /// Returns the node ID for a function translation unit.
    pub fn func_node_id(function: &str) -> String {
        format!("func_{}", function)
    }

    /// Strips the `.dll` extension and lowercases the name.
    pub fn base_name(dll: &str) -> String {
        dll.trim()
            .to_lowercase()
            .strip_suffix(".dll")
            .unwrap_or(dll)
            .to_string()
    }

    /// Finds the function name by entry address in a call graph.
    pub fn find_function_by_address(
        call_graph: &calxgloss_callgraph::CallGraph,
        address: u64,
    ) -> Option<&str> {
        call_graph
            .functions
            .iter()
            .find(|f| f.address == address)
            .map(|f| f.name.as_str())
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use calxgloss_callgraph::{CallGraphEdge, CallType, FunctionCallGraph, NodeCategory};
    use calxgloss_types::DllCategory;

    use crate::{DllClassification, Strategy};

    fn test_classification(
        dll: &str,
        category: DllCategory,
        crate_name: Option<&str>,
    ) -> DllClassification {
        let strategy = match crate_name {
            Some(name) => Strategy::CrateReplacement {
                crate_name: name.to_string(),
            },
            None => Strategy::ReverseEngineer,
        };
        DllClassification {
            dll: dll.to_string(),
            category,
            strategy,
            exports_count: 0,
            imports_count: 0,
            crate_replacement: crate_name.map(|s| s.to_string()),
        }
    }

    fn make_call_graph(dll: &str, functions: Vec<FunctionCallGraph>) -> calxgloss_callgraph::CallGraph {
        calxgloss_callgraph::CallGraph {
            dll: dll.to_string(),
            functions,
        }
    }

    // ── Dependency graph construction tests ──

    #[test]
    fn build_dependency_graph_from_simple_call_graph() {
        let classifications = vec![test_classification(
            "game_logic.dll",
            DllCategory::ProjectSpecific,
            None,
        )];

        let call_graph = make_call_graph(
            "game_logic.dll",
            vec![
                FunctionCallGraph {
                    name: "UpdatePlayer".to_string(),
                    address: 0x1000,
                    callers: vec![0x2000],
                    callees: vec![CallGraphEdge {
                        source: 0x1000,
                        target: 0x2000,
                        call_site: 0,
                        call_type: CallType::Direct,
                        callee_name: "UpdateAI".to_string(),
                    }],
                    node_category: NodeCategory::Middle,
                },
                FunctionCallGraph {
                    name: "UpdateAI".to_string(),
                    address: 0x2000,
                    callers: vec![0x1000],
                    callees: vec![],
                    node_category: NodeCategory::Middle,
                },
            ],
        );

        let graph = build_dependency_graph_from_call_graph(&classifications, &call_graph);

        // Nodes: 1 DLL classification + 2 functions
        assert_eq!(graph.nodes.len(), 3);

        // Check node types
        let node_ids: Vec<_> = graph.nodes.iter().map(|n| n.unit_id.as_str()).collect();
        assert!(node_ids.contains(&"dll_classify_game_logic"));
        assert!(node_ids.contains(&"func_UpdatePlayer"));
        assert!(node_ids.contains(&"func_UpdateAI"));

        // Each function depends on the DLL classification
        assert!(
            graph
                .edges
                .iter()
                .any(|e| e.from == "func_UpdatePlayer" && e.to == "dll_classify_game_logic")
        );
        assert!(
            graph
                .edges
                .iter()
                .any(|e| e.from == "func_UpdateAI" && e.to == "dll_classify_game_logic")
        );

        // UpdatePlayer depends on UpdateAI (UpdatePlayer calls UpdateAI)
        assert!(
            graph
                .edges
                .iter()
                .any(|e| e.from == "func_UpdatePlayer" && e.to == "func_UpdateAI")
        );
    }

    #[test]
    fn build_dependency_graph_with_shim_layer() {
        let classifications = vec![test_classification(
            "d3d9.dll",
            DllCategory::MicrosoftSdk,
            Some("wgpu"),
        )];

        let call_graph = make_call_graph(
            "d3d9.dll",
            vec![FunctionCallGraph {
                name: "DrawPrimitive".to_string(),
                address: 0x1000,
                callers: vec![],
                callees: vec![],
                node_category: NodeCategory::Middle,
            }],
        );

        let graph = build_dependency_graph_from_call_graph(&classifications, &call_graph);

        // Nodes: 1 DLL classification + 1 shim + 1 function
        assert_eq!(graph.nodes.len(), 3);

        // Edges: shim → DLL, function → shim
        assert!(
            graph
                .edges
                .iter()
                .any(|e| e.from == "shim_d3d9_wgpu" && e.to == "dll_classify_d3d9")
        );
        assert!(
            graph
                .edges
                .iter()
                .any(|e| e.from == "func_DrawPrimitive" && e.to == "shim_d3d9_wgpu")
        );
    }

    #[test]
    fn build_dependency_graph_root_function() {
        let classifications = vec![test_classification(
            "game_logic.dll",
            DllCategory::ProjectSpecific,
            None,
        )];

        let call_graph = make_call_graph(
            "game_logic.dll",
            vec![FunctionCallGraph {
                name: "WinMain".to_string(),
                address: 0x401000,
                callers: vec![],
                callees: vec![],
                node_category: NodeCategory::Root,
            }],
        );

        let graph = build_dependency_graph_from_call_graph(&classifications, &call_graph);

        // Root function node should have "Skip" in its label
        let winmain_node = graph
            .nodes
            .iter()
            .find(|n| n.unit_id == "func_WinMain")
            .expect("WinMain node should exist");
        assert!(winmain_node.name.contains("Skip"));
    }

    #[test]
    fn build_dependency_graph_leaf_function() {
        let classifications = vec![test_classification(
            "game_logic.dll",
            DllCategory::ProjectSpecific,
            None,
        )];

        let call_graph = make_call_graph(
            "game_logic.dll",
            vec![FunctionCallGraph {
                name: "InitGraphics".to_string(),
                address: 0x5000,
                callers: vec![],
                callees: vec![CallGraphEdge {
                    source: 0x5000,
                    target: 0x78000000,
                    call_site: 0,
                    call_type: CallType::Direct,
                    callee_name: "Direct3DCreate9".to_string(),
                }],
                node_category: NodeCategory::Leaf,
            }],
        );

        let graph = build_dependency_graph_from_call_graph(&classifications, &call_graph);

        let init_node = graph
            .nodes
            .iter()
            .find(|n| n.unit_id == "func_InitGraphics")
            .expect("InitGraphics node should exist");
        // Leaf functions still get "Translate" label
        assert!(init_node.name.contains("Translate"));
    }

    #[test]
    fn build_dependency_graph_no_classification_for_dll() {
        let classifications: Vec<DllClassification> = vec![];

        let call_graph = make_call_graph(
            "unknown.dll",
            vec![FunctionCallGraph {
                name: "SomeFunction".to_string(),
                address: 0x1000,
                callers: vec![],
                callees: vec![],
                node_category: NodeCategory::Middle,
            }],
        );

        let graph = build_dependency_graph_from_call_graph(&classifications, &call_graph);

        // Should still create a default DLL classification node
        assert_eq!(graph.nodes.len(), 2);
        let node_ids: Vec<_> = graph.nodes.iter().map(|n| n.unit_id.as_str()).collect();
        assert!(node_ids.contains(&"dll_classify_unknown"));
        assert!(node_ids.contains(&"func_SomeFunction"));
    }

    #[test]
    fn build_dependency_graph_empty_call_graph() {
        let classifications = vec![test_classification(
            "empty.dll",
            DllCategory::ProjectSpecific,
            None,
        )];

        let call_graph = make_call_graph("empty.dll", vec![]);

        let graph = build_dependency_graph_from_call_graph(&classifications, &call_graph);

        // Only DLL classification node
        assert_eq!(graph.nodes.len(), 1);
        assert!(graph.edges.is_empty());
    }

    #[test]
    fn dependency_graph_respects_topological_order() {
        let classifications = vec![test_classification(
            "game_logic.dll",
            DllCategory::ProjectSpecific,
            None,
        )];

        // A → B → C (A calls B, B calls C)
        let call_graph = make_call_graph(
            "game_logic.dll",
            vec![
                FunctionCallGraph {
                    name: "A".to_string(),
                    address: 0x1000,
                    callers: vec![],
                    callees: vec![CallGraphEdge {
                        source: 0x1000,
                        target: 0x2000,
                        call_site: 0,
                        call_type: CallType::Direct,
                        callee_name: "B".to_string(),
                    }],
                    node_category: NodeCategory::Middle,
                },
                FunctionCallGraph {
                    name: "B".to_string(),
                    address: 0x2000,
                    callers: vec![0x1000],
                    callees: vec![CallGraphEdge {
                        source: 0x2000,
                        target: 0x3000,
                        call_site: 0,
                        call_type: CallType::Direct,
                        callee_name: "C".to_string(),
                    }],
                    node_category: NodeCategory::Middle,
                },
                FunctionCallGraph {
                    name: "C".to_string(),
                    address: 0x3000,
                    callers: vec![0x2000],
                    callees: vec![],
                    node_category: NodeCategory::Middle,
                },
            ],
        );

        let graph = build_dependency_graph_from_call_graph(&classifications, &call_graph);
        let (ordered, cycles) = graph.topological_order();
        assert!(cycles.is_empty(), "no cycles expected");

        let order_ids: Vec<&str> = ordered.iter().map(|n| n.unit_id.as_str()).collect();

        // C should come before B (C is depended on by B)
        let c_idx = order_ids.iter().position(|&id| id == "func_C").unwrap();
        let b_idx = order_ids.iter().position(|&id| id == "func_B").unwrap();
        let a_idx = order_ids.iter().position(|&id| id == "func_A").unwrap();
        let dll_idx = order_ids
            .iter()
            .position(|&id| id == "dll_classify_game_logic")
            .unwrap();

        assert!(
            c_idx < b_idx,
            "C (depended on) should come before B"
        );
        assert!(
            b_idx < a_idx,
            "B (depended on) should come before A"
        );
        assert!(
            dll_idx < a_idx,
            "DLL classification should come before functions"
        );
    }

    // ── Node ID helper tests ──

    #[test]
    fn dll_node_id_strips_dll_extension() {
        assert_eq!(
            super::helpers::dll_node_id("d3d9.dll"),
            "dll_classify_d3d9"
        );
        assert_eq!(
            super::helpers::dll_node_id("GAME_LOGIC.DLL"),
            "dll_classify_game_logic"
        );
    }

    #[test]
    fn func_node_id_formats_correctly() {
        assert_eq!(
            super::helpers::func_node_id("DrawPrimitive"),
            "func_DrawPrimitive"
        );
    }

    #[test]
    fn base_name_strips_extension() {
        assert_eq!(
            super::helpers::base_name("d3d9.dll"),
            "d3d9"
        );
        assert_eq!(
            super::helpers::base_name("game_logic.dll"),
            "game_logic"
        );
    }

    #[test]
    fn find_function_by_address_returns_name() {
        let call_graph = make_call_graph(
            "test.dll",
            vec![
                FunctionCallGraph {
                    name: "foo".to_string(),
                    address: 0x1000,
                    callers: vec![],
                    callees: vec![],
                    node_category: NodeCategory::Middle,
                },
                FunctionCallGraph {
                    name: "bar".to_string(),
                    address: 0x2000,
                    callers: vec![],
                    callees: vec![],
                    node_category: NodeCategory::Middle,
                },
            ],
        );

        assert_eq!(
            super::helpers::find_function_by_address(&call_graph, 0x1000),
            Some("foo")
        );
        assert_eq!(
            super::helpers::find_function_by_address(&call_graph, 0x2000),
            Some("bar")
        );
        assert!(super::helpers::find_function_by_address(&call_graph, 0xFFFF).is_none());
    }

    #[test]
    fn find_function_by_address_not_found() {
        let call_graph = make_call_graph(
            "test.dll",
            vec![FunctionCallGraph {
                name: "foo".to_string(),
                address: 0x1000,
                callers: vec![],
                callees: vec![],
                node_category: NodeCategory::Middle,
            }],
        );

        assert!(super::helpers::find_function_by_address(&call_graph, 0xFFFF).is_none());
    }
}
