//! Call graph enrichment and dependency graph construction.
//!
//! This module bridges [`calxgloss_callgraph`] and the analysis pipeline:
//!
//! 1. **Statistics** — [`print_call_graph_stats`] prints a human-readable
//!    summary of call graph data (function count, root/middle/leaf distribution,
//!    call-type breakdown, external API count).
//!
//! 2. **Enrichment** — builds a call graph from analysis engine data,
//!    classifies each function as
//!    [`Root`](calxgloss_types::NodeCategory::Root),
//!    [`Leaf`](calxgloss_types::NodeCategory::Leaf), or
//!    [`Middle`](calxgloss_types::NodeCategory::Middle), and persists it to
//!    JSON. A known-library match from the persisted `libmatch` document at
//!    or above [`LIBMATCH_SKIP_CONFIDENCE_FLOOR`] produces
//!    [`Skip`](calxgloss_types::NodeCategory::Skip) ahead of the structural
//!    Root/Leaf/Middle cascade. If the document is missing or corrupt, that
//!    cascade decides alone.
//!
//! 3. **Dependency graph construction** — converts the persisted call graph
//!    into a [`DependencyGraph`](calxgloss_types::DependencyGraph) for the
//!    translation work queue.
//!
//! # Example
//!
//! ```no_run
//! use calxgloss_analysis::build_enriched_call_graph;
//! use calxgloss_kuna::KunaSource;
//! use std::path::Path;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let kuna = KunaSource::load(Path::new("/workspace/targets/eqmain.dll"))?;
//!
//! let graph = build_enriched_call_graph(&kuna, "eqmain.dll", Path::new("/workspace"), None).await?;
//!
//! calxgloss_analysis::print_call_graph_stats(&graph);
//!
//! for func in &graph.functions {
//!     println!("{}: {:?}", func.name, func.node_category);
//! }
//! # Ok(())
//! # }
//! ```

use calxgloss_callgraph::{
    CallGraphBuilder, CallGraphPersistor, CallType, LeafDetector, RootDetector,
};
use calxgloss_decomp::ScanSource;
use calxgloss_libmatch::{persist::LibmatchPersistor, types::LibmatchResult};
use calxgloss_types::{
    DependencyEdge, DependencyGraph, DependencyNode, NodeCategory, ReviewStatus,
    dashboard::WorkLevel,
};
use tracing::{debug, info};

// ============================================================
// Call graph statistics
// ============================================================

/// Format text in bold ANSI.
fn bold(s: &str) -> String {
    format!("\x1b[1m{s}\x1b[0m")
}

/// Print a human-readable summary of call graph statistics.
///
/// Reports function count, root/middle/leaf/skip distribution, call-type
/// breakdown (direct / indirect / virtual), the count of unique external
/// callee names (references to external APIs), and the average number of
/// callees per function.
///
/// Output is sent to `println!` so it appears in the terminal regardless of
/// the logging configuration.
pub fn print_call_graph_stats(graph: &calxgloss_callgraph::CallGraph) {
    let total = graph.functions.len();
    let roots = graph
        .functions
        .iter()
        .filter(|f| matches!(f.node_category, NodeCategory::Root))
        .count();
    let middles = graph
        .functions
        .iter()
        .filter(|f| matches!(f.node_category, NodeCategory::Middle))
        .count();
    let leaves = graph
        .functions
        .iter()
        .filter(|f| matches!(f.node_category, NodeCategory::Leaf))
        .count();
    let skips = graph
        .functions
        .iter()
        .filter(|f| matches!(f.node_category, NodeCategory::Skip))
        .count();

    let mut direct = 0u64;
    let mut indirect = 0u64;
    let mut virtual_ = 0u64;
    let mut total_edges = 0usize;
    let mut callee_names = std::collections::HashSet::new();

    for func in &graph.functions {
        total_edges += func.callees.len();
        for edge in &func.callees {
            match edge.call_type {
                CallType::Direct => direct += 1,
                CallType::Indirect => indirect += 1,
                CallType::Virtual => virtual_ += 1,
                #[allow(deprecated)]
                CallType::Unknown => {}
            }
            if !edge.callee_name.is_empty() {
                callee_names.insert(&edge.callee_name);
            }
        }
    }

    let avg_callees = if total > 0 {
        total_edges as f64 / total as f64
    } else {
        0.0
    };

    let w = 33; // total width minus padding
    let sep = "─".repeat(w);
    let hsep = "├".to_string() + &sep + "┤";
    let top = "┌".to_string() + &sep + "┐";
    let bot = "└".to_string() + &sep + "┘";

    fn pad(s: &str, w: usize) -> String {
        format!("{:<w$}", s, w = w)
    }

    println!();
    println!(
        "  → Call Graph Statistics for {} ({})",
        bold(&graph.binary),
        bold(&total.to_string())
    );
    println!("  {top}");
    println!(
        "  │ Functions: {}                  │",
        pad(&bold(&total.to_string()), 21)
    );
    println!("  {hsep}");
    println!(
        "  │ Roots:    {:>4}  Middle: {:>4}  │",
        pad(&bold(&roots.to_string()), 5),
        pad(&bold(&middles.to_string()), 8)
    );
    println!(
        "  │ Leaves:   {:>4}  Skip:   {:>4}  │",
        pad(&bold(&leaves.to_string()), 5),
        pad(&bold(&skips.to_string()), 8)
    );
    println!("  {hsep}");
    println!(
        "  │ Total edges: {}                │",
        pad(&bold(&total_edges.to_string()), 19)
    );
    println!("  {hsep}");
    println!(
        "  │ Direct:    {:>4}               │",
        pad(&bold(&direct.to_string()), 19)
    );
    println!(
        "  │ Indirect:  {:>4}               │",
        pad(&bold(&indirect.to_string()), 19)
    );
    println!(
        "  │ Virtual:   {:>4}               │",
        pad(&bold(&virtual_.to_string()), 19)
    );
    println!("  {hsep}");
    println!(
        "  │ External APIs: {:>3}           │",
        pad(&bold(&callee_names.len().to_string()), 16)
    );
    println!(
        "  │ Avg callees/fn: {:>6.1}          │",
        pad(&format!("{avg_callees:.1}"), 19)
    );
    println!("  {bot}");
    println!();
}

// ============================================================
// Call graph enrichment
// ============================================================

/// The confidence floor at which a libmatch match becomes a `Skip`.
///
/// A libmatch finding is an observation. `Skip` is an instruction to the
/// translator. This floor is the point where one turns into the other:
/// when a function's best finding on the 0–100 evidence-confidence scale
/// reaches it, the translator stubs the function instead of translating
/// it. Below the floor, the structural Root/Leaf/Middle cascade decides
/// alone. The finding itself is persisted with its own confidence no
/// matter what the floor does — the observation and the instruction stay
/// separate, per the binary-analysis record model (issue #265).
pub const LIBMATCH_SKIP_CONFIDENCE_FLOOR: u8 = 80;

/// Loads the persisted libmatch document for a binary.
///
/// Returns `None` when the document is missing or corrupt — exactly as
/// the translator tolerates a missing control-flow cache. A stale or
/// absent known-library artifact therefore never fails a call-graph
/// build: classification simply falls back to the structural cascade.
fn load_libmatch_result(workspace: &std::path::Path, dll_name: &str) -> Option<LibmatchResult> {
    let persistor = LibmatchPersistor::new(workspace);
    match persistor.load(dll_name) {
        Ok(result) => Some(result),
        Err(e) => {
            debug!(
                %dll_name,
                error = %e,
                "No usable libmatch result; classifying without known-library Skip"
            );
            None
        }
    }
}

/// True if any of the function's libmatch findings meets the Skip
/// confidence floor.
///
/// All of a function's findings are considered together: the best one
/// decides, so one finding at or above [`LIBMATCH_SKIP_CONFIDENCE_FLOOR`]
/// is enough. A weak propagated claim never cancels a strong direct
/// match.
fn meets_libmatch_floor(libmatch: Option<&LibmatchResult>, function: &str) -> bool {
    libmatch.is_some_and(|result| {
        result.for_function(function).any(|finding| {
            finding
                .confidence()
                .at_least(LIBMATCH_SKIP_CONFIDENCE_FLOOR)
        })
    })
}

/// Classifies every function in the graph.
///
/// If a function's best libmatch finding meets
/// [`LIBMATCH_SKIP_CONFIDENCE_FLOOR`], it becomes
/// [`Skip`](NodeCategory::Skip) before the structural cascade runs — a
/// known library body is never a root, leaf, or middle, no matter how it
/// sits in the call graph. Every other function goes through the
/// existing [`RootDetector`]/[`LeafDetector`] decision unchanged. With
/// no document (`None`), the cascade alone decides — plain structural
/// classification.
fn classify_call_graph(
    graph: &mut calxgloss_callgraph::CallGraph,
    libmatch: Option<&LibmatchResult>,
) {
    let root_detector = RootDetector::new();
    let leaf_detector = LeafDetector::new();

    for func in &mut graph.functions {
        func.node_category = if meets_libmatch_floor(libmatch, &func.name) {
            NodeCategory::Skip
        } else if root_detector.is_root(func) {
            NodeCategory::Root
        } else if leaf_detector.has_leaf_call(func) {
            NodeCategory::Leaf
        } else {
            NodeCategory::Middle
        };
    }
}

/// Builds, classifies, and persists a call graph for a single DLL.
///
/// This is the primary integration point between the call graph analysis
/// pipeline and the rest of the system. It:
///
/// 1. Fetches all function metadata through the scan source, via
///    [`CallGraphBuilder`].
/// 2. Loads the persisted libmatch document for the binary, if any, and
///    classifies each function through [`classify_call_graph`]: a
///    known-library match at or above [`LIBMATCH_SKIP_CONFIDENCE_FLOOR`]
///    becomes [`Skip`](calxgloss_types::NodeCategory::Skip) ahead of the
///    structural [`RootDetector`] / [`LeafDetector`] cascade.
/// 3. Updates each function's [`NodeCategory`].
/// 4. Persists the enriched graph to the cache directory.
///
/// # Arguments
///
/// * `source` — The scan source used to fetch function data: a loaded
///   [`KunaSource`](calxgloss_kuna::KunaSource) or a batch's cached source.
/// * `dll_name` — The DLL filename (e.g., `"eqmain.dll"`).
/// * `workspace` — The workspace root directory (used as base for cache path).
/// * `cache_dir` — Explicit directory for call graph JSON files. If `None`,
///   defaults to `{workspace}/re/analysis/`.
///
/// # Returns
///
/// A fully classified [`calxgloss_callgraph::CallGraph`], or an error if
/// engine data cannot be fetched or the graph cannot be persisted.
///
/// # Graceful degradation
///
/// If a single function's decompilation fails, it is included with an empty
/// callee list. If all decompilations fail, the graph still completes with
/// empty callee lists for every function. A missing or corrupt libmatch
/// document degrades to classification without known-library `Skip` — the
/// behavior from before this marking step existed — just as the translator
/// tolerates a missing control-flow cache.
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
pub async fn build_enriched_call_graph<S: ScanSource + Clone + Sync>(
    source: &S,
    dll_name: &str,
    workspace: &std::path::Path,
    cache_dir: Option<&std::path::Path>,
) -> anyhow::Result<calxgloss_callgraph::CallGraph> {
    info!(%dll_name, "Building enriched call graph");

    // 1. Build the call graph from the scan source.
    let builder = CallGraphBuilder::with_source(source.clone(), dll_name);
    let mut graph = builder.build().await?;

    // 2. Classify each function: a known-library match at or above the
    //    confidence floor marks the node Skip ahead of the structural
    //    cascade; a missing or corrupt libmatch document degrades to the
    //    cascade alone.
    let libmatch = load_libmatch_result(workspace, dll_name);
    classify_call_graph(&mut graph, libmatch.as_ref());

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
    let skip_count = graph
        .functions
        .iter()
        .filter(|f| matches!(f.node_category, NodeCategory::Skip))
        .count();

    info!(
        %dll_name,
        func_count,
        root_count,
        leaf_count,
        skip_count,
        middle_count = func_count - root_count - leaf_count - skip_count,
        "Classified call graph"
    );

    // 3. Persist to disk.
    let persistor = match cache_dir {
        Some(dir) => CallGraphPersistor::with_cache_dir(dir),
        None => CallGraphPersistor::new(workspace),
    };
    persistor.save(&graph)?;

    info!(%dll_name, "Saved enriched call graph");

    Ok(graph)
}

/// Loads a persisted call graph from the workspace.
///
/// Returns `None` if the graph file does not exist or fails to parse.
/// This allows callers to decide whether a missing graph is acceptable.
///
/// # Arguments
///
/// * `workspace` — The workspace root directory (used as base for cache path).
/// * `cache_dir` — Explicit directory for call graph JSON files. If `None`,
///   defaults to `{workspace}/re/analysis/`.
/// * `dll_name` — The DLL filename.
pub fn load_call_graph(
    workspace: &std::path::Path,
    cache_dir: Option<&std::path::Path>,
    dll_name: &str,
) -> Option<calxgloss_callgraph::CallGraph> {
    let persistor = match cache_dir {
        Some(dir) => CallGraphPersistor::with_cache_dir(dir),
        None => CallGraphPersistor::new(workspace),
    };
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
        if cls.binary == call_graph.binary {
            let node_id = helpers::dll_node_id(&cls.binary);
            graph.nodes.push(DependencyNode::with_level(
                node_id.clone(),
                format!("Classify {}", cls.binary),
                ReviewStatus::Queued,
                WorkLevel::DllClassification,
            ));
            dll_node_ids.insert(cls.binary.clone(), node_id);
        }
    }

    // If no classification exists for this DLL, create a default one
    if !dll_node_ids.contains_key(&call_graph.binary) {
        let node_id = helpers::dll_node_id(&call_graph.binary);
        graph.nodes.push(DependencyNode::with_level(
            node_id.clone(),
            format!("Classify {}", call_graph.binary),
            ReviewStatus::Queued,
            WorkLevel::DllClassification,
        ));
        dll_node_ids.insert(call_graph.binary.clone(), node_id);
    }

    // ── Phase 2: Add shim layer node if applicable ──

    let mut shim_node_id: Option<String> = None;

    for cls in classifications {
        if cls.binary == call_graph.binary {
            if let crate::Strategy::CrateReplacement { crate_name } = &cls.strategy {
                let shim_id = helpers::shim_node_id(&cls.binary, crate_name);
                graph.nodes.push(DependencyNode::with_level(
                    shim_id.clone(),
                    format!("Shim {} → {}", cls.binary, crate_name),
                    ReviewStatus::Queued,
                    WorkLevel::ShimLayer,
                ));
                graph.edges.push(DependencyEdge::new(
                    shim_id.clone(),
                    dll_node_ids[&cls.binary].clone(),
                ));
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
            graph
                .edges
                .push(DependencyEdge::new(func_id.clone(), shim_id.clone()));
        }
    } else {
        let dll_id = &dll_node_ids[&call_graph.binary];
        for func_id in function_node_ids.values() {
            graph
                .edges
                .push(DependencyEdge::new(func_id.clone(), dll_id.clone()));
        }
    }

    // Depend on call graph neighbors — callees only. Caller edges would
    // create cycles, because they point the opposite way from the callee
    // edges.
    for func in &call_graph.functions {
        let func_id = &function_node_ids[&func.name];

        // Edges to callees
        for edge in &func.callees {
            // Try to find the callee's function node by address
            if let Some(callee_name) = helpers::find_function_by_address(call_graph, edge.target)
                && let Some(callee_id) = function_node_ids.get(callee_name)
            {
                graph.edges.push(
                    DependencyEdge::new(func_id.clone(), callee_id.clone())
                        .with_type(calxgloss_types::EdgeType::Call),
                );
            }
        }
    }

    graph
}

/// Helper utilities for dependency graph construction from call graph data.
mod helpers {
    /// Returns the node ID for a DLL classification unit.
    pub fn dll_node_id(binary: &str) -> String {
        format!("dll_classify_{}", base_name(binary))
    }

    /// Returns the node ID for a shim layer unit.
    pub fn shim_node_id(binary: &str, crate_name: &str) -> String {
        format!(
            "shim_{}_{}",
            base_name(binary),
            crate_name.replace(['-', '.', '/'], "_")
        )
    }

    /// Returns the node ID for a function translation unit.
    pub fn func_node_id(function: &str) -> String {
        format!("func_{}", function)
    }

    /// Strips the `.dll` extension and lowercases the name.
    pub fn base_name(binary: &str) -> String {
        binary
            .trim()
            .to_lowercase()
            .strip_suffix(".dll")
            .unwrap_or(binary)
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
    use calxgloss_libmatch::persist::LibmatchPersistor;
    use calxgloss_libmatch::types::{
        LibmatchFinding, LibmatchMatch, LibmatchResult, LibraryFamily, VERSION_UNKNOWN_ADMISSION,
    };
    use calxgloss_types::{Confidence, DllCategory, ScanMetadata};

    use crate::{DllClassification, Strategy};

    fn test_classification(
        binary: &str,
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
            binary: binary.to_string(),
            category,
            strategy,
            exports_count: 0,
            imports_count: 0,
            crate_replacement: crate_name.map(|s| s.to_string()),
            known_runtime: false,
            reason: String::new(),
        }
    }

    fn make_call_graph(
        binary: &str,
        functions: Vec<FunctionCallGraph>,
    ) -> calxgloss_callgraph::CallGraph {
        calxgloss_callgraph::CallGraph {
            binary: binary.to_string(),
            functions,
        }
    }

    /// A `memcpy` match record for one function at `confidence`, shaped as
    /// the `libmatch` scan writes it.
    fn libmatch_match(function: &str, confidence: u8) -> LibmatchMatch {
        LibmatchMatch {
            function: function.to_string(),
            symbol: "memcpy".to_string(),
            family: LibraryFamily::Crt,
            suggestion: "slice copy — `copy_nonoverlapping`".to_string(),
            confidence: Confidence::new(confidence),
            evidence: "  *(undefined8 *)((long)puVar1 + -8) = *(undefined8 *)((long)lVar2 + -8);"
                .to_string(),
            admission: Some(VERSION_UNKNOWN_ADMISSION.to_string()),
        }
    }

    /// A body-signature finding for one function at `confidence`.
    fn libmatch_finding(function: &str, confidence: u8) -> LibmatchFinding {
        LibmatchFinding::BodySignature(libmatch_match(function, confidence))
    }

    /// The persisted libmatch document shape for one binary.
    fn libmatch_doc(binary: &str, findings: Vec<LibmatchFinding>) -> LibmatchResult {
        LibmatchResult {
            metadata: ScanMetadata::new(binary),
            findings,
        }
    }

    /// Saves a libmatch document where the classification pass reads it:
    /// the workspace's `re/analysis/libmatch/` document directory.
    fn persist_libmatch_doc(workspace: &std::path::Path, doc: &LibmatchResult) {
        LibmatchPersistor::new(workspace)
            .save(doc)
            .expect("libmatch document should save");
    }

    /// A three-function fixture covering the whole structural cascade:
    /// `WinMain` matches a root name pattern, `load_config` calls a known
    /// Windows API (leaf), and `FUN_18003ab00` is neither (middle).
    fn cascade_fixture() -> calxgloss_callgraph::CallGraph {
        make_call_graph(
            "eqmain.dll",
            vec![
                FunctionCallGraph {
                    name: "WinMain".to_string(),
                    address: 0x401000,
                    callers: vec![],
                    callees: vec![CallGraphEdge {
                        source: 0x401000,
                        target: 0x402000,
                        call_site: 0,
                        call_type: CallType::Direct,
                        callee_name: "FUN_18003ab00".to_string(),
                    }],
                    node_category: NodeCategory::Middle,
                },
                FunctionCallGraph {
                    name: "FUN_18003ab00".to_string(),
                    address: 0x402000,
                    callers: vec![0x401000],
                    callees: vec![],
                    node_category: NodeCategory::Middle,
                },
                FunctionCallGraph {
                    name: "load_config".to_string(),
                    address: 0x403000,
                    callers: vec![],
                    callees: vec![CallGraphEdge {
                        source: 0x403000,
                        target: 0x78000000,
                        call_site: 0,
                        call_type: CallType::Direct,
                        callee_name: "CreateFile".to_string(),
                    }],
                    node_category: NodeCategory::Middle,
                },
            ],
        )
    }

    /// Asserts the named fixture function holds the expected category in a
    /// classified graph.
    fn assert_category(graph: &calxgloss_callgraph::CallGraph, name: &str, expected: NodeCategory) {
        let found = graph
            .functions
            .iter()
            .find(|f| f.name == name)
            .expect("fixture function should exist");
        assert_eq!(
            found.node_category, expected,
            "{name} should be {expected:?}"
        );
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

        assert!(c_idx < b_idx, "C (depended on) should come before B");
        assert!(b_idx < a_idx, "B (depended on) should come before A");
        assert!(
            dll_idx < a_idx,
            "DLL classification should come before functions"
        );
    }

    // ── Known-library Skip classification tests (issue #265) ──

    #[test]
    fn persisted_finding_at_the_floor_marks_node_skip() {
        let ws = tempfile::tempdir().expect("temp workspace");
        persist_libmatch_doc(
            ws.path(),
            &libmatch_doc(
                "eqmain.dll",
                vec![libmatch_finding(
                    "FUN_18003ab00",
                    LIBMATCH_SKIP_CONFIDENCE_FLOOR,
                )],
            ),
        );

        let libmatch = load_libmatch_result(ws.path(), "eqmain.dll");
        assert!(libmatch.is_some(), "the persisted document should load");

        let mut graph = cascade_fixture();
        classify_call_graph(&mut graph, libmatch.as_ref());

        assert_category(&graph, "FUN_18003ab00", NodeCategory::Skip);
        // The floor marks only the matched function; the rest of the
        // cascade stands.
        assert_category(&graph, "WinMain", NodeCategory::Root);
        assert_category(&graph, "load_config", NodeCategory::Leaf);
    }

    #[test]
    fn finding_below_the_floor_leaves_classification_untouched() {
        let ws = tempfile::tempdir().expect("temp workspace");
        persist_libmatch_doc(
            ws.path(),
            &libmatch_doc(
                "eqmain.dll",
                vec![libmatch_finding(
                    "FUN_18003ab00",
                    LIBMATCH_SKIP_CONFIDENCE_FLOOR - 1,
                )],
            ),
        );

        let libmatch = load_libmatch_result(ws.path(), "eqmain.dll");
        assert!(libmatch.is_some(), "the persisted document should load");

        let mut graph = cascade_fixture();
        classify_call_graph(&mut graph, libmatch.as_ref());

        // The floor is inclusive; one point below it changes nothing.
        assert_category(&graph, "FUN_18003ab00", NodeCategory::Middle);
        assert_category(&graph, "WinMain", NodeCategory::Root);
        assert_category(&graph, "load_config", NodeCategory::Leaf);
    }

    #[test]
    fn missing_libmatch_document_degrades_to_structural_classification() {
        let ws = tempfile::tempdir().expect("temp workspace");

        let libmatch = load_libmatch_result(ws.path(), "eqmain.dll");
        assert!(
            libmatch.is_none(),
            "a scan that has not run yet just means no known-library claims"
        );

        let mut graph = cascade_fixture();
        classify_call_graph(&mut graph, libmatch.as_ref());

        assert_category(&graph, "FUN_18003ab00", NodeCategory::Middle);
        assert_category(&graph, "WinMain", NodeCategory::Root);
        assert_category(&graph, "load_config", NodeCategory::Leaf);
    }

    #[test]
    fn corrupt_libmatch_document_degrades_to_structural_classification() {
        let ws = tempfile::tempdir().expect("temp workspace");
        let doc_dir = ws.path().join("re").join("analysis").join("libmatch");
        std::fs::create_dir_all(&doc_dir).expect("document directory should be created");
        std::fs::write(doc_dir.join("eqmain.dll.json"), "{ this is not json")
            .expect("garbage document should write");

        let libmatch = load_libmatch_result(ws.path(), "eqmain.dll");
        assert!(
            libmatch.is_none(),
            "a corrupt document degrades to no document, never a failure"
        );

        let mut graph = cascade_fixture();
        classify_call_graph(&mut graph, libmatch.as_ref());

        assert_category(&graph, "FUN_18003ab00", NodeCategory::Middle);
        assert_category(&graph, "WinMain", NodeCategory::Root);
        assert_category(&graph, "load_config", NodeCategory::Leaf);
    }

    #[test]
    fn skip_marking_precedes_the_structural_cascade() {
        // WinMain matches a root name pattern. A known-library match at
        // the floor still marks it Skip: a matched library body is never
        // a root, leaf, or middle, whatever its position in the call
        // graph.
        let doc = libmatch_doc(
            "eqmain.dll",
            vec![libmatch_finding("WinMain", LIBMATCH_SKIP_CONFIDENCE_FLOOR)],
        );

        let mut graph = cascade_fixture();
        classify_call_graph(&mut graph, Some(&doc));

        assert_category(&graph, "WinMain", NodeCategory::Skip);
        assert_category(&graph, "FUN_18003ab00", NodeCategory::Middle);
        assert_category(&graph, "load_config", NodeCategory::Leaf);
    }

    #[test]
    fn the_best_finding_for_a_function_decides_the_floor() {
        // FUN_18003ab00 has a penalized thunk claim below the floor and a
        // strong direct match above it: the strong claim marks the node.
        // load_config has only a weak claim below the floor, so it stays
        // unmarked.
        let doc = libmatch_doc(
            "eqmain.dll",
            vec![
                LibmatchFinding::TailCallThunk(libmatch_match("FUN_18003ab00", 50)),
                libmatch_finding("FUN_18003ab00", LIBMATCH_SKIP_CONFIDENCE_FLOOR + 5),
                LibmatchFinding::IdenticalBody(libmatch_match(
                    "load_config",
                    LIBMATCH_SKIP_CONFIDENCE_FLOOR - 1,
                )),
            ],
        );

        let mut graph = cascade_fixture();
        classify_call_graph(&mut graph, Some(&doc));

        assert_category(&graph, "FUN_18003ab00", NodeCategory::Skip);
        assert_category(&graph, "load_config", NodeCategory::Leaf);
        assert_category(&graph, "WinMain", NodeCategory::Root);
    }

    #[test]
    fn skip_node_still_appears_in_the_dependency_graph() {
        // A wrong match hides nothing: the matched function's record keeps
        // its place in the dependency graph, labeled Skip.
        let classifications = vec![test_classification(
            "eqmain.dll",
            DllCategory::ProjectSpecific,
            None,
        )];

        let call_graph = make_call_graph(
            "eqmain.dll",
            vec![FunctionCallGraph {
                name: "FUN_18003ab00".to_string(),
                address: 0x402000,
                callers: vec![],
                callees: vec![],
                node_category: NodeCategory::Skip,
            }],
        );

        let graph = build_dependency_graph_from_call_graph(&classifications, &call_graph);

        let node = graph
            .nodes
            .iter()
            .find(|n| n.unit_id == "func_FUN_18003ab00")
            .expect("matched function should keep its dependency node");
        assert!(node.name.contains("Skip"));
    }

    // ── Node ID helper tests ──

    #[test]
    fn dll_node_id_strips_dll_extension() {
        assert_eq!(super::helpers::dll_node_id("d3d9.dll"), "dll_classify_d3d9");
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
        assert_eq!(super::helpers::base_name("d3d9.dll"), "d3d9");
        assert_eq!(super::helpers::base_name("game_logic.dll"), "game_logic");
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
