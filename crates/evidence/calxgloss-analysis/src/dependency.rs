//! Dependency graph builder for the Calxgloss work queue.
//!
//! This module provides [`DependencyTracker`], which constructs a
//! [`DependencyGraph`] from two sources:
//!
//! 1. **Shim layer declarations** — produced when a DLL is classified as
//!    [`CrateReplacement`](calxgloss_analysis::Strategy::CrateReplacement). Each
//!    shim layer becomes a node that depends on its DLL classification.
//!
//! 2. **Ghidra call graphs** — for every function whose call graph includes
//!    other functions, a dependency edge is added from the function to those
//!    callers and callees. When a function depends on a crate-replacement shim,
//!    it gets an edge to that shim as well.
//!
//! The resulting graph represents the full DAG of work items in
//! dependency order:
//!
//! ```text
//! DLL Classification (root)
//!   └── Shim Layer (depends on classification)
//!       └── Function Translation (depends on shim + call graph neighbors)
//! ```
//!
//! # Example
//!
//! ```
//! use calxgloss_analysis::{DependencyTracker, DllClassification, Strategy};
//! use calxgloss_types::{DllCategory, DependencyNode, ReviewStatus};
//!
//! let tracker = DependencyTracker;
//!
//! // Two classified DLLs: one that needs a shim, one that needs reverse engineering
//! let classifications = vec![
//!     DllClassification {
//!         binary: "d3d9.dll".to_string(),
//!         category: DllCategory::MicrosoftSdk,
//!         strategy: Strategy::CrateReplacement {
//!             crate_name: "wgpu".to_string(),
//!         },
//!         exports_count: 0,
//!         imports_count: 0,
//!         crate_replacement: Some("wgpu".to_string()),
//!     },
//!     DllClassification {
//!         binary: "game_logic.dll".to_string(),
//!         category: DllCategory::ProjectSpecific,
//!         strategy: Strategy::ReverseEngineer,
//!         exports_count: 10,
//!         imports_count: 5,
//!         crate_replacement: None,
//!     },
//! ];
//!
//! // Functions and their call graph neighbors (caller/callee names)
//! let call_graph = [
//!     ("DrawSprite", vec!["DrawSprite".to_string()]),
//!     ("Present", vec!["Present".to_string()]),
//!     ("InitDevice", vec!["InitDevice".to_string()]),
//! ];
//!
//! let graph = tracker.build(&classifications, &call_graph);
//!
//! // All nodes should be present
//! assert_eq!(graph.nodes.len(), 6); // 2 classifications + 1 shim + 3 functions
//! ```

use calxgloss_types::{
    DependencyEdge, DependencyGraph, DependencyNode, ReviewStatus, dashboard::WorkLevel,
};

use crate::DllClassification;

// ============================================================
// Dependency graph persistence
// ============================================================

/// Persists a [`DependencyGraph`] to `re/analysis/dependency_graph.json`.
///
/// This module provides [`DependencyGraphPersistor`] for saving and loading
/// the dependency graph on disk so that downstream consumers (web UI,
/// terminal dashboard, restitch engine) can read the full DAG without
/// rebuilding it from raw classifications.
///
/// # File Format
///
/// The file is a JSON object matching [`DependencyGraph`]:
///
/// ```json
/// {
///   "nodes": [
///     {
///       "unit_id": "dll_classify_d3d9",
///       "name": "Classify d3d9.dll",
///       "status": "queued",
///       "level": "DllClassification"
///     },
///     {
///       "unit_id": "shim_d3d9_wgpu",
///       "name": "Shim d3d9.dll → wgpu",
///       "status": "queued",
///       "level": "ShimLayer"
///     }
///   ],
///   "edges": [
///     { "from": "shim_d3d9_wgpu", "to": "dll_classify_d3d9" },
///     { "from": "func_DrawPrimitive", "to": "shim_d3d9_wgpu" }
///   ]
/// }
/// ```
///
/// # Example
///
/// ```no_run
/// use calxgloss_analysis::{DependencyTracker, DependencyGraphPersistor, DllClassification, Strategy};
/// use calxgloss_types::{DllCategory, DependencyEdge};
///
/// let tracker = DependencyTracker;
///
/// // Build a graph from classifications + call graph
/// let classifications = vec![DllClassification {
///     binary: "d3d9.dll".to_string(),
///     category: DllCategory::MicrosoftSdk,
///     strategy: Strategy::CrateReplacement {
///         crate_name: "wgpu".to_string(),
///     },
///     exports_count: 0,
///     imports_count: 0,
///     crate_replacement: Some("wgpu".to_string()),
/// }];
///
/// let call_graph: Vec<(&str, Vec<String>)> = vec![("DrawPrimitive", vec![])];
/// let graph = tracker.build(&classifications, &call_graph);
///
/// // Persist to workspace
/// let persistor = DependencyGraphPersistor::new("/path/to/workspace");
/// persistor.save(&graph).expect("should persist graph");
///
/// // Later: load it back
/// let loaded = persistor.load().expect("should load graph");
/// assert_eq!(loaded.nodes.len(), graph.nodes.len());
/// ```
#[derive(Debug, Clone)]
pub struct DependencyGraphPersistor {
    /// Base workspace path where `re/analysis/` resides.
    workspace: std::path::PathBuf,
}

impl DependencyGraphPersistor {
    /// Creates a new persistor targeting the given workspace directory.
    ///
    /// # Arguments
    ///
    /// * `workspace` — The workspace root path. The graph file will be written
    ///   to `<workspace>/re/analysis/dependency_graph.json`.
    pub fn new(workspace: impl Into<std::path::PathBuf>) -> Self {
        Self {
            workspace: workspace.into(),
        }
    }

    /// Saves the given dependency graph to the JSON file.
    ///
    /// Creates the `re/analysis/` directory structure if it does not already exist.
    /// Overwrites any existing graph file.
    ///
    /// # Errors
    ///
    /// Returns an [`std::io::Error`] if the file cannot be written (e.g., permission
    /// denied, disk full, or parent directory is read-only).
    ///
    /// # Example
    ///
    /// ```no_run
    /// use calxgloss_analysis::{DependencyTracker, DependencyGraphPersistor};
    /// use calxgloss_types::DependencyGraph;
    ///
    /// let graph = DependencyGraph {
    ///     nodes: vec![],
    ///     edges: vec![],
    /// };
    ///
    /// let persistor = DependencyGraphPersistor::new("/workspace");
    /// persistor.save(&graph).expect("graph should be saved");
    /// ```
    pub fn save(&self, graph: &DependencyGraph) -> std::io::Result<()> {
        let path = self.graph_path();

        // Ensure the directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Serialize with indentation for readability
        let contents = serde_json::to_string_pretty(graph)?;
        std::fs::write(&path, contents)?;

        Ok(())
    }

    /// Loads the dependency graph from the JSON file.
    ///
    /// Returns [`None`] if the file does not exist or contains invalid JSON.
    /// Does not error on missing files — this allows callers to decide
    /// whether a missing graph is acceptable (e.g., fresh workspace).
    ///
    /// # Example
    ///
    /// ```no_run
    /// use calxgloss_analysis::DependencyGraphPersistor;
    ///
    /// let persistor = DependencyGraphPersistor::new("/workspace");
    /// match persistor.load() {
    ///     Some(graph) => println!("Loaded {} nodes", graph.nodes.len()),
    ///     None => println!("No graph file found — build from scratch"),
    /// }
    /// ```
    pub fn load(&self) -> Option<DependencyGraph> {
        let path = self.graph_path();
        std::fs::read_to_string(&path)
            .ok()
            .and_then(|contents| serde_json::from_str(&contents).ok())
    }

    /// Builds and persists a dependency graph in one step.
    ///
    /// This is a convenience method that combines [`DependencyTracker::build`]
    /// with [`save`]. It takes raw classification and call-graph data,
    /// constructs the graph, and writes it to disk.
    ///
    /// # Returns
    ///
    /// The constructed [`DependencyGraph`] on success, or an [`std::io::Error`]
    /// if the file cannot be written.
    ///
    /// [`save`]: Self::save
    pub fn build_and_save(
        &self,
        classifications: &[DllClassification],
        call_graph: &[(&str, Vec<String>)],
    ) -> std::io::Result<DependencyGraph> {
        let tracker = DependencyTracker;
        let graph = tracker.build(classifications, call_graph);
        self.save(&graph)?;
        Ok(graph)
    }

    /// Returns the path to the dependency graph JSON file.
    ///
    /// The path is `<workspace>/re/analysis/dependency_graph.json`.
    pub fn graph_path(&self) -> std::path::PathBuf {
        self.workspace
            .join("re")
            .join("analysis")
            .join("dependency_graph.json")
    }
}

// ============================================================
// Shim layer declarations
// ============================================================

/// A declaration that a shim layer should be generated for a crate-replacement DLL.
///
/// Produced during DLL classification when a DLL's strategy is
/// [`CrateReplacement`](crate::Strategy::CrateReplacement). The shim layer
/// translates the original DLL's API surface to the equivalent Rust crate's API.
#[derive(Debug, Clone)]
pub struct ShimLayerDeclaration {
    /// The original DLL filename (e.g., `d3d9.dll`).
    pub source_dll: String,

    /// The Rust crate that provides equivalent functionality (e.g., `wgpu`).
    pub target_crate: String,
}

impl ShimLayerDeclaration {
    /// Creates a new shim layer declaration from a classified DLL.
    ///
    /// Returns `None` if the DLL is not a crate replacement (i.e., it doesn't
    /// have a recommended Rust crate).
    pub fn from_classification(classification: &DllClassification) -> Option<Self> {
        match &classification.strategy {
            crate::Strategy::CrateReplacement { crate_name } => Some(Self {
                source_dll: classification.binary.clone(),
                target_crate: crate_name.clone(),
            }),
            _ => None,
        }
    }
}

// ============================================================
// Dependency tracker
// ============================================================

/// Builds a [`DependencyGraph`] from DLL classifications and Ghidra call graph data.
///
/// The tracker produces a DAG where nodes represent pieces of work (DLL classifications,
/// shim layers, function translations) and edges represent dependency relationships.
///
/// # Dependency Rules
///
/// - **DLL Classification** — root nodes with no dependencies
/// - **Shim Layer** — depends on its DLL classification
/// - **Function Translation** — depends on the shim layer (if the DLL is a
///   crate replacement) plus all functions in its call graph
///
/// # Example
///
/// ```
/// use calxgloss_analysis::{DependencyTracker, DllClassification, Strategy, ShimLayerDeclaration};
/// use calxgloss_types::{DllCategory, ReviewStatus};
///
/// let tracker = DependencyTracker;
///
/// let classifications = vec![
///     DllClassification {
///         binary: "d3d9.dll".to_string(),
///         category: DllCategory::MicrosoftSdk,
///         strategy: Strategy::CrateReplacement {
///             crate_name: "wgpu".to_string(),
///         },
///         exports_count: 0,
///         imports_count: 0,
///         crate_replacement: Some("wgpu".to_string()),
///     },
/// ];
///
/// let shim_declarations = vec![
///     ShimLayerDeclaration {
///         source_dll: "d3d9.dll".to_string(),
///         target_crate: "wgpu".to_string(),
///     },
/// ];
///
/// let call_graph = [("DrawPrimitive", vec!["DrawPrimitive".to_string()])];
///
/// let graph = tracker.build(&classifications, &call_graph);
/// assert!(!graph.nodes.is_empty());
/// ```
#[derive(Debug, Default)]
pub struct DependencyTracker;

impl DependencyTracker {
    /// Creates a new dependency tracker.
    ///
    /// The tracker is stateless; construction is cheap and can be done
    /// repeatedly. Use [`build`](Self::build) to produce a graph.
    pub fn new() -> Self {
        Self
    }

    /// Builds a full dependency graph from DLL classifications and function call graphs.
    ///
    /// This is the primary entry point. It combines shim layer declarations
    /// (derived automatically from crate-replacement classifications) with
    /// function-level call graph data to produce a complete DAG of work items.
    ///
    /// # Arguments
    ///
    /// * `classifications` — The DLL classifications produced by
    ///   [`Analyzer::classify_dlls`](crate::Analyzer::classify_dlls). Each crate-replacement
    ///   DLL implicitly declares a shim layer.
    /// * `call_graph` — Function call graph data as `(function_name, neighbors)` pairs,
    ///   where `neighbors` contains all callers and callees for the function.
    ///
    /// # Returns
    ///
    /// A [`DependencyGraph`] containing nodes and edges for all work items
    /// in dependency order. Nodes are added in dependency order: classifications
    /// first, then shim layers, then function translations.
    ///
    /// The returned graph can be passed to
    /// [`ReviewDashboard::new`](calxgloss_types::ReviewDashboard::new) to build
    /// a full review dashboard.
    pub fn build(
        &self,
        classifications: &[DllClassification],
        call_graph: &[(&str, Vec<String>)],
    ) -> DependencyGraph {
        let mut graph = DependencyGraph {
            nodes: Vec::new(),
            edges: Vec::new(),
        };

        // ── Phase 1: Add DLL classification nodes (roots, no dependencies) ──

        let mut dll_node_ids: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();

        for cls in classifications {
            let node_id = Self::dll_node_id(&cls.binary);
            graph.nodes.push(DependencyNode::with_level(
                node_id.clone(),
                format!("Classify {}", cls.binary),
                ReviewStatus::Queued,
                WorkLevel::DllClassification,
            ));
            dll_node_ids.insert(cls.binary.clone(), node_id);
        }

        // ── Phase 2: Add shim layer nodes (depend on DLL classification) ──

        let mut shim_node_ids: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();

        for cls in classifications {
            if let crate::Strategy::CrateReplacement { crate_name } = &cls.strategy {
                let shim_id = Self::shim_node_id(&cls.binary, crate_name);
                graph.nodes.push(DependencyNode::with_level(
                    shim_id.clone(),
                    format!("Shim {} → {}", cls.binary, crate_name),
                    ReviewStatus::Queued,
                    WorkLevel::ShimLayer,
                ));
                shim_node_ids.insert(cls.binary.clone(), shim_id.clone());
                graph.edges.push(DependencyEdge {
                    from: shim_id,
                    to: dll_node_ids[&cls.binary].clone(),
                });
            }
        }

        // ── Phase 3: Register all DLLs referenced by functions ──

        // The classified binaries are the workspace's binary inventory: the
        // detector resolves function-name hints against these real filenames
        // (any extension) instead of inventing identities (issue #70).
        let binary_inventory: Vec<String> =
            classifications.iter().map(|c| c.binary.clone()).collect();

        let mut dll_nodes_added: std::collections::HashSet<String> =
            std::collections::HashSet::new();

        for (func_name, neighbors) in call_graph {
            // Try to detect the binary from function name/neighbors
            if let Some(ref func_binary) =
                Self::detect_binary_from_function(func_name, neighbors, &binary_inventory)
            {
                if let Some(dll_id) = dll_node_ids.get(func_binary.as_str()) {
                    if dll_nodes_added.insert(dll_id.clone()) {}
                } else {
                    let dll_id = Self::dll_node_id(func_binary);
                    graph.nodes.push(DependencyNode::with_level(
                        dll_id.clone(),
                        format!("Classify {}", func_binary),
                        ReviewStatus::Queued,
                        WorkLevel::DllClassification,
                    ));
                    dll_node_ids.insert(func_binary.clone(), dll_id.clone());
                    dll_nodes_added.insert(dll_id);
                }
            }
        }

        // ── Phase 4a: Add all function nodes ──

        let mut function_node_ids: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();

        for (func_name, _neighbors) in call_graph {
            let func_id = Self::func_node_id(func_name);
            graph.nodes.push(DependencyNode::new(
                func_id.clone(),
                format!("Translate {}", func_name),
                ReviewStatus::Queued,
            ));
            function_node_ids.insert(func_name.to_string(), func_id.clone());
        }

        // ── Phase 4b: Add all function dependency edges ──

        for (func_name, neighbors) in call_graph {
            let func_name_ref: &str = func_name;
            let func_id = &function_node_ids[func_name_ref];

            // Determine the function's binary: try name detection, fall back to first classification
            let func_binary =
                Self::detect_binary_from_function(func_name, neighbors, &binary_inventory)
                    .or_else(|| classifications.first().map(|c| c.binary.clone()));

            if let Some(ref func_binary_str) = func_binary {
                // Depend on shim layer if available
                if let Some(shim_id) = shim_node_ids.get(func_binary_str.as_str()) {
                    graph.edges.push(DependencyEdge {
                        from: func_id.clone(),
                        to: shim_id.clone(),
                    });
                } else {
                    // Depend on DLL classification directly
                    if let Some(dll_id) = dll_node_ids.get(func_binary_str.as_str()) {
                        graph.edges.push(DependencyEdge {
                            from: func_id.clone(),
                            to: dll_id.clone(),
                        });
                    }
                }
            }

            // Dependencies from call graph neighbors
            for neighbor in neighbors {
                if let Some(neighbor_func_id) = function_node_ids.get(neighbor.as_str()) {
                    graph.edges.push(DependencyEdge {
                        from: func_id.clone(),
                        to: neighbor_func_id.clone(),
                    });
                }
            }
        }

        graph
    }

    /// Builds a dependency graph for a single DLL, including its shim layer
    /// (if any) and all functions from the call graph that belong to it.
    ///
    /// This is a convenience method useful for incremental builds where you
    /// want to analyze one DLL at a time. The resulting graph contains only
    /// the nodes and edges relevant to this DLL.
    ///
    /// # Arguments
    ///
    /// * `classification` — The DLL's classification result.
    /// * `dll_functions` — Functions belonging to this DLL and their call
    ///   graph neighbors (callers and callees).
    pub fn for_dll(
        &self,
        classification: &DllClassification,
        dll_functions: &[(&str, Vec<String>)],
    ) -> DependencyGraph {
        let shim_decl = ShimLayerDeclaration::from_classification(classification);

        // Phase 1: DLL classification node
        let dll_id = Self::dll_node_id(&classification.binary);
        let mut nodes = vec![DependencyNode::with_level(
            dll_id.clone(),
            format!("Classify {}", classification.binary),
            ReviewStatus::Queued,
            WorkLevel::DllClassification,
        )];
        let mut edges = Vec::new();

        // Phase 2: Shim layer node (if applicable)
        let mut shim_id: Option<String> = None;
        if let Some(ref decl) = shim_decl {
            let sid = Self::shim_node_id(&classification.binary, &decl.target_crate);
            nodes.push(DependencyNode::with_level(
                sid.clone(),
                format!("Shim {} → {}", classification.binary, decl.target_crate),
                ReviewStatus::Queued,
                WorkLevel::ShimLayer,
            ));
            edges.push(DependencyEdge {
                from: sid.clone(),
                to: Self::dll_node_id(&classification.binary),
            });
            shim_id = Some(sid);
        }

        // Phase 3a: Add all function nodes
        let mut func_map: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        for (func_name, _neighbors) in dll_functions {
            let func_id = Self::func_node_id(func_name);
            nodes.push(DependencyNode::new(
                func_id.clone(),
                format!("Translate {}", *func_name),
                ReviewStatus::Queued,
            ));
            func_map.insert((*func_name).to_string(), func_id);
        }

        // Phase 3b: Add function dependency edges
        for (func_name, neighbors) in dll_functions {
            let func_name_ref: &str = func_name;
            let func_id = func_map.get(func_name_ref).unwrap();

            // Depend on shim layer or DLL classification
            if let Some(ref sid) = shim_id {
                edges.push(DependencyEdge {
                    from: func_id.clone(),
                    to: sid.clone(),
                });
            } else {
                edges.push(DependencyEdge {
                    from: func_id.clone(),
                    to: Self::dll_node_id(&classification.binary),
                });
            }

            // Depend on call graph neighbors (skip self-references)
            for neighbor in neighbors {
                if neighbor != func_name
                    && let Some(neighbor_id) = func_map.get(neighbor.as_str())
                {
                    edges.push(DependencyEdge {
                        from: func_id.clone(),
                        to: neighbor_id.clone(),
                    });
                }
            }
        }

        DependencyGraph { nodes, edges }
    }

    /// Converts shim layer declarations into nodes.
    ///
    /// Returns a map from DLL name to shim node ID for use as a lookup table
    /// when building function dependencies.
    #[allow(dead_code)]
    fn shim_layer_nodes(
        &self,
        declarations: &[ShimLayerDeclaration],
    ) -> std::collections::HashMap<String, String> {
        let mut map = std::collections::HashMap::new();
        for decl in declarations {
            let node_id = Self::shim_node_id(&decl.source_dll, &decl.target_crate);
            map.insert(decl.source_dll.clone(), node_id);
        }
        map
    }

    // ── Node ID helpers ──

    /// Returns the node ID for a DLL classification unit.
    fn dll_node_id(binary: &str) -> String {
        format!("dll_classify_{}", Self::base_name(binary))
    }

    /// Returns the node ID for a shim layer unit.
    fn shim_node_id(binary: &str, crate_name: &str) -> String {
        format!(
            "shim_{}_{}",
            Self::base_name(binary),
            crate_name.replace(['-', '.', '/'], "_")
        )
    }

    /// Returns the node ID for a function translation unit.
    fn func_node_id(function: &str) -> String {
        format!("func_{}", function)
    }

    /// Strips the `.dll` extension and lowercases the name.
    fn base_name(binary: &str) -> String {
        binary
            .trim()
            .to_lowercase()
            .strip_suffix(".dll")
            .unwrap_or(binary)
            .to_string()
    }

    /// Detects the binary a function belongs to by examining the function name
    /// and its call graph neighbors against the workspace's binary inventory.
    ///
    /// Candidates are the `/`- and `_`-separated parts of the function name
    /// (the common `dll_name/FunctionName` and `dll_Name_FunctionName`
    /// patterns) plus the neighbors themselves. A candidate resolves when it
    /// matches a binary in `binaries` — the workspace's classified binaries —
    /// case-insensitively, either verbatim or against the filename stem, so
    /// `eqgame_RunLoop` resolves to an `eqgame.exe` inventory entry. The
    /// inventory's spelling of the name is returned verbatim (glossary:
    /// *binary identity*).
    ///
    /// A candidate that already carries a binary extension (`.dll` or `.exe`)
    /// resolves to itself even when the workspace has not classified it —
    /// the extension is already there, nothing is invented. An
    /// extension-less candidate that matches no inventory binary resolves to
    /// `None`: the detector never fabricates an identity by appending an
    /// extension (issue #70); the caller falls back to its default binary.
    fn detect_binary_from_function(
        function: &str,
        neighbors: &[String],
        binaries: &[String],
    ) -> Option<String> {
        for part in function.split(['/', '_']) {
            if let Some(identity) = Self::resolve_binary_candidate(part, binaries) {
                return Some(identity);
            }
        }

        for neighbor in neighbors {
            if let Some(identity) = Self::resolve_binary_candidate(neighbor, binaries) {
                return Some(identity);
            }
        }

        None
    }

    /// Resolves one name candidate to a binary identity.
    ///
    /// Matches case-insensitively against the inventory — verbatim or against
    /// the filename stem — and returns the inventory's spelling. Otherwise a
    /// candidate already ending in a binary extension is its own identity,
    /// verbatim; anything else resolves to `None`.
    fn resolve_binary_candidate(candidate: &str, binaries: &[String]) -> Option<String> {
        if candidate.is_empty() {
            return None;
        }
        let candidate_lower = candidate.to_lowercase();
        if let Some(hit) = binaries.iter().find(|binary| {
            let binary_lower = binary.to_lowercase();
            binary_lower == candidate_lower
                || std::path::Path::new(&binary_lower)
                    .file_stem()
                    .is_some_and(|stem| stem == std::ffi::OsStr::new(&candidate_lower))
        }) {
            return Some(hit.clone());
        }
        Self::has_binary_extension(&candidate_lower).then(|| candidate.to_string())
    }

    /// Whether a lowercased name already carries a binary extension (`.dll`
    /// or `.exe`) — the set of extensions that make a name a complete binary
    /// identity on its own.
    fn has_binary_extension(name_lower: &str) -> bool {
        name_lower.ends_with(".dll") || name_lower.ends_with(".exe")
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DllClassification, Strategy};
    use calxgloss_types::DllCategory;

    fn test_shim_decl(binary: &str, crate_name: &str) -> ShimLayerDeclaration {
        ShimLayerDeclaration {
            source_dll: binary.to_string(),
            target_crate: crate_name.to_string(),
        }
    }

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
        }
    }

    // ── ShimLayerDeclaration tests ──

    #[test]
    fn shim_declaration_from_crate_replacement() {
        let cls = test_classification("d3d9.dll", DllCategory::MicrosoftSdk, Some("wgpu"));
        let shim = ShimLayerDeclaration::from_classification(&cls).unwrap();
        assert_eq!(shim.source_dll, "d3d9.dll");
        assert_eq!(shim.target_crate, "wgpu");
    }

    #[test]
    fn shim_declaration_from_reverse_engineer_returns_none() {
        let cls = test_classification("game_logic.dll", DllCategory::ProjectSpecific, None);
        assert!(ShimLayerDeclaration::from_classification(&cls).is_none());
    }

    #[test]
    fn shim_declaration_from_pal_mapping_returns_none() {
        let cls = test_classification("kernel32.dll", DllCategory::WindowsOs, None);
        assert!(ShimLayerDeclaration::from_classification(&cls).is_none());
    }

    // ── Node ID helper tests ──

    #[test]
    fn dll_node_id_strips_dll_extension() {
        assert_eq!(
            DependencyTracker::dll_node_id("d3d9.dll"),
            "dll_classify_d3d9"
        );
        assert_eq!(
            DependencyTracker::dll_node_id("GAME_LOGIC.DLL"),
            "dll_classify_game_logic"
        );
    }

    #[test]
    fn shim_node_id_formats_correctly() {
        assert_eq!(
            DependencyTracker::shim_node_id("d3d9.dll", "wgpu"),
            "shim_d3d9_wgpu"
        );
    }

    #[test]
    fn func_node_id_formats_correctly() {
        assert_eq!(
            DependencyTracker::func_node_id("DrawPrimitive"),
            "func_DrawPrimitive"
        );
    }

    #[test]
    fn base_name_strips_extension() {
        assert_eq!(DependencyTracker::base_name("d3d9.dll"), "d3d9");
        assert_eq!(DependencyTracker::base_name("game_logic.dll"), "game_logic");
        assert_eq!(DependencyTracker::base_name("no_extension"), "no_extension");
    }

    // ── DependencyGraph construction tests ──

    #[test]
    fn build_graph_with_shim_layer() {
        let tracker = DependencyTracker;

        let classifications = vec![test_classification(
            "d3d9.dll",
            DllCategory::MicrosoftSdk,
            Some("wgpu"),
        )];

        let call_graph = vec![("DrawPrimitive", vec![])];

        let graph = tracker.build(&classifications, &call_graph);

        // Expected nodes:
        // 1. dll_classify_d3d9
        // 2. shim_d3d9_wgpu
        // 3. func_DrawPrimitive
        assert_eq!(graph.nodes.len(), 3);

        // Expected edges:
        // 1. shim_d3d9_wgpu → dll_classify_d3d9
        // 2. func_DrawPrimitive → shim_d3d9_wgpu
        assert_eq!(graph.edges.len(), 2);

        // Verify the shim depends on classification
        assert!(
            graph
                .edges
                .iter()
                .any(|e| { e.from == "shim_d3d9_wgpu" && e.to == "dll_classify_d3d9" })
        );

        // Verify the function depends on the shim
        assert!(
            graph
                .edges
                .iter()
                .any(|e| { e.from == "func_DrawPrimitive" && e.to == "shim_d3d9_wgpu" })
        );
    }

    #[test]
    fn build_graph_function_calls_another_function() {
        let tracker = DependencyTracker;

        let classifications = vec![test_classification(
            "game_logic.dll",
            DllCategory::ProjectSpecific,
            None,
        )];

        // DrawSprite calls DrawPrimitive
        let call_graph = vec![
            ("DrawSprite", vec!["DrawPrimitive".to_string()]),
            ("DrawPrimitive", vec!["DrawSprite".to_string()]),
        ];

        let graph = tracker.build(&classifications, &call_graph);

        assert_eq!(graph.nodes.len(), 3); // 1 classification + 2 functions

        // DrawSprite depends on DrawPrimitive
        assert!(
            graph
                .edges
                .iter()
                .any(|e| { e.from == "func_DrawSprite" && e.to == "func_DrawPrimitive" })
        );
    }

    #[test]
    fn build_graph_mixed_dlls_with_shims() {
        let tracker = DependencyTracker;

        // Two DLLs: one needs a shim, one needs reverse engineering
        let classifications = vec![
            test_classification("d3d9.dll", DllCategory::MicrosoftSdk, Some("wgpu")),
            test_classification("game_logic.dll", DllCategory::ProjectSpecific, None),
        ];

        // Functions across both DLLs
        let call_graph = vec![
            // DirectX render function — depends on wgpu shim
            ("Present", vec!["Present".to_string()]),
            // Game logic function — depends on game_logic.dll classification
            ("UpdatePlayer", vec!["UpdatePlayer".to_string()]),
            // Function that calls both
            (
                "RenderFrame",
                vec!["Present".to_string(), "UpdatePlayer".to_string()],
            ),
        ];

        let graph = tracker.build(&classifications, &call_graph);

        // Nodes:
        // 1. dll_classify_d3d9
        // 2. shim_d3d9_wgpu
        // 3. dll_classify_game_logic
        // 4. func_Present
        // 5. func_UpdatePlayer
        // 6. func_RenderFrame
        assert_eq!(graph.nodes.len(), 6);

        // Edges:
        // 1. shim_d3d9_wgpu → dll_classify_d3d9
        // 2. func_Present → shim_d3d9_wgpu
        // 3. func_UpdatePlayer → dll_classify_game_logic
        // 4. func_RenderFrame → shim_d3d9_wgpu (for Present dep)
        // 5. func_RenderFrame → dll_classify_game_logic (for UpdatePlayer dep)
        // 6. func_RenderFrame → func_Present (call graph neighbor)
        // 7. func_RenderFrame → func_UpdatePlayer (call graph neighbor)
        assert!(graph.edges.len() >= 6);
    }

    // ── Shim layer declaration tests ──

    #[test]
    fn shim_declarations_from_classifications() {
        let classifications = [
            test_classification("d3d9.dll", DllCategory::MicrosoftSdk, Some("wgpu")),
            test_classification("fmod.dll", DllCategory::KnownThirdParty, Some("fmod-rs")),
            test_classification("game_logic.dll", DllCategory::ProjectSpecific, None),
            test_classification("kernel32.dll", DllCategory::WindowsOs, None),
        ];

        // Manually build shim declarations from classifications
        let shim_decls: Vec<ShimLayerDeclaration> = classifications
            .iter()
            .filter_map(ShimLayerDeclaration::from_classification)
            .collect();

        assert_eq!(shim_decls.len(), 2);
        assert_eq!(shim_decls[0].source_dll, "d3d9.dll");
        assert_eq!(shim_decls[0].target_crate, "wgpu");
        assert_eq!(shim_decls[1].source_dll, "fmod.dll");
        assert_eq!(shim_decls[1].target_crate, "fmod-rs");
    }

    // ── Shim layer nodes tests ──

    #[test]
    fn shim_layer_nodes_map_correctly() {
        let tracker = DependencyTracker;

        let declarations = vec![
            test_shim_decl("d3d9.dll", "wgpu"),
            test_shim_decl("fmod.dll", "fmod-rs"),
        ];

        let map = tracker.shim_layer_nodes(&declarations);

        assert_eq!(map.get("d3d9.dll"), Some(&"shim_d3d9_wgpu".to_string()));
        assert_eq!(map.get("fmod.dll"), Some(&"shim_fmod_fmod_rs".to_string()));
        assert_eq!(map.get("kernel32.dll"), None);
    }

    // ── for_dll tests ──

    #[test]
    fn for_dll_with_shim_layer() {
        let tracker = DependencyTracker;

        let classification =
            test_classification("d3d9.dll", DllCategory::MicrosoftSdk, Some("wgpu"));

        let dll_functions = vec![
            ("DrawPrimitive", vec!["DrawPrimitive".to_string()]),
            ("Present", vec!["Present".to_string()]),
        ];

        let graph = tracker.for_dll(&classification, &dll_functions);

        // Nodes:
        // 1. dll_classify_d3d9
        // 2. shim_d3d9_wgpu
        // 3. func_DrawPrimitive
        // 4. func_Present
        assert_eq!(graph.nodes.len(), 4);

        // Edges:
        // 1. shim_d3d9_wgpu → dll_classify_d3d9
        // 2. func_DrawPrimitive → shim_d3d9_wgpu
        // 3. func_Present → shim_d3d9_wgpu
        assert_eq!(graph.edges.len(), 3);
    }

    #[test]
    fn for_dll_without_shim_layer() {
        let tracker = DependencyTracker;

        let classification =
            test_classification("game_logic.dll", DllCategory::ProjectSpecific, None);

        let dll_functions = vec![("UpdatePlayer", vec!["UpdatePlayer".to_string()])];

        let graph = tracker.for_dll(&classification, &dll_functions);

        // Nodes:
        // 1. dll_classify_game_logic
        // 2. func_UpdatePlayer
        assert_eq!(graph.nodes.len(), 2);

        // Edge:
        // func_UpdatePlayer → dll_classify_game_logic
        assert_eq!(graph.edges.len(), 1);
        assert!(
            graph
                .edges
                .iter()
                .any(|e| { e.from == "func_UpdatePlayer" && e.to == "dll_classify_game_logic" })
        );
    }

    // ── Topological order tests ──

    #[test]
    fn topological_order_respects_shim_dependencies() {
        let tracker = DependencyTracker;

        let classifications = vec![test_classification(
            "d3d9.dll",
            DllCategory::MicrosoftSdk,
            Some("wgpu"),
        )];

        let call_graph = vec![("DrawPrimitive", vec![])];

        let graph = tracker.build(&classifications, &call_graph);

        let (ordered, cycles) = graph.topological_order();
        assert!(cycles.is_empty(), "no cycles expected");
        let order_ids: Vec<&str> = ordered.iter().map(|n| n.unit_id.as_str()).collect();

        // Classification must come before shim, shim before function
        let classify_idx = order_ids
            .iter()
            .position(|&id| id == "dll_classify_d3d9")
            .unwrap();
        let shim_idx = order_ids
            .iter()
            .position(|&id| id == "shim_d3d9_wgpu")
            .unwrap();
        let func_idx = order_ids
            .iter()
            .position(|&id| id == "func_DrawPrimitive")
            .unwrap();

        assert!(classify_idx < shim_idx, "classification before shim");
        assert!(shim_idx < func_idx, "shim before function");
    }

    // ── Empty input tests ──

    #[test]
    fn build_empty_graph() {
        let tracker = DependencyTracker;
        let graph = tracker.build(&[], &[]);
        assert!(graph.nodes.is_empty());
        assert!(graph.edges.is_empty());
    }

    #[test]
    fn for_dll_empty_functions() {
        let tracker = DependencyTracker;

        let classification =
            test_classification("d3d9.dll", DllCategory::MicrosoftSdk, Some("wgpu"));

        let graph = tracker.for_dll(&classification, &[]);

        // Should have classification node + shim layer node
        assert_eq!(graph.nodes.len(), 2);
        assert!(graph.edges.len() == 1);
    }

    // ── Dependency detection tests ──

    #[test]
    fn detect_binary_from_function_with_dll_prefix() {
        // When function name has a prefix matching a classified DLL, the
        // inventory's verbatim identity comes back.
        let binary = DependencyTracker::detect_binary_from_function(
            "d3d9_DrawPrimitive",
            &[],
            &["d3d9.dll".to_string()],
        );
        assert_eq!(binary, Some("d3d9.dll".to_string()));
    }

    #[test]
    fn detect_binary_from_empty_function_returns_none() {
        let binary = DependencyTracker::detect_binary_from_function("", &[], &[]);
        assert!(binary.is_none());
    }

    #[test]
    fn detect_binary_from_function_resolves_exe_stem_to_verbatim_identity() {
        // A function-name hint originating from an .exe binary resolves to
        // the verbatim .exe identity — never a fabricated .dll (issue #70).
        let binary = DependencyTracker::detect_binary_from_function(
            "eqgame_RunLoop",
            &[],
            &["eqgame.exe".to_string()],
        );
        assert_eq!(binary, Some("eqgame.exe".to_string()));
    }

    #[test]
    fn detect_binary_from_function_never_fabricates_dll_extension() {
        // An extension-less candidate that matches no workspace binary
        // resolves to nothing rather than `{candidate}.dll` (issue #70).
        let binary =
            DependencyTracker::detect_binary_from_function("mysterylib_DrawSprite", &[], &[]);
        assert!(binary.is_none());
    }

    #[test]
    fn detect_binary_from_function_returns_inventory_spelling() {
        // The inventory's spelling of the identity wins over the candidate's.
        let binary = DependencyTracker::detect_binary_from_function(
            "EQGAME_RunLoop",
            &[],
            &["EqGame.exe".to_string()],
        );
        assert_eq!(binary, Some("EqGame.exe".to_string()));
    }

    #[test]
    fn detect_binary_from_function_neighbor_with_extension_is_verbatim() {
        // A neighbor that already carries a binary extension is an identity
        // verbatim — case preserved, no inventory entry required.
        let binary = DependencyTracker::detect_binary_from_function(
            "Init",
            &["EqGame.EXE".to_string()],
            &[],
        );
        assert_eq!(binary, Some("EqGame.EXE".to_string()));
    }

    #[test]
    fn build_graph_exe_function_hint_resolves_to_exe_classification() {
        let tracker = DependencyTracker;

        let classifications = vec![test_classification(
            "eqgame.exe",
            DllCategory::ProjectSpecific,
            None,
        )];

        let call_graph = vec![("eqgame_RunLoop", vec![])];

        let graph = tracker.build(&classifications, &call_graph);

        // The function depends on the exe's classification node — the
        // function-name hint resolved against the inventory, not a
        // fabricated dll (issue #70).
        assert!(
            graph
                .edges
                .iter()
                .any(|e| { e.from == "func_eqgame_RunLoop" && e.to == "dll_classify_eqgame.exe" })
        );
    }

    // ── DependencyGraphPersistor tests ──

    fn temp_workspace(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("calxgloss-test-graph-{}", name));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn persistor_create() {
        let ws = temp_workspace("create");
        let persistor = super::DependencyGraphPersistor::new(&ws);
        assert_eq!(persistor.workspace, ws);
    }

    #[test]
    fn persistor_graph_path_construction() {
        let ws = std::path::PathBuf::from("/workspace");
        let persistor = super::DependencyGraphPersistor::new(&ws);
        let expected = ws.join("re").join("analysis").join("dependency_graph.json");
        assert_eq!(persistor.graph_path(), expected);
    }

    #[test]
    fn persistor_save_and_load_round_trip() {
        let ws = temp_workspace("round_trip");
        let persistor = super::DependencyGraphPersistor::new(&ws);

        let tracker = DependencyTracker;
        let classifications = vec![test_classification(
            "d3d9.dll",
            DllCategory::MicrosoftSdk,
            Some("wgpu"),
        )];
        let call_graph = vec![("DrawPrimitive", vec![])];
        let graph = tracker.build(&classifications, &call_graph);

        persistor.save(&graph).expect("save should succeed");
        let loaded = persistor.load().expect("load should succeed");

        assert_eq!(loaded.nodes.len(), graph.nodes.len());
        assert_eq!(loaded.edges.len(), graph.edges.len());
        assert_eq!(loaded.nodes[0].unit_id, "dll_classify_d3d9");
        assert_eq!(loaded.nodes[1].unit_id, "shim_d3d9_wgpu");
    }

    #[test]
    fn persistor_load_nonexistent() {
        let ws = temp_workspace("nonexistent");
        let persistor = super::DependencyGraphPersistor::new(&ws);
        assert!(persistor.load().is_none());
    }

    #[test]
    fn persistor_persists_across_instances() {
        let ws = temp_workspace("persist_across");
        let persistor1 = super::DependencyGraphPersistor::new(&ws);

        let tracker = DependencyTracker;
        let classifications = vec![test_classification(
            "fmod.dll",
            DllCategory::KnownThirdParty,
            Some("fmod-rs"),
        )];
        let call_graph = vec![("OpenSound", vec![])];
        let graph = tracker.build(&classifications, &call_graph);

        persistor1.save(&graph).expect("save should succeed");

        // New instance should read the same file
        let persistor2 = super::DependencyGraphPersistor::new(&ws);
        let loaded = persistor2.load().expect("should load from disk");
        assert_eq!(loaded.nodes.len(), 3); // classification + shim + function
    }

    #[test]
    fn persistor_build_and_save() {
        let ws = temp_workspace("build_and_save");
        let persistor = super::DependencyGraphPersistor::new(&ws);

        let classifications = vec![test_classification(
            "game_logic.dll",
            DllCategory::ProjectSpecific,
            None,
        )];
        let call_graph = vec![("UpdatePlayer", vec!["UpdatePlayer".to_string()])];

        let graph = persistor
            .build_and_save(&classifications, &call_graph)
            .expect("build_and_save should succeed");

        assert_eq!(graph.nodes.len(), 2); // classification + function (no shim)
        // 2 edges: function → classification, function → function (self-edge from call graph)
        assert!(!graph.edges.is_empty());

        // Verify it can be loaded back
        let loaded = persistor.load().expect("should load after build_and_save");
        assert_eq!(loaded.nodes.len(), graph.nodes.len());
    }

    #[test]
    fn persistor_overwrites_existing() {
        let ws = temp_workspace("overwrite");
        let persistor = super::DependencyGraphPersistor::new(&ws);

        let tracker = DependencyTracker;

        // Save a 3-node graph
        let classifications_a = vec![test_classification(
            "d3d9.dll",
            DllCategory::MicrosoftSdk,
            Some("wgpu"),
        )];
        let call_graph_a = vec![("DrawPrimitive", vec![])];
        let graph_a = tracker.build(&classifications_a, &call_graph_a);
        persistor.save(&graph_a).expect("first save should succeed");

        // Overwrite with a 2-node graph
        let classifications_b = vec![test_classification(
            "kernel32.dll",
            DllCategory::WindowsOs,
            None,
        )];
        let call_graph_b = vec![("CreateFile", vec![])];
        let graph_b = tracker.build(&classifications_b, &call_graph_b);
        persistor
            .save(&graph_b)
            .expect("second save should succeed");

        // Should have the 2-node version, not the 3-node version
        let loaded = persistor.load().expect("should load overwritten graph");
        assert_eq!(loaded.nodes.len(), 2);
        assert_eq!(loaded.nodes[0].unit_id, "dll_classify_kernel32");
    }

    #[test]
    fn persistor_empty_graph() {
        let ws = temp_workspace("empty_graph");
        let persistor = super::DependencyGraphPersistor::new(&ws);

        let empty_graph = DependencyGraph {
            nodes: Vec::new(),
            edges: Vec::new(),
        };

        persistor
            .save(&empty_graph)
            .expect("save empty graph should succeed");

        let loaded = persistor.load().expect("load empty graph should succeed");
        assert!(loaded.nodes.is_empty());
        assert!(loaded.edges.is_empty());
    }

    #[test]
    fn persistor_directory_created_automatically() {
        let ws = temp_workspace("auto_dir");
        let persistor = super::DependencyGraphPersistor::new(&ws);

        // The re/analysis/ subdirectory does not exist yet
        let deep_path = ws.join("re").join("analysis").join("deep");
        assert!(!deep_path.exists());

        // Saving the graph should create all intermediate directories
        let tracker = DependencyTracker;
        let classifications = vec![test_classification(
            "test.dll",
            DllCategory::ProjectSpecific,
            None,
        )];
        let call_graph = vec![("TestFunc", vec![])];
        let graph = tracker.build(&classifications, &call_graph);

        persistor
            .save(&graph)
            .expect("save should create directories");
        assert!(persistor.graph_path().exists());
    }
}
