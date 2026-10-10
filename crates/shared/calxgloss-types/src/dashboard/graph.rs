//! Dependency graph — nodes, edges, and topological sorting.

use serde::{Deserialize, Serialize};

use super::types::{ReviewStatus, WorkLevel};

// ============================================================
// DependencyNode
// ============================================================

/// A node in the dependency graph of units of work.
///
/// Beyond identity and status, a node carries display enrichment derived
/// from the unit it represents: the associated binary, the unit's token
/// usage, and its confidence. Each enrichment is optional — artifacts
/// written before these fields existed, or units with no recorded value,
/// leave them `None` rather than fabricating one.
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
    pub level: WorkLevel,
    /// The binary (DLL) this node's unit belongs to.
    ///
    /// `None` when the node predates binary attribution or no binary is
    /// associated with the unit.
    #[serde(default)]
    pub binary: Option<String>,
    /// Total tokens consumed by this unit across all recorded attempts.
    ///
    /// `None` when the token-usage log has no entries for this unit —
    /// consumers must not read that as "zero tokens".
    #[serde(default)]
    pub token_usage: Option<usize>,
    /// Unit confidence score (0.0 to 1.0).
    ///
    /// `None` when the unit has no recorded confidence.
    #[serde(default)]
    pub confidence: Option<f32>,
}

impl DependencyNode {
    /// Creates a new dependency node.
    pub fn new(unit_id: impl Into<String>, name: impl Into<String>, status: ReviewStatus) -> Self {
        Self {
            unit_id: unit_id.into(),
            name: name.into(),
            status,
            level: WorkLevel::FunctionTranslation, // default: treat as function translation
            binary: None,
            token_usage: None,
            confidence: None,
        }
    }

    /// Creates a dependency node with an explicit level.
    pub fn with_level(
        unit_id: impl Into<String>,
        name: impl Into<String>,
        status: ReviewStatus,
        level: WorkLevel,
    ) -> Self {
        Self {
            unit_id: unit_id.into(),
            name: name.into(),
            status,
            level,
            binary: None,
            token_usage: None,
            confidence: None,
        }
    }

    /// Sets the binary this node belongs to.
    pub fn with_binary(mut self, binary: impl Into<String>) -> Self {
        self.binary = Some(binary.into());
        self
    }

    /// Sets the total token usage recorded for this node's unit.
    pub fn with_token_usage(mut self, token_usage: usize) -> Self {
        self.token_usage = Some(token_usage);
        self
    }

    /// Sets the confidence score for this node's unit.
    pub fn with_confidence(mut self, confidence: f32) -> Self {
        self.confidence = Some(confidence);
        self
    }

    /// Sets the confidence when a value exists, leaving `None` honest.
    pub fn with_confidence_opt(mut self, confidence: Option<f32>) -> Self {
        self.confidence = confidence;
        self
    }
}

// ============================================================
// EdgeType
// ============================================================

/// The kind of relationship an edge represents.
///
/// The vocabulary is closed so the UI can label edges consistently:
/// scheduling dependencies, observed calls from call-graph data, and
/// data-flow relationships (produced by analyses that record them).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum EdgeType {
    /// One unit of work must be completed before the other can start.
    #[default]
    Dependency,
    /// The source function calls the target function (from call-graph data).
    Call,
    /// The source function consumes data produced by the target.
    DataFlow,
}

impl EdgeType {
    /// Returns a short snake_case label for display.
    pub fn label(&self) -> &'static str {
        match self {
            EdgeType::Dependency => "dependency",
            EdgeType::Call => "call",
            EdgeType::DataFlow => "data_flow",
        }
    }
}

impl std::fmt::Display for EdgeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

// ============================================================
// DependencyEdge
// ============================================================

/// An edge representing a dependency relationship between units of work.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyEdge {
    /// The unit that depends on another.
    pub from: String,
    /// The unit that is depended upon.
    pub to: String,
    /// The kind of relationship this edge encodes.
    ///
    /// Defaults to [`EdgeType::Dependency`] so artifacts written before
    /// edge typing existed still deserialize honestly — every old edge
    /// *is* a scheduling dependency.
    #[serde(default)]
    pub edge_type: EdgeType,
}

impl DependencyEdge {
    /// Creates a plain scheduling-dependency edge.
    pub fn new(from: impl Into<String>, to: impl Into<String>) -> Self {
        Self {
            from: from.into(),
            to: to.into(),
            edge_type: EdgeType::Dependency,
        }
    }

    /// Sets the relationship kind of this edge.
    pub fn with_type(mut self, edge_type: EdgeType) -> Self {
        self.edge_type = edge_type;
        self
    }
}

// ============================================================
// DependencyGraph
// ============================================================

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
        let get_level = |id: &str| -> WorkLevel {
            self.nodes
                .iter()
                .find(|n| n.unit_id == id)
                .map(|n| n.level)
                .unwrap_or(WorkLevel::FunctionTranslation)
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
