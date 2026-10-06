//! Dependency graph — nodes, edges, and topological sorting.

use serde::{Deserialize, Serialize};

use super::types::{ReviewStatus, WorkLevel};

// ============================================================
// DependencyNode
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
    pub level: WorkLevel,
}

impl DependencyNode {
    /// Creates a new dependency node.
    pub fn new(unit_id: impl Into<String>, name: impl Into<String>, status: ReviewStatus) -> Self {
        Self {
            unit_id: unit_id.into(),
            name: name.into(),
            status,
            level: WorkLevel::FunctionTranslation, // default: treat as function translation
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
        }
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
