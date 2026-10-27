//! Translation ordering for the call graph-assisted translation pipeline.
//!
//! The [`TranslationOrderer`] turns a call graph into a priority-ordered
//! list of functions for the translation pipeline. The order follows each
//! function's call-graph classification: Root, Middle, or Leaf.
//!
//! # Algorithm
//!
//! 1. Put every function into one of three priority bands:
//!    - **Root** (priority 0) — entry points and runtime init. Handled
//!      first, so the functions that depend on them can be resolved.
//!    - **Middle** (priority 1) — application logic. Sorted topologically
//!      within the band, so a caller is translated after its callees.
//!    - **Leaf** (priority 2) — functions that call known third-party
//!      APIs. Handled last, once context enrichment is complete.
//! 2. Within each band, sort the functions topologically using the
//!    call-graph edges that stay inside that band. A function with no
//!    callees inside its own band comes first.
//! 3. When the orderer is given a state-sharing edge set — taken from the
//!    persisted shared-globals index, never from a running scan — it also
//!    places each global's first definer before the other functions that
//!    touch it, within the same band. These edges extend the call-graph
//!    edges; they never replace them. An empty set leaves the order
//!    exactly as step 2 produces it.
//!
//! # Example
//!
//! ```no_run
//! use calxgloss_callgraph::{CallGraph, TranslationOrderer, NodeCategory, FunctionCallGraph, CallGraphEdge, CallType};
//!
//! # fn example() -> anyhow::Result<()> {
//! let graph = CallGraph {
//!     binary: "example.dll".to_string(),
//!     functions: vec![
//!         FunctionCallGraph {
//!             name: "WinMain".to_string(),
//!             address: 0x401000,
//!             callers: vec![],
//!             callees: vec![CallGraphEdge {
//!                 source: 0x401000,
//!                 target: 0x402000,
//!                 call_site: 0,
//!                 call_type: CallType::Direct,
//!                 callee_name: "app_init".to_string(),
//!             }],
//!             node_category: NodeCategory::Root,
//!         },
//!         FunctionCallGraph {
//!             name: "app_init".to_string(),
//!             address: 0x402000,
//!             callers: vec![0x401000],
//!             callees: vec![],
//!             node_category: NodeCategory::Middle,
//!         },
//!     ],
//! };
//!
//! let orderer = TranslationOrderer::new();
//! let plan = orderer.order(&graph)?;
//! assert_eq!(plan.len(), 2);
//! # Ok(())
//! # }
//! ```

use anyhow::{Result, bail};
use std::collections::{HashMap, HashSet, VecDeque};
use tracing::debug;

use crate::{CallGraph, NodeCategory};

/// State-sharing edges between units that touch the same program global
/// (issue #256, part of #225).
///
/// For each global the shared-globals index names, the first function that
/// writes it — the definer — must enter the translation queue before every
/// other function that touches the global, so the unit establishing the
/// global's representation is translated before the units that reuse it.
/// `calxgloss_globalstate::rollup::state_sharing_pairs` derives the pairs
/// from the persisted index records; a consumer that has no global-state
/// document supplies an empty set.
///
/// The set is an extension of the call-graph edges, not a replacement: an
/// empty set reproduces today's dependency order exactly. The orderer only
/// ever reads the persisted artifact behind the pairs — it never runs the
/// global-state scan itself.
#[derive(Debug, Clone, Default)]
pub struct StateSharingEdges {
    /// `(definer, reuser)` function-name pairs, in the index's own order.
    pairs: Vec<(String, String)>,
}

impl StateSharingEdges {
    /// Builds the edge set from `(definer, reuser)` function-name pairs —
    /// the shape `calxgloss_globalstate::rollup::state_sharing_pairs`
    /// answers from the shared-globals index.
    pub fn from_pairs(pairs: impl IntoIterator<Item = (String, String)>) -> Self {
        Self {
            pairs: pairs.into_iter().collect(),
        }
    }
}

/// Priority band for a function in the translation pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum TranslationPriority {
    /// Root functions — entry points and runtime init. Handled first.
    Root = 0,
    /// Middle functions — application logic. Handled after root.
    Middle = 1,
    /// Leaf functions — call known third-party APIs. Handled last.
    Leaf = 2,
}

impl TranslationPriority {
    /// Returns a human-readable label for this priority band.
    pub fn label(&self) -> &'static str {
        match self {
            TranslationPriority::Root => "root",
            TranslationPriority::Middle => "middle",
            TranslationPriority::Leaf => "leaf",
        }
    }
}

impl From<NodeCategory> for TranslationPriority {
    fn from(category: NodeCategory) -> Self {
        match category {
            NodeCategory::Root => TranslationPriority::Root,
            NodeCategory::Middle => TranslationPriority::Middle,
            NodeCategory::Leaf => TranslationPriority::Leaf,
            NodeCategory::Skip => TranslationPriority::Root,
        }
    }
}

/// Metadata about a function as it appears in the translation plan.
#[derive(Debug, Clone)]
pub struct FunctionTranslationPlan {
    /// The function's name.
    pub name: String,
    /// The function's entry address.
    pub address: u64,
    /// Priority band for translation ordering.
    pub priority: TranslationPriority,
    /// Call-graph classification of the function.
    ///
    /// This keeps the full [`NodeCategory`] so that the translation
    /// pipeline can tell entry points (Root) apart from runtime library
    /// functions (Skip): both map to the same
    /// [`TranslationPriority::Root`], but they need different handling.
    pub category: NodeCategory,
    /// Number of functions that call this one.
    pub caller_count: usize,
    /// Number of functions this one calls.
    pub callee_count: usize,
    /// Names of functions that call this one.
    pub caller_names: Vec<String>,
    /// Names of functions this one calls.
    pub callee_names: Vec<String>,
}

/// Produces a priority-ordered list of functions for the translation pipeline.
///
/// # Algorithm
///
/// 1. Build an address-to-function lookup from the call graph.
/// 2. Assign each function a [`TranslationPriority`] based on its
///    [`NodeCategory`].
/// 3. Within each priority band, perform a topological sort using only
///    the call-graph edges that stay inside that band, plus any
///    [`StateSharingEdges`] supplied via [`Self::with_state_sharing`].
/// 4. A function is ready once every callee it has inside its own band
///    is placed. Functions that form cycles never become ready this way
///    and are placed at the end of their band, in address order. Call
///    edges that point outside the band or outside the graph are ignored.
///
/// # Order Guarantee
///
/// The returned list is a [`VecDeque`] so that the translation pipeline
/// can efficiently dequeue the next function to translate. The order
/// satisfies:
///
/// - All root functions appear before all middle functions.
/// - All middle functions appear before all leaf functions.
/// - Within each band, a function appears after all of its callees that
///   are in the same band (callees before callers). Functions appended
///   at the end of a band because they form a cycle are the exception.
/// - When state-sharing edges are supplied, within each band a global's
///   first definer appears before the other functions that touch it,
///   unless a cycle among those functions forces the same exception.
pub struct TranslationOrderer {
    /// Maximum number of functions to order per target binary. Zero
    /// means unlimited.
    max_functions: usize,
    /// State-sharing edges from the persisted shared-globals index, empty
    /// when none were supplied (issue #256).
    state_sharing: StateSharingEdges,
}

impl TranslationOrderer {
    /// Creates a new `TranslationOrderer` with unlimited ordering.
    pub fn new() -> Self {
        Self {
            max_functions: 0,
            state_sharing: StateSharingEdges::default(),
        }
    }

    /// Creates a new `TranslationOrderer` that orders at most
    /// `max_functions` functions per target binary.
    pub fn with_max_functions(mut self, max_functions: usize) -> Self {
        self.max_functions = max_functions;
        self
    }

    /// Adds state-sharing edges to the ordering input. They come from the
    /// persisted shared-globals index (issue #256, part of #225). These
    /// edges go through the same per-band topological sort as the
    /// call-graph edges: within a band, a global's first definer is
    /// placed before the other functions that touch it. If the
    /// state-sharing edges form a cycle, the existing tie-break takes
    /// over — the functions involved are appended at the end of their
    /// band in address order and are never dropped. An empty set leaves
    /// today's dependency order exactly in force.
    pub fn with_state_sharing(mut self, edges: StateSharingEdges) -> Self {
        self.state_sharing = edges;
        self
    }

    /// Produces a priority-ordered translation plan from the given call graph.
    ///
    /// Returns an empty plan if the graph contains no functions.
    ///
    /// # Errors
    ///
    /// Returns an error if the graph contains functions whose addresses
    /// are duplicated (which would make topological sorting ambiguous).
    pub fn order(&self, graph: &CallGraph) -> Result<VecDeque<FunctionTranslationPlan>> {
        if graph.functions.is_empty() {
            debug!(binary = %graph.binary, "Empty call graph; returning empty plan");
            return Ok(VecDeque::new());
        }

        // Map each address to the index of its function, so a call edge
        // can quickly find the function it points to.
        let mut addr_to_index: HashMap<u64, usize> = HashMap::with_capacity(graph.functions.len());
        let mut seen_addresses: HashSet<u64> = HashSet::new();

        for (i, func) in graph.functions.iter().enumerate() {
            if !seen_addresses.insert(func.address) {
                bail!(
                    "Duplicate function address 0x{:x} for '{}'; cannot order graph",
                    func.address,
                    func.name
                );
            }
            addr_to_index.insert(func.address, i);
        }

        // Group functions by priority band.
        let mut tiers: HashMap<TranslationPriority, Vec<usize>> = HashMap::new();
        for (i, func) in graph.functions.iter().enumerate() {
            let priority: TranslationPriority = func.node_category.clone().into();
            tiers.entry(priority).or_default().push(i);
        }

        // Topologically sort each band and collect the final plan.
        let mut plan: VecDeque<FunctionTranslationPlan> =
            VecDeque::with_capacity(graph.functions.len());

        // Process the bands in priority order (Root → Middle → Leaf).
        for priority in [
            TranslationPriority::Root,
            TranslationPriority::Middle,
            TranslationPriority::Leaf,
        ] {
            let tier_indices = match tiers.get(&priority) {
                Some(indices) if !indices.is_empty() => indices,
                _ => continue,
            };

            debug!(
                tier = priority.label(),
                count = tier_indices.len(),
                "Sorting tier"
            );

            let sorted = self.topological_sort_tier(
                tier_indices,
                &addr_to_index,
                &self.state_sharing,
                graph,
            );
            for &idx in &sorted {
                let func = &graph.functions[idx];
                let caller_names = func
                    .callers
                    .iter()
                    .filter_map(|&caller_addr| {
                        addr_to_index
                            .get(&caller_addr)
                            .map(|&caller_idx| graph.functions[caller_idx].name.clone())
                    })
                    .collect();
                let callee_names = func
                    .callees
                    .iter()
                    .map(|edge| edge.callee_name.clone())
                    .collect();

                plan.push_back(FunctionTranslationPlan {
                    name: func.name.clone(),
                    address: func.address,
                    priority,
                    category: func.node_category.clone(),
                    caller_count: func.callers.len(),
                    callee_count: func.callees.len(),
                    caller_names,
                    callee_names,
                });
            }
        }

        // Enforce max_functions limit if set.
        if self.max_functions > 0 && plan.len() > self.max_functions {
            debug!(
                current = plan.len(),
                max = self.max_functions,
                "Trimming plan to max_functions limit"
            );
            let to_remove = plan.len() - self.max_functions;
            plan.truncate(self.max_functions);
            debug!(removed = to_remove, "Trimmed functions from plan");
        }

        debug!(
            binary = %graph.binary,
            total = plan.len(),
            "Translation plan generated"
        );

        Ok(plan)
    }

    /// Topologically sorts one band of function indices.
    ///
    /// Uses Kahn's algorithm. A call edge only counts when its callee is
    /// in the same band; a state-sharing edge only counts when both its
    /// definer and its reuser resolve to this band. Functions left over
    /// in cycles, which the sort can never place, go at the end of the
    /// sorted list.
    fn topological_sort_tier(
        &self,
        tier_indices: &[usize],
        addr_to_index: &HashMap<u64, usize>,
        state_sharing: &StateSharingEdges,
        graph: &CallGraph,
    ) -> Vec<usize> {
        let tier_set: HashSet<usize> = tier_indices.iter().copied().collect();

        // Build the in-degree map using only edges inside this band.
        // We want callees before callers, so each adjacency edge points
        // from the callee to the caller, and a node's in-degree is the
        // number of its callees inside the band.
        let mut in_degree: HashMap<usize, usize> = HashMap::new();
        let mut adj: HashMap<usize, Vec<usize>> = HashMap::new();

        for &idx in tier_indices {
            in_degree.entry(idx).or_insert(0);
            let func = &graph.functions[idx];
            for edge in &func.callees {
                if let Some(&callee_idx) = addr_to_index.get(&edge.target)
                    && tier_set.contains(&callee_idx)
                    && callee_idx != idx
                {
                    // Edge: callee_idx → idx (callee must be placed before caller)
                    adj.entry(callee_idx).or_default().push(idx);
                    *in_degree.entry(idx).or_insert(0) += 1;
                }
            }
        }

        // State-sharing edges join the same sort (issue #256): the
        // definer must be placed before each function that reuses its
        // global. The index names functions by name, so resolve those
        // names to this band's nodes — a name outside the band (or
        // outside the graph) simply contributes nothing here.
        let mut name_to_index: HashMap<&str, usize> = HashMap::new();
        for &idx in tier_indices {
            name_to_index
                .entry(graph.functions[idx].name.as_str())
                .or_insert(idx);
        }
        for (definer, reuser) in &state_sharing.pairs {
            let (Some(from), Some(to)) = (
                name_to_index.get(definer.as_str()).copied(),
                name_to_index.get(reuser.as_str()).copied(),
            ) else {
                continue;
            };
            if from != to {
                // Edge: from → to (definer must be placed before reuser)
                adj.entry(from).or_default().push(to);
                *in_degree.entry(to).or_insert(0) += 1;
            }
        }

        // Kahn's algorithm: start with zero in-degree nodes.
        let mut queue: VecDeque<usize> = VecDeque::new();
        let mut zero_degree: Vec<usize> = Vec::new();
        for &idx in tier_indices {
            if in_degree.get(&idx).copied().unwrap_or(0) == 0 {
                zero_degree.push(idx);
            }
        }

        // Sort the initial queue by address for deterministic output.
        zero_degree.sort_by_key(|&idx| graph.functions[idx].address);
        queue.extend(zero_degree);

        let mut sorted: Vec<usize> = Vec::with_capacity(tier_indices.len());
        let mut visited: HashSet<usize> = HashSet::with_capacity(tier_indices.len());

        while let Some(current) = queue.pop_front() {
            sorted.push(current);
            visited.insert(current);

            for &neighbor in adj.get(&current).into_iter().flatten() {
                let new_degree = in_degree.get_mut(&neighbor).map(|d| {
                    *d -= 1;
                    *d
                });
                if let Some(0) = new_degree {
                    queue.push_back(neighbor);
                }
            }
        }

        // Any unvisited nodes are in cycles — append them in address order.
        let mut cycle_nodes: Vec<usize> = tier_indices
            .iter()
            .copied()
            .filter(|&idx| !visited.contains(&idx))
            .collect();
        cycle_nodes.sort_by_key(|&idx| graph.functions[idx].address);

        sorted.extend(cycle_nodes);

        debug!(
            tier_size = tier_indices.len(),
            sorted = sorted.len(),
            cycles = queue.len(),
            "Topological sort complete"
        );

        sorted
    }
}

impl Default for TranslationOrderer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FunctionCallGraph;
    use crate::{CallGraphEdge, CallType};

    fn make_func(
        name: &str,
        address: u64,
        callers: Vec<u64>,
        callee_edges: Vec<CallGraphEdge>,
        category: NodeCategory,
    ) -> FunctionCallGraph {
        FunctionCallGraph {
            name: name.to_string(),
            address,
            callers,
            callees: callee_edges,
            node_category: category,
        }
    }

    fn make_edge(source: u64, target: u64, callee_name: &str) -> CallGraphEdge {
        CallGraphEdge {
            source,
            target,
            call_site: 0,
            call_type: CallType::Direct,
            callee_name: callee_name.to_string(),
        }
    }

    // ─── Priority band classification tests ───

    #[test]
    fn test_translation_priority_from_node_category() {
        assert_eq!(
            TranslationPriority::from(NodeCategory::Root),
            TranslationPriority::Root
        );
        assert_eq!(
            TranslationPriority::from(NodeCategory::Middle),
            TranslationPriority::Middle
        );
        assert_eq!(
            TranslationPriority::from(NodeCategory::Leaf),
            TranslationPriority::Leaf
        );
        assert_eq!(
            TranslationPriority::from(NodeCategory::Skip),
            TranslationPriority::Root
        );
    }

    #[test]
    fn test_translation_priority_ordering() {
        assert!(TranslationPriority::Root < TranslationPriority::Middle);
        assert!(TranslationPriority::Middle < TranslationPriority::Leaf);
        assert!(TranslationPriority::Root < TranslationPriority::Leaf);
    }

    #[test]
    fn test_priority_label() {
        assert_eq!(TranslationPriority::Root.label(), "root");
        assert_eq!(TranslationPriority::Middle.label(), "middle");
        assert_eq!(TranslationPriority::Leaf.label(), "leaf");
    }

    // ─── Order tests ───

    #[test]
    fn test_empty_graph_returns_empty_plan() {
        let graph = CallGraph {
            binary: "empty.dll".to_string(),
            functions: vec![],
        };
        let orderer = TranslationOrderer::new();
        let plan = orderer.order(&graph).unwrap();
        assert!(plan.is_empty());
    }

    #[test]
    fn test_root_functions_comes_first() {
        let graph = CallGraph {
            binary: "roots.dll".to_string(),
            functions: vec![
                make_func(
                    "app_logic",
                    0x402000,
                    vec![],
                    vec![make_edge(0x402000, 0x403000, "dll_entry")],
                    NodeCategory::Middle,
                ),
                make_func(
                    "dll_entry",
                    0x403000,
                    vec![0x402000],
                    vec![],
                    NodeCategory::Root,
                ),
            ],
        };

        let orderer = TranslationOrderer::new();
        let plan = orderer.order(&graph).unwrap();

        assert_eq!(plan.len(), 2);
        assert_eq!(plan[0].name, "dll_entry");
        assert_eq!(plan[0].priority, TranslationPriority::Root);
        assert_eq!(plan[1].name, "app_logic");
        assert_eq!(plan[1].priority, TranslationPriority::Middle);
    }

    #[test]
    fn test_leaf_functions_comes_last() {
        let graph = CallGraph {
            binary: "leaves.dll".to_string(),
            functions: vec![
                make_func(
                    "render_frame",
                    0x401000,
                    vec![],
                    vec![make_edge(0x401000, 0x403000, "Direct3DCreate9")],
                    NodeCategory::Leaf,
                ),
                make_func(
                    "game_loop",
                    0x402000,
                    vec![],
                    vec![make_edge(0x402000, 0x401000, "render_frame")],
                    NodeCategory::Middle,
                ),
            ],
        };

        let orderer = TranslationOrderer::new();
        let plan = orderer.order(&graph).unwrap();

        assert_eq!(plan.len(), 2);
        // Middle band: game_loop
        // Leaf band: render_frame
        assert_eq!(plan[0].name, "game_loop");
        assert_eq!(plan[0].priority, TranslationPriority::Middle);
        assert_eq!(plan[1].name, "render_frame");
        assert_eq!(plan[1].priority, TranslationPriority::Leaf);
    }

    #[test]
    fn test_topological_order_within_tier() {
        // app_init calls game_loop, which calls render_frame.
        // All three are in the middle band; the topological sort should
        // put each callee before its caller.
        let graph = CallGraph {
            binary: "topo.dll".to_string(),
            functions: vec![
                make_func(
                    "app_init",
                    0x403000,
                    vec![],
                    vec![make_edge(0x403000, 0x402000, "game_loop")],
                    NodeCategory::Middle,
                ),
                make_func(
                    "game_loop",
                    0x402000,
                    vec![0x403000],
                    vec![make_edge(0x402000, 0x401000, "render_frame")],
                    NodeCategory::Middle,
                ),
                make_func(
                    "render_frame",
                    0x401000,
                    vec![0x402000],
                    vec![],
                    NodeCategory::Middle,
                ),
            ],
        };

        let orderer = TranslationOrderer::new();
        let plan = orderer.order(&graph).unwrap();

        assert_eq!(plan.len(), 3);
        // render_frame (no callees inside the band) → game_loop → app_init
        assert_eq!(plan[0].name, "render_frame");
        assert_eq!(plan[1].name, "game_loop");
        assert_eq!(plan[2].name, "app_init");
    }

    #[test]
    fn test_function_plan_includes_metadata() {
        let graph = CallGraph {
            binary: "metadata.dll".to_string(),
            functions: vec![
                // Caller A
                make_func(
                    "caller_a",
                    0x401000,
                    vec![],
                    vec![make_edge(0x401000, 0x402000, "middle_fn")],
                    NodeCategory::Middle,
                ),
                // Caller B
                make_func(
                    "caller_b",
                    0x403000,
                    vec![],
                    vec![make_edge(0x403000, 0x402000, "middle_fn")],
                    NodeCategory::Middle,
                ),
                // Middle function with 2 callers and 2 callees
                make_func(
                    "middle_fn",
                    0x402000,
                    vec![0x401000, 0x403000],
                    vec![
                        make_edge(0x402000, 0x404000, "Direct3DCreate9"),
                        make_edge(0x402000, 0x405000, "internal_helper"),
                    ],
                    NodeCategory::Middle,
                ),
            ],
        };

        let orderer = TranslationOrderer::new();
        let plan = orderer.order(&graph).unwrap();

        assert_eq!(plan.len(), 3);

        let middle = plan.iter().find(|f| f.name == "middle_fn").unwrap();
        assert_eq!(middle.name, "middle_fn");
        assert_eq!(middle.address, 0x402000);
        assert_eq!(middle.priority, TranslationPriority::Middle);
        assert_eq!(middle.caller_count, 2);
        assert_eq!(middle.callee_count, 2);
        assert_eq!(middle.caller_names.len(), 2);
        assert_eq!(middle.callee_names.len(), 2);
        assert!(middle.callee_names.contains(&"Direct3DCreate9".to_string()));
        assert!(middle.callee_names.contains(&"internal_helper".to_string()));
    }

    #[test]
    fn test_all_three_tiers() {
        let graph = CallGraph {
            binary: "three_tiers.dll".to_string(),
            functions: vec![
                // Root: WinMain
                make_func(
                    "WinMain",
                    0x401000,
                    vec![],
                    vec![make_edge(0x401000, 0x402000, "app_init")],
                    NodeCategory::Root,
                ),
                // Middle: app_init
                make_func(
                    "app_init",
                    0x402000,
                    vec![0x401000],
                    vec![make_edge(0x402000, 0x403000, "game_loop")],
                    NodeCategory::Middle,
                ),
                // Middle: game_loop
                make_func(
                    "game_loop",
                    0x403000,
                    vec![0x402000],
                    vec![make_edge(0x403000, 0x404000, "render_frame")],
                    NodeCategory::Middle,
                ),
                // Leaf: render_frame
                make_func(
                    "render_frame",
                    0x404000,
                    vec![0x403000],
                    vec![make_edge(0x404000, 0x500000, "Direct3DCreate9")],
                    NodeCategory::Leaf,
                ),
            ],
        };

        let orderer = TranslationOrderer::new();
        let plan = orderer.order(&graph).unwrap();

        assert_eq!(plan.len(), 4);
        assert_eq!(plan[0].name, "WinMain");
        assert_eq!(plan[0].priority, TranslationPriority::Root);
        assert_eq!(plan[1].name, "game_loop");
        assert_eq!(plan[1].priority, TranslationPriority::Middle);
        assert_eq!(plan[2].name, "app_init");
        assert_eq!(plan[2].priority, TranslationPriority::Middle);
        assert_eq!(plan[3].name, "render_frame");
        assert_eq!(plan[3].priority, TranslationPriority::Leaf);
    }

    #[test]
    fn test_duplicate_address_returns_error() {
        let graph = CallGraph {
            binary: "dup.dll".to_string(),
            functions: vec![
                make_func("func_a", 0x1000, vec![], vec![], NodeCategory::Middle),
                make_func("func_b", 0x1000, vec![], vec![], NodeCategory::Middle),
            ],
        };

        let orderer = TranslationOrderer::new();
        let result = orderer.order(&graph);
        assert!(result.is_err());
    }

    #[test]
    fn test_max_functions_truncation() {
        let graph = CallGraph {
            binary: "trunc.dll".to_string(),
            functions: vec![
                make_func("fn_a", 0x1000, vec![], vec![], NodeCategory::Middle),
                make_func("fn_b", 0x2000, vec![], vec![], NodeCategory::Middle),
                make_func("fn_c", 0x3000, vec![], vec![], NodeCategory::Middle),
                make_func("fn_d", 0x4000, vec![], vec![], NodeCategory::Middle),
            ],
        };

        let orderer = TranslationOrderer::new().with_max_functions(2);
        let plan = orderer.order(&graph).unwrap();
        assert_eq!(plan.len(), 2);
    }

    #[test]
    fn test_skip_category_treated_as_root() {
        let graph = CallGraph {
            binary: "skip.dll".to_string(),
            functions: vec![
                make_func(
                    "runtime_helper",
                    0x401000,
                    vec![],
                    vec![make_edge(0x401000, 0x402000, "app_fn")],
                    NodeCategory::Skip,
                ),
                make_func(
                    "app_fn",
                    0x402000,
                    vec![0x401000],
                    vec![],
                    NodeCategory::Middle,
                ),
            ],
        };

        let orderer = TranslationOrderer::new();
        let plan = orderer.order(&graph).unwrap();

        assert_eq!(plan.len(), 2);
        assert_eq!(plan[0].priority, TranslationPriority::Root);
        assert_eq!(plan[0].name, "runtime_helper");
        assert_eq!(plan[1].priority, TranslationPriority::Middle);
    }

    #[test]
    fn test_plan_includes_node_category() {
        let graph = CallGraph {
            binary: "categories.dll".to_string(),
            functions: vec![
                make_func("WinMain", 0x401000, vec![], vec![], NodeCategory::Root),
                make_func(
                    "runtime_helper",
                    0x402000,
                    vec![],
                    vec![],
                    NodeCategory::Skip,
                ),
                make_func("app_logic", 0x403000, vec![], vec![], NodeCategory::Middle),
                make_func("render_frame", 0x404000, vec![], vec![], NodeCategory::Leaf),
            ],
        };

        let orderer = TranslationOrderer::new();
        let plan = orderer.order(&graph).unwrap();

        assert_eq!(plan.len(), 4);

        let winmain = plan.iter().find(|f| f.name == "WinMain").unwrap();
        assert_eq!(winmain.category, NodeCategory::Root);
        assert_eq!(winmain.priority, TranslationPriority::Root);

        let runtime = plan.iter().find(|f| f.name == "runtime_helper").unwrap();
        assert_eq!(runtime.category, NodeCategory::Skip);
        assert_eq!(runtime.priority, TranslationPriority::Root);

        let app = plan.iter().find(|f| f.name == "app_logic").unwrap();
        assert_eq!(app.category, NodeCategory::Middle);
        assert_eq!(app.priority, TranslationPriority::Middle);

        let render = plan.iter().find(|f| f.name == "render_frame").unwrap();
        assert_eq!(render.category, NodeCategory::Leaf);
        assert_eq!(render.priority, TranslationPriority::Leaf);
    }

    #[test]
    fn test_function_with_no_internal_callees_comes_first_in_tier() {
        // Two middle functions. The caller's only call edge leaves the
        // band (leaf_func is not in the band); callee_in_tier has no
        // call edges at all.
        let graph = CallGraph {
            binary: "no_internal.dll".to_string(),
            functions: vec![
                make_func(
                    "caller",
                    0x402000,
                    vec![],
                    vec![make_edge(0x402000, 0x500000, "leaf_func")],
                    NodeCategory::Middle,
                ),
                make_func(
                    "callee_in_tier",
                    0x401000,
                    vec![0x402000],
                    vec![],
                    NodeCategory::Middle,
                ),
            ],
        };

        let orderer = TranslationOrderer::new();
        let plan = orderer.order(&graph).unwrap();

        assert_eq!(plan.len(), 2);
        // Both functions have no callees inside the band, so both start
        // ready; callee_in_tier wins the tie-break because its address
        // is lower (leaf_func is outside the band).
        assert_eq!(plan[0].name, "callee_in_tier");
        assert_eq!(plan[1].name, "caller");
    }

    #[test]
    fn test_cyclic_functions_appended_at_end_of_tier() {
        // A calls B, B calls A — a cycle inside one band.
        let graph = CallGraph {
            binary: "cycle.dll".to_string(),
            functions: vec![
                make_func(
                    "func_a",
                    0x402000,
                    vec![0x401000],
                    vec![make_edge(0x402000, 0x401000, "func_b")],
                    NodeCategory::Middle,
                ),
                make_func(
                    "func_b",
                    0x401000,
                    vec![0x402000],
                    vec![make_edge(0x401000, 0x402000, "func_a")],
                    NodeCategory::Middle,
                ),
                make_func(
                    "independent",
                    0x403000,
                    vec![],
                    vec![],
                    NodeCategory::Middle,
                ),
            ],
        };

        let orderer = TranslationOrderer::new();
        let plan = orderer.order(&graph).unwrap();

        assert_eq!(plan.len(), 3);
        // independent has no cycle, should come first
        assert_eq!(plan[0].name, "independent");
        // func_a and func_b are in a cycle; order among them is by address
        assert_eq!(plan[1].name, "func_b");
        assert_eq!(plan[2].name, "func_a");
    }

    // ─── State-sharing edge tests (issue #256) ───

    use calxgloss_globalstate::persist::GlobalStatePersistor;
    use calxgloss_globalstate::rollup::state_sharing_pairs;
    use calxgloss_globalstate::types::{GlobalStateFinding, GlobalStateResult, SharedGlobalRecord};
    use calxgloss_types::ScanMetadata;

    fn shared_index_entry(global: &str, writers: &[&str], readers: &[&str]) -> SharedGlobalRecord {
        SharedGlobalRecord {
            global: global.to_string(),
            writers: writers.iter().map(|f| f.to_string()).collect(),
            readers: readers.iter().map(|f| f.to_string()).collect(),
            confidence: 85.into(),
        }
    }

    /// Builds edges from the given index entries the same way the real
    /// pipeline seam does — the path a pipeline consumer takes.
    fn edges_from(entries: &[SharedGlobalRecord]) -> StateSharingEdges {
        StateSharingEdges::from_pairs(state_sharing_pairs(entries))
    }

    fn plan_names(plan: &VecDeque<FunctionTranslationPlan>) -> Vec<&str> {
        plan.iter().map(|f| f.name.as_str()).collect()
    }

    #[test]
    fn test_empty_state_sharing_reproduces_dependency_order() {
        // The same graph ordered with and without an empty edge set must
        // come out identical — the set extends the ordering input, it
        // never rewrites it.
        let graph = CallGraph {
            binary: "sharing.dll".to_string(),
            functions: vec![
                make_func(
                    "WinMain",
                    0x401000,
                    vec![],
                    vec![make_edge(0x401000, 0x402000, "app_init")],
                    NodeCategory::Root,
                ),
                make_func(
                    "app_init",
                    0x402000,
                    vec![0x401000],
                    vec![make_edge(0x402000, 0x403000, "game_loop")],
                    NodeCategory::Middle,
                ),
                make_func(
                    "game_loop",
                    0x403000,
                    vec![0x402000],
                    vec![make_edge(0x403000, 0x404000, "render_frame")],
                    NodeCategory::Middle,
                ),
                make_func(
                    "render_frame",
                    0x404000,
                    vec![0x403000],
                    vec![make_edge(0x404000, 0x500000, "Direct3DCreate9")],
                    NodeCategory::Leaf,
                ),
            ],
        };

        let plain = TranslationOrderer::new().order(&graph).unwrap();
        let empty = TranslationOrderer::new()
            .with_state_sharing(StateSharingEdges::default())
            .order(&graph)
            .unwrap();
        assert_eq!(plan_names(&plain), plan_names(&empty));
        assert_eq!(
            plan_names(&empty),
            vec!["WinMain", "game_loop", "app_init", "render_frame"]
        );
    }

    #[test]
    fn test_first_definer_precedes_reusers_within_tier() {
        // Three middle functions with no call edges between them: with
        // no edges, address order alone puts the lower-addressed reader
        // first. The index names one writer and two readers — the writer
        // defines the global's representation, and it must come first.
        let graph = CallGraph {
            binary: "shared.dll".to_string(),
            functions: vec![
                make_func("reader_a", 0x401000, vec![], vec![], NodeCategory::Middle),
                make_func("writer_b", 0x402000, vec![], vec![], NodeCategory::Middle),
                make_func("reader_c", 0x403000, vec![], vec![], NodeCategory::Middle),
            ],
        };

        let plain = TranslationOrderer::new().order(&graph).unwrap();
        assert_eq!(plan_names(&plain), vec!["reader_a", "writer_b", "reader_c"]);

        let edges = edges_from(&[shared_index_entry(
            "DAT_180064e80",
            &["writer_b"],
            &["reader_a", "reader_c"],
        )]);
        let ordered = TranslationOrderer::new()
            .with_state_sharing(edges)
            .order(&graph)
            .unwrap();
        assert_eq!(
            plan_names(&ordered),
            vec!["writer_b", "reader_a", "reader_c"]
        );
    }

    #[test]
    fn test_first_writer_in_listing_order_is_the_definer() {
        // Two functions write one global. The index lists the writer it
        // sighted first ahead of the other one, and that first-sighted
        // writer — not the one with the lower address — establishes the
        // representation and is ordered first.
        let graph = CallGraph {
            binary: "twowriters.dll".to_string(),
            functions: vec![
                make_func(
                    "second_writer",
                    0x401000,
                    vec![],
                    vec![],
                    NodeCategory::Middle,
                ),
                make_func(
                    "first_writer",
                    0x402000,
                    vec![],
                    vec![],
                    NodeCategory::Middle,
                ),
            ],
        };

        let edges = edges_from(&[shared_index_entry(
            "g_counter",
            &["first_writer", "second_writer"],
            &[],
        )]);
        let ordered = TranslationOrderer::new()
            .with_state_sharing(edges)
            .order(&graph)
            .unwrap();
        assert_eq!(plan_names(&ordered), vec!["first_writer", "second_writer"]);
    }

    #[test]
    fn test_readers_only_global_adds_no_edges() {
        // A global no function writes establishes no representation. The
        // degenerate index entry contributes nothing, and the band keeps
        // its plain address order.
        let graph = CallGraph {
            binary: "readonly.dll".to_string(),
            functions: vec![
                make_func("reader_a", 0x401000, vec![], vec![], NodeCategory::Middle),
                make_func("reader_b", 0x402000, vec![], vec![], NodeCategory::Middle),
            ],
        };

        let edges = edges_from(&[shared_index_entry(
            "DAT_readonly",
            &[],
            &["reader_a", "reader_b"],
        )]);
        let ordered = TranslationOrderer::new()
            .with_state_sharing(edges)
            .order(&graph)
            .unwrap();
        assert_eq!(plan_names(&ordered), vec!["reader_a", "reader_b"]);
    }

    #[test]
    fn test_state_sharing_cycles_fall_back_to_tie_break() {
        // Two globals: each function defines the global the other one
        // reuses, so the state-sharing edges form a cycle. Kahn's drain
        // stops before the pair. The existing tie-break takes over: the
        // pair is appended at the end of the band in address order, with
        // no hang and no dropped unit.
        let graph = CallGraph {
            binary: "sharing_cycle.dll".to_string(),
            functions: vec![
                make_func("func_a", 0x401000, vec![], vec![], NodeCategory::Middle),
                make_func("func_b", 0x402000, vec![], vec![], NodeCategory::Middle),
                make_func(
                    "independent",
                    0x403000,
                    vec![],
                    vec![],
                    NodeCategory::Middle,
                ),
            ],
        };

        let edges = edges_from(&[
            shared_index_entry("DAT_one", &["func_b"], &["func_a"]),
            shared_index_entry("DAT_two", &["func_a"], &["func_b"]),
        ]);
        let ordered = TranslationOrderer::new()
            .with_state_sharing(edges)
            .order(&graph)
            .unwrap();
        assert_eq!(ordered.len(), 3, "no unit dropped");
        assert_eq!(
            plan_names(&ordered),
            vec!["independent", "func_a", "func_b"]
        );
    }

    #[test]
    fn test_state_sharing_edges_stay_within_tier() {
        // A definer in the middle band and a reuser in the leaf band.
        // Bands are sorted independently, so a pair that crosses bands
        // contributes nothing: the middle band keeps its own order, and
        // the leaf unit is neither moved nor dropped.
        let graph = CallGraph {
            binary: "crosstown.dll".to_string(),
            functions: vec![
                make_func("leaf_reuser", 0x401000, vec![], vec![], NodeCategory::Leaf),
                make_func(
                    "middle_other",
                    0x402000,
                    vec![],
                    vec![],
                    NodeCategory::Middle,
                ),
                make_func(
                    "middle_definer",
                    0x403000,
                    vec![],
                    vec![],
                    NodeCategory::Middle,
                ),
            ],
        };

        let edges = edges_from(&[shared_index_entry(
            "DAT_x",
            &["middle_definer"],
            &["leaf_reuser"],
        )]);
        let ordered = TranslationOrderer::new()
            .with_state_sharing(edges)
            .order(&graph)
            .unwrap();
        assert_eq!(
            plan_names(&ordered),
            vec!["middle_other", "middle_definer", "leaf_reuser"]
        );
    }

    #[test]
    fn test_edges_come_from_the_persisted_index_without_a_scan() {
        // The orderer reads the artifact the global-state scan writes.
        // Here the document was hand-written and saved through the
        // persistor — no analysis engine, no scan — and loading it back
        // yields the edges that put the definer first.
        let dir = tempfile::tempdir().expect("temp workspace");
        let persistor = GlobalStatePersistor::new(dir.path());
        let mut result = GlobalStateResult::new(ScanMetadata::new("eqmain.dll"));
        result
            .findings
            .push(GlobalStateFinding::SharedGlobal(shared_index_entry(
                "DAT_180064e80",
                &["writer_b"],
                &["reader_a"],
            )));
        persistor.save(&result).expect("the document saves");

        let loaded = persistor
            .load("eqmain.dll")
            .expect("the document loads back");
        let edges = StateSharingEdges::from_pairs(state_sharing_pairs(
            loaded
                .findings
                .iter()
                .filter_map(GlobalStateFinding::shared_global),
        ));

        let graph = CallGraph {
            binary: "eqmain.dll".to_string(),
            functions: vec![
                make_func("reader_a", 0x401000, vec![], vec![], NodeCategory::Middle),
                make_func("writer_b", 0x402000, vec![], vec![], NodeCategory::Middle),
            ],
        };
        let ordered = TranslationOrderer::new()
            .with_state_sharing(edges)
            .order(&graph)
            .unwrap();
        assert_eq!(plan_names(&ordered), vec!["writer_b", "reader_a"]);
    }
}
