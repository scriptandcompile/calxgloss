//! Translation ordering for the call graph-assisted translation pipeline.
//!
//! The [`TranslationOrderer`] produces a priority-ordered list of functions
//! for the translation pipeline, based on their classification as Root,
//! Middle, or Leaf in the call graph.
//!
//! # Algorithm
//!
//! 1. Classify each function into a priority tier:
//!    - **Root** (priority 0) — entry points and runtime init; handled first
//!      so their dependents can be resolved.
//!    - **Middle** (priority 1) — application logic; ordered topologically
//!      so that callers are translated after their callees.
//!    - **Leaf** (priority 2) — functions calling known third-party APIs;
//!      handled last so that context enrichment is complete.
//! 2. Within each tier, perform a topological sort based on call graph edges.
//!    Functions with no internal callees within the tier come first.
//!
//! # Example
//!
//! ```no_run
//! use calxgloss_callgraph::{CallGraph, TranslationOrderer, NodeCategory, FunctionCallGraph, CallGraphEdge, CallType};
//!
//! # fn example() -> anyhow::Result<()> {
//! let graph = CallGraph {
//!     dll: "example.dll".to_string(),
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

/// Priority tier for a function in the translation pipeline.
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
    /// Returns a human-readable label for this priority tier.
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
    /// Priority tier for translation ordering.
    pub priority: TranslationPriority,
    /// Call-graph classification of the function.
    ///
    /// This carries the full [`NodeCategory`] so that the translation
    /// pipeline can distinguish between entry points (Root) and runtime
    /// library functions (Skip) — both map to the same
    /// [`TranslationPriority::Root`] but require different handling.
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
/// 3. Within each priority tier, perform a topological sort using the
///    call graph edges restricted to that tier.
/// 4. Functions that form cycles or reference addresses outside the graph
///    are placed at the end of their tier.
///
/// # Order Guarantee
///
/// The returned list is a [`VecDeque`] so that the translation pipeline can
/// efficiently dequeue the next function to translate.  The order satisfies:
///
/// - All root functions appear before all middle functions.
/// - All middle functions appear before all leaf functions.
/// - Within each tier, a function appears after all of its internal callers
///   (i.e., callees before callers within the same tier).
pub struct TranslationOrderer {
    /// Maximum number of functions to order per DLL. Zero means unlimited.
    max_functions: usize,
}

impl TranslationOrderer {
    /// Creates a new `TranslationOrderer` with unlimited ordering.
    pub fn new() -> Self {
        Self { max_functions: 0 }
    }

    /// Creates a new `TranslationOrderer` that limits ordering to
    /// at most `max_functions` per DLL.
    pub fn with_max_functions(mut self, max_functions: usize) -> Self {
        self.max_functions = max_functions;
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
            debug!(dll = %graph.dll, "Empty call graph; returning empty plan");
            return Ok(VecDeque::new());
        }

        // Build an address-to-index lookup for quick neighbor resolution.
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

        // Group functions by priority tier.
        let mut tiers: HashMap<TranslationPriority, Vec<usize>> = HashMap::new();
        for (i, func) in graph.functions.iter().enumerate() {
            let priority: TranslationPriority = func.node_category.clone().into();
            tiers.entry(priority).or_default().push(i);
        }

        // Topologically sort each tier and collect the final plan.
        let mut plan: VecDeque<FunctionTranslationPlan> =
            VecDeque::with_capacity(graph.functions.len());

        // Process tiers in priority order (Root → Middle → Leaf).
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

            let sorted = self.topological_sort_tier(tier_indices, &addr_to_index, graph);
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
            dll = %graph.dll,
            total = plan.len(),
            "Translation plan generated"
        );

        Ok(plan)
    }

    /// Performs a topological sort on the given tier of function indices.
    ///
    /// Uses Kahn's algorithm.  Edges only consider callees that are
    /// within the same tier.  Functions that form cycles or reference
    /// unknown addresses are placed at the end of the sorted list.
    fn topological_sort_tier(
        &self,
        tier_indices: &[usize],
        addr_to_index: &HashMap<u64, usize>,
        graph: &CallGraph,
    ) -> Vec<usize> {
        let tier_set: HashSet<usize> = tier_indices.iter().copied().collect();

        // Build in-degree map for internal edges only.
        // We want callees before callers, so edges go from caller → callee
        // and in-degree of a node = number of callers within the tier.
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

    // ─── Tier classification tests ───

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
            dll: "empty.dll".to_string(),
            functions: vec![],
        };
        let orderer = TranslationOrderer::new();
        let plan = orderer.order(&graph).unwrap();
        assert!(plan.is_empty());
    }

    #[test]
    fn test_root_functions_comes_first() {
        let graph = CallGraph {
            dll: "roots.dll".to_string(),
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
            dll: "leaves.dll".to_string(),
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
        // Middle tier: game_loop
        // Leaf tier: render_frame
        assert_eq!(plan[0].name, "game_loop");
        assert_eq!(plan[0].priority, TranslationPriority::Middle);
        assert_eq!(plan[1].name, "render_frame");
        assert_eq!(plan[1].priority, TranslationPriority::Leaf);
    }

    #[test]
    fn test_topological_order_within_tier() {
        // app_init calls game_loop, which calls render_frame.
        // All middle-tier; topological sort should put callee before caller.
        let graph = CallGraph {
            dll: "topo.dll".to_string(),
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
        // render_frame (no internal callers) → game_loop → app_init
        assert_eq!(plan[0].name, "render_frame");
        assert_eq!(plan[1].name, "game_loop");
        assert_eq!(plan[2].name, "app_init");
    }

    #[test]
    fn test_function_plan_includes_metadata() {
        let graph = CallGraph {
            dll: "metadata.dll".to_string(),
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
            dll: "three_tiers.dll".to_string(),
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
            dll: "dup.dll".to_string(),
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
            dll: "trunc.dll".to_string(),
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
            dll: "skip.dll".to_string(),
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
            dll: "categories.dll".to_string(),
            functions: vec![
                make_func(
                    "WinMain",
                    0x401000,
                    vec![],
                    vec![],
                    NodeCategory::Root,
                ),
                make_func(
                    "runtime_helper",
                    0x402000,
                    vec![],
                    vec![],
                    NodeCategory::Skip,
                ),
                make_func(
                    "app_logic",
                    0x403000,
                    vec![],
                    vec![],
                    NodeCategory::Middle,
                ),
                make_func(
                    "render_frame",
                    0x404000,
                    vec![],
                    vec![],
                    NodeCategory::Leaf,
                ),
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
        // Two middle functions: A calls B, neither has callees in the same tier
        // (B's callees point to leaf functions outside the tier).
        let graph = CallGraph {
            dll: "no_internal.dll".to_string(),
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
        // callee_in_tier has no internal callees (leaf_func is outside tier), so it comes first
        assert_eq!(plan[0].name, "callee_in_tier");
        assert_eq!(plan[1].name, "caller");
    }

    #[test]
    fn test_cyclic_functions_appended_at_end_of_tier() {
        // A calls B, B calls A — cycle within the same tier.
        let graph = CallGraph {
            dll: "cycle.dll".to_string(),
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
}
