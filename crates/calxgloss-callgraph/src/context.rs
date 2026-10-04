//! Call graph context enrichment for LLM prompt injection.
//!
//! The [`ContextEnricher`] produces structured context data for each function
//! in a call graph, designed to be injected into LLM prompts so the translator
//! understands the calling and called environment.
//!
//! # MVP Context Fields
//!
//! For each function, the enricher produces:
//!
//! 1. **Callers** — function names that call this function, with addresses.
//! 2. **Callees** — function names this function calls, grouped by
//!    [`LeafCategory`] when the callee is a known API.
//! 3. **Leaf API context** — for functions that call known third-party APIs,
//!    the matched API signatures with suggested Rust crate replacements.
//!
//! # Example
//!
//! ```no_run
//! use calxgloss_callgraph::{
//!     CallGraph, ContextEnricher, FunctionContext, CallGraphEdge, CallType,
//!     NodeCategory,
//! };
//!
//! # fn example(graph: CallGraph) -> Vec<FunctionContext> {
//! let enricher = ContextEnricher::new();
//! let contexts = enricher.enrich(&graph);
//! for ctx in &contexts {
//!     println!("{}: {} callers, {} callees",
//!         ctx.name, ctx.callers.len(), ctx.callees.len());
//! }
//! # contexts
//! # }
//! ```

use crate::{CallGraph, FunctionCallGraph, LeafCategory, LeafDetector};
use std::collections::{HashMap, HashSet};
use tracing::debug;

/// A minimal reference to a call graph node (by name and address).
///
/// Used to represent callers and callees without duplicating full function data.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct CallGraphNode {
    /// The function's human-readable name.
    pub name: String,
    /// The function's entry address.
    pub address: u64,
}

/// Metadata about a call edge from the perspective of a neighbor function.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct CallEdgeInfo {
    /// The neighbor function reference.
    pub node: CallGraphNode,
    /// How this call was detected (direct, indirect, virtual).
    pub call_type: String,
}

/// A group of callees belonging to the same leaf API category.
///
/// When a function calls multiple known APIs of the same category
/// (e.g., both `MessageBox` and `CreateWindowEx` are UI APIs),
/// they are bundled together for compact context presentation.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct CalleeGroup {
    /// The API category this group belongs to.
    pub category: LeafCategory,
    /// The API names in this group.
    pub apis: Vec<String>,
}

/// Context about a matched leaf API.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct LeafApiContext {
    /// The API function name.
    pub api_name: String,
    /// The category this API belongs to.
    pub category: LeafCategory,
    /// Suggested Rust crate for cross-platform replacement.
    pub rust_crate: String,
}

/// Enriched context for a single function, designed for LLM prompt injection.
///
/// This is the primary output of the context enrichment pipeline.
/// Each field is populated from the call graph and leaf detector analysis.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct FunctionContext {
    /// The function's human-readable name.
    pub name: String,
    /// The function's entry address.
    pub address: u64,
    /// Functions that call this one, with call site metadata.
    pub callers: Vec<CallEdgeInfo>,
    /// This function's callees, split into internal calls and categorized API calls.
    pub callees: Vec<CallEdgeInfo>,
    /// Callees grouped by leaf API category (only APIs from the known signature list).
    pub categorized_callees: Vec<CalleeGroup>,
    /// Leaf API context: matched API signatures with Rust crate suggestions.
    pub leaf_api_context: Vec<LeafApiContext>,
    /// True when this function's context was skipped due to exceeding
    /// [`ContextEnricherConfig::max_neighbor_count`].
    pub context_skipped: bool,
}

/// Configuration for context enrichment behavior.
///
/// Controls how caller/callee data is limited and filtered when producing
/// [`FunctionContext`] objects, preventing excessively large prompts
/// for functions with many neighbors.
#[derive(Debug, Clone, PartialEq)]
pub struct ContextEnricherConfig {
    /// Maximum number of callers to include per function context.
    /// A value of 0 means no limit.
    pub max_callers: usize,
    /// Maximum number of callees to include per function context.
    /// A value of 0 means no limit.
    pub max_callees: usize,
    /// When true, filters out callees that exist as nodes in the same
    /// call graph (internal functions), keeping only external API calls.
    pub filter_internal_callees: bool,
    /// If the total neighbor count (callers + callees) for a function
    /// exceeds this value, that function's context is skipped entirely.
    /// A value of 0 means no skip threshold.
    pub max_neighbor_count: usize,
}

impl Default for ContextEnricherConfig {
    fn default() -> Self {
        Self {
            max_callers: 10,
            max_callees: 50,
            filter_internal_callees: true,
            max_neighbor_count: 200,
        }
    }
}

/// Produces enriched context data for all functions in a call graph.
///
/// The enricher uses the [`LeafDetector`] to classify callees into
/// API categories and attach Rust crate suggestions for context enrichment.
///
/// The enricher also applies limiting, filtering, and size-based
/// heuristics to keep context data manageable for LLM prompt injection:
///
/// - Top-N limiting on callers and callees
/// - Internal callee filtering (excludes same-graph functions)
/// - Size-based enrichment skipping for highly-connected functions
///
/// # Example
///
/// ```no_run
/// use calxgloss_callgraph::{CallGraph, ContextEnricher, CallGraphEdge, CallType, NodeCategory};
///
/// # fn example() {
/// let graph = CallGraph {
///     dll: "example.dll".to_string(),
///     functions: vec![],
/// };
/// let enricher = ContextEnricher::new();
/// let contexts = enricher.enrich(&graph);
/// assert!(contexts.is_empty());
/// # }
/// ```
pub struct ContextEnricher {
    /// Detector used to classify callees as known third-party APIs.
    leaf_detector: LeafDetector,
    /// Configuration controlling limiting and filtering behavior.
    config: ContextEnricherConfig,
}

impl ContextEnricher {
    /// Creates a new `ContextEnricher` with a default [`LeafDetector`]
    /// and default configuration.
    pub fn new() -> Self {
        Self::with_config(ContextEnricherConfig::default())
    }

    /// Creates a new `ContextEnricher` with the given [`ContextEnricherConfig`].
    pub fn with_config(config: ContextEnricherConfig) -> Self {
        Self {
            leaf_detector: LeafDetector::new(),
            config,
        }
    }

    /// Produces enriched [`FunctionContext`] for every function in the graph.
    ///
    /// The enrichment process:
    ///
    /// 1. Builds address-to-function and address-to-name lookups from the graph.
    /// 2. For each function, checks if neighbor count exceeds the skip threshold
    ///    and marks the context as skipped if so.
    /// 3. Applies top-N limiting and internal callee filtering per [`ContextEnricherConfig`].
    /// 4. Classifies each callee using the leaf detector for API categorization.
    /// 5. Collects leaf API context (matched APIs with Rust crate suggestions).
    ///
    /// Returns an empty vector if the graph contains no functions.
    pub fn enrich(&self, graph: &CallGraph) -> Vec<FunctionContext> {
        if graph.functions.is_empty() {
            debug!(dll = %graph.dll, "Empty call graph; returning empty context");
            return Vec::new();
        }

        // Build an address-to-function lookup for quick caller name resolution
        // and internal callee filtering.
        let addr_to_func: HashMap<u64, &FunctionCallGraph> =
            graph.functions.iter().map(|f| (f.address, f)).collect();

        let internal_addrs: HashSet<u64> = graph.functions.iter().map(|f| f.address).collect();

        let mut contexts = Vec::with_capacity(graph.functions.len());

        for func in &graph.functions {
            let ctx = self.enrich_function(func, &addr_to_func, &internal_addrs);
            contexts.push(ctx);
        }

        debug!(
            dll = %graph.dll,
            enriched = contexts.len(),
            "Context enrichment complete"
        );

        contexts
    }

    /// Enriches a single function with caller, callee, and leaf API context.
    ///
    /// Applies top-N limiting, internal callee filtering, and size-based
    /// skipping according to the enricher's configuration.
    fn enrich_function(
        &self,
        func: &FunctionCallGraph,
        addr_to_func: &HashMap<u64, &FunctionCallGraph>,
        internal_addrs: &HashSet<u64>,
    ) -> FunctionContext {
        // Resolve callers to named references.
        let raw_callers: Vec<CallEdgeInfo> = func
            .callers
            .iter()
            .map(|&caller_addr| {
                let node = match addr_to_func.get(&caller_addr) {
                    Some(f) => CallGraphNode {
                        name: f.name.clone(),
                        address: f.address,
                    },
                    None => CallGraphNode {
                        name: format!("0x{caller_addr:x}"),
                        address: caller_addr,
                    },
                };
                CallEdgeInfo {
                    node,
                    call_type: "direct".to_string(),
                }
            })
            .collect();

        // Resolve callees to named references.
        let raw_callees: Vec<CallEdgeInfo> = func
            .callees
            .iter()
            .map(|edge| {
                let node = CallGraphNode {
                    name: edge.callee_name.clone(),
                    address: edge.target,
                };
                let call_type = match edge.call_type {
                    crate::CallType::Direct => "direct".to_string(),
                    crate::CallType::Indirect => "indirect".to_string(),
                    crate::CallType::Virtual => "virtual".to_string(),
                    #[allow(deprecated)]
                    crate::CallType::Unknown => "unknown".to_string(),
                };
                CallEdgeInfo { node, call_type }
            })
            .collect();

        // Check size-based enrichment skipping BEFORE limiting/filtering.
        let context_skipped = self.config.max_neighbor_count > 0
            && (func.callers.len() + func.callees.len()) > self.config.max_neighbor_count;

        // Apply limiting and filtering.
        let (callers, callees) = if context_skipped {
            (Vec::new(), Vec::new())
        } else {
            // Apply top-N limiting on callers.
            let callers = self.limit_top_n(raw_callers, self.config.max_callers);

            // Filter internal callees and apply top-N limiting.
            let callees = if self.config.filter_internal_callees {
                let filtered: Vec<CallEdgeInfo> = raw_callees
                    .into_iter()
                    .filter(|edge| !internal_addrs.contains(&edge.node.address))
                    .collect();
                self.limit_top_n(filtered, self.config.max_callees)
            } else {
                self.limit_top_n(raw_callees, self.config.max_callees)
            };

            (callers, callees)
        };

        let (categorized_callees, leaf_api_context) = if context_skipped {
            (Vec::new(), Vec::new())
        } else {
            let categorized_callees = self.build_categorized_callees(func);
            let leaf_api_context = self.build_leaf_api_context(func);
            (categorized_callees, leaf_api_context)
        };

        debug!(
            func_name = %func.name,
            callers = callers.len(),
            callees = callees.len(),
            categories = categorized_callees.len(),
            leaf_apis = leaf_api_context.len(),
            skipped = context_skipped,
            "Enriched function context"
        );

        FunctionContext {
            name: func.name.clone(),
            address: func.address,
            callers,
            callees,
            categorized_callees,
            leaf_api_context,
            context_skipped,
        }
    }

    /// Limits a vector to its first `max_items` elements, or returns it
    /// unmodified if `max_items` is 0.
    fn limit_top_n<T>(&self, items: Vec<T>, max_items: usize) -> Vec<T> {
        if max_items == 0 {
            items
        } else {
            items.into_iter().take(max_items).collect()
        }
    }

    /// Groups this function's callees by leaf API category.
    ///
    /// Only callees that match the leaf detector's known API signatures
    /// are included. Internal function calls are excluded from categorization.
    fn build_categorized_callees(&self, func: &FunctionCallGraph) -> Vec<CalleeGroup> {
        let matched = match self.leaf_detector.classify(func) {
            Some(sigs) => sigs,
            None => return Vec::new(),
        };

        // Group matched APIs by category.
        let mut groups: HashMap<LeafCategory, Vec<String>> = HashMap::new();
        for sig in matched {
            groups
                .entry(sig.category.clone())
                .or_default()
                .push(sig.api_name);
        }

        // Convert to ordered list.
        groups
            .into_iter()
            .map(|(category, apis)| CalleeGroup { category, apis })
            .collect()
    }

    /// Builds leaf API context for this function.
    ///
    /// Returns a list of matched API signatures with category and
    /// suggested Rust crate, suitable for prompt injection.
    fn build_leaf_api_context(&self, func: &FunctionCallGraph) -> Vec<LeafApiContext> {
        let matched = match self.leaf_detector.classify(func) {
            Some(sigs) => sigs,
            None => return Vec::new(),
        };

        matched
            .into_iter()
            .map(|sig| LeafApiContext {
                api_name: sig.api_name,
                category: sig.category,
                rust_crate: sig.rust_crate,
            })
            .collect()
    }
}

impl Default for ContextEnricher {
    fn default() -> Self {
        Self::new()
    }
}

/// Returns the list of function contexts that were skipped during enrichment
/// due to exceeding the neighbor count threshold.
///
/// Skipped contexts have [`FunctionContext::context_skipped`] set to `true`.
/// They serve as placeholders so the output vector aligns with the input
/// graph's function ordering.
pub fn skipped_contexts(contexts: &[FunctionContext]) -> Vec<&FunctionContext> {
    contexts.iter().filter(|c| c.context_skipped).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CallGraphEdge, CallType, NodeCategory};

    fn make_func(
        name: &str,
        address: u64,
        callers: Vec<u64>,
        callees: Vec<(&str, u64, CallType)>,
        category: NodeCategory,
    ) -> FunctionCallGraph {
        FunctionCallGraph {
            name: name.to_string(),
            address,
            callers,
            callees: callees
                .into_iter()
                .map(|(cname, target, ctype)| CallGraphEdge {
                    source: address,
                    target,
                    call_site: 0,
                    call_type: ctype,
                    callee_name: cname.to_string(),
                })
                .collect(),
            node_category: category,
        }
    }

    #[test]
    fn test_empty_graph_returns_empty_contexts() {
        let graph = CallGraph {
            dll: "empty.dll".to_string(),
            functions: vec![],
        };
        let enricher = ContextEnricher::new();
        let contexts = enricher.enrich(&graph);
        assert!(contexts.is_empty());
    }

    #[test]
    fn test_function_with_no_neighbors_has_empty_callers_and_callees() {
        let graph = CallGraph {
            dll: "isolated.dll".to_string(),
            functions: vec![make_func(
                "standalone",
                0x1000,
                vec![],
                vec![],
                NodeCategory::Middle,
            )],
        };

        let enricher = ContextEnricher::new();
        let contexts = enricher.enrich(&graph);

        assert_eq!(contexts.len(), 1);
        let ctx = &contexts[0];
        assert_eq!(ctx.name, "standalone");
        assert_eq!(ctx.address, 0x1000);
        assert!(ctx.callers.is_empty());
        assert!(ctx.callees.is_empty());
        assert!(ctx.categorized_callees.is_empty());
        assert!(ctx.leaf_api_context.is_empty());
    }

    #[test]
    fn test_callers_resolved_to_names() {
        let func_caller = make_func(
            "caller_fn",
            0x2000,
            vec![],
            vec![("callee_fn", 0x3000, CallType::Direct)],
            NodeCategory::Middle,
        );
        let func_callee = make_func(
            "callee_fn",
            0x3000,
            vec![0x2000], // 0x2000 is caller_fn's address
            vec![],
            NodeCategory::Middle,
        );

        let graph = CallGraph {
            dll: "callers.dll".to_string(),
            functions: vec![func_caller, func_callee],
        };

        let enricher = ContextEnricher::new();
        let contexts = enricher.enrich(&graph);

        assert_eq!(contexts.len(), 2);
        let callee_ctx = contexts
            .iter()
            .find(|c| c.name == "callee_fn")
            .expect("callee_fn not found");
        assert_eq!(callee_ctx.callers.len(), 1);
        assert_eq!(callee_ctx.callers[0].node.name, "caller_fn");
        assert_eq!(callee_ctx.callers[0].node.address, 0x2000);
    }

    #[test]
    fn test_unknown_caller_address_falls_back_to_hex() {
        let graph = CallGraph {
            dll: "orphan.dll".to_string(),
            functions: vec![make_func(
                "orphan_fn",
                0x1000,
                vec![0xDEAD], // No function at 0xDEAD in graph
                vec![],
                NodeCategory::Middle,
            )],
        };

        let enricher = ContextEnricher::new();
        let contexts = enricher.enrich(&graph);

        assert_eq!(contexts.len(), 1);
        let ctx = &contexts[0];
        assert_eq!(ctx.callers.len(), 1);
        assert_eq!(ctx.callers[0].node.name, "0xdead");
        assert_eq!(ctx.callers[0].node.address, 0xDEAD);
    }

    #[test]
    fn test_callees_included_with_names() {
        let graph = CallGraph {
            dll: "callees.dll".to_string(),
            functions: vec![make_func(
                "caller",
                0x1000,
                vec![],
                vec![
                    ("internal_helper", 0x2000, CallType::Direct),
                    ("another_dep", 0x3000, CallType::Direct),
                ],
                NodeCategory::Middle,
            )],
        };

        let enricher = ContextEnricher::new();
        let contexts = enricher.enrich(&graph);

        assert_eq!(contexts.len(), 1);
        let ctx = &contexts[0];
        assert_eq!(ctx.callees.len(), 2);
        assert_eq!(ctx.callees[0].node.name, "internal_helper");
        assert_eq!(ctx.callees[1].node.name, "another_dep");
    }

    #[test]
    fn test_leaf_api_categorized() {
        let graph = CallGraph {
            dll: "leaf.dll".to_string(),
            functions: vec![make_func(
                "init_ui",
                0x1000,
                vec![],
                vec![
                    ("MessageBox", 0x500000, CallType::Direct),
                    ("CreateWindowEx", 0x500001, CallType::Direct),
                ],
                NodeCategory::Leaf,
            )],
        };

        let enricher = ContextEnricher::new();
        let contexts = enricher.enrich(&graph);

        assert_eq!(contexts.len(), 1);
        let ctx = &contexts[0];

        // Both should be grouped as UI category.
        assert_eq!(ctx.categorized_callees.len(), 1);
        let group = &ctx.categorized_callees[0];
        assert!(matches!(group.category, LeafCategory::Ui));
        assert_eq!(group.apis.len(), 2);
        assert!(group.apis.contains(&"MessageBox".to_string()));
        assert!(group.apis.contains(&"CreateWindowEx".to_string()));
    }

    #[test]
    fn test_leaf_api_context_includes_crate_suggestion() {
        let graph = CallGraph {
            dll: "leaf_crate.dll".to_string(),
            functions: vec![make_func(
                "do_crypto",
                0x1000,
                vec![],
                vec![
                    ("CryptAcquireContext", 0x500000, CallType::Direct),
                    ("CryptEncrypt", 0x500001, CallType::Direct),
                ],
                NodeCategory::Leaf,
            )],
        };

        let enricher = ContextEnricher::new();
        let contexts = enricher.enrich(&graph);

        assert_eq!(contexts.len(), 1);
        let ctx = &contexts[0];
        assert_eq!(ctx.leaf_api_context.len(), 2);

        for api in &ctx.leaf_api_context {
            assert_eq!(api.rust_crate, "ring");
            assert!(matches!(api.category, LeafCategory::Crypto));
        }

        let api_names: Vec<_> = ctx.leaf_api_context.iter().map(|a| &a.api_name).collect();
        assert!(api_names.contains(&&"CryptAcquireContext".to_string()));
        assert!(api_names.contains(&&"CryptEncrypt".to_string()));
    }

    #[test]
    fn test_multi_category_leaf_function() {
        let graph = CallGraph {
            dll: "multi_leaf.dll".to_string(),
            functions: vec![make_func(
                "complex_app",
                0x1000,
                vec![],
                vec![
                    ("Direct3DCreate9", 0x500000, CallType::Direct),
                    ("MessageBox", 0x500001, CallType::Direct),
                    ("CreateFile", 0x500002, CallType::Direct),
                    ("internal_calc", 0x2000, CallType::Direct),
                ],
                NodeCategory::Leaf,
            )],
        };

        let enricher = ContextEnricher::new();
        let contexts = enricher.enrich(&graph);

        assert_eq!(contexts.len(), 1);
        let ctx = &contexts[0];

        // Three API categories: Graphics, UI, Filesystem
        assert_eq!(ctx.categorized_callees.len(), 3);
        let cats: Vec<_> = ctx
            .categorized_callees
            .iter()
            .map(|g| &g.category)
            .collect();
        assert!(cats.contains(&&LeafCategory::Graphics));
        assert!(cats.contains(&&LeafCategory::Ui));
        assert!(cats.contains(&&LeafCategory::Filesystem));

        // leaf_api_context should have 3 entries (one per matched API)
        assert_eq!(ctx.leaf_api_context.len(), 3);
    }

    #[test]
    fn test_non_leaf_function_has_empty_categories_and_leaf_context() {
        let graph = CallGraph {
            dll: "normal.dll".to_string(),
            functions: vec![make_func(
                "pure_logic",
                0x1000,
                vec![],
                vec![("internal_helper", 0x2000, CallType::Direct)],
                NodeCategory::Middle,
            )],
        };

        let enricher = ContextEnricher::new();
        let contexts = enricher.enrich(&graph);

        assert_eq!(contexts.len(), 1);
        let ctx = &contexts[0];
        assert!(ctx.categorized_callees.is_empty());
        assert!(ctx.leaf_api_context.is_empty());
    }

    #[test]
    fn test_call_edge_info_has_call_type() {
        let graph = CallGraph {
            dll: "types.dll".to_string(),
            functions: vec![make_func(
                "indirect_caller",
                0x1000,
                vec![],
                vec![
                    ("func_ptr_call", 0, CallType::Indirect),
                    ("vtable_call", 0, CallType::Virtual),
                ],
                NodeCategory::Middle,
            )],
        };

        let enricher = ContextEnricher::new();
        let contexts = enricher.enrich(&graph);

        assert_eq!(contexts.len(), 1);
        let ctx = &contexts[0];
        assert_eq!(ctx.callees.len(), 2);

        let types: Vec<_> = ctx.callees.iter().map(|e| e.call_type.as_str()).collect();
        assert!(types.contains(&"indirect"));
        assert!(types.contains(&"virtual"));
    }

    #[test]
    fn test_enrich_produces_context_for_all_functions() {
        let graph = CallGraph {
            dll: "all.dll".to_string(),
            functions: vec![
                make_func("root_fn", 0x1000, vec![], vec![], NodeCategory::Root),
                make_func(
                    "middle_fn",
                    0x2000,
                    vec![0x1000],
                    // leaf_external is NOT in the graph, so it won't be filtered.
                    vec![("leaf_external", 0x8000, CallType::Direct)],
                    NodeCategory::Middle,
                ),
                make_func(
                    "leaf_fn",
                    0x3000,
                    vec![0x2000],
                    // MessageBox address not in the graph.
                    vec![("MessageBox", 0x500000, CallType::Direct)],
                    NodeCategory::Leaf,
                ),
            ],
        };

        let enricher = ContextEnricher::new();
        let contexts = enricher.enrich(&graph);

        assert_eq!(contexts.len(), 3);

        // Check root function has caller info
        let root_ctx = contexts
            .iter()
            .find(|c| c.name == "root_fn")
            .expect("root_fn not found");
        assert!(root_ctx.callers.is_empty());
        assert!(root_ctx.callees.is_empty());

        // Check middle function has caller + callee
        let middle_ctx = contexts
            .iter()
            .find(|c| c.name == "middle_fn")
            .expect("middle_fn not found");
        assert_eq!(middle_ctx.callers.len(), 1);
        assert_eq!(middle_ctx.callees.len(), 1);
        assert!(middle_ctx.leaf_api_context.is_empty()); // not leaf itself

        // Check leaf function has caller + leaf API context
        let leaf_ctx = contexts
            .iter()
            .find(|c| c.name == "leaf_fn")
            .expect("leaf_fn not found");
        assert_eq!(leaf_ctx.callers.len(), 1);
        assert_eq!(leaf_ctx.leaf_api_context.len(), 1);
        assert_eq!(leaf_ctx.leaf_api_context[0].api_name, "MessageBox");
    }

    #[test]
    fn test_default_constructs() {
        let enricher = ContextEnricher::default();
        let graph = CallGraph {
            dll: "default_test.dll".to_string(),
            functions: vec![make_func(
                "test_fn",
                0x1000,
                vec![],
                vec![],
                NodeCategory::Middle,
            )],
        };
        let contexts = enricher.enrich(&graph);
        assert_eq!(contexts.len(), 1);
    }

    #[test]
    fn test_context_clone_roundtrip() {
        let graph = CallGraph {
            dll: "clone.dll".to_string(),
            functions: vec![make_func(
                "clone_test",
                0x1000,
                vec![0x2000],
                vec![("MessageBox", 0x500000, CallType::Direct)],
                NodeCategory::Leaf,
            )],
        };

        let enricher = ContextEnricher::new();
        let contexts = enricher.enrich(&graph);

        let cloned = contexts.clone();
        assert_eq!(cloned.len(), contexts.len());
        assert_eq!(cloned[0].name, contexts[0].name);
        assert_eq!(cloned[0].callers.len(), contexts[0].callers.len());
        assert_eq!(
            cloned[0].leaf_api_context.len(),
            contexts[0].leaf_api_context.len()
        );
    }

    #[test]
    fn test_multiple_functions_with_leaf_apis() {
        let graph = CallGraph {
            dll: "multi_leaf_fn.dll".to_string(),
            functions: vec![
                make_func(
                    "ui_init",
                    0x1000,
                    vec![],
                    vec![("MessageBox", 0x500000, CallType::Direct)],
                    NodeCategory::Leaf,
                ),
                make_func(
                    "file_ops",
                    0x2000,
                    vec![],
                    vec![("CreateFile", 0x500001, CallType::Direct)],
                    NodeCategory::Leaf,
                ),
                make_func(
                    "app_main",
                    0x3000,
                    vec![],
                    vec![
                        ("ui_init", 0x1000, CallType::Direct),
                        ("file_ops", 0x2000, CallType::Direct),
                        // Add an external callee so internal filtering doesn't remove everything.
                        ("GetTickCount", 0x500002, CallType::Direct),
                    ],
                    NodeCategory::Middle,
                ),
            ],
        };

        let enricher = ContextEnricher::new();
        let contexts = enricher.enrich(&graph);

        assert_eq!(contexts.len(), 3);

        // Both leaf functions should have API context
        let ui_ctx = contexts
            .iter()
            .find(|c| c.name == "ui_init")
            .expect("ui_init not found");
        assert_eq!(ui_ctx.leaf_api_context.len(), 1);
        assert_eq!(ui_ctx.leaf_api_context[0].api_name, "MessageBox");

        let file_ctx = contexts
            .iter()
            .find(|c| c.name == "file_ops")
            .expect("file_ops not found");
        assert_eq!(file_ctx.leaf_api_context.len(), 1);
        assert_eq!(file_ctx.leaf_api_context[0].api_name, "CreateFile");

        // Middle function's internal callees (ui_init, file_ops) are filtered out,
        // but external callee (GetTickCount) remains.
        let main_ctx = contexts
            .iter()
            .find(|c| c.name == "app_main")
            .expect("app_main not found");
        assert!(main_ctx.leaf_api_context.is_empty());
        assert_eq!(main_ctx.callees.len(), 1);
        assert_eq!(main_ctx.callees[0].node.name, "GetTickCount");
        assert!(main_ctx.categorized_callees.is_empty());
    }

    // --- Top-N Caller Limiting ---

    #[test]
    fn test_top_n_caller_limiting() {
        // Build caller functions in the graph.
        let caller_data = [
            ("caller_a", 0x1000),
            ("caller_b", 0x1001),
            ("caller_c", 0x1002),
            ("caller_d", 0x1003),
            ("caller_e", 0x1004),
        ];
        let callers: Vec<_> = caller_data
            .iter()
            .enumerate()
            .map(|(_i, (name, addr))| make_func(name, *addr, vec![], vec![], NodeCategory::Middle))
            .collect();

        // Add the target function to the graph.
        let target = FunctionCallGraph {
            name: "target".to_string(),
            address: 0x5000,
            callers: caller_data.iter().map(|(_, addr)| *addr).collect(),
            callees: Vec::new(),
            node_category: NodeCategory::Middle,
        };

        let graph = CallGraph {
            dll: "limit_callers.dll".to_string(),
            functions: callers,
        };
        // Manually add target's context by including it in the graph.
        let mut graph_funcs = graph.functions;
        graph_funcs.push(target);
        let graph = CallGraph {
            dll: "limit_callers.dll".to_string(),
            functions: graph_funcs,
        };

        let config = ContextEnricherConfig {
            max_callers: 2,
            max_callees: 0,
            filter_internal_callees: false,
            max_neighbor_count: 0,
        };
        let enricher = ContextEnricher::with_config(config);
        let contexts = enricher.enrich(&graph);

        let target_ctx = contexts
            .iter()
            .find(|c| c.name == "target")
            .expect("target not found");
        assert_eq!(
            target_ctx.callers.len(),
            2,
            "should be limited to 2 callers"
        );
        assert_eq!(target_ctx.callers[0].node.name, "caller_a");
        assert_eq!(target_ctx.callers[1].node.name, "caller_b");
    }

    #[test]
    fn test_zero_max_callers_means_no_limit() {
        let graph = CallGraph {
            dll: "no_limit.dll".to_string(),
            functions: vec![
                make_func(
                    "target",
                    0x5000,
                    vec![0x1000, 0x1001, 0x1002],
                    vec![],
                    NodeCategory::Middle,
                ),
                make_func("caller_a", 0x1000, vec![], vec![], NodeCategory::Middle),
                make_func("caller_b", 0x1001, vec![], vec![], NodeCategory::Middle),
                make_func("caller_c", 0x1002, vec![], vec![], NodeCategory::Middle),
            ],
        };

        let config = ContextEnricherConfig {
            max_callers: 0,
            max_callees: 0,
            filter_internal_callees: false,
            max_neighbor_count: 0,
        };
        let enricher = ContextEnricher::with_config(config);
        let contexts = enricher.enrich(&graph);

        let target_ctx = contexts
            .iter()
            .find(|c| c.name == "target")
            .expect("target not found");
        assert_eq!(target_ctx.callers.len(), 3, "zero max means no limit");
    }

    // --- Top-N Callee Limiting ---

    #[test]
    fn test_top_n_callee_limiting() {
        let callees: Vec<_> = (0..10u64)
            .map(|i| CallGraphEdge {
                source: 0x1000,
                target: 0x2000 + i,
                call_site: 0,
                call_type: CallType::Direct,
                callee_name: format!("api_{}", i),
            })
            .collect();

        let graph = CallGraph {
            dll: "limit_callees.dll".to_string(),
            functions: vec![FunctionCallGraph {
                name: "big_caller".to_string(),
                address: 0x1000,
                callers: vec![],
                callees,
                node_category: NodeCategory::Middle,
            }],
        };

        let config = ContextEnricherConfig {
            max_callers: 0,
            max_callees: 3,
            filter_internal_callees: false,
            max_neighbor_count: 0,
        };
        let enricher = ContextEnricher::with_config(config);
        let contexts = enricher.enrich(&graph);

        let ctx = &contexts[0];
        assert_eq!(ctx.callees.len(), 3, "should be limited to 3 callees");
        assert_eq!(ctx.callees[0].node.name, "api_0");
        assert_eq!(ctx.callees[2].node.name, "api_2");
    }

    // --- Internal Callee Filtering ---

    #[test]
    fn test_internal_callees_filtered() {
        let func_a = make_func(
            "func_a",
            0x1000,
            vec![],
            vec![("func_b", 0x2000, CallType::Direct)],
            NodeCategory::Middle,
        );
        // func_b calls func_c (internal at 0x3000) AND MessageBox (external at 0x500000).
        let func_b = make_func(
            "func_b",
            0x2000,
            vec![0x1000],
            vec![
                ("func_c", 0x3000, CallType::Direct),
                ("MessageBox", 0x500000, CallType::Direct),
            ],
            NodeCategory::Middle,
        );
        let func_c = make_func(
            "func_c",
            0x3000,
            vec![0x2000],
            vec![("MessageBox", 0x500000, CallType::Direct)],
            NodeCategory::Leaf,
        );

        let graph = CallGraph {
            dll: "filter_internal.dll".to_string(),
            functions: vec![func_a, func_b, func_c],
        };

        let config = ContextEnricherConfig {
            max_callers: 0,
            max_callees: 0,
            filter_internal_callees: true,
            max_neighbor_count: 0,
        };
        let enricher = ContextEnricher::with_config(config);
        let contexts = enricher.enrich(&graph);

        let ctx_b = contexts
            .iter()
            .find(|c| c.name == "func_b")
            .expect("func_b not found");
        // func_b calls func_c (internal at 0x3000) and MessageBox (external).
        // Internal filtering should remove func_c, leaving only MessageBox.
        assert_eq!(ctx_b.callees.len(), 1);
        assert_eq!(ctx_b.callees[0].node.name, "MessageBox");
    }

    #[test]
    fn test_internal_callees_not_filtered_when_disabled() {
        let func_a = make_func(
            "func_a",
            0x1000,
            vec![],
            vec![("func_b", 0x2000, CallType::Direct)],
            NodeCategory::Middle,
        );
        let func_b = make_func(
            "func_b",
            0x2000,
            vec![0x1000],
            vec![("func_c", 0x3000, CallType::Direct)],
            NodeCategory::Middle,
        );
        let func_c = make_func(
            "func_c",
            0x3000,
            vec![0x2000],
            vec![("MessageBox", 0x500000, CallType::Direct)],
            NodeCategory::Leaf,
        );

        let graph = CallGraph {
            dll: "no_filter.dll".to_string(),
            functions: vec![func_a, func_b, func_c],
        };

        let config = ContextEnricherConfig {
            max_callers: 0,
            max_callees: 0,
            filter_internal_callees: false,
            max_neighbor_count: 0,
        };
        let enricher = ContextEnricher::with_config(config);
        let contexts = enricher.enrich(&graph);

        let ctx_b = contexts
            .iter()
            .find(|c| c.name == "func_b")
            .expect("func_b not found");
        // All callees should be present, including internal func_c.
        assert_eq!(ctx_b.callees.len(), 1);
        assert_eq!(ctx_b.callees[0].node.name, "func_c");
    }

    // --- Size-Based Skipping ---

    #[test]
    fn test_context_skipped_when_neighbor_count_exceeded() {
        // Create a function with many callers that exceeds the neighbor threshold.
        let many_callers: Vec<u64> = (0..50).map(|i| 0x1000 + i).collect();

        let graph = CallGraph {
            dll: "skipped.dll".to_string(),
            functions: vec![
                FunctionCallGraph {
                    name: "overloaded".to_string(),
                    address: 0x5000,
                    callers: many_callers,
                    callees: Vec::new(),
                    node_category: NodeCategory::Middle,
                },
                // Also add a few callers so their addresses are known.
                make_func("caller_0", 0x1000, vec![], vec![], NodeCategory::Middle),
                make_func("caller_1", 0x1001, vec![], vec![], NodeCategory::Middle),
            ],
        };

        let config = ContextEnricherConfig {
            max_callers: 0,
            max_callees: 0,
            filter_internal_callees: false,
            max_neighbor_count: 10,
        };
        let enricher = ContextEnricher::with_config(config);
        let contexts = enricher.enrich(&graph);

        let overloaded_ctx = contexts
            .iter()
            .find(|c| c.name == "overloaded")
            .expect("overloaded not found");
        assert!(overloaded_ctx.context_skipped);
        assert!(overloaded_ctx.callers.is_empty());
        assert!(overloaded_ctx.callees.is_empty());
        assert!(overloaded_ctx.categorized_callees.is_empty());
        assert!(overloaded_ctx.leaf_api_context.is_empty());
    }

    #[test]
    fn test_context_not_skipped_within_threshold() {
        let graph = CallGraph {
            dll: "within_threshold.dll".to_string(),
            functions: vec![
                FunctionCallGraph {
                    name: "moderate".to_string(),
                    address: 0x5000,
                    callers: vec![0x1000, 0x1001],
                    callees: vec![CallGraphEdge {
                        source: 0x5000,
                        target: 0x6000,
                        call_site: 0,
                        call_type: CallType::Direct,
                        callee_name: "MessageBox".to_string(),
                    }],
                    node_category: NodeCategory::Middle,
                },
                make_func("caller_0", 0x1000, vec![], vec![], NodeCategory::Middle),
                make_func("caller_1", 0x1001, vec![], vec![], NodeCategory::Middle),
            ],
        };

        let config = ContextEnricherConfig {
            max_callers: 0,
            max_callees: 0,
            filter_internal_callees: false,
            max_neighbor_count: 10,
        };
        let enricher = ContextEnricher::with_config(config);
        let contexts = enricher.enrich(&graph);

        let moderate_ctx = contexts
            .iter()
            .find(|c| c.name == "moderate")
            .expect("moderate not found");
        assert!(!moderate_ctx.context_skipped);
        assert_eq!(moderate_ctx.callers.len(), 2);
        assert_eq!(moderate_ctx.callees.len(), 1);
    }

    #[test]
    fn test_skipped_contexts_helper() {
        let graph = CallGraph {
            dll: "skip_helper.dll".to_string(),
            functions: vec![
                FunctionCallGraph {
                    name: "overloaded".to_string(),
                    address: 0x5000,
                    callers: (0..50).map(|i| 0x1000 + i).collect(),
                    callees: Vec::new(),
                    node_category: NodeCategory::Middle,
                },
                make_func("normal", 0x2000, vec![], vec![], NodeCategory::Middle),
            ],
        };

        let config = ContextEnricherConfig {
            max_callers: 0,
            max_callees: 0,
            filter_internal_callees: false,
            max_neighbor_count: 10,
        };
        let enricher = ContextEnricher::with_config(config);
        let contexts = enricher.enrich(&graph);

        let skipped = skipped_contexts(&contexts);
        assert_eq!(skipped.len(), 1);
        assert_eq!(skipped[0].name, "overloaded");
        assert!(skipped[0].context_skipped);
    }

    #[test]
    fn test_default_config_values() {
        let config = ContextEnricherConfig::default();
        assert_eq!(config.max_callers, 10);
        assert_eq!(config.max_callees, 50);
        assert!(config.filter_internal_callees);
        assert_eq!(config.max_neighbor_count, 200);
    }

    #[test]
    fn test_context_skipped_field_default() {
        let graph = CallGraph {
            dll: "skipped_field.dll".to_string(),
            functions: vec![make_func(
                "test_fn",
                0x1000,
                vec![],
                vec![],
                NodeCategory::Middle,
            )],
        };

        let enricher = ContextEnricher::new();
        let contexts = enricher.enrich(&graph);

        let ctx = &contexts[0];
        assert!(!ctx.context_skipped);
    }
}
