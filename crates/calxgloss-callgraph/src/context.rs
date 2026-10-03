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
use std::collections::HashMap;
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
#[derive(Debug, Clone, serde::Serialize)]
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
}

/// Produces enriched context data for all functions in a call graph.
///
/// The enricher uses the [`LeafDetector`] to classify callees into
/// API categories and attach Rust crate suggestions for context enrichment.
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
}

impl ContextEnricher {
    /// Creates a new `ContextEnricher` with a default [`LeafDetector`].
    pub fn new() -> Self {
        Self {
            leaf_detector: LeafDetector::new(),
        }
    }

    /// Produces enriched [`FunctionContext`] for every function in the graph.
    ///
    /// The enrichment process:
    ///
    /// 1. Builds address-to-function and address-to-name lookups from the graph.
    /// 2. For each function, resolves caller addresses to names.
    /// 3. Classifies each callee using the leaf detector for API categorization.
    /// 4. Collects leaf API context (matched APIs with Rust crate suggestions).
    ///
    /// Returns an empty vector if the graph contains no functions.
    pub fn enrich(&self, graph: &CallGraph) -> Vec<FunctionContext> {
        if graph.functions.is_empty() {
            debug!(dll = %graph.dll, "Empty call graph; returning empty context");
            return Vec::new();
        }

        // Build an address-to-function lookup for quick caller name resolution.
        let addr_to_func: HashMap<u64, &FunctionCallGraph> =
            graph.functions.iter().map(|f| (f.address, f)).collect();

        let mut contexts = Vec::with_capacity(graph.functions.len());

        for func in &graph.functions {
            let ctx = self.enrich_function(func, &addr_to_func);
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
    fn enrich_function(
        &self,
        func: &FunctionCallGraph,
        addr_to_func: &HashMap<u64, &FunctionCallGraph>,
    ) -> FunctionContext {
        // Resolve callers to named references.
        let callers: Vec<CallEdgeInfo> = func
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
        let callees: Vec<CallEdgeInfo> = func
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

        // Classify callees into categorized groups via leaf detector.
        let categorized_callees = self.build_categorized_callees(func);

        // Collect leaf API context for prompt injection.
        let leaf_api_context = self.build_leaf_api_context(func);

        debug!(
            func_name = %func.name,
            callers = callers.len(),
            callees = callees.len(),
            categories = categorized_callees.len(),
            leaf_apis = leaf_api_context.len(),
            "Enriched function context"
        );

        FunctionContext {
            name: func.name.clone(),
            address: func.address,
            callers,
            callees,
            categorized_callees,
            leaf_api_context,
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
                    vec![("leaf_fn", 0x3000, CallType::Direct)],
                    NodeCategory::Middle,
                ),
                make_func(
                    "leaf_fn",
                    0x3000,
                    vec![0x2000],
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

        // Middle function should have no leaf API context but should have callees
        let main_ctx = contexts
            .iter()
            .find(|c| c.name == "app_main")
            .expect("app_main not found");
        assert!(main_ctx.leaf_api_context.is_empty());
        assert_eq!(main_ctx.callees.len(), 2);
        assert!(main_ctx.categorized_callees.is_empty());
    }
}
