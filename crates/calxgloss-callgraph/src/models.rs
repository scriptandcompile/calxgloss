//! Core data types for call graph analysis.
//!
//! This module defines the [`CallGraph`], [`FunctionCallGraph`], [`CallGraphEdge`],
//! [`CallType`], and the [`NodeCategory`] type that forms the backbone of the
//! call graph analysis system.
//!
//! # NodeCategory
//!
//! [`NodeCategory`] is defined in `calxgloss-types` and re-exported here for
//! convenience. See that crate's documentation for the full description.

pub use calxgloss_types::NodeCategory;
use serde::{Deserialize, Serialize};

/// How a call between functions was detected.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CallType {
    /// `func()` — direct call found in decompiled text.
    Direct,
    /// `*func_ptr()` — indirect call found via disassembly scan.
    Indirect,
    /// `vtable->method()` — virtual call found via decompiler.
    Virtual,
    /// Scraper hit, uncertain.
    #[deprecated(note = "Falls back to text scraping; low confidence")]
    Unknown,
}

/// A single call edge between two functions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallGraphEdge {
    /// Entry address of the calling function.
    pub source: u64,
    /// Entry address of the called function.
    pub target: u64,
    /// Instruction address of the call site (0 if unknown).
    pub call_site: u64,
    /// How this edge was discovered.
    pub call_type: CallType,
    /// Original callee name as parsed from decompiled output.
    /// Empty when the edge was created without a name context.
    pub callee_name: String,
}

/// All call graph data for one binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallGraph {
    /// Name of the DLL / binary this graph belongs to.
    pub dll: String,
    /// Call graph data for each function in the binary.
    pub functions: Vec<FunctionCallGraph>,
}

/// Call graph data for a single function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionCallGraph {
    /// Human-readable function name.
    pub name: String,
    /// Entry address of the function.
    pub address: u64,
    /// Entry addresses of functions that call this function.
    pub callers: Vec<u64>,
    /// Edges representing calls made by this function.
    pub callees: Vec<CallGraphEdge>,
    /// Classification of this function in the translation pipeline.
    pub node_category: NodeCategory,
}

// TODO: Add CallType::Thunk for IAT indirection detection
// TODO: Add CallType::JumpTable for switch/vtable dispatch detection
// TODO: Persist call_type_confidence: f32 on each edge
// TODO: Add NodeCategory::EntryPoint (binary entry, not function entry)
// TODO: Add NodeCategory::Callback (registered callback functions that need special handling)

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_graph() -> CallGraph {
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
                            target: 0x403000,
                            call_site: 0x402008,
                            call_type: CallType::Direct,
                            callee_name: "Direct3DCreate9".to_string(),
                        },
                        CallGraphEdge {
                            source: 0x402000,
                            target: 0,
                            call_site: 0,
                            call_type: CallType::Indirect,
                            callee_name: "unknown_callback".to_string(),
                        },
                    ],
                    node_category: NodeCategory::Leaf,
                },
            ],
        }
    }

    #[test]
    fn test_serialize_deserialize_roundtrip() {
        let graph = sample_graph();
        let json = serde_json::to_string_pretty(&graph).expect("serialize");
        let loaded: CallGraph = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(loaded.dll, graph.dll);
        assert_eq!(loaded.functions.len(), graph.functions.len());
        assert_eq!(loaded.functions[0].name, "main");
        assert_eq!(loaded.functions[0].callers.len(), 0);
        assert_eq!(loaded.functions[0].callees.len(), 1);
        assert_eq!(loaded.functions[0].callees[0].callee_name, "helper");
        assert_eq!(loaded.functions[1].name, "helper");
        assert_eq!(loaded.functions[1].callers, vec![0x401000]);
        assert_eq!(loaded.functions[1].callees.len(), 2);
        assert_eq!(
            loaded.functions[1].callees[0].callee_name,
            "Direct3DCreate9"
        );
        assert_eq!(loaded.functions[1].callees[0].call_type, CallType::Direct);
        assert_eq!(loaded.functions[1].callees[1].call_type, CallType::Indirect);
        assert_eq!(loaded.functions[1].node_category, NodeCategory::Leaf);
    }

    #[test]
    fn test_call_type_partial_eq() {
        assert_eq!(CallType::Direct, CallType::Direct);
        assert_eq!(CallType::Indirect, CallType::Indirect);
        assert_eq!(CallType::Virtual, CallType::Virtual);
        assert_ne!(CallType::Direct, CallType::Indirect);
        assert_ne!(CallType::Indirect, CallType::Virtual);
    }

    #[test]
    fn test_node_category_partial_eq() {
        assert_eq!(NodeCategory::Root, NodeCategory::Root);
        assert_eq!(NodeCategory::Leaf, NodeCategory::Leaf);
        assert_eq!(NodeCategory::Middle, NodeCategory::Middle);
        assert_ne!(NodeCategory::Root, NodeCategory::Leaf);
        assert_ne!(NodeCategory::Leaf, NodeCategory::Middle);
    }

    #[test]
    fn test_call_graph_clone() {
        let graph = sample_graph();
        let cloned = graph.clone();
        assert_eq!(cloned.dll, graph.dll);
        assert_eq!(cloned.functions.len(), graph.functions.len());
    }

    #[test]
    fn test_call_graph_edge_fields() {
        let edge = CallGraphEdge {
            source: 0xDEAD,
            target: 0xBEEF,
            call_site: 0xCAFEBABE,
            call_type: CallType::Virtual,
            callee_name: "vtable_method".to_string(),
        };
        assert_eq!(edge.source, 0xDEAD);
        assert_eq!(edge.target, 0xBEEF);
        assert_eq!(edge.call_site, 0xCAFEBABE);
        assert_eq!(edge.call_type, CallType::Virtual);
        assert_eq!(edge.callee_name, "vtable_method");
    }

    #[test]
    fn test_json_structure_valid() {
        let graph = CallGraph {
            dll: "simple.dll".to_string(),
            functions: vec![FunctionCallGraph {
                name: "fn_a".to_string(),
                address: 0x1000,
                callers: vec![0x2000],
                callees: vec![],
                node_category: NodeCategory::Root,
            }],
        };
        let json = serde_json::to_string(&graph).expect("json serialize");
        // Verify the JSON contains expected keys
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("json parse");
        assert!(parsed["dll"].is_string());
        assert!(parsed["functions"].is_array());
        assert_eq!(parsed["dll"], "simple.dll");
        assert_eq!(parsed["functions"][0]["name"], "fn_a");
        assert_eq!(parsed["functions"][0]["address"], 0x1000);
        assert_eq!(parsed["functions"][0]["node_category"], "Root");
    }
}
