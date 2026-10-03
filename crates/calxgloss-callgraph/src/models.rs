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
