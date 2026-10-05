//! Call graph analysis for calxgloss.
//!
//! Extracts call graphs from Ghidra, detects root and leaf functions,
//! produces translation ordering, and persists results to JSON for
//! consumption by the translation pipeline.
//!
//! # Architecture
//!
//! The crate is organized into seven modules:
//!
//! - [`models`] - Core data types: [`CallGraph`], [`FunctionCallGraph`], [`CallGraphEdge`],
//!   [`NodeCategory`], and [`CallType`].
//! - [`builder`] - [`CallGraphBuilder`] fetches function metadata from Ghidra and
//!   constructs the call graph.
//! - [`root_detector`] - [`RootDetector`] and [`ConfigurableRootDetector`] identify
//!   entry-point and runtime functions that should be skipped or stubbed during
//!   translation. Supports VB6, .NET, MinGW, and MSVC runtime patterns.
//! - [`leaf_detector`] - [`LeafDetector`] identifies functions that call known
//!   third-party APIs, with fuzzy matching for name variations (A/W suffixes,
//!   stdcall decoration), DLL-qualified names, and transitive leaf analysis.
//! - [`context`] - [`ContextEnricher`] produces structured context data for
//!   LLM prompt injection (caller/callee lists, API categorization, crate suggestions).
//! - [`persist`] - [`CallGraphPersistor`] saves and loads call graphs to/from JSON.
//! - [`ordering`] - [`TranslationOrderer`] produces a priority-ordered translation plan.
//!
//! # Example
//!
//! ```no_run
//! use calxgloss_callgraph::{CallGraphBuilder, RootDetector, LeafDetector, CallGraphPersistor};
//!
//! # async fn example() -> anyhow::Result<()> {
//! let ghidra = calxgloss_ghidra::GhidraClient::new("http://localhost:8080")?;
//!
//! let builder = CallGraphBuilder::new(ghidra, "eqmain.dll");
//! let graph = builder.build().await?;
//!
//! let root_detector = RootDetector::new();
//! let leaf_detector = LeafDetector::new();
//!
//! for func in &graph.functions {
//!     if root_detector.is_root(func) {
//!         eprintln!("Skipping root: {}", func.name);
//!     } else if leaf_detector.has_leaf_call(func) {
//!         eprintln!("Leaf function: {}", func.name);
//!     }
//! }
//!
//! let persistor = CallGraphPersistor::new("/path/to/workspace");
//! persistor.save(&graph)?;
//! # Ok(())
//! # }
//! ```

pub mod builder;
pub mod context;
pub mod leaf_detector;
pub mod models;
pub mod ordering;
pub mod persist;
pub mod root_detector;

pub use builder::CallGraphBuilder;
pub use context::{
    CallEdgeInfo, CallGraphNode, CalleeGroup, ContextEnricher, ContextEnricherConfig,
    FunctionContext, LeafApiContext, skipped_contexts,
};
pub use leaf_detector::{ApiSignature, LeafCategory, LeafDetector, TransitiveLeafContext};
pub use models::*;
pub use ordering::{FunctionTranslationPlan, TranslationOrderer, TranslationPriority};
pub use persist::CallGraphPersistor;
pub use root_detector::{
    ConfigurableRootDetector, RootAction, RootDetector, RootDetectorConfig, RootPattern,
    RootPatternConfig,
};
