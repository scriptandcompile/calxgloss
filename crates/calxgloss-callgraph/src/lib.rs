//! Call graph analysis for calxgloss.
//!
//! Extracts call graphs from Ghidra, detects root and leaf functions,
//! and persists results to JSON for consumption by the translation pipeline.
//!
//! # Architecture
//!
//! The crate is organized into five modules:
//!
//! - [`models`] — Core data types: [`CallGraph`], [`FunctionCallGraph`], [`CallGraphEdge`],
//!   [`NodeCategory`], and [`CallType`].
//! - [`builder`] — [`CallGraphBuilder`] fetches function metadata from Ghidra and
//!   constructs the call graph.
//! - [`root_detector`] — [`RootDetector`] identifies entry-point and runtime functions
//!   that should be skipped or stubbed during translation.
//! - [`leaf_detector`] — [`LeafDetector`] identifies functions that call known
//!   third-party APIs, enabling context enrichment.
//! - [`persist`] — [`CallGraphPersistor`] saves and loads call graphs to/from JSON.
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
pub mod leaf_detector;
pub mod models;
pub mod persist;
pub mod root_detector;

pub use models::*;
pub use builder::CallGraphBuilder;
pub use root_detector::RootDetector;
pub use leaf_detector::{ApiSignature, LeafCategory, LeafDetector};
pub use persist::CallGraphPersistor;
