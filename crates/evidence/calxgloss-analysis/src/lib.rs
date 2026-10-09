//! DLL classification, call graph analysis, and Windows API tagging.
//!
//! This crate provides the [`Analyzer`] struct, which orchestrates the analysis
//! of target DLLs by combining data from a GhidraMCP server with the PAL mapping
//! table from `calxgloss-pal`.
//!
//! # Main Capabilities
//!
//! - **DLL Classification** — categorize each DLL as `WindowsOs`, `MicrosoftSdk`,
//!   `KnownThirdParty`, `ProjectSpecific`, or `UnknownThirdParty`, and determine
//!   the appropriate reverse-engineering strategy.
//! - **Function Analysis** — extract complete function metadata including
//!   disassembly, decompiler output, Windows API calls, and call graph neighbors.
//! - **Windows API Tagging** — cross-reference disassembly and imports against the
//!   PAL mapping table to identify and tag every Windows API call with its
//!   category and cross-platform replacement.
//!
//! # Example
//!
//! ```no_run
//! use calxgloss_analysis::Analyzer;
//! use calxgloss_pal::ApiMappings;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let ghidra = calxgloss_ghidra::GhidraClient::new("http://localhost:8080")?;
//! let api_mappings = ApiMappings::default();
//! let analyzer = Analyzer::new(ghidra, api_mappings);
//!
//! // Classify the DLLs you care about
//! let names = vec!["eqmain.dll".to_string()];
//! let target_dir = std::path::Path::new("/path/to/targets");
//! let classifications = analyzer.classify_dlls(&names, target_dir).await?;
//! for classification in &classifications {
//!     println!(
//!         "{:20} → {:?} ({:?})",
//!         classification.binary, classification.category, classification.strategy
//!     );
//! }
//! # Ok(())
//! # }
//! ```

mod analyzer;
mod callgraph;
mod classify;
pub mod dependency;
pub mod error;
pub mod experiment_log;
pub mod fault_log;
pub mod shim;
pub mod shim_gen;
pub mod shim_pipeline;
pub mod shim_test_gen;
pub mod token_usage;

pub use analyzer::*;
pub use callgraph::{
    build_dependency_graph_from_call_graph, build_enriched_call_graph, load_call_graph,
    print_call_graph_stats,
};
pub use classify::*;
pub use dependency::*;
pub use error::{AnalysisError, Result};
pub use experiment_log::*;
pub use fault_log::FaultLogger;
pub use token_usage::TokenUsageLogger;

// Re-export shim suggestion types from calxgloss-types.
pub use calxgloss_types::ShimSuggestionReport;
