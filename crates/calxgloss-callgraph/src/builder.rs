//! Call graph construction from Ghidra data.
//!
//! The [`CallGraphBuilder`] fetches function summaries, callers, and callee
//! information from a GhidraMCP server, then assembles them into a
//! [`CallGraph`] with all functions initially categorized as `NodeCategory::Middle`.

use anyhow::Result;
use tracing::info;

use crate::{CallGraph, FunctionCallGraph};

/// Fetches function metadata from Ghidra and constructs a call graph.
///
/// # Example
///
/// ```no_run
/// use calxgloss_callgraph::CallGraphBuilder;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let ghidra = calxgloss_ghidra::GhidraClient::new("http://localhost:8080")?;
/// let builder = CallGraphBuilder::new(ghidra, "eqmain.dll");
/// let graph = builder.build().await?;
/// # Ok(())
/// # }
/// ```
pub struct CallGraphBuilder {
    ghidra: calxgloss_ghidra::GhidraClient,
    dll_name: String,
}

impl CallGraphBuilder {
    /// Creates a new builder for the given DLL.
    pub fn new(
        ghidra: calxgloss_ghidra::GhidraClient,
        dll_name: impl Into<String>,
    ) -> Self {
        Self {
            ghidra,
            dll_name: dll_name.into(),
        }
    }

    /// Builds the complete call graph by querying Ghidra for all functions
    /// and their caller/callee relationships.
    ///
    /// Functions with decompilation failures are still included; the graph
    /// degrades gracefully with empty callee lists.
    pub async fn build(&self) -> Result<CallGraph> {
        let dll_name = self.dll_name.clone();
        info!(%dll_name, "Building call graph");

        // TODO: For indirect calls, scan disassembly for `call [reg]` and `call [rip + offset]`
        // TODO: For virtual calls, detect `vtable->method()` patterns in decompiled output
        // TODO: Optimize: batch ghidra calls with tokio::join_all to reduce wall time
        // TODO: Add progress reporting (callback or async channel for large DLLs)
        // TODO: Fallback: if decompile fails, use xrefs_from as callee source

        unimplemented!()
    }

    /// Processes a single function: fetches callers via `xrefs_to`,
    /// fetches callees via decompiled output, and returns a
    /// [`FunctionCallGraph`] with `NodeCategory::Middle`.
    fn process_function(
        &self,
        _summary: &calxgloss_ghidra::FunctionSummary,
    ) -> Result<FunctionCallGraph> {
        // TODO: Fetch callers via ghidra.callers(address)
        // TODO: Fetch callees by parsing decompiled output
        // TODO: Map callee names back to addresses using the lookup map

        unimplemented!()
    }
}
