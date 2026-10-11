//! Call graph construction from Ghidra data.
//!
//! The [`CallGraphBuilder`] fetches function summaries, callers, and callee
//! information through the shared [`ScanSource`](calxgloss_ghidra::ScanSource)
//! seam — a live client or the batch's read cache — then assembles them into a
//! [`CallGraph`] with all functions initially categorized as
//! `NodeCategory::Middle`.
//!
//! # Algorithm
//!
//! 1. Call `source.functions()` to get every function and build a
//!    name→address lookup map.
//! 2. For each function, call `source.callers(address)` for incoming
//!    cross-references, mapping the returned names back to addresses via
//!    the lookup map.
//! 3. For callees, call `source.decompile(name)` and parse
//!    call targets from the decompiled pseudo-C via
//!    `calxgloss_ghidra::parse::callees_from_decompiled`.
//! 4. Map callee names back to addresses using the lookup map.
//! 5. All functions start as `NodeCategory::Middle` — root/leaf classification
//!    happens in Tasks 4–5.
//!
//! # Graceful degradation
//!
//! If decompilation fails for a single function the graph still completes
//! with an empty callee list for that function.  A total `list_functions`
//! failure aborts the build.

use anyhow::Result;
use calxgloss_ghidra::parse;
use calxgloss_ghidra::ScanSource;
use tracing::{info, warn};

use crate::{CallGraph, CallGraphEdge, CallType, FunctionCallGraph, NodeCategory};

/// Fetches function metadata from Ghidra and constructs a call graph.
///
/// The builder reads through the shared [`ScanSource`] seam, so the same
/// graph build runs against a live [`calxgloss_ghidra::GhidraClient`] or
/// through the batch's [`calxgloss_ghidra::CachedGhidraSource`] without any
/// change of behaviour — a warm cache makes the whole build cost no live
/// reads.
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
pub struct CallGraphBuilder<S = calxgloss_ghidra::GhidraClient> {
    source: S,
    dll_name: String,
}

impl CallGraphBuilder<calxgloss_ghidra::GhidraClient> {
    /// Creates a new builder for the given DLL, reading live from `ghidra`.
    pub fn new(ghidra: calxgloss_ghidra::GhidraClient, dll_name: impl Into<String>) -> Self {
        Self {
            source: ghidra,
            dll_name: dll_name.into(),
        }
    }
}

impl<S> CallGraphBuilder<S> {
    /// Creates a new builder for the given DLL over any shared scan source.
    pub fn with_source(source: S, dll_name: impl Into<String>) -> Self {
        Self {
            source,
            dll_name: dll_name.into(),
        }
    }
}

impl<S: ScanSource + Sync> CallGraphBuilder<S> {

    /// Builds the complete call graph by querying Ghidra for all functions
    /// and their caller/callee relationships.
    ///
    /// Functions with decompilation failures are still included; the graph
    /// degrades gracefully with empty callee lists.
    ///
    /// # TODOs
    ///
    /// ```text
    /// TODO: For indirect calls, scan disassembly for `call [reg]` and `call [rip + offset]`
    /// TODO: For virtual calls, detect `vtable->method()` patterns in decompiled output
    /// TODO: Optimize: batch ghidra calls with tokio::join_all to reduce wall time
    /// TODO: Add progress reporting (callback or async channel for large DLLs)
    /// TODO: Fallback: if decompile fails, use xrefs_from as callee source
    /// ```
    pub async fn build(&self) -> Result<CallGraph> {
        let dll_name = self.dll_name.clone();
        info!(%dll_name, "Building call graph");

        // 1. Fetch all functions and build a name→address lookup map.
        let functions = self.source.functions().await?;
        let mut name_to_addr: std::collections::HashMap<String, u64> =
            std::collections::HashMap::with_capacity(functions.len());
        for func in &functions {
            name_to_addr.insert(func.name.clone(), func.address);
        }

        info!(
            %dll_name,
            func_count = functions.len(),
            "Fetched function listing"
        );

        // 2. Process each function sequentially for now; see TODO about
        //    batching with tokio::join_all.
        //
        // The per-function future is boxed to a `dyn Future + Send` so a
        // caller's `Send` check stops at this boundary instead of descending
        // through the source's whole read chain (the same #159228 recursion
        // guard the pipeline applies to its own futures).
        let mut call_graph_functions = Vec::with_capacity(functions.len());
        let mut failures = 0usize;

        for summary in &functions {
            let processed: std::pin::Pin<
                Box<dyn std::future::Future<Output = Result<FunctionCallGraph>> + Send + '_>,
            > = Box::pin(self.process_function(summary, &name_to_addr));
            match processed.await {
                Ok(func_graph) => call_graph_functions.push(func_graph),
                Err(e) => {
                    warn!(
                        func = %summary.name,
                        addr = format_args!("{:#x}", summary.address),
                        error = %e,
                        "Failed to process function; including with empty callees"
                    );
                    failures += 1;
                    // Still include the function with empty callers/callees
                    // so the graph is complete and address-indexable.
                    call_graph_functions.push(FunctionCallGraph {
                        name: summary.name.clone(),
                        address: summary.address,
                        callers: Vec::new(),
                        callees: Vec::new(),
                        node_category: NodeCategory::Middle,
                    });
                }
            }
        }

        if failures > 0 {
            info!(
                %dll_name,
                failures,
                total = call_graph_functions.len(),
                "Build completed with degraded functions"
            );
        }

        Ok(CallGraph {
            binary: dll_name,
            functions: call_graph_functions,
        })
    }

    /// Processes a single function: fetches callers via
    /// [`ScanSource::callers`](calxgloss_ghidra::ScanSource::callers),
    /// fetches callees via decompiled output parsed with
    /// [`callees_from_decompiled`](calxgloss_ghidra::parse::callees_from_decompiled),
    /// and returns a [`FunctionCallGraph`] with `NodeCategory::Middle`.
    ///
    /// Name→address resolution uses the `name_to_addr` lookup map built from
    /// the full function listing.
    ///
    /// # Graceful degradation
    ///
    /// If decompilation fails the caller list is still populated (it comes
    /// from `xrefs_to`, not the decompiler).  Only the callee list is
    /// affected.
    async fn process_function(
        &self,
        summary: &calxgloss_ghidra::FunctionSummary,
        name_to_addr: &std::collections::HashMap<String, u64>,
    ) -> Result<FunctionCallGraph> {
        let address = summary.address;
        let name = summary.name.clone();

        // 1. Fetch callers (cross-references to this function).
        let caller_names = self.source.callers(address).await.unwrap_or_default();

        // 2. Map caller names to addresses using the lookup map.
        let callers: Vec<u64> = caller_names
            .into_iter()
            .filter_map(|caller_name| {
                name_to_addr.get(&caller_name).copied().or({
                    // The caller name isn't in the listing — it might be
                    // an unnamed or anonymous caller reference.  Treat it
                    // as an xref whose target function has no listing
                    // entry and skip it.
                    None
                })
            })
            .collect();

        // 3. Fetch decompiled output and parse callees.
        let callees = match self.source.decompile(&name).await {
            Ok(decompiled) => {
                let callee_names = parse::callees_from_decompiled(&decompiled.body);
                resolve_callees(address, &callee_names, name_to_addr)
            }
            Err(e) => {
                warn!(
                    func = %name,
                    addr = format_args!("{:#x}", address),
                    error = %e,
                    "Decompilation failed; empty callee list"
                );
                Vec::new()
            }
        };

        info!(
            %name,
            addr = format_args!("{:#x}", address),
            callers = callers.len(),
            callees = callees.len(),
            "Processed function"
        );

        Ok(FunctionCallGraph {
            name,
            address,
            callers,
            callees,
            node_category: NodeCategory::Middle,
        })
    }
}

/// Resolves callee names to [`CallGraphEdge`] objects.
///
/// `source` is the entry address of the calling function. Each callee name
/// is mapped to its entry address using `name_to_addr`.  If a name is not
/// found in the lookup map it is still included with `target == 0` so that
/// no call target is silently lost.
///
/// The original callee name is preserved in [`CallGraphEdge::callee_name`]
/// so that leaf detection can match against known API names.
fn resolve_callees(
    source: u64,
    callee_names: &[String],
    name_to_addr: &std::collections::HashMap<String, u64>,
) -> Vec<CallGraphEdge> {
    callee_names
        .iter()
        .map(|callee_name| {
            let target = name_to_addr.get(callee_name).copied().unwrap_or(0);

            CallGraphEdge {
                source,
                target,
                call_site: 0, // TODO: extract from decompiler output
                call_type: CallType::Direct,
                callee_name: callee_name.clone(),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a name→address lookup map from function summaries.
    fn make_lookup(functions: &[&str]) -> std::collections::HashMap<String, u64> {
        let mut map = std::collections::HashMap::new();
        for (i, name) in functions.iter().enumerate() {
            map.insert((*name).to_string(), 0x1000 + i as u64 * 0x10);
        }
        map
    }

    #[test]
    fn test_resolve_callees_resolves_all_names() {
        let mut lookup = std::collections::HashMap::new();
        lookup.insert("foo".to_string(), 0x1010);
        lookup.insert("bar".to_string(), 0x1020);
        lookup.insert("baz".to_string(), 0x1030);

        let callees = resolve_callees(
            0x1000,
            &["foo".to_string(), "bar".to_string(), "baz".to_string()],
            &lookup,
        );

        assert_eq!(callees.len(), 3);
        assert_eq!(callees[0].source, 0x1000);
        assert_eq!(callees[0].target, 0x1010);
        assert_eq!(callees[0].call_type, CallType::Direct);
        assert_eq!(callees[0].call_site, 0);

        assert_eq!(callees[1].target, 0x1020);
        assert_eq!(callees[2].target, 0x1030);
    }

    #[test]
    fn test_resolve_callees_unresolved_name_gives_zero() {
        let lookup = make_lookup(&["known"]);

        let callees = resolve_callees(
            0x1000,
            &["known".to_string(), "unknown".to_string()],
            &lookup,
        );

        assert_eq!(callees.len(), 2);
        assert_eq!(callees[0].target, 0x1000); // known — resolved
        assert_eq!(callees[1].target, 0); // unknown — not found
    }

    #[test]
    fn test_resolve_callees_empty_input() {
        let lookup = make_lookup(&["foo"]);
        let callees = resolve_callees(0x1000, &[], &lookup);
        assert!(callees.is_empty());
    }

    #[test]
    fn test_resolve_callees_preserves_call_type() {
        let lookup = make_lookup(&["target"]);

        let callees = resolve_callees(0x1000, &["target".to_string()], &lookup);

        assert_eq!(callees[0].call_type, CallType::Direct);
    }

    #[test]
    fn test_resolve_callees_source_address() {
        let lookup = make_lookup(&["target"]);

        let callees = resolve_callees(0xDEAD0000, &["target".to_string()], &lookup);

        assert_eq!(callees[0].source, 0xDEAD0000);
        assert_eq!(callees[0].target, 0x1000);
    }

    #[test]
    fn test_callees_parsing_integration() {
        // Verify that Ghidra's decompiled callee output is correctly parsed
        // and fed into resolve_callees.
        let decompiled_text = "\
void FUN_18000a0d0(void)\n{\n  ppiVar4 = (int **)FUN_1800861f0(local_58);\n  uVar2 = FUN_180069f80(DAT_180381878,1);\n  FUN_180085460();\n}\n";

        let callee_names = parse::callees_from_decompiled(decompiled_text);
        assert_eq!(callee_names.len(), 3);
        assert!(callee_names.contains(&"FUN_1800861f0".to_string()));
        assert!(callee_names.contains(&"FUN_180069f80".to_string()));
        assert!(callee_names.contains(&"FUN_180085460".to_string()));

        // Now resolve through a lookup that has only some of them
        let mut lookup = std::collections::HashMap::new();
        lookup.insert("FUN_1800861f0".to_string(), 0x1800861f0);
        lookup.insert("FUN_180069f80".to_string(), 0x180069f80);
        // FUN_180085460 is intentionally missing

        let callees = resolve_callees(0x18000a0d0, &callee_names, &lookup);

        assert_eq!(callees.len(), 3);
        assert_eq!(callees[0].target, 0x1800861f0);
        assert_eq!(callees[1].target, 0x180069f80);
        assert_eq!(callees[2].target, 0); // unresolved
    }

    #[test]
    fn test_caller_names_mapped_to_addresses() {
        // Simulate the caller name→address resolution logic from process_function.
        let mut lookup = std::collections::HashMap::new();
        lookup.insert("caller_a".to_string(), 0x2000);
        lookup.insert("caller_b".to_string(), 0x3000);

        let caller_names = vec!["caller_a".to_string(), "caller_b".to_string()];
        let callers: Vec<u64> = caller_names
            .into_iter()
            .filter_map(|name| lookup.get(&name).copied())
            .collect();

        assert_eq!(callers.len(), 2);
        assert!(callers.contains(&0x2000));
        assert!(callers.contains(&0x3000));
    }

    #[test]
    fn test_caller_name_not_in_lookup_is_skipped() {
        let mut lookup = std::collections::HashMap::new();
        lookup.insert("known".to_string(), 0x2000);

        let caller_names = vec!["known".to_string(), "unnamed".to_string()];
        let callers: Vec<u64> = caller_names
            .into_iter()
            .filter_map(|name| lookup.get(&name).copied())
            .collect();

        assert_eq!(callers.len(), 1);
        assert_eq!(callers[0], 0x2000);
    }
}
