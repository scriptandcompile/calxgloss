//! Building the call graph from scan-source reads.
//!
//! The [`CallGraphBuilder`] reads function summaries, callers, and callee
//! information through the shared [`ScanSource`]
//! seam — either the loaded analysis engine or the scan read cache — and
//! assembles the answers into a [`CallGraph`]. Every function starts out
//! categorized as `NodeCategory::Middle`.
//!
//! # Algorithm
//!
//! 1. Call `source.functions()` to get every function, and build a
//!    name→address lookup map.
//! 2. For each function, call `source.callers(address)` for the incoming
//!    cross-references, and turn the returned names back into addresses with
//!    the lookup map.
//! 3. For callees, call `source.decompile(name)` and parse
//!    call targets from the decompiled pseudo-C via
//!    `calxgloss_decomp::parse::callees_from_decompiled`.
//! 4. Map callee names back to addresses using the lookup map.
//! 5. Every function starts as `NodeCategory::Middle` — the later root and
//!    leaf detector work does that classification (Tasks 4–5 in the original
//!    build plan).
//!
//! # Graceful degradation
//!
//! If decompilation fails for a single function the graph still completes,
//! and that function gets an empty callee list.  A total `functions()`
//! failure aborts the build.

use anyhow::Result;
use calxgloss_decomp::ScanSource;
use calxgloss_decomp::parse;
use tracing::{info, warn};

use crate::{CallGraph, CallGraphEdge, CallType, FunctionCallGraph, NodeCategory};

/// Fetches function data through the scan source and builds a call graph.
///
/// The builder reads through the shared [`ScanSource`] seam, so the same
/// graph build runs against a loaded `calxgloss_kuna::KunaSource` or
/// through the batch's [`calxgloss_decomp::CachedScanSource`] with no
/// change of behaviour — when the scan read cache is warm, the whole build
/// costs no live reads.
///
/// # Example
///
/// ```no_run
/// use calxgloss_callgraph::CallGraphBuilder;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let source = calxgloss_decomp::PipelineSource::from(
///     calxgloss_kuna::KunaSource::load("eqmain.dll".as_ref())?,
/// );
/// let builder = CallGraphBuilder::new(source, "eqmain.dll");
/// let graph = builder.build().await?;
/// # Ok(())
/// # }
/// ```
pub struct CallGraphBuilder<S = calxgloss_decomp::PipelineSource> {
    source: S,
    dll_name: String,
}

impl CallGraphBuilder<calxgloss_decomp::PipelineSource> {
    /// Creates a new builder for the given target binary, reading through
    /// the pipeline's scan source (the loaded Kuna analysis engine, usually
    /// served through the scan read cache).
    pub fn new(source: calxgloss_decomp::PipelineSource, dll_name: impl Into<String>) -> Self {
        Self::with_source(source, dll_name)
    }
}

impl<S> CallGraphBuilder<S> {
    /// Creates a new builder for the given target binary, reading through
    /// any scan source.
    pub fn with_source(source: S, dll_name: impl Into<String>) -> Self {
        Self {
            source,
            dll_name: dll_name.into(),
        }
    }
}

impl<S: ScanSource + Sync> CallGraphBuilder<S> {
    /// Builds the complete call graph by querying the scan source for all
    /// functions and their caller/callee relationships.
    ///
    /// Functions with decompilation failures are still included; they get
    /// empty callee lists, so the graph degrades gracefully.
    ///
    /// # TODOs
    ///
    /// ```text
    /// TODO: For indirect calls, scan disassembly for `call [reg]` and `call [rip + offset]`
    /// TODO: For virtual calls, detect `vtable->method()` patterns in decompiled output
    /// TODO: Optimize: batch engine calls with tokio::join_all to reduce wall time
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

        // 2. Process each function one at a time for now; see the TODO
        //    above about batching with `tokio::join_all`.
        //
        // The per-function future is boxed to a `dyn Future + Send`. That
        // makes the caller's `Send` check stop at this boundary, instead of
        // the compiler inferring the whole read chain behind the scan
        // source. This is the same guard against the rust-lang/rust#159228
        // trait-evaluation recursion limit that the pipeline applies to its
        // own futures.
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
                    // Include the function anyway, with empty callers and
                    // callees, so the graph covers every function and stays
                    // indexable by address.
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
    /// [`ScanSource::callers`](calxgloss_decomp::ScanSource::callers),
    /// fetches callees via decompiled output parsed with
    /// [`callees_from_decompiled`](calxgloss_decomp::parse::callees_from_decompiled),
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
        summary: &calxgloss_decomp::FunctionSummary,
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
                    // The caller name is not in the function listing, so the
                    // lookup map has no address for it — it might be an
                    // unnamed or anonymous caller reference. Skip it: a
                    // cross-reference without a listing entry adds no caller.
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
        // Verify that callee names written in Ghidra's decompile dialect
        // (placeholder `FUN_…` spellings) are parsed correctly and then
        // resolved by `resolve_callees`.
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
