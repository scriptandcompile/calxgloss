//! Memory lifecycle scan orchestration.
//!
//! [`MemoryEngine`] runs the three detectors — allocation/release pair
//! tracking, handle lifetime detection, and reference-counting
//! detection — over every function of one open Ghidra program and
//! assembles their findings into a single [`MemoryResult`] with its scan
//! provenance.
//!
//! The detectors are pure text analysis over one decompiled body, so the
//! engine fetches each function's pseudo-C exactly once and reads it with
//! all three, rather than having each detector pull its own copy. The
//! scan is then one sequential pass over the function listing: unlike
//! typeinfer's competing families there is nothing to resolve between the
//! detectors — they read disjoint body shapes — and keeping the pass
//! sequential keeps the persisted finding list in a stable, diffable
//! order.

use crate::allocator::AllocatorTracker;
use crate::cross_function::CrossFunctionAnalyzer;
use crate::error::Result;
use crate::handle::HandleDetector;
use crate::refcount::ReferenceCountDetector;
use crate::types::{MemoryFinding, MemoryResult, ScanMetadata};
use calxgloss_ghidra::{DecompiledFunction, GhidraClient};
use std::time::Instant;
use tracing::{info, warn};

/// The decompiler reads a memory lifecycle scan performs.
///
/// The shared trait from the Ghidra integration crate, re-exported here
/// so the engine's generic shape names it where it always has;
/// [`GhidraClient`] implements it over the live HTTP API, and tests
/// implement it over canned bodies so the orchestration runs without a
/// server. The futures are `Send` so a scan can be driven from an
/// orchestrating task.
pub use calxgloss_ghidra::ScanSource;

/// Orchestrates the three detectors into one [`MemoryResult`].
///
/// The engine is generic over its [`ScanSource`], so tests can run the
/// whole orchestration over canned bodies; [`new`](Self::new) builds one
/// over a live [`GhidraClient`]. Each detector carries no state and
/// starts configured with its standard name sets —
/// [`with_allocator`](Self::with_allocator), [`with_handles`](Self::with_handles),
/// and [`with_refcounts`](Self::with_refcounts) swap a detector's sets
/// whole — so one instance of each serves the whole scan.
#[derive(Debug, Clone)]
pub struct MemoryEngine<S = GhidraClient> {
    source: S,
    allocator: AllocatorTracker,
    handles: HandleDetector,
    refcounts: ReferenceCountDetector,
    cross_function: CrossFunctionAnalyzer,
}

impl MemoryEngine<GhidraClient> {
    /// An engine over a live GhidraMCP client, scanning with the three
    /// detectors' standard name sets.
    pub fn new(client: &GhidraClient) -> MemoryEngine<GhidraClient> {
        MemoryEngine {
            source: client.clone(),
            allocator: AllocatorTracker::with_default_names(),
            handles: HandleDetector::with_default_names(),
            refcounts: ReferenceCountDetector::with_default_names(),
            cross_function: CrossFunctionAnalyzer::new(),
        }
    }
}

impl<S> MemoryEngine<S> {
    /// An engine whose decompiles come from `source`, scanning with the
    /// three detectors' standard name sets.
    pub fn with_source(source: S) -> Self {
        MemoryEngine {
            source,
            allocator: AllocatorTracker::with_default_names(),
            handles: HandleDetector::with_default_names(),
            refcounts: ReferenceCountDetector::with_default_names(),
            cross_function: CrossFunctionAnalyzer::new(),
        }
    }

    /// Pair allocations against `tracker`'s name sets instead of the
    /// standard ones.
    pub fn with_allocator(mut self, tracker: AllocatorTracker) -> Self {
        self.allocator = tracker;
        self
    }

    /// Pair handles against `detector`'s name sets instead of the
    /// standard ones.
    pub fn with_handles(mut self, detector: HandleDetector) -> Self {
        self.handles = detector;
        self
    }

    /// Pair reference counts against `detector`'s name sets instead of
    /// the standard ones.
    pub fn with_refcounts(mut self, detector: ReferenceCountDetector) -> Self {
        self.refcounts = detector;
        self
    }

    /// Detect memory lifecycles across `binary`, decompiling each
    /// function exactly once and reading it with all three detectors.
    ///
    /// `binary` names the program the scan reads (e.g. `eqmain.dll`) and
    /// becomes the key a persisted result is filed under. The findings
    /// follow the function listing — function by function, and within one
    /// function the allocation pairs, then the handle lifetimes, then the
    /// reference counts — so two scans of the same program diff cleanly.
    ///
    /// A function whose body Ghidra cannot produce (a thunk, a bad entry
    /// point) is skipped with a warning; only a failure of the listing
    /// itself — the server being down — aborts the run, since then
    /// nothing was scanned.
    /// But when more than half the listing fails to decompile, the
    /// skip-rate breaker aborts the run too: that is the signature of
    /// the bridge answering from the wrong program, and skipping on
    /// would persist a phantom-clean record (issue #71).
    /// The three detectors read disjoint body
    /// shapes, so a function can carry findings of every kind at once
    /// and nothing is resolved between them.
    pub async fn scan(&self, binary: impl Into<String>) -> Result<MemoryResult>
    where
        S: ScanSource,
    {
        let started = Instant::now();
        let functions = self.source.functions().await?;

        let mut findings = Vec::new();
        let mut bodies: Vec<DecompiledFunction> = Vec::new();
        let mut skipped = 0usize;
        let mut decompile_failures = 0usize;
        for function in &functions {
            if function.name.is_empty() {
                // A nameless listing entry would send the name lookup
                // wandering into some other function's body; nothing can
                // be said about it, so it passes unrecorded.
                warn!(
                    address = format_args!("{:#x}", function.address),
                    "Skipping function with no name"
                );
                skipped += 1;
                continue;
            }
            let decompiled = match self.source.decompile(&function.name).await {
                Ok(decompiled) => decompiled,
                Err(error) => {
                    warn!(
                        function = %function.name,
                        error = %error,
                        "Skipping function: decompile failed"
                    );
                    skipped += 1;
                    decompile_failures += 1;
                    // Skip-rate breaker: once most of the listing has
                    // failed to decompile, the scan is reading the
                    // wrong program (or a half-broken server), and an
                    // empty result would persist as a phantom-clean
                    // record. Abort with the counts instead of
                    // skipping on.
                    if decompile_failures * 2 > functions.len() {
                        return Err(crate::MemoryError::DecompileBreaker {
                            failed: decompile_failures,
                            total: functions.len(),
                        });
                    }
                    continue;
                }
            };

            findings.extend(
                self.allocator
                    .detect_pairs(&decompiled)
                    .into_iter()
                    .map(MemoryFinding::Allocation),
            );
            findings.extend(
                self.handles
                    .detect_handles(&decompiled)
                    .into_iter()
                    .map(MemoryFinding::Handle),
            );
            findings.extend(
                self.refcounts
                    .detect_reference_counts(&decompiled)
                    .into_iter()
                    .map(MemoryFinding::RefCount),
            );
            bodies.push(decompiled);
        }

        // The cross-function pass runs after the per-function walk,
        // over the bodies the scan already decompiled — no extra
        // Ghidra round trips — and its findings append in listing
        // order, so the persisted list stays stable and diffable.
        findings.extend(
            self.cross_function
                .analyze(&bodies, &self.allocator, &self.handles),
        );

        let mut metadata = ScanMetadata::new(binary);
        metadata.duration_secs = started.elapsed().as_secs();
        info!(
            binary = %metadata.binary,
            functions = functions.len(),
            findings = findings.len(),
            skipped,
            duration_secs = metadata.duration_secs,
            "Detected memory lifecycles"
        );
        Ok(MemoryResult { metadata, findings })
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::allocator::AllocatorSignature;
    use crate::handle::HandleSignature;
    use crate::types::{AllocationType, CountStyle, HandleType, LeakResource, TransferDirection};
    use calxgloss_ghidra::{
        DataItem, DataTypeEntry, DecompiledFunction, EnumDefinition, FunctionSummary, GhidraError,
        Result, StringLiteral, StructLayout, Symbol, Xref,
    };
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    fn summary(name: &str) -> FunctionSummary {
        FunctionSummary {
            name: name.to_string(),
            address: 0x1800_3ab00,
        }
    }

    fn function(name: &str, signature: &str, body: &str) -> DecompiledFunction {
        DecompiledFunction {
            name: name.to_string(),
            signature: signature.to_string(),
            body: format!("\n{signature}\n\n{{\n{body}}}\n"),
        }
    }

    /// State shared by every clone of a [`FakeProgram`], so a test can read
    /// what the scan did after the engine has consumed its source.
    #[derive(Debug, Default)]
    struct Stats {
        decompiles: Mutex<Vec<String>>,
    }

    /// A canned program implementing [`ScanSource`], so the whole
    /// orchestration runs without a server.
    #[derive(Clone)]
    struct FakeProgram {
        listing: Vec<FunctionSummary>,
        bodies: HashMap<String, DecompiledFunction>,
        fail_decompiles: Vec<String>,
        fail_listing: bool,
        stats: Arc<Stats>,
    }

    impl FakeProgram {
        fn empty() -> Self {
            Self {
                listing: Vec::new(),
                bodies: HashMap::new(),
                fail_decompiles: Vec::new(),
                fail_listing: false,
                stats: Arc::new(Stats::default()),
            }
        }

        fn decompiled(&self) -> Vec<String> {
            self.stats.decompiles.lock().unwrap().clone()
        }
    }

    impl ScanSource for FakeProgram {
        async fn functions(&self) -> Result<Vec<FunctionSummary>> {
            if self.fail_listing {
                return Err(GhidraError::Reported {
                    status: Some(200),
                    message: "Ghidra is busy".into(),
                });
            }
            Ok(self.listing.clone())
        }

        async fn decompile(&self, name: &str) -> Result<DecompiledFunction> {
            self.stats.decompiles.lock().unwrap().push(name.to_string());
            if self.fail_decompiles.iter().any(|f| f == name) {
                return Err(GhidraError::NotFound {
                    kind: "function",
                    query: name.to_string(),
                });
            }
            self.bodies
                .get(name)
                .cloned()
                .ok_or_else(|| GhidraError::NotFound {
                    kind: "function",
                    query: name.to_string(),
                })
        }

        // The rest of the shared trait's reads: this engine never makes
        // them, so they answer with empty or not-found data.
        async fn strings(&self) -> Result<Vec<StringLiteral>> {
            Ok(Vec::new())
        }

        async fn callers(&self, _address: u64) -> Result<Vec<String>> {
            Ok(Vec::new())
        }

        async fn xrefs_to(&self, _address: u64) -> Result<Vec<Xref>> {
            Ok(Vec::new())
        }

        async fn data_types(&self, _category: Option<&str>) -> Result<Vec<DataTypeEntry>> {
            Ok(Vec::new())
        }

        async fn struct_layout(&self, name: &str) -> Result<StructLayout> {
            Err(GhidraError::NotFound {
                kind: "struct",
                query: name.to_string(),
            })
        }

        async fn enum_values(&self, name: &str) -> Result<EnumDefinition> {
            Err(GhidraError::NotFound {
                kind: "enum",
                query: name.to_string(),
            })
        }

        async fn data_items(&self) -> Result<Vec<DataItem>> {
            Ok(Vec::new())
        }

        async fn imports(&self) -> Result<Vec<Symbol>> {
            Ok(Vec::new())
        }

        async fn exports(&self) -> Result<Vec<Symbol>> {
            Ok(Vec::new())
        }

        async fn image_base(&self) -> Result<u64> {
            Ok(0)
        }

        async fn read_memory(&self, _address: u64, _length: usize) -> Result<Vec<u8>> {
            Ok(Vec::new())
        }
    }

    /// A body carrying a `malloc`/`free` pair, a `CreateFileW`/
    /// `CloseHandle` pair, and an `AddRef`/`Release` pair — one finding
    /// family per detector — all in one function.
    const EVERY_SHAPE_BODY: &str = "\
  pvVar1 = malloc(0x20);
  *(int *)pvVar1 = 5;
  free(pvVar1);
  hFile = CreateFileW(&DAT_3801a2b0,0xc0000000,0,(LPSECURITY_ATTRIBUTES)0x0,3,0x80,0);
  CloseHandle(hFile);
  AddRef((IUnknown *)param_1);
  Release((IUnknown *)param_1);";

    /// The canned program: one function whose body carries every shape,
    /// and one plain function that finds nothing.
    fn program() -> FakeProgram {
        let mut program = FakeProgram::empty();
        program.listing = vec![summary("FUN_18003ab00"), summary("FUN_18003e750")];
        program.bodies.insert(
            "FUN_18003ab00".into(),
            function(
                "FUN_18003ab00",
                "undefined FUN_18003ab00(IUnknown *param_1)",
                EVERY_SHAPE_BODY,
            ),
        );
        program.bodies.insert(
            "FUN_18003e750".into(),
            function(
                "FUN_18003e750",
                "undefined FUN_18003e750(void)",
                "  return;\n",
            ),
        );
        program
    }

    async fn scan(program: FakeProgram) -> MemoryResult {
        MemoryEngine::with_source(program)
            .scan("eqmain.dll")
            .await
            .expect("scan")
    }

    fn kinds(result: &MemoryResult, function: &str) -> Vec<&'static str> {
        result
            .for_function(function)
            .map(|finding| finding.kind())
            .collect()
    }

    #[tokio::test]
    async fn scan_collects_findings_from_all_three_detectors() {
        let result = scan(program()).await;

        assert_eq!(result.metadata.binary, "eqmain.dll");
        assert!(result.metadata.scanned_at > 0);

        let findings: Vec<&MemoryFinding> = result.for_function("FUN_18003ab00").collect();
        assert_eq!(findings.len(), 3);

        let MemoryFinding::Allocation(hint) = findings[0] else {
            unreachable!("the allocation pair reads as an allocation finding");
        };
        assert_eq!(hint.allocation_type, AllocationType::Malloc);
        assert_eq!(hint.evidence, "pvVar1 = malloc(0x20); free(pvVar1);");

        let MemoryFinding::Handle(record) = findings[1] else {
            unreachable!("the handle pair reads as a handle finding");
        };
        assert_eq!(record.handle_type, HandleType::KernelObject);
        assert_eq!(record.opener, "CreateFileW");
        assert_eq!(record.closer, "CloseHandle");

        let MemoryFinding::RefCount(record) = findings[2] else {
            unreachable!("the bump and drop read as a reference-count finding");
        };
        assert_eq!(record.style, CountStyle::ComMethods);
        assert_eq!(record.increment, "AddRef");
        assert_eq!(record.decrement, "Release");

        assert!(result.for_function("FUN_18003e750").next().is_none());
    }

    #[tokio::test]
    async fn scan_keeps_findings_in_scan_order() {
        // Both functions carry every shape, so the persisted list must
        // group their findings by function in listing order — and within
        // one function run allocation, handle, then reference count —
        // never interleaved.
        let mut program = program();
        program.listing = vec![summary("FUN_18003e750"), summary("FUN_18003ab00")];
        program.bodies.insert(
            "FUN_18003e750".into(),
            function(
                "FUN_18003e750",
                "undefined FUN_18003e750(IUnknown *param_1)",
                EVERY_SHAPE_BODY,
            ),
        );
        let result = scan(program).await;

        let order: Vec<(&str, &str)> = result
            .findings
            .iter()
            .map(|finding| (finding.function(), finding.kind()))
            .collect();
        assert_eq!(
            order,
            vec![
                ("FUN_18003e750", "allocation"),
                ("FUN_18003e750", "handle"),
                ("FUN_18003e750", "ref_count"),
                ("FUN_18003ab00", "allocation"),
                ("FUN_18003ab00", "handle"),
                ("FUN_18003ab00", "ref_count"),
            ]
        );
    }

    #[tokio::test]
    async fn scan_decompiles_each_function_exactly_once() {
        // The three detectors share one fetch per function; a scan that
        // asked each detector for its own copy would triple the wall time.
        let program = program();
        let result = scan(program.clone()).await;
        assert!(!result.is_empty());
        assert_eq!(
            program.decompiled(),
            vec!["FUN_18003ab00", "FUN_18003e750"],
            "one decompile per function, in listing order"
        );
    }

    #[tokio::test]
    async fn a_function_that_will_not_decompile_is_skipped() {
        // Ghidra cannot produce a body for every function; one bad entry
        // point must not cost the whole program its scan.
        let mut program = program();
        program.fail_decompiles = vec!["FUN_18003ab00".into()];
        let result = scan(program.clone()).await;

        assert!(
            result.is_empty(),
            "the failing function contributed nothing"
        );
        assert_eq!(program.decompiled(), vec!["FUN_18003ab00", "FUN_18003e750"]);
    }

    #[tokio::test]
    async fn a_scan_where_every_decompile_fails_aborts() {
        // The 2026-10-08 incident: the bridge answered the listing from
        // one program and the decompiles from another, every decompile
        // failed, and the scan nearly persisted a phantom-clean record
        // under the target's name. The skip-rate breaker aborts with
        // the counts instead, so nothing is persisted.
        let mut program = program();
        program.fail_decompiles = vec!["FUN_18003ab00".into(), "FUN_18003e750".into()];
        let result = MemoryEngine::with_source(program).scan("eqmain.dll").await;
        assert!(matches!(
            result,
            Err(crate::MemoryError::DecompileBreaker {
                failed: 2,
                total: 2
            })
        ));
    }

    #[tokio::test]
    async fn the_breaker_stops_the_scan_from_decompiling_the_rest() {
        // The breaker is a circuit breaker, not a post-mortem: once
        // most of the listing has failed, the remaining decompiles are
        // wasted round-trips against the wrong program.
        let mut program = program();
        program.listing.push(summary("FUN_1800412a0"));
        program.bodies.insert(
            "FUN_1800412a0".into(),
            function(
                "FUN_1800412a0",
                "undefined FUN_1800412a0(void)",
                "  return;\n",
            ),
        );
        program.fail_decompiles = vec!["FUN_18003ab00".into(), "FUN_18003e750".into()];
        let result = MemoryEngine::with_source(program.clone())
            .scan("eqmain.dll")
            .await;

        assert!(matches!(
            result,
            Err(crate::MemoryError::DecompileBreaker {
                failed: 2,
                total: 3
            })
        ));
        assert_eq!(
            program.decompiled(),
            vec!["FUN_18003ab00", "FUN_18003e750"],
            "the scan stopped once the breaker tripped"
        );
    }

    #[tokio::test]
    async fn a_nameless_listing_entry_is_skipped() {
        // An empty name would send the by-name lookup into an arbitrary
        // function's body, so the entry passes without a decompile.
        let mut program = program();
        program.listing.insert(0, summary(""));
        let result = scan(program.clone()).await;

        assert_eq!(program.decompiled(), vec!["FUN_18003ab00", "FUN_18003e750"]);
        assert!(!result.is_empty());
    }

    #[tokio::test]
    async fn a_failing_listing_fails_the_whole_run() {
        // With the listing gone nothing was scanned, so the run aborts
        // rather than returning a result that looks empty by detection.
        let mut program = program();
        program.fail_listing = true;
        let result = MemoryEngine::with_source(program).scan("eqmain.dll").await;
        assert!(matches!(
            result,
            Err(crate::MemoryError::Ghidra(GhidraError::Reported { .. }))
        ));
    }

    #[tokio::test]
    async fn custom_name_sets_reach_every_detector() {
        // Swapping a detector's sets whole reaches the scan: the
        // configured custom spellings pair in all three families, and the
        // standard names the swaps replaced pair nothing.
        let mut program = FakeProgram::empty();
        program.listing = vec![summary("FUN_1800412a0")];
        program.bodies.insert(
            "FUN_1800412a0".into(),
            function(
                "FUN_1800412a0",
                "undefined FUN_1800412a0(void)",
                "\
  pvVar1 = CoTaskMemAlloc(0x10);
  CoTaskMemFree(pvVar1);
  iVar2 = open(&DAT_3801a2b0,2);
  close(iVar2);
  retain(p);
  release(p);",
            ),
        );

        let engine = MemoryEngine::with_source(program)
            .with_allocator(AllocatorTracker::with_names(
                [AllocatorSignature::new(
                    "CoTaskMemAlloc",
                    AllocationType::Malloc,
                )],
                ["CoTaskMemFree"],
            ))
            .with_handles(HandleDetector::with_names(
                [HandleSignature::new("open", HandleType::KernelObject)],
                [HandleSignature::new("close", HandleType::KernelObject)],
            ))
            .with_refcounts(ReferenceCountDetector::with_names(
                Vec::<String>::new(),
                ["retain"],
                ["release"],
                Vec::<String>::new(),
            ));
        let result = engine.scan("eqmain.dll").await.expect("scan");

        assert_eq!(
            kinds(&result, "FUN_1800412a0"),
            ["allocation", "handle", "ref_count"]
        );
        let findings: Vec<&MemoryFinding> = result.for_function("FUN_1800412a0").collect();
        let MemoryFinding::Allocation(hint) = findings[0] else {
            unreachable!("the configured allocator pair reads as an allocation finding");
        };
        assert_eq!(
            hint.evidence,
            "pvVar1 = CoTaskMemAlloc(0x10); CoTaskMemFree(pvVar1);"
        );
        let MemoryFinding::Handle(record) = findings[1] else {
            unreachable!("the configured opener pair reads as a handle finding");
        };
        assert_eq!(record.opener, "open");
        assert_eq!(record.closer, "close");
        let MemoryFinding::RefCount(record) = findings[2] else {
            unreachable!("the configured bump pair reads as a reference-count finding");
        };
        assert_eq!(record.increment, "retain");
        assert_eq!(record.decrement, "release");
    }

    #[tokio::test]
    async fn a_scan_reports_an_allocation_released_by_a_callee() {
        // The cross-function pair the per-function detectors cannot
        // see: A allocates and hands the block to B, B's body releases
        // the parameter it arrived in.
        let mut program = FakeProgram::empty();
        program.listing = vec![summary("FUN_18003ab00"), summary("FUN_18003e750")];
        program.bodies.insert(
            "FUN_18003ab00".into(),
            function(
                "FUN_18003ab00",
                "undefined FUN_18003ab00(void)",
                "  pvVar1 = malloc(0x20);\n  FUN_18003e750(pvVar1);\n",
            ),
        );
        program.bodies.insert(
            "FUN_18003e750".into(),
            function(
                "FUN_18003e750",
                "undefined FUN_18003e750(void *param_1)",
                "  free(param_1);\n",
            ),
        );
        let result = scan(program).await;
        let findings: Vec<&MemoryFinding> = result.for_function("FUN_18003ab00").collect();
        assert_eq!(findings.len(), 1);
        let MemoryFinding::CrossFunction(record) = findings[0] else {
            unreachable!("the cross-function pass reads the hand-off pair");
        };
        assert_eq!(record.partner, "FUN_18003e750");
        assert_eq!(record.variable, "pvVar1");
        assert_eq!(record.confidence.value(), 70);
        // The finding belongs to the allocating function; the callee's
        // own release is its half of the pair, not a finding of its own.
        assert!(result.for_function("FUN_18003e750").next().is_none());
    }

    #[tokio::test]
    async fn a_scan_reports_a_pointer_handed_to_a_non_releasing_callee() {
        // The block escapes into a callee that keeps it: no pair forms,
        // but the move itself is the ownership transfer a Rust author
        // would express as `Box`.
        let mut program = FakeProgram::empty();
        program.listing = vec![summary("FUN_18003ab00"), summary("FUN_18003e750")];
        program.bodies.insert(
            "FUN_18003ab00".into(),
            function(
                "FUN_18003ab00",
                "undefined FUN_18003ab00(void)",
                "  pvVar1 = malloc(0x20);\n  FUN_18003e750(pvVar1);\n",
            ),
        );
        program.bodies.insert(
            "FUN_18003e750".into(),
            function(
                "FUN_18003e750",
                "undefined FUN_18003e750(void *param_1)",
                "  use(param_1);\n",
            ),
        );
        let result = scan(program).await;
        let findings: Vec<&MemoryFinding> = result.for_function("FUN_18003ab00").collect();
        assert_eq!(findings.len(), 1);
        let MemoryFinding::Ownership(record) = findings[0] else {
            unreachable!("the escape reads as an ownership transfer");
        };
        assert_eq!(record.direction, TransferDirection::HandedToCallee);
        assert_eq!(record.partner.as_deref(), Some("FUN_18003e750"));
        assert_eq!(record.variable, "pvVar1");
        assert_eq!(record.confidence.value(), 65);
        assert_eq!(record.suggestion, "Box<T>");
    }

    #[tokio::test]
    async fn a_scan_reports_a_pointer_returned_to_the_caller() {
        let mut program = FakeProgram::empty();
        program.listing = vec![summary("FUN_18003ab00")];
        program.bodies.insert(
            "FUN_18003ab00".into(),
            function(
                "FUN_18003ab00",
                "undefined FUN_18003ab00(void)",
                "  pvVar1 = malloc(0x20);\n  return pvVar1;\n",
            ),
        );
        let result = scan(program).await;
        let findings: Vec<&MemoryFinding> = result.for_function("FUN_18003ab00").collect();
        assert_eq!(findings.len(), 1);
        let MemoryFinding::Ownership(record) = findings[0] else {
            unreachable!("the return hands the block to the caller");
        };
        assert_eq!(record.direction, TransferDirection::ReturnedToCaller);
        assert_eq!(record.partner, None);
    }

    #[tokio::test]
    async fn a_scan_reports_an_allocation_never_released_or_handed_on() {
        // The thing the crate promises to find: the block is taken,
        // never freed, never passed, never returned — a leak.
        let mut program = FakeProgram::empty();
        program.listing = vec![summary("FUN_18003ab00")];
        program.bodies.insert(
            "FUN_18003ab00".into(),
            function(
                "FUN_18003ab00",
                "undefined FUN_18003ab00(void)",
                "  pvVar1 = malloc(0x20);\n  *pvVar1 = 0;\n",
            ),
        );
        let result = scan(program).await;
        let findings: Vec<&MemoryFinding> = result.for_function("FUN_18003ab00").collect();
        assert_eq!(findings.len(), 1);
        let MemoryFinding::Leak(record) = findings[0] else {
            unreachable!("an open allocation that goes nowhere is a leak");
        };
        assert_eq!(record.variable, "pvVar1");
        assert_eq!(
            record.resource,
            LeakResource::Allocation {
                allocation_type: AllocationType::Malloc,
            }
        );
        assert_eq!(record.confidence.value(), 60);
        assert_eq!(record.suggestion, "Box<T>");
    }

    #[tokio::test]
    async fn a_scan_reports_an_unclosed_handle_that_escapes_nowhere() {
        let mut program = FakeProgram::empty();
        program.listing = vec![summary("FUN_18003ab00")];
        program.bodies.insert(
            "FUN_18003ab00".into(),
            function(
                "FUN_18003ab00",
                "undefined FUN_18003ab00(void)",
                "  hFile = CreateFileW(&DAT_3801a2b0,0xc0000000,0,(LPSECURITY_ATTRIBUTES)0x0,3,0x80,0);\n  bVar1 = hFile != (void *)0x0;\n",
            ),
        );
        let result = scan(program).await;
        let findings: Vec<&MemoryFinding> = result.for_function("FUN_18003ab00").collect();
        assert_eq!(findings.len(), 1);
        let MemoryFinding::Leak(record) = findings[0] else {
            unreachable!("an unclosed handle that goes nowhere is a leak");
        };
        assert_eq!(record.variable, "hFile");
        assert_eq!(
            record.resource,
            LeakResource::Handle {
                handle_type: HandleType::KernelObject,
                opener: "CreateFileW".into(),
            }
        );
        assert_eq!(record.suggestion, "RAII guard struct with Drop impl");
    }

    #[tokio::test]
    async fn cross_function_findings_append_after_the_per_function_findings() {
        // One function carries an in-body pair and an open allocation
        // handed to a releasing callee: the pairing finding rides the
        // per-function walk, the cross-function finding lands after it.
        let mut program = FakeProgram::empty();
        program.listing = vec![summary("FUN_18003ab00"), summary("FUN_18003e750")];
        program.bodies.insert(
            "FUN_18003ab00".into(),
            function(
                "FUN_18003ab00",
                "undefined FUN_18003ab00(void)",
                "  pvVar1 = malloc(0x20);\n  free(pvVar1);\n  pvVar2 = malloc(0x30);\n  FUN_18003e750(pvVar2);\n",
            ),
        );
        program.bodies.insert(
            "FUN_18003e750".into(),
            function(
                "FUN_18003e750",
                "undefined FUN_18003e750(void *param_1)",
                "  free(param_1);\n",
            ),
        );
        let result = scan(program).await;
        assert_eq!(
            kinds(&result, "FUN_18003ab00"),
            ["allocation", "cross_function"]
        );
    }

    #[tokio::test]
    async fn a_function_that_will_not_decompile_fabricates_no_cross_function_claim() {
        // A hands an open allocation to B, but B never decompiled: the
        // pass reads only the bodies the scan holds, so a missing half
        // claims nothing.
        let mut program = program();
        program.bodies.insert(
            "FUN_18003ab00".into(),
            function(
                "FUN_18003ab00",
                "undefined FUN_18003ab00(IUnknown *param_1)",
                "  pvVar9 = malloc(0x20);\n  FUN_18003e750(pvVar9);\n",
            ),
        );
        program.fail_decompiles = vec!["FUN_18003e750".into()];
        let result = scan(program).await;
        assert!(
            result
                .findings
                .iter()
                .all(|finding| finding.kind() != "cross_function"),
            "a callee with no body releases nothing: {result:?}",
        );
    }

    #[tokio::test]
    async fn custom_deallocator_names_reach_the_cross_function_pass() {
        // The pass reads the tracker the engine was configured with,
        // not a private default set.
        let mut program = FakeProgram::empty();
        program.listing = vec![summary("FUN_1800412a0"), summary("FUN_1800413b0")];
        program.bodies.insert(
            "FUN_1800412a0".into(),
            function(
                "FUN_1800412a0",
                "undefined FUN_1800412a0(void)",
                "  pvVar1 = CoTaskMemAlloc(0x10);\n  FUN_1800413b0(pvVar1);\n",
            ),
        );
        program.bodies.insert(
            "FUN_1800413b0".into(),
            function(
                "FUN_1800413b0",
                "undefined FUN_1800413b0(void *param_1)",
                "  CoTaskMemFree(param_1);\n",
            ),
        );
        let engine =
            MemoryEngine::with_source(program).with_allocator(AllocatorTracker::with_names(
                [AllocatorSignature::new(
                    "CoTaskMemAlloc",
                    AllocationType::Malloc,
                )],
                ["CoTaskMemFree"],
            ));
        let result = engine.scan("eqmain.dll").await.expect("scan");
        assert_eq!(kinds(&result, "FUN_1800412a0"), ["cross_function"]);
    }

    #[tokio::test]
    async fn scan_stamps_the_scan_provenance() {
        // The metadata names the binary, carries a finish time, and the
        // duration is stamped from the wall clock — a canned scan is
        // instant, so it reads as zero seconds rather than never set.
        let result = scan(program()).await;
        assert_eq!(result.metadata.binary, "eqmain.dll");
        assert!(result.metadata.scanned_at > 0);
        assert!(result.metadata.duration_secs < 60);
    }

    #[tokio::test]
    async fn an_empty_program_yields_an_empty_result() {
        let result = scan(FakeProgram::empty()).await;
        assert!(result.is_empty());
        assert_eq!(result.metadata.binary, "eqmain.dll");
        assert!(result.metadata.scanned_at > 0);
    }
}
