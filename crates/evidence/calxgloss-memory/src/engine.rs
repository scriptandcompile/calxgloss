//! Memory lifecycle scan orchestration.
//!
//! [`MemoryEngine`] runs the three detectors — allocation/release pair
//! tracking, handle lifetime detection, and reference-counting
//! detection — over every function of one loaded program and
//! combines their findings into a single [`MemoryResult`] with its scan
//! provenance.
//!
//! The detectors are pure text analysis over one decompiled body. So the
//! memory scan fetches each function's pseudo-C exactly once, and all
//! three detectors read that one copy instead of each pulling its own.
//! The scan is then one sequential pass over the function listing.
//! Unlike typeinfer's competing families, there is nothing to resolve
//! between the detectors — they read disjoint body shapes. Keeping the
//! pass sequential keeps the persisted finding list in a stable order
//! that diffs cleanly.

use crate::allocator::AllocatorTracker;
use crate::cross_function::CrossFunctionAnalyzer;
use crate::error::Result;
use crate::handle::HandleDetector;
use crate::refcount::ReferenceCountDetector;
use crate::types::{MemoryFinding, MemoryResult, ScanMetadata};
use calxgloss_decomp::DecompiledFunction;
use calxgloss_kuna::KunaSource;
use calxgloss_types::{CoverageStatus, FacetCoverage, ScanCoverage};
use std::time::Instant;
use tracing::{info, warn};

/// The decompiler reads a memory lifecycle scan performs.
///
/// This is the shared trait from the decompiler seam crate, re-exported
/// here so the memory scan's generic bounds can name it directly.
/// [`KunaSource`] implements it over the in-process analysis engine, and
/// tests implement it over canned bodies so the orchestration runs
/// without a server. The futures are `Send` so a scan can be driven from
/// an orchestrating task.
pub use calxgloss_decomp::ScanSource;

/// How many unreached functions one coverage limitation line names by
/// name before counting the rest instead — bounded prose beside the
/// counts, not a dump (the P19-5 admitted-semantics track).
const MAX_NAMED_UNREACHED: usize = 5;

/// The facets a memory lifecycle scan declares, in order. The record
/// must name each one exactly once. The memory scan reads one facet:
/// the decompiled bodies all three detectors share.
pub const DECLARED_FACETS: &[&str] = &["function-bodies"];

/// The coverage record every memory lifecycle scan stamps about itself
/// (issue #349), beside the provenance and the timing.
///
/// The memory scan has one facet: `function-bodies`, the decompiled
/// bodies all three detectors read. The scan always reads the function
/// listing end to end: a failed listing aborts the scan, and more than
/// half the functions failing to decompile trips the skip-rate breaker
/// (see above). So what a finished scan could not read is exactly the
/// bodies it skipped along the way: a nameless listing entry, or a
/// decompile that failed. The cross-function pass reads only bodies
/// this walk already decompiled, so it adds no coverage border of its
/// own.
///
/// With nothing skipped, the facet is `complete`, and that is the
/// admission's point: a function no finding mentions was examined and
/// clean, never silently unchecked. With any skip, the facet is
/// `partial` and the limitation line names the unreached bodies (the
/// line names at most [`MAX_NAMED_UNREACHED`]), so silence and
/// never-reaching are distinguishable in the filed record itself. The
/// whole picture mirrors the single facet — this evidence engine
/// examines nothing else.
fn coverage_stamp(unreached: &[String], nameless: usize) -> ScanCoverage {
    let total = unreached.len() + nameless;
    if total == 0 {
        return ScanCoverage {
            status: CoverageStatus::Complete,
            facets: vec![FacetCoverage {
                id: "function-bodies".to_string(),
                status: CoverageStatus::Complete,
                limitation: None,
            }],
        };
    }
    let mut names = unreached
        .iter()
        .take(MAX_NAMED_UNREACHED)
        .cloned()
        .collect::<Vec<_>>();
    let hidden = unreached.len().saturating_sub(names.len()) + nameless;
    if hidden > 0 {
        names.push(format!("+{hidden} more"));
    }
    let body = if total == 1 { "body" } else { "bodies" };
    ScanCoverage {
        status: CoverageStatus::Partial,
        facets: vec![FacetCoverage {
            id: "function-bodies".to_string(),
            status: CoverageStatus::Partial,
            limitation: Some(format!(
                "{total} function {body} unreached: {}",
                names.join(", ")
            )),
        }],
    }
}

/// Orchestrates the three detectors into one [`MemoryResult`].
///
/// This type is generic over its [`ScanSource`], so tests can run the
/// whole orchestration over canned bodies. [`new`](Self::new) builds one
/// over a loaded [`KunaSource`]. Each detector carries no state and
/// starts configured with its standard name sets.
/// [`with_allocator`](Self::with_allocator), [`with_handles`](Self::with_handles),
/// and [`with_refcounts`](Self::with_refcounts) swap a detector's sets
/// whole, so one instance of each serves the whole scan.
#[derive(Debug, Clone)]
pub struct MemoryEngine<S = KunaSource> {
    source: S,
    allocator: AllocatorTracker,
    handles: HandleDetector,
    refcounts: ReferenceCountDetector,
    cross_function: CrossFunctionAnalyzer,
}

impl MemoryEngine<KunaSource> {
    /// A memory scan over a loaded Kuna program, using the three
    /// detectors' standard name sets.
    pub fn new(source: &KunaSource) -> MemoryEngine<KunaSource> {
        MemoryEngine {
            source: source.clone(),
            allocator: AllocatorTracker::with_default_names(),
            handles: HandleDetector::with_default_names(),
            refcounts: ReferenceCountDetector::with_default_names(),
            cross_function: CrossFunctionAnalyzer::new(),
        }
    }
}

impl<S> MemoryEngine<S> {
    /// A memory scan whose decompiles come from `source`, using the
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
    /// follow the function listing: function by function, and within one
    /// function the allocation pairs, then the handle lifetimes, then
    /// the reference counts. Two scans of the same program therefore
    /// diff cleanly.
    ///
    /// The scan skips a function whose body the decompiler cannot
    /// produce (a thunk, a bad entry point) and logs a warning. Only a
    /// failure of the listing itself — the server being down — aborts
    /// the scan, since then nothing was scanned.
    /// But when more than half the program's functions fail to
    /// decompile, the skip-rate breaker aborts the scan too. A high
    /// skip rate is the signature of a seam letting the scan answer
    /// about the wrong program. The breaker is a fuse: it aborts the
    /// scan rather than persisting a record that looks clean but is not
    /// (issue #71).
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
        // P19-5: track which bodies the scan could NOT read: named
        // where a name exists, counted where the listing entry is
        // nameless. The coverage record below persists this, so an
        // unmentioned function means examined-and-clean, never
        // silently unchecked.
        let mut unreached: Vec<String> = Vec::new();
        let mut nameless = 0usize;
        for function in &functions {
            if function.name.is_empty() {
                // With an empty name, the by-name lookup could land on
                // some other function's body. Nothing can be said about
                // the entry, so the scan passes it by without recording.
                warn!(
                    address = format_args!("{:#x}", function.address),
                    "Skipping function with no name"
                );
                skipped += 1;
                nameless += 1;
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
                    unreached.push(function.name.clone());
                    // Skip-rate breaker: more than half the program's
                    // functions have now failed to decompile, so the
                    // scan's answer cannot be trusted. A high skip
                    // rate is the signature of a seam letting the scan
                    // answer about the wrong program. The breaker is a
                    // fuse: it aborts the scan rather than persisting
                    // a record that looks clean but is not, so abort
                    // with the counts instead of skipping on.
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
        // over the bodies the scan already decompiled, so it makes no
        // extra reads from the analysis engine. Its findings append in
        // listing order, so the persisted list stays stable and diffs
        // cleanly.
        findings.extend(
            self.cross_function
                .analyze(&bodies, &self.allocator, &self.handles),
        );

        let mut metadata = ScanMetadata::new(binary);
        // The source names the analysis engine and pin under `kuna` (issue #208).
        metadata.engine = self.source.engine_provenance();
        // The scan records its own coverage inside its own scan, where
        // the truth lives — not the registry row and not the CLI (issue
        // #349). Every listed body was read by all three detectors
        // unless the scan says which ones it could not reach. The batch
        // scan phase and the CLI's force-rescan file the same admission
        // through the same single definition.
        metadata.coverage = Some(coverage_stamp(&unreached, nameless));
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
    use calxgloss_decomp::{
        DataItem, DataTypeEntry, DecompiledFunction, EngineError, EnumDefinition, FunctionSummary,
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

    /// State shared by every clone of a [`FakeProgram`], so a test can
    /// read what the scan did even after the scan has finished.
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
                return Err(EngineError::Reported {
                    message: "the engine is busy".into(),
                });
            }
            Ok(self.listing.clone())
        }

        async fn decompile(&self, name: &str) -> Result<DecompiledFunction> {
            self.stats.decompiles.lock().unwrap().push(name.to_string());
            if self.fail_decompiles.iter().any(|f| f == name) {
                return Err(EngineError::NotFound {
                    kind: "function",
                    query: name.to_string(),
                });
            }
            self.bodies
                .get(name)
                .cloned()
                .ok_or_else(|| EngineError::NotFound {
                    kind: "function",
                    query: name.to_string(),
                })
        }

        // The rest of the shared trait's reads: this scan never makes
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
            Err(EngineError::NotFound {
                kind: "struct",
                query: name.to_string(),
            })
        }

        async fn enum_values(&self, name: &str) -> Result<EnumDefinition> {
            Err(EngineError::NotFound {
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
        // Story 9 (#203): the fake source names itself, so the tests can pin
        // that scan() stamps the source's provenance onto the record (#208).
        fn engine_provenance(&self) -> Option<calxgloss_types::EngineProvenance> {
            Some(calxgloss_types::EngineProvenance {
                name: "fake-engine".into(),
                version: Some("9.9".into()),
                fingerprint: Some("0123456".into()),
            })
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
        // group their findings by function in listing order. Within one
        // function it must run allocation, then handle, then reference
        // count. The two functions' findings must never interleave.
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
        // The decompiler cannot produce a body for every function. One
        // bad entry point must not stop the scan of the whole program.
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
        // The 2026-10-08 incident: the seam served the function listing
        // from one program and the decompiles from another, so every
        // decompile failed. A high skip rate like that is the signature
        // of a seam letting the scan answer about the wrong program,
        // and this scan nearly persisted a record that looked clean but
        // was not, under the target's name. The skip-rate breaker now
        // aborts with the counts instead, so nothing is persisted.
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
        // The skip-rate breaker is a fuse, not a post-mortem: it aborts
        // the scan rather than persisting a record that looks clean but
        // is not. Once most of the listing has failed, the remaining
        // decompiles are wasted round-trips against the wrong program.
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
        // An empty name could send the by-name lookup into an arbitrary
        // function's body, so the scan skips the entry without a
        // decompile.
        let mut program = program();
        program.listing.insert(0, summary(""));
        let result = scan(program.clone()).await;

        assert_eq!(program.decompiled(), vec!["FUN_18003ab00", "FUN_18003e750"]);
        assert!(!result.is_empty());
    }

    #[tokio::test]
    async fn a_failing_listing_fails_the_whole_run() {
        // With the listing gone, nothing was scanned. The scan aborts
        // rather than returning a result that could pass for a scan
        // that legitimately found nothing.
        let mut program = program();
        program.fail_listing = true;
        let result = MemoryEngine::with_source(program).scan("eqmain.dll").await;
        assert!(matches!(
            result,
            Err(crate::MemoryError::Engine(EngineError::Reported { .. }))
        ));
    }

    #[tokio::test]
    async fn custom_name_sets_reach_every_detector() {
        // Swapping a detector's name sets whole reaches the scan: the
        // configured custom spellings pair in all three families, and
        // the standard names the swaps replaced pair nothing.
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
        // The block escapes into a callee that keeps it. No pair forms,
        // but the escape itself is an ownership transfer, which a Rust
        // author would express as `Box`.
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
        // What this crate exists to find: an allocation that is never
        // freed, never handed on, and never returned — a leak.
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
    async fn a_scan_upgrades_a_pair_whose_callee_keeps_the_block_to_rc() {
        // End-to-end through the seam: the callee frees the block and
        // also stores the parameter into a global. So the allocating
        // function's reading is shared ownership, not a move.
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
                "  global_ptr = param_1;\n  free(param_1);\n",
            ),
        );
        let result = scan(program).await;
        let findings: Vec<&MemoryFinding> = result.for_function("FUN_18003ab00").collect();
        assert_eq!(findings.len(), 1);
        let MemoryFinding::CrossFunction(record) = findings[0] else {
            unreachable!("the releasing callee pairs");
        };
        assert_eq!(record.suggestion, "Rc<T>");
        assert_eq!(record.confidence.value(), 70);
        assert!(record.evidence.contains("global_ptr = param_1;"));
    }

    #[tokio::test]
    async fn cross_function_findings_append_after_the_per_function_findings() {
        // One function carries an in-body pair and an open allocation
        // handed to a releasing callee. The per-function walk produces
        // the pairing finding, and the cross-function finding is
        // appended after it.
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
        // A hands an open allocation to B, but B never decompiled. The
        // pass reads only the bodies the scan holds, so the missing
        // half supports no claim.
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
        // The pass reads the tracker the scan was configured with,
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
        // The metadata names the binary, carries a finish time, and
        // stamps the duration from the wall clock. A canned scan is
        // instant, so the duration reads as zero seconds rather than
        // never set.
        let result = scan(program()).await;
        assert_eq!(result.metadata.binary, "eqmain.dll");
        assert!(result.metadata.scanned_at > 0);
        assert!(result.metadata.duration_secs < 60);
        // Story 9 (#203): the record also names the analysis engine
        // that produced it — scan() copies the source's provenance
        // through (#208).
        let engine = result
            .metadata
            .engine
            .expect("scan record names its engine");
        assert_eq!(engine.name, "fake-engine");
        assert_eq!(engine.version.as_deref(), Some("9.9"));
        assert_eq!(engine.fingerprint.as_deref(), Some("0123456"));
    }

    #[tokio::test]
    async fn an_empty_program_yields_an_empty_result() {
        let result = scan(FakeProgram::empty()).await;
        assert!(result.is_empty());
        assert_eq!(result.metadata.binary, "eqmain.dll");
        assert!(result.metadata.scanned_at > 0);
    }

    // ============================================================
    // Admitted scan coverage (issue #349)
    // ============================================================

    /// The data-level verdict from the roster pin. An empty list means
    /// the record names every declared facet exactly once. Each fault
    /// describes one drift from that rule.
    fn roster_faults(coverage: &ScanCoverage) -> Vec<String> {
        coverage.roster_faults(DECLARED_FACETS)
    }

    #[tokio::test]
    async fn a_fresh_scan_stamps_complete_bodies_coverage_and_a_clean_roster() {
        // This coverage stamp comes from the scan itself, not the
        // registry row and not the CLI: the batch scan phase and the
        // CLI's force-rescan file the same admission through this one
        // definition. Every body was read here, so the record is
        // complete and admits nothing.
        let result = scan(program()).await;
        let coverage = result
            .metadata
            .coverage
            .expect("a fresh memory scan states its coverage");
        assert_eq!(coverage.status, CoverageStatus::Complete);
        assert!(
            roster_faults(&coverage).is_empty(),
            "a fresh document must name every declared facet exactly once"
        );
        let bodies = coverage
            .facets
            .iter()
            .find(|facet| facet.id == "function-bodies")
            .expect("function-bodies is named");
        assert_eq!(bodies.status, CoverageStatus::Complete);
        assert_eq!(
            bodies.limitation, None,
            "a scan that read every body admits nothing — and silence now \
             means examined-and-clean, not unchecked"
        );
    }

    #[tokio::test]
    async fn a_decompiled_failure_is_admitted_by_name_on_the_coverage_record() {
        // The whole point of the admission: the record names a body
        // the scan could not read. So it is never mistaken for an
        // examined-and-clean function the findings simply left
        // unmentioned.
        let mut program = program();
        program.fail_decompiles = vec!["FUN_18003e750".into()];
        let result = scan(program).await;
        let coverage = result
            .metadata
            .coverage
            .expect("a partial memory scan states its coverage too");
        assert_eq!(
            coverage.status,
            CoverageStatus::Partial,
            "the whole picture mirrors the one facet it examined"
        );
        assert!(
            roster_faults(&coverage).is_empty(),
            "a partial scan still names every declared facet exactly once"
        );
        let bodies = coverage
            .facets
            .iter()
            .find(|facet| facet.id == "function-bodies")
            .expect("function-bodies is named");
        assert_eq!(bodies.status, CoverageStatus::Partial);
        assert_eq!(
            bodies.limitation.as_deref(),
            Some("1 function body unreached: FUN_18003e750"),
            "the unreached body is named, and only the unreached body"
        );
    }

    #[tokio::test]
    async fn the_coverage_line_is_capped_at_five_names_and_counts_the_nameless() {
        // Bounded prose beside the counts: of six decompile failures,
        // five are named inline and the sixth is counted. A nameless
        // listing entry counts toward the total without using one of
        // the five name slots.
        let names: Vec<String> = (0..12).map(|i| format!("FUN_body_{i:04}")).collect();
        let mut program = FakeProgram::empty();
        for (index, name) in names.iter().enumerate() {
            program.listing.push(FunctionSummary {
                name: name.clone(),
                address: 0x1800_0000 + index as u64,
            });
            if index >= 6 {
                program.bodies.insert(
                    name.clone(),
                    function(name, "undefined FUN_body_x(void)", "  return;\n"),
                );
            }
        }
        program.fail_decompiles = names[..6].to_vec();
        program.listing.push(summary(""));
        let result = scan(program).await;
        let bodies = result
            .metadata
            .coverage
            .expect("a partial memory scan states its coverage")
            .facets
            .into_iter()
            .find(|facet| facet.id == "function-bodies")
            .expect("function-bodies is named");
        assert_eq!(bodies.status, CoverageStatus::Partial);
        assert_eq!(
            bodies.limitation.as_deref(),
            Some(
                "7 function bodies unreached: FUN_body_0000, FUN_body_0001, \
                 FUN_body_0002, FUN_body_0003, FUN_body_0004, +2 more"
            ),
            "six named failures plus one nameless entry: five names, the \
             rest counted, the count covering both"
        );
    }

    #[test]
    fn the_roster_pin_fails_when_a_declared_facet_goes_missing() {
        let mut coverage = coverage_stamp(&[], 0);
        coverage
            .facets
            .retain(|facet| facet.id != "function-bodies");
        assert_eq!(
            roster_faults(&coverage),
            ["declared facet `function-bodies` is missing from the record"],
            "an engine quietly dropping its one facet fails loudly"
        );
    }

    #[test]
    fn the_roster_pin_fails_when_a_facet_is_doubled() {
        let mut coverage = coverage_stamp(&["FUN_18003e750".to_string()], 0);
        coverage.facets.push(coverage.facets[0].clone());
        assert_eq!(
            roster_faults(&coverage),
            ["declared facet `function-bodies` appears 2 times in the record"],
            "a facet crowded into two entries fails loudly"
        );
    }

    #[test]
    fn the_roster_pin_fails_when_coverage_names_an_orphan_facet() {
        let mut coverage = coverage_stamp(&[], 0);
        coverage.facets.push(FacetCoverage {
            id: "global-state".to_string(),
            status: CoverageStatus::Unexamined,
            limitation: None,
        });
        assert_eq!(
            roster_faults(&coverage),
            ["record names `global-state`, a facet the engine never declared"],
            "an id invented outside the declared roster fails loudly"
        );
    }
}
