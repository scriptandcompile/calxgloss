//! Concurrency scan orchestration.
//!
//! [`SyncEngine`] runs the per-body detectors — mutex/lock pair
//! tracking, atomic operation detection, thread spawn detection,
//! thread-local storage detection, async-runtime shape detection, and
//! futex-based synchronization detection — over every function of one
//! open program, then the cross-function pass over the bodies
//! it kept, and assembles their findings into a single [`SyncResult`]
//! with its scan provenance.
//!
//! The detectors are pure text analysis over one decompiled body, so
//! the engine fetches each function's pseudo-C exactly once and reads
//! it with all of them, rather than having each detector pull its own
//! copy; the cross-function pass reads those same kept bodies, so the
//! scan stays at one decompile per function. The scan is then one
//! sequential pass over the function listing: unlike typeinfer's
//! competing families there is nothing to resolve between the
//! detectors — they read disjoint body shapes — and keeping the pass
//! sequential keeps the persisted finding list in a stable, diffable
//! order.

use crate::async_runtime::AsyncDetector;
use crate::atomic::AtomicDetector;
use crate::cross_function::CrossFunctionAnalyzer;
use crate::error::Result;
use crate::futex::FutexDetector;
use crate::mutex::MutexDetector;
use crate::threading::ThreadingDetector;
use crate::tls::TlsDetector;
use crate::types::{ScanMetadata, SyncFinding, SyncResult};
use calxgloss_decomp::DecompiledFunction;
use calxgloss_kuna::KunaSource;
use calxgloss_types::{CoverageStatus, FacetCoverage, ScanCoverage};
use std::time::Instant;
use tracing::{info, warn};

/// The decompiler a concurrency scan reads.
///
/// The shared trait from the decompiler seam crate, re-exported here
/// so the engine's generic shape names it where it always has;
/// [`KunaSource`] implements it over the in-process engine, and tests
/// implement it over canned bodies so the orchestration runs without a
/// server. The futures are `Send` so a scan can be driven from an
/// orchestrating task.
pub use calxgloss_decomp::ScanSource;

/// How many unreached functions one coverage limitation line names inline
/// before folding the remainder into a count — bounded prose beside the
/// counts, not a dump (the P19-5 admitted-semantics track).
const MAX_NAMED_UNREACHED: usize = 5;

/// The coverage record every concurrency scan stamps about itself (issue
/// #349), beside the provenance and the timing.
///
/// The concurrency scan has one facet: `function-bodies`, the decompiled
/// bodies every per-body detector reads. The function listing is always
/// read end to end — a failed listing aborts the run, and more than half
/// failing to decompile trips the skip-rate breaker above — so what a
/// finished scan can not have read is exactly the bodies it skipped
/// along the way: a nameless listing entry, or a decompile that failed.
/// The cross-function pass reads only bodies this walk already kept, so
/// it adds no coverage border of its own. With nothing skipped, the facet
/// is `complete`, and that is the admission's point: a function no
/// finding mentions was examined and clean, never silently unchecked.
/// With any, the facet is `partial` and the limitation line names the
/// unreached bodies (bounded at [`MAX_NAMED_UNREACHED`]), so silence and
/// never-reaching are distinguishable in the filed record itself. The
/// whole picture mirrors the single facet — there is nothing else this
/// engine examines.
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
            limitation: Some(format!("{total} function {body} unreached: {}", names.join(", "))),
        }],
    }
}

/// Orchestrates the per-body detectors and the cross-function pass
/// into one [`SyncResult`].
///
/// The engine is generic over its [`ScanSource`], so tests can run the
/// whole orchestration over canned bodies; [`new`](Self::new) builds
/// one over a loaded [`KunaSource`]. Each detector carries no state
/// and starts configured with its standard name sets —
/// [`with_mutex`](Self::with_mutex), [`with_atomics`](Self::with_atomics),
/// [`with_threads`](Self::with_threads), and [`with_tls`](Self::with_tls)
/// swap a detector's sets whole — so one instance of each serves the
/// whole scan. The cross-function pass has no name set of its own: it
/// reads the mutex detector's configured acquire names, so custom
/// spellings reach it through [`with_mutex`](Self::with_mutex).
#[derive(Debug, Clone)]
pub struct SyncEngine<S = KunaSource> {
    source: S,
    mutex: MutexDetector,
    atomics: AtomicDetector,
    threads: ThreadingDetector,
    tls: TlsDetector,
    async_runtime: AsyncDetector,
    futex: FutexDetector,
    cross_function: CrossFunctionAnalyzer,
}

impl SyncEngine<KunaSource> {
    /// An engine over a loaded Kuna program, scanning with the four
    /// detectors' standard name sets.
    pub fn new(source: &KunaSource) -> SyncEngine<KunaSource> {
        SyncEngine {
            source: source.clone(),
            mutex: MutexDetector::with_default_names(),
            atomics: AtomicDetector::with_default_names(),
            threads: ThreadingDetector::with_default_names(),
            tls: TlsDetector::with_default_names(),
            async_runtime: AsyncDetector::with_default_names(),
            futex: FutexDetector::with_default_names(),
            cross_function: CrossFunctionAnalyzer::new(),
        }
    }
}

impl<S> SyncEngine<S> {
    /// An engine whose decompiles come from `source`, scanning with
    /// the four detectors' standard name sets.
    pub fn with_source(source: S) -> Self {
        SyncEngine {
            source,
            mutex: MutexDetector::with_default_names(),
            atomics: AtomicDetector::with_default_names(),
            threads: ThreadingDetector::with_default_names(),
            tls: TlsDetector::with_default_names(),
            async_runtime: AsyncDetector::with_default_names(),
            futex: FutexDetector::with_default_names(),
            cross_function: CrossFunctionAnalyzer::new(),
        }
    }

    /// Pair lock acquisitions against `detector`'s name sets instead
    /// of the standard ones.
    pub fn with_mutex(mut self, detector: MutexDetector) -> Self {
        self.mutex = detector;
        self
    }

    /// Read atomic calls against `detector`'s name set instead of the
    /// standard one.
    pub fn with_atomics(mut self, detector: AtomicDetector) -> Self {
        self.atomics = detector;
        self
    }

    /// Read thread spawns against `detector`'s name sets instead of
    /// the standard ones.
    pub fn with_threads(mut self, detector: ThreadingDetector) -> Self {
        self.threads = detector;
        self
    }

    /// Read thread-local keys against `detector`'s name sets instead
    /// of the standard ones.
    pub fn with_tls(mut self, detector: TlsDetector) -> Self {
        self.tls = detector;
        self
    }

    /// Read async runtime loops against `detector`'s name sets instead
    /// of the standard ones.
    pub fn with_async(mut self, detector: AsyncDetector) -> Self {
        self.async_runtime = detector;
        self
    }

    /// Read async runtime loops against `detector`'s name sets instead
    /// of the standard ones.
    pub fn with_async_runtime(mut self, detector: AsyncDetector) -> Self {
        self.async_runtime = detector;
        self
    }

    /// Read futex synchronization against `detector`'s name sets instead
    /// of the standard ones.
    pub fn with_futex(mut self, detector: FutexDetector) -> Self {
        self.futex = detector;
        self
    }

    /// Read futex synchronization against `detector`'s name sets instead
    /// of the standard ones.
    pub fn with_futexes(mut self, detector: FutexDetector) -> Self {
        self.futex = detector;
        self
    }

    /// Read futex synchronization against `detector`'s name sets instead
    /// of the standard ones.
    pub fn with_futex_detector(mut self, detector: FutexDetector) -> Self {
        self.futex = detector;
        self
    }

    pub fn with_futexes_detector(mut self, detector: FutexDetector) -> Self {
        self.futex = detector;
        self
    }

    pub fn with_futex_runtime(mut self, detector: FutexDetector) -> Self {
        self.futex = detector;
        self
    }

    pub fn with_futex_detection(mut self, detector: FutexDetector) -> Self {
        self.futex = detector;
        self
    }

    /// Detect concurrency constructs across `binary`, decompiling
    /// each function exactly once and reading it with all the per-body
    /// detectors.
    ///
    /// `binary` names the program the scan reads (e.g. `eqmain.dll`)
    /// and becomes the key a persisted result is filed under. The
    /// findings follow the function listing — function by function,
    /// and within one function the mutex pairings, then the atomic
    /// calls, then the thread spawns, then the TLS records, then the
    /// async-runtime shapes, then the futex calls — and after every
    /// function the cross-function pass adds its findings, in listing
    /// order, over the bodies this walk already decompiled: no extra
    /// engine reads. So two scans of the same program diff
    /// cleanly.
    ///
    /// A function whose body the decompiler cannot produce (a thunk, a bad
    /// entry point) is skipped with a warning; only a failure of the
    /// listing itself — the server being down — aborts the run, since
    /// then nothing was scanned.
    /// But when more than half the listing fails to decompile, the
    /// skip-rate breaker aborts the run too: that is the signature of
    /// the bridge answering from the wrong program, and skipping on
    /// would persist a phantom-clean record (issue #71).
    /// The detectors read disjoint
    /// body shapes, so a function can carry findings of every kind at
    /// once and nothing is resolved between them.
    pub async fn scan(&self, binary: impl Into<String>) -> Result<SyncResult>
    where
        S: ScanSource,
    {
        let started = Instant::now();
        let functions = self.source.functions().await?;

        let mut findings = Vec::new();
        let mut bodies: Vec<DecompiledFunction> = Vec::new();
        let mut skipped = 0usize;
        let mut decompile_failures = 0usize;
        // P19-5: which bodies the scan could NOT read, named where a name
        // exists, counted where the listing entry is nameless — the
        // coverage record below states it, so an unmentioned function
        // means examined-and-clean, never silently unchecked.
        let mut unreached: Vec<String> = Vec::new();
        let mut nameless = 0usize;
        for function in &functions {
            if function.name.is_empty() {
                // A nameless listing entry would send the name lookup
                // wandering into some other function's body; nothing
                // can be said about it, so it passes unrecorded.
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
                    // Skip-rate breaker: once most of the listing has
                    // failed to decompile, the scan is reading a
                    // program the engine cannot analyze, and an
                    // empty result would persist as a phantom-clean
                    // record. Abort with the counts instead of
                    // skipping on.
                    if decompile_failures * 2 > functions.len() {
                        return Err(crate::SyncError::DecompileBreaker {
                            failed: decompile_failures,
                            total: functions.len(),
                        });
                    }
                    continue;
                }
            };

            findings.extend(
                self.mutex
                    .detect_pairs(&decompiled)
                    .into_iter()
                    .map(SyncFinding::Mutex),
            );
            findings.extend(
                self.atomics
                    .detect(&decompiled)
                    .into_iter()
                    .map(SyncFinding::Atomic),
            );
            findings.extend(
                self.threads
                    .detect(&decompiled)
                    .into_iter()
                    .map(SyncFinding::Thread),
            );
            findings.extend(
                self.tls
                    .detect(&decompiled)
                    .into_iter()
                    .map(SyncFinding::Tls),
            );
            findings.extend(
                self.async_runtime
                    .detect(&decompiled)
                    .into_iter()
                    .map(SyncFinding::AsyncRuntime),
            );
            findings.extend(
                self.futex
                    .detect(&decompiled)
                    .into_iter()
                    .map(SyncFinding::Futex),
            );
            bodies.push(decompiled);
        }

        // The cross-function pass runs after the per-function walk,
        // over the bodies the scan already decompiled — no extra
        // engine reads — and its findings append in listing
        // order, after the per-function findings.
        findings.extend(self.cross_function.analyze(&bodies, &self.mutex));

        let mut metadata = ScanMetadata::new(binary);
        // The source names its engine and pin under `kuna` (issue #208).
        metadata.engine = self.source.engine_provenance();
        // The engine admits its own coverage inside its own scan, where
        // the truth lives — not the registry row and not the CLI (issue
        // #349): every listed body was read by every per-body detector
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
            "Detected concurrency constructs"
        );
        Ok(SyncResult { metadata, findings })
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atomic::AtomicSignature;
    use crate::mutex::MutexSignature;
    use crate::threading::{SpawnBinding, ThreadSpawnSignature};
    use crate::tls::{KeyBinding, TlsKeySignature};
    use crate::types::SyncType;
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
    /// read what the scan did after the engine has consumed its
    /// source.
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

    /// A body carrying an `EnterCriticalSection`/`LeaveCriticalSection`
    /// pair, an `InterlockedIncrement` call, and a `CreateThread`/
    /// `WaitForSingleObject` pair — one finding family per detector —
    /// all in one function.
    const EVERY_SHAPE_BODY: &str = "\
  EnterCriticalSection(&local_20);
  *(int *)local_18 = 5;
  LeaveCriticalSection(&local_20);
  uVar1 = InterlockedIncrement(&local_28);
  hThread = CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,worker,0x0,0,&local_14);
  WaitForSingleObject(hThread,0xffffffff);";

    /// The canned program: one function whose body carries every
    /// shape, and one plain function that finds nothing.
    fn program() -> FakeProgram {
        let mut program = FakeProgram::empty();
        program.listing = vec![summary("FUN_18003ab00"), summary("FUN_18003e750")];
        program.bodies.insert(
            "FUN_18003ab00".into(),
            function(
                "FUN_18003ab00",
                "undefined FUN_18003ab00(void)",
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

    async fn scan(program: FakeProgram) -> SyncResult {
        SyncEngine::with_source(program)
            .scan("eqmain.dll")
            .await
            .expect("scan")
    }

    fn kinds(result: &SyncResult, function: &str) -> Vec<&'static str> {
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

        let findings: Vec<&SyncFinding> = result.for_function("FUN_18003ab00").collect();
        assert_eq!(findings.len(), 3);

        let SyncFinding::Mutex(hint) = findings[0] else {
            unreachable!("the lock pair reads as a mutex finding");
        };
        assert_eq!(hint.sync_type, SyncType::StdMutex);
        assert_eq!(
            hint.evidence,
            "EnterCriticalSection(&local_20); LeaveCriticalSection(&local_20);"
        );

        let SyncFinding::Atomic(record) = findings[1] else {
            unreachable!("the interlocked call reads as an atomic finding");
        };
        assert_eq!(record.operation, "InterlockedIncrement");
        assert_eq!(record.suggestion, "std::sync::atomic::AtomicU32");

        let SyncFinding::Thread(record) = findings[2] else {
            unreachable!("the spawn and wait read as a thread finding");
        };
        assert_eq!(record.spawn, "CreateThread");
        assert_eq!(record.join.as_deref(), Some("WaitForSingleObject"));

        assert!(result.for_function("FUN_18003e750").next().is_none());
    }

    #[tokio::test]
    async fn scan_keeps_findings_in_scan_order() {
        // Both functions carry every shape, so the persisted list must
        // group their findings by function in listing order — and
        // within one function run mutex, atomic, then thread — never
        // interleaved.
        let mut program = program();
        program.listing = vec![summary("FUN_18003e750"), summary("FUN_18003ab00")];
        program.bodies.insert(
            "FUN_18003e750".into(),
            function(
                "FUN_18003e750",
                "undefined FUN_18003e750(void)",
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
                ("FUN_18003e750", "mutex"),
                ("FUN_18003e750", "atomic"),
                ("FUN_18003e750", "thread"),
                ("FUN_18003ab00", "mutex"),
                ("FUN_18003ab00", "atomic"),
                ("FUN_18003ab00", "thread"),
            ]
        );
    }

    #[tokio::test]
    async fn tls_findings_slot_after_the_thread_spawns() {
        // A body carrying every shape: the TLS record lands after the
        // thread spawn, so the within-function order — mutex, atomic,
        // thread, tls — stays fixed and diffable.
        let mut program = FakeProgram::empty();
        program.listing = vec![summary("FUN_1800412a0")];
        program.bodies.insert(
            "FUN_1800412a0".into(),
            function(
                "FUN_1800412a0",
                "undefined FUN_1800412a0(void)",
                "\
  EnterCriticalSection(&local_20);
  LeaveCriticalSection(&local_20);
  uVar1 = InterlockedIncrement(&local_28);
  hThread = CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,worker,0x0,0,&local_14);
  WaitForSingleObject(hThread,0xffffffff);
  local_4 = TlsAlloc();
  pvVar2 = TlsGetValue(local_4);",
            ),
        );
        let result = scan(program).await;

        assert_eq!(
            kinds(&result, "FUN_1800412a0"),
            ["mutex", "atomic", "thread", "tls"]
        );
        let findings: Vec<&SyncFinding> = result.for_function("FUN_1800412a0").collect();
        let SyncFinding::Tls(record) = findings[3] else {
            unreachable!("the key creation and access read as a tls finding");
        };
        assert_eq!(record.creation.as_deref(), Some("TlsAlloc"));
        assert_eq!(record.access, "TlsGetValue");
        assert_eq!(record.suggestion, "thread_local!");
        assert_eq!(record.confidence, 70);
    }

    #[tokio::test]
    async fn two_functions_that_lock_the_same_objects_in_opposite_orders_land_a_lock_order_finding()
    {
        // The classic deadlock shape, invisible to either body read
        // on its own: one function takes `local_20` before `local_40`,
        // the other the other way round.
        let mut program = FakeProgram::empty();
        program.listing = vec![summary("FUN_18003ab00"), summary("FUN_18003e750")];
        program.bodies.insert(
            "FUN_18003ab00".into(),
            function(
                "FUN_18003ab00",
                "undefined FUN_18003ab00(void)",
                "\
  EnterCriticalSection(&local_20);
  EnterCriticalSection(&local_40);
  LeaveCriticalSection(&local_40);
  LeaveCriticalSection(&local_20);",
            ),
        );
        program.bodies.insert(
            "FUN_18003e750".into(),
            function(
                "FUN_18003e750",
                "undefined FUN_18003e750(void)",
                "\
  EnterCriticalSection(&local_40);
  EnterCriticalSection(&local_20);
  LeaveCriticalSection(&local_20);
  LeaveCriticalSection(&local_40);",
            ),
        );
        let result = scan(program).await;

        let finding = result
            .findings
            .iter()
            .find(|finding| finding.kind() == "lock_order")
            .expect("the reversed orders read as a lock-order finding");
        let SyncFinding::LockOrder(record) = finding else {
            unreachable!("the reversed orders read as a lock-order finding");
        };
        assert_eq!(record.function, "FUN_18003ab00");
        assert_eq!(record.partner, "FUN_18003e750");
        assert_eq!(record.first_lock, "local_20");
        assert_eq!(record.second_lock, "local_40");
        assert_eq!(
            record.suggestion,
            "pick one consistent lock acquisition order"
        );
        assert_eq!(record.confidence, 70);
        // The evidence carries both functions' acquire orders.
        assert_eq!(
            record.evidence,
            "FUN_18003ab00: local_20 -> local_40; \
             FUN_18003e750: local_40 -> local_20"
        );
    }

    #[tokio::test]
    async fn functions_that_lock_shared_objects_in_a_consistent_order_claim_nothing() {
        // Clean code stays clean: both functions take `local_20`
        // before `local_40`, so there is no order to disagree about.
        let mut program = FakeProgram::empty();
        program.listing = vec![summary("FUN_18003ab00"), summary("FUN_18003e750")];
        program.bodies.insert(
            "FUN_18003ab00".into(),
            function(
                "FUN_18003ab00",
                "undefined FUN_18003ab00(void)",
                "\
  EnterCriticalSection(&local_20);
  EnterCriticalSection(&local_40);
  LeaveCriticalSection(&local_40);
  LeaveCriticalSection(&local_20);",
            ),
        );
        program.bodies.insert(
            "FUN_18003e750".into(),
            function(
                "FUN_18003e750",
                "undefined FUN_18003e750(void)",
                "\
  EnterCriticalSection(&local_20);
  EnterCriticalSection(&local_40);
  LeaveCriticalSection(&local_40);
  LeaveCriticalSection(&local_20);",
            ),
        );
        let result = scan(program).await;

        assert!(
            result
                .findings
                .iter()
                .all(|finding| finding.kind() != "lock_order"),
            "one shared order is not a conflict"
        );
    }

    #[tokio::test]
    async fn custom_acquire_names_reach_the_lock_order_pass() {
        // The pass reads the mutex detector's configured set, not a
        // private default: custom acquire and release spellings reach
        // the scan together — the pairing completes through the
        // configured releases and the conflict still reads through
        // the configured acquires.
        let mut program = FakeProgram::empty();
        program.listing = vec![summary("FUN_18003ab00"), summary("FUN_18003e750")];
        program.bodies.insert(
            "FUN_18003ab00".into(),
            function(
                "FUN_18003ab00",
                "undefined FUN_18003ab00(void)",
                "  my_lock(&a);\n  my_lock(&b);\n  my_unlock(&b);\n  my_unlock(&a);\n",
            ),
        );
        program.bodies.insert(
            "FUN_18003e750".into(),
            function(
                "FUN_18003e750",
                "undefined FUN_18003e750(void)",
                "  my_lock(&b);\n  my_lock(&a);\n  my_unlock(&a);\n  my_unlock(&b);\n",
            ),
        );
        let engine = SyncEngine::with_source(program).with_mutex(MutexDetector::with_names(
            [MutexSignature::new("my_lock", SyncType::ParkingMutex)],
            ["my_unlock"],
        ));
        let result = engine.scan("eqmain.dll").await.expect("scan");

        let conflicts: Vec<&SyncFinding> = result
            .findings
            .iter()
            .filter(|finding| finding.kind() == "lock_order")
            .collect();
        assert_eq!(conflicts.len(), 1, "the configured spellings conflict");
        let SyncFinding::LockOrder(record) = conflicts[0] else {
            unreachable!("the reversed orders read as a lock-order finding");
        };
        assert_eq!(record.first_lock, "a");
        assert_eq!(record.second_lock, "b");
        // The configured releases paired the acquisitions in-body, so
        // both name sets — not just the acquires — reached the scan.
        assert_eq!(
            result
                .findings
                .iter()
                .filter(|finding| finding.kind() == "mutex")
                .count(),
            4,
            "the configured release spellings closed the pairs"
        );
    }

    #[tokio::test]
    async fn a_function_that_will_not_decompile_fabricates_no_cross_function_claim() {
        // A skipped body has no sequence to compare: the surviving
        // function's order stands against nothing, so the pass claims
        // nothing about the function whose body never arrived.
        let mut program = FakeProgram::empty();
        program.listing = vec![summary("FUN_18003ab00"), summary("FUN_18003e750")];
        program.bodies.insert(
            "FUN_18003ab00".into(),
            function(
                "FUN_18003ab00",
                "undefined FUN_18003ab00(void)",
                "\
  EnterCriticalSection(&local_20);
  EnterCriticalSection(&local_40);
  LeaveCriticalSection(&local_40);
  LeaveCriticalSection(&local_20);",
            ),
        );
        program.fail_decompiles = vec!["FUN_18003e750".into()];
        let result = scan(program).await;

        assert!(
            result
                .findings
                .iter()
                .all(|finding| finding.kind() != "lock_order"),
            "a missing body forms no sequence and no conflict"
        );
    }

    #[tokio::test]
    async fn lock_order_findings_append_after_the_per_function_findings() {
        // One function carries in-body pairs and a cross-function
        // conflict: the pairings ride the per-function walk, the
        // cross-function finding lands after every function's own
        // findings.
        let mut program = FakeProgram::empty();
        program.listing = vec![summary("FUN_18003ab00"), summary("FUN_18003e750")];
        program.bodies.insert(
            "FUN_18003ab00".into(),
            function(
                "FUN_18003ab00",
                "undefined FUN_18003ab00(void)",
                "\
  EnterCriticalSection(&local_20);
  EnterCriticalSection(&local_40);
  LeaveCriticalSection(&local_40);
  LeaveCriticalSection(&local_20);",
            ),
        );
        program.bodies.insert(
            "FUN_18003e750".into(),
            function(
                "FUN_18003e750",
                "undefined FUN_18003e750(void)",
                "  EnterCriticalSection(&local_40);\n  EnterCriticalSection(&local_20);\n",
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
                ("FUN_18003ab00", "mutex"),
                ("FUN_18003ab00", "mutex"),
                ("FUN_18003ab00", "lock_order"),
            ]
        );
    }

    #[tokio::test]
    async fn two_functions_sharing_an_unprotected_global_land_a_data_race_finding() {
        // The shape neither body reads on its own: one function stores
        // into a program global under no lock, another reads the same
        // global, and nothing guards either side.
        let mut program = FakeProgram::empty();
        program.listing = vec![summary("FUN_18003ab00"), summary("FUN_18003e750")];
        program.bodies.insert(
            "FUN_18003ab00".into(),
            function(
                "FUN_18003ab00",
                "undefined FUN_18003ab00(void)",
                "  DAT_counter = iVar1 + 1;\n",
            ),
        );
        program.bodies.insert(
            "FUN_18003e750".into(),
            function(
                "FUN_18003e750",
                "undefined FUN_18003e750(void)",
                "  uVar1 = DAT_counter;\n",
            ),
        );
        let result = scan(program).await;

        let race = result
            .findings
            .iter()
            .find(|finding| finding.kind() == "data_race")
            .expect("the shared global reads as a data race");
        let SyncFinding::DataRace(record) = race else {
            unreachable!("the shared global reads as a data race");
        };
        assert_eq!(record.function, "FUN_18003ab00");
        assert_eq!(record.partner, "FUN_18003e750");
        assert_eq!(record.variable, "DAT_counter");
        assert_eq!(
            record.suggestion,
            "guard the shared global with one lock held by both functions"
        );
        // The unprotected side is absence-of-evidence: one rung below
        // the evidence-based kinds.
        assert_eq!(record.confidence, 60);
        assert_eq!(
            record.evidence,
            "FUN_18003ab00: DAT_counter = iVar1 + 1; FUN_18003e750: uVar1 = DAT_counter;"
        );
        assert_eq!(race.target(), "DAT_counter");
    }

    #[tokio::test]
    async fn the_same_lock_object_held_by_both_functions_suppresses_the_race() {
        // Both sides guard the global with one lock object: the scan
        // pairs the locks in-body and the race claim is withdrawn.
        let mut program = FakeProgram::empty();
        program.listing = vec![summary("FUN_18003ab00"), summary("FUN_18003e750")];
        program.bodies.insert(
            "FUN_18003ab00".into(),
            function(
                "FUN_18003ab00",
                "undefined FUN_18003ab00(void)",
                "  EnterCriticalSection(&guard);\n  DAT_counter = 5;\n  LeaveCriticalSection(&guard);\n",
            ),
        );
        program.bodies.insert(
            "FUN_18003e750".into(),
            function(
                "FUN_18003e750",
                "undefined FUN_18003e750(void)",
                "  EnterCriticalSection(&guard);\n  uVar1 = DAT_counter;\n  LeaveCriticalSection(&guard);\n",
            ),
        );
        let result = scan(program).await;

        assert!(
            result
                .findings
                .iter()
                .all(|finding| finding.kind() != "data_race"),
            "both sides hold the same lock over the data"
        );
        assert_eq!(
            result
                .findings
                .iter()
                .filter(|finding| finding.kind() == "mutex")
                .count(),
            2,
            "the pairs still read as mutex findings on their own"
        );
    }

    #[tokio::test]
    async fn a_function_that_will_not_decompile_contributes_no_race() {
        // The pass reads only the bodies the scan kept: the surviving
        // function's store has no partner to pair with, so the scan
        // claims no race against the function whose body never arrived.
        let mut program = FakeProgram::empty();
        program.listing = vec![summary("FUN_18003ab00"), summary("FUN_18003e750")];
        program.bodies.insert(
            "FUN_18003ab00".into(),
            function(
                "FUN_18003ab00",
                "undefined FUN_18003ab00(void)",
                "  DAT_counter = 5;\n",
            ),
        );
        program.bodies.insert(
            "FUN_18003e750".into(),
            function(
                "FUN_18003e750",
                "undefined FUN_18003e750(void)",
                "  uVar1 = DAT_counter;\n",
            ),
        );
        program.fail_decompiles = vec!["FUN_18003e750".into()];
        let result = scan(program).await;

        assert!(
            result
                .findings
                .iter()
                .all(|finding| finding.kind() != "data_race"),
            "a missing body names no access and forms no pair"
        );
    }

    #[tokio::test]
    async fn the_race_reading_runs_without_a_global_state_document() {
        // The pairing consumes the global-state crate's reading in
        // process, not its persisted artifact: this scan has no
        // global-state document behind it — the global-state engine
        // never ran — and the race finding still lands, so the two
        // engines stay independently runnable in either order.
        let mut program = FakeProgram::empty();
        program.listing = vec![summary("FUN_18003ab00"), summary("FUN_18003e750")];
        program.bodies.insert(
            "FUN_18003ab00".into(),
            function(
                "FUN_18003ab00",
                "undefined FUN_18003ab00(void)",
                "  DAT_counter = iVar1 + 1;\n",
            ),
        );
        program.bodies.insert(
            "FUN_18003e750".into(),
            function(
                "FUN_18003e750",
                "undefined FUN_18003e750(void)",
                "  uVar1 = DAT_counter;\n",
            ),
        );
        let result = scan(program).await;

        assert!(
            result
                .findings
                .iter()
                .any(|finding| finding.kind() == "data_race"),
            "no global-state scan ran, no document exists, the race finding still lands"
        );
    }

    #[tokio::test]
    async fn data_race_findings_append_after_the_per_function_findings() {
        // One function carries an in-body lock pair and an unprotected
        // store the other function reads: the pairings ride the
        // per-function walk, the race lands after every function's own
        // findings.
        let mut program = FakeProgram::empty();
        program.listing = vec![summary("FUN_18003ab00"), summary("FUN_18003e750")];
        program.bodies.insert(
            "FUN_18003ab00".into(),
            function(
                "FUN_18003ab00",
                "undefined FUN_18003ab00(void)",
                "  EnterCriticalSection(&local_20);\n  DAT_counter = 5;\n  LeaveCriticalSection(&local_20);\n",
            ),
        );
        program.bodies.insert(
            "FUN_18003e750".into(),
            function(
                "FUN_18003e750",
                "undefined FUN_18003e750(void)",
                "  uVar1 = DAT_counter;\n",
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
            vec![("FUN_18003ab00", "mutex"), ("FUN_18003ab00", "data_race"),]
        );
    }

    #[tokio::test]
    async fn scan_decompiles_each_function_exactly_once() {
        // The four detectors share one fetch per function; a scan
        // that asked each detector for its own copy would quadruple
        // the wall time.
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
        // The decompiler cannot produce a body for every function; one bad
        // entry point must not cost the whole program its scan.
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
        let result = SyncEngine::with_source(program).scan("eqmain.dll").await;
        assert!(matches!(
            result,
            Err(crate::SyncError::DecompileBreaker {
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
        let result = SyncEngine::with_source(program.clone())
            .scan("eqmain.dll")
            .await;

        assert!(matches!(
            result,
            Err(crate::SyncError::DecompileBreaker {
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
        // An empty name would send the by-name lookup into an
        // arbitrary function's body, so the entry passes without a
        // decompile.
        let mut program = program();
        program.listing.insert(0, summary(""));
        let result = scan(program.clone()).await;

        assert_eq!(program.decompiled(), vec!["FUN_18003ab00", "FUN_18003e750"]);
        assert!(!result.is_empty());
    }

    #[tokio::test]
    async fn a_failing_listing_fails_the_whole_run() {
        // With the listing gone nothing was scanned, so the run aborts
        // rather than returning a result that looks empty by
        // detection.
        let mut program = program();
        program.fail_listing = true;
        let result = SyncEngine::with_source(program).scan("eqmain.dll").await;
        assert!(matches!(
            result,
            Err(crate::SyncError::Engine(EngineError::Reported { .. }))
        ));
    }

    #[tokio::test]
    async fn custom_name_sets_reach_every_detector() {
        // Swapping a detector's sets whole reaches the scan: the
        // configured custom spellings pair in all four families, and
        // the standard names the swaps replaced pair nothing.
        let mut program = FakeProgram::empty();
        program.listing = vec![summary("FUN_1800412a0")];
        program.bodies.insert(
            "FUN_1800412a0".into(),
            function(
                "FUN_1800412a0",
                "undefined FUN_1800412a0(void)",
                "\
  my_lock(&local_20);
  my_unlock(&local_20);
  my_atomic(&local_28);
  h = my_spawn(worker);
  my_join(h);
  k = my_key_new();
  my_key_read(k);",
            ),
        );

        let engine = SyncEngine::with_source(program)
            .with_mutex(MutexDetector::with_names(
                [MutexSignature::new("my_lock", SyncType::ParkingMutex)],
                ["my_unlock"],
            ))
            .with_atomics(AtomicDetector::with_names([AtomicSignature::new(
                "my_atomic",
                32,
            )]))
            .with_threads(ThreadingDetector::with_names(
                [ThreadSpawnSignature::new(
                    "my_spawn",
                    SpawnBinding::ReturnValue,
                )],
                ["my_join"],
            ))
            .with_tls(TlsDetector::with_names(
                [TlsKeySignature::new("my_key_new", KeyBinding::ReturnValue)],
                ["my_key_read"],
            ));
        let result = engine.scan("eqmain.dll").await.expect("scan");

        assert_eq!(
            kinds(&result, "FUN_1800412a0"),
            ["mutex", "atomic", "thread", "tls"]
        );
        let findings: Vec<&SyncFinding> = result.for_function("FUN_1800412a0").collect();
        let SyncFinding::Mutex(hint) = findings[0] else {
            unreachable!("the configured lock pair reads as a mutex finding");
        };
        assert_eq!(hint.evidence, "my_lock(&local_20); my_unlock(&local_20);");
        let SyncFinding::Atomic(record) = findings[1] else {
            unreachable!("the configured atomic call reads as an atomic finding");
        };
        assert_eq!(record.operation, "my_atomic");
        assert_eq!(record.suggestion, "std::sync::atomic::AtomicU32");
        let SyncFinding::Thread(record) = findings[2] else {
            unreachable!("the configured spawn pair reads as a thread finding");
        };
        assert_eq!(record.spawn, "my_spawn");
        assert_eq!(record.join.as_deref(), Some("my_join"));
        let SyncFinding::Tls(record) = findings[3] else {
            unreachable!("the configured key pair reads as a tls finding");
        };
        assert_eq!(record.creation.as_deref(), Some("my_key_new"));
        assert_eq!(record.access, "my_key_read");
        assert_eq!(record.suggestion, "thread_local!");
    }

    #[tokio::test]
    async fn scan_stamps_the_scan_provenance() {
        // The metadata names the binary, carries a finish time, and
        // the duration is stamped from the wall clock — a canned scan
        // is instant, so it reads as zero seconds rather than never
        // set.
        let result = scan(program()).await;
        assert_eq!(result.metadata.binary, "eqmain.dll");
        assert!(result.metadata.scanned_at > 0);
        assert!(result.metadata.duration_secs < 60);
        // Story 9 (#203): the record also names the engine that produced it —
        // scan() copies the source's provenance through (#208).
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

    /// The facets a concurrency scan declares, in order — the roster the
    /// record must name exactly once each. The concurrency scan reads one
    /// facet: the decompiled bodies every per-body detector shares.
    const DECLARED_FACETS: &[&str] = &["function-bodies"];

    /// The data-level verdict of the roster pin: empty means the record
    /// names every declared facet exactly once, and each fault spells one
    /// drift.
    fn roster_faults(coverage: &ScanCoverage) -> Vec<String> {
        let mut faults = Vec::new();
        for declared in DECLARED_FACETS {
            let hits = coverage
                .facets
                .iter()
                .filter(|facet| facet.id == *declared)
                .count();
            if hits == 0 {
                faults.push(format!(
                    "declared facet `{declared}` is missing from the record"
                ));
            } else if hits > 1 {
                faults.push(format!(
                    "declared facet `{declared}` appears {hits} times in the record"
                ));
            }
        }
        for facet in &coverage.facets {
            if !DECLARED_FACETS.contains(&facet.id.as_str()) {
                faults.push(format!(
                    "record names `{}`, a facet the engine never declared",
                    facet.id
                ));
            }
        }
        faults
    }

    #[tokio::test]
    async fn a_fresh_scan_stamps_complete_bodies_coverage_and_a_clean_roster() {
        // The stamp rides the engine's own scan, not the registry row
        // and not the CLI — the batch scan phase and the CLI's
        // force-rescan file the same admission through this one
        // definition. Every body was read here, so the record is
        // complete and says nothing needs admitting.
        let result = scan(program()).await;
        let coverage = result
            .metadata
            .coverage
            .expect("a fresh concurrency scan states its coverage");
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
        // The whole point of the admission: a body the scan could not
        // read is named, so it is never mistaken for an examined-and-
        // clean function the findings simply left unmentioned.
        let mut program = program();
        program.fail_decompiles = vec!["FUN_18003e750".into()];
        let result = scan(program).await;
        let coverage = result
            .metadata
            .coverage
            .expect("a partial concurrency scan states its coverage too");
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
        // Bounded prose beside the counts: six decompile failures name
        // five inline and fold the sixth into a count, and a nameless
        // listing entry counts toward the total without stealing a name
        // slot.
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
            .expect("a partial concurrency scan states its coverage")
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
        coverage.facets.retain(|facet| facet.id != "function-bodies");
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
            id: "lock-ordering".to_string(),
            status: CoverageStatus::Unexamined,
            limitation: None,
        });
        assert_eq!(
            roster_faults(&coverage),
            ["record names `lock-ordering`, a facet the engine never declared"],
            "an id invented outside the declared roster fails loudly"
        );
    }
}
