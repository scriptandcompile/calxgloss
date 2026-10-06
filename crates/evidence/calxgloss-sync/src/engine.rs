//! Concurrency scan orchestration.
//!
//! [`SyncEngine`] runs the three detectors — mutex/lock pair tracking,
//! atomic operation detection, and thread spawn detection — over every
//! function of one open Ghidra program and assembles their findings
//! into a single [`SyncResult`] with its scan provenance.
//!
//! The detectors are pure text analysis over one decompiled body, so
//! the engine fetches each function's pseudo-C exactly once and reads
//! it with all three, rather than having each detector pull its own
//! copy. The scan is then one sequential pass over the function
//! listing: unlike typeinfer's competing families there is nothing to
//! resolve between the detectors — they read disjoint body shapes —
//! and keeping the pass sequential keeps the persisted finding list in
//! a stable, diffable order.

use crate::atomic::AtomicDetector;
use crate::error::Result;
use crate::mutex::MutexDetector;
use crate::threading::ThreadingDetector;
use crate::types::{ScanMetadata, SyncFinding, SyncResult};
use calxgloss_ghidra::{DecompiledFunction, FunctionSummary, GhidraClient};
use std::time::Instant;
use tracing::{info, warn};

/// The decompiler a concurrency scan reads.
///
/// [`GhidraClient`] implements it directly; tests implement it over
/// canned bodies so the orchestration runs without a server. The
/// futures are `Send` so a scan can be driven from an orchestrating
/// task.
pub trait ScanSource {
    /// Every function in the program, in listing order.
    fn functions(&self) -> impl std::future::Future<Output = Result<Vec<FunctionSummary>>> + Send;

    /// The pseudo-C for one function, by name.
    fn decompile(
        &self,
        name: &str,
    ) -> impl std::future::Future<Output = Result<DecompiledFunction>> + Send;
}

impl ScanSource for GhidraClient {
    async fn functions(&self) -> Result<Vec<FunctionSummary>> {
        Ok(self.list_functions().await?)
    }

    async fn decompile(&self, name: &str) -> Result<DecompiledFunction> {
        Ok(self.decompile_function_by_name(name).await?)
    }
}

/// Orchestrates the three detectors into one [`SyncResult`].
///
/// The engine is generic over its [`ScanSource`], so tests can run the
/// whole orchestration over canned bodies; [`new`](Self::new) builds
/// one over a live [`GhidraClient`]. Each detector carries no state
/// and starts configured with its standard name sets —
/// [`with_mutex`](Self::with_mutex), [`with_atomics`](Self::with_atomics),
/// and [`with_threads`](Self::with_threads) swap a detector's sets
/// whole — so one instance of each serves the whole scan.
#[derive(Debug, Clone)]
pub struct SyncEngine<S = GhidraClient> {
    source: S,
    mutex: MutexDetector,
    atomics: AtomicDetector,
    threads: ThreadingDetector,
}

impl SyncEngine<GhidraClient> {
    /// An engine over a live GhidraMCP client, scanning with the three
    /// detectors' standard name sets.
    pub fn new(client: &GhidraClient) -> SyncEngine<GhidraClient> {
        SyncEngine {
            source: client.clone(),
            mutex: MutexDetector::with_default_names(),
            atomics: AtomicDetector::with_default_names(),
            threads: ThreadingDetector::with_default_names(),
        }
    }
}

impl<S> SyncEngine<S> {
    /// An engine whose decompiles come from `source`, scanning with
    /// the three detectors' standard name sets.
    pub fn with_source(source: S) -> Self {
        SyncEngine {
            source,
            mutex: MutexDetector::with_default_names(),
            atomics: AtomicDetector::with_default_names(),
            threads: ThreadingDetector::with_default_names(),
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

    /// Detect concurrency constructs across `binary`, decompiling
    /// each function exactly once and reading it with all three
    /// detectors.
    ///
    /// `binary` names the program the scan reads (e.g. `eqmain.dll`)
    /// and becomes the key a persisted result is filed under. The
    /// findings follow the function listing — function by function,
    /// and within one function the mutex pairings, then the atomic
    /// calls, then the thread spawns — so two scans of the same
    /// program diff cleanly.
    ///
    /// A function whose body Ghidra cannot produce (a thunk, a bad
    /// entry point) is skipped with a warning; only a failure of the
    /// listing itself — the server being down — aborts the run, since
    /// then nothing was scanned. The three detectors read disjoint
    /// body shapes, so a function can carry findings of every kind at
    /// once and nothing is resolved between them.
    pub async fn scan(&self, binary: impl Into<String>) -> Result<SyncResult>
    where
        S: ScanSource,
    {
        let started = Instant::now();
        let functions = self.source.functions().await?;

        let mut findings = Vec::new();
        let mut skipped = 0usize;
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
        }

        let mut metadata = ScanMetadata::new(binary);
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
    use crate::types::SyncType;
    use calxgloss_ghidra::GhidraError;
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
                return Err(GhidraError::Reported {
                    status: Some(200),
                    message: "Ghidra is busy".into(),
                }
                .into());
            }
            Ok(self.listing.clone())
        }

        async fn decompile(&self, name: &str) -> Result<DecompiledFunction> {
            self.stats.decompiles.lock().unwrap().push(name.to_string());
            if self.fail_decompiles.iter().any(|f| f == name) {
                return Err(GhidraError::NotFound {
                    kind: "function",
                    query: name.to_string(),
                }
                .into());
            }
            self.bodies.get(name).cloned().ok_or_else(|| {
                GhidraError::NotFound {
                    kind: "function",
                    query: name.to_string(),
                }
                .into()
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
    async fn scan_decompiles_each_function_exactly_once() {
        // The three detectors share one fetch per function; a scan
        // that asked each detector for its own copy would triple the
        // wall time.
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
        // Ghidra cannot produce a body for every function; one bad
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
            Err(crate::SyncError::Ghidra(GhidraError::Reported { .. }))
        ));
    }

    #[tokio::test]
    async fn custom_name_sets_reach_every_detector() {
        // Swapping a detector's sets whole reaches the scan: the
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
  my_lock(&local_20);
  my_unlock(&local_20);
  my_atomic(&local_28);
  h = my_spawn(worker);
  my_join(h);",
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
            ));
        let result = engine.scan("eqmain.dll").await.expect("scan");

        assert_eq!(
            kinds(&result, "FUN_1800412a0"),
            ["mutex", "atomic", "thread"]
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
    }

    #[tokio::test]
    async fn an_empty_program_yields_an_empty_result() {
        let result = scan(FakeProgram::empty()).await;
        assert!(result.is_empty());
        assert_eq!(result.metadata.binary, "eqmain.dll");
        assert!(result.metadata.scanned_at > 0);
    }
}
