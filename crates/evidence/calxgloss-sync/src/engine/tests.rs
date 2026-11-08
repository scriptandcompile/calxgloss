// Tests for the module above, split out of the file they test.
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
/// read what the scan did even after `SyncEngine` takes the
/// source.
#[derive(Debug, Default)]
struct Stats {
    decompiles: Mutex<Vec<String>>,
    exports_reads: Mutex<usize>,
}

/// A canned program implementing [`ScanSource`], so the whole
/// orchestration runs without a server.
#[derive(Clone)]
struct FakeProgram {
    listing: Vec<FunctionSummary>,
    bodies: HashMap<String, DecompiledFunction>,
    fail_decompiles: Vec<String>,
    fail_listing: bool,
    fail_exports: bool,
    exports: Vec<Symbol>,
    stats: Arc<Stats>,
}

impl FakeProgram {
    fn empty() -> Self {
        Self {
            listing: Vec::new(),
            bodies: HashMap::new(),
            fail_decompiles: Vec::new(),
            fail_listing: false,
            fail_exports: false,
            exports: Vec::new(),
            stats: Arc::new(Stats::default()),
        }
    }

    /// Every named listing entry stands as an export, so the
    /// scan's reachability gate admits the whole program and the
    /// test reads as an ungated scan would.
    fn exporting(mut self, names: &[&str]) -> Self {
        self.exports = names
            .iter()
            .map(|name| Symbol {
                name: (*name).to_string(),
                address: 0x1800_3ab00,
                imported: false,
            })
            .collect();
        self
    }

    fn decompiled(&self) -> Vec<String> {
        self.stats.decompiles.lock().unwrap().clone()
    }

    fn exports_reads(&self) -> usize {
        *self.stats.exports_reads.lock().unwrap()
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

    // The rest of the shared trait's reads: the sync scan never
    // makes them, so they answer with empty or not-found data.
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
        *self.stats.exports_reads.lock().unwrap() += 1;
        if self.fail_exports {
            return Err(EngineError::Reported {
                message: "the engine is busy".into(),
            });
        }
        Ok(self.exports.clone())
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
    // The shared fixture exports its two functions: they stand in the
    // concurrent-reachability gate's entry set (issue #436), so pins
    // built on this fixture reach the cross-function comparison too.
    program.exports = export_symbols(&["FUN_18003ab00", "FUN_18003e750"]);
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

fn export_symbols(names: &[&str]) -> Vec<Symbol> {
    names
        .iter()
        .map(|name| Symbol {
            name: (*name).into(),
            address: 0x2000,
            imported: false,
        })
        .collect()
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
async fn two_functions_that_lock_the_same_objects_in_opposite_orders_land_a_lock_order_finding() {
    // The classic deadlock shape, invisible to either body read
    // on its own: one function takes `DAT_guard` before
    // `DAT_monitor`, the other the other way round. Both are exports,
    // so the reachability gate lets the pair through (issue #436).
    let mut program = FakeProgram::empty();
    program.listing = vec![summary("FUN_18003ab00"), summary("FUN_18003e750")];
    program.exports = export_symbols(&["FUN_18003ab00", "FUN_18003e750"]);
    program.bodies.insert(
        "FUN_18003ab00".into(),
        function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            "\
  EnterCriticalSection(&DAT_guard);
  EnterCriticalSection(&DAT_monitor);
  LeaveCriticalSection(&DAT_monitor);
  LeaveCriticalSection(&DAT_guard);",
        ),
    );
    program.bodies.insert(
        "FUN_18003e750".into(),
        function(
            "FUN_18003e750",
            "undefined FUN_18003e750(void)",
            "\
  EnterCriticalSection(&DAT_monitor);
  EnterCriticalSection(&DAT_guard);
  LeaveCriticalSection(&DAT_guard);
  LeaveCriticalSection(&DAT_monitor);",
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
    assert_eq!(record.first_lock, "DAT_guard");
    assert_eq!(record.second_lock, "DAT_monitor");
    assert_eq!(
        record.suggestion,
        "pick one consistent lock acquisition order"
    );
    assert_eq!(record.confidence, 70);
    // The evidence carries both functions' acquire orders.
    assert_eq!(
        record.evidence,
        "FUN_18003ab00: DAT_guard -> DAT_monitor; \
             FUN_18003e750: DAT_monitor -> DAT_guard"
    );
}

#[tokio::test]
async fn two_functions_reversing_same_named_stack_slot_locks_file_no_lock_order_finding() {
    // The false-positive gate (issue #435): `local_20` in one body is
    // that body's own stack slot, so two reversed bodies share no lock
    // instance and claim no deadlock. The in-body pairing still sees
    // both functions' lock pairs — only the cross-function claim goes.
    let mut program = FakeProgram::empty();
    program.listing = vec![summary("FUN_18003ab00"), summary("FUN_18003e750")];
    program.exports = export_symbols(&["FUN_18003ab00", "FUN_18003e750"]);
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

    assert!(
        result
            .findings
            .iter()
            .all(|finding| finding.kind() != "lock_order"),
        "two stack slots sharing a name are not one lock the pair could reverse"
    );
    assert_eq!(
        result
            .findings
            .iter()
            .filter(|finding| finding.kind() == "mutex")
            .count(),
        4,
        "the in-body pairing keeps both functions' lock pairs"
    );
}

#[tokio::test]
async fn functions_that_lock_shared_objects_in_a_consistent_order_claim_nothing() {
    // Clean code stays clean: both functions take `DAT_guard`
    // before `DAT_monitor`, so there is no order to disagree about.
    let mut program = FakeProgram::empty();
    program.listing = vec![summary("FUN_18003ab00"), summary("FUN_18003e750")];
    program.exports = export_symbols(&["FUN_18003ab00", "FUN_18003e750"]);
    program.bodies.insert(
        "FUN_18003ab00".into(),
        function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            "\
  EnterCriticalSection(&DAT_guard);
  EnterCriticalSection(&DAT_monitor);
  LeaveCriticalSection(&DAT_monitor);
  LeaveCriticalSection(&DAT_guard);",
        ),
    );
    program.bodies.insert(
        "FUN_18003e750".into(),
        function(
            "FUN_18003e750",
            "undefined FUN_18003e750(void)",
            "\
  EnterCriticalSection(&DAT_guard);
  EnterCriticalSection(&DAT_monitor);
  LeaveCriticalSection(&DAT_monitor);
  LeaveCriticalSection(&DAT_guard);",
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
    program.exports = export_symbols(&["FUN_18003ab00", "FUN_18003e750"]);
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
    program.exports = export_symbols(&["FUN_18003ab00", "FUN_18003e750"]);
    program.bodies.insert(
        "FUN_18003ab00".into(),
        function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            "\
  EnterCriticalSection(&DAT_guard);
  EnterCriticalSection(&DAT_monitor);
  LeaveCriticalSection(&DAT_monitor);
  LeaveCriticalSection(&DAT_guard);",
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
    // One function has in-body lock pairs and a cross-function
    // conflict. The pairs come from the per-function walk; the
    // cross-function finding lands after every function's own
    // findings.
    let mut program = FakeProgram::empty();
    program.listing = vec![summary("FUN_18003ab00"), summary("FUN_18003e750")];
    program.exports = export_symbols(&["FUN_18003ab00", "FUN_18003e750"]);
    program.bodies.insert(
        "FUN_18003ab00".into(),
        function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            "\
  EnterCriticalSection(&DAT_guard);
  EnterCriticalSection(&DAT_monitor);
  LeaveCriticalSection(&DAT_monitor);
  LeaveCriticalSection(&DAT_guard);",
        ),
    );
    program.bodies.insert(
        "FUN_18003e750".into(),
        function(
            "FUN_18003e750",
            "undefined FUN_18003e750(void)",
            "  EnterCriticalSection(&DAT_monitor);\n  EnterCriticalSection(&DAT_guard);\n",
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
    program.exports = export_symbols(&["FUN_18003ab00", "FUN_18003e750"]);
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
    // One finding for the shared global, naming each accessor once
    // on its side of the read/write split (issue #434).
    assert_eq!(record.variable, "DAT_counter");
    assert_eq!(record.writers, ["FUN_18003ab00".to_string()]);
    assert_eq!(record.readers, ["FUN_18003e750".to_string()]);
    assert_eq!(record.unguarded_writes, 1);
    assert_eq!(record.unguarded_reads, 1);
    assert_eq!(record.sides.len(), 2);
    assert_eq!(
        record.suggestion,
        "guard the shared global with one lock held by both functions"
    );
    // The unprotected side rests on absence of evidence, so it
    // scores one band below the evidence-based kinds.
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
    program.exports = export_symbols(&["FUN_18003ab00", "FUN_18003e750"]);
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
async fn an_atomic_guarded_global_files_its_atomic_records_and_claims_no_race() {
    // The guard suppression through the scan (issue #437): both bodies
    // touch the global only inside recognized interlocked calls naming
    // it. The atomic records the per-body detector files for those
    // calls stand on; the race claim is what must not join them.
    let mut program = FakeProgram::empty();
    program.listing = vec![summary("FUN_18003ab00"), summary("FUN_18003e750")];
    program.exports = export_symbols(&["FUN_18003ab00", "FUN_18003e750"]);
    program.bodies.insert(
        "FUN_18003ab00".into(),
        function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            "  uVar1 = InterlockedIncrement(&DAT_counter);\n",
        ),
    );
    program.bodies.insert(
        "FUN_18003e750".into(),
        function(
            "FUN_18003e750",
            "undefined FUN_18003e750(void)",
            "  uVar2 = InterlockedDecrement(&DAT_counter);\n",
        ),
    );
    let result = scan(program).await;

    assert_eq!(
        result
            .findings
            .iter()
            .filter(|finding| finding.kind() == "atomic")
            .count(),
        2,
        "one atomic record per recognized call"
    );
    assert!(
        result
            .findings
            .iter()
            .all(|finding| finding.kind() != "data_race"),
        "the guarded global is not also filed as racing"
    );
}

#[tokio::test]
async fn a_tls_indexed_global_files_its_tls_records_and_claims_no_race() {
    // The TLS half of the scan-seam suppression (issue #437): one
    // body creates the slot index and writes per-thread data through
    // it, the other reaches the index only through `TlsGetValue`. The
    // TLS records — the creation pairing and the lone-access
    // fragment — stand; no race claim joins them.
    let mut program = FakeProgram::empty();
    program.listing = vec![summary("FUN_18003ab00"), summary("FUN_18003e750")];
    program.exports = export_symbols(&["FUN_18003ab00", "FUN_18003e750"]);
    program.bodies.insert(
        "FUN_18003ab00".into(),
        function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            "  DAT_tls_slot = TlsAlloc();\n  TlsSetValue(DAT_tls_slot, pvVar1);\n",
        ),
    );
    program.bodies.insert(
        "FUN_18003e750".into(),
        function(
            "FUN_18003e750",
            "undefined FUN_18003e750(void)",
            "  pvVar2 = TlsGetValue(DAT_tls_slot);\n",
        ),
    );
    let result = scan(program).await;

    assert_eq!(
        result
            .findings
            .iter()
            .filter(|finding| finding.kind() == "tls")
            .count(),
        2,
        "the pairing and the fragment stay filed on their own"
    );
    assert!(
        result
            .findings
            .iter()
            .all(|finding| finding.kind() != "data_race"),
        "the TLS-indexed global is not also filed as racing"
    );
}

#[tokio::test]
async fn a_function_that_will_not_decompile_contributes_no_race() {
    // The pass reads only the bodies the scan kept: the surviving
    // function's store has no partner to pair with, so the scan
    // claims no race against the function whose body never arrived.
    let mut program = FakeProgram::empty();
    program.listing = vec![summary("FUN_18003ab00"), summary("FUN_18003e750")];
    program.exports = export_symbols(&["FUN_18003ab00", "FUN_18003e750"]);
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
    // The pairing uses the global-state evidence engine's reading
    // in process, not its persisted document. This scan has no
    // global-state document behind it — that evidence engine
    // never ran — and the race finding still lands. The two
    // evidence engines stay independently runnable in either
    // order.
    let mut program = FakeProgram::empty();
    program.listing = vec![summary("FUN_18003ab00"), summary("FUN_18003e750")];
    program.exports = export_symbols(&["FUN_18003ab00", "FUN_18003e750"]);
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
    // One function has an in-body lock pair and an unprotected
    // store that the other function reads. The pair comes from
    // the per-function walk; the race finding lands after every
    // function's own findings.
    let mut program = FakeProgram::empty();
    program.listing = vec![summary("FUN_18003ab00"), summary("FUN_18003e750")];
    program.exports = export_symbols(&["FUN_18003ab00", "FUN_18003e750"]);
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
        // The aggregate names no single function — it is about the
        // global, not an accessor (issue #434).
        vec![("FUN_18003ab00", "mutex"), ("", "data_race"),]
    );
}

#[tokio::test]
async fn many_bodies_sharing_a_decompiler_junk_name_form_no_cross_function_finding() {
    // The LaunchPad case shape, pinned small: several bodies that
    // share only the decompiler's own slot names — `v1` written in
    // one body and read in another, `a0`, `eax`, `stack` — pair into
    // no race finding, because the shared global reading rejects
    // those names outright. The one real global in the program still
    // pairs, so the rule removes the junk and not the scan.
    let mut program = FakeProgram::empty();
    let junk = [
        ("FUN_180010000", "  v1 = 5;\n"),
        ("FUN_180010010", "  iVar1 = v1;\n"),
        ("FUN_180010020", "  v1 = a0;\n"),
        ("FUN_180010030", "  uVar1 = v1 + a0;\n"),
        ("FUN_180010040", "  stack = eax;\n"),
        ("FUN_180010050", "  ebx = stack;\n"),
    ];
    program.listing = junk
        .iter()
        .map(|(name, _)| summary(name))
        .chain([summary("FUN_18003ab00"), summary("FUN_18003e750")])
        .collect();
    program.exports = export_symbols(&[
        "FUN_180010000",
        "FUN_180010010",
        "FUN_180010020",
        "FUN_180010030",
        "FUN_180010040",
        "FUN_180010050",
        "FUN_18003ab00",
        "FUN_18003e750",
    ]);
    for (name, body) in junk {
        program
            .bodies
            .insert(name.into(), function(name, "undefined {name}(void)", body));
    }
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

    let order: Vec<(&str, &str)> = result
        .findings
        .iter()
        .map(|finding| (finding.function(), finding.kind()))
        .collect();
    assert_eq!(
        order,
        // The aggregate is about the global, so it names no single
        // function — the rollup shape (issue #434).
        vec![("", "data_race")],
        "eight bodies sharing junk names, and only the real global reads into one finding"
    );
}

// ============================================================
// The concurrent-reachability gate (issue #436)
// ============================================================

#[tokio::test]
async fn functions_reachable_from_no_thread_entry_or_export_pair_nothing() {
    // Two bodies share a real global — a write in one, a read in
    // the other — but no export, no thread start, and no caller
    // reaches either, so they can never be running at the same
    // time and the scan claims no race. Before the gate this pair
    // enumerated: real programs claimed races between functions
    // that never run at the same time.
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
            .all(|finding| finding.kind() != "data_race"),
        "no thread entry and no export reaches the pair, so it forms no cross-function finding"
    );
}

#[tokio::test]
async fn reversed_lock_orders_claim_no_conflict_when_the_pair_cannot_run_at_once() {
    // The same gate stands over the lock-order reading: two bodies
    // acquire `DAT_guard` and `DAT_monitor` in opposite orders,
    // but nothing exported or spawned reaches either, so the two
    // are never live at once and the scan files no deadlock claim.
    // The in-body pairings, which read every kept body regardless,
    // keep filing.
    let mut program = FakeProgram::empty();
    program.listing = vec![summary("FUN_18003ab00"), summary("FUN_18003e750")];
    program.bodies.insert(
        "FUN_18003ab00".into(),
        function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            "\
  EnterCriticalSection(&DAT_guard);
  EnterCriticalSection(&DAT_monitor);
  LeaveCriticalSection(&DAT_monitor);
  LeaveCriticalSection(&DAT_guard);",
        ),
    );
    program.bodies.insert(
        "FUN_18003e750".into(),
        function(
            "FUN_18003e750",
            "undefined FUN_18003e750(void)",
            "\
  EnterCriticalSection(&DAT_monitor);
  EnterCriticalSection(&DAT_guard);
  LeaveCriticalSection(&DAT_guard);
  LeaveCriticalSection(&DAT_monitor);",
        ),
    );
    let result = scan(program).await;

    assert!(
        result
            .findings
            .iter()
            .all(|finding| finding.kind() != "lock_order"),
        "a pair that can never run at once invents no deadlock"
    );
    assert_eq!(
        result
            .findings
            .iter()
            .filter(|finding| finding.kind() == "mutex")
            .count(),
        4,
        "the per-body walk still covers every kept body"
    );
}

#[tokio::test]
async fn an_exported_function_pairs_with_a_transitively_reachable_callee() {
    // Reachability walks forward over the call map the kept bodies
    // spell: the exported function calls a second body, which
    // calls a third. The second writes a global the third reads —
    // one call chain, so both frames can be live at once, and the
    // race stands.
    let mut program = FakeProgram::empty();
    program.listing = vec![
        summary("FUN_18003ab00"),
        summary("FUN_18003e750"),
        summary("FUN_180041230"),
    ];
    program.bodies.insert(
        "FUN_18003ab00".into(),
        function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            "  FUN_18003e750();\n",
        ),
    );
    program.bodies.insert(
        "FUN_18003e750".into(),
        function(
            "FUN_18003e750",
            "undefined FUN_18003e750(void)",
            "  DAT_counter = iVar1 + 1;\n  FUN_180041230();\n",
        ),
    );
    program.bodies.insert(
        "FUN_180041230".into(),
        function(
            "FUN_180041230",
            "undefined FUN_180041230(void)",
            "  uVar1 = DAT_counter;\n",
        ),
    );
    let program = program.exporting(&["FUN_18003ab00"]);
    let result = scan(program).await;

    let race = result
        .findings
        .iter()
        .find(|finding| finding.kind() == "data_race")
        .expect("two callees down one exported chain can still pair");
    let SyncFinding::DataRace(record) = race else {
        unreachable!("the shared global reads as a data race");
    };
    assert_eq!(record.writers, ["FUN_18003e750".to_string()]);
    assert_eq!(record.readers, ["FUN_180041230".to_string()]);
}

#[tokio::test]
async fn a_thread_start_argument_names_the_pair_and_the_spawner_names_no_global() {
    // `CreateThread` names a kept body as its start routine: that
    // routine and what it reaches run on a thread and pair. The
    // spawning body writes the same global but stands outside
    // every entry's closure — no export, no thread starts it, no
    // caller reaches it — so it forms no pair and names no race
    // global: the aggregate's lists, sides, and counts carry only
    // the bodies that could actually run at the same time.
    let mut program = FakeProgram::empty();
    program.listing = vec![
        summary("FUN_18003ab00"),
        summary("FUN_18003e750"),
        summary("FUN_180041230"),
    ];
    program.bodies.insert(
        "FUN_18003ab00".into(),
        function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            "\
  DAT_counter = 0;
  hThread = CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,FUN_18003e750,0x0,0,&local_14);
  WaitForSingleObject(hThread,0xffffffff);",
        ),
    );
    program.bodies.insert(
        "FUN_18003e750".into(),
        function(
            "FUN_18003e750",
            "undefined FUN_18003e750(void)",
            "  DAT_counter = iVar1 + 1;\n  FUN_180041230();\n",
        ),
    );
    program.bodies.insert(
        "FUN_180041230".into(),
        function(
            "FUN_180041230",
            "undefined FUN_180041230(void)",
            "  uVar1 = DAT_counter;\n",
        ),
    );
    let result = scan(program).await;

    let race = result
        .findings
        .iter()
        .find(|finding| finding.kind() == "data_race")
        .expect("a thread's routine and its callee could run at the same time");
    let SyncFinding::DataRace(record) = race else {
        unreachable!("the shared global reads as a data race");
    };
    assert_eq!(record.writers, ["FUN_18003e750".to_string()]);
    assert_eq!(record.readers, ["FUN_180041230".to_string()]);
    assert_eq!(record.unguarded_writes, 1);
    assert_eq!(record.unguarded_reads, 1);
    assert_eq!(
        record.sides.len(),
        2,
        "the gated-out spawner stands in no reader list, writer list, side, or count"
    );
}

#[tokio::test]
async fn the_gate_reads_the_export_listing_exactly_once_per_scan() {
    // The gate's entry set costs one program-level read — the
    // export listing, once per scan — beside the one decompile per
    // function. The exactly-once decompile contract stands.
    let program = program();
    let result = scan(program.clone()).await;
    assert!(!result.is_empty());
    assert_eq!(
        program.exports_reads(),
        1,
        "one export listing read per scan"
    );
    assert_eq!(
        program.decompiled(),
        vec!["FUN_18003ab00", "FUN_18003e750"],
        "the gate adds no extra decompiles"
    );
}

#[tokio::test]
async fn a_thread_started_by_a_custom_spawn_spelling_pairs_at_the_scan_seam() {
    // The gate reads the scan's configured spawn names, not a
    // private default: a program's own wrapper starts the thread,
    // and the started function still pairs with its transitive
    // callee through the scan.
    let mut program = FakeProgram::empty();
    program.listing = vec![
        summary("FUN_18003ab00"),
        summary("FUN_18003e750"),
        summary("FUN_180041230"),
    ];
    program.bodies.insert(
        "FUN_18003ab00".into(),
        function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            "  hThread = my_spawn(FUN_18003e750);\n  my_join(hThread);\n",
        ),
    );
    program.bodies.insert(
        "FUN_18003e750".into(),
        function(
            "FUN_18003e750",
            "undefined FUN_18003e750(void)",
            "  DAT_counter = 1;\n  FUN_180041230();\n",
        ),
    );
    program.bodies.insert(
        "FUN_180041230".into(),
        function(
            "FUN_180041230",
            "undefined FUN_180041230(void)",
            "  uVar1 = DAT_counter;\n",
        ),
    );
    let mut threads = ThreadingDetector::new();
    threads.add_spawn(ThreadSpawnSignature::new(
        "my_spawn",
        SpawnBinding::ReturnValue,
    ));
    threads.add_join("my_join");
    let result = SyncEngine::with_source(program)
        .with_threads(threads)
        .scan("eqmain.dll")
        .await
        .expect("scan");

    let race = result
        .findings
        .iter()
        .find(|finding| finding.kind() == "data_race")
        .expect("the wrapper's routine and its callee pair at the scan seam");
    let SyncFinding::DataRace(record) = race else {
        unreachable!("the shared global reads as a data race");
    };
    assert_eq!(record.writers, ["FUN_18003e750".to_string()]);
    assert_eq!(record.readers, ["FUN_180041230".to_string()]);
}

#[tokio::test]
async fn a_failed_export_listing_aborts_the_scan() {
    // The gate's entry set rides on a program-level listing, like
    // the function listing: when it fails, nothing can be said
    // about which pairs could run, and pairing everything — or
    // nothing — would persist a record that looks clean but is not.
    // The run aborts with the engine's own words.
    let mut program = program();
    program.fail_exports = true;
    let error = SyncEngine::with_source(program)
        .scan("eqmain.dll")
        .await
        .expect_err("a failed export listing aborts the run");
    assert!(
        matches!(
            error,
            crate::SyncError::Engine(EngineError::Reported { .. })
        ),
        "the listing failure rides through as the engine's own error: {error:?}"
    );
}

#[tokio::test]
async fn scan_decompiles_each_function_exactly_once() {
    // The six per-body detectors share one decompile call per
    // function; a scan that asked each detector for its own copy
    // would multiply the wall time.
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
    // The 2026-10-08 incident: the seam answered the listing from
    // one program and the decompiles from another, every decompile
    // failed, and the scan nearly filed a record that looks clean
    // but is not under the target's name. The skip-rate breaker
    // aborts with the counts instead, so nothing is persisted.
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
    // The skip-rate breaker is a fuse, not a post-mortem: once
    // more than half the listing has failed to decompile, the
    // remaining decompiles are wasted round-trips against the
    // wrong program.
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
    // Looking up an empty name could land the by-name lookup on
    // an arbitrary function's body, so the entry is skipped
    // without a decompile.
    let mut program = program();
    program.listing.insert(0, summary(""));
    let result = scan(program.clone()).await;

    assert_eq!(program.decompiled(), vec!["FUN_18003ab00", "FUN_18003e750"]);
    assert!(!result.is_empty());
}

#[tokio::test]
async fn a_failing_listing_fails_the_whole_run() {
    // With the listing gone nothing was scanned, so the run
    // aborts rather than returning a result that reads like a
    // clean scan that simply found nothing.
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
    // The metadata names the binary and records a finish time.
    // The duration is stamped from the wall clock; a canned scan
    // is instant, so it reads as zero seconds rather than never
    // set.
    let result = scan(program()).await;
    assert_eq!(result.metadata.binary, "eqmain.dll");
    assert!(result.metadata.scanned_at > 0);
    assert!(result.metadata.duration_secs < 60);
    // Story 9 (#203): the record also names the analysis engine
    // behind the source — scan() copies the source's provenance
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

/// The data-level verdict of the roster pin. An empty result
/// means the record names every declared facet exactly once; each
/// fault states one drift.
fn roster_faults(coverage: &ScanCoverage) -> Vec<String> {
    coverage.roster_faults(DECLARED_FACETS)
}

#[tokio::test]
async fn a_fresh_scan_stamps_complete_bodies_coverage_and_a_clean_roster() {
    // The stamp comes from `SyncEngine`'s own scan, not from the
    // registry row and not from the CLI. The batch scan phase and
    // the CLI's force-rescan file the same admission through this
    // one definition. Every body was read here, so the record is
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
    // The pairs facet is unaffected: a body the decompiler never
    // produced is no kept body, so the reachability gate excluded
    // none of the bodies it had (issue #436).
    let pairs = coverage
        .facets
        .iter()
        .find(|facet| facet.id == "cross-function-pairs")
        .expect("cross-function-pairs is named");
    assert_eq!(pairs.status, CoverageStatus::Complete);
    assert_eq!(pairs.limitation, None);
}

#[tokio::test]
async fn the_coverage_line_is_capped_at_five_names_and_counts_the_nameless() {
    // Bounded prose beside the counts: six decompile failures name
    // five inline and replace the sixth with a count. A nameless
    // listing entry counts toward the total without taking a name
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

#[tokio::test]
async fn the_gate_admits_excluded_bodies_naming_five_and_counting_the_rest() {
    // Seven kept bodies the gate never reaches — read by every
    // per-body detector, excluded from every pairing. The pairs
    // facet names five inline and counts the rest, while the bodies
    // facet stays complete: nothing was skipped (issue #436).
    let names: Vec<String> = (0..7).map(|i| format!("FUN_body_{i:04}")).collect();
    let mut program = FakeProgram::empty();
    for (index, name) in names.iter().enumerate() {
        program.listing.push(FunctionSummary {
            name: name.clone(),
            address: 0x1800_0000 + index as u64,
        });
        program.bodies.insert(
            name.clone(),
            function(name, "undefined FUN_body_x(void)", "  return;\n"),
        );
    }
    let result = scan(program).await;
    let coverage = result
        .metadata
        .coverage
        .expect("a gated scan states its coverage too");
    assert!(
        roster_faults(&coverage).is_empty(),
        "the roster now carries two facets and names both exactly once"
    );
    assert_eq!(coverage.status, CoverageStatus::Partial);
    let bodies = coverage
        .facets
        .iter()
        .find(|facet| facet.id == "function-bodies")
        .expect("function-bodies is named");
    assert_eq!(
        bodies.status,
        CoverageStatus::Complete,
        "every body was decompiled and read — the gate excluded none of that"
    );
    let pairs = coverage
        .facets
        .iter()
        .find(|facet| facet.id == "cross-function-pairs")
        .expect("cross-function-pairs is named");
    assert_eq!(pairs.status, CoverageStatus::Partial);
    assert_eq!(
        pairs.limitation.as_deref(),
        Some(
            "7 functions excluded from cross-function pairing: FUN_body_0000, \
             FUN_body_0001, FUN_body_0002, FUN_body_0003, FUN_body_0004, +2 more"
        ),
        "five names, the rest counted — the existing cap, reused"
    );
}

#[tokio::test]
async fn a_gated_findings_list_and_a_full_coverage_list_never_render_alike() {
    // The coverage-honesty rule, pinned at the sync seam: two scans
    // whose findings lists are both empty must not read alike. The
    // exported program paired everything it kept, so it admits
    // nothing; the unexported one paired nothing, and its admission
    // line says so beside the empty list.
    let bodies = [
        ("FUN_18003ab00", "  DAT_counter = 5;\n"),
        ("FUN_18003e750", "  uVar1 = DAT_counter;\n"),
    ];
    let build = |exported: bool| {
        let mut program = FakeProgram::empty();
        for (name, body) in bodies {
            program.listing.push(summary(name));
            program.bodies.insert(
                name.to_string(),
                function(name, "undefined FUN_x(void)", body),
            );
        }
        if exported {
            program.exports = export_symbols(&["FUN_18003ab00", "FUN_18003e750"]);
        }
        program
    };
    let gated = scan(build(false)).await;
    let full = scan(build(true)).await;

    // The findings lists could easily match — and beside them one
    // record admits its gate and the other admits nothing.
    let gated_admission = gated
        .metadata
        .coverage
        .as_ref()
        .and_then(|coverage| coverage.admission())
        .expect("the gated scan states an admission");
    assert_eq!(
        gated_admission,
        "partial — 2 functions excluded from cross-function pairing: \
         FUN_18003ab00, FUN_18003e750"
    );
    assert!(
        gated.findings.is_empty(),
        "the gated bodies form no pair, so they claim no race"
    );
    assert_eq!(full.findings.len(), 1, "the exported pair claims the race");
    assert_eq!(
        full.metadata
            .coverage
            .as_ref()
            .and_then(|coverage| coverage.admission()),
        None,
        "a full-coverage scan admits nothing — and reads nothing like \
         the gated one beside its findings"
    );
}

// ============================================================
// Last-resort cross-function findings cap (issue #438)
// ============================================================

/// Two exported bodies sharing `count` globals between them: the
/// first stores to each once, the second reads it back — one
/// aggregate data race per global, bucketed in first-sighting order.
fn shared_globals_program(count: usize) -> FakeProgram {
    let writes = (0..count)
        .map(|index| format!("DAT_g{index:04} = 1;"))
        .collect::<Vec<_>>()
        .join(" ");
    let reads = (0..count)
        .map(|index| format!("uVar1 = DAT_g{index:04};"))
        .collect::<Vec<_>>()
        .join(" ");
    let mut program = FakeProgram::empty();
    program.listing = vec![summary("FUN_18003ab00"), summary("FUN_18003e750")];
    program.exports = export_symbols(&["FUN_18003ab00", "FUN_18003e750"]);
    program.bodies.insert(
        "FUN_18003ab00".into(),
        function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            &format!("  {writes}\n"),
        ),
    );
    program.bodies.insert(
        "FUN_18003e750".into(),
        function(
            "FUN_18003e750",
            "undefined FUN_18003e750(void)",
            &format!("  {reads}\n"),
        ),
    );
    program
}

#[tokio::test]
async fn cross_function_findings_past_the_cap_truncate_while_the_count_stays_whole() {
    // The last-resort cap (issue #438): past the cap the scan keeps
    // the first findings in scan order and keeps the whole count on
    // the coverage record. The constants engine's inline-table cap set
    // the precedent: the list truncates while the count stays whole.
    // Even a pathological program then files a bounded document that
    // says what it cut.
    let result = scan(shared_globals_program(MAX_CROSS_FUNCTION_FINDINGS + 1)).await;
    let races: Vec<&str> = result
        .findings
        .iter()
        .map(|finding| {
            let SyncFinding::DataRace(race) = finding else {
                unreachable!("every finding in this fixture is an aggregated race");
            };
            race.variable.as_str()
        })
        .collect();
    assert_eq!(
        races.len(),
        MAX_CROSS_FUNCTION_FINDINGS,
        "the findings list stops at the cap"
    );
    assert_eq!(
        &races[..2],
        ["DAT_g0000", "DAT_g0001"],
        "the kept races are the first in scan order"
    );
    assert_eq!(
        races.last().copied(),
        Some("DAT_g0511"),
        "and the 513th global is the one that falls off the end"
    );
    let coverage = result
        .metadata
        .coverage
        .expect("a capped scan states its coverage too");
    assert!(
        roster_faults(&coverage).is_empty(),
        "a capped record still names every declared facet exactly once"
    );
    assert_eq!(
        coverage.status,
        CoverageStatus::Partial,
        "a truncated findings list never reads as a complete picture"
    );
    let pairs = coverage
        .facets
        .iter()
        .find(|facet| facet.id == "cross-function-pairs")
        .expect("cross-function-pairs is named");
    assert_eq!(pairs.status, CoverageStatus::Partial);
    assert_eq!(
        pairs.limitation.as_deref(),
        Some(
            "513 cross-function findings truncated at the cap of 512: first 512 kept in scan order"
        ),
        "the admission stamps the truncation beside the whole count"
    );
}

#[tokio::test]
async fn a_scan_exactly_at_the_cap_stamps_no_truncation_admission() {
    // The cap engages only past itself: exactly the cap's worth of
    // findings all stand, and the record admits nothing — the same
    // clean look an ordinary aggregated scan has (issue #438).
    let result = scan(shared_globals_program(MAX_CROSS_FUNCTION_FINDINGS)).await;
    assert_eq!(
        result.findings.len(),
        MAX_CROSS_FUNCTION_FINDINGS,
        "the cap cuts nothing at its own boundary"
    );
    let coverage = result
        .metadata
        .coverage
        .expect("the capped-boundary scan states its coverage");
    assert_eq!(coverage.status, CoverageStatus::Complete);
    let pairs = coverage
        .facets
        .iter()
        .find(|facet| facet.id == "cross-function-pairs")
        .expect("cross-function-pairs is named");
    assert_eq!(pairs.status, CoverageStatus::Complete);
    assert_eq!(
        pairs.limitation, None,
        "a scan under the cap admits no truncation"
    );
    assert_eq!(
        coverage.admission(),
        None,
        "and the whole record says nothing that reads like a cut"
    );
}

#[tokio::test]
async fn the_cap_cuts_at_the_tail_of_the_scan_order_across_both_cross_function_shapes() {
    // The scan-order contract under the cap (issue #438): lock-order
    // conflicts stand before races, so past the cap the kept findings
    // are every conflict and the first races — the races fall off the
    // tail, never something from the middle. The per-body mutex
    // findings the same bodies file stand before them and count
    // nothing toward the cap.
    let locks: Vec<String> = (0..28).map(|index| format!("DAT_l{index:02}")).collect();
    let acquire_forward = locks
        .iter()
        .map(|lock| format!("EnterCriticalSection(&{lock});"))
        .collect::<Vec<_>>()
        .join("\n  ");
    let acquire_reversed = locks
        .iter()
        .rev()
        .map(|lock| format!("EnterCriticalSection(&{lock});"))
        .collect::<Vec<_>>()
        .join("\n  ");
    let write_all = (0..200)
        .map(|index| format!("DAT_c{index:03} = 1;"))
        .collect::<Vec<_>>()
        .join(" ");
    let read_all = (0..200)
        .map(|index| format!("uVar1 = DAT_c{index:03};"))
        .collect::<Vec<_>>()
        .join(" ");
    let mut program = FakeProgram::empty();
    program.listing = vec![summary("FUN_18003ab00"), summary("FUN_18003e750")];
    program.exports = export_symbols(&["FUN_18003ab00", "FUN_18003e750"]);
    program.bodies.insert(
        "FUN_18003ab00".into(),
        function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            &format!("  {acquire_forward}\n  {write_all}\n"),
        ),
    );
    program.bodies.insert(
        "FUN_18003e750".into(),
        function(
            "FUN_18003e750",
            "undefined FUN_18003e750(void)",
            &format!("  {read_all}\n  {acquire_reversed}\n"),
        ),
    );
    let result = scan(program).await;

    // 378 reversed lock pairs (28 locks, every pair inverted) plus
    // 200 shared globals — 578 cross-function claims against a cap of 512.
    let cross: Vec<(&str, &str)> = result
        .findings
        .iter()
        .filter_map(|finding| match finding {
            SyncFinding::LockOrder(conflict) => {
                Some((finding.kind(), conflict.first_lock.as_str()))
            }
            SyncFinding::DataRace(race) => Some((finding.kind(), race.variable.as_str())),
            _ => None,
        })
        .collect();
    assert_eq!(
        cross.len(),
        MAX_CROSS_FUNCTION_FINDINGS,
        "the per-body mutex findings before them count nothing toward the cap"
    );
    let conflicts = cross.iter().take_while(|(kind, _)| *kind == "lock_order");
    assert_eq!(conflicts.count(), 378, "every lock-order conflict stands");
    let races: Vec<&str> = cross
        .iter()
        .filter(|(kind, _)| *kind == "data_race")
        .map(|(_, name)| *name)
        .collect();
    assert_eq!(
        (&races[..2], races.last().copied()),
        (&["DAT_c000", "DAT_c001"][..], Some("DAT_c133")),
        "the kept races are the first 134 in first-sighting order — the tail is what goes"
    );
    assert_eq!(
        cross
            .iter()
            .find(|(kind, _)| *kind == "lock_order")
            .map(|(_, name)| *name),
        Some("DAT_l00"),
        "the kept conflicts keep their own scan order from the front"
    );
    let pairs = result
        .metadata
        .coverage
        .expect("a capped scan states its coverage too")
        .facets
        .into_iter()
        .find(|facet| facet.id == "cross-function-pairs")
        .expect("cross-function-pairs is named");
    assert_eq!(
        pairs.limitation.as_deref(),
        Some(
            "578 cross-function findings truncated at the cap of 512: first 512 kept in scan order"
        ),
        "the whole 578 stands on the record while the list stops at 512"
    );
}

#[tokio::test]
async fn an_engaged_gate_and_an_engaged_cap_admit_side_by_side_in_one_facet() {
    // Both admissions ride the same record (issue #438): the gate
    // excluded seven bodies from pairing, and what the pairable
    // bodies filed still ran past the cap. One facet prints both
    // sentences, and each keeps its own count whole.
    let mut program = shared_globals_program(MAX_CROSS_FUNCTION_FINDINGS + 1);
    for index in 0..7 {
        let name = format!("FUN_body_{index:04}");
        program.listing.push(FunctionSummary {
            name: name.clone(),
            address: 0x1800_0000 + index,
        });
        program.bodies.insert(
            name.clone(),
            function(&name, "undefined FUN_body_x(void)", "  return;\n"),
        );
    }
    let result = scan(program).await;
    let pairs = result
        .metadata
        .coverage
        .expect("a gated capped scan states its coverage")
        .facets
        .into_iter()
        .find(|facet| facet.id == "cross-function-pairs")
        .expect("cross-function-pairs is named");
    assert_eq!(pairs.status, CoverageStatus::Partial);
    assert_eq!(
        pairs.limitation.as_deref(),
        Some(
            "7 functions excluded from cross-function pairing: FUN_body_0000, \
             FUN_body_0001, FUN_body_0002, FUN_body_0003, FUN_body_0004, +2 more; \
             513 cross-function findings truncated at the cap of 512: first 512 kept in scan order"
        ),
        "the gate line keeps its exact wording and the cap line joins it"
    );
}

#[test]
fn the_roster_pin_fails_when_a_declared_facet_goes_missing() {
    let mut coverage = coverage_stamp(&[], 0, &[], None);
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
    let mut coverage = coverage_stamp(&["FUN_18003e750".to_string()], 0, &[], None);
    coverage.facets.push(coverage.facets[0].clone());
    assert_eq!(
        roster_faults(&coverage),
        ["declared facet `function-bodies` appears 2 times in the record"],
        "a facet crowded into two entries fails loudly"
    );
}

#[test]
fn the_roster_pin_fails_when_coverage_names_an_orphan_facet() {
    let mut coverage = coverage_stamp(&[], 0, &[], None);
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
