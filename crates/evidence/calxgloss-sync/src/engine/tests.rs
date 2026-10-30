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
async fn two_functions_that_lock_the_same_objects_in_opposite_orders_land_a_lock_order_finding() {
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
    // One function has in-body lock pairs and a cross-function
    // conflict. The pairs come from the per-function walk; the
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
    // The pairing uses the global-state evidence engine's reading
    // in process, not its persisted document. This scan has no
    // global-state document behind it — that evidence engine
    // never ran — and the race finding still lands. The two
    // evidence engines stay independently runnable in either
    // order.
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
    // One function has an in-body lock pair and an unprotected
    // store that the other function reads. The pair comes from
    // the per-function walk; the race finding lands after every
    // function's own findings.
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
