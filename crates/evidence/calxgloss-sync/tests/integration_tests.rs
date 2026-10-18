//! Integration tests for the calxgloss-sync crate.
//!
//! These tests exercise the multi-module workflows the unit tests cannot
//! cover on their own:
//!
//! - **Scan to disk** — [`SyncEngine`] scans a canned program, the
//!   [`SyncPersistor`] files the result in the workspace layout, and
//!   loading it back yields the same result the scan returned.
//! - **Consumption** — the loaded result answers the lookups a
//!   translation pipeline makes (the findings recorded for one
//!   function), and the persisted list keeps every finding in scan
//!   order: function by function, and within one function the mutex
//!   pairings, then the atomic calls, then the thread spawns, then
//!   the TLS records.
//! - **Prompt rendering** — the loaded findings render into
//!   `ConcurrencyInfo` prompt data and the escalate prompt carries
//!   the CONCURRENCY section.
//! - **Cache behavior** — the `exists` check decides whether a scan
//!   runs, and a rescan replaces the cached document.
//!
//! The fake program implements [`ScanSource`], so the whole flow runs
//! without an external server.

use std::collections::HashMap;

use calxgloss_ghidra::{
    DataItem, DataTypeEntry, DecompiledFunction, EngineError, EnumDefinition, FunctionSummary,
    Result, StringLiteral, StructLayout, Symbol, Xref,
};
use calxgloss_sync::engine::{ScanSource, SyncEngine};
use calxgloss_sync::persist::SyncPersistor;
use calxgloss_sync::types::SyncFinding;
use tempfile::TempDir;

// ------------------------------------------------------------
// The canned program
// ------------------------------------------------------------

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

/// A canned program implementing [`ScanSource`]: one function whose body
/// carries an `EnterCriticalSection`/`LeaveCriticalSection` pair, an
/// `InterlockedIncrement` call, and a `CreateThread`/
/// `WaitForSingleObject` pair — one finding family per detector — and
/// one plain function that finds nothing.
#[derive(Clone, Default)]
struct FakeProgram {
    listing: Vec<FunctionSummary>,
    bodies: HashMap<String, DecompiledFunction>,
}

impl FakeProgram {
    fn empty() -> Self {
        Self::default()
    }
}

impl ScanSource for FakeProgram {
    async fn functions(&self) -> Result<Vec<FunctionSummary>> {
        Ok(self.listing.clone())
    }

    async fn decompile(&self, name: &str) -> Result<DecompiledFunction> {
        self.bodies
            .get(name)
            .cloned()
            .ok_or_else(|| EngineError::NotFound {
                kind: "function",
                query: name.to_string(),
            })
    }

    // The rest of the shared trait's reads: these tests never make
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
}

fn program() -> FakeProgram {
    let mut program = FakeProgram::empty();
    program.listing = vec![summary("FUN_18003ab00"), summary("FUN_18003e750")];
    program.bodies.insert(
        "FUN_18003ab00".into(),
        function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            "  EnterCriticalSection(&local_20);\n\
             \x20 *(int *)local_18 = 5;\n\
             \x20 LeaveCriticalSection(&local_20);\n\
             \x20 uVar1 = InterlockedIncrement(&local_28);\n\
             \x20 hThread = CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,worker,0x0,0,&local_14);\n\
             \x20 WaitForSingleObject(hThread,0xffffffff);\n",
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

// ------------------------------------------------------------
// Scan to disk
// ------------------------------------------------------------

#[tokio::test]
async fn a_scan_files_its_result_in_the_workspace_and_reads_back() {
    let workspace = TempDir::new().unwrap();
    let result = SyncEngine::with_source(program())
        .scan("eqmain.dll")
        .await
        .expect("scan");

    let persistor = SyncPersistor::new(workspace.path());
    assert!(!persistor.exists("eqmain.dll"), "nothing is cached yet");

    persistor.save(&result).expect("save");
    assert!(persistor.exists("eqmain.dll"));
    assert_eq!(
        persistor.path_for("eqmain.dll"),
        workspace.path().join("re/analysis/sync/eqmain.dll.json")
    );

    let loaded = persistor.load("eqmain.dll").expect("load");
    assert_eq!(loaded, result, "the document round-trips exactly");
}

#[tokio::test]
async fn the_persisted_document_keeps_findings_in_scan_order() {
    // The four detectors read disjoint shapes in one pass, so what
    // reaches disk is function by function in listing order and, within
    // one function, mutex then atomic then thread then TLS — the order
    // two scans diff against.
    let workspace = TempDir::new().unwrap();
    let result = SyncEngine::with_source(program())
        .scan("eqmain.dll")
        .await
        .expect("scan");
    let persistor = SyncPersistor::new(workspace.path());
    persistor.save(&result).expect("save");

    let loaded = persistor.load("eqmain.dll").expect("load");
    let order: Vec<(&str, &str)> = loaded
        .findings
        .iter()
        .map(|finding| (finding.function(), finding.kind()))
        .collect();
    assert_eq!(
        order,
        vec![
            ("FUN_18003ab00", "mutex"),
            ("FUN_18003ab00", "atomic"),
            ("FUN_18003ab00", "thread"),
        ]
    );
}

// ------------------------------------------------------------
// Consumption
// ------------------------------------------------------------

#[tokio::test]
async fn a_loaded_result_answers_the_pipeline_lookups() {
    let workspace = TempDir::new().unwrap();
    let result = SyncEngine::with_source(program())
        .scan("eqmain.dll")
        .await
        .expect("scan");
    let persistor = SyncPersistor::new(workspace.path());
    persistor.save(&result).expect("save");

    let loaded = persistor.load("eqmain.dll").expect("load");

    // The pipeline asks what was found for the function it is about to
    // translate; the plain function carries nothing.
    let findings: Vec<&SyncFinding> = loaded.for_function("FUN_18003ab00").collect();
    assert_eq!(findings.len(), 3);
    assert!(loaded.for_function("FUN_18003e750").next().is_none());
    assert!(loaded.for_function("FUN_180099999").next().is_none());

    // Each record keeps its detector's detail and evidence through the
    // round trip, so a prompt sees the pairing that produced it.
    let SyncFinding::Mutex(hint) = findings[0] else {
        unreachable!("the lock pair reads as a mutex finding");
    };
    assert_eq!(hint.acquire, "EnterCriticalSection");
    assert_eq!(hint.release, "LeaveCriticalSection");
    assert_eq!(hint.suggestion, "std::sync::Mutex<T>");
    assert!(hint.evidence.contains("EnterCriticalSection(&local_20);"));

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
    assert_eq!(record.suggestion, "std::thread::spawn");
}

#[tokio::test]
async fn a_loaded_result_renders_into_the_escalate_prompt() {
    // The whole escalate path, no external server needed: the fixture
    // document on disk answers the per-function lookup, the findings
    // render into `ConcurrencyInfo` prompt data, and the rendered
    // escalate prompt carries the CONCURRENCY section with each
    // finding's suggestion, kind, confidence, and evidence.
    let workspace = TempDir::new().unwrap();
    let result = SyncEngine::with_source(program())
        .scan("eqmain.dll")
        .await
        .expect("scan");
    let persistor = SyncPersistor::new(workspace.path());
    persistor.save(&result).expect("save");

    let loaded = persistor.load("eqmain.dll").expect("load");
    let findings: Vec<calxgloss_prompts::ConcurrencyInfo> = loaded
        .for_function("FUN_18003ab00")
        .map(calxgloss_prompts::ConcurrencyInfo::from)
        .collect();
    assert_eq!(findings.len(), 3, "the target function's three findings");

    let prompt = calxgloss_prompts::build_escalate_prompt_with_context(
        "FUN_18003ab00".into(),
        "eqmain.dll".into(),
        "fn fun_18003ab00() { /* manual lock and unlock */ }".into(),
        "Wrong result".into(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        findings,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    )
    .expect("the escalate prompt should render");

    assert!(prompt.contains("CONCURRENCY"));
    assert!(prompt.contains("std::sync::Mutex<T>"));
    assert!(prompt.contains("mutex construct, confidence 70"));
    assert!(prompt.contains("std::sync::atomic::AtomicU32"));
    assert!(prompt.contains("atomic construct, confidence 70"));
    assert!(prompt.contains("std::thread::spawn"));
    assert!(prompt.contains("thread construct, confidence 70"));
    assert!(prompt.contains("EnterCriticalSection(&local_20);"));
}

// ------------------------------------------------------------
// TLS findings
// ------------------------------------------------------------

#[tokio::test]
async fn tls_findings_survive_the_scan_persist_and_prompt_walk() {
    // A canned program with one Win32 key created and used in one
    // function, one POSIX key created and used in another, and one
    // lone access whose creation lives out of view.
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
            "  local_4 = TlsAlloc();\n\
             \x20 pvVar1 = TlsSetValue(local_4, pvVar2);\n",
        ),
    );
    program.bodies.insert(
        "FUN_18003e750".into(),
        function(
            "FUN_18003e750",
            "undefined FUN_18003e750(void)",
            "  pvVar1 = pthread_getspecific(key);\n",
        ),
    );
    program.bodies.insert(
        "FUN_180041230".into(),
        function(
            "FUN_180041230",
            "undefined FUN_180041230(void)",
            "  pthread_key_create(&local_8,(code *)0x0);\n\
             \x20 pvVar1 = pthread_getspecific(local_8);\n",
        ),
    );

    let workspace = TempDir::new().unwrap();
    let result = SyncEngine::with_source(program)
        .scan("eqmain.dll")
        .await
        .expect("scan");
    let persistor = SyncPersistor::new(workspace.path());
    persistor.save(&result).expect("save");

    let loaded = persistor.load("eqmain.dll").expect("load");
    let tls: Vec<&SyncFinding> = loaded
        .findings
        .iter()
        .filter(|finding| finding.kind() == "tls")
        .collect();
    assert_eq!(tls.len(), 3, "two pairs and the fragment all surface");

    // The creation and access in one function pair up at 70, Win32 …
    let SyncFinding::Tls(pair) = tls[0] else {
        unreachable!("the key site reads as a tls finding");
    };
    assert_eq!(pair.creation.as_deref(), Some("TlsAlloc"));
    assert_eq!(pair.access, "TlsSetValue");
    assert_eq!(pair.suggestion, "thread_local!");
    assert_eq!(pair.confidence, 70);
    assert!(tls[0].target().contains("TlsSetValue"));

    // … and POSIX the same.
    let SyncFinding::Tls(posix) = tls[2] else {
        unreachable!("the key site reads as a tls finding");
    };
    assert_eq!(posix.function, "FUN_180041230");
    assert_eq!(posix.creation.as_deref(), Some("pthread_key_create"));
    assert_eq!(posix.access, "pthread_getspecific");
    assert_eq!(posix.confidence, 70);

    // The lone access, with no creation in view, is a fragment at 60.
    let SyncFinding::Tls(fragment) = tls[1] else {
        unreachable!("the key access reads as a tls finding");
    };
    assert_eq!(fragment.function, "FUN_18003e750");
    assert_eq!(fragment.creation, None);
    assert_eq!(fragment.access, "pthread_getspecific");
    assert_eq!(fragment.confidence, 60);

    // The escalate prompt describes each finding with its kind and
    // confidence, like every other detector's records.
    let findings: Vec<calxgloss_prompts::ConcurrencyInfo> = loaded
        .findings
        .iter()
        .map(calxgloss_prompts::ConcurrencyInfo::from)
        .collect();
    let prompt = calxgloss_prompts::build_escalate_prompt_with_context(
        "FUN_18003ab00".into(),
        "eqmain.dll".into(),
        "fn fun_18003ab00() { /* manual key allocation and access */ }".into(),
        "Wrong result".into(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        findings,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    )
    .expect("the escalate prompt should render");

    assert!(prompt.contains("CONCURRENCY"));
    assert!(prompt.contains("thread_local!"));
    assert!(prompt.contains("tls construct, confidence 70"));
    assert!(prompt.contains("tls construct, confidence 60"));
    assert!(prompt.contains("local_4 = TlsAlloc();"));
}

// ------------------------------------------------------------
// Cross-function lock-order findings
// ------------------------------------------------------------

#[tokio::test]
async fn lock_order_findings_survive_the_scan_persist_and_prompt_walk() {
    // The deadlock shape across two functions: one takes `local_20`
    // before `local_40`, the other the other way round. The conflict
    // rides the tagged union to disk and back, and renders into the
    // escalate prompt through the usual accessors.
    let mut program = FakeProgram::empty();
    program.listing = vec![summary("FUN_18003ab00"), summary("FUN_18003e750")];
    program.bodies.insert(
        "FUN_18003ab00".into(),
        function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            "  EnterCriticalSection(&local_20);\n\
             \x20 EnterCriticalSection(&local_40);\n\
             \x20 LeaveCriticalSection(&local_40);\n\
             \x20 LeaveCriticalSection(&local_20);\n",
        ),
    );
    program.bodies.insert(
        "FUN_18003e750".into(),
        function(
            "FUN_18003e750",
            "undefined FUN_18003e750(void)",
            "  EnterCriticalSection(&local_40);\n\
             \x20 EnterCriticalSection(&local_20);\n\
             \x20 LeaveCriticalSection(&local_20);\n\
             \x20 LeaveCriticalSection(&local_40);\n",
        ),
    );

    let workspace = TempDir::new().expect("workspace temp dir");
    let result = SyncEngine::with_source(program)
        .scan("eqmain.dll")
        .await
        .expect("scan");
    let persistor = SyncPersistor::new(workspace.path());
    persistor.save(&result).expect("save");

    let loaded = persistor.load("eqmain.dll").expect("load");
    let conflicts: Vec<&SyncFinding> = loaded
        .findings
        .iter()
        .filter(|finding| finding.kind() == "lock_order")
        .collect();
    assert_eq!(conflicts.len(), 1, "one conflict per lock pair");

    // The record keeps both functions and both lock objects through
    // the round trip, at the pairing's own confidence.
    let SyncFinding::LockOrder(record) = conflicts[0] else {
        unreachable!("the reversed orders read as a lock-order finding");
    };
    assert_eq!(record.function, "FUN_18003ab00");
    assert_eq!(record.partner, "FUN_18003e750");
    assert_eq!(record.first_lock, "local_20");
    assert_eq!(record.second_lock, "local_40");
    assert_eq!(record.confidence, 70);
    assert_eq!(
        record.evidence,
        "FUN_18003ab00: local_20 -> local_40; FUN_18003e750: local_40 -> local_20"
    );
    assert!(conflicts[0].target().contains("local_20"));

    // The cross-function finding lands after the per-function
    // findings, so the persisted document stays diffable.
    let order: Vec<(&str, &str)> = loaded
        .findings
        .iter()
        .map(|finding| (finding.function(), finding.kind()))
        .collect();
    assert_eq!(
        order,
        vec![
            ("FUN_18003ab00", "mutex"),
            ("FUN_18003ab00", "mutex"),
            ("FUN_18003e750", "mutex"),
            ("FUN_18003e750", "mutex"),
            ("FUN_18003ab00", "lock_order"),
        ]
    );

    // The escalate prompt describes the conflict with its kind and
    // confidence, like every other detector's records.
    let findings: Vec<calxgloss_prompts::ConcurrencyInfo> = loaded
        .findings
        .iter()
        .map(calxgloss_prompts::ConcurrencyInfo::from)
        .collect();
    let prompt = calxgloss_prompts::build_escalate_prompt_with_context(
        "FUN_18003ab00".into(),
        "eqmain.dll".into(),
        "fn fun_18003ab00() { /* two nested critical sections */ }".into(),
        "Wrong result".into(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        findings,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    )
    .expect("the escalate prompt should render");

    assert!(prompt.contains("CONCURRENCY"));
    assert!(prompt.contains("pick one consistent lock acquisition order"));
    assert!(prompt.contains("lock_order construct, confidence 70"));
    assert!(prompt.contains("FUN_18003e750: local_40 -> local_20"));
}

// ------------------------------------------------------------
// Data-race findings
// ------------------------------------------------------------

#[tokio::test]
async fn data_race_findings_survive_the_scan_persist_and_prompt_walk() {
    // The unsynchronized-global shape across two functions: one
    // stores into `DAT_counter` under no lock, the other reads it
    // under a lock of its own — neither side holds a lock the other
    // respects. The race rides the tagged union to disk and back, and
    // renders into the escalate prompt through the usual accessors.
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
            "  EnterCriticalSection(&local_20);\n\
             \x20 uVar1 = DAT_counter;\n\
             \x20 LeaveCriticalSection(&local_20);\n",
        ),
    );

    let workspace = TempDir::new().expect("workspace temp dir");
    let result = SyncEngine::with_source(program)
        .scan("eqmain.dll")
        .await
        .expect("scan");
    let persistor = SyncPersistor::new(workspace.path());
    persistor.save(&result).expect("save");

    let loaded = persistor.load("eqmain.dll").expect("load");
    let races: Vec<&SyncFinding> = loaded
        .findings
        .iter()
        .filter(|finding| finding.kind() == "data_race")
        .collect();
    assert_eq!(races.len(), 1, "one race per function pair and global");

    // The record keeps both functions and the shared variable through
    // the round trip, one rung below the evidence-based kinds.
    let SyncFinding::DataRace(record) = races[0] else {
        unreachable!("the shared global reads as a data race");
    };
    assert_eq!(record.function, "FUN_18003ab00");
    assert_eq!(record.partner, "FUN_18003e750");
    assert_eq!(record.variable, "DAT_counter");
    assert_eq!(record.confidence, 60);
    assert_eq!(
        record.evidence,
        "FUN_18003ab00: DAT_counter = iVar1 + 1; FUN_18003e750: uVar1 = DAT_counter;"
    );
    assert!(races[0].target().contains("DAT_counter"));

    // The cross-function finding lands after the per-function
    // findings, so the persisted document stays diffable.
    let order: Vec<(&str, &str)> = loaded
        .findings
        .iter()
        .map(|finding| (finding.function(), finding.kind()))
        .collect();
    assert_eq!(
        order,
        vec![("FUN_18003e750", "mutex"), ("FUN_18003ab00", "data_race"),]
    );

    // The escalate prompt describes the race with its kind and
    // confidence, like every other detector's records.
    let findings: Vec<calxgloss_prompts::ConcurrencyInfo> = loaded
        .findings
        .iter()
        .map(calxgloss_prompts::ConcurrencyInfo::from)
        .collect();
    let prompt = calxgloss_prompts::build_escalate_prompt_with_context(
        "FUN_18003ab00".into(),
        "eqmain.dll".into(),
        "fn fun_18003ab00() { /* reads and writes a shared counter */ }".into(),
        "Wrong result".into(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        findings,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    )
    .expect("the escalate prompt should render");

    assert!(prompt.contains("CONCURRENCY"));
    assert!(prompt.contains("guard the shared global with one lock held by both functions"));
    assert!(prompt.contains("data_race construct, confidence 60"));
    assert!(prompt.contains("FUN_18003ab00: DAT_counter = iVar1 + 1"));
}

// ------------------------------------------------------------
// Cache behavior
// ------------------------------------------------------------

#[tokio::test]
async fn a_rescan_replaces_the_cached_document() {
    let workspace = TempDir::new().unwrap();
    let persistor = SyncPersistor::new(workspace.path());

    let first = SyncEngine::with_source(program())
        .scan("eqmain.dll")
        .await
        .expect("first scan");
    persistor.save(&first).expect("save");

    // A second scan of a program whose only function carries no shape
    // replaces the document: the cache check still passes, but the
    // findings are gone.
    let mut quiet = FakeProgram::empty();
    quiet.listing = vec![summary("FUN_18003e750")];
    quiet.bodies.insert(
        "FUN_18003e750".into(),
        function(
            "FUN_18003e750",
            "undefined FUN_18003e750(void)",
            "  return;\n",
        ),
    );
    let second = SyncEngine::with_source(quiet)
        .scan("eqmain.dll")
        .await
        .expect("second scan");
    persistor.save(&second).expect("save");

    let loaded = persistor.load("eqmain.dll").expect("load");
    assert_eq!(loaded, second);
    assert!(loaded.is_empty());
    assert_ne!(loaded, first);
}

#[tokio::test]
async fn results_for_two_binaries_stay_independent() {
    let workspace = TempDir::new().unwrap();
    let persistor = SyncPersistor::new(workspace.path());

    let eqmain = SyncEngine::with_source(program())
        .scan("eqmain.dll")
        .await
        .expect("scan");
    persistor.save(&eqmain).expect("save");

    let mut other = FakeProgram::empty();
    other.listing = vec![summary("FUN_18003e750")];
    other.bodies.insert(
        "FUN_18003e750".into(),
        function(
            "FUN_18003e750",
            "undefined FUN_18003e750(void)",
            "  EnterCriticalSection(&local_20);\n\
             \x20 LeaveCriticalSection(&local_20);\n",
        ),
    );
    let eqgame = SyncEngine::with_source(other)
        .scan("eqgame.dll")
        .await
        .expect("scan");
    persistor.save(&eqgame).expect("save");

    assert_eq!(persistor.load("eqmain.dll").unwrap(), eqmain);
    assert_eq!(persistor.load("eqgame.dll").unwrap(), eqgame);
    assert!(!persistor.exists("other.dll"));
}
