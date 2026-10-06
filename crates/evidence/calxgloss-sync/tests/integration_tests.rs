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
//!   pairings, then the atomic calls, then the thread spawns.
//! - **Prompt rendering** — the loaded findings render into
//!   `ConcurrencyInfo` prompt data and the escalate prompt carries
//!   the CONCURRENCY section.
//! - **Cache behavior** — the `exists` check decides whether a scan
//!   runs, and a rescan replaces the cached document.
//!
//! The fake program implements [`ScanSource`], so the whole flow runs
//! without a Ghidra server.

use std::collections::HashMap;

use calxgloss_ghidra::{DecompiledFunction, FunctionSummary};
use calxgloss_sync::Result;
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
        self.bodies.get(name).cloned().ok_or_else(|| {
            calxgloss_ghidra::GhidraError::NotFound {
                kind: "function",
                query: name.to_string(),
            }
            .into()
        })
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
    // The three detectors read disjoint shapes in one pass, so what
    // reaches disk is function by function in listing order and, within
    // one function, mutex then atomic then thread — the order two scans
    // diff against.
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
    // The whole escalate path, no Ghidra server needed: the fixture
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
