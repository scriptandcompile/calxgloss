//! Integration tests for the calxgloss-memory crate.
//!
//! These tests exercise the multi-module workflows the unit tests cannot
//! cover on their own:
//!
//! - **Scan to disk** — [`MemoryEngine`] scans a canned program, the
//!   [`MemoryPersistor`] files the result in the workspace layout, and
//!   loading it back yields the same result the scan returned.
//! - **Consumption** — the loaded result answers the lookups a
//!   translation pipeline makes (the findings recorded for one
//!   function), and the persisted list keeps every finding in scan
//!   order: function by function, and within one function the
//!   allocation pairs, then the handle lifetimes, then the reference
//!   counts.
//! - **Cache behavior** — the `exists` check decides whether a scan
//!   runs, and a rescan replaces the cached document.
//!
//! The fake program implements [`ScanSource`], so the whole flow runs
//! without a Ghidra server.

use std::collections::HashMap;

use calxgloss_ghidra::{DecompiledFunction, FunctionSummary};
use calxgloss_memory::Result;
use calxgloss_memory::engine::{MemoryEngine, ScanSource};
use calxgloss_memory::persist::MemoryPersistor;
use calxgloss_memory::types::{AllocationType, CountStyle, HandleType, MemoryFinding};
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
/// carries a `malloc`/`free` pair, a `CreateFileW`/`CloseHandle` pair,
/// and an `AddRef`/`Release` pair — one finding family per detector —
/// and one plain function that finds nothing.
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
            "undefined FUN_18003ab00(IUnknown *param_1)",
            "  pvVar1 = malloc(0x20);\n\
             \x20 *(int *)pvVar1 = 5;\n\
             \x20 free(pvVar1);\n\
             \x20 hFile = CreateFileW(&DAT_3801a2b0,0xc0000000,0,(LPSECURITY_ATTRIBUTES)0x0,3,0x80,0);\n\
             \x20 CloseHandle(hFile);\n\
             \x20 AddRef((IUnknown *)param_1);\n\
             \x20 Release((IUnknown *)param_1);\n",
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
    let result = MemoryEngine::with_source(program())
        .scan("eqmain.dll")
        .await
        .expect("scan");

    let persistor = MemoryPersistor::new(workspace.path());
    assert!(!persistor.exists("eqmain.dll"), "nothing is cached yet");

    persistor.save(&result).expect("save");
    assert!(persistor.exists("eqmain.dll"));
    assert_eq!(
        persistor.path_for("eqmain.dll"),
        workspace.path().join("re/analysis/memory/eqmain.dll.json")
    );

    let loaded = persistor.load("eqmain.dll").expect("load");
    assert_eq!(loaded, result, "the document round-trips exactly");
}

#[tokio::test]
async fn the_persisted_document_keeps_findings_in_scan_order() {
    // The three detectors read disjoint shapes in one pass, so what
    // reaches disk is function by function in listing order and, within
    // one function, allocation then handle then ref_count — the order
    // two scans diff against.
    let workspace = TempDir::new().unwrap();
    let result = MemoryEngine::with_source(program())
        .scan("eqmain.dll")
        .await
        .expect("scan");
    let persistor = MemoryPersistor::new(workspace.path());
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
            ("FUN_18003ab00", "allocation"),
            ("FUN_18003ab00", "handle"),
            ("FUN_18003ab00", "ref_count"),
        ]
    );
}

// ------------------------------------------------------------
// Consumption
// ------------------------------------------------------------

#[tokio::test]
async fn a_loaded_result_answers_the_pipeline_lookups() {
    let workspace = TempDir::new().unwrap();
    let result = MemoryEngine::with_source(program())
        .scan("eqmain.dll")
        .await
        .expect("scan");
    let persistor = MemoryPersistor::new(workspace.path());
    persistor.save(&result).expect("save");

    let loaded = persistor.load("eqmain.dll").expect("load");

    // The pipeline asks what was found for the function it is about to
    // translate; the plain function carries nothing.
    let findings: Vec<&MemoryFinding> = loaded.for_function("FUN_18003ab00").collect();
    assert_eq!(findings.len(), 3);
    assert!(loaded.for_function("FUN_18003e750").next().is_none());
    assert!(loaded.for_function("FUN_180099999").next().is_none());

    // Each record keeps its detector's detail and evidence through the
    // round trip, so a prompt sees the pairing that produced it.
    let MemoryFinding::Allocation(hint) = findings[0] else {
        unreachable!("the allocation pair reads as an allocation finding");
    };
    assert_eq!(hint.allocation_type, AllocationType::Malloc);
    assert_eq!(hint.suggestion, "stack allocation");
    assert_eq!(hint.evidence, "pvVar1 = malloc(0x20); free(pvVar1);");

    let MemoryFinding::Handle(record) = findings[1] else {
        unreachable!("the handle pair reads as a handle finding");
    };
    assert_eq!(record.handle_type, HandleType::KernelObject);
    assert_eq!(record.suggestion, "RAII guard struct with Drop impl");

    let MemoryFinding::RefCount(record) = findings[2] else {
        unreachable!("the bump and drop read as a reference-count finding");
    };
    assert_eq!(record.style, CountStyle::ComMethods);
    assert_eq!(record.suggestion, "Rc<T>");
}

#[tokio::test]
async fn a_loaded_result_renders_into_the_escalate_prompt() {
    // The whole escalate path, no Ghidra server needed: the fixture
    // document on disk answers the per-function lookup, the findings
    // render into `MemoryInfo` prompt data, and the rendered escalate
    // prompt carries the MEMORY LIFECYCLE section with each finding's
    // suggestion, kind, confidence, and evidence.
    let workspace = TempDir::new().unwrap();
    let result = MemoryEngine::with_source(program())
        .scan("eqmain.dll")
        .await
        .expect("scan");
    let persistor = MemoryPersistor::new(workspace.path());
    persistor.save(&result).expect("save");

    let loaded = persistor.load("eqmain.dll").expect("load");
    let findings: Vec<calxgloss_prompts::MemoryInfo> = loaded
        .for_function("FUN_18003ab00")
        .map(calxgloss_prompts::MemoryInfo::from)
        .collect();
    assert_eq!(findings.len(), 3, "the target function's three findings");

    let prompt = calxgloss_prompts::build_escalate_prompt_with_context(
        "FUN_18003ab00".into(),
        "eqmain.dll".into(),
        "fn fun_18003ab00() { /* manual open/close */ }".into(),
        "Wrong result".into(),
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

    assert!(prompt.contains("MEMORY LIFECYCLE"));
    assert!(prompt.contains("stack allocation"));
    assert!(prompt.contains("allocation lifecycle, confidence 65"));
    assert!(prompt.contains("RAII guard struct with Drop impl"));
    assert!(prompt.contains("handle lifecycle, confidence 70"));
    assert!(prompt.contains("Rc<T>"));
    assert!(prompt.contains("ref_count lifecycle, confidence 70"));
    assert!(prompt.contains("pvVar1 = malloc(0x20); free(pvVar1);"));
}

// ------------------------------------------------------------
// Cache behavior
// ------------------------------------------------------------

#[tokio::test]
async fn a_rescan_replaces_the_cached_document() {
    let workspace = TempDir::new().unwrap();
    let persistor = MemoryPersistor::new(workspace.path());

    let first = MemoryEngine::with_source(program())
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
    let second = MemoryEngine::with_source(quiet)
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
    let persistor = MemoryPersistor::new(workspace.path());

    let eqmain = MemoryEngine::with_source(program())
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
            "  pvVar1 = malloc(0x20);\n  free(pvVar1);\n",
        ),
    );
    let eqgame = MemoryEngine::with_source(other)
        .scan("eqgame.dll")
        .await
        .expect("scan");
    persistor.save(&eqgame).expect("save");

    assert_eq!(persistor.load("eqmain.dll").unwrap(), eqmain);
    assert_eq!(persistor.load("eqgame.dll").unwrap(), eqgame);
    assert!(!persistor.exists("other.dll"));
}
