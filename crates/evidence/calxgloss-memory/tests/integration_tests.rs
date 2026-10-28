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
//! - **Cross-function claims** — the cross-function pass's release,
//!   hand-off, and leak claims are persisted in the document like every
//!   other kind of finding, appended after the per-function findings in
//!   order.
//! - **Cache behavior** — the `exists` check decides whether a scan
//!   runs, and a rescan replaces the cached document.
//!
//! The fake program implements [`ScanSource`], so the whole flow runs
//! without an external server.

use std::collections::HashMap;

use calxgloss_decomp::{
    DataItem, DataTypeEntry, DecompiledFunction, EngineError, EnumDefinition, FunctionSummary,
    Result, StringLiteral, StructLayout, Symbol, Xref,
};
use calxgloss_memory::engine::{MemoryEngine, ScanSource};
use calxgloss_memory::persist::MemoryPersistor;
use calxgloss_memory::types::{
    AllocationType, CountStyle, HandleType, LeakResource, MemoryFinding, TransferDirection,
};
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
    // The three detectors read disjoint shapes in one pass. So what
    // reaches disk is function by function in listing order, and
    // within one function allocation, then handle, then ref_count.
    // This is the order two scans diff against.
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
// Cross-function claims
// ------------------------------------------------------------

/// A canned program for the cross-function pass. One function makes
/// three allocations: one a callee inside the scanned set releases,
/// one is handed to a function outside the scanned set, and one is
/// never touched again. The releasing callee itself stands in the
/// function listing.
fn cross_program() -> FakeProgram {
    let mut program = FakeProgram::empty();
    program.listing = vec![summary("FUN_18003ab00"), summary("FUN_18004b210")];
    program.bodies.insert(
        "FUN_18003ab00".into(),
        function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            "  pvVar1 = malloc(0x20);\n\
             \x20 FUN_18004b210(pvVar1);\n\
             \x20 pvVar2 = malloc(0x30);\n\
             \x20 FUN_180099999(pvVar2);\n\
             \x20 pvVar3 = malloc(0x40);\n\
             \x20 *(int *)pvVar3 = 5;\n",
        ),
    );
    program.bodies.insert(
        "FUN_18004b210".into(),
        function(
            "FUN_18004b210",
            "undefined FUN_18004b210(void *param_1)",
            "  free(param_1);\n",
        ),
    );
    program
}

#[tokio::test]
async fn cross_function_claims_ride_the_persisted_document() {
    // The pass's three readings — a scanned callee's release, a hand-off
    // to an unscanned function, and an allocation that never leaves —
    // go from scan to disk and back like every other kind of finding:
    // appended after the per-function findings in listing order, and
    // within one function in allocation order.
    let workspace = TempDir::new().unwrap();
    let result = MemoryEngine::with_source(cross_program())
        .scan("eqmain.dll")
        .await
        .expect("scan");
    let persistor = MemoryPersistor::new(workspace.path());
    persistor.save(&result).expect("save");

    let loaded = persistor.load("eqmain.dll").expect("load");
    assert_eq!(loaded, result, "the document round-trips exactly");
    let order: Vec<(&str, &str)> = loaded
        .findings
        .iter()
        .map(|finding| (finding.function(), finding.kind()))
        .collect();
    assert_eq!(
        order,
        vec![
            ("FUN_18003ab00", "cross_function"),
            ("FUN_18003ab00", "ownership"),
            ("FUN_18003ab00", "leak"),
        ]
    );

    // Each record keeps its claim's detail through the round trip.
    let MemoryFinding::CrossFunction(lifecycle) = &loaded.findings[0] else {
        unreachable!("the scanned release reads as a cross-function finding");
    };
    assert_eq!(lifecycle.partner, "FUN_18004b210");
    assert_eq!(lifecycle.variable, "pvVar1");
    assert_eq!(lifecycle.suggestion, "Box<T>");
    assert_eq!(lifecycle.confidence, 70);

    let MemoryFinding::Ownership(transfer) = &loaded.findings[1] else {
        unreachable!("the hand-off to an unscanned function reads as an ownership finding");
    };
    assert_eq!(transfer.direction, TransferDirection::HandedToCallee);
    assert_eq!(transfer.partner.as_deref(), Some("FUN_180099999"));
    assert_eq!(transfer.variable, "pvVar2");
    assert_eq!(transfer.confidence, 65);

    let MemoryFinding::Leak(leak) = &loaded.findings[2] else {
        unreachable!("the untouched allocation reads as a leak finding");
    };
    assert_eq!(leak.variable, "pvVar3");
    assert_eq!(
        leak.resource,
        LeakResource::Allocation {
            allocation_type: AllocationType::Malloc,
        }
    );
    assert_eq!(leak.confidence, 60);
    assert!(
        leak.evidence.contains("pvVar3 = malloc(0x40);"),
        "the acquisition line is a leak's only positive evidence"
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
    // The whole escalate path, with no external server needed. The
    // fixture document on disk answers the per-function lookup, the
    // findings render into `MemoryInfo` prompt data, and the rendered
    // escalate prompt carries the MEMORY LIFECYCLE section with each
    // finding's suggestion, kind, evidence confidence, and evidence.
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
        calxgloss_prompts::EvidenceBundle {
            memory_findings: findings,
            ..Default::default()
        },
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
