//! Integration tests for the calxgloss-apidetect crate.
//!
//! These tests exercise the multi-module workflows the unit tests cannot
//! cover on their own:
//!
//! - **Scan to disk** — [`ApiEngine`] scans a canned program, the
//!   [`ApiPersistor`] files the result in the workspace layout, and
//!   loading it back yields the same result the scan returned.
//! - **Consumption** — the loaded result answers the lookups a
//!   translation pipeline makes (the usages recorded for one function),
//!   and the persisted list keeps every finding in scan order: import
//!   entries in listing order, then usages function by function in call
//!   graph order.
//! - **Prompt rendering** — the loaded findings render into `ApiInfo`
//!   prompt data and the escalate prompt carries the LIBRARIES AND APIS
//!   section.
//! - **Cache behavior** — the `exists` check decides whether a scan
//!   runs, and a rescan replaces the cached document.
//!
//! The fake program implements [`ApiSource`], so the whole flow runs
//! without a Ghidra server.

use calxgloss_apidetect::Result;
use calxgloss_apidetect::engine::{ApiEngine, ApiSource};
use calxgloss_apidetect::persist::ApiPersistor;
use calxgloss_apidetect::types::ApiFinding;
use calxgloss_callgraph::{CallGraphEdge, CallType, FunctionCallGraph};
use calxgloss_ghidra::Symbol;
use tempfile::TempDir;

// ------------------------------------------------------------
// The canned program
// ------------------------------------------------------------

fn import(name: &str) -> Symbol {
    Symbol {
        name: name.to_string(),
        address: 0,
        imported: true,
    }
}

fn node(name: &str, address: u64, callees: Vec<(&str, u64)>) -> FunctionCallGraph {
    FunctionCallGraph {
        name: name.to_string(),
        address,
        callers: Vec::new(),
        callees: callees
            .into_iter()
            .map(|(callee_name, target)| CallGraphEdge {
                source: address,
                target,
                call_site: 0,
                call_type: CallType::Direct,
                callee_name: callee_name.to_string(),
            })
            .collect(),
        node_category: calxgloss_types::NodeCategory::Middle,
    }
}

/// A canned program implementing [`ApiSource`]: imports covering an
/// identified zlib call, an identified Win32 call, and an unidentified
/// vendor function, and a call graph where `FUN_18003ab00` calls
/// `inflate` directly and reaches `CreateFileA` through
/// `FUN_18003c000` — one direct and one transitive usage — while
/// `FUN_18003e750` calls nothing.
#[derive(Clone, Default)]
struct FakeProgram {
    imports: Vec<Symbol>,
    graph: Vec<FunctionCallGraph>,
}

impl ApiSource for FakeProgram {
    async fn imports(&self) -> Result<Vec<Symbol>> {
        Ok(self.imports.clone())
    }

    async fn call_graph(&self, _binary: &str) -> Result<Vec<FunctionCallGraph>> {
        Ok(self.graph.clone())
    }
}

fn program() -> FakeProgram {
    FakeProgram {
        imports: vec![
            import("inflate"),
            import("CreateFileA"),
            import("VendorSpecialFunction"),
        ],
        graph: vec![
            node(
                "FUN_18003ab00",
                0x1800_3ab00,
                vec![("inflate", 0), ("FUN_18003c000", 0x1800_3c000)],
            ),
            node("FUN_18003c000", 0x1800_3c000, vec![("CreateFileA", 0)]),
            node("FUN_18003e750", 0x1800_3e750, Vec::new()),
        ],
    }
}

// ------------------------------------------------------------
// Scan to disk
// ------------------------------------------------------------

#[tokio::test]
async fn a_scan_files_its_result_in_the_workspace_and_reads_back() {
    let workspace = TempDir::new().unwrap();
    let result = ApiEngine::with_source(program())
        .scan("eqmain.dll")
        .await
        .expect("scan");

    let persistor = ApiPersistor::new(workspace.path());
    assert!(!persistor.exists("eqmain.dll"), "nothing is cached yet");

    persistor.save(&result).expect("save");
    assert!(persistor.exists("eqmain.dll"));
    assert_eq!(
        persistor.path_for("eqmain.dll"),
        workspace
            .path()
            .join("re/analysis/apidetect/eqmain.dll.json")
    );

    let loaded = persistor.load("eqmain.dll").expect("load");
    assert_eq!(loaded, result, "the document round-trips exactly");
}

#[tokio::test]
async fn the_persisted_document_keeps_findings_in_scan_order() {
    // Imports first, in listing order — identified and unidentified
    // alike — then usages function by function in call graph order,
    // direct before transitive: the order two scans diff against.
    let workspace = TempDir::new().unwrap();
    let result = ApiEngine::with_source(program())
        .scan("eqmain.dll")
        .await
        .expect("scan");
    let persistor = ApiPersistor::new(workspace.path());
    persistor.save(&result).expect("save");

    let loaded = persistor.load("eqmain.dll").expect("load");
    let order: Vec<(&str, &str, &str)> = loaded
        .findings
        .iter()
        .map(|finding| (finding.kind(), finding.function(), finding.target()))
        .collect();
    assert_eq!(
        order,
        vec![
            ("import", "", "inflate"),
            ("import", "", "CreateFileA"),
            ("import", "", "VendorSpecialFunction"),
            ("api_usage", "FUN_18003ab00", "inflate"),
            ("api_usage", "FUN_18003ab00", "CreateFileA"),
            ("api_usage", "FUN_18003c000", "CreateFileA"),
        ]
    );
}

// ------------------------------------------------------------
// Consumption
// ------------------------------------------------------------

#[tokio::test]
async fn a_loaded_result_answers_the_pipeline_lookups() {
    let workspace = TempDir::new().unwrap();
    let result = ApiEngine::with_source(program())
        .scan("eqmain.dll")
        .await
        .expect("scan");
    let persistor = ApiPersistor::new(workspace.path());
    persistor.save(&result).expect("save");

    let loaded = persistor.load("eqmain.dll").expect("load");

    // The pipeline asks what was found for the function it is about to
    // translate; the plain function and the unknown function carry
    // nothing, and import entries belong to the binary, not to any
    // function.
    let findings: Vec<&ApiFinding> = loaded.for_function("FUN_18003ab00").collect();
    assert_eq!(findings.len(), 2);
    assert!(loaded.for_function("FUN_18003e750").next().is_none());
    assert!(loaded.for_function("FUN_180099999").next().is_none());

    // Each record keeps its detector's detail and evidence through the
    // round trip, so a prompt sees the call path that produced it.
    let ApiFinding::ApiUsage(direct) = findings[0] else {
        unreachable!("the direct call reads as a usage finding");
    };
    assert_eq!(direct.api, "inflate");
    assert_eq!(direct.library, "zlib");
    assert_eq!(direct.rust_crate, "flate2");
    assert!(direct.direct);
    assert_eq!(direct.evidence, "FUN_18003ab00 → inflate");

    let ApiFinding::ApiUsage(transitive) = findings[1] else {
        unreachable!("the helper call reads as a usage finding");
    };
    assert_eq!(transitive.api, "CreateFileA");
    assert_eq!(transitive.library, "Win32");
    assert_eq!(transitive.rust_crate, "windows / std::fs");
    assert!(!transitive.direct);
    assert_eq!(
        transitive.evidence,
        "FUN_18003ab00 → FUN_18003c000 → CreateFileA"
    );
}

#[tokio::test]
async fn a_loaded_result_renders_into_the_escalate_prompt() {
    // The whole escalate path, no Ghidra server needed: the fixture
    // document on disk answers the per-function lookup, the findings
    // render into `ApiInfo` prompt data, and the rendered escalate
    // prompt carries the LIBRARIES AND APIS section with each
    // finding's suggestion, library, kind, confidence, and evidence.
    let workspace = TempDir::new().unwrap();
    let result = ApiEngine::with_source(program())
        .scan("eqmain.dll")
        .await
        .expect("scan");
    let persistor = ApiPersistor::new(workspace.path());
    persistor.save(&result).expect("save");

    let loaded = persistor.load("eqmain.dll").expect("load");
    let mut findings: Vec<calxgloss_prompts::ApiInfo> = loaded
        .findings
        .iter()
        .map(calxgloss_prompts::ApiInfo::from)
        .collect();
    findings.retain(|info| info.function == "FUN_18003ab00");
    assert_eq!(findings.len(), 2, "the target function's two usages");

    let prompt = calxgloss_prompts::build_escalate_prompt_with_context(
        "FUN_18003ab00".into(),
        "eqmain.dll".into(),
        "fn fun_18003ab00() { /* raw imports */ }".into(),
        "Wrong result".into(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
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
    )
    .expect("the escalate prompt should render");

    assert!(prompt.contains("LIBRARIES AND APIS"));
    assert!(prompt.contains("flate2"));
    assert!(prompt.contains("`inflate`"));
    assert!(prompt.contains("zlib direct, confidence 80"));
    assert!(prompt.contains("windows / std::fs"));
    assert!(prompt.contains("Win32 transitive, confidence 60"));
    assert!(prompt.contains("FUN_18003ab00 → FUN_18003c000 → CreateFileA"));
}

// ------------------------------------------------------------
// Cache behavior
// ------------------------------------------------------------

#[tokio::test]
async fn a_rescan_replaces_the_cached_document() {
    let workspace = TempDir::new().unwrap();
    let persistor = ApiPersistor::new(workspace.path());

    let first = ApiEngine::with_source(program())
        .scan("eqmain.dll")
        .await
        .expect("first scan");
    persistor.save(&first).expect("save");

    // A second scan of a program with no imports at all replaces the
    // document: the cache check still passes, but the findings are gone.
    let second = ApiEngine::with_source(FakeProgram::default())
        .scan("eqmain.dll")
        .await
        .expect("second scan");
    persistor.save(&second).expect("save");

    let loaded = persistor.load("eqmain.dll").expect("load");
    assert_eq!(loaded, second);
    assert!(loaded.findings.is_empty());
    assert_ne!(loaded, first);
}

#[tokio::test]
async fn results_for_two_binaries_stay_independent() {
    let workspace = TempDir::new().unwrap();
    let persistor = ApiPersistor::new(workspace.path());

    let eqmain = ApiEngine::with_source(program())
        .scan("eqmain.dll")
        .await
        .expect("scan");
    persistor.save(&eqmain).expect("save");

    let other = FakeProgram {
        imports: vec![import("SDL_Init")],
        graph: vec![node("FUN_140012340", 0x1400_12340, vec![("SDL_Init", 0)])],
    };
    let eqgame = ApiEngine::with_source(other)
        .scan("eqgame.dll")
        .await
        .expect("scan");
    persistor.save(&eqgame).expect("save");

    assert_eq!(persistor.load("eqmain.dll").unwrap(), eqmain);
    assert_eq!(persistor.load("eqgame.dll").unwrap(), eqgame);
    assert!(!persistor.exists("other.dll"));
}
