//! Integration tests for the calxgloss-callback crate.
//!
//! These tests exercise the multi-module workflows the unit tests cannot
//! cover on their own:
//!
//! - **Scan to disk** — [`CallbackEngine`] scans a canned program, the
//!   [`CallbackPersistor`] files the result in the workspace layout, and
//!   loading it back yields the same result the scan returned.
//! - **Consumption** — the loaded result answers the lookups a
//!   translation pipeline makes (the findings recorded for one
//!   function), and the persisted list keeps every finding in scan
//!   order: function by function, and within one function the
//!   function-pointer array calls, then the registrations, then the
//!   jump tables.
//! - **Cache behavior** — the `exists` check decides whether a scan
//!   runs, and a rescan replaces the cached document.
//!
//! The fake program implements [`ScanSource`], so the whole flow runs
//! without a Ghidra server.

use std::collections::HashMap;

use calxgloss_callback::Result;
use calxgloss_callback::engine::{CallbackEngine, ScanSource};
use calxgloss_callback::persist::CallbackPersistor;
use calxgloss_callback::types::CallbackFinding;
use calxgloss_ghidra::{DecompiledFunction, FunctionSummary};
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

/// A canned program implementing [`ScanSource`]: one function whose
/// body carries a cast-dereference call through `handlers`, a bare
/// indexed call through `dispatch`, a `register_callback` call, and a
/// bounds-checked switch-table dispatch, and one plain function that
/// finds nothing.
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
            "  (*(int (**)(int))handlers[uVar1])(param_1);\n\
             \x20 dispatch[uVar2](param_2);\n\
             \x20 register_callback(my_handler);\n\
             \x20 if (uVar3 < 6) {\n\
             \x20   (*(code *)(&switchdataD_1800412a0)[uVar3])();\n\
             \x20 }\n",
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
    let result = CallbackEngine::with_source(program())
        .scan("eqmain.dll")
        .await
        .expect("scan");

    let persistor = CallbackPersistor::new(workspace.path());
    assert!(!persistor.exists("eqmain.dll"), "nothing is cached yet");

    persistor.save(&result).expect("save");
    assert!(persistor.exists("eqmain.dll"));
    assert_eq!(
        persistor.path_for("eqmain.dll"),
        workspace
            .path()
            .join("re/analysis/callback/eqmain.dll.json")
    );

    let loaded = persistor.load("eqmain.dll").expect("load");
    assert_eq!(loaded, result, "the document round-trips exactly");
}

#[tokio::test]
async fn the_persisted_document_keeps_findings_in_scan_order() {
    // The detectors read disjoint shapes in one pass, so what reaches
    // disk is function by function in listing order and, within one
    // function, the call order the body carries — the order two scans
    // diff against.
    let workspace = TempDir::new().unwrap();
    let result = CallbackEngine::with_source(program())
        .scan("eqmain.dll")
        .await
        .expect("scan");
    let persistor = CallbackPersistor::new(workspace.path());
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
            ("FUN_18003ab00", "fp_array"),
            ("FUN_18003ab00", "fp_array"),
            ("FUN_18003ab00", "registration"),
            ("FUN_18003ab00", "jump_table"),
        ]
    );
}

// ------------------------------------------------------------
// Consumption
// ------------------------------------------------------------

#[tokio::test]
async fn a_loaded_result_answers_the_pipeline_lookups() {
    let workspace = TempDir::new().unwrap();
    let result = CallbackEngine::with_source(program())
        .scan("eqmain.dll")
        .await
        .expect("scan");
    let persistor = CallbackPersistor::new(workspace.path());
    persistor.save(&result).expect("save");

    let loaded = persistor.load("eqmain.dll").expect("load");

    // The pipeline asks what was found for the function it is about to
    // translate; the plain function carries nothing.
    let findings: Vec<&CallbackFinding> = loaded.for_function("FUN_18003ab00").collect();
    assert_eq!(findings.len(), 4);
    assert!(loaded.for_function("FUN_18003e750").next().is_none());
    assert!(loaded.for_function("FUN_180099999").next().is_none());

    // Each record keeps its detector's detail and evidence through the
    // round trip, so a prompt sees the call that produced it.
    let CallbackFinding::FpArray(record) = findings[0] else {
        unreachable!("the cast-dereference call reads as an fp-array finding");
    };
    assert_eq!(record.table, "handlers");
    assert_eq!(record.suggestion, "Vec<Box<dyn Fn(...)>>");
    assert!(
        record
            .evidence
            .contains("(*(int (**)(int))handlers[uVar1])(param_1);")
    );

    let CallbackFinding::FpArray(record) = findings[1] else {
        unreachable!("the bare indexed call reads as an fp-array finding");
    };
    assert_eq!(record.table, "dispatch");
    assert_eq!(record.confidence.value(), 70);

    let CallbackFinding::Registration(record) = findings[2] else {
        unreachable!("the registration call reads as a registration finding");
    };
    assert_eq!(record.registration, "register_callback");
    assert_eq!(record.callback, "my_handler");
    assert_eq!(record.suggestion, "Box<dyn Fn(...)>");
    assert!(record.evidence.contains("register_callback(my_handler);"));

    let CallbackFinding::JumpTable(record) = findings[3] else {
        unreachable!("the switch-table dispatch reads as a jump-table finding");
    };
    assert_eq!(record.table, "switchdataD_1800412a0");
    assert_eq!(record.index, "uVar3");
    assert_eq!(record.target_count, Some(6));
    assert_eq!(record.suggestion, "match index { /* 6 arms */ }");
    assert_eq!(record.confidence.value(), 70);
    assert!(
        record
            .evidence
            .contains("(*(code *)(&switchdataD_1800412a0)[uVar3])();")
    );
}

// ------------------------------------------------------------
// Cache behavior
// ------------------------------------------------------------

#[tokio::test]
async fn a_rescan_replaces_the_cached_document() {
    let workspace = TempDir::new().unwrap();
    let persistor = CallbackPersistor::new(workspace.path());

    let first = CallbackEngine::with_source(program())
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
    let second = CallbackEngine::with_source(quiet)
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
    let persistor = CallbackPersistor::new(workspace.path());

    let eqmain = CallbackEngine::with_source(program())
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
            "  (*callbacks[uVar1])(param_1);\n",
        ),
    );
    let eqgame = CallbackEngine::with_source(other)
        .scan("eqgame.dll")
        .await
        .expect("scan");
    persistor.save(&eqgame).expect("save");

    assert_eq!(persistor.load("eqmain.dll").unwrap(), eqmain);
    assert_eq!(persistor.load("eqgame.dll").unwrap(), eqgame);
    assert!(!persistor.exists("other.dll"));
}
