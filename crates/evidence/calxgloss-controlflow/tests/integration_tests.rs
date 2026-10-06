//! Integration tests for the calxgloss-controlflow crate.
//!
//! These tests exercise the multi-module workflows the unit tests cannot
//! cover on their own:
//!
//! - **Scan to disk** — [`ControlFlowEngine`] scans a canned program, the
//!   [`ControlFlowPersistor`] files the result in the workspace layout, and
//!   loading it back yields the same result the scan returned.
//! - **Consumption** — the loaded result answers the lookups a
//!   translation pipeline makes (the findings recorded for one
//!   function), and the persisted list keeps every finding in scan
//!   order: function by function, and within one function the switch
//!   chains, then the recursion, then the state machines.
//! - **Cache behavior** — the `exists` check decides whether a scan
//!   runs, and a rescan replaces the cached document.
//!
//! The fake program implements [`ScanSource`], so the whole flow runs
//! without a Ghidra server.

use std::collections::HashMap;

use calxgloss_controlflow::Result;
use calxgloss_controlflow::engine::{ControlFlowEngine, ScanSource};
use calxgloss_controlflow::persist::ControlFlowPersistor;
use calxgloss_controlflow::types::ControlFlowFinding;
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
/// body carries a three-arm switch-shaped chain over `local_4` with a
/// trailing default and a self-call inside one arm, one function whose
/// body is a named-constant state chain over `state` with transition
/// assignments, and one plain function that finds nothing.
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
    program.listing = vec![
        summary("FUN_18003ab00"),
        summary("FUN_1800412a0"),
        summary("FUN_18003e750"),
    ];
    program.bodies.insert(
        "FUN_18003ab00".into(),
        function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(int param_1)",
            "  if (local_4 == 1) {\n\
             \x20   puts(\"one\");\n\
             \x20 }\n\
             \x20 else if (local_4 == 2) {\n\
             \x20   FUN_18003ab00(param_1 - 1);\n\
             \x20 }\n\
             \x20 else if (local_4 == 0x10) {\n\
             \x20   puts(\"sixteen\");\n\
             \x20 }\n\
             \x20 else {\n\
             \x20   puts(\"other\");\n\
             \x20 }\n",
        ),
    );
    program.bodies.insert(
        "FUN_1800412a0".into(),
        function(
            "FUN_1800412a0",
            "undefined FUN_1800412a0(void)",
            "  if (state == STATE_IDLE) {\n\
             \x20   state = STATE_RUNNING;\n\
             \x20 }\n\
             \x20 else if (state == STATE_RUNNING) {\n\
             \x20   state = STATE_DONE;\n\
             \x20 }\n\
             \x20 else if (state == STATE_DONE) {\n\
             \x20   return;\n\
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
    let result = ControlFlowEngine::with_source(program())
        .scan("eqmain.dll")
        .await
        .expect("scan");

    let persistor = ControlFlowPersistor::new(workspace.path());
    assert!(!persistor.exists("eqmain.dll"), "nothing is cached yet");

    persistor.save(&result).expect("save");
    assert!(persistor.exists("eqmain.dll"));
    assert_eq!(
        persistor.path_for("eqmain.dll"),
        workspace
            .path()
            .join("re/analysis/controlflow/eqmain.dll.json")
    );

    let loaded = persistor.load("eqmain.dll").expect("load");
    assert_eq!(loaded, result, "the document round-trips exactly");
}

#[tokio::test]
async fn the_persisted_document_keeps_findings_in_scan_order() {
    // The three detectors read one body in one pass, so what reaches
    // disk is function by function in listing order and, within one
    // function, the switch chains, then the recursion, then the state
    // machines — the order two scans diff against.
    let workspace = TempDir::new().unwrap();
    let result = ControlFlowEngine::with_source(program())
        .scan("eqmain.dll")
        .await
        .expect("scan");
    let persistor = ControlFlowPersistor::new(workspace.path());
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
            ("FUN_18003ab00", "switch"),
            ("FUN_18003ab00", "recursion"),
            ("FUN_1800412a0", "switch"),
            ("FUN_1800412a0", "state_machine"),
        ]
    );
}

// ------------------------------------------------------------
// Consumption
// ------------------------------------------------------------

#[tokio::test]
async fn a_loaded_result_answers_the_pipeline_lookups() {
    let workspace = TempDir::new().unwrap();
    let result = ControlFlowEngine::with_source(program())
        .scan("eqmain.dll")
        .await
        .expect("scan");
    let persistor = ControlFlowPersistor::new(workspace.path());
    persistor.save(&result).expect("save");

    let loaded = persistor.load("eqmain.dll").expect("load");

    // The pipeline asks what was found for the function it is about to
    // translate; the plain function carries nothing.
    let findings: Vec<&ControlFlowFinding> = loaded.for_function("FUN_18003ab00").collect();
    assert_eq!(findings.len(), 2);
    assert!(loaded.for_function("FUN_18003e750").next().is_none());
    assert!(loaded.for_function("FUN_180099999").next().is_none());

    // Each record keeps its detector's detail and evidence through the
    // round trip, so a prompt sees the shape that produced it.
    let ControlFlowFinding::Switch(record) = findings[0] else {
        unreachable!("the three-arm chain reads as a switch finding");
    };
    assert_eq!(record.variable, "local_4");
    assert_eq!(record.cases, vec!["1", "2", "0x10"]);
    assert!(record.has_default);
    assert_eq!(record.suggestion, "match local_4 { /* 3 arms */ } + _");
    assert_eq!(record.confidence.value(), 70);
    assert!(
        record
            .evidence
            .contains("if (local_4 == 1) ... else if (local_4 == 0x10) + default")
    );

    let ControlFlowFinding::Recursion(record) = findings[1] else {
        unreachable!("the self-call reads as a recursion finding");
    };
    assert_eq!(record.self_calls, 1);
    assert!(!record.is_tail_call);
    assert_eq!(
        record.suggestion,
        "keep recursive fn FUN_18003ab00(...) or convert to loop"
    );
    assert!(record.evidence.contains("FUN_18003ab00() calls itself 1x"));

    // The state chain reads as both a switch and a state machine —
    // nothing is suppressed between the detectors.
    let state_findings: Vec<&ControlFlowFinding> = loaded.for_function("FUN_1800412a0").collect();
    assert_eq!(state_findings.len(), 2);
    assert!(matches!(state_findings[0], ControlFlowFinding::Switch(_)));

    let ControlFlowFinding::StateMachine(record) = state_findings[1] else {
        unreachable!("the named-constant chain reads as a state-machine finding");
    };
    assert_eq!(record.state_var, "state");
    assert_eq!(
        record.states,
        vec!["STATE_IDLE", "STATE_RUNNING", "STATE_DONE"]
    );
    assert_eq!(record.transitions, vec!["STATE_RUNNING", "STATE_DONE"]);
    assert_eq!(record.idle_state.as_deref(), Some("STATE_IDLE"));
    assert_eq!(
        record.suggestion,
        "enum State + match state { /* 3 states */ }"
    );
    assert_eq!(record.confidence.value(), 70);
}

#[tokio::test]
async fn a_loaded_result_renders_into_the_escalate_prompt() {
    // The whole escalate path, no Ghidra server needed: the fixture
    // document on disk answers the per-function lookup, the findings
    // render into `ControlFlowInfo` prompt data, and the rendered
    // escalate prompt carries the CONTROL FLOW section with each
    // finding's suggestion, kind, confidence, and evidence.
    let workspace = TempDir::new().unwrap();
    let result = ControlFlowEngine::with_source(program())
        .scan("eqmain.dll")
        .await
        .expect("scan");
    let persistor = ControlFlowPersistor::new(workspace.path());
    persistor.save(&result).expect("save");

    let loaded = persistor.load("eqmain.dll").expect("load");
    let findings: Vec<calxgloss_prompts::ControlFlowInfo> = loaded
        .for_function("FUN_18003ab00")
        .map(calxgloss_prompts::ControlFlowInfo::from)
        .collect();
    assert_eq!(findings.len(), 2, "the target function's two findings");

    let prompt = calxgloss_prompts::build_escalate_prompt_with_context(
        "FUN_18003ab00".into(),
        "eqmain.dll".into(),
        "fn fun_18003ab00(param_1: i32) { /* if-else ladder */ }".into(),
        "Wrong result".into(),
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
    )
    .expect("the escalate prompt should render");

    assert!(prompt.contains("CONTROL FLOW"));
    assert!(prompt.contains("match local_4 { /* 3 arms */ } + _"));
    assert!(prompt.contains("switch construct, confidence 70"));
    assert!(prompt.contains("keep recursive fn FUN_18003ab00(...) or convert to loop"));
    assert!(prompt.contains("recursion construct, confidence 70"));
    assert!(prompt.contains("if (local_4 == 1) ... else if (local_4 == 0x10) + default"));
}

// ------------------------------------------------------------
// Cache behavior
// ------------------------------------------------------------

#[tokio::test]
async fn a_rescan_replaces_the_cached_document() {
    let workspace = TempDir::new().unwrap();
    let persistor = ControlFlowPersistor::new(workspace.path());

    let first = ControlFlowEngine::with_source(program())
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
    let second = ControlFlowEngine::with_source(quiet)
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
    let persistor = ControlFlowPersistor::new(workspace.path());

    let eqmain = ControlFlowEngine::with_source(program())
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
            "undefined FUN_18003e750(int param_1)",
            "  if (param_1 == 0) {\n\
             \x20   return;\n\
             \x20 }\n\
             \x20 FUN_18003e750(param_1 - 1);\n",
        ),
    );
    let eqgame = ControlFlowEngine::with_source(other)
        .scan("eqgame.dll")
        .await
        .expect("scan");
    persistor.save(&eqgame).expect("save");

    assert_eq!(persistor.load("eqmain.dll").unwrap(), eqmain);
    assert_eq!(persistor.load("eqgame.dll").unwrap(), eqgame);
    assert!(!persistor.exists("other.dll"));
}
