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
//!   chains, then the recursion, then the state machines, then the
//!   loop reading, then the branch density, then the branch
//!   inventory — and after every function, the cross-function
//!   mutual-recursion cycles in listing order.
//! - **Cache behavior** — the `exists` check decides whether a scan
//!   runs, and a rescan replaces the cached document.
//!
//! The fake program implements [`ScanSource`], so the whole flow runs
//! without an external server.

use std::collections::HashMap;

use calxgloss_controlflow::engine::{ControlFlowEngine, ScanSource};
use calxgloss_controlflow::persist::ControlFlowPersistor;
use calxgloss_controlflow::types::ControlFlowFinding;
use calxgloss_decomp::{
    DataItem, DataTypeEntry, DecompiledFunction, EngineError, EnumDefinition, FunctionSummary,
    Result, StringLiteral, StructLayout, Symbol, Xref,
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

/// A canned program implementing [`ScanSource`]. Built by `program()`:
/// the first function's body carries a three-arm switch-shaped chain
/// over `local_4` with a trailing default, a self-call nested inside a
/// `while` loop in one arm (what sets the recursion finding's in-loop
/// flag), and a call to the second function in another arm. The second
/// function's body is a named-constant state chain over `state` with
/// transition assignments. The third function's body is plain and
/// finds nothing. The first two functions also call each other, so
/// the cross-function pass has a mutual-recursion cycle to read.
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
             \x20   while (local_9 < 3) {\n\
             \x20     FUN_18003ab00(param_1 - 1);\n\
             \x20     local_9 = local_9 + 1;\n\
             \x20   }\n\
             \x20 }\n\
             \x20 else if (local_4 == 2) {\n\
             \x20   puts(\"two\");\n\
             \x20 }\n\
             \x20 else if (local_4 == 0x10) {\n\
             \x20   FUN_1800412a0();\n\
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
             \x20   FUN_18003ab00(1);\n\
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
    // The six detectors read one body in one pass and the
    // cross-function pass reads the kept bodies after the walk, so
    // what reaches disk is function by function in listing order and,
    // within one function, the switch chains, then the recursion,
    // then the state machines, then the loop reading, then the branch
    // density, then the branch inventory — and only then the mutual-recursion cycle, attached to
    // the cycle's earliest member — the order two scans diff against.
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
            ("FUN_18003ab00", "loop"),
            ("FUN_18003ab00", "branch_density"),
            ("FUN_18003ab00", "branch_site"),
            ("FUN_18003ab00", "branch_site"),
            ("FUN_1800412a0", "switch"),
            ("FUN_1800412a0", "state_machine"),
            ("FUN_1800412a0", "branch_density"),
            ("FUN_18003ab00", "mutual_recursion"),
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
    assert_eq!(findings.len(), 7);
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
    assert!(
        record.in_loop,
        "the self-call sits inside the while body — a stack-depth multiplier",
    );
    assert_eq!(
        record.suggestion,
        "keep recursive fn FUN_18003ab00(...) or carry the work on an explicit stack",
    );
    assert!(
        record
            .evidence
            .contains("FUN_18003ab00() calls itself 1x (nested in a loop)")
    );

    let ControlFlowFinding::Loop(record) = findings[2] else {
        unreachable!("the while inside the first chain arm reads as a loop finding");
    };
    assert_eq!(record.loop_count, 1);
    // Nested under the chain arm, not beside it.
    assert_eq!(record.max_depth, 2);
    assert_eq!(
        record.kinds_seen,
        [calxgloss_controlflow::types::LoopKind::While]
    );
    assert_eq!(
        record.suggestion,
        "express as Rust while at nesting depth 2"
    );
    assert_eq!(record.evidence, "1 loop: while (max depth 2)");
    assert_eq!(record.confidence.value(), 70);

    let ControlFlowFinding::BranchDensity(record) = findings[3] else {
        unreachable!("the chain's six conditional edges over ten blocks read as branch-heavy");
    };
    assert_eq!(record.branch_count, 6);
    assert_eq!(record.block_count, 10);
    assert_eq!(
        record.classification,
        calxgloss_controlflow::types::BranchClassification::DispatchTable
    );
    assert_eq!(record.suggestion, "express as a match or dispatch table");
    assert_eq!(
        record.evidence,
        "6 conditional edges / 10 blocks (density 0.60)"
    );
    assert_eq!(record.confidence.value(), 60);

    // The branch inventory names the body's two readable sites in
    // body order: the loop exit inside the first arm, then the
    // trailing else arm — and the chain's plain arms record nothing.
    let ControlFlowFinding::BranchSite(record) = findings[4] else {
        unreachable!("the while header inside the first arm reads as a branch site");
    };
    assert_eq!(record.condition, "local_9 < 3");
    assert_eq!(record.params, ["local_9"]);
    assert_eq!(record.operator.as_deref(), Some("<"));
    assert_eq!(record.immediate.as_deref(), Some("3"));
    assert_eq!(
        record.guards,
        calxgloss_controlflow::types::GuardedTarget::LoopExit
    );
    assert_eq!(
        record.suggestion,
        "express the loop exit for local_9 < 3 at the boundary"
    );
    assert_eq!(record.evidence, "while (local_9 < 3) {");
    assert_eq!(record.confidence.value(), 80);

    let ControlFlowFinding::BranchSite(record) = findings[5] else {
        unreachable!("the trailing else arm reads as a branch site");
    };
    assert_eq!(record.condition, "else");
    assert_eq!(
        record.guards,
        calxgloss_controlflow::types::GuardedTarget::ElseArm
    );
    assert_eq!(
        record.operator, None,
        "a shape-only reading names no operator"
    );
    assert_eq!(record.immediate, None);
    assert_eq!(
        record.suggestion,
        "express the else arm as the match default"
    );
    assert_eq!(record.evidence, "else {");
    assert_eq!(record.confidence.value(), 50);

    // The cross-function pass read the cycle off the walk's kept
    // bodies: it lands last, attached to the cycle's earliest member,
    // and names both members in cycle order through the round trip.
    let ControlFlowFinding::MutualRecursion(record) = findings[6] else {
        unreachable!("the mutual calls read as a mutual_recursion finding");
    };
    assert_eq!(record.function, "FUN_18003ab00");
    assert_eq!(record.cycle, ["FUN_18003ab00", "FUN_1800412a0"]);
    assert_eq!(
        record.suggestion,
        "translate the cycle together via an explicit stack, a trampoline, or an enum-driven loop"
    );
    assert_eq!(
        record.evidence,
        "FUN_18003ab00() -> FUN_1800412a0() -> FUN_18003ab00()"
    );
    assert_eq!(record.confidence.value(), 70);

    // The state chain reads as both a switch and a state machine —
    // nothing is suppressed between the detectors.
    let state_findings: Vec<&ControlFlowFinding> = loaded.for_function("FUN_1800412a0").collect();
    assert_eq!(state_findings.len(), 3);
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

    let ControlFlowFinding::BranchDensity(record) = state_findings[2] else {
        unreachable!("the state chain carries a branch-density reading too");
    };
    assert_eq!(
        record.classification,
        calxgloss_controlflow::types::BranchClassification::DispatchTable
    );
    assert_eq!(record.confidence.value(), 60);
}

#[tokio::test]
async fn a_loaded_result_renders_into_the_escalate_prompt() {
    // The whole escalate path, no external server needed: the fixture
    // document on disk answers the per-function lookup, the findings
    // render into `ControlFlowInfo` prompt data, and the rendered
    // escalate prompt carries the CONTROL FLOW section with each
    // finding's suggestion, kind, evidence confidence, and evidence.
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
    assert_eq!(findings.len(), 7, "the target function's seven findings");

    let prompt = calxgloss_prompts::build_escalate_prompt_with_context(
        "FUN_18003ab00".into(),
        "eqmain.dll".into(),
        "fn fun_18003ab00(param_1: i32) { /* if-else ladder */ }".into(),
        "Wrong result".into(),
        calxgloss_prompts::EvidenceBundle {
            control_flow_findings: findings,
            ..Default::default()
        },
        Vec::new(),
    )
    .expect("the escalate prompt should render");

    assert!(prompt.contains("CONTROL FLOW"));
    assert!(prompt.contains("match local_4 { /* 3 arms */ } + _"));
    assert!(prompt.contains("switch construct, confidence 70"));
    assert!(
        prompt.contains(
            "keep recursive fn FUN_18003ab00(...) or carry the work on an explicit stack"
        )
    );
    assert!(prompt.contains("recursion construct, confidence 70"));
    assert!(prompt.contains("FUN_18003ab00() calls itself 1x (nested in a loop)"));
    assert!(prompt.contains("if (local_4 == 1) ... else if (local_4 == 0x10) + default"));
    assert!(prompt.contains("express as Rust while at nesting depth 2"));
    assert!(prompt.contains("loop construct, confidence 70"));
    assert!(prompt.contains("1 loop: while (max depth 2)"));
    assert!(prompt.contains("express as a match or dispatch table"));
    assert!(prompt.contains("branch_density construct, confidence 60"));
    assert!(prompt.contains("6 conditional edges / 10 blocks (density 0.60)"));
    assert!(prompt.contains("express the loop exit for local_9 < 3 at the boundary"));
    assert!(prompt.contains("branch_site construct, confidence 80"));
    assert!(prompt.contains("while (local_9 < 3) {"));
    assert!(prompt.contains("express the else arm as the match default"));
    assert!(prompt.contains("branch_site construct, confidence 50"));
    assert!(prompt.contains(
        "translate the cycle together via an explicit stack, a trampoline, or an enum-driven loop"
    ));
    assert!(prompt.contains("mutual_recursion construct, confidence 70"));
    assert!(prompt.contains("FUN_18003ab00() -> FUN_1800412a0() -> FUN_18003ab00()"));
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
