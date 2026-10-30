// Tests for the module above, split out of the file they test.
use super::*;
use crate::types::{BranchClassification, GuardedTarget, LoopKind};
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

/// State shared by every clone of a [`FakeProgram`]. The scan
/// consumes its source, so this lets a test read what the scan
/// decompiled after the scan is over.
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

    // The rest of the shared trait's reads: this scan never makes
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
    // Story 9 (#203): the fake source names itself, so the tests can
    // check that scan() copies the source's provenance onto the
    // record (#208).
    fn engine_provenance(&self) -> Option<calxgloss_types::EngineProvenance> {
        Some(calxgloss_types::EngineProvenance {
            name: "fake-engine".into(),
            version: Some("9.9".into()),
            fingerprint: Some("0123456".into()),
        })
    }
}

/// One body carrying every shape, all in one function: a
/// switch-shaped chain that tests named `STATE_*` constants and
/// reassigns the state variable (so it reads as a state machine
/// too), a self-call, and a loop inside the first case body — one
/// finding for each of the six detectors. The self-call names the
/// function that carries it, and the loop sits one level under the
/// chain, so the nesting reading has something real to report.
fn every_shape_body(name: &str) -> String {
    format!(
        "\
  if (local_4 == STATE_IDLE) {{
    local_4 = STATE_RUN;
    while (local_9 < 3) {{
      local_9 = local_9 + 1;
    }}
    {name}(0);
  }}
  else if (local_4 == STATE_RUN) {{
    local_4 = STATE_DONE;
  }}
  else if (local_4 == STATE_DONE) {{
    local_4 = STATE_IDLE;
  }}"
    )
}

/// The every-shape body plus a call to `partner`. Two of these
/// bodies naming each other close a mutual-recursion cycle the
/// cross-function pass can read.
fn mutual_shape_body(name: &str, partner: &str) -> String {
    format!("{}\n  {partner}(0);", every_shape_body(name))
}

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
            &every_shape_body("FUN_18003ab00"),
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

async fn scan(program: FakeProgram) -> ControlFlowResult {
    ControlFlowEngine::with_source(program)
        .scan("eqmain.dll")
        .await
        .expect("scan")
}

fn kinds(result: &ControlFlowResult, function: &str) -> Vec<&'static str> {
    result
        .for_function(function)
        .map(|finding| finding.kind())
        .collect()
}

#[tokio::test]
async fn scan_collects_findings_from_all_six_detectors() {
    let result = scan(program()).await;

    assert_eq!(result.metadata.binary, "eqmain.dll");
    assert!(result.metadata.scanned_at > 0);

    let findings: Vec<&ControlFlowFinding> = result.for_function("FUN_18003ab00").collect();
    assert_eq!(findings.len(), 6);

    let ControlFlowFinding::Switch(record) = findings[0] else {
        unreachable!("the if/else-if chain reads as a switch finding");
    };
    assert_eq!(record.variable, "local_4");
    assert_eq!(record.cases, ["STATE_IDLE", "STATE_RUN", "STATE_DONE"]);

    let ControlFlowFinding::Recursion(record) = findings[1] else {
        unreachable!("the self-call reads as a recursion finding");
    };
    assert_eq!(record.self_calls, 1);
    assert!(!record.is_tail_call);

    let ControlFlowFinding::StateMachine(record) = findings[2] else {
        unreachable!("the named-constant chain with transitions reads as a state machine");
    };
    assert_eq!(record.state_var, "local_4");
    assert_eq!(
        record.transitions,
        ["STATE_RUN", "STATE_DONE", "STATE_IDLE"]
    );

    let ControlFlowFinding::Loop(record) = findings[3] else {
        unreachable!("the loop inside the first case body reads as a loop finding");
    };
    assert_eq!(record.loop_count, 1);
    // Nested under the chain, not beside it: the wrapped body's
    // statement level re-anchors to 1, and the chain arm adds one.
    assert_eq!(record.max_depth, 2);
    assert_eq!(record.kinds_seen, [LoopKind::While]);
    assert_eq!(u8::from(record.confidence), 70);

    let ControlFlowFinding::BranchDensity(record) = findings[4] else {
        unreachable!("the three-arm chain over eight blocks reads as branch-heavy");
    };
    // The chain's five conditional edges over the chain-and-loop
    // graph's eight blocks — the last arm's not-taken edge leaves
    // the body, and the loop conditions stay out of the branch
    // count: iteration is not dispatch.
    assert_eq!(record.branch_count, 5);
    assert_eq!(record.block_count, 8);
    assert_eq!(record.classification, BranchClassification::DispatchTable);
    assert_eq!(u8::from(record.confidence), 60);

    let ControlFlowFinding::BranchSite(record) = findings[5] else {
        unreachable!("the loop header inside the first arm reads as a branch site");
    };
    // The chain's plain arms guard nothing in the inventory's
    // vocabulary — only the loop header names a site.
    assert_eq!(record.condition, "local_9 < 3");
    assert_eq!(record.params, ["local_9"]);
    assert_eq!(record.operator.as_deref(), Some("<"));
    assert_eq!(record.immediate.as_deref(), Some("3"));
    assert_eq!(record.guards, GuardedTarget::LoopExit);
    assert_eq!(u8::from(record.confidence), 80);
}

#[tokio::test]
async fn scan_keeps_findings_in_scan_order() {
    // Both functions carry every shape and call each other, so the
    // persisted list must group their findings by function in
    // listing order — and within one function run switch,
    // recursion, state machine, loop, branch density, then the
    // branch inventory — never
    // interleaved, with the cross-function mutual-recursion cycle
    // appended after every per-function finding.
    let mut program = program();
    program.listing = vec![summary("FUN_18003e750"), summary("FUN_18003ab00")];
    program.bodies.insert(
        "FUN_18003e750".into(),
        function(
            "FUN_18003e750",
            "undefined FUN_18003e750(void)",
            &mutual_shape_body("FUN_18003e750", "FUN_18003ab00"),
        ),
    );
    program.bodies.insert(
        "FUN_18003ab00".into(),
        function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            &mutual_shape_body("FUN_18003ab00", "FUN_18003e750"),
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
            ("FUN_18003e750", "switch"),
            ("FUN_18003e750", "recursion"),
            ("FUN_18003e750", "state_machine"),
            ("FUN_18003e750", "loop"),
            ("FUN_18003e750", "branch_density"),
            ("FUN_18003e750", "branch_site"),
            ("FUN_18003ab00", "switch"),
            ("FUN_18003ab00", "recursion"),
            ("FUN_18003ab00", "state_machine"),
            ("FUN_18003ab00", "loop"),
            ("FUN_18003ab00", "branch_density"),
            ("FUN_18003ab00", "branch_site"),
            ("FUN_18003e750", "mutual_recursion"),
        ]
    );
}

#[tokio::test]
async fn mutual_recursion_across_two_bodies_lands_one_finding_on_the_earlier_function() {
    // FUN_a calls FUN_b and FUN_b calls FUN_a: the ring is
    // invisible to every per-body detector, so the cross-function
    // pass lands one mutual_recursion finding on the earlier
    // function in listing order, naming both members in cycle
    // order, at the evidence confidence a self-call reading
    // carries.
    let mut program = FakeProgram::empty();
    program.listing = vec![summary("FUN_18003ab00"), summary("FUN_18003e750")];
    program.bodies.insert(
        "FUN_18003ab00".into(),
        function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(int param_1)",
            "  FUN_18003e750(param_1);\n",
        ),
    );
    program.bodies.insert(
        "FUN_18003e750".into(),
        function(
            "FUN_18003e750",
            "undefined FUN_18003e750(int param_1)",
            "  FUN_18003ab00(param_1);\n",
        ),
    );
    let program_for_checks = program.clone();
    let result = scan(program).await;

    let findings: Vec<&ControlFlowFinding> = result.for_function("FUN_18003ab00").collect();
    assert_eq!(
        findings.len(),
        1,
        "one cycle finding on the earlier function"
    );
    let ControlFlowFinding::MutualRecursion(record) = findings[0] else {
        unreachable!("the call ring reads as a mutual_recursion finding");
    };
    assert_eq!(record.cycle, ["FUN_18003ab00", "FUN_18003e750"]);
    assert_eq!(u8::from(record.confidence), 70);
    assert_eq!(
        record.suggestion,
        "translate the cycle together via an explicit stack, a trampoline, or an enum-driven loop"
    );
    assert_eq!(
        record.evidence,
        "FUN_18003ab00() -> FUN_18003e750() -> FUN_18003ab00()"
    );
    assert!(
        result.for_function("FUN_18003e750").next().is_none(),
        "the cycle lands once, not once per member"
    );
    assert_eq!(
        program_for_checks.decompiled(),
        vec!["FUN_18003ab00", "FUN_18003e750"],
        "the pass reads the kept bodies — no extra decompiles",
    );
}

#[tokio::test]
async fn a_three_function_cycle_lands_one_finding_naming_all_three_members() {
    // FUN_a → FUN_b → FUN_c → FUN_a: a pairwise-only reading does
    // not miss indirect recursion — one finding names every member
    // in cycle order.
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
            "undefined FUN_18003ab00(void)",
            "  FUN_1800412a0();\n",
        ),
    );
    program.bodies.insert(
        "FUN_1800412a0".into(),
        function(
            "FUN_1800412a0",
            "undefined FUN_1800412a0(void)",
            "  FUN_18003e750();\n",
        ),
    );
    program.bodies.insert(
        "FUN_18003e750".into(),
        function(
            "FUN_18003e750",
            "undefined FUN_18003e750(void)",
            "  FUN_18003ab00();\n",
        ),
    );
    let result = scan(program).await;

    let findings: Vec<&ControlFlowFinding> = result.findings.iter().collect();
    assert_eq!(findings.len(), 1, "one finding for the whole ring");
    let ControlFlowFinding::MutualRecursion(record) = findings[0] else {
        unreachable!("the three-function ring reads as a mutual_recursion finding");
    };
    assert_eq!(record.function, "FUN_18003ab00");
    assert_eq!(
        record.cycle,
        ["FUN_18003ab00", "FUN_1800412a0", "FUN_18003e750"]
    );
}

#[tokio::test]
async fn an_acyclic_call_shape_lands_no_mutual_recursion() {
    // An ordinary call tree — FUN_a calls FUN_b, FUN_b returns —
    // lands no recursion finding.
    let mut program = FakeProgram::empty();
    program.listing = vec![summary("FUN_18003ab00"), summary("FUN_18003e750")];
    program.bodies.insert(
        "FUN_18003ab00".into(),
        function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(int param_1)",
            "  FUN_18003e750(param_1);\n",
        ),
    );
    program.bodies.insert(
        "FUN_18003e750".into(),
        function(
            "FUN_18003e750",
            "undefined FUN_18003e750(int param_1)",
            "  return;\n",
        ),
    );
    let result = scan(program).await;

    assert!(result.is_empty(), "a one-way call is not a recursion cycle",);
}

#[tokio::test]
async fn a_plain_self_call_lands_no_mutual_recursion() {
    // The per-body recursion finding already covers the self-call;
    // the cross-function pass must not double-report it as a
    // cycle of one.
    let result = scan(program()).await;

    assert!(
        result
            .findings
            .iter()
            .all(|finding| finding.kind() != "mutual_recursion"),
        "the fixture's self-calls stay the per-body recursion finding's story",
    );
}

#[tokio::test]
async fn a_function_that_will_not_decompile_fabricates_no_cycle() {
    // FUN_a calls FUN_b and FUN_b calls FUN_a, but FUN_b's
    // decompile fails: the kept bodies hold only FUN_a, whose call
    // names no edge back, so the missing body fabricates no ring.
    let mut program = FakeProgram::empty();
    program.listing = vec![summary("FUN_18003ab00"), summary("FUN_18003e750")];
    program.bodies.insert(
        "FUN_18003ab00".into(),
        function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(int param_1)",
            "  FUN_18003e750(param_1);\n",
        ),
    );
    program.bodies.insert(
        "FUN_18003e750".into(),
        function(
            "FUN_18003e750",
            "undefined FUN_18003e750(int param_1)",
            "  FUN_18003ab00(param_1);\n",
        ),
    );
    program.fail_decompiles = vec!["FUN_18003e750".into()];
    let result = scan(program).await;

    assert!(
        result.is_empty(),
        "the skipped body carries no edges and claims no cycle",
    );
}

#[tokio::test]
async fn scan_decompiles_each_function_exactly_once() {
    // The six detectors share one fetch per function; a scan
    // that asked each detector for its own copy would sextuple
    // the wall time.
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
    // The 2026-10-08 incident: the seam was answering about the
    // wrong program — the listing from one program, the decompiles
    // from another — every decompile failed, and the scan nearly
    // persisted a record that looks clean but is not, filed under
    // the target's name. The skip-rate breaker aborts with the
    // counts instead, so nothing is persisted.
    let mut program = program();
    program.fail_decompiles = vec!["FUN_18003ab00".into(), "FUN_18003e750".into()];
    let result = ControlFlowEngine::with_source(program)
        .scan("eqmain.dll")
        .await;
    assert!(matches!(
        result,
        Err(crate::ControlFlowError::DecompileBreaker {
            failed: 2,
            total: 2
        })
    ));
}

#[tokio::test]
async fn the_breaker_stops_the_scan_from_decompiling_the_rest() {
    // The breaker is a fuse, not a post-mortem: once more than half
    // the listing has failed, the remaining decompiles are wasted
    // round-trips against the wrong program.
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
    let result = ControlFlowEngine::with_source(program.clone())
        .scan("eqmain.dll")
        .await;

    assert!(matches!(
        result,
        Err(crate::ControlFlowError::DecompileBreaker {
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
    // An empty name would send the by-name lookup into an
    // arbitrary function's body, so the entry passes without a
    // decompile.
    let mut program = program();
    program.listing.insert(0, summary(""));
    let result = scan(program.clone()).await;

    assert_eq!(program.decompiled(), vec!["FUN_18003ab00", "FUN_18003e750"]);
    assert!(!result.is_empty());
}

#[tokio::test]
async fn a_failing_listing_fails_the_whole_run() {
    // With the listing gone, nothing was scanned, so the run
    // aborts rather than returning an empty result that looks like
    // a real detection run.
    let mut program = program();
    program.fail_listing = true;
    let result = ControlFlowEngine::with_source(program)
        .scan("eqmain.dll")
        .await;
    assert!(matches!(
        result,
        Err(crate::ControlFlowError::Engine(
            EngineError::Reported { .. }
        ))
    ));
}

#[tokio::test]
async fn configured_detectors_reach_the_scan() {
    // Swapping a detector whole reaches the scan: a state machine
    // with a custom name set reads the MODE_* chain, and a switch
    // detector with a raised threshold skips the 3-arm chain.
    let mut program = FakeProgram::empty();
    program.listing = vec![summary("FUN_1800412a0")];
    program.bodies.insert(
        "FUN_1800412a0".into(),
        function(
            "FUN_1800412a0",
            "undefined FUN_1800412a0(void)",
            "\
  if (mode == MODE_ON) {
    mode = MODE_OFF;
  }
  else if (mode == MODE_OFF) {
    mode = MODE_SLEEP;
  }
  else if (mode == MODE_SLEEP) {
    mode = MODE_ON;
  }",
        ),
    );

    let engine = ControlFlowEngine::with_source(program)
        .with_switch(SwitchChainDetector::default().with_min_cases(4))
        .with_state_machine(StateMachineDetector::default().with_state_names(&["MODE_*"]));
    let result = engine.scan("eqmain.dll").await.expect("scan");

    assert_eq!(
        kinds(&result, "FUN_1800412a0"),
        ["state_machine", "branch_density"]
    );
    let findings: Vec<&ControlFlowFinding> = result.for_function("FUN_1800412a0").collect();
    let ControlFlowFinding::StateMachine(record) = findings[0] else {
        unreachable!("the configured name set reads the chain as a state machine");
    };
    assert_eq!(record.state_var, "mode");
    assert_eq!(u8::from(record.confidence), 70);
}

#[tokio::test]
async fn a_configured_loop_detector_reaches_the_scan() {
    // Swapping the loop detector whole reaches the scan too: the
    // default reads the single-loop body, and a raised threshold
    // skips it.
    let mut program = FakeProgram::empty();
    program.listing = vec![summary("FUN_1800412a0")];
    program.bodies.insert(
        "FUN_1800412a0".into(),
        function(
            "FUN_1800412a0",
            "undefined FUN_1800412a0(void)",
            "\
  while (local_4 < 10) {
    local_4 = local_4 + 1;
  }",
        ),
    );

    let result = scan(program.clone()).await;
    assert_eq!(kinds(&result, "FUN_1800412a0"), ["loop", "branch_site"]);
    let findings: Vec<&ControlFlowFinding> = result.for_function("FUN_1800412a0").collect();
    let ControlFlowFinding::Loop(record) = findings[0] else {
        unreachable!("the spelled-out while header reads as a loop finding");
    };
    assert_eq!(record.loop_count, 1);
    assert_eq!(record.max_depth, 1);

    let result = ControlFlowEngine::with_source(program)
        .with_loop(LoopDetector::default().with_min_loops(2))
        .scan("eqmain.dll")
        .await
        .expect("scan");
    assert_eq!(
        kinds(&result, "FUN_1800412a0"),
        ["branch_site"],
        "the raised loop threshold skips the loop finding, but the \
             branch inventory still names the loop exit",
    );
}

#[tokio::test]
async fn a_configured_branch_density_detector_reaches_the_scan() {
    // Swapping the branch-density detector whole reaches the scan
    // too: the default classifies the four-condition body as
    // branch-heavy, a raised minimum size skips it, and a raised
    // heavy threshold reads the same body as a scan.
    let mut program = FakeProgram::empty();
    program.listing = vec![summary("FUN_1800412a0")];
    program.bodies.insert(
        "FUN_1800412a0".into(),
        function(
            "FUN_1800412a0",
            "undefined FUN_1800412a0(void)",
            "\
  if (local_4 == 1) {
    a();
  }
  if (local_4 == 2) {
    b();
  }
  if (local_4 == 3) {
    c();
  }
  if (local_4 == 4) {
    d();
  }",
        ),
    );

    let result = scan(program.clone()).await;
    assert_eq!(kinds(&result, "FUN_1800412a0"), ["branch_density"]);
    let findings: Vec<&ControlFlowFinding> = result.for_function("FUN_1800412a0").collect();
    let ControlFlowFinding::BranchDensity(record) = findings[0] else {
        unreachable!("four conditionals in eight blocks read as branch-heavy");
    };
    // Seven conditional edges, not eight: the last condition's
    // not-taken edge leaves the body.
    assert_eq!(record.branch_count, 7);
    assert_eq!(record.block_count, 8);
    assert_eq!(record.classification, BranchClassification::DispatchTable);

    let result = ControlFlowEngine::with_source(program.clone())
        .with_branch_density(BranchDensityDetector::default().with_min_blocks(10))
        .scan("eqmain.dll")
        .await
        .expect("scan");
    assert!(
        result.is_empty(),
        "the raised minimum size skips the eight-block body"
    );

    let result = ControlFlowEngine::with_source(program)
        .with_branch_density(BranchDensityDetector::default().with_heavy_threshold(0.9))
        .scan("eqmain.dll")
        .await
        .expect("scan");
    let findings: Vec<&ControlFlowFinding> = result.for_function("FUN_1800412a0").collect();
    let ControlFlowFinding::BranchDensity(record) = findings[0] else {
        unreachable!("the raised threshold still classifies the body");
    };
    assert_eq!(record.classification, BranchClassification::SequentialScan);
}

#[tokio::test]
async fn a_configured_branch_inventory_detector_reaches_the_scan() {
    // Swapping the branch-inventory detector whole reaches the
    // scan too: the default inventories every readable site of a
    // body carrying guards, a loop, and a switch — one record per
    // site, asserted through the whole scan over the fake scan
    // source — and a raised confidence floor keeps only the exact
    // readings.
    let mut program = FakeProgram::empty();
    program.listing = vec![summary("FUN_1800412a0")];
    program.bodies.insert(
        "FUN_1800412a0".into(),
        function(
            "FUN_1800412a0",
            "undefined FUN_1800412a0(int param_1)",
            "\
  if (param_1 == 0) {
    return;
  }
  if (param_1 < 0) {
    return 0xffffffff;
  }
  while (param_1 < 10) {
    param_1 = param_1 + 1;
  }
  switch (param_1) {
    case 1:
      a();
      break;
    case 2:
      b();
      break;
    default:
      c();
  }",
        ),
    );

    let result = scan(program.clone()).await;
    let sites: Vec<&crate::types::BranchSite> = result
        .for_function("FUN_1800412a0")
        .filter_map(|finding| match finding {
            ControlFlowFinding::BranchSite(record) => Some(record),
            _ => None,
        })
        .collect();
    assert_eq!(sites.len(), 6, "one record per branch site");
    let guards: Vec<GuardedTarget> = sites.iter().map(|site| site.guards).collect();
    assert_eq!(
        guards,
        vec![
            GuardedTarget::EarlyReturn,
            GuardedTarget::ErrorPath,
            GuardedTarget::LoopExit,
            GuardedTarget::SwitchArm,
            GuardedTarget::SwitchArm,
            GuardedTarget::ElseArm,
        ]
    );
    assert_eq!(sites[0].condition, "param_1 == 0");
    assert_eq!(sites[0].operator.as_deref(), Some("=="));
    assert_eq!(sites[0].immediate.as_deref(), Some("0"));
    assert_eq!(sites[2].condition, "param_1 < 10");
    assert_eq!(sites[3].immediate.as_deref(), Some("1"));

    let result = ControlFlowEngine::with_source(program)
        .with_branch_inventory(BranchInventoryDetector::default().with_min_confidence(80))
        .scan("eqmain.dll")
        .await
        .expect("scan");
    let sites: Vec<&crate::types::BranchSite> = result
        .for_function("FUN_1800412a0")
        .filter_map(|finding| match finding {
            ControlFlowFinding::BranchSite(record) => Some(record),
            _ => None,
        })
        .collect();
    assert_eq!(
        sites.len(),
        5,
        "the raised floor drops the shape-only default arm",
    );
}

#[tokio::test]
async fn scan_stamps_the_scan_provenance() {
    // The metadata names the binary, carries a finish time, and
    // the duration is stamped from the wall clock — a canned scan
    // is instant, so it reads as zero seconds rather than never
    // set.
    let result = scan(program()).await;
    assert_eq!(result.metadata.binary, "eqmain.dll");
    assert!(result.metadata.scanned_at > 0);
    assert!(result.metadata.duration_secs < 60);
    // Story 9 (#203): the record also names the analysis engine that
    // produced it — scan() copies the source's provenance through (#208).
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

/// The data-level verdict of the roster pin: an empty result means
/// the record names every declared facet exactly once. Each fault
/// it reports is one way the record drifted from the roster.
fn roster_faults(coverage: &ScanCoverage) -> Vec<String> {
    coverage.roster_faults(DECLARED_FACETS)
}

#[tokio::test]
async fn a_fresh_scan_stamps_complete_bodies_coverage_and_a_clean_roster() {
    // The coverage stamp comes from the scan itself, not the
    // registry row and not the CLI — the batch scan phase and the
    // CLI's force-rescan file the same admission through this one
    // definition. Every body was read here, so the record is
    // complete and says nothing needs admitting.
    let result = scan(program()).await;
    let coverage = result
        .metadata
        .coverage
        .expect("a fresh control-flow scan states its coverage");
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
        .expect("a partial control-flow scan states its coverage too");
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
    // five inline and report the sixth as a count, and a nameless
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
        .expect("a partial control-flow scan states its coverage")
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
        id: "heap-allocations".to_string(),
        status: CoverageStatus::Unexamined,
        limitation: None,
    });
    assert_eq!(
        roster_faults(&coverage),
        ["record names `heap-allocations`, a facet the engine never declared"],
        "an id invented outside the declared roster fails loudly"
    );
}
