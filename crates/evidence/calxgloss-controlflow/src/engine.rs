//! Control-flow scan orchestration.
//!
//! [`ControlFlowEngine`] runs the five detectors — switch-shaped
//! if/else-if chains, self-recursion, state machines, loop
//! structure, and branch density — over every function of one open Ghidra program and
//! assembles their findings
//! into a single [`ControlFlowResult`] with its scan provenance.
//!
//! The detectors are pure text analysis over one decompiled body, so
//! the engine fetches each function's pseudo-C exactly once and reads
//! it with all five, rather than having each detector pull its own
//! copy. The scan is then one sequential pass over the function
//! listing: like sync's disjoint families there is nothing to resolve
//! between the detectors, and keeping the pass sequential keeps the
//! persisted finding list in a stable, diffable order.

use crate::branch_density::BranchDensityDetector;
use crate::error::Result;
use crate::loop_detect::LoopDetector;
use crate::recursion::RecursionDetector;
use crate::state_machine::StateMachineDetector;
use crate::switch::SwitchChainDetector;
use crate::types::{ControlFlowFinding, ControlFlowResult, ScanMetadata};
use calxgloss_ghidra::GhidraClient;
use std::time::Instant;
use tracing::{info, warn};

/// The decompiler a control-flow scan reads.
///
/// The shared trait from the Ghidra integration crate, re-exported here
/// so the engine's generic shape names it where it always has;
/// [`GhidraClient`] implements it over the live HTTP API, and tests
/// implement it over canned bodies so the orchestration runs without a
/// server. The futures are `Send` so a scan can be driven from an
/// orchestrating task.
pub use calxgloss_ghidra::ScanSource;

/// Orchestrates the five detectors into one [`ControlFlowResult`].
///
/// The engine is generic over its [`ScanSource`], so tests can run the
/// whole orchestration over canned bodies; [`new`](Self::new) builds
/// one over a live [`GhidraClient`]. Each detector carries no state and
/// starts configured with its standard thresholds and name set —
/// [`with_switch`](Self::with_switch), [`with_recursion`](Self::with_recursion),
/// [`with_state_machine`](Self::with_state_machine), [`with_loop`](Self::with_loop),
/// and [`with_branch_density`](Self::with_branch_density) swap a detector
/// whole — so one instance of each serves the whole scan.
#[derive(Debug, Clone)]
pub struct ControlFlowEngine<S = GhidraClient> {
    source: S,
    switch: SwitchChainDetector,
    recursion: RecursionDetector,
    state_machine: StateMachineDetector,
    loops: LoopDetector,
    branch_density: BranchDensityDetector,
}

impl ControlFlowEngine<GhidraClient> {
    /// An engine over a live GhidraMCP client, scanning with the five
    /// detectors' standard thresholds and name set.
    pub fn new(client: &GhidraClient) -> ControlFlowEngine<GhidraClient> {
        ControlFlowEngine {
            source: client.clone(),
            switch: SwitchChainDetector::default(),
            recursion: RecursionDetector,
            state_machine: StateMachineDetector::default(),
            loops: LoopDetector::default(),
            branch_density: BranchDensityDetector::default(),
        }
    }
}

impl<S> ControlFlowEngine<S> {
    /// An engine whose decompiles come from `source`, scanning with
    /// the five detectors' standard thresholds and name set.
    pub fn with_source(source: S) -> Self {
        ControlFlowEngine {
            source,
            switch: SwitchChainDetector::default(),
            recursion: RecursionDetector,
            state_machine: StateMachineDetector::default(),
            loops: LoopDetector::default(),
            branch_density: BranchDensityDetector::default(),
        }
    }

    /// Read switch-shaped chains against `detector`'s thresholds
    /// instead of the standard ones.
    pub fn with_switch(mut self, detector: SwitchChainDetector) -> Self {
        self.switch = detector;
        self
    }

    /// Read self-recursion against `detector` instead of the standard
    /// one.
    pub fn with_recursion(mut self, detector: RecursionDetector) -> Self {
        self.recursion = detector;
        self
    }

    /// Read state machines against `detector`'s name set and threshold
    /// instead of the standard ones.
    pub fn with_state_machine(mut self, detector: StateMachineDetector) -> Self {
        self.state_machine = detector;
        self
    }

    /// Read loop structure against `detector`'s threshold instead of
    /// the standard one.
    pub fn with_loop(mut self, detector: LoopDetector) -> Self {
        self.loops = detector;
        self
    }

    /// Read branch density against `detector`'s thresholds and minimum
    /// body size instead of the standard ones.
    pub fn with_branch_density(mut self, detector: BranchDensityDetector) -> Self {
        self.branch_density = detector;
        self
    }

    /// Detect control-flow patterns across `binary`, decompiling each
    /// function exactly once and reading it with all five detectors.
    ///
    /// `binary` names the program the scan reads (e.g. `eqmain.dll`)
    /// and becomes the key a persisted result is filed under. The
    /// findings follow the function listing — function by function, and
    /// within one function the switch chains, then the recursion, then
    /// the state machines, then the loop reading, then the branch
    /// density — so two scans of the same program diff cleanly.
    ///
    /// A function whose body Ghidra cannot produce (a thunk, a bad
    /// entry point) is skipped with a warning; only a failure of the
    /// listing itself — the server being down — aborts the run, since
    /// then nothing was scanned.
    /// But when more than half the listing fails to decompile, the
    /// skip-rate breaker aborts the run too: that is the signature of
    /// the bridge answering from the wrong program, and skipping on
    /// would persist a phantom-clean record (issue #71).
    /// A chain can read as both a switch and
    /// a state machine, so a function can carry findings of every kind
    /// at once and nothing is resolved between them.
    pub async fn scan(&self, binary: impl Into<String>) -> Result<ControlFlowResult>
    where
        S: ScanSource,
    {
        let started = Instant::now();
        let functions = self.source.functions().await?;

        let mut findings = Vec::new();
        let mut skipped = 0usize;
        let mut decompile_failures = 0usize;
        for function in &functions {
            if function.name.is_empty() {
                // A nameless listing entry would send the name lookup
                // wandering into some other function's body; nothing
                // can be said about it, so it passes unrecorded.
                warn!(
                    address = format_args!("{:#x}", function.address),
                    "Skipping function with no name"
                );
                skipped += 1;
                continue;
            }
            let decompiled = match self.source.decompile(&function.name).await {
                Ok(decompiled) => decompiled,
                Err(error) => {
                    warn!(
                        function = %function.name,
                        error = %error,
                        "Skipping function: decompile failed"
                    );
                    skipped += 1;
                    decompile_failures += 1;
                    // Skip-rate breaker: once most of the listing has
                    // failed to decompile, the scan is reading the
                    // wrong program (or a half-broken server), and an
                    // empty result would persist as a phantom-clean
                    // record. Abort with the counts instead of
                    // skipping on.
                    if decompile_failures * 2 > functions.len() {
                        return Err(crate::ControlFlowError::DecompileBreaker {
                            failed: decompile_failures,
                            total: functions.len(),
                        });
                    }
                    continue;
                }
            };
            let body = &decompiled.body;

            findings.extend(
                self.switch
                    .detect(&function.name, body)
                    .into_iter()
                    .map(ControlFlowFinding::Switch),
            );
            findings.extend(
                self.recursion
                    .detect(&function.name, body)
                    .into_iter()
                    .map(ControlFlowFinding::Recursion),
            );
            findings.extend(
                self.state_machine
                    .detect(&function.name, body)
                    .into_iter()
                    .map(ControlFlowFinding::StateMachine),
            );
            findings.extend(
                self.loops
                    .detect(&function.name, body)
                    .into_iter()
                    .map(ControlFlowFinding::Loop),
            );
            findings.extend(
                self.branch_density
                    .detect(&function.name, body)
                    .into_iter()
                    .map(ControlFlowFinding::BranchDensity),
            );
        }

        let mut metadata = ScanMetadata::new(binary);
        metadata.duration_secs = started.elapsed().as_secs();
        info!(
            binary = %metadata.binary,
            functions = functions.len(),
            findings = findings.len(),
            skipped,
            duration_secs = metadata.duration_secs,
            "Detected control-flow patterns"
        );
        Ok(ControlFlowResult { metadata, findings })
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{BranchClassification, LoopKind};
    use calxgloss_ghidra::{
        DataItem, DataTypeEntry, DecompiledFunction, EnumDefinition, FunctionSummary, GhidraError,
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
    /// read what the scan did after the engine has consumed its
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
                return Err(GhidraError::Reported {
                    status: Some(200),
                    message: "Ghidra is busy".into(),
                });
            }
            Ok(self.listing.clone())
        }

        async fn decompile(&self, name: &str) -> Result<DecompiledFunction> {
            self.stats.decompiles.lock().unwrap().push(name.to_string());
            if self.fail_decompiles.iter().any(|f| f == name) {
                return Err(GhidraError::NotFound {
                    kind: "function",
                    query: name.to_string(),
                });
            }
            self.bodies
                .get(name)
                .cloned()
                .ok_or_else(|| GhidraError::NotFound {
                    kind: "function",
                    query: name.to_string(),
                })
        }

        // The rest of the shared trait's reads: this engine never makes
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
            Err(GhidraError::NotFound {
                kind: "struct",
                query: name.to_string(),
            })
        }

        async fn enum_values(&self, name: &str) -> Result<EnumDefinition> {
            Err(GhidraError::NotFound {
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

    /// A body carrying a switch-shaped chain that also assigns its own
    /// variable (so it reads as a state machine too), a self-call, and
    /// a loop inside the first case body — one finding family per
    /// detector — all in one function. The self-call is spelled per the
    /// function that carries it, and the loop sits one level under the
    /// chain so the nesting reading has something real to report.
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
    async fn scan_collects_findings_from_all_five_detectors() {
        let result = scan(program()).await;

        assert_eq!(result.metadata.binary, "eqmain.dll");
        assert!(result.metadata.scanned_at > 0);

        let findings: Vec<&ControlFlowFinding> = result.for_function("FUN_18003ab00").collect();
        assert_eq!(findings.len(), 5);

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
    }

    #[tokio::test]
    async fn scan_keeps_findings_in_scan_order() {
        // Both functions carry every shape, so the persisted list must
        // group their findings by function in listing order — and
        // within one function run switch, recursion, state machine,
        // loop, then branch density — never interleaved.
        let mut program = program();
        program.listing = vec![summary("FUN_18003e750"), summary("FUN_18003ab00")];
        program.bodies.insert(
            "FUN_18003e750".into(),
            function(
                "FUN_18003e750",
                "undefined FUN_18003e750(void)",
                &every_shape_body("FUN_18003e750"),
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
                ("FUN_18003ab00", "switch"),
                ("FUN_18003ab00", "recursion"),
                ("FUN_18003ab00", "state_machine"),
                ("FUN_18003ab00", "loop"),
                ("FUN_18003ab00", "branch_density"),
            ]
        );
    }

    #[tokio::test]
    async fn scan_decompiles_each_function_exactly_once() {
        // The five detectors share one fetch per function; a scan
        // that asked each detector for its own copy would quintuple
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
        // Ghidra cannot produce a body for every function; one bad
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
        // The 2026-10-08 incident: the bridge answered the listing from
        // one program and the decompiles from another, every decompile
        // failed, and the scan nearly persisted a phantom-clean record
        // under the target's name. The skip-rate breaker aborts with
        // the counts instead, so nothing is persisted.
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
        // The breaker is a circuit breaker, not a post-mortem: once
        // most of the listing has failed, the remaining decompiles are
        // wasted round-trips against the wrong program.
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
        // With the listing gone nothing was scanned, so the run aborts
        // rather than returning a result that looks empty by
        // detection.
        let mut program = program();
        program.fail_listing = true;
        let result = ControlFlowEngine::with_source(program)
            .scan("eqmain.dll")
            .await;
        assert!(matches!(
            result,
            Err(crate::ControlFlowError::Ghidra(
                GhidraError::Reported { .. }
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
        assert_eq!(kinds(&result, "FUN_1800412a0"), ["loop"]);
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
        assert!(
            result.is_empty(),
            "the raised threshold skips the single-loop body"
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
        // Seven conditional edges, not eight: the last test's
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
    async fn scan_stamps_the_scan_provenance() {
        // The metadata names the binary, carries a finish time, and
        // the duration is stamped from the wall clock — a canned scan
        // is instant, so it reads as zero seconds rather than never
        // set.
        let result = scan(program()).await;
        assert_eq!(result.metadata.binary, "eqmain.dll");
        assert!(result.metadata.scanned_at > 0);
        assert!(result.metadata.duration_secs < 60);
    }

    #[tokio::test]
    async fn an_empty_program_yields_an_empty_result() {
        let result = scan(FakeProgram::empty()).await;
        assert!(result.is_empty());
        assert_eq!(result.metadata.binary, "eqmain.dll");
        assert!(result.metadata.scanned_at > 0);
    }
}
