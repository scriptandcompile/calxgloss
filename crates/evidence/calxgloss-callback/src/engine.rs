//! Callback-table scan orchestration.
//!
//! [`CallbackEngine`] runs the callback detectors — function-pointer
//! array calls, callback registrations, and jump-table dispatches —
//! over every function of one open Ghidra program and assembles their
//! findings into a single [`CallbackResult`] with its scan provenance.
//!
//! The detectors are pure text analysis over one decompiled body, so
//! the engine fetches each function's pseudo-C exactly once and reads
//! it with every wired detector, rather than having each detector pull
//! its own copy. The scan is then one sequential pass over the
//! function listing: unlike typeinfer's competing families there is
//! nothing to resolve between the detectors — they read disjoint body
//! shapes — and keeping the pass sequential keeps the persisted
//! finding list in a stable, diffable order.

use crate::callback_reg::CallbackRegDetector;
use crate::error::Result;
use crate::fp_array::FpArrayDetector;
use crate::jump_table::JumpTableDetector;
use crate::types::{CallbackFinding, CallbackResult, ScanMetadata};
use calxgloss_ghidra::{DecompiledFunction, FunctionSummary, GhidraClient};
use std::time::Instant;
use tracing::{info, warn};

/// The decompiler a callback scan reads.
///
/// [`GhidraClient`] implements it directly; tests implement it over
/// canned bodies so the orchestration runs without a server. The
/// futures are `Send` so a scan can be driven from an orchestrating
/// task.
pub trait ScanSource {
    /// Every function in the program, in listing order.
    fn functions(&self) -> impl std::future::Future<Output = Result<Vec<FunctionSummary>>> + Send;

    /// The pseudo-C for one function, by name.
    fn decompile(
        &self,
        name: &str,
    ) -> impl std::future::Future<Output = Result<DecompiledFunction>> + Send;
}

impl ScanSource for GhidraClient {
    async fn functions(&self) -> Result<Vec<FunctionSummary>> {
        Ok(self.list_functions().await?)
    }

    async fn decompile(&self, name: &str) -> Result<DecompiledFunction> {
        Ok(self.decompile_function_by_name(name).await?)
    }
}

/// Orchestrates the callback detectors into one [`CallbackResult`].
///
/// The engine is generic over its [`ScanSource`], so tests can run the
/// whole orchestration over canned bodies; [`new`](Self::new) builds
/// one over a live [`GhidraClient`]. Each detector carries no state
/// and starts configured with its standard name set —
/// [`with_fp_array`](Self::with_fp_array),
/// [`with_registration`](Self::with_registration) and
/// [`with_jump_table`](Self::with_jump_table) swap a detector's set
/// whole — so one instance of each serves the whole scan.
#[derive(Debug, Clone)]
pub struct CallbackEngine<S = GhidraClient> {
    source: S,
    fp_array: FpArrayDetector,
    registration: CallbackRegDetector,
    jump_table: JumpTableDetector,
}

impl CallbackEngine<GhidraClient> {
    /// An engine over a live GhidraMCP client, scanning with the
    /// detectors' standard name sets.
    pub fn new(client: &GhidraClient) -> CallbackEngine<GhidraClient> {
        CallbackEngine {
            source: client.clone(),
            fp_array: FpArrayDetector::with_default_names(),
            registration: CallbackRegDetector::with_default_names(),
            jump_table: JumpTableDetector::with_default_prefixes(),
        }
    }
}

impl<S> CallbackEngine<S> {
    /// An engine whose decompiles come from `source`, scanning with
    /// the detectors' standard name sets.
    pub fn with_source(source: S) -> Self {
        CallbackEngine {
            source,
            fp_array: FpArrayDetector::with_default_names(),
            registration: CallbackRegDetector::with_default_names(),
            jump_table: JumpTableDetector::with_default_prefixes(),
        }
    }

    /// Read function-pointer array calls against `detector`'s name set
    /// instead of the standard one.
    pub fn with_fp_array(mut self, detector: FpArrayDetector) -> Self {
        self.fp_array = detector;
        self
    }

    /// Read callback registrations against `detector`'s name set
    /// instead of the standard one.
    pub fn with_registration(mut self, detector: CallbackRegDetector) -> Self {
        self.registration = detector;
        self
    }

    /// Read jump-table dispatches against `detector`'s prefix set
    /// instead of the standard one.
    pub fn with_jump_table(mut self, detector: JumpTableDetector) -> Self {
        self.jump_table = detector;
        self
    }

    /// Detect callback tables across `binary`, decompiling each
    /// function exactly once and reading it with every wired detector.
    ///
    /// `binary` names the program the scan reads (e.g. `eqmain.dll`)
    /// and becomes the key a persisted result is filed under. The
    /// findings follow the function listing — function by function,
    /// and within one function the function-pointer array calls, then
    /// the registrations, then the jump tables — so two scans of the
    /// same program diff cleanly.
    ///
    /// A function whose body Ghidra cannot produce (a thunk, a bad
    /// entry point) is skipped with a warning; only a failure of the
    /// listing itself — the server being down — aborts the run, since
    /// then nothing was scanned. The detectors read disjoint body
    /// shapes, so a function can carry findings of every kind at once
    /// and nothing is resolved between them.
    pub async fn scan(&self, binary: impl Into<String>) -> Result<CallbackResult>
    where
        S: ScanSource,
    {
        let started = Instant::now();
        let functions = self.source.functions().await?;

        let mut findings = Vec::new();
        let mut skipped = 0usize;
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
                    continue;
                }
            };

            findings.extend(
                self.fp_array
                    .detect(&decompiled)
                    .into_iter()
                    .map(CallbackFinding::FpArray),
            );
            findings.extend(
                self.registration
                    .detect(&decompiled)
                    .into_iter()
                    .map(CallbackFinding::Registration),
            );
            findings.extend(
                self.jump_table
                    .detect(&decompiled)
                    .into_iter()
                    .map(CallbackFinding::JumpTable),
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
            "Detected callback tables"
        );
        Ok(CallbackResult { metadata, findings })
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use calxgloss_ghidra::GhidraError;
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
                }
                .into());
            }
            Ok(self.listing.clone())
        }

        async fn decompile(&self, name: &str) -> Result<DecompiledFunction> {
            self.stats.decompiles.lock().unwrap().push(name.to_string());
            if self.fail_decompiles.iter().any(|f| f == name) {
                return Err(GhidraError::NotFound {
                    kind: "function",
                    query: name.to_string(),
                }
                .into());
            }
            self.bodies.get(name).cloned().ok_or_else(|| {
                GhidraError::NotFound {
                    kind: "function",
                    query: name.to_string(),
                }
                .into()
            })
        }
    }

    /// A body carrying a cast-dereference call through `handlers`, a
    /// bare indexed call through `dispatch`, a `register_callback`
    /// call, and a switch-table dispatch — one finding family per
    /// detector — all in one function.
    const EVERY_SHAPE_BODY: &str = "\
  (*(int (**)(int))handlers[uVar1])(param_1);
  dispatch[uVar2](param_2);
  register_callback(my_handler);
  (*(code *)(&switchD_1800412a0)[uVar3])();";

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
                EVERY_SHAPE_BODY,
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

    async fn scan(program: FakeProgram) -> CallbackResult {
        CallbackEngine::with_source(program)
            .scan("eqmain.dll")
            .await
            .expect("scan")
    }

    fn kinds(result: &CallbackResult, function: &str) -> Vec<&'static str> {
        result
            .for_function(function)
            .map(|finding| finding.kind())
            .collect()
    }

    #[tokio::test]
    async fn scan_collects_findings_from_the_wired_detectors() {
        let result = scan(program()).await;

        assert_eq!(result.metadata.binary, "eqmain.dll");
        assert!(result.metadata.scanned_at > 0);

        let findings: Vec<&CallbackFinding> = result.for_function("FUN_18003ab00").collect();
        assert_eq!(findings.len(), 4);

        let CallbackFinding::FpArray(record) = findings[0] else {
            unreachable!("the cast-dereference call reads as an fp-array finding");
        };
        assert_eq!(record.table, "handlers");
        assert_eq!(
            record.evidence,
            "(*(int (**)(int))handlers[uVar1])(param_1);"
        );

        let CallbackFinding::FpArray(record) = findings[1] else {
            unreachable!("the bare indexed call reads as an fp-array finding");
        };
        assert_eq!(record.table, "dispatch");
        assert_eq!(record.suggestion, "Vec<Box<dyn Fn(...)>>");

        let CallbackFinding::Registration(record) = findings[2] else {
            unreachable!("the registration call reads as a registration finding");
        };
        assert_eq!(record.registration, "register_callback");
        assert_eq!(record.callback, "my_handler");
        assert_eq!(record.suggestion, "Box<dyn Fn(...)>");

        let CallbackFinding::JumpTable(record) = findings[3] else {
            unreachable!("the switch-table dispatch reads as a jump-table finding");
        };
        assert_eq!(record.table, "switchD_1800412a0");
        assert_eq!(record.index, "uVar3");
        assert_eq!(record.suggestion, "match index { ... }");

        assert!(result.for_function("FUN_18003e750").next().is_none());
    }

    #[tokio::test]
    async fn scan_keeps_findings_in_scan_order() {
        // Both functions carry the shape, so the persisted list must
        // group their findings by function in listing order — never
        // interleaved.
        let mut program = program();
        program.listing = vec![summary("FUN_18003e750"), summary("FUN_18003ab00")];
        program.bodies.insert(
            "FUN_18003e750".into(),
            function(
                "FUN_18003e750",
                "undefined FUN_18003e750(void)",
                EVERY_SHAPE_BODY,
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
                ("FUN_18003e750", "fp_array"),
                ("FUN_18003e750", "fp_array"),
                ("FUN_18003e750", "registration"),
                ("FUN_18003e750", "jump_table"),
                ("FUN_18003ab00", "fp_array"),
                ("FUN_18003ab00", "fp_array"),
                ("FUN_18003ab00", "registration"),
                ("FUN_18003ab00", "jump_table"),
            ]
        );
    }

    #[tokio::test]
    async fn scan_decompiles_each_function_exactly_once() {
        // Every detector shares one fetch per function; a scan that
        // asked each detector for its own copy would multiply the
        // wall time.
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
        let result = CallbackEngine::with_source(program)
            .scan("eqmain.dll")
            .await;
        assert!(matches!(
            result,
            Err(crate::CallbackError::Ghidra(GhidraError::Reported { .. }))
        ));
    }

    #[tokio::test]
    async fn custom_name_sets_reach_every_detector() {
        // Swapping a detector's set whole reaches the scan: the
        // configured custom spelling calls in the body, and the
        // standard names the swap replaced call nothing.
        let mut program = FakeProgram::empty();
        program.listing = vec![summary("FUN_1800412a0")];
        program.bodies.insert(
            "FUN_1800412a0".into(),
            function(
                "FUN_1800412a0",
                "undefined FUN_1800412a0(void)",
                "\
  (*(code *)msg_table[uVar1])(param_1);
  HookMessage(wnd_proc);
  (*(&tbl_events[uVar2]))(param_2);",
            ),
        );

        let engine = CallbackEngine::with_source(program)
            .with_fp_array(FpArrayDetector::with_names(["msg_table"]))
            .with_registration(CallbackRegDetector::with_names(["HookMessage"]))
            .with_jump_table(JumpTableDetector::with_prefixes(["tbl_"]));
        let result = engine.scan("eqmain.dll").await.expect("scan");

        assert_eq!(
            kinds(&result, "FUN_1800412a0"),
            ["fp_array", "registration", "jump_table"]
        );
        let findings: Vec<&CallbackFinding> = result.for_function("FUN_1800412a0").collect();
        let CallbackFinding::FpArray(record) = findings[0] else {
            unreachable!("the configured table call reads as an fp-array finding");
        };
        assert_eq!(record.table, "msg_table");
        assert_eq!(record.suggestion, "Vec<Box<dyn Fn(...)>>");
        let CallbackFinding::Registration(record) = findings[1] else {
            unreachable!("the configured registration reads as a registration finding");
        };
        assert_eq!(record.registration, "HookMessage");
        assert_eq!(record.callback, "wnd_proc");
        let CallbackFinding::JumpTable(record) = findings[2] else {
            unreachable!("the configured table prefix reads as a jump-table finding");
        };
        assert_eq!(record.table, "tbl_events");
        assert_eq!(record.index, "uVar2");
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
