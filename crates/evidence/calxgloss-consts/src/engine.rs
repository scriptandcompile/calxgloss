//! Constant scan orchestration.
//!
//! [`ConstEngine`] runs the three detectors — bitmask group detection,
//! sequential enum candidate detection, and repeated-value frequency
//! analysis — over every function of one open Ghidra program and
//! assembles their findings into a single [`ConstResult`] with its
//! scan provenance.
//!
//! The detectors are pure text analysis over one decompiled body, so
//! the engine fetches each function's pseudo-C exactly once and reads
//! it with all three, rather than having each detector pull its own
//! copy. The frequency analyzer counts literals during that same
//! pass, and its program-level findings are appended after the
//! per-function ones. The scan is one sequential pass over the
//! function listing — like sync, there is nothing to resolve between
//! the detectors, they read disjoint shapes — and keeping the pass
//! sequential keeps the persisted finding list in a stable, diffable
//! order.

use std::time::Instant;

use calxgloss_ghidra::{DecompiledFunction, FunctionSummary, GhidraClient};
use tracing::{info, warn};

use crate::bitmask::BitmaskDetector;
use crate::error::Result;
use crate::frequency::{FrequencyAnalyzer, ProgramTally};
use crate::sequential::SequentialDetector;
use crate::types::{ConstFinding, ConstResult, ScanMetadata};

/// The decompiler a constant scan reads.
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

/// Orchestrates the three detectors into one [`ConstResult`].
///
/// The engine is generic over its [`ScanSource`], so tests can run the
/// whole orchestration over canned bodies; [`new`](Self::new) builds
/// one over a live [`GhidraClient`]. Each detector carries no state
/// and starts configured with its standard thresholds —
/// [`with_bitmask`](Self::with_bitmask), [`with_sequential`](Self::with_sequential),
/// and [`with_frequency`](Self::with_frequency) swap a detector's
/// thresholds whole — so one instance of each serves the whole scan.
#[derive(Debug, Clone)]
pub struct ConstEngine<S = GhidraClient> {
    source: S,
    bitmask: BitmaskDetector,
    sequential: SequentialDetector,
    frequency: FrequencyAnalyzer,
}

impl ConstEngine<GhidraClient> {
    /// An engine over a live GhidraMCP client, scanning with the three
    /// detectors' standard thresholds.
    pub fn new(client: &GhidraClient) -> ConstEngine<GhidraClient> {
        ConstEngine {
            source: client.clone(),
            bitmask: BitmaskDetector::with_default_threshold(),
            sequential: SequentialDetector::with_default_threshold(),
            frequency: FrequencyAnalyzer::with_default_thresholds(),
        }
    }
}

impl<S> ConstEngine<S> {
    /// An engine whose decompiles come from `source`, scanning with
    /// the three detectors' standard thresholds.
    pub fn with_source(source: S) -> Self {
        ConstEngine {
            source,
            bitmask: BitmaskDetector::with_default_threshold(),
            sequential: SequentialDetector::with_default_threshold(),
            frequency: FrequencyAnalyzer::with_default_thresholds(),
        }
    }

    /// Read flag groups against `detector`'s threshold instead of the
    /// standard one.
    pub fn with_bitmask(mut self, detector: BitmaskDetector) -> Self {
        self.bitmask = detector;
        self
    }

    /// Read enum candidates against `detector`'s threshold instead of
    /// the standard one.
    pub fn with_sequential(mut self, detector: SequentialDetector) -> Self {
        self.sequential = detector;
        self
    }

    /// Count repeated values against `detector`'s thresholds instead
    /// of the standard ones.
    pub fn with_frequency(mut self, detector: FrequencyAnalyzer) -> Self {
        self.frequency = detector;
        self
    }

    /// Detect constant structures across `binary`, decompiling each
    /// function exactly once and reading it with all three detectors.
    ///
    /// `binary` names the program the scan reads (e.g. `eqmain.dll`)
    /// and becomes the key a persisted result is filed under. The
    /// per-function findings follow the function listing — function by
    /// function, bitmask group then enum candidates — and the
    /// program-level named constants the frequency analyzer tallied
    /// across the pass are appended after them, so two scans of the
    /// same program diff cleanly.
    ///
    /// A function whose body Ghidra cannot produce (a thunk, a bad
    /// entry point) is skipped with a warning; only a failure of the
    /// listing itself — the server being down — aborts the run, since
    /// then nothing was scanned.
    /// But when more than half the listing fails to decompile, the
    /// skip-rate breaker aborts the run too: that is the signature of
    /// the bridge answering from the wrong program, and skipping on
    /// would persist a phantom-clean record (issue #71).
    /// The three detectors read disjoint
    /// shapes, so a function can carry findings of every kind at once
    /// and nothing is resolved between them.
    pub async fn scan(&self, binary: impl Into<String>) -> Result<ConstResult>
    where
        S: ScanSource,
    {
        let started = Instant::now();
        let functions = self.source.functions().await?;

        let mut findings = Vec::new();
        let mut tally = ProgramTally::new();
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
                        return Err(crate::ConstError::DecompileBreaker {
                            failed: decompile_failures,
                            total: functions.len(),
                        });
                    }
                    continue;
                }
            };

            if let Some(group) = self.bitmask.detect(&function.name, &decompiled.body) {
                findings.push(ConstFinding::BitflagGroup(group));
            }
            findings.extend(
                self.sequential
                    .detect(&function.name, &decompiled.body)
                    .into_iter()
                    .map(ConstFinding::EnumCandidate),
            );
            for value in self.frequency.literals(&decompiled.body) {
                let entry = tally.entry(value).or_default();
                entry.count += 1;
                entry.functions.insert(function.name.clone());
            }
        }

        findings.extend(
            self.frequency
                .constants(&tally)
                .into_iter()
                .map(ConstFinding::NamedConstant),
        );

        let mut metadata = ScanMetadata::new(binary);
        metadata.duration_secs = started.elapsed().as_secs();
        info!(
            binary = %metadata.binary,
            functions = functions.len(),
            findings = findings.len(),
            skipped,
            duration_secs = metadata.duration_secs,
            "Detected constant structures"
        );
        Ok(ConstResult { metadata, findings })
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bitmask::BitmaskDetector;
    use crate::sequential::SequentialDetector;
    use crate::types::Confidence;
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

    /// A body carrying a flag-bit pair, a four-case switch run, and a
    /// repeated magic number — one finding family per detector — all
    /// in one function.
    const EVERY_SHAPE_BODY: &str = "  if ((uVar1 & 0x400) != 0) {\n    uVar1 |= 0x100;\n  }\n  switch(local_10) {\n  case 0:\n  case 1:\n  case 2:\n  case 3:\n    dispatch();\n  }\n  size = 0x280;\n  copy(dst, 0x280);\n";

    /// The canned program: one function whose body carries every
    /// shape, and one plain function that repeats the magic number so
    /// the frequency analyzer sees it across two functions.
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
                "  reserve(0x280);\n  return;\n",
            ),
        );
        program
    }

    async fn scan(program: FakeProgram) -> ConstResult {
        ConstEngine::with_source(program)
            .scan("eqmain.dll")
            .await
            .expect("scan")
    }

    fn kinds(result: &ConstResult, function: &str) -> Vec<&'static str> {
        result
            .for_function(function)
            .map(|finding| finding.kind())
            .collect()
    }

    #[tokio::test]
    async fn scan_collects_findings_from_all_three_detectors() {
        let result = scan(program()).await;

        assert_eq!(result.metadata.binary, "eqmain.dll");
        assert!(result.metadata.scanned_at > 0);

        let findings: Vec<&ConstFinding> = result.for_function("FUN_18003ab00").collect();
        assert_eq!(findings.len(), 3);

        let ConstFinding::BitflagGroup(group) = findings[0] else {
            unreachable!("the flag bits read as a bitflag finding");
        };
        assert_eq!(group.bits, vec![8, 10]);
        assert_eq!(group.mask, 0x500);
        assert_eq!(group.confidence, Confidence::new(70));

        let ConstFinding::EnumCandidate(candidate) = findings[1] else {
            unreachable!("the case run reads as an enum finding");
        };
        assert_eq!(candidate.values, vec![0, 1, 2, 3]);
        assert_eq!(
            candidate.suggestion,
            "enum State { /* variants for 0..=3 */ }"
        );

        let ConstFinding::NamedConstant(constant) = findings[2] else {
            unreachable!("the repeated literal reads as a named-constant finding");
        };
        assert_eq!(constant.value, 0x280);
        assert_eq!(constant.count, 3);
        assert_eq!(constant.confidence, Confidence::new(60));

        // The named constant belongs to both functions that use it.
        assert_eq!(kinds(&result, "FUN_18003e750"), ["named_constant"]);
    }

    #[tokio::test]
    async fn scan_keeps_findings_in_scan_order() {
        // Both functions carry every shape, so the persisted list must
        // group their per-function findings by function in listing
        // order — bitmask then enum — and append the program-level
        // named constants after them, never interleaved.
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
                ("FUN_18003e750", "bitflag_group"),
                ("FUN_18003e750", "enum_candidate"),
                ("FUN_18003ab00", "bitflag_group"),
                ("FUN_18003ab00", "enum_candidate"),
                ("", "named_constant"),
            ]
        );
    }

    #[tokio::test]
    async fn scan_decompiles_each_function_exactly_once() {
        // The three detectors share one fetch per function; a scan
        // that asked each detector for its own copy would triple the
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
            "the failing function contributed nothing and the plain one carries no shape alone"
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
        let result = ConstEngine::with_source(program).scan("eqmain.dll").await;
        assert!(matches!(
            result,
            Err(crate::ConstError::DecompileBreaker {
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
        let result = ConstEngine::with_source(program.clone())
            .scan("eqmain.dll")
            .await;

        assert!(matches!(
            result,
            Err(crate::ConstError::DecompileBreaker {
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
        let result = ConstEngine::with_source(program).scan("eqmain.dll").await;
        assert!(matches!(
            result,
            Err(crate::ConstError::Ghidra(GhidraError::Reported { .. }))
        ));
    }

    #[tokio::test]
    async fn custom_thresholds_reach_every_detector() {
        // Swapping a detector's thresholds whole reaches the scan: the
        // configured bars find shapes the standard ones miss, and the
        // standard bars miss these shapes.
        let mut program = FakeProgram::empty();
        program.listing = vec![summary("FUN_1800412a0")];
        program.bodies.insert(
            "FUN_1800412a0".into(),
            function(
                "FUN_1800412a0",
                "undefined FUN_1800412a0(void)",
                "  x &= 0x1;\n  switch(u) {\n  case 0:\n  case 1:\n    a();\n  }\n  b(7);\n  c(7);\n  d(7);\n  e(7);\n",
            ),
        );

        let engine = ConstEngine::with_source(program.clone())
            .with_bitmask(BitmaskDetector::with_min_bits(1))
            .with_sequential(SequentialDetector::with_min_run(2))
            .with_frequency(FrequencyAnalyzer::with_thresholds(4, 1, [0, 1, 2]));
        let result = engine.scan("eqmain.dll").await.expect("scan");

        assert_eq!(
            kinds(&result, "FUN_1800412a0"),
            ["bitflag_group", "enum_candidate", "named_constant"]
        );
        // The standard configuration finds none of these shapes.
        let standard = ConstEngine::with_source(program)
            .scan("eqmain.dll")
            .await
            .expect("scan");
        assert!(standard.is_empty());
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
