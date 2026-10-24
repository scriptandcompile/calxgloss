//! Float/SIMD usage scan orchestration.
//!
//! [`FloatsimdEngine`] decompiles every function of one open program
//! and reads each body with the [`FloatsimdDetector`], assembling the
//! per-function flags into a single [`FloatsimdResult`] with its scan
//! provenance.
//!
//! The detector is pure text analysis over one decompiled body, so
//! the engine fetches each function's pseudo-C exactly once and keeps
//! the scan one sequential pass over the function listing: there is
//! nothing to resolve between bodies — each flag names its own
//! function — and keeping the pass sequential keeps the persisted
//! flag list in listing order, stable and diffable across scans.
//! The reading makes no engine read beyond the decompiles themselves:
//! every family keys on the body the scan already keeps.

use crate::detector::FloatsimdDetector;
use crate::error::Result;
use crate::types::FloatsimdResult;
use calxgloss_kuna::KunaSource;
use calxgloss_types::ScanMetadata;
use std::time::Instant;
use tracing::{info, warn};

/// The decompiler a float/SIMD scan reads.
///
/// The shared trait from the decompiler seam crate, re-exported here
/// so the engine's generic shape names it where it always has;
/// [`KunaSource`] implements it over the in-process engine, and tests
/// implement it over canned bodies so the orchestration runs without
/// a server. The futures are `Send` so a scan can be driven from an
/// orchestrating task.
pub use calxgloss_decomp::ScanSource;

/// Orchestrates the per-body float evidence reading into one
/// [`FloatsimdResult`].
///
/// The engine is generic over its [`ScanSource`], so tests can run
/// the whole orchestration over canned bodies; [`new`](Self::new)
/// builds one over a loaded [`KunaSource`]. The detector carries no
/// state, so one instance serves the whole scan, and
/// [`with_detector`](Self::with_detector) swaps it for a configured
/// one.
#[derive(Debug, Clone)]
pub struct FloatsimdEngine<S = KunaSource> {
    source: S,
    detector: FloatsimdDetector,
}

impl FloatsimdEngine<KunaSource> {
    /// An engine over a loaded Kuna program, scanning with the
    /// detector's standard reading.
    pub fn new(source: &KunaSource) -> FloatsimdEngine<KunaSource> {
        FloatsimdEngine {
            source: source.clone(),
            detector: FloatsimdDetector::new(),
        }
    }
}

impl<S> FloatsimdEngine<S> {
    /// An engine whose decompiles come from `source`, scanning with
    /// the detector's standard reading.
    pub fn with_source(source: S) -> Self {
        FloatsimdEngine {
            source,
            detector: FloatsimdDetector::new(),
        }
    }

    /// Read bodies with `detector` instead of the standard one.
    pub fn with_detector(mut self, detector: FloatsimdDetector) -> Self {
        self.detector = detector;
        self
    }

    /// Flag the float/SIMD usage across `binary`, decompiling each
    /// function exactly once and reading it with the detector.
    ///
    /// `binary` names the program the scan reads (e.g.
    /// `game_logic.dll`) and becomes the key a persisted result is
    /// filed under. The flags follow the function listing — one flag
    /// per flagged function, in listing order — so two scans of the
    /// same program diff cleanly.
    ///
    /// A function whose body the decompiler cannot produce (a thunk,
    /// a bad entry point) is skipped with a warning and claims no
    /// flag — absence of a body is not evidence of integer-only math;
    /// only a failure of the listing itself — the server being down —
    /// aborts the run, since then nothing was scanned. But when more
    /// than half the listing fails to decompile, the skip-rate
    /// breaker aborts the run too: that is the signature of the
    /// bridge answering from the wrong program, and skipping on would
    /// persist a phantom-clean record (issue #71, the same rail the
    /// other evidence scans run on).
    pub async fn scan(&self, binary: impl Into<String>) -> Result<FloatsimdResult>
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
                    // failed to decompile, the scan is reading a
                    // program the engine cannot analyze, and an
                    // empty result would persist as a phantom-clean
                    // record. Abort with the counts instead of
                    // skipping on.
                    if decompile_failures * 2 > functions.len() {
                        return Err(crate::FloatsimdError::DecompileBreaker {
                            failed: decompile_failures,
                            total: functions.len(),
                        });
                    }
                    continue;
                }
            };

            // At most one flag per function: the detector folds the
            // body's whole evidence picture into one record naming
            // the shape, so the breakdown reads per function, not per
            // signal.
            if let Some(flag) = self.detector.detect(&decompiled) {
                findings.push(flag);
            }
        }

        let mut metadata = ScanMetadata::new(binary);
        // The source names its engine and pin under `kuna` (issue #208).
        metadata.engine = self.source.engine_provenance();
        metadata.duration_secs = started.elapsed().as_secs();
        info!(
            binary = %metadata.binary,
            functions = functions.len(),
            findings = findings.len(),
            skipped,
            duration_secs = metadata.duration_secs,
            "Detected float/SIMD usage"
        );
        Ok(FloatsimdResult { metadata, findings })
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::FloatsimdFinding;
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

    fn function(name: &str, body: &str) -> DecompiledFunction {
        DecompiledFunction {
            name: name.to_string(),
            signature: format!("undefined {name}(void)"),
            body: format!("undefined {name}(void)\n\n{{\n{body}}}\n"),
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

        // The rest of the shared trait's reads: this engine never
        // makes them, so they answer with empty or not-found data.
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
        // The fake source names itself, so the tests can pin that
        // scan() stamps the source's provenance onto the record (#208).
        fn engine_provenance(&self) -> Option<calxgloss_types::EngineProvenance> {
            Some(calxgloss_types::EngineProvenance {
                name: "fake-engine".into(),
                version: Some("9.9".into()),
                fingerprint: Some("0123456".into()),
            })
        }
    }

    /// The canned program: one function with an explicit float cast
    /// and literal, and one integer function the reading must leave
    /// unflagged.
    fn program() -> FakeProgram {
        let mut program = FakeProgram::empty();
        program.listing = vec![summary("FUN_18003ab00"), summary("FUN_18003e750")];
        program.bodies.insert(
            "FUN_18003ab00".into(),
            function(
                "FUN_18003ab00",
                "  fVar1 = (float)uVar2;\n  fVar3 = fVar1 * 1.5f;\n",
            ),
        );
        program.bodies.insert(
            "FUN_18003e750".into(),
            function("FUN_18003e750", "  return uVar1 + 4;\n"),
        );
        program
    }

    async fn scan(program: FakeProgram) -> FloatsimdResult {
        FloatsimdEngine::with_source(program)
            .scan("game_logic.dll")
            .await
            .expect("scan")
    }

    #[tokio::test]
    async fn scan_flags_every_body_with_float_evidence() {
        let result = scan(program()).await;

        assert_eq!(result.metadata.binary, "game_logic.dll");
        assert!(result.metadata.scanned_at > 0);

        let flags: Vec<&FloatsimdFinding> = result.for_function("FUN_18003ab00").collect();
        assert_eq!(flags.len(), 1, "one flag per function, not one per signal");

        let FloatsimdFinding::ScalarFloat(record) = flags[0] else {
            unreachable!("the spelled float reads as a scalar shape");
        };
        assert_eq!(record.evidence, "fVar1 = (float)uVar2;");
        assert_eq!(record.confidence.value(), 90);
        assert!(record.suggestion.contains("f32/f64"));

        assert!(
            result.for_function("FUN_18003e750").next().is_none(),
            "the integer body lands no flag"
        );
    }

    #[tokio::test]
    async fn scan_keeps_flags_in_listing_order() {
        // The scan-order contract: the persisted flag list follows
        // the function listing, never sorted or interleaved another
        // way, so two scans of one program diff cleanly.
        let mut program = program();
        program.listing = vec![summary("FUN_18003e750"), summary("FUN_18003ab00")];
        program.bodies.insert(
            "FUN_18003e750".into(),
            function(
                "FUN_18003e750",
                "  local_10 = CONCAT44(uVar2 >> 4, uVar2);\n",
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
                ("FUN_18003e750", "vector_matrix"),
                ("FUN_18003ab00", "scalar_float"),
            ],
            "one flag per flagged function, in listing order"
        );
    }

    #[tokio::test]
    async fn a_body_with_both_shapes_lands_one_mixed_flag() {
        let mut program = program();
        program.bodies.insert(
            "FUN_18003e750".into(),
            function(
                "FUN_18003e750",
                "  fVar1 = sqrt((float)uVar2);\n  local_10 = CONCAT44(fVar1, fVar2);\n",
            ),
        );
        let result = scan(program).await;

        let flags: Vec<&FloatsimdFinding> = result.for_function("FUN_18003e750").collect();
        assert_eq!(flags.len(), 1, "both shapes in one body read as one flag");
        assert_eq!(flags[0].kind(), "mixed");
        assert_eq!(flags[0].confidence().value(), 90);
        assert_eq!(flags[0].evidence(), "fVar1 = sqrt((float)uVar2);");
    }

    #[tokio::test]
    async fn scan_decompiles_each_function_exactly_once() {
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
        // The decompiler cannot produce a body for every function; one
        // bad entry point must not cost the whole program its scan.
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
        // The skip-rate breaker: every decompile failing is the
        // signature of the bridge answering from the wrong program,
        // and the scan aborts with the counts rather than persisting
        // a phantom-clean record (issue #71).
        let mut program = program();
        program.fail_decompiles = vec!["FUN_18003ab00".into(), "FUN_18003e750".into()];
        let result = FloatsimdEngine::with_source(program)
            .scan("game_logic.dll")
            .await;
        assert!(matches!(
            result,
            Err(crate::FloatsimdError::DecompileBreaker {
                failed: 2,
                total: 2
            })
        ));
    }

    #[tokio::test]
    async fn the_breaker_stops_the_scan_from_decompiling_the_rest() {
        // The breaker is a circuit breaker, not a post-mortem: once
        // most of the listing has failed, the remaining decompiles
        // are wasted round-trips against the wrong program.
        let mut program = program();
        program.listing.push(summary("FUN_1800412a0"));
        program.bodies.insert(
            "FUN_1800412a0".into(),
            function("FUN_1800412a0", "  fVar1 = 1.0f;\n"),
        );
        program.fail_decompiles = vec!["FUN_18003ab00".into(), "FUN_18003e750".into()];
        let result = FloatsimdEngine::with_source(program.clone())
            .scan("game_logic.dll")
            .await;

        assert!(matches!(
            result,
            Err(crate::FloatsimdError::DecompileBreaker {
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
        // With the listing gone nothing was scanned, so the run
        // aborts rather than returning a result that looks empty by
        // detection.
        let mut program = program();
        program.fail_listing = true;
        let result = FloatsimdEngine::with_source(program)
            .scan("game_logic.dll")
            .await;
        assert!(matches!(
            result,
            Err(crate::FloatsimdError::Engine(EngineError::Reported { .. }))
        ));
    }

    #[tokio::test]
    async fn scan_stamps_the_scan_provenance() {
        // The metadata names the binary, carries a finish time, and
        // the duration is stamped from the wall clock — a canned scan
        // is instant, so it reads as zero seconds rather than never
        // set. The record also names the engine that produced it:
        // scan() copies the source's provenance through (#208).
        let result = scan(program()).await;
        assert_eq!(result.metadata.binary, "game_logic.dll");
        assert!(result.metadata.scanned_at > 0);
        assert!(result.metadata.duration_secs < 60);
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
        assert_eq!(result.metadata.binary, "game_logic.dll");
        assert!(result.metadata.scanned_at > 0);
    }
}
