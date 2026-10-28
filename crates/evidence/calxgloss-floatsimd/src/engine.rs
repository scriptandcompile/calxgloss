//! Float/SIMD usage scan orchestration.
//!
//! [`FloatsimdEngine`] decompiles every function of one open program
//! and reads each body with the [`FloatsimdDetector`], combining the
//! per-function flags into a single [`FloatsimdResult`] with its scan
//! provenance.
//!
//! The detector is pure text analysis over one decompiled body, so
//! the evidence engine fetches each function's pseudo-C exactly once,
//! and the scan stays one sequential pass over the function listing.
//! Nothing needs resolving between bodies — each flag names its own
//! function. Keeping the pass sequential keeps the persisted flag list
//! in listing order, stable and diffable across scans. The reading
//! makes no engine read beyond the decompiles themselves: every
//! evidence family keys on text in the body the scan already keeps.

use crate::detector::FloatsimdDetector;
use crate::error::Result;
use crate::types::FloatsimdResult;
use calxgloss_kuna::KunaSource;
use calxgloss_types::{CoverageStatus, FacetCoverage, ScanCoverage, ScanMetadata};
use std::time::Instant;
use tracing::{info, warn};

/// The decompiler seam's read side that a float/SIMD scan reads through.
///
/// The shared trait from the decompiler seam crate, re-exported here so
/// the evidence engine's generic parameter names it directly;
/// [`KunaSource`] implements it over the in-process analysis engine,
/// and tests implement it over canned bodies so the orchestration runs
/// without a server. The futures are `Send` so a scan can be driven
/// from an orchestrating task.
pub use calxgloss_decomp::ScanSource;

/// How many unreached functions one coverage limitation line names
/// inline before the rest become a plain count — the prose beside the
/// counts stays bounded, it is not a dump (the P19-3 admitted-semantics
/// track).
const MAX_NAMED_UNREACHED: usize = 5;

/// The facets a floatsimd scan declares, in order — the roster the
/// record must name exactly once each. floatsimd reads one facet:
/// the decompiled bodies.
pub const DECLARED_FACETS: &[&str] = &["function-bodies"];

/// The coverage record every floatsimd scan stamps about itself (issue
/// #347), beside the provenance and the timing.
///
/// floatsimd has one facet: `function-bodies`, the decompiled bodies
/// the float/SIMD detector reads. The function listing is always read
/// end to end — a failed listing aborts the run, and more than half
/// failing to decompile trips the skip-rate breaker. So what a
/// finished scan could not read is exactly the bodies it skipped along
/// the way: a nameless listing entry, or a decompile that failed.
///
/// When nothing was skipped, the facet is `complete`, and that is the
/// admission's point: a function no flag mentions was examined and
/// clean, never silently unchecked — the record tells the clean body
/// apart from the never-reached body. When anything was skipped, the
/// facet is `partial`, and the limitation line names the unreached
/// bodies (at most [`MAX_NAMED_UNREACHED`] of them) and nothing else.
/// The whole-record status mirrors the single facet — the scan
/// examines nothing else.
fn coverage_stamp(unreached: &[String], nameless: usize) -> ScanCoverage {
    let total = unreached.len() + nameless;
    if total == 0 {
        return ScanCoverage {
            status: CoverageStatus::Complete,
            facets: vec![FacetCoverage {
                id: "function-bodies".to_string(),
                status: CoverageStatus::Complete,
                limitation: None,
            }],
        };
    }
    let mut names = unreached
        .iter()
        .take(MAX_NAMED_UNREACHED)
        .cloned()
        .collect::<Vec<_>>();
    let hidden = unreached.len().saturating_sub(names.len()) + nameless;
    if hidden > 0 {
        names.push(format!("+{hidden} more"));
    }
    let body = if total == 1 { "body" } else { "bodies" };
    ScanCoverage {
        status: CoverageStatus::Partial,
        facets: vec![FacetCoverage {
            id: "function-bodies".to_string(),
            status: CoverageStatus::Partial,
            limitation: Some(format!(
                "{total} function {body} unreached: {}",
                names.join(", ")
            )),
        }],
    }
}

/// Orchestrates the per-body float evidence reading into one
/// [`FloatsimdResult`].
///
/// The evidence engine is generic over its [`ScanSource`], so tests
/// can run the whole orchestration over canned bodies;
/// [`new`](Self::new) builds one over a loaded [`KunaSource`]. The
/// detector keeps no state, so one instance serves the whole scan,
/// and [`with_detector`](Self::with_detector) swaps in a configured
/// one.
#[derive(Debug, Clone)]
pub struct FloatsimdEngine<S = KunaSource> {
    source: S,
    detector: FloatsimdDetector,
}

impl FloatsimdEngine<KunaSource> {
    /// A scan over a loaded Kuna program, using the detector's
    /// standard reading.
    pub fn new(source: &KunaSource) -> FloatsimdEngine<KunaSource> {
        FloatsimdEngine {
            source: source.clone(),
            detector: FloatsimdDetector::new(),
        }
    }
}

impl<S> FloatsimdEngine<S> {
    /// A scan whose decompiles come from `source`, using the
    /// detector's standard reading.
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
    /// flag — absence of a body is not evidence of integer-only math.
    /// Only a failure of the listing itself — the server being down —
    /// aborts the run, since then nothing was scanned. But when more
    /// than half the listing fails to decompile, the skip-rate
    /// breaker aborts the run too: a high skip rate is the signature
    /// of the seam answering about the wrong program, and skipping on
    /// would persist a record that looks clean but is not (issue #71,
    /// the same breaker the other evidence engines run on).
    pub async fn scan(&self, binary: impl Into<String>) -> Result<FloatsimdResult>
    where
        S: ScanSource,
    {
        let started = Instant::now();
        let functions = self.source.functions().await?;

        let mut findings = Vec::new();
        let mut skipped = 0usize;
        let mut decompile_failures = 0usize;
        // P19-3: which bodies the scan could NOT read — named where a
        // name exists, counted where the listing entry is nameless. The
        // coverage record below states this, so an unflagged function
        // means examined-and-clean, never silently unchecked.
        let mut unreached: Vec<String> = Vec::new();
        let mut nameless = 0usize;
        for function in &functions {
            if function.name.is_empty() {
                // A nameless listing entry would let a by-name lookup
                // land in some other function's body, so it is never
                // looked up; nothing can be said about it beyond the
                // coverage count it adds to.
                warn!(
                    address = format_args!("{:#x}", function.address),
                    "Skipping function with no name"
                );
                skipped += 1;
                nameless += 1;
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
                    unreached.push(function.name.clone());
                    // Skip-rate breaker: once more than half the listing
                    // has failed to decompile, the scan is reading a
                    // program the analysis engine cannot analyze, and
                    // skipping on would persist a record that looks
                    // clean but is not. Abort with the counts instead of
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

            // At most one flag per function: the detector combines the
            // body's whole evidence picture into one record naming the
            // shape, so flags count per function, not per signal.
            if let Some(flag) = self.detector.detect(&decompiled) {
                findings.push(flag);
            }
        }

        let mut metadata = ScanMetadata::new(binary);
        // The source names its analysis engine and pin under `kuna`
        // (issue #208).
        metadata.engine = self.source.engine_provenance();
        // The scan admits its own coverage inside its own record, where
        // the truth lives — not the registry row and not the CLI (issue
        // #347): every listed body was read unless the scan names which
        // ones it could not reach, so a flagless function is
        // examined-and-clean rather than unchecked. The batch scan
        // phase and the CLI's force-rescan write the same admission
        // through this one definition.
        metadata.coverage = Some(coverage_stamp(&unreached, nameless));
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
    /// read what the scan did after the scan has consumed its source.
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
        // The fake source names itself, so the tests can check that
        // scan() copies the source's provenance onto the record (#208).
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
        // The decompiler cannot produce a body for every function. One
        // bad entry point must not stop the whole program's scan.
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
        // signature of the seam answering about the wrong program.
        // The scan aborts with the counts instead of persisting a
        // record that looks clean but is not (issue #71).
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
        // The breaker is a fuse, not a post-mortem: once more than
        // half the listing has failed, the remaining decompiles are
        // wasted round-trips against the wrong program.
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
        // arbitrary function's body, so the entry is skipped without a
        // decompile.
        let mut program = program();
        program.listing.insert(0, summary(""));
        let result = scan(program.clone()).await;

        assert_eq!(program.decompiled(), vec!["FUN_18003ab00", "FUN_18003e750"]);
        assert!(!result.is_empty());
    }

    #[tokio::test]
    async fn a_failing_listing_fails_the_whole_run() {
        // With the listing gone, nothing was scanned. The run aborts
        // instead of returning a result that looks empty as if the
        // detection had run.
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
        // set. The record also names the analysis engine that produced
        // it: scan() copies the source's provenance through (#208).
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

    // ============================================================
    // Admitted scan coverage (issue #347)
    // ============================================================

    /// What the roster pin finds, as data: an empty list means the
    /// record names every declared facet exactly once, and each fault
    /// describes one problem with the record.
    fn roster_faults(coverage: &ScanCoverage) -> Vec<String> {
        coverage.roster_faults(DECLARED_FACETS)
    }

    #[tokio::test]
    async fn a_fresh_scan_stamps_complete_bodies_coverage_and_a_clean_roster() {
        // The coverage stamp is written by the scan itself, not by the
        // registry row and not by the CLI — the batch scan phase and
        // the CLI's force-rescan write the same admission through this
        // one definition. Every body was read here — one flagged, one
        // clean — so the record is complete, and the clean body needs
        // no admission: silence after this stamp means
        // examined-and-clean.
        let result = scan(program()).await;
        assert_eq!(result.findings.len(), 1, "one body carries float evidence");
        let coverage = result
            .metadata
            .coverage
            .expect("a fresh floatsimd scan states its coverage");
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
        assert_eq!(bodies.limitation, None);
    }

    #[tokio::test]
    async fn a_never_reached_body_is_admitted_and_a_clean_body_is_not() {
        // This scan holds, in one place, the distinction silence used
        // to blur: a flagged body, an examined-and-clean body, and a
        // body the decompiler never produced. The limitation line names
        // ONLY the third.
        let mut program = program();
        program.listing.push(summary("FUN_1800412a0"));
        program.bodies.insert(
            "FUN_1800412a0".into(),
            function("FUN_1800412a0", "  xmm0 = __fmsub(xmm0, xmm1, xmm2);\n"),
        );
        program.fail_decompiles = vec!["FUN_18003e750".into()];
        let result = scan(program).await;
        let coverage = result
            .metadata
            .coverage
            .expect("a partial floatsimd scan states its coverage too");
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
            "the never-reached body is named; the flagged and the clean \
             bodies are not — silence means clean from here on"
        );
    }

    #[tokio::test]
    async fn the_coverage_line_is_capped_at_five_names_and_counts_the_nameless() {
        // Bounded prose beside the counts: six decompile failures name
        // five of them inline, and the sixth is counted instead of
        // named. A nameless listing entry counts toward the total
        // without taking one of the five name slots.
        let names: Vec<String> = (0..12).map(|i| format!("FUN_body_{i:04}")).collect();
        let mut program = FakeProgram::empty();
        for (index, name) in names.iter().enumerate() {
            program.listing.push(FunctionSummary {
                name: name.clone(),
                address: 0x1800_0000 + index as u64,
            });
            if index >= 6 {
                program
                    .bodies
                    .insert(name.clone(), function(name, "  return uVar1 + 4;\n"));
            }
        }
        program.fail_decompiles = names[..6].to_vec();
        program.listing.push(summary(""));
        let result = scan(program).await;
        let bodies = result
            .metadata
            .coverage
            .expect("a partial floatsimd scan states its coverage")
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
        let mut coverage = coverage_stamp(&["FUN_18003ab00".to_string()], 0);
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
            id: "import-table".to_string(),
            status: CoverageStatus::Unexamined,
            limitation: None,
        });
        assert_eq!(
            roster_faults(&coverage),
            ["record names `import-table`, a facet the engine never declared"],
            "an id invented outside the declared roster fails loudly"
        );
    }
}
