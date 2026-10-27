//! Global-state scan orchestration.
//!
//! [`GlobalStateEngine`] decompiles every function of one open
//! program and reads each body with the [`GlobalStateDetector`],
//! assembling the access records into a single [`GlobalStateResult`].
//! The result also holds the scan's provenance, the derived
//! per-function [`FunctionPurity`] summary, and the shared-globals
//! index that the [`rollup`](crate::rollup) pass derives from the
//! records once the walk ends.
//!
//! The detector is pure text analysis over one decompiled body, so
//! the scan fetches each function's pseudo-C exactly once. The scan is
//! one sequential pass over the function listing: there is nothing to
//! resolve between bodies — each record already names its own
//! function — and keeping the pass sequential keeps the persisted
//! finding list grouped by function in listing order, stable and
//! diffable across scans.

use crate::detector::GlobalStateDetector;
use crate::error::Result;
use crate::types::{FunctionPurity, GlobalStateResult};
use calxgloss_kuna::KunaSource;
use calxgloss_types::{CoverageStatus, FacetCoverage, ScanCoverage, ScanMetadata};
use std::time::Instant;
use tracing::{info, warn};

/// The decompiler a global-state scan reads.
///
/// The shared trait from the decompiler seam crate, re-exported here
/// so the generic parameters of [`GlobalStateEngine`] can name it
/// right where they use it. [`KunaSource`] implements it on top of
/// the in-process analysis engine, and tests implement it over canned
/// bodies so the whole orchestration runs without a server. The
/// futures are `Send` so a scan can be driven from an orchestrating
/// task.
pub use calxgloss_decomp::ScanSource;

/// How many unreached functions one coverage limitation line names
/// inline before it reports the rest as a count. This keeps the
/// admission line beside the counts bounded, not a name dump (the
/// P19-6 admitted-semantics track).
const MAX_NAMED_UNREACHED: usize = 5;

/// The facets a global-state scan declares, in order — the roster
/// the record must name exactly once each. The global-state scan
/// reads one facet: the decompiled bodies the detector reads.
pub const DECLARED_FACETS: &[&str] = &["function-bodies"];

/// The coverage record every global-state scan stamps about itself
/// (issue #350), beside the provenance and the timing.
///
/// The global-state scan has one facet: `function-bodies`, the
/// decompiled bodies the detector reads. The function listing is always
/// read end to end — a failed listing aborts the run, and more than
/// half failing to decompile trips the skip-rate breaker above — so
/// what a finished scan can not have read is exactly the bodies it
/// skipped along the way: a nameless listing entry, or a decompile that
/// failed. The purity summary and the shared-globals index are both
/// derived from the bodies this walk already kept, so they add no
/// coverage border of their own. With nothing skipped, the facet is
/// `complete`, and that is the admission's point: a function no access
/// record mentions was examined and clean, never silently unchecked.
/// With any, the facet is `partial` and the limitation line names the
/// unreached bodies (bounded at [`MAX_NAMED_UNREACHED`]), so silence and
/// never-reaching are distinguishable in the filed record itself. The
/// whole picture mirrors the single facet — there is nothing else this
/// engine examines.
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

/// Orchestrates the per-body access reading into one
/// [`GlobalStateResult`].
///
/// This evidence engine is generic over its [`ScanSource`], so tests
/// can run the whole orchestration over canned bodies;
/// [`new`](Self::new) builds one over a loaded [`KunaSource`]. The
/// detector holds no state, so one instance serves the whole scan, and
/// [`with_detector`](Self::with_detector) swaps it for a configured
/// one.
#[derive(Debug, Clone)]
pub struct GlobalStateEngine<S = KunaSource> {
    source: S,
    detector: GlobalStateDetector,
}

impl GlobalStateEngine<KunaSource> {
    /// An engine over a loaded Kuna program, scanning with the
    /// detector's standard reading.
    pub fn new(source: &KunaSource) -> GlobalStateEngine<KunaSource> {
        GlobalStateEngine {
            source: source.clone(),
            detector: GlobalStateDetector::new(),
        }
    }
}

impl<S> GlobalStateEngine<S> {
    /// An engine whose decompiles come from `source`, scanning with
    /// the detector's standard reading.
    pub fn with_source(source: S) -> Self {
        GlobalStateEngine {
            source,
            detector: GlobalStateDetector::new(),
        }
    }

    /// Read bodies with `detector` instead of the standard one.
    pub fn with_detector(mut self, detector: GlobalStateDetector) -> Self {
        self.detector = detector;
        self
    }

    /// Record the global-state accesses across `binary`, decompiling
    /// each function exactly once and reading it with the detector.
    ///
    /// `binary` names the program the scan reads (e.g. `eqmain.dll`)
    /// and becomes the key a persisted result is filed under. The
    /// findings follow the function listing — grouped by function in
    /// listing order, and within one function in body order — and
    /// after the whole walk the rollup appends the shared-globals
    /// index records last, in first-sighting order. The purity
    /// summary covers every function whose body the scan kept, also
    /// in listing order. So two scans of the same program diff
    /// cleanly.
    ///
    /// A function whose body the decompiler cannot produce (a thunk, a
    /// bad entry point) is skipped with a warning and claims no purity
    /// entry — absence of a body is not evidence of purity. Only a
    /// failure of the listing itself — the server being down — aborts
    /// the run, because then nothing was scanned. But when more than
    /// half the listing fails to decompile, the skip-rate breaker
    /// aborts the run too: that is the signature of the bridge
    /// answering from the wrong program, and skipping on would persist
    /// a record that looks clean but is not (issue #71).
    pub async fn scan(&self, binary: impl Into<String>) -> Result<GlobalStateResult>
    where
        S: ScanSource,
    {
        let started = Instant::now();
        let functions = self.source.functions().await?;

        let mut findings = Vec::new();
        let mut purity = Vec::new();
        let mut skipped = 0usize;
        let mut decompile_failures = 0usize;
        // P19-6: keep track of which bodies the scan could not read —
        // named where a name exists, counted where the listing entry
        // is nameless. The coverage record below states this, so a
        // function no finding mentions means examined and clean,
        // never silently unchecked.
        let mut unreached: Vec<String> = Vec::new();
        let mut nameless = 0usize;
        for function in &functions {
            if function.name.is_empty() {
                // A nameless listing entry would send the by-name
                // lookup into some other function's body. Nothing can
                // be said about it, so it passes without a record.
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
                    // Skip-rate breaker: once more than half of the
                    // listing has failed to decompile, the scan is
                    // reading a program the analysis engine cannot
                    // analyze, and an empty result would persist as a
                    // record that looks clean but is not. Abort with
                    // the counts instead of skipping on.
                    if decompile_failures * 2 > functions.len() {
                        return Err(crate::GlobalStateError::DecompileBreaker {
                            failed: decompile_failures,
                            total: functions.len(),
                        });
                    }
                    continue;
                }
            };

            let records = self.detector.detect(&decompiled);
            let reads = records
                .iter()
                .filter(|finding| matches!(finding, crate::GlobalStateFinding::GlobalRead(_)))
                .count();
            // The purity entry comes from the same reading, so a
            // consumer never recomputes it. It is stated for every
            // function whose body the scan kept, pure ones included:
            // the point of the flag is that the absence was checked.
            purity.push(FunctionPurity {
                function: decompiled.name.clone(),
                is_pure: records.is_empty(),
                reads,
                writes: records.len() - reads,
            });
            findings.extend(records);
        }

        let mut metadata = ScanMetadata::new(binary);
        // The cross-function rollup (the ADR-0027 precedent): the
        // shared-globals index is derived from the per-function
        // records the walk just made — the same kept bodies, no new
        // reads from the analysis engine — and lands after them in
        // the persisted list. The scan-order contract holds
        // unchanged: per-function findings grouped by function in
        // listing order, rollup records last, so two scans of one
        // program diff cleanly.
        let index = crate::rollup::shared_globals(&findings);
        let shared_globals = index.len();
        findings.extend(
            index
                .into_iter()
                .map(crate::GlobalStateFinding::SharedGlobal),
        );

        // The source reports its analysis engine's name and version
        // pin under `kuna` (issue #208).
        metadata.engine = self.source.engine_provenance();
        // The scan admits its own coverage where the truth lives, not
        // the registry row and not the CLI (issue #350): every listed
        // body was read by the detector unless the scan says which
        // ones it could not reach. The batch scan phase and the CLI's
        // force-rescan file the same admission through this one
        // definition.
        metadata.coverage = Some(coverage_stamp(&unreached, nameless));
        metadata.duration_secs = started.elapsed().as_secs();
        info!(
            binary = %metadata.binary,
            functions = functions.len(),
            findings = findings.len(),
            shared_globals,
            skipped,
            duration_secs = metadata.duration_secs,
            "Detected global-state accesses"
        );
        Ok(GlobalStateResult {
            metadata,
            findings,
            purity,
        })
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::GlobalStateFinding;
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

    /// The canned program: one function that stores and loads a
    /// `DAT_*` global, and one plain function that touches none.
    fn program() -> FakeProgram {
        let mut program = FakeProgram::empty();
        program.listing = vec![summary("FUN_18003ab00"), summary("FUN_18003e750")];
        program.bodies.insert(
            "FUN_18003ab00".into(),
            function(
                "FUN_18003ab00",
                "  DAT_180064e80 = param_1;\n  uVar1 = DAT_180064e80;\n",
            ),
        );
        program.bodies.insert(
            "FUN_18003e750".into(),
            function("FUN_18003e750", "  return;\n"),
        );
        program
    }

    async fn scan(program: FakeProgram) -> GlobalStateResult {
        GlobalStateEngine::with_source(program)
            .scan("eqmain.dll")
            .await
            .expect("scan")
    }

    #[tokio::test]
    async fn scan_records_the_accesses_every_body_makes() {
        let result = scan(program()).await;

        assert_eq!(result.metadata.binary, "eqmain.dll");
        assert!(result.metadata.scanned_at > 0);

        let findings: Vec<&GlobalStateFinding> = result.for_function("FUN_18003ab00").collect();
        assert_eq!(findings.len(), 2, "one store and one load, in body order");

        let GlobalStateFinding::GlobalWrite(record) = findings[0] else {
            unreachable!("the store reads as a global write");
        };
        assert_eq!(record.global, "DAT_180064e80");
        assert_eq!(record.evidence, "DAT_180064e80 = param_1");
        assert_eq!(record.confidence.value(), 85);

        let GlobalStateFinding::GlobalRead(record) = findings[1] else {
            unreachable!("the load reads as a global read");
        };
        assert_eq!(record.global, "DAT_180064e80");
        assert_eq!(record.evidence, "uVar1 = DAT_180064e80");

        assert!(result.for_function("FUN_18003e750").next().is_none());
    }

    #[tokio::test]
    async fn scan_groups_findings_by_function_in_listing_order() {
        // The scan-order contract: both functions carry accesses, so
        // the persisted list must group their records by function in
        // listing order — never interleaved. The rollup entries land
        // after the whole per-function group, never among it.
        let mut program = program();
        program.listing = vec![summary("FUN_18003e750"), summary("FUN_18003ab00")];
        program.bodies.insert(
            "FUN_18003e750".into(),
            function(
                "FUN_18003e750",
                "  DAT_flag = 1;\n  DAT_flag = DAT_flag + 1;\n",
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
                ("FUN_18003e750", "global_write"),
                ("FUN_18003e750", "global_write"),
                ("FUN_18003e750", "global_read"),
                ("FUN_18003ab00", "global_write"),
                ("FUN_18003ab00", "global_read"),
                ("", "shared_global"),
                ("", "shared_global"),
            ],
            "per-function findings grouped by function in listing order, rollup records last"
        );
    }

    #[tokio::test]
    async fn the_shared_globals_index_lands_after_the_per_function_findings() {
        // Two functions touch one global — one stores, one loads —
        // and the entry naming both lands last in scan order, readers
        // and writers separated by kind.
        let mut program = program();
        program.bodies.insert(
            "FUN_18003e750".into(),
            function("FUN_18003e750", "  uVar1 = DAT_180064e80;\n  return;\n"),
        );
        let result = scan(program).await;

        let entry = result
            .findings
            .last()
            .and_then(|finding| finding.shared_global())
            .expect("the scan's last finding is the rollup entry");
        assert_eq!(entry.global, "DAT_180064e80");
        assert_eq!(entry.writers, vec!["FUN_18003ab00"]);
        assert_eq!(
            entry.readers,
            vec!["FUN_18003ab00", "FUN_18003e750"],
            "both functions that load the global, in listing order"
        );
        assert_eq!(
            result
                .findings
                .iter()
                .filter(|finding| finding.shared_global().is_some())
                .count(),
            1,
            "no index record among the per-function findings"
        );
    }

    #[tokio::test]
    async fn the_purity_summary_covers_every_kept_function_in_listing_order() {
        // The derived summary states what the scan already knows: the
        // impure function records its read and write counts, and the
        // pure one is recorded as pure — the absence was checked, not
        // assumed.
        let result = scan(program()).await;
        assert_eq!(
            result.purity,
            vec![
                FunctionPurity {
                    function: "FUN_18003ab00".into(),
                    is_pure: false,
                    reads: 1,
                    writes: 1,
                },
                FunctionPurity {
                    function: "FUN_18003e750".into(),
                    is_pure: true,
                    reads: 0,
                    writes: 0,
                },
            ]
        );
    }

    #[tokio::test]
    async fn a_function_that_failed_to_decompile_claims_no_purity() {
        // Absence of a body is not evidence of purity: the function
        // the decompiler never produced stays out of the summary
        // entirely.
        let mut program = program();
        program.fail_decompiles = vec!["FUN_18003e750".into()];
        let result = scan(program).await;

        assert_eq!(result.purity.len(), 1);
        assert_eq!(result.purity[0].function, "FUN_18003ab00");
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
        // a record that looks clean but is not (issue #71).
        let mut program = program();
        program.fail_decompiles = vec!["FUN_18003ab00".into(), "FUN_18003e750".into()];
        let result = GlobalStateEngine::with_source(program)
            .scan("eqmain.dll")
            .await;
        assert!(matches!(
            result,
            Err(crate::GlobalStateError::DecompileBreaker {
                failed: 2,
                total: 2
            })
        ));
    }

    #[tokio::test]
    async fn the_breaker_stops_the_scan_from_decompiling_the_rest() {
        // The skip-rate breaker is a fuse, not a post-mortem: once
        // more than half of the listing has failed, the remaining
        // decompiles are wasted round-trips against the wrong
        // program.
        let mut program = program();
        program.listing.push(summary("FUN_1800412a0"));
        program.bodies.insert(
            "FUN_1800412a0".into(),
            function("FUN_1800412a0", "  return;\n"),
        );
        program.fail_decompiles = vec!["FUN_18003ab00".into(), "FUN_18003e750".into()];
        let result = GlobalStateEngine::with_source(program.clone())
            .scan("eqmain.dll")
            .await;

        assert!(matches!(
            result,
            Err(crate::GlobalStateError::DecompileBreaker {
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
        // aborts rather than returning a result that looks like
        // nothing was detected.
        let mut program = program();
        program.fail_listing = true;
        let result = GlobalStateEngine::with_source(program)
            .scan("eqmain.dll")
            .await;
        assert!(matches!(
            result,
            Err(crate::GlobalStateError::Engine(
                EngineError::Reported { .. }
            ))
        ));
    }

    #[tokio::test]
    async fn scan_stamps_the_scan_provenance() {
        // The metadata names the binary, carries a finish time, and
        // the duration is stamped from the wall clock — a canned scan
        // is instant, so it reads as zero seconds rather than never
        // set. The record also names the analysis engine that
        // produced it: scan() copies the source's provenance
        // through (#208).
        let result = scan(program()).await;
        assert_eq!(result.metadata.binary, "eqmain.dll");
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
        assert!(result.purity.is_empty());
        assert_eq!(result.metadata.binary, "eqmain.dll");
        assert!(result.metadata.scanned_at > 0);
    }

    // ============================================================
    // Admitted scan coverage (issue #350)
    // ============================================================

    /// The data-level verdict of the roster pin: empty means the
    /// record names every declared facet exactly once, and each fault
    /// reports one drift.
    fn roster_faults(coverage: &ScanCoverage) -> Vec<String> {
        coverage.roster_faults(DECLARED_FACETS)
    }

    #[tokio::test]
    async fn a_fresh_scan_stamps_complete_bodies_coverage_and_a_clean_roster() {
        // The stamp comes from the scan itself, not the registry row
        // and not the CLI — the batch scan phase and the CLI's
        // force-rescan file the same admission through this one
        // definition. Every body was read here, so the record is
        // complete and admits nothing.
        let result = scan(program()).await;
        let coverage = result
            .metadata
            .coverage
            .expect("a fresh global-state scan states its coverage");
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
        // clean function the access list simply left unmentioned.
        let mut program = program();
        program.fail_decompiles = vec!["FUN_18003e750".into()];
        let result = scan(program).await;
        let coverage = result
            .metadata
            .coverage
            .expect("a partial global-state scan states its coverage too");
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
        // Bounded prose beside the counts: six decompile failures
        // name five inline and count the sixth, and a nameless
        // listing entry counts toward the total without taking a name
        // slot.
        let names: Vec<String> = (0..12).map(|i| format!("FUN_body_{i:04}")).collect();
        let mut program = FakeProgram::empty();
        for (index, name) in names.iter().enumerate() {
            program.listing.push(summary(name));
            if index >= 6 {
                program
                    .bodies
                    .insert(name.clone(), function(name, "  return;\n"));
            }
        }
        program.fail_decompiles = names[..6].to_vec();
        program.listing.push(summary(""));
        let result = scan(program).await;
        let bodies = result
            .metadata
            .coverage
            .expect("a partial global-state scan states its coverage")
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
            id: "shared-globals-index".to_string(),
            status: CoverageStatus::Complete,
            limitation: None,
        });
        assert_eq!(
            roster_faults(&coverage),
            ["record names `shared-globals-index`, a facet the engine never declared"],
            "an entry outside the declared roster fails loudly — the \
             shared-globals index is derived from the kept bodies, not a \
             region the scan reads on its own"
        );
    }
}
