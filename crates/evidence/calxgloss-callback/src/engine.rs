//! Callback-table scan orchestration.
//!
//! [`CallbackEngine`] runs the callback detectors — function-pointer
//! array calls, callback registrations, jump-table dispatches, and
//! dynamic-loading plugin shapes — over every function of one open
//! program, then the cross-function pass over the bodies it
//! kept, and assembles their findings into a single
//! [`CallbackResult`] with its scan provenance.
//!
//! The detectors are pure text analysis over one decompiled body, so
//! the engine fetches each function's pseudo-C exactly once and reads
//! it with every wired detector, rather than having each detector pull
//! its own copy; the cross-function pass reads those same kept
//! bodies, so the scan stays at one decompile per function. The scan
//! is then one sequential pass over the function listing: unlike
//! typeinfer's competing families there is nothing to resolve between
//! the detectors — they read disjoint body shapes — and keeping the
//! pass sequential keeps the persisted finding list in a stable,
//! diffable order.

use crate::callback_reg::CallbackRegDetector;
use crate::cross_function::CrossFunctionAnalyzer;
use crate::error::Result;
use crate::fp_array::FpArrayDetector;
use crate::jump_table::JumpTableDetector;
use crate::plugin::PluginDetector;
use crate::signatures::{SignatureMap, enrich_suggestion};
use crate::types::{CallbackFinding, CallbackResult, ScanMetadata};
use calxgloss_decomp::DecompiledFunction;
use calxgloss_kuna::KunaSource;
use calxgloss_types::{CoverageStatus, FacetCoverage, ScanCoverage};
use std::time::Instant;
use tracing::{info, warn};

/// The decompiler a callback scan reads.
///
/// The shared trait from the decompiler seam crate, re-exported here
/// so the engine's generic shape names it where it always has;
/// [`KunaSource`] implements it over the in-process engine, and tests
/// implement it over canned bodies so the orchestration runs without a
/// server. The futures are `Send` so a scan can be driven from an
/// orchestrating task.
pub use calxgloss_decomp::ScanSource;

/// How many unreached functions one coverage limitation line names inline
/// before folding the remainder into a count — bounded prose beside the
/// counts, not a dump (the P19-6 admitted-semantics track).
const MAX_NAMED_UNREACHED: usize = 5;

/// The coverage record every callback-detection scan stamps about itself
/// (issue #350), beside the provenance and the timing.
///
/// The callback scan has one facet: `function-bodies`, the decompiled
/// bodies every detector reads. The function listing is always read end
/// to end — a failed listing aborts the run, and more than half failing
/// to decompile trips the skip-rate breaker above — so what a finished
/// scan can not have read is exactly the bodies it skipped along the
/// way: a nameless listing entry, or a decompile that failed. The
/// cross-function pass reads only the bodies this walk already kept, so
/// it adds no coverage border of its own. With nothing skipped, the
/// facet is `complete`, and that is the admission's point: a function
/// no callback finding mentions was examined and clean, never silently
/// unchecked. With any, the facet is `partial` and the limitation line
/// names the unreached bodies (bounded at [`MAX_NAMED_UNREACHED`]), so
/// silence and never-reaching are distinguishable in the filed record
/// itself. The whole picture mirrors the single facet — there is nothing
/// else this engine examines.
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
            limitation: Some(format!("{total} function {body} unreached: {}", names.join(", "))),
        }],
    }
}

/// Orchestrates the callback detectors into one [`CallbackResult`].
///
/// The engine is generic over its [`ScanSource`], so tests can run the
/// whole orchestration over canned bodies; [`new`](Self::new) builds
/// one over a loaded [`KunaSource`]. Each detector carries no state
/// and starts configured with its standard name set —
/// [`with_fp_array`](Self::with_fp_array),
/// [`with_registration`](Self::with_registration),
/// [`with_jump_table`](Self::with_jump_table) and
/// [`with_plugin`](Self::with_plugin) swap a detector's set
/// whole — so one instance of each serves the whole scan. A
/// caller-composed [`SignatureMap`] injected through
/// [`with_signatures`](Self::with_signatures) deepens the
/// registration and chain suggestions in place; with no map the scan
/// is exactly what it was.
#[derive(Debug, Clone)]
pub struct CallbackEngine<S = KunaSource> {
    source: S,
    fp_array: FpArrayDetector,
    registration: CallbackRegDetector,
    jump_table: JumpTableDetector,
    plugin: PluginDetector,
    cross_function: CrossFunctionAnalyzer,
    signatures: SignatureMap,
}

impl CallbackEngine<KunaSource> {
    /// An engine over a loaded Kuna program, scanning with the
    /// detectors' standard name sets.
    pub fn new(source: &KunaSource) -> CallbackEngine<KunaSource> {
        CallbackEngine {
            source: source.clone(),
            fp_array: FpArrayDetector::with_default_names(),
            registration: CallbackRegDetector::with_default_names(),
            jump_table: JumpTableDetector::with_default_prefixes(),
            plugin: PluginDetector::with_default_names(),
            cross_function: CrossFunctionAnalyzer::new(),
            signatures: SignatureMap::new(),
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
            plugin: PluginDetector::with_default_names(),
            cross_function: CrossFunctionAnalyzer::new(),
            signatures: SignatureMap::new(),
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

    /// Read dynamic-loading plugin shapes against `detector`'s name
    /// sets instead of the standard ones.
    pub fn with_plugin(mut self, detector: PluginDetector) -> Self {
        self.plugin = detector;
        self
    }

    /// Fill the real closure contract into the suggestions whose
    /// callback `signatures` names.
    ///
    /// A registration's bound callback — and a chain's callback — is
    /// looked up by its spelled name in the map, and a hit renders
    /// `Box<dyn Fn(i32) -> bool>` in place of the open
    /// `Box<dyn Fn(...)>` (see [`crate::signatures`]). The map is
    /// composed by the **caller** from another scan's persisted
    /// records — the CLI `callback` command and the batch
    /// pre-analysis read the type-inference document — because this
    /// crate takes no dependency on the type-inference crate
    /// (ADR-0036). An empty map, or a name the map does not carry,
    /// leaves every suggestion exactly as the detectors wrote it;
    /// function-pointer-array and jump-table suggestions are never
    /// touched, because their callees are unnamed.
    pub fn with_signatures(mut self, signatures: SignatureMap) -> Self {
        self.signatures = signatures;
        self
    }

    /// Deepen `suggestion` in place when `callback` has a known
    /// callable contract; anything else stands as written.
    fn enrich(&self, callback: &str, suggestion: &mut String) {
        if let Some(signature) = self.signatures.get(callback) {
            *suggestion = enrich_suggestion(suggestion, signature);
        }
    }

    /// Detect callback tables across `binary`, decompiling each
    /// function exactly once and reading it with every wired detector.
    ///
    /// `binary` names the program the scan reads (e.g. `eqmain.dll`)
    /// and becomes the key a persisted result is filed under. The
    /// findings follow the function listing — function by function,
    /// and within one function the function-pointer array calls, then
    /// the registrations, then the jump tables, then the plugin
    /// shapes — and after every function the cross-function pass adds
    /// its chain findings, in listing order, over the bodies this
    /// walk already decompiled: no extra engine reads. So two
    /// scans of the same program diff cleanly.
    ///
    /// A function whose body the decompiler cannot produce (a thunk, a bad
    /// entry point) is skipped with a warning; only a failure of the
    /// listing itself — the server being down — aborts the run, since
    /// then nothing was scanned. But when more than half the listing
    /// fails to decompile, the skip-rate breaker aborts the run too:
    /// that is the signature of the bridge answering from the wrong
    /// program, and skipping on would persist a phantom-clean record
    /// (issue #71). The detectors read disjoint body shapes, so a
    /// function can carry findings of every kind at once and nothing
    /// is resolved between them. Where a [`with_signatures`](Self::with_signatures)
    /// map names a bound callback, the registration and chain
    /// suggestions carry its real closure contract out of the scan —
    /// into the persisted document, the CLI report, and the escalate
    /// prompt alike.
    pub async fn scan(&self, binary: impl Into<String>) -> Result<CallbackResult>
    where
        S: ScanSource,
    {
        let started = Instant::now();
        let functions = self.source.functions().await?;

        let mut findings = Vec::new();
        let mut bodies: Vec<DecompiledFunction> = Vec::new();
        let mut skipped = 0usize;
        let mut decompile_failures = 0usize;
        // P19-6: which bodies the scan could NOT read, named where a name
        // exists, counted where the listing entry is nameless — the
        // coverage record below states it, so an unmentioned function
        // means examined-and-clean, never silently unchecked.
        let mut unreached: Vec<String> = Vec::new();
        let mut nameless = 0usize;
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
                    // Skip-rate breaker: once most of the listing has
                    // failed to decompile, the scan is reading a
                    // program the engine cannot analyze, and an
                    // empty result would persist as a phantom-clean
                    // record. Abort with the counts instead of
                    // skipping on.
                    if decompile_failures * 2 > functions.len() {
                        return Err(crate::CallbackError::DecompileBreaker {
                            failed: decompile_failures,
                            total: functions.len(),
                        });
                    }
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
                    .map(|mut record| {
                        self.enrich(&record.callback, &mut record.suggestion);
                        CallbackFinding::Registration(record)
                    }),
            );
            findings.extend(
                self.jump_table
                    .detect(&decompiled)
                    .into_iter()
                    .map(CallbackFinding::JumpTable),
            );
            findings.extend(
                self.plugin
                    .detect(&decompiled)
                    .into_iter()
                    .map(CallbackFinding::Plugin),
            );
            bodies.push(decompiled);
        }

        // The cross-function pass runs after the per-function walk,
        // over the bodies the scan already decompiled — no extra
        // engine reads — and its findings append in listing
        // order, after the per-function findings. A chain's callback
        // is enriched like a registration's; the event-system
        // suggestion names a crowd of handlers whose contracts can
        // differ, so no single one of them stands for the crowd and
        // the map never reaches it (ADR-0036).
        let mut cross_findings = self.cross_function.analyze(
            &bodies,
            &self.registration,
            &self.fp_array,
            &self.jump_table,
        );
        for finding in &mut cross_findings {
            if let CallbackFinding::Chain(record) = finding {
                self.enrich(&record.callback, &mut record.suggestion);
            }
        }
        findings.extend(cross_findings);

        let mut metadata = ScanMetadata::new(binary);
        // The source names its engine and pin under `kuna` (issue #208).
        metadata.engine = self.source.engine_provenance();
        // The engine admits its own coverage inside its own scan, where
        // the truth lives — not the registry row and not the CLI (issue
        // #350): every listed body was read by every wired detector
        // unless the scan says which ones it could not reach. The batch
        // scan phase and the CLI's force-rescan file the same admission
        // through the same single definition.
        metadata.coverage = Some(coverage_stamp(&unreached, nameless));
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
    use crate::signatures::{CallableSignature, SignatureMap};
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
        // Story 9 (#203): the fake source names itself, so the tests can pin
        // that scan() stamps the source's provenance onto the record (#208).
        fn engine_provenance(&self) -> Option<calxgloss_types::EngineProvenance> {
            Some(calxgloss_types::EngineProvenance {
                name: "fake-engine".into(),
                version: Some("9.9".into()),
                fingerprint: Some("0123456".into()),
            })
        }
    }

    /// A body carrying a cast-dereference call through `handlers`, a
    /// bare indexed call through `dispatch`, a `register_callback`
    /// call, a switch-table dispatch, and a load-and-resolve plugin
    /// shape with a host API table — one finding family per detector —
    /// all in one function.
    const EVERY_SHAPE_BODY: &str = "\
  (*(int (**)(int))handlers[uVar1])(param_1);
  dispatch[uVar2](param_2);
  register_callback(my_handler);
  (*(code *)(&switchD_1800412a0)[uVar3])();
  hMod = LoadLibrary(\"plugin.dll\");
  init = (code *)GetProcAddress(hMod, \"Plugin_Init\");
  Plugin_Init(&host_api);";

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
        assert_eq!(findings.len(), 5);

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

        let CallbackFinding::Plugin(record) = findings[4] else {
            unreachable!("the load-and-resolve shape reads as a plugin finding");
        };
        assert_eq!(record.load.as_deref(), Some("LoadLibrary"));
        assert_eq!(record.resolve.as_deref(), Some("GetProcAddress"));
        assert_eq!(record.entry_point.as_deref(), Some("Plugin_Init"));
        assert_eq!(record.host_table.as_deref(), Some("host_api"));
        assert_eq!(record.suggestion, "Box<dyn Plugin> (loader crate)");
        assert_eq!(record.confidence.value(), 70);

        assert!(result.for_function("FUN_18003e750").next().is_none());
    }

    #[tokio::test]
    async fn scan_keeps_findings_in_scan_order() {
        // Both functions carry the shape, so the persisted list must
        // group their findings by function in listing order — never
        // interleaved — and the cross-function findings, the
        // event-system reconstruction included, append after every
        // per-function finding.
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
                ("FUN_18003e750", "plugin"),
                ("FUN_18003ab00", "fp_array"),
                ("FUN_18003ab00", "fp_array"),
                ("FUN_18003ab00", "registration"),
                ("FUN_18003ab00", "jump_table"),
                ("FUN_18003ab00", "plugin"),
                ("FUN_18003e750", "event_system"),
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
        // The 2026-10-08 incident: the bridge answered the listing from
        // one program and the decompiles from another, every decompile
        // failed, and the scan nearly persisted a phantom-clean record
        // under the target's name. The skip-rate breaker aborts with
        // the counts instead, so nothing is persisted.
        let mut program = program();
        program.fail_decompiles = vec!["FUN_18003ab00".into(), "FUN_18003e750".into()];
        let result = CallbackEngine::with_source(program)
            .scan("eqmain.dll")
            .await;
        match result {
            Err(
                error @ crate::CallbackError::DecompileBreaker {
                    failed: 2,
                    total: 2,
                },
            ) => {
                // The message is the operator-facing diagnosis: it names
                // the counts and points at the wrong-program cause.
                assert_eq!(
                    error.to_string(),
                    "the engine failed to decompile 2 of 2 functions"
                );
            }
            other => panic!("expected the skip-rate breaker, got {other:?}"),
        }
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
        let result = CallbackEngine::with_source(program.clone())
            .scan("eqmain.dll")
            .await;

        assert!(matches!(
            result,
            Err(crate::CallbackError::DecompileBreaker {
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
        let result = CallbackEngine::with_source(program)
            .scan("eqmain.dll")
            .await;
        assert!(matches!(
            result,
            Err(crate::CallbackError::Engine(EngineError::Reported { .. }))
        ));
    }

    #[tokio::test]
    async fn custom_name_sets_reach_every_detector() {
        // Swapping a detector's set whole reaches the scan: the
        // configured custom spelling calls in the body, and the
        // standard names the swap replaced call nothing — the plugin
        // body spells both, standard first, and only the custom
        // spellings land in the record.
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
  (*(&tbl_events[uVar2]))(param_2);
  LoadLibrary(\"standard.dll\");
  GetProcAddress(hMod, \"Plugin_Init\");
  Plugin_Init(&standard_api);
  my_load(\"custom.mod\");
  my_bind(hMod, \"InitPlugin\");
  InitPlugin(&custom_api);",
            ),
        );

        let engine = CallbackEngine::with_source(program)
            .with_fp_array(FpArrayDetector::with_names(["msg_table"]))
            .with_registration(CallbackRegDetector::with_names(["HookMessage"]))
            .with_jump_table(JumpTableDetector::with_prefixes(["tbl_"]))
            .with_plugin(PluginDetector::with_names(
                ["my_load"],
                ["my_bind"],
                ["InitPlugin"],
            ));
        let result = engine.scan("eqmain.dll").await.expect("scan");

        assert_eq!(
            kinds(&result, "FUN_1800412a0"),
            ["fp_array", "registration", "jump_table", "plugin"]
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
        let CallbackFinding::Plugin(record) = findings[3] else {
            unreachable!("the configured loader pair reads as a plugin finding");
        };
        assert_eq!(record.load.as_deref(), Some("my_load"));
        assert_eq!(record.resolve.as_deref(), Some("my_bind"));
        assert_eq!(record.entry_point.as_deref(), Some("InitPlugin"));
        assert_eq!(record.host_table.as_deref(), Some("custom_api"));
    }

    #[tokio::test]
    async fn a_callback_registered_in_one_function_and_called_in_another_lands_a_chain() {
        // The lifecycle the per-body readings each see only half of:
        // one function hands the handler over, another calls it by
        // name. The chain lands on the earlier function in listing
        // order, naming the partner, with both ends' call lines as
        // evidence.
        let mut program = FakeProgram::empty();
        program.listing = vec![summary("FUN_18003ab00"), summary("FUN_18003e750")];
        program.bodies.insert(
            "FUN_18003ab00".into(),
            function(
                "FUN_18003ab00",
                "undefined FUN_18003ab00(void)",
                "  register_callback(my_handler);\n",
            ),
        );
        program.bodies.insert(
            "FUN_18003e750".into(),
            function(
                "FUN_18003e750",
                "undefined FUN_18003e750(void)",
                "  my_handler(param_1);\n",
            ),
        );
        let result = scan(program).await;

        let chains: Vec<&CallbackFinding> = result
            .findings
            .iter()
            .filter(|finding| finding.kind() == "chain")
            .collect();
        assert_eq!(chains.len(), 1, "one chain per function pair");
        let CallbackFinding::Chain(record) = chains[0] else {
            unreachable!("the cross-function pass lands a chain finding");
        };
        assert_eq!(record.function, "FUN_18003ab00");
        assert_eq!(record.partner, "FUN_18003e750");
        assert_eq!(record.callback, "my_handler");
        assert_eq!(record.table, None);
        assert_eq!(record.confidence.value(), 70);
        assert!(record.evidence.contains("register_callback(my_handler);"));
        assert!(record.evidence.contains("my_handler(param_1);"));
    }

    #[tokio::test]
    async fn a_chain_names_the_table_both_ends_share() {
        // One function registers the table itself; the other calls
        // through that same name — the chain names the table it runs
        // through.
        let mut program = FakeProgram::empty();
        program.listing = vec![summary("FUN_18003ab00"), summary("FUN_18003e750")];
        program.bodies.insert(
            "FUN_18003ab00".into(),
            function(
                "FUN_18003ab00",
                "undefined FUN_18003ab00(void)",
                "  register_callback(handlers);\n",
            ),
        );
        program.bodies.insert(
            "FUN_18003e750".into(),
            function(
                "FUN_18003e750",
                "undefined FUN_18003e750(void)",
                "  (*(int (**)(int))handlers[uVar1])(param_1);\n",
            ),
        );
        let result = scan(program).await;

        let CallbackFinding::Chain(record) = result
            .findings
            .iter()
            .find(|finding| finding.kind() == "chain")
            .expect("the shared table name lands a chain")
        else {
            unreachable!("the cross-function pass lands a chain finding");
        };
        assert_eq!(record.callback, "handlers");
        assert_eq!(record.table.as_deref(), Some("handlers"));
    }

    #[tokio::test]
    async fn a_registration_whose_callback_is_never_called_lands_no_chain() {
        // The handler is handed away but no kept body ever calls it:
        // an un-wired registration stays a registration, not a chain.
        let result = scan(program()).await;
        assert!(
            result
                .findings
                .iter()
                .all(|finding| finding.kind() != "chain")
        );
    }

    #[tokio::test]
    async fn cross_function_findings_append_after_the_per_function_findings() {
        // The calling function stands first in the listing and carries
        // its own fp-array finding; the chain still lands after every
        // per-function finding, both groups in listing order.
        let mut program = FakeProgram::empty();
        program.listing = vec![summary("FUN_18003e750"), summary("FUN_18003ab00")];
        program.bodies.insert(
            "FUN_18003e750".into(),
            function(
                "FUN_18003e750",
                "undefined FUN_18003e750(void)",
                "  dispatch[uVar2](param_2);\n  my_handler(param_1);\n",
            ),
        );
        program.bodies.insert(
            "FUN_18003ab00".into(),
            function(
                "FUN_18003ab00",
                "undefined FUN_18003ab00(void)",
                "  register_callback(my_handler);\n",
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
                ("FUN_18003ab00", "registration"),
                ("FUN_18003e750", "chain"),
            ]
        );
    }

    #[tokio::test]
    async fn a_function_that_will_not_decompile_fabricates_no_chain() {
        // The registering body never arrived: the kept calling body
        // names the callback, but with no registration in the kept
        // bodies the pass claims nothing.
        let mut program = FakeProgram::empty();
        program.listing = vec![
            summary("FUN_18003ab00"),
            summary("FUN_18003e750"),
            summary("FUN_180040b10"),
        ];
        program.bodies.insert(
            "FUN_18003e750".into(),
            function(
                "FUN_18003e750",
                "undefined FUN_18003e750(void)",
                "  my_handler(param_1);\n",
            ),
        );
        program.bodies.insert(
            "FUN_180040b10".into(),
            function(
                "FUN_180040b10",
                "undefined FUN_180040b10(void)",
                "  return;\n",
            ),
        );
        program.fail_decompiles = vec!["FUN_18003ab00".into()];
        let result = scan(program).await;

        assert!(
            result.is_empty(),
            "a body that never made it registers nothing and chains nothing"
        );
    }

    #[tokio::test]
    async fn custom_name_sets_reach_the_cross_function_pass() {
        // The pass keys on the configured sets, not a private default:
        // a custom registration spelling and a custom table name chain
        // across the two bodies, and the standard names the swaps
        // replaced claim nothing there.
        let mut program = FakeProgram::empty();
        program.listing = vec![summary("FUN_18003ab00"), summary("FUN_18003e750")];
        program.bodies.insert(
            "FUN_18003ab00".into(),
            function(
                "FUN_18003ab00",
                "undefined FUN_18003ab00(void)",
                "  HookMessage(msg_table);\n  register_callback(handlers);\n",
            ),
        );
        program.bodies.insert(
            "FUN_18003e750".into(),
            function(
                "FUN_18003e750",
                "undefined FUN_18003e750(void)",
                "  (*(code *)msg_table[uVar1])(param_1);\n  handlers[uVar2](param_2);\n",
            ),
        );
        let engine = CallbackEngine::with_source(program)
            .with_registration(CallbackRegDetector::with_names(["HookMessage"]))
            .with_fp_array(FpArrayDetector::with_names(["msg_table"]));
        let result = engine.scan("eqmain.dll").await.expect("scan");

        let chains: Vec<&CallbackFinding> = result
            .findings
            .iter()
            .filter(|finding| finding.kind() == "chain")
            .collect();
        assert_eq!(chains.len(), 1, "only the configured spellings chain");
        let CallbackFinding::Chain(record) = chains[0] else {
            unreachable!("the cross-function pass lands a chain finding");
        };
        assert_eq!(record.callback, "msg_table");
        assert_eq!(record.table.as_deref(), Some("msg_table"));
    }

    #[tokio::test]
    async fn two_registrations_and_a_dispatch_site_reconstruct_one_event_system() {
        // The scan's whole view: two bodies hand handlers to one
        // registration point and a third dispatches through a table —
        // the event architecture surfaces as one finding naming the
        // point, the handlers, and the dispatching function.
        let mut program = FakeProgram::empty();
        program.listing = vec![
            summary("FUN_18003ab00"),
            summary("FUN_18003e750"),
            summary("FUN_1800412a0"),
        ];
        program.bodies.insert(
            "FUN_18003ab00".into(),
            function(
                "FUN_18003ab00",
                "undefined FUN_18003ab00(void)",
                "  register_callback(handler_a);\n",
            ),
        );
        program.bodies.insert(
            "FUN_18003e750".into(),
            function(
                "FUN_18003e750",
                "undefined FUN_18003e750(void)",
                "  register_callback(handler_b);\n",
            ),
        );
        program.bodies.insert(
            "FUN_1800412a0".into(),
            function(
                "FUN_1800412a0",
                "undefined FUN_1800412a0(void)",
                "  handlers[uVar1](param_1);\n",
            ),
        );
        let result = scan(program).await;

        let events: Vec<&CallbackFinding> = result
            .findings
            .iter()
            .filter(|finding| finding.kind() == "event_system")
            .collect();
        assert_eq!(events.len(), 1, "one event system per point");
        let CallbackFinding::EventSystem(record) = events[0] else {
            unreachable!("the cross-function pass lands an event_system finding");
        };
        assert_eq!(record.function, "FUN_18003ab00");
        assert_eq!(record.registration, "register_callback");
        assert_eq!(record.callbacks, ["handler_a", "handler_b"]);
        assert_eq!(record.dispatchers, ["FUN_1800412a0"]);
        assert_eq!(record.confidence.value(), 60);
    }

    #[tokio::test]
    async fn registrations_with_no_visible_dispatch_site_report_no_event_system() {
        // The handlers reach each other across bodies by direct call —
        // the chains read them — but no kept body dispatches through
        // a table: the scan reports no event architecture.
        let mut program = FakeProgram::empty();
        program.listing = vec![summary("FUN_18003ab00"), summary("FUN_18003e750")];
        program.bodies.insert(
            "FUN_18003ab00".into(),
            function(
                "FUN_18003ab00",
                "undefined FUN_18003ab00(void)",
                "  register_callback(handler_a);\n  handler_b(param_2);\n",
            ),
        );
        program.bodies.insert(
            "FUN_18003e750".into(),
            function(
                "FUN_18003e750",
                "undefined FUN_18003e750(void)",
                "  register_callback(handler_b);\n  handler_a(param_1);\n",
            ),
        );
        let result = scan(program).await;

        assert!(
            result
                .findings
                .iter()
                .any(|finding| finding.kind() == "chain"),
            "the direct calls still chain"
        );
        assert!(
            result
                .findings
                .iter()
                .all(|finding| finding.kind() != "event_system"),
            "no dispatch site in sight, no event system claimed"
        );
    }

    #[tokio::test]
    async fn a_function_that_will_not_decompile_fabricates_no_event_system() {
        // Three registrations to one point, one of them in a body
        // that never made it, and a dispatch site in a kept body:
        // with only one kept registration the pass has fewer than
        // two sites to group and claims no architecture.
        let mut program = FakeProgram::empty();
        program.listing = vec![
            summary("FUN_18003ab00"),
            summary("FUN_18003e750"),
            summary("FUN_1800412a0"),
        ];
        program.bodies.insert(
            "FUN_18003e750".into(),
            function(
                "FUN_18003e750",
                "undefined FUN_18003e750(void)",
                "  register_callback(handler_b);\n",
            ),
        );
        program.bodies.insert(
            "FUN_1800412a0".into(),
            function(
                "FUN_1800412a0",
                "undefined FUN_1800412a0(void)",
                "  handlers[uVar1](param_1);\n",
            ),
        );
        program.fail_decompiles = vec!["FUN_18003ab00".into()];
        let result = scan(program).await;

        assert!(
            result
                .findings
                .iter()
                .all(|finding| finding.kind() != "event_system"),
            "a body that never made it registers nothing and reconstructs nothing"
        );
    }

    #[tokio::test]
    async fn custom_name_sets_reach_the_event_system_reading() {
        // The reconstruction keys on the configured sets, not a
        // private default: a custom registration spelling and a
        // custom table name reconstruct together, and the standard
        // names the swaps replaced claim nothing on the same bodies.
        let mut program = FakeProgram::empty();
        program.listing = vec![
            summary("FUN_18003ab00"),
            summary("FUN_18003e750"),
            summary("FUN_1800412a0"),
        ];
        program.bodies.insert(
            "FUN_18003ab00".into(),
            function(
                "FUN_18003ab00",
                "undefined FUN_18003ab00(void)",
                "  HookMessage(handler_a);\n  register_callback(other_a);\n",
            ),
        );
        program.bodies.insert(
            "FUN_18003e750".into(),
            function(
                "FUN_18003e750",
                "undefined FUN_18003e750(void)",
                "  HookMessage(handler_b);\n  register_callback(other_b);\n",
            ),
        );
        program.bodies.insert(
            "FUN_1800412a0".into(),
            function(
                "FUN_1800412a0",
                "undefined FUN_1800412a0(void)",
                "  (*(code *)msg_table[uVar1])(param_1);\n  handlers[uVar2](param_2);\n",
            ),
        );
        let engine = CallbackEngine::with_source(program)
            .with_registration(CallbackRegDetector::with_names(["HookMessage"]))
            .with_fp_array(FpArrayDetector::with_names(["msg_table"]));
        let result = engine.scan("eqmain.dll").await.expect("scan");

        let events: Vec<&CallbackFinding> = result
            .findings
            .iter()
            .filter(|finding| finding.kind() == "event_system")
            .collect();
        assert_eq!(events.len(), 1, "only the configured spellings reconstruct");
        let CallbackFinding::EventSystem(record) = events[0] else {
            unreachable!("the cross-function pass lands an event_system finding");
        };
        assert_eq!(record.registration, "HookMessage");
        assert_eq!(record.dispatchers, ["FUN_1800412a0"]);
    }

    #[tokio::test]
    async fn event_system_findings_append_after_the_per_function_findings() {
        // The dispatching function stands last in the listing and
        // carries its own fp-array finding; the reconstruction still
        // lands after every per-function finding, keeping the
        // persisted document diffable.
        let mut program = FakeProgram::empty();
        program.listing = vec![
            summary("FUN_18003ab00"),
            summary("FUN_18003e750"),
            summary("FUN_1800412a0"),
        ];
        program.bodies.insert(
            "FUN_18003ab00".into(),
            function(
                "FUN_18003ab00",
                "undefined FUN_18003ab00(void)",
                "  register_callback(handler_a);\n",
            ),
        );
        program.bodies.insert(
            "FUN_18003e750".into(),
            function(
                "FUN_18003e750",
                "undefined FUN_18003e750(void)",
                "  register_callback(handler_b);\n",
            ),
        );
        program.bodies.insert(
            "FUN_1800412a0".into(),
            function(
                "FUN_1800412a0",
                "undefined FUN_1800412a0(void)",
                "  dispatch[uVar1](param_1);\n",
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
                ("FUN_18003ab00", "registration"),
                ("FUN_18003e750", "registration"),
                ("FUN_1800412a0", "fp_array"),
                ("FUN_18003ab00", "event_system"),
            ]
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
        // Story 9 (#203): the record also names the engine that produced it —
        // scan() copies the source's provenance through (#208).
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

    // ------------------------------------------------------------
    // Injected signature enrichment (issue #173)
    // ------------------------------------------------------------

    fn callable_signature(params: &[&str], return_type: Option<&str>) -> CallableSignature {
        CallableSignature {
            param_types: params.iter().map(|param| (*param).to_string()).collect(),
            return_type: return_type.map(|return_type| return_type.to_string()),
        }
    }

    fn handler_signature_map() -> SignatureMap {
        [(
            "my_handler".to_string(),
            callable_signature(&["i32"], Some("bool")),
        )]
        .into_iter()
        .collect()
    }

    fn registered_handler_program() -> FakeProgram {
        // One function hands `my_handler` to `register_callback`,
        // another calls it by name: one scan carries both a
        // registration finding and a chain finding for the same
        // callback.
        let mut program = FakeProgram::empty();
        program.listing = vec![summary("FUN_18003ab00"), summary("FUN_18003e750")];
        program.bodies.insert(
            "FUN_18003ab00".into(),
            function(
                "FUN_18003ab00",
                "undefined FUN_18003ab00(void)",
                "  register_callback(my_handler);\n",
            ),
        );
        program.bodies.insert(
            "FUN_18003e750".into(),
            function(
                "FUN_18003e750",
                "undefined FUN_18003e750(void)",
                "  my_handler(param_1);\n",
            ),
        );
        program
    }

    fn suggestion_for<'a>(result: &'a CallbackResult, kind: &str, function: &str) -> &'a str {
        result
            .findings
            .iter()
            .find(|finding| finding.kind() == kind && finding.function() == function)
            .unwrap_or_else(|| panic!("a {kind} finding on {function}"))
            .suggestion()
    }

    #[tokio::test]
    async fn a_known_signature_fills_the_registration_closure_contract() {
        // The contrast at the engine seam: the same canned body,
        // scanned with a map naming the bound callback, renders the
        // real contract; scanned without one, it stays open.
        let enriched = CallbackEngine::with_source(registered_handler_program())
            .with_signatures(handler_signature_map())
            .scan("eqmain.dll")
            .await
            .expect("scan");
        assert_eq!(
            suggestion_for(&enriched, "registration", "FUN_18003ab00"),
            "Box<dyn Fn(i32) -> bool>"
        );

        let plain = scan(registered_handler_program()).await;
        assert_eq!(
            suggestion_for(&plain, "registration", "FUN_18003ab00"),
            "Box<dyn Fn(...)>"
        );
    }

    #[tokio::test]
    async fn a_known_signature_fills_the_chain_closure_contract() {
        // The chain's callback is enriched the same way, and the
        // prose around the placeholder rides on unchanged.
        let enriched = CallbackEngine::with_source(registered_handler_program())
            .with_signatures(handler_signature_map())
            .scan("eqmain.dll")
            .await
            .expect("scan");
        assert_eq!(
            suggestion_for(&enriched, "chain", "FUN_18003ab00"),
            "Box<dyn Fn(i32) -> bool> shared between the registering and calling functions"
        );

        let plain = scan(registered_handler_program()).await;
        assert_eq!(
            suggestion_for(&plain, "chain", "FUN_18003ab00"),
            "Box<dyn Fn(...)> shared between the registering and calling functions"
        );
    }

    #[tokio::test]
    async fn a_signature_map_leaves_the_table_suggestions_untouched() {
        // An fp-array or jump-table callee is unnamed — there is no
        // name to look up — so even a map naming the tables keeps
        // their suggestions open. The registered callback in the same
        // body is the only suggestion the map reaches.
        let mut signatures = handler_signature_map();
        signatures.insert(
            "handlers".to_string(),
            callable_signature(&["i32"], Some("bool")),
        );
        signatures.insert(
            "dispatch".to_string(),
            callable_signature(&["i32"], Some("bool")),
        );
        let result = CallbackEngine::with_source(program())
            .with_signatures(signatures)
            .scan("eqmain.dll")
            .await
            .expect("scan");
        let plain = scan(program()).await;
        assert_eq!(
            suggestion_for(&result, "fp_array", "FUN_18003ab00"),
            "Vec<Box<dyn Fn(...)>>"
        );
        assert_eq!(
            suggestion_for(&result, "jump_table", "FUN_18003ab00"),
            suggestion_for(&plain, "jump_table", "FUN_18003ab00"),
            "a jump-table suggestion rides the map untouched"
        );
        assert_eq!(
            suggestion_for(&result, "registration", "FUN_18003ab00"),
            "Box<dyn Fn(i32) -> bool>"
        );
    }

    #[tokio::test]
    async fn an_unknown_name_or_an_empty_map_leaves_suggestions_as_today() {
        // A map that names no bound callback — and the default no-map
        // scan — leave every suggestion exactly as the detectors
        // wrote it.
        let unrelated: SignatureMap = [(
            "some_other_function".to_string(),
            callable_signature(&["i32"], Some("bool")),
        )]
        .into_iter()
        .collect();
        let result = CallbackEngine::with_source(registered_handler_program())
            .with_signatures(unrelated)
            .scan("eqmain.dll")
            .await
            .expect("scan");
        assert_eq!(
            suggestion_for(&result, "registration", "FUN_18003ab00"),
            "Box<dyn Fn(...)>"
        );
        assert_eq!(
            suggestion_for(&result, "chain", "FUN_18003ab00"),
            "Box<dyn Fn(...)> shared between the registering and calling functions"
        );
    }

    // ============================================================
    // Admitted scan coverage (issue #350)
    // ============================================================

    /// The facets a callback-detection scan declares, in order — the
    /// roster the record must name exactly once each. The callback scan
    /// reads one facet: the decompiled bodies every detector reads.
    const DECLARED_FACETS: &[&str] = &["function-bodies"];

    /// The data-level verdict of the roster pin: empty means the record
    /// names every declared facet exactly once, and each fault spells one
    /// drift.
    fn roster_faults(coverage: &ScanCoverage) -> Vec<String> {
        let mut faults = Vec::new();
        for declared in DECLARED_FACETS {
            let hits = coverage
                .facets
                .iter()
                .filter(|facet| facet.id == *declared)
                .count();
            if hits == 0 {
                faults.push(format!(
                    "declared facet `{declared}` is missing from the record"
                ));
            } else if hits > 1 {
                faults.push(format!(
                    "declared facet `{declared}` appears {hits} times in the record"
                ));
            }
        }
        for facet in &coverage.facets {
            if !DECLARED_FACETS.contains(&facet.id.as_str()) {
                faults.push(format!(
                    "record names `{}`, a facet the engine never declared",
                    facet.id
                ));
            }
        }
        faults
    }

    #[tokio::test]
    async fn a_fresh_scan_stamps_complete_bodies_coverage_and_a_clean_roster() {
        // The stamp rides the engine's own scan, not the registry row
        // and not the CLI — the batch scan phase and the CLI's
        // force-rescan file the same admission through this one
        // definition. Every body was read here, so the record is
        // complete and says nothing needs admitting.
        let result = scan(program()).await;
        let coverage = result
            .metadata
            .coverage
            .expect("a fresh callback scan states its coverage");
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
        // clean function the finding list simply left unmentioned.
        let mut program = program();
        program.fail_decompiles = vec!["FUN_18003e750".into()];
        let result = scan(program).await;
        let coverage = result
            .metadata
            .coverage
            .expect("a partial callback scan states its coverage too");
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
        // five inline and fold the sixth into a count, and a nameless
        // listing entry counts toward the total without stealing a name
        // slot.
        let names: Vec<String> = (0..12).map(|i| format!("FUN_body_{i:04}")).collect();
        let mut program = FakeProgram::empty();
        for (index, name) in names.iter().enumerate() {
            program.listing.push(summary(name));
            if index >= 6 {
                program.bodies.insert(
                    name.clone(),
                    function(name, &format!("undefined {name}(void)"), "  return;\n"),
                );
            }
        }
        program.fail_decompiles = names[..6].to_vec();
        program.listing.push(summary(""));
        let result = scan(program).await;
        let bodies = result
            .metadata
            .coverage
            .expect("a partial callback scan states its coverage")
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
        coverage.facets.retain(|facet| facet.id != "function-bodies");
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
            id: "function-pointer-tables".to_string(),
            status: CoverageStatus::Complete,
            limitation: None,
        });
        assert_eq!(
            roster_faults(&coverage),
            ["record names `function-pointer-tables`, a facet the engine never declared"],
            "an entry outside the declared roster fails loudly — the \
             callback tables are read out of the kept bodies, not a \
             region the scan reads on its own"
        );
    }
}
