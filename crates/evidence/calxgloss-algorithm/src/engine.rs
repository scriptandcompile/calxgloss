//! Algorithm recognition orchestration.
//!
//! [`AlgorithmEngine`] runs the three detectors — control flow signature
//! matching, string-guided hints, and callback pattern detection — over
//! every function of one open Ghidra program and assembles their records
//! into a single [`AlgorithmRecognitionResult`] with its scan provenance.
//!
//! The control flow and callback detectors are pure text analysis over
//! one decompiled body, and the string engine additionally reads the
//! program's literal listing, so the engine fetches the listing and the
//! literals exactly once and reads them with every function — the way
//! the typeinfer detectors share one decompile. The scan is then one
//! pass over the function listing, keeping the persisted hint list in a
//! stable, diffable order. The callback detector is the only reader of
//! the call graph, and it runs only for functions whose arity a
//! configured contract could fit: a function of the wrong arity fits no
//! contract however it is used, so fetching its callers would be a round
//! trip guaranteed to be refused.

use crate::callback_db::CallbackPatternDb;
use crate::cfg_patterns::CfgPatternMatcher;
use crate::error::Result;
use crate::string_hints::StringHintEngine;
use crate::types::{AlgorithmRecognitionResult, ScanMetadata};
use calxgloss_ghidra::{DecompiledFunction, FunctionSummary, GhidraClient, StringLiteral};
use std::time::Instant;
use tracing::{info, warn};

/// The program reads a recognition scan performs.
///
/// [`GhidraClient`] implements it directly; tests implement it over
/// canned bodies so the orchestration runs without a server. The futures
/// are `Send` so a scan can be driven from an orchestrating task.
pub trait ScanSource {
    /// Every function in the program, in listing order.
    fn functions(&self) -> impl std::future::Future<Output = Result<Vec<FunctionSummary>>> + Send;

    /// The pseudo-C for one function, by name.
    fn decompile(
        &self,
        name: &str,
    ) -> impl std::future::Future<Output = Result<DecompiledFunction>> + Send;

    /// Every string literal defined in the program.
    fn strings(&self) -> impl std::future::Future<Output = Result<Vec<StringLiteral>>> + Send;

    /// The names of the functions that call the function at `address`.
    fn callers(
        &self,
        address: u64,
    ) -> impl std::future::Future<Output = Result<Vec<String>>> + Send;
}

impl ScanSource for GhidraClient {
    async fn functions(&self) -> Result<Vec<FunctionSummary>> {
        Ok(self.list_functions().await?)
    }

    async fn decompile(&self, name: &str) -> Result<DecompiledFunction> {
        Ok(self.decompile_function_by_name(name).await?)
    }

    async fn strings(&self) -> Result<Vec<StringLiteral>> {
        Ok(self.list_strings(None).await?)
    }

    async fn callers(&self, address: u64) -> Result<Vec<String>> {
        Ok(self.callers(address).await?)
    }
}

/// Orchestrates the three detectors into one [`AlgorithmRecognitionResult`].
///
/// The engine is generic over its [`ScanSource`], so tests can run the
/// whole orchestration over canned bodies; [`new`](Self::new) builds one
/// over a live [`GhidraClient`]. Each detector carries no state and
/// starts configured with its standard signature set —
/// [`with_matcher`](Self::with_matcher), [`with_string_engine`](Self::with_string_engine),
/// and [`with_callback_db`](Self::with_callback_db) swap a detector's set
/// whole — so one instance of each serves the whole scan.
#[derive(Debug, Clone)]
pub struct AlgorithmEngine<S = GhidraClient> {
    source: S,
    cfg: CfgPatternMatcher,
    strings: StringHintEngine,
    callbacks: CallbackPatternDb,
}

impl AlgorithmEngine<GhidraClient> {
    /// An engine over a live GhidraMCP client, scanning with the three
    /// standard signature sets.
    pub fn new(client: &GhidraClient) -> AlgorithmEngine<GhidraClient> {
        AlgorithmEngine {
            source: client.clone(),
            cfg: CfgPatternMatcher::with_default_patterns(),
            strings: StringHintEngine::with_default_signatures(),
            callbacks: CallbackPatternDb::with_default_patterns(),
        }
    }
}

impl<S> AlgorithmEngine<S> {
    /// An engine whose program reads come from `source`, scanning with
    /// the three standard signature sets.
    pub fn with_source(source: S) -> Self {
        AlgorithmEngine {
            source,
            cfg: CfgPatternMatcher::with_default_patterns(),
            strings: StringHintEngine::with_default_signatures(),
            callbacks: CallbackPatternDb::with_default_patterns(),
        }
    }

    /// Match control flow against `matcher`'s signatures instead of the
    /// standard set.
    pub fn with_matcher(mut self, matcher: CfgPatternMatcher) -> Self {
        self.cfg = matcher;
        self
    }

    /// Read string signatures from `engine` instead of the standard set.
    pub fn with_string_engine(mut self, engine: StringHintEngine) -> Self {
        self.strings = engine;
        self
    }

    /// Match callback contracts from `db` instead of the standard set.
    pub fn with_callback_db(mut self, db: CallbackPatternDb) -> Self {
        self.callbacks = db;
        self
    }

    /// Recognize algorithms across `binary`, decompiling each function
    /// exactly once and reading it with all three detectors.
    ///
    /// `binary` names the program the scan reads (e.g. `eqmain.dll`) and
    /// becomes the key a persisted result is filed under. The hints
    /// follow the function listing — function by function, and within one
    /// function the control flow matches, then the string-guided hints,
    /// then the callback matches — so two scans of the same program diff
    /// cleanly.
    ///
    /// A function whose body Ghidra cannot produce (a thunk, a bad entry
    /// point) is skipped with a warning, and a function whose callers
    /// cannot be read keeps its other hints with only its callback
    /// readings dropped. Only a failure of the program listing or the
    /// string listing — the server being down — aborts the run: the
    /// listing failure means nothing was scanned, and a listing failure
    /// would silently cost every function its string-guided evidence.
    /// But when more than half the listing fails to decompile, the
    /// skip-rate breaker aborts the run too: that is the signature of
    /// the bridge answering from the wrong program, and skipping on
    /// would persist a phantom-clean record (issue #71).
    pub async fn scan(&self, binary: impl Into<String>) -> Result<AlgorithmRecognitionResult>
    where
        S: ScanSource,
    {
        let started = Instant::now();
        let functions = self.source.functions().await?;
        let literals = self.source.strings().await?;

        let mut hints = Vec::new();
        let mut skipped = 0usize;
        let mut decompile_failures = 0usize;
        for function in &functions {
            if function.name.is_empty() {
                // A nameless listing entry would send the name lookup
                // wandering into some other function's body; nothing can
                // be recognized about it, so it passes unrecorded.
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
                        return Err(crate::AlgorithmError::DecompileBreaker {
                            failed: decompile_failures,
                            total: functions.len(),
                        });
                    }
                    continue;
                }
            };

            hints.extend(self.cfg.match_patterns(&decompiled));
            hints.extend(self.strings.detect_string_hints(&decompiled, &literals));

            // A contract fits only a function of exactly its arity, so
            // the caller fetch — the scan's only call-graph read — runs
            // just where some contract could still fit.
            let arity = decompiled.parameter_names().len();
            if self
                .callbacks
                .patterns()
                .iter()
                .any(|p| p.param_count == arity)
            {
                let callers = match self.source.callers(function.address).await {
                    Ok(callers) => callers,
                    Err(error) => {
                        warn!(
                            function = %function.name,
                            error = %error,
                            "Could not read callers: callback detection skips the function"
                        );
                        Vec::new()
                    }
                };
                hints.extend(
                    self.callbacks
                        .detect_callback_patterns(&decompiled, callers)
                        .into_iter()
                        .map(|detection| detection.hint),
                );
            }
        }

        let mut metadata = ScanMetadata::new(binary);
        metadata.duration_secs = started.elapsed().as_secs();
        info!(
            binary = %metadata.binary,
            functions = functions.len(),
            hints = hints.len(),
            skipped,
            duration_secs = metadata.duration_secs,
            "Recognized algorithms"
        );
        Ok(AlgorithmRecognitionResult { metadata, hints })
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AlgorithmCategory, AlgorithmHint, Confidence, DetectionMethod};
    use calxgloss_ghidra::GhidraError;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    fn summary(name: &str, address: u64) -> FunctionSummary {
        FunctionSummary {
            name: name.to_string(),
            address,
        }
    }

    fn function(name: &str, signature: &str, body: &str) -> DecompiledFunction {
        DecompiledFunction {
            name: name.to_string(),
            signature: signature.to_string(),
            body: format!("{signature}\n\n{{\n{body}}}\n"),
        }
    }

    const AB00: u64 = 0x1800_3ab00;
    const E750: u64 = 0x1800_3e750;
    const A12A0: u64 = 0x1800_412a0;

    /// State shared by every clone of a [`FakeProgram`], so a test can
    /// read what the scan did after the engine has consumed its source.
    #[derive(Debug, Default)]
    struct Stats {
        decompiles: Mutex<Vec<String>>,
        string_fetches: AtomicUsize,
        caller_fetches: Mutex<Vec<u64>>,
    }

    /// A canned program implementing [`ScanSource`], so the whole
    /// orchestration runs without a server.
    #[derive(Clone)]
    struct FakeProgram {
        listing: Vec<FunctionSummary>,
        bodies: HashMap<String, DecompiledFunction>,
        literals: Vec<StringLiteral>,
        callers: HashMap<u64, Vec<String>>,
        fail_listing: bool,
        fail_strings: bool,
        fail_decompiles: Vec<String>,
        fail_callers: Vec<u64>,
        stats: Arc<Stats>,
    }

    impl FakeProgram {
        fn empty() -> Self {
            Self {
                listing: Vec::new(),
                bodies: HashMap::new(),
                literals: Vec::new(),
                callers: HashMap::new(),
                fail_listing: false,
                fail_strings: false,
                fail_decompiles: Vec::new(),
                fail_callers: Vec::new(),
                stats: Arc::new(Stats::default()),
            }
        }

        fn decompiled(&self) -> Vec<String> {
            self.stats.decompiles.lock().unwrap().clone()
        }

        fn string_fetches(&self) -> usize {
            self.stats.string_fetches.load(Ordering::SeqCst)
        }

        fn caller_fetches(&self) -> Vec<u64> {
            self.stats.caller_fetches.lock().unwrap().clone()
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

        async fn strings(&self) -> Result<Vec<StringLiteral>> {
            self.stats.string_fetches.fetch_add(1, Ordering::SeqCst);
            if self.fail_strings {
                return Err(GhidraError::Reported {
                    status: Some(200),
                    message: "Ghidra is busy".into(),
                }
                .into());
            }
            Ok(self.literals.clone())
        }

        async fn callers(&self, address: u64) -> Result<Vec<String>> {
            self.stats.caller_fetches.lock().unwrap().push(address);
            if self.fail_callers.contains(&address) {
                return Err(GhidraError::Reported {
                    status: Some(200),
                    message: "Ghidra is busy".into(),
                }
                .into());
            }
            Ok(self.callers.get(&address).cloned().unwrap_or_default())
        }
    }

    /// A decompiled bubble sort: the outer pass, the inner sweep, the
    /// ordering comparison, and the swap through `iVar4` — the shape the
    /// standard control flow set reads as a comparison sort.
    fn sort_body() -> String {
        [
            "  int iVar2;",
            "  uint uVar3;",
            "  int iVar4;",
            "  ",
            "  uVar3 = 0;",
            "  while (uVar3 < (uint)param_2) {",
            "    iVar2 = 0;",
            "    while (iVar2 < param_2 - 1) {",
            "      if (param_1[iVar2] < param_1[iVar2 + 1]) {",
            "        iVar4 = param_1[iVar2];",
            "        param_1[iVar2] = param_1[iVar2 + 1];",
            "        param_1[iVar2 + 1] = iVar4;",
            "      }",
            "      iVar2 = iVar2 + 1;",
            "    }",
            "    uVar3 = uVar3 + 1;",
            "  }",
            "  return;",
        ]
        .join("\n")
    }

    /// A decompiled CRC loop: the byte-at-a-time fold through
    /// `crc_table` — the spelling the standard string set reads as crc.
    fn crc_body() -> String {
        [
            "  uint uVar1;",
            "  ",
            "  uVar1 = 0;",
            "  while (*param_1 != '\\0') {",
            "    uVar1 = (uVar1 ^ (ulong)(byte)*param_1) & 0xff;",
            "    uVar1 = (uVar1 >> 8) ^ crc_table[uVar1];",
            "    param_1 = param_1 + 1;",
            "  }",
            "  return uVar1;",
        ]
        .join("\n")
    }

    /// A decompiled compare callback: the two parameters compared
    /// against each other — the shape the qsort contract demands.
    fn compare_body() -> String {
        [
            "  if (*param_1 < *param_2) {",
            "    return -1;",
            "  }",
            "  if (*param_2 < *param_1) {",
            "    return 1;",
            "  }",
            "  return 0;",
        ]
        .join("\n")
    }

    /// The canned program: a sort the control flow set recognizes, a CRC
    /// loop the string set reads from the body, and a compare callback
    /// `qsort` reaches — plus a program-wide listing string carrying a
    /// `CRC32` marker no body spells.
    fn program() -> FakeProgram {
        let mut program = FakeProgram::empty();
        program.listing = vec![
            summary("FUN_18003ab00", AB00),
            summary("FUN_18003e750", E750),
            summary("FUN_1800412a0", A12A0),
        ];
        program.bodies.insert(
            "FUN_18003ab00".into(),
            function(
                "FUN_18003ab00",
                "void FUN_18003ab00(int *param_1,int param_2)",
                &sort_body(),
            ),
        );
        program.bodies.insert(
            "FUN_18003e750".into(),
            function(
                "FUN_18003e750",
                "undefined4 FUN_18003e750(char *param_1)",
                &crc_body(),
            ),
        );
        program.bodies.insert(
            "FUN_1800412a0".into(),
            function(
                "FUN_1800412a0",
                "int FUN_1800412a0(int *param_1,int *param_2)",
                &compare_body(),
            ),
        );
        program.literals = vec![StringLiteral {
            address: 0x1801_29350,
            value: "CRC32 verification failed".into(),
        }];
        program.callers.insert(AB00, vec!["FUN_180001900".into()]);
        program.callers.insert(A12A0, vec!["qsort".into()]);
        program
    }

    async fn scan(program: FakeProgram) -> AlgorithmRecognitionResult {
        AlgorithmEngine::with_source(program)
            .scan("eqmain.dll")
            .await
            .expect("scan")
    }

    fn finding<'a>(
        result: &'a AlgorithmRecognitionResult,
        function: &str,
        method: DetectionMethod,
    ) -> &'a AlgorithmHint {
        result
            .for_function(function)
            .find(|hint| hint.method == method)
            .expect("record from that detector")
    }

    #[tokio::test]
    async fn scan_collects_hints_from_all_three_detectors() {
        let result = scan(program()).await;

        assert_eq!(result.metadata.binary, "eqmain.dll");
        assert!(result.metadata.scanned_at > 0);

        let cfg = finding(&result, "FUN_18003ab00", DetectionMethod::CfgPattern);
        assert_eq!(cfg.algorithm, "comparison_sort");
        assert_eq!(cfg.category, AlgorithmCategory::Sorting);

        // The CRC loop's own text carries the marker, so the body match
        // wins the hint over the program-wide listing.
        let string_hint = finding(&result, "FUN_18003e750", DetectionMethod::StringHint);
        assert_eq!(string_hint.algorithm, "crc");
        assert_eq!(string_hint.category, AlgorithmCategory::Checksum);
        assert_eq!(string_hint.confidence, Confidence::new(60));

        let callback = finding(&result, "FUN_1800412a0", DetectionMethod::CallbackPattern);
        assert_eq!(callback.algorithm, "qsort_compare");
        assert_eq!(callback.category, AlgorithmCategory::Sorting);
        assert_eq!(callback.evidence, "qsort");
    }

    #[tokio::test]
    async fn the_listing_string_reaches_every_function_as_program_wide_evidence() {
        // A marker only the listing carries ties the algorithm to the
        // program, not to any one function, so it stands as a weaker
        // hint beside the function's own readings.
        let result = scan(program()).await;
        let crc = finding(&result, "FUN_18003ab00", DetectionMethod::StringHint);
        assert_eq!(crc.algorithm, "crc");
        assert_eq!(crc.confidence, Confidence::new(30));
        assert_eq!(crc.evidence, "CRC32 verification failed");
    }

    #[tokio::test]
    async fn hints_follow_the_listing_and_detector_order() {
        // The sort function carries a control flow match and a
        // listing-only string hint: within the function the cfg match
        // stands before the string hint, and the function's own place
        // in the listing order is kept.
        let result = scan(program()).await;
        let methods: Vec<DetectionMethod> = result
            .for_function("FUN_18003ab00")
            .map(|hint| hint.method)
            .collect();
        assert_eq!(
            methods,
            [DetectionMethod::CfgPattern, DetectionMethod::StringHint]
        );

        let mut functions: Vec<&str> = result.hints.iter().map(|h| h.function.as_str()).collect();
        functions.dedup();
        assert_eq!(
            functions,
            vec!["FUN_18003ab00", "FUN_18003e750", "FUN_1800412a0"]
        );
    }

    #[tokio::test]
    async fn scan_decompiles_each_function_exactly_once() {
        // The three detectors share one fetch per function; a scan that
        // asked each detector for its own copy would triple the wall
        // time.
        let program = program();
        let result = scan(program.clone()).await;
        assert!(!result.is_empty());
        assert_eq!(
            program.decompiled(),
            vec!["FUN_18003ab00", "FUN_18003e750", "FUN_1800412a0"],
            "one decompile per function, in listing order"
        );
    }

    #[tokio::test]
    async fn scan_fetches_the_string_listing_once() {
        // The listing is program-wide evidence read by every function;
        // pulling it per function would re-page the whole program.
        let program = program();
        scan(program.clone()).await;
        assert_eq!(program.string_fetches(), 1);
    }

    #[tokio::test]
    async fn callers_are_fetched_only_where_a_contract_could_fit() {
        // The standard contracts all take two parameters; the CRC loop
        // takes one, so no contract fits it however it is used and its
        // callers are never asked for.
        let program = program();
        scan(program.clone()).await;
        assert_eq!(program.caller_fetches(), vec![AB00, A12A0]);
    }

    #[tokio::test]
    async fn a_function_that_will_not_decompile_is_skipped() {
        // Ghidra cannot produce a body for every function; one bad entry
        // point must not cost the whole program its scan.
        let mut program = program();
        program.fail_decompiles = vec!["FUN_18003ab00".into()];
        let result = scan(program.clone()).await;

        assert!(result.for_function("FUN_18003ab00").next().is_none());
        assert_eq!(
            program.decompiled(),
            vec!["FUN_18003ab00", "FUN_18003e750", "FUN_1800412a0"]
        );
    }

    #[tokio::test]
    async fn a_scan_where_every_decompile_fails_aborts() {
        // The 2026-10-08 incident: the bridge answered the listing from
        // one program and the decompiles from another, every decompile
        // failed, and the scan nearly persisted a phantom-clean record
        // under the target's name. The skip-rate breaker aborts with
        // the counts instead, so nothing is persisted.
        let mut program = program();
        program.fail_decompiles = vec![
            "FUN_18003ab00".into(),
            "FUN_18003e750".into(),
            "FUN_1800412a0".into(),
        ];
        let result = AlgorithmEngine::with_source(program.clone())
            .scan("eqmain.dll")
            .await;

        // The breaker is a circuit breaker, not a post-mortem: it trips
        // the moment most of the listing has failed, so the third
        // decompile is never issued.
        assert!(matches!(
            result,
            Err(crate::AlgorithmError::DecompileBreaker {
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
        // An empty name would send the by-name lookup into an arbitrary
        // function's body, so the entry passes without a decompile.
        let mut program = program();
        program.listing.insert(0, summary("", 0x1800_00000));
        let result = scan(program.clone()).await;

        assert_eq!(
            program.decompiled(),
            vec!["FUN_18003ab00", "FUN_18003e750", "FUN_1800412a0"]
        );
        assert!(!result.is_empty());
    }

    #[tokio::test]
    async fn a_failing_listing_fails_the_whole_run() {
        // With the listing gone nothing was scanned, so the run aborts
        // rather than returning a result that looks empty by accident.
        let mut program = program();
        program.fail_listing = true;
        let result = AlgorithmEngine::with_source(program)
            .scan("eqmain.dll")
            .await;
        assert!(matches!(
            result,
            Err(crate::AlgorithmError::Ghidra(GhidraError::Reported { .. }))
        ));
    }

    #[tokio::test]
    async fn a_failing_string_listing_fails_the_whole_run() {
        // Every function's string-guided evidence comes from this one
        // fetch; a result assembled without it would silently lack a
        // whole evidence class, so the run aborts.
        let mut program = program();
        program.fail_strings = true;
        let result = AlgorithmEngine::with_source(program)
            .scan("eqmain.dll")
            .await;
        assert!(matches!(
            result,
            Err(crate::AlgorithmError::Ghidra(GhidraError::Reported { .. }))
        ));
    }

    #[tokio::test]
    async fn a_failing_caller_fetch_keeps_the_other_hints() {
        // The call graph read only feeds the callback detector; when it
        // fails the function keeps its control flow and string hints and
        // only its callback readings drop.
        let mut program = program();
        program.fail_callers = vec![A12A0];
        let result = scan(program).await;

        let methods = methods_for(&result, "FUN_1800412a0");
        assert!(
            !methods.contains(&DetectionMethod::CallbackPattern),
            "the callback reading dropped with the failed fetch"
        );
        assert!(
            methods.contains(&DetectionMethod::StringHint),
            "the function keeps the hints that did not need the call graph"
        );
        assert!(!result.for_function("FUN_18003ab00").next().is_none());
    }

    fn methods_for(result: &AlgorithmRecognitionResult, function: &str) -> Vec<DetectionMethod> {
        result
            .for_function(function)
            .map(|hint| hint.method)
            .collect()
    }

    #[tokio::test]
    async fn an_empty_program_yields_an_empty_result() {
        let result = scan(FakeProgram::empty()).await;
        assert!(result.is_empty());
        assert_eq!(result.metadata.binary, "eqmain.dll");
        assert!(result.metadata.scanned_at > 0);
    }

    #[tokio::test]
    async fn configuration_reaches_every_detector() {
        // Emptying a detector's set silences exactly that detector: the
        // sort loses its cfg hint, the CRC loop its string hint, and the
        // compare callback its contract match — with no contract
        // configured, no caller is ever fetched.
        let program = program();
        let result = AlgorithmEngine::with_source(program.clone())
            .with_matcher(CfgPatternMatcher::new())
            .with_string_engine(StringHintEngine::new())
            .with_callback_db(CallbackPatternDb::new())
            .scan("eqmain.dll")
            .await
            .expect("scan");

        assert!(result.is_empty());
        assert!(program.caller_fetches().is_empty());
    }

    #[tokio::test]
    async fn a_configured_detector_scans_with_its_own_set() {
        // Swapping in a custom set changes what the scan recognizes: a
        // matcher carrying only a recursion signature reads the CRC
        // loop's self-call and nothing else from the cfg side.
        let mut program = program();
        let crc = program.bodies.get("FUN_18003e750").unwrap().clone();
        let recursive = DecompiledFunction {
            body: format!("{}\n  FUN_18003e750(param_1 + 1);\n", crc.body),
            ..crc
        };
        program.bodies.insert("FUN_18003e750".into(), recursive);

        let matcher = CfgPatternMatcher::with_patterns(
            crate::cfg_patterns::default_patterns()
                .into_iter()
                .filter(|p| p.name == "recursion"),
        );
        let result = AlgorithmEngine::with_source(program)
            .with_matcher(matcher)
            .scan("eqmain.dll")
            .await
            .expect("scan");

        let cfg = finding(&result, "FUN_18003e750", DetectionMethod::CfgPattern);
        assert_eq!(cfg.algorithm, "recursion");
        let sort_function_methods = methods_for(&result, "FUN_18003ab00");
        assert!(
            !sort_function_methods.contains(&DetectionMethod::CfgPattern),
            "the custom set carries no sort signature"
        );
    }
}
