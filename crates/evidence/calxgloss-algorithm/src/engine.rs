//! Algorithm recognition orchestration.
//!
//! [`AlgorithmEngine`] runs the detectors — control flow signature
//! matching, string-guided hints, and callback pattern detection over
//! each function, then multi-function correlation over the whole listing
//! — and assembles their records into a single
//! [`AlgorithmRecognitionResult`] with its scan provenance.
//!
//! The control flow and callback detectors are pure text analysis over
//! one decompiled body, and the string engine additionally reads the
//! program's literal listing, so the engine fetches the listing and the
//! literals exactly once and reads them with every function — the way
//! the typeinfer detectors share one decompile. The scan is then one
//! pass over the function listing, run with bounded concurrency — at
//! most eight decompiles in flight — while results are collected in
//! listing order, so the persisted hint list stays stable and diffable.
//! Where several detectors claim one algorithm
//! for one function, the scan reports it once with the strongest
//! evidence — the [`confidence`](crate::confidence) module's resolution
//! — and a configured minimum-confidence floor
//! ([`with_min_confidence`](AlgorithmEngine::with_min_confidence))
//! keeps weak claims out of the persisted result. The callback detector
//! is the only reader of the call graph, and it runs only for functions
//! whose arity a configured contract could fit: a function of the wrong
//! arity fits no contract however it is used, so fetching its callers
//! would be a round trip guaranteed to be refused. The correlation
//! detector reads no graph at all: it derives the call map from the
//! bodies this scan already fetched, so it adds no round trip and runs
//! once the whole listing is in hand.

use crate::callback_db::CallbackPatternDb;
use crate::cfg_patterns::CfgPatternMatcher;
use crate::confidence::resolve_conflicts;
use crate::cross_function::CrossFunctionDetector;
use crate::error::Result;
use crate::string_hints::StringHintEngine;
use crate::types::{AlgorithmHint, AlgorithmRecognitionResult, ScanMetadata};
use calxgloss_ghidra::{DecompiledFunction, GhidraClient};
use futures_util::stream::{self, StreamExt};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;
use tracing::{info, warn};

/// The cap on decompiles one scan keeps in flight at once.
///
/// The per-function pass runs several functions' program reads
/// concurrently to hide the bridge's round-trip latency, but the
/// bridge answers one program at a time: a bounded handful of
/// in-flight decompiles is what shrinks wall time on a large binary
/// without flooding it. The engine tests' concurrency accounting
/// proves the scan never exceeds this cap (issue #156).
const MAX_IN_FLIGHT_DECOMPILES: usize = 8;

/// What one function's turn in the concurrent per-function pass produced.
///
/// The pass runs each function's reads and detectors off the listing
/// and hands the result back in listing order, so the assembled hint
/// list is exactly the sequential walk's; the variants say what the
/// scan owes the skip count and the breaker.
enum PassOutcome {
    /// The body, with the per-function hints read from it in detector
    /// order — control flow, then string-guided, then callback.
    Read {
        body: DecompiledFunction,
        hints: Vec<AlgorithmHint>,
    },
    /// The decompile failed; the skip-rate breaker counts it.
    Failed,
    /// A nameless listing entry, skipped without a decompile.
    Nameless,
    /// The breaker had already tripped before this function's decompile
    /// was issued — the pass read nothing. The collector normally
    /// aborts at the counted [`Failed`](PassOutcome::Failed) that
    /// tripped the breaker before one of these lands; this is the
    /// backstop that keeps the abort with the counts either way.
    Halted,
}

/// The skip-rate breaker: one shared decompile-failure count a
/// concurrent scan judges against the listing's size.
///
/// The rule is the sequential scan's — the run is reading the wrong
/// program once *most* of the listing has failed to decompile, more
/// than half of it, and an empty result would persist as a
/// phantom-clean record (issue #71). Under the concurrent pass the
/// count lives beside the pass, not behind it: every failed decompile
/// joins it as it lands, and every function not yet started consults
/// it before issuing its decompile, so a tripped breaker stops new
/// decompiles rather than merely ending the walk (issue #156).
struct SkipRateBreaker {
    failures: AtomicUsize,
    total: usize,
}

impl SkipRateBreaker {
    /// A breaker over a listing of `total` functions, nothing failed
    /// yet.
    fn new(total: usize) -> Self {
        SkipRateBreaker {
            failures: AtomicUsize::new(0),
            total,
        }
    }

    /// Record one failed decompile.
    fn record_failure(&self) {
        self.failures.fetch_add(1, Ordering::SeqCst);
    }

    /// Whether more than half the listing has failed to decompile.
    fn tripped(&self) -> bool {
        self.failures.load(Ordering::SeqCst) * 2 > self.total
    }

    /// The abort error, carrying the counts the breaker holds.
    fn error(&self) -> crate::AlgorithmError {
        crate::AlgorithmError::DecompileBreaker {
            failed: self.failures.load(Ordering::SeqCst),
            total: self.total,
        }
    }
}

/// The program reads a recognition scan performs.
///
/// The shared trait from the Ghidra integration crate, re-exported here
/// so the engine's generic shape names it where it always has;
/// [`GhidraClient`] implements it over the live HTTP API, and tests
/// implement it over canned bodies so the orchestration runs without a
/// server. The futures are `Send` so a scan can be driven from an
/// orchestrating task.
pub use calxgloss_ghidra::ScanSource;

/// Orchestrates the detectors into one [`AlgorithmRecognitionResult`].
///
/// The engine is generic over its [`ScanSource`], so tests can run the
/// whole orchestration over canned bodies; [`new`](Self::new) builds one
/// over a live [`GhidraClient`]. Each detector carries no state and
/// starts configured with its standard signature set —
/// [`with_matcher`](Self::with_matcher), [`with_string_engine`](Self::with_string_engine),
/// [`with_callback_db`](Self::with_callback_db), and
/// [`with_cross_detector`](Self::with_cross_detector) swap a detector's
/// set whole, and [`with_pattern_database`](Self::with_pattern_database)
/// swaps the three per-function sets at once from one
/// [database document](crate::pattern_db) — so one instance of each
/// serves the whole scan. A scan keeps every hint it resolves by
/// default; [`with_min_confidence`](Self::with_min_confidence) sets a
/// floor below which hints never reach the persisted result.
#[derive(Debug, Clone)]
pub struct AlgorithmEngine<S = GhidraClient> {
    source: S,
    cfg: CfgPatternMatcher,
    strings: StringHintEngine,
    callbacks: CallbackPatternDb,
    cross: CrossFunctionDetector,
    min_confidence: u8,
}

impl AlgorithmEngine<GhidraClient> {
    /// An engine over a live GhidraMCP client, scanning with the
    /// standard signature sets.
    pub fn new(client: &GhidraClient) -> AlgorithmEngine<GhidraClient> {
        AlgorithmEngine {
            source: client.clone(),
            cfg: CfgPatternMatcher::with_default_patterns(),
            strings: StringHintEngine::with_default_signatures(),
            callbacks: CallbackPatternDb::with_default_patterns(),
            cross: CrossFunctionDetector::with_default_relationships(),
            min_confidence: 0,
        }
    }
}

impl<S> AlgorithmEngine<S> {
    /// An engine whose program reads come from `source`, scanning with
    /// the standard signature sets.
    pub fn with_source(source: S) -> Self {
        AlgorithmEngine {
            source,
            cfg: CfgPatternMatcher::with_default_patterns(),
            strings: StringHintEngine::with_default_signatures(),
            callbacks: CallbackPatternDb::with_default_patterns(),
            cross: CrossFunctionDetector::with_default_relationships(),
            min_confidence: 0,
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

    /// Correlate call relationships with `detector`'s relationships
    /// instead of the standard set.
    pub fn with_cross_detector(mut self, detector: CrossFunctionDetector) -> Self {
        self.cross = detector;
        self
    }

    /// Scan with `database`'s sets for the detectors instead of the
    /// standard sets.
    ///
    /// The swap is whole, never a merge: each detector reads exactly
    /// the entries the [database](crate::pattern_db) carries, and a
    /// section the document omitted leaves that detector with nothing
    /// to read. Entries keep the detectors' semantics whole — the
    /// `{name}` placeholder, the lenient uncompilable-regex rule, and
    /// the per-entry confidence that overrides the standard score in
    /// resolution. The correlation section is no exception: a supplied
    /// database replaces the built-in relationship set whole, and only
    /// a scan with no database at all keeps the built-in relationships.
    pub fn with_pattern_database(mut self, database: crate::pattern_db::PatternDatabase) -> Self {
        self.cfg = CfgPatternMatcher::with_patterns(database.control_flow);
        self.strings = StringHintEngine::with_signatures(database.string_signatures);
        self.callbacks = CallbackPatternDb::with_patterns(database.callback_contracts);
        self.cross = CrossFunctionDetector::with_relationships(database.correlation_patterns);
        self
    }

    /// Persist only hints scoring `threshold` or higher.
    ///
    /// Mirrors the typesdb engine's filter: the floor drops hints below
    /// `threshold` and keeps those at or above it, and it applies after
    /// conflict resolution — to the surviving claim — so a reading
    /// another detector strengthened clears a threshold its first claim
    /// would have missed.
    pub fn with_min_confidence(mut self, threshold: u8) -> Self {
        self.min_confidence = threshold;
        self
    }

    /// Recognize algorithms across `binary`, decompiling each function
    /// exactly once and reading it with all three per-function
    /// detectors, then correlating the whole listing.
    ///
    /// `binary` names the program the scan reads (e.g. `eqmain.dll`) and
    /// becomes the key a persisted result is filed under. The hints
    /// follow the function listing — function by function, and within one
    /// function the control flow matches, then the string-guided hints,
    /// then the callback matches — and the correlation pass, which needs
    /// every body in hand to derive the call map, then reports its own
    /// hints in listing order, so two scans of the same program diff
    /// cleanly.
    ///
    /// The per-function pass is concurrent — up to eight functions'
    /// reads in flight at once, so a large binary scans faster without
    /// flooding the bridge — but each function's result is held until
    /// the one before it lands, so the assembled hint list is identical
    /// to the sequential walk's.
    ///
    /// Where several detectors claim the same algorithm for one function,
    /// the scan reports it once with its strongest evidence: a tie keeps
    /// the claim the scan surfaced first, and the survivor stands where
    /// that algorithm first appeared. Different algorithms claimed for
    /// one function all stand. A configured minimum-confidence floor
    /// ([`with_min_confidence`](Self::with_min_confidence)) then drops
    /// hints below the threshold — after resolution, so the floor judges
    /// each algorithm's surviving strongest claim.
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
    /// would persist a phantom-clean record (issue #71). The breaker
    /// counts failures across the concurrent pass, and once it trips no
    /// new decompile is issued (issue #156).
    pub async fn scan(&self, binary: impl Into<String>) -> Result<AlgorithmRecognitionResult>
    where
        S: ScanSource,
    {
        let started = Instant::now();
        let functions = self.source.functions().await?;
        let literals = self.source.strings().await?;
        let total = functions.len();

        // The skip-rate breaker lives beside the concurrent pass, not
        // behind it: every failed decompile joins the count as it
        // lands, and every function not yet started reads the count
        // before issuing its decompile — so once the run has clearly
        // lost most of the listing, no new decompile is issued.
        let breaker = Arc::new(SkipRateBreaker::new(total));

        let mut pass = stream::iter(functions.iter().map(|function| {
            let breaker = Arc::clone(&breaker);
            // The literals are program-wide evidence read by every
            // function: one fetch, shared by reference across the pass.
            let literals = &literals;
            async move {
                if function.name.is_empty() {
                    // A nameless listing entry would send the name lookup
                    // wandering into some other function's body; nothing can
                    // be recognized about it, so it passes unrecorded.
                    warn!(
                        address = format_args!("{:#x}", function.address),
                        "Skipping function with no name"
                    );
                    return PassOutcome::Nameless;
                }
                if breaker.tripped() {
                    // The breaker already tripped: this function's
                    // decompile is never issued.
                    return PassOutcome::Halted;
                }
                let decompiled = match self.source.decompile(&function.name).await {
                    Ok(decompiled) => decompiled,
                    Err(error) => {
                        warn!(
                            function = %function.name,
                            error = %error,
                            "Skipping function: decompile failed"
                        );
                        breaker.record_failure();
                        return PassOutcome::Failed;
                    }
                };

                let mut hints = Vec::new();
                hints.extend(self.cfg.match_patterns(&decompiled));
                hints.extend(self.strings.detect_string_hints(&decompiled, literals));

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

                PassOutcome::Read {
                    body: decompiled,
                    hints,
                }
            }
        }))
        .buffered(MAX_IN_FLIGHT_DECOMPILES);

        // Results land in listing order — `buffered` holds each
        // function's result until the one before it has been taken —
        // so the assembled hints and the kept bodies see exactly the
        // order the sequential walk saw.
        let mut hints = Vec::new();
        let mut bodies: Vec<DecompiledFunction> = Vec::with_capacity(total);
        let mut skipped = 0usize;
        while let Some(outcome) = pass.next().await {
            match outcome {
                PassOutcome::Read { body, hints: own } => {
                    hints.extend(own);
                    // Keep the body: the correlation pass reads the call map
                    // off the bodies this scan already fetched, so it costs
                    // no extra round trip.
                    bodies.push(body);
                }
                PassOutcome::Nameless => skipped += 1,
                PassOutcome::Failed => {
                    skipped += 1;
                    if breaker.tripped() {
                        return Err(breaker.error());
                    }
                }
                PassOutcome::Halted => return Err(breaker.error()),
            }
        }

        // The correlation pass runs once the whole listing is in hand —
        // a relationship spans a call, and the callee's body may sit
        // anywhere in the listing — and reports in listing order.
        hints.extend(self.cross.detect_correlations(&bodies));

        let mut metadata = ScanMetadata::new(binary);
        // The source names its engine and pin under `kuna`; the Ghidra
        // path names nothing and the record stays exactly as it was
        // (issue #208).
        metadata.engine = self.source.engine_provenance();
        metadata.duration_secs = started.elapsed().as_secs();
        // Competing claims for one (function, algorithm) resolve to
        // their strongest reading before the floor applies, so the
        // threshold judges each algorithm's best claim rather than
        // every duplicate, and the survivor keeps the position where
        // that algorithm first appeared in scan order.
        let hints: Vec<AlgorithmHint> = resolve_conflicts(hints)
            .into_iter()
            .filter(|hint| hint.confidence >= self.min_confidence)
            .collect();
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
    use crate::callback_db::CallbackPattern;
    use crate::pattern_db::PatternDatabase;
    use crate::types::{
        AlgorithmCategory, AlgorithmHint, AlgorithmPattern, Confidence, DetectionMethod,
    };
    use calxgloss_ghidra::{
        DataItem, DataTypeEntry, DecompiledFunction, EnumDefinition, FunctionSummary, GhidraError,
        Result, StringLiteral, StructLayout, Symbol, Xref,
    };
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    fn summary(name: &str, address: u64) -> FunctionSummary {
        FunctionSummary {
            name: name.to_string(),
            address,
        }
    }

    fn literal(address: u64, value: &str) -> StringLiteral {
        StringLiteral {
            address,
            value: value.to_string(),
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
        in_flight: AtomicUsize,
        max_in_flight: AtomicUsize,
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
        /// Hold each decompile open across an await so several are
        /// genuinely in flight at once — what proves the scan's
        /// concurrency cap is a real window, not a sequential walk.
        slow_decompiles: bool,
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
                slow_decompiles: false,
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

        /// The most decompiles the scan ever had in flight at once.
        fn max_in_flight(&self) -> usize {
            self.stats.max_in_flight.load(Ordering::SeqCst)
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
            let in_flight = self.stats.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            self.stats
                .max_in_flight
                .fetch_max(in_flight, Ordering::SeqCst);
            if self.slow_decompiles {
                tokio::task::yield_now().await;
            }
            self.stats.in_flight.fetch_sub(1, Ordering::SeqCst);
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

        async fn strings(&self) -> Result<Vec<StringLiteral>> {
            self.stats.string_fetches.fetch_add(1, Ordering::SeqCst);
            if self.fail_strings {
                return Err(GhidraError::Reported {
                    status: Some(200),
                    message: "Ghidra is busy".into(),
                });
            }
            Ok(self.literals.clone())
        }

        async fn callers(&self, address: u64) -> Result<Vec<String>> {
            self.stats.caller_fetches.lock().unwrap().push(address);
            if self.fail_callers.contains(&address) {
                return Err(GhidraError::Reported {
                    status: Some(200),
                    message: "Ghidra is busy".into(),
                });
            }
            Ok(self.callers.get(&address).cloned().unwrap_or_default())
        }

        // The rest of the shared trait's reads: this engine never makes
        // them, so they answer with empty or not-found data.
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
        program.literals = vec![literal(0x1801_29350, "CRC32 verification failed")];
        program.callers.insert(AB00, vec!["FUN_180001900".into()]);
        program.callers.insert(A12A0, vec!["qsort".into()]);
        program
    }

    /// A program whose bodies call each other: a recursive split that
    /// halves its range, and a library sort that hands the host the
    /// comparator sitting beside it in the listing. The default
    /// relationship set reads both correlations from the call map the
    /// scan already holds.
    fn correlated_program() -> FakeProgram {
        let mut program = FakeProgram::empty();
        program.listing = vec![
            summary("FUN_180050000", 0x1800_50000),
            summary("FUN_180050100", 0x1800_50100),
            summary("FUN_1800412a0", A12A0),
        ];
        program.bodies.insert(
            "FUN_180050000".into(),
            function(
                "FUN_180050000",
                "void FUN_180050000(int *param_1,int param_2)",
                &[
                    "  if (param_2 < 2) {",
                    "    return;",
                    "  }",
                    "  FUN_180050000(param_1,param_2 / 2);",
                    "  FUN_180050000(param_1 + (param_2 / 2),param_2 / 2);",
                    "  return;",
                ]
                .join("\n"),
            ),
        );
        program.bodies.insert(
            "FUN_180050100".into(),
            function(
                "FUN_180050100",
                "void FUN_180050100(int *param_1,int param_2)",
                &["  qsort(param_1,param_2,4,FUN_1800412a0);", "  return;"].join("\n"),
            ),
        );
        program.bodies.insert(
            "FUN_1800412a0".into(),
            function(
                "FUN_1800412a0",
                "int FUN_1800412a0(int *param_1,int *param_2)",
                &[
                    "  if (*param_1 < *param_2) {",
                    "    return -1;",
                    "  }",
                    "  return 1;",
                ]
                .join("\n"),
            ),
        );
        program
    }

    /// A program whose only call relationship is one no built-in
    /// relationship names: a custom host `my_sort` handed the comparator
    /// sitting beside it in the listing. The built-in set reads nothing
    /// here — it knows `qsort`, not this host — so a file that names the
    /// host is the only way the scan sees the relationship.
    fn custom_host_program() -> FakeProgram {
        let mut program = FakeProgram::empty();
        program.listing = vec![
            summary("FUN_180050200", 0x1800_50200),
            summary("FUN_1800412a0", A12A0),
        ];
        program.bodies.insert(
            "FUN_180050200".into(),
            function(
                "FUN_180050200",
                "void FUN_180050200(int *param_1,int param_2)",
                &["  my_sort(param_1,param_2,4,FUN_1800412a0);", "  return;"].join("\n"),
            ),
        );
        program.bodies.insert(
            "FUN_1800412a0".into(),
            function(
                "FUN_1800412a0",
                "int FUN_1800412a0(int *param_1,int *param_2)",
                &[
                    "  if (*param_1 < *param_2) {",
                    "    return -1;",
                    "  }",
                    "  return 1;",
                ]
                .join("\n"),
            ),
        );
        program
    }

    /// A listing of `count` plain functions — wide enough to outstrip
    /// the scan's in-flight cap, which is the shape the concurrency
    /// tests need. The bodies carry no algorithm shape, so the scan
    /// claims nothing and the tests read only the fetch accounting.
    fn wide_program(count: usize) -> FakeProgram {
        let mut program = FakeProgram::empty();
        program.listing = (0..count)
            .map(|i| summary(&format!("FUN_wide{i:04}"), 0x1800_60000 + i as u64))
            .collect();
        for entry in &program.listing {
            program.bodies.insert(
                entry.name.clone(),
                function(
                    &entry.name,
                    &format!("void {}(void)", entry.name),
                    "  return;\n",
                ),
            );
        }
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
    async fn the_breaker_aborts_a_concurrent_run_with_the_right_counts() {
        // A listing wider than the scan's in-flight cap, every decompile
        // failing: the breaker counts failures across the concurrent
        // pass, aborts with those counts, and stops issuing decompiles
        // once it trips — the functions past the trip are never read
        // at all (issue #156).
        let mut program = wide_program(12);
        program.fail_decompiles = program.listing.iter().map(|f| f.name.clone()).collect();
        let result = AlgorithmEngine::with_source(program.clone())
            .scan("eqmain.dll")
            .await;

        // The breaker trips at the first failure count that is most of
        // the listing: 7 of 12.
        assert!(matches!(
            result,
            Err(crate::AlgorithmError::DecompileBreaker {
                failed: 7,
                total: 12
            })
        ));
        let names: Vec<String> = (0..12).map(|i| format!("FUN_wide{i:04}")).collect();
        assert_eq!(
            program.decompiled(),
            names[..7],
            "the pass stopped issuing decompiles once the breaker tripped"
        );
    }

    #[tokio::test]
    async fn decompiles_run_concurrently_but_never_exceed_the_cap() {
        // The point of the parallel pass is overlap; the point of the
        // cap is that the bridge never drowns. With every decompile
        // held open, the fake's accounting proves the window: more than
        // one in flight at a time, never more than the cap, and still
        // exactly one decompile per function (issue #156).
        let mut program = wide_program(20);
        program.slow_decompiles = true;
        let result = scan(program.clone()).await;
        assert!(result.hints.is_empty(), "plain bodies claim nothing");
        assert_eq!(
            program.decompiled().len(),
            20,
            "each function still decompiled exactly once"
        );
        let max = program.max_in_flight();
        assert!(max >= 2, "the pass really overlaps decompiles");
        assert!(
            max <= MAX_IN_FLIGHT_DECOMPILES,
            "in-flight decompiles never exceed the cap"
        );
    }

    #[tokio::test]
    async fn the_concurrent_pass_produces_the_hint_list_of_the_sequential_walk() {
        // The cap reorders nothing: with every decompile held open, the
        // assembled hints are still function by function in listing
        // order, detector by detector — byte for byte what the same
        // program produces when each read lands before the next is
        // issued.
        let mut slow = program();
        slow.slow_decompiles = true;
        let concurrent = scan(slow).await;
        let sequential = scan(program()).await;
        assert_eq!(concurrent.hints, sequential.hints);
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

    #[tokio::test]
    async fn one_algorithm_claimed_by_two_detectors_reports_once_with_the_stronger_evidence() {
        // A callback contract naming `crc` reaches the sort function
        // through its caller at 75, while the program-wide listing
        // claims `crc` there at 30: the scan reports crc once, carrying
        // the callback's stronger reading.
        let db = CallbackPatternDb::with_patterns([CallbackPattern::new(
            "crc",
            AlgorithmCategory::Checksum,
            ["FUN_180001900"],
            2,
        )]);
        let result = AlgorithmEngine::with_source(program())
            .with_callback_db(db)
            .scan("eqmain.dll")
            .await
            .expect("scan");

        let crc: Vec<&AlgorithmHint> = result
            .for_function("FUN_18003ab00")
            .filter(|hint| hint.algorithm == "crc")
            .collect();
        assert_eq!(crc.len(), 1, "one claim per algorithm per function");
        assert_eq!(crc[0].method, DetectionMethod::CallbackPattern);
        assert_eq!(crc[0].confidence, Confidence::new(75));
        assert_eq!(crc[0].evidence, "FUN_180001900");
    }

    #[tokio::test]
    async fn a_tie_between_detectors_keeps_the_claim_the_scan_surfaced_first() {
        // A control flow signature and the string set's body match both
        // read the CRC loop as `crc` at 60; the scan surfaces the
        // control flow match first, so that claim stands.
        let matcher = CfgPatternMatcher::with_patterns([AlgorithmPattern::new(
            "crc",
            AlgorithmCategory::Checksum,
            ["crc_table"],
        )]);
        let result = AlgorithmEngine::with_source(program())
            .with_matcher(matcher)
            .scan("eqmain.dll")
            .await
            .expect("scan");

        let crc: Vec<&AlgorithmHint> = result
            .for_function("FUN_18003e750")
            .filter(|hint| hint.algorithm == "crc")
            .collect();
        assert_eq!(crc.len(), 1);
        assert_eq!(crc[0].method, DetectionMethod::CfgPattern);
        assert_eq!(crc[0].evidence, "uVar1 = (uVar1 >> 8) ^ crc_table[uVar1];");
    }

    #[tokio::test]
    async fn the_surviving_claim_stands_where_the_algorithm_first_appeared() {
        // For the sort function the scan surfaces the listing's crc
        // claim (30) before the callback contract's stronger crc claim
        // (75), with the http listing claim surfacing in between: the
        // surviving crc stands at the position crc first appeared, not
        // where its stronger claim arrived — and the different
        // algorithms beside it all coexist.
        let mut program = program();
        program
            .literals
            .push(literal(0x1801_29400, "HTTP/1.1 200 OK"));
        let db = CallbackPatternDb::with_patterns([CallbackPattern::new(
            "crc",
            AlgorithmCategory::Checksum,
            ["FUN_180001900"],
            2,
        )]);
        let result = AlgorithmEngine::with_source(program)
            .with_callback_db(db)
            .scan("eqmain.dll")
            .await
            .expect("scan");

        let claims: Vec<(&str, DetectionMethod)> = result
            .for_function("FUN_18003ab00")
            .map(|hint| (hint.algorithm.as_str(), hint.method))
            .collect();
        assert_eq!(
            claims,
            [
                ("comparison_sort", DetectionMethod::CfgPattern),
                ("crc", DetectionMethod::CallbackPattern),
                ("http", DetectionMethod::StringHint),
            ],
            "the crc winner stands where crc first appeared, and different algorithms coexist"
        );
    }

    #[tokio::test]
    async fn a_program_whose_bodies_call_each_other_yields_cross_function_hints() {
        // Both built-in relationships read the correlation: the
        // recursive split claims divide_and_conquer on the caller
        // itself, and the library sort claims comparison_sort because
        // the comparator it names compares its two arguments. Each
        // hint's evidence is the body line naming the partner.
        let result = scan(correlated_program()).await;

        let split = finding(&result, "FUN_180050000", DetectionMethod::CrossFunction);
        assert_eq!(split.algorithm, "divide_and_conquer");
        assert_eq!(split.category, AlgorithmCategory::Recursion);
        assert_eq!(split.confidence, Confidence::new(70));
        assert_eq!(split.evidence, "FUN_180050000(param_1,param_2 / 2);");

        let sort = finding(&result, "FUN_180050100", DetectionMethod::CrossFunction);
        assert_eq!(sort.algorithm, "comparison_sort");
        assert_eq!(sort.category, AlgorithmCategory::Sorting);
        assert_eq!(sort.confidence, Confidence::new(70));
        assert_eq!(sort.evidence, "qsort(param_1,param_2,4,FUN_1800412a0);");

        assert!(
            result.for_function("FUN_1800412a0").next().is_none(),
            "the comparator carries no relationship of its own"
        );
    }

    #[tokio::test]
    async fn the_call_map_adds_no_extra_program_reads() {
        // The correlation pass reads the bodies the scan already
        // fetched: emptying the cross detector changes which hints
        // appear but not how many times the program was read.
        let correlated = correlated_program();
        scan(correlated.clone()).await;
        let stripped = correlated_program();
        let result = AlgorithmEngine::with_source(stripped.clone())
            .with_cross_detector(CrossFunctionDetector::new())
            .scan("eqmain.dll")
            .await
            .expect("scan");

        assert!(
            !methods_for(&result, "FUN_180050100").contains(&DetectionMethod::CrossFunction),
            "the empty detector claims nothing"
        );
        assert_eq!(correlated.decompiled(), stripped.decompiled());
        assert_eq!(correlated.string_fetches(), stripped.string_fetches());
        assert_eq!(correlated.caller_fetches(), stripped.caller_fetches());
    }

    #[tokio::test]
    async fn a_correlated_claim_wins_resolution_against_a_weaker_body_match() {
        // A control flow signature naming the library host claims
        // comparison_sort at the standard body-match score of 60; the
        // correlation reads the same function at 70. Resolution keeps
        // the stronger claim, and the scan reports the algorithm once.
        let matcher = CfgPatternMatcher::with_patterns([AlgorithmPattern {
            min_lines: 4,
            ..AlgorithmPattern::new(
                "comparison_sort",
                AlgorithmCategory::Sorting,
                [r"\bqsort\s*\("],
            )
        }]);
        let result = AlgorithmEngine::with_source(correlated_program())
            .with_matcher(matcher)
            .scan("eqmain.dll")
            .await
            .expect("scan");

        let claims: Vec<&AlgorithmHint> = result
            .for_function("FUN_180050100")
            .filter(|hint| hint.algorithm == "comparison_sort")
            .collect();
        assert_eq!(claims.len(), 1, "one claim per algorithm per function");
        assert_eq!(claims[0].method, DetectionMethod::CrossFunction);
        assert_eq!(claims[0].confidence, Confidence::new(70));
    }

    #[tokio::test]
    async fn the_minimum_confidence_filter_applies_to_correlated_hints() {
        // Correlated hints sit at 70: a floor of 70 keeps them — the
        // filter drops below the threshold, not at it — while a floor
        // of 75, the callback contract's score, drops them.
        let kept = AlgorithmEngine::with_source(correlated_program())
            .with_min_confidence(70)
            .scan("eqmain.dll")
            .await
            .expect("scan");
        assert!(methods_for(&kept, "FUN_180050000").contains(&DetectionMethod::CrossFunction));
        assert!(methods_for(&kept, "FUN_180050100").contains(&DetectionMethod::CrossFunction));

        let dropped = AlgorithmEngine::with_source(correlated_program())
            .with_min_confidence(75)
            .scan("eqmain.dll")
            .await
            .expect("scan");
        assert!(
            !dropped
                .hints
                .iter()
                .any(|hint| hint.method == DetectionMethod::CrossFunction),
            "a floor above 70 drops every correlated hint"
        );
    }

    #[tokio::test]
    async fn a_pattern_database_silences_the_correlation_detector_too() {
        // The whole-swap contract reaches the fourth detector: the
        // document omits the correlation section, so a scan configured
        // from a file correlates nothing — the file is exactly what the
        // scan knows, and a file that retires the built-in qsort shape
        // never keeps a built-in correlation.
        let result = AlgorithmEngine::with_source(correlated_program())
            .with_pattern_database(PatternDatabase::default())
            .scan("eqmain.dll")
            .await
            .expect("scan");
        assert!(
            result.is_empty(),
            "the file leaves every detector nothing to read"
        );
    }

    #[tokio::test]
    async fn the_minimum_confidence_filter_drops_hints_below_the_threshold() {
        // The listing-only crc claims (30) fall below a floor of 40
        // while body matches (60) and the callback contract (75) stand.
        // The floor applies after resolution: the sort function's crc
        // claim was first surfaced at 30 but the contract strengthens
        // it to 75, so it clears a floor the raw listing claim could
        // not.
        let db = CallbackPatternDb::with_patterns([CallbackPattern::new(
            "crc",
            AlgorithmCategory::Checksum,
            ["FUN_180001900"],
            2,
        )]);
        let result = AlgorithmEngine::with_source(program())
            .with_callback_db(db)
            .with_min_confidence(40)
            .scan("eqmain.dll")
            .await
            .expect("scan");

        let sort: Vec<(&str, u8)> = result
            .for_function("FUN_18003ab00")
            .map(|hint| (hint.algorithm.as_str(), hint.confidence.value()))
            .collect();
        assert_eq!(sort, [("comparison_sort", 60), ("crc", 75)]);
        assert_eq!(
            result
                .for_function("FUN_18003e750")
                .next()
                .expect("the body match stands")
                .confidence
                .value(),
            60
        );
        assert!(
            result.for_function("FUN_1800412a0").next().is_none(),
            "the compare callback's only claim was the listing-only crc at 30"
        );
    }

    #[tokio::test]
    async fn the_threshold_keeps_hints_at_exactly_its_value() {
        // A floor of 30 keeps the listing-only claims sitting exactly
        // on it — the filter drops below the threshold, not at it.
        let result = AlgorithmEngine::with_source(program())
            .with_min_confidence(30)
            .scan("eqmain.dll")
            .await
            .expect("scan");
        let listing_claim = result
            .for_function("FUN_18003ab00")
            .find(|hint| hint.algorithm == "crc")
            .expect("the listing-only crc claim survives at exactly the floor");
        assert_eq!(listing_claim.confidence, Confidence::new(30));
    }

    /// Parse a pattern-file document, for the tests that configure a
    /// scan from a database. The documents are spelled as file contents
    /// on purpose: these tests pin the file format at the scan seam.
    fn database_document(json: &str) -> PatternDatabase {
        serde_json::from_str(json).expect("the database document parses")
    }

    #[tokio::test]
    async fn a_scan_configured_from_a_pattern_database_recognizes_a_shape_only_the_file_carries() {
        // A database document teaches the scan a shape no built-in set
        // knows: the crc32 variant reads on the CRC loop, at the
        // standard control flow score. And the swap is whole — the
        // file replaces the standard sets, so the built-in sort shape
        // is gone.
        let db = database_document(
            r#"{
                "control_flow": [{
                    "name": "crc32_variant",
                    "category": "checksum",
                    "match_patterns": ["crc_table\\["],
                    "min_lines": 5
                }]
            }"#,
        );
        let result = AlgorithmEngine::with_source(program())
            .with_pattern_database(db)
            .scan("eqmain.dll")
            .await
            .expect("scan");

        let variant: Vec<&AlgorithmHint> = result
            .for_function("FUN_18003e750")
            .filter(|hint| hint.algorithm == "crc32_variant")
            .collect();
        assert_eq!(variant.len(), 1);
        assert_eq!(variant[0].method, DetectionMethod::CfgPattern);
        assert_eq!(variant[0].confidence.value(), 60);
        assert_eq!(
            variant[0].evidence,
            "uVar1 = (uVar1 >> 8) ^ crc_table[uVar1];"
        );
        assert!(
            methods_for(&result, "FUN_18003ab00").is_empty(),
            "the file replaces the standard sets whole — the built-in sort claim is gone"
        );
    }

    #[tokio::test]
    async fn a_per_entry_confidence_in_the_database_outweighs_a_standard_score_claim() {
        // The file's string signature claims `crc` at 90 while its
        // control flow signature claims the same algorithm at the
        // standard 60; resolution keeps the stronger per-entry
        // reading, standing where crc first appeared in scan order.
        let db = database_document(
            r#"{
                "control_flow": [{
                    "name": "crc",
                    "category": "checksum",
                    "match_patterns": ["crc_table\\["],
                    "min_lines": 5
                }],
                "string_signatures": [{
                    "name": "crc",
                    "category": "checksum",
                    "markers": ["crc_table"],
                    "confidence": 90
                }]
            }"#,
        );
        let result = AlgorithmEngine::with_source(program())
            .with_pattern_database(db)
            .scan("eqmain.dll")
            .await
            .expect("scan");

        let claims: Vec<(DetectionMethod, u8)> = result
            .for_function("FUN_18003e750")
            .map(|hint| (hint.method, hint.confidence.value()))
            .collect();
        assert_eq!(
            claims,
            [(DetectionMethod::StringHint, 90)],
            "one claim for crc, the per-entry confidence wins resolution"
        );
    }

    #[tokio::test]
    async fn a_per_entry_confidence_below_the_standard_score_loses_resolution() {
        // A file entry that distrusts itself — the crc string
        // signature at 20 — still loses to the control flow claim at
        // the standard 60: the override moves the entry's score, it
        // does not privilege the entry.
        let db = database_document(
            r#"{
                "control_flow": [{
                    "name": "crc",
                    "category": "checksum",
                    "match_patterns": ["crc_table\\["],
                    "min_lines": 5
                }],
                "string_signatures": [{
                    "name": "crc",
                    "category": "checksum",
                    "markers": ["crc_table"],
                    "confidence": 20
                }]
            }"#,
        );
        let result = AlgorithmEngine::with_source(program())
            .with_pattern_database(db)
            .scan("eqmain.dll")
            .await
            .expect("scan");

        let claims: Vec<(DetectionMethod, u8)> = result
            .for_function("FUN_18003e750")
            .map(|hint| (hint.method, hint.confidence.value()))
            .collect();
        assert_eq!(claims, [(DetectionMethod::CfgPattern, 60)]);
    }

    #[tokio::test]
    async fn a_database_entry_with_an_uncompilable_regex_claims_nothing_and_vetoes_nothing() {
        // The detectors' lenient semantics survive the file: an entry
        // whose required regex will not compile makes no claim, and an
        // entry carrying an uncompilable exclusion is vetoed by nothing
        // — one bad entry never corrupts the rest of the scan.
        let db = database_document(
            r#"{
                "control_flow": [
                    {
                        "name": "broken_claim",
                        "category": "checksum",
                        "match_patterns": ["crc_table\\[", "("],
                        "min_lines": 5
                    },
                    {
                        "name": "crc32_variant",
                        "category": "checksum",
                        "match_patterns": ["crc_table\\["],
                        "exclude_patterns": ["("],
                        "min_lines": 5
                    }
                ]
            }"#,
        );
        let result = AlgorithmEngine::with_source(program())
            .with_pattern_database(db)
            .scan("eqmain.dll")
            .await
            .expect("scan");

        let claims: Vec<&str> = result
            .for_function("FUN_18003e750")
            .map(|hint| hint.algorithm.as_str())
            .collect();
        assert_eq!(claims, ["crc32_variant"]);
    }

    #[tokio::test]
    async fn the_name_placeholder_is_substituted_in_database_entries() {
        // `{name}` in a file entry speaks of the scanned function
        // itself, exactly as in the built-ins: the entry reads the
        // signature line carrying the function's own name, and every
        // function of the program fits it. Unsubstituted, the literal
        // `{name}(` would match nothing.
        let db = database_document(
            r#"{
                "control_flow": [{
                    "name": "names_itself",
                    "category": "recursion",
                    "match_patterns": ["{name}\\("],
                    "min_lines": 5
                }]
            }"#,
        );
        let result = AlgorithmEngine::with_source(program())
            .with_pattern_database(db)
            .scan("eqmain.dll")
            .await
            .expect("scan");

        let claims: Vec<&str> = result
            .hints
            .iter()
            .map(|hint| hint.algorithm.as_str())
            .collect();
        assert_eq!(
            claims,
            ["names_itself", "names_itself", "names_itself"],
            "one hint per function, each from the substituted placeholder"
        );
    }

    #[tokio::test]
    async fn a_per_entry_confidence_in_the_database_outweighs_a_built_in_claim() {
        // The acceptance criterion in its literal shape: a file entry
        // at 90 outweighs a built-in entry at the standard 60. The
        // database carries the crc control flow shape at a per-entry
        // 90, and the built-in string set is configured back in on top
        // of the swap, so the same algorithm is claimed from both sides
        // on the CRC loop — resolution keeps the file's stronger
        // reading, standing where crc first appeared in scan order.
        let db = database_document(
            r#"{
                "control_flow": [{
                    "name": "crc",
                    "category": "checksum",
                    "match_patterns": ["crc_table\\["],
                    "min_lines": 5,
                    "confidence": 90
                }]
            }"#,
        );
        let result = AlgorithmEngine::with_source(program())
            .with_pattern_database(db)
            .with_string_engine(StringHintEngine::with_default_signatures())
            .scan("eqmain.dll")
            .await
            .expect("scan");

        let claims: Vec<(DetectionMethod, u8)> = result
            .for_function("FUN_18003e750")
            .filter(|hint| hint.algorithm == "crc")
            .map(|hint| (hint.method, hint.confidence.value()))
            .collect();
        assert_eq!(
            claims,
            [(DetectionMethod::CfgPattern, 90)],
            "the built-in body claim at 60 and the file claim at 90 merge into one, at 90"
        );
    }

    #[tokio::test]
    async fn a_correlation_section_teaches_the_scan_a_relationship_only_the_file_carries() {
        // The fourth section in action: a custom host `my_sort` handing
        // the scan's comparator its callback is a relationship no
        // built-in relationship names — the default scan sees nothing —
        // while a file naming the host and the partner's comparison
        // shape claims the sort at the standard correlation score,
        // evidenced by the line naming the partner.
        let plain = scan(custom_host_program()).await;
        assert!(plain.is_empty(), "no built-in relationship names this host");

        let db = database_document(
            r#"{
                "correlation_patterns": [{
                    "name": "library_sort",
                    "category": "sorting",
                    "body_patterns": ["\\bmy_sort\\s*\\("],
                    "partner_patterns": ["[*&][^;]*[^-](?:[<>]|==|!=)[^;]*[*&]"],
                    "min_lines": 4
                }]
            }"#,
        );
        let result = AlgorithmEngine::with_source(custom_host_program())
            .with_pattern_database(db)
            .scan("eqmain.dll")
            .await
            .expect("scan");

        let hint = finding(&result, "FUN_180050200", DetectionMethod::CrossFunction);
        assert_eq!(hint.algorithm, "library_sort");
        assert_eq!(hint.category, AlgorithmCategory::Sorting);
        assert_eq!(hint.confidence.value(), 70);
        assert_eq!(hint.evidence, "my_sort(param_1,param_2,4,FUN_1800412a0);");
    }

    #[tokio::test]
    async fn a_correlation_section_replaces_the_built_in_relationships_whole() {
        // The section swaps the relationship set whole, like every
        // other section: the file names the qsort/comparator shape under
        // a new name, and the built-in set it replaces carries neither
        // `comparison_sort` nor `divide_and_conquer` — the recursive
        // split the built-ins claimed goes unclaimed, and the sort
        // stands under the file's name alone.
        let db = database_document(
            r#"{
                "correlation_patterns": [{
                    "name": "library_sort",
                    "category": "sorting",
                    "body_patterns": ["\\bqsort\\s*\\("],
                    "partner_patterns": ["[*&][^;]*[^-](?:[<>]|==|!=)[^;]*[*&]"],
                    "min_lines": 4
                }]
            }"#,
        );
        let result = AlgorithmEngine::with_source(correlated_program())
            .with_pattern_database(db)
            .scan("eqmain.dll")
            .await
            .expect("scan");

        let claims: Vec<(&str, &str)> = result
            .hints
            .iter()
            .map(|hint| (hint.function.as_str(), hint.algorithm.as_str()))
            .collect();
        assert_eq!(
            claims,
            [("FUN_180050100", "library_sort")],
            "the file's set is the whole set — no built-in claim survives beside it"
        );
    }
}
