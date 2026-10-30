//! Type inference orchestration.
//!
//! [`TypeInferEngine`] runs the scan over one loaded program. The scan
//! runs the inline detectors — this-pointer detection,
//! parameter-size detection, known-type propagation, the
//! name-borne readings of the mangling detector, the direction readings
//! of the parameter-direction detector, and the convention
//! readings of the convention detector — over every function of
//! one loaded program. It reads each listed function's machine listing
//! once, with the listing-borne convention detectors — the 32-bit
//! stack discipline and the Microsoft-x64 shape. It then runs the post-inline
//! passes over the same bodies: the assignment-chain pass types each
//! function's locals from its surviving parameter readings and known
//! contracts; the cross-function passes propagate readings across function
//! boundaries in both directions; the return-usage pass types each
//! function's return from how its callers use the value; and the
//! convention corroborator raises the evidence confidence of readings the
//! rest of the program's listings corroborate and records call-site views
//! of each detected callee in its callers. All of it runs over exactly the
//! kept bodies and listings, with no extra reads. Everything assembles
//! into one [`TypeInferenceResult`] with its scan provenance.
//!
//! The inline detectors are pure text analysis over one decompiled body.
//! So the scan fetches each function's pseudo-C exactly once and reads
//! it with all of them, rather than having each detector pull its own
//! copy. The cross-function passes re-read those same bodies, fetching a
//! caller outside the listing at most once, which keeps the scan at one
//! decompile per function. The listing-borne convention readings
//! use the same window: the scan takes exactly one disassembly read
//! per listed function, beside the body it pairs with, and none for a
//! function the listing never shows. The inline pass is one
//! sequential pass over the function listing. There are no disjoint
//! endpoint sets to overlap the way the type-database scans have, and
//! keeping the pass sequential keeps the persisted inference list in a
//! stable, diffable order.

use std::collections::HashMap;

use crate::confidence::resolve_conflicts;
use crate::convention::ConventionDetector;
use crate::corroboration::ConventionCorroborator;
use crate::cross_function::{CalleeParams, CrossFunctionPropagator};
use crate::error::Result;
use crate::known_type::KnownTypePropagationEngine;
use crate::local_chain::LocalChainDetector;
use crate::mangling::ManglingDetector;
use crate::param_direction::ParamDirectionDetector;
use crate::param_size::ParameterSizeDetector;
use crate::return_usage::{LocalReadings, ReturnUsageDetector};
use crate::stack_discipline::StackDisciplineDetector;
use crate::this_ptr::ThisPointerDetector;
use crate::types::{InferredType, ScanMetadata, TypeInferenceResult};
use calxgloss_decomp::DecompiledFunction;
use calxgloss_kuna::KunaSource;
use calxgloss_types::{CoverageStatus, FacetCoverage, ScanCoverage};
use std::time::Instant;
use tracing::{info, warn};

/// The decompiler reads a type-inference scan performs.
///
/// This is the shared trait from the decompiler seam crate, re-exported
/// here so `TypeInferEngine`'s generic parameter names it where it
/// always has. [`KunaSource`] implements it over the in-process
/// analysis engine at the seam, and tests implement it over canned
/// bodies so the orchestration runs without a server. The futures are
/// `Send` so a scan can be driven from an orchestrating task.
pub use calxgloss_decomp::ScanSource;

/// How many unreadable regions one coverage limitation line names inline
/// before it counts the rest — bounded prose beside the counts,
/// not a dump (the P19-7 admitted-semantics track).
const MAX_NAMED_UNREACHED: usize = 5;

/// The facets a type-inference scan declares, in order — the roster
/// the record must name exactly once each: the decompiled bodies,
/// the machine listings beside them, the import names the `@N`
/// reading runs over, and the caller edges the propagated passes
/// share.
pub const DECLARED_FACETS: &[&str] = &[
    "function-bodies",
    "machine-listings",
    "import-names",
    "caller-edges",
];

/// The coverage record every type-inference scan stamps about itself
/// (issue #351), beside the provenance and the timing.
///
/// The type-inference scan reads four facets.
///
/// `function-bodies` — the decompiled bodies the inline detectors read.
/// The function listing is always read end to end: a failed listing
/// aborts the run, and more than half failing to decompile trips the
/// skip-rate breaker. So on a finished scan, the only bodies it can not
/// have read are the ones it skipped: a nameless listing entry, or a
/// decompile that failed.
///
/// `machine-listings` — the machine listing beside each listed
/// function, the source of the stack-discipline convention readings.
/// A failed read costs only that function's listing-borne readings,
/// so it is admitted by name.
///
/// `import-names` — the import listing the `@N` convention reading
/// runs over. A failed listing costs only those readings, so the facet
/// is then `unavailable` with its reason rather than silently empty.
///
/// `caller-edges` — the call-graph lookups the caller→callee and
/// return-usage passes share. A failed lookup drops both passes for
/// that function, and is admitted by name.
///
/// The cross-function passes read the bodies and listings the walk
/// already kept, so they add no coverage border of their own.
///
/// With nothing skipped and every read answered, all four facets are
/// `complete`, and that is the admission's point: a function no record
/// mentions was examined and clean, never silently unchecked. With any
/// shortfall, the facet falls short and its limitation line names the
/// regions (bounded at [`MAX_NAMED_UNREACHED`]), so silence and
/// never-reaching are distinguishable in the filed record itself. The
/// whole picture mirrors the four facets together.
fn coverage_stamp(
    unreached: &[String],
    nameless: usize,
    listings_unreadable: &[String],
    imports_unreadable: bool,
    callers_unreadable: &[String],
) -> ScanCoverage {
    let bodies = {
        let total = unreached.len() + nameless;
        if total == 0 {
            FacetCoverage {
                id: "function-bodies".to_string(),
                status: CoverageStatus::Complete,
                limitation: None,
            }
        } else {
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
            FacetCoverage {
                id: "function-bodies".to_string(),
                status: CoverageStatus::Partial,
                limitation: Some(format!(
                    "{total} function {body} unreached: {}",
                    names.join(", ")
                )),
            }
        }
    };
    let listings = if listings_unreadable.is_empty() {
        FacetCoverage {
            id: "machine-listings".to_string(),
            status: CoverageStatus::Complete,
            limitation: None,
        }
    } else {
        let total = listings_unreadable.len();
        let mut names = listings_unreadable
            .iter()
            .take(MAX_NAMED_UNREACHED)
            .cloned()
            .collect::<Vec<_>>();
        let hidden = total.saturating_sub(names.len());
        if hidden > 0 {
            names.push(format!("+{hidden} more"));
        }
        let listing = if total == 1 { "listing" } else { "listings" };
        FacetCoverage {
            id: "machine-listings".to_string(),
            status: CoverageStatus::Partial,
            limitation: Some(format!(
                "{total} machine {listing} unreadable: {}",
                names.join(", ")
            )),
        }
    };
    let imports = if imports_unreadable {
        FacetCoverage {
            id: "import-names".to_string(),
            status: CoverageStatus::Unavailable,
            limitation: Some("import listing unreadable".to_string()),
        }
    } else {
        FacetCoverage {
            id: "import-names".to_string(),
            status: CoverageStatus::Complete,
            limitation: None,
        }
    };
    let edges = if callers_unreadable.is_empty() {
        FacetCoverage {
            id: "caller-edges".to_string(),
            status: CoverageStatus::Complete,
            limitation: None,
        }
    } else {
        let total = callers_unreadable.len();
        let mut names = callers_unreadable
            .iter()
            .take(MAX_NAMED_UNREACHED)
            .cloned()
            .collect::<Vec<_>>();
        let hidden = total.saturating_sub(names.len());
        if hidden > 0 {
            names.push(format!("+{hidden} more"));
        }
        let edge = if total == 1 { "edge" } else { "edges" };
        FacetCoverage {
            id: "caller-edges".to_string(),
            status: CoverageStatus::Partial,
            limitation: Some(format!(
                "{total} caller {edge} unreadable: {}",
                names.join(", ")
            )),
        }
    };
    let status = if bodies.status == CoverageStatus::Complete
        && listings.status == CoverageStatus::Complete
        && imports.status == CoverageStatus::Complete
        && edges.status == CoverageStatus::Complete
    {
        CoverageStatus::Complete
    } else {
        CoverageStatus::Partial
    };
    ScanCoverage {
        status,
        facets: vec![bodies, listings, imports, edges],
    }
}

/// Orchestrates the inline detectors and the cross-function pass into one
/// [`TypeInferenceResult`].
///
/// `TypeInferEngine` is generic over its [`ScanSource`], so tests can run
/// the whole orchestration over canned bodies; [`new`](Self::new) builds
/// one over a loaded [`KunaSource`]. The detectors hold no state, so one
/// instance of each serves the whole scan.
#[derive(Debug, Clone)]
pub struct TypeInferEngine<S = KunaSource> {
    source: S,
    this_ptr: ThisPointerDetector,
    param_size: ParameterSizeDetector,
    param_direction: ParamDirectionDetector,
    known: KnownTypePropagationEngine,
    local_chain: LocalChainDetector,
    cross: CrossFunctionPropagator,
    return_usage: ReturnUsageDetector,
    mangling: ManglingDetector,
    convention: ConventionDetector,
    stack_discipline: StackDisciplineDetector,
    corroborator: ConventionCorroborator,
}

impl TypeInferEngine<KunaSource> {
    /// A `TypeInferEngine` over a loaded Kuna program.
    pub fn new(source: &KunaSource) -> TypeInferEngine<KunaSource> {
        TypeInferEngine {
            source: source.clone(),
            this_ptr: ThisPointerDetector::new(),
            param_size: ParameterSizeDetector::new(),
            param_direction: ParamDirectionDetector::new(),
            known: KnownTypePropagationEngine::new(),
            local_chain: LocalChainDetector::new(),
            cross: CrossFunctionPropagator::new(),
            return_usage: ReturnUsageDetector::new(),
            mangling: ManglingDetector::new(),
            convention: ConventionDetector::new(),
            stack_discipline: StackDisciplineDetector::new(),
            corroborator: ConventionCorroborator::new(),
        }
    }
}

impl<S> TypeInferEngine<S> {
    /// A `TypeInferEngine` whose decompiles come from `source`.
    pub fn with_source(source: S) -> Self {
        TypeInferEngine {
            source,
            this_ptr: ThisPointerDetector::new(),
            param_size: ParameterSizeDetector::new(),
            param_direction: ParamDirectionDetector::new(),
            known: KnownTypePropagationEngine::new(),
            local_chain: LocalChainDetector::new(),
            cross: CrossFunctionPropagator::new(),
            return_usage: ReturnUsageDetector::new(),
            mangling: ManglingDetector::new(),
            convention: ConventionDetector::new(),
            stack_discipline: StackDisciplineDetector::new(),
            corroborator: ConventionCorroborator::new(),
        }
    }

    /// Infer types across `binary`, decompiling each function exactly
    /// once and reading it with all the inline detectors, then
    /// propagating the surviving readings across function boundaries in
    /// both directions. The scan reads each function's pseudo-C exactly
    /// once.
    ///
    /// `binary` names the program the scan reads (e.g. `eqmain.dll`) and
    /// becomes the key a persisted result is filed under. The inferences
    /// follow the function listing — function by function. Within one
    /// function the order is: the name-borne readings of its listing
    /// symbol (its mangling contract, then the convention its letter
    /// spells), then the this-pointer readings, then the size readings,
    /// then the known-signature readings, then the readings read from
    /// names inside the body, then the direction readings of its
    /// parameters (issue #274), then the convention readings off its
    /// machine listing — the 32-bit stack discipline or the
    /// Microsoft-x64 shape the listing's own register spelling keys.
    /// The import names' `@N` convention readings come after the
    /// listing. The local records and the cross-function records are
    /// appended after the inline ones, in listing order, so two scans
    /// of the same program diff cleanly. The
    /// convention corroborator (issue #249) runs last, over the resolved
    /// records and the kept listings: a corroborated reading replaces its
    /// own record in place, and the call-site records it writes into the
    /// callers append at the end, again in listing order.
    ///
    /// The caller→callee direction fetches each analyzed function's
    /// callers; a caller whose body the listing pass did not already
    /// produce is decompiled once and cached (a failed fetch is cached
    /// too), so no function's body is ever requested twice in one scan.
    /// The return-usage pass reads the same fetched caller bodies — how
    /// a caller uses the returned value types the callee's return — so
    /// one caller lookup per function serves both passes.
    ///
    /// Each listed function's machine listing is read exactly once, in
    /// listing order, inside the same breaker-gated window beside the
    /// body it pairs with; a function the listing never shows (a caller
    /// fetched by the caller→callee pass) never has its listing read.
    /// A failed or empty listing read costs only the listing-borne
    /// convention readings of that function: the read is not a decompile
    /// work item, so the skip-rate breaker's counts never move on it.
    ///
    /// A function whose body the decompiler cannot produce (a thunk, a bad entry
    /// point) is skipped with a warning; only a failure of the listing
    /// itself — the server being down — aborts the run, since then nothing
    /// was scanned.
    /// But when more than half the listing fails to decompile, the
    /// skip-rate breaker aborts the run too: that is the signature of
    /// the bridge answering from the wrong program, and skipping on
    /// would persist a phantom-clean record (issue #71).
    /// Where several detectors read one parameter differently
    /// — `strlen`'s argument stands read by the size detector and the
    /// known-signature detector at once — conflict resolution picks the
    /// strongest record before the result is assembled, so the result
    /// holds at most one inference per parameter, local, call-site
    /// argument, return, convention, or parameter direction —
    /// and since the direction target is keyed apart from the parameter
    /// one, one parameter's direction reading stands beside its type
    /// reading rather than competing with it (issue #274). The
    /// cross-function pass propagates only
    /// those resolved survivors, and its own records compete with the
    /// inline ones for the same targets in the final resolution.
    pub async fn scan(&self, binary: impl Into<String>) -> Result<TypeInferenceResult>
    where
        S: ScanSource,
    {
        let started = Instant::now();
        let functions = self.source.functions().await?;

        let mut inferences = Vec::new();
        // The bodies stay in hand after the inline pass so the
        // cross-function pass can re-read them without a second decompile.
        let mut bodies: Vec<DecompiledFunction> = Vec::new();
        // The kept machine listings, in listing order: the cross-function
        // convention corroborator (issue #249) re-reads exactly these
        // listings for callee epilogues and caller cleanup, so it costs
        // no read of its own.
        let mut listings: Vec<(String, String)> = Vec::new();
        let mut skipped = 0usize;
        let mut decompile_failures = 0usize;
        // The regions this walk never reached, named as it goes, so the
        // coverage record below can admit them (issue #351).
        let mut unreached: Vec<String> = Vec::new();
        let mut nameless = 0usize;
        let mut listings_unreadable: Vec<String> = Vec::new();
        for function in &functions {
            if function.name.is_empty() {
                // For a nameless listing entry, a name lookup could reach
                // some other function's body. Nothing can be inferred
                // about it, so the scan records nothing for it.
                warn!(
                    address = format_args!("{:#x}", function.address),
                    "Skipping function with no name"
                );
                skipped += 1;
                nameless += 1;
                continue;
            }
            // The contract in the symbol itself: an MSVC-mangled
            // listing name decodes without any body, so the reading
            // stands even when the decompile below fails.
            inferences.extend(self.mangling.detect_from_listing(&function.name));
            // The convention the same symbol's letter spells, keyed by
            // the same name: for a mangled member it is recorded beside
            // the implicit `this` parameter record the mangling reading
            // just pushed; the pair says the function is a method.
            if let Some(reading) = self.convention.from_listing_name(&function.name) {
                inferences.push(reading);
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
                    // program the analysis engine cannot analyze, and
                    // an empty result would persist as a phantom-clean
                    // record. The scan aborts with the counts instead
                    // of skipping on.
                    if decompile_failures * 2 > functions.len() {
                        return Err(crate::TypeInferError::DecompileBreaker {
                            failed: decompile_failures,
                            total: functions.len(),
                        });
                    }
                    continue;
                }
            };

            let readings = self
                .this_ptr
                .detect_this_pointer(&decompiled)
                .into_iter()
                .chain(self.param_size.detect_parameter_sizes(&decompiled))
                .chain(self.known.propagate_known_types(&decompiled));
            inferences.extend(readings.map(InferredType::Param));
            // The contract in names inside the body: the
            // function's own demangled name with a spelled parameter
            // list, and qualified calls whose callee spells one.
            inferences.extend(self.mangling.detect_from_body(&decompiled));
            // Which way the body's writes and reads move data through
            // the function's own pointer parameters (issue #274): read
            // off the body already in hand, with no extra read from
            // the analysis engine. The records join the same inline
            // set and resolve in the same pass as the type readings,
            // but key on a target of their own, so a direction reading
            // stands beside the type reading for one parameter
            // instead of competing with it.
            inferences.extend(
                self.param_direction
                    .detect_directions(&decompiled)
                    .into_iter()
                    .map(InferredType::Direction),
            );
            bodies.push(decompiled);

            // The machine listing beside the body: one disassembly read
            // per listed function, in listing order, inside the same
            // breaker-gated window. Its listing-borne convention
            // readings — the 32-bit stack discipline (a callee epilogue
            // that pops its own arguments, a caller that pops after a
            // call site naming its callee) and the Microsoft-x64 shape
            // (shadow-space prologue, register arguments, no cleanup) —
            // key on the stack register the listing itself spells
            // (issues #247, #248). A failed or empty read costs only
            // these readings: the read is not a decompile work item, so
            // the skip-rate breaker's counts never move on it.
            match self.source.disassembly(&function.name).await {
                Ok(listing) => {
                    inferences.extend(self.stack_discipline.from_listing(&function.name, &listing));
                    listings.push((function.name.clone(), listing));
                }
                Err(error) => {
                    warn!(
                        function = %function.name,
                        error = %error,
                        "Skipping listing-borne convention readings: disassembly read failed"
                    );
                    listings_unreadable.push(function.name.clone());
                }
            }
        }

        // The convention an import name's `@N` decoration spells. Import
        // names are not in the function listing, so this read runs after
        // the loop; the readings join the inline set and compete in the
        // same resolution. A failure to list imports costs only these
        // readings — the scan keeps whatever the names already showed,
        // and the coverage record admits the listing as unreadable
        // (issue #351).
        let mut imports_unreadable = false;
        match self.source.imports().await {
            Ok(imports) => {
                for import in &imports {
                    if let Some(reading) = self.convention.from_import_name(&import.name) {
                        inferences.push(reading);
                    }
                }
            }
            Err(error) => {
                warn!(
                    error = %error,
                    "Skipping @N convention readings: import listing failed"
                );
                imports_unreadable = true;
            }
        }

        // The detectors read each body independently, so one parameter can
        // stand read several times over; the cross-function pass only
        // propagates the strongest reading per parameter, so the inline
        // records resolve among themselves first.
        let mut collected = inferences.len();
        let inline = resolve_conflicts(inferences);
        let callee_params = surviving_param_readings(&inline);

        // Locals from assignment chains: a slot assigned one of those
        // surviving parameters, a known routine's result, or an
        // already-typed local takes that type. The pass reads the same
        // bodies and their surviving readings, so it runs right after
        // inline resolution — before the cross-function passes, whose
        // records compete with everything else in the final resolution.
        let mut locals: Vec<InferredType> = Vec::new();
        for body in &bodies {
            let readings = callee_params
                .get(body.name.as_str())
                .map(Vec::as_slice)
                .unwrap_or_default();
            locals.extend(
                self.local_chain
                    .detect_locals(body, readings)
                    .into_iter()
                    .map(InferredType::Local),
            );
        }

        // The surviving local readings, by function and name: the types
        // a caller's `local_8 = FUN_x();` can pass back to the callee as
        // its return type. First-seen per name, matching what the final
        // resolution will keep for an equal evidence-confidence tie.
        let mut local_types: LocalReadings = HashMap::new();
        for inference in &locals {
            if let InferredType::Local(record) = inference {
                local_types
                    .entry(record.function.as_str())
                    .or_default()
                    .entry(record.variable_name.as_str())
                    .or_insert(record.inferred_type.as_str());
            }
        }

        // Callee to caller: each body's calls to a user-defined callee
        // take that callee's surviving readings as the arguments' types,
        // and a caller's own parameter is read when the argument names
        // one. The bodies are the ones already decompiled — the scan
        // still visits each function exactly once.
        let mut propagated: Vec<InferredType> = Vec::new();
        for body in &bodies {
            propagated.extend(self.cross.propagate(body, &callee_params));
        }

        // Caller to callee: what each function's callers actually hand
        // in at their call sites types that function's own parameters.
        // Where the caller is in the listing, its body is already in
        // hand; any other caller is fetched once and kept in the cache,
        // failures included. So the scan never decompiles one
        // function's body twice.
        let inline_bodies: HashMap<&str, &DecompiledFunction> = bodies
            .iter()
            .map(|body| (body.name.as_str(), body))
            .collect();
        let mut fetched: HashMap<String, Option<DecompiledFunction>> = HashMap::new();
        let mut to_callee: Vec<InferredType> = Vec::new();
        let mut to_return: Vec<InferredType> = Vec::new();
        // Functions whose caller lookup was attempted and never answered
        // — the caller-edges facet admits them by name (issue #351).
        let mut callers_unreadable: Vec<String> = Vec::new();
        for function in &functions {
            if function.name.is_empty() {
                continue;
            }
            let Some(callee) = inline_bodies.get(function.name.as_str()) else {
                continue; // never decompiled — there is no body to type
            };
            let callers = match self.source.callers(function.address).await {
                Ok(callers) => callers,
                Err(error) => {
                    warn!(
                        function = %function.name,
                        error = %error,
                        "Skipping caller-to-callee pass: caller lookup failed"
                    );
                    callers_unreadable.push(function.name.clone());
                    continue;
                }
            };
            // Fetch what the listing pass did not already produce, once
            // each — a failed fetch is cached too, so a caller that will
            // not decompile is never asked for twice.
            for caller in &callers {
                if inline_bodies.contains_key(caller.as_str())
                    || fetched.contains_key(caller.as_str())
                {
                    continue;
                }
                let body = self.source.decompile(caller).await.ok();
                if body.is_none() {
                    warn!(function = %caller, "Skipping caller: decompile failed");
                }
                fetched.insert(caller.clone(), body);
            }
            let mut caller_bodies: Vec<&DecompiledFunction> = Vec::new();
            for caller in &callers {
                let body = inline_bodies
                    .get(caller.as_str())
                    .copied()
                    .or_else(|| fetched.get(caller.as_str()).and_then(|body| body.as_ref()));
                if let Some(body) = body {
                    caller_bodies.push(body);
                }
            }
            if !caller_bodies.is_empty() {
                to_callee.extend(self.cross.propagate_to_callee(
                    callee,
                    &caller_bodies,
                    &callee_params,
                ));
                // The same caller bodies answer the return question: how
                // each caller *uses* the value the callee hands back
                // types the callee's return. No extra fetch — the two
                // passes share one caller lookup per function.
                to_return.extend(self.return_usage.infer_returns(
                    callee,
                    &caller_bodies,
                    &local_types,
                ));
            }
        }

        // The propagated records compete with the inline ones — one
        // parameter can stand read by its own body and by a callee's
        // contract or its callers' arguments at once — so the assembled
        // list resolves once more, and the result holds at most one
        // inference per target. The inline chain is first, so an inline
        // reading wins every tie against a propagated one.
        collected += locals.len() + propagated.len() + to_callee.len() + to_return.len();
        let resolved = resolve_conflicts(
            inline
                .into_iter()
                .chain(locals)
                .chain(propagated)
                .chain(to_callee)
                .chain(to_return)
                .collect(),
        );

        // Cross-function convention corroboration (issue #249): a resolved
        // convention reading that the rest of the program's listings
        // corroborate — a `@N`-decorated function whose epilogue really
        // pops the `N` bytes its name declares, with no caller cleaning
        // up after any site — stands higher than it did alone, and every
        // caller whose listing holds a call site to a detected callee
        // receives a call-site record of that callee's convention. The
        // pass reads only the listings the scan already took and the
        // records already resolved: no extra decompiles, no second
        // listing read. Its output competes once more in the same
        // resolution: a corroborated reading outscores the single reading
        // it agrees with and replaces it where that record first
        // appeared, so a function keeps exactly one convention record;
        // the call-site records key on the (caller, callee) pair no
        // inline reading spells and come after the resolved records, in
        // listing order.
        let kept: Vec<(&str, &str)> = listings
            .iter()
            .map(|(name, text)| (name.as_str(), text.as_str()))
            .collect();
        let corroborated = self.corroborator.corroborate(&resolved, &kept);
        collected += corroborated.len();
        let inferences = resolve_conflicts(resolved.into_iter().chain(corroborated).collect());
        let conflicts_resolved = collected - inferences.len();

        let mut metadata = ScanMetadata::new(binary);
        // The scan records its own coverage where the skips and the
        // unreadable reads happened, so the filed record says what the
        // scan never reached (issue #351) — and a complete record lets
        // an unmentioned function read as examined and clean.
        metadata.coverage = Some(coverage_stamp(
            &unreached,
            nameless,
            &listings_unreadable,
            imports_unreadable,
            &callers_unreadable,
        ));
        // The source records the analysis engine's name and pin under
        // `kuna` (issue #208).
        metadata.engine = self.source.engine_provenance();
        metadata.duration_secs = started.elapsed().as_secs();
        info!(
            binary = %metadata.binary,
            functions = functions.len(),
            inferences = inferences.len(),
            conflicts_resolved,
            skipped,
            duration_secs = metadata.duration_secs,
            "Inferred types"
        );
        Ok(TypeInferenceResult {
            metadata,
            inferences,
        })
    }
}

/// The surviving parameter readings grouped by the function holding
/// them — the contracts the cross-function pass propagates. A callee
/// absent from the map is a library routine, a thunk, or a function no
/// detector read: it has nothing to propagate.
fn surviving_param_readings(inferences: &[InferredType]) -> CalleeParams<'_> {
    let mut by_callee: CalleeParams<'_> = HashMap::new();
    for inference in inferences {
        if let InferredType::Param(record) = inference {
            by_callee
                .entry(record.function.as_str())
                .or_default()
                .push(record);
        }
    }
    by_callee
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests;
