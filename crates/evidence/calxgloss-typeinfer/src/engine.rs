//! Type inference orchestration.
//!
//! [`TypeInferEngine`] runs the inline detectors — this-pointer
//! detection, parameter-size detection, known-type propagation, the
//! name-borne readings of the mangling detector, the direction readings
//! of the parameter-direction detector, and the convention
//! readings of the convention detector — over every function of
//! one loaded program, reads each listed function's machine listing
//! once with the listing-borne convention detectors — the 32-bit
//! stack discipline and the Microsoft-x64 shape — then runs the post-inline
//! passes over the same bodies: the assignment-chain pass types each
//! function's locals from its surviving parameter readings and known
//! contracts, the cross-function passes carry readings across function
//! boundaries in both directions, the return-usage pass types each
//! function's return from how its callers use the value, and the
//! convention corroborator raises readings the rest of the program's
//! listings corroborate and lands call-site views of each detected
//! callee in its callers — over exactly the kept bodies and listings,
//! no extra reads — and everything assembles into one
//! [`TypeInferenceResult`] with its scan provenance.
//!
//! The inline detectors are pure text analysis over one decompiled body,
//! so the engine fetches each function's pseudo-C exactly once and reads
//! it with all of them, rather than having each detector pull its own copy
//! — and the cross-function passes re-read those same bodies, fetching a
//! caller outside the listing at most once, keeping the scan at one
//! decompile per function. The listing-borne convention readings
//! ride the same window: the engine takes exactly one disassembly read
//! per listed function, beside the body it pairs with, and none for a
//! function the listing never shows. The inline pass is then one
//! sequential pass over the function listing: there are no disjoint
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
use std::time::Instant;
use tracing::{info, warn};

/// The decompiler reads a type-inference scan performs.
///
/// The shared trait from the decompiler seam crate, re-exported here
/// so the engine's generic shape names it where it always has;
/// [`KunaSource`] implements it over the in-process engine, and tests
/// implement it over canned bodies so the orchestration runs without a
/// server. The futures are `Send` so a scan can be driven from an
/// orchestrating task.
pub use calxgloss_decomp::ScanSource;

/// Orchestrates the inline detectors and the cross-function pass into one
/// [`TypeInferenceResult`].
///
/// The engine is generic over its [`ScanSource`], so tests can run the
/// whole orchestration over canned bodies; [`new`](Self::new) builds one over
/// a loaded [`KunaSource`]. The detectors carry no state, so one instance of
/// each serves the whole scan.
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
    /// An engine over a loaded Kuna program.
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
    /// An engine whose decompiles come from `source`.
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
    /// both directions.
    ///
    /// `binary` names the program the scan reads (e.g. `eqmain.dll`) and
    /// becomes the key a persisted result is filed under. The inferences
    /// follow the function listing — function by function, and within one
    /// function the name-borne readings of its listing symbol (its
    /// mangling contract, then the convention its letter spells), then
    /// the this-pointer readings, then the size readings, then
    /// the known-signature readings, then the readings carried in names
    /// inside the body, then the direction readings of its parameters
    /// (issue #274), then the convention readings off its machine
    /// listing — the 32-bit stack discipline or the Microsoft-x64 shape
    /// the listing's own register spelling keys — with the import
    /// names' `@N` convention readings
    /// after the listing, and the local records and the
    /// cross-function records appended after the inline ones, in listing
    /// order, so two scans of the same program diff cleanly. The
    /// convention corroborator (issue #249) runs last, over the resolved
    /// records and the kept listings: a corroborated reading replaces its
    /// own record in place, and the call-site records it lands in the
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
    /// known-signature engine at once — conflict resolution collapses the
    /// competition to the strongest record before the result is assembled,
    /// so the result carries at most one inference per parameter, local,
    /// call-site argument, return, convention, or parameter direction —
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
        // bodies for callee epilogues and caller cleanup, so it costs no
        // read of its own.
        let mut listings: Vec<(String, String)> = Vec::new();
        let mut skipped = 0usize;
        let mut decompile_failures = 0usize;
        for function in &functions {
            if function.name.is_empty() {
                // A nameless listing entry would send the name lookup
                // wandering into some other function's body; nothing can
                // be inferred about it, so it passes unrecorded.
                warn!(
                    address = format_args!("{:#x}", function.address),
                    "Skipping function with no name"
                );
                skipped += 1;
                continue;
            }
            // The contract carried in the symbol itself: an MSVC-mangled
            // listing name decodes without any body, so the reading
            // stands even when the decompile below fails.
            inferences.extend(self.mangling.detect_from_listing(&function.name));
            // The convention the same symbol's letter spells, keyed by
            // the same name: for a mangled member it lands beside the
            // implicit `this` parameter record the mangling reading just
            // pushed, together saying the function is a method.
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
                    // Skip-rate breaker: once most of the listing has
                    // failed to decompile, the scan is reading a
                    // program the engine cannot analyze, and an
                    // empty result would persist as a phantom-clean
                    // record. Abort with the counts instead of
                    // skipping on.
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
            // The contract carried in names inside the body: the
            // function's own demangled name with a spelled parameter
            // list, and qualified calls whose callee spells one.
            inferences.extend(self.mangling.detect_from_body(&decompiled));
            // Which way the body's writes and reads move data through
            // the function's own pointer parameters (issue #274): read
            // off the body already in hand, no extra engine read. The
            // records join the same inline set and resolve in the same
            // pass as the type readings, but key on a target of their
            // own, so a direction reading stands beside the type
            // reading for one parameter instead of competing with it.
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
                }
            }
        }

        // The convention an import name's `@N` decoration spells. Import
        // names are not in the function listing, so this read runs after
        // the loop; the readings join the inline set and compete in the
        // same resolution. A failure to list imports costs only these
        // readings — the scan keeps whatever the names already showed.
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
        // a caller's `local_8 = FUN_x();` can lend back to the callee as
        // its return type. First-seen per name, matching what the final
        // resolution will keep for an equal-confidence tie.
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
        // in at their sites types that function's own parameters. The
        // caller bodies are the ones already in hand wherever the caller
        // is in the listing; any other caller is fetched once and kept
        // in the cache — failures included — so no function's body is
        // decompiled twice across the whole scan.
        let inline_bodies: HashMap<&str, &DecompiledFunction> = bodies
            .iter()
            .map(|body| (body.name.as_str(), body))
            .collect();
        let mut fetched: HashMap<String, Option<DecompiledFunction>> = HashMap::new();
        let mut to_callee: Vec<InferredType> = Vec::new();
        let mut to_return: Vec<InferredType> = Vec::new();
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
        // list resolves once more, and the result carries at most one
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
        // carries a call-site record of that callee's convention. The
        // pass reads only the listings the scan already took and the
        // records already resolved: no extra decompiles, no second
        // listing read. Its output competes once more in the same
        // resolution: a corroborated reading outscores the single reading
        // it agrees with and replaces it where that record first
        // appeared, so a function keeps exactly one convention record;
        // the call-site records key on the (caller, callee) pair no
        // inline reading spells and land after the resolved records, in
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
        // The source names its engine and pin under `kuna` (issue #208).
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

/// The surviving parameter readings grouped by the function carrying
/// them — the contracts the cross-function pass propagates. A callee
/// absent from the map is a library routine, a thunk, or a function no
/// detector read: it carries nothing to propagate.
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
mod tests {
    use super::*;
    use crate::types::{
        CallingConvention, Confidence, InferenceMethod, InferenceScope, InferredCallType,
        InferredConvention, InferredLocalType,
    };
    use calxgloss_decomp::{
        DataItem, DataTypeEntry, DecompiledFunction, EngineError, EnumDefinition, FunctionSummary,
        Result, StringLiteral, StructLayout, Symbol, Xref,
    };
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    fn summary(name: &str) -> FunctionSummary {
        FunctionSummary {
            name: name.to_string(),
            address: addr(name),
        }
    }

    /// A deterministic per-name address, so a test's caller map can name
    /// one function without every summary sharing a single address.
    fn addr(name: &str) -> u64 {
        0x1800_0000
            + name.bytes().fold(0u64, |hash, byte| {
                hash.wrapping_mul(31).wrapping_add(byte as u64)
            })
    }

    fn function(name: &str, signature: &str, body: &str) -> DecompiledFunction {
        DecompiledFunction {
            name: name.to_string(),
            signature: signature.to_string(),
            body: format!("\n{signature}\n\n{{\n{body}}}\n"),
        }
    }

    /// State shared by every clone of a [`FakeProgram`], so a test can read
    /// what the scan did after the engine has consumed its source.
    #[derive(Debug, Default)]
    struct Stats {
        decompiles: Mutex<Vec<String>>,
        disassemblies: Mutex<Vec<String>>,
    }

    /// A canned program implementing [`ScanSource`], so the whole
    /// orchestration runs without a server.
    #[derive(Clone)]
    struct FakeProgram {
        listing: Vec<FunctionSummary>,
        bodies: HashMap<String, DecompiledFunction>,
        /// Which functions call which, keyed by the callee's address —
        /// what the caller→callee pass reads.
        callers: HashMap<u64, Vec<String>>,
        /// The import names the program answers with — what the `@N`
        /// convention reading runs over.
        imports: Vec<Symbol>,
        /// The canned SLEIGH-style disassembly text per function — what
        /// the stack-discipline detector reads (issue #247). A listed
        /// function absent from the map answers with an empty listing.
        listings: HashMap<String, String>,
        fail_decompiles: Vec<String>,
        fail_disassembly: Vec<String>,
        fail_listing: bool,
        stats: Arc<Stats>,
    }

    impl FakeProgram {
        fn empty() -> Self {
            Self {
                listing: Vec::new(),
                bodies: HashMap::new(),
                callers: HashMap::new(),
                imports: Vec::new(),
                listings: HashMap::new(),
                fail_decompiles: Vec::new(),
                fail_disassembly: Vec::new(),
                fail_listing: false,
                stats: Arc::new(Stats::default()),
            }
        }

        fn decompiled(&self) -> Vec<String> {
            self.stats.decompiles.lock().unwrap().clone()
        }

        fn disassembled(&self) -> Vec<String> {
            self.stats.disassemblies.lock().unwrap().clone()
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

        async fn disassembly(&self, name: &str) -> Result<String> {
            self.stats
                .disassemblies
                .lock()
                .unwrap()
                .push(name.to_string());
            if self.fail_disassembly.iter().any(|f| f == name) {
                return Err(EngineError::Reported {
                    message: format!("the engine cannot disassemble {name}"),
                });
            }
            Ok(self.listings.get(name).cloned().unwrap_or_default())
        }

        // The rest of the shared trait's reads: this engine never makes
        // them, so they answer with empty or not-found data.
        async fn strings(&self) -> Result<Vec<StringLiteral>> {
            Ok(Vec::new())
        }

        async fn callers(&self, address: u64) -> Result<Vec<String>> {
            Ok(self.callers.get(&address).cloned().unwrap_or_default())
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
            Ok(self.imports.clone())
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

    /// The canned program: one function whose body carries a vtable
    /// dispatch, a `strlen` call, and a `CloseHandle` call — one reading
    /// family per detector — and one plain function that infers nothing.
    fn program() -> FakeProgram {
        let mut program = FakeProgram::empty();
        program.listing = vec![summary("FUN_18003ab00"), summary("FUN_18003e750")];
        program.bodies.insert(
            "FUN_18003ab00".into(),
            function(
                "FUN_18003ab00",
                "undefined FUN_18003ab00(undefined8 param_1,undefined8 param_2,undefined8 param_3)",
                "  (**(code **)*param_1)(param_1);\n\
                 \x20 strlen(param_2);\n\
                 \x20 CloseHandle(param_3);\n",
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

    async fn scan(program: FakeProgram) -> TypeInferenceResult {
        TypeInferEngine::with_source(program)
            .scan("eqmain.dll")
            .await
            .expect("scan")
    }

    fn finding<'a>(
        result: &'a TypeInferenceResult,
        function: &str,
        method: InferenceMethod,
        param_index: usize,
    ) -> &'a InferredType {
        result
            .for_function(function)
            .find(|inference| match inference {
                InferredType::Param(record) => {
                    record.method == method && record.param_index == param_index
                }
                _ => false,
            })
            .expect("record from that detector")
    }

    fn param_count(result: &TypeInferenceResult, function: &str, param_index: usize) -> usize {
        result
            .for_function(function)
            .filter(|inference| {
                matches!(
                    inference,
                    InferredType::Param(record) if record.param_index == param_index
                )
            })
            .count()
    }

    #[tokio::test]
    async fn scan_collects_records_from_all_three_detectors() {
        let result = scan(program()).await;

        assert_eq!(result.metadata.binary, "eqmain.dll");
        assert!(result.metadata.scanned_at > 0);

        let this_ptr = finding(&result, "FUN_18003ab00", InferenceMethod::VtableCall, 0);
        let InferredType::Param(record) = this_ptr else {
            unreachable!("the this-pointer detector emits parameter records");
        };
        assert_eq!(record.param_index, 0);
        assert_eq!(record.param_name.as_deref(), Some("param_1"));
        assert_eq!(record.inferred_type, "void *");
        assert_eq!(record.scope, InferenceScope::Class);
        assert!(record.is_this_pointer());

        let size = finding(&result, "FUN_18003ab00", InferenceMethod::StringFunction, 1);
        let InferredType::Param(record) = size else {
            unreachable!("the size detector emits parameter records");
        };
        assert_eq!(record.param_index, 1);
        assert_eq!(record.inferred_type, "char *");

        // `strlen` is a string-function call and a known signature at once,
        // so the same parameter stands read twice, both at 70; the readings
        // tie and conflict resolution keeps the one the scan showed first —
        // the size detector's.
        assert_eq!(param_count(&result, "FUN_18003ab00", 1), 1);

        // The vtable dispatch's first argument also carries a bare
        // dereference, so the size detector reads that parameter too; the
        // stronger this-pointer reading wins the conflict.
        assert_eq!(param_count(&result, "FUN_18003ab00", 0), 1);

        let known = finding(&result, "FUN_18003ab00", InferenceMethod::KnownSignature, 2);
        let InferredType::Param(record) = known else {
            unreachable!("the propagation engine emits parameter records");
        };
        assert_eq!(record.param_index, 2);
        assert_eq!(record.inferred_type, "void *");
        assert_eq!(record.scope, InferenceScope::Program);

        assert!(result.for_function("FUN_18003e750").next().is_none());
    }

    #[tokio::test]
    async fn conflicting_readings_for_one_parameter_resolve_to_the_strongest() {
        // One parameter stands read by two detectors at different
        // strengths — `strlen`'s `char *` at 70 and `CloseHandle`'s
        // `void *` at 75 — and only the stronger survives the scan.
        let mut program = FakeProgram::empty();
        program.listing = vec![summary("FUN_1800412a0")];
        program.bodies.insert(
            "FUN_1800412a0".into(),
            function(
                "FUN_1800412a0",
                "undefined FUN_1800412a0(undefined8 param_1)",
                "  strlen(param_1);\n  CloseHandle(param_1);\n",
            ),
        );
        let result = scan(program).await;

        // The direction reading keys on a target of its own, so it stands
        // beside the surviving type record; among the type readings for
        // one parameter, only the stronger survives.
        let records: Vec<&InferredType> = result.for_function("FUN_1800412a0").collect();
        assert_eq!(
            records.len(),
            2,
            "one type reading and one direction reading"
        );
        let InferredType::Param(record) = records[0] else {
            unreachable!("the inline type records lead each function's block");
        };
        assert_eq!(record.method, InferenceMethod::KnownSignature);
        assert_eq!(record.inferred_type, "void *");
        assert_eq!(record.confidence, Confidence::new(75));
    }

    /// The canned program for the assignment-chain pass: one function
    /// whose `param_2` the inline detectors read as `char *`, and whose
    /// locals are assigned that parameter, a `malloc` result, and one
    /// hop from a typed local.
    fn locals_program() -> FakeProgram {
        let mut program = FakeProgram::empty();
        program.listing = vec![summary("FUN_18003ab00")];
        program.bodies.insert(
            "FUN_18003ab00".into(),
            function(
                "FUN_18003ab00",
                "undefined FUN_18003ab00(undefined8 param_1,undefined8 param_2)",
                "  strlen(param_2);\n\
                 \x20 local_8 = param_2;\n\
                 \x20 local_10 = (char *)malloc(0x10);\n\
                 \x20 local_18 = local_10;\n",
            ),
        );
        program
    }

    fn local_finding<'a>(
        result: &'a TypeInferenceResult,
        function: &str,
        variable_name: &str,
    ) -> &'a InferredLocalType {
        result
            .for_function(function)
            .find_map(|inference| match inference {
                InferredType::Local(record) if record.variable_name == variable_name => {
                    Some(record)
                }
                _ => None,
            })
            .expect("local record")
    }

    fn local_count(result: &TypeInferenceResult, function: &str, variable_name: &str) -> usize {
        result
            .for_function(function)
            .filter(|inference| {
                matches!(
                    inference,
                    InferredType::Local(record) if record.variable_name == variable_name
                )
            })
            .count()
    }

    #[tokio::test]
    async fn scan_emits_local_records_from_assignment_chains() {
        // A local assigned a surviving parameter reading, and one
        // assigned a known routine's result, take the assignment-chain
        // record; one hop from a typed local is chased, a second is not.
        let result = scan(locals_program()).await;

        let record = local_finding(&result, "FUN_18003ab00", "local_8");
        assert_eq!(record.inferred_type, "char *");
        assert_eq!(record.method, InferenceMethod::AssignmentChain);
        assert_eq!(record.scope, InferenceScope::Function);
        assert_eq!(record.confidence, Confidence::new(60));
        assert_eq!(record.evidence, "local_8 = param_2;");

        let record = local_finding(&result, "FUN_18003ab00", "local_10");
        assert_eq!(record.inferred_type, "void *");

        let record = local_finding(&result, "FUN_18003ab00", "local_18");
        assert_eq!(record.inferred_type, "void *");
        assert_eq!(local_count(&result, "FUN_18003ab00", "local_18"), 1);

        // The record renders into the prompt type-info section under
        // the variable's decompiled name.
        let rendered = calxgloss_prompts::TypeInfo::from(&InferredType::Local(record.clone()));
        assert_eq!(rendered.name, "local_18");
        assert_eq!(
            rendered.description,
            "void * (via assignment_chain, confidence 60)"
        );
    }

    #[tokio::test]
    async fn the_same_local_name_in_two_functions_does_not_conflict() {
        // `local_8` is the decompiler's name for one stack slot in each
        // of two bodies; the records key on function and name together,
        // so both survive resolution.
        let mut program = locals_program();
        program.listing.push(summary("FUN_18003e750"));
        program.bodies.insert(
            "FUN_18003e750".into(),
            function(
                "FUN_18003e750",
                "undefined FUN_18003e750(void)",
                "  local_8 = malloc(0x10);\n",
            ),
        );
        let result = scan(program).await;

        assert_eq!(local_count(&result, "FUN_18003ab00", "local_8"), 1);
        assert_eq!(local_count(&result, "FUN_18003e750", "local_8"), 1);
        assert_eq!(
            local_finding(&result, "FUN_18003ab00", "local_8").inferred_type,
            "char *"
        );
        assert_eq!(
            local_finding(&result, "FUN_18003e750", "local_8").inferred_type,
            "void *"
        );
    }

    /// The canned program for the cross-function pass: a helper whose
    /// body reads its own parameters — `char *` at position 0, `void *`
    /// at position 1 — and a caller that invokes it with its own
    /// parameter, a local, a literal, a cast, and a nested call.
    fn cross_program() -> FakeProgram {
        let mut program = FakeProgram::empty();
        program.listing = vec![summary("FUN_18004b210"), summary("FUN_180051c00")];
        program.bodies.insert(
            "FUN_18004b210".into(),
            function(
                "FUN_18004b210",
                "undefined FUN_18004b210(undefined8 param_1,undefined8 param_2)",
                "  uVar1 = strlen(param_1);\n  CloseHandle(param_2);\n",
            ),
        );
        program.bodies.insert(
            "FUN_180051c00".into(),
            function(
                "FUN_180051c00",
                "undefined FUN_180051c00(undefined8 param_1,undefined8 param_2)",
                "  FUN_18004b210(param_1, local_8);\n\
                 \x20 FUN_18004b210(\"name\", (char *)param_2);\n\
                 \x20 FUN_18004b210(get_name(), 0x10);\n",
            ),
        );
        program
    }

    fn call_site_finding<'a>(
        result: &'a TypeInferenceResult,
        function: &str,
        callee: &str,
        arg_index: usize,
    ) -> &'a InferredCallType {
        result
            .for_function(function)
            .find_map(|inference| match inference {
                InferredType::CallSite(record)
                    if record.callee == callee && record.arg_index == arg_index =>
                {
                    Some(record)
                }
                _ => None,
            })
            .expect("call-site record")
    }

    fn call_site_count(result: &TypeInferenceResult, function: &str) -> usize {
        result
            .for_function(function)
            .filter(|inference| matches!(inference, InferredType::CallSite(_)))
            .count()
    }

    #[tokio::test]
    async fn a_callee_s_surviving_reading_types_the_arguments_at_its_call_sites() {
        let program = cross_program();
        let result = scan(program.clone()).await;

        // The helper's own readings survive as before.
        assert_eq!(
            finding(&result, "FUN_18004b210", InferenceMethod::StringFunction, 0).inferred_type(),
            "char *"
        );

        // The call-site record: the helper's `char *` reading types the
        // first argument, with the call line as evidence.
        let site = call_site_finding(&result, "FUN_180051c00", "FUN_18004b210", 0);
        assert_eq!(site.arg_name.as_deref(), Some("param_1"));
        assert_eq!(site.inferred_type, "char *");
        assert_eq!(site.method, InferenceMethod::CrossFunction);
        assert_eq!(site.scope, InferenceScope::Function);
        assert_eq!(site.confidence, Confidence::new(70));
        assert_eq!(site.evidence, "FUN_18004b210(param_1, local_8);");

        // The second position takes the helper's `void *` reading; the
        // argument is a local, so no parameter record rides along.
        let site = call_site_finding(&result, "FUN_180051c00", "FUN_18004b210", 1);
        assert_eq!(site.arg_name.as_deref(), Some("local_8"));
        assert_eq!(site.inferred_type, "void *");

        // The argument that is the caller's own parameter gets a
        // parameter record too — the type climbing the call chain.
        let climb = finding(&result, "FUN_180051c00", InferenceMethod::CrossFunction, 0);
        let InferredType::Param(record) = climb else {
            unreachable!("the cross-function pass emits parameter records");
        };
        assert_eq!(record.param_name.as_deref(), Some("param_1"));
        assert_eq!(record.inferred_type, "char *");
        assert_eq!(record.scope, InferenceScope::Function);
        assert_eq!(record.confidence, Confidence::new(65));
        assert_eq!(record.evidence, "FUN_18004b210(param_1, local_8);");

        // The literal, cast, and nested-call sites produced nothing:
        // two call-site records for the caller, and its second
        // parameter carries no reading at all.
        assert_eq!(call_site_count(&result, "FUN_180051c00"), 2);
        assert_eq!(param_count(&result, "FUN_180051c00", 1), 0);

        // The cross-function pass re-read the bodies it already had:
        // still one decompile per function.
        assert_eq!(
            program.decompiled(),
            vec!["FUN_18004b210", "FUN_180051c00"],
            "one decompile per function, in listing order"
        );
    }

    #[tokio::test]
    async fn conflicting_call_site_readings_for_one_target_keep_the_first_seen() {
        // Two calls to one callee at one position, both bare names: the
        // target is the same, the readings tie at 70, and conflict
        // resolution keeps the site the body showed first.
        let mut program = FakeProgram::empty();
        program.listing = vec![summary("FUN_18004b210"), summary("FUN_180051c00")];
        program.bodies.insert(
            "FUN_18004b210".into(),
            function(
                "FUN_18004b210",
                "undefined FUN_18004b210(undefined8 param_1)",
                "  uVar1 = strlen(param_1);\n",
            ),
        );
        program.bodies.insert(
            "FUN_180051c00".into(),
            function(
                "FUN_180051c00",
                "undefined FUN_180051c00(undefined8 param_1)",
                "  FUN_18004b210(param_1);\n  FUN_18004b210(local_8);\n",
            ),
        );
        let result = scan(program).await;

        assert_eq!(call_site_count(&result, "FUN_180051c00"), 1);
        let site = call_site_finding(&result, "FUN_180051c00", "FUN_18004b210", 0);
        assert_eq!(site.arg_name.as_deref(), Some("param_1"));
        assert_eq!(site.evidence, "FUN_18004b210(param_1);");
    }

    #[tokio::test]
    async fn a_cross_function_reading_loses_to_a_stronger_inline_reading_for_one_parameter() {
        // The caller's parameter stands read by its own body (`strlen`,
        // 70) and by the callee's contract (65): the direct reading wins
        // the target and the cross-function record drops — while the
        // call-site record, a different target, survives on its own.
        let mut program = FakeProgram::empty();
        program.listing = vec![summary("FUN_18004b210"), summary("FUN_180051c00")];
        program.bodies.insert(
            "FUN_18004b210".into(),
            function(
                "FUN_18004b210",
                "undefined FUN_18004b210(undefined8 param_1)",
                "  CloseHandle(param_1);\n",
            ),
        );
        program.bodies.insert(
            "FUN_180051c00".into(),
            function(
                "FUN_180051c00",
                "undefined FUN_180051c00(undefined8 param_1)",
                "  uVar1 = strlen(param_1);\n  FUN_18004b210(param_1);\n",
            ),
        );
        let result = scan(program).await;

        assert_eq!(param_count(&result, "FUN_180051c00", 0), 1);
        let InferredType::Param(record) =
            finding(&result, "FUN_180051c00", InferenceMethod::StringFunction, 0)
        else {
            unreachable!("the size detector emits parameter records");
        };
        assert_eq!(record.inferred_type, "char *");
        let site = call_site_finding(&result, "FUN_180051c00", "FUN_18004b210", 0);
        assert_eq!(site.inferred_type, "void *");
    }

    #[tokio::test]
    async fn scan_decompiles_each_function_exactly_once() {
        // The three detectors share one fetch per function; a scan that
        // asked each detector for its own copy would triple the wall time.
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
    async fn scan_keeps_the_listing_order() {
        // Both functions infer something, so the persisted list must group
        // their records by function in listing order, never interleaved.
        let mut program = program();
        program.bodies.insert(
            "FUN_18003e750".into(),
            function(
                "FUN_18003e750",
                "undefined FUN_18003e750(char *param_1)",
                "  strlen(param_1);\n",
            ),
        );
        program.listing = vec![summary("FUN_18003e750"), summary("FUN_18003ab00")];
        let result = scan(program).await;

        let mut functions: Vec<&str> = result
            .inferences
            .iter()
            .map(|inference| inference.function())
            .collect();
        functions.dedup();
        assert_eq!(functions, vec!["FUN_18003e750", "FUN_18003ab00"]);
    }

    #[tokio::test]
    async fn a_function_that_will_not_decompile_is_skipped() {
        // The decompiler cannot produce a body for every function; one bad entry
        // point must not cost the whole program its scan.
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
        let result = TypeInferEngine::with_source(program)
            .scan("eqmain.dll")
            .await;
        assert!(matches!(
            result,
            Err(crate::TypeInferError::DecompileBreaker {
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
        let result = TypeInferEngine::with_source(program.clone())
            .scan("eqmain.dll")
            .await;

        assert!(matches!(
            result,
            Err(crate::TypeInferError::DecompileBreaker {
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
        program.listing.insert(0, summary(""));
        let result = scan(program.clone()).await;

        assert_eq!(program.decompiled(), vec!["FUN_18003ab00", "FUN_18003e750"]);
        assert!(!result.is_empty());
    }

    #[tokio::test]
    async fn a_failing_listing_fails_the_whole_run() {
        // With the listing gone nothing was scanned, so the run aborts
        // rather than returning a result that looks empty by inference.
        let mut program = program();
        program.fail_listing = true;
        let result = TypeInferEngine::with_source(program)
            .scan("eqmain.dll")
            .await;
        assert!(matches!(
            result,
            Err(crate::TypeInferError::Engine(EngineError::Reported { .. }))
        ));
    }

    #[tokio::test]
    async fn an_empty_program_yields_an_empty_result() {
        let result = scan(FakeProgram::empty()).await;
        assert!(result.is_empty());
        assert_eq!(result.metadata.binary, "eqmain.dll");
        assert!(result.metadata.scanned_at > 0);
    }

    #[tokio::test]
    async fn an_inline_reading_at_confidence_65_beats_the_cross_function_climb() {
        // Both readings sit at 65, so the first-seen rule decides — and
        // the inline chain is always resolved before the propagated one.
        let mut program = FakeProgram::empty();
        program.listing = vec![summary("FUN_18004b210"), summary("FUN_180051c00")];
        program.bodies.insert(
            "FUN_18004b210".into(),
            function(
                "FUN_18004b210",
                "undefined FUN_18004b210(undefined8 param_1)",
                "  *param_1 = 0;\n",
            ),
        );
        program.bodies.insert(
            "FUN_180051c00".into(),
            function(
                "FUN_180051c00",
                "undefined FUN_180051c00(undefined8 param_1)",
                "  *param_1 = 0;\n  FUN_18004b210(param_1);\n",
            ),
        );
        let result = scan(program).await;

        assert_eq!(param_count(&result, "FUN_180051c00", 0), 1);
        let InferredType::Param(record) = finding(
            &result,
            "FUN_180051c00",
            InferenceMethod::PointerArithmetic,
            0,
        ) else {
            unreachable!("the pointer detector emits parameter records");
        };
        assert_eq!(record.inferred_type, "void *");
    }

    /// The canned program for the caller→callee pass: a helper whose own
    /// body shows nothing interesting, and two callers that reveal its
    /// contract — one passing its own typed parameter and a `malloc`
    /// result, one passing a wide string literal and a bare number.
    fn callers_program() -> FakeProgram {
        let mut program = FakeProgram::empty();
        program.listing = vec![
            summary("FUN_18004b210"),
            summary("FUN_180051c00"),
            summary("FUN_180052000"),
        ];
        program.bodies.insert(
            "FUN_18004b210".into(),
            function(
                "FUN_18004b210",
                "undefined FUN_18004b210(undefined8 param_1,undefined8 param_2)",
                "  return;\n",
            ),
        );
        program.bodies.insert(
            "FUN_180051c00".into(),
            function(
                "FUN_180051c00",
                "undefined FUN_180051c00(undefined8 param_1)",
                "  uVar1 = strlen(param_1);\n  FUN_18004b210(param_1, malloc(0x10));\n",
            ),
        );
        program.bodies.insert(
            "FUN_180052000".into(),
            function(
                "FUN_180052000",
                "undefined FUN_180052000(void)",
                "  FUN_18004b210(L\"name\", 0x10);\n",
            ),
        );
        program.callers.insert(
            addr("FUN_18004b210"),
            vec!["FUN_180051c00".into(), "FUN_180052000".into()],
        );
        program
    }

    #[tokio::test]
    async fn callers_recognizable_arguments_type_the_callee_s_parameters() {
        // The helper's body says nothing; its callers do. The first
        // parameter takes the first caller's typed parameter (`char *`,
        // first-seen over the second caller's wide literal); the second
        // takes the `malloc` result, since the bare number beside it
        // says nothing.
        let result = scan(callers_program()).await;

        let InferredType::Param(record) =
            finding(&result, "FUN_18004b210", InferenceMethod::CrossFunction, 0)
        else {
            unreachable!("the caller→callee pass emits parameter records");
        };
        assert_eq!(record.param_name.as_deref(), Some("param_1"));
        assert_eq!(record.inferred_type, "char *");
        assert_eq!(record.scope, InferenceScope::Function);
        assert_eq!(record.confidence, Confidence::new(65));
        assert_eq!(record.evidence, "FUN_180051c00 passes FUN_18004b210");

        let InferredType::Param(record) =
            finding(&result, "FUN_18004b210", InferenceMethod::CrossFunction, 1)
        else {
            unreachable!("the caller→callee pass emits parameter records");
        };
        assert_eq!(record.inferred_type, "void *");
        assert_eq!(record.evidence, "FUN_180051c00 passes FUN_18004b210");
    }

    #[tokio::test]
    async fn a_caller_body_is_fetched_at_most_once_per_scan() {
        // One caller outside the listing calls both helpers: its body is
        // fetched once and cached, and a caller that will not decompile
        // is attempted once — the failure is cached too. The analyzed
        // functions themselves are still decompiled exactly once.
        let mut program = FakeProgram::empty();
        program.listing = vec![summary("FUN_18004b210"), summary("FUN_18004b300")];
        program.bodies.insert(
            "FUN_18004b210".into(),
            function(
                "FUN_18004b210",
                "undefined FUN_18004b210(undefined8 param_1)",
                "  return;\n",
            ),
        );
        program.bodies.insert(
            "FUN_18004b300".into(),
            function(
                "FUN_18004b300",
                "undefined FUN_18004b300(undefined8 param_1)",
                "  return;\n",
            ),
        );
        program.bodies.insert(
            "FUN_180051c00".into(),
            function(
                "FUN_180051c00",
                "undefined FUN_180051c00(void)",
                "  FUN_18004b210(\"name\");\n  FUN_18004b300(L\"name\");\n",
            ),
        );
        program.callers.insert(
            addr("FUN_18004b210"),
            vec!["FUN_180051c00".into(), "FUN_180052000".into()],
        );
        program
            .callers
            .insert(addr("FUN_18004b300"), vec!["FUN_180051c00".into()]);
        program.fail_decompiles = vec!["FUN_180052000".into()];
        let result = scan(program.clone()).await;

        assert_eq!(
            program.decompiled(),
            vec![
                "FUN_18004b210",
                "FUN_18004b300",
                "FUN_180051c00",
                "FUN_180052000"
            ],
            "the shared caller was fetched once, and the failed one only attempted once"
        );
        assert_eq!(
            finding(&result, "FUN_18004b210", InferenceMethod::CrossFunction, 0).inferred_type(),
            "char *"
        );
        assert_eq!(
            finding(&result, "FUN_18004b300", InferenceMethod::CrossFunction, 0).inferred_type(),
            "wchar_t *"
        );
    }

    #[tokio::test]
    async fn a_literal_argument_types_no_callee_parameter_though_the_callee_still_types_its_sites()
    {
        // The helper reads its own parameter as `char *`; a caller
        // passing a bare number gets nothing at that site — the
        // callee's contract types only the bare-identifier site beside
        // it — and the number is no evidence about the helper's
        // parameter, which keeps only its inline reading.
        let mut program = FakeProgram::empty();
        program.listing = vec![summary("FUN_18004b210"), summary("FUN_180051c00")];
        program.bodies.insert(
            "FUN_18004b210".into(),
            function(
                "FUN_18004b210",
                "undefined FUN_18004b210(undefined8 param_1)",
                "  uVar1 = strlen(param_1);\n",
            ),
        );
        program.bodies.insert(
            "FUN_180051c00".into(),
            function(
                "FUN_180051c00",
                "undefined FUN_180051c00(void)",
                "  FUN_18004b210(0x10);\n  FUN_18004b210(local_8);\n",
            ),
        );
        program
            .callers
            .insert(addr("FUN_18004b210"), vec!["FUN_180051c00".into()]);
        let result = scan(program).await;

        // The callee's contract still types the bare-name site beside
        // the literal — the literal's own site stays untyped.
        assert_eq!(call_site_count(&result, "FUN_180051c00"), 1);
        let site = call_site_finding(&result, "FUN_180051c00", "FUN_18004b210", 0);
        assert_eq!(site.arg_name.as_deref(), Some("local_8"));
        assert_eq!(site.inferred_type, "char *");

        // The helper's parameter: one record, the inline one — the
        // caller's number contributed nothing.
        assert_eq!(param_count(&result, "FUN_18004b210", 0), 1);
        assert_eq!(
            finding(&result, "FUN_18004b210", InferenceMethod::StringFunction, 0).inferred_type(),
            "char *"
        );
        // No cross-function parameter record for the helper at all.
        assert!(
            !result
                .for_function("FUN_18004b210")
                .any(|inference| matches!(
                    inference,
                    InferredType::Param(record) if record.method == InferenceMethod::CrossFunction
                )),
            "a bare number types no callee parameter"
        );
    }

    #[tokio::test]
    async fn an_inline_vtable_reading_beats_a_propagated_one() {
        // The helper dispatches through its first parameter (85) and a
        // caller hands it a string literal (65): the direct body
        // evidence wins the parameter, and the propagated record drops.
        let mut program = FakeProgram::empty();
        program.listing = vec![summary("FUN_18004b210"), summary("FUN_180051c00")];
        program.bodies.insert(
            "FUN_18004b210".into(),
            function(
                "FUN_18004b210",
                "undefined FUN_18004b210(undefined8 param_1)",
                "  (**(code **)*param_1)(param_1);\n",
            ),
        );
        program.bodies.insert(
            "FUN_180051c00".into(),
            function(
                "FUN_180051c00",
                "undefined FUN_180051c00(void)",
                "  FUN_18004b210(\"name\");\n",
            ),
        );
        program
            .callers
            .insert(addr("FUN_18004b210"), vec!["FUN_180051c00".into()]);
        let result = scan(program).await;

        assert_eq!(param_count(&result, "FUN_18004b210", 0), 1);
        let InferredType::Param(record) =
            finding(&result, "FUN_18004b210", InferenceMethod::VtableCall, 0)
        else {
            unreachable!("the this-pointer detector emits parameter records");
        };
        assert_eq!(record.inferred_type, "void *");
        assert!(record.confidence > Confidence::new(65));
    }

    /// The canned program for the return-usage pass: a helper whose own
    /// body says nothing about its return, and two callers that do —
    /// one assigns the result to a local its own scan typed `char *`,
    /// one passes it where `strlen` reads a character string.
    fn returns_program() -> FakeProgram {
        let mut program = FakeProgram::empty();
        program.listing = vec![
            summary("FUN_18004b210"),
            summary("FUN_180051c00"),
            summary("FUN_180052000"),
        ];
        program.bodies.insert(
            "FUN_18004b210".into(),
            function(
                "FUN_18004b210",
                "undefined FUN_18004b210(void)",
                "  return uVar1;\n",
            ),
        );
        program.bodies.insert(
            "FUN_180051c00".into(),
            function(
                "FUN_180051c00",
                "undefined FUN_180051c00(undefined8 param_1)",
                "  strlen(param_1);\n\
                 \x20 local_8 = param_1;\n\
                 \x20 local_8 = FUN_18004b210();\n",
            ),
        );
        program.bodies.insert(
            "FUN_180052000".into(),
            function(
                "FUN_180052000",
                "undefined FUN_180052000(void)",
                "  strlen(FUN_18004b210());\n",
            ),
        );
        program.callers.insert(
            addr("FUN_18004b210"),
            vec!["FUN_180051c00".into(), "FUN_180052000".into()],
        );
        program
    }

    fn return_finding<'a>(
        result: &'a TypeInferenceResult,
        function: &str,
    ) -> &'a crate::types::InferredReturnType {
        result
            .for_function(function)
            .find_map(|inference| match inference {
                InferredType::Return(record) => Some(record),
                _ => None,
            })
            .expect("return record")
    }

    fn return_count(result: &TypeInferenceResult, function: &str) -> usize {
        result
            .for_function(function)
            .filter(|inference| matches!(inference, InferredType::Return(_)))
            .count()
    }

    #[tokio::test]
    async fn scan_emits_a_return_record_from_how_callers_use_the_result() {
        // The helper's body never reads its own return; its callers do.
        // The first caller's typed-local reading wins the tie and its
        // line is the evidence the record carries.
        let program = returns_program();
        let result = scan(program.clone()).await;

        let record = return_finding(&result, "FUN_18004b210");
        assert_eq!(record.function, "FUN_18004b210");
        assert_eq!(record.inferred_type, "char *");
        assert_eq!(record.method, InferenceMethod::ReturnUsage);
        assert_eq!(record.scope, InferenceScope::Function);
        assert_eq!(record.confidence, Confidence::new(60));
        assert_eq!(record.evidence, "local_8 = FUN_18004b210();");

        // The record renders into the prompt type-info section under the
        // name `return`.
        let rendered = calxgloss_prompts::TypeInfo::from(&InferredType::Return(record.clone()));
        assert_eq!(rendered.name, "return");
        assert_eq!(
            rendered.description,
            "char * (via return_usage, confidence 60)"
        );

        // The return pass rides the caller lookup the caller→callee pass
        // already made: still one decompile per function.
        assert_eq!(
            program.decompiled(),
            vec!["FUN_18004b210", "FUN_180051c00", "FUN_180052000"],
            "one decompile per function, in listing order"
        );
    }

    #[tokio::test]
    async fn one_function_never_keeps_two_return_types() {
        // Two callers read the return differently — `char *` from the
        // typed local, `void *` from a dereference — both at 60: the
        // scan keeps the reading the callers showed first.
        let mut program = returns_program();
        program.bodies.insert(
            "FUN_180052000".into(),
            function(
                "FUN_180052000",
                "undefined FUN_180052000(void)",
                "  iVar1 = *FUN_18004b210();\n",
            ),
        );
        let result = scan(program).await;

        assert_eq!(return_count(&result, "FUN_18004b210"), 1);
        let record = return_finding(&result, "FUN_18004b210");
        assert_eq!(record.inferred_type, "char *");
        assert_eq!(record.evidence, "local_8 = FUN_18004b210();");
    }

    #[tokio::test]
    async fn a_dereferenced_result_lends_a_pointer_return() {
        // With no stronger reading in any caller, the dereference's
        // pointer reading survives on its own.
        let mut program = returns_program();
        program.bodies.insert(
            "FUN_180051c00".into(),
            function(
                "FUN_180051c00",
                "undefined FUN_180051c00(void)",
                "  iVar1 = *FUN_18004b210();\n",
            ),
        );
        let result = scan(program).await;

        let record = return_finding(&result, "FUN_18004b210");
        assert_eq!(record.inferred_type, "void *");
        assert_eq!(record.evidence, "iVar1 = *FUN_18004b210();");
    }

    #[tokio::test]
    async fn a_return_reading_does_not_compete_with_a_parameter_reading() {
        // The helper's own body types its parameter and its callers
        // type its return: different targets, both survive.
        let mut program = returns_program();
        program.bodies.insert(
            "FUN_18004b210".into(),
            function(
                "FUN_18004b210",
                "undefined FUN_18004b210(undefined8 param_1)",
                "  strlen(param_1);\n  return param_1;\n",
            ),
        );
        let result = scan(program).await;

        assert_eq!(
            finding(&result, "FUN_18004b210", InferenceMethod::StringFunction, 0).inferred_type(),
            "char *"
        );
        assert_eq!(return_count(&result, "FUN_18004b210"), 1);
        assert_eq!(
            return_finding(&result, "FUN_18004b210").inferred_type,
            "char *"
        );
    }

    // ---- C++ mangling analysis ----

    /// The canned program for the mangling pass: one function whose body
    /// carries a demangled qualified call with a spelled parameter list,
    /// and one function whose listing name is an MSVC-mangled symbol —
    /// `char * Widget::copy(char *)`, a member with an
    /// implicit `this`.
    fn mangling_program() -> FakeProgram {
        let mut program = FakeProgram::empty();
        program.listing = vec![
            summary("FUN_18003ab00"),
            summary("?copy@Widget@@QAGPADPAD@Z"),
        ];
        program.bodies.insert(
            "FUN_18003ab00".into(),
            function(
                "FUN_18003ab00",
                "undefined FUN_18003ab00(undefined8 param_1,undefined8 param_2)",
                "  Widget::Render(int,char *)(param_1, param_2);\n",
            ),
        );
        program.bodies.insert(
            "?copy@Widget@@QAGPADPAD@Z".into(),
            function(
                "?copy@Widget@@QAGPADPAD@Z",
                "undefined ?copy@Widget@@QAGPADPAD@Z(undefined8 param_1,undefined8 param_2)",
                "  return param_2;\n",
            ),
        );
        program
    }

    fn mangling_count(result: &TypeInferenceResult) -> usize {
        result
            .inferences
            .iter()
            .filter(|inference| match inference {
                InferredType::Param(record) => record.method == InferenceMethod::Mangling,
                InferredType::Return(record) => record.method == InferenceMethod::Mangling,
                _ => false,
            })
            .count()
    }

    #[tokio::test]
    async fn scan_emits_mangling_records_from_a_demangled_qualified_call() {
        let result = scan(mangling_program()).await;

        let record = finding(
            &result,
            "Widget::Render(int,char *)",
            InferenceMethod::Mangling,
            0,
        );
        let InferredType::Param(record) = record else {
            unreachable!("the spelled call emits parameter records");
        };
        assert_eq!(record.inferred_type, "int");
        assert_eq!(record.scope, InferenceScope::Function);
        assert_eq!(record.confidence, Confidence::new(80));
        assert_eq!(
            record.evidence,
            "Widget::Render(int,char *)(param_1, param_2);"
        );

        let second = finding(
            &result,
            "Widget::Render(int,char *)",
            InferenceMethod::Mangling,
            1,
        );
        assert_eq!(second.inferred_type(), "char *");
    }

    #[tokio::test]
    async fn an_msvc_mangled_listing_symbol_types_the_function_from_its_own_name() {
        // The unnamed wrapper typed from its own symbol: the member's
        // implicit `this` at zero, the decoded argument at one, and the
        // non-`void` return — all keyed and evidenced by the symbol.
        let result = scan(mangling_program()).await;

        let this_ptr = finding(
            &result,
            "?copy@Widget@@QAGPADPAD@Z",
            InferenceMethod::Mangling,
            0,
        );
        let InferredType::Param(record) = this_ptr else {
            unreachable!("the symbol emits parameter records");
        };
        assert_eq!(record.inferred_type, "Widget *");
        assert_eq!(record.confidence, Confidence::new(80));
        assert_eq!(record.evidence, "?copy@Widget@@QAGPADPAD@Z");

        let argument = finding(
            &result,
            "?copy@Widget@@QAGPADPAD@Z",
            InferenceMethod::Mangling,
            1,
        );
        assert_eq!(argument.inferred_type(), "char *");

        let return_record = result
            .for_function("?copy@Widget@@QAGPADPAD@Z")
            .find(|inference| matches!(inference, InferredType::Return(_)))
            .expect("the symbol's return reading");
        let InferredType::Return(record) = return_record else {
            unreachable!("the return reading is a return record");
        };
        assert_eq!(record.inferred_type, "char *");
        assert_eq!(record.method, InferenceMethod::Mangling);
    }

    #[tokio::test]
    async fn a_mangling_reading_beats_a_weaker_inline_reading_for_one_parameter() {
        // The symbol spells `void __thiscall Widget::setup(int)` while
        // the body's `strlen` reads the same position as `char *`: the
        // symbol-borne fact (80) outranks the usage reading (70), and
        // the target keeps one record.
        let mut program = FakeProgram::empty();
        program.listing = vec![summary("?setup@Widget@@QAEXH@Z")];
        program.bodies.insert(
            "?setup@Widget@@QAEXH@Z".into(),
            function(
                "?setup@Widget@@QAEXH@Z",
                "undefined ?setup@Widget@@QAEXH@Z(undefined8 param_1,undefined8 param_2)",
                "  strlen(param_2);\n",
            ),
        );
        let result = scan(program).await;

        assert_eq!(param_count(&result, "?setup@Widget@@QAEXH@Z", 1), 1);
        assert_eq!(
            finding(
                &result,
                "?setup@Widget@@QAEXH@Z",
                InferenceMethod::Mangling,
                1
            )
            .inferred_type(),
            "int"
        );
    }

    #[tokio::test]
    async fn a_name_without_a_spelled_list_emits_no_mangling_records() {
        // An ordinary qualified call and a plain `FUN_` listing name
        // carry no spelled contract: the this-pointer detector reads
        // what usage shows of them, the mangling pass says nothing.
        let mut program = FakeProgram::empty();
        program.listing = vec![summary("FUN_18003ab00")];
        program.bodies.insert(
            "FUN_18003ab00".into(),
            function(
                "FUN_18003ab00",
                "undefined FUN_18003ab00(undefined8 param_1)",
                "  Widget::paint(param_1);\n",
            ),
        );
        let result = scan(program).await;

        assert_eq!(mangling_count(&result), 0);
    }

    // ---- calling-convention analysis ----

    /// The convention record for one function, for asserting against.
    fn convention_finding<'a>(
        result: &'a TypeInferenceResult,
        function: &str,
    ) -> &'a InferredConvention {
        result
            .inferences
            .iter()
            .find_map(|inference| match inference {
                InferredType::Convention(record) if record.function == function => Some(record),
                _ => None,
            })
            .expect("a convention record for the function")
    }

    #[tokio::test]
    async fn a_mangled_listing_symbol_carries_its_convention_beside_its_this_pointer() {
        // `char * Widget::copy(char *)` as an old-EVC thiscall member:
        // the `G` letter reads the convention while the same symbol's
        // member shape reads the implicit `this` — the pair together
        // says the function is a method.
        let result = scan(mangling_program()).await;

        let record = convention_finding(&result, "?copy@Widget@@QAGPADPAD@Z");
        assert_eq!(record.convention, CallingConvention::Thiscall);
        assert_eq!(record.method, InferenceMethod::MangledConvention);
        assert_eq!(record.confidence, Confidence::new(90));
        assert_eq!(record.evidence, "?copy@Widget@@QAGPADPAD@Z");

        // The this-pointer reading for the same symbol is still there.
        let this_ptr = finding(
            &result,
            "?copy@Widget@@QAGPADPAD@Z",
            InferenceMethod::Mangling,
            0,
        );
        assert_eq!(this_ptr.inferred_type(), "Widget *");
    }

    #[tokio::test]
    async fn a_decorated_import_reads_stdcall_and_a_plain_one_reads_nothing() {
        // `CreateFileA@28` declares its argument bytes, so the import is
        // called stdcall; a plain `CloseHandle` import spells no
        // convention and yields no record rather than a guess.
        let mut program = FakeProgram::empty();
        program.imports = vec![
            Symbol {
                name: "CreateFileA@28".into(),
                address: 0x1800_0100,
                imported: true,
            },
            Symbol {
                name: "CloseHandle".into(),
                address: 0x1800_0108,
                imported: true,
            },
        ];
        let result = scan(program).await;

        let record = convention_finding(&result, "CreateFileA@28");
        assert_eq!(record.convention, CallingConvention::Stdcall);
        assert_eq!(record.method, InferenceMethod::ImportDecoration);
        assert_eq!(record.confidence, Confidence::new(85));
        assert_eq!(record.evidence, "CreateFileA@28");

        assert!(
            result
                .inferences
                .iter()
                .all(|inference| inference.function() != "CloseHandle"),
            "an undecorated import carries no convention reading"
        );
    }

    // ---- convention readings off the machine listing ----

    #[tokio::test]
    async fn the_scan_reads_each_listed_function_s_listing_exactly_once() {
        // The listing read rides the breaker-gated window: exactly one
        // read per listed function, in listing order, and none for a
        // function the listing never shows — the off-listing caller
        // the caller→callee pass fetches gets a body, never a
        // listing read.
        let mut program = program();
        program
            .callers
            .insert(addr("FUN_18003e750"), vec!["FUN_off_listing".into()]);
        program.bodies.insert(
            "FUN_off_listing".into(),
            function(
                "FUN_off_listing",
                "undefined FUN_off_listing(void)",
                "  FUN_18003e750();\n",
            ),
        );
        let result = scan(program.clone()).await;

        assert_eq!(
            program.disassembled(),
            ["FUN_18003ab00", "FUN_18003e750"],
            "one listing read per listed function, in listing order"
        );
        assert!(
            program
                .decompiled()
                .iter()
                .any(|name| name == "FUN_off_listing"),
            "the off-listing caller's body was fetched — and only its body"
        );
        assert!(
            result
                .inferences
                .iter()
                .all(|inference| !matches!(inference, InferredType::Convention(_))),
            "no canned listing, no stack-discipline reading"
        );
    }

    #[tokio::test]
    async fn an_epilogue_that_cleans_up_its_arguments_reads_stdcall() {
        // A canned esp-spelled listing whose epilogue pops twelve
        // argument bytes: the callee cleans up its own stack, so the
        // function reads stdcall — the exact-epilogue band, with the
        // epilogue line itself as the evidence.
        let mut program = program();
        program.listings.insert(
            "FUN_18003e750".into(),
            "00401000  PUSH EBP\n\
             00401001  MOV EBP, ESP\n\
             00401003  POP EBP\n\
             00401004  RET 0xC"
                .into(),
        );
        let result = scan(program).await;

        let record = convention_finding(&result, "FUN_18003e750");
        assert_eq!(record.convention, CallingConvention::Stdcall);
        assert_eq!(record.method, InferenceMethod::CalleeEpilogue);
        assert_eq!(record.confidence, Confidence::new(80));
        assert_eq!(record.evidence, "00401004  RET 0xC");

        // The other function, whose listing read answered empty, goes
        // unrecorded.
        assert!(
            result
                .inferences
                .iter()
                .all(|inference| inference.function() != "FUN_18003ab00"
                    || !matches!(inference, InferredType::Convention(_))),
            "an empty listing yields no convention reading"
        );
    }

    #[tokio::test]
    async fn a_caller_that_cleans_up_after_a_call_reads_cdecl_for_the_callee() {
        // A canned esp-spelled caller listing: a direct call naming its
        // callee, then the caller popping the arguments it pushed. The
        // record lands on the callee named at that site — cdecl, the
        // caller-cleanup band, evidenced by the cleanup line.
        let mut program = program();
        program.listings.insert(
            "FUN_18003ab00".into(),
            "00401100  PUSH EBP\n\
             00401101  MOV EBP, ESP\n\
             00401103  CALL FUN_1800412a0\n\
             00401108  ADD ESP, 0x8\n\
             0040110b  POP EBP\n\
             0040110c  RET"
                .into(),
        );
        let result = scan(program).await;

        let record = convention_finding(&result, "FUN_1800412a0");
        assert_eq!(record.convention, CallingConvention::Cdecl);
        assert_eq!(record.method, InferenceMethod::CallerCleanup);
        assert_eq!(record.confidence, Confidence::new(70));
        assert_eq!(record.evidence, "00401108  ADD ESP, 0x8");

        // The caller pops for its callee but cleans nothing of its own:
        // a bare `ret` is no epilogue reading — the only convention
        // record naming the caller is the corroborator's call-site view
        // of the callee, keyed by the caller and naming the callee with
        // the callee's own convention and confidence.
        let caller_records: Vec<&InferredConvention> = result
            .inferences
            .iter()
            .filter_map(|inference| match inference {
                InferredType::Convention(record) if record.function == "FUN_18003ab00" => {
                    Some(record)
                }
                _ => None,
            })
            .collect();
        assert_eq!(
            caller_records.len(),
            1,
            "a bare ret reads no convention for the caller itself"
        );
        let view = caller_records[0];
        assert_eq!(view.callee.as_deref(), Some("FUN_1800412a0"));
        assert_eq!(view.convention, CallingConvention::Cdecl);
        assert_eq!(view.method, InferenceMethod::CallSiteConvention);
        assert_eq!(view.confidence, Confidence::new(70));
        assert_eq!(view.evidence, "00401103  CALL FUN_1800412a0");
    }

    #[tokio::test]
    async fn an_rsp_spelled_listing_yields_no_32_bit_reading() {
        // The whole family keys on the stack register spelled in the
        // listing itself: the same cleanup shapes spelled with the
        // 64-bit register — even a `ret N` — produce no 32-bit
        // reading, so the families never cross-fire.
        let mut program = program();
        program.listings.insert(
            "FUN_18003e750".into(),
            "140001000  SUB RSP, 0x28\n\
             140001007  CALL FUN_18003ab00\n\
             14000100c  ADD RSP, 0x20\n\
             140001010  RET 0x20"
                .into(),
        );
        let result = scan(program).await;

        assert!(
            result
                .inferences
                .iter()
                .all(|inference| !matches!(inference, InferredType::Convention(_))),
            "a 64-bit-spelled listing never yields a 32-bit reading"
        );
    }

    #[tokio::test]
    async fn a_shadow_space_prologue_reads_microsoft_x64() {
        // A canned rsp-spelled listing showing the whole 64-bit shape:
        // the prologue allocates the 32-byte shadow space, the argument
        // registers are spelled, and the only add frees exactly the
        // prologue's allocation before a bare ret — the frame teardown,
        // not a cleanup. The function reads Microsoft x64 at the
        // shape-only band, with the prologue line as the evidence.
        let mut program = program();
        program.listings.insert(
            "FUN_18003e750".into(),
            "140001000  SUB RSP, 0x28\n\
             140001007  MOV [RSP+0x8], RCX\n\
             14000100c  MOV [RSP+0x10], RDX\n\
             140001011  CALL FUN_18003ab00\n\
             140001016  ADD RSP, 0x28\n\
             14000101a  RET"
                .into(),
        );
        let result = scan(program).await;

        let record = convention_finding(&result, "FUN_18003e750");
        assert_eq!(record.convention, CallingConvention::MicrosoftX64);
        assert_eq!(record.method, InferenceMethod::X64Shape);
        assert_eq!(record.confidence, Confidence::new(65));
        assert_eq!(record.evidence, "140001000  SUB RSP, 0x28");

        // The other function, whose listing read answered empty, goes
        // unrecorded.
        assert!(
            result
                .inferences
                .iter()
                .all(|inference| inference.function() != "FUN_18003ab00"
                    || !matches!(inference, InferredType::Convention(_))),
            "an empty listing yields no convention reading"
        );
    }

    #[tokio::test]
    async fn an_esp_spelled_listing_yields_no_x64_reading() {
        // The families never cross-fire from either side: a 32-bit
        // listing spelling the x64 shape's features — a 0x28 sub, an
        // argument register, no cleanup — keys the x86 family, which
        // reads no discipline in it, and the x64 family never fires.
        let mut program = program();
        program.listings.insert(
            "FUN_18003e750".into(),
            "00401000  SUB ESP, 0x28\n\
             00401007  MOV [ESP], RCX\n\
             0040100a  CALL FUN_18003ab00\n\
             0040100f  RET"
                .into(),
        );
        let result = scan(program).await;

        assert!(
            result
                .inferences
                .iter()
                .all(|inference| !matches!(inference, InferredType::Convention(_))),
            "a 32-bit-spelled listing never yields a 64-bit reading"
        );
    }

    // ---- cross-function convention corroboration (issue #249) ----

    /// A canned program: a `@12`-decorated function whose epilogue pops
    /// the twelve bytes its name declares, and one esp-spelled caller
    /// that calls it and cleans up after the site however the test asks.
    fn corroborated_program(caller_cleanup: bool) -> FakeProgram {
        let mut program = FakeProgram::empty();
        program.listing = vec![summary("paint@12"), summary("FUN_caller")];
        program.bodies.insert(
            "paint@12".into(),
            function("paint@12", "undefined paint@12(void)", "  return;\n"),
        );
        program.bodies.insert(
            "FUN_caller".into(),
            function(
                "FUN_caller",
                "undefined FUN_caller(void)",
                "  paint@12();\n",
            ),
        );
        program.listings.insert(
            "paint@12".into(),
            "00401000  PUSH EBP\n\
             00401001  MOV EBP, ESP\n\
             00401007  POP EBP\n\
             00401008  RET 0xC"
                .into(),
        );
        program.listings.insert(
            "FUN_caller".into(),
            if caller_cleanup {
                "00401100  PUSH EBP\n\
                 00401103  CALL paint@12\n\
                 00401108  ADD ESP, 0xC\n\
                 0040110b  POP EBP\n\
                 0040110c  RET"
            } else {
                "00401100  PUSH EBP\n\
                 00401103  CALL paint@12\n\
                 00401108  POP EBP\n\
                 0040110c  RET"
            }
            .into(),
        );
        program
    }

    /// The per-function convention records naming one function — the
    /// records keyed by it with no callee — for counting that exactly
    /// one stands.
    fn own_convention_records(result: &TypeInferenceResult, function: &str) -> usize {
        result
            .inferences
            .iter()
            .filter(|inference| {
                matches!(inference, InferredType::Convention(record)
                    if record.function == function && record.callee.is_none())
            })
            .count()
    }

    /// The call-site view one caller carries of one callee.
    fn call_site_view<'a>(
        result: &'a TypeInferenceResult,
        caller: &str,
        callee: &str,
    ) -> Option<&'a InferredConvention> {
        result
            .inferences
            .iter()
            .find_map(|inference| match inference {
                InferredType::Convention(record)
                    if record.function == caller && record.callee.as_deref() == Some(callee) =>
                {
                    Some(record)
                }
                _ => None,
            })
    }

    #[tokio::test]
    async fn agreement_across_functions_resolves_above_the_strongest_single_reading() {
        // `paint@12` declares twelve argument bytes, its epilogue pops
        // exactly those, and its one caller cleans up after no site:
        // three spellings across functions agree, so the reading lands
        // above every single one — and the persisted record shows the
        // bump. The scan still reads each listing exactly once.
        let program = corroborated_program(false);
        let result = scan(program.clone()).await;

        let record = convention_finding(&result, "paint@12");
        assert_eq!(record.convention, CallingConvention::Stdcall);
        assert_eq!(record.method, InferenceMethod::CorroboratedConvention);
        assert_eq!(
            record.confidence,
            Confidence::new(92),
            "the agreement outranks the epilogue band and every single reading"
        );
        assert_eq!(
            record.evidence,
            "00401008  RET 0xC; no caller cleanup at FUN_caller; declared bytes @12 agrees"
        );
        assert_eq!(
            own_convention_records(&result, "paint@12"),
            1,
            "the corroborated reading replaces the single reading it agrees with, it does not join it"
        );

        // The caller's view of its callee matches the callee's surviving
        // record: same convention, same bumped confidence, keyed by the
        // caller and naming the callee, evidenced by the call row.
        let view = call_site_view(&result, "FUN_caller", "paint@12")
            .expect("a call-site convention record in the caller");
        assert_eq!(view.convention, CallingConvention::Stdcall);
        assert_eq!(view.method, InferenceMethod::CallSiteConvention);
        assert_eq!(view.confidence, Confidence::new(92));
        assert_eq!(view.evidence, "00401103  CALL paint@12");

        // No extra reads: the corroborator works over the listings the
        // walk already kept — one decompile and one listing read per
        // listed function, in listing order, and nothing more.
        assert_eq!(program.decompiled(), ["paint@12", "FUN_caller"]);
        assert_eq!(program.disassembled(), ["paint@12", "FUN_caller"]);
    }

    #[tokio::test]
    async fn a_disagreeing_caller_leaves_the_higher_reading_standing_alone() {
        // The same decorated callee, but its caller pops after the site:
        // the caller-cleanup reading (cdecl, 70) competes with the
        // epilogue reading (stdcall, 80) for the same function, nothing
        // is corroborated, and resolution leaves exactly one record —
        // the higher one. The caller's view matches that survivor.
        let program = corroborated_program(true);
        let result = scan(program.clone()).await;

        let record = convention_finding(&result, "paint@12");
        assert_eq!(record.convention, CallingConvention::Stdcall);
        assert_eq!(record.method, InferenceMethod::CalleeEpilogue);
        assert_eq!(record.confidence, Confidence::new(80));
        assert_eq!(
            own_convention_records(&result, "paint@12"),
            1,
            "a function keeps exactly one convention record"
        );

        let view = call_site_view(&result, "FUN_caller", "paint@12")
            .expect("the caller still carries its callee's surviving convention");
        assert_eq!(view.convention, CallingConvention::Stdcall);
        assert_eq!(view.confidence, Confidence::new(80));
    }

    #[tokio::test]
    async fn a_detected_convention_lands_a_view_in_every_caller_in_listing_order() {
        // One epilogue-read callee, two callers: each caller's listing
        // carries the view, keyed by the caller and naming the callee,
        // and the records follow listing order — twice over, the same
        // scan of the same program diffs cleanly.
        let mut program = corroborated_program(false);
        program.listing.push(summary("FUN_second"));
        program.bodies.insert(
            "FUN_second".into(),
            function(
                "FUN_second",
                "undefined FUN_second(void)",
                "  paint@12();\n",
            ),
        );
        program.listings.insert(
            "FUN_second".into(),
            "00401200  CALL paint@12\n00401205  RET".into(),
        );

        let one = scan(program.clone()).await;
        let two = scan(program).await;
        let views = |result: &TypeInferenceResult| -> Vec<(String, Option<String>)> {
            result
                .inferences
                .iter()
                .filter_map(|inference| match inference {
                    InferredType::Convention(record)
                        if record.method == InferenceMethod::CallSiteConvention =>
                    {
                        Some((record.function.clone(), record.callee.clone()))
                    }
                    _ => None,
                })
                .collect()
        };
        assert_eq!(
            views(&one),
            [
                ("FUN_caller".to_string(), Some("paint@12".to_string())),
                ("FUN_second".to_string(), Some("paint@12".to_string())),
            ],
            "one view per caller, in listing order, identical across scans"
        );
        assert_eq!(
            views(&one),
            views(&two),
            "two scans of one program diff cleanly"
        );
    }

    #[tokio::test]
    async fn corroborated_x64_shape_lands_above_its_tier_at_the_clean_sites() {
        // A callee's Microsoft-x64 shape reading, corroborated by a call
        // site in an rsp-spelled caller that pops nothing — its `add rsp`
        // frees exactly its own prologue allocation, the frame teardown
        // the convention itself emits — climbs above the shape-only tier.
        let mut program = FakeProgram::empty();
        program.listing = vec![summary("FUN_18003e750"), summary("FUN_18003ab00")];
        program.bodies.insert(
            "FUN_18003e750".into(),
            function(
                "FUN_18003e750",
                "undefined FUN_18003e750(void)",
                "  return;\n",
            ),
        );
        program.bodies.insert(
            "FUN_18003ab00".into(),
            function(
                "FUN_18003ab00",
                "undefined FUN_18003ab00(void)",
                "  FUN_18003e750();\n",
            ),
        );
        program.listings.insert(
            "FUN_18003e750".into(),
            "140001000  SUB RSP, 0x28\n\
             140001007  MOV [RSP+0x8], RCX\n\
             14000100c  RET"
                .into(),
        );
        program.listings.insert(
            "FUN_18003ab00".into(),
            "140002000  SUB RSP, 0x28\n\
             140002007  MOV [RSP+0x8], RCX\n\
             14000200c  CALL FUN_18003e750\n\
             140002011  ADD RSP, 0x28\n\
             140002015  RET"
                .into(),
        );
        let result = scan(program).await;

        let record = convention_finding(&result, "FUN_18003e750");
        assert_eq!(record.convention, CallingConvention::MicrosoftX64);
        assert_eq!(record.method, InferenceMethod::CorroboratedConvention);
        assert_eq!(record.confidence, Confidence::new(75));
        assert_eq!(
            record.evidence,
            "140001000  SUB RSP, 0x28; no caller cleanup at FUN_18003ab00"
        );
        assert_eq!(own_convention_records(&result, "FUN_18003e750"), 1);

        let view = call_site_view(&result, "FUN_18003ab00", "FUN_18003e750")
            .expect("a call-site convention record in the caller");
        assert_eq!(view.convention, CallingConvention::MicrosoftX64);
        assert_eq!(view.confidence, Confidence::new(75));
    }

    #[tokio::test]
    async fn a_failing_listing_read_goes_unrecorded_and_never_moves_the_breaker() {
        // A listing read that fails, and one that answers empty, simply
        // leave their function unrecorded: the scan completes, the
        // failing function's body readings stand, and — the read is
        // not a decompile work item — two listing failures out of three
        // functions never move the skip-rate breaker's counts.
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
        program.fail_disassembly = vec!["FUN_18003ab00".into(), "FUN_18003e750".into()];
        // FUN_1800412a0 has no canned listing: its read answers empty.
        let result = scan(program.clone()).await;

        assert!(
            result
                .inferences
                .iter()
                .all(|inference| !matches!(inference, InferredType::Convention(_))),
            "failed and empty listing reads leave nothing recorded"
        );
        // The failing function's body readings are untouched.
        let this_ptr = finding(&result, "FUN_18003ab00", InferenceMethod::VtableCall, 0);
        assert!(matches!(this_ptr, InferredType::Param(_)));
        assert_eq!(
            program.disassembled(),
            ["FUN_18003ab00", "FUN_18003e750", "FUN_1800412a0"],
            "every listed function still gets its one read"
        );
        assert_eq!(
            program.decompiled(),
            ["FUN_18003ab00", "FUN_18003e750", "FUN_1800412a0"],
            "listing failures never move the decompile breaker's counts"
        );
    }
}
