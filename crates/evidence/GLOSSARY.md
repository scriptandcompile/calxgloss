# Evidence

The extraction side of the reverse-engineering effort: evidence engines read the loaded program and record what they find — classification, types, algorithms, memory, concurrency, callbacks, strings, constants — before any translation work is planned or prompted. This context owns the language of reading a program: scans, readings, confidence, passes, and coverage.

## Language

### Engines and their documents

**Evidence engine**:
One of the fifteen whole-binary analyzers whose findings plan and prompt translation — *type-database*, *type-inference*, *algorithm-recognition*, *memory-lifecycle*, *known-library*, *concurrency*, *global-state*, *constants*, *callback-detection*, *control-flow*, *string-context*, *library-api*, *serialization*, *error-handling*, *float-simd* — plus three readers without a scan row: classification, the call graph, and cross-version pairing.
_Avoid_: bare "engine" — *the analysis engine* is Kuna at the seam, Integrations' word.

**Scan**:
One evidence engine's single pass over the whole loaded program, and the record it leaves.
_Avoid_: sweep; "run" belongs to Pipeline.

**Scan row name**:
An evidence engine's canonical name — the identity carried in the pipeline's scan table, in coverage records, and (prospectively) in cache keys.
_Avoid_: the crate name or CLI name as the identity; every engine has several spellings, the row name outranks them.

**Per-binary document**:
One evidence engine's persisted findings about one target binary.
_Avoid_: per-DLL database (say it only where the unit really is a DLL), output file.

**Persistor**:
One evidence engine's own store, owning where its document lives and how it is saved; missing and corrupt stay distinguishable.

### Readings and their products

**Reading**:
The atomic act — and product — of deriving a fact from one body, symbol, or listing. Every reading is a hypothesis, never a program fact.

**Finding**:
One evidence engine's persisted observation about one function or site; the umbrella word.
_Avoid_: as product nouns — hint, record, match: engine-local names for findings.

**Claim**:
What a reading asserts; the unit that competes in resolution. At binary level, an inference composed from several readings (a format, a protocol message, a platform divergence) — a lone reading composes nothing.

**Resolution**:
Per-scan merging that leaves exactly one finding per subject: the strongest confidence wins; equal confidence keeps what the scan surfaced first.
_Avoid_: dedup, conflict handling; *merge* is typesdb's named-type merge, a different pass.

**First-seen rule**:
The context-wide tiebreaker: on equal standing, the claim first surfaced in scan order wins — detector registration order is load-bearing configuration.

**Surviving reading**:
A reading that won resolution; only survivors feed later passes. An inference never becomes evidence in the same scan that inferred it.

### Confidence vocabulary

**Evidence confidence**:
The 0–100 trust carried by every finding and claim.
_Avoid_: bare "confidence" — unit confidence is Pipeline's; *tier* is reserved for context tiers.

**Confidence band**:
A score anchored to a reading type — the decompiler's spelled frame outscores a name shape.

**Confidence ladder**:
A per-engine ordering of its bands; corroboration always ranks above the single signals that fed it.
_Avoid_: rung, tier.

**Corroboration**:
Independent readings agreeing with one another; only corroborated readings reach an engine's top band.

**Confidence penalty**:
A deduction marking second-hand evidence — an inherited failure code, a tail-call match; the penalty never outranks the first-hand reading it came from.
_Avoid_: unscoped use — the penalty is engine-scoped, with its own magnitude.

**Floor**:
An engine's minimum-confidence cutoff, applied after resolution, below which findings are not persisted.
_Avoid_: threshold; the write-back floor is a separate cutoff with its own default.

### Scan mechanics

**Per-function pass**:
The scan's walk down the function listing, decompiling each function exactly once and running inline detectors over each body as it arrives.
_Avoid_: inline window, per-function walk, single-pass scan.

**Exactly-once decompile**:
The pinned contract that every pass adds zero engine round-trips: any body a later pass reads is one the scan already paid for.

**Kept bodies**:
The bodies the per-function pass holds for the scan's duration — the substrate every cross-function pass reads at no extra engine cost.
_Avoid_: collected bodies; not the caller-body cache.

**Caller-body cache**:
The per-scan cache of caller bodies behind caller↔callee propagation, failures cached too; one lookup serves both directions.

**Call map**:
Call edges derived by scanning kept bodies for the program's own function names.
_Avoid_: call graph — that is the program-level structure that orders translation work.

**Call graph**:
The program-level who-calls-whom structure — roots, leaves, translation order — that decides what gets translated and when.

**Cross-function pass**:
A pass after the per-function loop that relates two or more functions, over kept bodies and the call map, with no new engine reads.
_Avoid_: post-loop pass.

**Post-inline pass**:
A pass that runs after inline resolution, so its inputs are surviving readings rather than raw detector output.

**Post-assembly pass**:
A pure pass over the final record list once every recovery scan has assembled — nesting and flagging ride here.

**Skip-rate breaker**:
A scan's fuse, shared across its concurrent decompiles: more than half of the listing failing to decompile aborts the scan rather than persisting a phantom-clean record. It is the signature of a wrong program.
_Avoid_: wrong-program guard — the retired seam-side mechanism it replaced.

**Scan order**:
Persisted findings follow the function listing, per-function findings before cross-function ones; two scans of one program diff cleanly.

### Coverage honesty

**Facet**:
An evidence engine's declared read surface — function bodies, import table, machine listings, and the rest. Coverage answers stay inside the declared set; a roster test pins each engine's declaration.

**Scan coverage**:
A scan's own record of how much it could read, stamped at scan time beside its provenance. Nothing downstream recomputes it.

**Admission line**:
A plain sentence, per facet, of what fell short — rendered beside the findings it qualifies.

**Unknown, never absent**:
A document with no coverage record reads as unknown: never *complete*, never an error. Silence about a finding means *unknown*, never *not there*.

**Never render alike**:
Empty findings under complete coverage and empty findings under an admission line must never render the same — unknown and falling-short never present as complete.

### Write-back

**Write-back**:
Applying scan records into the loaded program — named types, prototypes, locals — through the seam. The seam side of the word is Integrations'.
_Avoid_: annotation write-back.

**No-write-back doctrine**:
Not every finding is writable: directions and idioms ride prompts and review only; and the scan never overrules a hand-typed slot — it narrows only undefined slots, in program order.

### Classification and parking

**Classification**:
Deciding what kind of target binary this is, which decides whether and how it is translated.

**Classification precedence**:
The operator's override outranks PE facts, which outrank every name-table heuristic.

**Managed PE**:
A binary that declares the .NET runtime header — a fact about the file, not a guess. Never translated.

**Parking**:
The resting state of a do-not-translate target binary: held out of active work yet kept visible in the queue, never deleted, its reason carried into every unit's known gaps.
_Avoid_: skip — Pipeline's per-function exclusion is a different act; rejected.

### Engine-specific language

**Flag-only**:
A signal too weak to act on, strong enough to mark: the record is annotated, never dropped or rewritten.

**Named type** *(typesdb)*:
A type the program itself stores, recovered from its embedded type information.
_Avoid_: conflating with an inferred candidate.

**Inferred candidate** *(typesdb)*:
A struct hypothesis clustered from the string literals its readers share; confidence-scored, never a fact.

**Name origin** *(typesdb)*:
Where a recovered name came from — vtable class over literal prefix over function stem over bare address — the stronger origin paying higher confidence.

**Nesting** *(typesdb)*:
Linking a struct field to a recovered named type by exact name only; ambiguous names stay unlinked.

**Flagging** *(typesdb)*:
Marking recovered types whose name *shape* matches a known library family (STL/MFC) — name shape, not layout, and flag-only.

**Known-signature database** *(typeinfer)*:
Hardcoded contracts of known library routines — what they take and return.
_Avoid_: confusing it with the pattern database or the signature database; all three replace their built-ins whole, never merge.

**Parameter direction** *(typeinfer)*:
Which way data flows through a pointer parameter — in, out, or both; a fact separate from, and coexisting with, its type.

**Out evidence** *(typeinfer)*:
Writing *through* the pointer — directly, through a field, or by index — which establishes a parameter as *out*; read-only bodies make the *in* family, and both together make *inout*.

**Mangling** *(typeinfer)*:
A machine-readable naming convention some compilers leave in symbols, which types its function even when the body never decompiles.

**Integer bit-pattern** *(typeinfer)*:
Operator shapes — shifts, masked tests against a non-zero constant — that reveal an operand's width; a test against zero reads nothing.

**Pattern database** *(algorithm)*:
One supplied file that is exactly what the algorithm scan knows: a supplied database replaces the built-in sets whole, never merges.
_Avoid_: confusing it with the signature database (libmatch) or the known-signature database (typeinfer) — three "databases", one whole-replacement contract

**Correlation detector** *(algorithm)*:
The algorithm scan's cross-function pass: multi-function algorithm claims read off the call map — divide-and-conquer, comparison sort.
_Avoid_: "correlation key" — ADR-0024's title is subject plus verb; there is no such noun.

**Callback contract** *(algorithm)*:
A comparator/caller shape the host's API demands (qsort's compare function); a contract the call graph itself confirms names the host's demand rather than inferring it.

**Closure contract** *(callback)*:
The signature a callback carries that no single body spells; the callback scan receives it by injection from type-inference records — at scan time, never at prompt time.

**Registration site / chain** *(callback)*:
A call to a configured registration name with a callback bound; a chain links a registration to a partner body's direct call or table dispatch.

**Allocation pair** *(memory)*:
An allocation and its matching release inside one body; the engine stays silent on what never pairs.

**Open allocation** *(memory)*:
What the pairing walk leaves unpaired — the seam pair, transfer, and leak readings share, so they can never disagree about what stands open.

**Escape** *(memory)*:
Any hand-off of a whole block to somewhere else; it doubles as the leak's false-positive gate.

**Leak** *(memory)*:
The cross-function pass's silence case: an open allocation with neither pair nor escape.

**Transfer** *(memory)*:
A whole-block ownership hand-off across a call boundary — into a callee or back to a caller.

**Keep** *(memory)*:
A callee storing its parameter outside its own frame — the reading that turns a box into a shared handle.

**Handle pairing** *(memory)*:
An opener/closer pair over a non-memory resource; the type comes from the body's own declaration.

**Lock order** *(sync)*:
Two functions acquiring the same two locks in opposite relative orders — a deadlock claim, one per conflicting pair.

**Protected span** *(sync)*:
A recognized acquire→release pairing over one lock; the *same-lock rule* is the data race's false-positive gate — one lock covering every access in both bodies suppresses the claim.

**Divergence reading** *(apidetect)*:
A binary-level portability claim gated on imports from both platform families; platform-neutral categories count on neither side.

**Failure code** *(errhandling)*:
A named constant a function returns, raises, or guards on — the failure contract named without reading the body.

**Inherited code** *(errhandling)*:
A caller guarding on, or re-returning, a callee's recorded failure codes; codes travel the call map one hop — idioms never travel, and inheritance pays the confidence penalty.

**Body signature** *(libmatch)*:
A library function's shape with decompiler noise normalized away — body shape, not bytes; it never touches flagging's name-shape records. Its store is the *signature database* — second of the three databases (see pattern database, known-signature database); all three replace their built-ins whole, never merge.

**Global site** *(globalstate)*:
An identifier read or written as program data rather than as a function's own local; the single shared rule consumed by the data-race readings too.

**Pairing** *(bdiff)*:
Matching functions across two scans of one binary after a change — telling "same function, new address" from "changed" from "genuinely new"; address equality alone claims nothing.
