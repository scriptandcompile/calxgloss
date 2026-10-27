# Evidence

The extraction side of the reverse-engineering effort: evidence engines read the loaded program and record what they find — classification, types, algorithms, memory, concurrency, callbacks, strings, constants — before any translation work is planned or prompted. This context owns the language of reading a program: scans, readings, confidence, passes, and coverage.

## Language

### Engines and their documents

**Evidence engine**:
One of the fifteen whole-binary analyzers whose findings are used to plan and build the prompts for translation — *type-database*, *type-inference*, *algorithm-recognition*, *memory-lifecycle*, *known-library*, *concurrency*, *global-state*, *constants*, *callback-detection*, *control-flow*, *string-context*, *library-api*, *serialization*, *error-handling*, *float-simd*. Three more engines are readers with no scan row: classification, the call graph, and cross-version pairing.
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
One evidence engine's own store. It owns where that engine's document lives and how it is saved. A missing document and a corrupt document stay two different conditions.

### Readings and their products

**Reading**:
The atomic act of deriving a fact from one body, symbol, or listing — and the product of that act. Every reading is a hypothesis, never a program fact.

**Finding**:
One evidence engine's persisted observation about one function or site; the umbrella word.
_Avoid_: as product nouns — hint, record, match: engine-local names for findings.

**Claim**:
What a reading asserts; the unit that competes in resolution. At binary level, a claim is an inference composed from several readings — a format, a protocol message, a platform divergence. A lone reading composes nothing.

**Resolution**:
Per-scan merging that leaves exactly one finding per subject. The finding with the strongest confidence wins. If confidences are equal, the finding the scan surfaced first is kept.
_Avoid_: dedup, conflict handling; *merge* is typesdb's named-type merge, a different pass.

**First-seen rule**:
The context-wide tiebreaker: on equal standing, the claim first surfaced in scan order wins. Detector registration order is therefore configuration that behavior depends on.

**Surviving reading**:
A reading that won resolution. Only survivors are used by later passes. An inference never becomes evidence in the same scan that inferred it.

### Confidence vocabulary

**Evidence confidence**:
The 0–100 trust carried by every finding and claim.
_Avoid_: bare "confidence" — unit confidence is Pipeline's; *tier* is reserved for context tiers.

**Confidence band**:
A score anchored to a reading type. For example, a decompiler's spelled frame scores higher than a name shape.

**Confidence ladder**:
A per-engine ordering of its bands. A corroborated reading always ranks higher than the single signals that produced it.
_Avoid_: rung, tier.

**Corroboration**:
Independent readings agreeing with one another; only corroborated readings reach an engine's top band.

**Confidence penalty**:
A deduction marking second-hand evidence — an inherited failure code, a tail-call match. The penalty never scores higher than the first-hand reading it came from.
_Avoid_: unscoped use — the penalty is engine-scoped, with its own magnitude.

**Floor**:
An engine's minimum-confidence cutoff, applied after resolution. Findings below the floor are not persisted.
_Avoid_: threshold; the write-back floor is a separate cutoff with its own default.

### Scan mechanics

**Per-function pass**:
The scan's walk down the function listing, decompiling each function exactly once and running inline detectors over each body as it arrives.
_Avoid_: inline window, per-function walk, single-pass scan.

**Exactly-once decompile**:
The pinned contract that every pass adds zero engine round-trips. Any body a later pass reads is one the scan already decompiled.

**Kept bodies**:
The bodies the per-function pass holds for the scan's duration. Every cross-function pass reads from them, at no extra engine cost.
_Avoid_: collected bodies; not the caller-body cache.

**Caller-body cache**:
The per-scan cache of caller bodies behind caller↔callee propagation. Failed lookups are cached too. One lookup serves both directions.

**Call map**:
Call edges derived by scanning kept bodies for the program's own function names.
_Avoid_: call graph — that is the program-level structure that orders translation work.

**Call graph**:
The program-level who-calls-whom structure — roots, leaves, translation order — that decides what gets translated and when.

**Cross-function pass**:
A pass after the per-function loop that relates two or more functions, over kept bodies and the call map, with no new engine reads.
_Avoid_: post-loop pass.

**Post-inline pass**:
A pass that runs after inline resolution. Its inputs are therefore surviving readings, not raw detector output.

**Post-assembly pass**:
A pure pass over the final record list, run once every recovery scan has assembled. Nesting and flagging run here.

**Skip-rate breaker**:
A scan's fuse, shared across its concurrent decompiles: if more than half of the function listing fails to decompile, the scan aborts rather than persisting a record that looks clean but is not. A high skip rate is the signature of a wrong program.
_Avoid_: wrong-program guard — the retired seam-side mechanism it replaced.

**Scan order**:
Persisted findings follow the function listing, with per-function findings before cross-function ones. Two scans of one program therefore diff cleanly.

### Coverage honesty

**Facet**:
An evidence engine's declared read surface — function bodies, import table, machine listings, and the rest. Coverage answers stay inside the declared set; a roster test pins each engine's declaration.

**Scan coverage**:
A scan's own record of how much it could read. It is written at scan time, beside the scan's provenance. Nothing downstream recomputes it.

**Admission line**:
A plain sentence, per facet, saying what fell short. It is rendered beside the findings it qualifies.

**Unknown, never absent**:
A document with no coverage record reads as unknown: never *complete*, never an error. Silence about a finding means *unknown*, never *not there*.

**Never render alike**:
Empty findings under complete coverage and empty findings under an admission line must never render the same — unknown and falling-short never present as complete.

### Write-back

**Write-back**:
Applying scan records into the loaded program — named types, prototypes, locals — through the seam. The use of this word on the seam side belongs to Integrations.
_Avoid_: annotation write-back.

**No-write-back doctrine**:
Not every finding is writable. Directions and idioms reach people only through prompts and review. And the scan never overrules a slot a human typed by hand: it narrows only undefined slots, in program order.

### Classification and parking

**Classification**:
Deciding what kind of target binary this is, which decides whether and how it is translated.

**Classification precedence**:
The operator's override outranks PE facts, which outrank every name-table heuristic.

**Managed PE**:
A binary whose file declares the .NET runtime header — a fact about the file, not a guess. It is never translated.

**Parking**:
The resting state of a do-not-translate target binary. The binary is held out of active work but kept visible in the queue, and it is never deleted. Its reason is carried into every unit's known gaps.
_Avoid_: skip — Pipeline's per-function exclusion is a different act; rejected.

### Engine-specific language

**Flag-only**:
A signal too weak to act on, but strong enough to mark. The record is annotated, never dropped or rewritten.

**Named type** *(typesdb)*:
A type the program itself stores, recovered from its embedded type information.
_Avoid_: conflating with an inferred candidate.

**Inferred candidate** *(typesdb)*:
A struct hypothesis clustered from the string literals its readers share. It is confidence-scored, never a fact.

**Name origin** *(typesdb)*:
Where a recovered name came from. From strongest to weakest: vtable class, then literal prefix, then function stem, then bare address. A stronger origin carries higher confidence.

**Nesting** *(typesdb)*:
Linking a struct field to a recovered named type by exact name only; ambiguous names stay unlinked.

**Flagging** *(typesdb)*:
Marking recovered types whose name *shape* matches a known library family (STL/MFC). Only the name shape counts, not the layout, and the result is flag-only.

**Known-signature database** *(typeinfer)*:
Hardcoded contracts of known library routines — what they take and return.
_Avoid_: confusing it with the pattern database or the signature database; all three replace their built-ins whole, never merge.

**Parameter direction** *(typeinfer)*:
Which way data flows through a pointer parameter: in, out, or both. It is a separate fact from the parameter's type, and the two coexist.

**Out evidence** *(typeinfer)*:
Writing *through* the pointer — directly, through a field, or by index. This makes the parameter *out*. Read-only bodies make the *in* family, and both together make *inout*.

**Mangling** *(typeinfer)*:
A machine-readable naming convention some compilers leave in symbols. It identifies a function's types even when the body never decompiles.

**Integer bit-pattern** *(typeinfer)*:
Operator shapes that reveal an operand's width — shifts, and masked tests against a non-zero constant. A test against zero reveals nothing.

**Pattern database** *(algorithm)*:
One supplied file that is exactly what the algorithm scan knows: a supplied database replaces the built-in sets whole, never merges.
_Avoid_: confusing it with the signature database (libmatch) or the known-signature database (typeinfer) — three "databases", one whole-replacement contract

**Correlation detector** *(algorithm)*:
The algorithm scan's cross-function pass. It reads multi-function algorithm claims from the call map — for example, divide-and-conquer or a comparison sort.
_Avoid_: "correlation key" — ADR-0024's title is subject plus verb; there is no such noun.

**Callback contract** *(algorithm)*:
A comparator/caller shape that the host's API demands (qsort's compare function). If the call graph itself confirms the shape, that confirms the host's demand directly, rather than inferring it.

**Closure contract** *(callback)*:
The signature a callback carries that no single body spells out. The callback scan receives it by injection from type-inference records. This happens at scan time, never at prompt time.

**Registration site / chain** *(callback)*:
A call to a configured registration name with a callback bound. A chain links one such registration to a direct call or table dispatch in a partner body.

**Allocation pair** *(memory)*:
An allocation and its matching release inside one body; the engine stays silent on what never pairs.

**Open allocation** *(memory)*:
What the pairing walk leaves unpaired. The seam-pair, transfer, and leak readings all use this one shared result, so they can never disagree about what stands open.

**Escape** *(memory)*:
Any hand-off of a whole block to somewhere else; it doubles as the leak's false-positive gate.

**Leak** *(memory)*:
The cross-function pass's silence case: an open allocation with neither pair nor escape.

**Transfer** *(memory)*:
A whole-block ownership hand-off across a call boundary — into a callee or back to a caller.

**Keep** *(memory)*:
A callee storing its parameter outside its own frame. This is the reading that makes a box a shared handle.

**Handle pairing** *(memory)*:
An opener/closer pair over a non-memory resource; the type comes from the body's own declaration.

**Lock order** *(sync)*:
Two functions acquiring the same two locks in opposite relative orders. This makes a deadlock claim — one claim per conflicting pair.

**Protected span** *(sync)*:
A recognized acquire→release pairing over one lock. The *same-lock rule* is the data race's false-positive gate: if one lock covers every access in both bodies, the claim is suppressed.

**Divergence reading** *(apidetect)*:
A binary-level portability claim that requires imports from both platform families before it can be made. Platform-neutral categories count toward neither side.

**Failure code** *(errhandling)*:
A named constant a function returns, raises, or guards on. It names the failure contract without reading the body.

**Inherited code** *(errhandling)*:
A caller guarding on, or re-returning, a callee's recorded failure codes. Codes travel the call map one hop. Idioms never travel. Inheritance pays the confidence penalty.

**Body signature** *(libmatch)*:
A library function's shape with decompiler noise normalized away — body shape, not bytes. It never touches flagging's name-shape records. Its store is the *signature database* — second of the three databases (see pattern database, known-signature database); all three replace their built-ins whole, never merge.

**Global site** *(globalstate)*:
An identifier read or written as program data rather than as a function's own local. The same single rule is also used by the data-race readings.

**Pairing** *(bdiff)*:
Matching functions across two scans of one binary after a change. It tells apart "same function, new address", "changed", and "genuinely new". Address equality alone claims nothing.
