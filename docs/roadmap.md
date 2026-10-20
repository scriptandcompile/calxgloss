# Calxgloss Roadmap — Methodology Tracks

> **Purpose:** index of all open tracks — status, dependencies, and what's
> next. This is the *roadmap*, not the plan of record for active work.
>
> **Where plans live:** when a track is picked up, its detailed plan is
> published to GitHub Issues (`scriptandcompile/calxgloss`) via `/to-spec` →
> `/to-tickets` (tickets carry native blocking links + triage labels), and the
> epic link is added to the status matrix below. `/implement` works the
> tickets; `CHANGELOG.md` stays the record of what shipped.
>
> **Where done tracks go:** a completed track is removed from this roadmap —
> its shipped history lives in `CHANGELOG.md` and its key decisions are
> recorded as ADRs in `docs/adr/` (W0 → ADR-0002, W1 → ADR-0003, W2 →
> ADR-0004, W3 → ADR-0005, W4 → ADR-0006, G1 → ADR-0007, X2 → ADR-0008,
> P1.5 → ADR-0009–0013, X5 → ADR-0041).

## How a track gets built

1. Pick the next unblocked track from the matrix (table order = priority).
2. `/to-spec` — synthesize the track summary here (plus its archive section)
   into a spec issue.
3. `/to-tickets` — decompose into tracer-bullet tickets with blocking edges;
   label `ready-for-agent`.
4. `/implement` — drive the tickets (tdd + code-review per ticket).
5. Update this matrix when a phase completes.

Test counts in the archive are indicative targets, not exact requirements.

## Status matrix

| # | Track | Crate | Effort | Status | Next step | Epic |
|---|-------|-------|--------|--------|-----------|------|
| P12.5 | Branch-targeted baseline tests — Verification must pin every branch the CFG reveals, not just the happy path | evidence (`calxgloss-controlflow`) + pipeline (`calxgloss-testgen`, `calxgloss-translator`) | — | ✅ done | — | [#224](https://github.com/scriptandcompile/calxgloss/issues/224) |
| P13.5 | Float/SIMD usage flagging — flag which functions do float/SIMD math and name the shape, so the LLM stops mistranslating mangled vector pseudo-C | evidence (`calxgloss-floatsimd` (new)) + integrations (`calxgloss-prompts`) + pipeline (`calxgloss-translator`) + interface (`calxgloss-cli`) | — | ⬜ not started | `/to-tickets` from #229 | [#229](https://github.com/scriptandcompile/calxgloss/issues/229) |
| P14 | Known-library function identification — body-signature matching against statically-linked CRT/STL code so those functions become Skip nodes, not translation units | evidence (`calxgloss-libmatch` (new), `calxgloss-analysis`) + integrations (`calxgloss-prompts`) + pipeline (`calxgloss-translator`) + interface (`calxgloss-cli`) | — | ⬜ not started | `/to-tickets` from #227 | [#227](https://github.com/scriptandcompile/calxgloss/issues/227) |
| P12.7 | Parameter direction analysis — read each pointer parameter as in/out/inout from the body so the Rust signature shape stops guessing and out-param capture becomes possible | evidence (`calxgloss-typeinfer`) + integrations (`calxgloss-prompts`) + pipeline (`calxgloss-translator`) + interface (`calxgloss-cli`) | — | ⬜ not started | `/to-tickets` from #228 | [#228](https://github.com/scriptandcompile/calxgloss/issues/228) |
| P15 | SEH and cleanup-on-failure idiom detection — name each function's error-handling idiom (SEH frame, RaiseException, goto-cleanup ladder) and the failure codes baseline tests must preserve | evidence (`calxgloss-errhandling` (new)) + integrations (`calxgloss-prompts`) + pipeline (`calxgloss-translator`) + interface (`calxgloss-cli`) | — | ⬜ not started | `/to-tickets` from #230 | [#230](https://github.com/scriptandcompile/calxgloss/issues/230) |
| P16 | Data-table recovery — reconstruct read-only constant data tables (game stats, opcode tables) as named Rust const arrays instead of scattered `DAT_*` reads | evidence (`calxgloss-consts`) + integrations (`calxgloss-prompts`) + pipeline (`calxgloss-translator`) + interface (`calxgloss-cli`) | — | ⬜ not started | `/to-tickets` from #231 | [#231](https://github.com/scriptandcompile/calxgloss/issues/231) |
| P17 | Decompiler-noise pre-filter — strip GS stack-canary code at the exit of the decompile read so prompts and evidence bodies stop paying for compiler guard code | integrations (`calxgloss-decomp`) | — | ⬜ not started | `/to-tickets` from #232 | [#232](https://github.com/scriptandcompile/calxgloss/issues/232) |
| P18 | Binary-version diffing (BinDiff-style) — pair functions across binary versions by structural similarity so accepted translations carry over and only changed functions re-enter the queue | evidence (`calxgloss-bdiff` (new)) + pipeline (`calxgloss-translator`, `calxgloss-git`) + interface (`calxgloss-cli`) | — | ⬜ not started | `/to-tickets` from #233 | [#233](https://github.com/scriptandcompile/calxgloss/issues/233) |

Legend: ✅ done · 🔶 in progress · ⬜ not started.

## P12.5 — Branch-targeted baseline tests (evidence + pipeline)

**Verification must pin every branch the decompiled body reveals, not just
the happy path.** Today's baseline suites are mined from CMP immediates and
signature-shaped values alone, so guards, error paths, loop exits, and
switch arms go untested and a mistranslation of any of them survives
*Verified*. `calxgloss-controlflow` gains a **branch inventory** reading: a
new per-function detector walks the crate's existing internal CFG (blocks,
taken/not-taken edges, back edges — the builder stays `pub(crate)`) and
emits one record per branch site — condition text, involved parameters,
operator and immediate when present, guarded-target kind (early return /
error path / loop exit / else arm / switch arm), confidence, evidence —
riding the tagged union, the engine's `with_*` builder, and the persistor
exactly as the switch, loop, and branch-density detectors do, over the
bodies the scan already keeps. A shape-only reading (branch exists,
predicate unreadable) claims only a null/zero probe, never a fabricated
boundary. `calxgloss-testgen`'s existing public `generate_test_inputs` seam
grows an inventory parameter — empty inventory is today's behavior exactly
— and emits one case per branch target (equality value, immediate ±1,
null/zero for null checks, one value per switch arm; uninvolved parameters
hold typical values), deduplicated against the boundary cases and capped
per function, lowest-confidence branch cases dropped first. The translator
already loads the control-flow findings for the prompt; the same loaded
findings feed generation — one source of truth for context and oracle, no
second load. Ground-truth capture is untouched: the cases flow through the
existing Wine baseline run, and the shared test-case schema does not change.
Spec: #224. Tickets: #258–#261 (blocking edges set; #258 — the branch
inventory detector — #259 — its prompt rendering — #260 — the testgen
seam that turns each inventory record into a baseline case — and #261 —
the pipeline wiring that feeds the loaded findings to generation — all
landed, closing the track).

## P13.5 — Float/SIMD usage flagging (evidence + integrations + pipeline + interface)

**Nothing detects float/SIMD use, yet the decompiler mangles vector math into
garbage pseudo-C** — `CONCAT44`, `SUB4`, undefined-typed arithmetic over `DAT_*`
loads — on `game_logic.dll`-style targets, so the LLM mistranslates it as
integer/pointer logic and every retry chases a phantom divergence. A new
evidence crate, `calxgloss-floatsimd`, reads only the bodies the scan already
keeps — no new engine reads, no dependency on #226 — and lands one flag record
per function naming the shape (scalar float math, vector/matrix idioms, or
both) with evidence lines and Evidence-scale confidence; the evidence families
are the decompiler's own float/double tokens, casts, and float literals, CRT
math import calls, the CONCAT/SUB vector assembly idioms, and parallel
same-operator reads over component-shaped variables, strongest family winning.
No cross-function pass and nothing written back to the program (ADR-0020); the
document persists per binary under the analysis-directory convention (ADR-0043)
as a new file, so every existing artifact loads unchanged. Consumers: a
FLOAT/SIMD findings section on the module-context and escalate prompts (the
control-flow-findings pattern, omitted when the function has no flag) and a CLI
breakdown command. The record's shape field is chosen so the follow-ups need no
re-derivation: testgen swapping integer boundary sampling for rounding/NaN
sampling on flagged functions, and disassembly corroboration (SSE/x87
mnemonics) once #226's disassembly-text method lands. Spec: #229. Tickets: not
yet filed (`/to-tickets`).

## P14 — Known-library function identification (evidence + integrations + pipeline + interface)

**Statically linked CRT/STL code enters the queue as ordinary units of work.**
The Skip consumer chain — translator stubbing, translation ordering,
call-graph stats — is fully built, yet `build_enriched_call_graph` only ever
assigns Root/Leaf/Middle: nothing produces Skip, so the LLM "translates"
`memcpy` and `std::map` trees and the corpus gains false translations. A new
evidence crate, `calxgloss-libmatch`, matches *body shape*: each kept
decompiled body is normalized — Ghidra variables, temporaries, and volatile
addresses to wildcards, calls/operators/constants/literals/control-flow
keywords preserved — and matched against a signature database of known
library functions, the body-shape counterpart to ADR-0012's name-shape
flagging. The signature file rides ADR-0023's pattern-database contract
whole: one strict serde document, entries are the pattern types' own shapes
with per-entry confidence, a supplied file replaces the hand-authored
built-in starter set (MSVC CRT memory/string routines, allocator wrappers,
container tree idioms) outright. Per-function readings land findings —
matched symbol, family, evidence lines, Evidence-scale confidence — and a
cross-function pass over the kept bodies propagates them to identical-body
duplicates (COMDAT folding/ICF) and tail-call thunks at a confidence penalty,
scan order preserved. The call graph's classification pass loads the
persisted document and assigns `NodeCategory::Skip` to functions whose best
match meets a confidence floor (80 on the evidence scale) before the
Root/Leaf/Middle cascade; below the floor nothing changes, and a missing or
corrupt document degrades to today's behavior exactly. The prompt gains a
findings section naming the target function's matched *callees* (the
hint-loader pattern, joined against call-graph neighbors) so the translator
maps those calls to Rust equivalents instead of re-implementing them.
Spec: #227. Tickets: not yet filed (`/to-tickets`).

## P12.7 — Parameter direction analysis (evidence + integrations + pipeline + interface)

**A pointer parameter's inferred type says what it is, not which way the data
flows.** The translator guesses `&` vs `&mut` vs a return value from the type
alone; a wrong guess compiles and then diverges at Verification because the
Rust version never writes the caller's buffer the original wrote — and the
baseline suite never sees the write, because the harness observes return
values only. The reading lives in `calxgloss-typeinfer` as a new domain
detector: per-function readings over the kept bodies classify each pointer
parameter **in**, **out**, or **inout** — writes through the pointer
(`*param =`, `param->f =`, `param[i] =`, the double-pointer `*param = &local`
idiom) are the out family, string-function and comparison reads the in
family, both sets make inout, an unknown-callee hand-off is evidence-neutral
— with evidence lines and Evidence-scale confidence; the detector adds no
reads at all, riding the body the scan already decompiles exactly once per
function (ADR-0026). Records join the existing type-inference artifact as a
fifth tagged union variant — old documents still load — keyed on (function,
parameter position), so a direction record coexists with a type record on the
same parameter and resolution keeps one direction per parameter (highest
wins, tie keeps first seen); this-pointer parameters are not excluded — a
constructor writing through `this` is legitimately inout; nothing is written
back to the program (ADR-0020). Consumers: a PARAMETER DIRECTIONS findings
section on the module-context prompt (the control-flow-findings pattern), the
existing type-info section of the retry prompts through the union's prompt
conversion, and the CLI inference listing. The record's key is chosen so the
follow-ups need no re-derivation: baseline tests capturing out-params as
expected side effects, and cross-function direction propagation on the
ADR-0014/0015 pattern. Spec: #228. Tickets: not yet filed (`/to-tickets`).

## P15 — SEH and cleanup-on-failure idiom detection (evidence + integrations + pipeline + interface)

**MSVC binaries protect themselves two very different ways, and neither
shape is visible to the translator.** SEH frames (`__try`/`__except`/
`__finally`, `RaiseException`, filter-registration APIs) get translated as
straight-line logic that drops the exception semantics, and the C
cleanup-on-failure idiom — a ladder of guarded early gotos converging on one
shared release block that returns a failure code — gets re-implemented as
nested conditionals, while the HRESULT/NTSTATUS codes the original returns
dissolve into ad-hoc Rust error values no baseline test pins. A new evidence
crate, `calxgloss-errhandling`, reads only the bodies the scan already keeps
— no new engine reads, no CFG dependency — and lands four finding families:
`SehFrame` (spelled-out `try`/`catch` blocks, named personality-handler
thunks, exception-API calls — strongest family wins), `RaiseException` (a
direct call, naming the literal code argument), `GotoCleanup` (two or more
guarded forward gotos converging on one label block that performs release
calls or a common constant return — a lone goto claims nothing), and
`ErrorCode` (per-function HRESULT/NTSTATUS literals from returns, guard
comparisons, and `RaiseException` arguments — BOOL-shaped 0/1 returns claim
nothing). A cross-function pass propagates error codes over the body-derived
call map (ADR-0024's rails): a caller comparing against or re-returning a
callee's code inherits it at a confidence penalty, scan order preserved,
first claim wins (ADR-0028's precedent); the idioms themselves are not
propagated. Nothing is written back to the program (ADR-0020); the document
persists per binary under the analysis-directory convention (ADR-0043) as a
new file, so every existing artifact loads unchanged. Consumers: an ERROR
HANDLING findings section on the module-context and escalate prompts (the
control-flow-findings pattern, omitted when the function has no findings)
naming the idiom, its Rust mapping (`Result` + early returns + scope guards
for ladders, an exception-mapped error type for SEH frames), and the
function's failure codes; and a CLI breakdown command. GS stack-canary
checks must not false-fire as SEH frames — stripping them is specced as the
P17 decompiler-noise pre-filter (#232). Spec: #230. Tickets: not yet filed
(`/to-tickets`).

## P16 — Data-table recovery (evidence + integrations + pipeline + interface)

**Read-only constant data tables survive decompilation as scattered `DAT_*`
reads, and the translator re-implements them as match arms over magic
numbers.** Game stats, opcode tables, and damage curves sit in `.rdata` as
uniform arrays the decompiler never types, while the two finished readings
each own half the problem: callback's jump-table reading names
function-pointer tables, consts' named constants and codegen cover scalars —
the array half falls between the owners. The reading lives in
`calxgloss-consts` as a new program-level detector, not a new crate: it
enumerates the program's defined data objects through the existing
`data_items` read, decodes each read-only, array-shaped object into a
uniform element type and entry count from raw bytes via the existing
`read_memory` read (typesdb's vtable reconstruction is the prior art), and
corroborates the decode against `DAT_x[idx]` reads in the kept bodies — all
reads already cached under ADR-0043, no new seam methods. The write gate is
absolute: any kept body storing through the symbol disqualifies it as
mutable global state (the shipped global-state reference sets already name
such writes); an all-pointer table belongs to
callback and claims nothing, and so does a mixed pointer/scalar table;
incoherent decodes at every stride claim nothing. Confidence families:
engine-applied array type highest, decode corroborated by an indexed read
high-mid, unreferenced clean decode low. One `DataTable` finding per table —
symbol, address, element type, count, values capped at 512 with a truncation
flag, referencing functions, evidence, Evidence-scale confidence — joins the
existing tagged union, so the persistor, the pre-batch
`ensure_const_detection` pass, the CLI report, and codegen carry it with
zero new wiring; codegen grows a pass emitting `pub const NAME: [T; N] =
[...]`. Consumers: a new DATA TABLES findings section on the module-context
prompt (the control-flow-findings pattern — the table shape matters on the
first attempt, and consts findings reach only escalate today) and the
escalate prompt's existing CONSTANTS section through the union's prompt
conversion. Nothing is written back to the program (ADR-0020). Spec: #231.
Tickets: not yet filed (`/to-tickets`).

## P17 — Decompiler-noise pre-filter (integrations)

**Every MSVC function carries the same /GS stack-canary prologue and
epilogue, and it rides into every prompt and every kept body as if it were
the function's own logic** — the LLM pays for it in every prompt that carries
pseudo-C and invents Rust panic scaffolding for a check that never fires
under baseline inputs, while each body-reading detector must build its own
private canary guard (P15 had to write one into its own spec). A pure text
filter in the seam crate applies at the exit of the `decompile` read in both
analysis sources — one filter at the highest seam the body text passes — so
the scan's kept bodies, the persisted function records feeding the
translation and retry prompts, the neighbor context on escalate prompts, and
every evidence reading see the canary idiom already stripped. The scan cache
still stores the engine's raw text (ADR-0043 untouched); the filter runs
after the cache read, so raw output stays on disk and the filter stays
reversible. Recognized families, the whole first cut: the prologue
cookie-save (a named cookie global XORed with a stack-pointer-shaped operand
into a local), the epilogue cookie-check (its `if` wrapper and
`__report_gsfailure`, or a direct `__security_check_cookie` call), and
standalone named guard calls (`__security_init_cookie`,
`__security_check_cookie`, `__report_gsfailure`). Only complete idioms
strip — a lone XOR, lone cookie read, or lone comparison claims nothing
(ADR-0038's precedent); a body that would empty strips nothing; a
cookie-shaped local left unreferenced goes with it; SEH/EH shapes pass
byte-for-byte (P15's territory). No findings, no new document, no schema
change, no write-back to the program (ADR-0020), no new engine reads
(ADR-0026); stripping rides a debug log naming the function and families.
Old records still load — the text is opaque to consumers. Spec: #232.
Tickets: not yet filed (`/to-tickets`).

## P18 — Binary-version diffing (BinDiff-style) (evidence + pipeline + interface)

**When the target updates, the harness treats the new version as a brand-new
target.** Function names are address-derived and addresses shift between
versions, so the (dll, function) join key — attempt branches, the review
queue, baseline suites — almost never matches across versions: every unit
re-enters the queue from zero, including functions whose bytes are identical,
and accepted merged translations are silently orphaned. A new evidence crate,
`calxgloss-bdiff`, runs a document-level pairing pass when a binary's bytes
change: the scan cache keys on identity + SHA-256 of the file bytes (ADR-0043),
so the previous version's scan document is already on disk, and the pass reads
only the two cached scan documents — no new seam methods (ADR-0026), no
write-back (ADR-0020), no LLM. Pairing is a strongest-wins ladder: name
identity (exported/demangled exact match, 95), normalized-body structural
equivalence (the pseudo-C normalization P14's spec describes — one shared
normalizer, whichever track lands first owns it), and call-graph topology
propagation over already-paired neighbors (ADR-0024's rails; 70, two paired
neighbors required, a lone paired neighbor claims nothing; corroboration bumps
beat any single reading). Pairings are one-to-one — best wins, ties keep first
seen in scan order (ADR-0028's precedent) — and one pairing document per
(identity, old hash, new hash) persists under the analysis-directory convention
(ADR-0043) as a new file, so every existing artifact loads unchanged. Consumer:
the auto run's queue — a new function paired at ≥80 to an old function with a
merged branch gets its first attempt seeded from the accepted translation (a
standard attempt branch under the new name, pre-populated with the accepted
code) and verification re-runs against the new version's freshly captured
baseline — the translation carries, the ground truth does not; below-floor or
unpaired functions queue fresh, today's behavior exactly. A CLI breakdown
command lists pairs, scores, families, and one-sided-only functions. The
record shape — (function, function, confidence, family, evidence) — is chosen
so the sibling-seeding follow-up (seeding a machine attempt from a
near-identical accepted sibling within one scan) needs no re-derivation.
Spec: #233. Tickets: not yet filed (`/to-tickets`).
