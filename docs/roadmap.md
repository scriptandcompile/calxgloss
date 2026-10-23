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
| P13.5 | Float/SIMD usage flagging — flag which functions do float/SIMD math and name the shape, so the LLM stops mistranslating mangled vector pseudo-C | evidence (`calxgloss-floatsimd` (new)) + integrations (`calxgloss-prompts`) + pipeline (`calxgloss-translator`) + interface (`calxgloss-cli`) | — | ⬜ not started | `/to-tickets` from #229 | [#229](https://github.com/scriptandcompile/calxgloss/issues/229) |
| P15 | SEH and cleanup-on-failure idiom detection — name each function's error-handling idiom (SEH frame, RaiseException, goto-cleanup ladder) and the failure codes baseline tests must preserve | evidence (`calxgloss-errhandling` (new)) + integrations (`calxgloss-prompts`) + pipeline (`calxgloss-translator`) + interface (`calxgloss-cli`) | — | ⬜ not started | `/to-tickets` from #230 | [#230](https://github.com/scriptandcompile/calxgloss/issues/230) |
| P16 | Data-table recovery — reconstruct read-only constant data tables (game stats, opcode tables) as named Rust const arrays instead of scattered `DAT_*` reads | evidence (`calxgloss-consts`) + integrations (`calxgloss-prompts`) + pipeline (`calxgloss-translator`) + interface (`calxgloss-cli`) | — | 🔶 in progress | #279–#282 | [#231](https://github.com/scriptandcompile/calxgloss/issues/231) |
| P18 | Binary-version diffing (BinDiff-style) — pair functions across binary versions by structural similarity so accepted translations carry over and only changed functions re-enter the queue | evidence (`calxgloss-bdiff` (new)) + pipeline (`calxgloss-translator`, `calxgloss-git`) + interface (`calxgloss-cli`) | — | ⬜ not started | `/to-tickets` from #233 | [#233](https://github.com/scriptandcompile/calxgloss/issues/233) |

Legend: ✅ done · 🔶 in progress · ⬜ not started.

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
sampling on flagged functions, and disassembly corroboration against SSE/x87
mnemonics — unblocked now, since #226 landed its machine-listing reads with
P12.6. Spec: #229. Tickets: not yet filed (`/to-tickets`).

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
function's failure codes; and a CLI breakdown command. GS stack-canary code
is already stripped from the bodies this scan reads by the shipped
decompiler-noise pre-filter (#232, #271–#273), so the canary-false-fire gate
is redundant insurance against a filter miss, not a load-bearing guard.
Spec: #230. Tickets: not yet filed (`/to-tickets`).

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
Tickets: #278–#282 (#278 landed, #279–#282 open).

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
equivalence (riding the shared normalizer P14/#227 shipped and now owns —
`calxgloss-libmatch`'s `normalize` module), and call-graph topology
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
