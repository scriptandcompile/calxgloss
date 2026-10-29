# KRAKEN's rewrite pipeline — binary → verified Rust end to end, and the calxgloss head-to-head

> Part of the [KRAKEN overview](README.md). context: rewrite. Companion:
> [10-calxgloss-baseline](10-calxgloss-baseline.md). This is the mission
> chapter: KRAKEN's stated long-term goal — Rust rewrites of binaries,
> function by function, checked against the original — lives in one crate,
> `kraken-rewrite`, and this file walks it end to end, then compares it with
> calxgloss's translation pipeline axis by axis. The verdict table at the end
> is what the README's capability matrix takes as given.

Chapters 31–35 supply the ground this one stands on: the engine seam and
decompile text (31), the project database and annotations (32), the command
registry and jobs (33), the assistant backends and AI cost board (34), and
`kraken-emu` / `kraken-confine`, the emulator and OS confinement the oracle
runs inside (35). The rewrite pipeline is what those layers were ultimately
built for.

## What the crate is

`crates/kraken-rewrite` is 20,776 lines of `src/` (30,175 including tests) —
by itself as large as most of the calxgloss pipeline crates combined. Ten
registry commands drive it: `rewrite_plan`, `rewrite_status`, `rewrite_unit`,
`rewrite_function`, `rewrite_accept`, `rewrite_spec`, `rewrite_export`,
`rewrite_program`, `rewrite_program_status`, `rewrite_build`
(`crates/kraken-registry/src/commands/rewrite.rs:204, 352, 497, 634, 731, 823,
940`; `rewrite_program.rs`; `rewrite_build.rs`). The design doc behind it is
design 0013, `docs/design/0013-rewrite-pipeline.md` (259 lines), the user
guide is `docs/rewrite.md`, and the pre-design spike is
`spikes/rewrite-loop/NOTES.md`. Every verdict records the oracle that produced
it, pinned: `EMULATOR_PIN = "icicle-emu@638508b7…"` and `ORACLE_KIND =
"icicle-emu/x86-64-sleigh"` (`crates/kraken-rewrite/src/lib.rs:118-119`).
The spike notes record why: Unicorn was rejected because GPL-2.0-only cannot
combine with the project's GPL-3.0-or-later; icicle-emu was chosen because it
is Rust, multi-arch, and executes Ghidra SLEIGH p-code, so the oracle shares
the decompiler's instruction semantics (spikes/rewrite-loop/NOTES.md:57-58).

Three modes share one spine: per-function rewriting (`rewrite_function`),
whole-program rewriting (`rewrite_program`), and the strangler export
(`rewrite_export`). A fourth, spec mode, asks the model for a behavioural
spec — Markdown with address citations — before the translation
(`crates/kraken-registry/src/commands/rewrite.rs:823`;
`crates/kraken-rewrite/src/service.rs:1557`).

## The unit, the store, the accept gate

The record of one translation is a `RewriteUnit`
(`crates/kraken-rewrite/src/unit.rs:130`): function anchor (program SHA-256 +
entry address), the model's Rust and its hash, the inferred ABI, the oracle
descriptor, provenance (author, provider, model, task, **prompt hash**), the
`source_decompile_hash` it was made from (`unit.rs:149`), a `RepairLink` when
it answers a failed attempt (`unit.rs:175`), and the verdict. Status follows
verdict mechanically — pass → `verified`, fail → `failed`, everything else →
`translated` (`unit.rs:184`); `accepted` is only ever a human act.

Everything persists in `<project>/rewrite.sqlite`, a versioned-migration
database owned by `kraken-rewrite`, deliberately **not** in the project's
edit-log database (docs/design/0013-rewrite-pipeline.md:194-198). Tables:
`units` (one row per function: status, newest and accepted version),
`unit_versions` (append-only — every attempt is a version, older versions
stay), `unit_repairs`, `observed_hashes` (newest decompile hash per function),
`test_cases`, `verdicts` (verdict, counts, seed, sandbox label,
counterexamples), `unit_events` (status transitions with the actor), the plan
ledger, specs, and `program_runs` (schema at
`crates/kraken-rewrite/src/store.rs:60-101, 162-174`). `put_unit` assigns
monotonic per-function versions (`store.rs:403`).

The accept gate is mechanical: `accept` refuses anything that is not
`verified` — "only a verified unit can be accepted" — and demotes the previous
accepted version back to `verified` (`store.rs:621-662`). Accepting is users
only: agents get a refusal (`docs/design/0013-rewrite-pipeline.md:86`), and
even the `accept_verified` auto-accept flag on `rewrite_program` is refused
from a non-user caller before the job starts
(`crates/kraken-registry/src/commands/rewrite_program.rs:417-421`).

Staleness is computed, not declared: every unit records the decompile hashes
of its own function and its callees, the store tracks the newest observed
hashes, and a version is stale when any hash it was made from moved —
"the function's decompile changed since this version was made", or a named
callee's did (`store.rs:1106-1128`). The plan ledger records each function's
order, SCC group, callees, direct imports, unstubbed imports and flags
(`store.rs:300, 323`); a function with a unit that the current plan no longer
lists is stale for that reason too.

## Planning: callee-first, groups, flags

`collect.rs:1-2` reads the call graph through the engine seam and classifies
what it finds: program functions, import thunks (external calls), compiler
glue — the latter two are skipped and counted (`skipped_imports`,
`skipped_runtime`, `store.rs:323`). `plan.rs` orders the rest with an
iterative Tarjan: **SCCs emitted callee-first, so a translation is always
asked for after everything it calls** (`plan.rs:4, 109`). Four plan flags ride
the graph: `NeedsStubs` (imports without an oracle stub, transitively),
`UsesGlobals`, `UsesSyscalls`, `Recursive` (`plan.rs:196-205`). Caps: 20 000
functions maximum per plan (`service.rs:55`; docs/design/0013-rewrite-pipeline.md:210
says 2 000 by default).

In program mode the plan is not the crate: a reachability closure decides what
is actually translated. Roots are `main` (or the address whose decompile names
it in `__libc_start_main`, `service_program.rs:283`) plus named static
initializers; the closure grows through direct calls, function pointers handed
around, and tables of function pointers in data that a reached function
refers to (`service_program.rs:455-521`). Unreachable planned functions get a
row with reason and nothing is translated for them
(`service_program.rs:573-582`).

## What the model is shown

The translation unit is deliberately thin: **the function's decompile plus up
to six of its direct callees' decompiles** (`service.rs:474-488`,
docs/design/0013-rewrite-pipeline.md:208), plus **layout notes** — struct
field-offset tables pulled from the engine's own type information, because a
model that guesses a layout from the decompile invents padding and fails whole
programs (`layouts.rs:1-8`; attached at `service.rs:1744-1759`). Layout notes
are trusted operator/engine text, unlike the decompile, which travels inside
`untrusted` blocks. In spec mode the model first writes a Markdown spec whose
every fact must carry an address citation `[@0x401136]`
(`task.rs:382, 419-425`); the reply validator checks every section is present,
every fact is cited, and every citation names a real address in the given text
(`task.rs:499` — "every citation known"). A spec is reused while the decompile
hashes of the function and its callees are unchanged
(docs/design/0013-rewrite-pipeline.md:209).

The translation request itself: sections (target, ABI, decompile, callees,
layout notes, spec, repair feedback), and the reply contract is the Rust
source inside `<kraken-rust>` tags plus one JSON `<kraken-result>` block
listing what the translation does not support (`task.rs:85-88, 136-137,
222-223`). Generation is fixed conservative: `max_tokens` 4096, temperature
0.1, "translation is not creative work" (`task.rs:31-40`). If a callee is
already **accepted**, the unit is not re-translated — it is imported as a
generated module named `__kr_callee_<address>`, nested through its own reused
callees up to depth 8 (`reuse.rs:58, 130`); the callee's recorded export
symbol and version are checked against what is accepted now
(`reuse.rs:229-276`).

## The translation loop: repair, lint, blame feedback

`repair.rs` is the bounded loop, and it is deliberately agnostic about
verification: the caller passes a closure that checks and stores one attempt
(`repair.rs:1-14`) — the same loop runs the sandboxed differential test for
`rewrite_function` and the compile-only check when the oracle cannot compare
(`service.rs:740, 770, 802, 822`; the `Check` seam at `service.rs:701-708`).
Defaults: 3 attempts, cap 8 (`repair.rs:27, 29`). Feedback is capped — 4 000
bytes of compiler output or counterexample, 16 000 bytes of previous code
(`repair.rs:31, 33`). Three kinds are repairable, each with its own feedback
text — `compile`, `rejected`, `counterexample` — and **`inconclusive` is never
repaired: "the model cannot fix what the oracle could not run"**
(docs/design/0013-rewrite-pipeline.md:43-47). Every attempt is a stored
version with a repair link naming the version it answers and the feedback kind
(`unit_repairs` at `store.rs:146-150`; design 0013:47 records the same).

Before anything is built, a `syn` allowlist lint screens the model's Rust:
functions/types/impls/use only, no `extern` blocks, no file modules, no
`macro_rules!`, formatting and assertion macros only, nothing from `std::fs`,
`std::net`, `std::env`, `std::os`, `std::thread`, `std::process` (except exit
and abort), and `std`/`core`/`alloc` cannot be aliased whole — with a 256 KiB
source cap (`lint.rs:1-17, 24`). The lint is explicitly "defence in depth: the
compile step and the runner are confined by `sandbox` whatever the lint says"
(`lint.rs:16-17`).

## The function-level differential test

This is the engine of the whole design: **the original function is run, live,
against the translation, on every verification**, not captured once and frozen.

- **The oracle** runs one function of the program under `kraken-emu` —
  SLEIGH p-code — as a bare CPU: ELF segments mapped, relocations applied,
  every import slot pointed at a stub address, a call set up per the target's
  C calling convention, return caught by a sentinel address; stubs are host
  breakpoints, never emulated (`oracle.rs:1-11, 21`). Notably, the code has
  overtaken the design doc: the oracle header lists x86-64, x86, ARM/Thumb,
  AArch64, RISC-V 64/32 with five conventions (`oracle.rs:4-8`), while design
  design 0013:211 still says "Only x86-64 ELF is run by the oracle." `kraken-emu` can
  *detect* a PE's architecture (`crates/kraken-emu/src/arch.rs:119, 137-146`)
  but its loader only parses ELF (`crates/kraken-emu/src/loader.rs:102`;
  `arch.rs:85-87` refuses non-ELF) — so PE arch is identifiable, PE calls are
  not checkable. Budgets: 5 M instructions, image load base
  0x5555_5555_4000 (`oracle.rs:187, 206-207`). The stubbed imports are the
  `STUBBED_IMPORTS` table (`oracle.rs:41`): stdio, string/memory basics, a
  bump `malloc`, math — with a modelled `printf` formatter and glibc ctype
  table so the oracle and a translation print a double alike
  (`clib.rs:1-9`). Anything else ends the case as unsupported.
- **Inputs are generated, not harvested** (design 0013:71): seeded edge/random
  integers, 64-byte random buffers, small pointer graphs, curated generators
  for corpus targets (`infer.rs:1-16`, `targets.rs:1-8`). Refusal is loud and
  pre-flight: the ABI must fit registers — at most six integer-class and eight
  SSE parameters (`abi.rs:58-61`) — or `rewrite_function` stops **before any
  model call** (design 0013:205).
- **The Rust side** compiles with `rustc` into a runner built with overflow
  checks on, then one confined process per case: a translation that calls
  `exit`, panics, overflows, loops or crashes is observed as that case ending
  badly, not as an error (`native.rs:1-5, 425`). Compilation, build and runs
  all go through `kraken-confine` re-exports — scrubbed env, Landlock
  read/write scopes, no network, rlimits (`sandbox.rs:1-8`).
- **Verdicts and counterexamples.** Defaults: fixed seed
  `0x4b52_414b_454e`, 200 random cases, at most 3 counterexamples
  (`difftest.rs:565-567`). Counterexamples are sorted by **input size**
  (`difftest.rs:767-775`) and truncated to three (`difftest.rs:834-835`): the
  repair prompt gets the *smallest* disagreeing input, with what each side did.
  This is a selection, not delta-debugging shrinking — nothing mutates a
  failing input toward a smaller one. The verdict rules are honesty rules
  (`difftest.rs:836-862`): zero evaluable cases → `inconclusive`; any
  disagreement → `fail`; more than half the cases unevaluable →
  `inconclusive`; the original faulting on ≥90 % of cases → `inconclusive`
  ("the inputs do not reach the function's logic; it needs a curated input
  generator"). `compile_only` (`difftest.rs:874`) implements the
  `compile-only` oracle kind — verdict always `inconclusive` (design 0013:68).
- **Fail-closed.** `require_sandbox` refuses on a host that cannot enforce
  Landlock ABI 4 + network isolation (`service.rs:862`); design 0013:83-85 is blunt:
  no confinement, no rewriting, "no flag to run unconfined", macOS and
  Windows excluded until they grow their own.

The five oracle kinds — `icicle-emu/x86-64-sleigh` (implemented),
`ghidra-pcode` (reserved), **`native-process` (reserved: "the only
function-level kind that catches emulator and SLEIGH bugs")**,
`compile-only` (implemented), `process` (implemented, below) — are all laid
out in the design table at design 0013:63-69. The reserved native kind is the design
doc admitting its own fidelity ceiling: SLEIGH bugs are invisible to the
emulator (design 0013:213; the spike conceded the same, spikes/rewrite-loop/NOTES.md:159-161).

## Whole-program mode

`rewrite_program` (service_program.rs:339) is where KRAKEN does what
calxgloss cannot: verify the *whole program against the original, live*.

1. **Identity check first**: the binary on disk must SHA-256-match what the
   project analysed — "the program-level test would compare against the wrong
   program" (`service_program.rs:385`).
2. Plan, reachability, then translation callees-first. Globals live in a
   `ProgramImage` of the original's bytes; the native runner installs that
   image at the same base the emulator loads it
   (`service_program.rs:421, 531-535`) so both sides see identical initial
   data. Function-level oracle comparison against globals flags `UsesGlobals`
   functions whose initial state only makes sense in-program — they usually
   end `unchecked` (design 0013:207).
3. **Resume, not restart.** A rerun walks the whole plan again but takes an
   accepted unit whose decompile hash and callee set still match
   (`service_program.rs:587-611`), else any earlier `translated`/`verified`
   version that still matches — "a run that is started again picks up where
   the last one stopped"; a version that *failed* its test is re-translated
   (`service_program.rs:617-656`).
4. **The crate**: one binary, `main.rs` building argc/argv/envp as the C
   runtime does, the shared runtime shim `rt.rs` (all libc calls on Rust std —
   2 405 lines, the biggest file in the crate), one module per unit with
   symbol attributes stripped (`program.rs:1-14`).
5. **The `process` oracle**: original and rewritten program run in the sandbox
   on the same arguments and stdin; exit status, stdout, stderr — and files
   the programs write, compared as size + whole-file hash + 4 KiB block hashes
   — are diffed (`crates/kraken-rewrite/src/process.rs:104-125`; design 0013:69).
   Cases have provenance tags `baseline` / `corpus` / `generated` / `user`
   (`process.rs:36-54`); 10 s per case, 300 cases max (`process.rs:26, 30`).
6. **Program repair by blame.** On a failed verdict, the first differing byte
   or exit is located; the crate is rebuilt with debug lines and rerun with
   `KRAKEN_TRACE_AT=out:<byte>` — the runtime shim prints its call stack at
   that output byte (`program.rs:227-229`; blame.rs:1-27). Suspects are ranked:
   unverified-before-verified, stack-innermost-first, then callees nearest
   first (`blame.rs:1-27`, `rank` at `blame.rs:227`); **the first three**
   become the round (`SUSPECTS_PER_ROUND = 3`, `service_program.rs:51, 1323`;
   design 0013:154 "the first three suspects are the round"). Each suspect is
   retranslated through the normal loop seeded with the differing case; the
   crate is rebuilt and every case rerun; rounds default 2, cap 4
   (`crates/kraken-registry/src/commands/rewrite_program.rs:30-32`). It is a
   ranking, not a proof, and "a wrong guess costs a round, not correctness"
   (design 0013:154).

The measured evidence is the two-C++-audio-simulator table at
design 0013:185-190: `sim03` (1.0 MiB, 39 planned, 30 reached, 20 verified / 9
unchecked / 1 compile-only) reaches **program verdict pass, 11 of 11 cases,
`mix.wav` identical byte-for-byte**, across three runs (28+48+28 min);
`sim04` (340 KiB, 59 planned, 47 reached, 26/20/1) passes **11 of 11, both
`.wav` outputs identical** on its second run (34+31 min), both runs driven by
`kraken rewrite-program -y --accept-verified --max-attempts 2` through Claude
Code as the configured terminal agent (design 0013:185). The run narrative is honest
about the path: a first incomplete run, a NaN-printing shim bug found *by the
differential*, 27 of sim03's translations reused by the third run, functions
left `unchecked` because their inputs depend on other functions' state
(design 0013:192). Whatever else this table proves, it is a whole-program
machine-code-to-Rust pass on real programs — no other artifact in either
project's measured evidence gets that.

## Export, build, and the rails

`rewrite_export` turns accepted units into a Cargo workspace for the strangler
pattern: a library crate (one module per accepted unit) plus an `ffi` cdylib +
staticlib exporting the original symbol names, plus a generated C header
(`export.rs:1-19, 506-535`). Functions still needed from the original are
called by their mangled names and the export checks the built crate's symbol
table against the accepted units (`service.rs:1196-1206`; design 0013:192 records an
`sim04` export whose 26 accepted functions build while still calling
`voiceStartEvent` and `parsePart` in the original). Writing outside the
project directory drops the command from `mutating` to
approval-required-every-run (design 0013:86). `rewrite_build` reruns `cargo
build/test/run` on an exported crate in the same sandbox, 600 s/60 s budgets
(`build.rs:1-7, 18-20`).

Cost rails (ch. 34 owns the global AI-governance story; these are the
rewrite-specific hooks): every job's model calls ride a meter — `JobAi`
wraps the backend and posts to the session's AI board and the project
ledger (`metering.rs:37, 121`); a limit hit ends the job cleanly and keeps
every version made (`metering.rs:160`; docs/rewrite.md:104). The wizard and
the CLI both **estimate requests and cost before running and wait for
confirmation** (`docs/rewrite.md:102`); a whole-program run is "often around
60 requests in all" (rewrite.md:100); a cheaper dedicated rewrite model is
configurable (rewrite.md:105). The backend comes from the optional
`[rewrite]` config table else `[provider]`, and may be a model API **or a
terminal agent** (`service.rs:124-125`) — with the terminal agent given no
KRAKEN tools and every own-tool permission denied (design 0013:88).

The error taxonomy is pointed: `RewriteError` is for machinery — "a wrong
translation is not an error: it is a failed verdict" (`error.rs:6-7`), and
the first variant is `Image("image: …")` whose doc still says "The ELF could
not be read or is not x86-64" (`error.rs:10-12`).

## What KRAKEN itself says it cannot do

Design 0013:204-213 lists the limits; the sharp ones for the comparison:
only stubbed libc exists at function level; no struct-by-value / varargs /
pointer results in a function ABI; a function that frees its test inputs is
`inconclusive`; globals-dependent functions test from the wrong initial state
and end `unchecked`; recursive groups duplicate the group inside each member;
**only x86-64 ELF runs under the oracle** (design 0013:211 — the code's multi-arch
oracle header notwithstanding, everything end-to-end measured is x86-64
ELF on Linux); programs that read files/env/clock, fork or thread are outside
the program oracle (design 0013:212); emulator fidelity is SLEIGH's, and the
reserved `native-process` kind is the planned cross-check (design 0013:213).

"Done" is defined at three levels — function accepted after a passed
differential with real counts; program rewritten when the plan ledger adds up
with no unexplained `needs_stubs`/`uses_globals`/`uses_syscalls` flags and the
export builds with matching symbols; the original retired when a build with
the originals dropped behaves the same on the program's own regression inputs
— and the closing sentence is the design's creed: *"Differential testing is
evidence. 'Done' at every level means 'no known difference on what was
tested', and the reports say how much was tested"* (design 0013:215-223).

## calxgloss, the same mission, opposite bets

calxgloss aims at the same destination — a directory of Windows binaries
becomes a Rust workspace with identical observable behavior
([10-calxgloss-baseline](10-calxgloss-baseline.md):39-45) — and gets there
through opposite mechanism at every joint. The unit of work is one function
or **struct**, keyed `{file}/{function}`, queued call-graph-first and steered
by a reviewer overlay, translated by an **unattended pipeline**
(`calxgloss-translator`) whose attempt seam is one prompt → LLM → verification
→ record (`retry/attempt.rs:229`; ADR-0051,
`docs/adr/0051-an-attempt-is-one-seam-prompt-llm-verification-and-record-the-loop-keeps-only-policy-strategies-are-adapters-at-the-existing-door-and-the-failing-verdict-routes-into-the-next-prompt.md:45`).
Verification means: capture the original DLL's
behavior **once**, by running it under Wine through a per-function harness
(`crates/pipeline/calxgloss-testgen/src/lib.rs:17, 22-24`), then compile the
translation in a scratch Cargo project and replay the frozen `baseline.json`
against it (`crates/pipeline/calxgloss-verify/src/lib.rs:11-13`). Everything
happens three times — CLI, web review UI, pipeline — with git attempt branches
as the reversibility layer (`crates/pipeline/calxgloss-git/src/lib.rs:5`).

## The comparison, axis by axis

**(a) When the original speaks.** The central difference, everything else
follows. KRAKEN re-runs the original on *every verification*: the emulator
executes the original function live against the translation (difftest), or the
sandbox executes the original program live against the rewritten program
(`process`). calxgloss's oracle is a **recording**: Wine executes the original
DLL during baseline capture, and from then on verification compares Rust
against stored JSON (`testgen lib.rs:14-16`, `verify lib.rs:11-13`). Both
projects know their recording can be wrong — calxgloss records no capture
provenance (ch. 35, axis (c)), and KRAKEN reserved `native-process` precisely
because its live oracle has a fidelity ceiling of its own (design 0013:67, 213). But
the failure modes differ: a frozen baseline silently rots under a Wine change
and can never disagree about inputs it never captured; a live oracle can
disagree about anything it can execute but is capped by its stub layer (only
`STUBBED_IMPORTS` at function level, design 0013:204) and cannot touch PE at all.
Roadmap P22 — a differential API-call trace comparing ordered Win32/PAL calls
between original and restitch (`docs/roadmap.md:114`) — is calxgloss's own
not-started step *toward* live differential: the values come from a recording,
but the call sequence would be compared live on both sides.
KRAKEN has exactly this for one dimension — the global-write comparison at
function level (`oracle.rs` reports writes to globals; design 0013:65) — and its
reserved kinds say more native cross-checks are planned.

**(b) The unit of work and its queue.** KRAKEN's unit is one function version,
ordered by Tarjan SCC callee-first with the group flags that gate acceptance
(`plan.rs:109, 196-205`); "struct" is not a unit — structs only reach prompts
as layout notes (`layouts.rs:1-8`). calxgloss's unit is `{file}/{function}`
*or struct*, ordered by the callgraph's priority plan
(`crates/evidence/calxgloss-callgraph/src/lib.rs:5, 26`) with a reviewer queue
overlay on top, and the queue is recomputed per run, not a stored ledger.
KRAKEN additionally computes a *reachability* closure in program mode
(services: entry + static ctors + function-pointer tables,
`service_program.rs:455-521`) — calxgloss translates everything in the queue;
its equivalent of "deliberately not now" is the skip overlay
(ADR-0003). Both order callee-first; KRAKEN's version is algorithmic (SCC) and
doubles as the accept-gate flag ledger, calxgloss's is heuristic priority
plus human overlay.

**(c) Evidence in the prompt.** The gap is enormous and in calxgloss's favor.
KRAKEN shows: decompile, ≤6 callee decompiles, layout notes from engine types,
an optional spec (`service.rs:474-488`, `layouts.rs`, `rewrite.rs:823`).
calxgloss shows: the **evidence bundle** — 15 whole-binary scans projected
through registered rows into one render input, one section per engine, missing
evidence dropping silently with coverage admission lines beside it (ADR-0048
`docs/adr/0048-the-prompt-read-path-is-one-analysisdoc-seam-of-registered-projection-rows-kept-separate-from-the-scan-descriptor-write-seam.md:32`,
ADR-0049
`docs/adr/0049-the-evidence-bundle-is-the-single-render-input-of-the-bundle-fed-templates-with-one-shared-section-include-per-evidence-engine-kept-separate-from-the-projector-seam.md:36`,
ADR-0053
`docs/adr/0053-scan-coverage-is-the-scans-own-record-stamped-at-scan-time-beside-provenance-read-as-unknown-when-absent-and-pinned-to-the-engines-declared-facets.md:33`;
baseline chapter §Evidence engines). KRAKEN has no
evidence engines for the rewrite path at all — its type information (which
*does* feed layout notes) comes from debug info / operator-typed types via the
ch. 31 seam. calxgloss escalates *context* through five tiers —
`Signature` / `Disassembly` / `WithTests` / `ModuleContext` / `FullModule`
(`crates/shared/calxgloss-types/src/context_tier.rs:59-74`); KRAKEN has one
context shape per attempt and escalates nothing.

**(d) The LLM seam.** KRAKEN reuses the assistant's backends (`[rewrite]` else
`[provider]`, model APIs **or terminal agents** — sim03/04 ran through Claude
Code, `service.rs:124-125`, design 0013:185), pins nothing at prompt level beyond
tagged outputs and citation checks, and keeps its model tests deterministic
with cassettes keyed on a prompt fingerprint (design 0013:209 notes the cassette
fingerprint is the ready-made response-cache key). calxgloss is local-first:
OpenAI-compatible HTTP to Ollama/vLLM, askama templates per tier and
failure-informed variant, the attempt seam with the strategy ladder behind one
door — `run_attempt` is one seam, loop is policy, strategies are adapters,
verdicts route (ADR-0051,
`docs/adr/0051-an-attempt-is-one-seam-prompt-llm-verification-and-record-the-loop-keeps-only-policy-strategies-are-adapters-at-the-existing-door-and-the-failing-verdict-routes-into-the-next-prompt.md:44-46`;
`retry_strategy.rs:31-43`), fault monitors ending attempts
(baseline chapter §AI layer). KRAKEN's temperature 0.1 + tags is a weak
discipline by calxgloss's template-per-strategy standard; calxgloss's no-cloud
premise is the opposite bet to KRAKEN's "cloud or local, your config"
(design 0013:88).

**(e) Repair semantics.** Independent convergence with different teeth. Both
route by *kind of failure* into a specifically different next prompt: KRAKEN
has `compile` / `rejected` / `counterexample` feedback with per-kind caps and
refuses to repair `inconclusive` (design 0013:43-47; `repair.rs:26-32`); calxgloss
routes the failing verdict through `compile_fix` / `test_fix` / `edge_case_fix`
/ `escalate` adapters at one door (ADR-0051; `retry_strategy.rs:31-43`) and a
tier ladder with an operator cap. KRAKEN adds two things calxgloss lacks: the
counterexample *selection* rule (smallest-input first, cap 3 —
`difftest.rs:767-775, 834-835`), and repair history as stored, linked versions
(`unit_repairs`). calxgloss adds one thing KRAKEN lacks: escalation *up the
context ladder* when a fix keeps failing (tier walk), where KRAKEN's loop
"does not search for a better prompt" (design 0013:208). Both bound attempts
(3/8 vs the retry budget); neither re-gathers evidence mid-loop
(ADR-0051's "evidence is never re-gathered").

**(f) Honesty mechanics.** Converged values, different carriers. KRAKEN's
inconclusive rules (unevaluable >50 % → no verdict; ≥90 % faults → inputs
missed the logic, `difftest.rs:836-862`) and its "done means no known
difference **on what was tested**, and the reports say how much was tested"
(design 0013:223) are the same doctrine as ADR-0053's coverage stamps — absent reads
as unknown, never absent (`docs/adr/0053-scan-coverage-is-the-scans-own-record-stamped-at-scan-time-beside-provenance-read-as-unknown-when-absent-and-pinned-to-the-engines-declared-facets.md:33`) — and the same as
calxgloss's honest-degradation everywhere (baseline chapter). KRAKEN's
`Verdict` carries seed, cases-run/passed/skipped, sandbox label and
counterexamples per version (`store.rs` verdicts table); calxgloss's
`VerificationResult` carries compile status + per-test divergence (ch. 35
cites `calxgloss-verify`), and receipts (P25, `docs/roadmap.md:117`) are not
shipped. KRAKEN additionally stores the **prompt hash, model and provider per
unit version** (design 0013:198) — full provenance of the *attempt*, which calxgloss
logs as run records (`llm_io/log.jsonl`) but does not anchor to each merged
line of code.

**(g) Confinement of generated code.** KRAKEN: fail-closed Landlock+seccomp
sandbox for every build and run of model code, lint as defence-in-depth, one
process per case with rlimits, refusal over fallback (design 0013:83-85;
`sandbox.rs:1-8`; `require_sandbox` at `service.rs:862`). calxgloss: a
"scratch directory" convention under `scratch/` and nothing else — ch. 35
confirmed no permission/confinement layer exists anywhere in calxgloss.
calxgloss compiles and runs model-written Rust (verify's scratch project)
unconfined on the operator's machine. This axis is not close.

**(h) PAL vs the callee mechanism.** Both solve "what does the translation
call instead of the original", with opposite permanence. calxgloss has a
**mapping database** — each Windows API gets a PAL trait + suggested crate
(rendered as `[PAL placeholder]` entries,
`crates/integrations/calxgloss-pal/src/data.rs:204-227`) — plus generated shim
crates; the PAL is a plan the translated code follows, verified only by
compile+baseline. KRAKEN has no mapping layer: accepted callees become real
Rust modules (`__kr_callee_…`, `reuse.rs:58`), oracle stubs cover only the
modelled libc facts (`oracle.rs:41`, `clib.rs`), the program shim `rt.rs`
re-implements libc on Rust std, and unstubbed imports are flagged
`NeedsStubs` and block level-2 "done" (design 0013:220). KRAKEN's answer is *link the
real thing or say so*; calxgloss's is *map it and hope the mapping is right* —
which is exactly why P22 (call-trace differential) matters on calxgloss's
side.

**(i) Reversibility & work history.** calxgloss bets on git: every attempt a
commit on `re/{binary}/{function}v{N}`, failed branches kept forever, merged
after a callee-first dependency check, structured justification blocks per
commit (`crates/pipeline/calxgloss-git/src/lib.rs:10-13`; commit block `:18-27`). KRAKEN bets on an append-only
SQLite ledger: versions never deleted, `unit_events` audit trail, repair links
across attempts, staleness recomputed from observed decompile hashes
(`store.rs`). Same immutability principle, different substrate: git branches
are reviewable with normal tools and merge into the deliverable; the rewrite
ledger is richer per-attempt (prompt hash, seed, sandbox label) but lives in
one crate's private database, deliberately decoupled from the edit log
(design 0013:194-198).

**(j) Human role & the accept gate.** Both make a human acceptance the only
act that marks work as owned, and both make it mechanical-first: KRAKEN's
`accept` refuses anything not `verified` (`store.rs:621-662`), users-only for
agents (design 0013:86), `accept_verified` auto-accepting only passing units and
still refused from agents (`rewrite_program.rs:417-421`). calxgloss's web
review accepts/sends-back/patches per unit with overlays for intent
(baseline chapter §Automation surface). calxgloss's whole surface is built for
a reviewer steering a queue; KRAKEN's accept is one command on a workbench
that is otherwise agent-drivable (`rewrite_function` is `mutating` precisely
because the sandbox bounds what an agent can do, design 0013:86).

**(k) Output shape.** KRAKEN exports a *strangler workspace* — library + cdylib
with the original C symbols + header, originals still called where needed
(`export.rs:1-19`; design 0013:192) — for gradually replacing a live binary in place.
calxgloss produces a *standalone cross-platform Rust workspace* on `main`
shimmed above a PAL; there is no "link it back into the original" story — its
endgame is retiring the Windows build, not wrapping it. Neither is "better";
they answer different exit conditions (replace-in-place vs migrate-away).

**(l) Whole-program verification.** calxgloss cannot verify a whole artifact
at all: the FFI/Wine gate is per-export, and scenario capture for EXEs is
unstarted P24 (`docs/roadmap.md:116`); there is no conformance verdict
(P26, `docs/roadmap.md:118`). KRAKEN has a shipped whole-program oracle with
byte-identical-file comparison and two real-program passes (sim03/sim04).
This is the second axis where KRAKEN is not ahead by design but ahead in
shipped code.

**(m) Target support — the mirror gap.** KRAKEN: ELF only at the oracle, x86-64
end-to-end, Linux-only rails (design 0013:211; `loader.rs:102`; `arch.rs:85-87`),
corpus of C/C++ Linux binaries. calxgloss: PE32/PE32+ Windows targets only,
managed PEs parked (ADR-0044), fixture DLL as the only ground truth. Neither
project can touch the other's input format. A KRAKEN → PE rewrite of a
calxgloss-style target would need the loader+Windows syscall layer ch. 35
listed as a don't-copy; calxgloss rewriting ELF is out of scope by its own
charter (baseline chapter §What calxgloss is *not*).

## The capability matrix this chapter decides

| Capability | Shared (converged) | calxgloss-only | KRAKEN-only | Verdict |
|---|---|---|---|---|
| Unit & queue | callee-first ordering; bounded attempts; skip/park affordances | struct units; reviewer queue overlay; five context tiers | SCC groups + flags as accept-gate ledger; reachability closure | calxgloss richer scheduling, KRAKEN's flags-with-teeth worth copying |
| Evidence in prompt | layout/type facts reach the prompt | 15-scan evidence bundle, coverage stamps, tier escalation | engine-debug-info layout notes, cited spec step | **calxgloss by a mile**; no contest |
| LLM seam | bounded repair loop routing by failure kind, feedback from the verifier into the next prompt | attempt seam ADR-0051, strategies-at-door, fault monitors, local-only premise | assistant-backend reuse incl. terminal agents, per-prompt-hash provenance, cassettes | complementary; calxgloss more disciplined, KRAKEN more backend-flexible |
| Verification | compile-isolated build of generated code; divergence/counterexample feedback | Wine-captured per-export baselines; branch-targeted inputs; global-state side-effect expectations | **live differential**: emulator per-function oracle + whole-program `process` oracle; smallest-input counterexamples; honesty rules; global-write comparison; reserved native-process kind | **KRAKEN wins the axis** (a) — live beats recorded; calxgloss's inputs (branch-targeted, typed) beat KRAKEN's generic generators |
| Confinement | — | scratch-dir convention only | fail-closed Landlock/seccomp, lint defence-in-depth, per-case processes | **KRAKEN, non-negotiable** |
| PAL / linkage | "what to call instead" must be decided per unit | PAL mapping DB + generated shims | accepted-callee linking, oracle stubs, rt shim, NeedsStubs gate | different endgames; both incomplete (KRAKEN stubs only libc, calxgloss mapping unverified by trace — P22) |
| Work history | append-only, never delete, per-attempt records | git attempt branches + justification commits + merge dependency check | sqlite ledger: repair links, unit_events, prompt-hash provenance, staleness from decompile hashes | calxgloss substrate better for review/merges; KRAKEN's staleness + attempt links worth stealing |
| Human accept | mechanical gate before human act; users-only acceptance | web review with overlays, batch accept | accept refuses unverified mechanically; agents may run everything else | same doctrine; calxgloss better tooling, KRAKEN's mechanical verified-before-accept check is explicit in code |
| Output | compilable crate(s), sandbox-buildable | standalone Rust workspace + PAL | strangler workspace with original C ABI; whole-program binary | different goals — migrate-away vs replace-in-place |
| Coverage honesty | "no known difference on what was tested" doctrine | ADR-0053 stamps, honest degradation, roadmap P21/P25/P26 gap | inconclusive rules, "done" 3 levels, plan ledger + flags, coverage in export README | converged philosophy; KRAKEN ships more of it today, calxgloss's is more systematic on paper |
| Maturity evidence | — | one fixture DLL; no eval corpus | sim03/sim04 whole-program passes; corpus/truth suite (ch. 37) | KRAKEN's measured evidence is real-program; calxgloss must not read that as PE-feasibility |

## Steal / don't copy / confirm

**Steal, ranked** (mechanism, not slogan):

1. **Live original at verification — function level.** KRAKEN re-runs the
   original per attempt; calxgloss replays a recording. calxgloss *has* the
   live lane already: the same `WineRunner` harness that captures a baseline
   can be re-run per attempt against the same inputs (`testgen wine.rs`, ch.
   35), giving a PE `native-process` equivalent — KRAKEN's reserved kind that
   "catches emulator and recording bugs" (design 0013:67) — for the cost of one Wine
   process per case. Cheapest first step: re-run capture on demand and diff
   against `baseline.json` when a test fails, to tell "translation broke" from
   "recording rotted".
2. **The `process`-oracle shape for EXEs and scenarios (P24).** Run original
   and restitched program on the same argv/stdin in a sandbox, diff
   exit/stdout/stderr, and compare written files as size+sha256+4 KiB block
   hashes (`process.rs:104-125`). That is a concrete design for P24's scenario
   contract, and the block-hash comparison is worth adopting even inside the
   existing DLL flow (ch. 35's provenance steal extends to outputs).
3. **Fail-closed sandbox for verify.** Port the KRAKEN rails (ch. 35's
   `kraken-confine` primitives are the model) around calxgloss-verify's
   scratch projects: Landlock scopes + rlimits, and refuse to run model code
   when confinement cannot be enforced (`service.rs:862`; design 0013:85) instead of
   trusting the scratch-dir convention.
4. **Staleness by content hash.** KRAKEN stamps every unit with the decompile
   hash it was made from (its own function + callees) and recomputes staleness
   against observed hashes (`store.rs:1106-1128`). calxgloss's cache knows
   engine identity (ADR-0055) but nothing tells an *accepted* unit that its
   function's decompile moved since acceptance (bdiff covers whole-binary
   version pairing, not intra-version drift). A per-unit "made-from" digest
   beside each merged artifact closes that.
5. **Smallest-disagreeing-input-first feedback + verdict honesty rules.**
   calxgloss's `test_fix` already feeds failing tests back; adopt the ordering
   (sort counterexamples by input size, cap the set — `difftest.rs:767-775,
   834-835`) and the two honesty rules: >50 % unevaluable → no verdict, and
   "inputs don't reach the logic" as its own named outcome
   (`difftest.rs:836-862`). Both map cleanly onto `VerificationResult`
   divergence lists.
6. **Mechanical pre-refusal before any model call.** The ABI fits-registers
   check stops `rewrite_function` before the first request when the signature
   can't be checked (design 0013:205), and ch. 35's source-patch `validate` rejects
   impossible plans the same way. calxgloss should refuse-to-attempt (and
   record why) units whose signature can't be expressed by its FFI harness —
   struct-by-value exports today just churn attempts.
7. **Pre-confirmation cost estimate per run.** KRAKEN prints estimated
   requests+cost range and *waits* before every batch and program run
   (`docs/rewrite.md:102`); calxgloss logs token usage but has no pre-run
   estimate gate. Cheap to build from `token_usage.json` history.
8. **Repair links + prompt-hash provenance per version.** KRAKEN's
   `unit_repairs` and per-version provider/model/prompt-hash
   (`store.rs:60-99`, design 0013:198) make "why is this merged line what it is"
   answerable from the record, not the log. calxgloss's justification blocks
   come close; adding the prompt fingerprint (already in `llm_io`) would
   close it.
9. **Trace-armed blame ranking.** For scenario failures (once P24 exists),
   KRAKEN's `KRAKEN_TRACE_AT`-style stack capture plus unverified-before-verified
   ranking (`blame.rs`, `program.rs:227-229`) is a template for "which unit do
   I send back" — calxgloss today sends back units only as a human guess.

**Don't copy:**

- **SQLite as the work-history substrate.** calxgloss's git-branch reversibility
  is a core principle (baseline chapter, principle 6); review, merge, and the
  deliverable all live in git. KRAKEN needed the ledger because the workbench
  *is* a database tool; transplanting it would split calxgloss's history in
  two.
- **The emulator as the oracle** for PE — ch. 35's verdict stands, and KRAKEN's
  own design concedes its live oracle still needs native cross-checks
  (design 0013:213; NOTES.md:159-161).
- **One translation unit per function with duplicated callees.** KRAKEN
  re-translates unaccepted callees into every unit that needs them (design 0013:208)
  and duplicates whole SCCs; calxgloss's merge-time dependency check keeps one
  merged definition per unit. The duplication is a workaround for the
  incremental workbench, not a feature.
- **Spec mode as an extra step.** KRAKEN's spec is what calxgloss's evidence
  bundle *replaces*: a model-written Markdown summary is weaker than the
  projected scan records calxgloss already feeds; adopting it would be
  regressing to self-reported evidence (against the ADR-0048/0049 doctrine).
- **Terminal-agent backends for translation.** Fine for KRAKEN with tool-denial
  rails (design 0013:88); calxgloss's local-model premise and its no-arbitrary-agent
  posture (baseline chapter) say stay with the seam.

**Confirmed independently** (both projects arrived at the same answer without
coordination — treat as load-bearing):

- Bounded repair loops that route by *kind* of failure into a different next
  prompt, fed by the verifier, never re-gathering evidence mid-loop (design 0013:43-47
  ↔ ADR-0051).
- Verdict counts and per-case evidence stored with every attempt; a pass must
  name how many cases ran (`difftest.rs`/`verdicts` table ↔ justification
  commit blocks, `crates/pipeline/calxgloss-git/src/lib.rs:18-27`).
- "Done" means *no known difference on what was tested*, stated with its
  coverage — KRAKEN design 0013:223 ↔ ADR-0053's unknown-never-absent and the
  no-conformance-verdict honesty of P26's framing.
- Compile-isolated generation: the translation is built in a throwaway cargo
  project with a controlled environment (`native.rs`, `build.rs` ↔
  `calxgloss-verify`'s scratch project), not in the deliverable workspace.
- Both keep whole-binary *runs* resumable: KRAKEN by hash-matched version reuse
  (`service_program.rs:587-656`), calxgloss by cache-keyed scans and surviving
  accepted translations across binary versions (bdiff) — i.e. both independently
  decided the expensive artifacts must survive process death.
- Both flag the same missing thing about themselves: a native second opinion
  for the verifier's own fidelity (reserved `native-process` ↔ P22's
  live call-trace). That convergence is the strongest argument to do it.

## Sources

- KRAKEN at `68718c6` (clone at `/tmp/opencode/kraken`); all `path:line`
  cites verified 2026-10-28.
- KRAKEN docs: `docs/design/0013-rewrite-pipeline.md` (259 lines; :43-49,
  63-71, 83-88, 149-156, 185-192, 194-198, 200-213, 215-223);
  `docs/rewrite.md` (134 lines; :100-105); `spikes/rewrite-loop/NOTES.md`
  (:57-58, 159-161; 277 lines).
- KRAKEN crates: `kraken-rewrite` src 20 776 lines / 30 175 with tests —
  `lib.rs:118-119`; `unit.rs:130, 149, 175, 184`; `store.rs:60-99, 300-335,
  403, 621-662, 1106-1128`; `plan.rs:4, 109, 196-205`; `collect.rs:1-2`;
  `task.rs:31-40, 85-88, 136-137, 222-223, 382, 419-425, 499`;
  `repair.rs:1-14, 26-32`; `lint.rs:1-17, 24`; `blame.rs:1-27, 56, 227`;
  `difftest.rs:565-567, 767-775, 807, 834-862, 874`; `oracle.rs:1-11, 21, 41,
  187, 206-207`; `process.rs:26, 30, 36-54, 104-125`; `reuse.rs:58, 130,
  229-276`; `infer.rs:1-16`; `targets.rs:1-8`; `abi.rs:58-61`;
  `native.rs:1-5, 425`; `sandbox.rs:1-8`; `build.rs:1-20`; `clib.rs:1-9`;
  `error.rs:6-12`; `export.rs:1-19, 32, 506-535`; `program.rs:1-14, 227-229`;
  `metering.rs:37, 121, 160`; `layouts.rs:1-8`; `service.rs:55, 124-125,
  202-214, 474-488, 610, 701-708, 740, 770, 802, 822, 862, 1182, 1196-1206,
  1422, 1518, 1557, 1744-1759`; `service_program.rs:51, 283, 339, 359-360,
  385, 421, 455-521, 531-535, 573-582, 617-656, 680-692, 997;
  runtime: `runtime/rt.rs` (2 405 lines), `runtime/ptrdesc.rs` (70);
  `kraken-registry/src/commands/rewrite.rs:204, 352, 497, 634, 731, 823, 940`;
  `rewrite_program.rs:24, 30-32, 417-421`; `rewrite_build.rs`;
  `kraken-emu/src/arch.rs:85-87, 119, 137-146`; `kraken-emu/src/loader.rs:102`.
- calxgloss: `docs/research/kraken/10-calxgloss-baseline.md` (whole; esp.
   §pipeline, §AI layer, §Verification); ADR-0048
   `docs/adr/0048-the-prompt-read-path-is-one-analysisdoc-seam-of-registered-projection-rows-kept-separate-from-the-scan-descriptor-write-seam.md:32`;
   ADR-0049
   `docs/adr/0049-the-evidence-bundle-is-the-single-render-input-of-the-bundle-fed-templates-with-one-shared-section-include-per-evidence-engine-kept-separate-from-the-projector-seam.md:36`;
   ADR-0051
   `docs/adr/0051-an-attempt-is-one-seam-prompt-llm-verification-and-record-the-loop-keeps-only-policy-strategies-are-adapters-at-the-existing-door-and-the-failing-verdict-routes-into-the-next-prompt.md:44-46`;
   ADR-0053
   `docs/adr/0053-scan-coverage-is-the-scans-own-record-stamped-at-scan-time-beside-provenance-read-as-unknown-when-absent-and-pinned-to-the-engines-declared-facets.md:33`;
   ADR-0003, 0044, 0055;
  `crates/pipeline/calxgloss-translator/src/retry/attempt.rs:229`;
  `crates/shared/calxgloss-types/src/retry_strategy.rs:31-43`;
  `crates/shared/calxgloss-types/src/context_tier.rs:59-74`;
  `crates/pipeline/calxgloss-verify/src/lib.rs:11-13`;
  `crates/pipeline/calxgloss-testgen/src/lib.rs:14-16, 17, 22-24`;
  `crates/pipeline/calxgloss-git/src/lib.rs:10-13, 18-27`;
  `crates/evidence/calxgloss-callgraph/src/lib.rs:5, 26`;
  `crates/integrations/calxgloss-pal/src/data.rs:204-227`;
  `docs/roadmap.md:114, 116-118` (P22, P24, P25, P26);
  chapter 35 for the Wine/emulation axis and the confinement absence check.
