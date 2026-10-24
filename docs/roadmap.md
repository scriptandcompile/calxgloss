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

Tracks P19–P33 are the feature ideas catalogued by the [REA
comparison](rea/README.md) (`docs/rea/`, every chapter's "Steal ideas").
**Table order is dependency order** — no track appears before one that blocks
it (each summary names its blockers/blocked-by edges) — and among independent
tracks, ordered by how strongly each pulls calxgloss toward **complete
end-to-end restitching from binaries**: honest evidence about what the engines
could not determine (P19–P21), a verification gate wide enough to cover what
restitching can actually get wrong (P22–P24), and the durable receipts plus
fail-closed ledger that finally make "this binary is done" a checkable claim
instead of "the pipeline stopped with nobody complaining" (P25–P26). P27–P33
close stuck functions, strengthen evidence, or serve operations, and block
nothing above them.

| # | Track | Crate | Effort | Status | Next step | Epic |
|---|-------|-------|--------|--------|-----------|------|
| P19 | Admitted semantics — every evidence finding carries what its scan examined and what it could not, so `null`/absence reads as unknown, never as `false` | evidence (all scan crates) + shared (`calxgloss-types`) + pipeline (`calxgloss-translator`, `calxgloss-prompts`) + interface (`calxgloss-reports`, `calxgloss-web`) | — | ⬜ not started | not specced | — |
| P20 | Seam capability report + engine-identity cache key — the seam advertises which questions Kuna can currently answer, and the scan cache keys on the engine build digest instead of a hand-bumped format version | integrations (`calxgloss-decomp`, `calxgloss-kuna`) + pipeline (`calxgloss-translator`) + interface (`calxgloss-reports`) | — | ⬜ not started | not specced | — |
| P21 | First-class unknown records — per function, record what the evidence could not determine, with what evidence would close it; review UI resolves them, `escalate` retries consume them, the run leaves an audit ledger | shared (`calxgloss-types`) + pipeline (`calxgloss-translator`, `calxgloss-git`) + interface (`calxgloss-web`, `calxgloss-cli`) | — | ⬜ not started | not specced | — |
| P22 | Differential API-call trace in the gate — record the ordered Win32/PAL API-call sequence on both the original-DLL baseline and the restitched Rust, and compare order, catching right-result-wrong-path PAL-mapping errors value tests miss | pipeline (`calxgloss-testgen`, `calxgloss-verify`) + integrations (`calxgloss-pal`) + evidence (`calxgloss-apidetect`) | — | ⬜ not started | not specced | — |
| P23 | Real inputs for the baseline — mined argument vectors from hooked export entries plus Windows-minidump crash records replayed as concrete reproduction tests, killing the invented-inputs blind spot | pipeline (`calxgloss-testgen`, `calxgloss-verify`) + interface (`calxgloss-cli`) | — | ⬜ not started | not specced | — |
| P24 | Scenario-capture baseline for EXE targets — declared scenario contract (scripted interactions, filesystem observation, exit disposition) with five-dimension compare as the EXE-level verify signal FFI cannot reach | pipeline (`calxgloss-testgen`, `calxgloss-verify`) + interface (`calxgloss-web`, `calxgloss-cli`) | — | ⬜ not started | not specced | — |
| P25 | Verification receipts — every verify pass persists a digest-paired md+json receipt on the attempt branch (commands, case counts, dimensions, timings), durable and diffable between attempts | pipeline (`calxgloss-verify`, `calxgloss-git`) + interface (`calxgloss-reports`) | — | ⬜ not started | not specced | — |
| P26 | Fail-closed restitch conformance — per-unit obligation ledger (owner = attempt-branch digest, required case kinds, verifier receipt) and a digest-sealed whole-binary closure verdict; skipped, parked, overridden, or un-reviewed units never aggregate to complete | pipeline (`calxgloss-git`, `calxgloss-translator`, `calxgloss-verify`) + interface (`calxgloss-web`, `calxgloss-reports`, `calxgloss-cli`) | — | ⬜ not started | not specced | — |
| P27 | Hypothesis ledger for the retry loop — unclosable unknowns logged as declared static↔runtime mappings with expected patterns; recorded contradictions steer `escalate` vs `edge_case_fix` and survive as reviewable evidence | pipeline (`calxgloss-translator`, `calxgloss-llm`) + interface (`calxgloss-web`) | — | ⬜ not started | not specced | — |
| P28 | Masked byte search at the seam — `search_bytes(pattern, mask)` with wildcard hex and bit mask, feeding the `consts`/`serialize` magic-number scans real matches instead of guesses | integrations (`calxgloss-decomp`, `calxgloss-kuna`) + evidence (`calxgloss-consts`, `calxgloss-serialize`) | — | ⬜ not started | not specced | — |
| P29 | Ad-hoc call-path / def-use primitive at the seam — trace "how does this value reach this call" over kept bodies on demand, so `escalate` retries get targeted answers without a full re-scan | integrations (`calxgloss-decomp`, `calxgloss-kuna`) + pipeline (`calxgloss-translator`) | — | ⬜ not started | not specced | — |
| P30 | PE artifact-intelligence pass — block-entropy and debug-directory/note triage upgrading packing classification to measured evidence, per-subject content digests, and a before/after PE inventory diff as a restitch equivalence tripwire | evidence (`calxgloss-analysis`) + shared (`calxgloss-types`) + pipeline (`calxgloss-verify`) + interface (`calxgloss-reports`) | — | ⬜ not started | not specced | — |
| P31 | Deepen `calxgloss doctor` — read-only, scopable (`--target/--endpoint/--config`), checking LLM endpoint reachability, config validity, PE magic, cache writability, git/cargo presence; `scope_checks` vs `informational_checks`, JSON, exit codes | interface (`calxgloss-cli`, `calxgloss-reports`) + shared (`calxgloss-config`) | — | ⬜ not started | not specced | — |
| P32 | Contributor skill for driving the harness + doctrine — routing-shaped SKILL.md over the 23-command CLI with per-engine references, don't-repeat/remediation-literalism in `AGENTS.md`, doc version-skew pinning | — (docs + skills, no crate) | — | ⬜ not started | not specced | — |
| P33 | Whole-task measurement harness — benchmark pipeline tasks end to end (tokens, RSS, ms) with an oracle independent of the implementation, counting discovery, retries, and continuations in every token claim | — (dev-side experiment harness, no crate) | — | ⬜ not started | not specced | — |

Legend: ✅ done · 🔶 in progress · ⬜ not started.

## P19 — Admitted semantics: coverage + limits on every evidence finding (evidence + shared + pipeline + interface)

**An evidence engine that saw nothing and an evidence engine that looked and
found nothing currently read the same.** A scan's `null`, empty listing, or
absent finding is indistinguishable downstream from "examined and absent", so
prompts and reviewers can read an unexamined fact as an observed one — the
failure mode REA's contracts exist to kill (`coverage.status` per collection,
`facet_availability` distinguishing observed-absence from unobserved, "a
missing match does not establish absence"). Every scan crate's output gains
first-class coverage/limitation fields on the finding union (`calxgloss-
types`), rendered into prompt sections (`calxgloss-prompts`) and reports
without token bloat: `libmatch` says "signature match, version unknown",
`typesdb` says "vtable scan unavailable on this target", `apidetect` says
"import table parsed, delay imports unexamined". This is the data-layer
honesty that P21's unknown records and P26's fail-closed verdict consume —
`unknown` must become a representable, machine-visible value before it can
ever block a conclusion. Source: [33](rea/33-reconstruction-evidence-workflow.md)
steal 4, [32](rea/32-native-artifact-intelligence.md) steal 1, README #3/#7.
Blocks: P21, P26.

## P20 — Seam capability report + engine-identity cache key (integrations + pipeline + interface)

**The pipeline asks Kuna everything and learns the answer was unavailable only
as an empty result.** The seam keeps its single engine (ADR-0041) but gains a
session-style capability report — which query families the engine can answer
right now, with reasons — so prompts, fault monitors, and P21's ledger treat
unanswerable as *unknown*, and wrong-tier retries get pruned instead of
burning attempts (REA's `binary_session.tool_availability` posture). The same
track keys the scan cache on the Kuna crate version/build digest rather than
the hand-bumped `CACHE_FORMAT_VERSION` (ADR-0042/0043's key, REA's
engine-SHA-256 key), so an engine bump forces cold reads mechanically instead
of by maintainer memory. Source: [31](rea/31-deep-native-analysis.md) steals
2–3, README #6–7. Blocks: P21 (unanswerable facets must be reportable before
they can be honestly recorded).

## P21 — First-class unknown records (shared + pipeline + interface)

**Silent gaps today, audit ledger tomorrow.** When the evidence engines cannot
determine something — ambiguous vtable target, unresolved this-pointer,
export no baseline ever called — the fact disappears. Functions become
first-class unknown records in REA's record/update/verify shape: question,
severity, and `required_evidence` stating what would close it, with a
revision-guarded lifecycle; the review UI surfaces and resolves them, and
`escalate` retries consume them as prompt input. The run then ends with an
auditable ledger of what was never established instead of a queue that went
quiet. Built directly on P19's coverage fields (the gap must be visible in the
data before it can be recorded) and P20's capability report (unobserved ≠
observed-absent); the capstone P26 ledger consumes it — an open unknown must
block "DLL complete". Source: [33](rea/33-reconstruction-evidence-workflow.md)
steal 1, README #1. Blocked by: P19, P20. Blocks: P26, P27.

## P22 — Differential API-call trace in the gate (pipeline + integrations + evidence)

**Right bytes via the wrong path pass today.** The FFI baseline compares values
only, so a restitched function that computes the correct result through the
wrong GDI/DirectX route — a PAL-mapping error — is accepted. Record the
ordered Win32/PAL API-call sequence on both sides: an IAT interposer around
the original DLL in the testgen harness, PAL wrapper instrumentation on the
Rust side; store the sequence as an extra baseline dimension and compare
*order*, not membership. `calxgloss-apidetect` already supplies the expected
call shape per function, so it is fully automatable with zero driving —
keeping exactly the property REA's observation lanes can't offer (nobody
authors a scenario). This widens the restitch gate itself, so it lands before
the receipts and ledger pin the gate's verdicts. Source:
[34](rea/34-runtime-observation.md) steal 1, README #5. Blocks: P25, P26
(gate shape).

## P23 — Real inputs for the baseline (pipeline + interface)

**The gate only proves what its invented inputs happened to test.** testgen
builds arguments from export signatures + type evidence; real caller vectors
never enter, and an un-called export stays untested while the pipeline counts
the function translated. Two input sources close the blind spot: (1) hook the
original DLL's export entries during a baseline or reference-app run, record
raw argument vectors as observable events, and replay them as extra baseline
cases; (2) consume Windows minidumps REA-style — per-thread registers, fault
address, module maps as mapping candidates only — turning real crashes into
concrete reproduction inputs and regression tests (the dump part rides the
same record-and-replay machinery, so it ships after the hook lane). Every new
case is the strongest possible authority: `controlled-replay` at `observed`
confidence, which is exactly what P26's ledger will cite. Source:
[34](rea/34-runtime-observation.md) steal 2, [32](rea/32-native-artifact-intelligence.md)
steal 4. Blocks: P25, P26 (case coverage behind the verdict).

## P24 — Scenario-capture baseline for EXE targets (pipeline + interface)

**`target_dir` holds EXEs, and the FFI gate cannot touch their behavior at
all** — stdin, TUI, GUI, windowed flows have no baseline, so no EXE-level
restitch can ever be called done. Adopt REA's process-capture contract as the
EXE baseline format: a declared scenario (working dir, env, scripted
interactions, filesystem observation paths, exit + finalization) captured
against the original EXE, replayed against the restitched build, compared on
REA's five dimensions (terminal, interaction, exit, filesystem, process) with
normalization for flaky output — "authority build and reconstruction" is
literally calxgloss's original-vs-Rust framing. With owned-process discipline
(ownership token, rechecked before every signal, never a bare-PID kill) and
Frida's spawn-paused→load→resume order for any instrumented run. P26 cannot
return an honest verdict on an EXE until this exists. Source:
[34](rea/34-runtime-observation.md) steals 3+5. Blocks: P25, P26, P27.

## P25 — Verification receipts on the attempt branch (pipeline + interface)

**Verify results are pipeline-ephemeral; the commit message is the only trace
a pass ever leaves.** Each `calxgloss-verify` run persists a REA-style
verification receipt on the attempt branch: an md+json digest-paired record
naming the verifier command, baseline-suite digest, case counts per
dimension, timings, and result — durable justification for an accepted
commit and, `compare_bundles`-style, machine-diffable between attempts so a
reviewer sees exactly what changed between a failure and its fix. The
digest-pairing is what makes it citable authority: P26's obligation ledger
seals each unit's status by its verifier's receipt digest, so a green claim
without a matching receipt is an input error, not a pass. Placed after
P22–P24 deliberately: receipts pin the gate's verdicts, so they should pin its
widest agreed shape (values + API trace + mined inputs + scenarios) from day
one rather than re-sealing later. Source:
[33](rea/33-reconstruction-evidence-workflow.md) steal 5. Blocked by (shape):
P22, P23, P24. Blocks: P26.

## P26 — Fail-closed restitch conformance: obligation ledger + closure digest (pipeline + interface)

**"Queue empty" is not "binary done".** Today calxgloss cannot distinguish a
complete restitch from a run that stopped with nobody complaining — the gap
REA's conformance layer exists to close. Per unit of work, one obligation
ledger entry: owner = the attempt-branch commit digest (already an owner with
a content digest), required case kinds (positive/negative/malformed — testgen
can already classify its inputs), verifier = the P25 receipt digest;
skipped, parked (ADR-0044), overridden, and un-reviewed units record their
disposition but never count as verified; an export with no generated baseline
case stays `unknown`. Whole-binary status seals with a `closure_digest`, and
the evaluator is fail-closed: fail, unknown, skipped, truncated, and parked
never aggregate to pass, so the dashboard grows a real conformance verdict —
the definition of complete end-to-end restitching, made checkable. Source:
[33](rea/33-reconstruction-evidence-workflow.md) steals 2–3, README #2.
Blocked by: P19, P21, P25 (hard); P22–P24 (shape — the verdict should stand on
the widest gate and on a lane for EXEs). Blocks: nothing — this is the
capstone.

## P27 — Hypothesis ledger for the retry loop (pipeline + interface)

**Stuck functions retry on strategy rotation, not on evidence.** Each
unclosable P21 unknown, when a retry cycle can't resolve it, becomes a
declared static↔runtime mapping in REA's `correlate_static_and_runtime`
shape: a static dimension (`calls`, `cfg`) bound to a runtime/verify dimension
(`exit`, `filesystem`, API trace) with an expected pattern (`cochanged`,
`static_only`, `runtime_only`, `both_unchanged`). The retry loop already
produces both sides; the ledger joins them, and a recorded `contradiction` is
auditable evidence for choosing `escalate` vs `edge_case_fix` — surviving as
reviewable evidence in the UI rather than a transient log line. More stuck
units close, fewer park; pairs with P21's ledger as its consumption side.
Source: [34](rea/34-runtime-observation.md) steal 4. Blocked by: P21 (the
unknown), P24 (the runtime dimensions to correlate against).

## P28 — Masked byte search at the seam (integrations + evidence)

**Magic numbers found by frequency, not by match.** The seam grows one query
primitive — `search_bytes(pattern, mask)`, wildcard hex pairs plus an
equal-length bit mask (`pattern a0`, `mask f0` matches a0–af) — over
initialized analyzed data in address order, never crossing block
boundaries, reporting skipped ranges honestly (an admitted P19 coverage
field). `calxgloss-consts` and `calxgloss-serialize` then match magic-number
and format-sniffing candidates against real hits instead of statistical
guesses, strengthening bitflag/enum/format evidence for every downstream
prompt. No dependency on or from the spine — pure evidence quality.
Source: [31](rea/31-deep-native-analysis.md) steal 1, README #4.

## P29 — Ad-hoc call-path / def-use primitive at the seam (integrations + pipeline)

**`escalate` re-scans instead of asking.** calxgloss computes call graphs
batch-wide but can answer no ad-hoc structural question. A budgeted,
bounded-expansion primitive over the kept bodies — how does this value reach
this call, which path connects these two functions — gives escalate retries
targeted answers without re-running engine reads; an unreached goal with an
unresolved expansion reports `unknown`, never `not_reached` (P19's rule
again). Pairs with P21: the unknown ledger names the question, this primitive
is part of how a retry answers it. Source:
[31](rea/31-deep-native-analysis.md) steal 4. Pairs with: P21 (consumption
side).

## P30 — PE artifact-intelligence pass (evidence + shared + pipeline + interface)

**calxgloss parses no PE fact it doesn't have to, and restitching trusts the
loader silently.** Three PE-walking features in one file-intelligence track:
(1) block-entropy profiles plus debug-directory/build-id/note parsing in the
classification warmup, upgrading packing/obfuscation triage from heuristic
name checks to measured evidence and flagging which binaries deserve higher
context tiers; (2) per-subject content digests — each export, import-table
entry, and resource node hashed — letting scan caches survive binaries that
differ only in unrelated regions and giving `libmatch` content-addressed
library fingerprints; (3) a before/after PE inventory diff (exports, imports,
section digests, cert table) of original vs restitched artifact as a cheap
equivalence tripwire ahead of the test suite, with REA's rule that comparison
scope must match before any "unchanged" claim. Source:
[32](rea/32-native-artifact-intelligence.md) steals 2+3+5.

## P31 — Deepen `calxgloss doctor` (interface + shared)

**With an LLM endpoint down, the pipeline has no partial-work path and no
diagnosis.** `calxgloss doctor` stays read-only but becomes REA-scopable:
`--target/--endpoint/--config`, checking exactly what breaks runs — LLM
endpoint reachability (Ollama/vLLM), config validity, `target_dir` PE magic,
`re/` cache writability, git/cargo presence, graft freshness — splitting
`scope_checks` (gate `healthy` and the exit status) from
`informational_checks`, with `--json` so CI and agents gate on the task's
scope. Pairs with P20's seam capability report as the operator-facing half of
the same honesty surface. Source:
[35](rea/35-skills-and-agent-layer.md) steal 2, README #8.

## P32 — Contributor skill for driving the harness + doctrine (docs + skills)

**The 23-command surface has no operator manual.** A short,
routing-shaped SKILL.md pointed inward — when to run `classify` vs `translate`
vs `auto` vs one evidence command; the routing facts (managed PE → parked
per ADR-0044, EXE vs DLL → which lane) — with per-engine recipes and the
failure playbook in `references/`, progressive disclosure over a 1,390-line
design doc. Same track carries the doctrine steals: don't-repeat /
remediation-literalism rules into `AGENTS.md`, dated doc-claim pinning for
version skew, and machine-discoverable trigger/scope metadata on the
development skills. Source:
[35](rea/35-skills-and-agent-layer.md) steals 1+3+4+5, README #8.

## P33 — Whole-task measurement harness (dev-side)

**Nobody knows what one pipeline task actually costs or which change moved
it.** REA's `experiments/analysis-efficiency` shape: question/spec files, a
measurement script, and oracles independent of the implementation under test,
reporting tokens, RSS, and milliseconds per whole task with explicit state-
ment of what the run doesn't establish — counting schema transport, retries,
and continuations in every token claim, and refusing to generalize a narrow
warm-path win. calxgloss grows the analogue: pinned end-to-end tasks (binary
→ baseline → translated → verified) benchmarked across harness changes, so
tier and context-budget decisions ride measurements instead of intuition —
the discipline every other track's cost claims should stand on. Source:
[31](rea/31-deep-native-analysis.md) steal 5,
[35](rea/35-skills-and-agent-layer.md) (measurement discipline, :102–105).
