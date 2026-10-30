# Calxgloss Roadmap — Methodology Tracks

> **Purpose:** index of all open tracks — status, dependencies, and what's
> next. This is the *roadmap*, not the plan of record for active work.
>
> **Where plans live:** when a track is picked up, publish its detailed plan
> to GitHub Issues (`scriptandcompile/calxgloss`) via `/to-spec` →
> `/to-tickets` (tickets carry native blocking links and triage labels).
> Then add the epic link to the status matrix below. `/implement` works the
> tickets; `CHANGELOG.md` stays the record of what shipped.
>
> **Where done tracks go:** a completed track is removed from this roadmap —
> its shipped history lives in `CHANGELOG.md` and its key decisions are
> recorded as ADRs in `docs/adr/`.

## How a track gets built

1. Pick the next unblocked track from the matrix (table order = priority).
2. `/to-spec` — write the track summary here (plus its archive section) up
   into a spec issue.
3. `/to-tickets` — break the spec into tracer-bullet tickets with blocking
   links; label them `ready-for-agent`.
4. `/implement` — drive the tickets (tdd + code-review per ticket).
5. Update this matrix when a phase completes.

Test counts in the archive are indicative targets, not exact requirements.

## Status matrix

**Tracks P19–P33 are the feature ideas collected by the [REA
comparison](research/rea/README.md) (`docs/research/rea/`, each chapter's
"Steal ideas"). P19 (admitted semantics), P20 (seam capability report +
engine-identity cache key), and P21 (first-class unknown records) shipped
and left this matrix per the rule above
(ADR-0053–ADR-0056), so the verdict tracks P26 and P27 are unblocked on
their record side.**
**Table order is dependency order** — no track appears before another track
that blocks it (each summary below names which tracks block it and which
tracks it blocks). Among tracks that do not block each other, the order is
by how far each one moves calxgloss toward **complete end-to-end
restitching from binaries**: first, a verification gate wide enough to
cover what restitching can actually get wrong (P22–P24); then the durable
receipts and the fail-closed ledger that finally make "this binary is
done" a checkable claim instead of "the pipeline stopped with nobody
complaining" (P25–P26). P27–P33 resolve stuck functions, strengthen
evidence, or serve operations; none of them blocks a track listed above
it.

| # | Track | Crate | Effort | Status | Next step | Epic |
|---|-------|-------|--------|--------|-----------|------|
| P22 | Differential API-call trace in the gate — record the ordered Win32/PAL API-call sequence on both the original-DLL baseline and the restitched Rust, and compare the order; this catches PAL-mapping errors that reach the right result by the wrong path, which value tests miss | pipeline (`calxgloss-testgen`, `calxgloss-verify`) + integrations (`calxgloss-pal`) + evidence (`calxgloss-apidetect`) | — | ⬜ not started | not specced | — |
| P23 | Real inputs for the baseline — argument vectors mined from hooked export entries, plus Windows minidump crash records replayed as concrete reproduction tests; this closes the blind spot of invented inputs | pipeline (`calxgloss-testgen`, `calxgloss-verify`) + interface (`calxgloss-cli`) | — | ⬜ not started | not specced | — |
| P24 | Scenario-capture baseline for EXE targets — a declared scenario contract (scripted interactions, filesystem observation, exit disposition) with a five-dimension compare, as the EXE-level verification signal FFI cannot reach | pipeline (`calxgloss-testgen`, `calxgloss-verify`) + interface (`calxgloss-web`, `calxgloss-cli`) | — | ⬜ not started | not specced | — |
| P25 | Verification receipts — every verification pass persists a digest-paired md+json receipt on the attempt branch (commands, case counts, dimensions, timings); the receipt is durable and diffable between attempts | pipeline (`calxgloss-verify`, `calxgloss-git`) + interface (`calxgloss-reports`) | — | ⬜ not started | not specced | — |
| P26 | Fail-closed restitch conformance — a per-unit obligation ledger (owner = attempt-branch digest, required case kinds, verifier receipt) and a whole-binary closure verdict sealed by a digest; skipped, parked, overridden, or un-reviewed units never add up to complete | pipeline (`calxgloss-git`, `calxgloss-translator`, `calxgloss-verify`) + interface (`calxgloss-web`, `calxgloss-reports`, `calxgloss-cli`) | — | ⬜ not started | not specced | — |
| P27 | Hypothesis ledger for the retry loop — unknowns that cannot be closed are recorded as declared static↔runtime mappings with expected patterns; recorded contradictions decide `escalate` vs `edge_case_fix` and remain as reviewable evidence | pipeline (`calxgloss-translator`, `calxgloss-llm`) + interface (`calxgloss-web`) | — | ⬜ not started | not specced | — |
| P28 | Masked byte search at the seam — `search_bytes(pattern, mask)` with wildcard hex and a bit mask, giving the `consts`/`serialize` magic-number scans real matches instead of guesses | integrations (`calxgloss-decomp`, `calxgloss-kuna`) + evidence (`calxgloss-consts`, `calxgloss-serialize`) | — | ⬜ not started | not specced | — |
| P29 | Ad-hoc call-path / def-use primitive at the seam — trace "how does this value reach this call" over the kept bodies on demand, so `escalate` retries get targeted answers without a full re-scan | integrations (`calxgloss-decomp`, `calxgloss-kuna`) + pipeline (`calxgloss-translator`) | — | ⬜ not started | not specced | — |
| P30 | PE artifact-intelligence pass — block-entropy and debug-directory/note triage turn packing classification into measured evidence, per-subject content digests, and a before/after PE inventory diff as a restitch equivalence tripwire | evidence (`calxgloss-analysis`) + shared (`calxgloss-types`) + pipeline (`calxgloss-verify`) + interface (`calxgloss-reports`) | — | ⬜ not started | not specced | — |
| P31 | Deepen `calxgloss doctor` — read-only, scopable (`--target/--endpoint/--config`), checking LLM endpoint reachability, config validity, PE magic, cache writability, git/cargo presence; `scope_checks` vs `informational_checks`, JSON, exit codes | interface (`calxgloss-cli`, `calxgloss-reports`) + shared (`calxgloss-config`) | — | ⬜ not started | not specced | — |
| P32 | Contributor skill for driving the harness + doctrine — a routing-shaped SKILL.md for the 23-command CLI with per-evidence-engine references, the don't-repeat / remediation-literalism rules in `AGENTS.md`, and dated doc-claim pinning for version skew | — (docs + skills, no crate) | — | ⬜ not started | not specced | — |
| P33 | Whole-task measurement harness — benchmark pipeline tasks end to end (tokens, RSS, ms) with an oracle independent of the implementation, counting discovery, retries, and continuations in every token claim | — (dev-side experiment harness, no crate) | — | ⬜ not started | not specced | — |
| P40 | API-aware complexity mode reaches the prompt — `api_aware` is set by callers but no prompt builder reads it; either wire the mode in or remove it until a design exists | shared (`calxgloss-types`) + pipeline (`calxgloss-translator`) | — | ⬜ not started | filed as issue, not specced | [#365](https://github.com/scriptandcompile/calxgloss/issues/365) |
| P41 | Producer for the `re/analysis/` per-function artifacts — the workspace layout promises them and the web API Mapping panel reads them, but nothing writes them; persist `FunctionInfo` at analysis time or back the panel live | pipeline (`calxgloss-translator`) + interface (`calxgloss-web`) | — | 🔶 in progress | tracer landed (#379): translate files the body-scoped `windows_apis` artifact; the full `FunctionInfo` record and layout reconciliation stay open | [#366](https://github.com/scriptandcompile/calxgloss/issues/366) |
| P42 | CI foundation — calxgloss has no CI at all (no `.github/` anywhere); build, clippy, workspace tests, and the fixture-DLL e2e on every PR, the substrate every scored-eval and drift-check gate in this block runs on | — (infra, no crate) | — | ⬜ not started | not specced | — |
| P43 | Fail-closed sandbox for model output — port KRAKEN's `kraken-confine` vocabulary (read-only system paths, one read-write run dir, rlimits, network denied, refuse-to-spawn when confinement cannot be enforced) around `calxgloss-verify` scratch projects and `testgen`'s Wine runs, replacing the scratch-dir convention | pipeline (`calxgloss-verify`, `calxgloss-testgen`) | — | ⬜ not started | not specced | — |
| P44 | Baseline capture provenance + live-oracle hybrid — stamp `baseline.json` with DLL sha256, the `preflight_wine` Wine version, the harness load base, and the target triple; on a failing test re-run the Wine capture on demand and diff against `baseline.json`, telling "translation broke" from "recording rotted" for one Wine process per case | pipeline (`calxgloss-testgen`, `calxgloss-verify`) + shared (`calxgloss-types`) | — | ⬜ not started | not specced | — |
| P45 | Typed untrusted data on the bundle→prompt path — an `Untrusted<T>` wrapper that fails deserialization without its flag, plus a control/bidi/zero-width sanitizer with visible truncation, on the evidence-bundle sections the P36 templates render; adversarial-string e2e tests through the decomp→prompt path | shared (`calxgloss-types`) + pipeline (`calxgloss-translator`) | — | ⬜ not started | not specced | — |
| P46 | Engine-seam assurance — contract-test the seam so Kuna upgrades fail at the seam not in a pipeline run; record the fixture DLL's scan output as JSON at the pinned Kuna rev, replay it in workspace tests, and drift-check it at every pin bump; named stale-identity fields with one named repair command, a checkpoint-vs-watermark staleness probe, and a `reason:` beside every engine/capability decision | integrations (`calxgloss-kuna`, `calxgloss-decomp`, `calxgloss-testfixtures`) | — | ⬜ not started | not specced | — |
| P47 | Staleness by content hash — stamp each accepted unit with a "made-from" digest of the decompile plus its callees and re-check against observed hashes; the engine-identity cache key (ADR-0055) and bdiff pair whole binaries, but nothing yet notices one function's decompile drifting inside a pinned version | shared (`calxgloss-types`) + pipeline (`calxgloss-translator`, `calxgloss-git`) | — | ⬜ not started | not specced | — |
| P48 | Mechanical pre-refusal before the first model call — length/range/ABI sanity and FFI-harness expressibility checked by pure code; units the harness cannot express (struct-by-value exports today) are refused-and-recorded with reason instead of churning the compile+test loop | pipeline (`calxgloss-translator`, `calxgloss-testgen`) | — | ⬜ not started | not specced | — |
| P49 | Counterexample ordering + verdict honesty rules — feed the smallest disagreeing inputs first, sorted by input size and capped; ">50% unevaluable → no verdict" and "inputs don't reach the logic" as named outcomes on `VerificationResult` | shared (`calxgloss-types`) + pipeline (`calxgloss-verify`, `calxgloss-testgen`) | — | ⬜ not started | not specced | — |
| P50 | Cost as a first-class number — per-attempt cost metering on the attempt records, config-level budgets with a clean stop, and a pre-run estimate that pauses before each batch, built from the existing `token_usage` history | shared (`calxgloss-config`) + pipeline (`calxgloss-translator`, `calxgloss-llm`) + interface (`calxgloss-reports`) | — | ⬜ not started | not specced | — |
| P51 | Evidence-computed confidence, model self-assessment ignored — score name/type suggestions by counting the independent engine evidence kinds that agree, instead of parsing the model's claimed confidence out of the response | pipeline (`calxgloss-translator`, `calxgloss-llm`) + evidence (scan engines) | — | ⬜ not started | not specced | — |
| P52 | Small discipline steals bundle — `--json` printing the result structs' serde JSON from the same definition as the help text; a generated command reference from the clap enum + ADR-0052 rows; bundle-section size/pagination caps as protocol constants; per-slot `origin+version` stamps making ADR-0021's "never overrule" a predicate; prompt-hash provenance per attempt; one exit-criterion test per specced roadmap P; "name the dependents, *then* ask" previews before destructive review actions | interface (`calxgloss-cli`, `calxgloss-web`, `calxgloss-reports`) + pipeline (`calxgloss-translator`) + docs | — | ⬜ not started | not specced | — |

**P40–P41 are product gaps found by the 2026-10-28 plain-English sweep**:
features the docs, tests, or UI promise that the code never delivers. Each
was verified in the code and filed as an issue before landing here; the
sweep left honest doc notes in place describing today's behavior, and each
track must reconcile those notes with whatever it builds.

**P42–P52 are the ideas collected by the [KRAKEN
comparison](research/kraken/README.md) (`docs/research/kraken/`, the README's
"What calxgloss should steal" plus each chapter's "Steal").** They form a
new block and are listed after the older tracks; inside the block the order
is the README's value ranking, starting with CI (P42), because the QA-flavored
steals (P33's scored eval, P46's drift check, P52's exit-criterion tests)
want a runner before they can gate anything. Three steals deliberately fold
into existing tracks instead of opening new ones: the scored truth eval
lands on P33 as its missing oracle, KRAKEN's `process`-oracle shape
pre-designs P24's scenario contract, and trace-armed blame ranking extends
P27's send-back decision.

Legend: ✅ done · 🔶 in progress · ⬜ not started.

## P22 — Differential API-call trace in the gate (pipeline + integrations + evidence)

**Right bytes via the wrong path pass today.** The FFI baseline compares
values only. So it accepts a restitched function that computes the correct
result through the wrong GDI/DirectX route — a PAL-mapping error. Record
the ordered Win32/PAL API-call sequence on both sides: an IAT interposer
around the original DLL in the testgen harness, and PAL wrapper
instrumentation on the Rust side. Store the sequence as an extra baseline
dimension and compare *order*, not membership. `calxgloss-apidetect`
already supplies the expected call shape per function, so this runs fully
automatically with no hand-written driving — keeping exactly the property
REA's observation lanes cannot offer (nobody authors a scenario). This
widens the restitch gate itself, so it must ship before the receipts and
the ledger fix the gate's verdicts in place. Source:
[34](research/rea/34-runtime-observation.md) steal 1, README #5. Blocks: P25, P26
(gate shape).

## P23 — Real inputs for the baseline (pipeline + interface)

**The gate only proves what its invented inputs happened to test.** testgen
builds arguments from export signatures plus type evidence. Real caller
argument vectors never enter. An export that is never called stays untested
while the pipeline counts the function as translated. Two input sources
close the blind spot. (1) Hook the original DLL's export entries during a
baseline or reference-app run, record raw argument vectors as observable
events, and replay them as extra baseline cases. (2) Consume Windows
minidumps REA-style — per-thread registers, fault address, module maps used
only as mapping candidates — turning real crashes into concrete
reproduction inputs and regression tests. The minidump part uses the same
record-and-replay machinery as the hook part, so it ships after the hook
lane. Every new case carries the strongest possible authority:
`controlled-replay` at `observed` confidence — exactly what P26's ledger
will cite. Source:
[34](research/rea/34-runtime-observation.md) steal 2, [32](research/rea/32-native-artifact-intelligence.md)
steal 4. Blocks: P25, P26 (case coverage behind the verdict).

## P24 — Scenario-capture baseline for EXE targets (pipeline + interface)

**`target_dir` holds EXEs, and the FFI gate cannot touch their behavior at
all** — stdin, TUI, GUI, and windowed flows have no baseline, so no
EXE-level restitch can ever be called done. Adopt REA's process-capture
contract as the EXE baseline format: a declared scenario (working dir,
env, scripted interactions, filesystem observation paths, exit +
finalization) captured against the original EXE, then replayed against the
restitched build. Compare the two runs on REA's five dimensions (terminal,
interaction, exit, filesystem, process), with normalization for flaky
output — REA's "authority build and reconstruction" is literally
calxgloss's original-vs-Rust framing. Every instrumented run follows owned
process discipline (an ownership token, rechecked before every signal, and
never a bare-PID kill) and Frida's spawn-paused→load→resume order. KRAKEN
pre-designs part of the contract: run original and restitched side by side,
confined, on the same argv/stdin, diff exit/stdout/stderr, and compare
written files as size+sha256+4 KiB block hashes. P26
cannot return an honest verdict on an EXE until this exists. Source:
[34](research/rea/34-runtime-observation.md) steals 3+5,
[36](research/kraken/36-rewrite-pipeline.md) steal 2, README #9. Blocks:
P25, P26, P27.

## P25 — Verification receipts on the attempt branch (pipeline + interface)

**Verification results exist only inside the running pipeline; the commit
message is the only trace a pass ever leaves.** Each `calxgloss-verify` run
persists a REA-style verification receipt on the attempt branch: an
md+json record whose two files are paired by digest, naming the verifier
command, the baseline-suite digest, the case counts per dimension, the
timings, and the result. That record is durable justification for an
accepted commit. In the style of `compare_bundles`, it is machine-diffable
between attempts, so a reviewer sees exactly what changed between a failure
and its fix. The digest-pairing is what makes the receipt citable
authority: P26's obligation ledger records each unit's status together with
its verifier's receipt digest, so a green claim without a matching receipt
is an input error, not a pass. It is deliberately placed after P22–P24:
receipts fix the gate's verdicts in place, so they should record the gate's
widest agreed shape (values + API trace + mined inputs + scenarios) from
day one, rather than being made again later. Source:
[33](research/rea/33-reconstruction-evidence-workflow.md) steal 5. Blocked by
(shape): P22, P23, P24. Blocks: P26.

## P26 — Fail-closed restitch conformance: obligation ledger + closure digest (pipeline + interface)

**"Queue empty" is not "binary done".** Today calxgloss cannot tell a
complete restitch from a run that stopped with nobody complaining. That is
the gap REA's conformance layer exists to close. Each unit of work gets one
obligation ledger entry: owner = the attempt-branch commit digest (already
an owner with a content digest), the required case kinds
(positive/negative/malformed — testgen can already classify its inputs),
and verifier = the P25 receipt digest. Skipped, parked (ADR-0044),
overridden, and un-reviewed units record their disposition but never count
as verified. An export with no generated baseline case stays `unknown`.
Whole-binary status is fixed by a `closure_digest`. The evaluator is
fail-closed: fail, unknown, skipped, truncated, and parked never add up to
pass. So the dashboard grows a real conformance verdict — the definition of
complete end-to-end restitching, made checkable. Source:
[33](research/rea/33-reconstruction-evidence-workflow.md) steals 2–3, README #2.
Blocked by: P19 (data side — shipped, ADR-0053; the `unknown` value the
verdict reads is in place), P21 (shipped, ADR-0056; the open,
severity-carrying, evidence-demanding record the verdict gates on exists),
P25 (hard); P22–P24 (shape — the verdict
should stand on the widest gate and on a lane for EXEs). Blocks: nothing —
this is the capstone.

## P27 — Hypothesis ledger for the retry loop (pipeline + interface)

**Stuck functions retry on strategy rotation, not on evidence.** Today a
stuck unit gets another attempt because the retry strategy rotates to its
next option, not because anything new is known. When a retry cycle cannot
resolve a P21 unknown, that unknown becomes a declared static↔runtime
mapping, in REA's `correlate_static_and_runtime` shape: a static dimension
(`calls`, `cfg`) paired with a runtime/verify dimension (`exit`,
`filesystem`, API trace), plus an expected pattern (`cochanged`,
`static_only`, `runtime_only`, `both_unchanged`). The retry loop already
produces both sides; the ledger records them together. A recorded
`contradiction` is auditable evidence for choosing `escalate` vs
`edge_case_fix`, and it remains reviewable in the UI instead of being a log
line that disappears. More stuck units close, and fewer end up parked. It
pairs with P21's ledger as that ledger's consumption side. KRAKEN's
trace-armed blame ranking gives the send-back decision a concrete
template: arm a stack capture at the failing address and rank suspect units
unverified-before-verified — today the unit to send back is only a human
guess. Source:
[34](research/rea/34-runtime-observation.md) steal 4,
[36](research/kraken/36-rewrite-pipeline.md) steal 9. Blocked by: P21
(shipped, ADR-0056 — the named unknown to declare against), P24 (the
runtime dimensions to correlate against, and the
scenario failures to blame against).

## P28 — Masked byte search at the seam (integrations + evidence)

**Magic numbers found by frequency, not by match.** The seam gains one
query primitive: `search_bytes(pattern, mask)` — wildcard hex pairs plus an
equal-length bit mask (`pattern a0`, `mask f0` matches a0–af). It reads
initialized analyzed data in address order and never crosses block
boundaries. It reports skipped ranges honestly, as one of P19's admitted
coverage fields. `calxgloss-consts` and `calxgloss-serialize` then match
their magic-number and format-sniffing candidates against real hits instead
of statistical guesses, strengthening the bitflag, enum, and format
evidence in every downstream prompt. The track sits off the main track
chain: it depends on no other track and no other track depends on it — its
value is purely evidence quality. Source:
[31](research/rea/31-deep-native-analysis.md) steal 1, README #4.

## P29 — Ad-hoc call-path / def-use primitive at the seam (integrations + pipeline)

**`escalate` re-scans instead of asking.** calxgloss computes call graphs
for the whole batch at once, but cannot answer one-off structural
questions. The seam gains a budgeted, bounded-expansion primitive over the
kept bodies — it answers "how does this value reach this call" and "which
path connects these two functions" — so escalate retries get targeted
answers without re-running analysis engine reads. If the goal is not
reached and the expansion ran out unresolved, the primitive reports
`unknown`, never `not_reached` (P19's rule again). It pairs with P21: the
unknown ledger names the question, and this primitive is part of how a
retry answers it. Source:
[31](research/rea/31-deep-native-analysis.md) steal 4. Pairs with: P21 (consumption
side).

## P30 — PE artifact-intelligence pass (evidence + shared + pipeline + interface)

**calxgloss parses no PE fact it doesn't have to, and restitching trusts the
loader silently.** Three PE-walking features in one file-intelligence
track. (1) Block-entropy profiles plus debug-directory/build-id/note
parsing, added to the classification warmup: packing and obfuscation
triage becomes measured evidence instead of heuristic name checks, and the
results flag which binaries deserve higher context tiers. (2) Per-subject
content digests — each export, import-table entry, and resource node is
hashed — so scan caches survive binaries that differ only in unrelated
regions, and `libmatch` gets content-addressed library fingerprints. (3) A
before/after PE inventory diff (exports, imports, section digests, cert
table) of the original artifact against the restitched artifact, as a cheap
equivalence tripwire ahead of the test suite, following REA's rule that
comparison scope must match before any "unchanged" claim. Source:
[32](research/rea/32-native-artifact-intelligence.md) steals 2+3+5.

## P31 — Deepen `calxgloss doctor` (interface + shared)

**With an LLM endpoint down, the pipeline has no partial-work path and no
diagnosis.** `calxgloss doctor` stays read-only but becomes REA-scopable:
`--target/--endpoint/--config`. It checks exactly what breaks runs — LLM
endpoint reachability (Ollama/vLLM), config validity, `target_dir` PE
magic, `re/` cache writability, git/cargo presence, and graft freshness.
It splits `scope_checks` (these decide `healthy` and the exit status) from
`informational_checks`, and adds `--json` so CI and agents can gate on the
task's scope. It pairs with P20's seam capability report: together they
form the operator-facing half of the same honesty surface. Source:
[35](research/rea/35-skills-and-agent-layer.md) steal 2, README #8.

## P32 — Contributor skill for driving the harness + doctrine (docs + skills)

**The 23-command surface has no operator manual.** Add a short SKILL.md
shaped as routing, aimed inward at calxgloss itself: when to run
`classify` vs `translate` vs `auto` vs one evidence command, plus the
routing facts (managed PE → parked per ADR-0044, EXE vs DLL → which lane).
Its `references/` carry per-evidence-engine recipes and the failure
playbook, and the skill discloses the 1,390-line design doc's content in
layers instead of all at once. The same track carries the doctrine steals:
the don't-repeat and remediation-literalism rules go into `AGENTS.md`,
dated pinning of doc claims guards against version skew, and the
development skills get machine-discoverable trigger/scope metadata. Source:
[35](research/rea/35-skills-and-agent-layer.md) steals 1+3+4+5, README #8.

## P33 — Whole-task measurement harness (dev-side)

**Nobody knows what one pipeline task actually costs or which change moved
it.** REA's `experiments/analysis-efficiency` shape: question/spec files, a
measurement script, and oracles independent of the implementation under
test. Report tokens, RSS, and milliseconds per whole task, and say
explicitly what the run does not establish. Count schema transport,
retries, and continuations in every token claim, and refuse to generalize
a narrow warm-path win. calxgloss grows the analogue: fixed end-to-end
tasks (binary → baseline → translated → verified) benchmarked across
harness changes, so context-tier and context-budget decisions follow
measurements instead of intuition — the discipline every other track's cost
claims should stand on. KRAKEN names the missing oracle concretely: a
`truth.json` beside the fixture DLL (export names, import pairs, jump-table
span, string list — all already constants in `calxgloss-testfixtures`) plus
a handful of scored, model-free tasks — name-recovery F1, address
containment, import/string Q&A — with a minimum-score gate; the recorded
Kuna-output drift check (P46) runs on the same harness, and record/replay
cassettes of real transcripts come only after the eval exists, not before.
Source:
[31](research/rea/31-deep-native-analysis.md) steal 5,
[35](research/rea/35-skills-and-agent-layer.md) (measurement discipline, :102–105),
[37](research/kraken/37-inference-corpus-eval.md) steals 2–4, README #1.

## P40 — API-aware complexity mode reaches the prompt (shared + pipeline)

**A setting nothing reads.** Callers set `AnalysisOptions::api_aware` and
the flag travels through the pipeline, but no shared prompt builder looks
at it — every builder branches on the complexity mode only, so choosing
"API-aware" currently changes nothing about what the model sees. Either
give the mode a job (prompts that lean on the decompiler's API context,
naming the OS/library calls the function makes) or delete the flag until
there is a design for it. Whichever way, reconcile the honest note now in
`calxgloss-types`' `complexity.rs` with what gets built. Filed as
[#365](https://github.com/scriptandcompile/calxgloss/issues/365) during the
2026-10-28 plain-English sweep.

## P41 — Producer for the `re/analysis/` per-function artifacts (pipeline + interface)

**A panel that is always empty.** The workspace layout promises
`re/analysis/{binary}/{function}.json` and the web function-detail "API
Mapping" panel reads exactly that path — but no production tool ever writes
the file, so the panel 404s on every real workspace. The translate pipeline
already assembles the right data (`FunctionInfo`, including its API
mappings) in memory and then drops it. Either persist it at analysis time
in the documented layout, or back the panel with a live analysis endpoint
and retire the file-layout promise; `docs/research/rea/02-workspace-layout.md`, the
web handler's provenance note, and `FunctionInfo`'s docs all need
reconciling either way. Filed as
[#366](https://github.com/scriptandcompile/calxgloss/issues/366) during the
2026-10-28 plain-English sweep.

## P42 — CI foundation (infra)

**No QA-flavored idea in this roadmap has anywhere to run.** KRAKEN's whole
QA chapter — nightly engine-drift checks, a scored eval with a CI mode,
e2e exit-criterion tests — presupposes a CI calxgloss does not have: there
is no `.github/` anywhere. The first CI is deliberately boring: build,
clippy, workspace tests, and the fixture-DLL e2e on every PR. P33's scored
eval, P46's drift check, and P52's exit-criterion tests all want gates
here, so pick this track first inside the KRAKEN block. Source:
[37](research/kraken/37-inference-corpus-eval.md) steal 1 ("any CI"),
README #0. Blocks (as a runner, not a design): P33's eval, P46, P52.

## P43 — Fail-closed sandbox for model output (pipeline)

**Model output and untrusted DLL bodies run with the user's full
environment.** The verification gate checks behavior *after* code has run:
`calxgloss-verify` compiles and executes translated code in a scratch
project, and `testgen`'s Wine runs execute the original DLL's bodies — both
unconfined behind only a scratch-dir convention. Port KRAKEN's
`kraken-confine` policy vocabulary: read-only system paths, one read-write
run dir, rlimits, network denied — and refuse to spawn when the confinement
cannot be enforced, so the sandbox is a guarantee, not a hope. The same
confinement-based vocabulary (safe-by-confinement to execute, dangerous for
anything that writes) is what a capture step needs the day an agent ever
chooses functions or binaries. Source:
[34](research/kraken/34-ai-assistant-agents-safety.md) steal 4,
[36](research/kraken/36-rewrite-pipeline.md) steal 3,
[35](research/kraken/35-emulation-patching.md) (capture-step ranking),
README #2. Blocks: nothing.

## P44 — Baseline capture provenance + live-oracle hybrid (pipeline + shared)

**Nothing tells the pipeline whether the translation broke or the recording
rotted.** calxgloss captures behavior once through Wine and replays the
recording forever; a capture that has silently drifted is undetectable.
Two moves close the blind spot. (1) Stamp `baseline.json` with the capture
provenance — the DLL's sha256, the Wine version string `preflight_wine`
already probes, the load base the harness saw, and the target triple
compiled for — so drift becomes a detectable mismatch. (2) When a test
fails, re-run the Wine capture on demand against the same inputs and diff
against `baseline.json`: one Wine process per case buys the
`native-process`-equivalent oracle KRAKEN reserves exactly for catching
recording bugs. Pairs with P25/P26: those verdicts fix in place a gate
nothing currently certifies is fresh. Source:
[35](research/kraken/35-emulation-patching.md) steal 1,
[36](research/kraken/36-rewrite-pipeline.md) steal 1, README #3.

## P45 — Typed untrusted data on the bundle→prompt path (shared + pipeline)

**Binary-derived strings reach the prompt with only identifier mangling in
between.** Names, strings, and section contents from the target flow
through bundle sections into the P36 templates; today the only sanitizers
are identifier and filename mangling, and no untrusted marker exists
anywhere. Adopt KRAKEN's decision-61 stack: an `Untrusted<T>` wrapper whose
deserialization fails unless the flag is set, plus an invisible-character
sanitizer (control, bidi, zero-width) that keeps byte spans valid, applied
to the projector's output, with visible truncation. Adversarial-string e2e
tests then feed hostile strings through the decomp→prompt path and assert
the emitted prompt is clean. One small testable crate; the pipeline shape
is untouched. Source:
[32](research/kraken/32-edit-log-undo-gui.md) steal 2,
[34](research/kraken/34-ai-assistant-agents-safety.md) steal 1,
[37](research/kraken/37-inference-corpus-eval.md) (e2e safety row),
README #4.

## P46 — Engine-seam assurance (integrations)

**Nothing fails loudly when Kuna moves.** KRAKEN's engine assurance is a
contract suite every engine passes at the seam, fixtures recorded from the
pinned engine, and a nightly drift check against the pin — the pattern that
would have caught the libmatch dialect miss. Adopt all three for Kuna:
contract-test the seam so an engine-upgrade regression faults at the seam,
not in a pipeline run; record the fixture DLL's scan output as JSON at the
pinned Kuna rev, replay it in workspace tests, and re-check at every pin
bump. The same chapter's staleness diagnostics ride along: named
stale-identity fields plus one named repair command instead of a silent
cold cache, a checkpoint-vs-watermark staleness probe for the loaded
program, and a `reason:` string beside every engine/capability decision.
Source:
[31](research/kraken/31-analysis-engines.md) steals 1–5,
[37](research/kraken/37-inference-corpus-eval.md) steal 3, README #5.
Blocked by (as a runner): P42.

## P47 — Staleness by content hash for accepted units (shared + pipeline)

**An accepted unit never learns its decompile moved.** The scan cache names
the engine build that answered (ADR-0055) and bdiff pairs whole binaries,
but nothing notices one function's decompile drifting inside a pinned
version — a merged unit can rest on a body that is no longer what the
engines see. Stamp each accepted unit with a "made-from" digest of its
decompile plus its callees' bodies, beside the merged artifact, and
recompute staleness against observed hashes on the next open; a stale
accepted unit becomes visible evidence, in P21's terms, not a silent
assumption. Pairs with P26: a closure verdict should be able to say its
units are still fresh. Source:
[36](research/kraken/36-rewrite-pipeline.md) steal 4, README #6.

## P48 — Mechanical pre-refusal before the first model call (pipeline)

**Attempts churn on units the harness could never express.** A
struct-by-value export has never fit the FFI harness, yet the pipeline
spends model calls and full compile+test loops discovering it every time.
Put a mechanical check — length/range/ABI sanity, FFI-harness
expressibility — before the first model request: units that fail it are
refused-to-attempt, with the reason recorded as a reviewable disposition
(P19's honesty vocabulary again), never counted as a pass. KRAKEN's
ABI-fits-registers pre-check and its pure-code patch-plan `validate` are
the model. Source:
[35](research/kraken/35-emulation-patching.md) steal 3,
[36](research/kraken/36-rewrite-pipeline.md) steal 6, README #7.
Pairs with: P26 (a refusal is a recorded disposition).

## P49 — Counterexample ordering + verdict honesty rules (shared + pipeline)

**Failure feedback arrives unranked, and thin evidence still reads as a
verdict.** `test_fix` already feeds failing tests back to the model; adopt
KRAKEN's ordering — sort the disagreeing inputs by input size, smallest
first, cap the set — so the cheapest counterexample leads every repair
attempt. Adopt the two honesty rules as named outcomes on
`VerificationResult`: more than half the cases unevaluable means **no
verdict**, and "inputs don't reach the logic" is its own outcome, never a
silent pass. Pairs with P25: the receipt records what the verdict stood
on. Source:
[36](research/kraken/36-rewrite-pipeline.md) steal 5, README #8.

## P50 — Cost as a first-class number (shared + pipeline + interface)

**calxgloss logs tokens but has no money concept and no pre-run gate.**
Meter cost per attempt onto the attempt record (KRAKEN's per-call ledger
fields — feature, job/run, estimated cost — map cleanly onto it), give
config a budget with a clean stop, and print a pre-run estimate that
pauses before each batch — cheap to build from the existing
`token_usage.json` history. Distinct from P33: P33 measures what a task
costs; this track refuses to start runs that cannot pay. Source:
[34](research/kraken/34-ai-assistant-agents-safety.md) steal 2,
[36](research/kraken/36-rewrite-pipeline.md) steal 7, README #10.

## P51 — Evidence-computed confidence, model self-assessment ignored (pipeline + evidence)

**The model's own confidence is the least trustworthy number in the
response.** KRAKEN scores a name suggestion by counting the independent
evidence kinds that agree on it and discards the model's claimed
confidence outright. calxgloss has fifteen batch scans to make that
counting game real: score name/type suggestions by how many independent
engine evidence kinds agree, and stop parsing confidence claims out of the
response. Pairs with P21: the severity on an unknown record can stand on
the same evidence count. Source:
[34](research/kraken/34-ai-assistant-agents-safety.md) steal 3, README #11.

## P52 — Small discipline steals bundle (interface + pipeline + docs)

**Seven small mechanisms, each one ticket-sized.** `--json` printing
exactly the report struct's serde JSON — the result type carries the
machine shape, one line, progress on stderr — from the same definition as
the help text; a generated command reference from the clap enum plus the
ADR-0052 descriptor rows ("do not edit by hand", the `xtask` pattern);
size/pagination caps on bundle sections as protocol constants — bundle
sections feed the prompt templates uncapped today; per-slot
`origin + version` stamps on type write-back, making ADR-0021's "never
overrule a hand-typed slot" a checkable predicate instead of a policy
comment; prompt-hash provenance per attempt (the fingerprint is already in
`llm_io`) so "why is this merged line what it is" is answerable from the
record; one exit-criterion test per specced roadmap P that fails until the
P is done, as the P-closure ritual; and "name the dependents, *then* ask"
previews on the send-back and archive review actions. Split at ticket
time; nothing here changes pipeline shape. Source:
[32](research/kraken/32-edit-log-undo-gui.md) steals 1+3,
[33](research/kraken/33-automation-command-registry.md) steals 1–3,
[36](research/kraken/36-rewrite-pipeline.md) steal 8,
[37](research/kraken/37-inference-corpus-eval.md) steal 4, README #12.
Blocked by (as a runner): P42 (the exit-criterion tests).
