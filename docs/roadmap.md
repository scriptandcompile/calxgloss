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
> recorded as ADRs in `docs/adr/` (W0 → ADR-0002, W1 → ADR-0003, W2 →
> ADR-0004, W3 → ADR-0005, W4 → ADR-0006, G1 → ADR-0007, X2 → ADR-0008,
> P1.5 → ADR-0009–0013, X5 → ADR-0041, P35 → ADR-0048, P36 → ADR-0049,
> P37 → ADR-0050, P38 → ADR-0051, P39 → ADR-0052, P19 → ADR-0053,
> P20 → ADR-0054–0055).

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
comparison](rea/README.md) (`docs/rea/`, each chapter's "Steal ideas").**
**P19 (admitted semantics — a coverage record beside every evidence scan)
shipped through tickets #345–#351, with close-out record #352, and was
removed from this matrix when spec #344 closed (2026-10-26).** The data
honesty it introduced lives on as
[ADR-0053](adr/0053-scan-coverage-is-the-scans-own-record-stamped-at-scan-time-beside-provenance-read-as-unknown-when-absent-and-pinned-to-the-engines-declared-facets.md):
the admitted-coverage envelope (each scan states how much of the program
it could read and says plainly where it fell short), the
absent-reads-as-unknown rule (a read that is missing records *unknown*,
never "nothing there"), and the engine-stamps/roster-pins doctrine (each
evidence engine stamps its own coverage into its record at scan time, and
a roster test pins each evidence engine's declared facets one-for-one).
The data side of P21 and P26 is unblocked.
**P20 (seam capability report + engine-identity cache key) shipped through
tickets #354–#358, with track close-out #359, and was removed from this
matrix when spec #353 closed (2026-10-27).** The honesty it introduced
lives on as
[ADR-0054](adr/0054-the-seam-admission-line-is-a-run-path-only-exemption-to-the-run-equals-show-report-identity-because-capability-is-live-session-state-not-a-filed-document.md)
and
[ADR-0055](adr/0055-the-seam-answers-for-its-own-surface-and-the-cache-names-the-build-that-answered-capability-pinned-one-for-one-to-the-seams-own-read-and-engine-identity-keys-the-scan-read-cache.md):
the seam reports which questions it can answer right now, and every cached
answer names the analysis engine build that produced it, so a later
analysis-engine swap can never replay stale answers. P21 is unblocked.
**Table order is dependency order** — no track appears before another track
that blocks it (each summary below names which tracks block it and which
tracks it blocks). Among tracks that do not block each other, the order is
by how far each one moves calxgloss toward **complete end-to-end
restitching from binaries**: first, honest records of what the evidence
engines could not determine (P21); then a verification gate wide enough to
cover what restitching can actually get wrong (P22–P24); then the durable
receipts and the fail-closed ledger that finally make "this binary is
done" a checkable claim instead of "the pipeline stopped with nobody
complaining" (P25–P26). P27–P33 resolve stuck functions, strengthen
evidence, or serve operations; none of them blocks a track listed above
it.

**P34–P39 are architecture deepening tracks from the 2026-10-24 codebase
review. A standing decision keeps them at the top of this matrix: they must
be worked before anything else in this matrix.** Inside the group, only P39
was ever blocked — by P34's descriptor row. All six have shipped, and each
was removed from this matrix when its spec closed:

- P34 (evidence-scan registry) shipped through tickets #302–#308, its
  follow-up #309 is closed, and it was removed when spec #301 closed
  (2026-10-24).
- P35 (evidence-bundle projector) shipped through tickets #311–#314 with
  the verification close #315, and was removed when spec #310 closed
  (2026-10-25).
- P36 (prompt bundle through the templates) shipped through tickets
  #317–#320 with the verification close #321, and was removed when spec
  #316 closed (2026-10-25).
- P37 (pipeline assembly from settings) shipped through tickets #323–#327
  with the contract close #328 and the record close #329, and was removed
  when spec #322 closed (2026-10-25).
- P38 (the attempt seam over the retry loop) shipped through tickets
  #331–#334 with the pin close #335 and the record close #336, and was
  removed when spec #330 closed (2026-10-25).
- P39 (one CLI scan command per registry row) shipped through tickets
  #338–#342 with the pairing pin #342 and the record close #343, and was
  removed when spec #337 closed (2026-10-25). That completed the group.

Together they pay off by making every later Evidence track (P19–P21, P28)
and the retry-loop hypothesis ledger (P27) cheaper to ship:

- one place to add an evidence engine: one registry row plus one CLI
  contribution entry, with a roster test pinning the two lists to each
  other one-for-one (shipped — P39, ADR-0052);
- one place to read an evidence engine's findings into one evidence bundle
  (shipped — P35, ADR-0048);
- one place to render that bundle into the prompt templates (shipped —
  P36, ADR-0049);
- one place to assemble the pipeline from settings (shipped — P37,
  ADR-0050);
- one attempt seam through which every retry passes (shipped — P38,
  ADR-0051).

| # | Track | Crate | Effort | Status | Next step | Epic |
|---|-------|-------|--------|--------|-----------|------|
| P21 | First-class unknown records — for each function, record what the evidence engines could not determine and what evidence would close the gap; the review UI resolves these records, `escalate` retries use them, and the run ends with an audit ledger | shared (`calxgloss-types`) + pipeline (`calxgloss-translator`, `calxgloss-git`) + interface (`calxgloss-web`, `calxgloss-cli`) | — | ⬜ not started | not specced | — |
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
| P41 | Producer for the `re/analysis/` per-function artifacts — the workspace layout promises them and the web API Mapping panel reads them, but nothing writes them; persist `FunctionInfo` at analysis time or back the panel live | pipeline (`calxgloss-translator`) + interface (`calxgloss-web`) | — | ⬜ not started | filed as issue, not specced | [#366](https://github.com/scriptandcompile/calxgloss/issues/366) |

**P40–P41 are product gaps found by the 2026-10-28 plain-English sweep**:
features the docs, tests, or UI promise that the code never delivers. Each
was verified in the code and filed as an issue before landing here; the
sweep left honest doc notes in place describing today's behavior, and each
track must reconcile those notes with whatever it builds.

Legend: ✅ done · 🔶 in progress · ⬜ not started.

## P21 — First-class unknown records (shared + pipeline + interface)

**Silent gaps today, audit ledger tomorrow.** When the evidence engines
cannot determine something — an ambiguous vtable target, an unresolved
this-pointer, an export no baseline ever calls — the fact disappears
entirely. Make each function's unanswered question a first-class unknown
record, in REA's record/update/verify shape: each record holds a question,
a severity, and `required_evidence` naming what would close it, with a
lifecycle guarded by revisions. The review UI surfaces these records and
lets reviewers resolve them, and `escalate` retries use them as prompt
input. The run then ends with an auditable ledger of what was never
established, instead of a queue that simply went quiet. It builds directly
on P19's coverage fields (the gap must be visible in the data before it can
be recorded) and P20's seam capability report (not observed is not the
same as observed absent). The capstone P26 ledger reads it: an open unknown
must block a "DLL complete" verdict. Source:
[33](rea/33-reconstruction-evidence-workflow.md) steal 1, README #1.
Blocked by: P20 (shipped with the seam-capability track,
ADR-0054–ADR-0055) and P19 (data side shipped with the admitted-semantics
track, ADR-0053) — unblocked. Blocks: P26, P27.

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
[34](rea/34-runtime-observation.md) steal 1, README #5. Blocks: P25, P26
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
[34](rea/34-runtime-observation.md) steal 2, [32](rea/32-native-artifact-intelligence.md)
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
never a bare-PID kill) and Frida's spawn-paused→load→resume order. P26
cannot return an honest verdict on an EXE until this exists. Source:
[34](rea/34-runtime-observation.md) steals 3+5. Blocks: P25, P26, P27.

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
[33](rea/33-reconstruction-evidence-workflow.md) steal 5. Blocked by
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
[33](rea/33-reconstruction-evidence-workflow.md) steals 2–3, README #2.
Blocked by: P19 (data side — shipped, ADR-0053; the `unknown` value the
verdict reads is in place), P21, P25 (hard); P22–P24 (shape — the verdict
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
pairs with P21's ledger as that ledger's consumption side. Source:
[34](rea/34-runtime-observation.md) steal 4. Blocked by: P21 (the
unknown), P24 (the runtime dimensions to correlate against).

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
[31](rea/31-deep-native-analysis.md) steal 1, README #4.

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
[31](rea/31-deep-native-analysis.md) steal 4. Pairs with: P21 (consumption
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
[32](rea/32-native-artifact-intelligence.md) steals 2+3+5.

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
[35](rea/35-skills-and-agent-layer.md) steal 2, README #8.

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
[35](rea/35-skills-and-agent-layer.md) steals 1+3+4+5, README #8.

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
claims should stand on. Source:
[31](rea/31-deep-native-analysis.md) steal 5,
[35](rea/35-skills-and-agent-layer.md) (measurement discipline, :102–105).

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
and retire the file-layout promise; `docs/rea/02-workspace-layout.md`, the
web handler's provenance note, and `FunctionInfo`'s docs all need
reconciling either way. Filed as
[#366](https://github.com/scriptandcompile/calxgloss/issues/366) during the
2026-10-28 plain-English sweep.
