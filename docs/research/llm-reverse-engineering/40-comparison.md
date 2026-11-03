# 40 — Whole-project comparison: llm-reverse-engineering vs calxgloss

> Part of the [overview](README.md). Per-cell evidence lives in
> [20](20-llm-reverse-engineering-inventory.md)–[34](34-evaluation-corpus-and-effect.md);
> the calxgloss side is the [baseline](10-calxgloss-baseline.md). "LRE" =
> llm-reverse-engineering (see [00](00-scope-and-method.md) for the name).

## 1. One-sentence contrast

LRE is **decompilation-as-chat**: one human, one binary, one conversation —
the model steers 8 radare2 commands, the human's "proof" is a compile click,
a scorecard of ELF-surface metrics, and, finally, the author's own Polish
spreadsheet. calxgloss is **decompilation-as-factory-with-quality-gate**: a
pipeline pre-computes 15 kinds of evidence, the model only translates, the
output must survive compile + Wine-captured baselines + ordered API-trace
containment, and the human rules verdicts over records. LRE optimizes
interactive simplicity at toy scale; calxgloss optimizes unattended
reproducibility with proof.

## 2. Capability matrix

Winner in **bold**; "—" = absent.

| # | Capability domain | LRE | calxgloss | Verdict | Ch. |
|---|---|---|---|---|---|
| 1 | Mission / deliverable | chat-run decompilation of one ELF → merged single-file C | PE/DLL directory → verified cross-platform Rust workspace | different missions | 00, 10 |
| 2 | Behavioral-equivalence oracle | compile success + ELF-surface metrics; MD5 column tautologically "No" | Wine baselines (returns + ordered api-trace) + scratch-project compile/test + containment verdict (ADR-0057) | **calxgloss** | 32, 33 |
| 3 | Whole-task effect measurement | 3-sheet rubric xlsx + README strengths/weaknesses — qualitative, one assessor, but *published* | none (roadmap P33) | **LRE** (non-zero vs zero) | 34 |
| 4 | Analysis-engine depth | `pdc` microcode pseudocode + 8 r2 table commands | Kuna seam + 15 scans + 3 readers (types, memory, sync, callbacks, errhandling, …) | **calxgloss** | 31 |
| 5 | External-library semantics | black box → stub + confabulation (xlsx sheet 3) | apidetect + libmatch + PAL mapping DB (mitigation, unmeasured) | **calxgloss** by design | 31, 34 |
| 6 | Unit decomposition / throughput | one chat per binary; no queue | unit-of-work, call-graph queue, batch/auto, version pairing | **calxgloss** | 31, 33 |
| 7 | Evidence persistence across interactions | tool outputs die with the turn (UI); prompt renders history *after* scratchpad | read cache (binary-hash + engine-identity keyed) + bundle projection | **calxgloss** | 31 |
| 8 | Work history / reversibility | chat JSON + `_v{N}` files + demo-output graveyard | attempt branches per unit, failures archived, structured justification blocks | **calxgloss** | 32 |
| 9 | Human review surface | chat verdict; raw-JSON expander | accept/send-back/patch/skip/batch, diff/attempts/decomp views, overlays | **calxgloss** | 32 |
| 10 | Context management | unbounded history replay, no budget, no tiers | 5 tiers + failure-informed escalation + token logging | **calxgloss** | 31 |
| 11 | Fault handling | LangChain defaults (max_iters=15), errors as strings | named fault monitors + fault_log + recovery guidance | **calxgloss** | 31 |
| 12 | Provider breadth | Ollama **and** OpenAI (`o4-mini`) in one radio click | local-only doctrine (Ollama/vLLM) | **LRE** | 31 |
| 13 | Cost/token transparency | none | `token_usage.json`, `llm_io/log.jsonl`, prompt-strategy log | **calxgloss** | 31, 33 |
| 14 | Format / ISA breadth | ELF x86-64 (gcc/radare2 corpus), C and C++ | PE32/PE32+ x86 Windows, managed PE parked | near-tie; both narrow | 00, 10 |
| 15 | Multi-binary handling | 1 target + thin project-dir mode (decompile still 1 session) | whole `target_dir` + bdiff version pairing | **calxgloss** | 31 |
| 16 | Output architecture fidelity | merging files is the *reported norm* (author's own finding) | per-unit Rust modules + generated shims + PAL | **calxgloss** | 34 |
| 17 | Explanation of AI output | XAI Aspect/Explanation/**Evidence** table (unbound); auto README (fabrication exhibit committed) | justification commit block (factual, terse) | concept **LRE**, honesty **calxgloss** | 32, 34 |
| 18 | Evaluation corpus | 20-example ladder + 3 tier projects + csmith case; one fixture DLL (P33) | — | **LRE** | 34 |
| 19 | Randomized eval generation | CSmith wired into CLI (unused at scale) | — | **LRE** | 33 |
| 20 | Metric honesty (empty ≠ zero) | silent component-dropping, 0.0 sentinels, tautological MD5 | coverage honesty + admission lines doctrine (ADR-0053) | **calxgloss** in principle | 20, 33 |
| 21 | Execution-safety posture | `gcc` on model output, binaries left in-tree, no sandbox | scratch cargo projects; fail-closed sandbox is P43 (open) | tie (both lacking) | 32 |
| 22 | Tests / CI | zero tests, no CI | workspace tests + fixture e2e; no CI (P42) | **calxgloss** | 20 |
| 23 | Project health | solo student; 13 commits; dormant ~17 months; 0★/1 fork; 233 Docker pulls | solo; 57 ADRs; living roadmap; actively kept | different; **calxgloss** is alive | 21 |
| 24 | Automation surface | 2 Typer commands + one Streamlit app | 29-command CLI, web API + SPA, pipeline control, `live`/`serve` | **calxgloss** | 20 |
| 25 | LLM agency in analysis | model picks tools/order/stop | rails: pipeline steers, model translates only (ADR-0051) | **calxgloss** by doctrine (OGhidra's revert corroborates; [40 in OGhidra study](../OGhidra/40-comparison.md)) | 31 |
| 26 | Cross-turn claim consistency | drifts (chat_output two-phase pattern invention; `decompiled_chat_output.c` behavioral drift) | stateless attempts re-fed with evidence | **calxgloss** | 34 |
| 27 | Accessibility / deploy | `docker pull && run` — worked for 233 pulls; minutes to first analysis | Rust workspace + Wine + toolchain; real setup gravity | **LRE** | 21 |
| 28 | Caching / repeat-cost control | none (re-run tools every turn) | tiered scan read cache with staleness rules | **calxgloss** | 31 |

Score is lopsided — unsurprising: one is a year-old student demo, the other
a 34-crate plan-of-record. The two LRE wins that matter are #3, #18–19 and
#12: **measured effect (any kind), a corpus, and provider breadth**.

## 3. Philosophy axes

1. **Agency.** LRE trusts the model to steer; calxgloss rails it (translate
   only). The [OGhidra study](../OGhidra/README.md) found the same ceiling
   from the other direction — its multi-agent orchestrator was reverted by
   its own authors. LRE adds the below-the-line evidence: steering freedom
   on 8 tools bought nothing its fixed prompt-recipe wasn't already
   prescribing (the recipe `analyze→list→decompile→…` at
   `reverse_engineering_agent.py:53-58` is *de facto* a fixed pipeline
   expressed as prose).
2. **What counts as verification.** LRE: compiles ⇒ plausible (its own
   demo dir proves compiles ≠ same-behavior,
   [34 §3](34-evaluation-corpus-and-effect.md)); metrics measure the ELF
   shell, not semantics. calxgloss: executes the *original* under Wine and
   diffs behavior + trace order. Neither repo uses LLM-as-judge — a real
   philosophical agreement across the project family.
3. **Memory.** LRE's unit of persistence is a transcript; calxgloss's is a
   branch. LRE's own repo is the cautionary artifact: four generations of
   demo outputs + two README versions, named only by suffix —
   archaeology, not history ([32 §5](32-streamlit-ui-recompile-metrics-and-sessions.md)).
4. **Honesty mechanics.** LRE reaches honesty the human way — a Polish
   spreadsheet, candid weaknesses, committing its own fabrication exhibit.
   calxgloss reaches it mechanically — admission lines, unknown-never-absent,
   coverage records. Each lacks the other's: LRE has no machine that could
   tell a stubbed JSON parser from a SAX claim; calxgloss has no aggregate
   story to tell a human at all.

## 4. Effect, as far as either is knowable

- **LRE**: works at −O0, unstripped, 50–300-LOC C with familiar algorithms
  (and *fixes bugs* there); partially works on static-link projects (one
  function mangled + its behavior confabulated); fails on external-library
  semantics (parse logic stubbed, invented structures) — every tier graded
  in the open [34](34-evaluation-corpus-and-effect.md). Security-level
  narrative works across all tiers. Confounds (symbols, scale, source-known
  corpus) are not flagged by the author; flagged here.
- **calxgloss**: per-unit proof exists but no whole-task number has ever
  been published (P33); the claim "the evidence layer prevents LRE-class
  failures" is *architecturally plausible and empirically unproven*.
- The mirror-image is the headline: **each project has exactly one of the
  two halves** — LRE has the aggregate-evidence habit without the unit
  oracle; calxgloss has the unit oracle without any aggregate-evidence
  habit.

## 5. Steal ideas (priority order)

1. **Difficulty-ladder + 3-tier corpus for P33.** Flat program → static-link
   project → external-dep project, plus bands (control flow, data
   structures, OS APIs, vtables, deliberate vulns — CWE-121/416/134/190
   demos double as `errhandling`/`memory` scan tests). Re-instantiate as
   MinGW/MSVC PEs over `calxgloss-testfixtures`; ground truth = existing
   testgen baselines, **not** CPG similarity; run both stripped and
   unstripped ([34 §6](34-evaluation-corpus-and-effect.md))).
2. **Randomized known-source generation** (CSmith→PE via MinGW, seeded,
   committed seeds). Removes corpus-scarcity as an excuse for P33 never
   starting ([33 §4](33-cli-csmith-cpg-and-metrics.md))). Use CPG/graph
   similarity only as a *screening* metric with ADR-0053 admission lines —
   and never repeat LRE's omission: compile-both-and-diff behavior exists,
   LRE just never wrote the three lines.
3. **Bound-evidence explanation table** for the review UI: Aspect |
   Explanation | Evidence rows, with each Evidence cell joined from scan
   records/cache docs — an unbound row renders as *unknown*, never prose.
   LRE shipped the shape without the binding and produced the
   `putchar`-confirmed-itself and fabricated-README exhibits; that is
   precisely the failure ADR-0053/0056 machinery turns into refusals
   ([32 §3](32-streamlit-ui-recompile-metrics-and-sessions.md))).
4. **Sheet rubric shape for P26/P33 digests**: overall / problems /
   strengths per tier, with the *evidence-grounded vs output-grounded*
   distinction LRE's sheet-2 strength cell already makes ("LLM takes into
   account the decompiler's information — not just the generated code").
   Compute from records; the digest is a report, not a verdict.
5. **Evidence-flow visualization** for a run (turn graph per
   `app.py:147-204` as UI inspiration, built from `llm_io` + scan
   provenance instead of `intermediate_steps`) — reviewer onboarding aid.
6. **Provider-breadth experiment** (flagged as doctrine change, needs an
   ADR): allow an OpenAI-class model for hard units (typesdb/vtable/
   external-dep cases — exactly where local qwen2.5-7b and o4-mini
   comparisons would be informative) behind config, keeping local-first as
   default; LRE shows one radio click buys that breadth; calxgloss's
   token logging makes the cost consequence measurable immediately.

## 6. Anti-steal ledger (documented so calxgloss never grows these)

- MD5-equality of separately compiled binaries as a "match" column —
  tautological ([33 §2](33-cli-csmith-cpg-and-metrics.md))).
- ELF-surface metrics (first-10k-byte ratio, string-set stats) presented as
  correctness scorecards.
- Cross-turn amnesia of tool outputs; history rendered after the scratchpad.
- One-chat-per-binary with no decomposition — context blowout is structural.
- Silently-dropping metric components / empty-graph 0.0 sentinels.
- Unbound evidence columns; auto-generated prose documentation without
  record joins.
- Eval corpora that are only −O0/unstripped/source-known without reporting
  the confound.
- Fix loops gated by human clicks that don't re-verify automatically
  (AI-fix-suggest but no auto-recompile, [32 §2](32-streamlit-ui-recompile-metrics-and-sessions.md))).

## 7. Verdict

llm-reverse-engineering, read seriously, is **not** a smaller calxgloss — it
is the *same composition* (external analyzer, compiler-as-judge, human
final authority, local model option, zero LLM-judging) minus the four things
calxgloss was built to add: decomposition, durable evidence, a behavioral
oracle, and mechanical honesty. Where the composition alone is allowed to
go — even against friendly, symbol-carrying, −O0 toys — it degrades exactly
along the seams calxgloss's scans name (print semantics, types, library
behavior), and LRE's own author documented that degradation more candidly
than any sibling study's maintainers have. The single durable contribution
to calxgloss is its **evaluation corpus and rubric habit**: it is the only
thing in this repo family, including OGhidra and LLM4Decompile, that shows
an *effort* at published whole-tool effect — and its three tiers, bands,
and named failure classes are the cheapest possible seed for calxgloss's
still-unstarted P33.

## Sources

Every cited fact in the cited chapters (clone `aa74f48`, `file:line`;
GitHub/Docker Hub API records 2026-11-01; xlsx spot-verified verbatim);
calxgloss facts from the [baseline](10-calxgloss-baseline.md); cross-study
reference: [OGhidra 40](../OGhidra/40-comparison.md).
