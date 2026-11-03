# LLM4Decompile ↔ calxgloss — the full comparison

> Part of the [LLM4Decompile overview](README.md). Every LLM4Decompile claim
> below cites this dossier's files ([20](20-llm4decompile-inventory.md)–[34](34-tooling-and-workflows.md),
> clone-relative `path:line` at `85b364b`); every calxgloss claim cites the
> fixed baseline ([10](10-calxgloss-baseline.md), verified at HEAD `40fbf91f`,
> 2026-10-31).

**Bottom line up front: LLM4Decompile and calxgloss are the two opposing
answers to one question — "how do you make an LLM decompile reliably?" — and
they agree on the oracle while disagreeing on literally everything else.**
LLM4Decompile (7,195★, EMNLP 2024 line, idle since 2026-02-12) bakes
decompilation knowledge into fine-tuned open weights — DeepSeek-Coder/Yi-Coder/
Codestral bases trained on up to 2M curated pairs from 100M raw, later
reinforced with GRPO on execution rewards — and proves the result with the
*same* oracle calxgloss runs: the translation must **compile and re-execute
correctly** ([10](10-calxgloss-baseline.md) §Anchors; their manifesto at
`legacy-test/README.md:15-22`). But their oracle fires **offline, once per
benchmark function, at publication time**; calxgloss fires it **in-product,
per unit, every attempt** (compile + Wine-captured baselines + ordered
API-trace containment, ADR-0057). The dossier's decisive finding is that
LLM4Decompile's real weakness is not the weights but the measurement hygiene
around them: three harnesses score the same checkpoints into different ranges
(27.3% vs 16.22% for 1.3b-v1.5), README headline numbers are README-internal
math, and the flagship BringUpBench scores may evaluate **lightly-edited IDA
pseudocode, not model output** at all (ch.32 §10's `content-fix` forensics) —
a 7K-star, EMNLP-published, genuinely-measuring project whose published
numbers still cannot be traced end-to-end. calxgloss currently cannot make
that mistake, because it has no aggregate numbers at all (P33 open) — and
LLM4Decompile's CC0 eval corpora + MIT harness code are exactly the scored
substrate calxgloss's P33/P42 lack, inverting the steal direction of every
previous dossier.

## Capability matrix

Winner in **bold**. "—" = absent.

| Capability domain | LLM4Decompile | calxgloss | Verdict | Ch. |
|---|---|---|---|---|
| Mission & artifact | A **line of fine-tuned models** (1.3b→6.7b→9b→22b, V1→V1.5 End→V2 Ref→v1.6 DCBench→SK²) plus corpora and eval harnesses: the deliverable is weights on Hugging Face | A **harness + review factory**: drives off-the-shelf local LLMs over whole Windows PE32/PE32+ binaries; the deliverable is verified Rust rewrites with verdicts | split — different answers, not competitors; LLM4Decompile answers "which model decompiles best", calxgloss answers "which translation may I trust" | [20](20-llm4decompile-inventory.md), [10](10-calxgloss-baseline.md) |
| Where knowledge lives | In weights: ≤2M curated pairs from 100M raw ([33](33-models-training-and-data.md) §9), SFT three stacks (ColossalAI/DeepSpeed/LLaMA-Factory) + VERL/GRPO RL; fixing a wrong translation means **retraining** ([33](33-models-training-and-data.md) §5–§7) | In readable, versioned artifacts: 15 scan rows, PAL/pattern DBs, libmatch signatures, 57 ADRs; the model is untouched and generic (ADR-0051); fixing a wrong translation means re-scan / re-prompt / retry ([10](10-calxgloss-baseline.md) §Pipeline anatomy) | split — weights are cheap to reuse but opaque and frozen; calxgloss's artifacts are inspectable, correctable, and ADR-documented — see §Convergence for why *their* existence of trained weights doesn't refute *our* bet | [33](33-models-training-and-data.md), [10](10-calxgloss-baseline.md) |
| Input & target | Standalone x86-64 GCC function bodies (objdump at O0–O3) or Ghidra/IDA pseudo → **C**; V2 Ref literally refines Ghidra output (`ghidra/README.md`) | Kuna pseudo-code of `{binary}/{function}` units inside a call-graph-ordered queue → **Rust**, restitched toward whole-binary equivalence (P26 open) | split — L4D's unit is context-free and standalone (no call graph, no binary context); calxgloss's unit is one node of a whole-binary rewrite; their V2 Ref path is the closest analogue to our own prompt path, with a fine-tuner bolted on | [34](34-tooling-and-workflows.md), [10](10-calxgloss-baseline.md) |
| Context into the model | A **single text blob per function** (+ psychec-normalized pseudo in SK² preprocessing, `sk2decompile/Preprocess/`); no whole-binary evidence layer at all | 15 registry scans → coverage-stamped evidence bundle (ADR-0052/0053) → 5-tier ladder with `unavailable`-family pruning and named unknown records (ADR-0055/0056) | **calxgloss, by orders of magnitude** — even SK²'s two-phase skeleton→skin pipeline is one normalized pseudo string per function; there is no xref, no call graph, no PAL anywhere in their pipeline | [34](34-tooling-and-workflows.md) §5, [10](10-calxgloss-baseline.md) |
| Verification oracle | **The same oracle**: compile + run against test assertions ("re-executability"), explicitly rejecting BLEU/edit-sim as primary signal (`legacy-test/README.md:15-22`); SK²'s RL reward literally gates on compilation (`reward_functions/exe_type.py`) — but the oracle runs *offline, per benchmark function*, and its own harnesses read undocumented fields (§Effect) | The oracle *is* the product: `cargo check` + behavioral tests vs Wine-captured baselines + ordered API-trace containment (ADR-0057), every attempt; missing evidence reads *unknown*, never passing (ADR-0053) | **calxgloss on placement, LLM4Decompile on lineage** — same gate, opposite position: a benchmark score at publication vs a per-attempt gate forever; calxgloss's version is strictly stronger (behavioral baselines + trace containment vs their compile+assertion run) | [32](32-evaluation-and-effectiveness.md), [10](10-calxgloss-baseline.md) |
| Naming | SK² Phase 2 ("skin") is **pure identifier recovery**: identifiers are destroyed in Phase 1 (`ida_strip_pseudo`) and invented names land **verbatim** in output source (`sk2decompile/README.md`) | Never applied, by doctrine: names are scored, admission-stamped evidence fed to prompts; write-back is **types-only** (ADR-0020/0021); P51 scores name claims by independent evidence kinds | split by doctrine — L4D trusts invented names because their metric (re-executability) is indifferent to names; calxgloss refuses because names are claims, not facts; the collision is head-on and irreducible ([10](10-calxgloss-baseline.md) §Anchors) | [33](33-models-training-and-data.md), [10](10-calxgloss-baseline.md) |
| Retry loop | Trained **into the weights**: VERL/GRPO with exec+similarity/embedding rewards ([33](33-models-training-and-data.md) §7) | Run **at inference time**: failure-informed retries over typed verdicts, fault monitors; every attempt logged with model/context/token telemetry ([10](10-calxgloss-baseline.md) §Model layer) | split — GRPO's reward is compiled execution, the same signal calxgloss already records per attempt; but a trained retry loop can't be inspected or audited per decision, while calxgloss's retries are verdict-typed records | [33](33-models-training-and-data.md) §7, [10](10-calxgloss-baseline.md) |
| Evaluation substrate | HumanEval-Decompile (164×4), ExeBench (2,621 real functions), DecompBench-Eval (70K, CC0 `decompile-eval` 75,610 rows), BringUpBench (505 functions, whole-program rebuild + `make test`), metric code (`cal_execute_rate.py`, `cal_edit_sim.py`, GPT judge) — plus a 2026 critique of their own ExeBench fidelity (ExeBench-FHD, ch.32) | **None** (open P33): one fixture DLL, no scored eval, no corpus; verification data exists per unit but has never been aggregated into a score | **LLM4Decompile, decisively** — the one axis where they win outright, and the main thing worth taking; calxgloss's roadmap already names the gap (P33/P42) | [32](32-evaluation-and-effectiveness.md), [10](10-calxgloss-baseline.md) |
| Measurement hygiene | Zero repo CI/tests ([20](20-llm4decompile-inventory.md) §10); same checkpoint scores 27.3% vs 16.22% across harnesses with no reconciliation (inventory §9 item 9); 22b 63.6% vs paper 64.18% never reconciled ([33](33-models-training-and-data.md) §10); BringUpBench Avg row doesn't average its own rows (`bringupbench/README.md:24`); "+40.1%", ">100%" are README-internal arithmetic; `content-fix` forensics suggest headline BringUpBench numbers measure edited IDA pseudocode, not model output (ch.32 §10); reports timestamped 2025-11-19 committed 2026-02-12 against later code (inventory §9 item 11) | No aggregate score to rot; but also no CI (open P42), and per-unit proof has never been externally reproduced ([10](10-calxgloss-baseline.md) §Current state) | split — L4D has numbers without provenance, calxgloss has provenance without numbers; the cautionary table (inventory §9, 13 items) is exactly what P33+P42 together would prevent on our side | [20](20-llm4decompile-inventory.md) §9/§10, [32](32-evaluation-and-effectiveness.md) |
| State & provenance | Stateless batch: no per-unit history, no review UI, no unknown ledger; a benchmark score is the whole verdict; checked-in BringUpBench reports are the *only* run artifacts in the repo, and they predate their own commit | git attempt branches `re/{binary}/{function}v{N}`; failure branches kept forever; justification commits carry model + context size; accept/send-back verdicts are persisted state; `UnknownRecord`s by name | **calxgloss, non-negotiable** — a benchmark score records no per-decision provenance; their own artifact timestamps predate their code, the perfect illustration | [21](21-history-and-releases.md) §6, [10](10-calxgloss-baseline.md) §Surface & state |
| Human's role | Nobody in the loop: scores grade themselves; the GPT judge (rubric public, scores private, judge-failure silently counted as 1, ch.32 §8) is the only "reviewer" | Structured verdict review in the web UI (accept · send-back · patch · skip · override · batch) per unit; humans adjudicate, never addresses | **calxgloss** — and their judge-failure silence shows what happens when there is no reviewer at all | [32](32-evaluation-and-effectiveness.md) §8, [10](10-calxgloss-baseline.md) |
| Model economics | Training-side: the ghidra-100k replication pitch "3.5 h on one A100, re-exec 0.26, under $20" (`README.md:27`); zoo of public + gated HF checkpoints, community GGUF mirrors out-download official weights 4:1 ([33](33-models-training-and-data.md) §1) | Inference-side: local-first, no cloud default, discard-when-wrong (principle 5); token telemetry per attempt/tier; no budget number yet (P50 open) | split — opposite halves of the same "repetition should be cheap" bet; neither states a budget envelope; L4D proves training *can* be this cheap, calxgloss bets inference should stay this cheap | [33](33-models-training-and-data.md), [10](10-calxgloss-baseline.md) §Model layer |
| Maintenance | Idle since 2026-02-12 (`85b364b`); 7,195★/567 forks/43 open issues; no tags — releases are README bullets + HF drops; README quick-starts that crash at the flag or filename level ([34](34-tooling-and-workflows.md) §6); strongest late content came from two student drive-by PRs ([21](21-history-and-releases.md)) | Active factory: P-series P23–P52 open, 57 ADRs, shipping within days of HEAD | **calxgloss** — a citable reference implementation now, not a maintained tool; their 13-item staleness ledger is a frozen repo's autopsy | [21](21-history-and-releases.md) §9, [10](10-calxgloss-baseline.md) |
| License | MIT code, but **weights under `LICENSE-MODEL` = verbatim DeepSeek License v1.0** (PRC governing law, military use prohibited, `LICENSE-MODEL:5,51,71,82`), contradicting the HF `license:mit` tags ([33](33-models-training-and-data.md) §3); v1 weights gated behind HF 401s | MIT throughout, no weights to inherit any of this | **calxgloss** — their license tangle (org tag vs LICENSE-MODEL, gated v1, orphan `arise-sustech` line) poisons weight reuse; but their **code and CC0 datasets are cleanly stealable**, which is the point of the steal list | [20](20-llm4decompile-inventory.md) §9 item 6, [33](33-models-training-and-data.md) §3 |

## Effect, measured vs asserted

**LLM4Decompile measures — and still cannot be trusted to its own numbers.**
This is the inversion of the ReverserAI dossier: here the *other* project has a
real eval layer (HumanEval-Decompile 164×4, ExeBench 2,621, DecompBench-Eval
70K, BringUpBench whole-program rebuild) and the papers publish to two
decimals ([31](31-research-lineage-and-papers.md) §3). But the audit
([32](32-evaluation-and-effectiveness.md), [33](33-models-training-and-data.md) §10)
found the numbers untraceable end-to-end:

- **Same checkpoint, different scores**: 1.3b-v1.5 is 27.3% in the root README
  and 16.22% in the DCBench README — same benchmark name, different harness,
  never reconciled (inventory §9 item 9). SK²'s paper scores the *same
  6.7b-v2* family at 41.71/43.05 re-exec because its harness added C++ —
  versus 52.74 in the 2024 README ([33](33-models-training-and-data.md) §10).
  Three harnesses, three ranges, zero canonical table.
- **Headline deltas are README arithmetic**: "+40.1% over V1.5" is
  63.6 ÷ 45.4 − 1 computed from a number (63.6) that contradicts the paper's
  own 64.18 ([33](33-models-training-and-data.md) §10).
- **The flagship BringUpBench result may not measure the model at all**: the
  harness splices `pseudo["content-fix"]` into the source, not the
  `infer-out-model2` fields its own docstring names; forensic similarity +
  IDA-register-comment counts on all 382 rows show `content-fix` behaves like
  lightly-corrected **IDA pseudocode**, not SK² output — and the last splice
  step is hand-assembled anyway (`bringupbench/README.md:161`)
  ([32](32-evaluation-and-effectiveness.md) §10–§11). "SK² beats IDA Pro
  42.3%/27.0% vs 23.6%/21.7%" is, at best, unverifiable from the repo — and
  its Avg row doesn't average its own rows.
- **Silent-failure scoring**: the GPT judge counts unparseable verdicts as 1
  into the mean (ch.32 §8); the R2I entry point dies on a dead import
  (`evaluate_r2i.py:4`, ch.32 §7); checked-in reports predate the code they
  allegedly ran against.
- Even their oracle substrate is under external attack: ExeBench-FHD
  (arXiv:2610.28212, ch.32) shows the re-executability proxy drifts from true
  behavioral fidelity.

What *is* solid: the paper-vs-README v1.5/v2 table reproduces to two decimals
([33](33-models-training-and-data.md) §10), the corpus construction papers
are real (EMNLP 2024, NeurIPS data-track record, ch.31), and the obfuscation
collapse (90.2%→78.0% under CFF/BCF, Table 5, ch.31) is citable independent
evidence that fine-tuned decompilers break on adversarial input.

**calxgloss has per-unit proof but no aggregate score** — the same posture as
in the ReverserAI dossier: every merged unit compiles, passes Wine-captured
behavioral tests, and contains the ordered API trace (ADR-0057); but there is
no scored eval (P33 open), one fixture DLL instead of a corpus, and no CI to
hold the line (P42 open) ([10](10-calxgloss-baseline.md) §Current state).
LLM4Decompile's contribution to this axis is a new warning the previous
dossier couldn't give: **measurement without provenance discipline rots just
as instructively as no measurement at all** — a 7K-star EMNLP-published
project with real benchmarks still shipped contradictory scores, undated
prose claims, and a flagship metric whose input field nobody documented.

## Where the ideas converge

Genuine convergence, this time with one project citing the other's *problem*
in print:

- **The compile+execute oracle as the only metric that matters.** Their
  `legacy-test/README.md:15-22` argues name-normalization makes BLEU/edit-sim
  meaningless and re-executability is the adjudicating signal — a manifesto
  calxgloss can cite for its own compile+test+trace gate, published at EMNLP
  2024 ([31](31-research-lineage-and-papers.md), [10](10-calxgloss-baseline.md)
  §Anchors). SK²'s RL reward gates on compilation for the same reason
  (`exe_type.py`, [33](33-models-training-and-data.md) §7). Same gate; this
  is the strongest convergence in any of our dossiers.
- **Structure before identity, and refinement over one-shot.** SK²'s
  skeleton→skin split says *recover structure first, name it last* —
  structurally the same insight as calxgloss's callees-first queue and
  types-over-names write-back ([10](10-calxgloss-baseline.md) §Naming &
  typing); and V2 Ref's whole reason for existing is that raw Ghidra output
  is an input to be *refined*, which is calxgloss's Kuna-prompt path minus
  the fine-tune ([34](34-tooling-and-workflows.md) §1).
- **Cheap repetition as economics.** Their under-$20/3.5h replication pitch
  (`README.md:27`) and our discard-when-wrong principle 5 are the same bet on
  opposite sides of training vs inference ([10](10-calxgloss-baseline.md) §Anchors).
- **Both re-scored their own task mid-line** — L4D by moving harnesses
  (2024 → DCBench → SK² C+C++), calxgloss by widening gates (trace
  containment, ADR-0057). L4D shows the cost of doing it **without pinning
  (harness, corpus, date) per number**; calxgloss's verdict records are
  already typed and machine-readable, so P33 can aggregate without their
  drift ([21](21-history-and-releases.md) §Steal).

## What calxgloss can honestly steal

Ranked, argued, license-checked — the direction is inverted from previous
dossiers because LLM4Decompile is the first subject whose *substrate* is the
gift, not its workflow. MIT code + CC0 datasets make everything below legally
clean; only the weights are off-limits (DeepSeek LICENSE-MODEL, ch.33 §3 —
and calxgloss doesn't train anyway, so that costs nothing).

1. **The eval substrate itself — P33's missing corpus and harnesses.**
   `decompile-eval` is **CC0, 75,610 rows**, C+C++, per-opt-level, with
   `asm`/`ida_pseudo`/`ghidra_pseudo`/`test` columns
   ([33](33-models-training-and-data.md) §9); HumanEval-Decompile's 164×4 grid
   carries the opt level *inside each entry* ([20](20-llm4decompile-inventory.md) §5);
   `cal_execute_rate.py`/`cal_edit_sim.py` are 2024-era MIT metric code
   ([32](32-evaluation-and-effectiveness.md) §1–§5). Adopt: a scenario-format
   field equivalent to their opt-level axis (per-call-site Wine evidence
   class), and one-record-per-function with `ida_*`/`ghidra_*` baseline
   columns side by side — that schema is why baseline-vs-output comparisons
   reuse one file. Their own obfuscation result (ch.31 Table 5) argues for
   keeping obfuscated scenarios in the corpus, not just on the roadmap.
2. **BringUpBench's whole-program shape as P33's gold tier**
   ([32](32-evaluation-and-effectiveness.md) §9): copy the project into an
   isolated workspace, exact-string splice per function, `make` + project-native
   tests, report the replacement/compilable/executable triple with failure
   listings keyed by `path::func@0xaddr`. This is also the closest thing the
   ecosystem has to P26's whole-binary question — 505 functions inside 90
   whole programs, even if *their* execution of it is broken (ch.32 §10).
3. **Provenance discipline, learned from their failures (mostly negative
   steals).** Every P33 number pins (harness, corpus, scenario-set, build
   SHA, date) — the 27.3/16.22 pair is the citation ([21](21-history-and-releases.md)
   §Steal); run reports embed the git SHA they were generated from (their
   reports' timestamps predate their commit, inventory §9 item 11); one
   canonical numbers table regenerable by script (their claims scatter across
   four READMEs, [32](32-evaluation-and-effectiveness.md) §Steal); "scored N
   of M" with per-reason drop tallies as a first-class report column, judge
   fails marked and reported next to the mean, never silently averaged
   ([34](34-tooling-and-workflows.md) §Steal, [32](32-evaluation-and-effectiveness.md) §8).
4. **Three mechanical CI checks for P42, each directly motivated by an
   L4D defect**: (a) every script/README command at least `--help`s and
   resolves every path it names (their quick-starts crash at filename level —
   `sk2decompile.py` doesn't exist, inventory §9 items 2–3); (b) prompt/
   instruction-string equality: the string used in training, inference and
   docs must be byte-identical — their SK² silently mislabeled its own task
   via three-prompt skew ([33](33-models-training-and-data.md) §8); (c)
   repo-wide grep gate for absolute personal paths (`/home/`, `/workspace/`)
   — the fingerprints [34](34-tooling-and-workflows.md) §6 found are exactly
   what `git grep -E '/(home|workspace)/'` catches. Plus the free negative
   evidence package: the 13-item staleness ledger (inventory §9) is a frozen
   repo's autopsy, usable verbatim to justify P42.
5. **Reward shapes as scorer shapes, no training required**: `exe_type.py`'s
   compile-⊕-placeholder-Jaccard gate and the embedding-cosine identity reward
   are a scorer design calxgloss can copy without the GRPO
   ([20](20-llm4decompile-inventory.md) §Steal) — 0 if uncompilable,
   similarity bonus otherwise — and their modified-R2I scoring choice
   ("score 0, never discard the sample") is the adjudication rule A.2 states
   explicitly, the exact rule calxgloss must *state* for unparseable
   translations (ours: mark-unresolved, ADR-backed; ch.31 §Steal).
6. **Publishing-path template**: Decompile-Bench's NeurIPS datasets-track
   record + the GitHub2025-after-2025 leak-split trick
   ([31](31-research-lineage-and-papers.md)) is the working pattern for
   publishing calxgloss's own scenario corpus credibly.

**Explicitly not stolen**: the fine-tuned weights (DeepSeek LICENSE-MODEL +
PRC law + military clause, [33](33-models-training-and-data.md) §3 — and
calxgloss's whole ontology is generalist-model-plus-evidence, so the weights
wouldn't fit the architecture anyway); SK²'s identifier-recovery stage
(verbatim invented names are the exact laundering ADR-0020/0021 forbids —
their own metric tolerates it because re-executability is name-indifferent,
our trace gate and P51 evidence scoring do not); the GPT-judge-as-reviewer
pattern (ch.32 §8 shows it is the weakest link, not a workflow to copy).

## What LLM4Decompile confirms about calxgloss's choices

- **The generalist-model bet has a measured counterexample to answer — and
  calxgloss's answer is placement of the oracle, not denial.** Their line
  proves fine-tuning + RL on execution rewards *does* lift re-executability
  (16.22→27.3→45.4 within C-only HumanEval-style evals, ch.33 §10). calxgloss
  bets evidence+harness beats weights at the job of *trusted whole-binary
  rewrite*; LLM4Decompile confirms the weights side is real and forces P33 to
  make the comparison measurable rather than doctrinal.
- **Same oracle, independently chosen and defended in print** — the
  compile+execute gate is not a calxgloss idiosyncrasy; it is the EMNLP 2024
  consensus of the largest open decompile project ([31](31-research-lineage-and-papers.md),
  `legacy-test/README.md:15-22`). And the 2026 ExeBench-FHD critique confirms
  calxgloss's stronger variant (Wine-captured values + trace containment)
  targets exactly the fidelity gap the field's baseline oracle leaves open
  ([32](32-evaluation-and-effectiveness.md) §2 of Sources).
- **Structure-first is load-bearing in both ontologies** — SK²'s skeleton/
  skin split independently confirms calxgloss's naming doctrine *sequence*
  (structure recovered before identity asserted) even while rejecting its
  *trust rule* (structure-first, then names verbatim — vs names-first-as-scored-
  claims, never applied). Two projects reading the same decompilation problem
  in the same order is strong evidence the ordering is right and only the
  end-of-pipeline trust decision differs ([10](10-calxgloss-baseline.md) §Naming & typing).
- **Measurement rot is real and publishable**: a project with three papers,
  7,195★ and real harnesses still shipped the contradictions in
  [33](33-models-training-and-data.md) §10 and [32](32-evaluation-and-effectiveness.md) §10.
  This calibrates P33's design bar: aggregation without per-number provenance
  produces *worse* trust outcomes than honest nulls — which is what calxgloss
  currently is ([10](10-calxgloss-baseline.md) §Current state).
- **Zero CI + docs-as-release-process is a failure mode shared with
  ReverserAI, now twice documented** — inventory §9's 13 staleness items in a
  7K-star project, against ReverserAI's 23-month broken flagship
  ([../reverser_ai/40-comparison.md]), is a two-data-point argument that
  calxgloss's still-open P42 is the roadmap's most under-priced item.

## What LLM4Decompile would have to become to reach calxgloss's effect

- **A per-unit verification gate inside a product, not a benchmark**: their
  oracle would have to run per translation, forever, with unknown-when-missing
  semantics (ADR-0053) — i.e. grow `calxgloss-verify`/`calxgloss-testgen`
  around the model instead of around a leaderboard.
- **A state substrate**: attempt branches, kept-forever failure records,
  persisted verdicts, per-attempt model/context/token provenance — their repo
  has none of it, and the `content-fix` finding shows what replaces it when
  provenance is absent: a hand-spliced JSONL field nobody can trace
  ([32](32-evaluation-and-effectiveness.md) §10).
- **Whole-binary context and restitch**: their unit is a standalone function
  with stub+assertions; a call-graph queue, evidence bundles, and the P26
  restitch verdict are a different architecture, not a larger benchmark.
- **A human verdict surface with honest unknowns**: accept/send-back/patch
  per unit vs a GPT judge that silently averages its own failures.

The symmetric question: **for calxgloss to produce LLM4Decompile's effect it
would need to *train* — and that is legislated away** (generalist-model
doctrine, ADR-0051's attempt seam; no training crate exists). But calxgloss
can produce their *measured* effect without weights: P33 running their CC0
corpora + MIT harness shapes against our verified units is a scored number
comparable to their table — which is precisely why the steal list above is
substrate-first, not model-first.

## Verdict

LLM4Decompile is the strongest evidence the open ecosystem has that
compile-and-re-execute is *the* decompilation oracle — and the strongest
caution that an oracle without provenance discipline produces numbers nobody
can trust: a 7K-star, EMNLP-published, genuinely-measuring line still shipped
same-checkpoint contradictions (27.3/16.22), README-arithmetic deltas, a
flagship BringUpBench result whose input field is undocumented hand-spliced
IDA pseudocode (ch.32 §10), and a repo with zero CI and 13 documented
rot-findings. calxgloss stands at the mirror extreme: per-unit mechanical
proof, provenance-typed verdict records, honest nulls — and no aggregate
number at all. The dossier's conclusion is therefore substrate-first for the
first time: the honest steal list is *corpora and harness shapes* (CC0
`decompile-eval`, per-opt-level scenario axes, BringUpBench's whole-program
gold tier, reward-code scorer shapes) plus a battery of mechanical CI checks
each copied from one of their defects — while the weights, the verbatim-name
recovery, and the judge-as-reviewer pattern are rejected on doctrine and
license alike. Their line says "we trained it and proved it once"; calxgloss
says "we gate every unit forever and will prove it in aggregate as soon as
P33 ships" — and this dossier, for the first time, hands calxgloss the
measuring cup.

## Sources

Dossier files (this directory):
- [00-scope-and-method.md](00-scope-and-method.md) — scope, clone provenance
  (HEAD `85b364b`, 219 commits, no tags), GitHub metadata verified 2026-10-31.
- [10-calxgloss-baseline.md](10-calxgloss-baseline.md) — calxgloss anchor at
  HEAD `40fbf91f` (2026-10-31), incl. the ten "Anchors for the LLM4Decompile
  comparison" bullets this chapter expands, ADRs 0002/0020/0021/0051–0057,
  roadmap P23–P52.
- [20-llm4decompile-inventory.md](20-llm4decompile-inventory.md) — §3–§8
  surface inventory, §5 corpus grids, §9 staleness ledger (items cited above
  by number), §10 CI/test absence.
- [21-history-and-releases.md](21-history-and-releases.md) — six contributors,
  four phases, release ladder (HF-first), §7 PR/issue ledger, §9 maintenance.
- [31-research-lineage-and-papers.md](31-research-lineage-and-papers.md) —
  EMNLP 2024 paper record, Table 5 obfuscation collapse, modified-R2I
  protocol, phantom refutation, NeurIPS record for Decompile-Bench.
- [32-evaluation-and-effectiveness.md](32-evaluation-and-effectiveness.md) —
  §2–§6 runner/metric forensics, §7 dead import, §8 judge-failure policy,
  §9 BringUpBench harness, §10 `content-fix` forensics, §11 what artifacts
  can/cannot substantiate, ExeBench-FHD critique.
- [33-models-training-and-data.md](33-models-training-and-data.md) — §1
  artifact ledger (gated v1, orphaned 33B), §3 license ledger, §7 reward
  functions, §8 prompt skew, §9 dataset ledger (licenses), §10 effectiveness
  ledger.
- [34-tooling-and-workflows.md](34-tooling-and-workflows.md) — §3 serving
  bugs, §5 SK² inference CLI, §6 what still runs, interface fingerprints.
- [../reverser_ai/40-comparison.md](../reverser_ai/40-comparison.md) — the
  shared-zero-CI two-data-point argument.

Newly checked for this chapter (2026-10-31):
- calxgloss CI absence re-verified (`no CI at all`, baseline §Verification &
  evidence; ch.20's §Steal line corrected to match), calxgloss HEAD still
  `40fbf91f`.
- `/tmp/opencode/LLM4Decompile` @ `85b364b` spot-checks of load-bearing
  cites: `bringupbench/README.md:12,24` (505 claim, non-averaging Avg row),
  `reports/O0_results.md:6-9` (382/50.26/49.48), `eval_infer_out.py:572-577`
  (report writer), `ghidra/demo.py:46`, `config.env` placeholders,
  `decompile-bench/readme.md:91-94` (run_exe_rate invocation), 682/493-line
  script counts.
