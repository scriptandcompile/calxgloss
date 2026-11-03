# LLM4Decompile — complete overview & calxgloss comparison

> **LLM4Decompile** ([albertan017/LLM4Decompile](https://github.com/albertan017/LLM4Decompile),
> MIT code + DeepSeek-licensed weights) is the reference open-source line of
> **fine-tuned LLMs for decompilation** — asm/Ghidra-pseudo → C, judged by
> **re-executability** — from the EMNLP 2024 paper through Decompile-Bench to
> SK²Decompile: the opposite ontology to calxgloss (which keeps no knowledge
> in weights at all) while agreeing with it on the one oracle that matters.
> This directory is a complete overview of every part of LLM4Decompile (repo,
> releases, papers, models, datasets, eval harnesses, tooling), compared
> against calxgloss. Reviewed at HEAD `85b364b` (2026-02-12, 219 commits, no
> tags); calxgloss at HEAD `40fbf91f` (2026-10-31); see
> [scope and method](00-scope-and-method.md).

## Executive summary

**LLM4Decompile bakes decompilation into weights; calxgloss keeps it in
readable artifacts.** Their line — V1 → V1.5 End (objdump asm→C) → V2 Ref
(Ghidra-pseudo refinement) → 9b/22b → v1.6 Decompile-Bench → SK² skeleton/skin
with VERL/GRPO RL — trains DeepSeek-Coder/Yi-Coder/Codestral bases on up to
2M curated pairs from 100M raw ([33](33-models-training-and-data.md)), up to
"under $20 / 3.5 h on one A100" replications included. calxgloss drives
off-the-shelf local models with 15 evidence scans and fixes wrong
translations by re-scan/re-prompt/retry, never retraining
([10](10-calxgloss-baseline.md), [33](33-models-training-and-data.md)).

**They agree with calxgloss on the oracle — and disagree on everything
around it.** Their own docs argue n-gram/edit-similarity mislead and
compiled re-execution is the adjudicator (`legacy-test/README.md:15-22`,
EMNLP-published); SK²'s RL reward gates on compilation. But their oracle
fires **offline, once, at benchmark time**; calxgloss fires it **in-product,
per unit, every attempt** (compile + Wine baselines + trace containment,
ADR-0057), files honest unknowns, and never applies model-invented names —
while SK² Phase 2 exists precisely to invent names that land verbatim
([32](32-evaluation-and-effectiveness.md), [40](40-comparison.md)).

**They measure — and their measurement still cannot be trusted end-to-end.**
This dossier's decisive finding: same checkpoint scores 27.3% vs 16.22%
across harnesses without reconciliation; headline "+40.1%"/">100%" claims are
README-internal arithmetic; the BringUpBench flagship's harness splices an
undocumented, hand-assembled `content-fix` field whose forensics say *edited
IDA pseudocode*, not model output ([32](32-evaluation-and-effectiveness.md) §10);
checked-in reports predate their commit; zero CI, zero tests, and a 13-item
staleness ledger (dead quick-starts, broken imports, license contradictions)
in a repo idle since 2026-02-12 with 43 open issues
([20](20-llm4decompile-inventory.md) §9–§10). The research record itself is
real (EMNLP 2024 main; Decompile-Bench NeurIPS data record; the rumored
"second LLM4Decompile paper" at arXiv:2403.17246 is a refuted phantom —
[31](31-research-lineage-and-papers.md) §6).

**The steal direction inverts every previous dossier: their substrate is the
gift.** calxgloss has no scored eval at all (P33) and no CI (P42); LLM4Decompile
publishes CC0 corpora (`decompile-eval`, 75,610 rows, per-opt-level, C+C++),
MIT metric/harness code, and a whole-program rebuild-and-test harness
(BringUpBench) — exactly the eval substrate our roadmap is missing — plus a
battery of mechanical CI checks reverse-engineered from their defects
([40](40-comparison.md)).

## Capability matrix (condensed — full 14-row table in [40](40-comparison.md))

Winner in **bold**. "—" = absent.

| Capability domain | LLM4Decompile | calxgloss | Verdict |
|---|---|---|---|
| Where knowledge lives | fine-tuned weights (2M pairs, GRPO RL) | 15 scans, DBs, ADRs; model untouched | split — opaque+frozen vs inspectable+correctable |
| Evidence into prompts | single text blob per function | 15 whole-binary scans → 5-tier evidence bundle | **calxgloss, by orders of magnitude** |
| Verification oracle | same gate (compile + re-execute) — offline, at benchmark time | same gate in-product, every attempt + Wine baselines + trace containment | **calxgloss on placement** — same oracle, opposite position |
| Naming | SK² invents names, applies verbatim | never applies; names = scored evidence; types-only write-back | split by doctrine |
| Evaluation substrate | HumanEval-Decompile 164×4, ExeBench, DecompBench 70K, BringUpBench, metric code | none (P33 open), one fixture DLL | **LLM4Decompile, decisively** |
| Measurement hygiene | contradictory scores, README math, `content-fix` finding, zero CI | no aggregate number to rot; provenance-typed verdicts | split — numbers-without-provenance vs provenance-without-numbers |
| State & provenance | stateless batch; reports predate commits | attempt branches, kept failures, verdicts, unknown ledgers | **calxgloss, non-negotiable** |
| License | MIT code, but weights under DeepSeek license (PRC law, no-military), HF tags contradict it | MIT throughout, no weights | **calxgloss** — clean code/CC0 data still stealable |

## What calxgloss should steal (aggregated — full argument in [40](40-comparison.md))

1. **The eval substrate itself (P33)**: CC0 `decompile-eval` corpora + MIT
   metric code, per-opt-level scenario axis (our Wine-evidence-class analog),
   one-record-per-function with `ida_*`/`ghidra_*` baseline columns.
2. **BringUpBench's whole-program shape as P33's gold tier**: isolated
   workspace + exact splice + `make test`, replacement/compilable/executable
   triple, failures keyed by `path::func@0xaddr` (P26-adjacent).
3. **Provenance discipline learned from their rot**: per-number
   (harness, corpus, scenario-set, build SHA, date) pins; reports embed their
   generating git SHA; one regenerable numbers table; "scored N of M" drop
   tallies and judge-fail rates as first-class columns.
4. **Three P42 CI checks, each copied from one of their defects**: README
   commands must run/`--help`; training/inference/docs instruction strings
   byte-identical; repo-wide grep gate for absolute personal paths. The
   13-item staleness ledger is free negative evidence for P42 (twice now,
   with [ReverserAI's 23-month broken flagship](../reverser_ai/40-comparison.md)).
5. **Reward shapes as scorer shapes, no training**: `exe_type.py`'s
   compile-⊕-Jaccard gate; the stated modified-R2I rule ("score 0, never
   discard") as the adjudication rule we must state explicitly.
   **Rejected**: their weights (DeepSeek license + architecture mismatch),
   SK²'s verbatim name recovery (violates ADR-0020/0021), GPT-judge-as-reviewer.

## What LLM4Decompile confirms about calxgloss's choices

- **Compile+re-execute is the field's consensus oracle**, argued in print at
  EMNLP 2024 — calxgloss's gate is not an idiosyncrasy; and the 2026
  ExeBench-FHD critique confirms our stronger variant (Wine values + trace
  containment) targets the fidelity gap their oracle leaves open.
- **Structure-before-identity is load-bearing in both ontologies**: SK²'s
  skeleton/skin split reproduces calxgloss's naming *sequence* while
  rejecting its trust rule — strong evidence the ordering is right and only
  the end-of-pipeline trust decision differs.
- **The fine-tuning bet is real and measurable** (16.22→27.3→45.4 within
  their C-only harnesses), which sharpens rather than refutes calxgloss's
  opposing bet: the honest response is P33 running *their* CC0 corpora
  against *our* verified units, making the comparison measurable instead of
  doctrinal.
- **Measurement without provenance is worse than honest nulls**: a 7,195★,
  three-paper, genuinely-measuring line shipped contradictory scores and an
  unverifiable flagship metric — calxgloss's "no aggregate score yet" is the
  safer failure state, and P33's design bar is set by their mistakes.

## File index

| File | Domain |
|------|--------|
| [00-scope-and-method.md](00-scope-and-method.md) | scope, method, pinned HEADs, verified repo metadata |
| [10-calxgloss-baseline.md](10-calxgloss-baseline.md) | calxgloss capability inventory (comparison anchor, HEAD `40fbf91f`) |
| [20-llm4decompile-inventory.md](20-llm4decompile-inventory.md) | complete repo surface, corpora at HEAD, packaging/Docker, staleness ledger, CI/test absence |
| [21-history-and-releases.md](21-history-and-releases.md) | 219-commit archaeology, six contributors, HF-first release ladder, PR/issue ledger |
| [31-research-lineage-and-papers.md](31-research-lineage-and-papers.md) | the three arXiv records, EMNLP/NeurIPS trails, refuted 2403.17246 phantom, claims-vs-artifacts |
| [32-evaluation-and-effectiveness.md](32-evaluation-and-effectiveness.md) | harness forensics, corpora counts, judge, BringUpBench, the `content-fix` finding |
| [33-models-training-and-data.md](33-models-training-and-data.md) | HF artifact ledger, base-model forensics, license ledger, SFT/GRPO stacks, dataset ledger, numbers ledger |
| [34-tooling-and-workflows.md](34-tooling-and-workflows.md) | quick-start dissection, serving stack, Ghidra/IDA scripts, SK² CLI, what still runs |
| [40-comparison.md](40-comparison.md) | full 14-domain comparison, effects, steal list, confirmations |

## Citation notes

LLM4Decompile claims cite clone-relative `path:line` against
`/tmp/opencode/LLM4Decompile` at `85b364b`; history claims cite `<sha> <path>`;
web claims cite fetched URLs (arXiv, ACL Anthology, Hugging Face APIs, GitHub
API — all fetched 2026-10-31). Inside [32](32-evaluation-and-effectiveness.md)
the `bringupbench/…` shorthand resolves to
`sk2decompile/evaluation/bringupbench/…` (full path given at first mention).
calxgloss claims cite crate-relative paths (resolved under
`crates/<group>/calxgloss-*/…`) at HEAD `40fbf91f`, or ADR numbers. All
`path:line` citations were mechanically audited 2026-10-31: 523 total, 444
resolved to in-range lines at the pinned clone HEAD, 0 out-of-range; the
79 unmatched are by design — negative findings (`setup.py`,
`sk2decompile.py`, `data/decompile-eval.json` as *deleted/absent* citations),
deliberately ambiguous duplicates (both `llm_server.py`/`cal_execute_rate.py`
copies, md5-compared in text), HF-side file names (`config.json`, model cards)
resolved by the cited API fetches, and calxgloss-side crate paths that resolve
under `crates/<group>/`. Two cross-chapter slips ("calxgloss has CI") were
corrected against the baseline during assembly.
