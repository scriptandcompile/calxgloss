# ReverserAI — complete overview & calxgloss comparison

> **ReverserAI** ([mrphrazer/reverser_ai](https://github.com/mrphrazer/reverser_ai),
> GPL-2.0+) is Tim Blazytko's Binary Ninja plugin that uses **locally-hosted
> GGUF LLMs** (llama.cpp) to suggest semantic names for anonymous `sub_*`
> functions from decompiler (HLIL) output — the same "local LLM does RE on
> consumer hardware" thesis calxgloss is built on, in 1,028 lines of Python.
> This directory is a complete overview of every part of ReverserAI
> (code, releases, distribution, effectiveness record), compared against
> calxgloss. Reviewed at HEAD `1d572da` (tag v1.2, 2026-05-20); calxgloss at
> HEAD `40fbf91f` (2026-10-31); see [scope and method](00-scope-and-method.md).

## Executive summary

**ReverserAI is a label maker; calxgloss is a foundry.** ReverserAI is one
assistive task — name anonymous functions — executed by three BN menu
commands that send a function's HLIL text through a pinned Mistral-7B
Q4_K_M GGUF with a frozen one-shot template and write the result into the
database with zero validation and zero confirmation (undo = Ctrl+Z).
calxgloss automates the whole job — PE directory → behaviorally equivalent
Rust — through a pipeline whose every unit is mechanically verified
(compile + Wine-captured value baselines + API-trace containment, ADR-0057)
and adjudicated in a review UI. ReverserAI is where a human sits today;
calxgloss is where a verdict gets adjudicated. ([32](32-binary-ninja-plugin.md), [10](10-calxgloss-baseline.md))

**The naming axis is the whole comparison, and it inverts.** ReverserAI's
sole output is applied renames (`^sub_[0-9a-f]+$` gate, model output never
checked — sentences, empty strings, regenerated `sub_…` all accepted).
calxgloss *deliberately never renames*: unit identity is the binary-side
name, the engine seam's write side is types-only (ADR-0020/0021), and named
knowledge exists only as scored, confidence-stamped *evidence fed to
prompts* at four layers (imports+PAL, libmatch body signatures, algorithm
patterns, mangling/RTTI). The two projects don't disagree on naming —
they assign it opposite roles. ([32](32-binary-ninja-plugin.md), [10](10-calxgloss-baseline.md))

**"Research" here means configuration, not training — and that's verified,
not inferred.** No paper, preprint, dataset, fine-tuned model, or training
repo of any kind exists (arXiv, Hugging Face, PyPI, Zenodo, Crossref
searches documented in [31](31-ml-model-and-training.md)); the widely
repeated "arXiv:2304.02000" citation is a false attribution to an unrelated
math paper. Every version ever shipped uses off-the-shelf TheBloke GGUFs;
fine-tuning appears only as *future work* in the author's own words. Its
intelligence is pure context engineering — bottom-up call-graph rename
propagation (post-order DFS so renamed callees enrich caller HLIL for
free) plus string/import-xref triage — independently converging with
calxgloss's callee-first ordering and evidence-tier design. ([31](31-ml-model-and-training.md), [32](32-binary-ninja-plugin.md))

**Effect: asserted, never measured — and it carries a cautionary tale.**
The only effectiveness numbers ReverserAI ever published are latencies and
one self-scored 7-row qualitative table; its own talk deck concludes "no
real (code) understanding". Meanwhile its flagship bulk rename shipped
broken for ~23 months: commit `cf8e449` inverted the HLIL guard
(`if f.hlil_if_available != None: continue`), a ruff pass later made it
*look* correct (`is not None`), and no test or CI caught it until v1.2 —
while calxgloss today has *no CI either* (open P42). Neither project has a
scored eval; calxgloss at least has one on its roadmap (P33/P51) and a
verification substrate that makes eval possible. ([31](31-ml-model-and-training.md), [21](21-history-and-releases.md), [10](10-calxgloss-baseline.md))

## Capability matrix (condensed — full 14-row table in [40](40-comparison.md))

Winner in **bold**. "—" = absent.

| Capability domain | ReverserAI | calxgloss | Verdict |
|---|---|---|---|
| Analysis engine | none — rents BN's HLIL | Kuna in-process, 15 batch scans | **calxgloss** |
| Evidence into prompts | HLIL + selection/ordering tricks | 15 scans, 5 context tiers, coverage stamps | **calxgloss, by orders of magnitude** |
| Model layer | embedded llama-cpp-python, pinned GGUFs, frozen template | ADR-0051 seam (llama.cpp/Ollama/vLLM), telemetry | split — reproducible-fossil vs pluggable-instrumented |
| Function naming | applied, unvalidated | never applied; 4 evidence layers, types-only write-back | split by doctrine |
| Verification of model output | — | compile + Wine baselines + trace containment | **calxgloss, non-negotiable** |
| State & reversibility | BN Ctrl+Z, Log window | git attempt branches, verdicts | **calxgloss** |
| Evaluation & QA | zero tests; lint-only CI; 23-mo broken flagship | no CI (P42), no eval (P33), per-unit proof by construction | split — both weak; only one files its gaps |
| License | GPL-2.0+ | MIT | GPL blocks code import outright |

## What calxgloss should steal (aggregated — full argument in [40](40-comparison.md))

1. **The propagation principle (half-stolen already).** ReverserAI's one
   good idea: completed-unit knowledge enriches the text the model reads
   next. calxgloss does the safe half via types-only write-back; **name
   write-back is rejected** — it would launder a scoreable evidence claim
   into prompt text as fact (poisons P51) and break binary-side unit
   identity.
2. **Pinned-GGUF reproducibility cassette.** ReverserAI's byte-frozen
   template + pinned TheBloke model/quant pins is the right shape for
   P33's eval fixtures when calxgloss runs local models in the loop.
3. **Negative evidence, free.** The inverted-guard timeline
   (`cf8e449` → `b4b4cc2` → `1d572da`) is a documented case study for
   P42 (CI) and P33 (eval): lint-only CI made a broken guard *look*
   right for two years.
4. Triage-by-xref (string/import preselection) is ReverserAI's third
   trick, but it is already covered by calxgloss's string-context and
   library-api scan rows — at most a dashboard display idea, not a steal.

## What ReverserAI confirms about calxgloss's choices

- **Local GGUF naming-assist is a UX people adopt** (1,168★, BN
  marketplace, third-party IDA port) — principle 5's economics are real.
- **Context engineering beat fine-tuning as a bet**: the author shipped
  zero trained models, froze one prompt template, and told users to add
  context — independently vindicating calxgloss's evidence-tier design
  over model-fiddling.
- **A naming tool without verification stays a toy**: unvalidated strings
  + Ctrl+Z means a human re-reviews everything manually anyway — exactly
  why calxgloss keeps naming inside the compile+test gate.
- **Independent convergence marks load-bearing walls again**: local
  llama.cpp, callee-before-caller ordering, xref triage,
  discard-when-wrong economics.

## File index

| File | Domain |
|------|--------|
| [00-scope-and-method.md](00-scope-and-method.md) | scope, method, revisions reviewed |
| [10-calxgloss-baseline.md](10-calxgloss-baseline.md) | calxgloss capability inventory (comparison anchor, HEAD `40fbf91f`) |
| [20-reverser-ai-inventory.md](20-reverser-ai-inventory.md) | complete ReverserAI surface: files, packaging, CI, examples |
| [21-history-and-releases.md](21-history-and-releases.md) | v1.0 → v1.2 archaeology, what changed and disappeared |
| [31-ml-model-and-training.md](31-ml-model-and-training.md) | research lineage (all artifacts verified absent), shipped GGUF config, effectiveness record |
| [32-binary-ninja-plugin.md](32-binary-ninja-plugin.md) | BN plugin layer: commands, settings, HLIL guard, traversal, renaming |
| [33-ai-layer-and-prompts.md](33-ai-layer-and-prompts.md) | llama.cpp layer, pinned models, prompt anatomy, token budget, config |
| [40-comparison.md](40-comparison.md) | full 14-domain comparison, effects, steal list, confirmations |

## Citation notes

ReverserAI claims cite clone-relative `path:line` against
`/tmp/opencode/reverser_ai` at `1d572da` (v1.2); files under the
`reverser_ai/` package are sometimes cited in shorthand (`binary_ninja/…`,
`gpt/…`); history claims cite `<sha> <path>` or tags (v1.0/v1.1 paths are
shorthand-resolved at their tags). calxgloss claims cite crate-relative
paths (resolved under `crates/<group>/calxgloss-*/…`) at HEAD `40fbf91f`,
or ADR numbers. Web claims cite fetched URLs. All `path:line` citations
were mechanically audited 2026-10-31: 183 resolved, in-range; two line
spans corrected.
