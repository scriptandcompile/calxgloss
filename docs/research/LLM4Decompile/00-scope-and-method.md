# LLM4Decompile ↔ calxgloss comparison — scope and method

> Part of the [LLM4Decompile overview](README.md). Read this first for what
> is being compared and how.

## What LLM4Decompile is

**LLM4Decompile** ([albertan017/LLM4Decompile](https://github.com/albertan017/LLM4Decompile),
MIT code + a model license) is the reference open-source line of
**fine-tuned LLMs for decompilation**: LLMs trained to turn disassembled
x86-64 Linux function bodies (GCC O0–O3) — or Ghidra pseudo-code — back into
C source. It is the companion artifact of the paper
*"LLM4Decompile: Decompiling Binary Code with Large Language Models"*
(arXiv:2403.05286, Tan, Luo, Li, Zhang — per the repo homepage, published at
**EMNLP 2024 main**, aclanthology.org/2024.emnlp-main.203), extended through
several generations: V1 → V1.5 (End, direct asm→C) → V2 (Ref, Ghidra
pseudo-code refinement) → 9B/22B variants → **Decompile-Bench** (2M training
pairs from 100M raw pairs) → **SK²Decompile** (two-phase skeleton/skin
decompilation, arXiv:2509.22114, with LLaMA-Factory SFT and VERL/GRPO RL
pipelines and a BringUpBench vs IDA-Pro evaluation). Its one headline metric
is **re-executability** — decompiled C is compiled and run against predefined
test assertions; the authors argue explicitly that BLEU/edit-similarity
mislead for decompilation.

calxgloss is *not* a trained model: it is a harness that drives **off-the-shelf
local LLMs** with heavy structured evidence, verifies every translated unit by
compile + Wine-captured behavioral baselines + API-trace containment, and
adjudicates it in a review UI (see [10-calxgloss-baseline.md](10-calxgloss-baseline.md)).
The comparison is therefore fine-tuned-model-ontology vs
evidence-and-verification-ontology — the two opposing answers to "how do you
make an LLM decompile reliably".

## Comparison scope

**In scope** — every part of LLM4Decompile, in depth where it touches
calxgloss's concerns:

- Complete repository inventory at HEAD: every file/folder — `evaluation/`
  (vLLM/TGI/single-GPU runners), `decompile-bench/`, `ghidra/`, `legacy-test/`,
  `sk2decompile/` (Preprocess, LLaMA-Factory SFT, verl RL + reward functions,
  evaluation incl. BringUpBench pipeline), `train/` (ColossalAI,
  DeepSpeed/finetune.py, LLaMA-Factory example), `scripts/`, `samples/`,
  `Dockerfile`, requirements files; packaging, CI (verified absent/present),
  model cards referenced from the repo.
- Full git history and release archaeology: **the repo has no git tags** —
  releases are Hugging Face model drops announced in READMEs — so the
  V1→V1.5→V2→9b-v2→ghidra-100k→Decompile-Bench→v1.6→SK²Decompile→BringUpBench/VERL
  timeline is reconstructed from commits and README update logs; what each
  generation added, renamed (`decompile-eval` → `legacy-test`), or removed.
- The research line: **three real arXiv records** — the 2403.05286 paper and its EMNLP 2024
  publication, the Decompile-Bench data paper (arXiv:2505.12668), and the SK²Decompile paper
  (2509.22114) — plus the **refuted phantom** that a second "LLM4Decompile" exists (the widely
  rumored arXiv:2403.17246 "Huang et al." paper resolves on arXiv to an unrelated robotics paper;
  ch.31 §6 documents the exhaustive query log), and the *actual* third-party name neighbor,
  DecompileBench (Gao et al., arXiv:2505.11340, ACL Findings 2025).
- The Hugging Face artifact family: `LLM4Binary/*` models (1.3b-v1.5, 6.7b-v1.5,
  1.3b-v2, 6.7b-v2, 9b-v2, 22b-v2, 1.3b-v1.6/DCBench, sk2decompile-struct-6.7b,
  sk2decompile-ident-6.7) and datasets (decompile-ghidra-100k,
  decompile-bench, decompile-bench-raw 100M, decompile-bench-bins), including
  base models, licenses, and per-model reported scores.
- Evaluation methodology and effectiveness: the re-executability metric and
  its exact harness, HumanEval-Decompile (164×4), ExeBench (2,621 real
  functions), DecompBench-Eval (70K), BringUpBench (505 functions vs IDA Pro),
  the metrics code (`cal_execute_rate.py`, `cal_edit_sim.py`), the GPT-judge
  and exec/similarity RL reward functions, and every number the project itself
  publishes.
- The tooling layer: objdump preprocessing in the README, Ghidra batch scripts,
  inference servers (vLLM, TGI), training stacks (ColossalAI, DeepSpeed,
  LLaMA-Factory, VERL/GRPO), SK²Decompile preprocessing/normalization, Docker.

**Out of scope**

- Ghidra, IDA Pro, objdump, vLLM, TGI, LLaMA-Factory, VERL internals as such —
  cited only where LLM4Decompile's behavior depends on them.
- The broader LLM-for-decompilation literature (Octet, Decaf, etc.) except
  where the lineage entangles with LLM4Decompile itself (e.g. the name
  collision with 2403.17246, sibling eval work by the same authors).
- Running the models or reproducing scores — this dossier audits the
  artifacts and claims, it does not re-run them.

## Method and sources

- **Primary code source:** a full clone at `/tmp/opencode/LLM4Decompile`,
  HEAD `85b364b` (2026-02-12, "Merge pull request #73 from BaiRiDreamer/main"),
  all 219 commits, no tags. Claims cite clone-relative `path:line` at that
  commit; history claims cite `<sha> <path>`.
- **Repo facts at HEAD** (verified 2026-10-31 via GitHub API): created
  2024-02-28; last push 2026-02-12; 7,195 stars; 567 forks; 47 open issues;
  MIT (code; a separate `LICENSE-MODEL` covers weights); language Python;
  homepage points to the EMNLP 2024 proceedings; 121 tracked files, ≈160 MB
  worktree (checked-in BringUpBench JSONL data).
- **Primary research artifacts:** arXiv (2403.05286 +version history, 2505.12668, 2509.22114;
  2403.17246 fetched to refute the phantom collision), ACL Anthology (2024.emnlp-main.203,
  2025.findings-acl.1194), OpenAlex/Crossref for publication and citation records, Hugging Face
  model/dataset cards under `LLM4Binary` (plus the orphaned `arise-sustech` v1 line). All cited by
  URL.
- **calxgloss side:** [10-calxgloss-baseline.md](10-calxgloss-baseline.md)
  is the fixed anchor, pinned at calxgloss HEAD `40fbf91f` (2026-10-31); its
  claims cite this repo's docs, ADRs, and crates. Same snapshot as the
  [ReverserAI baseline](../reverser_ai/10-calxgloss-baseline.md).

## File index

| File | Domain | Status |
|------|--------|--------|
| [00-scope-and-method.md](00-scope-and-method.md) | this file | done |
| [10-calxgloss-baseline.md](10-calxgloss-baseline.md) | calxgloss capability inventory (comparison anchor) | done |
| [20-llm4decompile-inventory.md](20-llm4decompile-inventory.md) | complete LLM4Decompile surface: files, folders, packaging, Docker, CI, dataset formats | done |
| [21-history-and-releases.md](21-history-and-releases.md) | commit archaeology: V1 → V1.5 → V2 → v1.6 → SK²Decompile, what changed and moved | done |
| [31-research-lineage-and-papers.md](31-research-lineage-and-papers.md) | 2403.05286 / EMNLP 2024, Decompile-Bench 2505.12668, SK² 2509.22114, the refuted 2403.17246 phantom, claims vs artifacts | done |
| [32-evaluation-and-effectiveness.md](32-evaluation-and-effectiveness.md) | re-executability mechanics, HumanEval-Decompile, ExeBench, DecompBench, BringUpBench, metrics code, GPT judge, every published number | done |
| [33-models-training-and-data.md](33-models-training-and-data.md) | HF model family, base models and licenses, ColossalAI/DeepSpeed/LLaMA-Factory SFT, VERL GRPO rewards, datasets at scale | done |
| [34-tooling-and-workflows.md](34-tooling-and-workflows.md) | objdump preprocessing, Ghidra batch, vLLM/TGI servers, SK² preprocessing/normalization, Docker, end-user workflow | done |
| [40-comparison.md](40-comparison.md) | full feature & effect comparison vs calxgloss, steal list, confirmations | done |

## Citation notes

- LLM4Decompile claims cite clone-relative `path:line` at HEAD `85b364b`;
  history claims cite `<sha>` (short) with path.
- Web claims cite fetched URLs (arXiv, ACL Anthology, Hugging Face, GitHub API).
- calxgloss claims cite crate-relative paths (resolved under
  `crates/<group>/calxgloss-*/…`) at HEAD `40fbf91f`, or ADR numbers.
- Verified absences (no CI, no git tags, etc.) are recorded as negative
  findings with the search performed, not left as coverage gaps.
