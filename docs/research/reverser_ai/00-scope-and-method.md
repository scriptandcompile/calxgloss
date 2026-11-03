# ReverserAI ↔ calxgloss comparison — scope and method

> Part of the [ReverserAI overview](README.md). Read this first for what is
> being compared and how.

## What ReverserAI is

**ReverserAI** ([mrphrazer/reverser_ai](https://github.com/mrphrazer/reverser_ai),
GPL-2.0+) is Tim Blazytko's (mrphrazer) research project for AI-assisted
reverse engineering with **locally-hosted LLMs on consumer hardware**. It
ships as a **Binary Ninja plugin** whose one shipped capability is the
automatic suggestion of semantic function names from decompiler output,
augmented with static-analysis context. Repo history starts squashed at
creation (2024-03-17). There is **no public research artifact of any kind**:
the frequently repeated "arXiv:2304.02000" attribution is a false citation
of an unrelated math paper, arXiv/Hugging Face/PyPI searches return nothing,
and the README's "research" refers to model-configuration experiments
(per the author's own words). See
[31-ml-model-and-training.md](31-ml-model-and-training.md), which documents
these verified absessions.

## Comparison scope

calxgloss reverse engineers a directory of Windows PE binaries into a
cross-platform Rust workspace via a fully automated LLM pipeline with
verification and human review. ReverserAI is a far smaller, interactive,
single-task assistive tool. The comparison covers **every part of
ReverserAI**, in depth where it touches calxgloss's concerns:

**In scope**

- Complete repository inventory: every file at HEAD, plugin marketplace
  metadata, packaging (`setup.py`; **verified no PyPI package exists** —
  `reverser-ai`/`reverserai` 404 on PyPI), CI, examples.
- Full git history and release archaeology (tags v1.0, v1.0.1, v1.1, v1.2):
  what each release contained, what was added and **removed** between them,
  and what the squashed 2024-03-17 "initial release" commit hides about the
  2023 research lineage.
- The research line: what the 2023 project actually published, whether any
  fine-tuned models ever existed (verified: none in git history or on
  Hugging Face), the off-the-shelf Mistral/Mixtral GGUF configuration the
  project ships, and whatever the project itself reports about measured
  effectiveness.
- The Binary Ninja plugin layer: workflow, decompiler IL used, bottom-up
  call-graph traversal, context enrichment, renaming application, settings.
- The AI layer: model loading (llama.cpp), prompts, context construction,
  token-limit handling, CLI (`scripts/gpt_function_namer.py`), config.

**Out of scope**

- Binary Ninja and its decompiler internals as such — cited only where the
  plugin's behavior depends on them.
- mrphrazer's unrelated projects (unblob, ubpfrev, binary ninja scripts)
  except where they feed ReverserAI directly (e.g. training data sources).
- Broader LLM-for-RE literature; this dossier is ReverserAI ↔ calxgloss,
  not a survey.

## Method and sources

- **Primary code source:** a full clone at `/tmp/opencode/reverser_ai`,
  HEAD `1d572da` (2026-05-20, "Release ReverserAI v1.2 with dependency
  install fixes"), all 25 commits and tags v1.0/v1.0.1/v1.1/v1.2 present.
  Claims about ReverserAI code cite clone-relative `path:line` at that
  commit; claims about older releases cite `<tag> <path>` or `<sha> <path>`.
- **Primary research artifacts:** the author's own publications (blog and
  conference material reachable from the repo's own links), Hugging Face
  (searched: zero "ReverserAI" models), PyPI (searched: no package).
  Absences like these are recorded as verified negative findings, not gaps
  in coverage; all such sources are cited by URL.
- **calxgloss side:** [10-calxgloss-baseline.md](10-calxgloss-baseline.md)
  is the fixed anchor; its claims cite this repo's docs, ADRs, and crates.
- Repo facts at HEAD (verified 2026-10-31): 25 commits; 1 028 lines of
  Python across 14 files; `plugin.json` v1.2, `minimumbinaryninjaversion`
  2487; GPL-2.0+ license; requirements: `huggingface-hub`,
  `llama-cpp-python`, `networkx`, `toml`, `typer`; zero tests.

## File index

| File | Domain | Status |
|------|--------|--------|
| [00-scope-and-method.md](00-scope-and-method.md) | this file | done |
| [10-calxgloss-baseline.md](10-calxgloss-baseline.md) | calxgloss capability inventory (comparison anchor) | done |
| [20-reverser-ai-inventory.md](20-reverser-ai-inventory.md) | complete ReverserAI surface: files, packaging, CI, examples | done |
| [21-history-and-releases.md](21-history-and-releases.md) | v1.0 → v1.2 archaeology, what changed and disappeared | done |
| [31-ml-model-and-training.md](31-ml-model-and-training.md) | research lineage: what was actually published, model artifacts (verified absences), shipped GGUF config, effectiveness claims | done |
| [32-binary-ninja-plugin.md](32-binary-ninja-plugin.md) | BN plugin layer: workflow, HLIL, traversal, context, renaming | done |
| [33-ai-layer-and-prompts.md](33-ai-layer-and-prompts.md) | model loading, prompts, context building, CLI, config | done |
| [40-comparison.md](40-comparison.md) | full feature & effect comparison vs calxgloss, steal list | done |
