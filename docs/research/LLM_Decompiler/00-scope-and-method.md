# LLM_Decompiler ↔ calxgloss comparison — scope and method

> Part of the [LLM_Decompiler overview](README.md). Read this first for what
> is being compared and how.

## What LLM_Decompiler is

**LLM_Decompiler** ([Lami99/LLM_Decompiler](https://github.com/Lami99/LLM_Decompiler),
no license file) is a small, single-author **Ghidra-headless + GPT prompt
pipeline for whole-project decompilation and security work**: shell-driven
`analyzeHeadless` batch decompilation of a binary into per-function C files,
followed by Python scripts that walk those files and prompt an OpenAI chat
model (GPT-4 family, per its README) to translate/annotate/reconstruct them —
including a dedicated path for large code bases with per-module regrouping.
Adjacent tooling covers CTF/exploit work (`llm_pwn.py`, `llm_ctf_context.py`),
decompiler-error repair (`llm_fix.py`), function renaming (`llm_r.py`),
CTF-context enrichment (`llm_translate.py`), and a Juliet-suite/CWE dataset
builder (`dataset_scripts/`) oriented at training data rather than inference.
Created 2024-05-02, last pushed 2024-07-15, 26 commits, 30 tracked files,
single contributor ("Fatnassi", GitHub account Lami99), no tags, no releases,
no CI, no tests, no license; 3 stars.

calxgloss is *not* a script collection: it is a Rust workspace harness that
drives **off-the-shelf local LLMs** with structured evidence from 15 whole-
binary scans, verifies every translated unit by compile + Wine-captured
behavioral baselines + API-trace containment, and adjudicates it in a review
UI with per-attempt git branches (see
[10-calxgloss-baseline.md](10-calxgloss-baseline.md)). The comparison is
therefore a two-sentence shell+prompt prototype vs a verification-and-evidence
harness — both are "LLM decompiles Ghidra output for you", and almost
everything around that sentence differs.

## Comparison scope

**In scope** — every part of LLM_Decompiler, in depth where it touches
calxgloss's concerns:

- Complete repository inventory at HEAD: every one of the 30 tracked files —
  root `analyze_*.sh` / `decompile_*.sh` pipelines, the seven `llm_*.py`
  prompt drivers, `large_code_base_reconstruction.py`, `Decompiler/`
  (Ghidra headless scripts `gd_decomp*.sh`, `decompilation_scripts/`,
  `exec/`), `helper_scripts/`, `dataset_scripts/` (Juliet/CWE), `results/`,
  README; packaging, CI, tests, license, config — verified absent or present.
- Full git history archaeology: 26 commits, single author, no tags/releases;
  the May→July 2024 development arc (Ghidra automation → dataset scripts →
  README iteration → large-codebase support → functionality extension →
  exploit support → `.env` removal), what each phase added or deleted.
- The decompilation harness: `Decompiler/gd_decomp*.sh` Ghidra-headless
  automation, `decompile_pipe.sh` / `decompile_large_pipe.sh` end-to-end
  pipelines, `decompiler.py` vs `large_decompiler.py` prompt-loop design,
  model selection, prompt content, output handling, chunking/context
  strategy for big projects.
- The security/CTF surface: `analyze_binary.sh`, `analyze_all.sh`,
  `analyze_source.sh`, `analyze_and_fix.sh`, `analyze_and_exploit.sh`,
  `llm_pwn.py`, `llm_ctf_context.py`, `llm_fix.py`, `llm_r.py`,
  `llm_translate.py` — what each actually does to a binary or to Ghidra
  output, and what its success criteria are (spoiler: mostly none).
- The dataset line: `dataset_scripts/process_juliet_suite.py` and
  `select_from_cwe.py` — the Juliet C/C++ test-suite / CWE angle, and how
  it does and does not connect to the rest of the repo.
- `results/` and effectiveness evidence: what the checked-in outputs are,
  whether anything in the repo measures or verifies output quality, and the
  hygiene ledger (historical API-key handling: commits `72c3c11` "hide key"
  and `c242671` "Delete .env" — forensics on what history actually contains).

**Out of scope**

- Ghidra, `analyzeHeadless`, the Juliet test suite, the CWE catalog, and the
  OpenAI API as such — cited only where LLM_Decompiler's behavior depends
  on them.
- The broader LLM-decompilation literature — this repo cites no papers and
  has no publications; sibling dossiers
  ([LLM4Decompile](../LLM4Decompile/README.md),
  [ReverserAI](../reverser_ai/README.md)) cover the trained-model lines.
- Running the pipeline end-to-end (needs a paid OpenAI key and a Ghidra
  install) — this dossier audits artifacts and claims, it does not re-run them.

## Method and sources

- **Primary code source:** a full clone at `/tmp/opencode/LLM_Decompiler`,
  HEAD `c2426715340b84a3e2eea4e891fe913a50154f00` (2024-07-15, "Delete
  .env"), all 26 commits, no tags. Claims cite clone-relative `path:line` at
  that commit; history claims cite `<sha>` (short) with path.
- **Repo facts at HEAD** (verified 2026-10-31 via GitHub API): created
  2024-05-02; last push 2024-07-15; 3 stars; 3 forks; 0 open issues (the
  issues API returns 404 — issues feature disabled); **no license**
  (`license: null`); language Python; default branch `main`; not a fork;
  49 KB repo size, 152 KB worktree excluding `.git`; one contributor,
  "Fatnassi" / `Lami99`, 26/26 commits.
- **calxgloss side:** [10-calxgloss-baseline.md](10-calxgloss-baseline.md)
  is the fixed anchor, pinned at calxgloss HEAD `40fbf91f` (2026-10-31) —
  same snapshot as the
  [LLM4Decompile baseline](../LLM4Decompile/10-calxgloss-baseline.md).

## File index

| File | Domain | Status |
|------|--------|--------|
| [00-scope-and-method.md](00-scope-and-method.md) | this file | done |
| [10-calxgloss-baseline.md](10-calxgloss-baseline.md) | calxgloss capability inventory (comparison anchor) | done (anchors adapted for this project) |
| [20-llm-decompiler-inventory.md](20-llm-decompiler-inventory.md) | complete repo surface: 30 files, scripts, packaging, CI/license/tests absences, hygiene ledger | done |
| [21-history-and-releases.md](21-history-and-releases.md) | 26-commit archaeology, development arc, `.env`/key forensics | done |
| [31-ghidra-harness-and-core-pipeline.md](31-ghidra-harness-and-core-pipeline.md) | Ghidra headless harness, `decompile_pipe.sh`, `decompiler.py`/`large_decompiler.py`, prompts, models | done |
| [32-large-codebase-reconstruction.md](32-large-codebase-reconstruction.md) | large-project path: regrouping, `large_code_base_reconstruction.py`, context strategy | done |
| [33-security-ctf-and-datasets.md](33-security-ctf-and-datasets.md) | `analyze_*.sh`, pwn/CTF scripts, fix/rename/translate, Juliet/CWE dataset line | done |
| [34-results-effectiveness-and-hygiene.md](34-results-effectiveness-and-hygiene.md) | `results/`, effectiveness evidence (or absence), key-leak and staleness ledger | done |
| [40-comparison.md](40-comparison.md) | full feature & effect comparison vs calxgloss, steal list, confirmations | done |

## Citation notes

- LLM_Decompiler claims cite clone-relative `path:line` at HEAD `c242671`;
  history claims cite `<sha>` (short) with path.
- Web claims cite fetched URLs (GitHub API), fetched 2026-10-31.
- calxgloss claims cite crate-relative paths (resolved under
  `crates/<group>/calxgloss-*/…`) at HEAD `40fbf91f`, or ADR numbers.
- Verified absences (no CI, no license, no tests, no tags) are recorded as
  negative findings with the search performed, not left as coverage gaps.
