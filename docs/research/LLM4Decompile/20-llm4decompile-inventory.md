# LLM4Decompile complete inventory (HEAD `85b364b`)

> Part of the [LLM4Decompile overview](README.md). Fixed surface map of the repo at HEAD: every one of
> the 121 tracked files with line/byte counts, the checked-in dataset formats with verified entry
> counts, packaging and dependency posture, Docker, licensing, and the verified-absent CI/tests. All
> claims cite clone-relative `path:line` verified against the clone at `/tmp/opencode/LLM4Decompile`,
> HEAD `85b364b` (2026-02-12, merge of PR #73, 219 commits, no tags). Dataset counts are
> machine-counted from the checked-in files, not quoted from READMEs.

## 1. Repo shape and scale

Not a package: no `setup.py`, no `pyproject.toml`, no `Makefile`, no tests, no docs dir (verified:
`git ls-files` filtered for
`setup.py|pyproject|Makefile|conftest|pytest|.github|.pre-commit|ruff|toml|cfg` → zero hits at
HEAD). It is a **research drop-zip turned into a repo**: 8 top level code/data folders, a root
README, ~144 MB of checked-in JSON/JSONL — mostly *data and paper sidecars*, not shipping code.

Per-directory totals (verified: `git ls-files` + `wc`/`stat`):

| Dir | Files | Bytes | Content |
|---|---:|---:|---|
| `sk2decompile/` | 51 | 54.6 MB | SK²Decompile (arXiv:2509.22114): preprocess, SFT/RL configs, eval suite, BringUpBench data |
| `train/` | 24 | 97 KB | ColossalAI trainer, DeepSpeed `finetune.py`, LLaMA-Factory example |
| `samples/` | 19 | 10.9 MB | 14 PNG, 3 PDF figures, `sample.c`, `readability_template.txt` |
| `decompile-bench/` | 7 | 95.8 MB | Decompile-Bench eval data (2 JSON) + exe-rate/edit-sim runners |
| `legacy-test/` | 4 | 5.2 MB | the original HumanEval-Decompile eval JSON ×3 + its README |
| `evaluation/` | 5 | 26 KB | the 2024 V1/V2-era eval runners |
| `ghidra/` | 3 | 15 KB | Ghidra headless decompile script + end-to-end demo |
| `scripts/` | 1 | 424 B | one 15-line launcher (stale — §9) |
| root | 7 | ~30 KB | `README.md` (221 L), `LICENSE` (21 L), `LICENSE-MODEL` (91 L), `Dockerfile` (58 L), `.gitignore` (173 L), `requirements.txt` (6 L), `requirements-docker.txt` (4 L) |

**121 tracked files** (`git ls-files | wc -l` = 121), worktree ≈160 MB. Python: **42 files, 6,396
lines** (`git ls-files '*.py' | xargs wc -l`); shell: 9 files, 533 lines. GitHub reports `size`
31,156 KB; the single largest file is `decompile-bench/data/mbpp-decompile.json` at **77.7 MB**.

Code LOC leaders: `sk2decompile/evaluation/bringupbench/scripts/eval_infer_out.py` 682 and
`sk2decompile/evaluation/bringupbench/scripts/build-func-maps.py` 493 — **the newest pipeline
(BringUpBench, added `239cba2`) contains the most Python in the repo**, 1,237 L across its two
biggest scripts; then `train/colossalai_llm4decompile/train.py` 428,
`evaluation/run_evaluation_llm4decompile_vllm.py` 248, `evaluation/run_evaluation_llm4decompile.py`
245, `train/finetune.py` 225.

## 2. Root README (221 lines) — the de-facto release log

With no git tags and no GitHub Releases (§10), `README.md` is the only release ledger. Its Updates
section (`README.md:24-32`, compacted in the 2025-12-05 refactor `f5a6f43`/`86857f4`) has exactly 8
bullets:

| Line | Date | Announcement |
|---|---|---|
| `README.md:25` | 2025-10-04 | SK²Decompile two-phase release, 2 HF links |
| `README.md:26` | 2025-05-20 | Decompile-Bench (2M train / 70K eval pairs) |
| `README.md:27` | 2024-10-17 | `decompile-ghidra-100k` dataset + 3.5 h A100 training script, "0.26 re-executability rate, under $20" |
| `README.md:28` | 2024-09-26 | Colab notebook update |
| `README.md:29` | 2024-09-23 | 9B-v2 (Yi-Coder-9B base), re-executability **0.6494** |
| `README.md:30` | 2024-06-19 | V2 Ref series (1.3B–22B, Ghidra-based, 2B tokens) |
| `README.md:31` | 2024-05-13 | V1.5 End series (15B tokens, 4096 ctx, ">100% improvement") |
| `README.md:32` | 2024-03-16 | `llm4decompile-6.7b-uo` (arise-sustech org, optimization-agnostic, ≈0.219 avg) |

The model table (`README.md:68-75`) lists exactly six checkpoints — 1.3b/6.7b v1.5 at **27.3%** /
45.4%, 1.3b/6.7b/9b/22b v2 at 46.0% / 52.7% / 64.9% / 63.6% re-executability — and **no row for v1,
v1.6, -uo, or SK²** (those live only in bullets/sub-READMEs). The prose above it claims "between 1.3
billion and **33 billion** parameters" (`README.md:66`); no 33 B model is in the table or in the
`LLM4Binary` org, but a v1-era 33 B *does* exist on HF in the old `arise-sustech` org with full
weights — the stale echo of the V1 paper, first introduced `3a5326b` 2024-02-28, copied into
`ghidra/README.md:34`; weights forensics in
[ch.33 §1](33-models-training-and-data.md).
Benchmarks named: HumanEval-Decompile (164 funcs) (`README.md:51`) and **ExeBench, 2,621
real-project functions** (`README.md:52`) — ExeBench's data is not in the repo.

Quick Start (`README.md:85-171`) embeds the whole preprocessing + inference pipeline inline: gcc →
objdump → tab-column ASM scrubbing → the two-line `# This is the assembly code:` / `# What is the
source code?` prompt (`README.md:130-132`) → HF `generate(max_new_tokens=2048)` (`README.md:163`). A
Docker path exists (`README.md:173-185`). License section: "This code repository is licensed under
the MIT and DeepSeek License" (`README.md:205`).

## 3. `evaluation/` + `scripts/` — the 2024 V1/V2 runner set

- `evaluation/run_evaluation_llm4decompile_vllm.py` (248 L) — the recommended runner
  (`evaluation/README.md:7-25`): vLLM, 8-GPU sharding, `--temperature 0`.
- `evaluation/run_evaluation_llm4decompile.py` (245 L) — same flow against TGI.
- `evaluation/run_evaluation_llm4decompile_singleGPU.py` (106 L) — HF-transformers single loop;
  default model 6.7b-v1.5 (`:11`), default dataset path `../decompile-eval/...` (`:12`, **broken** —
  dir renamed to `legacy-test/`, §9).
- `evaluation/server/text_generation.py` (131 L) — TGI launcher.
- `scripts/run_evaluation_llm4decompile.sh` (15 L) — TGI launcher call; its `--model_path
  llm4decompile-1.3b` (`:5`) names a retired HF id and its `--testset_path
  $workspace/decompile-eval/decompile-eval.json` (`:7`) points into the deleted directory — it cannot
  run at HEAD as written.
- `evaluation/README.md:2-3` is the dataset↔model-era routing table: `…-gcc-ghidra.json` for V2,
  `…-gcc-obj.json` for V1.5.

Those five files are `evaluation/`'s *entire* membership history — `git log --all --name-only --
evaluation/` lists only them plus `README.md`, so there is no older metrics/BLEU tooling to find.

## 4. `ghidra/` (3 files) — the V2 Ref inference path

`decompile.py` (47 L) is **Jython for Ghidra headless** (Python2 print statements,
`ghidra/decompile.py:32`): iterates all functions, writes `// Function: <name>` + pseudo-C per
function; header says "Modified from galoget/ghidra-headless-scripts" (`:13`). `demo.py` (88 L) is
the end-to-end demo: gcc `-O0..O3` to a temp dir, `analyzeHeadless` with `-postScript decompile.py`
(`ghidra/demo.py:32-41`), cuts out `func0`, wraps it in the same two-line prompt as the ASM path
(`:63-65`), then refines with `LLM4Binary/llm4decompile-6.7b-v2` (`:72`). `ghidra/README.md` (203 L)
duplicates the root README's structure for the Ref line.

## 5. Datasets at HEAD — verified formats and counts

All counts machine-verified by JSON-parsing each file at HEAD.

**`legacy-test/`** (renamed from `decompile-eval/` in `757b7a2`, see
[history](21-history-and-releases.md) §3): three files, **656 entries each** (164 problems × O0–O3),
five keys `task_id, type, c_func, c_test, input_asm_prompt`. The three variants are the *input
modality* for each model era: plain objdump (`decompile-eval.json`, 1,756,454 B),
`…-executable-gcc-obj.json` (1,763,773 B) for V1.5, `…-executable-gcc-ghidra.json` (1,664,299 B) for
V2. Entry 0 begins `task_id: 0, type: O0, input_asm_prompt: '<func0>:\nendbr64\npush %rbp…'`.
`legacy-test/README.md:15-22` is the metric manifesto: BLEU/edit-sim "false scores" example ($src_4
"ES drops to 41.4%… during compilation, names are typically standardized by the compiler"),
concluding re-executability is "far more indicative".

**`decompile-bench/data/`** (Decompile-Bench eval, added `2025-05-21`):

- `humaneval-decompile.json` (18.0 MB) — **1,312 entries** = 164 × 4 opt × 2 languages (exactly 164
  per (opt,lang) cell, verified).
- `mbpp-decompile.json` (77.7 MB) — **7,792 entries** = 974 × 4 × 2.
- 12 keys per entry: `index, func_name, func_dep, func, test, opt, language, asm, ida_asm,
  ida_pseudo, ghidra_asm, ghidra_pseudo` — both IDA and Ghidra disassembly+pseudocode ship side by
  side, so the eval set doubles as a decompiler-comparison corpus (C++ entry 0: `func_dep
  "#include<stdio.h>\n#include<vector>…"`, `ghidra_pseudo "/* func0(std::vector<float…> int8
  func0(vector param_1,…"`, `asm "func0(std::vector<float,…> , float):\nendbr64…"`).
- `readme.md` (96 L) announces the full HF collection — 2M training pairs / 70K eval pairs
  (`decompile-bench/readme.md:15`) — and a third eval split, `github2025` ("huameval" typo at `:16`),
  **not** checked in; the repo-side subset is only 1,312 + 7,792 = 9,104 entries. It carries a
  **second model table** (`:63-66`) with HumanEval-Decompile scores 16.22% (1.3b-v1.5) and 20.89%
  (1.3b-v1.6, "LLM4Decompile-DCBench" alias), and routes R2I external (`:73` → github.com/e0mh4/R2I).

**`sk2decompile/evaluation/data/`** — the same corpora re-cut for SK² (IDA input + normalized pseudo
+ obfuscated source):

- `humaneval_normsrcpseudo.json` — **567 entries** (O0 164, O1 153, O2 137, O3 113; all `language:
  c`), 15 keys adding `ida_strip_asm`, `ida_strip_pseudo`, `func_name_ori`, `ida_strip_pseudo_norm`,
  `ida_pseudo_norm` — the obfuscation layer renames everything to `sub_XXXX` (`ida_strip_pseudo:
  "__int64 __fastcall sub_1169(…"` vs `ida_pseudo "__int64 __fastcall func0(…"`).
- `mbpp_normsrcpseudo.json` — **3,008 entries** (973/825/664/546 by opt).

**`sk2decompile/evaluation/bringupbench/data/`** — BringUpBench corpus (added `239cba2`):
`func_maps/merged.O{0..3}.func_map.jsonl` with **493/449/441/439 = 1,822** function entries (5
path-referenced keys: `source`, `pseudo`, `pseudo_normalize`, `binary`, `assembly`);
`infer_results/merged.O{0..3}….infer.jsonl` with **382/379/368/359 = 1,488** evaluated entries (adds
`infer-out-model1`, `infer-out-model2`, `pseudo_normalize-fix` fields).
`sk2decompile/evaluation/bringupbench/README.md:10-12` claims "90 self-contained C programs… 505
functions" — the checked-in data doesn't reconcile it: 1,822 function *instances* across four opt
levels (≤493 distinct per level), and the per-level evaluated counts (382/379/368/359, same README
`:20-23`) sum to 1,488.

**Training-data examples** (examples only — real data lives on HF):
`sk2decompile/LLaMA-Factory/SK2DECOMPILE/data/pseudo2norm-examples.jsonl` and
`norm2code-examples.jsonl` (20 lines each; keys `instruction, input, output, system`; pseudo2norm
entry 0 maps `# This is the pseudo code:\nlong long sub_4E05(…` → obfuscated `type1* func1(type2*
var1) {…`); `sk2decompile/verl/SK2DECOMPILE/data/sk2decompile-rl-examples.jsonl` (100 lines, 359 KB;
VERL format: `data_source: "llm4decompile_exe"`, `prompt`, `ability: "decompile"`,
`reward_model.ground_truth`, `extra_info.header`);
`train/llama_factory_llm4decompile/data/llm4binary_v1_example.json` (2 entries; asio C++-template
ASM → C++ method body, the "llm4binary" finetune flavor) + `dataset_info.json` registering
`llm4binary_v1`.

## 6. `train/` (24 files) — three generations of training stacks

1. **ColossalAI** (`train/colossalai_llm4decompile/`, 14 files, ~1,530 L): Colossal-LLaMA-clone
   pretraining (`train.py` 428 L, `colossal_llama/utils/` flash-attention/stream-chat/neftune patches).
   Data format `{"source": "asm_code", "target": "c_source_code", "category": "llm4decompile"}`
   (`train/colossalai_llm4decompile/README.md:18-22`); base model `deepseek-coder-6.7b-base`
   (`train/colossalai_llm4decompile/run_llm4decompile_train.sh:16`); `hostfile` is literally one
   `127.0.0.1`; README lesson "numpy above 2.0 has compatibility issues… numpy==1.23.3". Added
   `c18472e` 2024-06-27, **never touched again** — `train/README.md:1-2` now leads with LLaMA-Factory.
2. **DeepSpeed finetune** (`train/finetune.py` 225 L, adapted from deepseek-coder per
   `train/README.md:6`; default base `deepseek-ai/deepseek-coder-1.3b-base` `train/finetune.py:28`;
   `configs/ds_config_zero3.json`, `run_training.sh` 71 L, `compile.py` 123 L, `requirements.txt` 10 L)
   — the ghidra-100k 3.5 h/A100 path of `README.md:27`, added `52871dd` 2024-10-17.
3. **LLaMA-Factory example** (`train/llama_factory_llm4decompile/`, 4 files): README (`118 L`)
   documents a `deepspeed …/LLaMA-Factory/src/train.py` full-SFT recipe on
   `models/llm4decompile-1.3b-v1.5` with `--template empty --cutoff_len 4096 --lr 5e-6` (`:46-58`); its
   `requirements.txt` (220 L) is a raw `conda list --explicit` export (llamafactory build + torch
   2.5.1+cu121 — not a hand-maintained pin). Contributed by 7Sageer via PRs #48/#50/#55
   ([history](21-history-and-releases.md) §2).

SK²'s training entry points are config-only: `pseudo2norm-example.yaml` / `norm2code-example.yaml`
(38 L each) under `sk2decompile/LLaMA-Factory/SK2DECOMPILE/train/`, plus VERL launchers
`run_struct_rl.sh` (117 L) / `run_ident_rl.sh` (120 L).

## 7. `sk2decompile/` (51 files) — the SK²Decompile artifact

Structure per `sk2decompile/README.md:32-52` (matches `git ls-files` exactly):

- `Preprocess/` (4 files): `normalize_src_basedonpseudo.py` (211 L, source → obfuscated IR via
  tree-sitter), `format.py` (99 L, clang-format wrapper), `inf_type.py` (144 L, type inference via
  external `psychecgen`/ `psychecsolver-exe` — `sk2decompile/README.md:92-93` passes `--generator
  ../psychec/psychecgen`, not in repo), `standard_c.txt`.
- `evaluation/` (13 files): `sk2decompile_inf.py` (179 L, two-phase vLLM inference entry; default
  `--model_path LLM4Binary/sk2decompile-struct-6.7b` `:14`), `llm_server.py` (95 L),
  `normalize_pseudo.py` (211 L, R2I-style pseudo normalization), `evaluate_exe.py` (69 L, drives
  `metrics/cal_execute_rate.py` 102 L), `evaluate_r2i.py` (82 L) + `gpt_judge.py` (209 L) — see §9 for
  their breakage; `inf_type.py` (170 L) eval-side twin; `template.txt` (73 L, GPT-judge readability
  rubric prompt); plus the stray `stack.yaml` (§9).
- `evaluation/bringupbench/` (21 files): pipeline scripts `build-host-opt-levels.sh` (gcc O0–O3 over
  bringup-bench), `decompile-all-pseudo.sh` + `dump_pseudo.py` (62 L) — **IDA Pro headless**
  (`ida-bin` from `config.env`), `disasm-all-objdump.sh`, `build-func-maps.py` (493 L),
  `eval_infer_out.py` (682 L, compile+run of decompiled functions into `reports/O{0..3}_results.md`);
  `config.env` placeholder paths (`BENCH_REPO_ROOT=/path/to/bringup-bench`, `IDA_BIN=/path/to/idat`);
  the data + reports described in §5.
- `verl/SK2DECOMPILE/` (9 files): reward functions `exe_type.py` (85 L: compilable + placeholder
  Jaccard), `sim_exe.py` (69 L), `embedding_gte.py` / `embedding_qwen3.py` (189 L each, cosine-sim
  embedding reward); README states GRPO (`:11`) on **VERL v0.4.1** (`:68`), Eq. 3 as `r_structure =
  0.0 if uncompilable else 1.0 + Jaccard` (`sk2decompile/verl/SK2DECOMPILE/README.md:38-50`), Eq. 4 as
  embedding cosine (`:52-60`), and flags the rewards as "**reference implementations**" (`:16`,
  `:62`).

## 8. Packaging, deps, Docker — verified posture

- No package metadata of any kind (verified absent, §1). Nothing is pip-installable; every entry
  point is a `python script.py --flags`.
- `requirements.txt` (6 L) is the eval-env pin: `vllm==0.4.0`, `numpy==1.23.3`, `text_generation`,
  tqdm **listed twice** (`:1`, `:3`), and **no transformers** despite
  `evaluation/run_evaluation_llm4decompile_singleGPU.py:2` importing it. `requirements-docker.txt` (4
  L) is the demo path instead (`transformers==4.55.3`, "Required for running demo.py" `:1`).
- `Dockerfile` (58 L, PR #61): base `pytorch/pytorch:2.7.1-cuda12.8-cudnn9-runtime` (`:2`),
  downloads **Ghidra 11.0.3 (build 20240410)** (`:7-8,23`), openjdk-17 headless (`:19`), conda env
  `llm4decompile` (`:31`), installs `requirements-docker.txt` (`:37-39`).
- `.gitignore` (173 L, stock Python template) has a telling custom header: `/*.jsonl`, `/*.json`,
  `/*.sh` ignored **at repo root only** (`:3-5`) — the authors kept scratch data/scripts one level
  above the tracked tree; `*.sh` recurs at `:173` ("Demo file"), which is why no BringUpBench-era root
  scripts ever landed.

## 9. Stale references & internal contradictions (headline findings)

Verified at HEAD by cross-grepping docs vs tree:

1. **5 references to the deleted `decompile-eval/` dir**: `README.md:188` ("Data are stored in
   `llm4decompile/decompile-eval/…json`"), `scripts/run_evaluation_llm4decompile.sh:7`,
   `evaluation/README.md:17`, `evaluation/run_evaluation_llm4decompile_singleGPU.py:12`,
   `ghidra/README.md:192` — none resolve (the dir became `legacy-test/` in `757b7a2`).
2. **`sk2decompile.py` doesn't exist**: `sk2decompile/README.md:159` and `:172` invoke it; the real
   file is `sk2decompile/evaluation/sk2decompile_inf.py`.
3. **`Preprocess/normalize_pseudo.py` doesn't exist**: README tells you to `cd Preprocess` (`:77`)
   then run `normalize_pseudo.py` (`:83`); the file only exists in `evaluation/` (added later,
   `b82f0e5`).
4. **broken imports**: `sk2decompile/evaluation/evaluate_r2i.py:4` does `from metrics.R2I.run import
   run_r2i` but `sk2decompile/evaluation/metrics/` contains only `cal_execute_rate.py` (R2I is external
   per `decompile-bench/readme.md:73`); `:16` wants `./psychec/psychecgen`, not shipped.
5. **Template leftover**: clone URL `https://github.com/yourusername/SK2Decompile.git`
   (`sk2decompile/README.md:66`).
6. **License claim without file**: `sk2decompile/README.md:252` "MIT License. See LICENSE file" — no
   `LICENSE` inside `sk2decompile/`; root weights fall under `LICENSE-MODEL`, a verbatim **DeepSeek
   License v1.0** (© 2023 DeepSeek `:5`; use restrictions per Attachment A `:51`; **PRC governing law**
   `:71`; "For military use in any way" prohibited `:82`).
7. **Model-name rot**: `README.md:25` and `sk2decompile/README.md:17` still link
   `sk2decompile-ident-6.7` — HF is `LLM4Binary/sk2decompile-ident-6.7b` (created 2025-10-02; community
   GGUFs even propagated the wrong `-6.7` name). `1c164e2` (2026-01-25) fixed only
   `sk2decompile/README.md:159,172,174`. The HF org is **LLM4Binary**, not `LLM4Decompile` as most
   links spell it.
8. **The 33 B claim** (`README.md:66`, `ghidra/README.md:34`) vs max 22 B in every table —
   *corrected by ch.33 §1*: a v1-era `arise-sustech/llm4decompile-33b` (full weights, AnghaBench
   recipe) does exist on HF in the old org; what never existed is any 33 B in `LLM4Binary` or in
   any README table, and the v3-era 33 B run (200M tokens) was never released at all.
9. **Score contradiction**: 1.3b-v1.5 is **27.3%** (`README.md:70`) but **16.22%**
   (`decompile-bench/readme.md:65`) — same checkpoint, same-named benchmark, different harness (V1.5
   objdump JSON vs DCBench re-scored corpus); the repo never reconciles them.
10. **BringUpBench Avg row** (`sk2decompile/evaluation/bringupbench/README.md:24`):
42.3%/27.0% doesn't equal the mean of its own per-level rows (≈40.2%/≈38.1%) — the note at `:26`
waves to "the paper's aggregate numbers".
11. **Report timestamps predate their commit**: all four
`sk2decompile/evaluation/bringupbench/reports/O{0..3}_results.md` carry `Timestamp: 20251119-…`
(`sk2decompile/evaluation/bringupbench/reports/O0_results.md:3`) but were committed `239cba2`
(2026-02-12).
12. **Third-party LLM proxy hardcoded**: `sk2decompile/evaluation/gpt_judge.py:18`
`openai.base_url = "https://api5.xhub.chat/v1/"` with `model="gpt-5-mini"` (`:24`); judge-prompt
defaults leak internal experiment names — `sk2decompile/evaluation/gpt_judge.py:167` /
`sk2decompile/evaluation/evaluate_r2i.py:14`: `pseudo2normFinal-Debug,
pseudo2norm_RLFinal+norm2codeFinal-Debug-11000, …`.
13. **Stray file**: Haskell Stack's `stack.yaml` (resolver lts-5.1, 66 L) in
`sk2decompile/evaluation/` — upload accident from `357705d`.

## 10. GitHub metadata & CI/test absence (verified 2026-10-31)

API facts: created 2024-02-28T03:16:44Z, pushed 2026-02-12T03:02:03Z, **7,195 stars, 567 forks, 82
watchers, 47 open items (43 issues + 4 PRs)**, license MIT (code), homepage the EMNLP 2024 paper
page. Releases and Tags APIs both return `[]` — *zero* tags, *zero* GitHub Releases in 2 years; the
whole release history is HF model drops narrated by README bullets (§2, and
[21-history-and-releases.md](21-history-and-releases.md)). **CI: none** — no `.github/` at any path,
no workflow/pre-commit/linter config, no test suite, no conftest/pytest hits (verified via `git
ls-files` patterns and `find`). The only "quality" artifacts are the evaluation harnesses themselves
(§3, §5, §7).

## Steal ideas for calxgloss

- **The metric manifesto is calxgloss's doctrine, pre-published**: `legacy-test/README.md:15-22`
  argues name-normalization makes N-gram/edit similarity meaningless — the citable justification for
  calxgloss's compile+execute adjudication and the open-P33 eval substrate.
- **Per-(opt-level) eval matrices**: corpora are 164×4×2 grids with the opt level *inside* each
  entry (`decompile-bench/readme.md:46-59`). calxgloss's P33 harness should carry scenario difficulty
  (per-call-site Wine evidence class, the opt-level analog) as a first-class field so scores slice the
  same way.
- **Same-corpus decompiler-comparison columns**: `ida_*` and `ghidra_*` variants side by side in one
  record (humaneval-decompile 12-key schema, §5) let baseline-vs-output comparisons reuse one file —
  calxgloss trace/baseline evidence could follow one-record-per-function.
- **GRPO rewards as harness oracles**: `exe_type.py` (compile ⊕ placeholder Jaccard) and
  embedding-cosine identity reward (§7) are the shapes a calxgloss P33 scorer needs even without
  training — adopt the *shape* (0 if uncompilable, similarity bonus otherwise).
- **Naming-doctrine collision for 40-comparison**: SK² *destroys* identifiers in phase 1
  (`ida_strip_pseudo: sub_1169`) then regenerates them; calxgloss renames with human-in-the-loop
  evidence — opposite vector, same acknowledgment that rule-based names are a semantic loss.
- **Cautionary table**: §9 is what a docs-driven repo with no CI accumulates — the exact failure
  class calxgloss's open P42 exists to prevent (calxgloss currently has no CI either; baseline §QA) —
  renames without link updates, deleted dirs cited 5×, broken imports shipped.
  Reinforces mechanically checking calxgloss doc references.

## Sources

- Clone `/tmp/opencode/LLM4Decompile` @ `85b364b`; every cited line opened at the exact range; `git
  ls-files` (121 files), per-file `wc -l`/`stat -c%s`; JSON entry counts and key lists via
  `python3`+`json` (re-printed 2026-10-31); absence verification `git ls-files | grep -E
  'setup.py|pyproject|Makefile| conftest|pytest|.github|pre-commit'` (zero hits); `git log
  --diff-filter=AMD` for §9 rename facts (detailed in 21).
- `https://api.github.com/repos/albertan017/LLM4Decompile` (stars 7,195, forks 567, subscribers 82,
  open_issues 47, created/pushed, MIT spdx, homepage, `size` 31,156 KB; fetched 2026-10-31);
  `…/releases` and `…/tags` → `[]`.
- `https://huggingface.co/api/models?search=sk2decompile` (LLM4Binary/
  sk2decompile-{struct,ident}-6.7b created 2025-10-02; mradermacher GGUF mirrors incl. one named after
  the README's wrong `-6.7`); `…/api/models/LLM4Binary/llm4decompile-{1.3b-v1.5,1.3b-v1.6,6.7b-v1.5,
  6.7b-v2,9b-v2,22b-v2}` (creation/modification dates; `-1.3b-v1`/`-6.7b-v1`/ `-6.7b-ghidra-100k`
  return 401 = gated); `…/arise-sustech/llm4decompile-6.7b-uo` (created 2024-03-16).
