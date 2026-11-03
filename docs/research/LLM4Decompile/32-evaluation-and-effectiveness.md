# 32. Evaluation and Effectiveness — How LLM4Decompile Measures Itself

> How the project's scoring machinery actually works: the three evaluation
> generations checked into the repo, what each harness does byte-by-byte, what
> its corpora contain (machine-counted), and which published numbers the
> artifacts in the tree do — or do not — substantiate. The numbers ledger
> lives in ch.33 §10; this chapter audits the machinery behind those numbers.
> All `path:line` citations verified against the clone at HEAD `85b364b`
> (merge of PR #73, 2026-02-12); the repo reorganised its evaluation tree in
> PRs #71–73, so paths here are the *current* ones.

## 1. Three evaluation generations, three homes

At HEAD the repo carries three non-overlapping evaluation stacks, each built
for one era of the project:

1. **2024, assembly-in / C-out ("End"/"Ref" era)** — runners in
   `evaluation/`, corpora in `legacy-test/`; scoring is compile-and-run against
   `c_test` harnesses (§2–§3).
2. **2025, Decompile-Bench era** — `decompile-bench/` (runner
   `run_exe_rate.py`, metrics under `metrics/`, eval sets under `data/`);
   same re-executability idea, per-function `test`/`func_dep` schema (§5).
3. **SK²Decompile era (paper 2509.22114, code landed through PRs #71–73)** —
   `sk2decompile/evaluation/`: exe-rate (`evaluate_exe.py`), R2I
   (`evaluate_r2i.py`), GPT-judge (`gpt_judge.py`), and the BringUpBench
   source-replacement harness under `bringupbench/` (§6–§9).

The eras share no harnesses, corpora, or prompt formats — the background
condition for every comparability claim in §11 (inventory: ch.20 §3; corpora:
ch.20 §5).

## 2. The 2024 runners: one task, two servers, divergent prompts

`evaluation/` holds exactly three inference-eval runners plus a README and a
`server/` package (line counts verified `wc -l`, 2026-10-31):

| file | lines | serving |
|---|---|---|
| `evaluation/run_evaluation_llm4decompile.py` | 245 | TGI (`text-generation-launcher` subprocess) |
| `evaluation/run_evaluation_llm4decompile_vllm.py` | 248 | vLLM in-process |
| `evaluation/run_evaluation_llm4decompile_singleGPU.py` | 106 | plain HF `.generate()` (legacy; `--model_path` now an argument defaulting to v1.5, `:11`) |

They score the same task — assembly prompt in, C function out, compile+run
against `c_test` — but disagree in ways that change the numbers:

- **Context budget skew.** vLLM defaults `--max_total_tokens 8192`
  (`evaluation/run_evaluation_llm4decompile_vllm.py:27`); TGI 8800 with
  `--max_input_len 8192` (`evaluation/run_evaluation_llm4decompile.py:24-25`).
  Truncation is engine-level and silent either way. vLLM's `--max_num_seqs`
  (default 8, `:24`) is a no-op: the LLM constructor line is commented out
  (`:205`).
- **Prompt skew.** vLLM maps all four opt levels to the single string
  `"# This is the assembly code:"` (`run_evaluation_llm4decompile_vllm.py:187-190`);
  TGI labels each level (`"...O0 optimization:"` etc.,
  `run_evaluation_llm4decompile.py:186-189`).
  Same corpus, different prompt per runner — which prompt the papers used is a
  paper question (ch.31 §3); the repo fact is the disagreement (catalogue:
  ch.33 §8).
- **Artifact skew.** vLLM can write the testset with an `output` field
  (`run_evaluation_llm4decompile_vllm.py:233-235`); TGI has no result-file argument — scores go only to
  stdout (`run_evaluation_llm4decompile.py:166-168`). No scored run is
  reproducible from a file.
- **Gated inputs.** `model_path.is_dir()` at `run_evaluation_llm4decompile.py:175`
  and `run_evaluation_llm4decompile_vllm.py:176` rejects HF hub ids; models must be pre-downloaded.

## 3. `evaluate_func` — what "re-executability" means in the 2024 harness

The scoring core is duplicated in both 2024 runners (identical shape,
`evaluation/run_evaluation_llm4decompile.py:35-107`;
`evaluation/run_evaluation_llm4decompile_vllm.py:36-108`):

1. Split `#include` lines from `c_func` (reference) and `c_test` (harness);
   build `combine` = includes + **model output** + `c_test` and `onlyfunc` =
   includes + model output (`run_evaluation_llm4decompile.py:44-55`).
2. **Compile rate**: a `gcc -S` probe of `onlyfunc`, 10 s timeout
   (`run_evaluation_llm4decompile.py:42`, `:70-79`); failure returns `(0, 0)`
   immediately — executable rate is *conditioned on the output compiling in
   isolation*, with no reference to `c_func` beyond includes.
3. **Run rate**: compile `combine`, execute with `timeout=10`, `check=True`
   (`:85-101`); any nonzero exit or timeout scores 0. The asserts are plain C
   inside `c_test` — no `assert_list` key exists in the HEAD corpora (§4 keys
   are exhaustive).

Two caveats follow. The probe compiles *without* the harness, so
link-failures inside `combine` land in executable-rate, not compile-rate —
defensible, but not what "compile rate" reads like in paper prose. And the 10 s
clock is per-`subprocess.run`: ExeBench-FHD shows looping programs inflate such
rates (its P5: 9.27% of kept programs loop; fetched 2026-10-31,
https://arxiv.org/abs/2610.28212). Scoring is parallel
(`multiprocessing.Pool`, `run_evaluation_llm4decompile.py:112`, default 16 at
`:31`) and stats bucket by the corpus's own `type` field (`:140`) — the
`--decompilers`-style flags the root README still prints are read by nothing.

## 4. The 2024 corpus, machine-counted

`legacy-test/` holds the three 2024 corpora, 656 entries each (= 164 problems
× 4 opts, matching the root README's "164*4", `README.md:188`), all sharing the
five keys `c_func, c_test, input_asm_prompt, task_id, type` (machine counts via
`python3` JSON loads, 2026-10-31): `decompile-eval.json`,
`decompile-eval-executable-gcc-obj.json`, `decompile-eval-executable-gcc-ghidra.json`.
Field-by-field diffs over aligned positions: `c_func`, `task_id`, `type` are
identical across all three (0/656 diffs); `c_test` differs in exactly
**84/656** entries between the original and the executable variants (they add
`(const int[])` casts — 76 marker entries vs 12); and `input_asm_prompt`
differs in **656/656** between the obj and ghidra files despite the *same key
name* — the ghidra file's field holds **Ghidra pseudo-code**
(`undefined8 func0(float param_1,...`, verified first entry), not assembly.
One key name, two different inputs: prompt-skew baked into the data (ch.33 §8).

The 2025 corpora are committed in-tree: `decompile-bench/data/humaneval-decompile.json`
**1312** entries (164 × 4 opts × 2 languages), `mbpp-decompile.json` **7792**
(1948/opt); 12 keys per entry including `asm, ida_asm, ida_pseudo, ghidra_asm,
ghidra_pseudo` plus the per-function `test`/`func_dep` pair the 2025 metrics
consume (§5). Machine count, 2026-10-31. The SK² eval sets —
`sk2decompile/evaluation/data/humaneval_normsrcpseudo.json` (**567**: O0 164,
O1 153, O2 137, O3 113; 164 unique `index` values; the per-opt drop-off tracks
psychec timeouts, the 1 s budgets in `inf_type.py:33,41`, ch.34 §5) and
`mbpp_normsrcpseudo.json` (**3008**: 973/825/664/546), 15-key schema with
`ida_pseudo_norm` / `ida_strip_*` variants — are what the SK² runners default
to (`sk2decompile/evaluation/evaluate_exe.py:63`,
`sk2decompile/evaluation/evaluate_r2i.py:13`; machine count, 2026-10-31).

Stale paths persist: root `README.md:188`, `evaluation/README.md:17` and
`scripts/run_evaluation_llm4decompile.sh:7` all reference a `decompile-eval/`
directory that does not exist at HEAD (`find . -type d -name 'decompile-eval*'`
→ nothing); the real 2024 data is `legacy-test/` (ch.20 §9 items 1–2).

## 5. 2025 re-executability: `decompile-bench/run_exe_rate.py`

One command runs generation *and* scoring (`decompile-bench/readme.md:91-94`
documents exactly such a call). Mechanics (`decompile-bench/run_exe_rate.py`):
default model `LLM4Binary/llm4decompile-1.3b-v1.6` (`:12`); `--decompiler asm`
makes the model input the `asm` field of each sample (`:14`; prompt wrap
`before+sample[args.decompiler]+after` at `:38-40`, templates `:26-27`); vLLM
context 30000 (`:19`); per-opt generation saved under `--output_path`
(`:57-66` — the directory is `shutil.rmtree`-ed first, `:59`, so re-running
destroys previous generations); scoring calls `execute_rate_main(…,
num_workers=32)` (`:71`) and appends per-opt rates to `<dataset>_results.txt`
(`:79-83`).

The oracle proper is `decompile-bench/metrics/cal_execute_rate.py` (74 lines):
compile `func_dep` + model output + `test`, run with timeout 10 (`:12,:65-74`),
return `(eval_results, Σcompile, Σexecute)`. The SK² tree keeps a **second,
different** copy at `sk2decompile/evaluation/metrics/cal_execute_rate.py` (102
lines; md5 `7b9cf74b…` vs `c4e959bc…`, verified 2026-10-31): its
`execute_rate_main` defaults to `language='cpp'` and returns a *scalar* rate
(`:72-82`), and its `__main__` block reads hard-coded `/workspace/llm4binary/…`
paths (`:84-102`) — a private-server remnant that crashes standalone, the
fingerprint ch.34 §6 records. Edit similarity has one implementation at HEAD:
`decompile-bench/metrics/cal_edit_sim.py`, whitespace-line-normalised
Levenshtein `1 - dist/max(len)` (`:2-9`), walking `./data/humaneval/` and
`./data/mbpp/` against `item['func']` (`:15-33`).

## 6. SK² exe-rate and the `model_outputs/` convention

`sk2decompile/evaluation/evaluate_exe.py` (69 lines) is a *second* exe-rate
front door for the SK² corpora. It imports the SK² copy of the metrics module
(`:5`), filters the JSON by `opt`/`language` (`:14`), and reads model outputs
from a checked-out *filesystem convention*:
`./model_outputs/{dataset}/{decompiler}/{opt}/{index}_{opt}.{lang}` (`:26`).
Decompiler names are just directory names — the `--decompilers` default at
`:65` is an eight-name roster of **unpublished internal checkpoints**
(`gpt-5-mini-name7, idioms, lmdc6.7, pseudo2normFinal-Debug, …`), names that
appear nowhere on HF (existence of the artifacts behind them is not
verifiable from the clone; roster ledger: ch.33 §1/§10). A special case treats
`ida`/`ghidra` as *dataset fields* (`data[f'{decompiler}_pseudo']`, `:15-21`)
so baselines come from the JSON itself. Before scoring, both paths rewrite the
generated function's name to `func_name` (`:19-20`, `:35-44`) — name-mismatch
crashes are papered over so exe-rate measures body correctness.
`eval()` loops O0–O3 and writes per-opt CSVs to `results/` (`:49-58`).

The practical consequence: the "models" being scored are whatever directories
you drop under `model_outputs/`; the runner is reproducible only against
externally-produced outputs, and the SK² headline tables (ch.33 §10) are
exactly such externally-produced numbers.

## 7. R2I: a broken import at the only R2I entry point

`sk2decompile/evaluation/evaluate_r2i.py` is the repo's only R2I runner, and
it **cannot run at HEAD**: `:4` does
`from metrics.R2I.run import run_r2i`, but `sk2decompile/evaluation/metrics/`
contains only `cal_execute_rate.py`; there is no `R2I` submodule — no
`.gitmodules` exists at HEAD, and `find . -iname '*R2I*'` returns only this
file and README mentions (all three searches run 2026-10-31). The rest of the
file shows what R2I would do: read `model_outputs/` files (`:45-48`), write a
prediction JSON, then call `run_r2i(decompilers, names)`
(`sk2decompile/evaluation/evaluate_r2i.py:77`), with psychec
binaries defaulted to `./psychec/psychecgen` (`:16-17`) — psychec itself is
fetched and pinned upstream by the R2I project (e0mh4/R2I; upstream
type-inference toolchain forensics: ch.31 §5 and ch.33 §7). This is the
concrete instance behind ch.20 §9 item 4. Effect: the R2I column of the SK²
paper's tables is not reproducible from this tree, only re-derivable from the
upstream R2I tool (ch.31 §5).

## 8. The GPT judge: rubric public, scores private, failure silent

`sk2decompile/evaluation/gpt_judge.py` (209 lines) is the readability
measurement behind the SK² "Code Readability" numbers:

- **The rubric is checked in.** Default prompt `template.txt`
  (`sk2decompile/evaluation/gpt_judge.py:166`) — a 73-line 1-to-5 readability rubric (names, types, access
  patterns) demanding a JSON `{"Code Readability Assessment": {"score":…}}`
  verdict (`sk2decompile/evaluation/template.txt:1-19,67-73`). The scoring
  key is hard-coded to that single dimension (`gpt_judge.py:10-15`).
- **The judge is not GPT-4o any more**: model `gpt-5-mini` (`:24`, comments
  show `gpt-4o`/`gpt-4o-mini` as previous choices), called at temperature 0,
  `max_tokens 8192` (`:26-27`).
- **A third-party relay is hard-coded**: `openai.base_url =
  "https://api5.xhub.chat/v1/"` (`:18`) — a non-openai.com proxy, and judge
  traffic (proprietary model outputs included) goes through it (flagged in
  ch.20 §9 item 12).
- **Failures score 1.** On final retry the judge writes
  `"# Error during judge: …"` into the verdict file (`:67-69`, retries at
  `:21-23`); the re-scoring pass then cannot JSON-parse it and appends
  **score 1** for that case (`:95-125` — every `except` branch appends 1).
  Judge outages therefore drag the mean down silently and indistinguishably.
- **`--cal_score 0` crashes**: it calls `eval_funcs(json_file, decompiler,
  prompt)` missing `opt`/`api_key` (`:176-178` vs signature `:128`) — a
  TypeError before any work.
- Verdicts live per-function under
  `judge_outputs/{dataset}/{decompiler}/{opt}/{index}_{opt}.{lang}` (`:85`),
  so the *raw verdicts* are absent from the tree — no checked-in judge outputs,
  no way to recompute the published readability means locally.

## 9. BringUpBench: a real build-and-test harness at last

`sk2decompile/evaluation/bringupbench/` (18 files — `git ls-tree` count at
HEAD, all opened in the audit snapshot) is the only harness in the repo that
recompiles the **whole program** with the decompiled function substituted into
its original source file, then runs the project's own `make build` + `make
test` — the strongest fidelity available. Upstream benchmark: bringup-bench
(Apache-2.0; 108 benchmarks at fetch, fetched 2026-10-31); the pinned 2024
snapshot per the pipeline README (`sk2decompile/evaluation/bringupbench/README.md:10`)
describes the 90 libmin-only C programs / 4 `libtarg_*` syscalls the data was
built against.

Pipeline (README §Reproduction Pipeline, `bringupbench/README.md:60-189`; all
four shell scripts load paths from `bringupbench/config.env` — 14 lines of
`/path/to/...` placeholders, with `bringupbench/scripts/decompile-all-pseudo.sh:16`
falling back to the author's personal `/home/bairidreamer/software/IDA-Pro/idat`):
`build-host-opt-levels.sh` compiles each program at O0–O3;
`decompile-all-pseudo.sh` + `bringupbench/scripts/dump_pseudo.py` (IDA
headless Hex-Rays, usage `:3-4`, per-function loop `:45-55`) dump pseudocode
delimited by `/* function_name @ 0xADDRESS */` (`bringupbench/README.md:136`,
writer at `bringupbench/scripts/dump_pseudo.py:49`);
`bringupbench/scripts/build-func-maps.py` (493 lines) matches source/pseudo/
assembly by name and normalizes (hex→dec, keyword/typedef stripping,
clang-format `:108,:124-177`), emitting `data/func_maps/merged.O{0..3}.func_map.jsonl`
at **493/449/441/439 lines** (verified `wc -l`, 2026-10-31);
SK² inference output lands in `data/infer_results/merged.O*.func_map.infer.jsonl`
at **382/379/368/359 lines** (verified by JSON line count);
`bringupbench/scripts/eval_infer_out.py` (682 lines) does Step 5.

Step-5 mechanics: per case, a fresh workspace copies only `Makefile`,
`common/`, `target/`, and the benchmark dir (`:267-289`);
`replace_function_body` finds the **exact** `source.content` text in the file
and splices in the decompiled body (`:135-160` — three candidate spellings of
the same snippet, plain `str.find`, no AST); then `run_command` executes the
project's make targets with `--command-timeout` (default 20 s, `:117-119`) and
the report tallies Replacement / Compilable / Executable per benchmark and
lists failure cases by `path::func@0xaddr` (case-id format `:163-169`).
Concurrency: `--jobs` default is 96 (`:124`) while its own help text says
"default: 1" (`:125`) — code-vs-help contradiction; the README's options
block (`bringupbench/README.md:185`) states 96.

Checked-in reports (`bringupbench/reports/O{0..3}_results.md`,
295/333/344/354 lines, verified `wc -l`): each is titled
"# Infer-Out Model 2 Evaluation (merged.O{N}.func_map.infer-host)" (line 1,
matching the generator's `base_name` construction at
`bringupbench/scripts/eval_infer_out.py:572`) and the header block gives the
numbers — O0: 382 cases, 382 replacements (100%), 192 compilable (50.26%),
189 executable (49.48%) (`bringupbench/reports/O0_results.md:6-9`); O1
155/148 of 379 (40.90/39.05%); O2 139/126 of
368 (37.77/34.24%); O3 114/106 of 359 (31.75/29.53%) (verified `grep`,
2026-10-31). These per-opt rows match the README table
(`bringupbench/README.md:20-23`) and the two per-opt README rows the root SK²
README quotes (ch.33 §10). Report timestamps `20251119-17*` (line 3) predate
the merge commit that added them (2026-02-12) — the reports are archived
artifacts of an offline run, and their bare names (`O0_results.md`) do not
match what the generator writes today (`{stem}-{target}-{timestamp}.md` into
`reports/infer_out_eval/`, `eval_infer_out.py:572-577` + defaults `:94-98`), so they were
renamed on the way in (ch.20 §9 item 11).

## 10. The `content-fix` finding — what the harness actually evaluates

The headline audit result of this chapter, re-verified at HEAD:

- The docstring and CLI description say the harness evaluates
  **`infer-out-model2`** bodies: `bringupbench/scripts/eval_infer_out.py:3`
  ("Evaluate infer-out-model2 functions…"), `:72`. But the substitution value
  is `case["pseudo"]["content-fix"]` — `:248` (writing the artifact copy) and
  `:365` (the actual splice source). `infer-out-model1`/`infer-out-model2` are
  never read: the only occurrences of `model1|model2` in the file are those
  two prose strings (verified `grep -n`, 2026-10-31).
- `pseudo.content-fix` exists **only in the pre-baked infer files**; no script
  in the repo writes it. Grep across the tree: `content-fix` occurs only at
  `bringupbench/scripts/eval_infer_out.py:248,365` and
  `bringupbench/README.md:161,226` — and the README at `:161` documents it as
  a hand-glued field ("Results should be written into the JSONL with the
  `pseudo.content-fix` field"), i.e. **the last pipeline step is manual**
  (inference writes per-function files+logs elsewhere, §12/ch.34 §5; the
  harness expects a merged JSONL someone assembled offline).
- **What is `content-fix`?** Machine forensics on
  `bringupbench/data/infer_results/merged.O0.func_map.infer.jsonl`
  (382 rows, python3, 2026-10-31): it never equals the raw `pseudo.content`
  (0/382) but averages 0.990 SequenceMatcher similarity to it; similarity to
  `infer-out-model2` averages 0.409. Register-comment counts are decisive:
  bodies carrying an IDA-style `// <reg>` comment (regex
  `//\s*(eax|ebx|ecx|edx|esi|edi|esp|ebp|r(ax|bx|cx|dx|si|di|bp|sp)|al|cl|dl|bl)\b`)
  number 122/382 in `content-fix` and the same 122/382 in raw `pseudo.content`
  (the same functions), while **0/382** model outputs carry any. IDA type
  tokens (`dword|qword|byte|word|__int64|__int32|LOBYTE|HIDWORD`) appear in
  124/382 `content-fix` bodies vs 124/382 raw pseudocode but only 2/382 and
  5/382 of model1/model2 — yet `__fastcall`, present in 75/382 raw
  pseudobodies, is scrubbed from all 382 `content-fix` bodies.
  `pseudo_normalize-fix` differs from `pseudo_normalize` in 382/382 rows.
  Reading: `content-fix` behaves like lightly-corrected raw
  IDA pseudocode (fastcall scrubbed, casts otherwise kept), not like SK² model
  output. Honest hedge:
  the field's provenance is unknowable from the clone — but under this
  reading the published BringUpBench per-opt rates (§9) measure **edited IDA
  pseudocode re-inserted into source**, with the SK² models' actual outputs
  (`infer-out-model*`) scored by nobody. Any conclusion that
  "SK²Decompile reaches 42.3% compilable on BringUpBench" rests on data whose
  generating procedure is undocumented — treat as unverifiable, not as a
  model result.

## 11. What the checked-in artifacts can and cannot substantiate

- **The "505 functions" claim** (`bringupbench/README.md:12`, echoed at
  `sk2decompile/README.md:209`) is **not derivable** from the tree: the four
  func_maps total 1,822 rows, 493 distinct `(source.path, function_name)`
  pairs over 87 programs (machine count, 2026-10-31; the README itself notes
  func_maps hold more functions than are evaluated, `:247`). 505 sits between
  493 and 1,822 with no derivation shown.
- **The Avg row** (42.3/27.0%, `bringupbench/README.md:24`) does not equal the
  weighted mean of its own per-opt rows (§9: weighted ≈40.3/38.2% — executable
  side differs by ~11 points). The README's own note (`:26`) concedes the Avg
  row is "the paper's aggregate numbers (Table 8)"; the per-opt IDA baselines
  are not in the paper at all. Reproducing Table 8's arithmetic is **not
  verifiable** from the clone — that is ch.31 §3's paper-side territory and
  ch.33 §10's ledger.
- **Everything else published** (HumanEval/MBPP exe-rate, R2I, readability)
  comes from runners that consume `model_outputs/` trees that do not exist in
  the repo (§6) or crash on import (§7) — consistent with ch.20 §5's
  "published scores, unpublished pipelines" posture.

## 12. Inference side of the SK² eval pipeline

`sk2decompile/evaluation/sk2decompile_inf.py` (179 lines) is the two-phase
inference CLI the bringupbench README points at (`bringupbench/README.md:166-169`):
phase-1 model `--model_path` defaults to
`LLM4Binary/sk2decompile-struct-6.7b` (`:14`), phase-2 `--recover_model_path`
defaults to `LLM4Binary/sk2decompile-ident-6.7` (`:24`) — the non-canonical
spelling. Commit `1c164e2` (2026-01-25, "fix model name error") touched exactly
two `--recover_model_path` example lines in `sk2decompile/README.md` (`:159,174`:
`ident-6.7` → `ident-6.7b`) and nothing else (verified with `git show`,
2026-10-31) — the code default at `:24` and the root README announcement
(`README.md:25`) still carry the `b`-less name at HEAD. The HF hub serves
`ident-6.7` as a redirect to `ident-6.7b` today, and no repo literally named
`ident-6.7` appears in the LLM4Binary model list (HF API, fetched 2026-10-31;
ch.20 §9 item 7, ch.33 §1), so the id works only while the alias lives. Prompt
templates: `"# This is the assembly
code:"` wraps whatever field `--decompiler` names (`:31-32,56`) — with the
func_maps' field being `pseudo_normalize`, the README's example (which omits
`--decompiler`) would `KeyError: 'ida_pseudo_norm'` at `:56`
(verified by schema diff: func_map keys are
`source/pseudo/pseudo_normalize/binary/assembly`; §4 count method); phase-2
wraps phase-1 output in `"# This is the normalized code:"` (`:84-86`).
Outputs are per-function files `{index}_{opt}.{lang}` plus `.log` sidecars with
both phases, plus the script's own `inference_results.jsonl` whose per-record
fields are `gen_result_model1/2` (`:155-159`) — not the checked-in infer
files' `infer-out-model1/2` names — and it never reads or writes the merged
infer JSONL, confirming §10's manual-glue point. `--max_total_tokens 32768`/`--max_new_tokens 4096` (`:21-22`)
via the same `llm_server.py` vLLM wrapper as the 2025 runner (95 lines, md5
twins `58a211149e…` at `decompile-bench/llm_server.py` and
`sk2decompile/evaluation/llm_server.py`, verified md5sum 2026-10-31).

## 13. Method assessment and verifiability summary

The repo's own trajectory answers the method question: compile-and-run-a-test
(2024, §3) → per-function harnesses (2025, §5–§6) → whole-program rebuild
(BringUpBench, §9); each generation fixed the fidelity gap of the previous one
(ch.31 §5 dates the benchmark papers). External critiques bracket the whole
family: ExeBench-FHD (fetched 2026-10-31, https://arxiv.org/abs/2610.28212,
code https://github.com/Akchy/ExeBench-FHD) quantifies nine fidelity issues in
ExeBench-style harnesses — 9.27% looping programs (P5), 36.31% false-pass under
weak oracles (P6) — lifting reported exe-rate by 10–26.5 points once fixed;
MCGD (fetched 2026-10-31, https://arxiv.org/abs/2604.23940) shows compile-only
scoring can report ~0% behavioral success at 91–99% compile. The 2024/2025
LLM4Decompile harnesses are exactly the compile-adjacent designs those papers
attack; BringUpBench's rebuild-and-retest is the repo's own answer and the one
part of the published SK² evidence a third party *can* re-run today — modulo
§10's `content-fix` provenance hole, which survives the otherwise-sound
harness. (Lineage cross-refs: Idioms 54.4 vs 46.3 HumanEval, SLaDe/CHISEL:
ch.31 §7.)

Verifiability summary:

| published claim family | re-runnable from HEAD? | blocking artifact |
|---|---|---|
| 2024 HumanEval-Decompile exe-rate | yes, with local weights | data paths stale (§4) |
| 2025 DCBench exe/edit-sim | yes (1.3b-v1.6 is public) | model_outputs produced by you |
| SK² HumanEval/MBPP exe-rate | partially | model_outputs roster unpublished (§6) |
| SK² R2I | no | `metrics/R2I/run` absent (§7) |
| SK² readability (GPT-judge) | verdicts absent; judge proxy unstable | `judge_outputs/` not checked in (§8) |
| SK² BringUpBench rates | harness yes; inputs pre-baked | `content-fix` provenance (§10) |
| Table 8 Avg row | no | arithmetic unreproducible (§11) |

## Steal ideas for calxgloss

- **Whole-program rebuild + project-native test suites as the gold tier**
  (bringupbench pattern: isolated workspace copy, exact-string splice,
  make-build/make-test, per-benchmark failure lists): calxgloss P33 eval
  should mirror this shape — replacement-rate/compilable/executable triple,
  failure listings keyed by `path::func@0xaddr`.
- **Publish the oracle's input field explicitly** — LLM4Decompile's
  docstring-vs-code split (`infer-out-model2` vs `content-fix`) is the
  canonical failure of an eval harness not naming what it reads. Our harnesses
  should pin the evaluated field by constant and assert it exists.
- **Judge-failure policy**: never let an unparseable verdict score into the
  mean (L4D silently adds 1); mark judge-fails and report the judge-fail rate
  next to the score (P33 rubric eval).
- **Help-text == defaults invariant**: L4D's `--jobs` default 96 vs "default:
  1" help; cheap lint: compare argparse defaults to help strings.
- **Timestamps-in-reports discipline**: archived reports predate their commit;
  our reports should embed the git SHA they were generated from (P33 harness
  header).
- **Keep numbers out of prose ledgers**: L4D scatters claims across four
  READMEs; we already do the single-numbers-ledger right — this chapter defers
  all figures to ch.33 §10 on purpose.

## Sources

- `LLM4Decompile` clone at `85b364b`, paths cited inline (all `path:line`
  spans re-opened during self-audit, 2026-10-31; machine counts via
  `wc -l`/`md5sum`/`python3 - <<EOF json…` against a frozen `git archive HEAD`
  snapshot at `/tmp/opencode/llm4d-audit`).
- Sibling chapters: ch.20 §3/§5/§8/§9 (inventory, corpora, Docker posture,
  staleness ledger); ch.21 §8 (model-id fix `1c164e2`); ch.31 §3/§4/§5 (paper
  tables, modified R2I, benchmark papers); ch.33 §1/§7/§8/§10 (model zoo,
  rewards, prompt skew, numbers ledger).
- ExeBench fidelity critique (ExeBench-FHD), fetched 2026-10-31:
  https://arxiv.org/abs/2610.28212 (code https://github.com/Akchy/ExeBench-FHD,
  dataset https://huggingface.co/datasets/davish007/ExeBench-FHD);
  MCGG/MCGD compile-vs-behavior, fetched 2026-10-31:
  https://arxiv.org/abs/2604.23940; Idioms, ch.31 §7:
  https://arxiv.org/abs/2502.04536; SLaDe: https://arxiv.org/abs/2305.12520;
  CHISEL: https://arxiv.org/abs/2608.27981;
  ExeBench origin: Armengol-Estapé et al., MPLR 2022,
  https://doi.org/10.1145/3520312.3534867.
- bringup-bench upstream (fetched 2026-10-31):
  https://github.com/toddmaustin/bringup-bench (108 benchmarks at fetch, 4
  `libtarg_*` syscalls, Apache-2.0); R2I upstream:
  https://github.com/e0mh4/R2I (ch.31 §5 details); psychec:
  https://github.com/uptrendeco/psychec (type inference on `original` branch —
  ch.33 §7).
