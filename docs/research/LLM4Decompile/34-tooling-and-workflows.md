# 34. Tooling and workflows — the day-to-day surface, and what still runs at HEAD

> What it actually looks like to *use* this project: the quick-start workflow, the
> serving stack, the Ghidra/IDA integration scripts, the SK² inference and
> preprocessing CLIs, and a ledger of which entry points still execute at HEAD
> `85b364b`. Every `path:line` was re-opened and verified in the clone
> (`/tmp/opencode/LLM4Decompile`); "does not run" claims state what was searched.
> The evaluation-metric machinery is ch.32; the release ladder is ch.21 §8; the
> staleness headlines are ch.20 §9 — this chapter is the operator's view.

## 1. Five workflows, four generations

1. **2024 quick-start** (root `README.md:85-171`): a copy-paste Python snippet —
   gcc, objdump, scrub, prompt, HF `generate`. No CLI, no harness.
2. **2024 runner set** (`evaluation/` + `scripts/run_evaluation_llm4decompile.sh`):
   the TGI/vLLM batch scoring drivers (covered in ch.20 §3, ch.32 §2).
3. **2025 Decompile-Bench CLIs** (`decompile-bench/`: `run_exe_rate.py`,
   `cal_edit_sim.py`, `llm_server.py`): HF-dataset-driven, offline vLLM.
4. **SK² two-phase inference CLI** (`sk2decompile/evaluation/sk2decompile_inf.py`,
   179 L) plus its preprocessing suite (`sk2decompile/Preprocess/`).
5. **BringUpBench shell pipeline** (`sk2decompile/evaluation/bringupbench/scripts/`,
   ch.32 §7): `config.env`-driven build → IDA → objdump → func-maps → eval.

There is no top-level CLI, no console entry points, and the one Dockerfile targets
only the Ghidra-refine demo (§4). Everything below is about how these surfaces
actually behave when executed.

## 2. The 2024 quick-start, dissected

The root README (`README.md:81`) is still the canonical workflow and
doubles as the dataset-build recipe — `legacy-test/README.md:11-12` points its
own corpus construction back at this exact snippet ("assembly … with prompts,
can be derived as in our preprocessing example"). Setup block at `README.md:85-92`
(conda py3.9 + `requirements.txt`), then:

```python
compile_command = f'gcc -o {output_file}.o {input_file} -{opt_state} -lm'   # README.md:107
compile_command = f'objdump -d {output_file}.o > {output_file}.s'           # README.md:109
```

Two choices hide in those two lines. **The `.o` is disassembled, not a linked
binary** — call targets and constants stay unresolved relocations, precisely the
fidelity gap the ExeBench-FHD study (ch.32 §9) later measured at −10 to −26
points. And the extraction step (`README.md:116`) is string surgery:

```python
asm = '<'+func_name+'>:' + asm.split('<'+func_name+'>:')[-1].split('\n\n')[0]
```

`split(...)[-1]` — the **last** occurrence of the label, so a second function
whose name contains the target as a substring (`func0` inside `myfunc00`) can
hijack the extraction; `.split('\n\n')[0]` stops at the first blank line, which
works for objdump output but silently truncates on any assembler that emits blank
lines inside a body. The scrub loop (`README.md:118-128`) keeps `mnemonic operands` by
dropping tab-fields before index `min(len-1, 2)` (address column, hex bytes),
then cuts at `#` (objdump's operand comments — which on optimized code are
exactly where callee names and relocation targets would leak). The keep-if
predicate `len(tmp.split("\t"))<3 and '00' in tmp: continue` (`README.md:120-121`) is a
byte-pattern heuristic for junk lines, not a defined rule. The prompt wrap is the
famous pair `# This is the assembly code:\n` … `\n# What is the source code?\n`
(`README.md:130-132`).

The generate block (`README.md:152-164`): V1.5 model id `LLM4Binary/llm4decompile-6.7b-v1.5`
(`README.md:155`), plain `AutoModelForCausalLM`, `max_new_tokens=2048` with the comment
about the 4096 window (`README.md:163`), and decode via
`outputs[0][len(inputs[0]):-1]` (`README.md:164`) — the `:-1` drops the *last token of the
whole sequence*, i.e. the EOS, relying on greedy generation ending at EOS; if
generation ended by length instead, the last content token is chopped. The
convention layer is all one `func0` string substitution (`README.md:94-96`, "Replace the
'func0' with the function name you want to decompile" — a manual find/replace,
repeated as `#IMPORTANT replace func0` comments at `README.md:115-116`).

**Verified absence:** no script in the repo implements the quick-start end-to-end
(searched: no file reproduces the scrub + prompt + generate chain except
`ghidra/demo.py`, which swaps objdump for Ghidra pseudo, and `llm_server.py`'s
`__main__`, which instead reads the pre-baked `input_asm_prompt` field from
legacy-test JSON, `sk2decompile/evaluation/llm_server.py:76`).

## 3. The serving stack: three ways to run a model, three different bugs

- **TGI path** (`evaluation/server/text_generation.py`): the client spawns a
  `text-generation-launcher` with the flags it was handed, then probes readiness
  at **hardcoded `127.0.0.1:8080`** (`:50`) regardless of `--port` — point it at
  any other port and the readiness loop hangs forever (the launcher keeps
  running; the client never connects). Generation cleaning is only
  `generated_text.replace(stop_sequence, "")` per stop sequence (`:97-98`); any
  exception → empty string, logged, scored 0 silently (`:100-102`, ch.32 §2).
- **vLLM offline path** (`evaluation/run_evaluation_llm4decompile_vllm.py`):
  the batch driver used for V1.5/V2 tables; `--model_path` must be an existing
  local directory (`:176`) — README model ids must be `huggingface-cli`-pre-downloaded
  first, which the README never says.
- **`llm_server.py`** exists twice, **md5-identical**
  (`decompile-bench/llm_server.py` ≡ `sk2decompile/evaluation/llm_server.py`,
  md5 `58a211149e6d4d35a3d4c6afe59b531b`, 95 L): a thin vLLM wrapper whose
  `llm_inference()` (`:43`) accepts HF ids (unlike the 2024 vllm runner) and
  whose `__main__` (`:69-95`) is a legacy-test batch loop — reads
  `sample["input_asm_prompt"]` (`:76`), writes `{idx}.c` (`:94`). It is
  simultaneously the inference engine of the SK² chain (§5) and a stale 2024
  corpus consumer.

`requirements.txt` vs `requirements-docker.txt` divergence is inventoried in
ch.20 §8; nothing here adds to it beyond confirming the three serving paths pin
*nothing* (no vLLM version in the SK² README beyond "pip install vllm",
`sk2decompile/README.md:152-153`).

## 4. Ghidra and IDA: the integration scripts

**Ghidra V2-refine demo** (`ghidra/demo.py`, 88 L): the only flow the Dockerfile
supports. `ghidra_path = "./ghidra_11.0.3_PUBLIC/support/analyzeHeadless"`
(`:10`) — a relative path, "change the path accordingly"; compiles the sample to
an object at O0 **only** (`for opt in [OPT[0]]`, `:20`), runs
`analyzeHeadless … -postScript decompile.py <out> -deleteProject` with
`check=True` (`:33-40`), then parses the postscript's output by scanning for
`Function: func0` (`:46`) and cutting comments by finding the first line that
contains `func0` again (`:57-60`, with `raise ValueError('bad case no function
found')` at `:55-56`). It then wraps the pseudo in the *same assembly-flavored*
prompt pair (`# This is the assembly code:`) and refines with
`LLM4Binary/llm4decompile-6.7b-v2` (`:72`) — the V2 model's own trained prompt
shape is inherited from the pseudo-code template (prompt-skew analysis: ch.33 §8).
`ghidra/decompile.py` (47 L) is the Ghidra postscript itself: Python-2 Jython,
prints `// Function: <name>` before each decompiled function (the marker
`demo.py:46` greps), calls `decompileFunction` with timeout 0 (unlimited), and
credits itself as derived from a public galoget script (`:13`) — and note it
writes the marker/decompilation to a file, not stdout, so `demo.py`'s scan is of
that file (`:41,47`).

**Dockerfile** (58 L): `pytorch/pytorch:2.7.1-cuda12.8-cudnn9-runtime` base,
Ghidra **11.0.3** (build `20240410`) fetched and unzipped (`:7-9,22-25`), conda env
`llm4decompile` cloned from base + `requirements-docker.txt` (`Dockerfile:30-40`),
entrypoint activates it (`Dockerfile:50-57`). It is a Ghidra-demo container: it contains no
IDA (proprietary, unsurprising), no evaluation runner defaults, and pins a 2024
Ghidra against a 2025 PyTorch — fine for the demo, irrelevant for the 2025/2026
workflows (cross-ref ch.20 §8).

**IDA** appears only inside the BringUpBench pipeline:
`bringupbench/scripts/dump_pseudo.py` (62 L, single copy — verified by find/md5, no duplicate
at repo root) is the headless batch script: run as
`idat -A "-Sdump_pseudo.py <out>" <binary>`, it decompiles every function,
emitting `/* <name> @ 0x<addr> */` markers and logging Hex-Rays failures *inline*
at the marker instead of failing the run. The consumer
`decompile-all-pseudo.sh` defaults `IDA_BIN` to a personal absolute path
(`/home/bairidreamer/software/IDA-Pro/idat`) — a machine fingerprint left in the
published artifact (§6 ledger).

## 5. The SK² inference CLI and the Preprocess suite

**Inference chain** (`sk2decompile/evaluation/sk2decompile_inf.py`, 179 L) —
the only shipped implementation of the two-phase method:

- Phase-1 prompt: `"# This is the assembly code:\n"` + `sample[args.decompiler]`
  (`:31,56`) — but the `--decompiler` default is **`ida_pseudo_norm`** (`:16`):
  phase 1's "assembly" is in fact *normalized IDA pseudo-code* unless the user
  overrides.
- Phase-2 prompt: `"# This is the normalized code:\n"` + phase-1 output
  (`:80-85`), run through `llm_inference(…, args.recover_model_path, …)` (`:90`);
  `--recover_model_path` defaults to `LLM4Binary/sk2decompile-ident-6.7` (`:24`) —
  the non-canonical spelling (canonical: `-ident-6.7b`; the HF hub serves the
  `b`-less name as a redirect today, fetched 2026-10-31). Commit `1c164e2`
  (2026-01-25) fixed the id in exactly two README example lines
  (`sk2decompile/README.md:159,174`) — the CLI default at `:24` was never
  touched, and ch.33 §1 lists it among the propagated-broken names.
- `--strip 1` (default, `:27`) post-processes phase-2 output by re-substituting
  the generated function's name back to `samples["func_name"]` (`:110-122`),
  storing `gen_result_model2_stripped`.
- Outputs per sample: `<idx>_<opt>.<c|cpp>` body (`:129`), a `<path>.log` JSON with
  both raw model outputs (`:133-153`), `inference_results.jsonl` (`:155`), and
  `inference_stats.txt` (`:160`). Per-sample stdout `.log` sidecars make the run
  debuggable per function — the nicest output design in the repo.

**The README lies about this CLI's name.** Both the quick inference block
(`sk2decompile/README.md:158-159`) and the "Detailed version" block (`:171-174`)
tell users to run `python sk2decompile.py …`. **No file named `sk2decompile.py`
exists anywhere in the clone** (verified: `find . -name sk2decompile.py` → no
result). The runnable script is `evaluation/sk2decompile_inf.py`. Likewise the
eval examples at `sk2decompile/README.md:194-204` pass `--dcompilers` (missing `e`) on
`evaluate_exe.py`/`evaluate_r2i.py`, whose argparse defines `--decompilers`
(`evaluate_exe.py:65`, `evaluate_r2i.py:14`) — every README example command for
these two CLIs exits with an unknown-argument error.

**Preprocess suite** (`sk2decompile/Preprocess/`, four files):

- `normalize_pseudo.py` ≡ `normalize_src_basedonpseudo.py`: **md5-identical
  twins** (`7140bcfb712d1f4848c1a0d16f2c1414`) — one under `evaluation/`, one under
  `Preprocess/`, different names. The pipeline README cites *both* names in
  adjacent steps (`sk2decompile/README.md:83` calls `normalize_pseudo.py`, `:86`
  calls `normalize_src_basedonpseudo.py` with the same arguments it needs for the
  SK² IR). This is the source of `pseudo_normalize` in the func-map records
  (ch.32 §7).
- `format.py` (99 L): `comment_remover` (`:21`) → `clang-format --style=Google`
  with a **0.5 s timeout** (`:36-48`) → `good_func` size filter keeping only
  3 < body lines < 300 (`:8-15`, applied `:64`). The bare `except:` around
  clang-format (`:51-52`) and the filter both **drop records silently** — the
  output JSON can be shorter than the input with no accounting.
- `inf_type.py` exists twice and the copies are *not* identical: the
  `Preprocess/` copy ends in `main()` (`:137-140`; batch mode with
  `--input_json/--output_name/--split/--idx`, `:60-67`) and contains **mojibake'd
  Chinese help strings** (`:62-65`, `鈥` sequences) from an encoding accident;
  the `evaluation/` copy ends in `jsonfile()` (`:136-155`) — a mode that rewrites
  `one['func_dep'] = header` in-place over `github2025_normsrcpseudo.json` at
  hardcoded `/workspace/llm4binary/...` paths (`:138-139`) — plus a `folder()`
  mode whose default input is `/workspace/llm4binary/type/evaluation/result/exebench-8800_github1000`
  (`:108-110`), the corpus fingerprint ch.32 §9 relies on. Both modes shell out
  to `psychecgen` + `stack exec psychecsolver-exe` with **1-second timeouts**
  (`:33,41`) — psychec type inference on nontrivial functions routinely exceeds
  that, so silent header-drop is the expected failure mode.
- `standard_c.txt` (1 633 B, single line): a comma-separated libc symbol allowlist
  (`printf, scanf, fprintf, …`) used to decide which callees are "standard" and
  need no injected header — the only checkable artifact in the type pipeline.
- The psychec dependency itself is *not vendored and not pinned*: the README
  lists `https://github.com/ltcmelo/psychec.git` as a bullet (`sk2decompile/README.md:61,259`)
  and commands assume a sibling `../psychec/` build (`:93`); there is no install
  script, and psychec's own master branch no longer contains the type-inference
  tools this flow shells out to (they live on the `original` branch — psychec
  README, fetched 2026-10-31; details ch.32 §9). A fresh `git clone psychec` per
  README therefore produces a tree without `psychecgen`/`psychecsolver-exe`.
  The vestigial `sk2decompile/evaluation/stack.yaml` (66 L stock `stack init`
  stub) is where the Haskell solver build was meant to run.

## 6. What still runs at HEAD — an operator's ledger

Statuses verified by reading the code path (not by running GPU jobs); "broken"
means a checked condition that fails at import/argument time, stated per row.
Cross-references avoid re-listing ch.20 §9 items (4 and 12 in particular) and
ch.33 §1's broken-model-name catalogue.

| Entry point | Status | Evidence |
|---|---|---|
| `README.md` quick-start snippet | runs (CPU/gpu agnostic) | §2; assumes gcc/objdump present; HF ids downloadable |
| `scripts/run_evaluation_llm4decompile.sh` | runs with TGI | ch.20 §3 |
| `evaluation/run_evaluation_llm4decompile_vllm.py` | runs **if model pre-downloaded to dir** | `:176` is_dir gate |
| `evaluation/server/text_generation.py` | runs **only on port 8080** | `:50` hardcoded probe |
| `decompile-bench/run_exe_rate.py` + metrics | runs from `decompile-bench/` — the two corpora ARE committed (18 MB / 75 MB on disk, `du -h` 2026-10-31), only the model needs downloading | ch.32 §5 |
| `decompile-bench/metrics/cal_edit_sim.py` | runs (same `./data/` caveat) | ch.32 §3 |
| `sk2decompile/…/cal_execute_rate.py __main__` | **broken**: tuple-unpack of a float return + `/workspace/llm4binary` paths | ch.32 §4 |
| `sk2decompile/evaluation/evaluate_exe.py` | runs; silent-0 on missing `./model_outputs/…` files (`:26`), defaults leak experiment names (`:65`) | ch.32 §6 |
| `sk2decompile/evaluation/evaluate_r2i.py` | **broken at import**: `from metrics.R2I.run import run_r2i` (`:4`) — no `metrics/R2I/` in clone | verified find |
| `sk2decompile/evaluation/gpt_judge.py` | runs only with a working `--api_key` against hardcoded `api5.xhub.chat` (`:18-24`); `--cal_score 0` path `TypeError`s (`:178` vs `:128`) | ch.32 §6 |
| `sk2decompile/evaluation/sk2decompile_inf.py` | runs but phase-2 default model id is non-canonical, relying on an HF redirect (`:24`); README's `sk2decompile.py` name doesn't exist | §5, ch.21 |
| `sk2decompile/Preprocess/format.py` | runs; silent record drops | §5 |
| `sk2decompile/Preprocess/inf_type.py` (`main`) / `sk2decompile/evaluation/inf_type.py` (`jsonfile`) | **broken as shipped**: psychec tools absent from pinned repo's master; 1 s timeouts; `/workspace/...` defaults | §5, ch.32 §9 |
| `bringupbench/scripts/*.sh` | run given `config.env` filled (placeholders `/path/to/bringup-bench`, `/path/to/idat`) + real IDA; `decompile-all-pseudo.sh` defaults to a personal `IDA_BIN` path | §4 |
| `bringupbench/scripts/eval_infer_out.py` | runs; `--jobs` help says "default: 1", actual default 96 (`:121-126`); checked-in `reports/O*_results.md` were renamed offline — generator writes `{stem}-{target}-{timestamp}` names | ch.32 §7–8 |
| `Dockerfile` | builds; covers only the Ghidra demo | §4 |

Three structural observations fall out of the table:

1. **Silent-zero is the repo's dominant failure mode.** Generation errors (§3),
   missing model-output files (`evaluate_exe.py:26`), clang-format drops (§5),
   psychec timeouts (§5), judge failures (score 1, ch.32 §6) — none raise to the
   operator; they degrade the score toward 0 indistinguishably from a wrong
   answer. A calibration hazard the papers never acknowledge.
2. **The READMEs and the CLIs have drifted apart** at the *interface* level:
   script names (`sk2decompile.py`), flag spellings (`--dcompilers`), model ids
   (`-ident-6.7`), pipeline step names (`normalize_pseudo` vs
   `normalize_src_basedonpseudo`). Interface drift is how staleness becomes
   *unreproducible* rather than merely untidy — ch.20 §9 counts the doc
   contradictions; this table counts the dead commands.
3. **Machine fingerprints mark the un-rehearsed paths.** `/home/bairidreamer/…`
   (IDA), `/workspace/llm4binary/…` (type pipeline), `api5.xhub.chat` (judge),
   2025-11-19 report timestamps — the SK²-era runs happened on at least one
   private machine whose paths and names were committed rather than templatized
   (the bringupbench `config.env` pattern shows the authors knew the right
   pattern; it was applied only to one of five workflows).

## Steal ideas for calxgloss

- **Runnable-name discipline (P33/P42).** Calxgloss README commands should be
  generated from argparse help, not written by hand — half of LLM4Decompile's
  SK²-era commands fail at the flag or filename level. A CI check that
  `python <named-script> --help` exits 0 for every script named in a README is
  ~10 lines of shell (calxgloss has no CI at all today, ch.20 §10; this is a
  first CI job candidate, P42).
- **Interface fingerprints over config drift.** Prefer one `config.env`-style
  resolution chain (CLI > env > file, as `bringupbench/config.env:1-4` does)
  across *all* workflows; and a repo-wide grep gate for absolute personal paths
  (`/home/`, `/workspace/`) before publishing (the fingerprints in §6 are
  exactly what a `git grep -E '/(home|workspace)/'` pre-commit would catch).
- **Fail-loud with per-record accounting (P33).** Every drop point (format
  filter, psychec timeout, judge failure, missing output file) should emit a
  countable `dropped/scored` tally into the run's stats file. LLM4Decompile's
  silent zeros make half its published numbers unauditable; calxgloss's P33
  harness should treat "scored N of M" as a first-class report column.
- **Timeout budgets belong to the oracle, not the tool.** The repo's two-tier
  pattern (10 s for compile/run oracles, 1 s for psychec preprocessing) shows
  the right instinct (oracle budgets are fixed and stated) and its failure
  (1 s silently truncates real work). calxgloss EXE-scenario capture (P23–P33)
  should record timeout counts per stage, with budgets in the manifest.
- **Demo ≠ product surface.** The Dockerfile serves the 2024 demo while the
  2026 workflows (ch.21 §6) have no container story. If calxgloss ships a
  container, it should pin the *scoring* path (P33) first — that's the part
  third parties need to re-run to trust calxgloss numbers.

## Sources

- Clone at HEAD `85b364b`, all spans re-opened 2026-10-31:
  `README.md:12,25,81,85-171` (esp. `:94-96,107,109,115-116,118-128,130-132,152-164`);
  `Dockerfile:2,7-9,22-25,30-40,50-57`;
  `evaluation/server/text_generation.py:40-54,90-102`;
  `evaluation/run_evaluation_llm4decompile_vllm.py:176`;
  `scripts/run_evaluation_llm4decompile.sh`;
  `ghidra/demo.py:10,17,20,23-27,33-40,46,53-54,55-60,72,88`;
  `ghidra/decompile.py:13` (Jython postscript, 47 L);
  `decompile-bench/llm_server.py` ≡ `sk2decompile/evaluation/llm_server.py`
  (md5 `58a211149e6d4d35a3d4c6afe59b531b`, 95 L; `:43,69,76,94`);
  `sk2decompile/README.md:61,83,86,89,92-93,153-159,171-174,194-204,259`;
  `sk2decompile/Preprocess/{format.py:8-15,21,36-52,64, inf_type.py:60-67,137-140,
  normalize_src_basedonpseudo.py, standard_c.txt (1 633 B)}`;
  `sk2decompile/evaluation/{sk2decompile_inf.py:16,24,27,31,56,80-90,105-122,129,133-160,
  normalize_pseudo.py, inf_type.py:33,41,108-110,136-162, stack.yaml (66 L),
  evaluate_exe.py:26,65, evaluate_r2i.py:4,14, gpt_judge.py:18-24,128,176-178}`;
  `sk2decompile/evaluation/bringupbench/{config.env:1-4,10,13, scripts/{build-host-opt-levels.sh,
  decompile-all-pseudo.sh (IDA_BIN default), disasm-all-objdump.sh, dump_pseudo.py (62 L, sole copy),
  eval_infer_out.py:121-126}}`.
- Verified absences (search method stated inline): `sk2decompile.py`
  (`find . -name sk2decompile.py` → none); `metrics/R2I/` module
  (`find`/import trace); root-level `dump_pseudo.py` duplicate (find/md5);
  any end-to-end implementation of the README quick-start (grep for the scrub
  loop's distinctive predicates).
- psychec README (fetched 2026-10-31): type inference not on master, `original`
  branch holds it; BSD-3-Clause; driver `cnippet`. Also
  https://github.com/e0mh4/R2I (R2I artifact pointer mirrored by
  `decompile-bench/readme.md:73`) and https://dogbolt.org (SK² README's
  decompilation-everywhere suggestion for input preparation,
  `sk2decompile/README.md:166-167`).
- Cross-references: ch.20 §3 (runner scripts), §8 (Docker/deps), §9 items 4/12;
  ch.21 (model-id fix commit `1c164e2`, phase-4 timeline); ch.32 §2 (oracle
  defaults), §4–§6 (metric/judge internals), §7–§9 (BringUpBench + ExeBench
  substrate); ch.33 §1 (model zoo), §8 (prompt skew).
