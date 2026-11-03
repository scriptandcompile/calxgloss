# LLM_Decompiler complete inventory (HEAD `c242671`)

> Part of the [LLM_Decompiler overview](README.md). Every tracked file at HEAD
> `c2426715340b84a3e2eea4e891fe913a50154f00` ("Delete .env", 2024-07-15) —
> what it is, what it actually does, and what it claims vs what the code does.
> All claims cite clone-relative `path:line` at that HEAD from the read-only
> clone at `/tmp/opencode/LLM_Decompiler`; history claims cite `<sha>`
> (short). The
> file ledger, modes, trailing-newline battery, model literals, and the
> packaging negative-findings were produced by scripted batteries run inside
> the clone (Sources). GitHub metadata fetched 2026-10-31.

## 1. Repo shape and scale

One flat toolkit: **30 tracked files, 1,390 `wc -l` lines** (1,395 content
lines; five files end without a trailing newline: `README.md`,
`Decompiler/decompilation_scripts/decompiler.py`, `Decompiler/exec/README.md`,
`helper_scripts/README.md`, `large_code_base_reconstruction.py`). GitHub
reports repo `size: 49` KB (API, 2026-10-31; history chapter §7 for
the metadata battery).

Composition (`git ls-tree -r HEAD`): **14 Python, 11 shell, 5 Markdown**.
Of the Python: 2 are Ghidra Jython postScripts (§3), 8 call the OpenAI chat
API (§4), and 4 are dataset/helper CLIs (§6). Of the shell: 8 root pipelines
(`analyze_*`, `decompile_*`), 2 Ghidra launchers under `Decompiler/`, 1 dir
reorganizer under `helper_scripts/`. There is **one** root README (126 `wc -l`,
the whole "release narrative", §8) plus one README per subdirectory except
`Decompiler/` itself (which has only `Decompiler/exec/README.md`, one line).

There is no package, no build, no dependency manifest, no config file, no
test, no CI, and no license — each verified as a NEGATIVE FINDING in §9. The
tool is "run from the repo clone": every pipeline hardcodes relative or home
paths (§5, §11).

## 2. Complete 30-file ledger

Birth commit and later touches from the per-commit numstat battery; `wc -l`
at HEAD. (The `.env` file — 31st file from `72c3c11` to `c242671` — is not at
HEAD and is covered in the history chapter §5.)

| Path | `wc -l` | Born | Touched later | Role |
|---|---:|---|---|---|
| `README.md` | 126 | `9a5b3e0` (+2) | 9 commits (`9c64ffc` +87/−1 … `5a7de76`) — final 127 content lines | description + setup + 9-script usage |
| `analyze_all.sh` | 41 | `5b25d26` | never | find-exec sweep calling both binary pipelines |
| `analyze_binary.sh` | 31 | `5b25d26` | never | decompile → `llm_d.py` |
| `analyze_enhanced_binary.sh` | 50 | `5b25d26` | never | decompile → filter → enhance → `llm_d.py` |
| `analyze_source.sh` | 35 | `5b25d26` | never | source file → `llm_d.py` |
| `analyze_and_exploit.sh` | 62 | `e0db19e` | `51a2c98` (1/1) | 5-step CTF pipeline (pwn skeleton + ctf context) |
| `analyze_and_fix.sh` | 56 | `e0db19e` | never | 4-step pipeline ending in `llm_fix.py` |
| `decompile_pipe.sh` | 35 | `5b25d26` | never | end-to-end decompile to `<name>_decompiled.c` |
| `decompile_large_pipe.sh` | 35 | `8eff39b` | never | end-to-end decompile to `<name>_decompiled.json` |
| `large_code_base_reconstruction.py` | 96 | `5b25d26` (+98) | `72c3c11` +3/−2, `8eff39b` −2 | per-function GPT loop with rolling rename map |
| `llm_d.py` | 64 | `5b25d26` (+63) | `72c3c11` +3/−2 | vulnerability-report prompt |
| `llm_f.py` | 55 | `5b25d26` (+54) | `72c3c11` +3/−2 | function-filter prompt |
| `llm_r.py` | 50 | `5b25d26` (+49) | `72c3c11` +3/−2 | rename/comment enhancement prompt |
| `llm_pwn.py` | 60 | `e0db19e` | never | pwn-script skeleton prompt |
| `llm_fix.py` | 53 | `e0db19e` | never | fix-suggestion prompt |
| `llm_ctf_context.py` | 54 | `e0db19e` | never | CTF category/hints prompt |
| `llm_translate.py` | 48 | `e0db19e` | never | C→any-language translation prompt |
| `Decompiler/gd_decomp.sh` | 24 | `3363516` | never | analyzeHeadless launcher (`.c` variant) |
| `Decompiler/gd_decomp_large.sh` | 24 | `8eff39b` | never | analyzeHeadless launcher (`.json` variant) |
| `Decompiler/decompilation_scripts/decompiler.py` | 39 | `95016c1` (root) | `9c64ffc` R100 rename in | postScript → `decompiled_output.c` |
| `Decompiler/decompilation_scripts/large_decompiler.py` | 24 | `8eff39b` | never | postScript → `decompiled_output.json` |
| `Decompiler/exec/README.md` | 0 | `8058050` (+1) | never | one-line placeholder (no trailing newline) |
| `dataset_scripts/README.md` | 39 | `a4e57fc` | `d23429f`, `a80331c`, `2e7fee2` | documents the two dataset scripts |
| `dataset_scripts/process_juliet_suite.py` | 58 | `49df012` as `Dataset_scripts/…`; deleted `fadee84`; recreated `e913125` byte-identical | `9316783` (1/1) before the move | Juliet CWE dir filter + good/bad scrub |
| `dataset_scripts/select_from_cwe.py` | 55 | `49df012` as `helper_scripts/select_from_cwe.py` | `a4e57fc` R100 rename in | sample bad/good Juliet binary pairs |
| `helper_scripts/README.md` | 25 | `a4e57fc` | never | documents the three helpers |
| `helper_scripts/count_cpp_files.py` | 35 | `49df012` | never | count `.c/.cpp/.cc/.h` |
| `helper_scripts/regroup_subdirs.sh` | 41 | `49df012` | never | move subdirs matching a substring |
| `helper_scripts/strip_binaries.py` | 46 | `49df012` | never | `file` + `strip` sweep |
| `results/README.md` | 29 | `8058050` (+16) | `589c2c6` (+13) | output-tree naming convention only |

## 3. The two entry pipelines and the Ghidra layer

The core is a **Ghidra `analyzeHeadless` sandwich with two output shapes**.
`.c` path: `decompile_pipe.sh` stores the caller's cwd (`:10`), `cd
./Decompiler` (`:17`), wipes `tmp*` project residue (`:20`), copies the target
to `./exec/exe` (`:23`), runs `./gd_decomp.sh ./exec/exe /tmp/source.c`
(`:26`), then moves the postScript's `decompiled_output.c` next to the
original executable as `<exe-name>_decompiled.c` (`:30`–`:33`).
`decompile_large_pipe.sh` is the line-for-line twin whose output is
`<exe-name>_decompiled.json` (`:26`, `:30`, `:33`).

`Decompiler/gd_decomp.sh` (`:22`–`:23` is the live core): `GHIDRA_PATH=./
ghidra_11.0.1_PUBLIC` (`:5`) and `DECOMPILE_SCRIPT_PATH=.` (`:6`), a `-ne 2`
arg guard (`:8`), `rm -rf *.gpr *.rep` (`:17`), then
`analyzeHeadless . tmp_ghidra_project -import $1 -scriptPath . -postscript
decompiler.py $2`. `gd_decomp_large.sh` differs only in the postScript name.
Two oddities: the **echoed** command (`:22`, showing
`-postscript $DECOMPILE_SCRIPT_PATH/decompiler.py`) is not the **run** command
(`:23`, `-scriptPath . -postscript decompiler.py`); and since the postScripts
physically live in `decompilation_scripts/`, `-scriptPath .` only finds them
because README's setup step tells the user to copy them into
`ghidra_11.0.1_PUBLIC/Ghidra/Features/Decompiler/ghidra_scripts`
(`README.md:45`). The `$2` "output path" argument (`/tmp/source.c`) is passed
all the way to the postScript but **never used**: `decompiler.py` imports
`sys` (`:7`) and never touches `argv` — the output name `decompiled_output.c`
is hardcoded in CWD (`:26`).

The postScripts themselves are minimal. `decompiler.py` opens the
`DecompInterface` (`:12`–`:15`), iterates every function (`:18`), and writes
one C file with `----- START/END OF FUNCTION: {name} -----` markers around
each body (`:21`–`:22`, `:31`, `:40`), decompiling with timeout `0` (`:35`).
`large_decompiler.py` does the same sweep but emits JSON objects
`{name, signature, body}` (`:15`–`:19`) dumped to `decompiled_output.json`
(`:23`–`:24`). No LLM runs inside Ghidra; the postScripts are pure
decompilers.

## 4. The eight OpenAI prompt drivers — model and endpoint ledger

Eight scripts call the OpenAI chat API; all eight use the identical preamble
`load_dotenv(); OPENAI_API_KEY = os.getenv('OPENAI_API_KEY'); client =
OpenAI(api_key=…)` (8/8 in the battery, e.g. `llm_d.py:13`–`:15`) and all
eight send the **entire prompt as the `system` message** — no `user` role, no
temperature, no max-tokens, no retry, no streaming anywhere. Model literals
(grep battery):

| Script | Model literal | Prompt span | Output convention |
|---|---|---|---|
| `llm_d.py` | `gpt-4-turbo` (`:52`) | `:29`–`:49` | `<stem>_vulnerabilities.txt` (`:18`, `:61`) |
| `llm_f.py` | `gpt-4-turbo` (`:36`) | `:25`–`:31` | `<stem>_filtered.c` (`:42`) |
| `llm_r.py` | `gpt-4-turbo` (`:38`) | `:26`–`:33`, code appended by `+=` (`:35`) | `<stem>_enhanced.c` (`:16`) |
| `large_code_base_reconstruction.py` | `gpt-3.5-turbo` (`:49`) | `:17`–`:45` | `<stem>_enhanced.c` (`:87`) |
| `llm_pwn.py` | `gpt-4o` (`:26`) | `:12`–`:23` | `<name>_pwn.py` via 4th arg (`:57`) |
| `llm_fix.py` | `gpt-4o` (`:23`) | `:12`–`:20` | `<name>_fixes.txt` via 3rd arg (`:50`) |
| `llm_ctf_context.py` | `gpt-4o` (`:24`) | `:11`–`:21` | `<name>_ctf_context.txt` (`:51`) |
| `llm_translate.py` | `gpt-4o` (`:21`) | `:11`–`:18` | arg-supplied `output_file` (`:45`) |

So three models, never one: `gpt-4-turbo` for the original May-2024 trio,
`gpt-3.5-turbo` for the large-codebase loop, `gpt-4o` for all four `e0db19e`
CTF-era scripts (`git grep model= 5b25d26/e0db19e` battery — literals were
born as they read at HEAD; no script ever changed model). The README's claim
that the drivers use "the OpenAI GPT-4 model" (`README.md:101`, `:108`,
`:115`, `:122`) matches no call site (§8).

Behavioral notes that matter for comparison: `llm_d.py`'s prompt demands
near-zero false positives in broken-English emphasis ("false negative is much
much better than false positives … unless it is 100% confirmed", `:35`–`:36`)
and pins an output format of `Confirmed_vulnerabilities : list` /
`Potential_vulnerabilities : list` (`:47`–`:48`) — **nothing ever parses
either**; the raw response is written to disk (`:61`–`:62`).
`large_code_base_reconstruction.py` is the only driver with cross-function
state: a rolling `name_map` (`:80`) fed back into every prompt (`:30`), a
line-1 `new_map_pair: old : new` parse convention (`:56`–`:64`), and a
silent fallback to the original body on any API exception (`:68`–`:70`). Its
`FUNCTION_START_MARKER`/`FUNCTION_END_MARKER` constants (`:8`–`:9`) are dead
code — the only two occurrences in the repo; the JSON input path never uses
markers (NEGATIVE FINDING: grep `FUNCTION_START_MARKER\|FUNCTION_END_MARKER`
hits only `:8`–`:9` at HEAD, despite `decompiler.py:21`–`:22` emitting them
into the `.c` output). `llm_translate.py` is invoked by **no pipeline** — the
"preferred programming language" capability (`README.md:31`) has no wiring.

## 5. `analyze_*.sh` — orchestration ledger

Six root orchestrators chain the drivers over an artifact-name relay
(`<name>_decompiled.c` → `_filtered.c` → `_enhanced.c` → `_..._vulnerabilities.txt`):

| Pipeline | Steps (script@line) | Output home |
|---|---|---|
| `analyze_binary.sh` | pipe@`:15` → `llm_d.py`@`:20` | `./results/<name>/executable_analysis` (`:24`) |
| `analyze_enhanced_binary.sh` | pipe@`:19` → `llm_f`@`:24` → `llm_r`@`:29` → `llm_d`@`:34` | `./results/<name>/enhanced_executable_analysis` (`:38`) |
| `analyze_source.sh` | `llm_d.py` on the copied source@`:20` | `./results/<name>/source_analysis` (`:24`) |
| `analyze_all.sh` | `find -exec bash -c` sweep@`:39` over `[ -x ]` files@`:25`, runs both binary pipelines@`:28`–`:30` | per-child `results/` dirs |
| `analyze_and_fix.sh` | pipe@`:19` → `llm_f`@`:24` → `llm_r`@`:29` → `llm_d`@`:34` → `llm_fix`@`:39` | `results/…/enhanced_executable_analysis` + `_fixes.txt` one level up (`:54`) |
| `analyze_and_exploit.sh` | same four@`:19`–`:34` → `llm_pwn`@`:39` (4 args) → `llm_ctf_context`@`:44` (3 args) | same, plus `_pwn.py`/`_ctf_context.txt` (`:59`–`:60`) |

The two `e0db19e` twins are the outliers: both hardcode
`basePath=~/Desktop/sp_new` (`analyze_and_exploit.sh:10`,
`analyze_and_fix.sh:10`), `cd` there (`:18`), then run `./decompile_pipe.sh`
(`:19`) — i.e. they work only if a full repo copy (with Ghidra installed
inside) lives in that desktop folder. The four 2024-05-era pipelines use
`basePath="."` (`analyze_binary.sh:9`, `analyze_enhanced_binary.sh:10`,
`analyze_source.sh:9`) and run from the repo root. `analyze_source.sh`
carries a copy-paste wound: it `mv`s the copied source into `outputDir`
(`:32`) and then `rm`s the already-gone path (`:33`).

## 6. `dataset_scripts/` and `helper_scripts/`

`dataset_scripts/` is the (abandoned) evaluation line, documented only by
`dataset_scripts/README.md`. `process_juliet_suite.py` operates **destructively
in place** on a checked-out Juliet suite at a hardcoded relative path
(`base_directory_path = "../Dataset/juliet-test-suite-c-master/testcases"`,
`:49`): it `shutil.rmtree`s every `CWE*` dir whose number isn't in a
22-element keep-list (`:13`–`:22`, list at `:52`), then rewrites every
`.c/.cpp` replacing the suite's `Calling good()/Calling bad()` banner strings
with a neutral `calling routine()` (`:25`–`:30`) — the stated purpose is to
"hide where… we are calling the bad or good function" (`:10`, sic) for blind
testing. `select_from_cwe.py` samples `num_files=5` `-bad` Juliet test-case
pairs plus their `-good` mirrors (`:6`, `:26`–`:32`) into `../
selected_binaries` (`:53`) — which `dataset_scripts/README.md:24` explicitly
positions as input to `analyze_all.sh`. Nothing else in the repo touches
`selected_binaries`.

`helper_scripts/` is three generic tools: `count_cpp_files.py` (counts
`.c/.cpp/.cc/.h`, `:22`), `regroup_subdirs.sh` (moves `substring*` dirs into
a new `substring/` dir, `:37`–`:39`), and `strip_binaries.py` — the only code
in the repo that shells out beyond Ghidra: `subprocess.run(['file', …])` to
classify (`:24`) and `subprocess.run(['strip', …])` to strip every
"executable" (`:37`). Each directory's README documents its own scripts; the
root README names neither directory's files (see §8, §11).

## 7. `results/` — verified vacancy

`results/` contains exactly one file at HEAD: the 29-line `results/README.md`
describing the naming convention (`results/[item_name]/{executable_analysis,
enhanced_executable_analysis,source_analysis}/…`, `:5`–`:29`). NEGATIVE
FINDING: `git log --all --name-status -- 'results/*'` returns only `A
results/README.md` (`8058050`) and `M results/README.md` (`589c2c6`) — **no
analysis artifact was ever committed**, in any commit, on any path under
`results/`. The README's "Preliminary Results" claims (`README.md:21`–`:22`)
have zero supporting artifact in the repository (see also history §6).

## 8. README claims ledger

The 127-content-line README (`README.md`) is structured: Description
(`:3`–`:5`, "LLMs, such as GPT-4", `:5`), Experiment Validating Hypothesis
(`:7`–`:17`: GPT-4 on Juliet-suite binaries, two scan phases `:11`–`:15`),
Preliminary Results (`:19`–`:22`: "outperformed traditional methods across
all evaluated metrics" — with **no numbers, no table, no pointer to data**),
Conclusion (`:24`–`:26`), Capabilities (`:29`–`:34`), Setup Guide (`:36`–`:51`:
(1) install Ghidra 11.0.1 into `Decompiler/` + copy postScripts `:37`–`:48`;
(2) "Change the openai key with you own key in the .env file" `:50`;
(3) "Dataset setup(optional…)" — a single line with no commands and no
pointer to `dataset_scripts/README.md`, `:51`), then "Usage and Script
Descriptions" documenting exactly 9 scripts (`:55`–`:125`), closing with a
one-line pointer to `helper_scripts` (`:127`, "usefull" twice in the same
sentence).

Claim-vs-code ledger:

| README claim | Reality at HEAD |
|---|---|
| drivers use "the OpenAI GPT-4 model" (`:101`, `:108`, `:115`, `:122`; also `:5`, `:9`) | three literals: `gpt-4-turbo` ×3, `gpt-3.5-turbo` ×1, `gpt-4o` ×4 (§4) |
| "high-quality decompiled code **in the user's preferred programming language**" (`:31`) | only `llm_translate.py` can do this, and no pipeline invokes it (§4) |
| "Exploit Script Generation" (`:33`) | real (`analyze_and_exploit.sh`, `llm_pwn.py`) but **undocumented** in this README (§5) |
| "Change the openai key … in the .env file" (`:50`) | no `.env` exists — HEAD commit `c242671` deleted it (§11.1) |
| experiment "quantif[ied] … performance" (`:9`) + "outperformed … across all evaluated metrics" (`:21`) | no eval/scoring script exists anywhere; `results/` empty (§7) — no `eval`, no metric, no corpus build step (NEGATIVE FINDING: `grep -rni 'score\|accuracy\|precision\|evaluat'` over all `*.py`/`*.sh` → **0 hits in the whole repo**, even in code comments) |
| only link in the whole README | Ghidra release page (`:39`) — no dataset link, no paper, no model link (grep `http` battery) |

## 9. Packaging, build, config — the negative-findings battery

Each verified two ways: `git log --all --diff-filter=AD -- <path>` (empty) and
`git ls-files` at HEAD.

| Artifact | Status |
|---|---|
| `LICENSE` | **never in any commit** — repo is unlicensed (`license: null` via GitHub API, 2026-10-31) |
| `requirements.txt` / `Pipfile` / `environment.yml` / any conda lock | **never in any commit** — deps are inferable only from imports (`openai`, `python-dotenv`; stdlib elsewhere; Jython via Ghidra) |
| `setup.py` / `pyproject.toml` / `Makefile` | **never in any commit** |
| `.gitignore` | **never in any commit** — which is exactly how the API key got committed (history §5) |
| tests / CI | no test, no workflow, no CI config in any commit (`git ls-files \| grep -iE 'test\|workflow\|ci'` → nothing) |
| tags / GitHub Releases / PRs | 0 / 0 / 0 (API battery 2026-10-31; history §7) |
| gcc / clang / objdump / nm | **zero call sites** in the whole repo — nothing compiles, links, or disassembles; the only external tooling is Ghidra's `analyzeHeadless` (`Decompiler/gd_decomp*.sh:23`) and `file`/`strip` (`helper_scripts/strip_binaries.py:24`, `:37`) |
| Ghidra version pin | `ghidra_11.0.1_PUBLIC` hardcoded in `gd_decomp.sh:5`, `gd_decomp_large.sh:5`, and `README.md:45` |

## 10. Config & hygiene at HEAD

Runtime config is exactly one environment variable, `OPENAI_API_KEY`, read
via dotenv in 8/8 API scripts (§4). There is no endpoint, base-URL,
organization, or model configuration surface anywhere. The `OPENAI_API_KEY`
literal appears 16 times across the 8 scripts at HEAD (grep battery — twice
per script: the `os.getenv` read and the `OpenAI(api_key=…)` use). The API
key itself is absent from HEAD (`grep -rn 'sk-'` → **0 hits** at `c242671`) but is
fully recoverable from reachable history — `git show 5b25d26:llm_d.py` still
prints the original hardcoded line, and the same 51-character key (shape
`sk-<20 alnum>T3BlbkFJ<20 alnum>`) sits in `5b25d26`'s four scripts and in the
`.env` blob (`620a651`) added by `72c3c11`; equality verified by hashing the
extracted literals inside the clone, never re-emitting the key. Forensic
timeline in the history chapter §5.

## 11. Staleness ledger — what is broken at HEAD as written

Twelve verified breakages in 1,390 lines (the number ch10's anchors cite):

1. **README points at a file HEAD deleted.** Setup step 2 says edit the key
   "in the .env file" (`README.md:50`, wording added by `8eff39b`) — the HEAD
   commit `c242671` ("Delete .env") removed every `.env` and touched nothing
   else.
2. **No exec bits.** `git ls-files -s` → all 30 files mode `100644`; README
   commands say `./analyze_all.sh …` (`:62`, `:71`, `:80`, `:88`, `:97`) and
   the scripts invoke each other the same way (`decompile_pipe.sh:26` →
   `./gd_decomp.sh`, `decompile_large_pipe.sh:26` → `./gd_decomp_large.sh`,
   `analyze_all.sh:28`/`:30` → `./analyze_binary.sh`/`./analyze_enhanced_binary.sh`,
   the four `analyze_*` pipelines → `./decompile_pipe.sh` at `:15`/`:19`) —
   all fail `EACCES` on a fresh clone until chmod.
3. **Undeclared deps + `python` (not `python3`)**: every usage line runs
   `python …`; no manifest says `pip install openai python-dotenv` (§9).
4. **Name-contract mismatch on dotted inputs.** `decompile_pipe.sh:14` keeps
   the *full* basename for `<exe>_decompiled.c` (`:30`), while
   `analyze_*.sh` strip every extension (`cut -f 1 -d '.'`,
   `analyze_binary.sh:11`, `analyze_enhanced_binary.sh:14`,
   `analyze_source.sh:12`, `analyze_and_*.sh:14`) — for `a.out` the pipeline
   produces `a.out_decompiled.c` but the orchestrator's `mv` (`:28`–`:29`)
   and `llm_d.py` call look for `a_decompiled.c`: the chain breaks mid-relay.
5. **Two shipped scripts hardcode `basePath=~/Desktop/sp_new`**
   (`analyze_and_fix.sh:10`, `analyze_and_exploit.sh:10`) and call
   `./decompile_pipe.sh` relative to it (`:19`).
6. **Dead `rm` after `mv`** in `analyze_source.sh:33` (file already moved at
   `:32`) → guaranteed `rm: cannot remove … No such file or directory` on
   every run.
7. **PostScript lookup depends on an out-of-repo copy step**:
   `DECOMPILE_SCRIPT_PATH=.` (`gd_decomp*.sh:6`, used at `:23`
   `-scriptPath`) does not point at `decompilation_scripts/`; it works only
   via the manual `ghidra_scripts` copy (`README.md:45`). The echoed command
   (`:22`) and the run command (`:23`) also differ.
8. **The new CTF pipeline shipped broken and stayed broken 16 hours**:
   `e0db19e` called `llm_ctf_context.py` with 4 positional args (diff visible
   in `git show 51a2c98`), which its 3-arg parser (`llm_ctf_context.py:48`–`:51`)
   rejects; `51a2c98` (next day, 12:23) fixed exactly that line
   (`analyze_and_exploit.sh:44`) — no smoke test caught it.
9. **`llm_ctf_context.py` arg-order footgun**: parser order
   (`enhanced, report, out`, `:49`–`:51`) is the reverse of `main`'s signature
   (`report, enhanced, out`, `:33`); the call site (`:54`) matches `main`, so
   it works today while inviting the next caller to swap two files silently.
10. **Dead marker constants** in `large_code_base_reconstruction.py:8`–`:9`
    (only occurrences; JSON path never emits or parses markers).
11. **Model claims false in the README's own script descriptions** — four
    "GPT-4 model" lines vs `gpt-3.5-turbo`/`gpt-4-turbo`/`gpt-4o` (§4, §8).
12. **Eight runnable scripts are named nowhere in the README**:
    `analyze_and_exploit.sh`, `analyze_and_fix.sh`, `llm_pwn.py`,
    `llm_fix.py`, `llm_ctf_context.py`, `llm_translate.py`,
    `decompile_large_pipe.sh`, `gd_decomp_large.sh` — the entire CTF pivot
    (`e0db19e`) and the large-`.json` twin (`8eff39b`) landed with zero
    root-README documentation (history §6).

## Steal ideas for calxgloss

- **Rolling rename map as prompt state** —
  `large_code_base_reconstruction.py:80` + `:30` threads a growing
  old→new-name map into every subsequent prompt and asks the model to
  rewrite internal calls to match. calxgloss's naming doctrine (never apply
  names; evidence-scored suggestions only, ADR-0020/0021) must not adopt the
  *applying*, but the *consistency* trick is exactly what calxgloss's
  per-attempt prompt context could carry for callees-first queue entries
  without trusting the names.
- **`Confirmed/Potential` split as an honest-unknown analog** —
  `llm_d.py:39`–`:48` asks for certainty-tiered findings, i.e. the right
  instinct (never assert unconfirmed) but with no parsing, no gate, no
  ledger. calxgloss's `UnknownRecord`s + verdict types are the mechanized
  version of the same instinct.
- **Blind-scoring dataset scrubbing** — the good/bad banner scrub
  (`process_juliet_suite.py:25`–`:30`) is directly relevant to calxgloss P33
  (paired ground-truth corpora with truth hidden from the model); theirs
  demonstrates the scrub without ever building scoring, calxgloss should copy
  the scrub and keep the scorer.
- **Cautionary inventory, quantitatively**: 12 verified breakages in 1,390
  lines, zero tests, README drift against its own last commit — this is what
  a repo without any mechanical check becomes in 10 active days; the concrete
  lesson for calxgloss (also CI-less today, P42) is that docs rot against
  code unless something checks them.

## Sources

- Read-only clone `/tmp/opencode/LLM_Decompiler` @ `c2426715340b84a3e2eea4e891fe913a50154f00`
  (26 commits, single branch `main`). Batteries run in-clone and captured to
  `/tmp/opencode/facts2/`: full HEAD content dump with `path:line` prefixes
  (all 30 files, 1,395 lines), per-commit numstat (`num.txt`), name-status
  with rename detection (`ns-m.txt`), mode battery (`git ls-files -s`),
  trailing-newline battery (`tail -c1` per file), model-literal greps at HEAD +
  `5b25d26` + `e0db19e`, dotenv/getenv census, `sk-` pickaxe
  (`git log --all -S 'sk-'`), key-literal sha256 equality across `5b25d26` ×4
  and the `.env` blob, marker-usage grep, toolchain-string grep,
  absent-artifact battery, `results/`-path log battery.
- GitHub REST API via `gh api` (fetched 2026-10-31): repo metadata,
  releases/tags/pulls/branches/contributors — captured to
  `/tmp/opencode/facts2/web.txt`.
- Sibling anchor: [10-calxgloss-baseline.md](10-calxgloss-baseline.md)
  (calxgloss HEAD `40fbf91f`).
