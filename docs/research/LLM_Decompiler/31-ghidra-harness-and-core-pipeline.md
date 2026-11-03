# 31. The Ghidra harness and core pipeline — the decompilation machinery, line by line

> Part of the [LLM_Decompiler overview](README.md). The deep dive on the core path: `Decompiler/gd_decomp*.sh` → Ghidra
> `analyzeHeadless` → the Jython postScripts → `decompile_pipe.sh`/`decompile_large_pipe.sh` → `llm_d.py`. Where ch.20 §3
> inventoried these files, this chapter walks them statement by statement: what each argument does, what lands on disk
> where, and every way the machinery fails silently. All `path:line` re-opened and verified in the read-only clone at
> `/tmp/opencode/LLM_Decompiler`, HEAD `c2426715340b84a3e2eea4e891fe913a50154f00`; verified absences name the battery
> that established them. Claims about Ghidra's *own* semantics (`analyzeHeadless` flag behavior, Jython bindings,
> decompiler timeouts) are marked as such — not checkable inside the clone; end-to-end execution is out of scope (ch.00).
> The large-codebase driver is ch.32; the `analyze_*.sh` variants are ch.33; staleness headlines stay in ch.20 §11.

## 1. Orientation: six files, one cwd contract

The core pipeline is six files: two launchers (`Decompiler/gd_decomp.sh`, `Decompiler/gd_decomp_large.sh`, 24 `wc -l`
each), two postScripts (`Decompiler/decompilation_scripts/decompiler.py` 39, `large_decompiler.py` 24), two
orchestrators (`decompile_pipe.sh`, `decompile_large_pipe.sh`, 35 each; `wc -l` battery). The `Decompiler/` tree tracked
at HEAD is exactly five files — the launchers, the postScripts, and `Decompiler/exec/README.md` — and there is **no
`Decompiler/README`** of any kind (battery: `git ls-tree -r HEAD --name-only Decompiler/` → 5 entries). The only prose
in the harness is one line: "This directory serves as a tmp folder for the decompilation" (`Decompiler/exec/README.md:1`)
— half true: `exec/exe` is written on every run (`decompile_pipe.sh:23`) and **never deleted by anything** (verified
negative: `grep -rn 'rm.*exe' --include='*.sh' .` → 0 hits; the only `exec/exe` references are the `cp` and launcher
call in each pipe, `:23`+`:26`).

Everything runs under an unwritten **cwd contract**. `decompile_pipe.sh` stores the caller's pwd (`:10`), then `cd
./Decompiler` (`:17`) — a *relative* path, so the pipe must run from the repo root, exactly as its callers invoke it
(`analyze_binary.sh:9`,`:15` with `basePath="."`; ch.20 §5). No `cd "$(dirname "$0")"` exists anywhere (verified
negative: `grep -rn 'dirname' --include='*.sh' .` → 0 hits). Inside `Decompiler/`, the launcher's `$GHIDRA_PATH` is
itself relative (`./ghidra_11.0.1_PUBLIC`, `gd_decomp.sh:5`), the Ghidra project is created in `.` (`gd_decomp.sh:23`),
and the postScript opens its output at a bare relative name (`decompiler.py:26`) — so *every* intermediate artifact
lands in `Decompiler/`, and the final `mv` runs from there with relative source and absolute destination
(`decompile_pipe.sh:33`).

## 2. `gd_decomp.sh`: the analyzeHeadless call, argument by argument

The live command is `gd_decomp.sh:23`:

```
time $GHIDRA_PATH/support/analyzeHeadless . tmp_ghidra_project -import $1  -scriptPath $DECOMPILE_SCRIPT_PATH -postscript decompiler.py $2
```

With the variables expanded (`GHIDRA_PATH=./ghidra_11.0.1_PUBLIC` `:5`, `DECOMPILE_SCRIPT_PATH=.` `:6`):

| Argument | Value | Effect (Ghidra semantics unless noted) |
|---|---|---|
| project location | `.` | project lives in `Decompiler/` — creates `tmp_ghidra_project.gpr` + `tmp_ghidra_project.rep/` |
| project name | `tmp_ghidra_project` | the identity the cleanup steps target (§5) |
| `-import $1` | `./exec/exe` from the pipe (`decompile_pipe.sh:26`) | imports *and runs full auto-analysis* on that one file; no `-noanalysis`/`-process`/`-property` flags passed (verified negative: `grep -rn 'noanalysis\|-process\|property' Decompiler/gd_decomp*.sh` → 0 hits) |
| `-scriptPath .` | `Decompiler/` | adds `Decompiler/` to the script search path — where **no `.py` file exists** (postScripts sit in `decompilation_scripts/`, §1) |
| `-postscript decompiler.py` | bare name | runs after analysis of the imported program; `currentProgram` = the freshly imported `exe` |
| `$2` | `/tmp/source.c` (both pipes, `decompile_pipe.sh:26`, `decompile_large_pipe.sh:26`) | passed through as postScript script arguments — consumed by nothing (§3) |

There is **no `-deleteProject`**. The canonical invocation in the file's own comment (`gd_decomp.sh:19`, mirrored in
`gd_decomp_large.sh:19`) *ends with* `-deleteProject`, but the string appears nowhere outside those two comments
(verified negative: `grep -rn 'deleteProject' .` → two comment lines only). So the project is left behind, and each run
instead **pre-cleans** the previous one: `rm -rf *.gpr *.rep` in `Decompiler/` (`gd_decomp.sh:17`, author's own
`(CAREFUL!)` comment at `:16`) plus `find . -name 'tmp*' -exec rm -rf {} +` one level up in the pipe
(`decompile_pipe.sh:20`). Both cleans run *before* Ghidra starts; neither is conditional. Net lifecycle: fresh import
every run (the imported program, named `exe`, is never referenced again), residue (two project files + `exec/exe`) left
after every run, and with no `.gitignore` ever committed (ch.20 §9) that residue is permanent untracked noise — the
author in fact never committed any run artifact (ch.20 §7 battery).

**The echoed-vs-executed discrepancy.** `gd_decomp.sh:21-23`:

```
21  echo "running command:"
22  echo time $GHIDRA_PATH/support/analyzeHeadless . tmp_ghidra_project -import $1  -postscript $DECOMPILE_SCRIPT_PATH/decompiler.py $2
23  time $GHIDRA_PATH/support/analyzeHeadless . tmp_ghidra_project -import $1  -scriptPath $DECOMPILE_SCRIPT_PATH -postscript decompiler.py $2
```

`:22` is a dead documentation line — an `echo` of a *different* command than `:23` runs. It differs twice: it **omits
`-scriptPath`** and **prefixes the script name** (`$DECOMPILE_SCRIPT_PATH/decompiler.py`, expanding to the literal
`./decompiler.py`) where the executed form passes the bare name plus `-scriptPath`. The diff battery (`diff
Decompiler/gd_decomp.sh Decompiler/gd_decomp_large.sh` → only lines 22–23 differ between the twins, each carrying the
same echo/run split) shows the discrepancy is duplicated at birth, not drifted. Reading: `:22` is a fossil of an
earlier invocation shape that addressed the script by path; when the run line moved to `-scriptPath` + bare-name
resolution, the echo was left behind. Its harm is the operator-illusion variant of ch.34's interface drift: the line
printed under "running command:" is copy-paste bait, and the copy-pasted command would address `./decompiler.py` — a
file that does not exist under `Decompiler/` at HEAD (§1 tree). The **executed** form resolves `decompiler.py` from
`-scriptPath .` (no `.py` there) or from Ghidra's install/user `ghidra_scripts` directories (Ghidra semantics) — which
is why the README's setup step "Copy all scripts from `Decompiler/decompilation_scripts` to
`Decompiler/ghidra_11.0.1_PUBLIC/Ghidra/Features/Decompiler/ghidra_scripts`" (`README.md:45`) is load-bearing: the
harness works *only* via an out-of-repo manual copy (ch.20 §11 item 7).

**Preconditions and guards.** The only control flow is the arg guard at `:8` (`if [ "$#" -ne    2 ]`, stray whitespace
in the test) — on failure it prints usage `"$0 <binary path> <output source path>"` (`:10`) and bare-`exit`s (`:11`, no
explicit status, unlike the pipes' `exit 1` at `decompile_pipe.sh:6`). So the launcher demands exactly two positional
arguments: `$1` *must* be a real path to the binary (relative to the cwd at call time — the pipe passes `./exec/exe`),
and `$2` *may be anything*: the usage at `:10` advertises an "output source path", and §3 proves it reaches nothing.
`GHIDRA_PATH` is **not** an environment variable — it is a hardcoded assignment (`:5`) the README tells the operator to
*edit in the file* ("update the GHIDRA_PATH in the Decompiler/gd_decomp.sh script", `README.md:47-48`) — and the README
names only `gd_decomp.sh`; the large twin at `gd_decomp_large.sh:5` is undocumented anywhere (README mentions
`gd_decomp` only at `:48`; ch.20 §11 item 12). Both launchers are mode `100644` like everything else (`git ls-files
-s` battery; ch.20 §11 item 2) yet the pipes invoke them as `./gd_decomp.sh` (`decompile_pipe.sh:26`) — EACCES on a
fresh clone (§8). `decompile_large_pipe.sh` differs from its twin only at `:26` (`./gd_decomp_large.sh ./exec/exe
/tmp/source.c`), `:30` (`output_file="${executable_name}_decompiled.json"`) and `:33` (`mv decompiled_output.json …`)
— the whole large-`.json` variant is a 3-line diff away (battery).

## 3. `decompiler.py`: the postScript inside Ghidra's Jython

`Decompiler/decompilation_scripts/decompiler.py` (40 content lines, 39 `wc -l`) is a **Ghidra script**, not CPython: it
runs inside Ghidra's Jython 2.7 (Ghidra semantics for `.py` postScripts in 11.x) and relies on the injected
`currentProgram` global — used bare at `:15` (`decompinterface.openProgram(currentProgram);` — stray semicolon, a
JS-ism) and `:18`, importing only `DecompInterface` (`:8`) and `ConsoleTaskMonitor` (`:9`). Two consequences, both
verified in-clone:

1. **`sys` is dead.** Battery: `grep -n 'sys\|argv\|args' Decompiler/decompilation_scripts/decompiler.py` → exactly one
   hit, `:7 import sys`. The script touches neither `sys.argv` nor the Ghidra-Jython `args` binding (Ghidra semantics:
   script arguments arrive via injected globals, not `sys.argv`), so the `$2` passthrough (`/tmp/source.c` →
   `gd_decomp.sh:23` → postScript args) **lands nowhere**. The docstring says it all: results go "into
   `decompiled_output.c`" (`:4`) — a hardcoded relative name opened at `:26`, i.e. in the JVM's cwd = `Decompiler/`.
   And `/tmp/source.c` is never created by anything (battery: `grep -rn 'source\.c' --include='*.sh' --include='*.py' .`
   → only the two pass-through lines, `decompile_pipe.sh:26`, `decompile_large_pipe.sh:26`). The "output path" argument
   is theatre across the whole chain.
2. **Function iteration has no selection and no error handling.** `:18` grabs
   `currentProgram.getFunctionManager().getFunctions(True)` — forward iteration over *everything in the program's
   function index* (Ghidra semantics: index order, effectively address order; not entry points, not call graph). No
   `isExternal`/`isThunk`/entrypoint filter exists (verified negative: `grep -n 'isExternal\|isThunk\|EntryPoint\|entrypoint'
   Decompiler/decompilation_scripts/*.py` → 0 hits), so import thunks and analyzer-created fallback bodies get the same
   treatment as real functions, and everything downstream keys on name strings alone. The single decompile call at `:35`
   is `decompinterface.decompileFunction(function, 0, ConsoleTaskMonitor())` — timeout `0` = unlimited (Ghidra
   semantics) — and its result is chained unguarded into the file write: `getDecompiledFunction().getC()` at `:37`.
   Neither postScript ever consults `decompileCompleted`/`isCancelled`/`isError`/`getErrorMessage` (verified negative:
   `grep -rn 'decompileCompleted\|isCancelled\|isError\|getErrorMessage' Decompiler/decompilation_scripts/` → 0 hits).
   A failed function yields a Jython `None`-attribute exception that **aborts the script mid-file** — and because the
   write streams through a `with open(...)` block (`:26`) that closes cleanly on the exception, the result is a
   *truncated but well-formed* `decompiled_output.c` that §5's `mv` and §6's reader treat as complete. That is the
   pipeline's worst failure mode: not no output, but half output.

The on-disk layout is **one flat file**, all functions concatenated, three-part frame per function:

```
----- START OF FUNCTION: <name> -----       (template :21, written :31)
// Function: <name>                         (:32 — a second name echo)
<getC() body — full C including signature>  (:37)
                                            (newline + END marker + \n\n, :40; template :22)
```

The loop materializes the whole function list first (`for function in list(functions)`, `:27`). No address, offset,
section, or call-graph edge ever reaches the file — the join key for everything downstream is the function-name string
inside the marker. That marker pair (`----- START/END OF FUNCTION: {name} -----`) is a home-grown line-based IPC format;
§4/ch.32 record the twist that **its own downstream consumer never parses it** (the marker constants at
`large_code_base_reconstruction.py:8-9` are dead — only occurrences, ch.20 §4).

## 4. `large_decompiler.py` and the seam to the large path (ch.32)

`decompile_large_pipe.sh:26` invokes `gd_decomp_large.sh`, whose `:23` runs the identical `analyzeHeadless` call with
`-postscript large_decompiler.py` (twins differ nowhere else — §2 battery). The postScript (24 lines) does the same
sweep — `openProgram(currentProgram)` `:7`, `getFunctions(True)` `:10`, `decompileFunction(function, 0,
ConsoleTaskMonitor())` `:14` — but builds JSON records instead of streaming text: `{"name": …, "signature":
function.getSignature().getPrototypeString(), "body": …getC()}` (`:15-19`), dumped `indent=2` to a hardcoded relative
`decompiled_output.json` (`:23-24`) — again in `Decompiler/`. Note the redundancy the `.c` path avoids: `getC()`
(`:18`) already contains the signature line, yet the signature is stored a second time via `getPrototypeString()`
(`:17`, the only such call in the repo — battery). Unlike `decompiler.py`, this script builds the whole `function_list`
in memory before one write — so a decompile failure on function *k* loses **all** output on this path, while on the `.c`
path it silently truncates (§3). Neither behavior is checked; both are accident.

Who wires this path? **No one, verified**: `decompile_large_pipe.sh` has no caller anywhere (`grep -rn
'decompile_large_pipe' --include='*.sh' --include='*.py' .` → 0 hits), and neither has
`large_code_base_reconstruction.py` (only hits: its own usage string at `:95` and `README.md:104`). So the `.json` path
is a **manual two-command flow** that the README wires halfway: it documents the consumer (`README.md:99-104`: "Execute
the script by providing the path to a JSON file containing decompiled function data" → `python
large_code_base_reconstruction.py path_to_decompiled_output_json`) but never names the producer that creates such JSON
— `decompile_large_pipe.sh`, `gd_decomp_large.sh`, `large_decompiler.py` together get zero README mentions (README's
only `gd_decomp` hit is the path-edit note `:48`). `<exe-name>_decompiled.json` (`decompile_large_pipe.sh:30`) has no
scripted consumer at all (battery: `grep -rn '_decompiled\.json' --include='*.py' --include='*.sh' .` → only its
producer line). Which stage invokes which script is exactly the seam ch.32 picks up; the ledger here: `.c` path =
scripted end-to-end up to the prompt driver, `.json` path = two disconnected manual commands.

## 5. `decompile_pipe.sh`: orchestration, stage by stage

The 35-line orchestrator (3 lines' diff from `decompile_large_pipe.sh`, §2) runs, in the `Decompiler/` frame:

1. **Guard** `:4-7` — exactly one arg or `exit 1` (the only nonzero-exit decision in the file).
2. **Name capture** `:10-14` — `original_dir=$(pwd)`; `executable_path=$(realpath "$1")` (GNU coreutils dependency,
   undeclared like everything else, ch.20 §9); `executable_name=$(basename "$executable_path")` at `:14` — **full
   basename, extension kept**. This is the load-bearing line of the ch.20 §11 item 4 relay mismatch: for `a.out` the
   pipe emits `a.out_decompiled.c` (`:30`) while `analyze_binary.sh:11` strips at the first dot (`basename … | cut -f 1
   -d '.'` → `a`) and then looks for `a_decompiled.c` at its `llm_d.py` call (`:20`) and its `mv` (`:28`). Verified
   side-by-side at `decompile_pipe.sh:14` vs `analyze_binary.sh:11` — the two halves of one chain compute the artifact
   name with different string algebra, agreeing only for dotless names (like the internal `exe`).
3. **cd + clean** `:17-20` — into `Decompiler/`, wipe every `tmp*` (leftover Ghidra project, §2).
4. **Stage the binary** `:23` — `cp "$executable_path" ./exec/exe`: Ghidra never opens the original directly; the
   rename normalizes the program-name field (spaces, extensions, anything). Never removed (§1).
5. **Ghidra** `:26` — `./gd_decomp.sh ./exec/exe /tmp/source.c` (§2).
6. **Relay** `:29-33` — `mv decompiled_output.c "$original_dir/${executable_name}_decompiled.c"`, still run from
   `Decompiler/` (no cd-back exists).
7. **Banner** `:35` — "Decompilation finished. Output saved to …".

**Failure discipline is zero.** No `set -e`, no `&&`, no `$?` test; the only conditionals are the arg guards — battery:
`grep -n 'set -e\|set -o\|&&\|\$?\|if ' decompile_pipe.sh decompile_large_pipe.sh Decompiler/gd_decomp.sh` returns only
`decompile_pipe.sh:4`, `decompile_large_pipe.sh:4`, `gd_decomp.sh:8`. Consequences: a non-executable `gd_decomp.sh`
(fresh clone) fails EACCES and the pipe *continues*; the missing-postscript case (§2) still imports and analyzes but
writes no output; §3's mid-file abort leaves a partial file that passes; and in *all* of these cases `mv` (`:33`) spits
"No such file or directory" to stderr and the script **still prints its success banner at `:35`** and exits 0 —
because `echo` is unconditional. Callers inherit the lie: `analyze_binary.sh:15-16` runs the pipe then unconditionally
echoes "Decompilation completed." and feeds `"${executable_name}_decompiled.c"` to `llm_d.py` (`:20`), which at least
checks existence (`llm_d.py:21-26`: "File does not exist." + bare `exit()`) — so the chain dies at the *LLM* stage with
a one-line message, never at the decompile stage. Neither pipe ever calls `python` (verified negative: `grep -n
'python' decompile_pipe.sh decompile_large_pipe.sh Decompiler/gd_decomp.sh Decompiler/gd_decomp_large.sh` → 0 hits):
the Ghidra half of the repo is dependency-free apart from Ghidra itself.

## 6. `llm_d.py`: the whole-file prompt driver

`llm_d.py` (64 lines) is the `.c` path's only LLM stage, and it runs in plain CPython (not Ghidra): arg guard `:7-9`,
`filename = sys.argv[1]` `:11`, the dotenv preamble `:13-15` (the 8/8-identical pattern, ch.20 §4), output name
`f"{os.path.splitext(filename)[0]}_vulnerabilities.txt"` `:18` — a **side-by-side new file**; the original is never
rewritten or read back. It reads the *entire* input into one string (`:21-23`, `code = file.read()`) with no size
check, chunking, or context arithmetic, and embeds it verbatim mid-prompt (`:44`). The prompt, verbatim (`:29-49`;
`{code}` interpolates at `:44`):

```text
As a highly skilled static code analyzer for C code, you're tasked with examining the provided decompiled source code, originally written in C. The code has potentially gone through multiple rounds of filtering and reconstruction to enhance context awareness, as the original executable was stripped.

Please perform a thorough analysis, taking into account that some artifacts may be introduced by the enhancements from another language model. Ignore any vulnerabilities that seem to arise due to these enhancements and filtering processes.

Your analysis should only include vulnerabilities that you can confirm with certainty. Any uncertain or potential vulnerabilities should be cataloged separately.
Act such that false negative is much much better than false positives, ie really avoid annoncing any vulnerability unless it is 100% confirmed
you are not expected to always annonce the presence of vulnerabilities, you will encounter situations where you are given the code of a bug after it was fixed, be conservatif and only annonce when it is obivious the presence of the bug


Output Format:
- Confirmed Vulnerabilities: List each confirmed vulnerability along with the line number where it occurs.
- Potential Vulnerabilities: List each potential or doubtful vulnerability along with the line number, separated from the confirmed issues.

Source Code:
{code}

Provide the results as follows:
Confirmed_vulnerabilities : list
Potential_vulnerabilities : list
```

Prose notes. `:30` encodes the tool's theory of itself — stripped binaries, "multiple rounds of filtering and
reconstruction" (the `llm_f`→`llm_r`→`llm_d` relay; the enhanced chain passes
`${executable_name}_decompiled_filtered_enhanced.c`, `analyze_enhanced_binary.sh:34`, ch.20 §5) — and `:32` is the one
genuinely thoughtful sentence in the repo: *the analyzer is told upstream artifacts may be other models' rewrites and
instructed not to report them as vulnerabilities*. `:35` is the certainty doctrine ("false negative is much much better
than false positives … unless it is 100% confirmed"; `annoncing`/`annonce`/`conservatif`/`obivious` are the prompt's own
typos, verbatim); `:36` pre-legitimizes the null answer ("you will encounter situations where you are given the code of
a bug after it was fixed"). The output contract is specified **twice** — prose with line numbers (`:39-41`) and a
machine-shaped tail (`:46-48`) — and parsed **zero times** (battery: `grep -rn
'Confirmed_vulnerabilities\|Potential_vulnerabilities' .` → the two prompt lines `:47`/`:48` only). The requested "line
number" anchors (`:40-41`) index §3's concatenated marker file — an offset nothing computes or validates.

The call (`:51-56`): `model="gpt-4-turbo"` (`:52`, per ch.20 §4's per-file model ledger — the README's "the OpenAI
GPT-4 model" at `README.md:108` is one of its four false model claims, ch.20 §8); the message list is a **single
`system`-role message**, no `user` turn (`:53-55`). No `temperature`, no `max_tokens`, no `stream`, no `try/except`, no
retry anywhere in `llm_d.py` — and no sampling parameter in any Python file in the repo (batteries: `grep -n
'temperature\|max_tokens\|stream\|retry\|try:\|except' llm_d.py` → 0 hits; `grep -rln 'temperature\|max_tokens'
--include='*.py' .` → 0 files). Response handling is maximalist-blind: `response.choices[0].message.content` (`:58`)
with no `finish_reason` check and no token-`usage` accounting (battery: `grep -n 'finish_reason\|usage\|token' llm_d.py`
→ 0 hits) — a length-truncated report is written indistinguishably from a complete one. The raw text goes to
`<stem>_vulnerabilities.txt` (`:61-62`), path printed (`:64`). The file is terminal: no script reads
`*_vulnerabilities.txt` (its only other appearances are the orchestrators' `mv`s, e.g. `analyze_binary.sh:29`). And no
stage of the whole `.c` pipeline ever compiles anything — `gcc`/`clang`/`ld`/`objdump` have **zero call sites
repo-wide** (battery, ch.20 §9), so the decompiled C is compile-checked neither at birth nor after any "enhancement".

The scale question the repo never confronts: one request carries the *entire* whole-binary pseudocode (`:44`);
`gpt-4-turbo`'s window is a hosted-OpenAI fact (not verifiable in-clone), but `results/` holds no artifact of any run
(ch.20 §7) suggesting it was ever tested at full-binary size. The `.json` per-function loop (ch.32) exists precisely
because whole-file prompts do not scale — and it is the path nothing scripts end-to-end (§4).

## 7. The pipeline as a whole vs calxgloss's eight stages

The `.c` path reduced: `cp ▸ analyzeHeadless ▸ postScript ▸ mv ▸ read-whole-file ▸ one system prompt ▸ write-prose`.
Against calxgloss's per-unit loop `read cache ▸ evidence warmup ▸ fetch ▸ prompt ▸ translate ▸ verify ▸ retry ▸ commit`
(`docs/data_flow.md` §3.2.2; calxgloss HEAD `40fbf91f`, per the [baseline](10-calxgloss-baseline.md)):

| Stage | LLM_Decompiler (verified) | calxgloss |
|---|---|---|
| Read / re-acquire the binary view | none — every run re-copies and re-imports (`decompile_pipe.sh:23`), previous Ghidra project pre-deleted (`:20`) | in-process analysis seam with read cache; Kuna-only (ADR-0039/0040/0041, ADR-0054/0055) |
| Evidence warmup | Ghidra auto-analysis only — not even disableable (§2); nothing persisted: the `.c` dump *is* the evidence, disposable, regenerated per run | 15 scan rows with registry + coverage records (`calxgloss-translator/src/pipeline/scan_phase.rs:273`, `scan_registry.rs:606`; ADR-0052/0053) |
| Fetch / order units | flat forward iteration of the function index (`decompiler.py:18`); no dependency notion anywhere (§3) | call-graph-topological queue, callees first (`calxgloss-analysis/src/callgraph.rs:964-1032`, `calxgloss-web/.../handlers/queue.rs:450-491`) |
| Prompt build | one f-string per input file, single `system` role (`llm_d.py:29-56`) | askama `.j2` templates, evidence bundle as sole render input (ADR-0048/0049), 5-tier ladder (`calxgloss-types/src/context_tier.rs:59-84`) |
| Translate / analyze | one shot, whole file, no size logic (§6) | per unit of work `{binary}/{function}` off the queue |
| Verify | **absent, verified** — no compiler call site repo-wide (ch.20 §9); output never re-read; `finish_reason` ignored (`llm_d.py:58`) | compile + behavioral + trace gates every attempt (ADR-0057; `calxgloss-testgen`, `calxgloss-verify/tests/api_trace_verdict.rs`) |
| Retry | **absent, verified** — 0 `try:`/`except`/retry hits in `llm_d.py` (§6 battery); failure = crash or one-line message (`llm_d.py:25`) | attempt seam ADR-0051 (`retry/attempt.rs:229`), strategy catalog `docs/data_flow.md` §8 |
| Commit / state | files + `mv` into `results/<name>/…` (`analyze_binary.sh:24-29`); success banner unconditional (`decompile_pipe.sh:35`); no git use in the pipeline | per-attempt branches `re/{binary}/{function}v{N}` (`calxgloss-git/src/lib.rs:4-5`), named `UnknownRecord`s (ADR-0056) |

The one structural *similarity* worth naming: both pipelines are whole-binary in scope and per-function in granularity
— the `.c` dump carries one entry per function (`decompiler.py:27`) like calxgloss's unit key — but here the unit
boundary exists **only inside one flat text file**, and the only stage that could consume it (`large_code_base_reconstruction.py`)
bypasses the `.c` path entirely (§4). "Same granularity" is coincidental: the ordering, the identity key (name string
vs `(dll, function, attempt)`), and the verification envelope are all structurally absent.

## 8. Runnability today — an operator's ledger, pipeline angle

Consistent with ch.20 §11 (12 breakages overall) but specific to this path; "blocked" names the checked condition that
fails:

| Step | Status at HEAD | Condition |
|---|---|---|
| `./decompile_pipe.sh bin` | **blocked** | mode `100644` (§2 battery) → EACCES; `bash decompile_pipe.sh` works around |
| cwd | **fragile** | repo root required — relative `cd ./Decompiler` (`:17`), relative `./gd_decomp.sh` (`:26`), no script-dir resolution (§1) |
| Ghidra present | **manual, pinned** | ghidra_11.0.1 unzipped *inside* `Decompiler/` (`README.md:39-42`); dir name hardcoded at `gd_decomp.sh:5` **and** `gd_decomp_large.sh:5`; the version-edit note names only the `.c` twin (`README.md:47-48`) |
| postScript resolvable | **manual, out-of-repo** | required copy into `Ghidra/Features/Decompiler/ghidra_scripts` (`README.md:45`); `-scriptPath .` finds nothing in the repo tree (§1/§2) |
| Ghidra itself | **runs (given the above)** | flag grammar of `analyzeHeadless` 11.x assumed; full auto-analysis on import by default (§2) |
| Ghidra → pipe handoff | **silent-fail by construction** | no exit-code checks (§5); partial-output hazard (§3); success banner always prints (`:35`) |
| `.env` with the key | **absent** | no `.env`/`.gitignore` tracked at HEAD (battery: `git ls-files \| grep -i 'env\|gitignore'` → 0 hits); `README.md:50` still orders the operator to edit that nonexistent file (ch.20 §11 item 1); the leaked historical key is 2024-era, its revocation unknowable from the repo (ch.21 §5) — a fresh paid key is required either way |
| `python llm_d.py …` | **blocked on deps** | `openai`/`python-dotenv` undeclared (ch.20 §9); `python` must be py3 for the f-string (`llm_d.py:18`) |
| `llm_d.py` on a real binary | **unbounded** | whole-file embed, no size logic (§6); whether a given binary fits is an OpenAI-window question the repo never tested — `results/` holds no artifact to say it ever ran (ch.20 §7) |
| Artifact relay to callers | **name-fragile** | dot-in-name inputs break the `mv`/call names (`decompile_pipe.sh:14` vs `analyze_binary.sh:11`, §5 step 2) |
| Post-run tree hygiene | **dirty** | `exec/exe` + `tmp_ghidra_project.{gpr,rep}` persist after every run (§2, §5); no `.gitignore` |

The pipeline is *conceptually* runnable with effort (chmod, Ghidra 11.0.1, the scripts copy, a live key, dotless filenames, a small binary) and *mechanically* silent when any of it is wrong — the operator learns of failures only from stderr noise between two success banners.

## Steal ideas for calxgloss

- **Provenance admission in the *consuming* prompt** (`llm_d.py:32`). The one sentence worth stealing: the analyzer is
  told the input may contain another model's rewrites and must not report rewrite artifacts as findings. calxgloss
  renders structural provenance (admission lines ADR-0048/0049; coverage stamps ADR-0053), but the retry strategies
  (`docs/data_flow.md` §8) re-feed model-authored failing code into the next prompt — a "this code is prior model
  output" admission rendered *on the artifact itself* is the mechanized version of that sentence. Steal the instinct;
  render it, never instruct for it.
- **A prompt output contract with no typed reader is dead weight, twice over** (`llm_d.py:46-48` unparsed — §6 battery;
  `decompiler.py:21-22` markers emitted but never parsed while their declared constants sit dead at
  `large_code_base_reconstruction.py:8-9`, ch.20 §4 item 10). Lesson: every prompt convention needs a reader (verdict
  type, `UnknownRecord` kind) **and** every emitted artifact format a consumer test pinning it; otherwise it is a
  phantom interface.
- **The fixed-bug instruction** (`llm_d.py:36`: "you will encounter situations where you are given the code of a bug
  after it was fixed … only annonce when it is obivious"). Legitimizing the null answer in prompt prose is a one-line
  idea calxgloss has mechanized (unknowns, never-pass-unassessed, ADR-0056/0057) but not verbalized — translate
  templates (`translate.j2`) always presuppose a translatable unit. Cheap candidate: an explicit "if nothing can be
  said with the given evidence, say so" clause in the minimal-tier prompt, routed to the existing unknown-record path.
- **Certainty prose without a gate is theatre** (anti-pattern): `llm_d.py:35` demands 100%-confirmed findings,
  `README.md:108` advertises "minimizing false positives", and nothing measures a single false positive or negative
  (eval-string battery, ch.20 §8). For P33: honesty claims must live in the *scorer*, not the prompt.
- **Unconditional terminal banners** (`decompile_pipe.sh:35` prints success even when every stage failed, §5) are the
  calibration bug calxgloss's fail-loud `doctor` posture (`README.md:130-134`, per baseline) prevents; a P42 smoke job
  should assert *artifact existence*, not just exit 0 of the last command.
- **Anti-pattern, never crib: line-number anchoring in prose output** (`llm_d.py:40-41`) — offsets into a concatenated
  dump are unvalidated and unstable; calxgloss keys on `(dll, function, attempt)` + RVA/FUN-name identity and should
  keep it that way.

## Sources

- Read-only clone `/tmp/opencode/LLM_Decompiler` @ `c2426715340b84a3e2eea4e891fe913a50154f00` (`git rev-parse HEAD`
  verified, clean worktree, 2026-10-31). Files re-opened whole: `Decompiler/gd_decomp.sh:5,6,8,10,11,14,16,17,19,21,22,23`;
  `Decompiler/gd_decomp_large.sh:5,19,22,23`; `Decompiler/decompilation_scripts/decompiler.py:4,7,8,9,15,18,21,22,26,27,31,32,35,37,40`;
  `Decompiler/decompilation_scripts/large_decompiler.py:7,10,14,15-19,23,24`; `Decompiler/exec/README.md:1`;
  `decompile_pipe.sh:4,6,10,13,14,17,20,23,26,29,30,33,35`; `decompile_large_pipe.sh:23,26,30,33`;
  `llm_d.py:7-11,13-15,18,21-26,29-56,58,61-64`; `analyze_binary.sh:9,11,15,16,20,24,28,29`;
  `analyze_enhanced_binary.sh:34`; `README.md:39,42,45,47,48,50,90,97,99-104,108`.
- Batteries run in-clone (used inline where cited): `git ls-tree -r HEAD Decompiler/` (5 files, no Decompiler README);
  `git ls-files -s` (modes `100644` ×7 harness files); `diff` of both twin pairs (only `:22-23` / `:26,:30,:33` differ);
  grep negatives — `sys|argv|args` in `decompiler.py` (1 hit `:7`); `decompileCompleted|isCancelled|isError|getErrorMessage`
  (0); `deleteProject` (2 comment lines); `source\.c` (2 pass-through lines); `dirname` (0);
  `isExternal|isThunk|EntryPoint` (0); `set -e|set -o|&&|$?|if` in the three scripts (3 guard lines only); `python` in
  pipes/launchers (0); `temperature|max_tokens|stream|retry|try:|except` in `llm_d.py` (0) and `temperature|max_tokens`
  across `*.py` (0 files); `finish_reason|usage|token` in `llm_d.py` (0);
  `Confirmed_vulnerabilities|Potential_vulnerabilities` repo-wide (the 2 prompt lines); `decompiled_output*` /
  `_decompiled.json` producer-consumer map; callers of `decompile_large_pipe`/`gd_decomp_large`/
  `large_code_base_reconstruction` (0 script callers); `llm_d` call sites (5 orchestrators); `exec/exe` (4) vs
  `rm.*exe` (0); `env|gitignore` in `git ls-files` (0); `wc -l` harness battery.
- Ghidra-API semantics (flag meanings, Jython `currentProgram`/`args` bindings, `getFunctions(True)` order, timeout-0,
  auto-analysis-on-import, `getC()` shape) marked inline as not verifiable in-clone; end-to-end execution out of scope
  per ch.00.
- Cross-references: [20-llm-decompiler-inventory.md](20-llm-decompiler-inventory.md) §3, §4 (model ledger), §9,
  §11 items 2/4/7; [21-history-and-releases.md](21-history-and-releases.md) §2 rows 3–4, 18 (births of
  `decompiler.py`, `gd_decomp.sh`, the large trio); [32-large-codebase-reconstruction.md](32-large-codebase-reconstruction.md),
  [33-security-ctf-and-datasets.md](33-security-ctf-and-datasets.md),
  [34-results-effectiveness-and-hygiene.md](34-results-effectiveness-and-hygiene.md) (planned);
  [10-calxgloss-baseline.md](10-calxgloss-baseline.md) at calxgloss HEAD `40fbf91f` (all stage-table cites).
