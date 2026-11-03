# 32. Large-codebase reconstruction — the `.json` path and the name-map context model, line by line

> Part of the [LLM_Decompiler overview](README.md). Deep dive on the "Support for large source code base"
> line (commit `8eff39b`, 2024-05-09 17:07): `large_decompiler.py` → `decompiled_output.json` →
> `large_code_base_reconstruction.py`, plus the `helper_scripts/` trio. Ch.31 walked the `.c` path — the
> `gd_decomp*.sh` mechanics and the cwd contract are *referenced*, not re-derived. Added here: the `.json`
> postScript diff, the reconstruction loop line by line, a whole-repo context ledger, and runnability at
> HEAD. All `path:line` re-opened and verified in the read-only clone `/tmp/opencode/LLM_Decompiler` at
> HEAD `c2426715340b84a3e2eea4e891fe913a50154f00`; verified absences name the battery. Hosted-model
> semantics are marked external; end-to-end execution is out of scope (ch.00).

## 1. Orientation: what "large" means, and the inverted birth order

The large path is the `.json` twin of the core pipeline: the same Ghidra sweep, per-function JSON records
instead of a marked flat `.c`, and — the payload — a per-function LLM loop with a rolling rename map.
"Large" buys **per-function granularity and nothing else**: no chunking, no context budget, no module
decomposition, no function selection, no parallelism — the whole answer to "big project" is "one API call
per function instead of one per file".

The origin story inverts the commit message. `8eff39b` "Support for large source code base" adds the
producer trio (`large_decompiler.py` 24 `wc -l`, `gd_decomp_large.sh` 24, `decompile_large_pipe.sh` 35),
deletes two debug prints from `large_code_base_reconstruction.py`, and appends "in the .env file" to README
setup step 2. But the *consumer* it feeds (97 content lines, no trailing newline — `tail -c1` = `)`) was
born two days earlier in the big-bang `5b25d26` (battery: `git log --oneline --
large_code_base_reconstruction.py` → `5b25d26`, `72c3c11` dotenv-only, `8eff39b` −2). At `5b25d26` it
*already* read the JSON array of `{name, signature, body}`, *already* carried the map-prompt machinery
(`git show 5b25d26:… | grep -c 'Current Name Map\|json.dumps(name_map'` → 2), and *already* declared the
dead marker constants — and no repo file produced that JSON until `8eff39b`: the phase is **"retrofit a
producer for a consumer that shipped first"**, the author's local flow predating the committed one.

| File | `wc -l` | Born | Role |
|---|---:|---|---|
| `Decompiler/decompilation_scripts/large_decompiler.py` | 24 | `8eff39b` | postScript → `decompiled_output.json` |
| `Decompiler/gd_decomp_large.sh` | 24 | `8eff39b` | analyzeHeadless launcher (ch.31 §2 twin) |
| `decompile_large_pipe.sh` | 35 | `8eff39b` | orchestrator → `<exe>_decompiled.json` |
| `large_code_base_reconstruction.py` | 96 | `5b25d26` | the per-function GPT-3.5 loop with rolling `name_map` |
| `helper_scripts/{strip_binaries 46, regroup_subdirs 41, count_cpp_files 35}` | 122 | `49df012` | batch "support" tools, zero scripted callers (§5) |

The helpers predate even the consumer and nothing ever invokes them (§5 battery) — git's "support for large
code bases" is three unconnected files and one 97-line script.

## 2. `large_decompiler.py`: the JSON postScript and its diff ledger

Format verified at `Decompiler/decompilation_scripts/large_decompiler.py:15-19`: `"name":
function.getName()` (`:16`), `"signature": function.getSignature().getPrototypeString()` (`:17`), `"body":
decompiled_function.getDecompiledFunction().getC()` (`:18`). Top level is a **JSON array**: records appended
to `function_list` (`:11`, `:20`), one `json.dump(function_list, output_file, indent=2)` (`:23-24`) to the
hardcoded relative `decompiled_output.json` — JVM cwd = `Decompiler/` (ch.31 §1 contract). The shape is
load-bearing, never asserted: the reader iterates `json.load` output directly
(`large_code_base_reconstruction.py:78`, `:83-84`). The signature is **stored twice per record** — `getC()`
(`:18`) already begins with the signature line (Ghidra semantics; ch.31 §3/§4), `getPrototypeString()`
(`:17`) restates it (the repo's only such call, ch.31 §4 battery) — and the reader uses *both* copies
(prompt `:24`+`:27`, output `:85`): every prompt and output block carries the prototype twice.

The diff against `decompiler.py` (battery: `diff -u` of the twins), as a ledger:

| Aspect | `decompiler.py` | `large_decompiler.py` | Delta |
|---|---|---|---|
| docstring | `:1-5` promises `decompiled_output.c` | **deleted** | the only prose in either twin lies, and only in the `.c` one |
| imports | `import sys` (`:7`, dead — ch.31 §3) | `import json` (`:1`, used `:24`) | dead-import twin → used-import twin |
| interface var | `decompinterface`, stray `;` (`:7`, `:15`) | `decompInterface`, semicolon fixed (`:6-7`) | cosmetic |
| function sweep | `getFunctions(True)` (`:18`), `list(functions)` (`:27`) | `getFunctions(True)` (`:10`), raw iterator (`:13`) | same unfiltered sweep incl. thunks/fallbacks (ch.31 §3) |
| markers | emits `----- START/END OF FUNCTION: {name} -----` (`:21-22`,`:31`,`:40`) | **no markers** | the format named by the consumer's dead constants (`:8-9`) exists only on the `.c` path |
| write discipline | streaming inside the loop (`:26-40`) | in-memory list, one dump after (`:23-24`) | failure on function *k*: `.c` **truncates silently**, `.json` **loses everything** (ch.31 §4) — both unchecked |
| decompile call | `decompileFunction(function, 0, ConsoleTaskMonitor())` (`:35`) | identical (`:14`) | timeout `0`, no completion check either (ch.31 §3 battery) |
| name echo | `// Function: <name>` comment (`:32`) | `"name"` key (`:16`) | the join key moves from comment to typed JSON |

Who consumes the JSON: **exactly one script, wired by hand.** Battery — `grep -rn
'decompiled_output\.json\|_decompiled\.json' --include='*.py' --include='*.sh' --include='*.md' .` → three
hits: producer `:23`, relay `decompile_large_pipe.sh:30`+`:33`; the consumer opens whatever `sys.argv[1]`
names (`:77-78`; usage `:95`) and nothing ever passes it — the producer→consumer hop is operator typing.

## 3. `decompile_large_pipe.sh`: three lines' difference, and where the JSON lands

`diff -u decompile_pipe.sh decompile_large_pipe.sh` → **exactly three changed lines**: `:26`
(`./gd_decomp_large.sh ./exec/exe /tmp/source.c`), `:30` (`output_file="${executable_name}_decompiled.json"`),
`:33` (`mv decompiled_output.json …`); the launcher twin `gd_decomp_large.sh` vs `gd_decomp.sh` differs only
at `:22-23` (postScript name + output `.c`→`.json`). Everything else inherits ch.31 §5 verbatim: arg guard
(`:4-7`), `original_dir=$(pwd)` (`:10`), full-basename algebra (`:13-14`, dotted-name hazard, ch.20 §11
item 4), relative `cd ./Decompiler` (`:17`), unconditional `tmp*` pre-clean (`:20`), binary staged to
`./exec/exe` (`:23`), zero failure discipline, unconditional success banner (`:35`).

Artifact geography: `decompiled_output.json` is born in `Decompiler/` and `mv`'d to the caller's original
cwd as `<full basename>_decompiled.json` (`:33`) — and stops. No `python` call exists in either pipe
(ch.31 §5 battery), and `decompile_large_pipe.sh` has **no caller anywhere** (battery: `grep -rn
'decompile_large_pipe' --include='*.sh' --include='*.py' --include='*.md' .` → 0 hits). Structured as it
is, the JSON never meets the scripted consumers: `analyze_*.sh` only speak the `.c` relay names (ch.20 §5).

## 4. `large_code_base_reconstruction.py`: the centerpiece, control flow

**Entry, load, loop.** `__main__` guard `:93-97` (usage literally `python script.py
<path_to_decompiled_output_json>`); existence check `:73-75` (`sys.exit(1)`); `json.load` `:77-78`. **No
schema validation** — and the prompt f-string interpolates `function_data['signature']`/`['body']` (`:24`,
`:27`) *before* the `try:` at `:47`, so a malformed record raises an uncaught `KeyError`/`TypeError` that
kills the run mid-loop, `enhanced_code_blocks` (`:81`, written only at `:88-89`) taking every
already-paid-for enhancement with it. The loop `:83-84` runs in the producer's Ghidra order (address order,
ch.31 §3), one paid call per record *including* thunks and analyzer fallback bodies — no selection or
ordering anywhere in the reader.

**The prompt** (f-string `:17-45`, verbatim; the 4-space source indentation rides onto the wire):

```text
    Enhance the readability and maintainability of this C function(the result of decompiling a stripped binary) by adding comments and renaming variables and functions to be more descriptive. Your task includes two main parts:

    1. Analyze the provided C function code for readability improvements.
    2. Update any internal function calls using the provided name map to ensure all references are consistent with previously enhanced functions.

    Function Signature:
    {function_data['signature']}

    Original Function Code:
    {function_data['body']}

    Current Name Map for Reference (Use this to update internal function calls):
    {json.dumps(name_map, indent=2)}

    Instructions:
    - If the function contains calls to other functions that appear in the name map, replace these calls with the new names from the map.
    - Decide on a new descriptive name for the function you're currently enhancing, if necessary. Add this new name as a key-value pair in your response.
    - Avoid renaming or modifying standard library functions or their calls; focus only on user-defined functions and logic.
    - Ensure your response strictly follows the below format, containing only the necessary structured information with no additional comments or verbose explanations.

    Expected Response Format:
    new_map_pair: old_function_name : new_descriptive_function_name
    enhanced_code:
    // New Function Signature: [optional if changed]
    [Enhanced code here]

    Note: Ensure that the enhanced code does not change the core logic or behavior of the original code. The goal is to improve code clarity and maintainability without altering functionality.
```

Interpolations: signature `:24`, whole body `:27`, the whole map as JSON `:29-30`; response contract three
lines (`:39-42`), enforced only by the `lines[0]` parse below; prompt bytes byte-identical to `5b25d26`
(`72c3c11`/`8eff39b` touched only the preamble and the prints). The call (`:48-51`) uses
`model="gpt-3.5-turbo"` (`:49`), flatly against the README calling *this* script a GPT-4 user
(`README.md:101`; ch.20 §4/§8); single `system`-role message (`:50`); no sampling params, no length
control, no metadata (budget battery below).

**Parse and map update.** `:55-57`: `lines = output_text.split('\n')`; line 1 is the contract's map pair,
`enhanced_code = '\n'.join(lines[1:])` is *everything else* — "Assuming all lines after the first are code"
is the author's comment (`:57`). The pair parses only if line 1 starts with `"new_map_pair: "` (`:60-61`),
`split(' : ')` unpacks `old_name, new_name` (`:63`), `name_map.update(...)` (`:64`). Consequences:

- **`name_map` is one shared mutable dict** — created `:80`, passed by reference `:84`, mutated in the
  callee `:64`: the repo's entire cross-function state, alive for one run only.
- **Nothing validates the pair** — no `old_name == function_data['name']` anywhere (validation battery:
  `grep -n '==\|if \|assert\|valid' large_code_base_reconstruction.py` → arg guards, the `startswith`
  guard, prose only). A pair for a callee, a past function, or an invented name is accepted verbatim.
  **Collisions are silent**: `dict.update` is last-write-wins on a re-emitted `old_name`, and two functions
  picking the *same* new name both enter, so later prompts see two distinct functions under one token,
  undetected — no symbol table, no set (same battery).
- **A malformed pair discards a good response**: prefix present but no `' : '` on line 1 → `ValueError`
  *inside* the try (`:63`) → blanket except (`:68`) → the whole `enhanced_code` is thrown away and the
  original body emitted. A cosmetic slip costs the entire enhancement.
- **A missing pair is not an error** (`:61` guard — the prompt says rename "if necessary", `:34`). And an
  *empty* `content` parses fine (`''.split('\n') == ['']`), returning `enhanced_code = ''` (`:55-57`,
  `:66`) — an **empty block** in the output. `finish_reason` is never checked (`grep -n 'finish_reason'
  large_code_base_reconstruction.py` → 0 hits, as in `llm_d.py`, ch.31 §6): zero-content or truncated
  responses are indistinguishable from success.

**The silent except → original-body path** (`:68-70`, verified exactly): `except Exception as e` prints one
line (`Error during API call or processing: …`) and `return function_data['body']` — author's comment
"Fallback to original body in case of failure". It catches *everything*: API errors, rate limits,
context-overflow errors (hosted-OpenAI semantics, external), and the parse failures above. The only signal
is that stdout line — no counter, no log — and the final banner `Enhanced code saved to …` (`:91`) prints
identically whether zero or all functions failed: a 100% pass-through run reports full success.

**`name_map` propagation and its structural limits.** The map rides into every later prompt as
`json.dumps(name_map, indent=2)` (`:30`); instructions `:21`/`:33` ask the model to rewrite internal calls
to already-renamed names — but the map only holds functions processed **earlier in the loop**, in Ghidra
**address order**, not call-graph order (ch.31 §3; the reader adds no sorting), so it *cannot* cover the
whole project. A caller processed before its callee keeps the original name forever, and nothing revisits
emitted blocks (`enhanced_code_blocks` are final strings, `:85`; file written once, `:89`) — coverage is an
accident of link layout. Crude inverse of calxgloss's callees-first queue — `topological_order` pins
callee-before-caller (`calxgloss-analysis/src/callgraph.rs:964-1032`; queue never puts a dependent first,
`calxgloss-web/.../handlers/queue.rs:450-491`; merge gate `calxgloss-git/src/dependency.rs:80-87`;
[baseline](10-calxgloss-baseline.md) at `40fbf91f`).

**Where renames are written back: nowhere but the output file.** Output `:85-89`: blocks of
`// Function: {original name}\n{original signature}\n{enhanced code}\n` joined by `"\n\n"`, written to
`<input stem>_enhanced.c` (`:87`). Three facts: (a) header and signature lines stay the **original**
name/prototype even when the function was renamed inside the block — output anchors are stale by
construction; (b) on fallback the block is signature-line + `getC()` which *starts with the same signature*
(§2) — a duplicated prototype; (c) the map is **never written to disk** — the file's only
`json`/`open`/`write` calls are `:30`/`:77-78`/`:88-89` — the rename ledger is destroyed at exit. **What
"reconstruction" produces:** one annotated pseudocode `.c`, not re-compilable (no compiler call site
repo-wide, `gcc|clang|ld|objdump` → 0, ch.20 §9; no includes/prototypes for Ghidra bodies' external refs)
and never re-read — the `grep -rn '_enhanced' --include='*.sh' --include='*.py' .` hits all name the
`llm_r.py` relay family (e.g. `analyze_enhanced_binary.sh:34`; ch.20 §5), never
`<stem>_decompiled_enhanced.c`, which appears exactly once, at its producer `:87`. The model is *told* not
to change behavior (`:44`) or rename stdlib (`:35`); neither is checked — unverified text surgery.

**Context arithmetic: none, verified.** Budget battery — `grep -n
'max_tokens\|temperature\|truncat\|finish_reason\|usage\|token\|budget\|chunk\|window'
large_code_base_reconstruction.py` → **0 hits**. Each call embeds the **whole function body** (`:27`) at
any size plus the **whole map** (`:30`). Both terms unbounded: pseudocode of a big `main` runs to thousands
of lines (decompiler fact, external), uncapped and unsplit; and prompt *i* carries *i−1* map pairs —
aggregate map traffic over *N* functions is **Θ(N²) pairs** of `indent=2` JSON, never truncated or pruned.
Hence the chapter's sharpest failure: an over-window request raises at the OpenAI API (hosted semantics,
external), and the blanket except turns it into a one-line note plus the original body — **context overflow
degrades to pass-through precisely on the biggest functions, the ones the "large code base" path exists to
handle**, while the run still prints success. Cost is unmeasured too: no `usage` accounting (same battery)
— vs calxgloss's per-attempt `re/analysis/token_usage.json` telemetry, P50 (baseline).

## 5. `helper_scripts/`: three utilities, zero wires

The root README bills the directory as batch support in its last line ("Other usefull scripts are under
helper_scripts directory, that can be usefull for batch analysis", `README.md:127`, "usefull" ×2), and
`helper_scripts/README.md` documents all three. Callers battery — `grep -rn
'strip_binaries\|regroup_subdirs\|count_cpp_files' --include='*.sh' --include='*.py' .` → self-hits only:
**zero scripted callers** for all three.

- **`strip_binaries.py` (46 L).** One directory in (`:41-46`); nothing out — it mutates in place.
  `os.walk` (`:31`); classify via a `file` subprocess and the `'executable' in result.stdout` substring
  test (`:24-25`); then `subprocess.run(['strip', file_path], check=True)`
  (`:37`), per-file errors printed not fatal (`:38-39`). A **binutils `strip` sweep** (docstring `:5-6`;
  what `strip` removes is binutils semantics, external) with `file`-prose-dependent coverage — Linux DSOs
  print "shared object" and the substring misses them. **The "enhancements from another language model" /
  anti-scorer question resolves as a negative:** neither the file nor its README entry mentions
  LLMs or scorers — `helper_scripts/README.md:21`'s rationale is mundane ("reducing their size and
  preparing them for production environments or further security analysis"). That phrase belongs to
  `llm_d.py:30-32` (the *consuming* vulnerability prompt admitting its input may contain model rewrites,
  ch.31 §6); the blind-scorer scrub lives in `dataset_scripts/process_juliet_suite.py:25-30` (ch.20 §6).
  The one real connection: the repo's thesis is analysis of *stripped* binaries (`README.md:5`;
  `llm_d.py:30`) — and this is how a corpus gets stripped: destructive, in place, no backup.
- **`regroup_subdirs.sh` (41 L).** Input `<directory_path> <substring>` (`:16-23`); output: filesystem
  mutation. The whole logic is `:39` —
  `find . -maxdepth 1 -type d -name "${substring}*" ! -name "$substring" -exec mv {} "$target_directory/" \;`
  — after `mkdir` of the substring-named target (`:29-35`, self-exclusion comment `:38`). One level deep,
  prefix-glob: *module regrouping by name convention* (sweeping `CWE134*` siblings into `CWE134/`); its
  README rationale (`helper_scripts/README.md:12`) is "directory management and project organization".
  Wiring: none (battery). The repo's only gesture toward *module structure* — over directories no LLM
  stage ever reads per-module (§6).
- **`count_cpp_files.py` (35 L).** One directory in (`:29-33`), one printed total out (`:35`) of files
  ending `.c/.cpp/.cc/.h` (tuple `:22`, `endswith` `:25`, `os.walk` `:23-26`). Its README purpose —
  "assessing project size or complexity" (`helper_scripts/README.md:3`) — has nothing to feed: no script
  has a budget (§4 battery, 0 hits), no caller exists, and it counts *source* files — the large path's *N*
  is the JSON's function count, which the consumer never prints either.

## 6. The context-model ledger: every LLM call site, repo-wide

Eight `chat.completions.create` call sites (ch.20 §4), payloads and cross-function state verified at the
read/interpolation lines:

| Call site | Prompt embeds | Cross-function / cross-module state |
|---|---|---|
| `llm_d.py:29-56` | whole input file (`:21-23`, mid-prompt `:44`) | none — output `.txt` terminal, never re-read (ch.31 §6) |
| `llm_f.py:25-31` | whole decompiled `.c` (`:21-22`, `:28`) | none |
| `llm_r.py:26-35` | whole decompiled `.c` (`:19-20`, appended `:35`); **no `try:` at all** (`grep -c 'try:' llm_r.py` → 0) — an API failure kills the relay chain | none — one-shot whole-file rename |
| `large_code_base_reconstruction.py:17-50` | signature (`:24`) + whole body (`:27`) + whole map JSON (`:30`) | **the map** — names only, one run, unpersisted |
| `llm_pwn.py:12-28` | three whole files: enhanced `.c`, report, original `.c` (reads `:37,:40,:43`; interpolations `:16,:19,:22`) | file-as-prompt relay |
| `llm_fix.py:12-25` | enhanced `.c` + report (reads `:34,:37`; `:16,:19`) | relay |
| `llm_ctf_context.py:11-26` | report + enhanced `.c` (reads `:35,:38`; `:15,:18`) | relay |
| `llm_translate.py:11-23` | one whole file (read `:32`; `:15`) | none; unwired driver (ch.20 §4) |

Repo-wide truth: **the only cross-function state anywhere is the `name_map` dict**, and the only two
answers to context pressure are "one prompt per function" and "relay whole files through the `analyze_*.sh`
name chain". What is structurally absent — what a big project needs vs what this repo provides:

1. **Ordering** — Ghidra index order end-to-end; callees are not before callers (§4). calxgloss:
   call-graph-topological queue with pinned tests (`callgraph.rs:964-1032`, `queue.rs:450-491`), merge
   gate (`dependency.rs:80-87`).
2. **Budgeting** — zero token/window/length logic repo-wide (§4 battery; the file-embedding drivers share
   the absence, ch.31 §6). calxgloss: the context ladder *as policy* — `Signature → Disassembly →
   WithTests → ModuleContext → FullModule` (`calxgloss-types/src/context_tier.rs:59-84`, enum
   spot-checked at `40fbf91f`), pruned by seam capability (ADR-0055), named unknowns for pruned steps
   (ADR-0056).
3. **Evidence beyond the body** — every payload is pseudocode text + prose. Nothing injects import/API
   tables (calxgloss `calxgloss-apidetect`; PAL rows at `translate.j2:15-41`), body-signature matches
   (libmatch `BODY_MATCH_CONFIDENCE`, `calxgloss-libmatch/src/engine/tests.rs:507-527`), algorithm claims,
   constants, strings, types, or coverage records — the **15-scan warmup** (`scan_phase.rs:273`, registry
   `scan_registry.rs:606`, count pinned by `calxgloss-cli/src/commands/scan_command.rs:1407-1424`;
   `README.md:38`'s "13" is stale) rendered through a typed **evidence bundle**, every template's single
   render input (ADR-0048/0049). Here the evidence *is* the decompiler's output, re-prompted.
4. **Module structure** — no per-module prompts or cross-module state; the only module-adjacent code is the
   unwired renamer (§5). calxgloss makes neighbors a declared tier (`ModuleContext`/`FullModule`).
5. **Per-unit selection** — no thunk/fallback/entry filter at producer or consumer (ch.31 §3 battery; §2
   table): every index entry gets a paid API call.

The difference in one line: calxgloss treats context as an **assembled, budgeted, ordered, evidenced
artifact** (scan rows, tiers, admission lines — inspectable, versioned); this repo treats it as **string
concatenation** (body + prose + a growing JSON blob).

## 7. Runnability of the large path at HEAD — the operator's flow

All large-path files are mode `100644` (`git ls-files -s` battery — both scripts, the postScript, the
consumer, the three helpers) — `./decompile_large_pipe.sh` is EACCES on a fresh clone (ch.20 §11 item 2).
The analyzeHeadless call is the ch.31 §2 twin with `ghidra_11.0.1_PUBLIC` hardcoded at
`gd_decomp_large.sh:5`, while the README's version note names only `gd_decomp.sh` (`README.md:48`) and the
trio `decompile_large_pipe.sh` / `gd_decomp_large.sh` / `large_decompiler.py` get **zero README mentions**
(README grep battery: only `decompile_pipe` at `:90`/`:97`, and the consumer at `:99-104`; inventory §11
item 12). One README step covers the path invisibly: "Copy all scripts from Decompiler/decompilation_scripts
to … ghidra_scripts" (`README.md:45`) also stages `large_decompiler.py` — it resolves by accident of the
word "all". The manual flow (nothing runs end-to-end scripted):

| # | Operator action | Condition at HEAD |
|---|---|---|
| 1 | `chmod +x` or call via `bash` | modes `100644` (battery above) |
| 2 | Unzip Ghidra 11.0.1 into `Decompiler/`; copy both postScripts to `ghidra_scripts` | `README.md:39-45`; dir name hardcoded at `gd_decomp_large.sh:5`, undocumented |
| 3 | Create `.env` with a live key | `README.md:50` orders editing a file HEAD commit `c242671` deleted (ch.20 §11 item 1; ch.21 §5); `pip install openai python-dotenv` never stated (ch.20 §9) |
| 4 | Run `decompile_large_pipe.sh` from the repo root | **undocumented script** — the operator must find it in the tree; relative `cd ./Decompiler` (`:17`) enforces the cwd contract (ch.31 §1) |
| 5 | Take `<exe>_decompiled.json` from the invocation dir | emitted `:30`/`:33`; no script says where it should go |
| 6 | `python large_code_base_reconstruction.py <exe>_decompiled.json` | the one wired half: `README.md:99-104` — with a false model claim (`:101` "GPT-4" vs `:49` `gpt-3.5-turbo`) |
| 7 | Read one-line errors, trust the banners | Ghidra-half failures stay silent behind `:35`; LLM-half failures print one line and fall back to original bodies (`:68-70`), banner unchanged (`:91`); a mid-sweep Ghidra failure leaves **no JSON at all** (§2) |

The path is *mechanically* runnable with the core path's effort (ch.31 §8) plus one act of discovery — and
silent failure is total here: producer, launcher, orchestrator absent from the README; the consumer cannot
distinguish work from no-work.

## Steal ideas for calxgloss

- **The one steal: consistency-across-a-batch as prompt state, mechanized.** The `name_map` trick
  (`:64` update → `:30` re-embed) is the crude version of what calxgloss does by construction —
  callees-first order plus callee evidence rows put callees' typed signatures and suggestions in the
  bundle before the caller runs (§6). The instinct is right; the mechanism (unvalidated, unpersisted prose
  dict, Θ(N²) prompt growth) is not. If P51 (evidence-counted name/type confidence, `docs/roadmap.md:74`)
  ever feeds prior suggestions forward, render them as scored, admission-stamped bundle rows
  (ADR-0048/0049) — never a raw map dump — counted against a context budget (P50).
- **Persist every cross-unit artifact.** `name_map` — the run's only cross-function value — dies at exit
  (§4); calxgloss's artifact culture (scan rows, coverage records ADR-0053, `llm_io/log.jsonl`) is the
  countermeasure: in-process-only state is lost work.
- **Anti-pattern, name it: pass-through indistinguishable from work.** Blanket except → original body
  (`:68-70`) + unconditional banner (`:91`) means a run where every API call failed reports success with
  original code. For P42 smoke jobs assert *content* (a rename happened, records > 0), not exit 0;
  calxgloss's per-attempt verdicts and fail-loud `doctor` (`README.md:130-134`) are the answer.
- **Anti-pattern: unbounded prompt accumulators.** The whole map re-embedded every call (§4) is the
  quadratic foot-gun P50 budgets must cover *prompt-side state*, not just logged token counts.
- **Anti-pattern: destructive corpus mutation.** `strip_binaries.py` strips in place, no backup (§5) — the
  anti-P44 pattern; P33 corpora and provenance work stays read-only over targets (`target_dir` by design).
- **Anti-pattern: consumer-before-producer contracts and dead format constants.** The consumer shipped two
  days before any producer of its input existed, and its marker constants (`:8-9`) name a format the JSON
  path never emits or parses — dead from birth (§1, §4). calxgloss's culture (graft spans, ADRs, pinned
  counts) exists so a format contract lands producer + consumer + pinning test together.

## Sources

- Read-only clone `/tmp/opencode/LLM_Decompiler` @ `c2426715340b84a3e2eea4e891fe913a50154f00` (`git
  rev-parse HEAD` re-verified, clean worktree, 2026-10-31). Files re-opened whole:
  `Decompiler/decompilation_scripts/large_decompiler.py:1-24`; `Decompiler/gd_decomp_large.sh` +
  `decompile_large_pipe.sh` (esp. `:4-35`); `large_code_base_reconstruction.py:1-97` (esp.
  `:8-9,11-13,17-45,47-51,55-57,60-66,68-70,73-78,80-91,93-97`);
  `helper_scripts/{strip_binaries.py:5-6,22-46; regroup_subdirs.sh:16-41; count_cpp_files.py:22-35;
  README.md:3,12,21}`; `README.md:5,45,48,50,90,97,99-104,101,127`; `llm_f.py:21-36`; `llm_r.py:16-35`;
  `llm_pwn.py:12-43`; `llm_fix.py:12-37`; `llm_ctf_context.py:11-38`; `llm_translate.py:11-32`.
- Batteries run in-clone, all quoted inline where cited: `diff -u` of the three twin pairs; producer /
  consumer / caller greps for the JSON, the large path, the pipe, the helpers, `_enhanced`, the marker
  constants; the budget, validation, and `json/open/read/write` batteries on the consumer;
  `grep -c 'try:' llm_r.py`; `git ls-files -s`; `tail -c1`; `git log --oneline --` per large-path file;
  `git show 5b25d26/72c3c11/8eff39b` replays.
- History facts per [21-history-and-releases.md](21-history-and-releases.md) §2 rows 2/7/17/18 and §3
  P1/P3: `5b25d26` (consumer birth), `49df012` (helpers), `72c3c11` (dotenv), `8eff39b` (producer trio).
  External semantics marked inline: binutils `strip` and `file` phrasing; Ghidra `getC()` /
  `getFunctions(True)` order (ch.31); OpenAI context-window exceptions, 2024-era `gpt-3.5-turbo` windows;
  pseudocode size of very large functions. End-to-end execution out of scope per ch.00.
- calxgloss side at HEAD `40fbf91f` (tier enum spot-checked live at
  `crates/shared/calxgloss-types/src/context_tier.rs:59-66`; remaining spans per
  [10-calxgloss-baseline.md](10-calxgloss-baseline.md) anchors): `callgraph.rs:964-1032`,
  `handlers/queue.rs:450-491`, `calxgloss-git/src/dependency.rs:80-87`, `context_tier.rs:59-84`,
  `scan_phase.rs:273`, `scan_registry.rs:606`, `scan_command.rs:1407-1424`, `translate.j2:15-41`,
  `libmatch/src/engine/tests.rs:507-527`, `docs/roadmap.md:74` (P51), ADR-0048/0049/0052/0053/0055/0056,
  P41/P42/P44/P50, `README.md:38` stale "13", `README.md:130-134`.
- Cross-references: [20-llm-decompiler-inventory.md](20-llm-decompiler-inventory.md) §3–§6, §11 items
  2/10/12; [21-history-and-releases.md](21-history-and-releases.md) §2–§3, §5;
  [31-ghidra-harness-and-core-pipeline.md](31-ghidra-harness-and-core-pipeline.md) §1–§6 — all referenced,
  none re-derived.
