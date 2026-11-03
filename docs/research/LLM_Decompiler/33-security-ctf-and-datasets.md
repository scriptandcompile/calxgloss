# 33. Security, CTF, and the Juliet line — the exploit layer, the task drivers, and the experiment that never shipped a scorer

> Part of the [LLM_Decompiler overview](README.md). Deep dive on the security/CTF surface: the `analyze_*.sh`
> six `analyze_*.sh` orchestrators and their artifact-relay algebra, the five purpose-specialized prompt drivers (`llm_fix`, `llm_pwn`,
> `llm_ctf_context`, `llm_translate`, plus `llm_r` re-situated), the CTF chain as actually shipped, and the
> Juliet/CWE dataset scripts — read as pieces of one unscored vulnerability-detection experiment. The Ghidra
> mechanics are ch.31's, the model ledger is ch.20 §4's, the chronology is ch.21 §2's — *referenced*, not
> re-derived. Added here: the dot-vs-identity name algebra and per-driver failure modes when the relay misses,
> verbatim prompt anatomy of the four GPT-4o task drivers, the `51a2c98` one-line repair replayed, the
> label-blinding mechanics of `process_juliet_suite.py`, and the verified absence of any scorer, consumer, or
> Ghidra-side rename path. All `path:line` re-opened and verified in the read-only clone
> `/tmp/opencode/LLM_Decompiler` at HEAD `c2426715340b84a3e2eea4e891fe913a50154f00`; verified absences name the
> battery. Hosted-model semantics and upstream-Juliet facts are marked external; end-to-end execution is out of
> scope (ch.00).

## 1. Orientation: two births, a two-week silence, and a README that stopped listening

The security layer of this repo is two commits wide. `5b25d26` (2024-05-07, "Functionality scripts") gave birth
to the analysis core — `analyze_binary.sh` 31 lines, `analyze_all.sh` 41, `analyze_enhanced_binary.sh` 50,
`analyze_source.sh` 35, `decompile_pipe.sh` 35, and the `gpt-4-turbo` trio `llm_d.py`/`llm_f.py`/`llm_r.py`
(`git show --stat`). Sixteen days later, `e0db19e` (2024-05-23 20:43, "Functionality extension") touched
*exactly six files* and nothing else: `analyze_and_exploit.sh` 62, `analyze_and_fix.sh` 56, `llm_ctf_context.py`
54, `llm_fix.py` 53, `llm_pwn.py` 60, `llm_translate.py` 48 — the whole exploit/fix/CTF layer in one
333-insertion commit, all four new drivers on `gpt-4o` (battery: `grep -rn 'model="' *.py` → `llm_fix.py:23`,
`llm_pwn.py:26`, `llm_ctf_context.py:24`, `llm_translate.py:21`).

The docs never learned. The README's "Usage and Script Descriptions" section (`README.md:54-125`) lists exactly
nine scripts — the `5b25d26` set (`analyze_all/binary/enhanced/source`, `decompile_pipe`,
`large_code_base_reconstruction`, `llm_d` `:106-111`, `llm_f` `:113-118`, `llm_r` `:120-125`) — and the last
README commit predates `e0db19e` by two weeks (ch.21 §2). Not one of the five e0db19e-era scripts has a README
usage entry; the only acknowledgment of the layer anywhere in the docs is the Capabilities bullet "Exploit
Script Generation: Provides skeleton scripts that can serve as a basis or inspiration for crafting
proof-of-concept exploits" (`README.md:33`). `llm_translate.py` has no README presence at all: battery
`grep -rn "llm_translate" --include="*.sh" --include="*.py" --include="*.md" .` → zero hits outside the file
itself, and `git log --oneline --all -S 'llm_translate'` → empty: the string never entered or left any committed
blob in the repo's whole history. §5 buries it.

## 2. The relay algebra: one `cut` separates working chains from silent no-ops

Every orchestrator stages the same relay of filename-conventions, and the conventions do not match. The pipe
names its output from the *full* basename — `executable_name=$(basename "$executable_path")`
(`decompile_pipe.sh:14`), `output_file="${executable_name}_decompiled.c"` (`:30`) — so `a.out` yields
`a.out_decompiled.c`. Every orchestrator then computes `executable_name` with a dot-truncation —
`basename "$executable_path" | cut -f 1 -d '.'` (`analyze_binary.sh:11`, `analyze_enhanced_binary.sh:14`,
`analyze_and_fix.sh:14`, `analyze_and_exploit.sh:14`, and `source_name` at `analyze_source.sh:12`) — and all
downstream stages address `"${executable_name}_decompiled.c"` (e.g. `analyze_binary.sh:20`,
`analyze_enhanced_binary.sh:24`). For `a.out` the writer says `a.out_decompiled.c`, every reader says
`a_decompiled.c`, and the chain is dead on arrival. (ch.31 §5 step 2 flagged the pipe side of the same
mismatch; here is the orchestrator side and the consequence algebra.) The truncation is worse than
dot-eating for multi-dot names: `cut -f 1` keeps only the segment before the *first* dot, so `libfoo.so.1`
becomes `libfoo` — collision-prone, while extensionless names (`test1`, `CWE23_..._bad`) survive as identity.

That identity case is load-bearing. The dataset pipeline's example inputs are `…/bin/CWE23/bad`-style paths
(`dataset_scripts/README.md:28-30`, §7) whose executables carry `-bad`/`-good` suffixes and no dots
(`dataset_scripts/select_from_cwe.py:6` defaults `suffix_bad='-bad'`), and the author's experiment corpus was
Juliet-shaped — so the one corpus the repo is wired to feed dodges the bug. For anything named like a default
`gcc` output, §3's failure table is what runs.

One more relay quirk on the pipe side: it records the caller's cwd as `original_dir` (`decompile_pipe.sh:10`),
cd's into `./Decompiler` (`:17`), copies the target to `./exec/exe` (`:23`), runs `./gd_decomp.sh ./exec/exe
/tmp/source.c` (`:26`), and moves `decompiled_output.c` to `$original_dir` (`:33`) — the comment says "the same
directory as the original executable" (`:32`), the code writes the *invocation cwd*.

## 3. What each driver does when its input is missing — the silence is per-driver

When the relay misses, each driver fails differently, and none of the six orchestrators has `set -e` (battery:
`grep -n "set -e\|set -o\|pipefail" *.sh` → zero hits), so the stage script walks to the end and prints its
"Analysis complete" banner regardless:

| Driver | Missing-input behavior | Exit |
|---|---|---|
| `llm_d.py:24-26` | prints `File does not exist.`, bare `exit()` | 0 |
| `llm_f.py:16-18` | prints `Error: The file … does not exist.`, `return` | 0 |
| `llm_r.py:18-23` | prints `Decompiled code file does not exist.`, `sys.exit()` | 0 |
| `llm_fix.py:33,36` / `llm_pwn.py:36,39,42` / `llm_ctf_context.py:34,37` | bare `open()` in `main` — traceback | 1 |

The three `gpt-4-turbo` drivers guard with existence checks and exit **zero**; the four GPT-4o task drivers
open files raw and crash. Either way the caller continues: the orchestrator's `mv` lines then emit their own
`No such file or directory` noise (`analyze_binary.sh:28-29`, `analyze_enhanced_binary.sh:45-48`,
`analyze_and_exploit.sh:55-60`), the success echo fires (`analyze_binary.sh:31`,
`analyze_enhanced_binary.sh:50`, `analyze_and_exploit.sh:62`), and the console shows the same shape a fully
successful run would. A `results/` tree with nothing in it is the tell — ch.20 §7 verified `results/` vacant at
HEAD, which is consistent with either nobody running the tool or runs dying exactly this silently.

`llm_r.py` additionally has no `try:` around its API call (ch.32 §6 counted `grep -c 'try:' llm_r.py` → 0): an
API hiccup mid-chain kills the relay with a traceback *after* `llm_f` already paid its call, and the downstream
`llm_d`/`llm_pwn`/`llm_ctf` stages then run on missing inputs per the table. `llm_f.py:33-49` is the repo's
only API `try/except` among these seven — and it swallows to a print (`:48-49`), returning no retry.

## 4. The six orchestrators, stage by stage — inputs, chains, artifact relays

Line ranges re-opened at HEAD; the model/prompt/output-convention columns of these drivers are ch.20 §4's
ledger, not restated.

| Script | Chain (line) | Artifact layout |
|---|---|---|
| `analyze_binary.sh` (31) | pipe `:15` → `llm_d.py:20` | `results/<name>/executable_analysis/` (`:24`), `mv` decompiled + report (`:28-29`) |
| `analyze_enhanced_binary.sh` (50) | pipe `:19` → `llm_f.py:24` → `llm_r.py:29` → `llm_d.py:34` | `results/<name>/enhanced_executable_analysis/` (`:38`); the *original executable* is `cp`'d beside the outputs (`:42`); four `mv` (`:45-48`) |
| `analyze_and_fix.sh` (56) | enhanced chain + `llm_fix.py:39` (enhanced `.c`, report, out) | `basePath=~/Desktop/sp_new` (`:10`); `_fixes.txt` lands one level *above* the enhanced dir (`:54`) |
| `analyze_and_exploit.sh` (62) | enhanced chain + `llm_pwn.py:39` (enhanced, report, **original** `_decompiled.c`, out) + `llm_ctf_context.py:44` (enhanced, report, out) | same `sp_new` (`:10`); `_pwn.py` and `_ctf_context.txt` one level above (`:59-60`) |
| `analyze_source.sh` (35) | **no Ghidra at all**: `cp` the `.c` into cwd (`:16`) → `llm_d.py` directly on the source (`:20`) | `results/<name>/source_analysis/` (`:24`); report moved by stem (`:28`, matching `llm_d.py:18`'s `<stem>_vulnerabilities.txt`); then `mv` the copy (`:32`) followed by `rm` of the same path (`:33`) — the `rm` can never succeed, dead line |
| `analyze_all.sh` (41) | sweep: `find "$DIRECTORY" -type f -exec bash -c 'analyze_files "$0"' {} \;` (`:39`) with `[ -x ]` gate (`:25`) and `export -f analyze_files` (`:35`) | invokes both stage scripts per hit (`:28,30`) — per-*name* results dirs mean two binaries sharing a basename in different subdirs collide into one `results/<name>/` and clobber each other's in-cwd intermediates |

All five single-target scripts open with the identical preflight `[ "$#" -ne 1 ] → usage → exit 1` (`:4-7`),
except `analyze_all.sh`'s `[ -z "$1" ]` variant (`:11-14`); drivers are invoked as `python`, not `python3`
(ch.20 §11 staleness ledger). Line counts at HEAD: 310 shell, 384 driver, 113 dataset (`wc -l`).

The `sp_new` hardcode deserves its one line: `analyze_and_fix.sh:10` and `analyze_and_exploit.sh:10` both set
`basePath=~/Desktop/sp_new` and `cd "$basePath"` before calling `./decompile_pipe.sh` (`:18-19`), which cd's
into `./Decompiler` relative to it. As shipped, the two security orchestrators work only if the whole repo
(decompilation-scripts and all) is *also* deployed at `~/Desktop/sp_new` on the operator's machine — the sole
surviving fingerprint of the experiment environment (§8). The three May-7 stage scripts use `basePath="."`
(`analyze_binary.sh:9`, `analyze_enhanced_binary.sh:10`, `analyze_source.sh:9`); the exploit/fix pair is the one
place a personal desktop path shipped inside an orchestrator.

## 5. The four GPT-4o task drivers — prompts, and the fate of every artifact they emit

All four follow the house style ch.20 §4 pinned: whole prompt as a single `system` message, no params, no
retry. They differ in what they're asked to *do with the code*, and all four agree on dumping free text to a
file nobody downstream reads (battery: `grep -rn "_fixes.txt\|_pwn.py\|_ctf_context.txt" --include="*.py"
--include="*.sh" --include="*.md" .` → only the producing lines `analyze_and_fix.sh:39,54` and
`analyze_and_exploit.sh:39,44,59-60`; zero consumers, repo-wide, at HEAD and in no commit ever).

**`llm_fix.py`** (53 lines) — repair suggestions. The whole task is one sentence (`:13`): *"Based on the
following decompiled code and vulnerability report, suggest the necessary changes to make the code bug-free.
Provide specific changes and a brief explanation for each change."* Inputs: enhanced `.c` + the `llm_d` report,
read whole (`:33-37`); output `<name>_fixes.txt` (`:41-42`). Note what this is: prose fed by prose — the report
it is built on is `llm_d`'s unparsed free-text response (`llm_d.py:61-62`), so the repo's "fix" layer is a
game of telephone with no schema at either hop, and the fixes are never applied, compiled, or re-verified by
anything in the tree.

**`llm_pwn.py`** (60 lines) — exploit *plans*, not exploits. Prompt (`:13`): *"generate a skeleton for a PWN
script in Python. The script should include comments on steps to be done to finish the proof of concept of the
bug found or the exploit, with a text explaining the overall idea behind the attack."* Three whole files go in
— enhanced `.c`, report, and the **raw pre-filter decompile** as a grounding third context (`:36-43`) — and one
`<name>_pwn.py` comes out (`:57`). Nothing in the repo can run it: battery
`grep -rniE "pwntools|from pwn|gdb|checksec|ROP|objdump|readelf|nasm|libc" --include="*.py" --include="*.sh"
--include="*.md" .` (excluding `Decompiler/`) → **zero hits**, at HEAD and in every commit. The generated
"PWN script" is a to-do list wearing Python syntax; the produced artifact has zero consumers; the original
executable sits in the results dir (`analyze_and_exploit.sh:52`) but no driver ever opens it.

**`llm_ctf_context.py`** (54 lines) — challenge classification from artifacts alone. Prompt (`:12`): *"determine
the category of the CTF challenge. Provide brief hints, relevant sources, webpages, and references to old CTF
challenges that could help in solving this challenge."* The ask for *references to old CTF challenges* is pure
parametric retrieval — no search tool, no binary, no debugger: the driver reads only report + enhanced code
(`:34-38`) and writes one free-text `<name>_ctf_context.txt` (`:42-43`). Two details: (1) the CLI positional
order (`enhanced`, `report`, `out` at `:49-51`) is *swapped* relative to `main()`'s (`report`, `enhanced`, `out`
at `:33`) and the dispatcher at `:54` bridges them — correct at HEAD, shape-swap fragility forever; (2) it
didn't start correct. Born in
`e0db19e:analyze_and_exploit.sh:44` with a *fourth* argument (`"${executable_name}_decompiled.c"` wedged before
the out-path), the 3-positional parser would exit 2 `unrecognized arguments` on every run from 05-23 to 05-24,
the `mv` at `:60` shipped nothing, and the banner at `:45` printed `ctf context completed.` anyway. `51a2c98`
(2024-05-24 12:23, "Update analyze_and_exploit.sh", 1/1) deleted exactly that one argument — diff:
- `-python llm_ctf_context.py "${executable_name}_decompiled_filtered_enhanced.c" "…vulnerabilities.txt" "${executable_name}_decompiled.c" "${executable_name}_ctf_context.txt"`
- `+python llm_ctf_context.py "${executable_name}_decompiled_filtered_enhanced.c" "…vulnerabilities.txt" "${executable_name}_ctf_context.txt"`

**`llm_translate.py`** (48 lines) — dead at birth. Prompt (`:12`): *"Translate the following C source code to
{target_language}:"* — any language, free text out (`:36-37`), 3-positional CLI (`:43-45`). No orchestrator,
no README entry, no mention in any committed blob ever (§1's dual battery: HEAD grep → zero refs outside the
file; `git log --all -S 'llm_translate'` → zero content hits repo-wide across all 26 commits;
`git log --oneline -- llm_translate.py` → just `e0db19e`). It is the sole implementation of the README's
"Code Recovery: … in the user's preferred programming language" (`README.md:31`), and the capability was
vaporware from the day the script was added (ch.20 §4 already tagged it "unwired driver"; the eulogy: it was
never even wired *once*).

**`llm_r.py` re-situated** — the security layer's "rename" is a text relay, not a symbol-table operation. Its
prompt orders: *"Rename variables and functions to names that are more representative of their purpose… as it
will be analyzed for vulnerabilities later"* (`:29`) and then spells out the mechanism: *"The result of this
prompt, will directly be pasted inside a .c file and sent again to another LLM for vulnerability detection"*
(`:30`) — and the orchestrators do exactly that, feeding `<stem>_enhanced.c` straight back to `llm_d`
(`analyze_enhanced_binary.sh:29,34`). The renames never reach the disassembler's view of the binary. Battery:
`grep -rniE "renameFunction|setName|createFunction|Symbol|flat_api|importProgram|analyzeHeadless" --include="*.py"
--include="*.sh" .` (excluding `Decompiler/`) → a single hit, the word "symbols" in
`helper_scripts/strip_binaries.py:6`'s docstring about binutils `strip`. The only Ghidra entry point in the repo
is the read-side `analyzeHeadless -import` in `Decompiler/gd_decomp.sh:22-23` (ch.31 §2); there is no
write-side path. calxgloss's rename doctrine lands claims through the IDB + human approval (10-baseline,
Naming & typing; `shared_routes`, ADR-0002); this repo's renames die in the next prompt's input string. ch.32
§2's `name_map` on the large path has the same property, one level up.

## 6. The CTF chain as shipped — one honest trace

Feed a dotless Juliet `-bad` binary to `analyze_and_exploit.sh` and, if every API call survives, the chain is:
pipe writes `foo-bad_decompiled.c` → `cut` is identity → `llm_f` keeps "functions that have substantial logic"
(`llm_f.py:26`) → `llm_r` rewrites with comments and renames → `llm_d` writes a report ordered
Confirmed/Potential (`llm_d.py:40-41`) → `llm_pwn` drafts an exploit *plan* → `llm_ctf_context` guesses the
category and cites old CTF challenges → four artifacts + the copied binary land under
`results/foo-bad/enhanced_executable_analysis/`, with `_pwn.py` and `_ctf_context.txt` parked one level above
(`analyze_and_exploit.sh:59-60`). Cost: five API prompts, three of them re-sending the same enhanced code
(`llm_d.py:44`, `llm_pwn.py:16,22`, `llm_ctf_context.py:18`). If any relay stage dies mid-chain, §3's table
takes over and the run still reports success.

The security framing is entirely *on top of* the reconstruction stack: category, hints, fixes, pwn-skeleton —
all derived from reconstructed text, none from the machine code itself (contrast: calxgloss's binary-first
scanners, 10-baseline Pipeline anatomy).

## 7. The Juliet line: two scripts, a tree the repo cannot build, and blinding as the whole point

**Lineage** (all 26 commits checked): `49df012` (05-07) adds `Dataset_scripts/process_juliet_suite.py` (58
lines) and `helper_scripts/select_from_cwe.py` (55); `9316783` (05-07) is the one-line fix at `:49` —
- `-base_directory_path = "Dataset/juliet-test-suite-c-master/testcases"`
- `+base_directory_path = "../Dataset/juliet-test-suite-c-master/testcases"`

— because the scripts live one directory deep; `a4e57fc` (05-08) renames `select_from_cwe.py` into
`dataset_scripts/` with a 0-line diff (pure move) and adds `dataset_scripts/README.md` (39 lines); `fadee84`
(05-08) deletes `Dataset_scripts/`, and `e913125` (05-08) re-creates `dataset_scripts/process_juliet_suite.py`
— byte-identical to the deleted file (battery: `git diff fadee84^:Dataset_scripts/process_juliet_suite.py
HEAD:dataset_scripts/process_juliet_suite.py` → empty). This is the case-dance ch.21 §4 documents; its net
effect at HEAD is that `process_juliet_suite.py` is 58 lines of the same file that was born on 05-07.

**`process_juliet_suite.py`** (58 lines) does two things, and its own docstring names the second one exactly:
*"The purpose of the script is to clean up the dataset by keeping only relevant directories and standardizing
certain text in source files to hide wheras we are calling the bad or good function"* (`:10`, sic). (1) Pruning:
`filter_directories` (`:13-22`) walks bottom-up (`topdown=False`, `:15`), extracts the CWE number from each
`CWE…` dir via `dirname.split('_')[0][3:]` (`:18`), and `rmtree`s everything not in a 22-entry keep-list
(`:52`: 78, 122, 134, 197, 242, 367, 391, 401, 415, 416, 457, 467, 468, 476, 478, 480, 482, 561, 562, 563, 590,
835). (2) **Label blinding**: four compiled regexes (`:25-31`) rewrite, in every `.c`/`.cpp` file, in place
(`:43-45`):

- `Calling good\(\)\.\.\.` → `calling routine()...` and `Finished good\(\)` → `Finished routine()` (`:26-27`)
- `Calling bad\(\)\.\.\.` → `calling routine()...` and `Finished bad\(\)` → `Finished routine()` (`:28-29`)

Those four strings are verbatim the runtime banners Juliet's `main()` prints around the vulnerable and fixed
calls. Verified against a representative suite file via the GitHub mirror
`arichardson/juliet-test-suite-c` (fetched 2026-10-31 through the GitHub API): `testcases/…execl_01.c` contains
`printLine("Calling good()...")`, `printLine("Finished good()")`, `printLine("Calling bad()...")` inside
`#ifndef OMITGOOD/#ifndef OMITBAD` gates (`:178-184` region of that file), plus the `@description / BadSource /
BadSink / Flow Variant` header (`:6-15`) that names the flaw in English. Upstream grounding: the Juliet C/C++
suite lives at `samate.nist.gov/SRD` (suite 112 = C/C++ 1.3, 64,099 test cases, NSA Center for Assured
Software, 2017-10-01; 1.3.1 = suite 116, 2022-08-11; fetched 2026-10-31), and the mirror's default branch is
`master` — which is exactly why the author's hard-coded directory is `juliet-test-suite-c-master` (`:49`): that
is the folder a GitHub zipball unzips to, so the author cloned the *mirror*, not the NIST archive. Blinding
effect: after scrubbing, a good and a bad testcase of the same variant emit *identical* runtime banners, so a
model fed the decompiled output cannot score itself by pattern-matching "good"/"bad" tokens. The dataset README
says the same thing in its own words: the replacement *"typically aims to obscure whether a particular function
call in the source code is 'good' or 'bad', which can be important for blind testing and evaluation"*
(`dataset_scripts/README.md:7`).

**`select_from_cwe.py`** (55 lines) works on the *compiled* tree, not the scrubbed sources: `select_files`
(`:6-44`) lists files ending `-bad` in a base dir (`:26`), draws `random.sample(all_bad_files, num_files)` with
`num_files=5` as a default argument (`:6,29` — unguarded: a CWE dir with fewer than five `-bad` files raises
`ValueError` and kills the run), mirrors each name to its twin by `f.replace(suffix_bad, suffix_good)` (`:32`),
keeps only twins that exist in the mirror dir (`:35` — missing good halves are silently dropped while bad halves
copy unconditionally, `:38-42`), and drops everything flat into `../selected_binaries` (`:23,53`). Usage and
the layout it assumes: `python select_from_cwe.py /path/to/bad/files /path/to/good/files`, "typically…
`Dataset/juliet-test-suite-c-master/bin/CWE23/bad`" (`dataset_scripts/README.md:26-30`) — a prebuilt
`bin/CWExx/{bad,good}` tree with hyphen-suffixed executables. Note the README example cites CWE23, which is
*not* in the keep-list (`process_juliet_suite.py:52`) — the docs' showcase CWE and the script's filter
disagree.

**Wiring and its honest limits.** The dataset README's one wire: samples *"could be used as input to
`analyze_all.sh`"* (`dataset_scripts/README.md:24`) — and that is the only reference to `selected_binaries`
anywhere (battery: grep `selected_binaries` → `select_from_cwe.py:53` + that README line). `process_juliet`'s
scrubbed `testcases/` tree has no pipeline consumer at all: nothing in the repo compiles anything (battery:
`grep -rniE "gcc|clang|cmake" --include="*.py" --include="*.sh" .` excluding `Decompiler/` → zero; every `make`
hit is the English verb in prose or `os.makedirs`), and upstream Juliet ships sources, not `bin/` dirs. So the
author's `bin/CWExx` corpus was built off-repo — the suite's own Makefile machinery, external, is implied but
absent. And there is no ordering or rebuild hook between scrub and sampling: the blinding at `:25-30` only
reaches the sampled *binaries* if the tree was recompiled between the two scripts' runs. Inference, flagged:
the two scripts were written for an off-repo loop (scrub sources → build → sample binaries → `analyze_all.sh`),
and only the outer legs of that loop shipped.

## 8. The experiment the README describes — and the scorer that was never committed

`README.md:9` states the purpose outright: *"we sought to quantify the performance of the GPT-4 model on binary
vulnerability analysis, drawing parallels to studies like those documented in 'On the capability of static code
analysis to detect security vulnerabilities', which examined static analyzers on the Juliet Test Suite"* — a
title-identical match to Goseva-Popstojanova & Perhinschi, *Information and Software Technology* 2015, DOI
10.1016/j.infsof.2015.08.002 (Crossref, fetched 2026-10-31; external). That study's design is tool-vs-Juliet:
run static analyzers over paired good/bad test cases, compute precision and recall per weakness class. The
README imitates the design down to the corpus: `:5` frames the hypothesis ("LLMs have demonstrated effectively
akin to static analyzers on source code… prompted the exploration of their limitations and capabilities with
compiled stripped code"); `:11-15` names the two experimental arms — *"Direct analysis of decompiled outputs"*
(`= analyze_binary.sh`) and *"Analysis of source code post-enhancement and reconstruction"* (`=
analyze_enhanced_binary.sh`, with `analyze_source.sh` as the source-side control arm); `:17` cites the
prior-methodology rationale; `:19-26` then *reports results*: "outperformed traditional methods across all
evaluated metrics" (`:21`), "incurred more false positives" (`:22`). Setup step 3 admits the dataset scripts
exist for exactly this: *"Dataset setup(optional: only if you want reproduce or extend the experiement
described above)"* (`:51`, sic).

Now the negatives. Scoring vocabulary over code: `grep -rniE "scor|precision|recall|accuracy|benchmark|ground.
?truth|true.?positive|false.?(positive|negative)|tp:|fp:" --include="*.py" --include="*.sh" .` (excluding
`Decompiler/`) → exactly **one** hit, and it is not scoring code but the calibration instruction inside
`llm_d.py:35`. History: `git log --oneline --all -S 'precision'` → empty; `-S 'recall'` → empty — the words
never entered or left any blob in any of the 26 commits (full table: ch.21 §2). Metrics output: `results/` is
vacant at HEAD (ch.20 §7). The prompt itself shows the author knew what corpus he was feeding: *"you will
encounter situations where you are given the code of a bug after it was fixed, be conservatif and only annonce
when it is obivious the presence of the bug"* (`llm_d.py:36`, sic) — the single prompt must handle both halves
of the good/bad pair — and `:34-36` (`"only include vulnerabilities that you can confirm with certainty"`;
*"false negative is much much better than false positives"*) is precision-biased calibration for exactly the
trade-off `README.md:22` reports.

The reading, stated as inference with its confidence high: **the repo ships the apparatus of a Juliet
benchmark — corpus preparation (`§7`), two-arm pipelines (`§1`), calibration prompt (`llm_d.py:34-36`) — but the
measurement was the author reading `_vulnerabilities.txt` files against known labels, off-repo.** The scorer was
a human at a desk. Nothing here computes, stores, or diffs a metric; nothing ever consumed the `confirmed /
potential` pseudo-schema (`llm_d.py:47-48` → raw write at `:61-62`, "nothing ever parses either" per ch.20 §4).
Falsification would require a scoring script in some commit (all 26 accounted for: none) or outputs in
`results/` (vacant: ch.20 §7).

## 9. Ontology check — security-shaped tool vs meaning-extractor

| Dimension | LLM_Decompiler security layer | calxgloss (10-baseline anchors) |
|---|---|---|
| Question asked of the binary | "is it vulnerable, what category, how might one exploit it?" | "what was this program written to do?" (Naming & typing) |
| Ground truth | Juliet's planted good/bad labels, external | no planted-truth corpus; scored eval (P33) open |
| Labels in the analysis path | actively scrubbed before analysis (`process_juliet_suite.py:10,25-30`) | inputs are never hidden from the pipeline; the *eval* corpus is where blinding would apply |
| Uncertainty | prompt etiquette: Confirmed vs Potential in free prose (`llm_d.py:34,40-41`), nothing parses it | first-class records: confidence-scored claims + named unknowns (ADR-0053/0056) |
| Findings' fate | `.txt`/`.py` artifacts in per-target folders, zero consumers (§5 battery) | claims land in the PAL DB and feed the rename flow |
| Rename mechanics | rewritten C text pasted into the next prompt (`llm_r.py:30`); never touches the symbol table (§5 battery) | renames land in the IDB with human approval (`shared_routes`, ADR-0002) |
| Relation to the machine code | binary read once, at Ghidra's output; everything after is prose-about-prose | binary-first evidence throughout (stringctx, consts, algorithm scans) |
| ELF/PE exploitation | none: pwntools/gdb/objdump battery → zero hits (§5) | n/a — a naming/typing tool, but its whole surface rests on reading the actual target |

The honest overlap: both codebases believe an LLM's C understanding improves when the input is *triaged* first —
`llm_f.py:26` ("remove any empty functions… keep only functions that have substantial logic") is the same
instinct as calxgloss's scan ladder, and the string-constant attention the Juliet blinding targets
(`printLine` banners) is precisely the evidence band calxgloss's stringctx and consts scans mine (10-baseline,
Pipeline anatomy). The difference isn't technique, it's epistemics: calxgloss treats uncertainty as data
(admission lines, coverage records, unknown records); this layer treats it as tone — `llm_d.py:35-36` begs for
honesty in prompt words and then writes the answer to disk unstructured. And the one genuinely empirical part of
this repo — the Juliet pairing — is exactly the part that shipped without measurement code.

## Steal ideas for calxgloss

- **Blinding for P33.** When calxgloss's scored eval (P33 open, 10-baseline) uses any paired corpus, copy
  `process_juliet_suite.py:25-30`'s cheap trick: scrub the tokens that give away which twin is which, and keep
  the pair-name invariant the sampler already enforces (`select_from_cwe.py:32` mirrors a name by a single
  suffix `replace`). Pairs of binaries differing by one planted CWE are the closest thing to a unit test for the
  naming pipeline — and symbol-blinding is already solved at corpus level by binutils `strip`
  (`helper_scripts/strip_binaries.py`, ch.20 §6). Cost is a corpus-build script this repo never wrote (§7).
- **The scorer is the experiment.** `README.md:21`'s "across all evaluated metrics" is unauditable because no
  scoring code exists in any of the 26 commits (§8 batteries). P33 must ship the scorer in-repo with the
  corpus, or the number is a story. This is the single strongest anti-pattern in the whole repo.
- **Confirmed/Potential as schema, not prose.** `llm_d.py:40-41`'s two-bucket output is a decent idea for
  calxgloss scans' confidence handling — but borrow the *idea* and route it into typed records (the
  ADR-0056 unknown-record family), never into prompt prose, whose two-bucket cousin here was parsed by no one
  (§8).
- **Anti-patterns, for the record:** findings→txt→no-consumer (`_fixes.txt`, `_pwn.py`, `_ctf_context.txt` —
  three artifacts, zero readers, §5); name relay by string munging (`cut -f 1 -d '.'` vs full-basename writer,
  §2 — calxgloss has real program identity; never rebuild it from filenames); renames that never reach the
  symbol table (§5 battery); a personal desktop path hardcoded into shipped orchestrators
  (`analyze_and_fix.sh:10`, `analyze_and_exploit.sh:10`); a dead driver shipped and never once wired
  (`llm_translate.py`, §5).

## Sources

- Read-only clone `/tmp/opencode/LLM_Decompiler` @ `c2426715340b84a3e2eea4e891fe913a50154f00` (`git rev-parse
  HEAD` re-verified, worktree untouched, 2026-10-31). Files re-opened whole at HEAD: all of
  `analyze_binary.sh`–`analyze_source.sh` (`1-31`/`1-41`/`1-50`/`1-56`/`1-62`/`1-35`), `decompile_pipe.sh:1-35`,
  `llm_d.py:1-64`, `llm_f.py:1-55`, `llm_r.py:1-50`, `llm_fix.py:1-53`, `llm_pwn.py:1-60`,
  `llm_ctf_context.py:1-54`, `llm_translate.py:1-48`, `dataset_scripts/process_juliet_suite.py:1-58`,
  `dataset_scripts/select_from_cwe.py:1-55`, `dataset_scripts/README.md:1-39`, `results/README.md:1-29`,
  `README.md:5,9-17,19-26,31-34,45-51,54-127`, `Decompiler/gd_decomp.sh:5,22-23`,
  `helper_scripts/strip_binaries.py:1-20`.
- History replays in-clone: `git show --stat` of `5b25d26`/`e0db19e` (file sets quoted in §1), `51a2c98` (diff
  lines quoted in §5), `49df012`/`9316783` (diff quoted in §7)/`a4e57fc`/`fadee84`/`e913125`; `git diff
  fadee84^:Dataset_scripts/process_juliet_suite.py HEAD:dataset_scripts/process_juliet_suite.py` → empty;
  `git log --oneline --follow --` per file; `wc -l` battery.
- Verified-absence batteries, quoted inline where cited: script-reference grep across sh/py/md (§1);
  `grep -rn 'model="' *.py` (ch.20 §4 cross-check); artifact-consumer grep for `_fixes.txt`/`_pwn.py`/
  `_ctf_context.txt`/`selected_binaries` (§5, §7); `grep -n "set -e\|set -o\|pipefail" *.sh` → 0 (§3);
  exploitation-tool battery `pwntools|from pwn|gdb|checksec|ROP|objdump|readelf|nasm|libc` → 0 (§5); Ghidra
  symbol-apply battery `renameFunction|setName|createFunction|Symbol|flat_api|importProgram|analyzeHeadless` →
  1 prose hit (§5); scorer-vocabulary grep over py/sh → 1 prose hit (`llm_d.py:35`) plus
  `git log --all -S 'precision'`/`-S 'recall'`/`-S 'llm_translate'` → all empty (§1, §8); build battery
  `gcc|clang|cmake` → 0 (§7).
- External, marked as such: Juliet/SARD facts from `samate.nist.gov/SRD` (C/C++ 1.3 = suite 112, 64,099 test
  cases, NSA Center for Assured Software, 2017-10-01; 1.3.1 = suite 116, 2022-08-11; fetched 2026-10-31); the
  `arichardson/juliet-test-suite-c` mirror (GitHub API fetches 2026-10-31: `master` default branch explaining
  the `-master` dir name at `process_juliet_suite.py:49`; representative file
  `testcases/CWE78_OS_Command_Injection/s01/…execl_01.c` header `:1-15`, `OMITBAD/OMITGOOD` gates, and the
  `printLine("Calling good()...")`-family banners the four scrub regexes target); the pinned cited paper
  Goseva-Popstojanova & Perhinschi, *Inf. Softw. Technol.* 2015, DOI 10.1016/j.infsof.2015.08.002 (Crossref);
  upstream Juliet Makefile machinery (§7 inference); OpenAI hosted-model semantics (ch.00).
- Cross-links: model ledger and staleness — ch.20 §4, §7, §11; chronology and the case dance — ch.21 §2, §4;
  pipe mechanics and `llm_d` prompt anatomy — ch.31 §4-§6; `name_map` and the repo-wide context ledger — ch.32
  §2, §6; style sibling LLM4Decompile ch.34; calxgloss anchors — 10-baseline (Naming & typing, Pipeline
  anatomy, ADR-0002/0053/0056, P33). End-to-end execution out of scope per ch.00.
