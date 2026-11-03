# GameFrame's toolkit: 100+ tested tools and the tests that prove them

> Part of the [game-frame overview](README.md). This chapter covers the
> `tools/` tree in full — every family, every file, the mechanics of the key
> instruments — plus the `tests/run.sh` self-test harness and the sample
> games it proves the tools on. Ghidra *launcher* semantics (`scripts/
> ghidra-run.sh`) and the CLI internals live in ch.34/ch.31; this chapter
> covers the tool-side surface. All citations are clone-relative `path:line`
> at HEAD `f195a074`, verified by opening the file at that line; counts state
> their command.

## 1. Tool doctrine: one tool, one question, `--help` as the contract

**The count.** `find tools -type f | wc -l` = **158 files** across **14 families**, **23,475 lines**
(ch.20 §8; re-verified this session). Breakdown: 146 `.py` + 9 Ghidra `.java` + one `.c`
(`live/winput.c`), one `.rs` template (`dos/templates/pascal.rs`), one `.json` config. Of the 141
non-`__init__` Python files, **93 carry an `if __name__ == '__main__'` block** and 48 are libraries
or helpers the programs import; add the 9 Ghidra jobs and the 15 top-level `scripts/*.sh`, and the
runnable instrument count is ~117 — the "~100 tools" claim is a round-down, not a stretch.

**The rules that make a tool a tool** are `AGENTS.md` rules 2 and 3: "Every tool is tested. A new
or changed tool gets a check in `tests/run.sh` against the sample game" (`AGENTS.md:36-37`) and
"Every tool documents itself. A module docstring or header comment with usage, inputs, outputs and
**what it does not do**; `--help` or no arguments prints it" (`AGENTS.md:38-39`). The negative
section is mandatory doctrine, not style: the docstrings quoted throughout this chapter show nearly
every tool carries an explicit "What it does not do:" paragraph.

**The index is the filesystem.** `tools/gameframe/catalog.py` finds tools "on disk, each with the
help it carries" (`catalog.py:1`), classifying each as `program` (a Python file with a main block),
`library`, `script` (in `scripts/`), or `ghidra` (`catalog.py:7-10`), and pulling the one-line
summary straight out of its docstring header (`headers.py`). The CLI exposes it: `./gameframe tools`
lists every tool and script (`__main__.py:107`), `./gameframe tool NAME` prints one tool's own help
(`:109`), and `./gameframe find WORD` says which skills and tools mention a word (`:112`). There is
no separate tool manual to drift — the help *is* the manual, generated from the file.

**Model-powered tools follow the same doctrine with a gate.** `tools/llm/` is documented as
"GameFrame's model-powered tools": the shared client defaults to a **local model**
(`GAMEFRAME_LLM_ENDPOINT` + `GAMEFRAME_LOCAL_MODEL`); hosted use is **explicit and per provider**
(`GAMEFRAME_LLM_PROVIDER=anthropic|openai` swaps endpoint and key handling, and "Local mode never
sends a hosted key") — `tools/llm/client.py:2-24`. Nothing in the toolkit routes *translation*
through a model; §10 shows the LLM tools answer auxiliary questions only.

**vs calxgloss.** This is the exact collision point with calxgloss's closed seam: calxgloss answers
only seam-declared scan/query families (ADR-0054/0055) and lists ad-hoc per-address queries as open
roadmap P29 (`10-calxgloss-baseline.md:259-260, 299-301`). GameFrame's answer surface *is* ad-hoc —
`decomp_query.py`, `sigscan.py`, `triage/insns.py` etc. each answer one open-ended question about
whatever bytes the agent points at, and each is an independently testable program rather than a
crate-internal query family. One shape buys cacheability and coverage accounting; the other buys
composability by an agent.

## 2. `tools/ghidra/` — nine Java exporters and appliers

These are Ghidra `GhidraScript`s, not standalone programs: they run headless through
`scripts/ghidra-export.sh` (full analysis + export, 45 L) or `scripts/ghidra-run.sh` (one job on an
already-analysed project, "without analysing it again", 75 L — launcher mechanics are ch.34's;
the job names and file mapping are at `scripts/ghidra-run.sh:40-51`). Every file is Java; LOC total
635 (ch.20 §8). One line each:

| file | L | Question it answers |
|---|---|---|
| `ExportAll.java` | 50 | "What does the whole binary look like as text?" — the full export |
| `ExportAddressBatch.java` | 71 | "What do these N addresses mean?" — decompile arbitrary addresses, creating missed functions |
| `ExportAddressRefs.java` | 47 | "Who references this address, and from where?" |
| `ExportNamedFunctions.java` | 42 | "Which functions match these name terms?" |
| `ExportVtableSlots.java` | 46 | "What functions sit in these 64-bit MSVC vtable slots?" |
| `ExportCallArgs.java` | 183 | "What constant arguments does every call to these functions pass?" |
| `ExportDisasm.java` | 85 | "What are the actual instructions here, byte-for-byte?" |
| `ApplyLabels.java` | 58 | (write) "Apply my chosen names back into the program." |
| `AddMemoryBlocks.java` | 53 | (write) "Assemble this program from raw memory pieces." |

**The export text format** is the contract the rest of the toolkit parses. `ExportAll.java:2-8`
enumerates it verbatim: `OUT/<program>/decomp.c` — "every function's pseudocode, each headed
`// ==== <addr> <name>`"; `functions.tsv` (address, size, name, thunk flag); `bodies.tsv` — each
piece of each function, "a function's body can be several pieces apart"; `strings.txt`;
`imports.txt` (`library!function`); `exports.txt`. `triage/coverage.py`, `decomp_query.py`,
`exportcov.py` and `cite_labels.py` all parse exactly these files, and
`ghidra-export.sh:43` reports exports by counting `^// ==== ` headers — the header line is the
record separator *by design*.

**The label round-trip is the distinctive move.** `ApplyLabels.java:2-10`: a `labels/names.tsv`
(address, label, evidence) makes executable addresses into named functions (creating functions
Ghidra missed, disassembling if needed) and non-executable addresses into primary symbols; "It does
not set types, parameters or comments" is the declared negative. `ghidra-export.sh --labels FILE`
inserts `ApplyLabels.java` as a pre-`ExportAll` postScript (`ghidra-export.sh:23`), and
`ghidra-run.sh:21-22` warns that labels "saves the project, so export again after it". This is the
write-back calxgloss refuses to do — names land in the analysis program itself
(`10-calxgloss-baseline.md:321-325`).

**`ExportCallArgs.java` is the deepest of the nine** (183 L). Its header (`:1-19`) states the use —
"Answers 'every sound the game plays and its id', 'every file it opens', 'every random draw and its
range' in one pass" — one TSV line per call: callee, call address, calling function, arguments. It
works on the **decompiler's P-Code, so it is processor-independent** ("the same for x86, 68000,
MIPS", `:13-14`). The `regs=SPEC` mode (`:16-19`) handles arguments the decompiler drops under a
wrong calling convention (Watcom, hand-written asm): it walks back within the same basic block to
the last writer of each register (`mov REG,imm`, `xor REG,REG`, `lea REG,[address]`), reporting `?`
when a register is written another way — "It does not follow values across jumps or calls" is the
honest bound.

**`AddMemoryBlocks.java:1-12`** builds a program from raw pieces — booter load maps, unpacked dumps,
console ROM banks, run-time overlays — one TSV line per piece (file, address, offset, length, name,
optional `code` to disassemble a function there), with overlapping pieces becoming Ghidra *overlay*
blocks; segmented 16-bit addresses take Ghidra's `1000:0000` form. **`ExportDisasm.java:9-17`**
exists for the case where "pseudocode is not exact enough": per-instruction listings over
`START-END` ranges decoded in order even across non-function gaps, undecodable bytes printed `??`,
for "checking arithmetic, flags and instruction counts against a port."

**`fill-gaps` is a script-level job, not a tenth file**: `ghidra-run.sh:16,28-32,56-73` maps it to
`ExportAddressBatch` over the starts that `tools/triage/exportcov.py --starts` wrote, then re-runs
`ExportAll.java` into `analysis/export` so the export files themselves absorb the recovered
functions, printing "fill-gaps: N of M starts decompiled" (`:70`). The triage→Ghidra→triage loop is
closed: exportcov finds the gaps, fill-gaps closes them, exportcov re-runs "to see what is left."

## 3. `tools/triage/` — the biggest family: first looks on any binary

30 files, 4,978 lines — the largest family, and the one an agent touches first (ch.20 §8). Every
file, one line each, LOC from the ch.20 §8 walk:

| file | L | Question it answers |
|---|---|---|
| `axes.py` | 167 | "Which axis is up, which way is forward, is it mirrored?" — fits a `memrec.py` recording against level vertices |
| `binview.py` | 147 | "What does this file *look like*?" — one pixel per byte, colour by byte class or entropy, Hilbert or row layout |
| `buildid.py` | 204 | "Which build of this game am I holding?" — every version claim in files, images or one executable, written into `docs/versions.md` between marker comments |
| `cite_labels.py` | 264 | "What names does the port already know?" — turns every `/// Original: FUN_…` citation in the reimplementation into a labels TSV |
| `compare_trees.py` | 112 | "Are these two copies the same program and data?" — path-matched (case-blind) SHA-256 tree diff, `--similar` pairing renames |
| `constants.py` | 203 | "Which RNG / CRC / hash / cipher / maths trick is in here?" — magic-number scan that lands the address of the algorithm |
| `coverage.py` | 145 | "How much of the original's code does the reimplementation cite?" — citations vs the Ghidra export's function set |
| `coverdiff.py` | 118 | "Which code runs only when the player does X?" — diff of two drcov-format coverage runs (DynamoRIO/Frida/Lighthouse) |
| `dates.py` | 136 | "Where is that timestamp stored?" — every offset scanned in ~10 date formats, kept only if near a human-known date |
| `decomp_query.py` | 309 | "What do these addresses/functions mean?" — ad-hoc queries over the Ghidra export without re-entering Ghidra |
| `deviations.py` | 133 | "Where do we knowingly differ from the original?" — one ledger from every `Deviation:` / `not ported` comment |
| `dictionary.py` | 158 | "Is our data dictionary well-formed, and what does it say?" — ten-column `labels/dictionary.tsv` validator/table |
| `exportcov.py` | 186 | "How much code did the Ghidra export cover, where are the gaps, and where do missed functions probably start?" |
| `filetypes.py` | 184 | "What is each file, from its bytes alone?" — magic, size, whole-file and per-block entropy |
| `fixity.py` | 143 | "How do we prove this copy is unchanged for years?" — BagIt bags, manifests, tag manifests, verify |
| `hashnames.py` | 252 | "Which name does that hash constant stand for?" — hashes every candidate string with every common function, picks the function with the outlier match count |
| `insns.py` | 90 | "Where are all the `in`/`out`/`int 0x21`/`rdtsc`/far-call instructions?" — capstone regex scan of PE or MZ code |
| `match_functions.py` | 202 | "Which function in build B is this build-A function?" — export-to-export matching, carries labels across with the match as evidence |
| `memscan.py` | 140 | "Where does the game keep that value?" — Cheat-Engine-style equality/change/up/down filtering over dumps |
| `needs.py` | 186 | "What does this game need to run?" — CPU features, APIs, extenders, DRM, media, each with its evidence line |
| `needs_signs.py` | 77 | (data) the sign tables `needs.py` reads — imports, sections, files, strings → `kind:value` needs; "keep them stable" (`:1-5`) |
| `pointerpaths.py` | 115 | "How do I reach that moving value from a fixed global?" — pointer-chain search to depth 4 by default |
| `refs.py` | 159 | "Which instructions refer to this address?" — raw-byte scan (works in functions or in none), classifies read/write/value, `--near N` for table±k |
| `report_issue.py` | 134 | "What has the port reported hitting as unported/crashed?" — lists `gameframe-report` JSONs, files one GitHub issue per place |
| `screenmarks.py` | 96 | "Are these 3D memory positions really those pixels?" — projects points by view+projection matrices onto a screenshot as SVG |
| `sentences.py` | 160 | "What text did a person write for the player?" — long-string extraction, min-words, story order by address |
| `sigscan.py` | 259 | "Where is this already-named function in that other binary?" — make/scan wildcard byte signatures |
| `similar.py` | 130 | "How alike are two files, short of identity?" — context-triggered piecewise hashing, score 0–100 ("GameFrame's own implementation, and its scores are not ssdeep's", `:24`) |
| `tables.py` | 152 | "How exactly was that sine table generated?" — searches parameterised table shapes; rounding mismatches listed so you copy the table instead of recomputing |
| `versiondiff.py` | 213 | "What changed between two editions?" — folder-vs-folder or disc-vs-disc, Markdown for `docs/versions.md`, PE link dates, language inventory |

**`decomp_query.py` is the ad-hoc query surface calxgloss doesn't have** (§1). Its nine commands
(`fn · callers · callees · find · strings · writers · layout · biggest · stats`,
`decomp_query.py:5-17`) all parse the export text, not a live Ghidra program: a
`HEADER = re.compile(r'^// ==== ([0-9a-fA-F:]+) (.*)$')` scanner (`:39`) splits `decomp.c` into
functions, and `FUN = re.compile(...)` (`:40`) handles both flat `FUN_1400be770` and 16-bit
segmented `FUN_1000_873a` address dialects (`:19-20, 53, 100`). Label precedence is a documented
cascade — `labels/<binary>.tsv` (per-binary, read first for overlapping overlays/DLLs), then each
`--labels FILE` (first to name an address wins), then `labels/names.tsv` in the project, then the
project's, then GameFrame's own (`:22-26`) — and output renders FUN_ names *replaced by labels with
the original kept in a comment* (`:131`), so the answer already reads like the project's vocabulary.
Some commands do real static analysis over pseudocode: `writers OFFSET` matches stores of the form
`+ OFFSET) = ` (`:259`); `layout FN[:VAR]` mines a struct's fields out of the cast/offset
expressions in the functions that use it (`:159`) and prints "a C struct to start from" (`:14-15`).
This is calxgloss roadmap P29 territory (ad-hoc call-path/def-use queries) existing as one plain
script (`10-calxgloss-baseline.md:260`).

**`sigscan.py` vs calxgloss's libmatch.** Both attack the same problem — recognising compiled code
from bytes — but the databases point in opposite directions. calxgloss `calxgloss-libmatch` ships a
built-in known-symbol DB (CRT/STL body signatures) and files body matches as read-only,
confidence-scored evidence with no write-back (`10-calxgloss-baseline.md:127-135`). `sigscan.py`
ships *no* known-symbol DB: `make` generates signatures from functions **you** have already named,
and `scan --labels OUT.tsv` writes matches straight back as a labels file for
`ghidra-run.sh labels` (`sigscan.py:5, 15`) — evidence with a write-back path, the inverse trust
decision (lineage stated in-file: Cifuentes's dcc and IDA FLIRT, `:27-28`). Mechanically, `make`
disassembles the function with capstone and wildcards exactly the build-dependent bytes: call/jump
immediates, 4-byte immediates inside the plausible address range, ≥4-byte displacements, and every
byte the PE base-relocation table lists (`sigscan.py:173-207`, reloc table read at `:70`); `scan`
anchors on the longest fixed run (`anchor()`, `:139-151`), requires ≥3 fixed bytes, then confirms
the wildcard match per byte (`:153-170`), and repeats are reported because "a match is a lead: two
different functions can begin with the same bytes" (`:28-29`). `tools/dos/omf.py` supplies the
compiler-library variant of the same file format (`:10`).

**`exportcov.py` is the completeness instrument, and it feeds a repair loop.** It computes the share
of PE executable-section bytes lying in some function, using `bodies.tsv` pieces rather than entry+
size runs when available, because multi-piece function bodies would otherwise be undercounted
(`exportcov.py:8-9, 41-45`). For each gap larger than padding it proposes *likely function starts*
by three heuristics: `E8 rel32` call targets landing in a gap; gap-first instructions on 16-byte
boundaries or at known prologues after nop/int3 padding; and the first instruction after a `ret`
(C3/C2) plus padding (`:19-24`). The stated motivation is a real measured case: "In one 1997 game a
quarter of the code section was outside every function after the first export" (`:31-33`, citing
`docs/knowhow/decompile-missed-pointer-functions.md`) — Ghidra follows direct calls only, so
pointer-reached code (vtables, handler tables, callbacks) hides. `--starts FILE` writes the
candidates; `ghidra-run.sh fill-gaps` runs them through `ExportAddressBatch` and re-exports
(§2); the docstring closes the honesty loop: "The starts are candidates, not proof" (`:37`) and
`--min PERCENT` (default 90) "exit 1 when the coverage is below" (`:16`) — a machine-checkable
gate, the closest thing in the repo to a whole-binary completeness metric.

**Port-coverage accounting is text, by doctrine: `coverage.py`, `cite_labels.py`,
`deviations.py`.** The re-port rule is that every ported item names its original in a comment
(`/// Original: FUN_1400be770`), so "how much of the original has been ported" is measured by
*citation matching*, not code comparison. `coverage.py:24-26`: a function counts as cited when the
sources contain `FUN_<hex>` or `0x<hex>` (16-bit `1000:873a` form included) or its labelled name in
backticks after `Original:`; thunks drop from the totals; the headline number is **share by size**,
"which says more than the count: a thousand small getters are less work than one large update"
(`:27-29`). Its declared negative is load-bearing: "What it does not do: decide whether a cited
function is fully reimplemented" (`:30-31`) — citation means *somebody ported from it*, nothing
more. `cite_labels.py:8-11` runs the same text in the other direction — the port's citations become
a labels file, so knowledge gained during porting flows back into the Ghidra program.
`deviations.py` builds the ledger of *known-wrong*: comment blocks containing `Deviation:` or
`not ported`, grouped by file (`:1-6`), with `--check` exiting 1 when the written ledger is out of
date "for tests and CI" (`:14`) and the admitted weakness "It does not judge the comments" (`:24`).
Together the three are calxgloss's unknown-records system (`ADR-0053/0056`,
`10-calxgloss-baseline.md:190-196`) re-expressed as greppable comment conventions: both make
gaps first-class records; calxgloss types and closes them in a database, game-frame keeps them in
the source text itself.

The rest are compact instruments: `memscan.py`/`pointerpaths.py` locate values in dumps
(the offline twin of §7's live tools); `insns.py`/`refs.py` scan raw code bytes independently of
any decompiler and name hits through `functions.tsv` when given one; `screenmarks.py` is an
evidence device — "If the circles sit on the objects, the positions, the matrices and their layout
are right. If they do not, one of the three is wrong" (`:8-10`); `fixity.py`, `compare_trees.py`,
`versiondiff.py` and `buildid.py` are the preservation layer, and note the legal nuance built into
`compare_trees.py:11-12`: "hashes are not game material" — the checksums pin a version without
committing the bytes, consistent with AGENTS rule 1 (`AGENTS.md:30-34`).

## 4. `tools/emu/` — Unicorn ground truth (PE and DOS)

17 files, 2,513 lines (ch.20 §8): the execution layer that turns "what does the original do?"
from inference into measurement. One line each:

| file | L | What it is |
|---|---|---|
| `pe_emu.py` | 349 | Call functions inside a Windows **x64** EXE/DLLs under Unicorn — the ground-truth oracle |
| `pe32_emu.py` | 300 | The **x86** twin, built for hand-written asm that passes arguments in registers (EDI/ESI-style span fillers, mixers), "MMX and x87 included" (`:4-6`) |
| `fragments.py` | 201 | Capture before/after state pairs of a DOS program's main loop from one headless run, for fragment-level port verification |
| `mem_trace.py` | 161 | Emulator-side taint analysis: which instructions read/wrote marked bytes, with copy-following |
| `call_trace.py` | 60 | Record calls to chosen functions (the RNG!) in order with call sites — the RNG-draw recorder |
| `dos_emu/__init__.py` | 88 | The 16-bit counterpart: NE (protected mode, Ghidra selectors) and MZ under Unicorn |
| `dos_emu/loader.py` | 166 | NE/MZ loading: segments, selectors "as Ghidra numbers them", relocations, import stubs, constant imports |
| `dos_emu/memory.py` | 131 | Selectors/bases, FarPtr reads/writes, script-allocated segments, registers, stack |
| `dos_emu/run.py` | 181 | Pascal/C calls, fragments between addresses, run slices with interrupt delivery, import stubs, stopping |
| `dos_emu/trace.py` | 48 | The 16-bit call tracer ("as `tools/emu/call_trace.py` does for x64", `:11-12`) |
| `dos_emu/types.py` | 60 | Shared names: registers, address constants, `FarPtr`/`Long` argument types |
| `dos_env/__init__.py` | 108 | "A small DOS, BIOS and PC … so a whole 16-bit program can run headless" (`:1-2`) |
| `dos_env/dos.py` | 202 | INT 21h: files from a read-only root with a write-overlay, find first/next, vectors, exit |
| `dos_env/dpmi.py` | 134 | INT 31h DPMI host + KERNEL/RTM imports; some semantics "inferred from how Borland Pascal 7's heap manager calls them (Tyrian 2000, 1040:0433…)" (`:2-4`) |
| `dos_env/bios.py` | 128 | INT 10h/16h/33h/2Fh/1Ah, BDA, PSP |
| `dos_env/keyboard.py` | 86 | Scan codes on port 0x60 delivered as IRQ 1 through INT 9, scripted (`key_script`) |
| `dos_env/pc.py` | 110 | Ports: VGA status, DAC, PIT, PIC, joystick, SB, AdLib; timer IRQ; screenshots |

**How PE is loaded and made callable** (`pe_emu.py:14-25`): every module maps at its preferred base
(or relocates when two overlap) written "as the Windows loader would"; each import links to an
export of another loaded module by name or ordinal; **every other import becomes a stub that runs a
Python handler**, `CRT_STUBS` ships working handlers for malloc/memcpy/strlen and no-op kernel32
locks (`:339-349`) — and "an import with no handler stops the run with its name, so you know
exactly what to stub next". The declared negatives are equally pointed: no DllMain, no TLS, no
threads, no files, no Direct3D (`:27-29`). Calls follow the x64 convention exactly (rcx/rdx/r8/r9,
`F32`/`F64` wrappers into xmm0–3, 32-byte shadow space, `:20-24`), and there's a TEB with GS base
so thread-local reads work (`:18-19`).

**The oracle discipline** is what makes this ground truth rather than a sandbox. Inputs are pinned:
the caller allocates buffers (`emu.malloc`/`alloc`), writes them byte-for-byte, and passes literals
— nothing ambient reaches the routine (no wall clock, no files by default). `pe32_emu.py:26` makes
repeatability explicit: "`reset()` puts the image's data back and clears the allocator, so each
trial starts from the same state". Outputs are read back as exactly typed views: `f32s(addr, n)`
(`pe_emu.py:235`), register dicts, `get(addr, '<i')` field reads. Two details show how seriously
bit-exactness is taken: the **x87 starts as Windows starts a program** — control word 0x037f,
because "Unicorn alone starts at 0, which rounds every result to 24 bits" (`pe32_emu.py:21-23`,
citing `docs/knowhow/unicorn-fpu-starts-single-precision.md`) — and calls can pass `fpu_cw=0x0f7f`
when the original's float→int conversion uses truncation ("the 'magic number' fadd of 1.5×2^68",
`:37-39`). Watcom quirks are handled too: zero-vsize sections from raw sizes, `file_pointer == 0`
.bss zeroed not filled (`:17-19`, `docs/knowhow/pe-bss-file-pointer-zero.md`). `until=ADDR` stops
before a library call so its argument register/stack contents can be read as the oracle for that
call (`:41-43`).

**RNG draw recording is a first-class oracle.** `call_trace.py:2-5` states the doctrine: "most
'almost right' reimplementations of a simulation draw random numbers in a different order or
count" — so `CallTrace(emu, {export: label})` records **one line per draw in order**, call sites
included, "only outermost calls … as the port would count one draw" (`:12-13`), and the port's
draws are recorded the same way and diffed with `tools/verify/seqdiff.py` (§6). Same recorder in
16-bit (`dos_emu/trace.py:11-12`). `mem_trace.py:2-4` does the Pin/DynamoRIO taint trick "done on
the emulator instead of a live process", with `follow_copies=True` re-marking destinations written
by a copy (`:12-13`).

**Whole-program DOS execution** is layered: `dos_emu` runs the program (NE in protected mode with
Ghidra-numbered selectors — `selector(n) = FIRST_SELECTOR + 8*(n-1)`, `dos_emu/memory.py:13-15`;
MZ in real mode; `run_range` entry-to-address, `run_to_any` first-of-several ends,
`dos_emu/__init__.py:11-13`), and `dos_env` supplies a deliberately *finite* machine: root files
read-only with writes diverted to an overlay and later opens reading the overlay copy
(`dos_env/__init__.py:16-18`), **fixed clock `env.clock` "so runs repeat exactly"** (`:19`), VGA
status alternating "so retrace waits end" and a tick counter that advances one tick per 128 reads
"so wait-for-the-next-tick loops end" (`:21-26`) — a determinism-by-construction emulator where
every ambient source is either frozen or scripted, and every port write is counted in `env.ports`
(`:24`). `fragments.py` then cuts the loop into verifiable units: each fragment saves program state
at START and END, and "a port of the fragment loads `before`, runs, and must give `after`"
(`:7-9`).

**vs calxgloss (Wine comparison).** GameFrame's emulator is the analogue of calxgloss's Wine
harness, and the differences track their parity bars exactly. Wine runs the original DLL *as a
Windows would* — real loader, real OS services — and the harness captures return values plus the
ordered API-call trace the original made, judging *observable behavior* and trace containment
(`10-calxgloss-baseline.md:170-185`). Unicorn here runs the original *function or fragment* with no
OS at all — imports are Python stubs and unhandled imports *stop the run* — because the bar is
*bit-exact machine state*: x87 control words, MMX, register-level calling conventions, and ordered
RNG streams that a Wine-level harness would never pin down. Each measures what its project promises
to rebuild: calxgloss promises cross-platform Rust with equivalent observable behavior, so OS-level
fidelity is the right oracle; game-frame promises an identical simulation core, so CPU-level
fidelity is the right oracle — and note the direction of cost: Wine fidelity comes free with less
control, Unicorn control comes with a stub-writing tax (the `stubs=` and `hook_export` surfaces
exist to pay it knowingly).

## 5. `tools/formats/` — decoder scaffolding and byte-accounting proof

15 files, 2,514 lines. The family's centre of gravity is a doctrine stated in `reader.py:1-11`:
"Write the decoder here first, run it over every file of its type with validate.py, and only then
port it to the reimplementation's language." One line each:

| file | L | Question it answers |
|---|---|---|
| `reader.py` | 138 | (library) "How do I read this format without lying to myself?" — bounds-checked LE/BE/LEB128/bit reads + `done()` |
| `validate.py` | 85 | "Does the decoder read every byte of **every** file — and write it back identical?" |
| `catalog.py` | 215 | "What is every file of the game, and what do our decoders make of it?" — HTML page + JSON manifest, marked as game material to keep out of git (`:8-9`) |
| `skeleton.py` | 246 | "Where are the skeletons/poses?" — parent-index arrays (root `-1`, parents before children) and unit-quaternion runs |
| `xorscan.py` | 276 | "What is the obfuscation key?" — single byte, repeating key, byte add, stepped key, byte-chain XOR, with known-plaintext anchors and `--apply` |
| `swfinfo.py` | 251 | "What is this Flash/Director file?" — SWF tags, projectors (SWF inside an .exe), Director detection |
| `shaders.py` | 175 | "Which compiled shaders (D3D9, D3D10-12, SPIR-V) or shader sources (GLSL/HLSL/ARB) are inside this file?" |
| `shadetable.py` | 139 | "How does the palette game shade?" — remap/fog tables: black level, identity level, fade colour |
| `rawimage.py` | 198 | "Do these bytes make a picture?" — raw VRAM → PNG across period pixel layouts |
| `pcap.py` | 161 | "How did the clients and server actually talk?" — pcap/pcapng → flows, messages, streams |
| `fields.py` | 150 | "Which byte offsets in these records are constant / counters / lengths / kind-selectors?" |
| `derived.py` | 129 | "Which unexplained fields next to geometry are computed from it (bounds, centres, normals)?" |
| `pngio.py` | 127 | (library) PNG read/write, standard library only |
| `timestamps.py` | 129 | "What time is this number?" — every common timestamp kind, or scan a file for them |
| `markers.py` | 95 | "Where does each byte of this save file land in memory?" — plant unique values, find them in dumps |

**The byte-accounting mechanics — how "proved to read every byte" is actually enforced**
(`reader.py`, `validate.py`, read in full this session):

1. **Every read is bounds-checked and position-tracked.** `Reader._take(n)` refuses any read that
   "passes the end" and the error names the file, the position, and the limit
   (`reader.py:28-33`); the reader carries `(pos, end, name)`, so a failure says *which* sub-block
   failed.
2. **`done()` is the accounting assertion.** `reader.py:135-138`: if `pos != end` it raises
   `FormatError` reporting "N bytes left unread at POS" **plus a 16-byte hex preview of what was
   missed** — an unread tail is not a silent success, it is a named, previewed defect. The
   docstring is blunt about the point: "raises if any byte is left: a field you have not found
   yet" (`reader.py:8`).
3. **Nesting localises the accounting.** `r.block(size)` returns a sub-reader with its own `end`
   (`reader.py:126-129`), "so a decoder can check that each section is consumed exactly" —
   section-level completeness, not just whole-file.
4. **`validate.py` quantifies the claim over a corpus.** It imports a decoder exposing
   `decode(reader)`, runs it over **every file matching the glob**, calls `r.done()` after each,
   and prints "N of M files decode completely", exit 1 on any failure
   (`validate.py:1-9, 87-88`). The corpus is the point: "A decoder is right only when every file of
   its type passes: one sample is not enough, because optional fields and version differences show
   up in a few files only" (`:7-8`).
5. **`--write` raises the bar to round-trip identity.** With an `encode(result)`, each file is
   decoded, re-encoded, and compared byte-for-byte; a mismatch reports the first differing offset
   and both byte values, plus lengths in/out (`validate.py:10-13, 66-73`). The rule: "A reader is
   a writer only when every file of the player's copy comes back identical … Change one value only
   after that" — the discipline that prevents a decoder from quietly *normalising* data it did not
   understand (citing `docs/knowhow/writer-round-trip-every-file.md`).

Note what this proof is *not*: it proves the decoder's byte accounting, not the decoder's
semantics — a field read as the wrong type can still consume the right number of bytes and
round-trip. Semantics get proven elsewhere: bit comparison against the original's rendering, or
emulator fragments (§4).

**`rawimage.py`** is the palette-era workhorse: seven pixel modes — `linear8`, Mode X `modex`
(4×64 KB planes), EGA/VGA `planar4`, `cga2` (even lines at 0, odd at 0x2000 — an actual dump of
B800:0000), `packed4/2/1`, `rgb565`/`rgb555` (`:7-16`) — with palette input as raw 768-byte DAC or
JASC `.pal`, and the subtle 6-bit-to-8-bit question called out explicitly: `--dac shift|scale`
("Many games shift; read the palette loader and use its rule when comparing pixels with the
original", `:26-28`). It doubles as a format detector — "A wrong width shows as slanted stripes:
change it until the picture stands straight" (`:31-33`).

**vs calxgloss.** calxgloss has a *serialization* evidence scan (one of the 15 engines,
`10-calxgloss-baseline.md:75-78`) that flags record-ish structure for the prompt, but no
equivalent of `validate.py`'s per-file byte-accounting gate and no decoder corpus to run it over —
its outputs are Rust functions judged by compile+behavior, not decoders judged on every artifact
byte. The formats family is what a byte-exactness doctrine looks like when wired into instruments.

## 6. `tools/verify/` — differential comparison instruments

4 files, 373 lines. These convert "the port looks right" into a diff with an exit status:

| file | L | Question it answers |
|---|---|---|
| `bitcompare.py` | 50 | "Do these two buffers match value-for-value, **bit for bit**?" |
| `seqdiff.py` | 53 | "In which event do the original's and the port's ordered traces first diverge?" |
| `replay.py` | 143 | "Does the port's state-by-state trace agree with a live recording of the original, sample by sample?" |
| `ramdiff.py` | 127 | "Which frame, and which addresses, is the first where the port's memory stops matching the original's?" |

**`bitcompare.py` defines what bit-exact means, in code** (`:5-10`): floats are compared by their
raw bits — "0.0 and -0.0 differ and NaNs compare equal only when identical, which is what
bit-exact means". On mismatch it reports the count, the first N offenders with indices, and for
floats **the largest difference in ULP**, with the diagnostic reading built in: "1 ULP usually
means one operation in a different order or precision; large differences mean a wrong formula or a
wrong input." Exit 1 on any mismatch — the gate shape.

**`seqdiff.py` is the first-draw-differs instrument.** Fed two `label<TAB>where` traces (the
original's from `call_trace.py`, the port's written in the same format), it compares only the
first field by default "since the call sites differ by nature" (`:8-9`) and prints the headline
sentence the workflow is named for: "the first N events match; event K differs" (`:36`), with
five lines of context from both sides aligned, then exit 1. Length mismatch is its own finding:
"the first n events match; then only the original goes on" (`:33-35`) — a port that draws fewer
times fails even when every draw it does make agrees.

**`replay.py`** compares *sampled live truth* against the port: a `memrec.py` JSONL recording vs
the port's per-step trace, aligned on `--clock` "the game's own clock or frame counter" (`:8-9`),
with `--block` forcing values read together to hold in one port state ("a sample passes only when
one port state holds all of them", `:13-14`) and `--require NAME=RATE` pinning rates. **`ramdiff.py`**
is the same idea at whole-memory scale: frame-ordered snapshots from an emulator script vs the
port's same-layout dump, reporting "the first frame where they differ is where the port went wrong"
(`:10-11`), with `--ignore` ranges for known-divergent regions (the deviations ledger, §3).

**vs calxgloss.** These are the instrumentised form of game-frame's parity bar, and calxgloss
deliberately does not have them: its verification is behavioral-value + ordered-API-trace
*containment*, because "functional equivalence over binary precision" is principle 1 and
float-ULP-level agreement across platforms is unattainable by design
(`10-calxgloss-baseline.md:34-37, 176-185`). The instruments are structurally identical —
first-divergence + context + nonzero exit — and differ only in what equality means.

## 7. `tools/live/` — observing the running original

14 files, 2,745 lines — the counterpart to §4: instead of running a function in a sandbox, watch
the real game run (under Wine on Linux, or in a VM) and measure it from outside. One line each:

| file | L | Question it answers |
|---|---|---|
| `memrec.py` | 244 | "What are the game's live values, over time?" — snapshots + named-value recordings from `/proc/PID/mem` |
| `memlog.py` | 103 | "What does that recording say?" — summary/CSV/sample-at-time readers |
| `align.py` | 264 | "Where in this screen capture is that reference screen?" — offset+scale with a saved mapping |
| `gdbremote.py` | 373 | (library) GDB remote-protocol client: registers, memory, `run_to`, watchpoints, `libraries()` |
| `winegdb.py` | 262 | "What is the game doing right now?" — attach via winedbg's GDB server: regs/read/break/watch, "always detach so the program runs on" (`:1-2`) |
| `harness.py` | 222 | "Which modules does this game need to run?" — plans a runtime + per-need layers, keyed to `needs_signs.py` |
| `emupc.py` | 205 | "How do I get a clean disposable PC for this game?" — QEMU+Debian+Wine+Xvfb file generation, base image never written (`:11-12`) |
| `frida_trace.py` | 190 | "In what order does the running game call these functions, with what arguments?" |
| `emulock.py` | 102 | "Who owns the emulator right now?" — take/show/free locks "so two sessions do not drive one game at once" (`:1-2`) |
| `shot.py` | 99 | "Keep this screen capture under a name; never overwrite one" (`:1-2`) |
| `modfolder.py` | 110 | "Put my changed files into the install, and take them out again" — install/list/clear |
| `loopcut.py` | 75 | "Cut a recording to one closed loop" — a lap, a patrol |
| `winput.py` + `winput.c` | 105+391 | "Drive the game's inputs programmatically" — a Zig-cc-built Wine helper: keys, mouse, waits |

**`memrec.py` is the value-location/recording spine.** Three verbs (`:4-7`): `snap` copies every
writable mapping (`rw` in `/proc/PID/maps`) to per-region dumps — the input side of the value hunt,
whose stated next step is exactly `tools/triage/memscan.py DUMP:RULE --base 0xSTART` (`:14-16`);
`record` samples named addresses at 10 Hz into the JSONL format every verifier consumes
(`{"t": seconds, "n": sample, "NAME": value or [values]}`), where SPEC lines give name, address,
type, count and stride — "eight cars' x positions: `car_x 0x61aad0 i32 8 0x558`" (`:22-23`);
`--wait ADDR=VALUE` starts the recording only when a phase flag matches (`:20`). The honesty block
is the interesting part (`:25-30`): "Nothing is injected. The game is not changed or slowed. Values
are kept as raw integers, so 16.16 fixed point is not rounded. **A sample is not atomic** … At
10 Hz an outside reader sees about one frame in eight" — the instrument's blind spots are written
into the tool, and `verify/replay.py`'s `--block` option (§6) exists precisely because samples
straddle frames. Process discovery survives restarts ("Found again on every poll, so a game that
restarts is followed", `:9-10`), and `--proc DIR` makes the whole thing testable against a fixture
folder of fake `/proc`s — which is how `tests/run.sh` exercises it hermetically (§12).

The other value-location tool is `triage/memscan.py` (§3): offline dump-diff filtering — the live
loop is `snap → memscan → pointerpaths → memrec record`, with `frida_trace.py`/`winegdb.py` as the
instrumented variant when injection is acceptable. `align.py` + `shot.py` + `modfolder.py` +
`winput.py` close the observe/act loop: capture, register against a reference, inject input
scripts, capture again — the playbook's "observe" step made mechanical.

## 8. `tools/pe/`, `tools/dos/`, `tools/disc/` — binary and disc metadata

**`tools/pe/` — 8 files, 1,008 lines.** Windows PE introspection that does *not* go through
Ghidra:

| file | L | Question / role |
|---|---|---|
| `peinfo.py` | 120 | "What is this PE, how was it built, what does it use?" — machine, base, sections, **PDB path and build date**, Rich-header compiler/linker hints, import counts, *engine fingerprints* (Unity, Unreal, FMOD, Steam, Denuvo) (`:2-9`) |
| `apitable.py` | 220 | "What are this 32-bit DLL's exports' conventions and argument bytes?" — reads them from the DLL's own code or an import lib's decorated names (`_ATI3DCIF_Init@0`) — this generated the wrappers' `.def` tables (ch.35) |
| `probegen.py` | 150 | "What does the game actually send to this DLL?" — generates a stand-in C library that logs every call |
| `peres.py` | 142 | "What's in the resources?" — version info, string tables, dialogs, icons; `--extract` with BMP headers |
| `stackstrings.py` | 140 | "Where is the text the file's string table doesn't show?" — recovers `mov`-immediate stack-built strings ("`mov dword [ebp-0x10], 0x45564153`", `:7-8`) |
| `relocs.py` | 115 | "Which data pointers exist?" — from the base-reloc table: runs of pointers are vtables/function/string/record tables — "A recursive disassembler misses functions reached only through such tables" (`:8-9`) |
| `vtable.py` | 66 | "What's in this C++ vtable?" — slots until a pointer leaves executable memory, named via `functions.tsv` + labels; the locator hint: the vtable is the last store to the object's first word in its constructor (`:8-9`) |
| `readdata.py` | 55 | "What value is really at this DAT_ global?" — typed reads at Ghidra addresses; "read it here rather than trusting the decompiler's typing" (`:7-8`) |

Debug-symbol posture: **MSVC PDBs are read shallowly** — `peinfo.py:61-63` prints the CodeView
debug-directory `PdbFileName` (that path often names the project, module, and build machine), but
nothing in `tools/` parses a `.pdb`. That's consistent with the doctrine — the PDB is *evidence
about the build*, while names come from the agent's own labels — but it means MSVC-symbol-rich
targets lean entirely on Ghidra for name recovery.

**`tools/dos/` — 10 files, 1,999 lines.** The 16-bit era, end to end:

| file | L | Question / role |
|---|---|---|
| `dosinfo.py` | 173 | "What is this DOS/Win3x binary?" — the 16-bit `peinfo`: format (MZ / NE / LE-LX extenders / PE), MZ load image + appended data (overlays, Borland .OVR, packed payloads), NE module name, per-segment Ghidra selector `0x1000 + 8*(N-1)`, imports by use-count, exports; **fingerprints** for compilers (Turbo/Borland Pascal, BC++, MS C, Watcom, DJGPP), extenders, packers (LZEXE, PKLITE, EXEPACK), middleware; `--pstrings` finds Pascal length-byte strings "Ghidra does not find … by itself" (`:16-18`); declared negatives: no unpacking, no resources, no LE/LX parsing (`:25`) |
| `tdinfo.py` | 430 | "Give me the original names" — reads **Borland Turbo Debugger symbols** (TDINFO, signature FB52): `labels` emits a full names TSV, `procs` prints parameters and locals *with their types* (`:2-7`) |
| `td_rust.py` | 282 | From those symbols, **generate Rust**: record-type structs with read/write, a `Globals` module with one file per Pascal unit at data-segment offsets, per-procedure locals structs at BP offsets (`:3-9`) |
| `ne.py` | 145 | (library) MZ/NE/LE/LX/PE loader shared by `dosinfo`/`readseg`/emulators; addresses "follow Ghidra" (`:8-9`); explicitly "does not parse resources, LE/LX internals or overlays" |
| `omf.py` | 199 | "Which runtime-library functions are inside the game?" — reads `.OBJ`/`.LIB` OMF libraries and emits one sigscan signature per public name (`:6-7`), so CRT code can be "left unread" |
| `nedis.py` | 87 | "Disassemble 16-bit code with relocations applied" — fixes `lcall 0:ffff` placeholders the way `dos_emu` loads them, names targets from labels |
| `readseg.py` | 109 | "Read typed values at seg:off" — the 16-bit `readdata`, incl. Pascal typed constants and far `ptr` (offset word then segment word) |
| `fileio_trace.py` | 144 | "How does the program read this file?" — DOSBox-X file logs → per-file read offsets/sizes/order: "The read sizes … are the file's record layout, measured" (`:2-4`) |
| `dbx_control.py` | 216 | Drive DOSBox-X's built-in debugger over its control channel (DOSBox-X 2026.10+, `mcp_server` setting) — "the script-facing side" of the same channel the optional `dosbox-x-mcp-server` provider uses (`:2-8`) |
| `templates/pascal.rs` | 214 | The Rust Pascal-type template `td_rust.py` fills in |

The debug-symbol split here inverts the MSVC posture: for Borland targets the embedded symbols
are read **fully** (`tdinfo.py` → labels, types, generated globals), because Turbo Debugger info
lives inside the EXE — `dosinfo.py:155-158` reports both kinds and marks the boundary honestly: a
CodeView trailer is announced as "not read by these tools".

**`tools/disc/` — 4 files, 762 lines.** CD images read in place, never extracted:

| file | L | Question / role |
|---|---|---|
| `image.py` | 180 | (library) tracks and sectors from CUE/BIN, raw BIN, or ISO; the 2352→2048 sector geometry (`:7-9`) |
| `volumes.py` | 281 | (library) file systems in a data track: ISO 9660 + Joliet, **High Sierra** (older than 9660), El Torito boot, HFS/HFS+ hybrid Mac/PC discs (`:1-4`) |
| `discinfo.py` | 200 | "What's on this disc?" — tracks, file systems, dates, files; `--map` lists sector runs that hold data but belong to no file (`:4-8`) |
| `checks.py` | 101 | "Does the mastered disc account for every sector?" — unused data, system area, files only one directory tree lists, dates later than the volume date — "Data outside all of them can be a file left over from development, a second copy…" (`:6-9`) |

`checks.py` is the disc-level cousin of `exportcov.py`: same instinct — a master *should* account
for every byte, and unaccounted bytes are a finding.

## 9. `tools/rea/` — the REA MCP bridge helpers

2 files, 413 lines. REA is the optional external analysis provider (ch.31/ch.34 for the enable
flow); these two files let **scripts** use it the way agents do:

- `rea_session.py` (279 L) — "REA on a game's binary from a script, with the project's labels and
  a saved snapshot" (`:2-3`). Three verbs: `snapshot` warms REA's Ghidra provider per address and
  persists an analysis snapshot so "the answers add up over runs" (`:12-14`); `fn` reopens from
  the snapshot, pushes the project's labels via `set_addresses_names`, and pulls per-function
  "dossiers" (size, referrers — "a vtable slot shows as data", callees, memory reads/writes)
  (`:16-21`); `labels` chunks the labels files for an agent's own session (`:23-24`). Label
  sources default to `labels/names.tsv`, `names-from-port.tsv` (the `cite_labels.py` output of §3!)
  and `labels/library.tsv`, filtered to the binary's ImageBase range, `::` → `__` for Ghidra
  (`:26-29`). It even carries measured cost facts: "REA 6.7.0, measured on a 2 MB x64 game: the
  first question of a session waits about 50 s" (`:31`).
- `mcp_client.py` (134 L) — a minimal stdio JSON-RPC MCP client so "a script and the agent run
  the same version" of a provider, read from `.mcp.json` via
  `./gameframe mcp-provider rea VERSION` (`:2-7`).

**vs calxgloss.** calxgloss runs its analysis engine (Kuna) fully in-process and has no MCP client
surface at all — its ADR-0039/0041 position (`10-calxgloss-baseline.md:255-257, 295-296`) is the
mirror image of a toolkit whose second analysis engine is literally a subprocess across a wire
protocol, snapshotted to disk.

## 10. `tools/llm/` — auxiliary model helpers, never the translator

9 files, 1,692 lines. The provider gate is `client.py` (§1 quoted its header): local endpoint by
default; `GAMEFRAME_LLM_PROVIDER=anthropic|openai|openai-compatible` opts into hosted, each with
its own model and key variables; "Local mode never sends a hosted key" (`client.py:19`); the
Anthropic protocol doubles as the headless Claude Code driver (`client.py:14-15`); declared
negative: "track provider spending or download models" is out of scope — `--budget`/`--max` instead
(`client.py:22-24`).

| file | L | Question it answers |
|---|---|---|
| `client.py` | 351 | (library) Which model/API am I talking to, and what may I send it? — the §1 gate |
| `name_functions.py` | 316 | "What might each unnamed function be?" — suggest name + signature + summary for every unnamed function |
| `ask.py` | 70 | "Has anyone hit this before?" — answer from `docs/knowhow/` entries only, citing each one; "When no entry fits, the answer says so, and the question may be a new gap" (`:12-13`) |
| `decision.py` | 194 | Bounded choice/yes-no/score questions to a configured "System One" decision endpoint (`GAMEFRAME_DECISION_ENDPOINT`), 2–24 options per question (`:4-9`) |
| `decision_feedback.py` | 264 | Store human corrections of decision answers per OS user and export a local SFT dataset; "It never records model responses automatically" (`:6-7`) |
| `skillcheck.py` | 119 | "Does each skill work on its own?" — give an agent one skill + a sample-game task from `tests/skill-tasks.json`, with a USD budget (default $1) |
| `headless.py` | 117 | Run one GameFrame agent through Claude Code with a USD budget (default $5); "Without `--write`, it can read and run commands only" (`:9-10`) |
| `locate.py` | 135 | Vision: find a screen element or reference screen in a capture — the `--ref` mode emits the same mapping JSON `align.py` consumes (`:8-10`) |
| `fake_api.py` | 126 | Test double: "A stand-in for the Claude API and the claude command, so the tests spend nothing" (`:2`) — serves `/v1/messages`, message batches, schema-filling answers |

`name_functions.py` is the largest and most disciplined: a prepare→submit→status→fetch→cancel
state machine where **`prepare` sends nothing** — "Read the count before you submit" (`:11-12`),
hosted batches default 200 requests (`:29`), submitting needs typed confirmation (`:38-39`). Its
key negative: "It never writes `labels/` and never applies names in Ghidra" (`:38-40`) — even the
one tool that *generates* names keeps them in `analysis/llm/…` for a human/agent to vet; applying
names stays `ApplyLabels.java`'s job, driven by the project's own `labels/names.tsv` (§2).

**The negative finding that matters for this dossier: none of `tools/llm/` translates or
decompiles code.** Exhaustive grep for `translat`/`decompil` across `tools/llm/*.py` matches
exactly one line — the name-suggestion system prompt ("You name functions in a decompiled game
binary", `name_functions.py:53`). There is no tool that turns pseudocode into a port. In
game-frame the translator is always the coding agent itself following the `re-port` skill; the
model-powered tools classify, name, locate, answer-from-knowhow, and check the playbook. That is
the exact inversion of calxgloss, where the local LLM *is* the load-bearing translator behind the
attempt seam (`10-calxgloss-baseline.md:286-294`), and it explains most of the other toolkit
choices: because no model output is auto-applied, there is no need for the per-attempt
compile/behavior/trace gate calxgloss runs inside the product — instead the *instruments* must be
right, which is what §12 is about. `fake_api.py` completes the picture: the LLM plumbing is tested
hermetically against a fake endpoint that "fills the schema" mechanically (`:8-11`), so the suite
never spends money or needs a model.

## 11. `tools/site/`, `tools/install/`, `tools/gameframe/` — plumbing

**`tools/site/check.py` (210 L)** — "Check a project's website before it is published: safe to
share, and useful to read" (`:2-3`). It polices the diary-per-milestone site shape that
`scripts/new-site.sh` scaffolds (ch.34): live entries `YYYY-MM-DD-HHMM-slug.md` vs one day post
per past day, and it can list past days still missing a day post (`--days`, `:6`). In a toolkit
where AGENTS rule 1 forbids game material, this is the instrument that keeps the *publishable*
artifacts publishable.

**`tools/install/` (5 files, 547 L)** — turns a built port into a player-openable application in
the GameFrame home: `install_app.py` (255 L) builds release programs and installs vanilla/extra
builds (`:2-8`); `places.py` fixes the per-OS split — programs in a GameFrame folder among the
system's apps, data in the user's own data folder, "so a new install never touches it" (the table
at `places.py:4-9`: `/Applications/GameFrame/NAME.app` vs
`~/Library/Application Support/GameFrame/NAME`, etc.); `macos.py` builds+ad-hoc-signs the .app
bundle ("not a Developer ID signature, so another Mac asks first", `:2-4`); `desktop.py` writes
`.desktop`/`.cmd` launchers and Start-menu shortcuts; `launch.py` solves the Finder/Start-menu
cwd problem — start in a writable data folder, `{data}`/`{resources}` argument substitution
(`:2-8`). This is the install side of the *frame* concept (ch.35); root `install.json` and
`examples/frame-demo` (§13) are its self-demonstration.

**`tools/gameframe/` (30 files, 3,086 L)** is the `./gameframe` CLI itself — commands, catalog,
MCP server, client emitters — covered in ch.31 (discovery CLI) and ch.34 (home layout, MCP);
counted here for completeness. Tool-relevant detail already used in §1: `catalog.py` +
`headers.py` are what make `gameframe tools|tool|find` work off the docstrings, and
`commands.py:1-4` states the no-duplication rule — "The text comes from the skills and the tools
themselves (catalog.py, skills.py); nothing here copies it."

## 12. `tests/run.sh` — the harness that proves the instruments

**Scale and shape.** `tests/run.sh` is 2,128 lines and *is* the harness (36 files in `tests/`,
ch.20 §10; re-counted this session: `find tests -type f | wc -l` = 36). It opens by stating its
own purpose — "Prove every tool in GameFrame's toolkit against the sample game. Run after
changing any tool" (`tests/run.sh:2`) — and the two modes:

> tests/run.sh            the fast checks (about 20 s): PE tools, emulator, call traces,
>                         ground truth against the port, format validation, the 16-bit DOS
>                         tools and emulator, project scaffold
> tests/run.sh --ghidra   also the Ghidra exports (Windows x64 and 16-bit NE), labels and
>                         decomp_query (about a minute more)   (`tests/run.sh:3-8`)

**Structure.** One file, one shell. Three primitives do everything: `ok`, `bad` (counters +
failure echo) and `expect "name" "expected-substring" command...` — run a real tool, assert its
output contains the string (`:19-24`). 36 named `echo "Group"` sections, ~340 `expect`/`ok`/`bad`
call sites (`grep -cE '^\s*(expect|ok|bad)'` = 340; ch.20 §10's counts — 335 lines contain
`expect`, 110 end in `&& ok`). Many groups end in one composite assertion that checks several
tools together, so the individual behavioural checks number in the hundreds. The whole run ends
`echo "$pass passed, $fail failed"; [[ $fail == 0 ]]` (`:2127-2128`) — pass/fail counters, exit
status, no framework.

**The 36 groups, in file order:** Building the sample game (`:26`); PE tools (`:29`); Input
inside Wine / winput (`:92`); Installing builds (`:234`); Live tracing (`:323`); Emulator
(`:342`); Ground truth and the port (`:572`); Formats (`:605`); 16-bit DOS tools (`:623`);
16-bit emulator (`:665`); Headless DOS environment (`:725`); Fragments of a main loop (`:759`);
DOSBox-X runtime (`:774`); Installers and releases (`:817`); Discs, file kinds, similarity,
obfuscation, timestamps (`:833`); Constants, resources, stack strings, Flash, function matching
(`:906`); Pictures, tables, signatures, pointers, markers, instructions (`:993`); Network
captures, fields, coverage, fixity (`:1045`); Reports to issues (`:1078`); Ledger and coverage
(`:1095`); Project scaffold (`:1114`); Project sites / re-site (`:1181`); Engine run-time: hashed
names, skeletons, structures, shaders, memory per frame (`:1249`); Gates (`:1300`); Releases
(`:1379`); Game folder gates (`:1413`); GameFrame home (`:1468`); Agent Skills (`:1503`); Claude
Code plugin (`:1525`); Help and discovery (`:1638`); Know-how (`:1663`); Crates (`:1855`);
Library page (`:1864`); Wrappers (`:1882`); Documentation site (`:1951`); API credit tools
(`:1982`); Screen alignment, needs and the harness (`:2035`); Ghidra (`:2086`, under
`--ghidra`, `if [[ "${1:-}" == --ghidra ]]` `:2085`).

**What `--ghidra` adds** (`:2085-2126`): a full real export of `game.exe` + `engine.dll`, then
`decomp_query fn/strings`, `coverage` against the real export, `ghidra-run decompile` (including
the honest failure case "reports a bad address and goes on"), `exportcov`, `callargs` (constant +
string arguments, and the `regs=watcom` register mode verified byte-exact in its own expect at
`:2104-2105`), `disasm` by name and by range, the 16-bit export with **TD-symbol labels applied**
("Ghidra numbers NE segments 1000, 1008"; "ApplyLabels creates a function Ghidra missed"
`:2113-2117`), and the showcase composite at `:2107-2112`: `mixer32.dll` hides a routine
(`hidden_triple`) with no prologue reached only through an XORed pointer — "Ghidra misses it,
exportcov finds it, fill-gaps makes it (a bad start does not stop the batch) and exports again" —
asserting the recovered function's body `param_1 * 3` appears in the re-exported `decomp.c`, a
deliberately bogus start `0xdeadbeef` still fails gracefully ("1 of 2 starts decompiled, 1
failed"), and `exportcov` then reports "0 likely function starts" left. That one block proves
§2 and §3's whole gap-repair loop end to end.

**Hermetic dependencies.** Needs `scripts/setup.sh --install` (the `.venv`: unicorn, pefile,
capstone) and **zig** to build the sample game — the *only* binaries ever tested are built from
`examples/` sources (`AGENTS.md:31-34`); if zig is missing the suite aborts immediately (`:27`).
Beyond that it isolates itself: its own throwaway GameFrame home so "the checks never touch the
real ~/gameframe" (`:17-18`); `tests/fixtures/rea/fake_rea.py` as the REA stand-in used through
the real MCP client path (`:38-46`); `tools/llm/fake_api.py` for the model tools — section
`"API credit tools (tools/llm), against fake_api.py: nothing is sent"` (`:1982`) drives naming,
schemas, batches, key isolation and the hosted-confirmation gate with zero API calls; install
tests fake `--system macos` into temp dirs (`:234-244`); `memrec` tests point `--proc` at a
fixture process tree. The heavier pieces degrade instead of failing: cargo-gated crate tests
"skip" when cargo is absent (`:1856, 1861`), DOSBox-X and live pieces run only when present. The
`Crates` group (`:1857-1859`) is the only one that shells out to `cargo test --release` — this
dossier did not execute it, per scope (ch.00).

**The release/version-gate tests** (the mechanics ch.21 documents) live here: `:1379-1411`
builds a throwaway git repo, runs `scripts/release.py 1.1.0 --no-next` and asserts plugin.json
version, tag, and CHANGELOG ladder were rewritten together; `:1533` (Claude Code plugin group)
asserts at repo HEAD that CHANGELOG's newest release equals plugin.json's version — the
`AGENTS.md:84` lockstep made machine-checkable. Also checked here: the gates engine (`:1300`),
the game-folder and delete gates (`:1413`), skill copy/symlink integrity (`:1503`), and the
help/discovery CLI (`:1638`) — including `gameframe tool ghidra-export` resolving a script by
name (`:1650`).

**This is calxgloss's P42 mirror image.** calxgloss has *no CI at all* and its absence is a
named roadmap item P42 (`10-calxgloss-baseline.md:199-200, 281-282`). game-frame's CI is local
and manual-by-convention (AGENTS rule 2: the suite "passes before you commit", `AGENTS.md:36-37`;
`.github/workflows/site.yml` builds docs only, ch.20 §16) — but it is an *executable* proof of
the instruments on checked-in targets, which is exactly the substrate shape P42 asks for. Note
what neither suite does: neither scores a model (calxgloss P33 open; game-frame has no model to
score); game-frame's suite proves tools+emulators+ports-on-samples, calxgloss's `cargo test`
proves pipeline internals. Same move — trust your instruments — different coverage.

## 13. The sample games — targets built to be reverse-engineered

**Why the suite can test anything at all.** AGENTS rule 1 forbids committing game material, so
`tests/run.sh` has exactly one source of binaries: "the *only* binaries ever tested are built
from `examples/` sources (`AGENTS.md:31-34`)" (§12). The example projects are therefore not
demos bolted onto a toolkit — they are synthetic RE targets, written so the ground truth is
known by construction and every tool's check has a literal expected string. **17 files, 1,361
lines, 108 KB** (`find examples -type f | wc -l` = 17; `find examples -type f -exec wc -l {} +`
= 1,361; `du -sh examples` = 108K — ch.20 §14's counts, re-verified this session).

**`examples/sample-game/` — the Windows x64 target (9 files, 397 LOC: per-directory
`wc -l examples/sample-game/*`).** "A tiny Windows x64 game, written in C for GameFrame, to
practise on and to test the tools", whose parts "are the parts a real game has" (README:3-6;
`game.c:1-3` says the same). Each part is an instrument's reason to exist:

- **Fixed-step update:** `game.c:48-58` — `simulate(seed, steps, out)` runs `steps` updates of
  `1.0f / 60.0f` with "random rain" that speeds growth (`rng_next(&rng) % 4 == 0` boosts `dt`,
  `:52-55`) and writes one f32 per step; "The result depends on every random draw, in order"
  (`:47`) — exactly the property §4's draw tracers and §6's `seqdiff.py` exist to pin.
- **RNG in a DLL:** the engine "export[s] by name, the way many game engines ship a runtime DLL
  beside the game executable" (`engine.c:1-2`) — an LCG with the MSVC `rand()` constants
  214013/2531011 (`:10-14`) and an `rng_float` whose op order is flagged for the porter: "note
  the order of operations, which a port must copy exactly" (`:16-18`).
- **Constant table:** `growth_table[4]` — "Constants a port must read from the binary, not
  guess" (`game.c:13-14`); `port.py:19` obliges: "read from the binary with
  `tools/pe/readdata.py`" (§8's tool).
- **Vtable object:** `Entity`/`EntityVtbl`/`tree_vtbl` (`game.c:16-36`) laid out "as C++
  compilers lay out virtual methods" — §8's `vtable.py` and §2's `ExportVtableSlots` target shape.
- **Data file:** `load_records` with magic `SMPL` and `(u32 id, f32 weight, u8 len, name)`
  records (`game.c:60-72`), written by `make_data.py:8-13`, decoded by `decode_sample.py` —
  §5's `validate.py` corpus of one, run at `run.sh:606`.

`build.sh:7-10` cross-builds it all with `zig cc` (`-target x86_64-windows-gnu` for the EXE +
engine DLL, `x86-windows-gnu` for a 32-bit DLL, `-luser32`), and the README warns what the
optimiser does to the lesson plan: "The compiler inlined `tree_new` and the vtable calls into
`simulate`, and the data loader compares its magic as one integer: both are lessons from real
games" (README:20-22).

**`mixer32.c` is the trap DLL — every routine exists to spring one §2/§4 instrument.** A 16.16
`fix_mul` done by the "magic number" add of 1.5×2^68 whose rounding "is the FPU's current mode
(pe32_emu's fpu_cw)" (`mixer32.c:30-38`); Watcom-order register arguments set up by a
hand-written caller (`:67-81`) for `ExportCallArgs`' `regs` mode (§2), verified byte-exact at
`run.sh:2102-2103`; and `hidden_triple` — hand-written asm with no prologue, after int3 padding,
reached only through a pointer the code XORs with a key at run time, "1990s games hid code the
same way" (`:83-96`) — the quarry of the exportcov → fill-gaps loop whose end-to-end proof §12
quotes.

**Ground truth: 20 seeds under the emulator.** `ground_truth.py` *is* §4's stack (it imports
`CallTrace` and `Emu`, `:17-18`): for seeds 1-20 (`:26`), a fresh emulator per seed "so no state
leaks between runs" (`:27-28`), `simulate` called through the export (`:32`), writing
`seed-N.f32` (600 output floats read out of emulated memory) and `seed-N.trace` (every draw, in
order, with its call site) (`:4-6, 33-35`).

**The port that matches bit-for-bit.** `port.py` is a reimplementation "written from the
decompiled code, that must match the original bit for bit" (`port.py:1-2`) — in Python, where
floats are doubles, so every operation is wrapped in `f32()` (a struct pack/unpack round-trip,
`:23-24`) in the original's order: "`(rng_float + 1.0) * dt`, not `dt + dt * rng_float`, which
can differ in the last bit" (`:10-12`). Same 20 seeds, same two file kinds, draw trace included
(`:71-76`).

**The negative control: `--naive`.** The same file ships a deliberately *wrong* port — "the
most common mistake: it keeps the same formulas in the same order but computes the simulation
in 64-bit doubles (Python's default) instead of the original's 32-bit floats" (`port.py:6-8`).
In code it is three lines: inside `simulate`, `global f32` … `if naive: f32 = float`, comment
"no rounding to 32 bits: doubles throughout" (`:49-51`). Naive is therefore correct except for
rounding — the drift is pure f32-vs-f64. README:13 dares you: "doubles instead of floats: watch
the checks fail"; the README's screenshot caption supplies the numbers — the good port "matches
the original in 600 of 600 values, and its 746 random draws are identical. The naive port
matches only 7 values" (README:16).

**The suite demands both verdicts.** The "Ground truth and the port" group (`tests/run.sh:572`)
builds all three artifacts and runs every seed through `bitcompare` twice and `seqdiff` once
(`:573-580`), then:

> ```
> [[ $same == 20 ]] && ok "the port matches the original bit for bit (20 seeds x 600 steps)" || bad "port matches on $same of 20 seeds"
> [[ $draws == 20 ]] && ok "the port draws random numbers in the original's order (20 seeds)" || bad "draw order matches on $draws of 20 seeds"
> [[ $drift == 20 ]] && ok "bitcompare catches the naive double-precision port (20 seeds)" || bad "naive port caught on only $drift of 20 seeds"
> ```
> (`tests/run.sh:581-583`)

Note the direction of the third gate: the check is *caught on 20 of 20*, not "caught on at least
one" — a `bitcompare` that somehow never failed would fail the suite. The naive build is reused
as a generic nonzero-exit fixture: `gameframe run` must propagate its tool's exit code, and the
artifact chosen for that check is truth-vs-naive (`run.sh:1653`).

**The pattern is systematic, not one lucky fixture.** The suite plants a defect for every
instrument that must be able to say *no*: `broken.dat` with 5 unread trailing bytes must make
`validate.py` report "5 bytes left unread" (`run.sh:607-608`); a *lossy writer* made on the fly
by `sed`-uppercasing names must make `--write` name the first changed byte (`:610-611`); a
toy "bad port" one unit off must fail `replay --block` (`:595-601`); `nedis` must not mistake
`[si + 4]` for the `Total` global at the same offset (`:662-663`, planted at `sample.s:109-111`);
`tdinfo labels` must leave imported procedures out (`:647`); a bogus function start
`0xdeadbeef` must fail gracefully inside fill-gaps ("1 of 2 starts decompiled, 1 failed",
`:2107-2113`); unhandled imports and interrupts must *name themselves* (`:702-705, 714-717`).
Shipping wrong artifacts the tools are required to catch is the epistemics of the whole suite:
each pass asserts the detector's sensitivity, not just its verdict.

**`examples/dos-sample/` — the 16-bit target (3 files, 592 LOC).** "A tiny 16-bit program for
testing GameFrame's DOS tools. It is our own code: no game is involved" (README:3-4).
`sample.s` (303 L) is 16-bit AT&T-syntax asm written "in the style of a Borland Pascal program"
— FAR routines, Pascal calling convention (callee pops with `lretw $N`), DS = the NE auto data
segment (`sample.s:1-8`); a Turbo-Pascal-style RNG (`RandSeed * $08088405 + 1`, `:39-52`), a
far-pointer checksum, an import (`KERNEL` ordinal 3 via a loader-filled `call far ptr 0:0`,
`:96-99`), an `INT 21h` call (`:103-106`), `INT 8`/`INT 9` handlers (`:138-163, 257-260`), and
`main_loop` — eight frames of DPMI blocks, VGA writes and a file read each frame, with named
fragment labels `frame_top`/`draw`/`event` (`:192-253`) for §4's `fragments.py`.
`make_exe.py` (264 L) assembles it with `zig cc` (`-target x86-freestanding`, `:44-45`) and
then "links the result itself, so GameFrame needs no 16-bit compiler or linker" — GameFrame's
own NE/MZ linker (`:6-7`; README:14: "links it with Python") — into `sample.exe` (NE, protected
mode, selector relocation + named exports), `sample-mz.exe` (the same code as a real-mode MZ
with paragraph relocations), and `sample-td.exe` (the NE with **Turbo Debugger TDINFO 3.0
symbols in a CodeView-style NB02 wrapper, "laid out as Borland Pascal 7 writes them"**
(`make_exe.py:6-18`); the TDINFO writer at `:179` is honest: it "proves the reader keeps
working, not that the layout is Borland's own specification" (`:20-22`); outputs written at
`:252-253`). The checked-under-a-real-emulator contract is stated at README:20-22: "The first
random draw from the built-in seed `0x1234` with range 100 is 23: the emulator, the program's
exit code under DOSBox-X and the debugger channel must all agree" — and the suite enforces the
tie: the DOSBox-X gate's own name is "dosbox-run runs a DOS program and reads its exit code
(= dos_emu's first draw)" expecting "exit code 23" (`run.sh:791-794`), and `dbx_control` reads
"AL=23 seed=3b032b05" through the debugger channel (`:798`); the emulator side is verified the
same way as §4's oracles — NE draws against a Python reference RNG (`:666-677`), real-mode MZ
code at Ghidra's addresses (`:718-723`). In between: dosinfo's NE header/selectors/Pascal
strings/TD-symbol detection
(`:626-633`), readseg typed constants and Turbo Pascal `Real` (`:634-641`), tdinfo labels/types/
Rust generation (`:642-658`), nedis relocations (`:660-663`), dos_env's finite PC (`:725-757`),
fragments captures (`:759-772`). Even the assembler has a documented pitfall: LLVM's Intel
syntax misassembles `retf 2` in `.code16`, so the source uses AT&T (`README:24-25`,
`sample.s:7-8`).

**`examples/frame-demo/` — the third example project, and it is not an RE target.** ch.20 §14
counts three projects (the root README still says "the two sample games" — ch.20 §14's note).
`frame-demo/` (5 files, 372 LOC) is the *output* side: "The frame with no game"
(`frame-demo/README.md:3`) — a Rust/Dioxus Cargo workspace that stands the `crates/frame` demo
game in for a port: three renderers and three sound cards, five settings, a pad of controls,
library-page sections from the template, starting in the Windows 98 preset (`:3-8`,
`src/main.rs:1-20`); it is what root `install.json` installs via §11's tools
(`README.md:27-37`; ch.20 §14). Its declared negative keeps the fiction honest: "Start runs
only the demo game's loading steps. No game is drawn" (`README.md:56-58`). It demonstrates the
frame a real port ships inside; it tests no decoder or emulator.

## 14. What the toolkit proves, and what it does not

**The ledger.** The suite's object is the instruments; the samples are the proof medium. What
each claim is certified *by*, and where each certificate stops:

| Claim | Instrument | What it certifies | Limit |
|---|---|---|---|
| Every tool runs and answers as its own help claims | `tests/run.sh` (36 groups, ~340 `expect`/`ok`/`bad` sites, §12) | real tool × real (synthetic) binary, output contains the named string | substring containment on toy-scale targets |
| Decoders read every byte of every file they claim | `formats/reader.py` `done()` + `validate.py` (§5) | per-file byte accounting; with `--write`, byte-identical re-encode | accounting, not field *semantics* (§5's own caveat) |
| The original's functions run under measurement | `tools/emu/` + `ground_truth.py` (§4, §13) | deterministic machine state and ordered draws under pinned inputs | no OS: unhandled imports stop the run; no DllMain, TLS, threads (`pe_emu.py:27-29`) |
| A port agrees with the original | `verify/bitcompare.py` + `seqdiff.py`, 20 seeds (`run.sh:576-583`) | 20/20 seeds agree on values *and* draw order — and the planted naive port is caught 20/20 (§13) | only what the sample's 600 steps exercise |
| The export covered the binary; gaps are closable | `exportcov.py --min` + fill-gaps (`run.sh:2105-2113`) | share of executable bytes in functions; a gained function verified in the re-export | "The starts are candidates, not proof" (`exportcov.py:37`); bytes ≠ meaning |
| The port knows what it ported and knowingly broke | `coverage.py`, `cite_labels.py`, `deviations.py --check` (§3) | citation share by size; a current deviations ledger | "decide whether a cited function is fully reimplemented" is the declared negative (`coverage.py:30-31`) |

**Four named absences — what nothing in the repo proves.** *No model quality score anywhere*:
the closest instrument, `skillcheck.py`, is 3 tasks (`tests/skill-tasks.json`, `json.load` len
3) scored by *presence* of ground-truth strings in `answer.txt` (`skillcheck.py:20-21, 24`),
and in the suite its own pass/fail runs against `fake_api.py` with canned `FAKE_ANSWER`s
(`run.sh:2011-2014`) — real agent runs are budgeted side-quests, never gates (§10). *No
whole-program conformance verdict*: `exportcov --min` measures bytes inside functions and
`coverage.py` measures citations — both declare the gap (§3); the nearest verdict is §13's
sample-scoped 20-seed counter, and calxgloss names this same missing object as open roadmap
P26 (`10-calxgloss-baseline.md:99, 200`). *No CI beyond `site.yml`*: `ls .github/workflows/`
lists exactly that one file (ch.20 §16) — the suite is the missing CI's script, run by AGENTS
rule 2 convention (§1, §12). *No scored corpus*: no tool's accuracy is tabulated across games
or builds; `match_functions`/`sigscan` stay per-project and the measured know-how cases
(`exportcov.py:31-33`) are prose — the calxgloss P33 analog (`10-calxgloss-baseline.md:199`).

**Negative finding — the skills' tool vocabulary checks out, with two named exceptions that
aren't tools.** The audit (Sources) finds 66 `tools/...` paths referenced by skills, every one
a real file — zero dangling docs. The names that don't resolve under `tools/` live where the
skills say they do: `gameframe-report` is a Rust crate (`crates/report/Cargo.toml:2`;
`skills/re-start/SKILL.md:265`, consumed at `triage/report_issue.py:4`) and REA verbs like
`xrefs`/`analyze_function` are MCP-provider tools (`skills/re-rea/SKILL.md:20, 37`; §9).

**What this adds to §12's mirror point is direction.** GameFrame's suite certifies
*detectivity*: every instrument that can say "yes" must say "no" to a planted defect — naive
port, `broken.dat`, the `sed`-made lossy writer, `bad.jsonl`, `0xdeadbeef`, the `[si + 4]`
lookalike (§13) — so the passes are trusted *because* the fails are required. Its ceiling is
built in: rule 1 keeps real games out of the repo (§1), so what is certified is instruments
against synthetic targets, and transfer to a real game rides on docs and know-how notes, not
on `run.sh`. The calxgloss ledger has the complementary hole: per-attempt compile/behavior/
trace gates run inside its product against whatever target is being
worked (only the fixture DLL is proven end-to-end, ch.10), but nothing
certifies that certifying layer — P42 (no CI), P33 (no eval), P26 (no whole-binary verdict),
`10-calxgloss-baseline.md:199-200`. Each project ships one half of "trustworthy instruments +
trustworthy verdicts"; neither ships both.

## Sources

**Example/test files read for §13-§14** (every span opened at the cited line, clone HEAD
`f195a074`): `examples/sample-game/` — README.md:1-31; game.c:1-79 (:13-14, :16-36, :48-58,
:60-72); engine.c:1-22 (:10-19); port.py:1-83 (:6-13, :23-24, :47-66 incl. :49-51, :71-77);
ground_truth.py:1-41 (:23-37); build.sh:1-12; make_data.py:1-13; decode_sample.py:1-20;
mixer32.c:1-96 (:30-38, :67-81, :83-96). `examples/dos-sample/` — README.md:1-25;
sample.s:1-80 and the routine/label map via
`grep -nE '^[a-z_]+:|main_loop|frame_top|# ' examples/dos-sample/sample.s`
(:96-99, :103-106, :109-111, :138-163, :192-253, :257-260); make_exe.py:1-60 (:2-22, :31-38,
:44-45) plus `:179, :252-253, :257` (grep). `examples/frame-demo/` — README.md:1-58;
src/main.rs:1-30; library.json:1-22, :93-138. `tests/run.sh` — :14, :555-583, :584-604,
:605-613, :623-663, :665-723, :725-757, :759-772, :774-815, :1653, :2011-2014, :2085-2123.
Supporting: `tools/llm/skillcheck.py:1-30`; `crates/report/Cargo.toml:1-4`;
`skills/re-start/SKILL.md:265`; `skills/re-rea/SKILL.md:20, 37`.

**Commands behind the counts.** Stated in §1-§12: `find tools -type f | wc -l` = 158 with the
ch.20 §8 line walk (23,475 L) (§1); `find tests -type f | wc -l` = 36 and
`grep -cE '^\s*(expect|ok|bad)' tests/run.sh` = 340 (§12); the `translat`/`decompil` grep over
`tools/llm/*.py` (§10). New in §13-§14: `find examples -type f | wc -l` = 17;
`find examples -type f -exec wc -l {} +` = 1,361 total (sample-game 397 via
`wc -l examples/sample-game/*`, dos-sample 592, frame-demo 372); `du -sh examples` = 108K;
`grep -n naive tests/run.sh` = 4 hits (:574, :578, :583, :1653); `ls .github/workflows/` =
`site.yml` only; the skills↔tools audit
`grep -rhoE 'tools/[a-z_/]+\.py|tools/[a-z_/]+\.java|tools/[a-z_/]+\.rs|tools/[a-z_/]+\.c' skills/ |
sort -u` = 66 paths, each existence-checked (zero missing); `git rev-parse HEAD` = the pinned
`f195a074`.
