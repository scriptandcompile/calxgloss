# GameFrame's method: playbook, loop, and the 16 skills

> Part of the [game-frame overview](README.md).

GameFrame's product is not really the bit-exact ports it produces — it is the
*method* for producing them, written down as executable prose. The method loop
is a table inside a skill file that a CLI parses at runtime
(`tools/gameframe/skills.py:80-90`); "what do I do next?" is a command
(`./gameframe steps`, `./gameframe advise`); the accumulated failure lore is a
validated, machine-searchable corpus of 142 entries (`docs/knowhow/`); and the
agents' behavior is constrained by executable gates, not by prose alone
(`docs/working/gates.md`). The engineering artifact and the methodology that
produced it are the same repository, licensed for exactly that purpose: code
under Apache 2.0, the method itself — skills, agents, docs — under CC0,
"dedicated to the public domain" (`README.md:368-376`). This chapter reads that
method layer: the loop, the 16 skills, the evidence discipline, the clean-room
doctrine, the governance files, and the `./gameframe` discovery CLI. *cf.*
calxgloss: our tools are documented in prose that humans route by; GameFrame's
routing layer is parsed from the same files the agents read.

## 1. The loop

The loop is defined once, in `skills/re-start/SKILL.md:55-60`:

```
inventory -> profile -> observe -> decompile -> trace -> format -> emulate -> reimplement -> verify -> land
                                       ^                                             |
                                       +---------------- when a check fails ---------+
```

Two facts about the diagram:

- **The failure edge returns to decompile.** The caret sits under
  `decompile`, and the branch after `reimplement` carries "when a check fails"
  back to it (`re-start:57-59`). A failed check is a signal to go read more
  code, not to re-run tools.
- **The loop is per-slice, not per-project.** "A small task may use only two
  or three steps. Do not skip `land`." (`re-start:79`). `land` is the one
  non-optional step.

The same skill turns the diagram into a 14-row step table
(`re-start:62-77`), and the CLI reads that table back out of the file:
`steps()` parses "the loop diagram and the step table of re-start"
(`tools/gameframe/skills.py:80-90`), because "The steps come from the re-start
skill, so they change when that skill changes" (`skills.py:8`). One source of
truth, deliberately parsed rather than duplicated.

| Step (skill) | Question it answers |
|---|---|
| Set up (`re-setup`) | Are Ghidra, Java, Python, Unicorn and REA ready? |
| Inventory (`re-inventory`) | Which files hold the game's own code? Engine, protection, containers? What kind of game? |
| Profile (`re-profile`) | Genre, engine, release, presentation, hardware? What to check first? |
| View (`re-browse`) | Can a person and an agent see every file and the decoders' output? |
| Observe (`re-observe`) | What does the original actually do, captured with its inputs? |
| Investigate with REA (`re-rea`) | Quick, evidence-backed answers about a binary or package? |
| Decompile (`re-ghidra`) | Pseudocode as searchable text; one-off decompiles |
| Trace (`re-trace`) | How does the original do X — which function, fields, constants? |
| Decode a format (`re-format`) | What is in this data file, field by field, on every file? |
| Emulate (`re-emulate`) | What exactly does this original function return for these inputs? |
| Reimplement (`re-port`) | Write new code that behaves the same |
| Verify (`re-verify`) | Bit-exact? Deterministic? Real-save compatible? |
| Land (`re-land`) | Document, label, commit |
| Publish (`re-site`) | A diary entry per milestone; the docs as pages |

The drift cluster around the failure edge is worth recording because it shows
what the single-source discipline actually costs to maintain. The README's
figure alt-text says "When a check fails, the work goes back to the trace"
and omits the `profile` step (`README.md:135`); the skill's diagram says back
to **decompile** (`re-start:57-59`); the agent-pipeline summary says "back to
the tracer or the porter" (`README.md:199`); and the project template's inline
loop parenthesizes `format` as optional — "(format)"
(`templates/project/AGENTS.md:122`). Four renderings, three different failure
edges, one canonical diagram.

*cf.* calxgloss: our cited-locator stages have fixed inputs/outputs and fail
loud through invariant gates; GameFrame routes on *claims about one function*,
and the loop itself is data a CLI can print.

## 2. The evidence grammar: four labels

The vocabulary is four labels, not five: "Label every claim with how you know
it" (`re-start:43-48`):

| Label | Meaning (as defined) |
|---|---|
| *observed* | read in the code or the data (name the function or file) |
| *measured* | produced by running original code (emulator or game), with the inputs |
| *inferred* | a reasoned guess; say what would confirm it |
| *unknown* | an open question, listed as such |

The table is repeated, near-identical, in `docs/working/writing.md:48-53` and
in the rules of a generated project (`templates/project/AGENTS.md:65-67`),
and the README restates it in one line ("*observed*, *measured*, *inferred* or
*unknown*", `README.md:137`). Two rules ride along with the labels: the
static/dynamic wall — "Never write that the game 'does' something at run time
from static reading alone" (`re-start:48`, `writing.md:55`) — and the
consequence for prose: an *inferred* claim must name what would confirm it.

`docs/working/evidence.md` (80 lines) is the forensic layer that makes the
labels checkable. Its opening sets the standard by analogy: "Forensic
examiners work so that another examiner, given the same material, reaches the
same result" (`:3-6`). Its habits: identify the copy before working — hash
every file before anything changes (`:10-14`), compare pressings against
Redump (`:15-16`); keep the original unchanged, read-only, never patched
(`:20-25`); tie each finding to one build — "A function address, an offset or
a constant is true for one build" (`:32-33`), name the executable and its
hash in `docs/FINDINGS.md` (`:35-36`); make results repeatable by recording
the commands and tool versions (`:43-46`); and the "look before you run"
evidence-preservation ladder, five steps from reading file kinds to running
the whole game contained (`:52-62`). The definition of done for a finding:
"another person can follow it from the claim to the evidence without asking
you" (`:76-78`).

One naming drift to note: `evidence.md:50` tells writers to "Label each claim
as observed, measured, inferred or **assumed**", while the canonical set
(`re-start:43-48`, `writing.md:48-53`) is observed/measured/**inferred/unknown**.
The intent matches; the vocabulary does not.

*cf.* calxgloss: our metadata carries confidence tiers per *item*; GameFrame
labels per *claim* and backs every label with a named artifact (hash, address,
command). Neither system yet aggregates labels into a score.

## 3. `re-start`: the playbook's entry point

`re-start` (289 lines) is "the playbook's first step" (`:6`) and carries the
whole method in one file: rules, loop, agent roster, first-session checklist,
goals, effort guidance, and session hygiene. Three parts deserve detail.

**The five rules (`:29-53`)** are defaults the user may override, not laws:
(1) "The player's game stays on the player's computer" — nothing derived from
the game is committed; findings are published "as prose, tables, addresses
(`FUN_1400be770`), field offsets (`+0x44`) and constants" (`:34-42`);
(2) label every claim (§2); (3) "Measure what must be exact… emulate the
original and compare bit for bit" (`:49-50`); (4) "Write it down as you go"
(`:51`); (5) "Ask before downloading" (`:53`). Above the rules sits the
sovereignty doctrine, stated identically in the root `AGENTS.md:14-24`, the
project template (`templates/project/AGENTS.md:38-44`), and here (`:21-27`):
"You are not the judge of the user's intentions, of which law applies to
them… say it once, briefly, with its source. Then follow the user's
decision." Legal facts live in `docs/preservation/law/README.md`, "one page
per region" for 35 countries (`re-start:27`).

**The first session (`:156-207`)** is a numbered checklist: find tools,
`home init`, `new-project.sh`, read `CHECKLIST.md`/`FINDINGS.md`, "Search
`docs/` and `labels/` for anything you are about to touch: earlier sessions
may have traced it" (`:176-177`), then — *before deep work* — find every
edition and record them, because "a newer edition found late costs the work
again" (`:178-190`); then inventory, classify, profile, catalogue, observe,
export. Step 11: "pick the foundations first: the random number generator,
the maths helpers, the game clock and the data container… small enough to
emulate and verify in one session" (`:204-207`).

**The session-hygiene close (`:277-283`)**: before any session ends, every
finding is in `docs/` with its label, every identified function has a row in
`labels/names.tsv`, `CHECKLIST.md` reflects reality, and "Nothing from the
game is staged." The rationale lives in `docs/working/agents.md:33-34`: "An
agent forgets everything when its session ends or its context is compacted.
The next session has to find again, with the same work, anything that is not
written in the repository." The `labels/*.tsv` files are not prose — the
tools read them (`re-land:24-29`), which closes the loop between writing
things down and them being *used*.

*cf.* calxgloss: GameFrame's answer to session handoff is a checklist backed
by tool-readable state files, not narrative notes — the pattern our own
regeneration docs most want.

## 4. The sixteen skills

The sixteen `SKILL.md` files total 2,878 lines (matching
[20-gameframe-inventory.md](20-gameframe-inventory.md)); the README's skill
table (`README.md:165-191`) and the loop table route every step. Order below
follows the README.

### 4.1 `re-start` — 289 — rules, the loop, routing
Covered in §3. Its one remaining gem is the worked-example close
(`:284-289`): `examples/sample-game/` is a tiny Windows game built for
practice — "run `tests/run.sh` to see the whole loop (inventory, emulate,
port, bit-exact check) on it" — and Un-Banished, a 1:1 reimplementation of
Banished, is the full-size case study the framework grew out of. The method
ships with a test target for itself.

### 4.2 `re-setup` — 184 — install and prove the toolchain
Check before installing (`scripts/setup.sh` prints an ok/MISSING table,
`:8-14`), announce sizes before installing on the user's machine ("Ghidra
about 500 MB… Zig about 200 MB", `:22-24`), and *prove it works* with
`tests/run.sh` — "All checks must pass. A failure names the tool and shows
its output" (`:34-41`). Section 3 registers REA as an opt-in MCP provider,
"pinned to `rea-agents` 6.7.0" with specific Node versions required
(`:43-60`); section 4 sets up DOSBox-X and its debugger for DOS games
(`:104`).

### 4.3 `re-inventory` — 256 — what is in the game
Opens with the cost of misclassification: "analysing the C++ runtime of a
Unity game instead of its C# code… wastes days" (`:6`). Rule zero: "Never run
an installer: extract it" (`:16`), with `./gameframe game add` recording size
and SHA-256 per copy (`:18-21`). The skill routes by binary kind — native,
managed, scripted, packed, 16-bit DOS — records into `docs/FINDINGS.md`
(`:156`), and picks the reference edition: "by default the last version
released, which has the most fixes" (`:175-209`). Uniquely, it also reads
*the story*: the manual and the program's long strings into `docs/lore.md`,
keyed "in the story → in the code → evidence" — the lore "says what each
system is for and which must be exact" (`re-start:200-202`).

### 4.4 `re-profile` — 123 — the evidence-backed profile
After the first inventory, `docs/GAME_PROFILE.md` collects release, engine,
presentation, and hardware evidence, separating "official support, file/code
evidence, measured behavior and community reports" (`:15-30`). Its distinctive
rule is about *asking*: "Use the evidence first. Do not ask for a fact that
can be read from the game" — ask the human only what "could change the
recommended route, the project goal or what must be exact" (`:73-88`), and
leave unanswered items *unknown* rather than guessed.

### 4.5 `re-browse` — 163 — a viewer from day one
"A resource viewer opens the player's copy of the game and shows every file:
what it is, what the decoders make of it, and what is not understood yet"
(`:8-10`); the catalogue runs "before any decoder exists" (`:12-16`). It is a
first-class goal, not tooling garnish: the project milestones list puts "a
viewer of every asset" before the port (`re-start:212-219`,
`templates/project/AGENTS.md:29-32`) because "the port starts with its data
layer done and tested, mod tools come for free, and the person directing the
work can check every decoder by looking" (`re-start:216-219`). Its pitfalls
are about drift: "A viewer with its own decoder drifts from the port's. Keep
one reader" (`:157`); "A picture can look right while the decoder skips
bytes. Show whether every byte was consumed" (`:158-159`).

### 4.6 `re-observe` — 135 — run the original, capture with its inputs
The rule for every capture: "write next to it the game version (hash),
settings, seed, and the inputs or demo, so it can be made again" (`:71-73`).
The capture table spans frames (video memory via `rawimage.py`), state
(`memscan.py` across dumps, `pointerpaths.py` for a pointer chain that finds
the value every run), driving Wine from inside (`winput.py` sends scancodes),
where-to-click (image alignment first; if the screen "changed too much (score
below 0.5)", ask a *local* vision model, `locate.py`), file reads, draw
calls, network, and two-run coverage diffs that isolate one action's code
(`:75-92`). Then "List every input" — a table of everything outside the game
that can change state, feeding the port's input record (`:94-101`).

### 4.7 `re-rea` — 100 — REA over MCP, with citable evidence
A decision table, not a cheer: REA when the target is an APK/.NET/Electron/
browser/archives, for a quick cited answer on one function, for call paths
between two functions, or when "a finding must carry a citable Evidence ID";
the text export when searching the whole program as text "many times (grep is
instant)" or tracing across hundreds of functions (`:15-27`). They compose
because "both read the same binary through Ghidra; addresses match" (`:28-29`).
Labels learned in REA flow back into `labels/names.tsv` so GameFrame's tools
see them (`:35-36`).

### 4.8 `re-ghidra` — 214 — export once, then work as text
"Import the game's own binaries **together**, so calls between the EXE and its
DLLs resolve" (`:13-16`); known names go into the export so "Ghidra names
everything and creates the functions it missed" (`:21-23`). After that, the
pseudocode is searched with `decomp_query.py`, and one-off decompiles run
without re-analysis. The pitfalls section is a catalog of decompiler failure
modes — inlined functions, magic numbers (`"SMPL"` is `0x4c504d53`), decimal
offsets printed as `param_1 + 100`, thunks, wrong signatures — each with the
check that settles it, usually the disassembly (`:166-181`).

### 4.9 `re-trace` — 114 — from a string to the function, with a written trail
"Tracing means following the program from something concrete to the code you
need, and leaving a written trail. Static reading only: label conclusions
*observed*, *inferred* or *unknown*" (`:9-11`). Step zero is `grep -rn` over
`docs/` and `labels/` — "Has it been done?" (`:12-16`). Entry points rank by
usefulness: strings first ("Developers leave log messages that name the
function they are in"), then exports with real names (`:23-30`). Output is a
topic document keyed by address and offset with **Open questions** at the
end, "Never paste pseudocode or disassembly: describe it" (`:99-105`).

### 4.10 `re-format` — 158 — decode formats, proved byte-exact
The standard: "A decoder is right only when it reads **every file** of its
type to the **last byte**" (`:8-10`). Method: find the code that reads the
format (the trace feeds this), prototype with `reader.py`, then `validate.py`
proves "all bytes consumed" across every file of the type (description:
frontmatter). Writers are proven by round trip — read, write back, compare —
"Each difference is a field the writer loses" (`:132-141`). Saves get their
own section: "Saves are the strictest test of a format: they hold the whole
state of a running game" (`:143-146`).

### 4.11 `re-emulate` — 149 — ground truth by running original functions
The Unicorn harness loads the real binaries — "loads, relocates, links imports
by name" (`:16-18`); imports without a stand-in "stop the run with their
name" so gaps are explicit (`:22-23`); `emu.call` follows the x64 convention
with floats wrapped (`F32`/`F64`); `hook_function` replaces anything touching
files, threads or the GPU with Python observers (`:24-34`). `call_trace.py`
records the random draws in order. This is what *measured* evidence is made
of — the source for the ground-truth files `re-verify` later diffs against.

### 4.12 `re-port` — 204 — reimplement with citations
"Read the pseudocode to understand the behaviour, then write the new code
from your notes… By default, do not paste decompiled code into the new code
base: it is the original author's work… This is the line between a
reimplementation and a copy" (`:11-18`). Structure mirrors the original, and
two rules make verification mechanical: constants keep their read value —
"`0.33333331f`, not `1.0 / 3.0`" (`:30`) — and "Every reimplemented item names
its original in a comment… in one consistent form the tools can search"
(`:31-33`). `coverage.py` then reads those `Original:` citations and reports
how much of the original the port has actually ported "by count and by size,
with the largest functions nobody cites yet" (`:191-194`). Intentional
differences get a `Deviation:` comment in a generated ledger — "A deviation
is a decision; an accidental difference is a bug" (`:171-177`) — and
unreached-and-unported paths call `unported!`, so a running port reports its
own gaps with the values at the spot (`:178-190`).

### 4.13 `re-cleanroom` — 46 — the source-blind gate
Short on purpose: it is a boundary, not a workflow. "It gives different roles
different inputs. It does not itself create filesystem or legal separation"
(`:8-9`). Roles: `re-specifier` may inspect the original and writes a neutral
behavior contract plus a separate evidence ledger; `re-cleanroomporter`
"receives only the allow-listed packet… does not inspect original artifacts
or the evidence ledger"; `re-verifier` "reports failing inputs and values
without source-derived explanations" (`:19-25`). "Never reuse a source-reading
task as the source-blind implementer" (`:27`). Section 6 covers the doctrine
around it.

### 4.14 `re-verify` — 331 — the verification scale
"It builds is not verification" (`:9`). Effort scales with risk, and *every*
slice gets at least the first row: recorded frames through the port compared
against the original's state; arithmetic/RNG/physics additionally get "direct
calls on random inputs… thousands of them"; branchy code gets fuzzing "from
real states"; menus and drawing get "recorded frames and pictures only; no
fuzz" (`:11-21`). The eight sections order the checks: bit-exact parity
against emulator ground truth (`bitcompare.py`), random draw order
(`seqdiff.py`), determinism (two identical runs, digests at checkpoints and
on every platform), real save round trips, picture comparison, version
against version, and test tiers — quick per change, standard before a
game-touching commit, long before release, where "a baseline that changes is
a change in behaviour: find the cause" (`:321-327`).

### 4.15 `re-land` — 127 — document, label, commit owned files, merge
"Undocumented findings are re-derived by the next session, at full cost.
Landing is part of the work" (`:8-9`). Document in evidence style (tables
keyed by address and offset, every claim labeled, no pasted pseudocode, and
"plain English with no rhetorical patterns", `:11-23`); label every function,
field, and value into the TSVs (`:24-29`); stage only your own files; then
"merge that commit into the local `main` branch before hand-off… Never leave
completed, merge-ready work uncommitted or waiting in a branch" (`:99-114`).
The gates enforce the exclusivity: only `re-lander` may commit or push
(`docs/working/gates.md:24-25`).

### 4.16 `re-site` — 285 — the diary and the docs as one copy
"The site is a view of the repository… the reference pages show the documents
in `docs/` with VitePress's `<!--@include: ...-->`, so each fact has one copy
and the site never drifts from the repository" (`:12-14`); the pitfall states
the failure: "Copies drift. Copying a document into the site gives two
versions within a week. Always `@include`" (`:271-274`). Its diary is two-tier
— live entries per milestone with a 24-hour timestamp, consolidated into one
day post per past day (`:100-113`) — and a milestone is reader-defined:
a format decoded, a system verified, a release, "a dead end that cost a day
and taught something" (`:115-120`). The build fails on dead links, including
inside included documents (`:95-97`).

## 5. Clean-room doctrine

`re-cleanroom` points to the doctrine file,
`docs/working/clean-room-implementations.md` (167 lines), whose honesty about
its own limits is its strongest feature: "Separate agent tasks and prompts
create a useful working boundary. They do not create an access control
boundary when every task can read the same files or machine. Record that
limit accurately" (`:8-11`). The role table (`:27-33`) adds a **Coordinator**
whose job is packet hygiene — "It does not forward source snippets or
source-specific explanations". The mechanics: contracts cite evidence IDs
(`E01`) with the addresses kept in a separate ledger (`:44-46`); "Do not
include source code, pseudocode, decompiler output or a line-by-line
translation" (`:47-48`); the hand-off packet is allow-listed and its manifest
records "the packet's file list and SHA-256 values" (`:61-67`); gaps go back
through the coordinator, and "The implementer receives the missing behavior,
not the source agent's reasoning" (`:78-81`); the verifier reports mismatches
as "cases and values, not source explanations" (`:88-96`).

The file also *shows its own receipts*: the audio-driver work "used separate
source-specification and implementation tasks. The tasks shared a host and
repository, so the record should call this source-blind, clean-room-style
implementation, not claim a technically enforced or legally conclusive clean
room" (`:151-153`). The legal envelope (`docs/LEGAL.md`, 68 lines) is equally
hedged: practical guidance "not legal advice" (`:3-4`); the four assumptions
— own copy, nothing redistributed, result is new work, players bring their
own copy (`:13-20`); the reason table (decompiled code is "a derivative of
the original program"; behavioral facts "are generally not protected the way
expression is"; citations "show that the reimplementation came from analysis
rather than a leak" — `:26-30`); interoperability law with EU Software
Directive Art. 6 and *Sega v. Accolade* / *Sony v. Connectix* named as
jurisdiction-specific examples (`:34-42`); and on clean-room itself: the
Phoenix BIOS precedent "is not a court ruling or a guarantee… Task
separation is a working method; it does not create technical access controls
or settle whether a project meets a legal clean-room standard" (`:53-62`).
"When the same agent studies and writes (as in Un-Banished), say so in the
project's documents" (`:58`).

Even the two-licence split encodes the doctrine: code Apache 2.0,
documentation and skills CC0, "as far as the law allows" (`README.md:368-380`).

*cf.* calxgloss: our licensing dossier covers what the law permits;
GameFrame's doctrine is the operational side — per-packet manifests, ledger
separation, and mandatory honesty labels about which kind of boundary was
actually maintained.

## 6. Governance: two AGENTS.md files, layered

`AGENTS.md:3-5` states the split: the root file governs "changes to
**GameFrame itself**"; a project made with `new-project.sh` "gets its own
`AGENTS.md` from `templates/project/`". The rule sets differ in kind, which
is the point:

- **Root (87 lines)** — repository rules: no game material, ever; the only
  test binaries are built from their own samples (`:30-35`); every tool is
  tested against the sample game (`:36-37`) and documents itself (`:38-39`);
  "Skills are self-contained. An agent that loads one skill must be able to
  do that step from it alone" (`:40-42`); plain English, "the skills are read
  by agents and translated by people" (`:45-46`); improve GameFrame from real
  games but keep game-specific parts out (`:52-57`); stage only your own
  files, never `git add -A` (`:61`).
- **Project template (144 lines)** — reconstruction rules: game material as
  *links into the GameFrame home*, never force-added, and "the gates block
  such commands" like `git clean -x` (`:51-62`); "Evidence before code" (`:65-67`);
  "Measure before claiming exactness" (`:68-69`); `Deviation:` marks
  (`:70-72`); the exact core with additions behind a build option, reaching
  the core "only through commands, events and queries" (`:73-77`); "An
  undocumented finding is re-derived by the next session" (`:80-81`);
  multi-session rules — each session stages its own files, completed slices
  merge into local `main`, never revert another session's work (`:83-89`);
  clean-room task boundaries must be *classified* — "prompt-based,
  workspace-isolated or independently staffed" (`:93-96`).

Between them sits the agent layer: 9 stage agents + 14 task agents = 23 files
in `agents/`. Two drift findings: the root layout table says "One agent per
stage and twelve task agents" (`AGENTS.md:68`) while there are fourteen and
the README says "Fourteen task agents" (`README.md:202`). The roster's rules
are opt-in delegation — "A task being self-contained is not permission to
start a subagent" (`re-start:96-98`) — hard routing — "Send one agent at a
time for one subject. Only the lander commits" (`re-start:125`), each agent
ending with a `## Hand-off` block naming the next (`re-start:102-104`) — and
strict escalation: "Agents do not start other agents. They stop and ask
before downloading, working around protection, writing outside the project or
choosing a version of the game" (`re-start:109-112`).

The enforcement is executable, not just textual. `docs/working/gates.md`
(`:3-8`) defines gates as checks before commit/push/write/delete that "run in
git itself, so they protect people and every agent" — blocking staged game
material, added lines that "look like Ghidra's decompiled code", commits and
pushes by any agent but `re-lander`, and any command that would delete the
user's game copy (including `git clean -x` and `cargo clean` into `target/`),
with an explicit escape hatch (`GAMEFRAME_DELETE_GAME=1`) rather than silent
permission (`:24-27`). Gates are honest about themselves: "a safety net for
honest mistakes… not a security boundary" (`:10-11`).

*cf.* calxgloss: we keep a single AGENTS.md per repo; the root-vs-project
split is the pattern to copy — governance text for touching *one's own code*
and governance text for touching *someone else's binary* genuinely differ.

## 7. `./gameframe`: the discovery CLI

`tools/gameframe/__main__.py` (213 lines) is a thin dispatcher whose docstring
is the command menu (`:1-51`); README:112-127 shows the same surface. The
design note is the whole thesis in one line: "It reads the skills and the
tools' own help from the files, so it never goes out of date" — AGENTS.md
adds "a new tool needs no entry there" (`AGENTS.md:71`).

| Command | What it answers | Where the fact lives |
|---|---|---|
| `steps` | the loop + step table | parsed from `re-start` — `skills.py:80-90` |
| `skills`, `skill NAME --section` | one-line skill list / a section of one skill | `skills/*/SKILL.md` frontmatter, `skills.py:44-77` |
| `tools`, `tool NAME` | every tool + its own help | each tool's docstring/`--help` |
| `run NAME ARGS` | run a tool with the shared `.venv` | `__main__.py` docstring `:15` |
| `find WORD` | which skills/tools mention a word | live text search |
| `advise TEXT` | known failures & context for an error | `docs/knowhow/` + `advise.py` |
| `progress [AGENT]` | what running agents logged (`derived/progress/*.log`) | `:23-26` |
| `serve` | GameFrame's own MCP server on stdio | `:27` |
| `agents --table --emit CLIENT` | the 23 agents in each client's format | `agents/*.md`, `agents.py` |
| `home`, `game` | the GameFrame home: games, projects, machines | `home.py`, `games.py` |
| `doctor`, `install` | toolchain check / release install | `scripts/setup.sh`, `tools/install/` |
| `mcp --list/--enable/--disable/--emit` | opt into external MCP providers | `mcp_providers.json` |

**Advise scoring is deliberately dumb.** The weights are a single line —
`SIGNATURE, FACET, TITLE, BODY, BODY_CAP = 100, 12, 4, 1, 6`
(`tools/gameframe/advise.py:18`) — mirrored in prose at
`docs/working/knowhow.md:121-125`: an error-signature regex match counts 100;
a taxonomy facet or tag named by the query, 12 each; query words in the
title, 4; in the body, 1 each capped at 6, and a body-only match needs two
words (`advise.py:69-96`). A STOP-word list keeps prose noise out of the
scores (`advise.py:19-20`). `--signatures` keeps only regex hits, and that is
what the hook uses. The design rationale is written down: "Keywords, aliases
and regular expressions are enough for the first hundred entries… It gives
the same answer on every machine" — and embeddings are deferred with explicit
trigger conditions ("people ask in their own words and `advise` misses… Then
the plan is a small local index"), logging misses to `GAPS.md` so "the
decision rests on evidence" (`knowhow.md:130-150`).

**The corpus itself is validated data.** 142 entries in `docs/knowhow/`, one
failure mode or context note each; the front matter carries facets (era,
platform, runtime, hardware, api, compiler, genre, symptom), free tags, and
*error signatures* — regexes "matched against output, case-insensitively"
(`knowhow.md:19-40`). Body sections are fixed titles: `## Symptoms`,
`## Cause`, `## Evidence`, `## What to do`, `## Tried`, `## What to know`,
with status determining which are required (`:77-84`). `advise --check`
validates ids, facets, regexes, cross-links, and section requirements, and
`tests/run.sh` runs it (`:86-89`). A worked entry —
`docs/knowhow/wine-privileged-instruction.md` — shows the shape: three
signatures including exception code `0xc0000096`, tools and skills cross-referenced,
and `seen: ['POD: Planet of Death (1997), 2026-10-23']` naming the game and
date it was hit (`:1-21`).

**Three reach paths, one of them automatic.** The agent can ask
(`advise "<error text>"`, or pipe a log: `wine GAME.EXE 2>&1 | tail -100 |
./gameframe advise -`, `knowhow.md:105-112`); a post-tool hook names matching
entries after every shell command — checking the last 40,000 characters
"even when the command succeeds, because Wine prints its errors and still
exits 0", adding at most three entries, naming each entry once per session,
never blocking (`:152-166`); and `re-start` routes agents to run `advise`
proactively at era/runtime changes (`re-start:258-262`). When it matches, the
print format is fixed: status, title, short answer, its tools/skills/docs,
and the command to see it whole (`knowhow.md:114-116`). When nothing matches,
`advise` exits 1 and points to the skill section that says how to add an
entry (`:116-117`).

**MCP as governance.** The repo's own `.mcp.json` contains exactly one
server: `gameframe → ["./gameframe", "serve"]`. Everything else is opt-in:
"External MCPs are off until a project opts in with
`./gameframe mcp --enable NAME`" (`README.md:102-104`), and the candidate
registry pins versions — REA `6.7.0`, DOSBox-X `v0.1.2`, `mcp-emulate`
`0.1.0`, 86Box by full git revision — as launcher args
(`./gameframe mcp-provider rea 6.7.0`) rather than letting clients resolve
floating packages (`tools/gameframe/mcp_providers.json:2-14, 43-47`;
`re-setup:59-60`). GameFrame's own server exposes know-how, search, workflow
discovery, and *execution* of catalog programs and scripts by reusing the
existing CLI (`knowhow.md:183-200`; `mcp_server/` module per capability).

**`--json` drift:** the README lists five JSON commands — "`steps`, `skills`,
`tools`, `tool` and `find`" (`README.md:130`) — while the CLI docstring lists
seven: the same five plus `agents` and `advise` (`__main__.py:51`).

*cf.* calxgloss: we have no equivalent layer — our tools are found by reading
docs prose. The stealable pattern is the *self-parsing registry*: one skill
file feeds the human docs, the agent playbook, and the CLI with zero
duplication.

## 8. Method vs. pipeline: how GameFrame's method works, and where ours differs

Four properties, each verifiable from the method's own files, make this a
*loop discipline* rather than a tool pipeline:

1. **Routing is claim-shaped, not stage-shaped.** The loop's failure edge
   returns to decompile (`re-start:57-59`) because a failed check names a
   *behavior*, and the fix is more reading about one function. Verification
   is likewise risk-tiered per code kind (`re-verify:11-21`), and coverage is
   measured per citation (`re-port:191-194`). A pipeline routes on stage
   boundaries; this routes on claims about one function at a time.
2. **Working memory is on disk, by design.** "An agent forgets everything
   when its session ends or its context is compacted"
   (`docs/working/agents.md:33-34`); the countermeasure is tool-readable state
   — `labels/*.tsv`, `docs/CHECKLIST.md`, the deviations ledger, the knowhow
   corpus — written *as you go* (`re-start:51`, `re-land:8-9`), plus the
   end-of-session checklist (`re-start:277-283`).
3. **Every claim travels with its proof obligation.** Labels name their
   artifact (`writing.md:48-53`); addresses name their build's hash
   (`evidence.md:32-39`); ported code cites `Original: FUN_…` so
   `coverage.py` can audit it (`re-port:31-33, 191-194`); clean-room packets
   carry SHA-256 manifests (`clean-room-implementations.md:61-67`).
4. **The method is mostly *don't* rules, because it learns from failure.**
   The knowhow corpus is "the record of these failures"
   (`docs/working/knowhow.md:3-5`); the rules that follow: agents don't start
   agents (`re-start:109`), delegation is opt-in (`:96-98`), MCP is off until
   enabled (`README.md:102-104`), paid API runs are opt-in
   (`docs/working/agents.md:168-170`), nothing from the game is committed,
   nothing is re-derived that `docs/` already records
   (`docs/working/agents.md:44-53`).

What it is *not*: a batch pipeline. There is no stage queue, no artifact DAG,
no run-everything mode — the loop is worked per slice ("A small task may use
only two or three steps", `re-start:79`), and even the sample game is tested
by running "the whole loop… on it" (`re-start:284-289`). Our cited-locator
pipeline optimizes for *many fields at once, consistently shipped, gates at
stage boundaries*; GameFrame's loop optimizes for *one behavior at a time,
provably right, forever revisable*. The trade each makes: ours can batch and
regenerate but routes failures to stages rather than claims; theirs makes
every claim audit-to-the-byte but has no notion of a fleet. Whether
Stardew-scale targets want a loop discipline over our pipeline, and whether
calxgloss should grow a self-parsing registry with an `advise`-equivalent, is
the question the next chapter weighs.

## 9. Sources

- `tmp/opencode/game-frame/skills/re-start/SKILL.md` — `:6`, `:13-27`,
  `:29-53`, `:55-81` (loop, 14-step table), `:79`, `:82-127` (stage agents,
  hand-offs, `:96-99`, `:102-104`, `:106-112`, `:125-126`), `:128-155` (task
  agents), `:156-207` (first session), `:208-227` (goals), `:228-256`
  (effort), `:257-276` (how to work), `:277-289` (session close, worked
  example).
- The other 15 `skills/*/SKILL.md` — anchors as cited in §4-§5: re-setup
  `:8-14, 22-24, 34-41, 43-60, 104`; re-inventory `:6, 16-21, 156, 175-209`;
  re-profile `:15-30, 73-88`; re-browse `:8-16, 157-159`; re-observe
  `:71-101`; re-rea `:15-43`; re-ghidra `:13-23, 166-181`; re-trace
  `:9-30, 99-114`; re-format `:8-10, 132-150`; re-emulate `:16-34`; re-port
  `:11-33, 171-194`; re-cleanroom `:8-9, 19-29`; re-verify `:9, 11-21,
  321-327, 329-331`; re-land `:8-29, 99-118`; re-site `:12-14, 75-97,
  100-120, 271-274`.
- `docs/working/evidence.md:3-18, 20-26, 32-39, 43-50, 52-62, 76-80`;
  `docs/working/writing.md:42-65` (labels, findings structure, commit style).
- `docs/working/clean-room-implementations.md:8-11, 27-38, 42-57, 61-69,
  78-96, 128-134, 151-153, 157-165`; `docs/LEGAL.md:3-7, 13-20, 24-30,
  32-49, 51-62, 64-68`; `skills/re-cleanroom/SKILL.md:8-46`.
- `AGENTS.md:3-5, 9-12, 14-24, 30-61, 67-71, 87`;
  `templates/project/AGENTS.md:26-44, 51-96, 120-131`.
- `docs/working/agents.md:31-53, 71-83, 148-177, 331-351, 353-357`;
  `docs/working/gates.md:3-27`; `agents/` (23 files); `README.md:100-130,
  135, 165-191, 199, 202, 368-380`.
- `tools/gameframe/__main__.py:1-51, 170-197`; `tools/gameframe/skills.py:6-8,
  44-90`; `tools/gameframe/advise.py:1-20, 69-96`; `tools/gameframe/
  mcp_providers.json`; `.mcp.json`; `docs/working/knowhow.md:3-16, 19-47,
  77-101, 105-128, 130-150, 152-166, 183-209`.
- `docs/knowhow/` (142 files); worked entry
  `docs/knowhow/wine-privileged-instruction.md:1-28`.
- Cross-references: [20-gameframe-inventory.md](20-gameframe-inventory.md)
  (the 16-skill / 2,878-line / 142-entry / 23-agent / 14-family counts this
  chapter verifies),
  [22-licensing-and-reverse-engineering-legality.md](22-licensing-and-reverse-engineering-legality.md)
  (outside view of §5),
  [2-architecture-and-toolchain.md](../2-architecture-and-toolchain.md)
  (the calxgloss pipeline contrasted in §8).
