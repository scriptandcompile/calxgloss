# GameFrame's documentation corpus: a domain encyclopedia wired into the workflow

> Part of the [game-frame overview](README.md).

The previous chapters covered the machinery: the CLI (chapter 20), the method
(chapters 30–33), the artifact lifecycle (chapter 34). This chapter covers the other half:
the 734-file markdown-and-SVG corpus under `docs/` that the agents read while they work —
9 MB, larger than the tooling by file count, the only component with no compiled code
behind it. Counts and quotes were measured at the merged HEAD `f195a07` (1 Nov 2026).

What the corpus turns out to be is not a wiki. It is a **reference encyclopedia for a
domain no participant model natively knows** (Intel x86 real mode, Watcom register calls,
OPL2 and SB16 chip semantics), written **for agents to read**, cited by name at specific
steps inside the skill files, and policed by a gap ledger that treats missing
documentation as a tracked defect. The comparison for calxgloss readers is deliberate:
GameFrame's agents carry no compiled knowledge base — their knowledge is prose, loaded on
demand at the right workflow step — while ours is machine-scanable (the pattern
database ADR-0023, the mangling spec ADR-0018, the float/simd scan
rules). Chapter 31 §7 noted the one place
GameFrame's knowledge is machine-served, the `advise` command over `docs/knowhow/`; this
chapter maps the whole corpus and weighs the prose-for-agents design.

## 1. What the corpus is, and how it is wired in

**The counts, as measured at `f195a07`.** `find docs -type f | wc -l` → **734 files**:
371 SVG, 351 markdown, 11 webp, 1 txt — `du -sh docs/` ≈ 9 MB. The 351 markdown files
total 29,545 lines (`find docs -name '*.md' -exec cat {} + | wc -l`).

**The reference guides at the corpus root** — the spine every skill points back to:

| file | lines | subject |
|---|---|---|
| `docs/COMPILED-CODE.md` | 378 | reading compiled x86: entry chains, library-code signatures, optimised arithmetic, evaluation order, decompiler failure modes |
| `docs/DOS.md` | 309 | DOS program kinds, 16-bit Ghidra setup, `dos_emu` / `dos_env` headless running, DOSBox-X, scripted debugging |
| `docs/GAME-PATTERNS.md` | 286 | fixed-step loops, update order, drift, RNG, saves |
| `docs/DATA-DICTIONARY.md` | 120 | the per-value table (unit, range, evidence) every project fills in |
| `docs/TYPES.md` | 121 | type recovery from uses, C++ containers, date/time encodings |
| `docs/TAXONOMIES.md` | 95 | controlled vocabularies: kinds of code, data, values, evidence, difference |
| `docs/ABI.md` | 107 | calling conventions by platform, MSVC C++ layout, floating point, integers |
| `docs/README.md` | 98 | the corpus map; it also points at the site build |
| `docs/LEGAL.md`, `docs/OUTPUTS.md`, `docs/SETUP.md` | 68 / 119 / 65 | licence policy, ship list, toolchain |

**The topic directories** (markdown files / lines):

| directory | files | lines | directory | files | lines |
|---|---|---|---|---|---|
| `knowhow/` | 142 | 6,775 | `working/` | 20 | 2,929 |
| `hardware/` | 32 | 3,540 | `arcade/` | 14 | 2,586 |
| `engines/` | 16 | 1,434 | `computers/` | 17 | 2,503 |
| `observe/` | 13 | 1,269 | `handhelds/` | 14 | 1,052 |
| `preservation/` | 14 | 1,072 | `consoles/` | 9 | 1,046 |
| `games/` | 12 | 955 | `teams/` | 10 | 507 |
| `harness/` | 10 | 430 | `media/` | 5 | 665 |
| `case-studies/` | 6 | 523 | `semantics/` + `crates/` | 6 | 493 |

Two things stand out. `knowhow/` is the largest directory — bigger than all platform
knowledge combined — and the platform shelves (`computers`/`handhelds`/`consoles`/`arcade`,
54 files, 7,187 lines) are one coverage matrix, one page per machine or board family;
chapter 20 §15 covered the same tree from the CLI's side.

**How it is wired.** Explicitly, at three layers:

1. **Skills cite the guides by name, at the step where the knowledge is needed.**
   `skills/re-profile/SKILL.md:22-24` sends the profiler to the game taxonomy
   (`docs/games/README.md`, its family page, `docs/games/interaction.md`) and the
   engine/platform/hardware pages, then to `docs/working/knowhow.md` and `./gameframe
   advise` (`:25`). `re-port/SKILL.md:16` cites `docs/LEGAL.md` before any clean-room
   decision; `:18` cites `docs/crates/` ("Before you write a sound chip, a codec or a
   language runtime yourself, check `docs/crates/`"); `:81` cites
   `docs/working/building-the-port.md` for the frame; `:150` cites `docs/COMPILED-CODE.md`
   ("Order of evaluation") and `:154` cites `docs/GAME-PATTERNS.md` ("Update order").
   `re-emulate/SKILL.md:91` cites `docs/ABI.md`, `:142` cites `docs/DOS.md` §5b (`dos_env`),
   `:148` cites §6–7. `re-trace/SKILL.md:80` and `agents/re-typer.md:24,30` cite
   `docs/TYPES.md`; `re-land/SKILL.md:28` cites `docs/DATA-DICTIONARY.md` and `:51-52`
   copies `docs/knowhow/_template.md` into the project. A skill line is a pointer, not a
   summary — the corpus is what the pointer resolves to.
2. **The CLI serves the corpus.** `docs search` / `docs read` / `docs index`
   (chapter 20 §15); `tools/triage/dictionary.py:8` names `docs/DATA-DICTIONARY.md`
   ("describes each column") and `docs/TAXONOMIES.md` ("lists the kinds") as its source of
   truth; `./gameframe advise` ranks `docs/knowhow/` entries (weights at
   `tools/gameframe/advise.py:18`) and the hook `scripts/hooks/advise.py` names entries
   automatically "when a command's output matches" (`docs/knowhow/README.md:4-6`) — the
   strongest routing wire in the project: knowledge fires on command output, without an
   agent deciding to go read (chapter 31 §7).
3. **The website is the same corpus rendered.** `docs/README.md:9-10`: "The website is
   built from these files where they are (see [site/README.md])" — the site lives at the
   repo root, its menu order is the READMEs' order, `site/diagrams/` holds the 21 Python
   files that regenerate the figures, and `site/lab/` pages are in-browser versions of the
   triage tools whose results "match the one the tool gives in a project"
   (`site/lab/index.md:3-4`). Documents, site, lab and CLI read one tree — four surfaces.

**The diagrams.** 371 SVG, all under `docs/assets/`: 365 figures under
`docs/assets/diagrams/`, 5 terminal screenshots under `docs/assets/captures/`, and
`docs/assets/method-loop.svg`; the 11 webp images sit in `docs/assets/case-studies/`.
What a figure carries, four examples: `compile-stages.svg` (`docs/COMPILED-CODE.md:13`)
walks the build stages and what each *removes* — the licence for reading decompiler output
backwards; `signature-match.svg` (`:53`) draws a library function as a wildcarded byte
signature matched into a game's binary; `eval-order.svg` (`:206`) shows two RNG draws
taken as arguments of one call "in the order the binary shows" — the figure *is* the
procedure; `fixed-step.svg` (`docs/GAME-PATTERNS.md:13`) draws equal simulation updates
fitted into unequal frames. The captures are evidence, too: `captures/run-tests.svg`, a
real harness run captioned "94 passed, 0 failed", sits at `docs/SETUP.md:45` as the
specimen of the evidence culture.

## 2. The compiled-code spine: six cross-referenced guides

The corpus's deepest thread is reading *x86 as compiled source*; the guides cross-reference
each other deliberately (`docs/COMPILED-CODE.md:7` sends the reader to ABI, DOS and TYPES
for conventions, segment models and type shapes).

**`docs/COMPILED-CODE.md` (378 lines) — the master guide**, whose section list *is* the
reading procedure: what compiling removes (§11); finding the game's own code from the entry
point through the C runtime to `main` (§33); naming library code by signature — wildcarded
byte signatures against a library-function database (§52); optimised arithmetic (§76);
branches, loops, functions, registers, stack slots (§113–173); order of evaluation (§204);
the flags (§225); *when the decompiler is wrong* — its staged assumptions about code/data
separation and function boundaries (§249); the linker, symbols, game-compiled tools
(§271–350); what to record (§371). Three passages stand out:

- Float constants: "A folded float constant is exact in the binary. Copy its bits into
  the port (`f32::from_bits(0x3eaaaaab)`) or write a literal that gives the same bits.
  A float expression in the port's source can be folded with a different precision or a
  different order." (`:99-101`)
- Recovered divisors: "The multiply-and-shift form comes from the compiler. It gives the
  same result. Confirm a recovered divisor with `re-emulate` on a few inputs, including
  negative ones." (`:106-107`) — knowledge that ends by routing back to a tool.
- Evaluation order as a determinism tool: the `eval-order.svg` figure heads §204, and the
  prose notes that some languages "compute arguments from left to right" while many x86
  compilers passing arguments on the stack do not (`:216-217`) — the binary's push order
  recovers the real one, which is how an RNG's draw order gets pinned. Compiler identity
  rides in tell tables along the way (Watcom DOS/4GW: "the entry of the LE program calls
  `__CMain`, which calls `main`" — `:46`).

**`docs/ABI.md` (107 lines) — the convention reference.** §Calling conventions opens with
the `abi-stack.svg` figure (`:9`) and a per-platform table (Windows x64 shadow space,
System V red zone, the 32-bit conventions), then MSVC C++ layout (§27), floating point
(§42), integers (§78). Consumed at `re-emulate/SKILL.md:91` for exactly the decision the
table is built for ("pass `ecx=` for thiscall").

**`docs/DOS.md` (309 lines) — the era's runtime, reorganized around its own tools.** §1
classifies the DOS program via `tools/dos/dosinfo.py` — "format, segments, imports,
fingerprints" (`:11`); §2 Ghidra addressing (§56); §3 *check debug symbols before anything
else* (§72); §4 16-bit decompilation in Ghidra (§112); §5 one function under `dos_emu`
(§189); §5b the whole program headless under `dos_env` — "a small DOS, BIOS, DPMI host and
PC, so a whole Borland Pascal 7 DPMI16 program can start and run, with no DOSBox and no
window" (`:212-213`); §6 DOSBox-X (§252); §7 the debugger from an agent or script (§282).

**`docs/TYPES.md` (121 lines) — type recovery.** Where types come from (§12); reading a
structure from its uses (§25); shapes in the code (§44); the C++ standard containers (§60);
and **dates and times in data** (§85): an eight-form table (`:90-99` — Unix seconds/ms,
FILETIME, SYSTEMTIME, DOS date, HFS, OLE DATE, ISO 9660) plus the two-save probe: "the
offset whose value moved by those minutes is the date" via `tools/triage/dates.py`
(`:101-104`). Consumed at `re-trace/SKILL.md:80` and `agents/re-typer.md:24,30`. One
wrinkle for §7: `GAPS.md:36` calls this gap "nine stored forms" while the merged table has
eight rows — number-drift a ticked entry accumulates after a reorg.

**`docs/TAXONOMIES.md` (95 lines) — the shared vocabulary.** One controlled list per
dimension: kinds of code (§13), data (§29), values (§45), evidence (§64), difference (§76),
and using the names (§90). It is the type system behind the data dictionary
(`dictionary.py:8`).

**`docs/DATA-DICTIONARY.md` (120 lines) — the per-value contract.** Definition (`:5-11`):
the labels files name functions and fields, but "Neither says what a value means, in which
unit it is counted, which values it can take, or which code changes it. The data
dictionary holds that. It is one table, with one row for each value the rules use, and
every row cites its evidence." It "serves three readers": a person reading findings, an
agent writing a type, a test author finding edge cases (`:13-16`). Sections: the columns
(§25), an example (§54), how to fill it (§71), checking (§90), using (§106), what to
record (§116). Consumed at `re-land/SKILL.md:28`.

**`docs/knowhow/` (142 files, 6,775 lines) — the corpus's memory.** The largest directory,
titles as topic index: `watcom-pseudocode-drops-register-arguments`, `context-watcom`,
`x87-magic-add-rounding`, `wine-wow64-rosetta-fault`, `writer-round-trip-every-file`,
`replay-sample-straddles-frames`, `trace-claims-need-an-address-scan`. The README states
the design: entries record a failure and what was done, "one failure mode or one piece of
context. An agent finds them with `./gameframe advise`. A hook names them when a command's
output matches" (`:3-5`). Frontmatter carries a `status:`; measured: **69 `context`, 60
`solved`, 8 `workaround`, 3 `open`, 1 `dead-end`**. The `dead-end` status is the notable
one — a recorded negative result stays rankable, so an agent can be told this route
already failed ("Some of them are known dead ends" — `docs/case-studies/pod.md:80`).

**vs calxgloss.** calxgloss encodes this class of knowledge as machine-scanable artifacts —
pattern database, mangling parser (ADR-0018), float/simd rules — because our consumers are
tools. GameFrame's equivalent is prose an agent applies judgment to — *except* where the
knowledge must fire mechanically, and there it builds our shapes anyway: wildcard
signature matchers (§52), `dosinfo.py` fingerprints, `dates.py`'s probe, `constants.py`'s
recognizers. Both converge on the same split from opposite directions: prose for what
needs judgment, code for what must fire.

## 3. The game-domain spine

**`docs/GAME-PATTERNS.md` (286 lines).** The opening figure (`:13`) draws the shape the
guide rests on — equal simulation updates in unequal frames — and the MSVC `rand()` figure
walks the LCG bit-by-bit (`:35`). The deepest section is **Update order** (§97): a table of
every place execution order hides — a fixed-size pool ("which slot a new object takes, and
so its id and its place in the update order", `:110`), a dirty-flag cache ("if the
computation uses random numbers or rounds floats, the moment matters", `:112`),
one-object-vs-one-system iteration ("a port that runs one system over all objects, then the
next system, draws in another order", `:114`), spatial grids (`:120`). The stakes:
"Record each decision with the address that shows it. A port that gets one of these wrong
can look right for minutes, then drift once an object dies in the middle of a frame."
(`:117-118`) Drift gets a computed figure — the float-clock error over an hour (`:156`) —
and the rule the drift sections lean on: "the same steps in the same order with the same
numbers, or objects drift apart within seconds" (`:175-176`); a save is "the serialized
world... plus the random" state (`:258`). Consumed at `re-port/SKILL.md:154`.

**`docs/games/` (12 files, 955 lines).** Not genres-as-shelf-labels but an axis model.
Premise (`:5-10`): "The hard part differs by kind of game: the frame loop in a shooter, the
simulation and saves in a city builder, the script engine in an adventure game. This
section sorts games into families, gives each family a **rule set** (what must be exact,
where the rules live, what to capture, how to check), names reference games, and lists
public projects that rebuilt such games." Procedure (`:14-16`): decide who drives (the game
or the player — `interaction.md`), place the game on the axes table (`:40-48`), then step
3: "Read its family page (or pages, for a mixed game) and copy the rule set into the
project's" — taxonomy becomes project configuration. The families table (`:56`) maps ten
families to *who drives*, *typical time model*, *the hardest part*; the pages are
management, strategy, rpg, adventure, first-person, racing-sports, vehicle-sims,
arcade-action, puzzle-board, online (+ interaction) — the management page's "a world that
runs on its own, slowly, and a player who arranges it through windows, menus and clicks"
(`:5-6`) is where the Frontier study sends its OpenRCT2/OpenLoco precedent
(`frontier.md:86`). Consumed at `re-profile/SKILL.md:22-23`.

**`docs/engines/` (16 files, 1,434 lines).** Historical premise (`:5-9`): from the
mid-1990s games were "built on a licensed engine (Build, the Quake engines, Unreal)... Most
games also use **middleware**: libraries for one job, such as video (Smacker, Bink), sound
(Miles, FMOD) or physics (Havok)." Recognising an engine from strings, file names, magic
numbers and libraries (§27); family pages — id-tech, Build, Unreal ("packages, native
classes and UnrealScript", §38); internals — interpreters, coroutines, garbage collection,
script runtimes. The payoff is the **known-engine multiplier** table (`:73-82`): with a
known engine you name functions from its source or exports, read the scripts first, check
maths against the engine's released source, and verify against the engine's own demos and
test maps — an extra oracle the corpus hands the method, tempered by the version warning
and its figure of licensee forks diverging (`:84-86`).

**`docs/hardware/` (32 files, 3,540 lines).** Premise (`:6-13`): a PC game from 1985–2005
"uses its hardware far more directly than a modern program... you need to know what each
piece of hardware did, how the game used it, and which of its details the player can see
or hear." The README doubles as an *agent prompt* (`:19-33`): find the IN/OUT/INT
instructions and writes to A000/B800/0040, name the driver functions, "list the values the
game reads back from the hardware. They are inputs", propose one reference configuration
and ask a human to confirm it. Pages: CPU/FPU/SIMD history, 2D modes, 3D accelerators, the
rendering pipeline ("the port built as a virtual card"), the card makers' 3D APIs (Glide
2.x, ATI3DCIF, S3D), and the merge's biggest growth — **sound-card API contracts**:
twenty-odd pages pinning what each register interface promises (`sound.md`,
`sound-card-apis.md`, eight `sb16-*-contract` pages, the sbbasic pages, AdLib Gold, CMS,
Tandy, YMF262). `wrappers.md` (430 lines) keeps the corpus's honesty note: the replacement
DLLs "have been tested with one game so far, POD: Planet of Death. They implement only the
calls POD makes." (`:12-13`) §7's ledger tracks the audio pages' open seams.

**`docs/semantics/` (5 files, 400 lines).** The platform-difference pages — integers,
floats, library behaviour (`rand`, `qsort`, `printf`), text/encodings — opened by the
thesis any reimplementation project inherits (`:3-7`): "A reimplementation runs on a
different CPU, a different compiler and often a different language from the original. Most
of what the original computes comes out the same anyway. A few things do not."

**The platform shelves** — `computers/` (17/2,503: Amiga, Atari ST, Acorn, CPC, Apple II,
IBM PC, Mac), `consoles/` (9/1,046), `handhelds/` (14/1,052), `arcade/` (14/2,586: CPS,
Neo Geo, Williams/Midway, coin-op practice, protection) — are one coverage matrix, one page
per machine or board. They also enforce the licence line at the knowledge level: leaked
schematics circulate, but "GameFrame's rule against game material means a project does not
copy such source" (`arcade/practices.md:225`); and the Williams page states what the record
supports — "No primary source shows an official release of the Defender or Robotron"
prototypes (`williams-and-midway.md:55`).

## 4. The process spine (brief — the machinery chapters cover it)

| shelf | size | what it fixes | covered in |
|---|---|---|---|
| `working/` | 20/2,929 | the method in motion — "The skills describe each step of the method. These pages cover the work that spans several steps and several sessions" (`README.md:5-7`). `building-the-port.md` (365 lines) carries the **frame contract**: "The original had no frame. GameFrame provides it... the core talks to it only through a versioned contract of events" (`:11-12`); §The contract (`:94-97`): core and frame "exchange events and nothing else" (topics/manifest/session on the `gameframe-frame` crate). Plus `lore.md` ("they often say what a system is for before the code does", `:3-5`, worked example Hardwar), `hybrid-port.md` (replacing the original routine by routine), `knowhow.md` (the knowhow design), `evidence.md`, `gates.md`, `versions.md`, `viewer.md`, `mods.md` | ch. 32 §4; ch. 20 §13; ch. 35 §5 |
| `observe/` | 13/1,269 | the evidence toolkit: `running-the-original.md`, `recording.md`, `object-model.md` ("a model to query"), emulators (86Box, DOSBox-X), memory, inputs, network, debuggers, ui — its README opens with a copy-paste agent prompt: "Record next to each capture the game version, the settings, the seed and the inputs" (`:13`) | ch. 31 §2 |
| `harness/` | 10/430 | the environment-test harness: README + 8 modules + `_template.md` (disc-drive, dosbox-x, emupc-wine, glide-wrapper, silent-audio, steam-client-wine, wine-host, xaudio2-wma). "The harness writes each answer down once, as a module, so the next game that needs the same thing starts with it" (`:5-6`); "A need is a lead and never a proof" (`:32`); `needs.py` proposes which modules a binary needs | ch. 33; ch. 35 §5 |
| `semantics/` | 5/400 | the platform-difference rules (§3) | ch. 34 §1 |
| `teams/` | 10/507 | the org model: "GameFrame has 23 agents. Nine stage agents follow the steps of the method. Fourteen task agents do one job each" (`README.md:3-4`) | ch. 32 §2 |
| `preservation/` + `media/` | 14/1,072 + 5/665 | the artefact lifecycle — why games disappear, rights-holders, the law directory (`rights-holders.md:5`: "GameFrame never ships your game, its files or its assets") — plus media formats, discs, protection | ch. 34 §§1–2, §6 |
| `crates/` | 1/93 | the crate index with a provenance column (§5) | ch. 35 §9 |

## 5. The case studies: five worked ports, five different jobs

`docs/case-studies/` (6 files, 523 lines) is the corpus's worked examples; each report
feeds the shelves above differently.

| study | lines | the build | what it fed back |
|---|---|---|---|
| `banished.md` | 114 | Banished (2014) → **Un-Banished**: ~130k lines of Rust, Windows/macOS/Linux/browser | the framework itself: "GameFrame was extracted from it: the skills, the Ghidra scripts and the emulator began there and were made generic here" (`:5-6`) |
| `tyrian.md` | 78 | Tyrian 2000 (DOS 1999) → clean-room 1:1 Rust ("Tyrian 2026") | `tools/dos/` and `tools/emu/dos_env/` "came from it" (`:6`) |
| `frontier.md` | 86 | Frontier: Elite II (1993) → Rust+wgpu, **original running inside the port** | the hybrid-port route (`working/hybrid-port.md`); per-module label generation (`cite_labels.py`) |
| `pod.md` | 85 | POD: Planet of Death (1997) → docs+rebuild from the disc image | the know-how layer itself; tools (`winput`, `memrec`, `refs`, `emupc`, `shot`, `modfolder`); `wrappers/`; crates `mmx` + `gpu-1997` (`:56-70`) |
| `hardwar.md` | 113 | Hardwar (1998) → 1:1 Rust over the player's pack | `working/lore.md` (lore-as-evidence), `constants` findings, the viewer pattern |

**Un-Banished** is the scale reference and the ancestor: "2,050 of 9,846 original functions
traced (68 % of the game's code by size); 170 of 170 resource types; around 45 documented
deviations" (`:99-100`); its own generated labels raised the labelled share of the binary
"from 10.2 % to 28.2 % by size" (`:94-95`). Its last section maps its repo onto GameFrame
file by file — `AGENTS.md` → the project template, `banished-*` skills → `re-*` — the
corpus citing its origin.

**Tyrian** is the 16-bit cautionary tale: Turbo Pascal 7 real mode, and the shipped program
"kept its Turbo Debugger symbols" (`:20-21`) — symbols deciding the whole route. The frame
loop (MAIN, ~19 KB) "is split into about" a dozen fragments, each re-verified from captured
states in the original's order (`:31`); the teaching: "A fragment that matches stays matched
while the rest is written" (`:74-75`). OPL2 music was matched at register-write level (`:46-47`).

**Frontier** is the in-process-oracle case: "The port runs the original inside itself and
replaces it routine by routine" (`:8-9`), on a runtime the project wrote — "an in-process
386 real-mode CPU with the DOS" (`:26`) — twenty demand-loaded overlays plus separate
maths/video/sound driver overlays, all 47 maths-overlay routines ported first (`:31`). Its
labels cover "97.8 % of `EL2MATH3`'s code, 97.6 % of `EL2ADLIB` and 23.0 % of `EL2MCGA3`,
where before nothing was labelled" (`:54-55`). Its teachings are test-design rules
(`:73-83`): "running it inside the port gives a playable game on day one and an oracle in
every test"; "Several early tests passed while comparing nothing, because every call was
declined or skipped"; "Count the calls that still go to the original in a real session."

**POD: Planet of Death** is the origin story for *knowledge*: Watcom C with register calls,
DirectDraw, DirectInput (`:13`), and GameFrame's know-how "began here" (`:16`) — entries
cited inline at each step of the walkthrough. What it gave back (`:56-70`): the know-how
layer (56 entries), seven tools, the replacement libraries in `wrappers/` "made
game-agnostic (POD's window class, marker colour and code patches became settings)", and
the MMX/gpu-1997 crates. Its lessons are corpus doctrine (`:79-80`): "Ask the know-how
before you debug a run. Most failures of a 1997 game on a modern machine are already known.
Some of them are known dead ends."

**Hardwar** is the lore case. The data pack: sequential records plus a trailing directory
of 28-byte entries whose names are "XORed with a 16-byte key... the padding stores the key
itself... the key is the developer's name, stored in the program" (`:34`); 614 of 621
entries decoded by the viewer milestone (`:42`). Foundations found by signature: one
Park–Miller generator "found by its multiplier 16,807" (`:55-56`), an FPU set to single
precision with truncation, a world clock of 0x10000000 units a day (`:57-58`), a logging
function called from 777 places (`:59-60`). *What the story explained* (`:67-77`): the
manual on disc 1 plus ~200 in-program strings predicted which code mattered — "craft that
run on solar cells, so lighting is game logic and the crater lights follow the time of
day" — the case that grew `docs/working/lore.md`.

The README's consensus list (`:35-47`) is the five studies talking at once: **name
everything first**; **capture from the original, then port**; **build an entry point into
the game** ("one narrow way in that tests, scripts and agents all use"); **read the story
for what each system is for** (cited "from Hardwar"); **check in small pieces, then as a
whole**. Above it, the comparison table (`:20-33`) puts every tool the five projects needed
side by side — how generic tools get identified (chapter 35's provenance map reads the same
table from the code side). The sixth project lives in the CHANGELOG (`:12-18`):
"Lessons from TabStationToo, PCSX2 compiled to WebAssembly" — `re-verify` gained written
lists of what is compared and left out, **lockstep** ("the program goes on with the
reference's result"), fuzzing against a reference, deterministic thread mode, V8
dual-compiler testing; `building-the-port.md` gained browser pitfalls (hosting headers,
storage limits, WebGPU readback, gamepads). A browser port with no prior knowledge
anywhere — now two guides and several skill rules heavier.

## 6. Legal, outputs, setup

**`docs/LEGAL.md` (68 lines)** — the project's ground rules in one page, opening with a
figure of what goes in the public repo and what stays local (`assets/diagrams/shared-kept.svg`,
`:11`). The core rule: "Nothing from the game is redistributed. Binaries, data files,
extracted art, sound, text, saves, decompiled code and disassembly stay on the local
machine, in folders git ignores." (`:14-15`) The authorship rule: "The result is new work.
A reimplementation is written from your understanding of the behaviour, recorded in your
own words, not translated from decompiled code." (`:16-17`) The ship shape: "Players bring
their own copy. A reimplementation reads the player's game files at run time, as projects
such as OpenRCT2, OpenMW, DevilutionX and Un-Banished do." (`:18-19`) The *why* table
(`:23-31`) gives each default a reason — decompiled code is a derivative ("publishing it
can infringe"); behaviour facts "are generally not protected the way expression is". The
row that underwrites the evidence culture: "Cite the original function for every finding —
Anyone can check the finding against the original. The citation also shows that the
reimplementation came from analysis rather than a leak." (`:29`) **This rule is why the
evidence in chapter 35's repo review was capped** — everything in-repo is self-recorded,
because the originals' artifacts may never ship.

**`docs/OUTPUTS.md` (119 lines)** — what a project can ship: findings documents "useful on
their own to modders and to other projects" (`:11`); a generated website "built by CI on
every push" via the `re-site` skill (`:12-13`); the reimplementation with ready-made
programs per system (§29); the browser version — "the page asks for them, keeps them in
the browser's storage, and never uploads them" (`:89`), built on the library-page template
(`:92`); and *Additions to the original* (§95): the features-but-vanilla switch shipped
alongside.

**`docs/SETUP.md` (65 lines)** — the toolchain with the corpus's pinned-version honesty.
The clone plus a *GameFrame home* outside it: `./gameframe home init` (defaults to
`~/gameframe`; holds the games, projects, machines and shared Python) and `home doctor` as
the health check (`:9-16`). Every observation server is pinned — "REA, DOSBox-X MCP,
MCPEmulate and 86Box MCP each have a pinned version or source revision" (`:38`); REA needs
Node 22.23.4+ with `rea-agents` 6.7.0 (`:57`). The pytest capture at `:45`
("94 passed, 0 failed") is the run-evidence specimen.

## 7. GAPS.md: the corpus's anti-rot device

`GAPS.md` (repo root, 356 lines) is a **todo ledger for the encyclopedia itself**. Its
standing instruction (`:3-6`): "The list of topics found missing from GameFrame's guides
and tools... Tick an item when its guide section or tool is merged... Items marked *out of
scope* stay listed, with the reason, so they are not proposed again." Counts as measured:
`grep -c '^- \[x\]' GAPS.md` → **149 ticked**, `grep -c '^- \[ \]'` → **29 open**. The
groups are the corpus's own contents — *Reading compiled code* (:8), *Types and data*
(:34), *Game patterns* (:40), *Graphics* (:53), *Sound* (:70), *Engines* (:145),
*Observing* (:149), *Media and protection* (:162), *Tools* (:169), *Reading the story*
(:234), *Know-how* (:242) — plus *Out of scope* (:339).

The ledger shows what the corpus is *working on*, because the open items concentrate:
nearly all 29 sit in Graphics and Sound — YMF262 four-operator routing (`:83`), the YAC512
analog transfer curve (`:80`), CT1741 ADPCM timing (`:131`), SN76496 noise taps (`:117`),
the `ddraw.dll` COM call log (`:68`). The same gaps appear, in matching wording, in the
hardware contract pages and the crate index ("independent four-operator carrier routing,
YAC512 analog conversion and card adapters remain open" — `docs/crates/README.md:10`):
ledger, guides and crate notes are **one tracking system with three surfaces** — an open
seam recorded wherever a consumer meets it. Gaps also close by guide section *and* tool at
once — "Dates and times in data, nine stored forms (`tools/triage/dates.py`)" (`:36`),
"`constants.py`: Park-Miller's 16807 reported when its modulus or Schrage's constants are
beside it" (`:204`). The out-of-scope block (`:341-356`) defines the corpus's edge with
reasons: compiler/SSA theory ("reading their output needs only the results above"); cycle
counting ("they change speed, not results"); cheats ("they change play"); keygens and ROP
("security work, not porting"). The eight-vs-nine date-form count (§2) is the
counter-example — number drift a ticked entry accumulates once its guide reorganizes.

**vs calxgloss.** No direct analog. The nearest are the roadmap's P-numbers and the closed
six-kind `UnknownRecord` roster — but both are *machine-visible*: an unknown-kind record
makes staleness a parse event, not a reading-comprehension problem. GameFrame's ledger
works because each item names the guide *and* the tool that closes it; if our pattern DB
grows prose entries, that two-sided item shape is worth copying.

## 8. Assessment: what the corpus design buys, and what it costs

**Docs-for-agents-to-read vs machine-consumed evidence.** The corpus is written for a
reader that can *decide*: a skill line ("read GAME-PATTERNS.md, Update order") routes an
agent to prose it applies judgment to. calxgloss knowledge is mostly *executed*. But
GameFrame's knowledge becomes machine-consumed exactly where it must fire without
judgment — advise ranking (`advise.py:18`) plus the hook firing on command output,
`needs.py`, `dates.py`, `constants.py`, `dictionary.py`, `dosinfo.py` fingerprints, the
wildcard signature matcher. Both projects converge on the same rule: **knowledge is
machine-consumed only where it must fire without judgment; everything else stays prose and
gets routed, not loaded.** GameFrame's routing is three-tier — skill pointers to sections,
the CLI serving files, advise/hooks injecting top-scoring entries — which is the
relationship calxgloss has between an evidence *bundle* and a run: the store is large,
each phase gets a small curated slice, and the store's shape (typed, indexed, sectioned)
makes slicing cheap. The mirror-check: our bundles are small *by construction* (a gloss
run has narrow needs); GameFrame's corpus is large because an encyclopedia serves every
need — and the cost is routing infrastructure (CLI, site, advisor, hooks) we don't pay.

**Token budget.** 734 files, 29,545 lines of markdown, 371 figures — no context window
holds it, and GameFrame never tries: skills embed pointers and section names, nothing
else. The corpus is structured to be *addressed* — family pages, named sections, one-page
incident files with frontmatter status. That section-level addressability is what our own
reference docs should steal: ADRs are addressable units, but our pattern-DB prose and
glossary entries are not yet addressable at the granularity an agent mid-run needs.

**Staleness.** A 29.5k-line prose corpus drifts, and GameFrame fights it structurally:
GAPS items close by guide *and* tool together; out-of-scope items stay listed with
reasons; crates carry "remain open" clauses mirroring the ledger. The eight-vs-nine
date-form count is the failure mode surviving all that. Compare calxgloss: an ADR is
*allowed* to be stale because the code is the arbiter and the gloss engine regenerates
evidence from code; a GAPS item is a claim with no arbiter. Our profile is better by
construction; GameFrame's is more honest by procedure.

**The provenance loop.** Case studies feed guides, guides feed skills, skills produce the
next case study, and the consensus list (`case-studies/README.md:35-47`) audits the loop.
The crates index makes it mechanical: every crate names the project and evidence that
produced it (opl2 from Frontier "sample for sample"; wma from Un-Banished "within 60 dB of
FFmpeg"; mmx from POD "matched the original on 500 random channels" —
`docs/crates/README.md:9-20`), and unproven seams carry the same open/closed lifecycle as
GAPS, attached to code. calxgloss bundles have no equivalent of a *what the last run taught
us* guide — attempt-commit justifications and the web analytics are
per-run records; nothing distils lessons across runs. GameFrame's discipline: no lesson is general
until it lands in a guide with a status, and no code ships without its evidence line.

**Net.** The corpus is the most durable-looking part of GameFrame — five ports deep, and
it absorbed this year's merges (the DOS guide re-shelved around its new runnable tools; the
hardware shelf rebuilt around the sound-card contracts). Its weakness is every
encyclopedia's: prose re-asserting its own numbers, and single-game testing declared
inside the page that depends on it. For calxgloss the transferable parts are the *wiring
pattern* — skill-step-to-section pointers, the knowhow `status:` lifecycle including
`dead-end`, gap items naming both the doc and the tool, the provenance column on code.

## 9. Sources

Read in full (at `f195a07`, clone-relative): `GAPS.md` (356); the eleven root guides
(`docs/README.md` 98, `COMPILED-CODE.md` 378, `DOS.md` 309, `GAME-PATTERNS.md` 286,
`DATA-DICTIONARY.md` 120, `TYPES.md` 121, `TAXONOMIES.md` 95, `ABI.md` 107, `LEGAL.md` 68,
`OUTPUTS.md` 119, `SETUP.md` 65); `docs/case-studies/README.md` + banished 114 / tyrian 78
/ frontier 86 / pod 85 / hardwar 113; `docs/games/README.md` 111 and `management.md` 85;
`docs/hardware/README.md` 119 and `wrappers.md` (head); `docs/engines/README.md` 90;
`docs/semantics/README.md` 22; `docs/preservation/` README + `rights-holders.md`;
`docs/media/README.md` 38; `docs/observe/README.md` 48; `docs/harness/README.md` 76;
`docs/working/` README 50 + `lore.md`/`knowhow.md` heads + `building-the-port.md`
(sections + `:8-14`, `:94-122`); `docs/teams/README.md` 121; `docs/crates/README.md` 93;
`docs/knowhow/README.md` + `watcom-pseudocode-drops-register-arguments.md` 63;
`docs/arcade/practices.md:225`, `williams-and-midway.md:55`; `CHANGELOG.md:10-18`.

Read by targeted grep/section survey: the inventories of `docs/games/`, `docs/engines/`,
`docs/hardware/`, `docs/computers/`, `docs/consoles/`, `docs/handhelds/`, `docs/arcade/`,
`docs/observe/`, `docs/preservation/`, `docs/media/`, `docs/semantics/`, `docs/working/`;
the six cited `skills/re-*/SKILL.md` files, `agents/re-typer.md`, the 23-agent `agents/`
listing, `tools/triage/dictionary.py:8`, `tools/gameframe/advise.py:18`, `site/index.md`,
`site/lab/index.md`, `templates/`.

Count commands (from the clone root): `find docs -type f | wc -l` (734); extension
breakdown (371 svg / 351 md / 11 webp / 1 txt); `find docs -name '*.md' -exec cat {} + |
wc -l` (29,545); per-directory md counts/lines likewise; `du -sh docs/` (9.0M); svg split
(diagrams 365, captures 5, method-loop 1); `find site -name '*.py' | wc -l` (21);
`grep -c '^- \[x\]' GAPS.md` (149) / `'^- \[ \]'` (29); knowhow statuses via
`grep -h '^status:' docs/knowhow/*.md | sort | uniq -c` (69 context, 60 solved, 8
workaround, 3 open, 1 dead-end).

Cross-references: ch. 20 §15 (the tree from the CLI side) and §16 (the generated site);
ch. 31 §2 (the observe toolset) and §7 (advise's knowhow ranking); ch. 32 §4 (the frame
contract); ch. 34 §6 (sample governance); ch. 35 §5–§6 (evidence cap, library ceiling),
§9 (case-to-crate provenance).
