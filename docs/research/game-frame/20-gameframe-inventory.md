# GameFrame repository inventory at HEAD f195a074

> Part of the [game-frame overview](README.md).

Complete file-by-file inventory of the GameFrame repository
(`tanepiper/game-frame`) as checked out at commit
`f195a074a63cc150673c38becdec696163b0b3d1`. This is
one chapter of the GameFrame dossier; scoping and methodology live in `00-scope-and-method.md`.

**Verification posture.** Every number below was counted on 2026-10-31 against a full, clean clone
pinned at `f195a074` (`git status --short` empty at capture time). Every claim about a file cites
the clone-relative path, with line numbers for specific claims and path-only for whole-file
purpose. Self-counted numbers state the counting command. The clone had to be re-created during
this work (the earlier checkout at this path carried stale, non-committed state); all counts here
come from the fresh clone's committed tree, and all line-number citations were re-opened against
it. **This tree is materially different from the one an earlier draft of this chapter was written
against** — see §21 and §22.

## 1. Repository-level facts

**Scale.** The tracked tree at `f195a074` holds **1,645 files** (`git ls-tree -r HEAD --name-only |
wc -l`), of which **1,642 regular files and 3 symlinks** (`git ls-tree -r HEAD | grep '^120000'`:
`.claude/agents`, `.claude/skills`, `.agents/skills`). Total tracked content is **185,381 lines**
(`git ls-tree -r HEAD --name-only | xargs cat | wc -l` — every tracked file, sources, markdown,
SVG diagrams, lock files).

**Size on disk.** `du -sh`: `.git` 7.9 MB, full checkout 26 MB. No `.venv` or build outputs in a
fresh clone (they are gitignored: `.gitignore` covers `analysis/`, `*/target/`, `site/node_modules/`,
`.venv/`, `derived/`, `__pycache__/`; full text 38 lines, `.gitignore:1-38`).

**GitHub state** (`gh repo view tanepiper/game-frame`, fetched 2026-10-31): 20 stars, 6 forks,
default branch `main`, homepage `https://tanepiper.github.io/game-frame/`, **`isTemplate: true`** —
it is registered as a template repository. The same facts are cited from `00-scope-and-method.md:95-101`.

**History.** 383 commits (`git rev-list --count HEAD`), first 2026-10-21, last 2026-10-30, by a
single author: `383 Tane Piper` (`git shortlog -sn HEAD` shows one name). Daily cadence
(`git log --date=short --format='%ad' | sort | uniq -c`): 21 Oct 66, 22nd 54, 23rd 40, 24th 87,
25th 78, 26th 36, 27th 20, 28th **0**, 29th 1, 30th 1. HEAD: `f195a07` "Merge completed slices
into local main", 2026-10-30 21:56:26 +0100.

**Tags and release position.** Six tags, `v1.0.0` … `v1.4.0`; `git describe --tags` gives
**`v1.4.0-49-gf195a07`** — HEAD is 49 commits past the last release tag. The working version is
`1.5.0-dev` (`.claude-plugin/plugin.json:3`, matching the CHANGELOG Unreleased section,
`CHANGELOG.md:8`; the release flow that keeps the two in lockstep is `AGENTS.md:84`).

## 2. Repository root layout

Root-level tracked files — all 15 of them (`git ls-tree HEAD --name-only`, LOC counted):

| File | LOC | Role |
|---|---|---|
| `.gitignore` | 38 | Build outputs, Ghidra exports, site caches, editor files |
| `.mcp.json` | 10 | Claude Code MCP config: **only** `gameframe` → `./gameframe serve` |
| `AGENTS.md` | 87 | Agent rules and the layout table (`CLAUDE.md` is a 3-line `@AGENTS.md` pointer) |
| `CHANGELOG.md` | 867 | Releases newest-first; see §3 |
| `CLAUDE.md` | 3 | Pointer to `AGENTS.md` |
| `GAPS.md` | 356 | Coverage gaps ledger; see §3 |
| `LICENSE-APACHE` | 201 | Apache 2.0 — all code |
| `LICENSE-CC0-1.0` | 116 | CC0 — documentation, skills, guides |
| `README.md` | 384 | The front page: method, skills, agents, setup |
| `gameframe` | 11 | Python launcher: `runpy.run_path` into `tools/gameframe/` (`gameframe:1-11`) |
| `install.json` | 10 | Demo install config for `examples/frame-demo` (name, build, programs, start) |
| `opencode.json` | 13 | OpenCode client config: the `gameframe` MCP entry |
| `requirements.txt` | 4 | `unicorn>=2.0`, `pefile>=2023.2`, `capstone>=5.0` (+ header comment) |
| `requirements-live.txt` | 2 | extras for the live-observation tools |
| `requirements-llm.txt` | 2 | extras for the LLM tools |

Root directories (LOC per area, `find <dir> -type f -exec cat {} + | wc -l`): `agents/` (23 files,
2,210), `skills/` (20 files, 3,024), `tools/` (158, 23,475), `scripts/` (26, 2,642), `tests/` (36,
≈4,700), `crates/` (249, 48,441), `wrappers/` (138, 16,089), `launcher/` (7, 268), `examples/` (17,
1,361), `docs/` (734, incl. 351 markdown at 29,545), `site/` (62, 18,790), `templates/` (48, 2,894),
`labels/` (2, 2), `hooks/` (2, 76), plus the client dot-directories of §18.

**The three symlinks are load-bearing.** `agents/` and `skills/` at the root are the master copies;
`.claude/agents → ../agents`, `.claude/skills → ../skills`, `.agents/skills → ../skills`
(all mode `120000` in the tree). `AGENTS.md:67` states the design: "`.claude/skills` and
`.agents/skills` link here, so every agent finds the one copy."

## 3. Releases and the gaps ledger

**CHANGELOG.md, 867 lines, seven sections** (grep of `^## `):
`[1.5.0-dev] - Unreleased` at `:8`, `[1.4.0] - 2026-10-26` at `:208`, `[1.3.0] - 2026-10-25` at
`:265`, `[1.2.0] - 2026-10-25` at `:368`, `[1.1.0] - 2026-10-24` at `:516`, `[1.0.1] - 2026-10-23`
at `:782`, `[1.0.0] - 2026-10-23` at `:819`. **There is no 1.4.1 or 1.4.2 section** — the whole
delta since v1.4.0 sits under Unreleased.

**GAPS.md, 356 lines, 12 `## ` sections**, tracks the same things the tools half-implement:
**149 checked `- [x]`, 29 unchecked `- [ ]`** (`grep -c '^- \[x\]' / '^- \[ \]'`). Sections include
Reading compiled code `:8`, Types and data `:34`, Game patterns `:40`, Graphics `:53`, Sound `:70`,
Tools `:169`, Reading the story `:234`, Know-how `:242`, and an explicit
**`## Out of scope` at `:339`**. There are no `Deferred:` or `Parked:` markers anywhere in it.

## 4. The method as documented (README + AGENTS rules)

**README.md (384 lines)** carries the method itself: `## The method` at `:133`, `## Skills` at
`:165` with a 16-row skills table at `:172-187`, the stage chain and the task-agent roster at
`:196-216`, teams at `:218` ("eight teams"), and a setup table at `:227-238` whose commands row
`:238` says the checks run "against the two sample games". Quick start begins at `:30` with the
clone-into-`~/code/game-frame` instruction.

**AGENTS.md (87 lines)**: rules 1–10 at `:30-61` — no game material ever (`:30`), every tool tested
(`:36`), every tool self-documenting (`:38`), skills self-contained (`:40`), plain English (`:45`),
files stay small (`:47`), dependencies stay small (`:50`), improve from real games (`:52`), two
licences (`:58`), stage only your own files (`:61`). The **Layout table at `:63-87`** documents
every root path; §18 and §21 quote its claims about `.claude-plugin/`, hooks, and `.mcp.json`.
The layout row at `:68` and the `.mcp.json` row at `:87` are both contradicted by the tree — see
§21.

**docs/ root guides (11 files)** — the standing reference set: `README.md` 98, `LEGAL.md` 68,
`TYPES.md` 121, `DOS.md` 309, `ABI.md` 107, `OUTPUTS.md` 119, `DATA-DICTIONARY.md` 120, `SETUP.md`
65, `TAXONOMIES.md` 95, `GAME-PATTERNS.md` 286, `COMPILED-CODE.md` 378.

## 5. Skills — 16, plus 4 reference files

`skills/` holds **20 files, 3,024 lines** (find/cat count): 16 `SKILL.md` (2,878 lines) plus the
four `skills/re-cleanroom/references/` templates (50/33/32/31: `contract-template.md`,
`source-side.md`, `source-blind.md`, `packet-checklist.md`). Per-skill LOC (counted with `wc -l
skills/*/SKILL.md`):

| Skill | LOC | Skill | LOC |
|---|---|---|---|
| `re-start` | 289 | `re-emulate` | 149 |
| `re-setup` | 184 | `re-format` | 158 |
| `re-inventory` | 256 | `re-port` | 204 |
| `re-profile` | 123 | `re-cleanroom` | 46 |
| `re-browse` | 163 | `re-verify` | 331 |
| `re-observe` | 135 | `re-land` | 127 |
| `re-ghidra` | 214 | `re-site` | 285 |
| `re-rea` | 100 | `re-trace` | 114 |

**Frontmatter is name+description only** — `grep -c` for `name:`/`description:`/`allowed-tools`
returns exactly 2 per SKILL.md (e.g. `skills/re-rea/SKILL.md:1-3`); the "Use when…" trigger lives
inside the description prose. There is **no `skills/INDEX.md`** (and no INDEX.md anywhere in the
repo). The README skills table (`README.md:172-187`) and AGENTS `:67` both route to these paths;
`.claude/skills` and `.agents/skills` symlink here (§2). `re-setup` embeds the REA pin:
`npx -y rea-agents@6.7.0 setup --client codex --yes` (`skills/re-setup/SKILL.md:87`) and
`doctor --client claude_code --json` (`:101`).

## 6. Agents — 23 masters, 4 emitted copies

**Master copies: `agents/`, 23 markdown files, 2,210 lines** (`wc -l agents/*.md`). 9 stage agents
plus 14 task agents — the task roster is itemised at `README.md:202-210`: `re-identifier`,
`re-randomiser`, `re-listener`, `re-cataloguer`, `re-mapper`, `re-typer`, `re-matcher`,
`re-editor`, `re-checker`, `re-publisher`, `re-vectoriser` (MMX/SIMD), `re-accelerator` (3D card
APIs), `re-specifier` (source-visible contracts), `re-cleanroomporter` (source-blind). Per-file
LOC of the masters:

| Agent | LOC | Agent | LOC | Agent | LOC |
|---|---|---|---|---|---|
| re-accelerator | 110 | re-mapper | 98 | re-specifier | 45 |
| re-cataloguer | 96 | re-matcher | 94 | re-surveyor | 110 |
| re-checker | 89 | re-measurer | 95 | re-tracer | 99 |
| re-cleanroomporter | 54 | re-observer | 98 | re-typer | 107 |
| re-decoder | 101 | re-porter | 99 | re-vectoriser | 108 |
| re-decompiler | 98 | re-publisher | 119 | re-verifier | 99 |
| re-editor | 89 | re-randomiser | 104 | | |
| re-identifier | 99 | re-lander | 101 | | |
| re-listener | 98 | | | | |

**Emitted copies are never edited by hand.** `AGENTS.md:68` documents the pipeline: `gameframe
agents --emit all` writes the same roster into four client formats. Each copy tree holds all 23
agents; LOC totals differ by format verbosity: `.codex/agents/*.toml` 2,136, `.gemini/agents/*.md`
2,446, `.github/agents/*.agent.md` 2,159, `.opencode/agents/*.md` 2,216 (per-file LOC counted in
this session; e.g. `re-accelerator`: 108 codex / 123 gemini / 109 copilot / 110 opencode). Claude
Code reads the masters through the `.claude/agents` symlink (§2).

## 7. The MCP surface

**`.mcp.json` (10 lines) registers exactly one server**: `gameframe` → `command: "./gameframe"`,
`args: ["serve"]` — quoted verbatim from the file. **No REA, no DOSBox-X entry exists in it.**

- The server itself is `tools/gameframe/mcp.py` (394 L, emits per-client MCP config) and the
  `tools/gameframe/mcp_server/` package (6 files, 465 L: `server.py` 129, `toolsets/runner.py`
  196, `toolsets/discovery.py` 138, `toolsets/knowledge.py` 59, `protocol.py` 39,
  `registry.py` 68, `context.py` 35, `__init__` files 10), with `serve.py` (9 L) as the entry.
- **Opt-in external providers live in `tools/gameframe/mcp_providers.json`** (40 lines, first key
  `"rea"`) and are wired per-project by `scripts/mcp-provider.sh` (97 L; the exec line is
  `npx -y "rea-agents@$selected" mcp` at `:35`).
- Client-side emission targets all carry only `gameframe`: `.codex/config.toml` (6 lines,
  `[mcp_servers.gameframe]` block), `.cursor/mcp.json` 11 L, `.vscode/mcp.json` 11 L,
  `.gemini/settings.json` 15 L, `opencode.json` 13 L.
- `tests/mcp_provider_config.py` (216 L) pins the provider machinery: it asserts the enabled list
  shows `rea (6.7.0)` (`:80`) and writes a `rea-agents@6.4.0` entry in a fixture (`:121`).
- `.claude/launch.json` (17 lines) contains **two preview configurations, not MCP servers**:
  `site` (VitePress dev on 5180, `:4-8`) and `diagrams` (`python3 -m http.server 5181`, `:9-14`).
- `tools/rea/` (2 files, 413 L) is the REA bridge on the tool side: `rea_session.py` 279,
  `mcp_client.py` 134.

## 8. Python tooling — `tools/`, 14 families, 158 files, 23,475 lines

Counted with `find tools -type f | wc -l` and per-family `find tools/<f> -type f -exec cat {} + |
wc -l`; per-file LOC below from the same walk. All Python unless marked; `tools/ghidra/` is Java,
`tools/live/winput.c` and `tools/dos/templates/pascal.rs` are the two non-script sources.

| Family | Files | LOC | What it covers |
|---|---|---|---|
| `disc/` | 4 | 762 | CD image structure: `discinfo.py` 200, `volumes.py` 281, `image.py` 180, `checks.py` 101 |
| `dos/` | 10 | 1,999 | 16-bit era binaries: `tdinfo.py` 430 and `td_rust.py` 282 (Turbo Debugger info), `dbx_control.py` 216 (DOSBox-X console), `omf.py` 199, `dosinfo.py` 173, `fileio_trace.py` 144, `ne.py` 145 (NE loader), `readseg.py` 109, `nedis.py` 87, `templates/pascal.rs` 214 |
| `emu/` | 17 | 2,513 | Unicorn-based execution: `pe_emu.py` 349, `pe32_emu.py` 300, `fragments.py` 201, `dos_env/` (dos 202, dpmi 134, bios 128, pc 110, `__init__` 108, keyboard 86), `dos_emu/` (run 181, loader 166, memory 131, `__init__` 88, types 60, trace 48), `mem_trace.py` 161, `call_trace.py` 60 |
| `formats/` | 15 | 2,514 | Data-file decoding: `catalog.py` 215, `skeleton.py` 246, `xorscan.py` 276, `swfinfo.py` 251, `shaders.py` 175, `shadetable.py` 139, `rawimage.py` 198, `pcap.py` 161, `fields.py` 150, `derived.py`/`validate.py` 129/85, `reader.py` 138, `pngio.py` 127, `timestamps.py` 129, `markers.py` 95 |
| `gameframe/` | 30 | 3,086 | The `gameframe` CLI itself + MCP server (§7) + client emitters (`clients/`: codex 28, copilot 24, gemini 21, opencode 24, `__init__` 114) + command surface (`commands.py` 250, `games.py` 283, `knowhow.py` 238, `home.py` 181, `advise.py` 151, `catalog.py` 89, `agents.py` 55, `headers.py` 53, `paths.py` 41, `progress.py` 83, `search.py` 31, `skills.py` 90, `__main__.py` 213, `mcp_providers.json` 40, `serve.py` 9) |
| `ghidra/` | 9 | 635 | Ghidra headless Java exporters: `ExportCallArgs.java` 183 (header comment at `:1-3`), `ExportDisasm.java` 85, `ExportAddressBatch.java` 71, `AddMemoryBlocks.java` 53, `ExportAll.java` 50, `ExportVtableSlots.java` 46, `ExportNamedFunctions.java` 42, `ApplyLabels.java` 58, `ExportAddressRefs.java` 47 |
| `install/` | 5 | 547 | Port-as-app install: `install_app.py` 255, `macos.py` 88, `desktop.py` 76, `launch.py` 77, `places.py` 51 |
| `live/` | 14 | 2,745 | Observing the running original: `gdbremote.py` 373, `winput.c` 391, `align.py` 264, `winegdb.py` 262, `memrec.py` 244, `harness.py` 222, `emupc.py` 205, `frida_trace.py` 190, `emulock.py` 102, `shot.py` 99, `modfolder.py` 110, `memlog.py` 103, `loopcut.py` 75, `winput.py` 105 |
| `llm/` | 9 | 1,692 | LLM-assisted RE: `client.py` 351, `name_functions.py` 316, `decision_feedback.py` 264, `decision.py` 194, `skillcheck.py` 119, `headless.py` 117, `locate.py` 135, `fake_api.py` 126 (test double), `ask.py` 70 |
| `pe/` | 8 | 1,008 | Windows PE: `apitable.py` 220, `probegen.py` 150, `peres.py` 142, `stackstrings.py` 140, `relocs.py` 115, `peinfo.py` 120, `vtable.py` 66, `readdata.py` 55 |
| `rea/` | 2 | 413 | REA MCP bridge: `rea_session.py` 279, `mcp_client.py` 134 |
| `site/` | 1 | 210 | `check.py` — the docs/site link and content checker |
| `triage/` | 30 | 4,978 | First-look on any binary (biggest family): `decomp_query.py` 309, `cite_labels.py` 264, `hashnames.py` 252, `sigscan.py` 259, `constants.py` 203, `match_functions.py` 202, `buildid.py` 204, `filetypes.py` 184, `exportcov.py` 186, `needs.py` 186, `versiondiff.py` 213, `axes.py` 167, `sentences.py` 160, `refs.py` 159, `dictionary.py` 158, `tables.py` 152, `binview.py` 147, `coverage.py` 145, `fixity.py` 143, `memscan.py` 140, `dates.py` 136, `similar.py` 130, `coverdiff.py` 118, `pointerpaths.py` 115, `report_issue.py` 134, `screenmarks.py` 96, `insns.py` 90, `needs_signs.py` 77, `compare_trees.py` 112, `deviations.py` 133 |
| `verify/` | 4 | 373 | Differential verification: `replay.py` 143, `ramdiff.py` 127, `seqdiff.py` 53, `bitcompare.py` 50 |

**Negative findings.** No `tools/__init__.py` or shared package; each family is standalone scripts
invoked through the `gameframe` CLI (`gameframe:1-11` shows the launcher just `runpy`s
`tools/gameframe/`). No Rust or C++ in `tools/` beyond the two template/source files noted above.

## 9. Scripts and the gate engine

`scripts/` = **26 files, 2,642 lines** (15 top-level, 1,765; 11 under `hooks/`, 877; per-file LOC
from `wc -l` over the tracked list).

**Top level:** `update-project.sh` 315, `clients.py` 243 (client discovery),
`codex-cloud-environment-install.sh` 161, `new-project.sh` 136, `release.py` 135 (the tagged
release flow behind `AGENTS.md:84`), `setup.sh` 132 (installs deps and the REA pin at `:126`,
`rea-agents@6.7.0`), `dosbox-run.sh` 105, `mcp-provider.sh` 97, `extract-installer.sh` 89,
`ghidra-run.sh` 75, `lib.sh` 72, `new-site.sh` 67, `zcc.sh` 59, `ghidra-export.sh` 45, `env.sh` 34.
`new-site.sh` supports `--single`, `--manual`, `--repo URL` (usage line `:4`, flag parse `:28`);
the `--manual` option is not mentioned in the README (see §21).

**The gates (`scripts/hooks/`):** `gate.py` 98 and `advise.py` 103 are the hook entrypoints; the
rule engine is `scripts/hooks/gates/` — `deletes.py` 196, `game_folder.py` 161, `checks.py` 142,
`adapters.py` 127, `post_events.py` 90, `session.py` 41, `version.py` 41, `__init__.py` 12. The
git pre-commit hook ships as `scripts/hooks/git/pre-commit` (25 L); **a fresh clone has no git
hooks installed** (`ls .git/hooks`: zero non-`.sample` files) — `setup.sh` installs it.

**Wiring:** `.claude/settings.json` (80 lines) defines `allow` `:4-21`, `ask` `:22-31` (including
`Bash(npx -y rea-agents@6.4.0 setup *)` at `:25`), `deny` `:32-37`, and five hook groups that all
call `gate.py`/`advise.py` — session start `:43`, commit/push/delete `:51-53`, post-tool write
`:59`, and two `advise.py post` hooks `:67`/`:75`. The same gates are wired for other clients via
`hooks/hooks.json` (44 L), `hooks/gemini-settings.json` (32 L), `.codex/hooks.json` (30 L),
`.cursor/hooks.json` (19 L), `.github/hooks/gameframe.json` (29 L) — the `AGENTS.md:69` layout
row lists exactly this set.

## 10. Test harness — `tests/`, 36 files

**`tests/run.sh`, 2,128 lines, is the whole harness**: counted on this tree, **335 lines contain
`expect` and 110 end in `&& ok`** (`grep -c`), i.e. hundreds of behavioural checks run against the
sample games; the header advertises `--ghidra` to add the Ghidra-dependent ones (`README.md:238`).

**Python test drivers:** `mcp_provider_config.py` 216, `mcp_tool_coverage.py` 204,
`decision_adapter.py` 193, `make_disc.py` 138, `llm_protocols.py` 129, `make_engine.py` 88,
`make_omf.py` 79, `make_pcap.py` 49, `make_swf.py` 54, `decision_feedback.py` 105.

**Fixtures (`tests/fixtures/`, 21 files):** `apitable/` (`api.c` 12, `api.def` 8, `api.h` 7),
`cite/` (`lib.rs` 54, `functions.tsv` 3, `names.tsv` 2), `dictionary/` (3 tsv 6/5/4),
`export-layout/` (`decomp.c` 19 + 2 tsv), `gdbstub_fake.py` 117, `install-project/` (build.sh 7,
install.json 15, library.json 1), `knowhow/` (README 12, two fixture docs 24/29), `rea/`
(`fake_rea.py` 66, 2 tsv), `resources.rc` 24, `stackstring.c` 3.

**`tests/skill-tasks.json` (17 lines) holds exactly 3 tasks** — one each for `re-inventory`
(x64, image base, imported DLLs), `re-format` (decode a record file), `re-emulate` (run exported
`rng_seed`/`rng_next` under the emulator). `tests/fixtures/apitable/api.def` is the only `.def`
fixture (the `wrappers/` `.def` files are §12).

## 11. The Rust crates workspace — 28 members, hardware-centric

**`crates/` = 249 tracked files, 48,441 lines** (find/cat count): 189 `.rs` (43,667 Rust lines),
29 `Cargo.toml` (28 members + workspace), 29 `.md` (a README per crate plus
`crates/wma/THIRD_PARTY.md`), `Cargo.lock` (2,285 L), and per-crate `tests/` data (18 `tests/`
dirs). The workspace header (`crates/Cargo.toml:1-12`) states the purpose — "Clean
implementations of hardware and runtime pieces … taken from the case-study reimplementations and
made generic" — lists the **28 members at `:5`**, and pins `version = "0.1.0"` `:8`,
`rust-version = "1.80"` `:12`.

Per-crate LOC (find/cat per directory, includes the crate README and Cargo.toml):

| Crate | LOC | Crate | LOC |
|---|---|---|---|
| wma | 10,859 | frame-ui | 1,463 |
| sound-blaster | 5,321 | d3d | 1,291 |
| frame | 3,091 | adlib-gold | 1,244 |
| indeo | 2,786 | opl2 | 1,208 |
| powervr | 2,152 | turbo-pascal | 804 |
| voodoo | 2,119 | report | 728 |
| library | 1,805 | saa1099 | 712 |
| game-source | 1,723 | opl3 | 659 |
| msvc-crt | 1,631 | sn76496 | 629 |
| ymz263 | 1,597 | bitmap-font | 629 |
| disc-image | 1,464 | mmx | 565 |
| rage | 345 | yac512 | 322 |
| virge | 279 | raster | 263 |
| texel | 244 | scale | 211 |

One-line identities from each crate's README third line (quoted or condensed): audio chips —
opl2/opl3/saa1099/sn76496/yac512/ymz263 (Yamaha/Philips/TI parts), `adlib-gold` (YMF262+YMZ263B
port block), `sound-blaster` (DSP 1.xx–4.xx device model); 3D — `powervr` (PCX2 as SGL 3.1 drives
it), `voodoo` (Glide 2.x pixel pipeline), `d3d` (Direct3D 3 immediate mode), `rage`/`virge`
(knowledge packs for ATI3DCIF / S3D Toolkit), `raster`/`texel`/`scale` (triangle rasteriser, 1990s
texel layouts, integer frame scaling); runtime plumbing — `wma` (xWMA/ASF decoder → WebAssembly),
`indeo` (IV41 clean-room), `msvc-crt` (bit-for-bit libm/rand), `turbo-pascal` (Real/Random
layouts), `mmx` (Pentium MMX as plain Rust), `disc-image` (CUE/BIN, ISO, Joliet in place),
`game-source` (folder/CD/URL ranged reads), `library` (player game data), `frame` (the port↔frame
contract), `frame-ui` (Dioxus views/themes), `report` (unported-path and crash reports),
`bitmap-font` (bitmap font → in-memory TTF).

**No `GLOSSARY.md`, no `docs/adr/`, no vendor directory inside `crates/`** — crate provenance is
consolidated in `docs/crates/README.md` (93 lines, **28 provenance rows**, counted with
`grep -c '^| \[gameframe'`). The largest crate READMEs: `crates/frame/README.md` 198,
`crates/opl3/README.md` 138, `crates/sound-blaster/README.md` 123, `crates/wma/README.md` 101.

## 12. `wrappers/` — drop-in DLLs, 10 members, 16,089 lines

Drop-in replacements so unchanged 1990s games load on modern systems; `wrappers/README.md` (131 L)
opens with the rule ("Each DLL here has the original's file name and exports", `:5-6`) and the
7-DLL table at `:12-20`. Counted: 138 files — 99 `.rs`, 7 `.def` export tables
(`glide2x.def`, `sgl.def`, `ddraw.def`, `ir41_32.def`, `maxi94.def`, `ati3dcif.def`,
`s3dtkw.def`), 12 `.toml`, 11 `.md`, plus shared root files `Cargo.toml` 34 and
`stubgen.py` 133 (the `.def`-driven entry generator).

| Wrapper | LOC | Stands in for |
|---|---|---|
| `glide/` | 6,560 | 3dfx Glide 2.x (`glide2x.dll`) |
| `sgl/` | 4,901 | PowerVR SGL scene graph + immediate mode |
| `ddraw/` | 1,151 | DirectDraw 1–3 |
| `shim/` | 864 | shared shim crate |
| `maxi94/` | 803 | Guillemot Maxi Sound (Dream SAM9407, audio only) |
| `ir41/` | 580 | Indeo RT codec shim (`ir41_32.dll`) |
| `ati3dcif/` | 305 | ATI 3D Rage (ATI3DCIF) |
| `s3dtkw/` | 299 | S3 ViRGE S3D Toolkit |
| `scalers/` | 168 | shared scaling support crate |
| `pixels/` | 149 | shared pixel-format support crate |

The only `.def` outside this directory is the test fixture (`tests/fixtures/apitable/api.def`,
§10).

## 13. `launcher/` — the frame: desktop (WIP)

**7 files, 268 lines total** (`find launcher -type f -exec wc -l {} +`): `README.md` 78, `Cargo.toml`
16 (its own workspace, deliberately outside `crates/`: `[workspace]` `:10`, Dioxus 0.7.10 dep
`:16`), `src/main.rs` 153, `example/frame.json` 18, `example/game/TRACKS/CANYON.TRK` and
`HARBOUR.TRK` (both **0 lines** — placeholder save files), and a 3-line `.gitignore` for its build
output. No icons or resources are shipped; the crate is labelled WIP in `Cargo.toml:9-10`.

## 14. `examples/` — three worked samples

**17 files, 1,361 lines, 108 KB** (`find examples -type f -exec wc -l {} +`; `du -sh`):

- **`sample-game/` (9 files)** — the C sample target and its ground-truth tooling: `game.c` 79,
  `mixer32.c` 96, `engine.c` 22, `port.py` 83, `ground_truth.py` 41, `decode_sample.py` 20,
  `make_data.py` 13, `build.sh` 12, README 31.
- **`dos-sample/` (3 files)** — `sample.s` 303 + `make_exe.py` 264 build a hand-written 16-bit
  `.COM`/EXE; README 25.
- **`frame-demo/` (5 files)** — the frame: contract demo: `Cargo.toml` 25 (path-deps on
  `crates/frame` and `crates/frame-ui`, `:18-19`), `library.json` 139, `src/main.rs` 138,
  `index.html` 12, README 58. It is also what root `install.json:1-10` installs.

The README still says "the two sample games" (`:238`) while the tree carries three example
projects — see §21.

## 15. `docs/` — 734 files, 351 markdown, 29,545 prose lines

Counted with `find docs -type f | wc -l`, markdown LOC by `find docs -name '*.md' -exec cat {} +
| wc -l`. 11 root guides (§4) + 18 subdirectories:

| Dir | Files | Dir | Files |
|---|---|---|---|
| `arcade/` | 14 | `knowhow/` | 142 |
| `assets/` | 382 | `media/` | 5 |
| `case-studies/` | 6 | `observe/` | 13 |
| `computers/` | 17 | `preservation/` | 14 |
| `consoles/` | 9 | `semantics/` | 5 |
| `crates/` | 1 | `teams/` | 10 |
| `engines/` | 16 | `working/` | 21 |
| `games/` | 12 | `hardware/` | 32 |
| `handhelds/` | 14 | | |

**`assets/` is 371 SVG + 11 WebP, zero PNG** (`find docs/assets -type f | sed 's/.*\.//' | sort |
uniq -c`; `find docs -name '*.png' | wc -l` = 0) — the diagrams are vector, generated by
`site/diagrams/` (§16). **`knowhow/` at 142 files is the largest section**: solved-case notes
("ai-chance-from-the-frame-clock.md" style names) feeding the `gameframe knowhow` tool.
**`case-studies/` holds five studies plus README, 523 lines total**: `banished.md` 114,
`hardwar.md` 113, `frontier.md` 86, `pod.md` 85, `tyrian.md` 78, README 47.
**`working/` (21 files)** documents the practice: `gates.md`, `writing.md`, `mcp-toolchain.md`,
`agents.md`, `lore.md`, `clean-room-implementations.md`, `codex-cloud-*` pair, and 14 more.

## 16. `site/` and CI — one workflow

**`site/` is VitePress** (`AGENTS.md:86` says so explicitly: "The documentation website
(VitePress) … it holds no copies of their content"). **62 files, 18,790 lines**: route shells
(`index.md`, `[section]/index.md` + `*.paths.mts`, `agents/[agent].md`, `skills/[skill].md`,
`tools/[tool].md`), `lab/` interactive demos (5 md pages + Vue components), `.vitepress/`
(config/theme: `catalog.mts`, `links.mts`, `llms.mts`, `repo.mts`, `sidebar.mts`, theme Vue
components incl. a pipeline explorer), `package.json` + lock, README, and the content generators:
**21 Python scripts in `site/diagrams/`** (the SVGs in `docs/assets/`) and
`site/captures/{make.sh,term_svg.py}`.

**CI is exactly one workflow: `.github/workflows/site.yml` (64 lines, the only yml in
`.github/workflows/`)** — builds on push touching `docs/**` (`:10`) or itself (`:18`), keeps a
single deploy in flight with a concurrency group carrying an incident comment about stuck run
39803187786 (`:26-32`), then checkout `:37`, Node 22 `:42`, `npm --prefix site run build` `:48`,
`upload-pages-artifact` `:52`, deploy job `:57`. **There is no test workflow**: `tests/run.sh` is
local-only (`README.md:238`); no `.pre-commit-config.yaml`, no dependabot, no issue/PR templates,
no `FUNDING.yml` (`ls .github` shows only `agents/`, `hooks/`, `workflows/`).

## 17. `templates/` and `labels/`

`templates/` = **48 files, 2,894 lines**: `project/` 15 files / 880 lines (the scaffold `new-project.sh`
copies — including a `settings.json` whose REA ask-line pins **6.7.0** at `:30`), `library-page/`
22 / 1,754 (the `gameframe-library` player-facing page, README 185), `site/` 11 / 260.
`labels/` = **2 files, 1 line each**: `names.tsv` and `fields.tsv` are **header-only TSVs**
(quoted first lines: `# address	label	evidence …` and `# class or struct	offset	name …`).
There is **no `labels/dictionary.tsv`** in the tracked tree — that one exists only as a test
fixture (`tests/fixtures/dictionary/`).

## 18. Client surface — the dot-directories

All LOC counted per file from the tracked list:

| Dir | Contents |
|---|---|
| `.claude/` | `settings.json` 80 (§9), `launch.json` 17 (§7), symlinks `agents`/`skills` (§2) |
| `.agents/` | `skills` symlink only |
| `.claude-plugin/` | `plugin.json` 21 (`"version": "1.5.0-dev"` `:3`), `marketplace.json` 14 (name `game-frame`, owner Tane Piper), `icon.png` (binary) |
| `.codex/` | 23 agent TOMLs (2,136), `config.toml` 6, `hooks.json` 30 |
| `.gemini/` | 23 agent MDs (2,446), `settings.json` 15 |
| `.github/` | 23 `*.agent.md` (2,159), `hooks/gameframe.json` 29, `workflows/site.yml` 64 |
| `.opencode/` | 23 agent MDs (2,216) only |
| `.cursor/` | `hooks.json` 19, `mcp.json` 11 — **no agents dir** |
| `.vscode/` | `mcp.json` 11 only — no settings/extensions/launch |
| `hooks/` | `hooks.json` 44, `gemini-settings.json` 32 (the shared gate wiring at `AGENTS.md:69`) |

Every emitted MCP config registers only `gameframe` (§7). Note `.gitignore` ignores `.vscode/`
while `.vscode/mcp.json` is tracked anyway (added before/despite the pattern).

## 19. Licensing

Split licence, stated in three places consistently: **code is Apache 2.0** (`LICENSE-APACHE`, 201
lines), **docs/skills/guides are CC0** (`LICENSE-CC0-1.0`, 116 lines — public-domain dedication,
**not CC-BY**). The rule is `AGENTS.md:58-60` ("Two licences"); `README.md` has a `## Licence`
section (table at its end); `AGENTS.md:63-87` layout rows restate it per directory; the plugin
carries `Apache-2.0 AND CC0-1.0` in `.claude-plugin/plugin.json`; every crate `Cargo.toml`
inherits `license = "Apache-2.0"` from `crates/Cargo.toml:10`. No SPDX headers in sources; no
`licenses/` vendor directory.

## 20. Negative findings (what is not in the tree)

Searched by `git ls-tree -r HEAD --name-only` and `find` on the clean clone — none of these exist
at `f195a074`: **`TOOLS.md`, `ARCHITECTURE.md`, `QUICKSTART.md`, `GLOSSARY.md`,
`TOOLS_REFERENCE.md`, `.claude.json`, `.editorconfig`, `.gitattributes`,
`.pre-commit-config.yaml`, `.github/ISSUE_TEMPLATE`, `.github/dependabot.yml`,
`docs/plans/`, `docs/adr/`, `docs/releases/`, `docs/writing-guide.md`, `skills/INDEX.md`,
`labels/dictionary.tsv`, any PNG/JPG in `docs/`**, plus no `package.json` at the repo root, no
Makefile, no Dockerfile, no vendored third-party code (only `crates/wma/THIRD_PARTY.md`, a note,
not vendored code), and no installed git hooks in a fresh clone (§9). The 3 symlinks of §2 are
the tree's only symlink entries.

## 21. Internal contradictions and stale text (the ledger)

Verified at this HEAD; each item quotes both sides:

1. **Task-agent count.** `README.md:202`: "**Fourteen** task agents do one job each" (and lists
   fourteen by name, `:202-210`) vs `AGENTS.md:68`: "One agent per stage and **twelve** task
   agents". The tree contains 23 agents = 14 + 9, so the README is right and AGENTS.md's row is
   stale.
2. **`.mcp.json` contents.** `AGENTS.md:87` describes `.mcp.json` as "The MCP servers (REA,
   DOSBox-X) for Claude Code", but the file (10 lines, quoted in §7) registers **only**
   `gameframe`; REA is opt-in via `tools/gameframe/mcp_providers.json` + `scripts/mcp-provider.sh`.
   Stale rule text.
3. **REA version pin.** Current docs and tooling pin **6.7.0** (`scripts/setup.sh:126`,
   `docs/SETUP.md:57`, `skills/re-setup/SKILL.md:87,101`, `templates/project/settings.json:30`),
   while `.claude/settings.json:25` still allows only `rea-agents@6.4.0 setup` — the shipped
   project settings lag the pinned version. (`tests/mcp_provider_config.py:121` also uses 6.4.0,
   but that one is a deliberate fixture while `:80` asserts 6.7.0.)
4. **"two sample games".** `README.md:238` says the checks run "against the two sample games";
   `examples/` holds **three** projects (the third, `frame-demo`, postdates the sentence —
   `install.json:1-10` is built around it).
5. **`--manual` flag.** `scripts/new-site.sh:4,28` implement `--manual`; the README setup section
   never mentions it.
6. **Transient sibling-dossier staleness (fixed at assembly).** `00-scope-and-method.md`
   originally said "31 crates" where the tree says 28 workspace members
   (`crates/Cargo.toml:5`); corrected to 28 across the dossier — recorded here as the
   only ledger error *we* caught, at the pinned tree it is 28.

## 22. Observations from the count

- **The repository pivoted shortly before HEAD.** The committed `f195a074` tree is *hardware
  emulation*: 28 crates are chips and 3D APIs (Sound Blaster, OPL family, PowerVR, Voodoo, D3D3,
  MMX), and `wrappers/` (16,089 L, glide+sgl dominant) is a drop-in-DLL project. An earlier
  working state at the same path — and the first draft of this chapter — contained an entirely
  different crate set (a PE/DOS-emulation/`rea-client`/`wad` family). Treat any GameFrame figure
  sourced before this capture as suspect; all numbers here come from the clean tree at
  `f195a074`.
- **Documentation outweighs tools.** 734 doc files (29.5k prose lines, 382 assets) vs 158 Python
  tool files (23.5k lines). The largest single prose corpus is `knowhow/` (142 files), and the
  largest tool family is `triage/` (4,978 L).
- **Rust is where the bulk is**: 48,441 L in `crates/` + 16,089 L in `wrappers/` + 268 L in
  `launcher/` = 64.8k, roughly a third of the 185k tracked lines — one crate (`wma`, 10,859 L) is
  bigger than the largest tool family.
- **The gate engine is the security story**: one Python package (`scripts/hooks/gates/`, 810 L)
  fronted by five client hook configs (§9) enforcing the no-game-material rule (AGENTS rule 1)
  mechanically, not just in prose.
- **A single author built all of this in nine working days** (383 commits, 21–30 Oct, one gap
  day), shipping six releases — v1.4.0 on 26 Oct, 49 commits in the Unreleased 1.5.0-dev window.

## Sources

- Primary: clean clone at `/tmp/opencode/game-frame`, pinned `f195a074a63cc150673c38becdec696163b0b3d1`,
  working tree clean, captured 2026-10-31. Ground-truth dumps retained at `/tmp/gt3.txt` and
  `/tmp/gt4.txt` (regenerable from the same pin).
- Commands behind every count are stated inline: `git ls-tree`, `git rev-list`, `git shortlog`,
  `git describe`, `find … -exec cat {} + | wc -l`, `grep -c`, `du -sh`, `wc -l`.
- GitHub metadata: `gh repo view tanepiper/game-frame --json …`, fetched 2026-10-31.
- Sibling chapters: `00-scope-and-method.md` (scope, method, GitHub facts at `:95-101`; its
  one-time "31 crates" slip was corrected at assembly — §21 item 6).
