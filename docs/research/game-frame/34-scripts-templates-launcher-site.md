# GameFrame's operational layer: scripts, project lifecycle, launcher, and site

> Part of the [game-frame overview](README.md).

> All paths are relative to the GameFrame repo root at clone `/tmp/opencode/game-frame`,
> HEAD `f195a074a63cc150673c38becdec696163b0b3d1` (branch `main`, clean tree). Every `path:line`
> below was re-opened at HEAD via `git cat-file`/`git grep` before being written down — the
> earlier draft of this chapter cited files that do not exist at this commit and is fully
> replaced. Chapter 20 sized this layer (its §9, §13, §16, §17 are the counts we reuse); hook
> bodies and agent clients are chapter 32 §5–7; the release ladder is chapter 21 §3. Crate
> internals are chapters 29–31. Nothing was executed: every script here installs, mutates, or
> rebuilds something, so all findings are static reads.

## 1. What the layer is

The operational layer is everything a user or agent touches that is not a skill, an agent, a
gate, or a tool binary: the `scripts/` shell-and-Python surface, the `gameframe` CLI
(`tools/gameframe/`), the project templates (`templates/`), the desktop launcher crate
(`launcher/`), the port-installer suite (`tools/install/`), and the two VitePress site worlds
(`site/` for GameFrame itself, `templates/site/` for projects).

| Piece | Size | Verified against |
|---|---|---|
| `scripts/` | 26 files / 2,642 lines (15 top-level / 1,765; `hooks/` 877) | ch.20 §9; `wc -l` over the tracked list |
| `gameframe` CLI | root `gameframe` 11 L + `tools/gameframe/` (`__main__.py` 213, `commands.py` 250, `home.py` 181, `games.py` 283, `paths.py` 41, …) | direct counts at HEAD |
| `tools/install/` | 5 files / 547 L (`install_app.py` 255, `macos.py` 88, `launch.py` 77, `desktop.py` 76, `places.py` 51) | direct counts |
| `templates/` | 48 files / 2,894 L: `project/` 15 files / 880, `site/` 11 / 260, `library-page/` 22 / 1,754 | ch.20 §17 (`find … wc -l`) |
| `launcher/` | 7 files / 268 L (Cargo.toml 16, README 78, `src/main.rs` 153, `example/frame.json` 18) | ch.20 §13 |
| `site/` | 62 files / 18,790 L | ch.20 §16 |
| CI | exactly one workflow: `.github/workflows/site.yml` (64 L) | `git ls-tree HEAD .github/workflows/` |

Two scope notes. First, the CLI is not a separate binary: the root `gameframe` (mode 100755) is
an 11-line `runpy` shim that execs `tools/gameframe/` as `__main__` (`gameframe:6,10-11`), and
`tools/gameframe/__main__.py` is the argparse router (command list `__main__.py:5-49`;
`run`/`doctor`/`install` are pass-through verbs, `__main__.py:87,174-182`). Second, CI carries
no test, lint, or release workflow — the only yml builds the docs site (§6.2), so the entire
update/install/release story runs on the user's or agent's own machine.

## 2. `scripts/` — the thin shell surface

### 2.1 Shared plumbing: `lib.sh` and `env.sh`

`scripts/lib.sh` (72 L) is sourced by every shell script. It fixes `ROOT` (the toolkit's own
folder — a clone *or* a plugin install), `PROJECT` (`$GAMEFRAME_PROJECT` if set, else `ROOT`)
and `GAMEFRAME_HOME` (`${GAMEFRAME_HOME:-$HOME/gameframe}`) at `lib.sh:8-10`, then layers
environment files: the home's `config.env` first, then `$PROJECT/.env`, which wins
(`lib.sh:11-14`). Both are plain `KEY=value` files loaded with `set -a` (`lib.sh:11`). The
finder functions are fixed-path probes: `find_ghidra` tries `$GHIDRA_INSTALL_DIR`, two Homebrew
prefixes, `/opt/ghidra`, `/usr/share/ghidra`, and `~/ghidra_*_PUBLIC` (`lib.sh:16-21`);
`find_java21` likewise (`:23-28`); `PYTHON` resolves project `.venv` → root `.venv` →
`$GAMEFRAME_HOME/python/bin/python` (`:30-34`). `ghidra_project_dir` works around Ghidra's
refusal of dot-folders by symlinking through `$TMPDIR` (`:36-46`). The DOSBox-X trio
(`:48-72`) pins the debugger-channel requirement at version 2026.10+ (`:64-72`).

`scripts/env.sh` (34 L) is the source-able twin for interactive shells and agents that spawn a
fresh shell per command: it exports `GAMEFRAME_ROOT`/`GAMEFRAME_HOME`, loads the same two env
files (`env.sh:16-17`), re-finds Ghidra/Java (`:18-25`), and prepends the repo root (where
`gameframe` lives) and `.venv/bin` to `PATH` (`:27-31`). Its contract: "It changes nothing on
disk" (`:9`).

### 2.2 Toolchain check-and-repair: `setup.sh`

`setup.sh` (132 L) is the toolchain gate. Default mode is check-only — "Nothing is installed
without `--install`" (`setup.sh:20`); the `--install` flag (`:29`) unlocks a two-package-manager
installer, Homebrew on macOS and `sudo apt-get` on Debian/Ubuntu (`pkg_install`, `:42-48`),
used by a `check()` helper that prints an aligned `ok/installed/MISSING` table (`:50-55`). The
checked set (`:57-71`): python3, JDK 21 (`:59`), Ghidra — installed via brew on macOS, but on
Linux only the release-page hint is printed rather than downloading ~500 MB (`:20-21,60-62`),
objdump, node, and five optional rows: zig (`:65`), innoextract and 7-Zip (`:66-67`), DOSBox-X
plus an explicit version complaint when the debugger channel is missing (`:68-71`). The Python
side is three stacked venv layers, each installed on demand and checked by import: base
`unicorn/pefile/capstone` (`:73-82`), `requirements-live.txt` for Frida (`:83-91`),
`requirements-llm.txt` for `anthropic` (`:92-99`). Two project-side duties: it sets
`core.hooksPath` to `scripts/hooks/git` only when none is set (`:101-109`), and in a project
(not the clone) it runs the game-folder gate's `check`, which also writes the
`GAME-FILES-NOT-BUILD-OUTPUT.txt` marker (`:111-114`; gate engine is ch.32 §5). When Ghidra and
Java were found but no env file exists anywhere, it writes a two-line `$PROJECT/.env`
(`:116-121`). `--rea` prints REA's registration plan as a dry run, pinned:
`npx -y rea-agents@6.7.0 setup --client "$client" --dry-run` (`:123-128`, pin at `:126`).

### 2.3 The runner scripts

| Script | L | Contract (from its own header) |
|---|---|---|
| `extract-installer.sh` | 89 | get a game's files out of an installer "without running it" (`:2`); `--detect` prints kind+tool (`:4`); kind→tool table: innoextract for Inno/GOG, 7z for NSIS/MSI/cab/rar, unshield for InstallShield (`:6-11`) |
| `ghidra-export.sh` | 45 | headless analyse + text export (`decomp.c`, `functions.tsv`, `strings.txt`, imports, exports) per binary (`:2-4`); defaults `analysis/ghidra-project`, `analysis/export/<binary>/` (`:6`); `--labels FILE` pre-names functions (`:7-8`); "A large game takes 10-30 minutes", tunable `GHIDRA_CPUS`/`MAXMEM` (`:10-11`) |
| `ghidra-run.sh` | 75 | run one `tools/ghidra` script against an already-analysed project, ~1 min startup, batch addresses in one run (`:2-4`); six worked examples incl. `labels` and `callargs` (`:6-11`) |
| `dosbox-run.sh` | 105 | run the whole original game under DOSBox-X for ground truth a single emulated function cannot give (`:2-3`); `--out/--time/--window/--fileio/--int21` flags (`:6-11`) |
| `mcp-provider.sh` | 97 | launch one *opt-in* external MCP provider at the version pinned in `tools/gameframe/mcp_providers.json` (`:2-5`); exec's into the provider's stdio server (`:6`); installs nothing (`:7`) — provider management is `gameframe mcp`, covered in ch.32 §7 |
| `zcc.sh` | 59 | rustc linker wrapper for 32-bit Windows DLLs via `zig cc`, no MinGW (`:2-3`); wired through `.cargo/config.toml` or `CARGO_TARGET_…_LINKER` (`:5-8`); `ZCC_DEF_DIR` for def files (`:10`) |
| `codex-cloud-environment-install.sh` | 161 | pins the Python/Rust/Zig/Ghidra/Java/DOSBox-X toolchain for the Codex *cloud* environment under `/workspace/toolchains`, then runs the setup checks (`:5-9`); touches no tracked file (`:10`) |
| `clients.py` | 243 | per-client file writer (see §2.4) |
| `release.py` | 135 | the release cutter — see ch.21 §3, not duplicated here |

### 2.4 `clients.py` — the multi-client file writer

The docstring is the spec (`clients.py:2-35`). Six clients (`CLIENTS`, `:46`); each gets its
agent copies (`AGENT_DIRS`, `:48-49`), its config files (`CONFIGS`, `:51-56`), and hooks that
either call `scripts/hooks/gate.py`/`advise.py` directly or, in plugin projects, are rewritten
to call `./gameframe gate` and `./gameframe advise-hook` (`:21-23`; regex rewrite
`via_launcher`, `:82-89`). `MARKERS` (`:58-62`) drive `detect` (`:78-79`). Write policy is the
same three-state rule as the project updater (§4.3): a file that GameFrame's git history holds
exactly (blob probe `shipped(git_blob(path))`, `:100-106`) is replaced; anything else is the
project's edit and is kept and listed (`:129-145`). Skill links `.claude/skills` → `../skills`
with a copytree fallback where symlinks fail (`:159-171`). Copilot agents are *rendered* per
project so their allowlists name the project's enabled MCP servers (`copilot_agents`, `:109-121`,
calling `gameframe agents --emit copilot`); every other non-Claude client's MCP config is
regenerated via `gameframe mcp --emit` (`:200-212`). It never removes a client's files (`:34-35`).
Hook bodies themselves are ch.32 §5; this section is only the file-writing mechanics.

### 2.5 The git pre-commit hook

`scripts/hooks/git/pre-commit` (25 L) runs `gate.py staged` on the index and blocks game
material and decompiled-looking added lines (`:7-9`); it locates `gate.py` next to itself so it
works identically in the clone and in `--copy` projects (`:10`). The two installation sites —
`core.hooksPath scripts/hooks/git` in GameFrame, `.githooks` in a project — are named in its own
header (`:4-5`) and performed by `setup.sh:101-109` and `new-project.sh:119-122` (§4.2).

## 3. The GameFrame home: `$GAMEFRAME_HOME` (default `~/gameframe`)

### 3.1 Layout

`tools/gameframe/home.py:1-33` is the specification, and the docstring *is* the user
documentation (`gameframe home` prints essentially it, `:115-122`). One folder per machine,
outside every clone and every game repository:

| Entry | Purpose (from `home.py:41-53`) |
|---|---|
| `config.env` | machine-wide settings: `GAMEFRAME_ROOT`, `GHIDRA_INSTALL_DIR`, `JAVA_HOME`, `DOSBOX_X_BINARY`, LLM endpoints; read by every script before the project's `.env`, which holds only what differs (`:16-18`) |
| `python/` | shared venv for the toolkit (`:42`) |
| `tools/`, `emulators/`, `machines/` (+`machines/os`), `drivers/` | downloaded tools, emulator programs + ROM sets, VMs, period drivers/SDKs (`:43-47`) |
| `games/ID/` | one game's files, "never in any repository" (`:48`; §3.2) |
| `projects/ID/` | one git repo per game (`:49`) |
| `worktrees/`, `cache/`, `data/` | hand-made worktrees; scratch ("safe to delete"); tool state (`:50-52`) |

`init` creates the folders, writes a home `README.md` (`:55-70,129-130`), and records what
`lib.sh` finds by sourcing lib.sh from bash and capturing the finder functions
(`detect`, `:106-112`); `merge_env` appends only keys the file lacks, preserving the user's
lines (`:93-103`). `--live/--llm` opt the shared venv into the two extra requirements files
(`:134-142`). `doctor` checks folders, the three critical config keys (present *and*
existing-on-disk, `:162-172`), the venv (`:173-175`), then every game and every project's links
(`:176-179`). The module promises it never deletes anything (`:30-31`) and does not install
Ghidra/Java/emulators — that division with `setup.sh` is stated at `:31-32`.

### 3.2 `games.py` — the media manifest and the links

`games.py:1-32` owns `games/ID/`. The core artifact is `game.json`:
`{"id", "media": [{"file","size","sha256","version"}], "extracted_from"}` (`:21`), with
`media/` "read-only after they are added" (`:22`) and a five-part layout `media/ game/ saves/
analysis/ derived/` (`:44`). `add` (`:104-146`) copies (or `--move`s) discs/installers into
`media/[NAME]/` (versioned via `--version`, `:108`), streams a SHA-256 over each file
(`:62-67`), and refuses on byte conflict rather than overwriting: an existing same-name
different-bytes file raises unless the user separates versions (`:124-126`). Then it extracts
the first added artifact into `game/` *only when that is empty* (`:137-145`), dispatching disc
images (`.iso .cue .bin .img .mdf .nrg .chd`, `:46`) through `tools/disc/discinfo.py --extract`
and everything else through `extract-installer.sh` — "It never runs an installer" (`:26-27,93-101`).
A folder argument copies straight into `game/` (`:113-119`).

`link` (`:163-179`) makes the project's five paths symlinks into `games/ID/`; a real folder in
the way must be empty or it stops with a pointer to `adopt` (`:174-177`). `adopt` (`:209-250`)
is the one-time migration: it moves a project's game folders into the home under the modern
names via the `OLD` map — `target/`→`game/`, `game-data/`→`game/`, `save-game/`→`saves/`,
`truth/`→`derived/truth/` (`:47-49`) — but *keeps any folder git itself tracks* (`:220-225`),
leaves each old name as a link so project code keeps working (`:230-234`), appends a commented
ignore block to `.gitignore` (`:235-241`), and with `--move-project` also relocates the repo to
`projects/ID/` behind a link (`:243-249`). `_move_into` refuses on name clashes before moving
anything and restores read-only modes on macOS (`:188-206`). Integrity checking is
size-always, SHA-256-on-`--hashes` (`check_game`, `:253-268`); `check_links` flags broken links
and game folders still resident in a project (`:271-283`).

### 3.3 Wiring

`paths.py` resolves everything from its own file location — "The same layout holds in GameFrame
and in a project" — with `python()` falling back `$PYTHON` → project `.venv` → home `python/` →
interpreter, and a note telling the user to run `setup.sh --install` or `gameframe home init`
when nothing is found (`paths.py:1-4,11,17-33`). `__main__.py` routes `home`/`game` subverbs
straight to `home.py`/`games.py` (`__main__.py:193-201`); `commands.doctor` shells to
`setup.sh` (`commands.py:190-191`). For a project, the resolver in `templates/project/gameframe`
(§4.4) reads `GAMEFRAME_ROOT` from the project `.env`, the *main* checkout's `.env` (so worktrees
inherit it), or the home's `config.env` (`templates/project/gameframe:25-35`), then falls back
to `~/code/game-frame`, `~/code/reverse-engineer-games`, or the newest plugin install under
`~/.claude/plugins/cache` sorted `-V` (`:36-39`).

**Vs calxgloss.** This is the closest thing in the whole project to a corpus story, and it
inverts calxgloss's. calxgloss keeps the *records* inside the repo (`re/` —
baselines, attempt branches, analysis logs) while the target binaries
stay outside in the user's `target_dir`, and fixity exists only as
roadmap intent (P44/P47); GameFrame pushes the corpus *outside* every repository — home `games/ID/media/` — and
makes fixity executable: `game.json` carries per-file size+SHA-256, `doctor --hashes` verifies
them, and the gates treat anything under `game/`/`media/` as commit-forbidden (ch.32 §5). The
"never overwrite, stop with a message, version instead" rule (`games.py:29-31,124-126`) is also
stricter than calxgloss's current write posture
(read-only `target_dir`, the scratch-dir convention; the P43 sandbox
is open).

## 4. Project lifecycle: create → check → update

### 4.1 `setup.sh` from a project

A project runs the same script through `./gameframe doctor` (launcher `templates/project/gameframe:51-59`
pass-through → `commands.doctor`), which adds two project-only steps: the `game/` folder check
(`setup.sh:111-114`) and the `.env` write (§2.2). There is no `--clone-only`/`--force`: the only
flags are `--install`, `--rea`, `--client NAME` (`:27-36`).

### 4.2 `new-project.sh` (136 L) — scaffold, then game

The header (`:3-35`) is the user manual; flags parse at `:38-49`. The decisions it encodes:

| Decision | Where | Detail |
|---|---|---|
| bare name = home project | `:56-57` | `pod` means `$GAMEFRAME_HOME/projects/pod`; game id defaults to the lower-cased folder name (`:58`) |
| refuse non-empty target | `:59` | one-shot guard |
| game files out of the project | `:62-63` | default: `gameframe game link` makes the five links into `games/ID/`; `--local` makes real folders for cloud machines or Windows without links, with `home adopt` as the later migration (`:21-22`) |
| **plugin vs copy** | `:64-87` | default project = plugin: `templates/project/settings.json` enables the Claude plugin and `templates/project/gameframe` is the only toolkit file copied. `--copy` drags in `tools/`, `scripts/`, the site template, one `skills/` copy plus agent links, agent copies, the repo's own `.claude/settings.json` (with the local gates), requirements, `.mcp.json`, the 8 reference docs and 14 doc guide folders |
| other clients | `:52-54,88-89` | `--agent LIST` validated by `clients.parse` before anything is written; per-client files written by `clients.py write … [--plugin]` |
| seeds | `:90-96` | licences, `.gitignore` from template, three header-only `labels/*.tsv`, and seven seed files (`AGENTS.md`, README, FINDINGS, GAME_PROFILE, CHECKLIST, lore, versions) with `GAME_NAME`/`DATE` substituted by `sed` |
| pins | `:97-100,103-108` | `CLAUDE.md` is a two-line shim `@AGENTS.md` only when claude is chosen; Cargo output moved to `build/` via `.cargo/config.toml` (`target-dir`, `:100`); a plugin project pins `GAMEFRAME_ROOT` into its git-ignored `.env` so worktrees resolve the same checkout (`:105-108`) |
| game intake | `:112-117` | folder arg copied into `game/` in `--local` mode, installer arg run through `extract-installer.sh`; otherwise `gameframe game add ID FILE` in the home |
| git + gate | `:119-122` | copies the pre-commit hook to `.githooks/`, `git init` + first commit, `core.hooksPath .githooks` |
| first look | `:123-129` | for each PE/DOS binary, prints `peinfo.py` or `dosinfo.py` output |

The printed "Next" block (`:130-136`) tells the user to edit the goal paragraph, run
`./gameframe doctor --install` (or `scripts/setup.sh --install` in a copy project), and start
with the `re-start` skill.

### 4.3 `update-project.sh` (315 L) — the blob-hash updater

The three-state contract, stated in the header (`:11-17`): missing → added; identical → left;
"an older version of GameFrame's file (its exact contents are in GameFrame's git history)" →
replaced; project-modified → kept and listed. The implementation is pure git plumbing:
`blob()` = `git hash-object`, `known(h)` = `git cat-file -e` against the toolkit's object DB,
`tracked(sub)` = the provided-file set (`:62-70`); the pair list covers `tools/ scripts/
templates/site`, skills matching `re-*`, `agents/ → .claude/agents`, the per-client files,
requirements + `.mcp.json` + `gameframe`, the 8 reference docs and the 14 guide folders
(`:72-88`). Plugin projects take a shortcut: refresh the launcher (byte-identical blob compare,
`put_launcher`, `:181-186`) and the plugin settings, write the client files, done (`:188-194`);
`is_plugin_project` recognises a project by its launcher's blob or a launcher that sets
`GAMEFRAME_PROJECT` (`:141-144`). `--plugin` migrates a copy project: every copied file that is
GameFrame's (current *or historical*) is deleted (`:200-207`), the project's changed copies are
kept (`:208-209`), then a scanner greps the project's tracked files for mentions of the now-dead
`tools/…|scripts/…` paths and prints the `./gameframe run NAME` alternative for each
(`:233-253`). Skill-folder migration (`skills/` plus `.claude/skills`/`.agents/skills` links) is
`move_skills/link_skills/unlink_skills` (`:101-139`); settings.json merging removes the local
gate hooks and adds the plugin marketplace/enabledPlugins/permissions in place (`:146-179`).
Finally, the bash tail applies the game-folder safeguards idempotently: warn-or-write
`.cargo/config.toml` when Cargo still targets `target/` (`:298-304`), write the
`GAME-FILES-NOT-BUILD-OUTPUT.txt` marker (`:305-309`), and tell any project still holding real
game folders to run `gameframe home adopt` (`:310-314`). Nothing is destructive without `--dry-run`
available (`:43`), and the project's own files are out of the pair list entirely (`:34-36`).

**Vs calxgloss.** The `git hash-object`/`cat-file -e` three-state rule is the strongest idea in
the layer — an updater that can distinguish "my old version" from "the user's edit" without a
manifest or version markers. calxgloss has no equivalent: our bootstrap docs tell humans what
to install, but nothing in the repo can tell a stale copy from a customized one.

### 4.4 What the template puts in a project

- `templates/project/AGENTS.md` (144 L) is the whole method compressed for the project: plugin
  provenance of skills/agents/gates (`:6-8`), the other clients' copies (`:9-12`), an editable
  goal paragraph (`:15-19`), a six-milestone ladder that puts *a viewer of every asset before
  the game* (`:21-36`), the "the user decides" jurisdiction rule naming
  `docs/preservation/law/README.md` (`:38-44`), eleven working rules — game material out of git
  and never `git clean -x` (`:51-64`), evidence labels observed/measured/inferred/unknown
  (`:65-67`), `Deviation:` ledgers (`:70-72`), per-TSV record-keeping (`:78-81`),
  multi-session staging rules (`:82-87`) — a path table (`:100-118`), and the one-checkout rule:
  change GameFrame only in a worktree of the pinned checkout (`:139-144`, matching
  `docs/working/environments.md`).
- `templates/project/settings.json` (44 L) is thin by design: marketplace `game-frame` →
  `tanepiper/game-frame` with `autoUpdate: true` (`:3-11`), `enabledPlugins:
  gameframe@game-frame` (`:12-14`), and permissions — 10 allow rules (`:16-26`), an ask list
  guarding push, `doctor --install`, the REA pin `npx -y rea-agents@6.7.0 setup *` (`:30`),
  brew, sudo, curl/wget, cargo-install (`:27-36`), and four force-add/force-push denies
  (`:37-42`). No pinned plugin versions of its own: currency comes from `autoUpdate` plus
  `update-project.sh`. (The root repo's own 80-line settings with the hook wiring is ch.32 §5.)
- `templates/project/gitignore` (23 L) ignores `/game /media /saves /analysis /derived` with the
  comment "No trailing slash: a link is not a folder to git" (`:1-12`), plus `build/`, the
  legacy `target/`, `*.sav`, `.venv/`, `.env` (`:13-20`).
- Seeds: `docs/CHECKLIST.md` (39 L) encodes traced→measured→reimplemented→verified as the state
  vocabulary (`:5-7`) and tool commands as checkbox items (`:11-12,19`); `docs/FINDINGS.md`
  (32 L) is claim-evidence tables (`:3-5`); `docs/GAME_PROFILE.md` (71 L) an at-a-glance
  evidence table (`:15-26`); README (25 L) the per-part build/run table and the Apache/CC0 split
  (`:12-25`); `labels/*.tsv` three header-only tables, the dictionary naming
  `docs/DATA-DICTIONARY.md` in GameFrame.
- `templates/project/gameframe` (60 L) is the one executable: usage header for
  `run/python/doctor/root/gate/advise-hook` (`:5-14`), the `GAMEFRAME_ROOT` + plugin-cache
  resolver (§3.3), a three-location `PYTHON` chain (`:46-50`), and dispatch — `gate`/`advise-hook`
  exec the gate engine's entry points, `python` prepends the toolkit families to `PYTHONPATH` so
  project scripts can `import pe_emu, dos_emu, reader…` (`:55-58`), and everything else execs
  the clone's `gameframe` (`:59`).

## 5. The launcher crate and installing a built port

### 5.1 `launcher/` — a frame in front of a game that says nothing

`launcher/` is deliberately outside the 28-member `crates/` workspace: "Its own workspace, so
the desktop's dependencies stay out of `crates/`" (`launcher/Cargo.toml:9-10`; `[workspace]`
`:10`), with exactly four dependencies — `gameframe-frame`, `gameframe-frame-ui`,
`gameframe-library` by path, and `dioxus 0.7.10` desktop (`:12-16`). `src/main.rs` (153 L, of
which 29 are the header doc) is a composition script, not a framework: `options()` parses
`[PATH] [--frame|--no-frame] [--data DIR] [--preset NAME]` and defaults data to
`launcher-data/` beside `frame.json` (`:51-72`, default `:71`); `spec()` reads a `library.json`
beside `frame.json` — with its pages loaded — else synthesizes a title + all `THEMES` presets
(`:79-97`); `main()` loads `show_at_start` from the saved settings to decide window visibility
(`:99-114`); `make_setup()` loads `Configured::load(frame.json)` (the `gameframe_frame::Configured`
format from ch.30), builds a `Session`, sets `session.hide_while_running(true)` (`:126-130`),
and wires the `frame-ui` `Frame` component with save/start-at-once/exit/window callbacks
(`:133-147`) plus a `gameframe_library::Library` over a `Folder` store when `library.json`
exists (`:148-151`).

The `frame.json` contract is the point (`launcher/README.md:34-57`): a `manifest` (contract,
renderers, settings) plus `start: {command, args}` plus `folder` — the launcher runs an
arbitrary command in the game folder, filling `{renderer}`, `{device:sound}`, `{setting:KEY}`
(`:48-49`) and `{folder}`/`{image}` paths (`:50-54`); choices can enumerate game files with
`"from": {"files": "TRACKS/*.TRK"}`, "the tracks, the cars or the levels" (`:55-57`). The
shipped example's game is literally `sh -c "echo … sleep 3"` (`launcher/example/frame.json:16`)
with two empty `.TRK` files (ch.20 §13). The honesty section states the limits plainly: it does
not install, find, or check the game; a `frame.json`-launched game has *no channel back* to the
frame, and only contract-speaking ports can `frame.open` (`launcher/README.md:73-78`;
`src/main.rs:21-28`). Desktop-only, WIP (ch.20 §13 labels it so; the Cargo.toml carries no
version-pinning of its own beyond the path deps).

### 5.2 `tools/install/` + `install.json` — where a finished port goes

The other half of "launcher" is installing the port as an application, driven by a 10-line
manifest. `install.json` at the project root: `name/id/version/icon` + per-build `build`
(commands), `programs`, `start`, `args`, `resources`; the shipped example builds
`examples/frame-demo` (`install.json:5-8`). `install_app.py` (255 L) does the work: `vanilla` vs
`extra` (the additions-on build installed as "NAME Extra") (`install_app.py:12-16`), keys table
(`:28-47`), and the placement contract (`:49-54`): macOS `/Applications/GameFrame/NAME.app` (or
`~/Applications` when unwritable) with data in `~/Library/Application Support/GameFrame/NAME`;
Windows `%LOCALAPPDATA%\Programs\GameFrame\NAME`; Linux `$XDG_DATA_HOME/GameFrame/NAME` —
"per user, with no administrator rights" except the macOS `/Applications` case
(`places.py:6-13`). The split programs-vs-data means "a new install never touches" player data
(`places.py:3-4,54`). Platform back-ends: `macos.py` writes the `.app` bundle + `Info.plist` and
ad-hoc codesigns, explicitly disclaiming Developer ID (`macos.py:1-4`); `desktop.py` a Linux
`.desktop` entry and a Windows Start-menu shortcut made via PowerShell (`desktop.py:4-7`);
`launch.py` the cd-into-data-folder start scripts (`launch.py:1-9`). Entry point:
`gameframe install [vanilla|extra]` passes straight through (`commands.py:194-196`,
`__main__.py:41-43`), and the project AGENTS template advertises it (`templates/project/AGENTS.md:114`).
What it does not do: cross-compile or purchase-like behavior — build each system's install on
that system (`install_app.py:59-60`).

## 6. Two site worlds: GameFrame's own, and the project template's

### 6.1 `site/` — pages generated from the repo, never copied

`site/README.md:3-4` states the principle: "It holds no copies of the documentation: the pages
are read where they are." The mapping table (`:12-22`) is the mechanism: `/overview` is
`README.md`; guide sections come from `docs/README.md`'s `## ` headings; folder pages from each
`docs/<folder>/README.md` and its link order; `/skills/<name>`, `/agents/<name>`, `/tools/<name>`
are dynamic routes (`site/skills/[skill].md` etc.) rendering the same files the CLI renders —
the tool pages show each tool's docstring "as `./gameframe tool NAME` prints it" (`:20`).
Adding a page means writing Markdown in `docs/` and linking it — the menu follows the links
(`:28-36`), and relative links (GitHub-correct) are rewritten to page URLs by `links.mts`
(`:38`). `config.mts` is small because the helpers do the work: it imports `repo/links/llms/sidebar`
modules (`site/.vitepress/config.mts:6-9`), computes a home-page date from the newest commit
touching any site source via `git log -1 --format=%at` (`gitTime`, `:17-25`, sources `:28`), and
takes the Pages base from `SITE_BASE` (`:30`). `llms.mts` writes `llms.txt`-style files at build
time (`writeLlmsFiles`, `:8`). Deps pin exactly: vitepress 1.6.4, mermaid 11.17.2,
vitepress-plugin-mermaid 2.0.17 (`site/package.json`).

`.github/workflows/site.yml` (64 L) is the repo's only workflow (ch.20 §16). Triggers: push to
`main` touching docs/skills/agents/tools/scripts/examples/README/site or itself, plus
`workflow_dispatch` (`:6-19`). Node 22 and `fetch-depth: 0` so "last updated dates come from git
history" (`:37-39`); build with `SITE_BASE`/`SITE_URL` from `configure-pages` (`:45-51`);
artifact + deploy jobs (`:52-64`). The concurrency block carries a rare artifact of real
operations: the group was renamed to `pages-site` because run 39803187786 (22 Oct 2026) got
stuck in "waiting" and held the old `pages` group for every later run — with an instruction to
change it back once GitHub clears it (`:26-31`).

### 6.2 `templates/site/` + `new-site.sh` — the project diary machine

`new-site.sh` (67 L) stamps a VitePress site from `templates/site/` into `sites/NAME/` (or
`site/` with `--single`) (`new-site.sh:38`), substituting `SITE_TITLE/SITE_DESCRIPTION/SITE_NAME/
REPO_URL/DOCS/` into seven files by `sed` with a double-quote escaper (`:46-51`), and drops
`templates/site/sites.yml` in as the *project's* `.github/workflows/sites.yml` — with `--manual`
deleting its `push:` trigger by sed so it only runs by hand, "to save Actions minutes"
(`:54-65`; header `:16-19`). It never runs npm (`:21`); the printed next step does (`:66-67`).

The template's workflow builds *many* sites per repo: it discovers `site/` plus every `sites/*`
with a `package.json`, serves one at `/<repo>/` or several at `/<repo>/<name>/` with a generated
HTML index linking each (`templates/site/sites.yml:33-50`), again `fetch-depth: 0` for
`lastUpdated` (`:27-29`). The content model is diary-first: entries named `YYYY-MM-DD-slug.md`,
plus *live* entries `YYYY-MM-DD-HHMM-slug.md` written during the day, which disappear from the
sidebar once that day's day-post exists (`config.mts:13-32`, `diary/posts.data.mts:6-25`).
`findings.md`/`status.md` are single-line `@include`s of `docs/FINDINGS.md`/`docs/CHECKLIST.md`
(`findings.md:1`, `status.md:1`) — the same "one copy of the prose" rule as §6.1. Local search,
en-GB, footer disclaiming game files (`config.mts:39-63`). Guarding it: `tools/site/check.py`
(210 L) checks a site before publication — includes, game material left in pages, diary hygiene
(live entries vs the missing day posts, `--days`), leftover TODOs (`:2-8`).

### 6.3 `templates/library-page/` — the browser-port storefront

A framework-free, build-step-free HTML page a browser port copies into its web folder
(`README.md:3-6`): the file table (`:8-19`) separates what users edit (`library.json`,
`index.html`) from what they don't (the JS/CSS), with 11 ready-made `themes/*.css` presets. The
store layer — IndexedDB "in the layout of the Rust crate" (`:15`) — is deliberately mirrored
with `crates/library`: "It reads the same `library.json` and the same database, so the game sees
what the player added" (`:21-22`). Exactly one section is `kind: game-data` and the Start button
waits on its `required` files (`:24-33`). The desktop launcher and this page are two views of the
same `library.json` (§5.1 `spec()`), which is what makes them one system across chapters 30–31
and this layer.

## 7. Assessment

1. **A lifecycle, not a script pile.** The pieces compose into one story: `setup.sh` (check) →
   `new-project.sh` (create) → `gameframe doctor`/`update-project.sh` (keep current) →
   `gameframe home adopt` (migrate) → `install` (ship). Each step's contract is written in its
   own header and repeated in the seeds; the AGENTS template is the user manual for the result.
2. **Two safety properties run through everything**: game bytes never enter git, and nothing
   that holds game bytes is ever overwritten or cleaned (§3.2, §4.3 tail, template rules). The
   enforcement is layered — `.gitignore`, the marker file, the gates, and the updater's
   git-history three-state rule.
3. **Pin discipline is selective.** REA is pinned at exactly 6.7.0 in two places
   (`setup.sh:126`, project settings `:30`); the GameFrame plugin itself is *unpinned by design*
   (`autoUpdate: true`); the desktop toolchain (Ghidra/JDK21/vitepress/mermaid/dioxus) is pinned
   by version in checks and package files. There is no lockfile story for the Rust side beyond
   path deps.
4. **Honest negative surface.** No test/lint/release CI at all (a single Pages workflow);
   `update.sh`/`doctor.sh`/`bootstrap.sh` do not exist — check-and-repair is one script, home
   setup is `home init`; the launcher refuses to be an installer; the site refuses to copy docs.
   For a project this polished, the single-workflow CI is the weakest operational link (ch.20 §16).
5. **Vs calxgloss, briefly** (the full adopt-list is ch.40): adopt the blob-hash three-state
   updater idea, the out-of-repo corpus with executable SHA-256 fixity, and the
   marker-file-plus-hook pattern for "never delete the irreplaceable folder"; the typed-config
story calxgloss has (TOML config with flag→env→TOML→default
resolution and per-value source tracking, ch.10 §Surface & state) has no
GameFrame counterpart — their
   config layer is plain layered env files (`lib.sh:11-14`) with `KEY=value` parsing
   (`home.py:78-90`), and their `install.json` is schema'd only by prose.

## 8. Sources (all re-opened at `f195a07` via `git cat-file -p` / `git grep -n`)

`scripts/setup.sh`, `scripts/lib.sh`, `scripts/env.sh`, `scripts/new-project.sh`,
`scripts/update-project.sh`, `scripts/new-site.sh`, `scripts/clients.py`,
`scripts/mcp-provider.sh`, `scripts/dosbox-run.sh`, `scripts/extract-installer.sh`,
`scripts/ghidra-export.sh`, `scripts/ghidra-run.sh`, `scripts/zcc.sh`,
`scripts/codex-cloud-environment-install.sh`, `scripts/release.py` (header),
`scripts/hooks/git/pre-commit`, `gameframe`, `templates/project/gameframe`,
`templates/project/settings.json`, `templates/project/AGENTS.md`,
`templates/project/gitignore`, `templates/project/README.md`,
`templates/project/docs/{CHECKLIST,FINDINGS,GAME_PROFILE}.md`, `templates/project/labels/*.tsv`,
`templates/site/{sites.yml,package.json,config.mts,posts.data.mts,index.md,findings.md,status.md}`,
`templates/library-page/README.md`, `templates/library-page/library.json`,
`tools/gameframe/{__main__,commands,home,games,paths}.py`, `tools/site/check.py` (header),
`tools/install/{install_app,places,desktop,launch,macos}.py`, `launcher/{Cargo.toml,README.md}`,
`launcher/src/main.rs`, `launcher/example/frame.json`, `install.json`,
`site/README.md`, `site/.vitepress/config.mts`, `site/package.json`,
`.github/workflows/site.yml`, `templates/site/.vitepress/config.mts`,
`.claude-plugin/{plugin.json,marketplace.json}` (versions 1.5.0-dev),
counts per ch.20 §9/§13/§16/§17; gates and clients cross-referenced from ch.32 §5–7;
release flow from ch.21 §3.
