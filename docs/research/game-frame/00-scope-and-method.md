# GameFrame ↔ calxgloss comparison — scope and method

> Part of the [game-frame overview](README.md). Read this first for what
> is being compared and how.

## What GameFrame is

**GameFrame** ([tanepiper/game-frame](https://github.com/tanepiper/game-frame),
Apache-2.0 code + CC0-1.0 content) is an **agentic framework for reverse
engineering games**: a *playbook* (16 skills in `skills/re-*/`, 23 stage and
task agents in `agents/`, team recipes, rules in `AGENTS.md`) that runs inside
whatever coding agent the user brings (Claude Code, Codex, Cursor, Gemini CLI,
Copilot, OpenCode), plus a *toolkit* (~100 self-documenting Python/Java/Rust
tools in `tools/`, 13 scripts, a `tests/run.sh` that proves every tool on
checked-in sample games). Its method loop is *inventory → observe →
decompile → trace → format → emulate → reimplement → verify → land*, with
every claim labelled *observed · measured · inferred · unknown* and every
number the port must match **measured by running the original function under
an emulator**; the reimplementation must match **bit for bit**. It grew out of
Un-Banished, a 1:1 reimplementation of Banished, and ships reusable Rust
artifacts: 31 crates (chips like OPL2, codecs like Indeo 4.1, MSVC-CRT math,
rasterizers) and 5 replacement 3D-card DLLs, plus *the frame* — a launcher,
library, settings and event console wrapped around every port behind a
versioned event contract.

calxgloss is the opposite build shape: a **fully automated Rust pipeline +
review harness** in which a deterministic orchestrator drives off-the-shelf
local LLMs with 15 evidence-engine scans, gates every attempt on
compile + Wine-captured behavior baselines + API-trace containment, and has a
human adjudicate each unit in a web UI (see
[10-calxgloss-baseline.md](10-calxgloss-baseline.md)). game-frame automates
*nothing* end-to-end — it automates *trust*: the method is markdown the agent
follows, and the tools exist so any claim can be checked against the original.
The comparison is pipeline-ontology vs playbook-ontology, and the two meet at
the same ground-truth move — run the original binary and compare.

## Comparison scope

**In scope** — every part of game-frame, in depth where it touches
calxgloss's concerns:

- Complete repository inventory at HEAD: every top-level area — `skills/`,
  `agents/`, `tools/` (14 families, ~100 tools: Ghidra export/query, Unicorn
  emulators, format validation, bit-exact comparison, DOS tooling, live
  memory tools, LLM helpers), `scripts/`, `tests/`, `examples/` (sample-game,
  dos-sample), `crates/` (28-crate Cargo workspace), `wrappers/` (replacement
  DLL workspace), `launcher/`, `templates/`, `hooks/`, `site/`, `docs/` —
  plus packaging (requirements files, `install.json`, `.claude-plugin/`),
  licensing split (Apache-2.0 vs CC0), CI presence/absence, and verified
  GitHub metadata.
- Git history and releases: 383 commits, tags v1.0.0 → v1.4.0, the
  `CHANGELOG.md` ladder, `scripts/release.py`, plugin-version propagation.
- The playbook in full: every `skills/re-*/SKILL.md`, the method loop, the
  evidence-label discipline, `AGENTS.md` rules, the project template's own
  rules, and the `./gameframe` discovery CLI.
- The agent layer: all 23 agents in `agents/`, hand-off routing, the eight
  teams in `docs/teams/`, permission gates and hooks (`docs/working/gates.md`,
  `hooks/`), multi-client generation (`scripts/clients.py`,
  `gameframe agents --emit`), and the Claude Code plugin distribution model.
- The toolkit in depth: what each tool family measures, the key tools'
  mechanics (Ghidra headless export & `ghidra-run.sh` jobs, `pe32_emu.py` /
  `dos_emu` / `call_trace.py`, `reader.py`/`validate.py` decoder proving,
  `bitcompare.py`/`seqdiff.py`, `coverage.py`/`deviations.py`), and what
  `tests/run.sh` proves.
- The artifact layer: every crate in `crates/` (chips, codecs, math-identical
  CRT, rasterizers, frame/frame-ui/library/game-source/report contract),
  every DLL in `wrappers/`, and `launcher/`.
- The documentation corpus: `docs/` (~40 areas: game taxonomy, engines,
  period hardware, consoles/handhelds/arcade, `COMPILED-CODE.md`, `ABI.md`,
  `TYPES.md`, `GAME-PATTERNS.md`, `DATA-DICTIONARY.md`, case studies,
  `knowhow/`, `working/`, `harness/`, `observe/`, `LEGAL.md`, `OUTPUTS.md`),
  `GAPS.md` as a public gap ledger, and the built website (`site/`).
- Scope boundaries the project itself declares (Windows x64 + 16-bit DOS end
  to end; DOS extenders recognized but not emulated; managed/scripted/packed
  routed elsewhere) and its legal posture.

**Out of scope**

- Ghidra, Unicorn, REA, DOSBox-X, 86Box, Zig, dioxus internals as such —
  cited only where game-frame's behavior depends on them.
- The Un-Banished / Tyrian 2000 / Frontier: Elite II / POD case-study *games*
  themselves; only what tooling and knowledge each contributed back.
- Running the toolkit (Ghidra analysis, emulations, `tests/run.sh`) — this
  dossier audits the artifacts and claims as written at the pinned HEAD; it
  does not re-execute them.

## Method and sources

- **Primary code source:** a full clone at `/tmp/opencode/game-frame`, HEAD
  `f195a074a63cc150673c38becdec696163b0b3d1` (2026-10-30, "Merge completed
  slices into local main"), full history (383 commits, first `fad70ad`
  2026-10-21 "Set up the reverse-engineering harness for games"), tags
  v1.0.0–v1.4.0. Claims cite clone-relative `path:line` at that commit;
  history claims cite `<sha> <path>`.
- **Repo facts at HEAD** (verified 2026-10-31 via GitHub API): created
  2026-10-21T07:31Z; last push 2026-10-30T20:58Z; **20 stars, 6 forks,
  2 open issues**; default branch `main`; GitHub-reported primary language
  Rust; repo size ≈6.9 MB (git data), ≈23 MB full worktree; homepage
  https://tanepiper.github.io/game-frame/ (GitHub Pages enabled); GitHub
  license field Apache-2.0 (the repo's actual split is Apache-2.0 code +
  CC0-1.0 content); template repo (`is_template: true`), Discussions enabled.
- **calxgloss side:** [10-calxgloss-baseline.md](10-calxgloss-baseline.md)
  is the fixed anchor, pinned at calxgloss HEAD `40fbf91f` (2026-10-31);
  same calxgloss snapshot as the [LLM4Decompile](../LLM4Decompile/README.md)
  and [reverser_ai](../reverser_ai/README.md) baselines; its claims cite this
  repo's docs, ADRs, and crates.

## File index

| File | Domain | Status |
|------|--------|--------|
| [00-scope-and-method.md](00-scope-and-method.md) | this file | done |
| [10-calxgloss-baseline.md](10-calxgloss-baseline.md) | calxgloss capability inventory (comparison anchor) | done |
| [20-gameframe-inventory.md](20-gameframe-inventory.md) | complete repo surface: folders, every tool/script enumerated, packaging, licenses, CI, metadata | done |
| [21-history-and-releases.md](21-history-and-releases.md) | 383-commit archaeology, v1.0.0→v1.4.0 ladder, release process, contributors | done |
| [31-method-playbook-skills.md](31-method-playbook-skills.md) | method loop, evidence labels, all 16 skills, AGENTS.md rules, `./gameframe` CLI | done |
| [32-agents-teams-gates.md](32-agents-teams-gates.md) | all 23 agents, hand-offs, 8 teams, gates/hooks, multi-client emit, plugin + MCP | done |
| [33-toolkit-tools-tests.md](33-toolkit-tools-tests.md) | all 14 tool families in depth, key tool mechanics, tests/run.sh, the two sample games | done |
| [34-scripts-templates-launcher-site.md](34-scripts-templates-launcher-site.md) | scripts, project template & lifecycle, launcher, site build, GameFrame home layout | done |
| [35-crates-wrappers.md](35-crates-wrappers.md) | all 28 crates, 10-member wrapper workspace, frame contract, verification of each | done |
| [36-documentation-corpus.md](36-documentation-corpus.md) | docs/ encyclopedia area by area, GAPS.md ledger, knowhow, legal posture | done |
| [40-comparison.md](40-comparison.md) | full feature & effect comparison vs calxgloss, adopt list, confirmations | done |
| [README.md](README.md) | overview: executive summary, condensed matrix, adopt list, reading order | done |

## Citation notes

- game-frame claims cite clone-relative `path:line` at HEAD `f195a074`;
  history claims cite `<sha>` (short) with path.
- Web claims cite fetched URLs (GitHub API fetched 2026-10-31).
- calxgloss claims cite crate-relative paths (resolved under
  `crates/<group>/calxgloss-*/…`) at HEAD `40fbf91f`, or ADR numbers.
- Verified absences (CI, tests, renames, etc.) are recorded as negative
  findings with the search performed, not left as coverage gaps.
