# OGhidra history & release archaeology (147 commits, one tag, zero releases)

> Part of the [OGhidra overview](README.md). The complete commit history —
> 147 commits, ten humans plus a bot, 342 days of public life — reconstructed
> from the clone at `/tmp/opencode/OGhidra` (`6224d26`, `origin/main` tip
> 2026-10-28): monthly cadence, identity-merged shortlog, per-commit numstat
> for every mega-commit, and a `rev-list --left-right` table over all eleven
> non-main remote branches. **There is exactly one tag (`v0.0.0`) and zero
> GitHub Releases**, yet a package sits on PyPI — the release ladder is one
> silent rung, and §5 shows why the number on it is 0.0.0. All dates are
> author dates in `-0800` (LLNL timezone) unless stated; GitHub facts are
> `gh api` recorded 2026-11-01, PyPI facts the JSON API the same day.

## 1. Commit shape and the ten humans

**147 commits** on `origin/main` (measured: `git rev-list --count
origin/main` = 147), spanning 2025-11-20 11:12 → 2026-10-28 11:59, which
matches the API `created_at` 2025-11-20T19:12:38Z and `pushed_at`
2026-10-28T18:59:33Z. Author counts (merge commits included, so the column
sums to 147), with author names and emails folded per identity (§Sources):

| Identity | Commits | Share | What they actually touched |
|---|---:|---:|---|
| Enoch Wang — `ezrealenoch`, `Enoch Wang`, `78103303+…@users.noreply`, `enochsurge@gmail.com` | 83 | 56% | everything through 2026-03-04; all six mega-commits; the README drumbeat |
| Erik McCutchen (`Eriken79`) | 16 | 11% | pyghidra backend (#23), Docker + CI (#33), health-check fix (#59) |
| Ryan Mast (`nightlark`) | 14 | 10% | ruff/import-sort sweeps, the orchestrator revert, VCS versioning + PyPI workflow (#52) |
| Joshua Dunn (`jdunns`) | 14 | 10% | pre-commit (#21), ruff/shellcheck sweep (#25), `ui.py` split (#27), gradle fixes; later the DSPy rewrite on its branch |
| `pre-commit-ci[bot]` | 11 | 7% | autoupdate + auto-fix commits, always squash-merged |
| Jack Mooney (`moonjck`) | 3 | 2% | #51 "Bugs/slasher findings", #61, the direct gradle-docs commit `2a31adc` |
| Seth Lyles (`slyles1001`) | 3 | 2% | ollama auth (#6) `10064a1`, the #23 merge commit `cedeb94`, plugin-ID README `eb07109`; also leads `add-lore` and `delete-ghidra_mcp_client` |
| Manny Bhidya (`abhidya`) | 1 | 1% | "Fix Linux UI crash" #44 `93a4380` (plus 7 more commits on the related branches) |
| TahaW863 | 1 | 1% | semantic-similarity benchmark `8150f0d` → PR #4 |
| Wangmo Tenzing (`wangmot`) | 1 | 1% | missing-import fix, PR #17 `a7435b1` |

Monthly cadence (measured: `git log --format='%ad' --date=format:'%Y-%m'
origin/main | sort | uniq -c`) tells the whole story at a glance:

| Month | 25-11 | 25-12 | 26-01 | 26-02 | 26-03 | 26-04 | 26-05 | 26-06 | 26-07 | 26-08 | 26-09 | 26-10 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Commits | 19 | 27 | 16 | 6 | 9 | 11 | **31** | 18 | 4 | 3 | 1 | 2 |

Two peaks and a cliff. The Nov–Dec peak is the open-source import and the
author's solo build-out; the May peak is *post-hoc polish of someone else's
mega-commit* (§4) — feature work by the creator had already ended on
2026-03-04. From July onward the repo runs on bot hygiene and one-off
community fixes: 4 + 3 + 1 + 2 commits in four months.

## 2. Birth: an LLNL C++ skeleton, Pythonized in four minutes

`71da7d7` "Initial commit" (2025-11-20 11:12 `-0800`, 9 files +314, measured
`git show --stat`) is not this project at all — it is the stock LLNL C++
release scaffold: `CMakeLists.txt`, the BLT build system, a `tpl/raja`
submodule, `src/example.cpp`, an MIT-style `LICENSE`, the DOE `NOTICE`, and a
132-line README. Four minutes of history later, `5fa72ea`
"OGhidra-Open-Source" (11:56) drops the real project on top of it: **58
files, +22,487/−177**, taking the tree to 54 files (measured
`git ls-tree -r --name-only 5fa72ea | wc -l` = 54). The import is not a
rewrite — `src/bridge.py` arrives already at **4,761 lines** (measured
`git show 5fa72ea:src/bridge.py | wc -l`), i.e. the whole tool had lived
off-GitHub. The C++ scaffold is then pruned within minutes: `dc36929`
"Delete raja" (11:58), `50e869e` "Delete config_template.env" (12:01).

Two more birth facts that outlive the repo:

- **`.env` was tracked from the import** (it carries the config; no secrets
  in it) until `30d130d` deleted it and added `.env.example` on 2026-01-21
  (measured via `git show 30d130d --name-status | grep -i env`).
- **The license pivoted on day five.** `524235e` "Change license from MIT to
  BSD 3-Clause" + `f666b1b` "Update license" (2025-11-25) installed the
  current *BSD 3‑Clause with Commercial License alternative* text
  (`LICENSE:1` title; non-commercial condition at `LICENSE:6-8`,
  LLNS-issued commercial alternative at `LICENSE:22-33`). GitHub classifies
  the result as `NOASSERTION` (API, 2026-11-01) — see §7. The LLNL release
  number **LLNL-CODE-2013290** appears only once in the whole tree, at
  `README.md:600`; this has always been a lab release, not a hobby repo.

## 3. The Enoch era (Nov 2025 – Mar 2026): six mega-commits and a README drumbeat

Between the import and the author's last substantive commit, the history is
six chunky code commits separated by README/image/`.env` housekeeping —
classic open-sourcing cadence ("Add files via upload", "Images", "Fix image
syntax", zip renames). The mega-commits, all authored by `ezrealenoch`
(numstat measured):

| Sha | Date | Δ | What it is |
|---|---|---|---|
| `5fa72ea` | 2025-11-20 | 58 files +22,487/−177 | the private tool lands whole (§2) |
| `3c499f0` | 2025-12-25 | 22 files +381/−95 | "BigUpdate" — modest despite the name; architecture README section lands the same morning (`1e89b22`–`548a0f4`) |
| `c231fdd` | 2026-01-19 | 2 files **0/0** | "New Plugin Handles Multiple Instance" — binary Ghidra-plugin zip swapped with zero text lines |
| `30d130d` | 2026-01-21 | 38 files +3,200/−429 | "Added Gemini Support and Robust Agentic Analysis"; also deletes `.env`, adds `.env.example` |
| `4841c4c` | 2026-02-09 | 55 files +6,875/−227 | "Leads and Convergence"; its `docs/tool_capabilities.md` edit is that file's **last content update ever** (inventory §10) |
| `262cf2f` | 2026-03-04 | 36 files +8,933/−1,648 | "Major update: … **sanitized for open source release**" — plus a seven-commit README cluster the same hour |

The `262cf2f` message is the tell: even the public March "update" was a
batched import from off-GitHub work. The only outside code the era accepted
is TahaW863's benchmark PR #4 (`8150f0d`, merged `555970e`, 2026-01-21) and
Seth Lyles' ollama username/password option #6 (`10064a1`, 2026-03-25).
After 2026-03-04 the founder writes README tweaks (`e9d05d5` YouTube
section, 2026-04-07) and nothing else on main — every later OGhidra idea of
his lives on the branch map (§6), especially the orchestrator (§4).

## 4. The maintainer takeover: the orchestrator incident, then PR discipline

The repo's single most dramatic sequence ran entirely through `main`:

1. **2026-04-02 01:05** — `d5dec8a` "Harnesses and Helpers" lands **directly
   on main**, no PR: 38 files **+16,969/−4,640** (numstat measured). It
   drops an entire multi-agent orchestrator on the tool:
   `src/orchestrator.py` 2,764, `src/report_generator.py` 2,520,
   `src/agents/worker_agent.py` 1,385, `src/recipes.py` 754,
   `src/blackboard.py` 395, plus ≈3.75k lines of fresh tests
   (`test_orchestrator.py` 1,790, `test_worker_agent.py` 1,004,
   `test_recipes.py` 958).
2. **May 8–13** — the LLNL maintainers polish it on main: Joshua Dunn
   commits dated 05-08 (its tip note reads "Cherry-picked from commit
   `59419af3a1` in PR #18"), then Ryan Mast's ruff/import-sort sweeps on
   the added files.
3. **2026-05-15 14:57** — `c62ec6e` **reverts the whole thing**:
   38 files +4,639/−16,974, the exact mirror. Four minutes later
   `44ee11d` "Add link in README to the orchestrator branch" points users
   at `origin/orchestrator`. Measured today the branch is **0 commits ahead
   of main, main 39 ahead** — the branch exists purely to keep the
   pre-revert tree alive at tip `aa03aa8` (2026-05-08). The orchestrator is
   therefore not "dead", it is *branch-resident*: chapter 36 reads it there.

After the revert, the repo finally behaves like a PR-driven project: 20 PR
numbers appear in main's messages (#4, 6, 17, 21, 23, 24, 25, 27, 32, 33,
35, 37, 44, 45, 47, 48, 51, 52, 59, 61). The load-bearing ones:

| PR | Sha | Date | Change |
|---|---|---|---|
| #21 | `9fa3682` | 2026-05-22 | pre-commit config (from branch `21-precommit-autofixes`, tip `a361d3c`) |
| #24/#25 | `d8ba106`/`421c0b2` | 2026-06-08 | ruff bump; "Fix all ruff and shellcheck issues and remove unused code" |
| #23 | `cedeb94` | 2026-06-17 | **pyghidra backend merged** (Eriken79's branch; merge commit authored by Seth Lyles): 9 files +2,601/−734 |
| #33 | `8fd8590` | 2026-06-17 | Dockerfile + GitHub Actions CI merge (Eriken79) |
| #27 | `b43b36a` | 2026-06-26 | "Break up ui.py into separate class-only python files" (jdunns) |
| #44 | `93a4380` | 2026-07-29 | "Fix Linux UI crash" (abhidya) — squashed delivery of the `fix/session-loading-ui-freeze` + `19-gui` work, 9 files +716/−503 |
| #52 | `1b51e06` + `aea39dd` | 2026-08-14 | VCS-based versioning, then "Add PyPI release workflow" (nightlark) — the only release machinery the repo ever got (§5) |
| #51 | `55d2888` | 2026-08-21 | "Bugs/slasher findings" (moonjck) |
| #59 | `41829c6` | 2026-09-16 | health-check bugfix (Eriken79) |
| #61 | `9078cd9` | 2026-10-22 | pre-commit followup — **the last human commit on main** |

Bot notes: 11 of the 147 commits are `pre-commit-ci[bot]` and every one was
merged — bots are the only uninterrupted traffic. One anachronism slips
through the PR discipline: `2a31adc` "Improved gradle install and
documentation" (Jack Mooney, 2026-07-24) is pushed **straight to main**, a
holdover of the direct-push era. The `pyghidra` branch was deleted after
#23, which is why the Dockerfile's `git clone -b pyghidra` is broken today
(measured: `git ls-remote --heads origin` shows 12 heads, no `pyghidra` —
see inventory §8).

## 5. Releases, versioning, PyPI — why the number is 0.0.0

- **GitHub Releases: zero.** (API `/releases`, 2026-11-01.) No release
  notes, no assets, no changelog — the README is the release narrative, and
  the README never mentions PyPI at all.
- **Tags: exactly one.** Measured: `git tag -l` → `v0.0.0`;
  `git rev-parse v0.0.0` = `aea39dd…` — i.e. the tag points at *"Add PyPI
  release workflow (#52)"* itself (2026-08-14), never at a built artifact.
- **PyPI: one package, one push.** PyPI JSON API (2026-11-01): `oghidra`
  has a single release `0.0.0` (wheel + sdist) uploaded 2026-08-14T22:59Z,
  license field "BSD-3-Clause" — published by the `aea39dd` workflow
  (49-line release.yml) minutes after the tag.
- **The version number is a side effect of the tooling, not a decision.**
  `1b51e06` switched to VCS-based versioning (setuptools-scm-style), so the
  version literally *is* the latest tag — and the only tag is `v0.0.0`.
  Meanwhile `src/__init__.py:7` still hardcodes `__version__ = "0.1.0"`, a
  number no release ever had: three version stories, none agreeing
  (the Java plugin has its own three-way disagreement — inventory §6).

So the release archaeology collapses to: *a lab PyPI push that happened by
infrastructure, on a repo that has never cut a GitHub Release.* Any chapter
citing an "OGhidra 0.0.0" is citing the tag, not the README, not the
package metadata story anyone told.

## 6. Branch map: the work that never merged

Eleven non-main branches exist (12 heads total, measured
`git ls-remote --heads origin`). The delta columns are
`git rev-list --left-right --count origin/main...origin/<b>` (main-only /
branch-only), measured today:

| Branch | Tip (measured `git log -1`) | main Δ / branch Δ | What it holds |
|---|---|---|---|
| `orchestrator` | `aa03aa8` 2026-05-08 "Remove unused … vector_db function" | 39 / **0** | the **pre-revert orchestrator tree**, kept alive by `44ee11d`'s README link; fully contained in main's history but its content was reverted |
| `OGhidraEX` | `483664f` 2025-12-24 "Add project description for OGhidraEX" | 118 / 1 | a single project-description commit on base `41a424c`; an abandoned fork-of-the-brand |
| `21-precommit-autofixes` | `a361d3c` 2026-05-22 "Run pre-commit on all files…" | 37 / 4 | became #21 (merged); four orphaned pre-squash commits |
| `19-gui-crashes-on-linux` | `7d2ca25` 2026-06-19 "Fix the renamed functions panel's async crashing" | 13 / 19 | 19 orphaned commits; the crash fix itself landed squashed as #44 |
| `fix/session-loading-ui-freeze` | `88013c9` 2026-07-29 "Merge … origin/HEAD" | 7 / 10 | `ui_thread` work, skip-analyzed option, ETA display; delivered through #44, branch never deleted |
| `multiple-binaries-pyghidra` | `9327b4f` 2026-07-20 "setting up initial work for getting multiple binaries working" | 21 / 3 | open PR **#46**; `ghidra_client.py` +1,418 lines toward multi-binary sessions |
| `add-ghcr-docker-release-job` | `0529847` 2026-08-24 "Add optional container publishing to release workflow" | 4 / 1 | +44-line GHCR job for release.yml — never merged; explains why nightly images don't exist (inventory §8) |
| `plugin-infrastructure` | `48cdebc` 2026-09-16 "leftover from first commit" | 3 / 3 | customizable workflow host/runtime; `tests/test_workflow_host.py` 794 + `test_workflow_runtime.py` 539 lines; merge-base diff +18,817/−13,282 (measured) |
| `dspy-plugin-vibes` | `9b466f3` 2026-10-08 "small build changes" | 3 / 5 | **a rewrite in flight**: `63674d7` (2026-10-06, jdunns) "Remove old Oghidra and start the barebone DSPy approach" deletes 44,742 lines (150 files, +1,337); open PR **#63** |
| `add-lore` | `794b571` 2026-10-12 "fleshed-out wiki" | 2 / 2 | in-repo loreforge wiki: 24 files +1,587 (measured `git show --shortstat`) |
| `delete-ghidra_mcp_client` | `1a3e060` 2026-10-22 "Delete src/ghidra_mcp_client.py" | 1 / 1 | open PR **#62**; removes the 509-line legacy client (inventory §2) |

Read together with the PR ledger (API, 2026-11-01: 37 PRs total — 22 merged,
7 closed-unmerged, 8 open) the branch map says: **the real feature pipeline
is branches + open PRs, not main.** The 8 open PRs (#46, #62, #63, #64,
#65, #67, #68, #69) include four from first-time contributors (vssinghh,
AlicanAkyol, MilindChatrabhuji) opened 2026-10-22…31 — the community queue
is growing exactly while core maintenance is quiet (§1). Closed-unmerged
PRs show the triage pattern: supersessions (#3→#4, #13→#23, #18→#27,
#11→#44) and one consequential casualty, **#50 "Add GitHub Actions test
workflow and Dependabot config"** — never merged, which is why there is no
test CI and the shipped CI (#33) covers the Docker path only (inventory §8).

## 7. GitHub signals

API battery 2026-11-01: **465 stars, 50 forks, 3 subscribers** — attention
outruns care by two orders of magnitude (three people watch this repo).
`open_issues` 30 = 22 issues + 8 PRs; 10 closed issues. `has_wiki` true,
`has_discussions` **false** — yet `README.md:607` invites readers to
"GitHub Discussions", a link that goes nowhere (inventory §10 keeps the
contradictions list). `license.spdx_id` is `NOASSERTION` for the licensing
reasons in §2 above and inventory §10.

Open-issue themes match the branch map's blind spots: a headless /
programmatic surface (#49, #55–#58, #66 — the tool is GUI-bound),
benchmarks and model comparisons (#14, #15, #16), CI/lint hygiene
(#10, #28, #29, #30, #36), GUI defects (#34, #42, #43), backend questions
(#7, #8, #12), model reliability (#53). The maintainers visible in §1
(Enoch absent since April, Ryan Mast's last touch 2026-08-14) have not
answered most of it.

## 8. Verdict — what this history means for the OGhidra chapters

- **A lab research artifact, mid-handoff.** LLNL-CODE-2013290, the DOE
  NOTICE, the non-commercial + commercial-license split, and a founder who
  moved everything off-GitHub and stopped committing in March: this reads as
  a lab release passing from its creator to lab maintainers, and the
  orchestrator revert (§4) is the visible seam of that handoff.
- **Near-dormant core, live periphery.** Four months of 4/3/1/2 commits
  with bots carrying the traffic, against 465★/50 forks and four new
  contributors queuing PRs in the last ten days. Expect main to be
  different by the time the 3x chapters ship — date every citation.
- **History explains the inventory's mysteries**, one for one: version
  0.0.0 (§5 ← VCS versioning on a single tag), broken Docker build (branch
  `pyghidra` deleted after #23), no test CI (#50 closed unmerged),
  orchestrator missing from main (`c62ec6e`), stale `tool_capabilities.md`
  (`4841c4c`, Feb 2026). Chapters should cite causes, not just symptoms.
- **A rewrite may already be coming.** `dspy-plugin-vibes` deletes 44,742
  lines and PR #63 is open against it; if it lands, most surface maps in
  chapter 20 go stale overnight. Watch it before the deep chapters close.
- Versus the frozen drift of [LLM_Decompiler's history](../LLM_Decompiler/21-history-and-releases.md)
  (26 commits, dead in a drawer): OGhidra is *drifting while alive* — the
  comparison with calxgloss must be made against a moving target, and the
  honest posture is "as of 2026-11-01".

## Sources

- Read-only clone `/tmp/opencode/OGhidra` @ `6224d26` — batteries:
  `rev-list --count` (147), monthly `log --format=%ad | uniq -c` (19/27/16/
  6/9/11/31/18/4/3/1/2), identity-folded shortlog, numstat of `71da7d7`,
  `5fa72ea`, `3c499f0`, `c231fdd`, `30d130d`, `4841c4c`, `262cf2f`,
  `d5dec8a` (incl. per-file orchestrator line counts), `c62ec6e`,
  `cedeb94`, `93a4380`, `1b51e06`, `aea39dd`, `63674d7`, `794b571`,
  `0529847`, `1a3e060`; `ls-tree` of `5fa72ea` (54 files) and `71da7d7`
  (9 files +314); `wc -l` of `5fa72ea:src/bridge.py` (4,761);
  `name-status` of `30d130d` (`.env` D / `.env.example` A);
  `rev-list --left-right --count` table over all 11 branches;
  merge-base + diffstat for `plugin-infrastructure` (+18,817/−13,282);
  `git tag -l` / `rev-parse v0.0.0`; `git ls-remote --heads origin`
  (12 heads, no `pyghidra`).
- GitHub REST API via `gh api` (2026-11-01): metadata (stars/forks/
  subscribers, created/pushed, `NOASSERTION`, `has_discussions false`),
  `/releases` (0), `/tags` (1), PR ledger (22 merged / 7 closed-unmerged /
  8 open), issue themes.
- PyPI JSON API `https://pypi.org/pypi/oghidra/json` (2026-11-01): single
  release `0.0.0`, uploaded 2026-08-14T22:59Z, wheel + sdist.
- Cross-chapter: [20-oghidra-inventory](20-oghidra-inventory.md) (surface
  map the branch/PR state explains), chapter 36 for the orchestrator branch
  content, [00-scope-and-method](00-scope-and-method.md) (its seeds —
  147 commits, 465 stars, 50 forks — all re-verified),
  [10-calxgloss-baseline](10-calxgloss-baseline.md) (comparison anchor),
  and [LLM_Decompiler 21](../LLM_Decompiler/21-history-and-releases.md)
  (the dead-repo contrast).
