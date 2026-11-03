# GameFrame history and releases

> Part of the [game-frame overview](README.md). 383 commits at `f195a074`, 2026-10-21 → 2026-10-30.

Builds on [`20-gameframe-inventory.md`](20-gameframe-inventory.md): its HEAD-state counts
are not re-derived here except where history explains them. History claims cite
`<shortsha> <path-or-subject>`; file-state claims cite `path:line` in the pinned clone at
HEAD `f195a074`; fetched web facts record their URL and fetch date. Checks that came back
empty are recorded as negative findings with the search that produced them.

## 0. Method and dataset

Two clones were used, and they agree, which is what makes the numbers below citable:

- `/tmp/opencode/game-frame` — the pinned clone, `origin` = `git@github.com:tanepiper/game-frame.git`,
  HEAD `f195a074a63cc150673c38becdec696163b0b3d1`, tree `9cec9d7bae89e09007e475f6de7a5adfc7679f17`.
- `/tmp/opencode/gf-verify` — a second clone made on 2026-10-31 with
  `gh repo clone tanepiper/game-frame`, used to re-measure every figure in this chapter after an
  earlier measurement pass at the first path returned values that no longer reproduced. Both
  report the same HEAD, the same tree, the same six tag objects and the same 383 commits, so every
  number below was measured twice.

Companion file: `/tmp/opencode/gf-subjects.txt` (all 383 `hash|date|subject` triples from
`git log --reverse --format='%h|%ad|%s' --date=format:'%Y-%m-%d %H:%M'`). GitHub facts come from
authenticated `gh api` calls on 2026-10-31:
`https://api.github.com/repos/tanepiper/game-frame/releases?per_page=100`,
`…/issues?state=all&per_page=100`, `…/pulls?state=all&per_page=100`, `…/branches?per_page=100`,
`…/pulls/1`, and `https://api.github.com/repos/tanepiper/game-frame`.

## 1. The shape of the ten days

| metric | value |
|---|---|
| commits | 383, authored entirely by Tane Piper `<me@tane.dev>` (`git log --format='%an' \| sort -u` → one name) |
| committers | Tane Piper 345, `GitHub` 38 — and those 38 are exactly the 38 "Merge pull request #" commits |
| window | 2026-10-21 → 2026-10-30; commit dates land on 8 of the 10 days |
| per day (21→30) | 66 / 54 / 40 / 87 / 78 / 36 / 20 / **0** / 1 / 1 |
| merges | 71 multi-parent commits: 38 `Merge pull request #`, 21 `Merge remote-tracking branch`, 5 `Merge branch …`, 7 other Merge-subject merges |
| first-parent spine | 241 commits (`git rev-list --count --first-parent HEAD`) |
| PRs | 39 on GitHub (`#1`–`#41`, with `#4`/`#5` created as issues), all opened **and** merged by `tanepiper` |
| issues | 2, both open, both by `tanepiper`: `#4` UI-position mapper, `#5` universal harness, created 2026-10-24 13:56–13:57Z |
| tags | 6, all annotated: `v1.0.0` … `v1.4.0`; remote holds those six and no others (`git ls-remote --tags origin`) |
| releases | 6 GitHub Releases, one per tag, published 9–86 s after each tag |
| agents | 251 of 383 messages carry `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>` |
| clocks | author offset `+0200` through 2026-10-24 and the early hours of 10-25, `+0100` from 2026-10-25 onward (the autumn clock change) |

One person, ten days, 383 commits, 39 pull requests, six releases, 38 remote branches. The
density is agent work: a quarter of the messages carry no co-author trailer, the rest name the
model that pair-wrote them.

**The dates are internally consistent, and no history was rewritten to make them so.** 20 of the
383 commits have an author date that differs from the committer date, all by seconds to minutes —
`4743a0c` 21:00:37 → 21:00:42, `e279c19` 23:13:44 → 23:14:51, `0bf89e5` 21:04:33 → 21:13:03. Those
are the signature of a commit prepared by an agent and landed a moment later by a hook or a person,
not of a replay: a rebased tree would move committer dates by days, and none here do.

## 2. The release ladder

All six tags are annotated tag objects; the table reads from
`git for-each-ref refs/tags --format='%(refname:short) %(objecttype) %(taggerdate:iso) %(*objectname:short) %(contents:subject)'`.

| tag | tagger date | tagged commit | subject | window | version commit |
|---|---|---|---|---:|---|
| `v1.0.0` | 2026-10-23 15:32:34 +0200 | `c705e8e` | Give the plugin its release version, 1.0.0 | 138 | `c705e8e` |
| `v1.0.1` | 2026-10-23 16:43:12 +0200 | `014b912` | Release GameFrame 1.0.1 | 3 | `014b912` |
| `v1.1.0` | 2026-10-24 11:28:25 +0200 | `794b2a9` | Merge tools/llm into 1.1.0 | 55 | `794b2a9` |
| `v1.2.0` | 2026-10-25 02:29:33 +0200 | `5e122a3` | Release GameFrame 1.2.0 | 67 | `5e122a3` |
| `v1.3.0` | 2026-10-25 22:10:13 +0100 | `b463b9b` | release: prepare GameFrame 1.3.0 | 60 | `b463b9b` |
| `v1.4.0` | 2026-10-26 18:19:26 +0100 | `1d9d9b8` | Release 1.4.0 | 11 | `1d9d9b8` |
| *(unreleased)* | — | HEAD `f195a07` | `git describe` → `v1.4.0-49-gf195a07` | 49 | — |

Windows are `git rev-list --count <tag> ^<previous tag>`; the 138 of `v1.0.0` is every commit
before it, since it is the first tag (`git rev-list --count v1.0.0` = 138, and 383 − 138 = 245 for
the rest of history).

The ladder is one four-day sprint: first commit 2026-10-21 09:53 to last tag 2026-10-26 18:19, then
49 commits over four days with no tag. `0d2221a Open 1.5.0-dev` (2026-10-26 18:22) opened the next
line three minutes after the v1.4.0 tag, and `.claude-plugin/plugin.json:3` still reads
`"version": "1.5.0-dev"` at HEAD.

**GitHub mirrors every tag, immediately.** The fetched release JSON gives, for each of the six, a
`created_at` equal to the tagger date and a `published_at` 9–86 seconds later (v1.4.0 17:19:26Z →
17:19:35Z; v1.2.0 00:29:33Z → 00:30:59Z, the slowest). Titles are exactly "GameFrame X.Y.Z". Bodies
grow with the release: 1,751 bytes for v1.0.0, 2,262 for v1.0.1, 20,396 for v1.1.0, 10,641 for
v1.2.0, 7,383 for v1.3.0, 4,317 for v1.4.0.

**The version lives in the plugin manifest, not in the crates.** `.claude-plugin/plugin.json` is
born at `d1f5f4d` (2026-10-21 22:15) and every release commit edits it; the Cargo workspaces
(`crates/Cargo.toml`, `wrappers/Cargo.toml`) carry no release version of their own, and `tests/run.sh`
at v1.0.0 asserts only that `plugin.json` holds `MAJOR.MINOR.PATCH` (v1.0.0 tree,
`tests/run.sh:733`). So "release" in this repository means: the plugin's version.

### 2.1 The CHANGELOG ladder

`CHANGELOG.md` is born at `67d92b4` (2026-10-23 15:50) — nineteen minutes **after** the v1.0.0 tag,
inside the three-commit v1.0.1 window — and its first version already dates 1.0.0 retroactively
(`git show 67d92b4:CHANGELOG.md`: `## [Unreleased]` at line 8, `## [1.0.0] - 2026-10-23` at line 26).
The same commit adds 36 lines to `tests/run.sh`, and the new file's header says why:
"The newest version here is the one in `.claude-plugin/plugin.json`, and `tests/run.sh` checks that
the two match" (`CHANGELOG.md:6` at HEAD). The pairing of tag, version file and changelog was a
checked rule before it was a command.

At HEAD the file is 867 lines, newest release first
(`git show HEAD:CHANGELOG.md | grep -nE '^## '`):

| section | heading line | span | lines |
|---|---:|---|---:|
| `[1.5.0-dev] - Unreleased` | 8 | 8–207 | 200 |
| `[1.4.0] - 2026-10-26` | 208 | 208–264 | 57 |
| `[1.3.0] - 2026-10-25` | 265 | 265–367 | 103 |
| `[1.2.0] - 2026-10-25` | 368 | 368–515 | 148 |
| `[1.1.0] - 2026-10-24` | 516 | 516–781 | 266 |
| `[1.0.1] - 2026-10-23` | 782 | 782–818 | 37 |
| `[1.0.0] - 2026-10-23` | 819 | 819–867 | 49 |

The shape is the release history read backwards: a thin first release, the biggest notes at 1.1.0
(the wrappers sprint), then shrinking sections as releases get cut in smaller slices — down to 57
lines for the eleven-commit 1.4.0 — and a 200-line Unreleased section for the four days after the
last tag.

### 2.2 The crate ladder

Counting `Cargo.toml` files under each tag (`git ls-tree -r --name-only <tag> -- crates wrappers |
grep -c 'Cargo.toml$'`), excluding each workspace root:

| at | crates | wrappers | crates added in the window |
|---|---:|---:|---|
| `v1.0.0` | 4 | 0 | `bcf6343` four clean crates from the case studies (2026-10-21 22:44) |
| `v1.0.1` | 4 | 0 | — |
| `v1.1.0` | 7 | 0 | `e015303` MMX and 1997 3D-card guides, crates, specialists (2026-10-23 18:15) |
| `v1.2.0` | 8 | 11 | `8dbb2f8` Add wrappers/: POD's replacement libraries for 1997 3D cards (2026-10-24 16:04) |
| `v1.3.0` | 15 | 11 | audio crates: `sound-blaster`, `opl3`, `ymz263`, … (the PR #30 sprint) |
| `v1.4.0` | 20 | 11 | `d2e8811` Add the frame, the player's library and ready-made themes (2026-10-26 18:14) |
| HEAD | 28 | 10 | `7e495d8` One crate per 3D chip; gpu-1997 removed (2026-10-26 21:35), then `voodoo`, `powervr`, `d3d`, `rage`, `virge` |

Twenty-eight commits in `v1.4.0..HEAD` touch `crates/` or `wrappers/`: the 3D-card split continues
after the last tag, which is why the inventory's crate counts read as stale.

## 3. How a release is cut

Until v1.4.0 the cut is manual, and the release commit is the tag target: `c705e8e` "Give the plugin
its release version, 1.0.0", `014b912` "Release GameFrame 1.0.1", `5e122a3` "Release GameFrame 1.2.0",
`b463b9b` "release: prepare GameFrame 1.3.0", `1d9d9b8` "Release 1.4.0". `794b2a9` "Merge tools/llm
into 1.1.0" breaks the pattern: it carries a Merge subject but has one parent (verified with
`git rev-list --parents -n1 794b2a9`), so the v1.1.0 tag sits on a flattened merge-shaped commit.
The same shape appears twice more, at `07df070` and at HEAD `f195a07`.

The automation arrives after the last tag, ninety seconds of history later:

- `1d9d9b8` Release 1.4.0 — 2026-10-26 18:19;
- `0d2221a` Open 1.5.0-dev — 18:22;
- `e347a08` Add the release script and version gate; keep live diary entries — 18:36, adding
  `scripts/release.py` and `scripts/hooks/gates/version.py`.

`scripts/release.py:1-27` states the contract in full: `python3 scripts/release.py X.Y.Z
[--push] [--publish] [--no-next]` renames the `## [...-dev] - Unreleased` heading to
`## [X.Y.Z] - TODAY`, sets `plugin.json`, commits both as "Release X.Y.Z", tags `vX.Y.Z`, then runs
`next` to open `X.(Y+1).0-dev` unless `--no-next`; `--publish` makes the GitHub release with `gh`,
using the changelog section as the notes. It "does not run the tests: run `tests/run.sh --ghidra`
before a release", and "does not write the changelog's entries" — the entries are written by the
work, not by the release.

The gate is the enforcement half. `scripts/hooks/gates/version.py:1-13`: when `plugin.json` names a
version with no `-dev` suffix **and** the matching tag already exists, the commit is refused until
`scripts/release.py next` opens the next development version. So the 49 commits after v1.4.0 could
not have been made against a released version; the 1.5.0-dev line is mandatory, not cosmetic.

Both halves are tested. `tests/run.sh:1379-1411` drives `release.py` against a fixture repository
and asserts the heading rename and compare link, that the gate exits 2 ("a commit on top of a tagged
release is blocked"), that a `-dev` version passes, and that running `next` twice is refused.
`tests/run.sh:1531-1533` asserts the newest `## [X]` section of `CHANGELOG.md` **is** `plugin.json`'s
version (`tests/run.sh:1533`), and `tests/run.sh:1399` is the gate assertion
("a commit on top of a tagged release is blocked"). At v1.0.0 the equivalent block asserted only the
version shape (`tests/run.sh:733` at that tag); the changelog half arrives with the changelog itself
at `67d92b4`. The gate package grew
the same way: `scripts/hooks/gates/` has 4 modules at `v1.0.0` (`__init__`, `adapters`, `checks`,
`session`) and 8 at HEAD, adding `deletes`, `game_folder`, `post_events` and `version`. `tests/run.sh`
itself grew from 928 lines at `v1.0.0` to 1,947 at `v1.4.0` and 2,128 at HEAD.

## 4. What the phases built

Day by day, with the commits that set the character:

| day (2026) | commits | what lands |
|---|---:|---|
| Wed 21 | 66 | the harness before anything else: `fad70ad` Set up the reverse-engineering harness for games (60 files, +3,392); `53e8613` the one CI workflow (`.github/workflows/site.yml`); `d1f5f4d` `.claude-plugin/plugin.json`; `bcf6343` the first four crates (13,661 lines changed, the largest commit in the history); licences settled three times in one day — `39540a6` MIT/Apache at 12:49, `d152389` Apache-2.0 code plus CC BY 4.0 content at 19:26, `64cbf12` CC0 for the content at 22:49, and HEAD keeps `LICENSE-APACHE` and `LICENSE-CC0-1.0` |
| Thu 22 | 54 | the guardrails: `d749a7d` Add light permissions and gates for Claude Code; the diagram floods — `f889511` 7,917, `8157bfd` 7,748, `531ff76` 4,786 lines changed; `3a0967a` GAPS.md |
| Fri 23 | 40 | the agent surface: `4033bb2` the agents for Codex, Gemini CLI, Copilot and OpenCode (6,340); `bfebf86` Keep the skills in one skills/ folder — the commit that adds `skills/re-land/`; then v1.0.0 (15:31), the CHANGELOG (15:50), v1.0.1 (16:43), and `e015303` (18:15) adding the MMX and 3D-card crates |
| Sat 24 | 87 | the biggest day: `5091dc0` POD's know-how promoted (08:02), `bdde29a` Hardwar findings plus five tools, including `new-site.sh --manual` (08:49), `aff124e` tools/llm (10:51), v1.1.0 (11:28), then the wrappers PR storm — PRs `#6`–`#26` land through the day, `8dbb2f8` creates `wrappers/` at 16:04 (8,887 lines) |
| Sun 25 | 78 | the audio marathon and v1.2.0 (02:29), then `0283082` Merge pull request #30 from tanepiper/codex/audio-coverage at 15:37 — 47 commits on that branch's second parent, running 01:47→15:19; `188657b` feat: make external MCP providers opt in (22:07, and the first commit to name REA 6.7.0) two minutes before `b463b9b` prepare GameFrame 1.3.0 |
| Mon 26 | 36 | v1.4.0 (11 commits) with `d2e8811` the frame, the player's library and ready-made themes at its front (106 files, +11,812); then the open line: `0d2221a`, `e347a08`, `7e495d8` One crate per 3D chip (21:35), `0bf89e5` the GameFrame home (21:04), `e279c19` gameframe-report (23:13) |
| Tue 27 | 20 | the tail: `7243879` rea_session (11:37), `07df070` Merge Un-Banished's cite_labels changes (14:45), `4743a0c` Add gameframe install (21:00, adds `install.json` and `tools/install`), `f53528a` winegdb (19:21), `7f2f82e` the call log of every call a game makes (23:19) |
| Wed 28 | 0 | nothing. Negative finding: no commit carries an author date of 2026-10-28 in the whole history (`git log --date=format:%Y-%m-%d --format='%ad' \| sort \| uniq -c`) |
| Thu 29 | 1 | `597ceee` Lessons from TabStationToo: lockstep, browser pitfalls, measuring speed |
| Fri 30 | 1 | `f195a07` Merge completed slices into local main, HEAD, 21:56 +0100 (pushed 20:58Z) |

**The method is stated by the last commit.** `f195a07` is a single-parent re-land of `597ceee`, and
its body gives the rule that produced this shape: completed work must be committed and integrated
into local main before hand-off, and completed slices are merged rather than left on branches. That
is the same rule `skills/re-land/` encodes, which is born three days earlier at `bfebf86`. Across
383 commit messages the stem `re-land`/`re-lander` appears 11 times — a working term, not a slogan.

## 5. How the work is organised

- **Pull requests are the land vehicle, and every one is self-issued.** All 39 PRs on GitHub were
  opened by `tanepiper` and all 39 were merged (`…/pulls?state=all`, fetched 2026-10-31). 38 of them
  appear in history as merge commits with the subject `Merge pull request #N from tanepiper/<branch>`;
  the PR numbers present are `#2`, `#3`, and `#6`–`#41` (`git log --merges --format='%s' | grep -oE
  'Merge pull request #[0-9]+'`).
- **PR #1 landed without a merge commit.** `…/pulls/1` reports `merged_at` 2026-10-24T08:21:13Z,
  `merge_commit_sha` `3cb0183`, and `merged_by` null — GitHub closed it from a merge that was made
  locally and pushed (`3cb0183 Merge remote-tracking branch
  'origin/claude/hardwar-findings-843b4f'`, 2026-10-24 10:21 +0200, an ancestor of HEAD). Negative
  finding: `git log --grep='Merge pull request #1 '` returns 0 commits.
- **`#4` and `#5` are the two open issues**, not pull requests: "A tool that maps UI positions
  between screenshots of one screen" and "A universal harness: analyse a program, then run it with
  the modules it needs". Both were opened on 2026-10-24, both are still open, and GitHub's
  `open_issues_count: 2` for the repository is exactly these two. They read as an idea ledger: the
  ladder stopped, the ideas did not.
- **Branch names are agent work-queue bookkeeping.** The remote holds 38 heads: 14 under `claude/`,
  12 under `codex/`, and 12 plain names (`d3d`, `ir41`, `llm-fetch-one-client`, `llm-small-batches`,
  `main`, `maxi64`, `powervr`, `sgl`, `sound-cards`, `sound-cards-race`, `wrappers-coverage`,
  `wrappers-site`).
- **Conventional-commit subjects are a tool's handwriting, not the project's.** 10 of 383 subjects
  start `feat:`/`fix:`/`docs:`/`chore:`/`test:`, and all 10 fall between 2026-10-25 01:47 (`b9e78f4`
  docs(audio): map era coverage) and 2026-10-26 13:13 (`94406d3` fix: make 86Box provider
  transport container-safe) — the `codex/` era. Everything else is prose: "One crate per 3D chip;
  gpu-1997 removed", "Is this the latest version? buildid, and a day-one check for later official
  releases".
- **Co-authorship is disclosed in the trailer.** 251 of 383 messages end
  `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`; the other 132 carry none.

## 6. Velocity, and what grew

| at tag | files | crates | wrappers | docs | site | examples | tests | tools | skills | agents |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `v1.0.0` | 904 | 4 | 0 | 536 | 55 | 11 | 17 | 95 | 13 | 18 |
| `v1.4.0` | 1,542 | 20 | 11 | 722 | 57 | 17 | 29 | 146 | 20 | 23 |
| HEAD | 1,645 | 28 | 10 | 734 | 62 | 17 | 36 | 158 | 20 | 23 |

(`git ls-tree -r --name-only <tag> -- <dir> | wc -l`; crates/wrappers are crate directories, see §2.2.)

The growth is not uniform. Between v1.0.0 and HEAD the repository gains 741 files, and the file
types move: at `v1.0.0` the tree is 366 `.svg`, 274 `.md`, 119 `.py`, 20 `.rs`; at HEAD it is 540
`.md`, 371 `.svg`, 292 `.rs`, 197 `.py`. Rust more than fourteen-folds, from 20 files to 292, which
is the port becoming real, while the docs stop growing after v1.4.0 (536 → 722 → 734 files) — the
documentation phase ends roughly where the release ladder ends.

Whole-history churn: `git log --numstat` sums to **+201,605 / −18,564** lines. The largest single
commits are content drops, not refactors:

| lines changed | commit | subject |
|---:|---|---|
| 13,661 | `bcf6343` | Add four clean crates from the case studies: OPL2, WMA, MSVC CRT, Turbo Pascal |
| 11,899 | `d2e8811` | Add the frame, the player's library and ready-made themes |
| 8,887 | `8dbb2f8` | Add wrappers/: POD's replacement libraries for 1997 3D cards, made shared |
| 7,917 | `f889511` | a diagram for each topic in the engine, game, media and preservation guides |
| 7,748 | `8157bfd` | a diagram for each topic in the computer and arcade guides |
| 7,428 | `0ba4ce1` | Arcade and Handhelds sections, keep Consoles for home consoles, drop the raw notes |
| 6,340 | `4033bb2` | the agents for Codex, Gemini CLI, Copilot and OpenCode |

The paths that absorbed the most added lines overall: `docs/assets` 20,919, `site/diagrams` 12,801,
`crates/wma` 10,859, `docs/knowhow` 6,991, `wrappers/glide` 6,931, `wrappers/sgl` 6,907,
`crates/sound-blaster` 5,494, `tools/triage` 5,298. Diagrams and generated art sit at the top of
that list, which is worth remembering when a line count is quoted as a measure of effort.

Per-window file touches (`git log --name-only` over the window, first path segment): v1.0.0 window
`docs` 1,464 / `tools` 163 / `site` 155; v1.0.1..v1.1.0 `docs` 291 / `tools` 75 / `.github` 68;
v1.2.0..v1.3.0 `crates` 115 / `docs` 108; v1.3.0..v1.4.0 `crates` 59 / `templates` 24;
v1.4.0..HEAD `crates` 212 / `docs` 78 / `wrappers` 67. The centre of work moves from docs to crates
exactly once, at the v1.2.0/v1.3.0 boundary, and never moves back.

## 7. Dating §20's staleness ledger

§20 lists claims that were true when written and are not true at HEAD. History can say when each
was last touched (`git blame -L n,n --porcelain HEAD -- <path>`) and when the thing it describes
changed:

| claim at HEAD | entered by | last touched by | the fact that made it stale |
|---|---|---|---|
| `README.md:202` "Fourteen task agents" | `c4c160b` 2026-10-25 15:19 | same | none — it is right: `agents/re-*.md` holds 23 files at HEAD, and `docs/teams/README.md:3` says nine stage + fourteen task |
| `AGENTS.md:68` "twelve task agents" | `e015303` 2026-10-23 18:15 | same | `c4c160b` added two more task agents on 10-25 and did not revisit AGENTS.md |
| `.claude/settings.json:25` `rea-agents@6.4.0` | `d749a7d` 2026-10-22 08:51 | same | `188657b` (2026-10-25 22:07) is the first commit to name REA 6.7.0; the settings file was edited three times in total and never again |
| REA pinned to 6.7.0 — `scripts/setup.sh:126`, `docs/working/mcp-toolchain.md:87`, `skills/re-rea/SKILL.md:13` | `188657b` 2026-10-25 22:07 | `7243879` 2026-10-27 11:37 | none: 6.7.0 is current at HEAD; the stale half is the 6.4.0 permission row above |
| `AGENTS.md:87` `.mcp.json` = "The MCP servers (REA, DOSBox-X)" | `1eaae1f` 2026-10-23 | same | `188657b` made external providers opt-in; `.mcp.json` at HEAD registers one server, `gameframe serve` (`.mcp.json:1-10`), while `v1.0.0:.mcp.json` really did register `rea-agents@6.4.0` and a DOSBox entry |
| `README.md:238` "checks against the two sample games" | `ee49ccf` 2026-10-21 10:51 | `e347a08` 2026-10-26 18:36 | `d2e8811` (2026-10-26 18:14) adds `examples/frame-demo`; `examples/` is 17 files at HEAD |
| `AGENTS.md:77` frame-demo row | `d2e8811` 2026-10-26 18:14 | same | none — it is current, and it is inside the v1.4.0 window (tagged five minutes later) |
| `AGENTS.md:73` `tools/install` / `install.json` row | `4743a0c` 2026-10-27 21:00 | same | it post-dates the last tag, so it belongs to no release; `install.json` is 2026-10-27 work |
| `scripts/new-site.sh:4,28` `--manual` | `bdde29a` 2026-10-24 08:49 | same | none — the flag is current; `scripts/new-site.sh` itself is born at `a9c4822` (2026-10-23 16:27) |
| version drift: inventory says one version, HEAD says another | `0d2221a` 2026-10-26 18:22 | — | `1.5.0-dev` has been the working version for four days and 49 commits, and no tag names it |

**A ledger mismatch worth recording rather than smoothing over.** §20's inventory counts 28
crate manifests and 14 wrapper crates at HEAD. The pinned clone at `f195a074` has 42 `Cargo.toml`
files: 29 under `crates/` (workspace root + 28 crates), 11 under `wrappers/` (root + 10 crates),
plus `examples/frame-demo/Cargo.toml` and `launcher/Cargo.toml` (`cde5790` Add the launcher,
disc-filled choices, the way back and game exit, 2026-10-26 19:10). The wrapper crates at HEAD are
`ati3dcif`, `ddraw`, `glide`, `ir41`, `maxi94`, `pixels`, `s3dtkw`, `scalers`, `sgl`, `shim` — ten,
not fourteen, because `wrappers/raster` is deleted in the 3D-card split
(`322cba6` The Rage and ViRGE draw in their own crates, on gameframe-raster and `77c7611`
gameframe-powervr, both 2026-10-27). §20 already warns (its §22) that GameFrame figures from before
this snapshot are suspect; this is that warning materialising, and both clones give the counts above.

## 8. Negative and bounded findings

- **No reverts, and nothing that looks like a correction of history.** `git log -i --grep=revert`
  returns 0 commits; `git log --grep='Merge pull request #1 '` returns 0; the 20 author/committer
  date mismatches are all sub-minute to minute gaps (§1). This clone's reflog holds 1 entry (a fresh
  clone), so local rewriting is unobservable here — the claim made in §1 is about the shape of the
  committed dates, not about remote reflogs, which the API does not expose.
- **There is no v1.5.0 anywhere**: not in `git ls-remote --tags origin` (six tags, each with its
  peeled entry), not in the release JSON (six releases), not in `git describe` (`v1.4.0-49-gf195a07`).
- **No commit is dated 2026-10-28**, and 2026-10-29 has exactly one (`597ceee`).
- **GitHub Releases do exist for this repository** — six, one per tag, published seconds after the
  tag. The expectation carried into this research file from other repos in this family (no releases,
  tags only) does not hold here.
- **The repository is a template and is fully self-governed**: `is_template: true`, default branch
  `main`, `created_at` 2026-10-21T07:31:42Z — twenty-one minutes before the first commit
  (`fad70ad`, 09:53 +0200) — `pushed_at` 2026-10-30T20:58:00Z, 38 branches, no contributor other than
  `tanepiper` in any of the 39 PRs or 2 issues.
- **Counts that depend on what you count are not comparable across the two snapshots.** §20's crate
  counts and the counts in §2.2 above are the same command run against different states of the
  remote; the difference is reported in §7 rather than reconciled.

## 9. Sources

- `git` in `/tmp/opencode/game-frame` (pinned, `f195a074`) and in `/tmp/opencode/gf-verify` (cloned
  2026-10-31 with `gh repo clone tanepiper/game-frame`), both at tree `9cec9d7`:
  `git log`, `git log --merges`, `git log --numstat`, `git log -S`, `git log --grep`,
  `git log --diff-filter=A/D -- <path>`, `git blame -L`, `git ls-tree -r`, `git rev-list --count`
  (incl. `--first-parent` and tag windows), `git for-each-ref refs/tags`, `git cat-file`,
  `git describe`, `git ls-remote --tags`, `git reflog`, `git merge-base --is-ancestor`,
  `git show <tag>:<path>`.
- `/tmp/opencode/gf-subjects.txt` — 383 `hash|date|subject` triples, the basis for the subject-style
  and vocabulary counts.
- GitHub REST API via `gh api` on 2026-10-31:
  `https://api.github.com/repos/tanepiper/game-frame/releases?per_page=100` (6 releases: titles,
  `created_at`/`published_at`, body lengths), `…/issues?state=all&per_page=100` (41 items, 2 of them
  issues), `…/pulls?state=all&per_page=100` (39 PRs, all merged, all `tanepiper`),
  `…/pulls/1` (merge metadata), `…/branches?per_page=100` (38 heads, prefix counts),
  `https://api.github.com/repos/tanepiper/game-frame` (creation, push, default branch, template flag).
- Companion research: [`20-gameframe-inventory.md`](20-gameframe-inventory.md) — its §21 staleness
  ledger is the input to §7 here, and its §22 caution about older GameFrame figures is the reason
  §0 records two clones and a re-measurement.
