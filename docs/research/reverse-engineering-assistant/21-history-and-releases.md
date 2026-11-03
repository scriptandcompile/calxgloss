# ReVa history & release archaeology (628 commits, v0.8 → v7.3.1)

> Part of the ReVa research set ([inventory](20-reva-inventory.md)). Commit and
> release archaeology of `cyberkaida/reverse-engineering-assistant` ("ReVa",
> Ghidra MCP server), including a **failed verification of the claimed
> BoSSViePl3x/ReVa lineage** (§2). Git claims verified in the full clone at
> `/tmp/opencode/cyberkaida-rea`; GitHub/PyPI metadata via `gh api` / PyPI JSON,
> fetched 2026-10-31.

## 1. Origin: single-author start, August 2023

628 commits on `main` (`git rev-list --count HEAD`; 51 merges, 577 non-merge).
Earliest (`git log --reverse`): `983b467` "Initial script" (**2023-08-03**),
`307a94c` "Working assistant! ✨" (2023-08-04) — both by **カイダ
<kaida@cyberkaida.gg>**, i.e. cyberkaida. GitHub `created_at` is
**2023-08-18T07:03:15Z** (`gh api repos/cyberkaida/…`) — local history predates
publication by ~2 weeks ("Add Apache license file" `fc1141e` lands on the
publication day). Account `cyberkaida` ("サイバーかいだ", bio: *"a reverse
engineering vtuber 💫✨"*) was created 2022-11-21 (`gh api users/cyberkaida`).

Original name and toolset: `git show c30abc8:README.md` (2023-08-18) titles it
**"Reverse Engineering Assistant (RevA)"** — a disassembler-agnostic assistant
using **OpenAI embeddings as "long-term memory"** (RAG over the binary). By the
first tag README (`v2024-02-05`) it had pivoted to a **"tool driven approach"**
(`c278551` 2024-01-29 "Allow LLM to rename variables! 🎉"); early backends were
OpenAI, Text Generation WebUI, Ollama (`c8e2cea`) and Ghidra 10.4 (`719f763`
2023-10-31), with an abandoned Binary Ninja extension (`9301af9`).

## 2. The claimed BoSSViePl3x lineage — NOT verified (contradicted)

`00-scope-and-method.md:28-29` calls this repo "the maintained successor of the
original ReVa by `BoSSViePl3x`". Every check fails — treat the claim as
**fabricated** absent an external source:

- `gh api repos/BoSSViePl3x/ReVa` and `gh api users/BoSSViePl3x` → **404**
  (renamed accounts/repos leave 301 redirects — none exists); GitHub user
  search `q=BoSSViePl3x` → **0 users**; the repo API says `"fork": false`, no
  parent, no transfer.
- Pickaxe across **all refs** (`git log --all -S`) for `"Vector Assistant"` /
  `"vector_assistant"` → **0 commits**; "vector" in any of the 628 commit
  messages → 0; `git grep -il bossviepl3x HEAD` → 0; no author/email contains
  "BoSSV" (all 15 `%ae` addresses are cyberkaida/collaborators/bots).
- History is **continuous and monogenetic**: all 628 commits (2023-08-03 →
  HEAD 2026-10-27) sit on one line of descent and the earliest README
  (`git show c30abc8`) already uses the RevA/ReVA/ReVa name — **ReVa** just
  shortens **Rev**erse **A**ssistant. **No takeover/succession exists in the
  git record**: one author started and maintained it throughout.

## 3. Tag and release ladder (`git tag -l`, `gh release list`)

20 GitHub releases; tag naming goes date/v0 tags → date/alpha tags → semver
from v4.0.0. PyPI package is **`reverse-engineering-assistant`** — *not*
`mcp-reva`, which is only its CLI console script (`pyproject.toml:56`;
`pypi.org/pypi/mcp-reva/json` → "Not Found").

| Tag / commit | Date | Meaning |
|---|---|---|
| `v0.8` = `15e6ec7` | 2024-01-29 | first PyPI drop **1.0.0** (2024-01-29T05:39Z) |
| `v2024-02-05` = `860aa7f`; `2024-03-15` `c14b120`; `2024-03-24` `6ca8221` | 2024-02/03 | README rewrite milestone; "Bump version" tags → PyPI 1.0.1 / 1.0.3 |
| `v2024-05-06` = PR #41 "big-refactor" | 2024-05-06 | GitHub release **v3.0.0-alpha.1** + PyPI **2.9.1**: "Switched from custom RPC to gRPC", `revassistant` split into `reva-server` + `reva-chat`, BN plugin removed |
| `v2024-05-17` `f5f42fa` / `v2024-07-11` `cfda30b` | 2024-05/07 | PyPI 2.9.2 / 2.9.4, release **v3.0.0-alpha2** |
| *(dormancy)* | 2024-08→2025-02 | 24 commits in 7 months; `ca4e527`/`a916e04` (2024-12-08) "Rewrite for Ghidra 11.3", `e51bf0e` (2025-02-02) "Start refactor to MCP and PyGhidra" |
| **v4.0.0** `532d1a4` | 2025-06-02 | "MCP Integration & Enhanced String Analysis" — README: "Rewritten from scratch as a Model Context Protocol server" |
| v4.1.0/v4.1.1 / v4.2.0 / v4.3.0 | 2025-06→08 | `4636a88` "Add Ghidra 11.4 support"; MCP SDK v0.11.1 + transport improvements |
| v4.4.0 "Auto import!" / v4.5.0 | 2025-09 | auto-import; remote MCP (PR #196 `remote-mcp`) |
| v4.6.0 = v5.0.0 = `cd6ef61` | 2025-10-11 | same commit double-tagged; v5 notes: "drops Ghidra 11.3… v4.5.0 was the last version supporting 11.3", MCP SDK 0.14 |
| **v6.0.0** (pre) / **v6.0.1** | 2025-11-09 / 11-16 | **headless mode!** (`375db9e` 2025-11-08 "headless Ghidra and stdio MCP server" — introduces the `mcp-reva` CLI) + Claude Skills + Claude Code plugin (`319e65f`) |
| **v7.0.0** | 2025-12-14 | "requires Ghidra 12 and pyghidra 3" (`0f444de` "breaks compat with 11"); skerit's get-decompilation perf fix PR #228 |
| v7.1.0 / v7.1.1 | 2026-01-05 / 01-07 | import rewrite, debug captures; VSCode-incompat workaround (issues #239/#249) |
| v7.2.0 (`v7.2.0a` pre) | 2026-03-29 | MCP Java SDK session-disconnect workarounds; tool refactor "reduce context usage"; PyPI publish fix `f202bd7` (2026-03-15) → PyPI 7.2.1 (2026-04-07) ends a 20-month PyPI gap |
| **v7.3.0** | 2026-06-13 | "Diffing, performance and long tasks!": persistent staged **diff sessions** (`b4581a6` 2026-06-09), background **analysis jobs** + MCP notifications (`79b5da4` 2026-06-09), **API-key auth** (`51966f1`/`fa19192`/`5d6ebde`), **Tool Groups** options page (`430e22f`), Version Tracker import; PyPI 7.3.0 |
| v7.3.1 (Latest) | 2026-09-03 | "Ghidra 12.1.3 and MCP 2.0 support" (`3cb3e65`, `58912a1` CI); PyPI 7.3.1 |
| *unreleased main* | 2026-10 | `a0d66e8` (2026-10-26) "Update ReVa for Ghidra 12.2… Build on JDK 25, Gradle 9.8.1" (CI diff: Java 21→25); `1f13d96` `feat(cli)!:` "migrate to MCP Python SDK v2" (breaking); HEAD `a2fcd94` 2026-10-27 = `pushed_at` |

Ghidra support timeline: 10.4 (2023-10) → 11.3 rewrite (`ca4e527` 2024-12) →
11.4 (`4636a88` 2025-06-28) → 11.4-only (v5.0.0) → **12.x-only + Java 21**
(v7.0.0) → 12.1 (`3d6eec2` 2026-06-01) → 12.1.3 (v7.3.1) → 12.2 + **JDK 25,
Gradle 9.8.1** (`a0d66e8`, unreleased). HEAD CI matrix: `12.0, 12.1, 12.1.4,
12.2, latest` with `java-version: "25"` in every workflow.

## 4. Contributors (`git shortlog -sn --no-merges`)

Bus factor ≈1: **cyberkaida** = 599/577 non-merge commits under three
identities (カイダ\|kaida@cyberkaida.gg 516, サイバーかいだ\|GitHub noreply 76,
cyberkaida\|Apple privaterelay 7). Then dependabot[bot] 56; **Jelle De Loecker
(@skerit)** 16 (v7.0.0 decompilation perf fix, `skerit-changes` branch); Claude
(`noreply@anthropic.com`) 6 + copilot-swe-agent[bot] 3 — **AI agents commit
directly** (many `origin/claude/*`, `origin/copilot/*` branches); ILOVEPIE 4,
Fathi 3, three 2-commit contributors, and 4 one-offs incl. **Antonio Vázquez
Blanco**, author of the `setup-ghidra` CI action ReVa uses.

## 5. Community signals (fetched 2026-10-31)

**887 stars, 82 forks, 11 watchers**, 15 open + 98 closed issues, 260 PRs,
Discussions enabled (5 threads), not archived, Apache-2.0. PyPI
`reverse-engineering-assistant` (9 releases): **384 downloads/last month**
(pypistats) — modest; distribution runs via the Ghidra extension page + Claude
Code plugin marketplace.

## 6. Velocity: two long burns, one long lull

Monthly commits (`git log --format='%ad' --date=format:'%Y-%m' | sort | uniq -c`):
**2023-08→2024-07 build-out** — 17 (2023-08), 18 (2023-11), 21 (2024-01), 36
(2024-05, gRPC v3-alpha refactor), then 5–7/month and 2024-10→2025-04 only
2–5/month. **2025-05→2026-06 MCP renaissance** — 36, **81 (2025-06, v4
rewrite)**, 35, steady 19–32 through 2025-12, then **45+79 (2026-05/06, the
diff/jobs/auth sprint landing v7.3.0)**; 1,1,6,12 (2026-07→10). Bursts around
majors, near-dormancy between eras.

## 7. Direction of travel (release notes)

One arc: "LLM with RAG memory" (2023) → **tool-driven Ghidra MCP server**
(v4.0.0) → operational maturity (v6 headless pipelines + Claude Skills, incl.
shipped `ReVa/skills/ctf-{rev,pwn,crypto}`, `binary-triage`, `deep-analysis`,
`pyghidra-scripting` `16b0637`) → **long-running autonomous work** (v7.2
"reduce context usage… reduce steps taken by models"; v7.3.0 diff sessions +
async analysis jobs + MCP notifications; v7.3.1 MCP 2.0). Unreleased main
chases Ghidra 12.2/JDK 25 + MCP Python SDK v2.

## Takeaway for calxgloss

The best-evidenced *maintained* RE-agent toolchain: one author + AI-agent
commits, monthly-to-quarterly cadence, fast drop-old/support-new coupling to
Ghidra majors, and "small tools, schema-tolerant inputs" tool design worth
borrowing. The v7.3.0 stack (analysis jobs + diff sessions + tool groups +
API-key auth) is a ready model for long-running glossary/analysis jobs. And
**correct the record**: §2 shows the BoSSViePl3x lineage claimed in
`00-scope-and-method.md` does not exist.

## Sources

- Clone `/tmp/opencode/cyberkaida-rea` @ `a2fcd94`: `git log --reverse`,
  `git rev-list --count {HEAD,--merges HEAD}`, `git shortlog -sn --no-merges`,
  `git tag -l` + per-tag `git log -1`, all-refs pickaxe/`--grep` sweeps,
  `git show {c30abc8,v2024-02-05,v4.0.0,v0.8,a0d66e8}`, `git log v7.3.1..HEAD`,
  skill-file listing, workflow `java-version` grep, `git grep -il bossviepl3x
  HEAD`, author-email census.
- `gh api repos/cyberkaida/reverse-engineering-assistant` (created_at, fork,
  pushed_at); `gh api repos/BoSSViePl3x/ReVa` / `users/BoSSViePl3x` /
  `search/users?q=BoSSViePl3x`; `gh api users/cyberkaida`; `gh api
  search/issues` (15/98 issues, 260 PRs); GraphQL discussions = 5;
  `gh release list` (20) + `gh release view --json body` for v2024-05-06 and
  v4.0.0…v7.3.1.
- PyPI JSON `reverse-engineering-assistant` (9 versions, upload times) +
  `mcp-reva` (Not Found); pypistats recent = 384/last month.
- Contradicted: `00-scope-and-method.md:28-29,54,93` — superseded by §2.
