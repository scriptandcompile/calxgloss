# 21 — llm-reverse-engineering: history, provenance, releases

> Part of the [overview](README.md). Commit facts from the clone at `aa74f48`;
> GitHub/Docker Hub API facts recorded 2026-11-01.

## 1. Provenance

One human did everything: **Michał Jurzak** (all 13 commits; GitHub
contributor `mjurzak`), committing under three identities —
`m.jurzak1@gmail.com` (5 commits), `michaljurzak@student.agh.edu.pl` (7),
and the GitHub noreply `65761848+michaljurzak1@users.noreply.github.com`
(1). The noreply suffix shows the account was renamed **`michaljurzak1` →
`mjurzak`**; the README's clone URL still points at the old name (GitHub
redirects it). Docker Hub remains under the *old* namespace
(`michaljurzak/llm-reverse-engineering`) — one identity drift in two
places, a small durability tax the author pays.

Self-description (README.md:7): created as part of the project
**"LLM – code translation and reverse engineering"**. The committed
artifacts corroborate a Polish university course context: the first-commit
log lines run from `/home/mjurzak/studio_projektowe/` and the workspace
state references `/mnt/d/University/Studio Projektowe/…` (WSL + Windows dual
box) — "studio projektowe" is the AGH University phrasing for the semester
design project, matching the student address. The xlsx evaluation is written
in Polish ([34](34-evaluation-corpus-and-effect.md)).

There is no paper, no write-up beyond the README, and no external
contribution. This is a **course/design-project artifact**, not a
maintained tool.

## 2. Commit timeline (13 commits, 2025-04-24 → 2025-06-13)

| date | commit | Δ | meaning |
|---|---|---|---|
| 04-24 | `bff1e18` "First program" | +1,738 / 33 files | the **whole CLI form** in one drop: `main.py` (252 L, final size), `code_generator.py` (272 L, final size: CSmith + Joern CPG + binary metrics), `radare2_tools.py` (128 L — a third of final size), 14-line requirements; **plus** `demo_code/` with 4 C outputs and 5 binaries, a csmith `test.c`, logs, workspace state — the author had already run the loop before first commit |
| 05-25 | `5b0e41a` "Update to the program" | +449 / 8 files | tool-surface growth: r2 tools 128→~270 L region (list_functions filters, read_memory, project support groundwork), agent 116→140 L |
| 06-04 | `6518401` + merge `5fdf7e1` + `f56bb40` | +1,141 / −174 | **Streamlit UI era** (`app.py` born, ~670 L by next day): chat sessions, compile/metrics/AI-fix, XAI, visualizations; merged against the May branch ("resolve merge conflicts") |
| 06-05 | `626a563` → `19ef5d8` → `dc1ee33` (4 commits) | +7,650 / −3,536 | **evaluation sprint in a single day**: 20-example corpus (+3,493), 3 test projects + `project_analysis.xlsx` + project-directory mode in `app.py`/`radare2_tools.py` (+648 — commit message typo "ratader2_tools.py"), "Fixed files for compilation errors" (+3,509/−3,473: corpus churn), the 21 compiled binaries, "Final adjustments" |
| 06-13 | `69c4319`, `482f83f`, `aa74f48` | +287 / −162 | **wrap-up week**: Docker two-stage build, full README rewrite (removes CLI-era docs, adds the evaluation/Strengths-Weaknesses section), MIT LICENSE — 7 weeks after first commit, the repo was briefly *unlicensed*, so until `aa74f48` reuse was technically not granted |

Everything in the tool as reviewed was **written inside ten working days**
(Apr 24 – May 25, then Jun 4–5, then Jun 13 packaging). The xlsx evidence
base and the product UI are four days apart; the corpus's "fix compilation
errors" churn (3.5k lines rewritten one day after being added) shows the
corpus was *created for the runs*, not accumulated organically.

## 3. Two-phase design drift

History shows a clean pivot that explains the repo's odd dual nature:

1. **Phase 1 (April–May): research tool.** CSmith-random programs in,
   Joern-CPG similarity out — an experiment for "can an LLM decompile at
   all", with MD5/CPG metrics as crude automated scoring
   ([33](33-cli-csmith-cpg-and-metrics.md)). `demo_code/test.c`
   (csmith 2.3.0, seed `7614197739445800702`) is a relic of this phase
   ([34](34-evaluation-corpus-and-effect.md)).
2. **Phase 2 (June): demoable product.** Streamlit chat, curated toy
   corpus, spreadsheet evaluation, Docker for reproducibility — the CSmith
   pipeline stays in the tree but is orphaned (not in Docker, not used by
   the UI, `code_generator.py` import commented out at `app.py:17`).

The automated-metrics dream died with phase 1: phase 2's answer to "did it
work?" is the human spreadsheet ([34](34-evaluation-corpus-and-effect.md)).

## 4. Releases and community surface

- **Releases:** none. No tags, no version string anywhere (`git tag` empty;
  GitHub releases API empty).
- **Docker Hub image** `michaljurzak/llm-reverse-engineering`: registered
  2025-06-13T08:04:39Z (same morning as the packaging commits — Dockerfile
  pushed 09:15), **233 pulls** recorded 2026-11-01, ~348 MB, `latest` only.
  By far the strongest signal of any use beyond the author.
- **GitHub stats** (2026-11-01): 0 stars, 1 fork, 1 watcher, 0 open/closed
  issues, 0 PRs, single branch `main`. Language stats report "C" — the
  5k+ line test corpus outweighs 1.7k lines of Python, a reminder that the
  *corpus* is nearly half the repo's substance.
- Dormancy: last push 2025-06-13 → **~17 months dormant** at review date.

## 5. Comparison to calxgloss

- **Decision record vs commit stream.** calxgloss carries its reasoning in
  57 ADRs + a living roadmap; LRE's reasoning exists only as commit
  messages and a README. Its "Future Development" section is the closest
  analogue — and is *candid* (it lists a known session-load bug, and admits
  the library-black-box failure mode as open). For comparison value: the
  phase-1→phase-2 pivot (automated metrics abandoned for human eval) is a
  decision LRE never records as such — a calxgloss ADR would have named
  the tradeoff.
- **Licensing window** is a small calxgloss-style hygiene win: calxgloss is
  planned/structured from day one; LRE ran unlicensed for 7 weeks and left
  stale identity references behind.
- **Durability of evidence:** LRE's xlsx and Polish prose are honest but
  closed evidence — no scripts reproduce it. calxgloss's runs are
  git-branch reproducible by design (per-attempt branches, ADR-0012-style
  reversibility). Neither repo has CI; both rely on human-initiated runs
  (see [40](40-comparison.md)).

## Sources

`git log`/`git show --numstat`/`git tag` on clone `aa74f48`; GitHub API
(stars/forks/watchers/issues/releases/branches/contributors, account
redirect for `michaljurzak1`) and Docker Hub v2 API, recorded 2026-11-01;
log/workspace path evidence in `logs/analysis.log`,
`workspace/output.json/project.json`, and commit `bff1e18` stat.
