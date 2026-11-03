# game-frame — complete overview & calxgloss comparison

> **game-frame** ([tanepiper/game-frame](https://github.com/tanepiper/game-frame),
> Apache-2.0 code + CC0-1.0 docs) is a **verification-first RE playbook**:
> sixteen markdown skills, 23 stage/task agent cards, ~100 checking tools, a
> 28-crate Rust workspace of *proven* chip emulators and replacement DLLs, and
> a 734-file documentation encyclopedia — all built so that **someone else's
> coding agent** (Claude Code, Codex, Cursor, OpenCode…) can reverse-engineer
> and rebuild shipped games, with the tools adjudicating every claim. The
> counter-ontology to calxgloss's Rust pipeline: here the method is prose and
> the machine is only the immune system. Reviewed at clone HEAD
> `f195a074` (2026-10-30, 383 commits over 10 days, tags v1.0.0–v1.4.0);
> calxgloss at HEAD `40fbf91f` (2026-10-31); see
> [scope and method](00-scope-and-method.md).

## Executive summary

**A week-and-a-bit of authored velocity pointed at a different epistemic
goal.** game-frame went from empty repo to six annotated releases in ten days
(2026-10-21→30), 383 commits, one author, 251 co-authored by Claude — 16
skills, 8 team templates, ~100 checking tools, 48k lines of crates, and
a public VitePress site generated from the repo itself
([21](21-history-and-releases.md), [20](20-gameframe-inventory.md)). calxgloss
documents its doctrine in markdown too — a 2,360-line design bible
(`docs/Calxgloss.md` + `docs/data_flow.md`) and 57 ADRs — but *executes*
the method as its own Rust translator loop
([10](10-calxgloss-baseline.md)). Method-in-markdown-for-hire-an-agent
vs harness-owns-the-loop is the deepest split in the comparison.

**The decisive asymmetry is instrument self-proof.** game-frame's
`tests/run.sh` (2,128 lines, 36 groups) runs the *shipped* launcher, gates,
and tools end-to-end against a synthetic sample game — and includes negative
controls: a deliberately naive `--naive` port must *fail* the replay checks,
and `bitcompare` catches it on 20/20 seeds (`tests/run.sh:573-583`).
calxgloss carries 4,692 test attributes across 34 crates that **no CI runs**
(P42) and has zero negative-control tests. Same instinct, one order of
magnitude apart in paranoia — an immune system vs a test suite nothing runs
([33](33-toolkit-tools-tests.md) §12–13, [40](40-comparison.md)).

**Both converged, independently and within days, on the same three
pillars** — run-the-original ground truth as the final oracle, honesty filed
as records rather than prose (their 356-line GAPS.md / our typed
`UnknownRecord` roster), and a git ledger per unit of work. The
"verification inversion" game-frame markets is narrower than the rhetoric:
its own artifact proofs are deterministic (live-DLL WRAPPER_CALLS, conformance
tests), and its LLM sits where ours does — gap-filling between machines
([40](40-comparison.md) §5).

**Their honesty is real; their medium drifts.** The dossier's staleness
ledger is small but genuine: README "Fourteen" task agents vs `AGENTS.md:68`
"twelve"; GAPS.md's "nine stored forms" vs the eight-row table it closes;
the REA pin at 6.4.0 beside 6.7.0 in the template; no CI except the site
deploy. Prose ledgers rot; typed ledgers don't — calxgloss's machine-first
media is the vaccine for the exact disease game-frame caught in itself, and
game-frame's harness is the vaccine for ours.

## Capability matrix (condensed — full 17-row table in [40](40-comparison.md))

Winner in **bold**. "—" = absent.

| Capability domain | game-frame | calxgloss | Verdict |
|---|---|---|---|
| Who translates | third-party coding agent works the slice; the repo ships no translator | own Rust loop (read cache ▸ warmup ▸ fetch ▸ prompt ▸ translate ▸ verify ▸ retry ▸ commit) + locally hosted LLM seam | split — curates conditions vs owns the loop |
| Method medium | 16 skills + 23 agent cards in markdown, read by whatever agent is present | 2,360-line design bible + 57 ADRs; the method itself runs as Rust + `.j2` templates | split, deepest in the comparison |
| Instrument self-proof | `tests/run.sh` 36 groups, negative controls, `--naive` port caught 20/20 | 4,692 test attributes, no CI (P42), no negative controls | **game-frame, decisively** |
| Analysis engine | Ghidra headless + ad-hoc question tools (`decomp_query.py` 9 commands) | Kuna in-process, seam-declared scans only (P29 open) | **game-frame** — the P29 gap is real |
| Ground truth | real product launched, replays vs live DLLs, WRAPPER_CALLS | Wine per-function baselines + trace containment (ADR-0057) | same shape, different rigs |
| Naming | names are evidence to recover; `labels/names.tsv` read by tools | no renaming anywhere — identity verbatim, types-only write-back (ADR-0020/21) | split by doctrine — must stay split |
| Honesty records | GAPS.md checkbox ledger (149/29), drifts | typed 6-kind unknown ledger, chips in web UI | split by medium — typed wins on rot, prose wins on reach |
| Fixity of originals | `game.json` size+SHA-256 per file, `home doctor --hashes` verifies | none (P44/P47 open) | **game-frame** |
| Guardrails | gates as data: delete gate, game-folder sentinel, `GAMEFRAME_AGENT` identity | no guard yet; P43 files a fail-closed sandbox | **game-frame** |
| Models & economics | zero model-layer code; the user's subscription is the cost model | OpenAI-compatible seam, telemetry logged not budgeted, P50 open | split — externalized vs self-owned |
| Artifacts | rebuilt headers/DLLs/ports that load, link, run; 28 crates | restitched cross-platform Rust + attempt branches + unknowns ledger per unit | different artifact classes |
| Targets | real shipped games across DOS↔Windows, 16↔64-bit | PE32/PE32+ `target_dir`; one fixture ground truth, no corpus yet | **game-frame on proof of scale** |
| Distribution | launcher + 6-vendor config emit + Claude plugin/marketplace | CLI (29 subcommands) + web UI; no MCP/plugin surface at all | **game-frame** |

## What calxgloss should adopt (aggregated — full argument in [40](40-comparison.md) §4)

1. **The harness shape, negative controls first**: a `run.sh` that drives
   shipped entrypoints end-to-end (P42 CI wraps it), plus a deliberately
   WRONG translated fixture the gates must catch — the pattern
   `calxgloss-testfixtures` does not yet contain.
2. **Fixity manifests + the never-clobber updater rule** into P44
   (stamp DLL sha256/Wine version on `baseline.json`) and P47
   (per-function "made-from" digests), built in their checked-by-doctor shape.
3. **The ad-hoc query surface (P29) — unscheduled behind anything**:
   question-shaped verbs beside the batch scan ("without reading it whole",
   `decomp_query.py:2`), and an exportcov→`UnknownKind::ExportUncovered`
   fill-gaps loop.
4. **A public gap page generated from the typed ledger** — their GAPS.md
   lesson (prose drifts) attached.
5. **Project the evidence grammar onto human surfaces**: confidence tiers
   beside claims in the web review queue / `dashboard` and in commit
   messages (closes P51's display side).
6. **A failure-*knowledge* layer**: `docs/knowhow/`-shaped curated fixes, fed
   to retries and one `advise`-style verb; `trace_divergence_index` today has
   no consumer — wire it into the retry prompt and web UI.
7. **"What it does not do" docstrings as a lint + `--json` everywhere**
   (P46/P52 posture).
8. **Gates as data** for the P43 guard: rules load from per-target config,
   warn-and-allow severity, agent identity as an env fact.
9. **The case-study story form** for the first full-binary runs: a published
   post-run REPORT generated from the gates that already fire.

**Rejected**: any renaming of the analysis artifact (calxgloss has no
rename path at all — ADR-0020/21 write back types only); importing the markdown playbook *before* CI + negative
controls ("vocabulary of verification without its immune system");
bit-identical parity as a bar; wrapper DLLs as a distribution medium
(PAL-as-database stands).

## What game-frame confirms about calxgloss's choices

- **The three pillars are project-independent**: two unrelated codebases,
  built within days of each other, converged on run-the-original truth,
  honesty-as-record, and a per-unit git ledger — our architecture is not
  idiosyncratic.
- **The epistemic skeleton is shared**: game-frame's LLM sits between
  deterministic engines exactly where ours does; the "inversion" is about
  audience and paranoia engineering, not a different theory of proof
  ([40](40-comparison.md) §5d).
- **Honest records with drift beats no records**: their self-caught ledger
  drifts are exactly the failures ADR-0053/0056's typed ledger makes
  structurally impossible — the diagnosis we share, the cure we already have.
- **Proof-of-scale cuts both ways**: their Banished story is author-local
  (the harness proves tools against a sample game, not the shipped binary);
  we have no published full-binary story at all (P26). What to borrow is the
  story form, not the emulation bar.

## File index

| File | Domain |
|------|--------|
| [00-scope-and-method.md](00-scope-and-method.md) | scope, method, pinned HEADs, verified repo metadata, staleness ledger |
| [10-calxgloss-baseline.md](10-calxgloss-baseline.md) | calxgloss capability inventory (comparison anchor, HEAD `40fbf91f`) |
| [20-gameframe-inventory.md](20-gameframe-inventory.md) | complete repo surface: folders, every tool/script enumerated, packaging, licenses, CI, metadata |
| [21-history-and-releases.md](21-history-and-releases.md) | 383-commit archaeology, v1.0.0→v1.4.0 ladder, release process, contributors |
| [31-method-playbook-skills.md](31-method-playbook-skills.md) | method loop, evidence labels, all 16 skills, AGENTS.md rules, `./gameframe` CLI |
| [32-agents-teams-gates.md](32-agents-teams-gates.md) | all 23 agents, hand-offs, 8 teams, gates/hooks, multi-client emit, plugin + MCP |
| [33-toolkit-tools-tests.md](33-toolkit-tools-tests.md) | all 14 tool families in depth, key tool mechanics, tests/run.sh + negative controls, the sample games |
| [34-scripts-templates-launcher-site.md](34-scripts-templates-launcher-site.md) | scripts, project template & lifecycle, launcher, site build, GameFrame home layout |
| [35-crates-wrappers.md](35-crates-wrappers.md) | all 28 crates, the 10-member wrapper workspace, frame contract, verification of each |
| [36-documentation-corpus.md](36-documentation-corpus.md) | docs/ encyclopedia area by area, GAPS.md ledger, knowhow, case studies, legal posture |
| [40-comparison.md](40-comparison.md) | full 17-domain comparison, effects, adopt list, confirmations & challenges |

**Reading order**: this page for the verdict, [40](40-comparison.md) for the
argument, then any topic chapter via the index. Every game-frame citation is
a clone-relative `path:line` verified against `f195a074`; every calxgloss
citation resolves at `40fbf91f`.
