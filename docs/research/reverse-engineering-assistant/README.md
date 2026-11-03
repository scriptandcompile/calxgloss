# ReVa (cyberkaida/reverse-engineering-assistant) — complete overview & calxgloss comparison

> **ReVa** ([cyberkaida/reverse-engineering-assistant](https://github.com/cyberkaida/reverse-engineering-assistant), PyPI `reverse-engineering-assistant`) is a
> **Ghidra extension whose core is an MCP server**: 88 LLM-shaped tools
> (19 providers, 6 togglable groups) over a live Ghidra program database, a
> Python `mcp-reva` headless launcher (PyGhidra — Ghidra without UI), and a
> Claude Code marketplace of 6 analysis/CTF skills. Its thesis: many *small*
> tools, output shaped to fight context rot, the LLM as orchestrator.
> This directory is an exhaustive overview of every part of ReVa, compared
> against **calxgloss** — this repo's automated PE/DLL → cross-platform-Rust
> decompilation factory. ReVa reviewed at `a2fcd94` (2026-10-27); see
> [scope and method](00-scope-and-method.md). Not to be confused with
> morluto/rea, covered in [`../rea/`](../rea/).

## Executive summary

**The two projects answer the same question — "how does a machine turn a
binary into trustworthy code?" — with opposite authorities.** ([40](40-comparison.md))

- **calxgloss is an unattended factory.** The whole workflow is encoded in
  Rust: 15-row evidence-scan registry, 5 context tiers, the
  `CompileFix→TestFix→Escalate→EdgeCaseFix` retry cycle, a hard verify gate
  (Rust must compile and pass Wine-run baseline tests against the real DLL,
  API-call traces *assessed*, "silence never counts as a pass"), 9-state
  review queue. Output is a durable record tree + git wiki + tested Rust.
- **ReVa is a workbench for an agent.** 88 query/decompile/rename/diff/script
  tools mutate a live Ghidra program; an LLM (Claude Code, headless `mcp-reva`)
  orchestrates; the run ends when the model is satisfied and its temp project
  is deleted. Nothing compiled output is ever compiled or tested; ReVa's
  ground-truth tests certify its *tools*, not its *analyses*.

Neither has the other's gate: ReVa guards against **"the tool lies to the
agent"** (input ladders, `resolvedFrom` echoes, errors naming the fixing tool,
read-before-write gating); calxgloss guards against **"the translation
misbehaves"** (compile + execute + trace). The comparison is unusually
productive because they attack the same failure modes — context budget,
honesty about unknowns, error recovery — from opposite ends. ([40](40-comparison.md))

One correction to folklore: ReVa is **not** a successor of a "BoSSViePl3x/ReVa"
project — that lineage is unverifiable (404s) and the clone's history is a
single continuous line by **cyberkaida** since 2023-08-03. ([21 §2](21-history-and-releases.md))

## Capability matrix (condensed)

Winner in **bold**; "—" = absent. Full 16-row table with reasoning in
[40 §2](40-comparison.md).

| Capability domain | ReVa | calxgloss | Verdict |
|---|---|---|---|
| Analysis-engine breadth | any Ghidra loader/ISA, 5-Ghidra-version CI matrix | Kuna in-process; PE + x86 only | **ReVa** |
| Interactive query surface | 88 live tools, error redirect | 29 batch subcommands, no per-address question | **ReVa** |
| Batch evidence scanning | auto-analysis, results live only in session DB | 15 scans → machine-readable record tree | **calxgloss** |
| Write-back (rename/retype) | ≥9 transactional writers | confidence-floored lanes only | **ReVa** surface; calxgloss gating |
| Whole-binary reconstruction | none — Ghidra state + prose, project deleted | whole-program graph → wiki + Rust, replayable | **calxgloss** |
| Verification gates | tests tools, never outputs | compile + Wine tests + assessed traces | **calxgloss** |
| Diffing | 13 tools, durable staged sessions, markup transfer | bdiff report + review command | **ReVa** |
| Runtime observation | — (static only) | executes the real DLL under Wine as oracle | **calxgloss** |
| Unknown/gap tracking | honesty flags per payload | 6 unknown kinds, versioned corrections | **calxgloss** |
| Agent layer | 6 skills (~7.9k lines), discipline is prose | workflow in code, enforced by types | split |
| Headless automation | one-prompt generality, LLM in loop | deterministic, replayable `auto` | split |
| Human review UI | Ghidra GUI, no reviewer construct | typed review queue + dashboard + wiki | **calxgloss** structured; ReVa live |
| Security posture | engineered server policy (keys, binding guards) | offline by design, tiny surface | **ReVa** engineering; calxgloss exposure |
| Context budgeting | 6 tool groups; ~15–20k-token schema bill | 5 tiers, zero bill | **calxgloss** factory fit |
| Extensibility | `run-script` = full Ghidra API today | 34 crates but no ad-hoc query path | **ReVa** |
| Maintenance | releases, CI, dependabot; bus factor ≈1 | no CI; 57 ADRs, 4.7k test fns | **ReVa** maintained |

## What calxgloss should steal (top items)

Full 15-row ledger with crate-level build sketches in
[40 §5](40-comparison.md). Highest leverage:

1. **Right-answer e2e suite on CI** — ReVa's pytest harness boots `mcp-reva`
   against fixture DLLs and *asserts answers* (callees, strings, signatures);
   calxgloss has zero CI, and its 4.7k unit tests never touch the product path.
   ([32](32-headless-cli-and-automation.md), [34](34-analysis-workflows-and-effect.md))
2. **Durable staged diff sessions** for `calxgloss-bdiff` — per-stage
   checkpoints, resumable, with a summary that refuses near-zero results on
   under-matched inputs. ([31](31-mcp-tool-surface.md), [34](34-analysis-workflows-and-effect.md))
3. **Hybrid wait + single-flight job primitive** — `JobStatus`/`JobLog` with
   log cursors behind `verify`/`testgen`/`auto`; long Wine runs today have no
   handle, no cancel, no attach. ([31](31-mcp-tool-surface.md))
4. **Identifier ladder + `resolvedFrom` echo** — forgiving function selectors
   that report which rung matched; kills silent near-misses. ([31](31-mcp-tool-surface.md))
5. **Errors that teach** + read-before-write gate + under-analysis guard —
   verbal fault payloads naming the next tool, an expiring read-tracker
   refusing blind write-backs. ([31](31-mcp-tool-surface.md), [34](34-analysis-workflows-and-effect.md))
6. **Refuse-to-bind policy for `calxgloss-web`** — ReVa's tested
   loopback-or-auth guard quadrants, ~60 lines. ([32](32-headless-cli-and-automation.md))
7. **A `calxgloss-triage/review` contributor skill + `.mcp.json`-style client
   wiring** — the 29-command CLI has no driver today. ([33](33-skills-and-agent-layer.md))

## What ReVa confirms about calxgloss's choices (no action)

- **Engine in-process beats engine-as-dependency** — ReVa's fragility is the
  Ghidra install dance: zip per version, JVM boots, a dedicated setup *agent*,
  deleted docs still cited. Kuna vendored sidesteps all of it. ([32](32-headless-cli-and-automation.md))
- **Durable artifacts beat session state** — headless ReVa `rmtree`s its
  database; calxgloss's record tree + git wiki is the counterexample. ([32](32-headless-cli-and-automation.md))
- **Tiered context beats per-call shaping for a factory** — ReVa pays a fixed
  ~15–20k-token schema bill every session; context tiers pay it never. ([31](31-mcp-tool-surface.md))
- **Workflow-in-code where the job is fixed** — ReVa must hand-code workflow
  in prose (skills, unenforced budgets); calxgloss's one PE→Rust job lets the
  workflow compile into retry/fault types. ([33](33-skills-and-agent-layer.md))

## File index

| File | Domain |
|------|--------|
| [00-scope-and-method.md](00-scope-and-method.md) | scope, method, ReVa revision |
| [10-calxgloss-baseline.md](10-calxgloss-baseline.md) | calxgloss capability inventory (comparison anchor) |
| [20-reva-inventory.md](20-reva-inventory.md) | complete ReVa surface (88 tools, 6 skills, CLI, build) |
| [21-history-and-releases.md](21-history-and-releases.md) | origin, release ladder, community (lineage check) |
| [31-mcp-tool-surface.md](31-mcp-tool-surface.md) | tool design doctrine, schemas, error redirect, jobs |
| [32-headless-cli-and-automation.md](32-headless-cli-and-automation.md) | assistant/headless modes, mcp-reva, security |
| [33-skills-and-agent-layer.md](33-skills-and-agent-layer.md) | marketplace, 6 skills, dev scaffolding |
| [34-analysis-workflows-and-effect.md](34-analysis-workflows-and-effect.md) | import→analyze→annotate→diff, effect evidence |
| [40-comparison.md](40-comparison.md) | master comparison + discrepancy adjudications |

All ReVa claims cite `path:line` in the clone at `/tmp/opencode/cyberkaida-rea`
(revision above); calxgloss claims cite this repo's crates/ADRs directly.
Known-stale chapter claims were fixed in place 2026-10-31 — see
[40 §7](40-comparison.md) for the ledger of what changed.
🌱 graft saved ~2.78M tokens during orientation of this analysis.
