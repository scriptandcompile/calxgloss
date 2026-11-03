# ReVa (cyberkaida/reverse-engineering-assistant) ↔ calxgloss — scope and method

> Part of the [ReVa overview](README.md). Read this first for what is being
> compared and how.

## What ReVa is

**ReVa — "Reverse Engineering Assistant"**
([cyberkaida/reverse-engineering-assistant](https://github.com/cyberkaida/reverse-engineering-assistant))
is a **Ghidra extension** whose core is an **MCP server** (streamable-HTTP,
Java, ~28k LOC under `src/main`; ~54k LOC including its own test suites)
that exposes Ghidra's reverse-engineering
capabilities as 88 small, LLM-oriented tools. It ships three more
layers:

- a **Python CLI / headless launcher** (`mcp-reva`, PyPI package
  `reverse-engineering-assistant`, `src/reva_cli`) that runs Ghidra
  headless via PyGhidra — no UI needed;
- a **Claude Code marketplace** with **agent skills** (`ReVa/skills/`:
  binary triage, deep analysis, cryptography analysis, CTF guides) plus
  `.claude/` agents and hooks;
- a **PyGhidra scripting bridge** — ReVa exposes a `run_script`-style tool
  giving agents the Ghidra scripting environment.

Its stated design thesis: a **tool-driven approach** with many *small* tools
"just as your RE environment provides a set of small tools to you", shaped to
tolerate sloppy LLM input, redirect correctable mistakes back to the LLM, and
reduce context rot and hallucination by returning small critical fragments
with cross-reference reinforcement. The repo's git history is a single
continuous line started by **cyberkaida** on 2023-08-03; a claimed lineage as
successor of a `BoSSViePl3x/ReVa` project proved unverifiable (that user/repo
404s; see [history](21-history-and-releases.md) §2 for the evidence trail).

> Naming note: this repo's `docs/research/rea/` folder covers a *different*
> project (morluto/rea, "Reverse Engineer Anything"). This folder covers
> **cyberkaida's ReVa**. When the two meet, spell the names out.

## Comparison scope

calxgloss works only on **Windows PE/DLL targets → cross-platform Rust**.
ReVa is Ghidra-based and architecture-agnostic. Per the goal ("complete
overview covering every part"), the inventory (`20-*.md`) records **every**
part of ReVa, and the deep-dive chapters (`3x-*.md`) cover:

**In scope**

- The MCP tool surface: every tool, its schema, input tolerance, output
  shaping, tool groups/toggling — ReVa's core claim to competence.
- The two run modes: Ghidra-UI assistant mode vs headless (PyGhidra) mode;
  project/import management, diff workflow, analysis jobs, scripting tool.
- Security posture: API-key auth, public-interface warnings, script tool
  gating.
- Skills & agent layer: the Claude Code marketplace, each skill, hooks,
  agents, CLAUDE.md conventions.
- Effect: test suites (`src/test`, `src/test.slow`, `tests/*e2e*`),
  documented workflows, README example questions, any benchmark evidence.
- History/lineage: the BoSSViePl3x fork lineage, release cadence.

**Out of scope** (noted, not compared in depth)

- Ghidra itself (the disassembler/decompiler ReVa rides on) is treated as an
  external engine, the way Kuna is treated in other comparisons.
- GitHub/Kagi MCP pairing examples — they are third-party servers, not ReVa.

## Method

1. **Baselines first**: `10-calxgloss-baseline.md` (this repo's capabilities,
   verified against the current tree + ADRs) and `20-reva-inventory.md`
   (complete ReVa surface from the clone).
2. **Per-domain files** (`3x-*.md`): first state what ReVa does concretely —
   naming classes, tools, flags, docs — then a direct **calxgloss
   comparison** section: overlap, calxgloss-only, ReVa-only, verdict.
3. **Comparison** (`40-comparison.md`) + master `README.md` index: executive
   summary, capability matrix, ideas worth stealing.

Every claim cites `path:line` in the clone (revision below) or a file in this
repo. ReVa code lives under `/tmp/opencode/cyberkaida-rea`.

## ReVa revision reviewed

```
git clone of https://github.com/cyberkaida/reverse-engineering-assistant
commit a2fcd946ec9c0bcf204da308365c16abb781dc53  (2026-10-27)
"chore(deps): bump Jackson core, databind, dataformat-yaml to 2.22.4 (#380)"
```

Facts below cite ReVa paths relative to that clone root.

## File index

| File | Domain |
|------|--------|
| `00-scope-and-method.md` | this file |
| `10-calxgloss-baseline.md` | calxgloss capability inventory (comparison baseline) |
| `20-reva-inventory.md` | complete ReVa surface |
| `21-history-and-releases.md` | origin, release ladder, community (lineage check) |
| `31-mcp-tool-surface.md` | every MCP tool, schemas, tool groups, output shaping, context-rot design |
| `32-headless-cli-and-automation.md` | PyGhidra headless mode, reva_cli, projects, security config |
| `33-skills-and-agent-layer.md` | Claude Code marketplace, skills, hooks, agents, CLAUDE.md |
| `34-analysis-workflows-and-effect.md` | workflows, scripting, diff, tests, evidence of effectiveness |
| `40-comparison.md` | master comparison with calxgloss |
| `README.md` | executive summary, capability matrix, file index |
