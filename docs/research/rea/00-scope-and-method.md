# REA ↔ calxgloss comparison — scope and method

> Part of the [REA overview](README.md). Read this first for what is being
> compared and how.

## What REA is

**REA — "Reverse Engineer Anything"** ([morluto/rea](https://github.com/morluto/rea),
[rea.tools](https://rea.tools/), npm package `rea-agents`) is a Node.js/TypeScript
**MCP server + CLI** for reverse engineering, together with an agent **skill**
that teaches coding agents how to use it. As of the revision reviewed here, REA
is not primarily "a collection of skills" in the agent-skill sense: it is one
user-facing skill (`reverse-engineer-anything`, plus 6 reference files) and four
*development* skills for working on REA itself. What gives REA its capability is:

- **~150 MCP tools** (mirrored by ~180 CLI commands) spanning native binaries,
  JS/Electron, .NET, Android, firmware, WASM, EVM, packet captures, and more;
- **~90 documentation guides** (~23k lines of markdown) that spell out, for
  each type of target, the investigation steps and the rules for what counts as
  evidence;
- **engine providers** ("engine" here is REA's word): Hopper, Ghidra, IDA,
  Cutter/rizin, **Kuna**, GNU objdump, GDB, Frida.

## Comparison scope

calxgloss only works on **native applications** (Windows PE/DLL targets
decompiled to cross-platform Rust). Per the maintainer's direction, this
comparison covers REA capabilities relevant to that world:

**In scope**

- The 5 SKILL.md files (the user-facing skill in depth; dev skills summarized).
- Deep native-binary analysis: the Hopper/Ghidra/IDA/Kuna/objdump/rizin/Cutter/GDB
  providers, and REA's tools for investigating a native binary.
- Native binary intelligence: headers, sections, symbols, certificates,
  embedded build metadata, crash dumps, firmware regions.
- Reconstruction methodology: evidence contracts, evidence bundles, unknown
  tracking, coverage/readiness ledgers, function matching.
- Runtime observation: Frida instrumentation, process capture, native UI/call
  observation, static↔runtime correlation, debuggers.
- Agent-layer mechanics: setup/doctor, MCP prompts, connection recovery, and
  the rules for what happens to evidence after it is recorded — these shape how
  an agent harness works.

**Out of scope** (recorded in the inventory, not compared in depth)

- JavaScript/Electron/website/browser tooling, .NET managed analysis, Android/
  APK/JADX/ADB, HAR/SAZ network captures, packet/pcap analysis, logic-signal
  decoding, SQLite, WASM/EVM analysis, Flutter/HarmonyOS identification.
  These are real REA features but target non-native or non-Windows ecosystems
  that calxgloss never touches.

## Method

1. **Baselines first**: `10-calxgloss-baseline.md` (this repo's capabilities,
   from README, `docs/Calxgloss.md`, `docs/data_flow.md`, ADR titles) and
   `20-rea-inventory.md` (complete REA surface with native-relevance triage).
2. **Per-domain files** (`3x-*.md`): each covers one capability domain. First
   they state what REA does concretely — naming the tools, flags, and what its
   docs require — then they give a direct **calxgloss comparison** section:
   overlap, calxgloss-only, REA-only, verdict.
3. **Master index** (`README.md`): executive summary, capability matrix, and a
   gap analysis of ideas worth stealing.

Every claim points to a file:line or doc path. REA claims use the clone at
`/tmp/opencode/rea` (revision below); calxgloss claims use this repo.

## REA revision reviewed

```
git clone of https://github.com/morluto/rea
commit 28a33cae8f8d4de8e11f7a266ff0d756432ab092  (2026-10-23)
"fix(runtime)!: require patched Node.js security releases (#6315)"
```

Facts below cite REA paths relative to that clone root.

## File index

| File | Domain |
|------|--------|
| `00-scope-and-method.md` | this file |
| `10-calxgloss-baseline.md` | calxgloss capability inventory (comparison baseline) |
| `20-rea-inventory.md` | complete REA surface + native-relevance triage |
| `31-deep-native-analysis.md` | engine providers & the native tool surface |
| `32-native-artifact-intelligence.md` | binary formats, metadata, inventories, dumps |
| `33-reconstruction-evidence-workflow.md` | evidence contracts, bundles, unknowns, coverage ledgers |
| `34-runtime-observation.md` | Frida, debuggers, process capture, static↔runtime correlation |
| `35-skills-and-agent-layer.md` | all 5 skills, references, setup/doctor, MCP prompts |
| `README.md` | executive summary, capability matrix, gap analysis |
