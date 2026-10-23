# REA (Reverse Engineer Anything) — complete overview & calxgloss comparison

> **REA** ([morluto/rea](https://github.com/morluto/rea), npm `rea-agents`) is an
> MCP server + CLI + agent-skill system that lets a coding agent reverse engineer
> *anything* — binaries, apps, runtimes — by answering its queries with
> evidence-backed findings. This directory is an exhaustive overview of every
> REA skill and capability, compared against **calxgloss** — this repo's
> automated PE/DLL → Rust decompilation harness. REA reviewed at
> `28a33ca` (2026-10-23); see [scope and method](00-scope-and-method.md).

## Executive summary

**The premise "REA is a collection of skills" is only half true.** REA ships
exactly **one** reverse-engineering skill (452 lines + 6 reference files) and
four *development* skills for working on REA itself. Its actual capability mass
is elsewhere: **~150 MCP tools / ~180 CLI commands** and **~90 guide documents
(≈23k lines)** that encode per-format investigation workflows. The skill's job
is to route an agent to that machinery and keep it honest — not to contain the
capabilities itself. ([35](35-skills-and-agent-layer.md), [inventory](20-rea-inventory.md))

**Fundamental difference of kind, not degree:**

- **calxgloss is a factory.** It knows its job (Windows PE/DLL → cross-platform
  Rust with behavior tests) and encodes the *entire* workflow in code: 11 batch
  evidence scans, 5-tier prompt escalation, retry strategies, compile+test
  verification, per-function attempt branches, a human review UI. Unattended,
  deterministic, narrow. Only one engine: **Kuna in-process**.
- **REA is a laboratory bench.** It answers *any* question about *any* artifact
  (native, managed, JS, Android, firmware, WASM, captures…) through
  evidence-contract tools across swappable engines (Hopper, Ghidra, IDA, Kuna,
  Cutter/rizin, objdump, GDB, Frida). The agent — guided by the skill — is the
  orchestrator. Human/LLM judgment does the synthesis; REA never "translates"
  a whole binary itself.

They **share the same core engine** (Kuna) and solve the same deep problems
(context budget, evidence honesty, error recovery) from opposite ends — which
makes the comparison unusually productive. ([31](31-deep-native-analysis.md))

## Capability matrix

Winner in **bold**. "—" = absent.

| Capability domain | REA | calxgloss | Verdict | Ch. |
|---|---|---|---|---|
| Deep native disassembly/decompilation | 7 providers incl. Kuna; arbitrary-address queries; xrefs/call paths; arch breadth incl. 16-bit DOS | Kuna only, in-process; whole-binary batch scans; **type write-back** | split — calxgloss for batch PE, REA for question-driven | [31](31-deep-native-analysis.md) |
| Binary-format intelligence | 14+ built-in decoders (Go/Rust build metadata, PE certs, ELF notes, IL2CPP, PCK, BEAM, GPU code objects), crash-core forensics, firmware | PE-centric classification, ADR-0044 managed-PE parking, libmatch body-signature matching | **REA** (breadth); calxgloss's inference wins where no declared metadata exists | [32](32-native-artifact-intelligence.md) |
| Reconstruction & completeness | evidence bundles, unknown tracking, obligation ledgers, coverage/readiness **fail-closed conformance**, byte-exact showcases (DX-Ball: 3,205 cases + 63 bytes) | per-function units of work on attempt branches, review queue, FFI baseline tests, verify loop | split — REA leads verification *bookkeeping*, calxgloss leads verification *execution* | [33](33-reconstruction-evidence-workflow.md) |
| Runtime observation | Frida (pinned 17.23.2), GDB/rizin debug sessions, PTY scenario capture + comparison, native UI/call observation, static↔runtime correlation | black-box FFI baseline on original DLL; replayable, fully automated | split — calxgloss zero-driving gates; REA white-box visibility | [34](34-runtime-observation.md) |
| Skills & agent layer | 1 RE skill (v45) + 6 refs, doctor/recovery ladder for 20+ clients, compact MCP schemas, 6 MCP prompts, 4 dev skills | no shipped skill; harness encodes workflow; dev-workflow skills + graft navigation; fault monitors + retry ladder | split — opposite strategies for the same failure modes | [35](35-skills-and-agent-layer.md) |
| Output product | findings/evidence/pseudocode for an agent to synthesize | compiled, tested, cross-platform **Rust source** — end artifact | **calxgloss** for its mission | [31](31-deep-native-analysis.md) |
| Target breadth | native (many arches/formats), managed, JS/Electron, Android, web, firmware, WASM, EVM, captures | Windows PE32/PE32+ only, by design | **REA** (irrelevant axis for calxgloss) | [20](20-rea-inventory.md) |

## What calxgloss should steal (aggregated, by value)

1. **First-class unknown records** surfaced in the review UI and consumed by
   `escalate` retries — REA's `record/list/update/verify_unknown_resolution`
   lifecycle; turns silent gaps into an audit ledger. ([33](33-reconstruction-evidence-workflow.md))
2. **Fail-closed completeness conformance** — REA's readiness/obligation-ledger
   model ("unknown never aggregates to pass") applied to "this DLL is done":
   per-function obligation ledger with owner digests. ([33](33-reconstruction-evidence-workflow.md))
3. **Coverage/limitation fields on evidence-engine output** — REA's admitted
   semantics: each scan says which fields it actually examined; a `null` is not
   a `false`. ([32](32-native-artifact-intelligence.md), [33](33-reconstruction-evidence-workflow.md))
4. **Masked byte search** (`search_bytes(pattern, mask)`) on the decomp seam —
   feeds `consts`/`serialize` magic-number scans with real matches. ([31](31-deep-native-analysis.md))
5. **Differential API-call observation** in `verify` — REA-style call
   observation / interposer traces comparing original vs restitched DLL,
   catching behavior FFI unit tests miss. ([34](34-runtime-observation.md))
6. **Engine-identity cache keys** — key the scan cache on Kuna's version/build
   digest instead of a hand-bumped format version. ([31](31-deep-native-analysis.md))
7. **Capability advertising on the seam** — engine reports what it can/cannot
   answer, so prompts and fault monitors treat unknown ≠ false and wrong-tier
   retries get pruned. ([31](31-deep-native-analysis.md), [35](35-skills-and-agent-layer.md))
8. **"Don't repeat the unchanged failed call" doctrine** + scoped doctor —
   calxgloss-cli's `doctor` could gain REA's diagnose-before-repair ladder for
   its own LLM/engine/connection failure classes. ([35](35-skills-and-agent-layer.md))

## What REA shows about calxgloss's choices (confirmation, not change)

- **The verify/branch/review spine is the hard part** — REA's own contracts
  concede the behavioral-equivalence wall; its showcases celebrate what
  calxgloss automates wholesale. calxgloss's testgen→verify→attempt-branch
  chain is the stronger machinery *for reconstruction*, and REA's docs
  effectively say so. ([33](33-reconstruction-evidence-workflow.md))
- **In-process Kuna was right**: REA pays cross-process costs for the same
  engine (export/inventory staging, timeouts) and its Kuna provider doesn't
  even accept PE — calxgloss is the only one of the two using Kuna for PE at
  all. ([31](31-deep-native-analysis.md))
- **Tiered context beats one-shot prompting** — both projects independently
  converged on escalating context budgets (calxgloss 5 prompt tiers ↔ REA
  compact/full schema profiles + reference-file progressive disclosure). ([35](35-skills-and-agent-layer.md))

## File index

| File | Domain |
|------|--------|
| [00-scope-and-method.md](00-scope-and-method.md) | scope, method, REA revision |
| [10-calxgloss-baseline.md](10-calxgloss-baseline.md) | calxgloss capability inventory (comparison anchor) |
| [20-rea-inventory.md](20-rea-inventory.md) | complete REA surface + native-relevance triage |
| [31-deep-native-analysis.md](31-deep-native-analysis.md) | engine providers, Kuna integration, query surface |
| [32-native-artifact-intelligence.md](32-native-artifact-intelligence.md) | format decoders, metadata, dumps, firmware |
| [33-reconstruction-evidence-workflow.md](33-reconstruction-evidence-workflow.md) | evidence contract, unknowns, ledgers, verification |
| [34-runtime-observation.md](34-runtime-observation.md) | Frida, debuggers, process/UI capture, correlation |
| [35-skills-and-agent-layer.md](35-skills-and-agent-layer.md) | every skill, setup/doctor, MCP prompts, tool design |

All chapters cite REA `path:line` (clone at `/tmp/opencode/rea`) and calxgloss
ADRs/crates directly. 🌱 graft saved ~2.19M tokens during orientation of this analysis.
