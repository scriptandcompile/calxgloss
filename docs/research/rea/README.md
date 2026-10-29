# REA (Reverse Engineer Anything) — complete overview & calxgloss comparison

> **REA** ([morluto/rea](https://github.com/morluto/rea), npm `rea-agents`) is an
> MCP server + CLI + agent-skill system for reverse engineering. A coding agent
> asks it questions about *anything* — binaries, apps, runtimes — and REA answers
> with findings backed by evidence. This directory is an exhaustive overview of
> every REA skill and capability, compared against **calxgloss** — this repo's
> automated PE/DLL → Rust decompilation harness. REA reviewed at
> `28a33ca` (2026-10-23); see [scope and method](00-scope-and-method.md).

## Executive summary

**The premise "REA is a collection of skills" is only half true.** REA ships
exactly **one** reverse-engineering skill (452 lines + 6 reference files) and
four *development* skills for working on REA itself. The real capability sits
elsewhere: **~150 MCP tools / ~180 CLI commands** and **~90 guide documents
(≈23k lines)** that spell out, for each file format, the step-by-step way to
investigate it. The skill itself does not contain these capabilities. Its job is
to point an agent at the right tool and hold the agent to REA's evidence rules.
([35](35-skills-and-agent-layer.md), [inventory](20-rea-inventory.md))

**Fundamental difference of kind, not degree:**

- **calxgloss is a factory.** It knows its job (Windows PE/DLL → cross-platform
  Rust with behavior tests) and encodes the *entire* workflow in code: 11 batch
  evidence scans, escalation through 5 context tiers, retry strategies,
  compile-and-test verification, per-function attempt branches, a human review
  UI. It works unattended, deterministically, and in a narrow lane. It has one
  analysis engine: **Kuna, in-process**.
- **REA is a laboratory bench.** It answers *any* question about *any* artifact
  (native, managed, JS, Android, firmware, WASM, captures…) using tools whose
  answers must follow its evidence contract, and its engines can be swapped
  (Hopper, Ghidra, IDA, Kuna, Cutter/rizin, objdump, GDB, Frida). The agent does
  the orchestrating, guided by the skill. Human or LLM judgment combines the
  findings; REA itself never "translates" a whole binary.

The same analysis engine — Kuna — sits inside both projects, and they attack
the same hard problems (context budget, evidence honesty, error recovery) from
opposite ends, which makes the comparison unusually productive.
([31](31-deep-native-analysis.md))

## Capability matrix

Winner in **bold**. "—" = absent.

| Capability domain | REA | calxgloss | Verdict | Ch. |
|---|---|---|---|---|
| Deep native disassembly/decompilation | 7 providers incl. Kuna; queries for any address; xrefs/call paths; many architectures incl. 16-bit DOS | Kuna only, in-process; whole-binary batch scans; **type write-back** | split — calxgloss for batch scanning whole PE files, REA for answering a question about one address | [31](31-deep-native-analysis.md) |
| Binary-format intelligence | 14+ built-in decoders (Go/Rust build metadata, PE certs, ELF notes, IL2CPP, PCK, BEAM, GPU code objects), crash-core forensics, firmware | PE-centric classification, ADR-0044 managed-PE parking, libmatch body-signature matching | **REA** (breadth); calxgloss's inference wins where no declared metadata exists | [32](32-native-artifact-intelligence.md) |
| Reconstruction & completeness | evidence bundles, unknown tracking, obligation ledgers, coverage/readiness checks that **fail closed**, byte-exact showcases (DX-Ball: 3,205 cases + 63 bytes) | per-function units of work on attempt branches, review queue, FFI baseline tests, verification loop | split — REA leads the *bookkeeping* of what has been verified; calxgloss leads *running* the verification | [33](33-reconstruction-evidence-workflow.md) |
| Runtime observation | Frida (pinned 17.23.2), GDB/rizin debug sessions, PTY scenario capture + comparison, native UI/call observation, static↔runtime correlation | black-box FFI baseline tests against the original DLL; fully automated and replayable | split — calxgloss gates on tests that never run the live program; REA sees inside the running program | [34](34-runtime-observation.md) |
| Skills & agent layer | 1 RE skill (v45) + 6 reference files, doctor/recovery ladder for 20+ clients, compact MCP schemas, 6 MCP prompts, 4 dev skills | no shipped skill; the harness encodes the workflow in code; dev-workflow skills + graft navigation; fault monitors + escalating retry strategies | split — the two handle the same failure modes in opposite ways | [35](35-skills-and-agent-layer.md) |
| Output product | findings, evidence, and pseudocode for an agent to combine into an answer | compiled, tested, cross-platform **Rust source** — the finished artifact | **calxgloss** for its mission | [31](31-deep-native-analysis.md) |
| Target breadth | native (many architectures/formats), managed, JS/Electron, Android, web, firmware, WASM, EVM, captures | Windows PE32/PE32+ only, by design | **REA** (an axis calxgloss deliberately ignores) | [20](20-rea-inventory.md) |

## What calxgloss should steal (aggregated, by value)

1. **Unknowns as first-class records**, shown in the review UI and used by
   `escalate` retry strategies — adopt REA's
   `record/list/update/verify_unknown_resolution` lifecycle. Gaps that would
   otherwise go unnoticed become entries in an audit ledger.
   ([33](33-reconstruction-evidence-workflow.md))
2. **Completeness checks that fail closed** — apply REA's readiness/obligation
   ledger model ("unknown never aggregates to pass") to the question "is this
   DLL done": one obligation ledger per function, with owner digests.
   ([33](33-reconstruction-evidence-workflow.md))
3. **Coverage/limitation fields on evidence-engine output** — REA's admitted
   semantics: each scan says which fields it actually examined; a `null` is not
   a `false`. ([32](32-native-artifact-intelligence.md), [33](33-reconstruction-evidence-workflow.md))
4. **Masked byte search** (`search_bytes(pattern, mask)`) at the seam — the
   `consts` and `serialize` magic-number scans would get real matches to work
   with. ([31](31-deep-native-analysis.md))
5. **Diff the API calls the two DLLs make** in `verify` — REA-style call
   observation: traces that intercept the calls going to the original DLL and
   to the restitched one, catching behavior differences the FFI baseline unit
   tests miss. ([34](34-runtime-observation.md))
6. **Cache keys that name the analysis engine** — key the scan read cache on
   Kuna's version/build digest instead of a cache-format version number that a
   human has to bump by hand. ([31](31-deep-native-analysis.md))
7. **The seam reports what the analysis engine can and cannot answer** — then
   prompts and fault monitors treat unknown as different from false, and retry
   strategies at the wrong context tier are dropped.
   ([31](31-deep-native-analysis.md), [35](35-skills-and-agent-layer.md))
8. **"Don't repeat the unchanged failed call" doctrine** + a scoped `doctor` —
   calxgloss-cli's `doctor` could gain REA's ladder of diagnosing before
   repairing, for its own LLM, analysis engine, and connection failures.
   ([35](35-skills-and-agent-layer.md))

## What REA shows about calxgloss's choices (confirmation, not change)

- **The verify / attempt-branch / review spine is the hard part** — REA's own
  contracts admit how hard behavioral equivalence is, and its showcases show off
  exactly what calxgloss automates end to end. For reconstruction, calxgloss's
  chain — generate baseline tests, verify, commit to the function's attempt
  branch — is the stronger machinery, and REA's documentation effectively says
  so. ([33](33-reconstruction-evidence-workflow.md))
- **Running Kuna in-process was the right call**: REA pays the costs of running
  the same engine in a separate process (export/inventory staging, timeouts),
  and REA's Kuna provider doesn't even accept PE files — calxgloss is the only
  one of the two that uses Kuna for PE at all.
  ([31](31-deep-native-analysis.md))
- **Escalating context tiers beats one big prompt** — both projects reached the
  same idea independently: calxgloss escalates through 5 context tiers, and REA
  has compact/full schema profiles plus reference files that an agent opens
  only when it needs them. ([35](35-skills-and-agent-layer.md))

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
