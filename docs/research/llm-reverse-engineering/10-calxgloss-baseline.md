# 10 — calxgloss capability baseline — the comparison anchor

> Part of the [overview](README.md). Fixed anchor every `3x-*` chapter
> compares against — the same anchor used by the
> [OGhidra](../OGhidra/10-calxgloss-baseline.md) (re-verified 2026-11-01),
> [KRAKEN](../kraken/10-calxgloss-baseline.md) and
> [LLM4Decompile](../LLM4Decompile/10-calxgloss-baseline.md) studies.
> Condensed here; the OGhidra edition is the fullest sibling and every fact
> below carries its crate/ADR citations.

## What calxgloss is

A **Rust workspace** — 34 crates / 475 `.rs` files under `crates/` — that
reverse engineers a *directory of Windows binaries* (`target_dir`: EXEs and
DLLs, read-only) into a **cross-platform Rust workspace** with identical
observable behavior. It is an automated **pipeline + review harness**, not a
conversational tool: an LLM (locally hosted, via Ollama/vLLM) does the
translation work; 15 evidence scans supply structured evidence; a verification
gate proves equivalence; a human reviews each **unit of work** in a web UI.
Steering happens at run/queue/verdict level — never per address.

Core philosophy (docs/Calxgloss.md): functional equivalence over binary
precision; cross-platform by default (PAL); **test-driven decompilation**;
incremental restitching (Phase 6 engine *not yet implemented*); **LLM-first,
discard-when-wrong**; source-control-backed reversibility; human-in-the-loop
review.

## The pipeline (`calxgloss-translator`)

- **Unit of work** = one function/struct keyed `{file}/{function}`; **run** =
  one session; steering lands at unit boundaries; queue order comes from the
  call graph + reviewer overlay (`crates/pipeline/GLOSSARY.md`). `live` runs
  pipeline + review server in one process.
- Per-function loop: `read cache ▸ evidence warmup ▸ fetch ▸ prompt ▸
  translate ▸ verify ▸ retry ▸ commit`.
- **Pre-batch scans**: 15 scan rows (`scan_registry.rs:606-624`) run over the
  whole binary first, concurrent window 4, `waits_for` latches, skip-rate
  breaker (ADR-0026), coverage record + admission line stamped per scan
  (ADR-0053), then binary-**version pairing** (`calxgloss-bdiff`) so accepted
  translations survive a binary update.
- **Attempt seam** (ADR-0051): one attempt = prompt → LLM call → verify →
  record (`retry/attempt.rs:229`); failure-informed strategies
  (`compile_fix`, `test_fix`, `escalate`, `edge_case_fix`) dispatched by
  verdict, **escalating 5 context tiers** `Signature → Disassembly →
  WithTests → ModuleContext → FullModule` (`context_tier.rs:59-84`).
- **Fault monitors** (`calxgloss-llm`): context overflow, hallucination,
  infinite loop, behavior divergence, resource exhaustion — each named, each
  logged to `re/analysis/fault_log.json` with recovery guidance.

## Evidence engines (15 scans + 3 readers)

One crate per methodology, all reading through the decompiler seam:
typesdb, typeinfer, algorithm, memory, sync, globalstate, consts, callback,
controlflow, stringctx, apidetect, serialize, errhandling, floatsimd,
libmatch (scan rows); plus readers analysis (DLL classification), callgraph
(translation order), bdiff (version pairing). Engines also **write typed
discoveries back** into the loaded program — narrow-only, never overwriting
hand-typed slots (ADR-0020/0021). Full table in the
[OGhidra baseline](../OGhidra/10-calxgloss-baseline.md) §Evidence engines.

## The seam

- Fixed boundary (`ScanSource` read trait; separate write trait; the cache
  type never implements write — compile-time tripwire).
- **Kuna is the only analysis engine, fully in-process** (ADR-0041): no
  install/spawn/attach; one engine thread; per-function budgets; produces
  Ghidra-flavored pseudo-C as a dialect, not a live Ghidra.
- **Scan read cache** keyed by binary SHA-256 + format version + engine
  build identity (ADR-0042/0043/0055) — an engine swap can never replay
  stale answers.
- **Capability report** (ADR-0054/0055): per query family the engine declares
  `answerable`/`unavailable` with admission lines; absent coverage reads as
  *unknown, never absent*.

## Verification — the oracle chain (the axis LRE lacks)

1. **Baseline capture** (`calxgloss-testgen`): export signatures → FFI
   bindings → generated inputs (boundary/typical/edge + one per branch) →
   **the original DLL is executed under Wine** capturing return values AND,
   since P22/ADR-0057, the **ordered API-call trace** per case.
2. **Verification** (`calxgloss-verify`): throwaway Cargo **scratch project**,
   `cargo check`, run behavioral tests vs `re/baseline/.../baseline.json`;
   trace verdict by **ordered containment**; a data-only `VerificationResult`
   travels to CLI, dashboard, and stored records.
3. Output lands as Rust on `main` + generated shim crates (`re/shims/`);
   `calxgloss-pal` is a Windows-API→crate mapping database, not a compiled
   dependency.

There is **no conformance verdict** yet ("binary done") — roadmap P26 — and
**no whole-task measurement harness** — roadmap P33. calxgloss has honest
*unit-level* proof but no *aggregate* score. No CI (P42).

## Work history, review, surfaces

- **Git is the edit log**: attempt branches `re/{bin}/{fn}v{N}`, failures kept
  forever, structured justification blocks per commit (`calxgloss-git`).
- **Review web UI** (Axum + React): accept / send-back / patch / skip / batch,
  queue overlay, analytics computed from records (ADR-0005), honest
  degradation, live pipeline control over REST/WebSocket.
- **29-command CLI**, layered config with recorded value *Source*, `doctor`
  loads targets through Kuna; no daemon, no MCP surface, no JSON CLI mode,
  no built-in chat — the seam answers only declared query families.

## What calxgloss is *not*

Not interactive, no per-address queries; **PE32/PE32+ x86 Windows targets
only** (no ELF, no other ISAs; managed PE parked); no debugger/emulator;
output is reconstructed Rust, not findings or pseudocode; no program-vs-
program diff (bdiff pairs *versions of the same* binary).

## Capability summary (anchor table)

| Domain | calxgloss | Key refs |
|--------|-----------|----------|
| Mission | PE/DLL directory → verified cross-platform Rust, unattended, human reviews units | `calxgloss-translator` |
| Analysis engine | Kuna, in-process, seam, capability report | ADR-0041, 0054/0055 |
| Evidence | 15 scans + 3 readers, coverage honesty, typed write-back | `crates/evidence/*` |
| Prompting | 5 tiers, evidence bundle → askama templates | ADR-0048/0049/0051 |
| LLM | local models, attempt seam, retry strategies, fault monitors | `calxgloss-llm` |
| History | attempt branches per unit, failures archived | `calxgloss-git` |
| Review | verdict UI (accept/send-back/patch/skip) over artifacts | `calxgloss-web` |
| Verification | Wine baselines (returns + api trace) + compile/test gate + ordered-containment verdict | ADR-0057 |
| Completion honesty | named unknown records (P21); no conformance verdict (P26); no whole-task score (P33) | roadmap |
| Gaps | no CI (P42), no EXE scenario baselines (P24), restitch engine unimplemented | roadmap/Calxgloss.md |

## Sources

`docs/Calxgloss.md`, `README.md`, `docs/data_flow.md`, `docs/roadmap.md`,
57 ADRs, per-context glossaries, and code spans as cited in the
[OGhidra baseline](../OGhidra/10-calxgloss-baseline.md) (same facts, verified
2026-11-01 against this workspace).
