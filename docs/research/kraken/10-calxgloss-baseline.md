# calxgloss capability baseline — the comparison anchor

> Part of the [KRAKEN overview](README.md). This is the fixed baseline every
> `3x-*` domain file compares KRAKEN against. Facts come from `README.md`,
> `docs/Calxgloss.md` (1,387 lines), `docs/data_flow.md` (969 lines, the
> `live` workflow), `docs/roadmap.md`, the 55 ADRs in `docs/adr/`, the
> per-context `GLOSSARY.md` files, and code spans verified in `crates/` on
> 2026-10-28. Where this differs from the [REA baseline](../rea/10-calxgloss-baseline.md),
> the repo is authoritative; changes are marked *updated*.

## What calxgloss is

A **Rust workspace** — 34 member crates in six groups under `crates/`
(`calxgloss` root, `shared/`, `integrations/`, `evidence/`, `pipeline/`,
`interface/`), 431 `.rs` files — that reverse engineers a *directory of
Windows binaries* (`target_dir`: EXEs and DLLs, read-only) into a
**cross-platform Rust workspace** with identical observable behavior. It is
a fully automated **pipeline + review harness**, not an interactive tool: an
LLM does the decompilation work, evidence engines supply the structured
evidence, verification proves equivalence, and a human reviews each unit of
work in a web UI — steering happens at the level of runs, queues, and
verdicts, never per address.

Core principles (`README.md` "Core Principles", `docs/Calxgloss.md` "Core
Philosophy"):

1. **Functional equivalence over binary precision** — behavior, not instruction sequences.
2. **Cross-platform by default** — Windows APIs map to Rust equivalents via a PAL.
3. **Test-driven decompilation** — baseline tests capture original behavior; Rust must pass them.
4. **Incremental restitching** — swap in Rust implementations one function at a time.
5. **LLM-first, discard-when-wrong** — the local LLM does the primary translation work; discarding bad output is cheap.
6. **Source-control backed reversibility** — every unit of work is a commit on that function's attempt branch.
7. **Human-in-the-loop review** — web UI reviews every unit, its justification, and its dependencies.

Vocabulary precision matters: per-context glossaries (`crates/<group>/GLOSSARY.md`)
define *unit of work*, *attempt*, *run*, *scan*, *coverage*, *seam*, *PAL*
and forbid synonyms; later chapters should use these words as defined.

## The pipeline (`calxgloss-translator`)

**Unit of work** = one function or struct, keyed `{file}/{function}` with the
binary identity verbatim (`game_logic/DrawSprite`). **Run** = one continuous
session; **steering** (skip a unit, hold a binary, reprioritize) lands at a
**unit boundary**; the **queue** order comes from the call graph, edited only
by the reviewer's overlay (`crates/pipeline/GLOSSARY.md`).
`live` = the one process running pipeline + review server together — the
only place pipeline control exists. Per-function loop
(`docs/data_flow.md` §3.2.2):

```
read cache ▸ evidence warmup ▸ fetch ▸ prompt ▸ translate ▸ verify ▸ retry ▸ commit
```

- **Pre-batch scan phase** (`run_prebatch_scans`,
  `crates/pipeline/calxgloss-translator/src/pipeline.rs:2312-2370`): *15*
  evidence scans (updated from 11 — the README's "13" is itself stale) run
  over the whole binary before translation, driven by the **evidence-scan
  registry**: one `ScanDescriptor` row per engine (`scan_registry.rs:606-624`)
  fanned out through a sliding window capped at 4 (`pipeline.rs:104`), with
  completion latches for declared `waits_for` edges (callback follows
  type-inference), a cached-hit short-circuit ahead of any engine read, and
  a join-everything / cancel-nothing rule (ADR-0052). Each scan stamps its
  own **coverage record** beside its provenance (ADR-0053); a **skip-rate
  breaker** aborts a scan whose listing mostly fails to decompile. Then
  **binary-version pairing** (`calxgloss-bdiff`) compares this scan against
  surviving scans of the same binary identity (`re/cache/{identity}/` sibling
  hash directories) so accepted translations carry across a binary update
  (`pipeline.rs:2357-2369`).
- **The attempt seam** (ADR-0051): one attempt = prompt → LLM call →
  verification → record, inside `retry/attempt.rs` (`run_attempt`, L229);
  the loop keeps only policy — strategy ladder, tier walk with an operator
  cap, stop routing on the verdict. Strategies (`compile_fix`, `test_fix`,
  `escalate`, `edge_case_fix`, `auto` cycling through them;
  `docs/data_flow.md` §8) are adapters behind one dispatch door keyed by
  `RetryStrategy`; the failing verdict routes into the next prompt and
  evidence is never re-gathered.
- **5 context tiers** for escalation: `Signature` → `Disassembly` →
  `WithTests` → `ModuleContext` → `FullModule` (adds shim + PAL code) —
  `crates/shared/calxgloss-types/src/context_tier.rs:59-84`. A failed lower
  tier sends the next attempt a larger one; a seam-declared `unavailable`
  query family drops that tier's step from the ladder (ADR-0055).
- **Fault monitors** (`calxgloss-llm`) end an attempt on a characteristic
  LLM failure — context overflow, hallucination, infinite loop, behavior
  divergence, resource exhaustion (`hallucination.rs`, `infinite_loop.rs`,
  `behavior_divergence.rs`, `context.rs`, `resource_exhaustion.rs`) — and
  log it to `re/analysis/fault_log.json` with recovery guidance.

### Evidence engines (15 scans + 3 readers; updated)

One crate per methodology; all read the loaded program through the seam. The
canonical set is the fifteen **scan rows** (`crates/evidence/GLOSSARY.md:10`,
`scan_registry.rs:606-624`; document paths at `docs/data_flow.md:186-200`):

| Scan row | Crate | Extracts |
|----------|-------|----------|
| type-database | `calxgloss-typesdb` | Type Manager scans, vtable detection, struct inference; RTTI linking; nesting/flagging post-assembly passes (ADR-0009–0013) |
| type-inference | `calxgloss-typeinfer` | this-pointer, parameter-size detection, propagation callee→caller and caller→callee, param directions, mangling contracts, local/return type inference (ADR-0014–0019, 0045) |
| algorithm-recognition | `calxgloss-algorithm` | pattern-database matching, correlation detector over the call map; claims resolved by strongest evidence (ADR-0022–0025) |
| memory-lifecycle | `calxgloss-memory` | alloc/free pairing, open allocations, escape, leak, transfer, handle lifecycle, RC upgrade (ADR-0026–0031) |
| concurrency | `calxgloss-sync` | lock pairs, atomics, lock-order graphs, data-race readings, async runtime detection (ADR-0032–0034) |
| global-state | `calxgloss-globalstate` | per-function global read/write records; feeds baseline side-effect expectations and the data-race readings (*new crate since the REA set*) |
| constants | `calxgloss-consts` | bitflag groups, enum candidates, magic-number frequency; renders `consts/{binary}.rs` |
| callback-detection | `calxgloss-callback` | function-pointer arrays, registration→call chains, closure contracts by injection (ADR-0035/0036) |
| control-flow | `calxgloss-controlflow` | switch-shaped if-else chains, self-recursion, state-variable chains, branch inventories |
| string-context | `calxgloss-stringctx` | nine-category string classification, per-function string maps, format-string inference |
| library-api | `calxgloss-apidetect` | import tables, library→crate mapping, per-function API summaries, portability divergence readings (ADR-0037) |
| serialization | `calxgloss-serialize` | byte-swap matching, bit-packing, magic-byte format sniffing (ADR-0038) |
| error-handling | `calxgloss-errhandling` | SEH frames, goto ladders, failure codes traveling the call map one hop (ADR-0046/0047) (*new crate*) |
| float-simd | `calxgloss-floatsimd` | float/vector/SIMD usage flags (*new crate*) |
| known-library | `calxgloss-libmatch` | known-library identification by body-signature matching of statically linked CRT/STL |

Readers with **no scan row** (`crates/evidence/GLOSSARY.md:10`):
`calxgloss-analysis` (DLL classification + shim suggestions; managed PEs
detected from the COM descriptor and parked as do-not-translate, ADR-0044),
`calxgloss-callgraph` (roots/leaves/translation order;
`re/analysis/{binary}_call_graph.json`, `docs/data_flow.md:303`), and
`calxgloss-bdiff` (version pairing keyed by the binary's old/new SHA-256).

Evidence engines also **write discovered types back** into the loaded
program through the seam's write side; the write-back narrows only undefined
slots, in program order, and never overrules a hand-typed slot
(ADR-0020/0021, no-write-back doctrine in `crates/evidence/GLOSSARY.md`).

## The analysis engine's seam

- The **seam** is the fixed boundary between the analysis engine and every
  consumer: reads through the `ScanSource` trait, write-back through a
  separate write trait (`crates/integrations/calxgloss-decomp/`).
  `CachedScanSource` never implements the write trait — compile-time
  tripwire (`type_write_source.rs:222-227`).
- **Kuna is the only analysis engine** and runs fully in-process — nothing
  to install, spawn, attach, or connect to (ADR-0039/0040/0041; the Ghidra
  HTTP bridge and JVM lifecycle are deleted, ADR-0001/0007 kept as visible
  history). One engine thread holds the loaded program, answering one call
  at a time; per-function budgets (instructions, seconds, memory) come from
  settings and refuse loud overspend. The engine reproduces
  Ghidra-flavored pseudo-C (`FUN_…`, `DAT_…`, `vftable`, WARNING preamble)
  as a *decompile dialect* — a format name, never a live component; the
  seam's noise filter strips shapes that would fake a structure and passes
  evidence shapes (spelled try/catch frames) byte for byte.
- **Scan read cache** (ADR-0042/0043, engine identity added by ADR-0055): a
  tiered read-through store — in-memory memo, then JSON documents under
  `re/cache/{binary identity}/{sha256 of binary}/` (`manifest.json` +
  per-read documents `decompile/{fn}.json`, `callers/{addr}.json`,
  `memory/{addr}-{len}.json`, …), then the engine
  (`calxgloss-decomp/src/cache.rs:16-23`). Validity is the key: the
  manifest records the binary hash, `CACHE_FORMAT_VERSION` (now 4,
  `cache.rs:140`), and the **identity of the engine build that produced the
  answers**, so an engine swap can never replay stale cache.
- **Seam capability report** (ADR-0054/0055): per query family the engine
  declares `answerable`/`unavailable` with one admission line each
  (`ScanSource::capability_report`, `scan_source.rs:648-660`; the cache
  passes it through byte-identical, `cache.rs:621-629`). Capability is live
  session state, never a filed document; capability wording and scan
  coverage wording never share bytes.

## Data model & persistence

calxgloss has **no edit log**. The nearest equivalents, each with a
different job: reversibility is **git** (every attempt is a commit on a
branch; undo = discard/retry a branch; failed branches stay, unmerged ones
are renamed into an *Archive*, never removed); reviewer intent is **overlay
files** (ADR-0003); program mutations are the **write-back** of scan records
(typed, confidence-floored, narrow-only; no per-change authoring or undo).
Humans never rename or comment at an address, so there is nothing an edit
log could log.

The on-disk memory of an effort is the **record tree** under the workspace's
`re/` (`docs/data_flow.md:675-770`; full tree there — summary):

| Artifact | Path | Written by |
|----------|------|-----------|
| classification records | `re/classify/{binary}.json` | `classify` (committed to `main`) |
| per-engine scan documents (+ rendered `.rs`/`.toml` for typesdb/consts/apidetect) | `re/analysis/{engine}/{binary}.json` | each engine's own *persistor* |
| version-pairing documents | `re/analysis/bdiff/{binary}-{old}-{new}-sha256.json` | `bdiff` |
| call graph | `re/analysis/{binary}_call_graph.json` | analysis warmup |
| run logs (fault, token usage, prompt strategy, LLM I/O) | `re/analysis/{fault_log,token_usage,prompt_strategy_log}.json`, `re/analysis/llm_io/log.jsonl` | translator + `calxgloss-llm` |
| scan read cache | `re/cache/{identity}/{sha256}/` | the seam |
| reviewer intent (skips, queue order/priority, unit + classification overrides) | `re/review/skips.json`, `re/review/queue_overlay.json`, `re/analysis/unit_overrides.json`, `re/analysis/classification_overrides.json` | web / CLI overlays (ADR-0003) |
| shim crates, baselines, accept/reject/patch records | `re/shims/`, `re/baseline/`, `re/accepts/`, `re/rejections/`, `re/patches/` | auto-shim, testgen, review actions |
| sandboxed verify projects | `scratch/…` (one Cargo project per verify call) | `calxgloss-verify` |
| translated output | `src/modules/{function}/translated.rs` on `main` | accepted merges |

**Scan descriptors & coverage** (ADR-0052/0053): each engine's identity is
its *scan row name*; its coverage record is stamped at scan time beside
provenance and names which declared *facets* it fell short of with an
*admission line*. Absent coverage reads as **unknown, never absent**;
empty findings under complete coverage and under an admission line must
never render alike.

**Git flow** (`calxgloss-git`): one branch per attempt,
`re/{binary}/{function}v{N}` (`crates/pipeline/calxgloss-git/src/lib.rs:5`);
success merges into `main` after a callee-first dependency check
(`DependencyChecker`), failure keeps the branch forever, and each commit
carries a structured justification block (attempt N, dependencies, test
counts, passing?, model, context size) (`lib.rs:10-11,18-31`).

## Automation surface

**CLI (`calxgloss-cli`)** — 29 subcommands
(`crates/interface/calxgloss-cli/src/cli_types.rs:196`):
`init · doctor · classify · translate · batch-translate · typesdb ·
typeinfer · algorithm · memory · libmatch · bdiff · sync · globalstate ·
consts · callback · controlflow · stringctx · apidetect · serialize ·
errhandling · floatsimd · config · verify · dashboard · auto · serve · live ·
auto-shim · gc` (updated: the REA baseline listed 23; ADR-0052 made each
engine's scan command ride its registry row, with `--show` reading the filed
document and an overwrite policy as refresh-cache). Config resolves flag →
env → TOML (`calxgloss.toml`) → default, records each value's *Source*, and
refuses unknown keys at parse (`crates/shared/GLOSSARY.md`). `doctor` is the
machine-gateable check: it *loads* the target through Kuna and reports
(ADR-0041).

There is **no `--json` CLI output mode** — prints are human-formatted
(`calxgloss-reports`); JSON output is roadmap P31, not shipped. There is
**no daemon**: `live` is a foreground process holding pipeline + server,
`serve` the review server alone. No Python bindings, no IPC protocol, no
command registry shared across surfaces — CLI, web API, and pipeline are
three separately-written surfaces over shared `calxgloss-types` records.

**Web API (`calxgloss-web`)** — Axum + React SPA, two routers by design
(ADR-0002): `shared_routes()` (`crates/interface/calxgloss-web/src/server/mod.rs:863`)
answers everywhere from persisted artifacts — dashboard, pipeline state
(honest empty on `serve`), unit detail/diff/attempts/attempts-diff/decomp,
accept / send-back / patch / skip / unskip, batch accept / send-back / skip,
queue overlay, LLM I/O, fault/token analytics (computed on demand, ADR-0005)
— while `live_only_routes()` (`mod.rs:1040`) carries in-flight state
(`/api/progress*`, WebSocket, pipeline control). Control is a shared state
machine over REST (ADR-0004): pause · resume · stop · start · restart ·
cancel-current, live-only, refusals naming the illegal transition,
pause/stop effective at the next unit boundary; WebSocket is server→client
only. All views are read-only over artifacts or overlays (ADR-0006), with
honest degradation everywhere.

## AI layer

- **LLM loop**: `calxgloss-llm`'s `LlmClient` speaks OpenAI-compatible HTTP
  to locally hosted models (Ollama, vLLM) — endpoint and model are config,
  there is no provider abstraction beyond base URLs (`client.rs`,
  `calxgloss-llm/src/lib.rs:3`). The **local** model is the premise: bad
  output is discarded, asking again is the normal path.
- **Prompts**: askama templates in `calxgloss-prompts`, one per context tier
  and failure-informed variant; orphaned templates are deleted, not parked
  (ADR-0008). The **evidence bundle** — one unit's evidence assembled from
  the engines' filed documents through a projector seam of registered
  projection rows (ADR-0048) — is the single render input of the bundle-fed
  templates, one shared section include per engine (ADR-0049); missing
  evidence just drops sections, a prompt never fails, and coverage /
  capability admission lines render beside what they qualify.
- **Verification of LLM output is compile + baseline tests only** (next
  section); no semantic critique, self-consistency sampling, or second-model
  review anywhere in the repo. **Retry policy** lives in the loop, strategies
  at the door, verdicts routing (ADR-0051); every prompt strategy, token
  count, and raw prompt/response is logged (`prompt_strategy_log.json`,
  `token_usage.json`, `llm_io/log.jsonl`). Fault monitors watch responses,
  not the model server.
- **What is not there** (verified by search, 2026-10-28): no MCP server or
  any MCP surface — the only "MCP" text is the deleted GhidraMCP client's
  historical note (`calxgloss-decomp/src/lib.rs:5`); no built-in
  chat/assistant in the web UI; no external-agent integration (no ACP, no
  plugin API); no model management beyond config endpoints; no arbitrary
  user questions against the program — the seam answers only its declared
  query families, and ad-hoc call-path/def-use (roadmap P29) is not started.

## Verification & correctness

- **Baseline capture** (`calxgloss-testgen`): PE export/import tables →
  signatures; FFI bindings (`extern "system"`); inputs from signatures +
  type evidence (boundary/typical/edge + one branch-targeted case per
  branch in the control-flow scan's inventory); **the original DLL is then
  executed under Wine** — `WineRunner` builds a per-function harness,
  cross-compiles for the DLL's architecture, runs it under Wine, and
  captures return values (`calxgloss-testgen/src/lib.rs:17,22-24`) —
  *updated*: the REA baseline's "runs the original DLL through FFI" predates
  the Wine lane. Global side-effect expectations come from the
  **global-state scan's records**, not from the run (same lib doc).
- **Verification** (`calxgloss-verify`): scaffold a sandboxed **scratch
  project** (throwaway Cargo project under `scratch/`, shared PAL stub crate),
  write the translated code + PAL stubs, `cargo check`, then run the
  behavioral tests against `re/baseline/.../baseline.json`; result is a
  data-only `VerificationResult` (compile status + per-test divergence) that
  travels the same shape to CLI, dashboard, and stored records.
- **Cross-platform output**: accepted code lands on `main` in the translated
  workspace; shim layers are generated crates (`re/shims/{dll}`,
  `auto-shim`); `calxgloss-pal` is a **mapping database** — each Windows API
  (Win32/GDI/DirectX) gets a PAL trait, suggested crate (`tiny-skia` etc.
  appear as "[PAL placeholder]" entries, `calxgloss-pal/src/data.rs:204-227`)
  and feature flags — not a compiled dependency (updated nuance vs the REA
  baseline).
- **Testing ground**: one checked-in, source-built fixture DLL (small x86-64
  PE with named exports, imports, strings, a jump-table switch) built by
  `calxgloss-testfixtures` and asserted on by the engine harnesses; no
  broader ground-truth corpus or eval harness (roadmap P33). There is **no
  conformance verdict** ("binary done") — queue-empty is not complete; that
  gap is roadmap P26 (obligation ledger + closure digest).

## Known gaps (from `docs/roadmap.md`, 2026-10-28)

Open tracks P21–P33, P40–P41, none started: first-class **unknown records**
(P21); **differential API-call trace** in the gate (P22); **mined inputs /
minidump replay** (P23); **scenario-capture baseline for EXEs** — the
FFI/Wine gate cannot touch EXE stdin/TUI/GUI behavior at all (P24);
**verification receipts** (P25); **fail-closed restitch conformance** with a
closure digest (P26); **hypothesis ledger** for stuck retries (P27);
**masked byte search** and **ad-hoc call-path/def-use** at the seam
(P28/P29); **PE artifact intelligence** (P30); **deep `doctor`** with JSON +
exit codes (P31); contributor **skill/manual** (P32); **whole-task
measurement** (P33). P40/P41 are verified product gaps: `api_aware` is set
but never reaches a prompt; the `re/analysis/` per-function artifacts the web
Mapping panel reads have no producer (issues #365/#366). Shipped since the
REA set, worth noting for comparison freshness: scan registry (ADR-0052),
projector/bundle/templates (ADR-0048/0049), pipeline assembly (ADR-0050),
attempt seam (ADR-0051), coverage honesty (ADR-0053), seam capability +
engine-identity cache key (ADR-0054/0055), `bdiff` version pairing, Wine
baseline execution, and four new crates (`globalstate`, `errhandling`,
`floatsimd`, `bdiff`) plus `calxgloss-reports`.

## What calxgloss is *not*

- Not interactive; no MCP surface; no arbitrary per-address queries.
- Not multi-format: PE32/PE32+ Windows targets only; managed PEs detected
  and parked, not translated (ADR-0044). No ELF, no non-x86 target
  architectures.
- No debugger, emulator, hooking/Frida, or byte patching; the original
  binary *executes* only for baseline capture under Wine in `testgen`.
- Output is *reconstructed Rust source*, an end product — not findings,
  pseudocode excerpts, or evidence reports (evidence documents are internal,
  rendered for prompts and review, not the deliverable).
- No comparison of *different programs* (bdiff pairs versions of the *same*
  binary); no capture/browser/app-packaging workflows.

## Capability summary table

| Domain | calxgloss capability | Key crates / ADRs |
|--------|----------------------|-------------------|
| Mission | PE/DLL directory → verified cross-platform Rust, unattended, human reviews units | `calxgloss-translator`; `docs/Calxgloss.md` |
| Analysis engine | Kuna only, fully in-process, seam-fixed boundary; capability report per query family | `calxgloss-kuna`, `calxgloss-decomp`; ADR-0039/0040/0041, 0054/0055 |
| Evidence | 15 whole-binary scan rows + 3 readers, confidence-scored readings, write-back, coverage honesty | `crates/evidence/*`; ADR-0009–0038, 0045–0047, 0052/0053 |
| Scheduling | registry-driven scan fan-out with latches + fuse; call-graph-ordered queue; version pairing | `calxgloss-translator` (`scan_registry.rs`), `calxgloss-callgraph`, `calxgloss-bdiff` |
| Prompting | 5 context tiers, evidence bundle → askama templates, bundle-fed section includes | `calxgloss-prompts`; ADR-0048/0049/0051 |
| LLM | local Ollama/vLLM, attempt seam, failure-informed retry strategies, fault monitors | `calxgloss-llm`, `calxgloss-translator/retry`; ADR-0051 |
| Persistence | record tree under `re/`, per-engine persistors, run logs; three-tier read cache keyed to binary hash + engine build | `calxgloss-decomp/cache`, `calxgloss-types`; ADR-0042/0043/0055 |
| Work history | git: attempt branches `re/{bin}/{fn}v{N}`, never deleted, structured justification commits, archive refs | `calxgloss-git`; principle 6 |
| Review | Axum+React: accept/send-back/patch/skip/batch, overlays for intent, queue controls, honest degradation | `calxgloss-web`; ADR-0002/0003/0004/0006 |
| Ops/automation | 29-command CLI, layered config, live/serve processes, REST control; no daemon, no MCP, no JSON CLI mode, no registry-unified surface | `calxgloss-cli`, `calxgloss-config`, `calxgloss-reports` |
| Verification | Wine-captured FFI baselines + scratch-project compile/test gate; PAL mapping DB + generated shims | `calxgloss-testgen`, `calxgloss-verify`, `calxgloss-pal` |
| Completion honesty | no conformance verdict yet; no unknowns ledger; no receipts | roadmap P21/P25/P26 |
| Testing ground | one source-built fixture DLL for the engine harnesses; no corpus/truth/eval layer | `calxgloss-testfixtures`; roadmap P33 |
