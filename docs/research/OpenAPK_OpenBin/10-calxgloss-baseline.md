# calxgloss capability baseline — the comparison anchor

> Part of the [OpenAPK/OpenBin overview](README.md). This is the fixed
> baseline every `3x-*` domain file compares OpenAPK/OpenBin against. Facts
> come from `README.md`, `docs/Calxgloss.md` (1,387 lines), `docs/data_flow.md`
> (973 lines, the `live` workflow), `docs/roadmap.md`, the 57 ADRs in
> `docs/adr/`, the per-context `GLOSSARY.md` files, and code spans verified in
> `crates/` on 2026-10-31. Where this differs from the [KRAKEN-era
> baseline](../kraken/10-calxgloss-baseline.md) (snapshot 2026-10-28), the repo
> is authoritative; changes are marked *updated*.

## What calxgloss is

A **Rust workspace** — 34 member crates in six groups under `crates/`
(`calxgloss` root, `shared/`, `integrations/`, `evidence/`, `pipeline/`,
`interface/`), 475 `.rs` files (updated from 431 at the KRAKEN snapshot) —
that reverse engineers a *directory of Windows binaries* (`target_dir`: EXEs
and DLLs, read-only) into a **cross-platform Rust workspace** with identical
observable behavior. It is a fully automated **pipeline + review harness**,
not an interactive tool and not a service: an LLM does the decompilation
work, evidence engines supply the structured evidence, verification proves
equivalence, and a human reviews each unit of work in a web UI — steering
happens at the level of runs, queues, and verdicts, never per address.

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

## Architecture & operating model

calxgloss is **local-first with no server substrate at all**. There is no
hosted service, no daemon, no database — persistence is plain JSON artifacts
on the filesystem plus git, and the only long-running process is the one the
operator starts (`live` = pipeline + review server together; `serve` =
review server alone; both foreground). The pipeline has no persistent state
between runs: a run **assembles itself** from the on-disk record tree and the
scan read cache — assembly lives only in the pipeline context, the settings
fold in the CLI, the constructor is assembly-internal (ADR-0050). Each run
is therefore *cold* for fresh bytes and *warm* on replay: the same binary
hash replays cached scan documents without touching the engine (pinned by
the translator's cold/warm scan-phase heartbeat test,
`crates/pipeline/calxgloss-translator/src/pipeline/tests.rs:3425`).

**Git is the work-history substrate** (`calxgloss-git`): one branch per
attempt, `re/{binary}/{function}v{N}` (`crates/pipeline/calxgloss-git/src/lib.rs:5`);
success merges into `main` after a callee-first dependency check
(`DependencyChecker`), failure keeps the branch forever, unmerged branches
are renamed into `refs/archive/` by `gc` (`git_manager.rs:1044,1101`), and
each commit carries a structured justification block (attempt N,
dependencies, test counts, passing?, model, context size) (`lib.rs:10-11,18-31`).
Reviewer intent is separate: **overlay files**, never derived artifacts
(ADR-0003).

The review UI is a **read-only web view over artifacts and overlays**
(ADR-0006) — see *Automation surface*. Everything is single-operator,
single-machine, single-workspace; there is no account, project, or share
concept anywhere (verified absence, see *Multi-user & collaboration*).

## The pipeline (`calxgloss-translator`)

**Unit of work** = one function or struct, keyed `{file}/{function}` with the
binary identity verbatim (`game_logic/DrawSprite`). **Run** = one continuous
session; **steering** (skip a unit, hold a binary, reprioritize) lands at a
**unit boundary**; the **queue** order comes from the call graph, edited only
by the reviewer's overlay (`crates/pipeline/GLOSSARY.md`). Per-function loop
(`docs/data_flow.md` §3.2.2):

```
read cache ▸ evidence warmup ▸ fetch ▸ prompt ▸ translate ▸ verify ▸ retry ▸ commit
```

- **Pre-batch scan phase** (`run_prebatch_scans`,
  `crates/pipeline/calxgloss-translator/src/pipeline/scan_phase.rs:273`,
  *updated* — the KRAKEN baseline's `pipeline.rs:2312-2370` citation moved):
  *15* evidence scans run over the whole binary before translation, driven by
  the **evidence-scan registry**: one `ScanDescriptor` row per engine
  (`scan_registry.rs:606-624`, table verified to hold exactly 15 rows) fanned
  out through a sliding window capped at 4 (`MAX_CONCURRENT_EVIDENCE_SCANS`,
  `pipeline/scan_phase.rs:33`; *updated* citation from `pipeline.rs:104`),
  with completion latches for declared `waits_for` edges (callback follows
  type-inference, `scan_registry.rs:637-650`), a cached-hit short-circuit
  ahead of any engine read, and a join-everything / cancel-nothing rule
  (ADR-0052). Each scan stamps its own **coverage record** beside its
  provenance (ADR-0053); a **skip-rate breaker** aborts a scan whose listing
  mostly fails to decompile. Then **binary-version pairing**
  (`calxgloss-bdiff`) compares this scan against surviving scans of the same
  binary identity (`re/cache/{identity}/` sibling hash directories,
  `version_pairing.rs:1-15`) so accepted translations carry across a binary
  update.
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

### Evidence engines (15 scans + 3 readers)

One crate per methodology; all read the loaded program through the seam. The
canonical set is the fifteen **scan rows** (`crates/evidence/GLOSSARY.md:10`,
`scan_registry.rs:606-624`, document paths at `docs/data_flow.md:186-200` —
all fifteen re-verified against the current table):

| Scan row | Crate | Extracts |
|----------|-------|----------|
| type-database | `calxgloss-typesdb` | Type Manager scans, vtable detection, struct inference; RTTI linking; nesting/flagging post-assembly passes (ADR-0009–0013) |
| type-inference | `calxgloss-typeinfer` | this-pointer, parameter-size detection, propagation callee→caller and caller→callee, param directions, mangling contracts, local/return type inference (ADR-0014–0019, 0045) |
| algorithm-recognition | `calxgloss-algorithm` | pattern-database matching, correlation detector over the call map; claims resolved by strongest evidence (ADR-0022–0025) |
| memory-lifecycle | `calxgloss-memory` | alloc/free pairing, open allocations, escape, leak, transfer, handle lifecycle, RC upgrade (ADR-0026–0031) |
| concurrency | `calxgloss-sync` | lock pairs, atomics, lock-order graphs, data-race readings, async runtime detection (ADR-0032–0034) |
| global-state | `calxgloss-globalstate` | per-function global read/write records; feeds baseline side-effect expectations and the data-race readings |
| constants | `calxgloss-consts` | bitflag groups, enum candidates, magic-number frequency; renders `consts/{binary}.json` |
| callback-detection | `calxgloss-callback` | function-pointer arrays, registration→call chains, closure contracts by injection (ADR-0035/0036) |
| control-flow | `calxgloss-controlflow` | switch-shaped if-else chains, self-recursion, state-variable chains, branch inventories |
| string-context | `calxgloss-stringctx` | nine-category string classification, per-function string maps, format-string inference |
| library-api | `calxgloss-apidetect` | import tables, library→crate mapping, per-function API summaries, portability divergence readings (ADR-0037); its per-function usage findings also **scope the API-call-trace cases** in the gate (ADR-0057) |
| serialization | `calxgloss-serialize` | byte-swap matching, bit-packing, magic-byte format sniffing (ADR-0038) |
| error-handling | `calxgloss-errhandling` | SEH frames, goto ladders, failure codes traveling the call map one hop (ADR-0046/0047) |
| float-simd | `calxgloss-floatsimd` | float/vector/SIMD usage flags |
| known-library | `calxgloss-libmatch` | known-library identification by body-signature matching of statically linked CRT/STL |

Readers with **no scan row** (`crates/evidence/GLOSSARY.md:10`):
`calxgloss-analysis` (DLL classification + shim suggestions; managed PEs
detected from the COM descriptor and parked as do-not-translate, ADR-0044,
`DoNotTranslate` disposition in `crates/shared/calxgloss-types/src/dll.rs`),
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
  history, still stated at `calxgloss-decomp/src/lib.rs:5-7`). One engine
  thread holds the loaded program, answering one call at a time;
  per-function budgets (instructions, seconds, memory) come from settings
  and refuse loud overspend. The engine reproduces Ghidra-flavored pseudo-C
  (`FUN_…`, `DAT_…`, `vftable`, WARNING preamble) as a *decompile dialect* —
  a format name, never a live component; the seam's noise filter strips
  shapes that would fake a structure and passes evidence shapes (spelled
  try/catch frames) byte for byte.
- **Scan read cache** (ADR-0042/0043, engine identity added by ADR-0055): a
  tiered read-through store — in-memory memo, then JSON documents under
  `re/cache/{binary identity}/{sha256 of binary}/` (`manifest.json` +
  per-read documents `decompile/{fn}.json`, `callers/{addr}.json`,
  `memory/{addr}-{len}.json`, …), then the engine
  (`calxgloss-decomp/src/cache.rs:14-26`). Validity is the key: the
  manifest records the binary hash, `CACHE_FORMAT_VERSION` (4,
  `cache.rs:140`), the program name, and the **identity of the engine build
  that produced the answers**, so an engine swap can never replay stale
  cache.
- **Seam capability report** (ADR-0054/0055): per query family the engine
  declares `answerable`/`unavailable` with one admission line each
  (`ScanSource::capability_report`, `scan_source.rs:648-660`; the cache
  passes it through byte-identical, `cache.rs:621`). Capability is live
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
log could log. There is also **no database** — verified: no sqlite/postgres/
sled/redb dependency anywhere in the workspace; every record is a JSON file
written through shared JSON-store machinery (`crates/shared/calxgloss-types/src/persist.rs`)
plus a per-engine **persistor** (`persist.rs` in each evidence crate).

The on-disk memory of an effort is the **record tree** under the workspace's
`re/` (full tree at `docs/data_flow.md` §6, lines 675-777 — summary):

| Artifact | Path | Written by |
|----------|------|-----------|
| classification records | `re/classify/{binary}.json` | `classify` (committed to `main`) |
| per-engine scan documents (+ rendered `.rs`/`.toml` for typesdb/consts/apidetect) | `re/analysis/{engine}/{binary}.json` | each engine's own *persistor* |
| version-pairing documents | `re/analysis/bdiff/{binary}-{old}-{new}-sha256.json` | `bdiff` (`bdiff/src/persist.rs:8,42`) |
| call graph | `re/analysis/{binary}_call_graph.json` | analysis warmup |
| per-function analysis artifact (tagged `windows_apis`) | `re/analysis/{binary}/{function}.json` | the translate path, per translated unit (P41 tracer, issue #379) |
| run logs (fault, token usage, prompt strategy, LLM I/O) | `re/analysis/{fault_log,token_usage,prompt_strategy_log}.json`, `re/analysis/llm_io/log.jsonl` | translator + `calxgloss-llm` |
| **unknown ledger** (per binary) + **unknown resolutions** (reviewer-owned) | `re/unknowns/{binary identity}.json`, `re/review/unknown_resolutions.json` | pipeline / review actions (ADR-0056, *new*) |
| scan read cache | `re/cache/{identity}/{sha256}/` | the seam |
| reviewer intent (skips, queue order/priority, unit + classification overrides, unknown resolutions) | `re/review/{skips,queue_overlay,unknown_resolutions}.json`, `re/analysis/{unit_overrides,classification_overrides}.json` | web / CLI overlays (ADR-0003) |
| shim crates, baselines, accept/reject/patch records | `re/shims/`, `re/baseline/`, `re/accepts/{dll}/{function}/v{N}.json`, `re/rejections/…`, `re/patches/` | auto-shim, testgen, review actions (`docs/data_flow.md:827-828`) |
| sandboxed verify projects | `scratch/…` (one Cargo project per verify call) | `calxgloss-verify` |
| translated output | `src/modules/{function}/translated.rs` on `main` | accepted merges |

**Scan descriptors & coverage** (ADR-0052/0053): each engine's identity is
its *scan row name*; its coverage record is stamped at scan time beside
provenance and names which declared *facets* it fell short of with an
*admission line*. Absent coverage reads as **unknown, never absent**;
empty findings under complete coverage and under an admission line must
never render alike.

**Unknown records** (ADR-0056, P21 shipped 2026-10-29, issues #367–#377):
every admitted gap becomes a **named record**, not prose — id
`{binary}/{function or -}/{kind}/{source slot}` derived deterministically
(never from the wording lines), one question, one severity, the evidence
that would close it. Two documents, two owners, joined only at read time:
the pipeline owns the ledger (`re/unknowns/<binary identity>.json`, replaced
outright per batch in scan order — a derived set, not an append log), the
reviewer owns resolutions (keyed by unknown id, overlay-surviving, beside
skips and queue overlay). The honesty lineage is turned on its own
artifact: the translator folds each filed document's coverage admissions,
each seam `unavailable` family, each retry decision, and each unassessed
verification dimension into residue modules —
`coverage_residue.rs`, `seam_residue.rs`, `ladder_residue.rs`,
`verification_residue.rs` (e.g. `coverage_residue.rs:1-13`: every facet
stamped `partial`/`unavailable` becomes one `coverage_facet` record; the
admission on disk is the only write site). Absent ledger = zero unknowns,
never "unknown has no unknowns".

## Automation surface

**CLI (`calxgloss-cli`)** — 29 subcommands (count re-verified at
`crates/interface/calxgloss-cli/src/cli_types.rs:196-197`):
`init · doctor · classify · translate · batch-translate · typesdb ·
typeinfer · algorithm · memory · libmatch · bdiff · sync · globalstate ·
consts · callback · controlflow · stringctx · apidetect · serialize ·
errhandling · floatsimd · config · verify · dashboard · auto · serve · live ·
auto-shim · gc`. Each engine's scan command rides its registry row, with
`--show` reading the filed document and an overwrite policy as refresh-cache
(ADR-0052). Config resolves flag → env → TOML (`calxgloss.toml`) → default,
records each value's *Source*, and refuses unknown keys at parse
(`crates/shared/GLOSSARY.md`). `doctor` is the machine-gateable check: it
*loads* the target through Kuna, reports program identity, and **exits
non-zero so CI can gate on it** (ADR-0041, `cli_types.rs` Doctor doc) —
though today there is no CI to gate (`docs/roadmap.md` P42).

There is **no `--json` CLI output mode** — prints are human-formatted
(`calxgloss-reports`); JSON output is roadmap P52 (folded in from P31).
There is **no daemon**: `live` is a foreground process holding pipeline +
server, `serve` the review server alone. No Python bindings, no IPC
protocol, no command registry shared across surfaces — CLI, web API, and
pipeline are three separately-written surfaces over shared
`calxgloss-types` records.

**Web API (`calxgloss-web`)** — Axum server + static HTML/JS/CSS frontend
(*updated, corrected*: the KRAKEN-era baseline called it a "React SPA" and
`docs/Calxgloss.md:30-31` still says "Axum + React SPA" — that doc line is
stale; the shipped UI is vanilla ES-module JS under
`crates/interface/calxgloss-web/static/` (+ `static/js/`, 20+ view modules,
no `package.json`, no build step anywhere in the repo; the crate doc
`calxxgloss-web/src/lib.rs:1` says "API layer + static HTML/JS/CSS
frontend"). Two routers by design (ADR-0002): `shared_routes()`
(`crates/interface/calxgloss-web/src/server/mod.rs:865`, *updated* from
:863) answers everywhere from persisted artifacts — index, dashboard
(now carrying each unit's open unknown records, P21 #376), pipeline state
(honest empty on `serve`), unit detail/diff/decomp/accept/patch/skip/
unskip, **unknown resolve/dismiss/reopen**
(`/api/units/{id}/unknowns/{unknown_id}/{resolve,dismiss,reopen}`,
`mod.rs:898-906`, *new*), queue + next, LLM I/O (+clear), faults
(+summary/trend), binaries list/detail, dependency graph, GC candidates/
archive, `/health`, server status/shutdown/restart — while
`live_only_routes()` (`mod.rs:1060`, *updated* from :1040) carries
in-flight state (`/api/progress`, WebSocket `/api/events/upgrade`,
pipeline pause/resume/stop/start, `/api/scope`). Control is a shared state
machine over REST (ADR-0004): pause · resume · stop · start · restart ·
cancel-current, live-only, refusals naming the illegal transition,
pause/stop effective at the next unit boundary; WebSocket is server→client
progress only. All GET views are read-only over artifacts or overlays
(ADR-0006), with honest degradation everywhere; the POSTs are review
dispositions that write overlays and git actions, not free-form edits.

## AI layer

- **LLM loop**: `calxgloss-llm`'s `LlmClient` speaks OpenAI-compatible HTTP
  — endpoint, model, and an **optional API key** are config
  (`LlmConfig.api_key`, `client.rs:67,104`; `CALXGLOSS_LLM_URL` /
  `_MODEL` / `_API_KEY` env layer, `calxgloss-config/src/layers.rs:70-72` —
  *updated*: the key option is newer than the KRAKEN-era baseline's
  "endpoint and model are config"). The **local** model is still the
  premise (Ollama, vLLM, llama.cpp); there is no provider abstraction
  beyond the OpenAI-compatible base URL, no routing, no fallback chain.
  Bad output is discarded; asking again is the normal path.
- **Prompts**: askama templates in `calxgloss-prompts/templates/`
  (`minimal_translate.j2` … `full_module_translate.j2`, `escalate.j2`,
  `edge_case.j2`, `failure_fix.j2` …), one per context tier and
  failure-informed variant; orphaned templates are deleted, not parked
  (ADR-0008). The **evidence bundle** — one unit's evidence assembled from
  the engines' filed documents through a projector seam of registered
  projection rows (`crates/pipeline/calxgloss-translator/src/evidence_projector/`,
  ADR-0048) — is the single render input of the bundle-fed templates, one
  shared section include per engine (ADR-0049); missing evidence just drops
  sections, a prompt never fails, and coverage / capability admission
  lines render beside what they qualify.
- **Usage & cost**: every prompt strategy, token count, and raw
  prompt/response is logged (`prompt_strategy_log.json`,
  `token_usage.json` — per-attempt `TokenUsageEntry`/aggregates in
  `calxgloss-types/src/token_usage.rs:49-257`, `llm_io/log.jsonl`) and the
  web dashboard renders fault/token analytics computed on demand
  (ADR-0005). **Tokens only — there is no cost tracking**: no pricing
  model, no budget, no per-attempt money figure (roadmap P50 open). Fault
  monitors watch responses, not the model server.
- **Verification of LLM output is compile + baseline tests only** (next
  section); no semantic critique, self-consistency sampling, or second-model
  review anywhere in the repo. **Retry policy** lives in the loop,
  strategies at the door, verdicts routing (ADR-0051).
- **What is not there** (verified by search, 2026-10-31): no MCP server or
  any MCP surface — the only "MCP" text is the deleted GhidraMCP client's
  historical note (`calxgloss-decomp/src/lib.rs:5`); no built-in
  chat/assistant or Q&A surface in the web UI; no agentic tool loop for
  users; no external-agent integration (no ACP, no plugin API); no model
  management beyond config endpoints; **no arbitrary user questions against
  the program** — the seam answers only its declared query families, and
  ad-hoc call-path/def-use (roadmap P29) is not started.

## Verification & correctness

- **Baseline capture** (`calxgloss-testgen`): PE export/import tables →
  signatures; FFI bindings (`extern "system"`); inputs from signatures +
  type evidence (boundary/typical/edge + one branch-targeted case per
  branch in the control-flow scan's inventory); **the original DLL is then
  executed under Wine** — `WineRunner` builds a per-function harness,
  cross-compiles for the DLL's architecture, runs it under Wine, and
  captures return values (`calxgloss-testgen/src/lib.rs:17,22-24`).
  Global side-effect expectations come from the **global-state scan's
  records**, not from the run (same lib doc).
- **API-call trace capture** (*new, P22 / ADR-0057, shipped 2026-10-31*):
  the Wine harness also generates an **IAT interposer** that records the
  ordered Win32 calls the original made during each baseline case
  (`testgen/src/wine/harness.rs:438-446,515`), scoped per unit by the
  apidetect scan's per-function API usage (the unit's **API roster**).
- **Verification** (`calxgloss-verify`): scaffold a sandboxed **scratch
  project** (throwaway Cargo project under `scratch/`, shared PAL stub
  crate, `calxgloss-verify/src/lib.rs:4-9`), write the translated code +
  PAL stubs, `cargo check`, then run the behavioral tests against
  `re/baseline/.../baseline.json`. The `VerificationResult` now carries
  **two verdict dimensions** — value divergence and **API-call trace**
  (`trace_divergence_index: Option<usize>`,
  `trace_assessed_tests` count, `calxgloss-types/src/verification.rs:42-105`).
  The trace verdict is **ordered containment, not sequence equality**: the
  expected names must appear inside the actual route in order, extras on
  the actual side never fail a case, skipped/permuted/under-repeated
  observed calls still fail, a case with no recorded trace is
  **unassessed** (silence is never a pass), and the divergence index names
  where the hunt for the first unhonoured call gave up (ADR-0057). The
  honesty is deliberate: the IAT capture is structurally blind to COM
  vtable calls, so the gate judges every unit under the honesty the
  weakest capture supports — extras can no longer be caught at the trace
  dimension (ADR-0057's accepted loss). A trace divergence routes into the
  fix prompt exactly like a value failure.
- **Cross-platform output**: accepted code lands on `main` in the translated
  workspace; shim layers are generated crates (`re/shims/{dll}`,
  `auto-shim`); `calxgloss-pal` is a **mapping database** — each Windows API
  (Win32/GDI/DirectX) gets a PAL trait, suggested crate (`tiny-skia`
  appear as "[PAL placeholder]" entries, `calxgloss-pal/src/data.rs:204-227`)
  and feature flags — not a compiled dependency.
- **Testing ground**: one checked-in, source-built fixture DLL (small x86-64
  PE with named exports, imports, strings, a jump-table switch, and the
  trace-scope exports added for P22) built by `calxgloss-testfixtures` and
  asserted on by the engine harnesses; no broader ground-truth corpus or
  scored eval harness (roadmap P33). There is **no conformance verdict**
  ("binary done") — queue-empty is not complete; that gap is roadmap P26
  (obligation ledger + closure digest). P21's unknown ledger is the record
  substrate P26 will gate on.

## Multi-user, collaboration & publishing — verified absence

OpenAPK/OpenBin's core value is hosted collaboration; calxgloss has
**none of it, by construction**. Verified absence on 2026-10-31:

- **No authentication or user identity anywhere.** grep for
  login/password/jwt/oauth/oidc/tenant/multi-user/collaboration in
  `crates/interface/calxgloss-web/src` returns nothing relevant (only
  "authoritative" prose and a git commit *author* read in `gc.rs:249`). The
  web server binds `0.0.0.0:{port}` (`server/mod.rs:1297`) with **no auth
  and no ACL** — single-operator trust zone; exposing it is a real,
  currently unmitigated weakness. `SessionManager` is a WebSocket fan-out
  session, not a user session.
- **No accounts, projects, sharing, forking, publishing, comments,
  notifications, presence, or social layer** — no such concept exists in
  types, routes, or the frontend.
- **No multi-tenancy substrate**: no database, no object store, no queue —
  persistence is the local `re/` record tree plus git (see *Data model*).
  One workspace = one effort = one operator.
- **No publishing/export story**: `calxgloss-reports` is dashboard/CLI
  rendering, not report authoring or document sharing; there is nothing
  resembling a shareable writeup, CTF, or public-read surface. The
  deliverable is the translated Rust workspace itself.
- **No API tokens for third parties**: the REST API is unauthenticated
  local control, not a public API with keys or scopes.

## QA & CI

- **Tests**: ~4,700 inline `#[test]`/`#[tokio::test]` functions across the
  workspace plus 51 integration test files under per-crate `tests/`,
  including end-to-end runs: web e2e (`calxgloss-web/tests/e2e.rs`), a
  full Kuna scan over the fixture DLL (`calxgloss-web/tests/kuna_scan_e2e.rs`),
  and a testgen DLL baseline e2e (`calxgloss-testgen/tests/dll_e2e.rs`);
  contract pins like the per-function artifact e2e (#380) and the
  unknown-id pins (ADR-0056).
- **No CI, verified**: no `.github/`, no `*.yml`/`*.yaml` pipeline, no
  Makefile/justfile anywhere in the repo — matching roadmap P42's own
  words ("calxgloss has no CI at all (no `.github/ anywhere)"). Everything
  above runs by hand. P42 (CI foundation) is not started; the scored-eval
  and drift-check gates (P33, P46, P52 exit-criterion tests) all want it
  as substrate.
- **Eval honesty**: no scored corpus or measurement harness (P33 open,
  with KRAKEN's scored-truth eval folded onto it as its missing oracle);
  `token_usage` logging exists but no cost accounting (P50).

## Known gaps (from `docs/roadmap.md`, 2026-10-31)

**Shipped since the KRAKEN-era baseline** (both after 2026-10-28, so the
older baseline's gap list is stale): **P21 first-class unknown records**
(ADR-0056, issues #367–#377) and **P22 API-call trace dimension in the
gate** (ADR-0057, issues #382–#389) — together unblocking P26/P27 on their
record side. The KRAKEN comparison itself fed a new roadmap block:
**P42–P52** (CI foundation, fail-closed sandbox for model output, baseline
capture provenance + live-oracle, typed untrusted data on the prompt path,
engine-seam contract tests + scan-output drift checks, staleness by content
hash, mechanical pre-refusal, counterexample ordering + verdict honesty,
cost metering, evidence-computed confidence, small-discipline bundle) —
all not started.

Open tracks **P23–P33, P40, P42–P52**, none started: **mined inputs /
minidump replay** (P23); **scenario-capture baseline for EXEs** — the
FFI/Wine gate cannot touch EXE stdin/TUI/GUI behavior at all (P24);
**verification receipts** (P25); **fail-closed restitch conformance** with
a closure digest (P26); **hypothesis ledger** for stuck retries (P27);
**masked byte search** and **ad-hoc call-path/def-use** at the seam
(P28/P29); **PE artifact intelligence** (P30); deep `doctor` with JSON +
exit codes (P31); contributor skill/manual (P32); **whole-task
measurement** (P33). P40 is a verified product gap: `api_aware` is set but
never reaches a prompt (#365). P41 is 🔶 in progress: the translate path
files the per-function artifact at `re/analysis/{binary}/{function}.json`
with body-scoped `windows_apis` (#379), contract pinned e2e (#380), stale
notes retired (#381); the full `FunctionInfo` record stays open (#366).

## What calxgloss is *not*

- Not interactive; no MCP surface; no arbitrary per-address queries.
- Not multi-format: **PE32/PE32+ Windows x86 targets only**; managed PEs
  detected and parked, not translated (ADR-0044). No ELF, no Mach-O, no
  APK/DEX, no non-x86 target architectures — the OpenAPK/OpenBin target
  universe (Android APKs, ELF, Mach-O) is entirely outside calxgloss's
  scope.
- Not hosted, not multi-user, not collaborative (section above); no
  upload/download flow — the binaries are already on disk in `target_dir`,
  read-only.
- No debugger, emulator, hooking/Frida, or byte patching; the original
  binary *executes* only for baseline capture under Wine in `testgen`
  (now with an IAT interposer for trace capture — observation, not
  interactive instrumentation).
- Output is *reconstructed Rust source*, an end product — not findings,
  pseudocode excerpts, or evidence reports (evidence documents are internal,
  rendered for prompts and review, not the deliverable); no
  report-authoring or research-publishing workflow.
- No comparison of *different programs* (bdiff pairs versions of the *same*
  binary).

## Capability summary table

| Domain | calxgloss capability | Key crates / ADRs |
|--------|----------------------|-------------------|
| Mission | PE/DLL directory → verified cross-platform Rust, unattended, human reviews units | `calxgloss-translator`; `docs/Calxgloss.md` |
| Operating model | local foreground CLI/pipeline; run assembles from artifacts + read cache; no daemon, no DB, no server substrate | ADR-0050; `crates/shared/calxgloss-types/src/persist.rs` |
| Analysis engine | Kuna only, fully in-process, seam-fixed boundary; capability report per query family | `calxgloss-kuna`, `calxgloss-decomp`; ADR-0039–0041, 0054/0055 |
| Evidence | 15 whole-binary scan rows + 3 readers, confidence-scored readings, write-back, coverage honesty | `crates/evidence/*`; ADR-0009–0038, 0045–0047, 0052/0053 |
| Scheduling | registry-driven scan fan-out with latches + fuse; call-graph-ordered queue; version pairing | `calxgloss-translator` (`scan_registry.rs`), `calxgloss-callgraph`, `calxgloss-bdiff` |
| Prompting | 5 context tiers, evidence bundle → askama templates, bundle-fed section includes | `calxgloss-prompts`; ADR-0048/0049/0051 |
| LLM | OpenAI-compatible local models (url/model/optional key), attempt seam, failure-informed retry, fault monitors; token logs, no cost tracking | `calxgloss-llm`, `calxgloss-translator/retry`; ADR-0051; P50 open |
| Persistence | record tree under `re/`, per-engine persistors, run logs; three-tier read cache keyed to binary hash + engine build | `calxgloss-decomp/cache`; ADR-0042/0043/0055 |
| Work history | git: attempt branches `re/{bin}/{fn}v{N}`, never deleted, structured justification commits, archive refs | `calxgloss-git`; principle 6 |
| Review | Axum + static-JS SPA: accept/send-back/patch/skip/batch, unknown resolve/dismiss/reopen, overlays for intent, honest degradation | `calxgloss-web`; ADR-0002/0003/0004/0006, 0056 |
| Gap honesty | unknown ledger + reviewer resolutions with deterministic ids; residue modules run the honesty doctrine over coverage, capability, retry, verification admissions | ADR-0056; `re/unknowns/`, `re/review/unknown_resolutions.json` |
| Verification | Wine-captured FFI baselines + ordered API-call trace (IAT interposer, ordered containment) + scratch-project compile/test gate; PAL mapping DB + generated shims | `calxgloss-testgen`, `calxgloss-verify`, `calxgloss-pal`; ADR-0057 |
| Completion honesty | no conformance verdict yet; no receipts; ledger substrate now exists | roadmap P25/P26 |
| Collaboration / publishing | **none** — no auth, users, projects, sharing, reports, or multi-tenancy (verified) | section *Multi-user & collaboration* |
| Ops/automation | 29-command CLI, layered config, live/serve processes, REST control; no daemon, no MCP, no JSON CLI mode, no registry-unified surface | `calxgloss-cli`, `calxgloss-config`, `calxgloss-reports` |
| QA | ~4.7k inline tests + e2e over the fixture DLL; **no CI at all** (verified; P42) | `calxgloss-testfixtures`; roadmap P42/P33 |
