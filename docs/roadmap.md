# Calxgloss Roadmap — 16 Methodology Tracks

> **Purpose:** index of all 17 tracks (11 analysis crates + 5 web UI phases +
> 1 infrastructure track) — status, dependencies, and what's next. This is the
> *roadmap*, not the plan of record for active work.
>
> **Where plans live:** when a track is picked up, its detailed plan is
> published to GitHub Issues (`scriptandcompile/calxgloss`) via `/to-spec` →
> `/to-tickets` (tickets carry native blocking links + triage labels), and the
> epic link is added to the status matrix below. `/implement` works the
> tickets; `CHANGELOG.md` stays the record of what shipped.
>
> **History:** the full original plan — every phase checklist with its
> completion notes — is frozen at
> `docs/archive/step_by_step-2026-10-05.md`.
>
> **Bridge decision (2026-10-03):** the Ghidra bridge is
> [bethington/ghidra-mcp](https://github.com/bethington/ghidra-mcp) v6.0.0,
> load port 8089 — see `docs/adr/0001-bethington-ghidra-mcp-bridge.md`; client
> endpoint mapping and record formats in `docs/ghidra_endpoint_map.md`.

## How a track gets built

1. Pick the next unblocked track from the matrix (table order = priority).
2. `/to-spec` — synthesize the track summary here (plus its archive section)
   into a spec issue.
3. `/to-tickets` — decompose into tracer-bullet tickets with blocking edges;
   label `ready-for-agent`.
4. `/implement` — drive the tickets (tdd + code-review per ticket).
5. Update this matrix when a phase completes.

The analysis track (P4–P11) and the web track (W0–W4) are independent and can
run in parallel. Within the web track, W0 comes first; W1–W4 depend only on
backend pipeline data, not on the analysis crates. Test counts in the archive
are indicative targets, not exact requirements.

## Status matrix

| # | Track | Crate | Effort | Status | Next step | Epic |
|---|-------|-------|--------|--------|-----------|------|
| P1 | Data Structure Recovery | `calxgloss-typesdb` | 4–6 wk | ✅ Phases 0a–4 done (2026-10-03) | Phase 5 future items | — |
| P2 | Type Inference & Propagation | `calxgloss-typeinfer` | 3–4 wk | ✅ Phases 0–4 done (2026-10-04) | Phase 5 future items (incl. Ghidra write-back) | — |
| P3 | Algorithm Recognition | `calxgloss-algorithm` | 4–6 wk | ✅ Phases 0–4 done (2026-10-05) | Phase 5 future items | — |
| P4 | Memory Lifecycle / RAII | `calxgloss-memory` | 3–4 wk | ✅ Phases 0–4 done (2026-10-05) | Phase 5 future items | — |
| P5 | Concurrency & Synchronization | `calxgloss-sync` | 2–3 wk | ✅ Phases 0–4 done (2026-10-06) | Phase 5 future items | [#11](https://github.com/scriptandcompile/calxgloss/issues/11) |
| P6 | Callback / Function Pointer Tables | `calxgloss-callback` | 2–3 wk | ✅ Phases 0–4 done (2026-10-06) | Phase 5 future items | [#12](https://github.com/scriptandcompile/calxgloss/issues/12) |
| P7 | Control Flow Pattern Recognition | `calxgloss-controlflow` | 2–4 wk | ✅ Phases 0–4 done (2026-10-06) | Phase 5 future items | [#13](https://github.com/scriptandcompile/calxgloss/issues/13) |
| P8 | String & Configuration Context | `calxgloss-stringctx` | 1–2 wk | ✅ Phases 0–4 done (2026-10-06) | Phase 5 future items | [#15](https://github.com/scriptandcompile/calxgloss/issues/15) |
| P9 | Library & API Identification | `calxgloss-apidetect` | 1–2 wk | ✅ Phases 0–4 done (2026-10-06) | Phase 5 future items | [#17](https://github.com/scriptandcompile/calxgloss/issues/17) |
| P10 | Constants & Enum Recovery | `calxgloss-consts` | 2–3 wk | ✅ Phases 0–4 done (2026-10-06) | Phase 5 future items | [#14](https://github.com/scriptandcompile/calxgloss/issues/14) |
| P11 | Endianness & Serialization | `calxgloss-serialize` | 1–2 wk | ✅ Phases 0–4 done (2026-10-06) | Phase 5 future items | [#16](https://github.com/scriptandcompile/calxgloss/issues/16) |
| W0 | Web UI Foundation & Phase Progress | `calxgloss-web` | 2–3 wk | 🔶 in progress | `/implement` from [#55](https://github.com/scriptandcompile/calxgloss/issues/55) | [#55](https://github.com/scriptandcompile/calxgloss/issues/55) |
| W1 | Web UI Status & Visibility | `calxgloss-web` | 1–2 wk | ⬜ not started | after W0 Phases 0–1 | — |
| W2 | Web UI Process Control | `calxgloss-web` + types/translator | 3–4 wk | ⬜ not started | after W0 Phase 1 | — |
| W3 | Web UI Historical & Analytical Views | `calxgloss-web` | 2–3 wk | ⬜ not started | after W0 Phases 1–2 | — |
| W4 | Web UI New Views | `calxgloss-web` | 2–3 wk | ⬜ not started | after W0 P1, W1 P0–1 | — |

Legend: ✅ MVP phases complete (Phase 5 "future" items may remain) · 🔶 in
progress · ⬜ not started.

## Infrastructure tracks

| # | Track | Crate | Effort | Status | Next step | Epic |
|---|-------|-------|--------|--------|-----------|------|
| G1 | Ghidra Lifecycle Integration | `calxgloss-ghidra` + `calxgloss-cli` | 3–4 wk | ⬜ not started | spec from design doc (P0–P4 phasing) | — |

G1 design doc: `docs/ghidra_integration.md` — preflight, headless server
spawn/supervise, project bootstrap, `doctor --fix` install path. Endpoint
reference: `docs/ghidra_endpoint_map.md`.

## Done tracks — future items (Phase 5)

- **P1 `calxgloss-typesdb`** — cross-reference clustering, heuristic struct
  naming, nested structs/unions, STL type detection, Rust codegen output for
  recovered structs. *(Write-back wrappers were deferred to P2 Phase 5.)*
- **P2 `calxgloss-typeinfer`** — cross-function call-site propagation, integer
  bit-pattern analysis, C++ mangling analysis, local-variable and return-type
  inference, **write inferred types back into Ghidra** (`set_function_prototype`/
  `set_local_variable_type`; create missing types first via `create_struct`/
  `create_enum`/`create_typedef` — the bridge supports it, see ADR-0001).
- **P3 `calxgloss-algorithm`** — confidence scoring improvements, dynamic
  (JSON) pattern database, multi-function correlation, parallelize across
  functions.

Full completion notes for each phase: archive §17.1–17.4.

## P4 — Memory Lifecycle / RAII (`calxgloss-memory`)

Detectors done (2026-10-05): allocator/deallocator pair tracking (→ `Box<T>`/
stack), handle lifetimes (→ RAII guard + `Drop`), reference counting (→ `Rc<T>`/
`Arc<T>`); 132 unit tests. **Phase 4 — pipeline integration done (2026-10-05)**,
following the exact shape P3 shipped (archive §17.4 Phase 4).

Done: `MemoryResult` + shared `ScanMetadata` per-binary document type (with the
`MemoryFinding` union, serde-tagged by kind); `MemoryPersistor` →
`re/analysis/memory/{dll}.json` (wrapping `calxgloss_types::persist::JsonStore`,
typesdb convention); `MemoryEngine` scan orchestration (engine generic over a
`ScanSource` source trait — `functions()` + `decompile(name)`, implemented for
`GhidraClient`, canned-source tests; one sequential pass, one decompile per
function read by all three detectors, findings in scan order, skip-with-warning
on body-fetch failure, only a failed listing aborts, per-detector name sets
swappable whole); `calxgloss memory --dll <dll>` scan+save wired to the engine
and `--show` printing the cached document (target-dir-exempt);
`calxgloss-memory` re-exported from the meta-crate; 5 scan-to-disk integration
tests; `ensure_memory_detection(dll)` pre-analysis at the top of `batch_translate`
and `batch_translate_from_callgraph` (`exists()` cache check → skip, else
`MemoryEngine::scan` + save to `re/analysis/memory/{dll}.json`; missing workspace,
unreachable Ghidra server, or a failed save only log a warning and the batch
proceeds; 5 unit tests, with a canned in-test GhidraMCP server driving the
scan-to-save and failed-save paths); `extract_memory_hints()` in
`calxgloss-translator/src/retry/helpers.rs` reads the cached document on the
retry path (only the target function's findings; missing workspace, missing
cache, or corrupt document degrade to empty; 5 unit tests) and the escalate
template renders a MEMORY LIFECYCLE section beside RECOGNIZED ALGORITHMS
(`MemoryInfo` prompt data in `calxgloss-prompts`, `From<&MemoryFinding>`
conversion on the finding in the memory crate per the typesdb/typeinfer/
algorithm convention; 2 template unit tests, 1 conversion unit test, 1
fixture-document-to-prompt integration test); **follow-up (issue #6)**:
`default_allocators()`/`default_deallocators()` now carry both spellings
Ghidra has written the C++ operators in — the demangled dot form
(`operator.new`/`operator.delete`) and the live 6.x decompiler's
underscore form (`operator_new`/`operator_delete`, array `[]` variants
included) — after the live eqmain scan's whole-name matching paired
nothing at the plainly visible `operator_new` sites; 3 new unit tests plus
extended coverage of the two standard-set tests;
clippy + fmt clean.

Dependencies: soft on P2 (done).

## P5 — Concurrency & Synchronization (`calxgloss-sync`)

Done (2026-10-06), following the exact shape P4 shipped (archive §5 + §17.5).

Done: `SyncResult` + shared `ScanMetadata` per-binary document type (with the
`SyncFinding` union, serde-tagged by kind — `mutex`/`atomic`/`thread`);
`SyncPersistor` → `re/analysis/sync/{dll}.json` (wrapping
`calxgloss_types::persist::JsonStore`, memory convention); `SyncEngine` scan
orchestration (engine generic over a `ScanSource` source trait — `functions()`
+ `decompile(name)`, implemented for `GhidraClient`, canned-source tests; one
sequential pass, one decompile per function read by all three detectors,
findings in scan order — mutex pairings, then atomic calls, then thread spawns
— skip-with-warning on body-fetch failure, only a failed listing aborts,
per-detector name sets swappable whole); mutex/lock pairing (`EnterCriticalSection`
→ `std::sync::Mutex<T>`, `pthread_mutex_lock` → `parking_lot::Mutex<T>` — no
poisoning to translate — and the `pthread_rwlock_*` trio → `std::sync::RwLock<T>`,
acquire binds the lock variable, release closes the latest open acquire of it);
atomics (`InterlockedIncrement`/`Decrement` → `AtomicU32`,
`__atomic_fetch_add`/`__sync_fetch_and_add` → `AtomicU64` as a documented
default; one finding per call site); threading (`CreateThread`/
`std::thread::spawn` bind the handle by return value, `pthread_create` by first
argument; joined by `WaitForSingleObject`/`pthread_join`/the demangled
`std::thread::JoinHandle::join` → `std::thread::spawn` at 70, unjoined →
`tokio::spawn` at 60); 104 unit tests;
`calxgloss sync --dll <dll>` scan+save wired to the engine and `--show`
printing the cached document (target-dir-exempt); `calxgloss-sync` re-exported
from the meta-crate; 6 scan-to-disk integration tests;
`ensure_sync_detection(dll)` pre-analysis at the top of `batch_translate` and
`batch_translate_from_callgraph` (`exists()` cache check → skip, else
`SyncEngine::scan` + save to `re/analysis/sync/{dll}.json`; missing workspace,
unreachable Ghidra server, or a failed save only log a warning and the batch
proceeds; 5 unit tests, reusing the canned in-test GhidraMCP server);
`extract_concurrency_hints()` in `calxgloss-translator/src/retry/helpers.rs`
reads the cached document on the retry path (only the target function's
findings; missing workspace, missing cache, or corrupt document degrade to
empty; 5 unit tests) and the escalate template renders a CONCURRENCY section
beside MEMORY LIFECYCLE (`ConcurrencyInfo` prompt data in `calxgloss-prompts`,
`From<&SyncFinding>` conversion on the finding in the sync crate per the
memory convention; 2 template unit tests, 1 conversion unit test, 1
fixture-document-to-prompt integration test); clippy + fmt clean.
Phase 5 future: data-race analysis, lock ordering, async runtime, TLS, futex.

Dependencies: soft on P2 (done).

## P6 — Callback / Function Pointer Tables (`calxgloss-callback`)

Soft dependencies on P1+P2. MVP: function-pointer array detection
(`*(handlers[i])(args)` → `Box<dyn Fn(...)>`); callback registration
(`register_callback(fp)` → closures); jump tables (`jmp [table + index*N]` →
`match`). Phases: 0 setup → 1 fp arrays → 2 registration → 3 jump tables →
4 integration → 5 future (callback chains, plugin architectures, event
systems). Archive §6 + §17.6.

## P7 — Control Flow Pattern Recognition (`calxgloss-controlflow`)

Soft dependency on P2. MVP: switch detection (if-else chains, ≥3 cases,
dispatch-table suggestion at 10+); recursion (self-calls, tail-call status);
state machines (state-variable if-else chains, named `STATE_*` constants,
≥3 states). Phases: 0 setup → 1 switch → 2 recursion → 3 state machine →
4 integration (also updates ModuleContext/Complexity/FullModule prompt structs)
→ 5 future (full CFG, recursion depth, loop nesting, branch density).
Archive §7 + §17.7.

## P8 — String & Configuration Context (`calxgloss-stringctx`)

Independent (Ghidra-native string data). MVP: classify strings into 9
categories (priority-ordered patterns); per-function string summary (hybrid:
decompiled-body parse, `get_xrefs_to` fallback); format-string type inference
(`%s` → `*const i8`, `%d` → `i32`). Phases: 0 setup → 1 classification →
2 hybrid mapper → 3 format strings → 4 integration → 5 future (localization,
cross-function correlation). Archive §8 + §17.8.

## P9 — Library & API Identification (`calxgloss-apidetect`)

Depends on the call graph (exists). MVP: import-table extraction; library→Rust-
crate mapping DB (DirectX 9, SDL2, Win32, POSIX, PNG, zlib, stdio, C++ STL);
per-function API summary via call-graph traversal. Phases: 0 setup → 1 imports
→ 2 mapping DB → 3 per-function summary → 4 integration → 5 future (FFI
bindings, dependency manifests). Archive §9 + §17.9.

## P10 — Constants & Enum Recovery (`calxgloss-consts`)

Independent. MVP: bitmask enum detection (power-of-2 groups in bitwise ops →
bitflags); sequential constants from switch cases → enum candidates; magic-
number frequency analysis → named constants. Phases: 0 setup → 1 bitmask →
2 sequential → 3 frequency → 4 integration → 5 future (protocol constants,
RGB grouping, codegen output). Archive §10 + §17.10.

## P11 — Endianness & Serialization (`calxgloss-serialize`)

Independent. MVP: byte-swap detection (`ntohs/ntohl/bswap` → `byteorder`);
bit-packing (`|`/`<<`/`>>` patterns); magic-byte format detection (PNG, gzip,
ZIP → format crates). Phases: 0 setup → 1 byteswap → 2 bitpack → 3 magic
bytes → 4 integration → 5 future (protocol/serialization format inference).
Archive §11 + §17.11.

## W0 — Web UI Foundation & Phase Progress (`calxgloss-web`)

Independent; first web track. Current UI: 5 tabs (Dashboard, Review Queue,
Dependency Graph, Branch Cleanup, LLM I/O Log) — a review gate that doesn't
show pipeline position, context tiers, faults/recovery, token cost, or any
process control (archive §12 "Current State Summary").

- Phase 0 — server management endpoints: `/api/server/status` (done), enhanced
  `/health` (done), shutdown/restart (done), `PATCH /api/server/log-level` (done). **Router note:**
  `/api/progress` and the WS upgrade exist only in the WS router
  (`calxgloss live`); `/api/pipeline` is shared — it serves an honest empty
  payload on plain `serve` (issue #61). Every new endpoint must state which
  router(s) it registers in.
- Phase 1 — pipeline progress dashboard: per-phase progress for all 7 phases
  (+ Phase 2.5 PAL) (done — `PipelinePhase`/`PhaseProgress`/`BinaryProgress`
  in `calxgloss-types`, `/api/pipeline` derivation, `PipelinePhaseBar`);
  per-binary rows with strategy, function counts, tokens, success rate, and
  shim/PAL status (done — issue #63, `binary-rows.js`; quick-action buttons
  are W2 placeholders).
  **Prerequisite resolved:** Phases 6 (Restitching) and 7 (Documentation)
  have no backing data source and report `NoDataSource`, never fabricated
  progress; per-function duration recording must be added before time
  estimates work.
- Phase 2 — in-flight status: `TranslationPhase` enum + per-unit phase history
  in live progress (done); context-tier/fault/token/retry display in unit
  detail (done — `process` object on `GET /api/units/{id}`, four detail
  sections); WS phase events.
- Phase 3 — live translation view (`/api/progress/enhanced`, `LiveView`).
- Phase 4 — dashboard enhancements.

**Frontend note:** `static/app.js` is a single ~2,250-line IIFE — split into
per-view ES modules (no build step) before adding new views.

## W1 — Web UI Status & Visibility (`calxgloss-web`)

After W0 Phases 0–1. Unit-detail enhancements (tier info, fault history,
tokens, retry strategy, API mappings, caller/callee context); queue view
(priority/skip/estimate columns, multi-select batch actions — needs a
queue-order persistence mechanism, none exists today); dependency-graph
filters + visual encoding + export; LLM I/O log enhancements —
**prerequisite:** the log is client-side in-memory only; build server-side
persistence (`re/analysis/llm_io/`) + read endpoint first. Archive §13 + §17.13.

## W2 — Web UI Process Control (`calxgloss-web`, `calxgloss-types`, `calxgloss-translator`)

After W0 Phase 1. `PipelineState` enum in **`calxgloss-types`** (not the CLI —
web can't depend on it); state machine as shared `Arc` between translator and
web router (pipeline + web only coexist under `calxgloss live`); pause/resume/
stop/restart/cancel-current endpoints; controls UI; translation scope controls
(skip functions/binaries, priorities, constraints); per-function override panel
(force tier/strategy, hints, notes); binary classification override. **Note:**
the WebSocket has no client→server command channel (`WsCommand` only has
`Register`) — control goes through REST or extend `WsCommand`. Archive §14 + §17.14.

## W3 — Web UI Historical & Analytical Views (`calxgloss-web`)

After W0 Phases 1–2. Faults view (`/api/faults*`, charts, CSV export); token
usage view (`/api/token-usage*`, cost estimates); strategy analytics
(`/api/strategy-analytics*`); LLM performance metrics (`/api/llm-metrics*`,
latency percentiles). Archive §15 + §17.15.

## W4 — Web UI New Views (`calxgloss-web`)

After W0 Phase 1, W1 Phases 0–1. Binaries view (`/api/binaries*`, shim + PAL
trackers); unit-detail attempt comparison (side-by-side diff across all
attempts, per-attempt metadata). Archive §16 + §17.16.

## Cross-cutting open items

Carried from the archive's Cross-Cutting Checklist (all still open):

- Shared `re/analysis/` path helper (every persistor builds the path ad hoc today)
- All crates re-exported from the `calxgloss` meta-crate (done with the 5-context
  reorg: `callgraph`, `typeinfer`, `algorithm`, `config` added); all 11 CLI
  commands registered (typesdb, typeinfer, algorithm, memory done; rest pending)
- Integration-test backend: prefer bethington's headless server over a
  hand-built mock (current: inline fixtures + `#[ignore]`d live tests)
- Orphaned templates `fix.j2` / `disassembly_translate.j2` removed or wired up
- `data_flow.md` updated to include all methodologies
- All 8 web lifecycle endpoints + analytics + process-control endpoints
  (tracked by W0–W4)
- `app.js` split into per-view ES modules (done); new views in `index.html` tabs;
  dark-theme CSS + vanilla-JS patterns for all new frontend code
- Architecture diagrams in source docs match implementation
