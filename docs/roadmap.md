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
| P4 | Memory Lifecycle / RAII | `calxgloss-memory` | 3–4 wk | 🔶 Phases 0–3 done, Phase 4 in progress (2026-10-05) | **Phase 4 — pipeline integration** ← next up | — |
| P5 | Concurrency & Synchronization | `calxgloss-sync` | 2–3 wk | ⬜ not started | spec + crate | — |
| P6 | Callback / Function Pointer Tables | `calxgloss-callback` | 2–3 wk | ⬜ not started | spec + crate | — |
| P7 | Control Flow Pattern Recognition | `calxgloss-controlflow` | 2–4 wk | ⬜ not started | spec + crate | — |
| P8 | String & Configuration Context | `calxgloss-stringctx` | 1–2 wk | ⬜ not started | spec + crate | — |
| P9 | Library & API Identification | `calxgloss-apidetect` | 1–2 wk | ⬜ not started | spec + crate | — |
| P10 | Constants & Enum Recovery | `calxgloss-consts` | 2–3 wk | ⬜ not started | spec + crate | — |
| P11 | Endianness & Serialization | `calxgloss-serialize` | 1–2 wk | ⬜ not started | spec + crate | — |
| W0 | Web UI Foundation & Phase Progress | `calxgloss-web` | 2–3 wk | ⬜ not started | spec (independent of P-tracks) | — |
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

## P4 — Memory Lifecycle / RAII (`calxgloss-memory`) ← next up

Detectors done (2026-10-05): allocator/deallocator pair tracking (→ `Box<T>`/
stack), handle lifetimes (→ RAII guard + `Drop`), reference counting (→ `Rc<T>`/
`Arc<T>`); 132 unit tests. **Phase 4 — pipeline integration in progress
(2026-10-05)**, following the exact shape P3 shipped (archive §17.4 Phase 4).

Done: `MemoryResult` + shared `ScanMetadata` per-binary document type (with the
`MemoryFinding` union, serde-tagged by kind); `MemoryPersistor` →
`re/analysis/memory/{dll}.json` (wrapping `calxgloss_types::persist::JsonStore`,
typesdb convention); `calxgloss memory --dll <dll> --show` prints the cached
document (target-dir-exempt); `calxgloss-memory` re-exported from the
meta-crate.

Remaining:

- `MemoryEngine` orchestrating the three detectors (source-trait generic,
  canned-source tests)
- `extract_memory_hints()` in `calxgloss-translator/src/retry/helpers.rs` +
  prompt section (`MemoryHint` → prompt struct in `calxgloss-prompts`)
- `ensure_memory_detection(dll)` pre-analysis in batch translation
- `calxgloss memory --dll <dll>` scan+save half of the CLI command (lands
  with `MemoryEngine`)
- Integration tests + clippy clean

Dependencies: soft on P2 (done).

## P5 — Concurrency & Synchronization (`calxgloss-sync`)

Soft dependency on P2. MVP: mutex/lock detection (`pthread_mutex_*`,
`EnterCriticalSection` → `std::sync::Mutex`/`RwLock`); atomics
(`InterlockedIncrement`, `__atomic_fetch_add` → `AtomicU32/64`); threading
(`CreateThread`, `pthread_create` → `std::thread`/`tokio::spawn`).
Phases: 0 setup → 1 mutex → 2 atomics → 3 threading → 4 pipeline integration →
5 future (data-race analysis, lock ordering, async runtime, TLS, futex).
Archive §5 + §17.5.

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

- Phase 0 — server management endpoints: `/api/server/status`, enhanced
  `/health`, shutdown/restart, `PATCH /api/server/log-level`. **Router note:**
  `/api/pipeline` and `/api/progress` exist only in the WS router
  (`calxgloss live`); every new endpoint must state which router(s) it
  registers in.
- Phase 1 — pipeline progress dashboard: per-phase progress for all 7 phases
  (+ Phase 2.5 PAL). **Prerequisite:** Phases 6 (Restitching) and 7
  (Documentation) have no backing data source — define what they report (or
  mark "not started") first; per-function duration recording must be added
  before time estimates work.
- Phase 2 — in-flight status: `TranslationPhase` enum, WS phase events,
  context-tier/fault/token/retry display in unit detail.
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
- All 11 crates re-exported from the `calxgloss` meta-crate; all 11 CLI
  commands registered (typesdb, typeinfer, algorithm, memory done; rest pending)
- Integration-test backend: prefer bethington's headless server over a
  hand-built mock (current: inline fixtures + `#[ignore]`d live tests)
- Orphaned templates `fix.j2` / `disassembly_translate.j2` removed or wired up
- `data_flow.md` updated to include all methodologies
- All 8 web lifecycle endpoints + analytics + process-control endpoints
  (tracked by W0–W4)
- `app.js` split into per-view ES modules; new views in `index.html` tabs;
  dark-theme CSS + vanilla-JS patterns for all new frontend code
- Architecture diagrams in source docs match implementation
