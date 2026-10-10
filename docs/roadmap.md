# Calxgloss Roadmap — Methodology Tracks

> **Purpose:** index of all open tracks — status, dependencies, and what's
> next. This is the *roadmap*, not the plan of record for active work.
>
> **Where plans live:** when a track is picked up, its detailed plan is
> published to GitHub Issues (`scriptandcompile/calxgloss`) via `/to-spec` →
> `/to-tickets` (tickets carry native blocking links + triage labels), and the
> epic link is added to the status matrix below. `/implement` works the
> tickets; `CHANGELOG.md` stays the record of what shipped.

## How a track gets built

1. Pick the next unblocked track from the matrix (table order = priority).
2. `/to-spec` — synthesize the track summary here (plus its archive section)
   into a spec issue.
3. `/to-tickets` — decompose into tracer-bullet tickets with blocking edges;
   label `ready-for-agent`.
4. `/implement` — drive the tickets (tdd + code-review per ticket).
5. Update this matrix when a phase completes.

Within the web track, W0 comes first; W1–W4 depend only on backend pipeline
data, not on the analysis crates. Test counts in the archive are indicative
targets, not exact requirements.

## Status matrix

| # | Track | Crate | Effort | Status | Next step | Epic |
|---|-------|-------|--------|--------|-----------|------|
| W0 | Web UI Foundation & Phase Progress | `calxgloss-web` | 2–3 wk | ✅ done | closed — see epic [#55](https://github.com/scriptandcompile/calxgloss/issues/55) | [#55](https://github.com/scriptandcompile/calxgloss/issues/55) |
| W1 | Web UI Status & Visibility | `calxgloss-web` | 1–2 wk | ✅ done | closed — see epic [#72](https://github.com/scriptandcompile/calxgloss/issues/72) | [#72](https://github.com/scriptandcompile/calxgloss/issues/72) |
| W2 | Web UI Process Control | `calxgloss-web` + types/translator | 3–4 wk | 🔶 in progress | W2.1 backend done — next: W2 controls UI | [#88](https://github.com/scriptandcompile/calxgloss/issues/88) |
| W3 | Web UI Historical & Analytical Views | `calxgloss-web` | 2–3 wk | 🔶 planned | spec published — `/to-tickets` next | [#89](https://github.com/scriptandcompile/calxgloss/issues/89) |
| W4 | Web UI New Views | `calxgloss-web` | 2–3 wk | ⬜ not started | after W0 P1, W1 P0–1 | — |
| G1 | Ghidra Lifecycle Integration | `calxgloss-ghidra` + `calxgloss-cli` | 3–4 wk | ⬜ not started | spec from design doc (P0–P4 phasing) | — |
| P1.5 | typesdb Phase 5: cross-reference clustering, heuristic struct naming, nested structs/unions, STL type detection, Rust codegen for recovered structs | `calxgloss-typesdb` | — | ⬜ not started | `/to-spec` when picked up | — |
| P2.5 | typeinfer Phase 5: cross-function call-site propagation, integer bit-pattern analysis, C++ mangling analysis, local-variable and return-type inference, **write inferred types back into Ghidra** | `calxgloss-typeinfer` + `calxgloss-ghidra` | — | ⬜ not started | `/to-spec` when picked up | — |
| P3.5 | algorithm Phase 5: confidence scoring improvements, dynamic (JSON) pattern database, multi-function correlation, parallelize across functions | `calxgloss-algorithm` | — | ⬜ not started | `/to-spec` when picked up | — |
| P4.5 | memory Phase 5: cross-function allocation tracking, ownership transfer detection, smart-pointer conversion, resource leak detection, per-type `Drop` suggestions | `calxgloss-memory` | — | ⬜ not started | `/to-spec` when picked up | — |
| P5.5 | sync Phase 5: data-race analysis, lock ordering, async runtime detection, thread-local storage, futex-based synchronization | `calxgloss-sync` | — | ⬜ not started | `/to-spec` when picked up | — |
| P6.5 | callback Phase 5: full callback chain analysis, plugin architecture detection, event system reconstruction, closure signatures via type inference | `calxgloss-callback` | — | ⬜ not started | `/to-spec` when picked up | — |
| P7.5 | controlflow Phase 5: full CFG, recursion depth limits, loop nesting, branch density | `calxgloss-controlflow` | — | ⬜ not started | `/to-spec` when picked up | — |
| P8.5 | stringctx Phase 5: localization detection, cross-function string correlation | `calxgloss-stringctx` | — | ⬜ not started | `/to-spec` when picked up | — |
| P9.5 | apidetect Phase 5: API category enrichment (incl. feature flags), Windows-vs-POSIX divergence, COM interface method suggestions, auto-generated FFI bindings, per-DLL dependency manifests | `calxgloss-apidetect` | — | ⬜ not started | `/to-spec` when picked up | — |
| P10.5 | consts Phase 5: full bitmask enum reconstruction, named constants from context, protocol constants, RGB grouping, codegen output | `calxgloss-consts` | — | ⬜ not started | `/to-spec` when picked up | — |
| P11.5 | serialize Phase 5: full serialization format inference, cross-field validation, protocol message / network protocol identification, per-type endianness mapping | `calxgloss-serialize` | — | ⬜ not started | `/to-spec` when picked up | — |
| X1 | Integration-test backend: prefer bethington's headless server over a hand-built mock | test infra | — | ⬜ not started | `/to-spec` when picked up | — |
| X2 | Orphaned templates `fix.j2` / `disassembly_translate.j2` removed or wired up | `calxgloss-prompts` | — | ✅ done | closed — deleted, see [#87](https://github.com/scriptandcompile/calxgloss/issues/87) | [#87](https://github.com/scriptandcompile/calxgloss/issues/87) |
| X3 | `data_flow.md` updated to include all methodologies | docs | — | ⬜ not started | `/to-spec` when picked up | — |
| X4 | Architecture diagrams in source docs match implementation | docs | — | ⬜ not started | `/to-spec` when picked up | — |

Legend: ✅ done · 🔶 in progress · ⬜ not started. Rows P1.5–P11.5 and X1,
X3–X4 are open future-work items — optional Phase 5 depth work and
cross-cutting chores — verified still open in the code (2026-10-08); no
effort estimates yet.

## W0 — Web UI Foundation & Phase Progress (`calxgloss-web`)

Independent; first web track. Complete — Phases 0–4 plus the Phase 2 tail:
server management endpoints, pipeline phase bar, per-binary rows, in-flight
unit phases, unit process detail, live translation view, dashboard
enhancements, and WS phase events (the live server pushes per-unit
`unit_phase` records — current phase and history — over the WebSocket, and
the live view updates its rows from them) — shipped under epic #55, see
`CHANGELOG.md`.

**Router note:** `/api/progress`, `/api/progress/enhanced`, and the WS
upgrade exist only in the WS router (`calxgloss live`); `/api/pipeline` is
shared — it serves an honest
empty payload on plain `serve` (issue #61). Every new endpoint must state
which router(s) it registers in.

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

## G1 — Ghidra Lifecycle Integration (`calxgloss-ghidra` + `calxgloss-cli`)

Design doc: `docs/ghidra_integration.md` — preflight, headless server
spawn/supervise, project bootstrap, `doctor --fix` install path; spec from
the doc's P0–P4 phasing. Endpoint reference: `docs/ghidra_endpoint_map.md`.
**Bridge decision (2026-10-03):** the Ghidra bridge is
[bethington/ghidra-mcp](https://github.com/bethington/ghidra-mcp) v6.0.0,
load port 8089 — see `docs/adr/0001-bethington-ghidra-mcp-bridge.md`.
**Incident (2026-10-08):** multiple open CodeBrowser windows made the bridge
answer listings and name searches from different programs; scans skipped
everything and nearly persisted phantom-clean records. Program selectors +
preflight program check moved into P1; see risk 7 and issue #71.

## P1.5 — typesdb Phase 5 (`calxgloss-typesdb`)

Optional depth work on the shipped MVP (archive §1, Phase 5): cross-reference
clustering, heuristic struct naming, nested structs/unions, STL type
detection, Rust codegen output for recovered structs. Write-back wrappers
were deferred to P2.5.

## P2.5 — typeinfer Phase 5 (`calxgloss-typeinfer` + `calxgloss-ghidra`)

Optional depth work (archive §2, Phase 5): cross-function call-site
propagation, integer bit-pattern analysis, C++ mangling analysis,
local-variable and return-type inference, and **write inferred types back
into Ghidra** — `set_function_prototype`/`set_local_variable_type`, creating
missing types first via `create_struct`/`create_enum`/`create_typedef`; the
bridge supports it (ADR-0001, endpoint map in `docs/ghidra_endpoint_map.md`).

## P3.5 — algorithm Phase 5 (`calxgloss-algorithm`)

Optional depth work (archive §3, Phase 5): confidence scoring improvements,
dynamic (JSON) pattern database replacing the built-in patterns,
multi-function correlation, parallelize across functions.

## P4.5 — memory Phase 5 (`calxgloss-memory`)

Optional depth work (archive §4, Phase 5): cross-function allocation
tracking, ownership transfer detection, smart-pointer conversion, resource
leak detection, per-type `Drop` suggestions.

## P5.5 — sync Phase 5 (`calxgloss-sync`)

Optional depth work (archive §5, Phase 5): data-race analysis, lock ordering,
async runtime detection, thread-local storage, futex-based synchronization.

## P6.5 — callback Phase 5 (`calxgloss-callback`)

Optional depth work (archive §6, Phase 5): full callback chain analysis,
plugin architecture detection, event system reconstruction, closure
signatures via type inference (soft dependency on P2.5).

## P7.5 — controlflow Phase 5 (`calxgloss-controlflow`)

Optional depth work (archive §7, Phase 5): full CFG, recursion depth limits,
loop nesting, branch density.

## P8.5 — stringctx Phase 5 (`calxgloss-stringctx`)

Optional depth work (archive §8, Phase 5): localization detection,
cross-function string correlation.

## P9.5 — apidetect Phase 5 (`calxgloss-apidetect`)

Optional depth work (archive §9, Phase 5): API category enrichment (incl.
feature flags), Windows-vs-POSIX divergence detection, COM interface method
suggestions, auto-generated FFI bindings, per-DLL dependency manifests.

## P10.5 — consts Phase 5 (`calxgloss-consts`)

Optional depth work (archive §10, Phase 5): full bitmask enum
reconstruction, named constant suggestion from context, protocol constants,
color/RGB constant grouping, codegen output to a separate Rust file.

## P11.5 — serialize Phase 5 (`calxgloss-serialize`)

Optional depth work (archive §11, Phase 5): full serialization format
inference, cross-field validation detection, protocol message / network
protocol identification, per-type endianness mapping.

## X1 — Integration-test backend (test infra)

Prefer bethington's headless server over a hand-built mock for integration
tests; current state is inline fixtures + `#[ignore]`d live tests.

## X2 — Orphaned templates (`calxgloss-prompts`)

Done — decision was remove. `fix.j2` and `disassembly_translate.j2` sat in
`templates/` unreferenced in `templates.rs`; the renderer already covers both
jobs with other templates, so both files were deleted (#87).

## X3 — `data_flow.md` update (docs)

`docs/data_flow.md` updated to include all methodologies — the analysis
crates shipped after the doc was written.

## X4 — Architecture diagrams (docs)

Architecture diagrams in source docs match implementation.
