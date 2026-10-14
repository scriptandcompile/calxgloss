# Calxgloss Roadmap — Methodology Tracks

> **Purpose:** index of all open tracks — status, dependencies, and what's
> next. This is the *roadmap*, not the plan of record for active work.
>
> **Where plans live:** when a track is picked up, its detailed plan is
> published to GitHub Issues (`scriptandcompile/calxgloss`) via `/to-spec` →
> `/to-tickets` (tickets carry native blocking links + triage labels), and the
> epic link is added to the status matrix below. `/implement` works the
> tickets; `CHANGELOG.md` stays the record of what shipped.
>
> **Where done tracks go:** a completed track is removed from this roadmap —
> its shipped history lives in `CHANGELOG.md` and its key decisions are
> recorded as ADRs in `docs/adr/` (W0 → ADR-0002, W1 → ADR-0003, W2 →
> ADR-0004, W3 → ADR-0005, W4 → ADR-0006, G1 → ADR-0007, X2 → ADR-0008,
> P1.5 → ADR-0009–0013).

## How a track gets built

1. Pick the next unblocked track from the matrix (table order = priority).
2. `/to-spec` — synthesize the track summary here (plus its archive section)
   into a spec issue.
3. `/to-tickets` — decompose into tracer-bullet tickets with blocking edges;
   label `ready-for-agent`.
4. `/implement` — drive the tickets (tdd + code-review per ticket).
5. Update this matrix when a phase completes.

Test counts in the archive are indicative targets, not exact requirements.

## Status matrix

| # | Track | Crate | Effort | Status | Next step | Epic |
|---|-------|-------|--------|--------|-----------|------|
| P5.5 | sync Phase 5: data-race analysis, lock ordering, async runtime detection, thread-local storage, futex-based synchronization | `calxgloss-sync` | — | ⬜ not started | `/to-spec` when picked up | — |
| P6.5 | callback Phase 5: full callback chain analysis, plugin architecture detection, event system reconstruction, closure signatures via type inference | `calxgloss-callback` | — | ⬜ not started | `/to-spec` when picked up | — |
| P7.5 | controlflow Phase 5: full CFG, recursion depth limits, loop nesting, branch density | `calxgloss-controlflow` | — | ⬜ not started | `/to-spec` when picked up | — |
| P8.5 | stringctx Phase 5: localization detection, cross-function string correlation | `calxgloss-stringctx` | — | ⬜ not started | `/to-spec` when picked up | — |
| P9.5 | apidetect Phase 5: API category enrichment (incl. feature flags), Windows-vs-POSIX divergence, COM interface method suggestions, auto-generated FFI bindings, per-DLL dependency manifests | `calxgloss-apidetect` | — | ⬜ not started | `/to-spec` when picked up | — |
| P10.5 | consts Phase 5: full bitmask enum reconstruction, named constants from context, protocol constants, RGB grouping, codegen output | `calxgloss-consts` | — | ⬜ not started | `/to-spec` when picked up | — |
| P11.5 | serialize Phase 5: full serialization format inference, cross-field validation, protocol message / network protocol identification, per-type endianness mapping | `calxgloss-serialize` | — | ⬜ not started | `/to-spec` when picked up | — |
| X1 | Integration-test backend: prefer bethington's headless server over a hand-built mock | test infra | — | ⬜ not started | `/to-spec` when picked up | — |
| X3 | `data_flow.md` updated to include all methodologies | docs | — | ⬜ not started | `/to-spec` when picked up | — |
| X4 | Architecture diagrams in source docs match implementation | docs | — | ⬜ not started | `/to-spec` when picked up | — |

Legend: ✅ done · 🔶 in progress · ⬜ not started. Rows P5.5–P11.5 and X1,
X3–X4 are open future-work items — optional Phase 5 depth work and
cross-cutting chores — verified still open in the code (2026-10-08); no
effort estimates yet. P2.5 (typeinfer Phase 5) shipped through #150 and was
pruned from this matrix when epic #142 closed (2026-10-14); P3.5 (algorithm
Phase 5) shipped through #156 and was pruned when epic #151 closed
(2026-10-14); P4.5 (memory Phase 5) shipped through #162 and was pruned when
epic #157 closed (2026-10-14).

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

## X3 — `data_flow.md` update (docs)

`docs/data_flow.md` updated to include all methodologies — the analysis
crates shipped after the doc was written.

## X4 — Architecture diagrams (docs)

Architecture diagrams in source docs match implementation.
