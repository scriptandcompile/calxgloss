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
| X5 | Kuna decompiler engine behind the `ScanSource` seam (`analysis.engine = ghidra \| kuna`) | integrations (new `calxgloss-kuna`) | — | 🔶 in progress | #205–#207 shipped — #208 next | [#203](https://github.com/scriptandcompile/calxgloss/issues/203) |

Legend: ✅ done · 🔶 in progress · ⬜ not started. Row X5 is in progress
(engine skeleton + selection, #205, and the core scan reads, #206, shipped
2026-10-16, and the full read-seam coverage, #207, shipped 2026-10-18);
no effort estimate yet.
X5's spec shipped early (2026-10-16, #203). P2.5 (typeinfer Phase 5) shipped through #150 and was
pruned from this matrix when epic #142 closed (2026-10-14); P3.5 (algorithm
Phase 5) shipped through #156 and was pruned when epic #151 closed
(2026-10-14); P4.5 (memory Phase 5) shipped through #162 and was pruned when
epic #157 closed (2026-10-14); P5.5 (sync Phase 5) shipped through #168 and
was pruned when epic #163 closed (2026-10-14); P6.5 (callback Phase 5)
shipped through #173 and was pruned when epic #169 closed (2026-10-15);
P7.5 (controlflow Phase 5) shipped through #179 and was pruned when epic
#174 closed (2026-10-15); P8.5 (stringctx Phase 5) shipped through #182 and
was pruned when epic #180 closed (2026-10-15); P9.5 (apidetect Phase 5)
shipped through #188 and was pruned when epic #183 closed (2026-10-15);
P10.5 (consts Phase 5) shipped through #195 and was pruned when epic #189
closed (2026-10-16); P11.5 (serialize Phase 5) shipped through #202 and was
pruned when epic #197 closed (2026-10-16); X3 (data_flow.md methodology
update) shipped untracked — docs-only chore — and was pruned (2026-10-16);
X4 (architecture diagrams audit) shipped untracked — docs-only chore — and
was pruned (2026-10-16).

## X5 — Kuna decompiler engine (integrations)

Add an in-process **Kuna** engine (Noelo-Lab/kuna — the Rust port of
Ghidra's decompiler; crates `kuna-decomp`/`kuna-analysis`, git-pinned)
behind the existing seams: a new `calxgloss-kuna` crate implements
`ScanSource` (read) and `TypeWriteSource` (write-back via Kuna's
`--assert` directive plane, persisted as a replayable directive file in
`re/kuna/`), with `PipelineSource` gaining a `Kuna` variant and config/CLI
choosing `analysis.engine = ghidra | kuna` (default `ghidra`). Under
`kuna` the whole ADR-0007 lifecycle — Ghidra install, extension pairing,
headless JVM supervision — disappears. Ghidra stays untouched; the known
gaps (TypeManager-style type-library listing, output parity) are decided
in the spec. Spec: #203 (ready-for-agent).
