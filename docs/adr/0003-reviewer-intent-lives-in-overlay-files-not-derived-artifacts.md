# ADR-0003: Reviewer intent lives in overlay files, never in derived artifacts

- **Status:** Accepted
- **Date:** 2026-10-10 (W1 shipped, epic #72; recorded 2026-10-13)
- **Deciders:** Arthur (solo project)

## Context

The review queue needed to remember what the reviewer arranged — a manual
order, per-unit priority (HIGH/NORMAL/LOW), and skipped units — but the
dashboard's unit state is *derived* from git branch state and rebuilt on every
run. Writing reviewer intent into the derived artifacts would have made them
no longer regenerable.

## Decision

Reviewer intent is persisted as **overlay files layered on top of the
artifact-derived state**, under `re/review/`:

- `queue_overlay.json` — manual order + priority; the overlay **only breaks
  ties between units at the same dependency depth**, so no manual arrangement
  can ever put a unit ahead of its prerequisites.
- `skips.json` — the skip set, applied on every dashboard rebuild (so skips
  show in the CLI dashboard too). A merged (Accepted) unit **refuses** the
  skip: branch state is authoritative.

The LLM I/O history, previously client-side in-memory only, moves
server-side to `re/analysis/llm_io/log.jsonl`, bounded at the newest 500
entries with rotation — the prerequisite for the log UI's search and filters.

## Consequences

Reviewer intent survives restarts while every derived artifact stays
regenerable. The 500-entry rotation bounds what the LLM I/O view can show —
older entries are honestly absent, not hidden.
