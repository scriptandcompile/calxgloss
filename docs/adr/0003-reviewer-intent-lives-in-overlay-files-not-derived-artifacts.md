# ADR-0003: Reviewer intent lives in overlay files, never in derived artifacts

- **Status:** Accepted
- **Date:** 2026-10-10 (W1 shipped, epic #72; recorded 2026-10-13)
- **Deciders:** Arthur (solo project)

## Context

The review queue needed to remember what the reviewer arranged: a manual
order, per-unit priority (HIGH/NORMAL/LOW), and skipped units. The
dashboard's unit state is *derived* from git branch state and rebuilt on
every run. Writing reviewer intent into the derived artifacts would have
made them no longer regenerable.

## Decision

Reviewer intent is persisted as **overlay files on top of the
artifact-derived state**, under `re/review/`:

- `queue_overlay.json` — manual order and priority. The overlay **only
  breaks ties between units at the same dependency depth**, so no manual
  arrangement can ever put a unit ahead of its prerequisites.
- `skips.json` — the skip set. It applies on every dashboard rebuild, so
  skips also show in the CLI dashboard. A merged (Accepted) unit **refuses**
  the skip, because branch state is authoritative.

The LLM I/O history used to live in browser memory only. It moves
server-side to `re/analysis/llm_io/log.jsonl`. Rotation keeps only the
newest 500 entries. This was the prerequisite for the log UI's search and
filters.

## Consequences

Reviewer intent survives restarts, and every derived artifact stays
regenerable. The 500-entry rotation limits what the LLM I/O view can show:
older entries are honestly absent, not hidden.
