# ADR-0004: Pipeline control is a shared state machine in calxgloss-types, driven over REST

- **Status:** Accepted
- **Date:** 2026-10-12 (W2 shipped, epic #88; recorded 2026-10-13)
- **Deciders:** Arthur (solo project)

## Context

An operator running `calxgloss live` could start a translation run but not
steer it: the only control was Ctrl+C, which killed both the pipeline and the
review server. The web crate cannot depend on the CLI crate, yet the pipeline
and the web router only coexist under `calxgloss live` — so the control state
had to live somewhere both can reach.

## Decision

- **`PipelineState` and the `PipelineControl` handle live in
  `calxgloss-types`**, not `calxgloss-cli` (the web crate cannot depend on the
  CLI). States: `Idle`/`Running`/`Paused`/`Stopping`/`Complete`/`Error`.
- **`PipelineControl` is an `Arc`-backed, cheaply cloneable handle modeled on
  the existing `StopSignal`**, with atomic compare-and-set transitions; invalid
  transitions are rejected with a typed error, never silently ignored. It is
  created in the `live` command, passed to the pipeline, and attached to the
  web router's state as an optional field — plain `serve` has no handle and
  the control endpoints honestly answer 503.
- **Control flows exclusively through REST; the WebSocket stays server→client.**
  `WsCommand` (which only has `Register`) is deliberately *not* extended with a
  client→server command channel. Every lifecycle operation emits a progress
  event so connected dashboards reflect state without polling.
- **All W2 control endpoints register on the live router only**, following the
  ADR-0002 router rule.
- **Pause and stop take effect at the next unit boundary** — the unit in flight
  is never interrupted mid-LLM-call — while `cancel-current` aborts at the
  earliest safe point and records the attempt as a cancelled failure. Nothing
  is discarded: an interrupted branch stays reachable under `refs/archive/`.
- **Scope, constraints, per-unit overrides, and classification overrides
  persist under the workspace record tree** (`re/analysis/*.json`), so a
  restarted run honors them without re-entering anything. The token-spend
  counter is per-run and deliberately *not* persisted.

## Consequences

The state machine is testable without a browser, and the dashboard header and
the pipeline can never disagree — both read the same handle, and transitions
land on the WebSocket stream. The cost: control only exists under `live`;
plain `serve` must keep answering honestly (503/empty) for every control
endpoint.
