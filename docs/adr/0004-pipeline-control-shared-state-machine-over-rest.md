# ADR-0004: Pipeline control is a shared state machine in calxgloss-types, driven over REST

- **Status:** Accepted
- **Date:** 2026-10-12 (W2 shipped, epic #88; recorded 2026-10-13)
- **Deciders:** Arthur (solo project)

## Context

An operator running `calxgloss live` could start a translation run but not
steer it. The only control was Ctrl+C, which killed both the pipeline and
the review server. The web crate cannot depend on the CLI crate. The
pipeline and the web router only run together under `calxgloss live`. So
the control state had to live somewhere both can reach.

## Decision

- **`PipelineState` and the `PipelineControl` handle live in
  `calxgloss-types`**, not `calxgloss-cli` (the web crate cannot depend on
  the CLI). States: `Idle`/`Running`/`Paused`/`Stopping`/`Complete`/`Error`.
- **`PipelineControl` is an `Arc`-backed handle that clones cheaply**,
  modeled on the existing `StopSignal`. Its state transitions use atomic
  compare-and-set. An invalid transition is rejected with a typed error,
  never silently ignored. The `live` command creates the handle, gives it
  to the pipeline, and attaches it to the web router's state as an optional
  field. Plain `serve` has no handle, so its control endpoints honestly
  answer 503.
- **Control flows only through REST; the WebSocket stays server→client.**
  `WsCommand` has only `Register`. We deliberately do *not* add a
  client→server command channel to it. Every lifecycle operation emits a
  progress event, so connected dashboards show state without polling.
- **All W2 control endpoints register on the live router only**, following
  the ADR-0002 router rule.
- **Pause and stop take effect at the next unit boundary**; the unit in
  flight is never interrupted mid-LLM-call. `cancel-current` aborts the
  current unit at the earliest safe point and records the attempt as a
  cancelled failure. Nothing is discarded: an interrupted branch stays
  reachable under `refs/archive/`.
- **Scope, constraints, per-unit overrides, and classification overrides
  persist under the workspace record tree** (`re/analysis/*.json`). A
  restarted run honors them with nothing to re-enter. The token-spend
  counter belongs to one run and is deliberately *not* persisted.

## Consequences

The state machine is testable without a browser. The dashboard header and
the pipeline can never disagree, because both read the same handle, and
every transition lands on the WebSocket stream. The cost: control exists
only under `live`. Plain `serve` must keep answering honestly (503/empty)
for every control endpoint.
