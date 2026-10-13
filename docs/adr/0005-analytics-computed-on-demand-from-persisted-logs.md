# ADR-0005: Analytics views are computed on demand from persisted logs — no new persistence

- **Status:** Accepted
- **Date:** 2026-10-12 (W3 shipped, epic #89; recorded 2026-10-13)
- **Deciders:** Arthur (solo project)

## Context

W3 added four historical/analytical views — faults, token usage, strategy
analytics, LLM performance metrics. The obvious alternative was a metrics
store or pre-aggregated rollups written as the run proceeds. But the run
already persists the raw logs (`re/analysis/fault_log.json`,
`token_usage.json`, `prompt_strategy_log.json`, session logs), and a second
copy of the truth would drift.

## Decision

- **Analytics are computed on demand from the persisted logs at request time.**
  No new persistence format, no rollups, no metrics store.
- **All analytics endpoints register on the shared router** — `serve` and
  `live` answer identically (ADR-0002 router rule).
- **Honest degradation throughout:** a missing or corrupt log shows an honest
  "no … recorded yet" instead of a wall of zeros; unmeasured values render as
  em dashes, never invented numbers; percentiles are nearest-rank over
  durations that actually happened, never interpolated.
- **A metric with no honest data source stays out of scope** rather than being
  estimated: per-model metrics and pass-rate-by-complexity were cut because no
  model name or complexity is persisted per attempt.
- **Every endpoint in a view honors the same filters/time range** so cards,
  bars, and tables always describe the same set; a malformed filter answers 400
  naming the accepted shape rather than being silently ignored.
- **One test seam per view:** exact-JSON API tests plus headless-browser view
  tests — the pattern established here and reused by W4.

## Consequences

Counts cover the log's *retained* window (trimmed events carry no timestamp to
date-filter on) — a deliberate, documented limit of the on-demand approach.
The trade buys a single source of truth and zero sync machinery.
