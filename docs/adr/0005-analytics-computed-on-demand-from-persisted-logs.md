# ADR-0005: Analytics views are computed on demand from persisted logs — no new persistence

- **Status:** Accepted
- **Date:** 2026-10-12 (W3 shipped, epic #89; recorded 2026-10-13)
- **Deciders:** Arthur (solo project)

## Context

W3 added four historical and analytical views: faults, token usage,
strategy analytics, and LLM performance metrics. The obvious alternative
was a metrics store, or pre-aggregated rollups written while the run
proceeds. But the run already persists the raw logs
(`re/analysis/fault_log.json`, `token_usage.json`,
`prompt_strategy_log.json`, session logs), and a second copy of the truth
would drift.

## Decision

- **Analytics are computed on demand from the persisted logs at request
  time.** No new persistence format, no rollups, no metrics store.
- **All analytics endpoints register on the shared router**, so `serve` and
  `live` answer identically (ADR-0002 router rule).
- **Honest degradation throughout:** a missing or corrupt log shows an
  honest "no … recorded yet", not a wall of zeros. An unmeasured value
  renders as an em dash, never an invented number. Percentiles use
  nearest-rank over durations that actually happened, never interpolation.
- **A metric with no honest data source stays out of scope** rather than
  getting an estimate: per-model metrics and pass-rate-by-complexity were
  cut, because one attempt persists no model name and no complexity.
- **Every endpoint in a view honors the same filters/time range**, so
  cards, bars, and tables always describe the same set. A malformed filter
  gets a 400 that names the accepted shape, rather than being silently
  ignored.
- **One test seam per view:** exact-JSON API tests plus headless-browser
  view tests. This pattern was established here, and W4 reused it.

## Consequences

Counts cover only the log's *retained* window, because trimmed events have
no timestamp left to date-filter on — a deliberate, documented limit of the
on-demand approach. The trade buys a single source of truth and zero sync
machinery.
