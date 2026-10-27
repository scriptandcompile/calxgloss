# ADR-0054: The seam admission line is a run-path-only exemption to the run-equals-`--show` report identity, because capability is live session state, not a filed document

- **Status:** Accepted
- **Date:** 2026-10-27 (P20-2 shipped, issue #355, spec #353)
- **Deciders:** Arthur (solo project)

## Context

P20-2 (#355) grew the scan command's run report with a seam capability
admission line: when the opened analysis engine seam says one of its query
families is unavailable, the run report states the family and the seam's own
reason line (`Seam:`) after the entry's report. The fifteen commands already
have a locked contract (ADR-0052, re-locked across all fifteen by #352): a
command's run report and a later `--show` report of the same document are
byte-identical — the same read of the same filed document. This is the
run-equals-`--show` rule.

The seam line has no `--show` twin. `--show` re-renders only the filed
document, and #354 fixed the capability report as live session state:
nothing about seam capability persists into scan documents or cache keys —
the document's admitted coverage (ADR-0053) stays the persisted half. A
seam's "this family is unavailable — reason" belongs to the session that
opened the seam, not to the document the scan filed. Printing it on the
`--show` path would either invent a persistence that #354 forbade, or fake
a live read on a path that opens no seam.

## Decision

The seam admission line prints on the run path only, immediately after the
scan row's own report (`entry.print`), and the run-equals-`--show` contract
stands with this line as its recorded exception. The ten process tests that
pair run stdout against `--show` stdout pass unchanged: Kuna's declaration
says every family on its full roster is answerable, so today no seam line
prints anywhere, and the equality is byte-identical silence. The translator
counterpart of the same line (prompt-side, #355) is likewise added only
where the pipeline itself opened the seam — the escalated prompt's
imported-APIs section — never into a document re-render.

## Consequences

- Operators reading a scan run report see the live seam admission — the
  plain statement of what the opened seam could not answer — that belongs
  to the session in front of them; `--show` reports stay pure reads of the
  filed document, and all fifteen run-equals-`--show` pins — the tests
  that lock that equality — still have their force.
- The exception is the designed turning point, not an accident to hunt: the
  day a seam declares a family unavailable (a second analysis engine, or a
  degraded session), that session's run report grows the line — the
  in-crate partial-print test (#355, cli) already proves that half — and
  the equality tests over that session must record the difference.
- #356 (engine-identity cache key, spec #353) is the planned future twin:
  it persists the analysis engine build's identity into the cache envelope,
  and if it also records the seam's declaration into the document, a later
  ticket can give `--show` its own capability line and retire this
  exception. Until then, the run path is the only honest place for the
  seam's live word.
