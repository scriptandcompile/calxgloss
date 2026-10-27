# ADR-0054: The seam admission line is a run-path-only exemption to the run-equals-`--show` report identity, because capability is live session state, not a filed document

- **Status:** Accepted
- **Date:** 2026-10-27 (P20-2 shipped, issue #355, spec #353)
- **Deciders:** Arthur (solo project)

## Context

P20-2 (#355) grew the scan command's run report with a seam capability
admission line: when the opened analysis seam declares a query family
unavailable, the run report names the family and the seam's own reason line
(`Seam:`) after the entry's report. The fifteen commands already carry a
pinned contract (ADR-0052, re-pinned across all fifteen by #352): a command's
run report and a later `--show` report of the same document are byte-identical
— the same read of the same filed document.

The seam line has no `--show` twin. `--show` re-renders only the filed
document, and #354 fixed the capability report as live session state: nothing
about seam capability persists into scan documents or cache keys — the
document's admitted coverage (ADR-0053) stays the persisted half. A seam's
"this family is unavailable — reason" belongs to the session that opened the
seam, not to the document the scan filed. Printing it on the `--show` path
would either invent a persistence #354 forbade or fake a live read on a path
that opens no seam.

## Decision

The seam admission line prints on the run path only, immediately after the
scan row's own report (entry.print), and the run-equals-`--show` contract
stands with this line as its recorded exemption. The ten process pins pairing
run stdout against `--show` stdout pass unchanged: under Kuna's full-roster
all-answerable declaration no seam line prints anywhere, so today's equality
is byte-identical silence. The translator mirror of the same line
(prompt-side, #355) is likewise folded only where the pipeline itself opened
the seam — the escalated prompt's imported-APIs section — never into a
document re-render.

## Consequences

- Operators reading a scan run report see the live seam admission that
  belongs to the session in front of them; `--show` reports stay pure reads
  of the filed document, and all fifteen run-equals-`--show` pins keep their
  teeth.
- The exemption is the designed flip point, not an accident to hunt: the day
  a seam declares a family unavailable (a second engine, or a degraded
  session), the run report for that session grows the line — the in-crate
  partial-print pin (#355, cli) already proves that half — and the equality
  pins over that session must record the difference.
- #356 (engine-identity cache key, spec #353) is the planned future twin: it
  persists engine identity into the cache envelope, and if it also stamps
  the seam's declaration into the document, a later ticket can give
  `--show` its own capability line and retire this exemption. Until then,
  the run path is the only honest home for the live word.
