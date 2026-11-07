# ADR-0060: Conformance records and never acts

- **Status:** Accepted
- **Date:** 2026-11-07 (P26 shipped, slices #417–#424, spec #392)
- **Deciders:** Arthur (solo project)

## Context

Track P26 made "this binary is done" a checkable claim. Before it, calxgloss
could only report that a pipeline run had stopped with nobody complaining.
The track grew in eight slices: the *obligation ledger* document and its
*closure digest* (#417), *case kinds* stamped at baseline generation
(#418), the per-binary *conformance verdict* derived fresh on every
dashboard build (#419), the read seam that joins ledger dispositions with
the reviewer's live skip, park, and override records (#420), receipt
citations and the unknown gate inside the closure (#421), the pipeline
filing the ledger at batch close with a roster from the binary's own export
listing (#422), the run close printing the conformance audit line for line
identical to the terminal dashboard (#423), and the web review surfaces —
the queue's per-binary section and each unit detail's *obligation entry*
(#424).

The honesty lineage that began with ADR-0053 made two promises at each
stop: a human being must be able to read the record somewhere, and no
surface may start deciding with what it reads. ADR-0056 filed admitted
gaps as named records, ADR-0058 put authority on the replay rather than
the capture, and ADR-0059 reported *scenario verdicts* without letting
them move a unit. P26.8 closes the lineage: conformance was the last filed
verdict nobody could read at a review surface, and this slice puts it on
both web surfaces while pinning the same boundary there.

## Decision

- **The obligation ledger is a record, not an actor.** Filing an entry,
  reading a disposition, or deriving a verdict changes no unit's review
  status, files no review action, and blocks no Accept. The web e2e seam
  pins it the same way ADR-0059 pinned scenario verdicts: file a ledger
  whose verdict is *incomplete*, and every unit's derived status is
  exactly what it was, `re/actions/` stays unwritten, and the open unit's
  Accept still answers 200. Wiring conformance into send-back machinery
  would be a decision, and decisions belong to the reviewer.
- **Review remains the only door into verified.** The *complete* verdict
  reports that a chain of already-decided facts stands — attempt branch,
  owner pin, receipt pair, Accept action, landed merge. It grants nothing
  itself. The reverse holds too: a reviewer's skip, a parked
  classification, or a unit override never launders work into verified;
  the read seam reads those dispositions honestly, and the tallies show
  them apart from the verified count.
- **No disposition ever aggregates into a pass.** *Skipped*, *parked*,
  *overridden*, *un-reviewed*, and *no-baseline* obligations are counted
  separately from verified ones at every surface — terminal, dashboard
  model, and browser alike. Only *complete* names closure, and
  *complete* requires every obligation closed on checked evidence. A
  binary with a hundred honest hold-outs and zero verified obligations
  never renders as close to done.
- **The verdict is derived on every build and stored nowhere.** The
  terminal dashboard, the web payload, and the run close each re-read the
  filed documents and re-derive the rows. #423's agreement pin requires
  the run close and the terminal print identical lines from separate
  derivations. Nothing writes a conformance field to disk, so no second
  copy exists to drift.
- **Surfaces render; none computes a second derivation.** Spec #392's rule
  stands: the reports dashboard build runs one ledger read and one
  live-record join, and fills both the per-binary row and each unit's
  entry from it. The web server copies those fields into its payloads;
  the browser JavaScript only turns JSON into words. Because the entry
  and the row share one join, the two surfaces can never disagree — and
  where a live skip record stands for the unit, both read *skipped*, not
  the filed claim.
- **An absent field reads as unknown — never zero, never a pass.** An
  older unit document that predates the obligation field, a binary with
  no filed ledger, a ledger that cannot be read, and a ledger that names
  no entry for the unit all arrive at the surfaces as the unknown
  reading. Each surface spells it out: the queue says "unknown: no ledger
  filed — never a clean run", the unit detail says "never shown as zero
  obligations", and no `?` collapses into a `0`. A surface that finds no
  ledger for a binary says *unknown*; it never reports that binary as
  having no obligations.
- **The lineage closes here.** ADR-0053 → ADR-0056 → ADR-0059 each added a
  record and a surface that reads it honestly. With conformance now
  rendered at the queue and the unit detail, every filed verdict in the
  harness has a human-readable surface and a pinned boundary between
  reading and deciding. Later tracks may act on conformance — P27's
  retry evidence and any future gate — and when they do, they must say so
  as a decision of their own, with its own pin. The surfaces keep reading
  without deciding, for every record added after this ADR.
