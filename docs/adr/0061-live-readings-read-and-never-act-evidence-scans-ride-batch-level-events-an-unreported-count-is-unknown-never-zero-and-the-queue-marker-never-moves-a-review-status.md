# ADR-0061: Live readings read, and never act

- **Status:** Accepted
- **Date:** 2026-11-07 (P53 shipped, slices #428–#431, spec #425)
- **Deciders:** Arthur (solo project)

## Context

Track P53 answered a run that read as seventeen minutes of silence. A cold
`live` run on LaunchPad.exe (7,267 functions) spent ~15 minutes in the
pre-batch evidence scans (the `sync` scan alone: 785 s, 43,547,588 findings)
plus the cold call-graph build (57 s) before its first unit moved, while the
web progress panel held `{"units":[]}`, the queue view showed no movement,
and no panel named a running scan. The scans logged their own name,
duration, and count, but default `warn` verbosity hides those lines — the
operator's only signal was `tail -f`.

The track shipped in four slices: a batch-level started/completed event pair
per registered scan plus the live view's scan panel (#428), the failed-scan
and unknown-count honesty edges on that panel (#429), the worklist
heartbeat rendered as a tick line naming Kuna's current function beside the
running pass (#430), and the queue row's *live reading* — the in-flight
unit's phase, kept beside its persisted review status (#431).

The same honesty lineage that ADR-0053 opened and ADR-0060 closed — a
record must be readable by a human, and no surface may start deciding with
what it reads — runs through every live-progress decision below, and #363
had already pinned that two kinds of meaning never share one field.

## Decision

- **Evidence scans become batch-level progress events, never unit phases.**
  One `EvidenceScanStarted` / `EvidenceScanCompleted` pair per registered
  scan per pass, cold and warm alike. Both name no unit: their `unit_key()`
  and `TranslationPhase::from_event()` are `None`, exactly as `BatchStarted`
  behaves, so a scan's visibility never creates a unit record and never
  touches a unit's phase history.
- **An unreported finding count is unknown, never zero.** The completed
  event's findings field is absent when the engine reported no count, and
  the panel spells it out as `findings: unknown`. A scan whose engine
  failed, or whose task panicked inside the concurrent window, still ends
  with its own completed event carrying its error, and its count stays
  unknown — a failed row reads apart from a completed one. This is
  ADR-0053's unreadable-is-unknown rule arriving on live progress.
- **The scan records live in memory and are persisted nowhere.** The web
  progress store keeps the latest record per scan name, clears them when a
  new binary's pass opens, and the panel's honesty edge before the first
  started event says the phase has not started — never "0 scans ran". The
  scans' durable documents already exist under `re/analysis/`; the live
  store is the run's mirror of them, not a second record.
- **The scan registry's table is the single source of truth for scan
  names.** The panel rows and the pair-count tests follow the registered
  table; a scan added to the registry appears in the panel with no panel
  edit and no new test name.
- **A queue row's live reading and the git-backed review status are two
  fields, never one.** The served queue payload gains `live_state` beside
  `status`: an in-flight unit reads with its current pipeline phase, a
  unit the run finished without failing reads `awaiting_review`, a failed
  unit reads `failed`, a cancelled one `cancelled`, and a unit the run
  never touched carries no field at all — never a blank that reads as idle
  or stuck. Live traffic never rewrites a review status; serving, pushing,
  and rendering the reading merges no branch, files no review action, and
  leaves no skip state, pinned at the web e2e seam the way ADR-0060 pinned
  the ledger. This carries #363's two-fields rule — retry strategy and
  batch outcome never share a name — into the progress vocabulary.
- **The web view is the whole surface; the terminal grows nothing.** No new
  terminal progress output, verbosity change, or spinner: terminal reports
  are P56's deletion target, and every read landed in this track lands in
  the browser.

## Consequences

A cold run answers, within seconds and in the browser, which scan is
running with a ticking clock, what the last completed step was with its
elapsed time and count, which function Kuna is working, and which unit is
being worked — without tailing a log file. The count P53 made visible is
the same count P54 (#426) now sets out to shrink; visibility and the
false-positive fix stand on separate tracks and neither waits on the other.
Because every live reading is a reading and not an actor, any later track
that wants live progress to *change* something — auto-pause a slow scan,
flag a stuck unit — must say so as its own decision, with its own pin.
