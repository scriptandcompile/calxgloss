# ADR-0034: The sync data-race reading keys on shared globals, and one lock held by both functions is its false-positive gate

- **Status:** Accepted
- **Date:** 2026-10-14
- **Deciders:** Arthur (solo project)
- **Amended:** 2026-10-19 (issue #255) — the global-identification rule is no longer restated inside the sync crate: the data-race pass consumes the `calxgloss-globalstate` crate's pure access-site reading and keeps only its lock-span attribution on top, so the restated-rule caveat below is retired in favor of one implementation.

## Context

Issue #168 (P5.5-5) asks the cross-function pass that ADR-0033 built
for lock orders to read a second shape over the same kept bodies: one
function storing into a program global while another reads that same
global, and neither side respects a lock. Per-body detectors cannot
see it — each stops at its body's closing brace. And unlike the
lock-order conflict, a race claim rests on an *absence* of evidence:
the body shows no lock, which is weaker ground than a matched
spelling. The reading must use the same tagged-union finding list,
persistence, CLI kind breakdown, and escalate-prompt path as every
other detector. It must add no `ScanSource` reads. And above all
it must not fire on data that both functions properly guard: a scan
that flags every shared variable would hide the deadlock findings next
to it.

## Decision

Run the race reading inside `CrossFunctionAnalyzer::analyze`, after
the lock-order pairing, over the same kept bodies:

- A **global** is a plain identifier the decompiler did not name as
  one of its own locals — not `param_*`, not `local_*`, not the
  `*Var<digits>` family. Since the 2026-10-19 amendment this rule
  lives in exactly one place, the `calxgloss-globalstate` crate: the
  sync pass consumes that crate's pure access-site reading instead of
  restating the rule, so no two crates can disagree about the same
  identifier.
- An access **site** is an identifier outside string and char
  literals, and outside a call. The whole call, including its
  arguments, is skipped, so a lock object or an operation constant
  passed to a callee gives this reading nothing to match on. The
  identifier is also not a qualified or member name, not a
  cast-position type word, not a declaration's type, and not a control
  keyword. The site rule, its type-word vocabulary included, is
  likewise one shared rule in the global-state crate that the sync
  pass reads through (amended). It used to reuse the mutex detector's
  `is_type_word`, so the two in-sync readings could not disagree.
  Control keywords keep their parentheses scanned: `if (DAT_flag)`
  still counts as an access.
- A **protected span** is a recognized acquire→release pairing,
  paired by the mutex detector's own rule: a release closes the most
  recent still-open acquire that names the same lock object. The race
  reading and the pairing detector therefore cannot disagree about
  what a span covers. An access inside nested spans is protected by
  each of them.
- The **false-positive gate** is the same-lock rule: suppress the
  claim when **one lock object's spans cover every access to the
  global in both bodies**. Both functions guard the data with the same
  lock, and properly locked data is not a race. An unprotected access
  on either side leaves the claim standing. Two sides guarded by
  *different* locks also leave it standing — neither lock keeps the
  other side out.
- The **mixed read/write gate** stops a pair from claiming unless the
  two bodies show both a store and a read of the global somewhere. Two
  functions that each only overwrite the same slot lose updates, but
  no reader is caught mid-write; the classic read/write race is what
  this detector reports. This gate also keeps the scan's every-shape
  contract body — two functions each writing
  `hThread = CreateThread(...)` — off the findings list, which is why
  the scan-order contract test stays green untouched.
- The pass reports one `SyncFinding::DataRace` per function pair per
  global, attached to the earlier function in listing order, recording
  the later one as `partner`, appended after the lock-order findings.
  The evidence is each side's access statement: the first unprotected
  one when there is one, otherwise the first access.
- Confidence **60**: the claim rests on no lock being *found*, not on
  a matched spelling. That is one band below the evidence-based kinds
  at 70, and level with the TLS fragment's inference. A race reading
  that adds no `ScanSource` reads adds no new evidence to score.

## Consequences

- The scan's cost and safety model is untouched: one decompile per
  function, the breaker still aborting a run on decompile failures,
  the finding order still stable. The contract tests, unmodified,
  still pin all of this.
- The pairing depends on the decompiler's naming: the same global
  spelled differently in two functions reads as no pair, and a global
  that only ever appears as a call argument is invisible. Both come
  from skipping calls, deliberately inherited: the reading never
  claims what it cannot see.
- Read/read pairs are not races, and write/write-only pairs are not
  reported — the mixed gate's trade-off, accepted at confidence 60.
- Spans cover one body only: a lock held across a call boundary is not
  seen. Suppression therefore errs toward reporting — a missed span
  reports a race rather than hiding one — and the low score of 60 is
  what keeps that extra noise cheap to read past.
- The evidence engine keeps every body for the scan's duration, the
  ADR-0033 consequence, and now does so for two readings instead of
  one.
- Since the 2026-10-19 amendment (issue #255), the global and site
  rules have one implementation, in `calxgloss-globalstate`, and the
  sync pass consumes its sites — name, position, kind — keeping only
  its own lock-span attribution on top. By construction, race findings
  and the global-state artifact report the same accesses, and the
  restated-rule risk this ADR originally accepted is gone. The sync
  scan still runs with no global-state document in the workspace: the
  reading is consumed in-process, not from the persisted artifact.
