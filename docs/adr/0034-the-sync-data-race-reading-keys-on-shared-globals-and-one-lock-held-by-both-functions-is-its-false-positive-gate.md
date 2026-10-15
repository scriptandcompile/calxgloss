# ADR-0034: The sync data-race reading keys on shared globals, and one lock held by both functions is its false-positive gate

- **Status:** Accepted
- **Date:** 2026-10-14
- **Deciders:** Arthur (solo project)

## Context

Issue #168 (P5.5-5) asks the cross-function pass ADR-0033 built for
lock orders to read a second shape across the same kept bodies: one
function storing into a program global while another reads that same
global, with no lock either side respects. Per-body detectors cannot
see it — each stops at its body's closing brace — and unlike the
lock-order conflict, a race claim is *absence*-of-evidence: the body
shows no lock, which is weaker ground than a matched spelling. The
reading must ride the same tagged-union, persistence, CLI breakdown,
and escalate-prompt plumbing, add no `ScanSource` reads, and above all
not fire on data both functions properly guard — a scan that flags
every shared variable would bury the deadlock findings it sits beside.

## Decision

Run the race reading inside `CrossFunctionAnalyzer::analyze`, after
the lock-order pairing, over the same kept bodies:

- A **global** is a plain identifier the decompiler did not name as
  one of its own locals — not `param_*`, not `local_*`, not a
  `*Var<digits>` family. That is the memory crate's existing
  `is_decompiler_local` rule, restated here so the two crates cannot
  disagree about what a program symbol is.
- An access **site** is an identifier outside string and char
  literals, outside a call — the whole call including its arguments is
  skipped, so a lock object or an operation constant passed to a
  callee names nothing this reading can key on — and not a qualified
  or member name, a cast-position type word, a declaration's type, or
  a control keyword. The type words come from the mutex detector's
  own `is_type_word` (made `pub(crate)`), so the two readings cannot
  disagree about what a type word is. Control keywords keep their
  parens scanned: `if (DAT_flag)` still names an access.
- A **protected span** is a recognized acquire→release pairing,
  paired by the mutex detector's own rule — a release closes the most
  recent still-open acquire naming the same lock object — so the race
  reading and the pairing detector cannot disagree about what a span
  covers. An access inside nested spans is protected by each of them.
- The **false-positive gate** is the same-lock rule: suppress the
  claim when **one lock object's spans cover every access to the
  global in both bodies**. Both functions guard the data with the same
  lock; properly locked data is not a race. An unprotected access on
  either side leaves the claim standing, and two sides guarded by
  *different* locks leave it standing too — neither lock keeps the
  other side out.
- The **mixed read/write gate** keeps a pair from claiming unless the
  two bodies show both a store and a read of the global somewhere.
  Two functions that each only overwrite the same slot lose updates,
  but nobody watches a half-written value; the classic read/write
  race is what this detector reports. This also keeps the engine's
  every-shape contract body — two functions each writing
  `hThread = CreateThread(...)` — off the list, which is why the
  scan-order contract test stays green untouched.
- One `SyncFinding::DataRace` per function pair per global, on the
  earlier function in listing order naming the later as `partner`,
  appended after the lock-order findings. The evidence is each side's
  access statement — the first unprotected one when there is one, the
  first access otherwise.
- Confidence **60**: the claim rests on no lock being *found*, not on
  a matched spelling, one rung below the evidence-based kinds at 70
  and level with the TLS fragment's inference. A race reading that
  adds no `ScanSource` reads adds no new evidence to grade.

## Consequences

- The scan's cost and safety model is untouched: one decompile per
  function, the breaker gating as before, the finding order stable —
  all still pinned by the contract tests, unmodified.
- Pairing keys on the decompiler's naming: the same global spelled
  differently in two functions reads as no pair, and a global that
  only ever appears as a call argument is invisible. Both are the
  call-skip blindness, inherited deliberately: the reading never
  claims what it cannot see.
- Read/read pairs are not races, and write/write-only pairs are not
  reported — the mixed gate's trade, accepted at confidence 60.
- Spans are in-body only: a lock held across a call boundary is not
  seen, so suppression is conservative in the reporting direction —
  a missed span reports a race rather than hiding one, and the 60
  floor is what keeps that noise cheap to read past.
- The engine keeps every body for the scan's duration, the ADR-0033
  consequence, now carrying two readings instead of one.
