# ADR-0028: The memory cross-function pass claims each open allocation once, lets a read release beat an escape, and reads any hand-off as a move

- **Status:** Accepted
- **Date:** 2026-10-14 (P4.5-2 shipped, issue #159)
- **Deciders:** Arthur (solo project)

## Context

ADR-0027's pass reports an open allocation only when a scanned callee's
body was actually read releasing the parameter it arrived in. That
leaves most open allocations silent: the pointer handed to a library
routine (`external_free(pvVar1)`), the pointer handed to a scanned
callee that never frees it, and the pointer returned whole to the
caller. In Rust terms the block *moved out of the function* in every
one of those cases, and the author needs to see it. But the far side of
the move is unseen, so the claim is weaker than a pair and must not
pretend otherwise.

The questions this had to settle: can one open allocation carry more
than one finding? Which spellings count as the block leaving — handed
over at a call site, returned whole, returned through a cast, an
interior pointer? What does a member call like `obj.FUN_x(pvVar1)` mean
now that a non-pair reading exists? And where should a transfer score
against the readings that do see the release?

## Decision

- **One claim per open allocation: a pair or a transfer, never both.**
  Where an open variable both reaches a releasing callee and escapes
  elsewhere, the pair wins. One moved block moves once, and the pair is
  the claim whose release was actually read. The pass stays a single
  sweep over the same open-allocation list ADR-0027 established.
- **An escape is any hand-off of the whole block.** Two spellings
  count. The first is the variable sitting as a plain argument (seen
  through any cast) at *any* call site — including a callee outside the
  scanned set, which forms no pair but still receives the value. The
  second is a `return` of the variable whole, bare or cast
  (`return pvVar1;`, `return (void *)pvVar1;`). A return of anything else — `return
  pvVar1 + 1;`, a bare `return;` — hands back no block and transfers
  nothing.
- **The finding names the direction, not just the fact.** A new
  `ownership` kind includes a direction — `handed_to_callee` or
  `returned_to_caller` — and an optional partner: the callee's spelled
  name for a hand-off, `None` for a return, where the caller is by
  definition outside the function's own body.
- **A member call transfers without pairing.** `obj.FUN_18003e750(pvVar1)`
  stays invisible to the *pair* reading. The implicit receiver shifts
  the positional tie ADR-0027 depends on, so no release is claimed
  against that body. But the pointer still leaves at that site, so the
  escape reading records it, naming the dotted callee verbatim as the
  partner. Whether pairing fails and whether escape is honest are
  separate questions, and they get separate answers.
- **Confidence 65 — below a pair, level with the short-lived stack
  reading.** The allocation and the escape are both explicit body
  evidence, but what the far side does with the value is unseen: the
  callee may store it, free it, or just borrow it. A transfer scores one
  below the 70 pair whose release was read.
- **The suggestion is `Box<T>`, like the pair's.** A block that moves
  out of its allocating function is what a boxed value owns when it
  is moved. The direction and the evidence tell the author which move it
  was. The Rc upgrade (#161) will refine the suggestion where the
  callee shares rather than owns.

## Consequences

- The finding union gained a fifth kind, `ownership`, which uses the
  existing accessors. The persisted JSON, the CLI kind breakdown, and
  the prompt conversion picked it up with no shape change.
- The escape reading widens what the scan reports: library hand-offs
  and whole returns now surface where the pass was previously silent,
  at a deliberately lower confidence than a read release.
- Leak detection (#160) is the complement on the same list: an open
  allocation with neither a pair nor an escape is the block that
  goes nowhere.
