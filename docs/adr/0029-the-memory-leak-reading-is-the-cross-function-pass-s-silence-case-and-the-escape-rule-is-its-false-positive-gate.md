# ADR-0029: The memory leak reading is the cross-function pass's silence case — an open resource with no pair and no escape — and the escape rule is its false-positive gate

- **Status:** Accepted
- **Date:** 2026-10-14 (P4.5-3 shipped, issue #160)
- **Deciders:** Arthur (solo project)

## Context

The crate promises to find resources that are never released, but
every detector so far reported only presences — a pair, a transfer, a
bump — and stayed silent on absences. The pairing detector's pinned
contract ("never released → not reported") exists precisely because a
single body cannot tell a leak from a resource that escapes: the
unpaired allocation it leaves open might be freed by a callee, stored
in a global, or returned to the caller. Only the cross-function pass,
which sees both the open list and every way the value could leave,
can tell the two apart.

The questions this had to settle: which reading owns the leak claim,
what gates it, whether handles join, what a leak's evidence and
suggestion are when the finding is an absence, and where it scores.

## Decision

- **The leak is the cross-function pass's silence case.** For each
  open allocation the reading already consults for the pair and the
  transfer, the third branch — no releasing callee *and* no escape —
  is a [`MemoryFinding::Leak`]. The pairing detector's silence on
  unpaired allocations stays pinned: leaks come only from the pass
  that has checked every way the value could leave.
- **The escape rule is the false-positive gate, unchanged.** Any
  hand-off that ADR-0028 reads as a transfer — a plain argument at
  any call site, seen through casts, or a whole return — suppresses
  the leak. A resource that left is someone else's to release;
  claiming a leak on it would be exactly the false positive the
  pairing's silence was protecting against.
- **Handles join through the same two lists.** `HandleDetector`
  gained `open_handles`, the same walk as `detect_handles` returning
  what it leaves unclosed — the same precedent as
  `AllocatorTracker::open_allocations`, so the pairing and the leak
  reading can never disagree about what stands open. The same escape
  gate reads them: an unclosed handle handed to any callee or returned
  whole says nothing (the ownership finding is allocation-shaped;
  handle ownership transfer is out of scope), and one that escapes
  nowhere leaks by its opener.
- **The evidence is the acquisition line alone.** A leak is an
  absence; the only positive fact is where the resource was taken.
  The suggestion names the owner that would have made the absence
  impossible: `Box<T>` for a block, the handle pairing's existing
  RAII guard spelling for a handle.
- **Confidence 60 — one rung below the transfer.** The acquisition
  and the checked absence are body facts, but an absence is only what
  this body shows: the resource may be a deliberate process-lifetime
  allocation or released through a path the scan cannot read. The
  ladder reads 70 pair → 65 transfer → 60 leak.
- **Within one function, open allocations first in allocation order,
  then open handles in open order** — the cross-function group's
  deterministic order, so two scans of one program stay byte-identical.

## Consequences

- The finding union gained a sixth kind, `leak`, carrying a
  `resource` tag — the allocation family, or the handle family and
  its opener — so one record shape covers both resources and the
  CLI's target column names what leaked.
- The scan now reports the absence it was built for: `calxgloss
  memory` output ends with the resources that go nowhere, at the
  deliberately lowest confidence of the cross-function readings.
- The Rc upgrade (#161) reads the same call-map seam for the sharing
  pattern; a leaked resource is by construction one no callee was
  handed, so the two readings stay disjoint.
