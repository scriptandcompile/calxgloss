# ADR-0029: The memory leak reading is the cross-function pass's silence case — an open resource with no pair and no escape — and the escape rule is its false-positive gate

- **Status:** Accepted
- **Date:** 2026-10-14 (P4.5-3 shipped, issue #160)
- **Deciders:** Arthur (solo project)

## Context

The crate promises to find resources that are never released. But
every detector so far reported only things that are present — an
allocation pair, a transfer, a reference-count increase — and stayed
silent about things that are absent. The pairing detector's pinned
contract ("never released → not reported") exists for a reason: a
single body cannot tell a leak from a resource that escapes. The
allocation it leaves open and unpaired might be freed by a callee,
stored in a global, or returned to the caller. Only the cross-function
pass can tell the two apart, because it sees both the open list and
every way the value could leave.

This ADR had to settle five questions. Which reading owns the leak
claim? What gates it? Do handles take part? When the finding is an
absence, what are its evidence and its suggestion? Where does its
confidence sit?

## Decision

- **The leak is the cross-function pass's silence case.** The reading
  already checks each open allocation for a pair and for a transfer.
  The third outcome — no releasing callee *and* no escape — produces a
  [`MemoryFinding::Leak`]. The pairing detector's silence on unpaired
  allocations stays pinned: leaks come only from the pass that has
  checked every way the value could leave.
- **The escape rule stays the false-positive gate, unchanged.** Any
  hand-off that ADR-0028 reads as a transfer suppresses the leak.
  That covers a plain argument at any call site, seen through casts,
  and a whole return. A resource that has left is someone else's to
  release. Claiming a leak on it would produce exactly the false
  positive that the pairing detector's silence was protecting against.
- **Handles enter through the same two lists.** `HandleDetector`
  gained `open_handles`. It runs the same walk as `detect_handles` and
  returns the handles that walk leaves unclosed — the same precedent
  as `AllocatorTracker::open_allocations`, so the pairing reading and
  the leak reading can never disagree about what stands open. The
  same escape gate checks handles too. An unclosed handle that is
  passed to any callee, or returned whole, produces no claim (the
  ownership findings are allocation-shaped; transferring handle
  ownership is out of scope). An unclosed handle that escapes nowhere
  leaks, reported at its opener.
- **The evidence is the acquisition line alone.** A leak is an
  absence. The only positive fact is where the resource was acquired.
  The suggestion gives the owner that would have made the absence
  impossible: `Box<T>` for a block, and the handle pairing's existing
  RAII guard spelling for a handle.
- **Confidence 60 — one band below the transfer on the ladder.** The
  acquisition and the checked absence are both facts read from the
  body. But an absence shows only what this body contains: the
  resource may be a deliberate process-lifetime allocation, or it may
  be released through a path the scan cannot read. The ladder reads
  70 pair → 65 transfer → 60 leak.
- **Within one function, open allocations come first in allocation
  order, then open handles in the order they opened** — the
  cross-function group's deterministic order, so two scans of one
  program stay byte-identical.

## Consequences

- The finding union gained a sixth kind, `leak`, with a `resource`
  tag. The tag holds the allocation family, or the handle family and
  its opener. One record shape therefore covers both resource kinds,
  and the CLI's target column reports what leaked.
- The scan now reports the absence it was built to find: the
  `calxgloss
  memory` output ends with the resources that go nowhere, at the
  deliberately lowest confidence of the cross-function readings.
- The Rc upgrade (#161) reads the same part of the call map for the
  sharing pattern. By construction, a leaked resource is one that was
  never passed to a callee, so the two readings stay disjoint.
