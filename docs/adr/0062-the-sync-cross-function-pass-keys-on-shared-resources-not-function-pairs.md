# ADR-0062: The sync cross-function pass keys on shared resources, not function pairs

- **Status:** Accepted
- **Date:** 2026-11-07
- **Deciders:** Arthur (solo project)
- **Supersedes:** ADR-0034 (the data-race reading's per-pair output shape)

## Context

ADR-0034's race reading and ADR-0033's lock-order reading each made one
claim per pair of functions, over the bodies the scan keeps. On
LaunchPad.exe — 7,267 functions — that output model exploded: the sync
scan emitted 43,547,588 findings in 785 s and filed a 14 GB per-binary
document (issue #426, measured 2026-11-07). Both readings enumerated all
26.4M function pairs, twice. The race reading emitted one row per
(function, partner, global), so one global touched by thousands of
functions restated the same claim millions of times.

Much of that volume was fake rather than real. The decompiler's own
stack-slot and register names read as program globals, until the issue
#433 name rule retired those reads through one shared reading. The pass
keyed a lock held in a stack slot as shared across two functions,
though a stack slot never leaves its own frame. And the pass compared
functions that could only ever run one after the other as if they could
race.

The owner decided, for roadmap P54 (spec #432), to kill the false
positives at the source and never truncate real findings: fix the
output's shape rather than cut its length. This ADR replaces ADR-0034's
output shape and records the two input rules both readings now run
under. ADR-0033's kept-bodies rule survives untouched. Its lock
comparison takes the keying rule as an amendment there.

## Decision

Three rules, each pinned at the scan seam as it shipped:

- **One race claim per shared global (issue #434).** This is the
  *per-global race claim*. The race reading buckets the kept bodies'
  access sites into a global→accessors index, in first-sighting order.
  A global named by two or more accessor functions lands one
  `SyncFinding::DataRace`, only if at least one access reads and at
  least one writes. The record names the global, with its readers and
  writers in listing order, each function named once per list. It
  counts the accesses no recognized guard covers. Each accessor
  contributes one example access statement to the record. The claim is
  about the global, so it attaches to no single function — its
  `function` answers `""`, like the global-state crate's rollup entry.
  ADR-0034's mixed read/write gate and same-lock suppression carry
  over, read over the whole bucket. When one lock object's protected
  spans cover every access across every accessor, the accessors guard
  the data together, and properly locked data is not a race. Beside
  it, the *direct guard* rule drops the claim too (issue #437): when
  every access of the global sits under a recognized atomic call
  naming it, or the global is reached only through a TLS index, the
  reading drops the race claim. The per-body atomic and TLS findings
  stay filed. Confidence stays **60** — the unprotected accesses are
  still absence-of-evidence. The evidence string keeps naming each
  side's statement, so a two-sided claim reads as it did under
  ADR-0034.
- **Lock comparisons key on one lock instance (issue #435).** This is
  the *single-lock-instance rule*. A lock-order sequence keeps only
  acquisitions whose lock name could stand for the same object in both
  bodies. The global-state crate's shared name rule (`is_global_name`)
  decides, and it has exactly one implementation there. The rule
  rejects names a decompiler mints for one frame: stack slots, typed
  temporaries such as `uVar1`, register names, and `stack`
  pseudo-words. It also rejects the body's own words, type names and
  keywords. What survives names a program symbol or a named heap
  handle. A `local_20` lock never leaves its own frame, so two
  same-named stack-slot locks form no conflict. The tie between the
  two bodies stays the decompiler's naming, not resolved data flow,
  exactly as ADR-0033 accepted. The rule drops only names that cannot
  be shared.
- **Pair only functions that could run at the same moment — the
  concurrent-reachability gate (issue #436).** Both readings pair only
  bodies the gate admits. Entries are the export listing and every
  thread-start argument that a configured spawn call names inside a
  kept body. From the entries, a forward walk follows direct call
  edges derived from the kept bodies themselves. The walk adds no
  engine reads. A body the walk never reaches could only run
  sequentially, so it shares no lock order and no racing global with
  any other body. The gate admits its exclusions instead of hiding
  them. The pass reports the excluded bodies to the scan. The coverage
  record's `cross-function-pairs` facet then reads Partial with an
  "`N` functions excluded from cross-function pairing" line: a bounded
  set of names inline, the rest counted. The `function-bodies` facet
  stays Complete — the gate excluded pairings, never reads. A gated
  findings list can therefore never render alike with a full-coverage
  one.

## Consequences

- Output scales with the program's shape, not with the square of its
  function count: race claims land once per shared global, lock
  conflicts only where one instance is possible, and pairs only where
  concurrency is possible. A normal program's concurrency document
  lands under a megabyte. The cross-function findings cap (issue #438)
  stays a safety net, not the primary answer. When the cap engages, it
  stamps a truncation admission with the whole count into the same
  coverage facet.
- The two input rules err toward silence: a lock named like a local, or
  a body unreachable from any export or spawn argument, forms no claim.
  A gated scan can therefore miss a race between two unreachable
  functions. The coverage record's exclusion line is the admitted cost.
- The aggregate record names no single function: the CLI's kind
  breakdown counts one aggregate race as one `data_race` whatever its
  accessor count. The per-kind names are unchanged. The persist and
  prompt round trip is pinned with the aggregate shape intact.
- Lock-order conflicts keep their pair shape — one finding per
  conflicting lock pair, on the earlier function in listing order,
  naming the later one as `partner`. Only their inputs changed: gated
  pairing, keyed names. Scan order survives: per-function findings
  first, then lock-order conflicts, then races in the order the scan
  first sighted each global. Two scans of one program still diff
  cleanly.
