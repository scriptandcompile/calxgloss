# ADR-0033: The sync cross-function pass reads lock orders over the bodies the scan keeps

- **Status:** Accepted
- **Date:** 2026-10-14
- **Deciders:** Arthur (solo project)

## Context

Phase 5 of the sync scan (issue #163) asks the scan to see lock
discipline across function boundaries: two functions that acquire the
same two lock objects in opposite relative orders — the classic
deadlock shape — are invisible to every per-body detector, each of
which stops at its body's closing brace. The reading has to land on
the same tagged-union finding list, persistence, CLI kind breakdown,
and escalate prompt plumbing as every other detector, and it must not
disturb the scan's two provable contracts: each function is
decompiled exactly once, and the skip-rate breaker gates the run on
decompile failures. The memory crate solved the same shape for
allocation lifecycles in ADR-0027 by running its cross-function pass
over the bodies the scan already fetched.

## Decision

Mirror ADR-0027 in the sync crate:

- A new `cross_function` module holds a stateless `CrossFunctionAnalyzer`
  that the engine runs **after the per-function walk**, over the
  `DecompiledFunction` values the walk kept. The lock map is derived
  from those bodies with the same call-site scan the mutex detector
  uses — **no new `ScanSource` reads** — so the exactly-once-decompile
  guarantee and the skip-rate breaker survive untouched, proven by
  their existing tests staying green.
- Per function, the pass records the sequence of **distinct lock
  objects acquired in body order**. It matches acquisitions against
  the **mutex detector's configured name sets** — custom acquire
  spellings reach it through `with_mutex`, not a private default set —
  and ties calls to lock objects through the pairing detector's own
  `lock_object` extraction (made `pub(crate)`), so the two readings
  cannot disagree about what an acquire names.
- Two functions whose sequences hold the same two locks in opposite
  relative orders land one `SyncFinding::LockOrder` **per conflicting
  lock pair** on the earlier function in listing order, naming the
  later one as `partner` and both lock objects, at confidence **70** —
  both orders are explicit body evidence, level with an in-body mutex
  pairing. The two functions' acquire sequences are the evidence.
- Cross-function findings **append after the per-function findings**,
  both groups in listing order, keeping the persisted document
  diffable. A function whose decompile failed is absent from the kept
  bodies, forms no sequence, and fabricates no conflict.

## Consequences

- The scan's cost and safety model is untouched: one decompile per
  function, the breaker gating as before, and the finding order
  staying stable across scans — all still pinned by the contract
  tests, unmodified.
- Sequences key on the decompiler's variable naming: the same lock
  named differently in two functions reads as no conflict. That is
  the pairing detector's existing limitation, inherited whole rather
  than made worse.
- The once-per-lock-pair rule means a full reversal of three locks
  reads as three two-lock conflicts — the shape a deadlock review
  takes one lock pair at a time.
- The engine now holds every decompiled body for the scan's duration,
  so peak memory grows with the program's decompiled text. Accepted:
  the bodies are the same text the scan already read once, and the
  alternative — re-fetching for the pass — would break the
  exactly-once contract.
- The kept bodies are the substrate the data-race reading (issue #168)
  builds on next; its same-lock suppression rule is a separate
  decision.
