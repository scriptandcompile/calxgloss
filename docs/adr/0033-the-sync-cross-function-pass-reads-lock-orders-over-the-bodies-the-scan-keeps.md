# ADR-0033: The sync cross-function pass reads lock orders over the bodies the scan keeps

- **Status:** Accepted
- **Date:** 2026-10-14
- **Deciders:** Arthur (solo project)

## Context

Phase 5 of the sync scan (issue #163) asks the scan to see lock
discipline across function boundaries. Two functions that acquire the
same two lock objects in opposite relative orders — the classic
deadlock shape — are invisible to every per-body detector: each
detector stops at its body's closing brace. The reading must use the
same tagged-union finding list, persistence, CLI kind breakdown, and
escalate prompt path as every other detector. And it must not disturb
the scan's two provable contracts: each function is decompiled exactly
once, and the skip-rate breaker aborts the run when too many functions
fail to decompile. The memory crate solved the same problem for
allocation lifecycles in ADR-0027, by running its cross-function pass
over the bodies the scan had already fetched.

## Decision

Mirror ADR-0027 in the sync crate:

- A new `cross_function` module holds a stateless `CrossFunctionAnalyzer`.
  The evidence engine runs it **after the per-function walk**, over the
  `DecompiledFunction` values the walk kept. The lock map is built
  from those bodies, using the same call-site scan the mutex detector
  uses — **no new `ScanSource` reads** — so the exactly-once-decompile
  guarantee and the skip-rate breaker survive untouched, proven by
  their existing tests staying green.
- Per function, the pass records the sequence of **distinct lock
  objects acquired in body order**. It matches acquisitions against
  the **mutex detector's configured name sets** — custom acquire
  spellings reach it through `with_mutex`, not a private default set —
  and it links calls to lock objects through the pairing detector's
  own `lock_object` extraction (made `pub(crate)`), so the two
  readings cannot disagree about which lock object an acquire
  identifies.
- When two functions' sequences hold the same two locks in opposite
  relative orders, the pass reports one `SyncFinding::LockOrder` **per
  conflicting lock pair**. The finding is attached to the earlier
  function in listing order, records the later function as `partner`,
  and names both lock objects, at confidence **70** — both orders are
  explicit body evidence, level with an in-body mutex pairing. The two
  functions' acquire sequences are the evidence.
- Cross-function findings **are appended after the per-function
  findings**, both groups in listing order, keeping the persisted
  document diffable. A function whose decompile failed is absent from
  the kept bodies: it forms no sequence and produces no conflict.

## Consequences

- The scan's cost and safety model is untouched: one decompile per
  function, the breaker still aborting a run on decompile failures,
  and the finding order still stable across scans. The contract tests,
  unmodified, still pin all of this.
- The sequences depend on the decompiler's variable naming: the same
  lock named differently in two functions reads as no conflict. That
  is the pairing detector's existing limitation, inherited unchanged
  rather than made worse.
- The once-per-lock-pair rule means a full reversal of three locks
  reads as three two-lock conflicts. That matches how a deadlock
  review works: one lock pair at a time.
- The evidence engine now holds every decompiled body for the scan's
  duration, so peak memory grows with the size of the program's
  decompiled text. Accepted: the bodies are the same text the scan
  already read once, and the alternative — re-fetching them for the
  pass — would break the exactly-once contract.
- The data-race reading (issue #168) builds next on these kept bodies;
  its same-lock suppression rule is a separate decision.
