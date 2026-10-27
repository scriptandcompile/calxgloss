# ADR-0027: The memory cross-function pass runs over the scan's kept bodies, ties releases positionally, and lets the first releasing callee win

- **Status:** Accepted
- **Date:** 2026-10-14 (P4.5-1 shipped, issue #158)
- **Deciders:** Arthur (solo project)

## Context

All three memory detectors stop at a body's closing brace. An allocation
that the function never releases is invisible to the pairing: "never
released → not reported". And the callee that does release it pairs
nothing, because no allocation sits in its own body. A lifecycle that
crosses a call boundary — ownership moved into a helper that frees —
was reported by neither half.

Spec #157 asked for cross-function allocation tracking. The questions
this had to settle: where does the callee's body come from (re-fetch
through the graph, or the scan's own kept bodies)? What counts as the
callee releasing the value — name matching, or positional binding? What
happens when several callees could release one block? Where do the new
findings land in the persisted order? And how does the pairing
detector's pinned silence on unpaired allocations survive?

## Decision

- **The pass runs after the per-function pass, over the kept bodies the
  scan already held — no new Ghidra round trips.** The evidence engine
  collects the `DecompiledFunction` values the per-function pass
  decompiled and passes them to a pure `CrossFunctionAnalyzer`. The call
  map is derived from those bodies with the same pseudo-C call scan the
  pairing walk uses. This is the ADR-0014/ADR-0024 precedent: every
  function in the listing is already in hand, so the caller-fetch route
  the typeinfer caller→callee pass needed adds nothing here.
  Exactly-once decompiles and the skip-rate breaker are untouched.
- **The pass starts from the pairing walk's own open-allocation list.**
  `AllocatorTracker::open_allocations` runs the same walk as
  `detect_pairs`: the same configured name sets, the same variable
  binding, and the same most-recent-allocation-closing rule. It returns
  what the walk leaves standing. The pairing's contract ("report only
  pairs, stay silent on unpaired allocations") is untouched. The two
  readings can never disagree about what stands open.
- **The callee's release is tied positionally.** The argument sitting at
  position *i* at the call site arrives in the parameter that the
  callee's signature declares at *i*. The release must name that
  parameter as the deallocator's first argument, seen through any cast —
  the same reading the in-body pairing applies to a local. The tie is
  the decompiler's positional naming, not resolved data flow. The
  finding says so by carrying the relevant line from each body as
  evidence.
- **Only functions this scan decompiled can release.** A callee outside
  the scanned set — a library routine, a thunk, or a function whose
  decompile failed — shows no release, so it claims nothing. A missing
  half fabricates no cross-function claim.
- **The first releasing callee in source order wins.** Where one open
  variable reaches several releasing callees, only the first call site
  claims it. One moved block moves once. The rule also keeps two scans
  of one program byte-identical.
- **Confidence 70 — level with an in-body pair.** Both sides are
  explicit calls to recognized names, and the hand-off site is a
  concrete line. But the variable-to-parameter tie is positional naming,
  not one body's assignment. So this reading neither outranks nor falls
  below the direct pairing.
- **Findings append after the per-function findings, in listing order,
  and within one function in allocation order.** The persisted list
  stays stable and diffable. The existing scan-order contract —
  per-function findings grouped by function in listing order — holds
  unchanged with the new group appended.

## Consequences

- The finding union gained a fourth kind, `cross_function`, which uses
  the existing accessors. The persisted JSON, the CLI report's kind
  breakdown, and the prompt conversion picked it up with no shape
  change.
- The evidence engine now holds every body for the scan's duration. The
  memory cost of a scan is one program's worth of pseudo-C. The
  cross-function depth requires this, and the sequential walk alone did
  not.
- The open-allocation reading is the seam the rest of P4.5 builds on.
  Ownership-transfer detection (#159) reads where those open variables
  escape. Leak detection (#160) reports the ones that escape nowhere.
  The smart-pointer upgrade (#161) reads what the callee does with what
  it was handed.
