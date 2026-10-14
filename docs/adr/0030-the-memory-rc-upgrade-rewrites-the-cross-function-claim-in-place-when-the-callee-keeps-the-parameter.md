# ADR-0030: The memory Rc upgrade rewrites the cross-function claim in place when the callee's body keeps the parameter, and the keep is a store outside the callee's own frame

- **Status:** Accepted
- **Date:** 2026-10-14 (P4.5-4 shipped, issue #161)
- **Deciders:** Arthur (solo project)

## Context

ADR-0027/0028 read a handed-over block as a move: `Box<T>` into the
releasing callee, or out to the caller. But a callee that stores the
parameter somewhere the call survives — a global, a struct field —
keeps a copy that outlives the move. A `Box` moved into that callee
leaves the stored copy dangling in the Rust translation; the honest
pattern is shared ownership. The scan already holds the callee's body
(the pair reading reads its release), so the keep is visible at zero
extra Ghidra cost.

The questions: what counts as keeping (any assignment? which
left-hand sides?), which claims the upgrade touches, what happens to
the confidence and the evidence, and how the upgrade stays coherent
with the one-claim-per-allocation rule.

## Decision

- **The keep is a store outside the callee's own frame.** An
  assignment whose right side, seen through any cast, is the
  parameter whole, and whose left side names a place the call
  survives: a field access (`obj.field = param_1;`, `this->ptr =
  param_1;`) or a plain identifier the decompiler did not name as one
  of its own locals — Ghidra names locals `param_N`, `local_N`, and
  the `*Var<N>` families, so any other plain name is a program
  symbol. A store through a bare dereference (`*puVar1 = param_1;`)
  names no place the scan can tell from a stack slot, so it keeps
  nothing; a store of an interior pointer (`global_ptr = param_1 +
  1;`) or of a different parameter keeps nothing.
- **The upgrade rewrites the claim that already exists.** Whether
  the open allocation became a pair (ADR-0027) or a handed-to-callee
  transfer (ADR-0028), a keep by the callee that body was read turns
  that one finding's suggestion from `Box<T>` to `Rc<T>` and appends
  the store line to its evidence. The confidence is the claim's own
  — 70 pair, 65 transfer — unchanged: the keep refines *which*
  pattern, not how strongly the relationship was read. One claim per
  allocation means Box and Rc can never contradict each other for
  one pointer.
- **A keep can only be read where a body was read.** A returned
  pointer has no callee body, and a callee outside the scanned set
  has none this scan holds — both keep the plain reading. No new
  Ghidra reads: the keep reads the same kept bodies the pair uses.
- **`Arc<T>` stays the reference-count detector's spelling.** The
  keep reads a stored pointer, not a count bump, and thread-awareness
  is out of scope: shared-but-possibly-cross-thread is not something
  this evidence can distinguish.

## Consequences

- No new finding kind: the upgrade rides the existing `suggestion`
  field of the pair and transfer records, so persistence, the CLI,
  and the prompt conversion carry `Rc<T>` with no shape change.
- The decompiler-local naming scheme is now load-bearing: a program
  whose locals were *user*-named outside the `param_N`/`local_N`/
  `*Var<N>` scheme reads its local stores as global keeps. Scans run
  against unworked programs, where the scheme holds; the risk is
  noted, not engineered away.
- The refcount detector's `Rc<T>` suggestions (AddRef/Release
  shapes) and this upgrade are disjoint readings of the same
  pattern family: one sees the counts, this one sees the store.
