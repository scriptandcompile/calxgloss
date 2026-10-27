# ADR-0030: The memory Rc upgrade rewrites the cross-function claim in place when the callee's body keeps the parameter, and the keep is a store outside the callee's own frame

- **Status:** Accepted
- **Date:** 2026-10-14 (P4.5-4 shipped, issue #161)
- **Deciders:** Arthur (solo project)

## Context

ADR-0027 and ADR-0028 read a block that is passed over a call boundary
as a move: a `Box<T>` moved into the releasing callee, or moved out to
the caller. But a callee can also store the parameter somewhere the
call does not survive — a global or a struct field. That store keeps
a copy that outlives the move. If the Rust translation moves a `Box`
into that callee, the stored copy dangles. The honest pattern is
shared ownership. The scan already holds the callee's body, because
the pair reading reads the callee's release. So the keep is visible at
zero extra Ghidra cost.

The questions: what counts as keeping — any assignment? which
left-hand sides? which claims does the upgrade change? what happens
to the confidence and the evidence? and how does the upgrade stay
coherent with the one-claim-per-allocation rule?

## Decision

- **The keep is a store outside the callee's own frame.** A keep is an
  assignment whose right side, seen through any cast, is the parameter
  whole, and whose left side identifies a place that outlives the
  call:
  a field access (`obj.field = param_1;`, `this->ptr =
  param_1;`) or a plain identifier the decompiler did not name as one
  of its own locals. Ghidra names locals `param_N`, `local_N`, and the
  `*Var<N>` families, so any other plain name is a program symbol. A
  store through a bare dereference (`*puVar1 = param_1;`) identifies
  no place the scan can tell apart from a stack slot, so it keeps
  nothing. A store of an interior pointer (`global_ptr = param_1 +
  1;`) keeps nothing, and so does a store of a different parameter.
- **The upgrade rewrites the claim that already exists.** The open
  allocation has already become either a pair (ADR-0027) or a
  transfer into the callee (ADR-0028). If that callee makes a keep,
  the upgrade changes that one finding's suggestion from `Box<T>` to
  `Rc<T>` and appends the store line to its evidence. The confidence
  stays the claim's own — 70 pair, 65 transfer — unchanged: the keep
  refines *which* pattern holds, not how strongly the relationship was
  read. Because there is one claim per allocation, Box and Rc can
  never contradict each other for one pointer.
- **A keep can only be read where a body was read.** A returned
  pointer has no callee body. A callee outside the scanned set has no
  body this scan holds. Both keep the plain reading. No new Ghidra
  reads: the keep reads the same kept bodies the pair reading uses.
- **`Arc<T>` stays the reference-count detector's spelling.** The keep
  reads a stored pointer, not a reference-count increase.
  Thread-awareness is out of scope: shared-but-possibly-cross-thread
  is not something this evidence can tell apart.

## Consequences

- No new finding kind: the upgrade writes into the existing
  `suggestion` field of the pair and transfer records, so persistence,
  the CLI, and the prompt conversion show `Rc<T>` with no shape
  change.
- The decompiler-local naming scheme now carries weight: a program
  whose locals were *user*-named outside the `param_N`/`local_N`/
  `*Var<N>` scheme reads its local stores as global keeps. Scans run
  against unworked programs, where the scheme holds. The risk is
  recorded, not engineered away.
- The refcount detector's `Rc<T>` suggestions (AddRef/Release shapes)
  and this upgrade are disjoint readings of the same pattern family:
  one sees the reference counts, this one sees the store.
