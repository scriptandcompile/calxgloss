# ADR-0014: Propagate inferred types callee→caller in one post-inline pass

- **Status:** Accepted
- **Date:** 2026-10-13 (P2.5-1 shipped, issue #143)
- **Deciders:** Arthur (solo project)

## Context

The typeinfer detectors are inline. Each one reads a single decompiled
body, and its readings stop at that body's closing brace. A helper whose
parameter the body reads as `char *` types nothing outside itself. The
record vocabulary already defines the call-site record kind
(`InferredCallType`), but no detector has ever emitted it. Spec #142 asks
for types to cross function boundaries. Ticket #143 covers the
callee→caller direction: the callee's known parameter contract should type
the arguments sitting at its call sites, and should also type the caller's
own parameter when an argument *is* one.

The obvious sources for a callee's contract are a signature database (the
approach the known-type evidence engine uses), a second round of Ghidra
reads, or the scan's own surviving readings. The obvious shapes for the
new pass are an interleaved step in the per-function loop, or a separate
pass over the whole program.

## Decision

A dedicated cross-function pass (`cross_function::CrossFunctionPropagator`)
runs **after the inline detectors**. It reads the bodies the inline pass
already decompiled, and it propagates **only the scan's own surviving
parameter readings**.

- **The contract is the scan's own output.** A callee's contract is its
  conflict-resolved parameter records — no signature table, no extra
  Ghidra round-trips. A callee that is absent from the surviving-reading
  map (a library routine, a thunk, or a function no detector read) has
  nothing to propagate. This is also what makes "user-defined callee"
  precise: it is a function this scan typed.
- **One decompile per function still holds.** The evidence engine keeps
  the decompiled bodies from the inline pass and hands the same
  `DecompiledFunction` values to the propagator. The cross-function pass
  adds no Ghidra reads.
- **Resolve first, then propagate.** The inline records resolve among
  themselves before the pass runs, so only surviving readings become
  contracts — never contested or weaker ones. The propagated records then
  compete with the inline ones in a second `resolve_conflicts` pass. One
  parameter can stand read by its own body and by a callee's contract at
  once. The existing rule decides: highest confidence wins, and a tie
  keeps the first-seen record. Inline records are listed first, so a
  direct body reading wins any tie.
- **The record shape is the existing vocabulary.** A typed argument gets
  an `InferredCallType` (method `cross_function`, scope `function`,
  confidence 70, the call line as evidence). When the argument *is* one of
  the caller's own parameters, the pass also emits a `cross_function`
  parameter record at confidence 65, so the type moves one step up the
  call chain. This band sits deliberately below most inline evidence: a
  propagated reading is one inference removed from direct body evidence,
  and the step to the caller's parameter is one step further. Only
  bare-identifier arguments are read: a literal, cast, or nested call
  does not name a single value to type.
- **One pass, no fixpoint.** The pass propagates from inline survivors
  only. A caller-parameter record it emits does not itself become a
  contract in the same scan. Multi-hop chains are not chased in one scan —
  the caller→callee direction (#144) or a later iteration can revisit
  this.

## Consequences

- The call-site record kind appears in scan results for the first time.
  It flows through conflict resolution, persistence, and prompt rendering
  unchanged, because those paths already keyed on (function, callee, arg
  position).
- Scan memory grows: the evidence engine holds every decompiled body
  until the cross-function pass finishes, instead of dropping each body
  after reading it.
- The CLI's method breakdown gains a `cross_function` count.
- Today, a two-hop chain moves only one step per scan. If that proves too
  weak in practice, the fix is an iterative pass, or #144's reverse
  direction feeding the same map — not a change to the record shape.
