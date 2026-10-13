# ADR-0014: Propagate inferred types callee→caller in one post-inline pass

- **Status:** Accepted
- **Date:** 2026-10-13 (P2.5-1 shipped, issue #143)
- **Deciders:** Arthur (solo project)

## Context

The typeinfer detectors are inline: each reads one decompiled body and
its readings stop at that body's closing brace. A helper whose parameter
the body reads as `char *` types nothing outside itself, and the
call-site record kind (`InferredCallType`) that the record vocabulary
already defines has never been emitted by any detector. Spec #142 asks
for types to cross function boundaries; ticket #143 is the callee→caller
direction: the callee's known parameter contract should type the
arguments sitting at its call sites, and climb to the caller's own
parameter when an argument *is* one.

The obvious sources for a callee's contract are a signature database
(the known-type engine's approach), a second round of Ghidra reads, or
the scan's own surviving readings. The obvious shapes for the new pass
are an interleaved step in the per-function loop or a separate pass over
the whole program.

## Decision

A dedicated cross-function pass (`cross_function::CrossFunctionPropagator`)
runs **after the inline detectors**, over the bodies the inline pass
already decompiled, and propagates **only the scan's own surviving
parameter readings**.

- **The contract is the scan's own output.** A callee's contract is its
  conflict-resolved parameter records — no signature table, no extra
  Ghidra round-trips. A callee absent from the surviving-reading map (a
  library routine, a thunk, a function no detector read) carries nothing
  to propagate, which is also what makes "user-defined callee" precise:
  it is a function this scan typed.
- **One decompile per function still holds.** The engine keeps the
  decompiled bodies from the inline pass and hands the same
  `DecompiledFunction` values to the propagator; the cross-function pass
  adds no Ghidra reads.
- **Resolve first, then propagate.** The inline records resolve among
  themselves before the pass runs, so only surviving readings — never
  contested or weaker ones — become contracts. The propagated records
  then compete with the inline ones in a second `resolve_conflicts`
  pass: one parameter can stand read by its own body and by a callee's
  contract at once, and the existing highest-confidence-wins,
  tie-keeps-first-seen rule decides, with inline records listed first
  so a direct body reading wins any tie.
- **The record shape is the existing vocabulary.** A typed argument gets
  an `InferredCallType` (method `cross_function`, scope `function`,
  confidence 70, the call line as evidence); when the argument names
  one of the caller's own parameters, a `cross_function` parameter
  record at confidence 65 rides along, so the type climbs one step up
  the call chain. The band sits deliberately below most inline evidence
  — a propagated reading is one inference removed from direct body
  evidence, and the climb one step further. Only bare-identifier
  arguments are read: a literal, cast, or nested call names no single
  value to type.
- **One pass, no fixpoint.** The pass propagates from inline survivors
  only; a caller-parameter record it emits does not itself become a
  contract in the same scan. Multi-hop chains are not chased per scan —
  the caller→callee direction (#144) and any later iteration can
  revisit this.

## Consequences

- The call-site record kind appears in scan results for the first time,
  and flows through conflict resolution, persistence, and prompt
  rendering unchanged — those paths already keyed on
  (function, callee, arg position).
- Scan memory grows: the engine holds every decompiled body until the
  cross-function pass finishes instead of dropping each after reading it.
- The CLI's method breakdown gains a `cross_function` count.
- A two-hop chain climbs only one step per scan today. If that proves
  too weak in practice, the fix is an iterative pass (or #144's reverse
  direction feeding the same map), not a change to the record shape.
