# ADR-0015: Propagate inferred types caller→callee on a per-scan caller-body cache

- **Status:** Accepted
- **Date:** 2026-10-13 (P2.5-2 shipped, issue #144)
- **Deciders:** Arthur (solo project)

## Context

ADR-0014 carried types from a callee out to its callers, but a helper
whose own body proves nothing — one that only forwards or stores its
parameters — stays untyped even when every caller hands it a string
literal. Ticket #144 is the reverse direction: read what an analyzed
function's callers actually pass at their call sites and type that
function's own parameters from it, so the contract the callers reveal
types a helper the body cannot.

The shape questions were where the caller bodies come from, what counts
as evidence about a parameter, and how the new readings compete with the
inline ones. Unlike the callee→caller pass, this one cannot work from
the bodies the scan already holds: the callers of an analyzed function
are other functions, mostly not yet decompiled, so this is the first
propagation pass that adds Ghidra round-trips. And the known-signature
database carried parameter contracts only, so "a known routine's result"
was not yet a readable argument.

## Decision

A second propagator method
(`cross_function::CrossFunctionPropagator::propagate_to_callee`) runs
after the callee→caller pass, walks the listing in order, and emits
**parameter records for the callee only** — never call-site records.

- **The evidence is what callers hand in.** An argument types a
  parameter only when it carries a recognizable type without needing the
  callee's body to say so: a bare identifier naming one of the caller's
  parameters that has a surviving inline reading (the caller passes
  along, untouched, something it was itself handed); a string literal
  (`"…"` is `char *`, `L"…"` is `wchar_t *`); or a call to a
  known-signature routine, read as that routine's **return type**. A
  numeric literal, a cast, an indexing or member operand, and an
  identifier the scan never typed say nothing, and the position gets no
  reading — the call site may still be typed by the callee→caller pass,
  but the callee's parameter is not.
- **The signature database gains return types.** `KnownSignature` grows
  a `returns: Option<&'static str>` field, populated for the allocator
  and string routines (`malloc` → `void *`, `strlen` → `size_t`, …) and
  left `None` for `void` returns and bare success flags (`free`,
  `CloseHandle`, `strcmp`), whose width says nothing about a callee
  parameter.
- **Caller bodies are fetched at most once per scan.** The engine seeds
  a per-scan cache from the bodies the inline pass already decompiled; a
  caller already in the listing costs nothing, any other caller is
  decompiled once and cached — **failures cached too**, so a caller that
  will not decompile is never asked for twice. The analyzed function's
  own body is still decompiled exactly once. This cache is the seam
  return-type inference (#146) reuses.
- **Confidence 65, the bottom of the cross-function band.** A
  caller-argument reading is aggregated across call sites and one step
  removed from the callee's direct body evidence, so it sits level with
  the caller-parameter climb: an inline vtable reading (85) beats it
  outright, and any inline reading wins the tie because the inline chain
  is always resolved first.
- **Only declared positions get records.** A reading lands only where
  the callee's own signature declares a parameter; a caller passing more
  arguments than the callee declares (a Ghidra prototype gap) types
  nothing.
- **One pass, no fixpoint.** Like ADR-0014, the pass reads only the
  inline survivors — the same surviving-reading map the callee→caller
  pass uses — so a caller's propagated reading does not itself become
  evidence in the same scan.

## Consequences

- The scan now makes one extra `callers` query per analyzed function,
  plus one decompile per caller outside the listing — the first pass
  that grows the scan's Ghidra round-trips. The cache bounds the damage:
  no function's body is fetched twice, and a failed fetch costs one
  round-trip total.
- Helpers with opaque bodies — forwarders, setters, storage writers —
  now reach the translator's prompts typed, which is the point of the
  direction.
- The caller-body cache is the shared plumbing return-type inference
  (#146) builds on; it lives in the engine, not the propagator, so the
  propagator stays stateless and fetch-free like its sibling pass.
- A propagated reading rarely wins outright today: any function the
  inline detectors already typed keeps its reading. The direction earns
  its keep on the untyped-helper case, and the confidence ladder keeps
  that from ever displacing direct evidence.
- The CLI's method breakdown is unchanged — `cross_function` records
  were already counted since ADR-0014; only their volume grows.
