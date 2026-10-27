# ADR-0015: Propagate inferred types caller→callee on a per-scan caller-body cache

- **Status:** Accepted
- **Date:** 2026-10-13 (P2.5-2 shipped, issue #144)
- **Deciders:** Arthur (solo project)

## Context

ADR-0014 propagated types from a callee out to its callers. But a helper
whose own body proves nothing stays untyped — one that only forwards or
stores its parameters, even when every caller hands it a string literal.
Ticket #144 is the reverse direction. It reads what an analyzed
function's callers actually pass at their call sites, and types that
function's own parameters from those arguments. The contract the callers
reveal can then type a helper that the body cannot.

Three design questions came up: where the caller bodies come from, what
counts as evidence about a parameter, and how the new readings compete
with the inline ones. Unlike the callee→caller pass, this one cannot
work from the kept bodies the scan already holds: the callers of an
analyzed function are other functions, mostly not yet decompiled. So
this is the first propagation pass that adds Ghidra round-trips. Also,
the known-signature database held parameter contracts only. "A known
routine's result" was therefore not yet a readable argument.

## Decision

A second propagator method
(`cross_function::CrossFunctionPropagator::propagate_to_callee`) runs
after the callee→caller pass. It walks the listing in order and emits
**parameter records for the callee only** — never call-site records.

- **The evidence is what callers hand in.** An argument types a
  parameter only when it shows a recognizable type on its own, without
  the callee's body to explain it. Three forms qualify: a bare
  identifier naming one of the caller's parameters that has a surviving
  inline reading (the caller passes along, untouched, something it was
  itself handed); a string literal (`"…"` is `char *`, `L"…"` is
  `wchar_t *`); or a call to a known-signature routine, read as that
  routine's **return type**. A numeric literal, a cast, an indexing or
  member operand, and an identifier the scan never typed say nothing.
  That position gets no reading. The call site may still be typed by the
  callee→caller pass, but the callee's parameter is not.
- **The signature database gains return types.** `KnownSignature` grows
  a `returns: Option<&'static str>` field. The allocator and string
  routines fill it in (`malloc` → `void *`, `strlen` → `size_t`, …).
  `void` returns and bare success flags (`free`, `CloseHandle`,
  `strcmp`) leave it `None`, because their width says nothing about a
  callee parameter.
- **Caller bodies are fetched at most once per scan.** The evidence
  engine seeds a per-scan cache from the bodies the inline pass already
  decompiled. A caller already in the listing costs nothing. Any other
  caller is decompiled once and cached — **failures cached too** — so a
  caller that will not decompile is never asked for twice. The analyzed
  function's own body is still decompiled exactly once. Return-type
  inference (#146) reuses this same cache.
- **Confidence 65, the bottom of the cross-function band.** A
  caller-argument reading combines evidence across call sites, and it is
  one step removed from the callee's direct body evidence. So it scores
  level with the propagated caller-parameter readings. The inline vtable
  reading (85) always wins against it. Any inline reading wins a tie,
  because the inline chain is always resolved first.
- **Only declared positions get records.** A reading is recorded only
  where the callee's own signature declares a parameter. If a caller
  passes more arguments than the callee declares (a Ghidra prototype
  gap), nothing gets typed.
- **One pass, no fixpoint.** Like ADR-0014, the pass reads only the
  inline survivors, from the same surviving-reading map the
  callee→caller pass uses. So a caller's propagated reading does not
  itself become evidence in the same scan.

## Consequences

- The scan now makes one extra `callers` query per analyzed function,
  plus one decompile per caller outside the listing. This is the first
  pass that grows the scan's Ghidra round-trips. The cache bounds the
  cost: no function's body is fetched twice, and a failed fetch costs
  one round-trip total.
- Helpers with opaque bodies — forwarders, setters, storage writers —
  now reach the translator's prompts already typed. That is the point of
  this direction.
- The caller-body cache is the shared plumbing that return-type
  inference (#146) builds on. It lives in the evidence engine, not in
  the propagator, so the propagator stays stateless and fetch-free like
  its sibling pass.
- A propagated reading rarely wins outright today: any function the
  inline detectors already typed keeps its reading. This direction
  proves its value on the untyped-helper case. The confidence ladder
  keeps a propagated reading from ever replacing direct evidence.
- The CLI's method breakdown is unchanged. `cross_function` records
  were already counted since ADR-0014; only their volume grows.
