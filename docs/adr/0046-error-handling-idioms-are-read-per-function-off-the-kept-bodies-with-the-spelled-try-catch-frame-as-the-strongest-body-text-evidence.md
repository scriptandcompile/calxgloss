# ADR-0046: Error-handling idioms are read per function off the kept bodies, with the spelled try/catch frame as the strongest body-text evidence

- **Status:** Accepted
- **Date:** 2026-10-23 (P15-1 shipped, issue #287)
- **Deciders:** Arthur (solo project)

## Context

MSVC binaries protect themselves two very different ways — structured
exception handling (SEH) and the C cleanup-on-failure idiom — and
neither shape is visible to the translator today: the LLM renders an
SEH frame as straight-line logic and drops the exception semantics,
and the failure contract the frame encodes dissolves into ad-hoc Rust
error values that baseline tests never pin (spec #230). Where the
decompiler *recognizes* an SEH frame it already spells the frame into
the decompiled body as a `try {` … `catch(...){` block — a spelling
the seam's noise filter treats as P15 territory and passes through
byte-for-byte (issue #286). The tracer bullet (issue #287) reads that
spelling and lands a persisted finding; the track's later tickets add
the exception-API readings, the goto-cleanup ladder, the failure-code
records, and the cross-function propagation.

The shape questions were where the reading runs, what may stand as a
spelled frame, where the spelled block sits on the Evidence ladder, and
whether a finding ever writes back. Like parameter direction (ADR-0045)
this is a body-text reading, not a program fact: ADR-0020/0021 keep the
write trait silent here, so an idiom can only ever be a reported
reading. And like the callback cross-function pass (ADR-0035) the
reading must ride the scan's two provable contracts — each function
decompiled exactly once, the skip-rate breaker gating the run — without
adding a single engine read.

## Decision

A new evidence crate (`calxgloss-errhandling`, evidence context) built
on the established engine-crate shape — generic over the `ScanSource`
with a `with_source` constructor and per-detector `with_*` builders, a
tagged-union findings enum with the standard accessors, a metadata-
stamped result, and a persistor — exactly as the global-state (P13) and
known-library (P14) tracks shaped it.

- **A per-function detector over the kept bodies.** `SehFrameDetector`
  reads each function's frames **inline, function by function, off the
  body the scan already kept** — the same kept bodies every body-text
  pass rides (ADR-0045's rails) — **no extra engine reads, no
  disassembly, no control-flow-graph dependency**. The engine decompiles
  each function exactly once and the detector reads that one
  `DecompiledFunction`, so the exactly-once-decompile invariant and the
  ADR-0026 skip-rate breaker hold unchanged, proven by their contract
  tests staying green.
- **The spelled frame, decided by shape.** The frame stands where the
  body pairs a `try {` line — the whole trimmed line, so a `try`
  standing inside a larger statement is not a frame opening — with a
  *later* line opening a spelled `catch` clause: `catch` immediately
  followed by its `(`, so an identifier merely starting with the word
  (`catch_count = 3;`) claims nothing. One frame block is one claim per
  function, the first in body order; the evidence is the `catch` clause
  line that completes the frame — the clause is the deciding sighting,
  since a `try` with no handler claims nothing. A lone `try`, a lone
  `catch`, and an ordinary guard all stay silence: absence of a spelled
  block is unknown, never a guessed frame.
- **A tagged union, first kind `seh_frame`.** `SehFrame` (function,
  confidence, evidence, suggestion) joins `ErrhandlingFinding` under
  serde tag `"seh_frame"`; the idiom kind lives in the tag, not a
  field, so a persisted record can never disagree with its own tag. The
  track's later families — named personality-handler thunks and
  exception-API calls, the `RaiseException` reading, the goto-cleanup
  ladder, and the per-code failure-code records (spec #230) — join the
  union as their own kinds; consumers read the shared accessors
  (function, kind, confidence, evidence, target, suggestion) without
  naming the family first.
- **The spelled-block band, anchored: 80.** The decompiler read the
  exception data and reconstructed the frame itself — the strongest
  error-handling evidence a kept body can carry, the body-text analogue
  of globalstate's exact-spelling band. The named-handler reading sits
  a rung below and the exception-API call a rung below that (spec
  #230's family ladder); each follow-up anchors its own band as it
  lands, strictly below the family above it, and no reading of a
  spelled block ever scores below 80.
- **Scan order holds.** Findings follow the function listing, function
  by function, so two scans of one program diff cleanly — the union's
  standing guarantee.
- **A new document, nothing existing touched.** One strict serde
  document per binary at `re/analysis/errhandling/{binary}.json`
  (ADR-0043's analysis-directory convention); a missing artifact and a
  corrupt one stay distinguishable to the loader (`NotFound` vs
  `Json`). No existing artifact changes shape, so every previously
  persisted analysis document loads byte-for-byte unchanged.
- **No write-back.** An idiom is not a program fact: findings are
  flag-only (ADR-0020), and what they instruct downstream — the ERROR
  HANDLING prompt sections, the testgen failure-code oracles — is
  derived from the persisted document elsewhere.

## Consequences

- The reading adds **zero engine round-trips**: it reads the
  `DecompiledFunction` the walk already fetched, so the one-decompile-
  per-function invariant the engine tests assert still holds with the
  detector on, and the reading adds no surviving state the walk must
  carry.
- Persisted results gain a new document under the union's `seh_frame`
  kind and the CLI gains `errhandling --binary <name> [--show]`,
  printing idiom, confidence, and evidence per function; nothing else
  reads the document yet.
- The union's kind set is closed per release: documents written before
  a kind existed keep loading because each new kind is a new tag, the
  union has no unknown-field surprises (strict documents, findings
  omitted when empty), and consumers pattern-match on tags they know.
- The false-positive surface the spec names — GS-canary shapes,
  BOOL-shaped returns, lone gotos — belongs to the families that
  introduce those readings; the spelled block cannot fire on them
  because it never claims without the pair spelled. Cross-function
  error-code propagation follows on ADR-0035's rails over the bodies
  the scan keeps, in the track's later tickets (#288+).
