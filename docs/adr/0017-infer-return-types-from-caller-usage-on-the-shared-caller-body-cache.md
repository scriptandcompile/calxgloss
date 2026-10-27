# ADR-0017: Infer return types from caller usage on the shared caller-body cache

- **Status:** Accepted
- **Date:** 2026-10-13 (P2.5-4 shipped, issue #146)
- **Deciders:** Arthur (solo project)

## Context

A body never reads its own return value. So the decompiler's own
evidence can never type one. A helper whose every caller treats the
result as a string — assigning it to a `char *` slot, feeding it to
`strlen`, dereferencing it — still decompiles as `undefined FUN_x(void)`.
The typeinfer vocabulary had three record kinds
(parameter, local, call-site argument). The return kind was the fourth
the record vocabulary never had. Spec #142 asks for return types
inferred from caller usage; ticket #146 is that pass.

Four design questions came up: where the pass runs, what counts as a use
of the returned value, what the reading is keyed on, and how the new
records compete. The scan already fetches caller bodies for the
caller→callee pass (ADR-0015) and caches them per scan. Asking the
return question a second time would double the Ghidra round-trips for no
new information. Also, a return reading belongs to the *callee*, not to
the caller whose body shows the use. So the record's key, and its
competition with other return readings, need a new target kind.

## Decision

A dedicated detector (`return_usage::ReturnUsageDetector`) runs inside
the caller→callee loop. For each analyzed function the evidence engine
already collects its callers' bodies, and the same `caller_bodies` slice
is passed to the return pass. **One caller lookup per function serves
both directions**, and the scan stays at one decompile per function.

- **Three usage shapes give a return type; everything else gives
  nothing.** A call site contributes when the returned value sits in a
  shape that carries a reading:
  1. **assigned to a local the scan typed in that same caller** —
     `local_8 = FUN_x();`, where the locals pass (ADR-0016) left
     `local_8` typed as `char *`, gives the function that return type;
  2. **passed at a known-signature position** — `strlen(FUN_x());` reads
     the result the way the contract types that argument position
     (`KnownTypePropagationEngine::match_signature`). The pass counts
     top-level commas to find the position and consults only the
     *innermost* enclosing call;
  3. **dereferenced or field-accessed** — `*FUN_x()` or `FUN_x()->field`
     says the result is a pointer, pointee unknown. This is the
     byte-buffer reading that the database's buffer contracts use.
  A bare statement call, a comparison, a multiplication (the `*` is
  binary there), an assignment to an untyped or non-local target, a cast
  around the call, and a nesting inside a callee the database does not
  know all contribute nothing.
- **A new record kind, keyed by the callee.** `InferredReturnType`
  joins the union as `InferredType::Return` with serde tag `"return"`.
  The persisted document's shape is otherwise unchanged, so documents
  written before the kind still load. Conflict resolution gains
  `Target::Return { function }`. One function never keeps two return
  types. A return reading never competes with a parameter, local, or
  call-site reading for the same name.
- **Every call site contributes; resolution picks the winner.** Each
  caller's reading is emitted at `RETURN_USAGE_CONFIDENCE` 60 — the
  bottom of the ladder, level with the assignment-chain family. The use
  is concrete, but the type is only as good as the reading behind the
  shape: an inferred local, a library contract, or the bare fact of a
  dereference. The final `resolve_conflicts` keeps the strongest
  candidate for the function, and a tie goes to the first-seen caller.
  So the record's evidence is the winning caller's decompiled line.
- **The pass checks the shapes against the scan's own surviving local
  readings.** Before the loop, the evidence engine builds a (function,
  name) → type map from the locals pass records. It keeps the first-seen
  reading per name, which matches what resolution will keep. The
  detector itself stays stateless and fetch-free like its sibling
  passes.

## Consequences

- The union has a fourth kind. Persisted results gain `kind: "return"`
  entries, the CLI's kind and method breakdowns gain `return` and
  `return_usage`, and translation prompts gain a `return` type-info line
  for the function. That is the operator-visible point of the ticket.
- The return pass adds **zero Ghidra round-trips**. It reads the caller
  bodies the caller→callee pass already fetched and cached. So the
  one-decompile-per-function invariant that the evidence engine's tests
  assert still holds with the pass on.
- Keying on the callee means a function's return is typed from all its
  callers *together*, not per call site. Where callers disagree, the
  scan shows one type with one line of evidence. The losing readings are
  removed by resolution, exactly like duplicate parameter readings
  already are.
- Reading only the innermost enclosing call keeps the contract lookup
  honest. `foo(strlen(FUN_x()))` types the return from `strlen`, never
  from the unknown outer `foo`. A reading that looked through an unknown
  callee would be guessing at that callee's argument contract.
- The dereference shape types the return as a bare pointer (`void *`)
  rather than guessing a pointee. The scan has no evidence for what is
  on the other end. A confidently wrong pointee would corrupt the prompt
  more than an honest `void *`.
