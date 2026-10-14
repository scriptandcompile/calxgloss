# ADR-0017: Infer return types from caller usage on the shared caller-body cache

- **Status:** Accepted
- **Date:** 2026-10-13 (P2.5-4 shipped, issue #146)
- **Deciders:** Arthur (solo project)

## Context

No body reads its own return value, so the decompiler's own evidence
can never type one: a helper whose every caller treats the result as a
string — assigning it to a `char *` slot, feeding it to `strlen`,
dereferencing it — still decompiles as `undefined FUN_x(void)`. The
typeinfer vocabulary carried three record kinds (parameter, local,
call-site argument); the return was the fourth the record vocabulary
never had. Spec #142 asks for return types inferred from caller usage;
ticket #146 is that pass.

The shape questions were where the pass runs, what counts as a use of
the returned value, what the reading is keyed on, and how the new
records compete. The scan already fetches caller bodies for the
caller→callee pass (ADR-0015) and caches them per scan; asking the
return question a second time would double the Ghidra round-trips for
no new information. And a return reading belongs to the *callee*, not
to the caller whose body shows the use — so the record's key, and its
competition with other return readings, is a new target kind.

## Decision

A dedicated detector (`return_usage::ReturnUsageDetector`) rides the
caller→callee loop: for each analyzed function the engine already
collects its callers' bodies, and the same `caller_bodies` slice is
handed to the return pass — **one caller lookup per function serves
both directions**, and the scan stays at one decompile per function.

- **Three usage shapes name a type, everything else says nothing.**
  A call site contributes when the returned value sits in a shape that
  carries a reading:
  1. **assigned to a local the scan typed in that same caller** —
     `local_8 = FUN_x();` where the locals pass (ADR-0016) left
     `local_8` standing `char *` lends the function that return type;
  2. **passed at a known-signature position** — `strlen(FUN_x());`
     reads the result as the contract types that argument position
     (`KnownTypePropagationEngine::match_signature`), counting
     top-level commas to find the position and consulting only the
     *innermost* enclosing call;
  3. **dereferenced or field-accessed** — `*FUN_x()` or
     `FUN_x()->field` says the result is a pointer, pointee unknown —
     the byte-buffer reading the database's buffer contracts use.
  A bare statement call, a comparison, a multiplication (the `*` is
  binary there), an assignment to an untyped or non-local target, a
  cast around the call, and a nesting inside a callee the database
  does not know all contribute nothing.
- **A new record kind, keyed by the callee.** `InferredReturnType`
  joins the union as `InferredType::Return` with serde tag `"return"`;
  the persisted document's shape is unchanged otherwise, so documents
  written before the kind still load. Conflict resolution gains
  `Target::Return { function }`: one function never keeps two return
  types, and a return reading never competes with a parameter, local,
  or call-site reading for the same name.
- **Every call site contributes; resolution picks the winner.** Each
  caller's reading is emitted at `RETURN_USAGE_CONFIDENCE` 60 — the
  bottom of the ladder with the assignment-chain family, since the
  usage is concrete but the type is only as good as the reading behind
  the shape (an inferred local, a library contract, or the bare fact
  of a dereference). The final `resolve_conflicts` keeps the strongest
  candidate for the function, ties going to the first-seen caller, so
  the record's evidence is the winning caller's decompiled line.
- **The local readings the shapes read against are the scan's own
  survivors.** The engine builds a (function, name) → type map from
  the locals pass records before the loop, first-seen per name,
  matching what resolution will keep; the detector itself stays
  stateless and fetch-free like its sibling passes.

## Consequences

- The union has a fourth kind: persisted results gain `kind: "return"`
  entries, the CLI's kind and method breakdowns gain `return` and
  `return_usage`, and translation prompts carry a `return` type-info
  line for the function — the operator-visible point of the ticket.
- The return pass adds **zero Ghidra round-trips**: it reads the
  caller bodies the caller→callee pass already fetched and cached, so
  the one-decompile-per-function invariant the engine tests assert
  still holds with the pass on.
- Keying on the callee means a function's return is typed from its
  callers *en masse*, not per call site: where callers disagree, the
  scan shows one type with one line of evidence, and the losing
  readings are resolved away exactly like duplicate parameter readings
  already are.
- Reading only the innermost enclosing call keeps the contract lookup
  honest: `foo(strlen(FUN_x()))` types the return from `strlen`, never
  from the unknown outer `foo` — a reading that reached through an
  unknown callee would be guessing at its argument's contract.
- The dereference shape types the return as a bare pointer (`void *`)
  rather than guessing a pointee: the scan has no evidence for what is
  on the other end, and a confident wrong pointee would poison the
  prompt more than an honest `void *`.
