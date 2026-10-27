# ADR-0016: Infer local-variable types from assignment chains in a post-inline pass

- **Status:** Accepted
- **Date:** 2026-10-13 (P2.5-3 shipped, issue #145)
- **Deciders:** Arthur (solo project)

## Context

The typeinfer record vocabulary has defined a local-variable kind
(`InferredLocalType`) since it was written, but no detector has ever
emitted one. The decompiled bodies an operator reads still call their
stack slots `local_8` / `uVar1` with type `undefined`. That holds even
when the body plainly says what the slot holds. For example
`local_8 = param_1;` where an inline reading already types `param_1` as
`char *`, or `local_10 = (char *)malloc(0x10);` where the allocator's
contract says it returns a buffer. Spec #142 asks for locals typed
through assignment chains; ticket #145 is that detector.

Four design questions came up: where the pass runs, what may count as a
source of a type, how far a chain is followed, and how the new records
compete. "A parameter with a surviving reading" has a clear meaning only
*after* inline resolution. Before resolution, one parameter can have
several competing readings at once. The scan also already has two
contract sources: its own surviving readings (ADR-0014/0015) and the
known-signature database, which since ADR-0015 also records return
types.

## Decision

A dedicated detector (`local_chain::LocalChainDetector`) runs **after
inline resolution**, over the kept bodies the inline pass already
decompiled. It types the target of each plain assignment whose source
already has a reading of its own.

- **The sources are the scan's own survivors plus the signature
  database.** A bare identifier naming a parameter with a surviving
  inline reading lends that reading. A call to a known-signature
  routine lends the contract's return type
  (`KnownTypePropagationEngine::return_type` — `malloc` → `void *`,
  `strlen` → `size_t`). A cast around the source (`(char *)param_1`) is
  stripped off, and the value inside it is what counts. A literal, an
  unknown callee, or an identifier the scan never typed says nothing.
- **One hop per chain, no fixpoint.** A local typed from a parameter or
  a known call has a *direct* source. A local typed from a direct source
  passes the type one hop and then stops being a source itself. `a = param;
  b = a; c = b` types `a` and `b` and leaves `c` alone. This is
  the same no-chasing rule ADR-0014/0015 set for propagated readings: a
  reading that is itself an inference never becomes evidence in the same
  scan.
- **Keyed by function and decompiled name.** The records are the local
  kind the vocabulary already defines, and conflict resolution's
  `Target::Local` key already exists. Two different names in one
  function never collide. The same name in two functions never collides,
  because the key carries the function. Where one name is assigned
  twice, both candidates are emitted. Resolution keeps the strongest,
  first-seen one, exactly as the cross-function passes already behave.
- **Confidence 60, the bottom of the ladder.** The assignment is direct
  body evidence, but the type is only as good as its source. That source
  is an inferred parameter reading or a library contract, one step
  removed. So the reading sits below every inline parameter family. It
  can add a typed slot there without ever replacing stronger evidence.
- **Only shapes that name a single variable count as assignments.** A
  dereference (`*puVar5 = …`), an index (`local_8[0] = …`), a member
  write, a comparison (`==`), a compound assignment (`+=`), a control
  header (`for (uVar2 = 0; …)`), and a write to a parameter are all
  skipped. The evidence is the trimmed assignment line.
- **No new plumbing.** The pass adds no Ghidra round-trips; it reads the
  same `DecompiledFunction` values the inline pass fetched. The records
  flow through the existing final `resolve_conflicts`, the unchanged
  persistor, and the existing union→`TypeInfo` prompt conversion, which
  already rendered locals under their variable name.

## Consequences

- The local record kind finally has a producer. Persisted results gain
  `kind: "local"` entries, and the CLI's method breakdown gains
  `assignment_chain`. Translation prompts name their stack slots with
  real types. That is the operator-visible point of the ticket.
- Ghidra's intermediate variables (`uVar1`, `iVar2`) are typed by the
  same rule as stack slots: any bare assignment target that is not a
  parameter is a local of this body. The decompiler names them
  per-function, so the (function, name) key keeps them separate.
- Running after inline resolution means the sources are the *inline*
  survivors. A local assigned a parameter that no inline detector read
  gets nothing — even a parameter a cross-function pass later types.
  The pass deliberately waits for resolved readings rather than deriving
  parameter types itself. This is also what keeps one parameter from
  ever lending two different types to two slots. The body is read top to
  bottom, so a hop types its target only when its source was assigned
  earlier in the body.
- The one-hop cap leaves genuinely longer chains (`c = b = a = param`)
  partly untyped. That is accepted. Following further hops compounds the
  source's uncertainty, and the return-usage pass (#146) does not need
  deeper local chains to do its job.
- Like its sibling passes, the detector is stateless and fetch-free. So
  it stays testable over canned bodies and shareable across an entire
  scan.
