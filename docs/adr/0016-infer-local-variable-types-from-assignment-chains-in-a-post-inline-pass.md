# ADR-0016: Infer local-variable types from assignment chains in a post-inline pass

- **Status:** Accepted
- **Date:** 2026-10-13 (P2.5-3 shipped, issue #145)
- **Deciders:** Arthur (solo project)

## Context

The typeinfer record vocabulary has defined a local-variable kind
(`InferredLocalType`) since it was written, but no detector has ever
emitted one: the decompiled bodies an operator reads still name their
stack slots `local_8` / `uVar1` with type `undefined`, even when the
body plainly says what the slot holds — `local_8 = param_1;` where
`param_1` stands read as `char *`, or `local_10 = (char *)malloc(0x10);`
where the allocator's contract hands back a buffer. Spec #142 asks for
locals typed through assignment chains; ticket #145 is that detector.

The shape questions were where the pass runs, what may stand as a
source of a type, how far a chain is chased, and how the new records
compete. "A parameter with a surviving reading" is only well-defined
*after* inline conflict resolution — before it, one parameter can stand
read several ways at once. And the scan already has two contract
sources: its own surviving readings (ADR-0014/0015) and the
known-signature database, which since ADR-0015 carries return types.

## Decision

A dedicated detector (`local_chain::LocalChainDetector`) runs **after
inline conflict resolution**, over the bodies the inline pass already
decompiled, and types the target of each plain assignment whose source
carries a reading on its own.

- **The sources are the scan's own survivors plus the signature
  database.** A bare identifier naming a parameter with a surviving
  inline reading lends that reading; a call to a known-signature
  routine lends the contract's return type
  (`KnownTypePropagationEngine::return_type` — `malloc` → `void *`,
  `strlen` → `size_t`); a cast around the source (`(char *)param_1`)
  is stripped and still names the value. A literal, an unknown callee,
  or an identifier the scan never typed says nothing.
- **One hop per chain, no fixpoint.** A local typed from a parameter or
  a known call is a *direct* source; a local typed from a direct source
  propagates one hop and then stops being a source itself. `a = param;
  b = a; c = b` types `a` and `b` and leaves `c` alone — the same
  no-chasing rule ADR-0014/0015 set for propagated readings: a reading
  that is itself an inference never becomes evidence in the same scan.
- **Keyed by function and decompiled name.** The records are the local
  kind the vocabulary already defines, and conflict resolution's
  `Target::Local` key already exists — two different names in one
  function never collide, and the same name in two functions never
  collides, because the key carries the function. Where one name is
  assigned twice, both candidates are emitted and resolution keeps the
  strongest, first-seen one, exactly as the cross-function passes
  already behave.
- **Confidence 60, the bottom of the ladder.** The assignment is direct
  body evidence, but the type is only as good as its source — an
  inferred parameter reading or a library contract one step removed —
  so it sits below every inline parameter family, where it can add a
  typed slot without ever displacing stronger evidence.
- **Only shapes that name a single variable are assignments.** A
  dereference (`*puVar5 = …`), an index (`local_8[0] = …`), a member
  write, a comparison (`==`), a compound assignment (`+=`), a control
  header (`for (uVar2 = 0; …)`), and a write to a parameter are all
  skipped; the evidence is the trimmed assignment line.
- **No new plumbing.** The pass adds no Ghidra round-trips — it reads
  the same `DecompiledFunction` values the inline pass fetched — and
  the records flow through the existing final `resolve_conflicts`, the
  unchanged persistor, and the existing union→`TypeInfo` prompt
  conversion, which already rendered locals under their variable name.

## Consequences

- The local record kind finally has a producer: persisted results gain
  `kind: "local"` entries, the CLI's method breakdown gains
  `assignment_chain`, and translation prompts name their stack slots
  with real types — the operator-visible point of the ticket.
- Ghidra's intermediate variables (`uVar1`, `iVar2`) are typed on the
  same rule as stack slots: any bare assignment target that is not a
  parameter is a local of this body. The decompiler names them
  per-function, so the (function, name) key keeps them separate.
- Running after inline resolution means the sources are the *inline*
  survivors: a local assigned a parameter that no inline detector read —
  even one a cross-function pass later types — gets nothing, because
  the pass deliberately waits for resolved readings rather than
  re-deriving parameter types itself, which is also what keeps one
  parameter from ever carrying two types into two slots. The body is
  read top to bottom, so a hop only types when its source was assigned
  earlier in the body.
- The one-hop cap leaves genuinely longer chains (`c = b = a = param`)
  partially untyped. That is accepted: chasing further compounds the
  source's uncertainty, and the return-usage pass (#146) does not need
  deeper local chains to do its job.
- The detector is stateless and fetch-free like its sibling passes, so
  it stays testable over canned bodies and shareable across an entire
  scan.
