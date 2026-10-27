# ADR-0045: Read parameter directions in a per-function pass over the kept bodies, with a write through the pointer as the out-evidence family

- **Status:** Accepted
- **Date:** 2026-10-22 (P12.7-1 shipped, issue #274)
- **Deciders:** Arthur (solo project)

## Context

A decompiled signature says what a parameter *is* but never which way data
*flows* through it. A routine that stores through `param_1` before
returning — an out-parameter, the shape Rust translations must capture as a
returned or borrowed value — still reads as just another `undefined *`.
Spec #228 asks for in/out/inout readings read from the function body, so
the LLM stops guessing the signature shape and baseline tests can capture
out-parameters as expected side effects. Ticket #274 is the first delivered
slice — one thin end-to-end cut that lands the new record kind — and #275
widens the evidence families.

The open questions were where the pass runs, what may count as a write,
what the reading is keyed on, how the confidence bands sit on the
confidence ladder, and whether a direction ever writes back. Direction is
*not* a type: ADR-0020/0021 keep the write trait speaking types in program
slots, so a direction can only ever be a reported reading. The keying
question decided a second question by itself: a parameter already has a
type record, and writing a direction under the same key would make the two
facts compete in resolution and one would always win — so the direction
readings need their own conflict target.

## Decision

A dedicated detector (`param_direction::ParamDirectionDetector`) reads
each function's directions **inline, function by function, from the body
the scan already kept** — the same kept bodies the assignment-chain
(ADR-0016) and return-usage (ADR-0017) passes read, with no extra analysis
engine reads — and records a direction only where the body shows a deciding
shape.

- **A closed enum, a new tagged record.** `Direction` (`in`, `out`,
  `inout`) joins the vocabulary as an enum, not strings;
  `InferredParamDirection` (function, parameter position, optional
  decompiled name, direction, method, scope, confidence, evidence) joins
  the union as `InferredType::Direction` with serde tag `"direction"`.
  Otherwise the persisted document's shape is unchanged, so documents
  written before this kind still load. Scope is `Function` only in v1 — a
  class-member direction reading would key on the `this` slot's class
  identity, which the scan has no shape for yet.
- **One method: `param_direction`.** Every record's evidence line quotes
  the deciding write or read — the decompiled line the reading rests on,
  never a paraphrase.
- **The out family: writes *through* the pointer.** The first delivered
  slice (issue #274) covers the direct-write spelling — `*param_1 = x`, and
  its double-pointer hand-back form `*param_2 = &local_8` — decided soundly
  by shape: a `*` on the name's near side and an `=` opening an assignment
  right behind it. A multiplication cannot take an assignment on its left,
  so a `*` beside a name the body assigns through can only be a
  dereference; `==`, `!=`, `<=`, and `>=` never put the `=` at the name's
  side, so a comparison through the pointer stays silent. Field
  (`param_1->count = x`) and indexed (`param_1[i] = x`) writes are writes
  through the pointer too and join the family in #275 — scored at their own
  band, below the direct write, and silent until then.
- **The in family: bodies that only read through.** A known string-function
  call (the same `STRING_FUNCTIONS` table the size detector reads — one
  table, so "string function" means one thing to both readings) with the
  parameter at a character-pointer position is the read the first slice
  covers. Comparison through the pointer and use as an rvalue join the
  family in #275. A parameter merely passed to a callee the pass has not
  read is no evidence either way — the reading never guesses about an
  unseen callee's contract.
- **Bands, anchored for every family the follow-ups land.** Direct
  write: solid-high **75** — the store is spelled out in one line.
  Field and indexed writes: solid **70** — the write is plain but sits one
  indirection of inference from the pointer itself, and the decompiler's
  member/index spellings can name a rebase the scan has not read.
  Read-only body: modest **60** — the read is explicit but rules out no
  write elsewhere. **inout** composes when both families are non-empty,
  scored at the band of the family that supplied the out half (75 for a
  direct write, 70 for a field or indexed write) and keeping the write's
  line as evidence — the out half is the stronger claim.
- **Absence is unknown, never silently *in*.** No deciding shape, no
  record. A parameter with no record has no direction claim; the reading
  records what the body shows and stays quiet otherwise.
- **A new conflict target, keyed beside the type.** Conflict
  resolution gains `Target::Direction { function, param_index }`, separate
  from `Target::Param`: what a parameter is and which way it flows are
  separate facts and coexist on one parameter. One parameter never keeps
  two directions — the highest-confidence reading wins, a tie keeps the one
  the scan showed first, exactly as every other target behaves.
- **Scan order holds.** The detector runs inside the per-function pass, so
  direction records follow the function listing, function by function; two
  scans of one program diff cleanly, the way the union has always
  guaranteed.
- **No write-back.** A direction is not a program type: the write-back
  pass skips every direction record with a `SkipReason::Direction`, so the
  prototype merge never sees it, holding the ADR-0020/0021 boundary — the
  setters speak types.

## Consequences

- The union has a sixth kind: persisted results gain `kind:
  "direction"` entries, the CLI's kind and method breakdowns gain
  `direction` and `param_direction`, and the report's inference list shows
  a direction beside its parameter's type reading (the target column spells
  `param_N direction` so the two lines stand apart).
- The existing union→`TypeInfo` prompt conversion gains a direction
  arm, so retry prompts' type-info section includes direction lines from
  the first scan; polishing that rendering for the signature shape is
  #276/#277's prompt work, not a data change.
- The pass adds **zero analysis engine round-trips**: it reads the
  `DecompiledFunction` the per-function pass already fetched, so the
  exactly-once decompile the engine tests assert still holds with the
  detector on — and unlike the local-chain pass it needs no surviving
  readings, so it can run inline rather than waiting behind resolution.
- The read family reuses the size detector's string-function table, so
  `strlen`'s argument is `char *` (70) and *in* (60) off the same line of
  evidence — one callee list to grow, not two.
- Keying apart from the parameter arm means the strongest-record resolution
  never weighs a direction against a type: both survive, and the only
  competition is between direction readings of the same parameter — which
  #275's widened families will exercise when a field write (70) meets a
  direct write (75) or a read (60) on one pointer.
- Baseline tests capturing out-parameters (#228's downstream goal) read
  the records from the persisted artifact; cross-function direction
  propagation on the ADR-0014/0015 pattern stays the follow-up the
  spec names, not part of this ticket line.
