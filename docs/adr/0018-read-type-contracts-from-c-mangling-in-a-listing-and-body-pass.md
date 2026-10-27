# ADR-0018: Read type contracts from C++ mangling in a listing pass and a body pass

- **Status:** Accepted
- **Date:** 2026-10-13 (P2.5-5 shipped, issue #147)
- **Deciders:** Arthur (solo project)

## Context

Sometimes a name visible in the scan already spells out a signature: a
demangled qualified call like `Widget::Render(int,char *)` in a
decompiled body, or an MSVC-mangled listing symbol like
`?Render@Widget@@QAEXH@Z`. In that case the parameter contract is
already in the name, and nothing a body does with the parameters says
more than the symbol does. Every inline detector so far read *usage*
(what a body does with a parameter); none read the *name* itself. Spec
#142 asks for C++ mangling analysis; ticket #147 is that detector.

Four design questions came up: where each spelling is read, how far the
MSVC decoder goes, how a decoded member's implicit `this` lines up with
decompiled parameter positions, and where these readings sit on the
confidence ladder. A mangled symbol is also the only signature source
available for a function whose body will not decompile — the listing
name is there either way. That decides where in the per-function pass
the symbol pass runs.

## Decision

A dedicated stateless detector (`mangling::ManglingDetector`) reads both
spellings. The evidence engine gives it two different inputs at two
different points of the per-function pass:

- **The listing pass runs before the decompile attempt.** The evidence
  engine calls `detect_from_listing(&function.name)` on every listing
  symbol before asking Ghidra to decompile it. So an MSVC-mangled symbol
  types its own function — implicit `this`, decoded arguments, and a
  non-`void` return — even when the body never decompiles. The symbol
  itself is the record's evidence. The records carry no decompiled
  parameter names, so the prompt falls back to `param_N`.
- **The body pass runs after the three inline usage detectors**, on the
  same `DecompiledFunction` text they read. One decompile per function
  still holds. It reads the analyzed function's own demangled name
  against its decompiled parameters. It also reads qualified calls whose
  callee carries a spelled list (`Widget::Render(int,char *)(param_1, uVar2)`), keys the records by the callee's spelled name,
  and keeps the call line as evidence. The body pass skips own-names
  starting with `?`. The listing pass already handles those, and reading
  them twice would only duplicate.

- **The MSVC decoder covers a deliberate practical subset, and nothing
  else produces records.** It decodes: the member conventions (function
  class letters `Y`/`Z` free, `C D K L S T` static members with no
  `this`, `A B E F I J M N Q R U V` members with an implicit one, thunks
  `G H O P W X` refused), the `E` 64-bit-`this` qualifier, the
  calling-convention letters, simple integer/float/`bool`/`wchar_t`
  arguments, `P`/`PE` pointers with optional const/volatile storage
  letters, pointers to and by-value class/struct types (`PAV`/`AEAV`
  spellings), and nested class chains (innermost-first in the name,
  reversed to `Outer::Inner`). Anything outside the subset — references,
  function pointers, enums, templates, operator spellings, name
  back-references like `V1@` — makes the *whole name* unparseable. An
  unparseable name produces no records at all, never a partial guess: a
  half-decoded signature would mistype positions the decoder is not sure
  of. Back-references are skipped on purpose; the subset covers the
  symbols real listings carry for the arguments that matter.
- **Placement is count-checked, never guessed.** A member symbol puts
  `this` at position 0 and the decoded arguments after it. The reading
  is recorded only when the spelled argument count equals the decompiled
  parameter count, or that count plus one for the implicit `this`. A
  call whose spelled list and observed argument count disagree produces
  nothing. The mismatch means the scan is not looking at the signature
  it thinks it is.
- **A spelled list is required.** A qualified name with no parameter
  list (`Widget::paint(param_1)`) says nothing; only a spelled contract
  types anything. Namespace noise — `std::` segments and `operator`
  spellings, matched on the whole segment — never counts as a member
  contract. This is the same guard the this-pointer detector applies
  (`NAMESPACE_NOISE` in `this_ptr`).
- **Multi-word type spellings must pass a whitelist.** A spelled entry
  parses as a type only when every word in it is a known type word
  (`unsigned int`, `long long`), or it is a single type word with an
  optional name. So `int width` (a named parameter) is refused while
  `unsigned int` parses.
- **Confidence 80.** A mangling reading is a fact stated by the symbol
  itself. It sits above every usage-inference family (known-signature
  75, cross-function 65–70, assignment-chain and return-usage 60) and
  just below the structural dispatch evidence (vtable 85–90, COM 88).
  Conflict resolution is untouched: a mangling reading wins against a
  weaker inline reading for the same parameter, and a tie keeps the
  first-seen reading.

## Consequences

- The scan gains a fifth inline reading family, and the vocabulary gains
  a new `InferenceMethod::Mangling` (serde label `mangling`). The CLI's
  method breakdown lists it. The records use the existing conflict
  resolution, persistence, and prompt plumbing like every other kind.
- Functions whose bodies never decompile can now still be typed. The
  listing pass runs before the decompile attempt, so a mangled listing
  symbol is enough. This is the only reading family with that property,
  and it is why the pass is not simply chained after the others.
- The decoder is a hand-written subset checked against ground-truth
  manglings, not a third-party demangler dependency. The workspace stays
  dependency-light. The subset's boundaries are exactly the places where
  a wrong guess would put a wrong type into a prompt.
- Because an unparseable name says nothing, coverage on heavily
  templated or reference-heavy C++ programs is partial by design.
  Widening the subset is a follow-up, not a correctness risk.
- The one-decompile-per-function invariant holds: the body pass reads
  the same fetched text, and the listing pass needs no fetch at all.
