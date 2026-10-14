# ADR-0019: Widen the integer bit-pattern detector's operation set

- **Status:** Accepted
- **Date:** 2026-10-13 (P2.5-6 shipped, issue #148)
- **Deciders:** Arthur (solo project)

## Context

The parameter-size detector's integer family already read shifts and
bitwise ANDs, weighing the constants beside them: a mask wider than the
default word, or a shift count the word cannot hold, pinned the reading
to `u64`. But bodies carry their width evidence in more shapes than
those two — `param_1 == 0x100000000`, `param_1 | 0xff0000000`,
`param_1 += 0x100000000` all say the parameter spans more than the
decompiler's default word, and none of them was read. Spec #142 asks
for the bit-pattern analysis to be deepened; ticket #148 is that
widening.

The shape questions were which operations join the family, whether an
operation's *shape alone* reads a parameter as an integer or only its
constant does, how left-hand constants are reached, and where the new
readings sit on the ladder. The tension: a shift or mask only exists on
integers, but a comparison or a `+=` is just as natural on a pointer —
`param_1 == 0` is the null-test spelling, and `param_1 += 4` could
advance one — so the same operation class cannot carry the same
evidence strength.

## Decision

- **The existing detector is extended in place.** Same
  `ParameterSizeDetector`, same `InferenceMethod::IntegerBitPattern`
  records, same confidence ladder (default word 55, pinned width 60),
  same family ordering (string 70 beats pointer 65 beats integer). No
  new method, kind, or plumbing.
- **The operation set widens to four classes**, each classified by what
  its shape alone proves:
  - *Shifts* (`<<`, `>>`, `<<=`, `>>=`) and *bitwise* operations
    (`&`, `|`, `^`, `&=`, `|=`, `^=`): these only exist on integers, so
    the shape alone reads the parameter as one, exactly as shifts and
    masks always did.
  - *Comparisons* (`==`, `!=`, `<`, `>`, `<=`, `>=`) and *arithmetic
    compound assignments* (`+=`, `-=`, `*=`, `/=`, `%=`): pointers
    compare and advance too, so the shape alone names nothing — only a
    **non-zero constant** beside the operator reads an integer. A
    comparison against zero is the null test, and a small `+=` could be
    pointer arithmetic; neither reads a width on its own.
- **Constants bound the width the way masks already do.** A shift the
  parameter is the operand of needs one bit past its count; every other
  operation needs the bits the constant itself spans. The widest
  constant across a function's operations still pins the width, and the
  record's evidence is the line carrying that constant — whatever
  operation carries it. A parameter *supplying* a shift count — in the
  plain or the compound spelling (`uVar2 >>= param_1`) — is an integer
  use that bounds no width.
- **Both sides of the operator are read.** A constant may sit before
  the parameter (`0xff | param_1`, `0x100000000 <= param_1`) as well as
  after it; the left-hand constant is reached past the operator's
  leading byte, the same walk the left-hand mask already used.
- **What bounds nothing stays bound by nothing.** Non-constant operands
  (`param_1 == param_2`), parameters behind casts
  (`(ulonglong)param_1 == 0x100000000` — the cast types the
  expression), field operations (`param_1->flags | 0xff` — the
  whole-word guard keeps the field's operation off the parameter), the
  logical `&&`/`||`, and a unary address-of all read no width.
- **Hex constants parse by C's rule.** A hex value's trailing `a`-`f`
  are digits, not an integer suffix: only the non-hex letters (`u`, `l`
  and capitals) end it. The old trim stripped any trailing alphabetic
  run, so `0xff` parsed as zero — invisible while only masks read
  constants (a zero bound never moved the word), exposed the moment
  comparisons did, where zero means "null test, no reading".

## Consequences

- Where today a `u32` guess stood, a `u64` (or narrower default-word)
  reading now wins on the evidence: comparisons, OR/XOR, and compound
  assignments feed the same width ladder masks and shifts filled.
- The zero-constant rule keeps the null-test shape out of the integer
  family entirely — a parameter tested only against zero keeps no
  reading at all rather than a misleading `u32`, leaving the pointer
  family's read-through evidence uncontested where it exists.
- The detector's internals gained a small operator taxonomy
  (`Operator` with a per-class reading rule) in place of the inline
  shift/AND match; the public surface is untouched, so every consumer —
  conflict resolution, persistence, prompt rendering, the CLI
  breakdowns — rides unchanged.
- The hex-suffix fix slightly strengthens existing mask readings
  (`0xff` now bounds 8 bits rather than 0); no width outcome changes,
  since both sit inside the default word.
