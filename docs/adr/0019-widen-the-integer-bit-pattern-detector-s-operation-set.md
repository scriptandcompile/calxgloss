# ADR-0019: Widen the integer bit-pattern detector's operation set

- **Status:** Accepted
- **Date:** 2026-10-13 (P2.5-6 shipped, issue #148)
- **Deciders:** Arthur (solo project)

## Context

The parameter-size detector's integer family already read shifts and
bitwise ANDs, and it judged the constants next to them. A mask wider
than the default word pinned the reading to `u64`, and so did a shift
count the word cannot hold. But bodies show their width evidence in more
shapes than those two. `param_1 == 0x100000000`, `param_1 | 0xff0000000`,
and `param_1 += 0x100000000` all say the parameter is
wider than the decompiler's default word. The detector read none of
them. Spec #142 asks for the bit-pattern analysis to be deepened; ticket
#148 is that widening.

Four design questions came up: which operations join the family; whether
an operation's *shape alone* marks a parameter as an integer, or only
its constant does; how to read a constant sitting on the left; and where
the new readings sit on the ladder. The tension: shifts and masks exist
only on integers, but a comparison or a `+=` is just as natural on a
pointer. `param_1 == 0` is the null-test spelling, and `param_1 += 4`
could advance a pointer by one. So the same operation class cannot have
the same evidence strength.

## Decision

- **The existing detector is extended in place.** Same
  `ParameterSizeDetector`, same `InferenceMethod::IntegerBitPattern`
  records, same confidence ladder (default word 55, pinned width 60),
  same family ordering (string 70 wins over pointer 65, and pointer 65
  wins over integer). No new method, kind, or plumbing.
- **The operation set widens to four classes**, each classified by what
  its shape alone proves:
  - *Shifts* (`<<`, `>>`, `<<=`, `>>=`) and *bitwise* operations
    (`&`, `|`, `^`, `&=`, `|=`, `^=`): these only exist on integers, so
    the shape alone marks the parameter as an integer, exactly as shifts
    and masks always did.
  - *Comparisons* (`==`, `!=`, `<`, `>`, `<=`, `>=`) and *arithmetic
    compound assignments* (`+=`, `-=`, `*=`, `/=`, `%=`): pointers can
    be compared and advanced too, so the shape alone says nothing. Only
    a **non-zero constant** beside the operator marks an integer. A
    comparison against zero is the null test, and a small `+=` could be
    pointer arithmetic. Neither gives a width on its own.
- **Constants set a width bound the way masks already do.** For a shift
  whose operand is the parameter, the width must include one bit past
  the shift count. Every other operation needs the bits the constant
  itself spans. The widest constant across a function's operations still
  decides the width. The record's evidence is the line carrying that
  constant, whatever operation carries it. A parameter that *supplies* a
  shift count — in the plain or the compound spelling (`uVar2 >>= param_1`)
  — is an integer use that bounds no width.
- **The detector reads both sides of the operator.** A constant may sit
  before the parameter (`0xff | param_1`, `0x100000000 <= param_1`) as
  well as after it. The detector reaches a left-hand constant past the
  operator's leading byte, the same walk the left-hand mask already
  used.
- **Shapes that prove no width are ignored.** The detector reads no
  width from: non-constant operands (`param_1 == param_2`), parameters
  behind casts (`(ulonglong)param_1 == 0x100000000` — the cast types the
  expression), field operations (`param_1->flags | 0xff` — the
  whole-word guard keeps the field's operation off the parameter), the
  logical `&&`/`||`, or a unary address-of.
- **Hex constants parse by C's rule.** A hex value's trailing `a`-`f`
  are digits, not an integer suffix. Only the non-hex letters (`u`, `l`
  and capitals) end the value. The old trim stripped any trailing run of
  letters, so `0xff` parsed as zero. That stayed invisible while only
  masks read constants, because a zero bound never changed the word.
  Comparisons exposed it, because zero there means "null test, no
  reading".

## Consequences

- Where the scan used to guess `u32`, an evidence-based reading now
  wins: `u64`, or the narrower default-word reading. Comparisons,
  OR/XOR, and compound assignments now fill the same width ladder that
  masks and shifts filled.
- The zero-constant rule keeps the null-test shape out of the integer
  family entirely. A parameter tested only against zero gets no reading
  at all instead of a misleading `u32`. Where the pointer family's
  read-through evidence exists, it now stands uncontested.
- The detector's internals gained a small operator taxonomy (`Operator`
  with a per-class reading rule) in place of the inline shift/AND match.
  The public surface is untouched. Every consumer — conflict resolution,
  persistence, prompt rendering, the CLI breakdowns — is unchanged.
- The hex-suffix fix slightly strengthens existing mask readings (`0xff`
  now bounds 8 bits rather than 0). No width outcome changes, since both
  sit inside the default word.
