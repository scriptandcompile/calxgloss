# ADR-0038: A lone reading composes no format, a lone magic names no protocol, a literal comparison validates nothing, and direction-neutral swaps name no byte order

- **Status:** Accepted
- **Date:** 2026-10-16 (P11.5-1–4 shipped, issues #198–#201)
- **Deciders:** Arthur (solo project)

## Context

P11.5 (spec #197) deepened the serialization scan with four readings: a
`cross_field_validation` detector that sees checksum and framing comparisons,
a `serialization_format` combiner that composes a function's byte-swap and
bit-pack records into one ordered layout, a `protocol_message` combination
that promotes a protocol-magic hit corroborated by other readings, and an
`endianness_map` post-pass that aggregates the scan's byte-swap findings by
width into one binary-level profile. Each new claim is an inference over
records the single-pass scan already made — the component readings
themselves are solid (an `ntohl` call is an identified fact), but the
composed claims sit on top of them, and the scan's honesty rule says a
reading must never over-read an ordinary binary. The ordinary binary has
one `ntohl` in a codec, compares literals against constants all over,
sniffs file signatures in decoders, and byte-swaps for reasons that have
nothing to do with wire order. Loose gates would fill the finding list
with message layouts, protocol identifications, and byte-order profiles a
reviewer cannot check against the decompilation.

The spec named four gates as ADR candidates when the tickets landed — the
format-inference two-readings gate, the validation silence gates, the
protocol promotion gate, and the endianness map's name-family inference;
this records them.

## Decision

All four readings are crate-internal pure modules over the findings and
bodies the single-pass scan already produces — no new `ScanSource` reads,
still exactly one decompile per function — and each ships with its
false-positive gate as the module's central rule:

**Cross-field validation (`validation::ValidationDetector::detect`).**

- The reading claims only on an **explicit comparison between a stored
  field and a value computed from other fields**: the checksum shape
  (`uVar7 == uVar5 + uVar6`) and the length shape (a read length checked
  against a size or remaining value, by arithmetic or by a length-ish
  name — `len`/`size`/`count`/`remain`/`avail`/`bytes`/`capacity`/`left`
  — on either side).
- **Constant-vs-constant claims nothing**, and **variable-vs-literal
  claims nothing** — that comparison is the magic-byte and protocol
  story, not this one.
- **A comparison already reported as a magic hit claims nothing**: the
  engine hands the detector exactly the magic findings it just made for
  the body, so a signature check lands exactly once, as magic, whatever
  signature table is configured.
- The scan is **quote-aware**: a comparison spelled inside a string
  literal fabricates nothing. Each qualifying check lands its own
  finding in body order at confidence **65**, between the bit-pack
  floor (60) and the byte-swap floor (70) — the comparison is explicit
  but its shape is inferred.

**Serialization format (`format::FormatCombiner::combine`).**

- The gate is **two readings**: a function carrying at least two
  serialization readings (byte swaps and/or bit-pack chains) composes
  them, in body order, into one layout; **a single reading claims no
  format** — a lone `ntohl` never invents a message layout.
- A swapped field names its **wire endianness only when the swap name
  belongs to the network-order family** (`ntohl`/`ntohs`/`htons`/
  `htonl`); a direction-neutral builtin (`__builtin_bswap*`) contributes
  a field whose bytes reverse and whose wire order is not claimed.
- A **reader-or-writer direction is named only when the directional
  swap names all point the same way**; direction-neutral names neither
  corroborate nor contradict, and mixed families claim no direction.
- The claim rides at confidence **75** — corroborated by two independent
  readings, so above the byte-swap floor (70), below the lone-magic
  floor (80).

**Protocol message (`protocol::ProtocolMessageCombiner::identify`).**

- The promotion gate is **a protocol-section magic hit plus at least one
  corroborating reading** — a network-order byte swap or a cross-field
  validation. A direction-neutral builtin corroborates nothing: it
  reverses bytes for any reason.
- **A protocol magic on its own never promotes** — the bare sniff stays
  a plain magic finding — and **a file-format magic combined with swaps
  stays a magic finding**, so a PNG decoder is never mislabeled as a
  network handler. The gate keys on the configured table's protocol
  flag, so custom tables join by flagging their own entries.
- **A hit spelled only as a decimal constant never promotes**: a
  protocol magic is also an ordinary number (IPv4's `0x800` is 2048, a
  plausible buffer size), and only the hex spelling on the evidence
  line marks a wire-value sniff.
- Exactly **one finding per function**, naming the protocol and listing
  its corroborating readings with every contributing finding's own line
  as evidence, at confidence **85** — the top of the P11.5 ladder,
  above the lone-magic floor (80), because independent readings
  corroborate it.

**Endianness map (`endianness::EndiannessProfiler::profile`).**

- The inference is **by name family per width**: a width where the
  network-order family appears at all implies **`be`** — one
  network-order spelling says that width travels big-endian somewhere —
  while a width seen only through direction-neutral builtins reads
  **`reversal_only`**: the bytes reverse somewhere and no wire order is
  claimed.
- **Widths with no observed swaps are absent**; contributors are listed
  in listing order, each named once however many swaps it made.
- **Exactly one binary-level finding per scan**, appended after all
  per-function findings, in the apidetect divergence pattern: its
  function accessor reads as the empty string, and the per-function
  lookup answers it to each contributing function.
- The claim rides at confidence **75** — a program-wide aggregation over
  identified call sites is stronger evidence than any single one, so
  one rung above the byte-swap floor (70), the same rung as the
  composed format, below the lone-magic floor (80).

## Consequences

- Positive:
  - The four claims most likely to over-read a binary are pinned by
    their silences — the lone reading, the constant and literal
    comparisons, the magic-hit overlap, the lone protocol magic, the
    file-format magic with swaps, the decimal spelling, and the
    builtin-only width all have unit tests on their pure modules.
  - The confidence ladder is pinned by a contract test read off one
    scan (P11.5-5): bit-pack 60 < validation 65 < byte-swap 70 <
    format 75 = map 75 < magic 80 < protocol message 85 —
    corroboration always ranks above the single signals that fed it.
  - Every reading consumes records the single-pass scan already made:
    the exactly-once-decompile, skip-rate-breaker, and scan-order
    contracts stayed green untouched through the whole phase.
- Negative:
  - The swap-name vocabulary (the network-order family, the
    `__builtin_bswap*` builtins) is a hardcoded string set: a binary
    swapping bytes through hand-rolled shift/mask code or its own
    named helpers leaves no name on the gate and claims nothing at
    that width. Accepted — name-based matching was the whole phase's
    shape, and hand-rolled swaps stay invisible to it.
  - The hex-spelling gate means a handler comparing a protocol magic
    through a named enum constant, with no hex literal on the evidence
    line, never promotes. Deliberate — the same honesty line the
    validation detector draws at literal-vs-variable comparisons —
    but it is a real silence.
  - The validation length-shape vocabulary (`len`/`size`/`count`/…) is
    a string set: a framing check over differently-named variables
    with no arithmetic on either side reads as a plain variable pair
    and claims nothing.
  - Composed claims stay per-function: a handler that spreads its
    field reads across callees composes no layout and promotes no
    protocol, because there is no cross-function message-flow
    tracking — that was explicitly out of scope.
