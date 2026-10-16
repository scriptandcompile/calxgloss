# ADR-0037: The apidetect divergence reading needs both platform families, and a named COM interface suppresses the nameless runtime claim

- **Status:** Accepted
- **Date:** 2026-10-15 (P9.5-2/-3 shipped, issues #185, #186)
- **Deciders:** Arthur (solo project)

## Context

P9.5 (spec #183) added two structural readings to the library & API
scan: a `platform_divergence` claim that a binary straddles the Win32
and POSIX/stdio families, and a `com_interface` claim that a binary
drives the COM component model. Both ride on records that are
themselves solid — an identified import sits at confidence 90 — but the
claims they support are inferences over those records, not directly read
facts, and the scan's honesty rule says a reading must never over-read
an ordinary binary. The ordinary binary is purely Win32 or purely
POSIX, and `Release` is a perfectly ordinary name outside COM. Loose
gates would fill the finding list with claims a reviewer cannot check
against the import table.

The spec named both gates as ADR candidates when the tickets landed;
this records them.

## Decision

Both readings are crate-internal pure modules over the classified
import listing the import scanner already emitted — no new
`ScanSource` reads — and each ships with its false-positive gate as the
module's central rule:

**Divergence (`divergence::detect_divergence`).**

- The gate is **both families**: at least one import whose mapping
  category names the Win32 family (`Win32Core`) **and** at least one
  naming the POSIX family (`POSIX`, or its C-runtime surface, `stdio`).
  A purely Win32 or purely POSIX binary claims nothing.
- **Category-less imports join neither side** — unidentified and
  ordinal-only imports carry no category, and the gate never infers a
  category the mapping did not state. **Platform-neutral categories**
  (DirectX, SDL2, PNG, zlib, C++ STL) count on neither side: they say
  nothing about which OS the binary straddles.
- **Only import entries stand on the gate** — a usage finding repeats
  an import the listing already carries.
- **One binary-level claim per scan**, however many import pairs sit
  across the families, at confidence **70** — level with the other
  structural readings: each trigger is an identified 90-confidence
  entry, but the portability claim over their pairing is an inference.
  The finding names the categories that triggered it, Win32 side
  first, and lists the triggering imports from both sides as evidence
  (`api (category)`, each side in import-listing order) so the claim
  checks against the import table.

**COM (`com::detect_com`).**

- Three signal kinds: known **COM runtime imports**
  (`CoCreateInstance`, `CoTaskMemAlloc`, …), the **IUnknown-shape
  trio** — `QueryInterface`/`AddRef`/`Release` *together*, since a lone
  `Release` is too common a name to claim COM on — and
  **MSVC-decorated method names** (`?QueryInterface@IDataSource@@…`)
  whose class segment names the interface.
- **Named recovery outranks the nameless claim**: when at least one
  decorated name recovers an interface, the scan lands **one finding
  per interface**, in first-seen order, at confidence **70**, naming
  the interface, listing the method names it saw, and carrying the
  decorated names as evidence. A nested class path names its innermost
  segment; a decorated data object recovers nothing.
- **A named claim suppresses the runtime claim** — the same evidence
  must not count twice.
- With no name recoverable, **exactly one binary-level runtime claim**
  names the signals seen as evidence, at confidence **50** — visibly
  below every other reading in the crate, because runtime imports and
  bare IUnknown-shape names with no interface behind them are the
  weakest COM read the scan can make.
- **No signal claims nothing**, and only import entries stand on the
  gate. The reading runs even when the call-graph fetch fails: the
  graph's node and callee names enrich the signal list, and the
  imports-only signal survives the degraded path.

## Consequences

- Positive:
  - The two claims most likely to over-read a binary are pinned by
    their silences — the pure-side listings, the lone `Release`, the
    category-less and platform-neutral imports, and the no-signal
    listings all have unit tests on their pure modules.
  - The confidence tiers tell the prompt consumer how solid each read
    is: 70 for a pairing over identified imports and for a recovered
    interface name, 50 for the nameless runtime read.
  - Custom library mappings join the divergence gate by naming one of
    its categories with their own — the gate keys on the category
    string, not on the builtin table.
- Negative:
  - The gate's category vocabulary (`Win32Core`, `POSIX`, `stdio`) is
    a string set aligned with PAL's `ApiCategory` display names without
    the evidence crate depending on PAL — if PAL's vocabulary drifts,
    these sets must drift with it. Accepted: the spec explicitly
    refused the coupling, and the drift risk is the cheaper half of
    the trade.
  - Divergence is a binary-level claim: a binary importing Win32 file
    APIs in one subsystem and POSIX sockets in another is flagged
    once, and the finding does not localize the straddle to functions.
    Per-function attribution was out of scope.
  - The COM read stays name-based: an interface driven purely through
    vtable offsets in memory leaves no decorated name and claims
    nothing — vtable reconstruction was out of scope.
  - The IUnknown trio gate is set membership over the whole name list:
    a binary importing `QueryInterface` and `AddRef` but never
    `Release` claims nothing. Deliberate — the trio is the shape, and
    a partial trio is too weak a signal to land a structural claim on.
