# ADR-0037: The apidetect divergence reading needs both platform families, and a named COM interface suppresses the nameless runtime claim

- **Status:** Accepted
- **Date:** 2026-10-15 (P9.5-2/-3 shipped, issues #185, #186)
- **Deciders:** Arthur (solo project)

## Context

P9.5 (spec #183) added two structural readings to the library & API
scan: a `platform_divergence` claim that a binary uses both the Win32
and the POSIX/stdio families, and a `com_interface` claim that a
binary drives the COM component model. Both rest on records that are
themselves solid — an identified import sits at confidence 90 — but
the claims they support are inferences over those records, not
directly read facts. The scan's honesty rule says a reading must never
claim more than an ordinary binary shows. The ordinary binary is
purely Win32 or purely POSIX, and `Release` is a perfectly ordinary
name outside COM. Loose gates would fill the finding list with claims
a reviewer cannot check against the import table.

The spec marked both gates as ADR candidates when the tickets landed;
this ADR records them.

## Decision

Both readings are pure modules inside the crate, running over the
classified import listing the import scanner already emitted — no new
`ScanSource` reads. Each ships with its false-positive gate as the
module's central rule:

**Divergence (`divergence::detect_divergence`).**

- The gate is **both families**: at least one import whose mapping
  category identifies the Win32 family (`Win32Core`) **and** at least
  one import whose category identifies the POSIX family (`POSIX`, or
  its C-runtime surface, `stdio`). A purely Win32 or purely POSIX
  binary claims nothing.
- **Category-less imports join neither side** — unidentified and
  ordinal-only imports have no category, and the gate never infers a
  category the mapping did not state. **Platform-neutral categories**
  (DirectX, SDL2, PNG, zlib, C++ STL) count on neither side: they say
  nothing about which OS the binary needs both platforms for.
- **Only import entries count at the gate** — a usage finding repeats
  an import the listing already carries.
- **One binary-level claim per scan**, however many import pairs sit
  across the families, at confidence **70** — level with the other
  structural readings: each trigger is an identified 90-confidence
  entry, but the portability claim built from their pairing is an
  inference. The finding records the categories that triggered it,
  Win32 side first, and lists the triggering imports from both sides
  as evidence (`api (category)`, each side in import-listing order) so
  the claim can be checked against the import table.

**COM (`com::detect_com`).**

- Three signal kinds: known **COM runtime imports**
  (`CoCreateInstance`, `CoTaskMemAlloc`, …), the **IUnknown-shape
  trio** — `QueryInterface`/`AddRef`/`Release` *together*, because a
  lone `Release` is too common a name to claim COM on — and
  **MSVC-decorated method names** (`?QueryInterface@IDataSource@@…`)
  whose class segment identifies the interface.
- **Named recovery outranks the nameless claim.** When at least one
  decorated name recovers an interface, the scan reports **one finding
  per interface**, in first-seen order, at confidence **70**. The
  finding records the interface, lists the method names it saw, and
  carries the decorated names as evidence. For a nested class path,
  the name is the innermost segment. A decorated data object recovers
  nothing.
- **A named claim suppresses the runtime claim** — the same evidence
  must not count twice.
- With no name recoverable, the scan reports **exactly one
  binary-level runtime claim**, naming the signals it saw as evidence,
  at confidence **50** — visibly below every other reading in the
  crate, because runtime imports and bare IUnknown-shape names with no
  interface behind them are the weakest COM reading the scan can make.
- **No signal, no claim**, and only import entries count at the gate.
  The reading runs even when the call-graph fetch fails: the graph's
  node and callee names enrich the signal list when the fetch
  succeeds, and the imports-only signals still stand when it fails.

## Consequences

- Positive:
  - The two claims most likely to over-fire on an ordinary binary are
    pinned down by their silence cases: the pure-side listings, the
    lone `Release`, the category-less and platform-neutral imports,
    and the no-signal listings all have unit tests on their pure
    modules.
  - The confidence scores tell the prompt consumer how solid each
    reading is: 70 for a pairing over identified imports and for a
    recovered interface name, 50 for the nameless runtime reading.
  - Custom library mappings join the divergence gate by giving their
    own entries one of its categories — the gate matches on the
    category string, not on the built-in table.
- Negative:
  - The gate's category vocabulary (`Win32Core`, `POSIX`, `stdio`) is
    a string set aligned with PAL's `ApiCategory` display names,
    without the evidence crate depending on PAL. If PAL's vocabulary
    changes, these sets must change with it. Accepted: the spec
    explicitly refused the coupling, and the risk of drift is the
    cheaper half of the trade.
  - Divergence is a binary-level claim: a binary importing Win32 file
    APIs in one subsystem and POSIX sockets in another is flagged
    once, and the finding does not say which functions make up the
    cross-platform use. Per-function attribution was out of scope.
  - The COM reading stays name-based: an interface driven purely
    through vtable offsets in memory leaves no decorated name and
    claims nothing — vtable reconstruction was out of scope.
  - The IUnknown trio gate is set membership over the whole name list:
    a binary importing `QueryInterface` and `AddRef` but never
    `Release` claims nothing. Deliberate — the trio is the shape, and
    a partial trio is too weak a signal to build a structural claim
    on.
