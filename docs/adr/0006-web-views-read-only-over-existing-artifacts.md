# ADR-0006: New web views are read-only over existing artifacts — no new persistence formats

- **Status:** Accepted
- **Date:** 2026-10-12 (W4 shipped, epic #129; recorded 2026-10-13)
- **Deciders:** Arthur (solo project)

## Context

W4 added two views — a Binaries view (per-binary classification, shim
tracker, PAL tracker) and unit-detail attempt comparison. Both could have
introduced dedicated tracking records written by the pipeline. But every
fact they show already exists in artifacts the pipeline writes
(`re/classify/`, `re/analysis/`, `re/shims/`, translation branches,
`re/patches/`), and a parallel record set would drift from them.

## Decision

- **Both views are read-only over persisted artifacts, introducing no new
  persistence format.** The attempt set is exactly the union of the unit's
  translation branches and its patch-record files — nothing invented, nothing
  dropped.
- **The PAL tracker is honestly derived web-side**, not persisted: the needed
  trait set comes from each function's recorded API-call categories mapped
  through the same category→trait table the translator's Tier-4 extraction
  mirrors; existence scans the generated PAL/shim sources for real `trait`
  definitions. No pipeline change.
- **The classification-override fold lives on the type itself**
  (`override_reason()` / `is_crate_replacement()` in the shared crate), so the
  dashboard and the analyzer spell the in-force-decision rule once.
- **All endpoints register on the shared router** (serve + live answer
  identically), per the ADR-0002 router rule.
- **Honest degradation, W3 pattern:** a missing or corrupt artifact is *no
  artifact* — "not generated" with no mapping count rather than a zeroed one,
  absent fields on the wire rather than guessed ones, 404s naming what is
  missing instead of fabricated payloads, "nothing to compare" for
  single-attempt units. The prompt-strategy log is deliberately *not* joined
  into the attempt list (its entries carry no function field — joining would
  invent identity), and `tests_passed` stays out of the contract (no
  per-attempt pass count is persisted anywhere).

## Consequences

The views can never disagree with the artifacts, and no new format needs
versioning or migration. The cost: the category→trait table is mirrored in
two places (translator + web) and must be kept in sync by hand.
