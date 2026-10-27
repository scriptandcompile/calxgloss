# ADR-0006: New web views are read-only over existing artifacts — no new persistence formats

- **Status:** Accepted
- **Date:** 2026-10-12 (W4 shipped, epic #129; recorded 2026-10-13)
- **Deciders:** Arthur (solo project)

## Context

W4 added two views: a Binaries view (per-binary classification, shim
tracker, PAL tracker) and the unit-detail attempt comparison view. Both
could have introduced dedicated tracking records written by the pipeline.
But every fact they show already exists in artifacts the pipeline writes
(`re/classify/`, `re/analysis/`, `re/shims/`, translation branches,
`re/patches/`), and a parallel record set would drift from them.

## Decision

- **Both views are read-only over persisted artifacts, and no new
  persistence format appears.** The attempt set is exactly the union of the
  unit's translation branches and its patch-record files — nothing
  invented, nothing dropped.
- **The PAL tracker is honestly derived web-side**, not persisted. The
  needed trait set comes from each function's recorded API-call categories,
  mapped through the same category→trait table that the translator's
  Tier-4 extraction mirrors. Existence is checked by scanning the
  generated PAL/shim sources for real `trait` definitions. The pipeline
  does not change.
- **The classification-override fold lives on the type itself**
  (`override_reason()` / `is_crate_replacement()` in the shared crate), so
  the dashboard and the analyzer state the in-force-decision rule in one
  place.
- **All endpoints register on the shared router** (serve + live answer
  identically), per the ADR-0002 router rule.
- **Honest degradation, W3 pattern:** a missing or corrupt artifact is *no
  artifact*. The view shows "not generated" with no mapping count, not a
  zeroed one. A field with no value is absent from the wire, not guessed.
  A 404 names what is missing, instead of returning a fabricated payload. A
  single-attempt unit shows "nothing to compare". The prompt-strategy log
  is deliberately *not* joined into the attempt list: its entries have no
  function field, so joining them would invent an identity. `tests_passed`
  stays out of the contract, because no per-attempt pass count is
  persisted anywhere.

## Consequences

The views can never disagree with the artifacts, and no new format needs
versioning or migration. The cost: the category→trait table is mirrored in
two places (translator + web) and must be kept in sync by hand.
