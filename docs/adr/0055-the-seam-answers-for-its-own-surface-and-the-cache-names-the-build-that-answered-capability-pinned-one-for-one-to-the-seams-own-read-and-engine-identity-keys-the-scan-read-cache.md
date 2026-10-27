# ADR-0055: The seam answers for its own surface, and the cache names the build that answered — capability pinned one-for-one to the seam's own read, and engine identity, not a hand-bumped integer, keys the scan read cache

- **Status:** Accepted
- **Date:** 2026-10-27 (P20 shipped, issues #354–#359, spec #353)
- **Deciders:** Arthur (solo project)
- **Amends:** ADR-0042's and ADR-0043's engine-drift narrative (ADR-0042 and ADR-0043 are left as written)

## Context

Two failures, one per half of track P20, both versions of a failure this
repo has now fixed twice.

**The seam answered program questions and said nothing about its own
limits.** An empty callers list read byte-identically whether the program
had no callers or the engine could not answer about callers at all; the
retry ladder burned attempts re-asking families the opened engine could not
answer; and P21's unknown-records ledger cannot record "the engine could
not answer" until unanswerable is reportable at all. ADR-0053 had already
fixed exactly this one level below — the filed scan and its coverage — with
the engine-stamps/roster-pins doctrine; the open session needed the same
treatment one level up.

**The scan read cache guarded engine drift with a hand-bumped integer.**
ADR-0042 and ADR-0043 told the truth of their day: the `CACHE_FORMAT_VERSION`
marker inside a directory was what made superseded directories cold, and
renaming a cache directory cost nothing because that marker invalidated the
old bytes anyway. But the same integer was quietly also the engine-drift
guard: every change to what the pinned Kuna build answers asked a
contributor to remember to raise it, and a forgotten bump silently kept
replaying the old engine's answers under the new engine's name.

## Decision

**One: the engine declares its own answer surface at the seam, and the
declaration pairs one-for-one with the seam's own queries — every level
where that pairing can be checked checks it, in one report.**

- One entry per query family — `answerable` or `unavailable`, one bounded
  reason sentence the only free-text slot — in the shared types crate
  (`CapabilityReport`, `FamilyCapability`, `AvailabilityStatus`), beside the
  P19 coverage shapes and keeping their discipline: there is no writable
  `unknown`, a family no report declares reads as `unknown` at read time,
  and unknown never prunes anything and is never mistaken for an answer or
  for an absence (issue #354).
- The declaration is live session state: pulled from the opened seam beside
  the batch's cached source, exactly once, costing no additional engine
  read, and held for the batch — never filed into a scan document, a cache
  key, or any read plumbing. The document's admitted coverage (ADR-0053)
  stays the persisted half; the run-equals-`--show` contract keeps its one
  run-path-only exemption for the seam line (ADR-0054).
- `QUERY_FAMILIES` in the seam crate — each declared family paired with the
  trait methods it answers — is the single source of truth, pinned at every
  level where the pairing is checkable: against the seam trait itself
  (#354), through the cache wrapper byte-identically — a cache never changes
  capabilities, it only caches answers (#354) — as the held report feeding
  prompt folds and retry decisions (#355–#357), and by the track sweep over
  the **real pipeline's seam read** — the same report the run path prints —
  where every query method must be claimed by exactly one declared family
  and every declared family carried by the read exactly once, with an
  orphan check rejecting a declared family that names no seam query method
  or a read naming a family no roster carries. Missing, doubled, and
  orphaned faults arrive in one failure report naming every offender at
  once (issue #359), the one-report doctrine of the registry pairing (#342)
  and the P19 track sweep (#352) now guarding the seam itself.
- Only a declared `unavailable` prunes a retry rung (#356); an answerable
  family admits nothing to prune and an undeclared family blocks nothing —
  P19's two-directional rule kept exactly.
- The capability wording and the coverage wording never share bytes at
  either end of their journeys. The raw admissions are deliberately
  collidable — one status-word machinery, and a coverage admission and a
  capability admission can spell byte-identical raw strings — and the pins
  build that collision on purpose and prove each line keeps its own frame:
  `Coverage:` beside `Analysis engine:` at the prompt end, the family-id
  prefix and `Seam:` label column at the report end. Two admits, never one
  merged line, never a borrowed frame (issues #355, #359).

**Two: the engine build names itself in every cache manifest, and the
identity — not the integer — keys the cache.**

- `EngineProvenance::identity()` in the shared types crate words
  `name@version@fingerprint` once, from the opened seam's own provenance
  stamp, and the seam crate has exactly one construction site
  (`kuna_provenance()`); source-scan pins fail loudly if the cache module
  ever spells an engine identity by hand, so the guard cannot be fed a
  hand-maintained constant (issue #358).
- Every manifest records the identity of the build that filed it, and the
  identity rides the checks the directory already passes: a mismatch is not
  a surviving scan, a warm open wipes and refiles it cold, and the
  pipeline's version pairing refuses a sibling scan filed under another
  identity — a batch never pairs answers the opened engine did not produce.
- A manifest carrying no identity — bytes filed before this decision —
  loads without error, reads its identity as unknown, matches no real
  engine, and goes cold: never hot, never an error (#358).
- `CACHE_FORMAT_VERSION` stays at its value with its meaning narrowed to
  what it always physically was: the record-shape gate. Engine drift is the
  identity's job now, and a pinned-Kuna bump moves the identity on its own.
  The track pins the mechanism rather than the memory: a simulated bump —
  scan directories filed under a previous build's identity at an untouched
  format version, and this very build playing the post-bump engine against
  them — forces every scan directory cold at once, refuses the stale
  pairing siblings, and refiles the manifests naming this build's identity,
  while a control directory filed under the current identity survives
  untouched (issue #359): the refusal is the bump, not the harness.

## Consequences

- An empty answer from an admitted family now admits itself: one bounded
  line at the run report (`Seam:`) and one per fed prompt section
  (`Analysis engine:`), and today's production — Kuna's full-roster
  all-answerable declaration — prints byte-identical silence everywhere,
  with all fifteen run-equals-`--show` pins passing as pure equality.
- The retry ladder never burns an attempt re-asking a family the engine
  says it cannot answer; the prune is recorded, never silent (#356).
- An engine swap can never silently replay stale answers. **The next
  pinned-Kuna bump is the self-running regression**: pulling the pin
  moves the identity, every old directory goes cold by mechanism, and
  nobody is asked to remember a constant.
- A seam that grows — P28's masked byte search, P29's def-use primitive —
  must grow the trait, the roster, and the declaration in the same change
  or the track sweep faults, naming itself.
- The review UI needed nothing new, and that is the decision recorded, not
  an omission: it renders filed documents, capability is live session
  state with no filed half to display, and a process pin keeps seam lines
  out of the review UI's render path (#359).
- P21 is unblocked: unanswerable is reportable, so honest unknowns finally
  have both halves — filed coverage below, live capability above — to
  build on.
- ADR-0042's and ADR-0043's format-version narrative reads as history for
  engine drift and stays live for record shape; this ADR is the amendment
  record, the ADRs themselves left as written.
