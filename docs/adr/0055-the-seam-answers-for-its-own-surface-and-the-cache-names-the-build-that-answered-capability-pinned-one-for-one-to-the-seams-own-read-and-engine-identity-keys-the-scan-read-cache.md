# ADR-0055: The seam answers for its own surface, and the cache names the build that answered — capability pinned one-for-one to the seam's own read, and engine identity, not a hand-bumped integer, keys the scan read cache

- **Status:** Accepted
- **Date:** 2026-10-27 (P20 shipped, issues #354–#359, spec #353)
- **Deciders:** Arthur (solo project)
- **Amends:** ADR-0042's and ADR-0043's engine-drift narrative (ADR-0042 and ADR-0043 are left as written)

## Context

Two failures, one in each half of track P20. Both are versions of a failure
this repo has now fixed twice.

**The analysis engine answered program questions and said nothing about its
own limits.** An empty callers list read byte-identically whether the
program had no callers or the analysis engine could not answer about
callers at all. The retry ladder wasted attempts re-asking families the
opened analysis engine could not answer. And P21's unknown-records ledger
cannot record "the analysis engine could not answer" until unanswerable can
be reported at all. ADR-0053 had
already fixed exactly this one level below — the filed scan and its
coverage — with its doctrine that each scan records its own coverage and
roster tests check it; the open session needed the same treatment one level
up.

**The scan read cache guarded analysis engine drift with a hand-raised
integer.**
ADR-0042 and ADR-0043 told the truth of their day: the `CACHE_FORMAT_VERSION`
marker inside a directory was what made superseded directories cold, and
renaming a cache directory cost nothing because that marker invalidated the
old bytes anyway. But the same integer was quietly also the analysis engine
drift guard: every change to what the repo's fixed Kuna build answers asked
a contributor to remember to raise it, and a forgotten raise silently kept
replaying the old analysis engine's answers under the new analysis engine's
name.

## Decision

**One: the analysis engine declares its own answer surface at the seam, and
the declaration matches the seam's own queries one-for-one — every level
where that match can be checked checks it, in one report.**

- One entry per query family — `answerable` or `unavailable`, plus one
  bounded reason sentence, the only free-text slot — in the shared types
  crate (`CapabilityReport`, `FamilyCapability`, `AvailabilityStatus`),
  beside the P19 coverage shapes, keeping their discipline: there is no
  writable `unknown`, a family no report declares reads as `unknown` at
  read time, and `unknown` never removes anything from the retry ladder and
  is never mistaken for an answer or for an absence (issue #354).
- The declaration is live session state: read from the opened seam beside
  the batch's cached source, exactly once, costing no additional analysis
  engine read, and held for the batch — never filed into a scan document, a
  cache key, or any read plumbing. The document's admitted coverage
  (ADR-0053) stays the persisted half; the run-equals-`--show` contract —
  a run's report matching a later `--show` report of the same document byte
  for byte — keeps its one run-path-only exemption for the seam line
  (ADR-0054).
- `QUERY_FAMILIES` in the seam crate — each declared family paired with the
  trait methods it answers — is the single source of truth, checked at
  every level where the pairing is checkable: against the seam trait itself
  (#354); byte-identically through the cache wrapper — a cache never
  changes capabilities, it only caches answers (#354); as the held report
  feeding prompt assembly and retry decisions (#355–#357); and by the
  whole-track test pass over the **real pipeline's seam read** — the same
  report the run path prints — where every query method must be claimed by
  exactly one declared family and the read must carry every declared family
  exactly once, with an orphan check rejecting a declared family that names
  no seam query method, or a read naming a family no roster lists. Missing,
  doubled, and orphaned faults arrive in one failure report naming every
  offender at once (issue #359): the one-report doctrine of the registry
  pairing (#342) and the P19 whole-track pass (#352) now guards the seam
  itself.
- Only a declared `unavailable` removes a step from the retry ladder
  (#356); an answerable family gives nothing to remove, and an undeclared
  family blocks nothing — P19's two-directional rule, kept exactly.
- The capability wording and the coverage wording never share bytes at
  either end of their journeys. The raw admission statements are
  deliberately able to collide — there is one status-word machinery, and a
  coverage admission and a capability admission can spell byte-identical
  raw strings — and the tests build that collision on purpose and prove
  each line keeps its own frame: `Coverage:` beside `Analysis engine:` at
  the prompt end, the family-id prefix and `Seam:` label column at the
  report end. Two admission lines, never one merged line, never one
  borrowing the other's frame (issues #355, #359).

**Two: every cache manifest records which analysis engine build wrote it,
and that identity — the engine identity, naming the build that answered —
not the integer, decides whether the cache is reused.**

- `EngineProvenance::identity()` in the shared types crate words
  `name@version@fingerprint` once, from the opened seam's own provenance
  stamp, and the seam crate has exactly one construction site
  (`kuna_provenance()`); source-scan tests fail loudly if the cache module
  ever spells an engine identity by hand, so the guard can never be fed a
  hand-maintained constant (issue #358).
- Every manifest records the identity of the build that filed it, and the
  identity joins the checks the directory already passes: a mismatch leaves
  no surviving scan, a warm cache open wipes the directory and refills it
  from the analysis engine, and the pipeline's version pairing refuses a
  sibling scan filed under another identity — a batch never pairs answers
  the opened analysis engine did not produce.
- A manifest carrying no identity — bytes filed before this decision —
  loads without error, reads its identity as unknown, matches no real
  analysis engine, and goes cold: its answers are never replayed, and it
  is never an
  error (#358).
- `CACHE_FORMAT_VERSION` stays at its value with its meaning narrowed to
  what it always physically was: the record-shape gate. Engine drift is the
  identity's job now, and a Kuna version bump moves the identity on its
  own. The track tests the mechanism rather than a contributor's memory: a
  simulated bump — scan directories filed under a previous build's identity
  at an untouched format version, and this very build acting as the
  post-bump analysis engine against them — forces every scan directory
  cold at once,
  refuses the stale pairing siblings, and refills the manifests naming this
  build's identity, while a control directory filed under the current
  identity survives untouched (issue #359): the version change causes the
  refusal; the test harness does not cause it by hand.

## Consequences

- An empty answer from a family the seam declared unavailable now says so
  plainly: one
  bounded line at the run report (`Seam:`) and one per fed prompt section
  (`Analysis engine:`), and today's production — Kuna declaring every
  family on its full roster answerable — prints byte-identical silence
  everywhere, with all fifteen run-equals-`--show` pins passing as pure
  equality.
- The retry ladder never wastes an attempt re-asking a family the analysis
  engine says it cannot answer; the removal is recorded, never silent
  (#356).
- An analysis engine swap can never silently replay stale answers. **The
  next Kuna version bump is its own regression test**: raising the version
  moves the identity, every old directory goes cold by the mechanism
  itself, and nobody is asked to remember a constant.
- A seam that grows — P28's masked byte search, P29's def-use primitive —
  must grow the trait, the roster, and the declaration in the same change,
  or the whole-track test pass faults, naming itself.
- The review UI needed nothing new, and that is recorded as the decision,
  not an omission: it renders filed documents, capability is live session
  state with no filed half to display, and a process test keeps seam lines
  out of the review UI's render path (#359).
- P21 is unblocked: unanswerable is reportable, so honest unknowns finally
  have both halves — filed coverage below, live capability above — to build
  on.
- ADR-0042's and ADR-0043's format-version narrative reads as history for
  analysis engine drift and stays live for record shape; this ADR is the
  amendment
  record, the ADRs themselves left as written.
