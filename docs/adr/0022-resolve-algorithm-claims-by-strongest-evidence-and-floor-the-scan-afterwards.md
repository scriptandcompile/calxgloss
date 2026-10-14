# ADR-0022: Resolve algorithm claims by strongest evidence, and floor the scan afterwards

- **Status:** Accepted
- **Date:** 2026-10-14 (P3.5-1 shipped, issue #152)
- **Deciders:** Arthur (solo project)

## Context

The algorithm scan runs several detectors over the same functions —
control-flow shapes, body strings, listing strings, the callback
contract database — and each reports its hints straight into the scan's
result. The detectors never talk to each other, so a finished scan can
carry several claims for one *(function, algorithm)* pair: the CRC
loop's own decompiled text and a program-wide listing marker both name
`crc`, at different confidences, and the old scan emitted both as
separate hints. The standard scores themselves were hardcoded inside
each detector, and nothing could suppress weak leads short of editing
code.

The `confidence` module had stated this contract in its doc comment
since the crate was scaffolded but held no code. Ticket #152 makes the
contract real: resolve competing claims to one hint per
*(function, algorithm)*, and give the engine a configurable
minimum-confidence filter mirroring the typesdb engine's.

The questions the resolution must answer: what "strongest" means when
two claims tie; where in the hint list the survivor stands; whether the
floor runs before or after resolution; and what the floor's default
should be — typesdb's filter defaults to a non-zero 40, but the
algorithm scan has shipped without any floor so far.

## Decision

- **Resolution lives in the `confidence` module as
  `resolve_conflicts`, keyed by `(function, algorithm)`.** Same shape
  as typeinfer's resolver of the same name: one map, strict `>`, so
  the highest-confidence claim wins and **a tie keeps the claim the
  scan surfaced first** — detector registration order is the
  tiebreaker, and the first detector's evidence (a body match, say) is
  the one kept. Claims naming *different* algorithms for one function
  never conflict: a function that both does a hash lookup and recurses
  reports both hints.
- **The survivor stands where that algorithm first appeared in scan
  order,** not where the winning claim came from. The hint list stays
  in scan order end to end, so two scans of the same program diff
  cleanly even when a later detector strengthened an earlier claim.
- **The floor applies *after* resolution.** `AlgorithmEngine` carries
  `min_confidence: u8` with a `with_min_confidence(threshold)` builder,
  and `scan` filters the resolved survivors, keeping hints at or above
  the threshold (`>=`, like typesdb's filter). Filtering afterwards
  means a claim another detector strengthened clears a floor its first
  claim would have missed — filtering before would drop evidence that
  resolution would have promoted.
- **The default floor is 0 (keep everything), deliberately diverging
  from typesdb's 40.** The typesdb filter guards a *write* path where
  weak candidates pollute type candidates; the algorithm scan's output
  is hint evidence for the translation prompt, where a weak lead is
  still a lead. Keeping the default at 0 means every existing run and
  test behaves exactly as before, and a caller that wants a floor —
  the CLI, when a ticket asks for one — opts in explicitly.
- **The per-detector standard scores move into the `confidence`
  module** as `pub const`: `CFG_CONFIDENCE` = 60 (control-flow match),
  `BODY_CONFIDENCE` = 60 (marker in the function's own body),
  `LISTING_CONFIDENCE` = 30 (marker somewhere in the binary's strings),
  `CALLBACK_CONFIDENCE` = 75 (callback-contract database hit). The
  detectors import their score from there, so tuning the scoring model
  is a one-module change and adding a detector means naming its score
  in the model, not hiding it in the detector.

## Consequences

- Every persisted scan document now carries at most one hint per
  *(function, algorithm)*: the duplicate-hint noise the translation
  prompt used to carry is gone, and hint counts per function mean
  "distinct algorithms detected", not "detector hits".
- The `confidence` module is the single home of the scoring model —
  constants, resolution rule, and the doc that explains how the floor
  interacts with resolution. A new detector reads its standard score
  from there.
- Detector registration order is now load-bearing for ties: reordering
  detectors can change *which* equal-confidence evidence survives,
  though never how many hints exist. Scan-seam tests pin the current
  order's behavior.
- The floor is engine configuration, not a persisted property: the
  same program scanned under different floors yields different
  documents, and only survivors reach disk. An integration test pins
  that the resolved and floored survivors are exactly what the
  persistor writes.
- If a later CLI ticket wants a non-zero default for user runs, it
  sets it at the call site — the engine's keep-everything default
  stays as the neutral seam behavior.
