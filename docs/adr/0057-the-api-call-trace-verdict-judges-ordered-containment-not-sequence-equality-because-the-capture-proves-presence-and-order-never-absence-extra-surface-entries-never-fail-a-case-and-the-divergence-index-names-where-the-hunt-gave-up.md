# ADR-0057: The API-call trace verdict judges ordered containment, not sequence equality — because the capture proves presence and order, never absence, extra surface entries never fail a case, and the divergence index names where the hunt for the unhonoured call gave up

- **Status:** Accepted
- **Date:** 2026-10-31 (P22 shipped, issues #382–#389, spec #388, containment ticket #389)
- **Deciders:** Arthur (solo project)

## Context

Track P22 widened the restitch gate with a second verdict dimension: the
**ordered API-call trace**. The testgen baseline records the Win32 call
sequence an original DLL actually made — via an IAT interposer around the
DLL in the Wine harness — and the verify side records the ordered
verify-PAL-surface route the restitched Rust body takes in the generated
scratch runner. The apidetect document's per-function usage findings scope
the captured traces onto the generated suite's cases (the unit's **API
roster**, de-duplicated in first-seen order), and a case with no recorded
trace leaves the dimension **unassessed** — silence never counts as a
pass.

The first shipped comparator demanded sequence *equality*: the restitched
route had to equal the captured trace name-for-name, position-for-position.
That turned out to make a claim the capture can never support, and issue
#387 caught it at the gate itself — the two sides are not the same
vocabulary. The IAT interposer sees direct IAT calls only; a COM-driven
unit (Direct3D, GDI) spends its life in vtable calls the interposer is
structurally blind to, while the restitched Rust side legitimately *adds*
surface entries a correct translation needs (render targets, housekeeping)
that the original capture could never have recorded. Under equality, those
structurally unspellable extras failed cases whose values were right — the
gate was enforcing a route no honest capture had ever observed from both
sides.

Issue #388 weighed where to fix the honesty line: widen the capture
(COM-vtable interposition), gate at fold time, or move the comparator to
ordered containment. The first was ruled out as a research project in its
own right that still could not guarantee both sides speak identically; the
second would turn the roster — a scoping device — into an unmeasured
completeness judge. The spec fixed the decision at the comparator, and
ticket #389 landed it.

## Decision

Move the honesty line all the way to the comparator. Five decisions:

- **Ordered containment, greedily matched.** A case's trace dimension
  passes when the expected names appear inside the actual route in order,
  repetitions intact, each found at or after the position where the
  previous one matched. The matcher never skips an expected call and never
  re-uses an actual entry. Extras — actual-side entries the expectation
  never named — never fail a case, because they are exactly the entries
  the capture vocabulary cannot speak. Skipped, permuted, and
  under-repeated *observed* calls still fail: containment is the capture's
  own limit, not a free pass.
- **The capture proves presence and order, never absence.** This is the
  rule the record shape already stated (a missing or empty trace reads
  *unassessed*); this ADR extends it to the comparator, which must not
  claim more than the artifact that fed it. An absent expected name means
  "not observed", never "not called" — so it can neither force nor forbid
  an actual-side entry.
- **The divergence index names the give-up position, redefined in place.**
  On a failing case the index says where in the *actual route* the search
  gave up its hunt for the first unhonoured expected call: 0 when the
  very first was never found, the position just after the last honoured
  call for a later miss, and the route's own length when the search ran
  off its end. The old index named where two equal-length sequences first
  parted — a position with no referent once extras are legal. The failure
  prose ("API-call trace divergence at position N: expected [...],
  got [...]"), both full sequences side by side as typed data, and the
  `Option<usize>` wire shape are untouched, so the retry ladder routes a
  trace divergence into the fix prompt exactly as before and the prompt
  quotes the position unchanged.
- **One verdict, one vocabulary for every unit.** The concession is
  deliberate and accepted: for storage-shape and thread-shape units, whose
  capture *was* complete, extra actual-side calls no longer fail either.
  An exact-equality verdict cannot be made vocabulary-aware per unit —
  nothing on the verdict knows which side's capture was honest — so the
  gate judges every unit under the honesty the weakest capture supports.
  The loss is real (extras can no longer be caught at the trace
  dimension) and is the price of never failing a unit for a difference no
  capture could see.
- **The judge lives where the route lives.** The containment walk runs
  inside the generated scratch runner's own judge, beside the value
  compare, because the ordered route only exists there. The verdict
  travels out through the existing verification record — same fields, same
  parsing, same assessed-count rule — and the recorder, the interposer,
  the roster scoping, the spelling table, the drop rule, and the fold are
  untouched. No new seam: the compile-backed verdict suite is the pinning
  point, and the shipped extra-call pin was *inverted* — from "an extra
  call diverges" to "an extra call the capture cannot speak is tolerated"
  — so the suite's own prose records the change of mind.

## Consequences

- Graphics and COM-driven restitches stop failing the gate for calls no
  capture could have recorded on both sides; the trace dimension now
  catches what it can actually see: a projected call the body never makes,
  a permuted route, or a repeated observed call honoured only once — each
  named at its give-up position, with both sequences beside it.
- The extras-blindness concession is permanent unless a future track makes
  the capture vocabulary complete on both sides (COM-vtable interposition
  was explicitly out of scope for P22); until then, extras are caught
  nowhere at the gate.
- Retry routing is untouched end to end: a value-clean case failing on the
  trace dimension still records the divergence line and still feeds the
  next attempt's fix prompt, which quotes the position with the same
  wording. Pins that assert an exact position number re-derive under the
  give-up rule (the retry-ladder pin's fixture moves from position 0 to
  position 2) — position numbers in pins are derivations, not contracts;
  the format and the routing are.
- The roadmap's gate-widening block is half shipped: P23 (real inputs) and
  P24 (EXE scenarios) still shape the gate before P25's receipts freeze
  its verdicts in place and P26's ledger closes a binary. P22 left the
  roadmap per the removal rule; its shipped history lives in
  `CHANGELOG.md`.
