# ADR-0026: The per-function pass runs as an order-preserving window of eight decompiles, with the skip-rate breaker gating each decompile from shared state

- **Status:** Accepted
- **Date:** 2026-10-14 (P3.5-5 shipped, issue #156)
- **Deciders:** Arthur (solo project)

## Context

The algorithm scan's per-function pass was sequential. It made one
decompile round trip to the Ghidra bridge at a time, so scan wall time
grew with the listing's length times the round-trip latency. Spec #151
asked to parallelize across functions with bounded concurrency. The
scan's observable contract, pinned by tests and earlier ADRs, had to
survive: hints land in listing order (ADR-0022's tie and survivor rules
depend on this, and two scans of one program must diff cleanly); each
function is decompiled exactly once; the string listing is fetched
once; caller fetches stay arity-gated; and the skip-rate breaker (issue
#71) still aborts a wrong-program scan with its counts instead of
persisting a record that looks clean but is not. ADR-0024 additionally
fixed the correlation pass as a once-after-the-loop pass over the
collected bodies, not per-function work.

Four questions had to be settled: the concurrency shape (window vs full
fan-out), the cap, how the breaker counts and stops under concurrency,
and how a test can prove the cap at all.

## Decision

- **The pass is an order-preserving window, not a fan-out.** The
  listing maps to one future per function and runs through
  `futures::stream::iter(...).buffered(8)`. `buffered` polls the
  window concurrently but *yields results in input order*. So the
  listing-order hint contract holds for free — no index bookkeeping, no
  re-sort, no reassembly step. A `join_all` plus sort, or spawning per
  function, would have brought back that bookkeeping and its failure
  modes for the same wall-time win. The correlation pass stays exactly
  where ADR-0024 put it: once after the window, over the bodies the
  window collected.
- **The cap is a constant, eight in flight.** The bridge is one shared
  server per program. The point of the bound is to speed the scan
  without flooding it: eight parallel decompiles is a wide enough
  pipeline to hide round-trip latency while staying polite to a single
  Ghidra instance. It is a named constant
  (`MAX_IN_FLIGHT_DECOMPILES`), not an operator flag. Nothing yet asks
  to tune it, and a knob with no demand is a contract someone must keep
  stable.
- **The skip-rate breaker becomes shared state that gates each
  decompile.** One `SkipRateBreaker` lives beside the pass: an
  `AtomicUsize` failure count over the listing's fixed total. Every
  failed decompile joins the count as it lands, and every function not
  yet started consults it *before its decompile is issued*. A tripped
  breaker therefore stops new decompiles instead of merely ending a
  sequential walk. The sequential semantics ("no third decompile after
  two of three fail") survive unchanged. The abort error carries
  whatever counts the breaker holds at the moment of abort. Under a
  real async client those counts can run ahead of the sequential
  numbers by up to the window, because in-flight failures land before
  the collector notices the trip. The spec's contract is *counting
  across the concurrent pass and stopping new decompiles once tripped*,
  not exact counts. A test pins the abort with the right counts on a
  deterministic fake.
- **Per-function futures return a private `PassOutcome`, not a
  `Result`.** The variants `Read { body, hints }`, `Failed`, `Nameless`,
  and `Halted` keep the collector's match arms explicit, so the abort
  decision lives in one place. `Halted` is a defensive backstop. The
  collector normally aborts on the counted `Failed` arm first, but a
  future that notices the trip itself still returns the breaker's
  error rather than inventing an empty success.
- **The cap is proven at the fake-program seam.** `FakeProgram` gained
  a slow-decompile mode (each decompile yields to the executor) plus
  `in_flight`/`max_in_flight` counters. A test asserts that the
  observed maximum is at least 2 (the pass really is concurrent) and at
  most `MAX_IN_FLIGHT_DECOMPILES` (the bound holds). The default fake
  stays synchronous, so `buffered` polls its futures in listing order.
  That is what keeps the pre-existing sequential breaker test green
  without modification. Concurrency is therefore opt-in per test, and
  breaker determinism never depends on executor timing.

## Consequences

- Scan wall time on a real bridge drops roughly by the window factor
  for listings dominated by decompiles. The fetch counts — exactly-once
  decompiles, one string read, arity-gated caller reads — are
  untouched, and the existing fetch-count tests keep proving it.
- The breaker's reported counts under a real async client are
  window-dependent: up to seven failures beyond the sequential trip
  point can land before the abort. The abort itself is exact: no
  decompile is issued after the trip. A 12-function test pins this,
  where only the first seven are ever decompiled.
- The crate gained a `futures-util` dependency (workspace-pinned). The
  trait seam (`ScanSource`) already returned `Send` futures, so no
  client code changed.
- Two scans of one program still produce byte-identical hint lists.
  The ordering comes from `buffered` itself, not from a later sort. So
  the scan-order contract cannot regress unless the window itself
  changes.
