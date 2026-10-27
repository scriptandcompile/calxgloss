# ADR-0023: One JSON pattern database replaces the standard sets whole, with per-entry confidence riding on the pattern types

- **Status:** Accepted
- **Date:** 2026-10-14 (P3.5-2 shipped, issue #153)
- **Deciders:** Arthur (solo project)

## Context

The algorithm scan's recognizable shapes lived entirely in Rust: three
`default_*` functions holding the standard control flow signatures,
string signatures, and callback contracts. Teaching the scan a new sort
variant or comparator contract meant editing Rust and recompiling. An
operator working a binary with domain-specific algorithms had no way to
describe what the scan should look for.

Spec #151 asked for a dynamic pattern database: one JSON document, a
`--patterns <file>` flag, and no change to a scan that supplies no
file. Four questions had to be settled. Is the file format a new wire
format, or the pattern types' existing serde shape? Do a file's entries
merge with the built-in sets or replace them? Where does a per-entry
confidence live, and how does it interact with the resolution ADR-0022
established? And how does a malformed file behave?

## Decision

- **The database is one serde document with one section per detector,
  and its entries are exactly the pattern types' existing serde
  shapes.** `PatternDatabase` (new `pattern_db` module) holds
  `control_flow: Vec<AlgorithmPattern>`, `string_signatures:
  Vec<StringSignature>`, and `callback_contracts: Vec<CallbackPattern>`
  — no parallel wire format. What a scan persists and what a
  database holds are the same thing, and every existing serde
  round-trip test already pins half the file format. The fourth
  section that a correlation detector will need (#155) is an additive
  change to the same document.
- **A supplied database replaces the standard sets whole; it never
  merges.** `AlgorithmEngine::with_pattern_database` swaps all three
  detector sets at once, and a section the document omits is an empty
  set. Merging would make the effective set depend on both the file and
  the built-ins. It would leave no way to *remove* a built-in signature
  that misfires on one binary. And it would make two operators' files
  mean different things. With replacement, the file is exactly what the
  scan knows. The built-in sets stay the default only when no file is
  supplied.
- **The per-entry confidence is a field on the pattern types, not on a
  database wrapper.** `AlgorithmPattern`, `StringSignature`, and
  `CallbackPattern` each gained `confidence: Option<u8>`
  (serde-defaulted, skipped when absent), and each detector uses
  `confidence.unwrap_or(standard_score)` when it emits a hint. The
  entry *is* the pattern, so the field belongs on the pattern type.
  Built-in and file entries then share one type and one set of rules,
  and a later programmatic caller can pass an override without a file.
  For a string signature the override covers either reading —
  body or listing-only — because the entry states its own confidence,
  not a per-evidence-kind ladder.
- **The override wins resolution only by being stronger.** Hints enter
  ADR-0022's `resolve_conflicts` carrying their final score. A
  per-entry 90 wins against a standard-score claim for the same
  algorithm, and a per-entry 20 loses to a claim at 60. Coming from a
  file gives a claim no privilege; resolution stays purely score-based.
- **Loading goes through the shared JSON persistence plumbing, and a
  bad file fails the run loudly.** `PatternDatabase::load` wraps
  `calxgloss_types::persist::load_json`. A missing, unreadable, or
  malformed document becomes `AlgorithmError::PatternDatabase`, naming
  the path. A typo in the file must never quietly reduce recognition to
  a partial set, so the document is strict: `deny_unknown_fields`
  rejects a misspelled section key or entry field as a malformed file
  rather than ignoring it. Inside a well-formed entry the detectors'
  lenient per-entry rules are untouched: an uncompilable regex
  matches nothing and blocks nothing, and the `{name}` placeholder
  keeps working. File entries are built-in entries in every other
  respect.
- **The CLI flag is scan-only.** `calxgloss algorithm --patterns
  <file>` configures the scan. `--show` prints a cached result and
  ignores the flag, because the flag describes how a scan was run, not
  what a persisted document holds.

## Consequences

- Operators can teach the scan new algorithm shapes without
  recompiling. The format is pinned by serde round-trip tests over the
  document and by scan-seam tests over a parsed file.
- The three pattern types grew one optional field each. Documents
  persisted before the change still load, because the field is
  serde-defaulted. The standard sets serialize unchanged — the field is
  skipped when absent.
- A file that supplies only some sections silently leaves the other
  detectors with nothing to read. That is the replacement contract, and
  the CHANGELOG and command help state it. A future authoring aid
  (validation or reporting of empty sections) stays out of scope.
- Detector registration order keeps its ADR-0022 role for ties. File
  section order is now part of that same configuration order that
  behavior depends on.
- The `--patterns` path is covered at the evidence engine's seam and through the
  persist round trip. The CLI itself stays a thin wiring layer with no
  test harness of its own, like every other flag before it.
