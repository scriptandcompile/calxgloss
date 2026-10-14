# ADR-0020: Keep type write-back on its own trait the read cache never implements

- **Status:** Accepted
- **Date:** 2026-10-13 (P2.5-7 shipped, issue #149)
- **Deciders:** Arthur (solo project)

## Context

Spec #142 asks the typeinfer scan's inferred types to be written back
into Ghidra — prototypes, local-variable types, and the named types a
prototype needs (struct, enum, typedef, struct field). ADR-0001 chose
the bethington v6.0.0 bridge precisely because it serves those calls.
Ticket #149 makes the capability exist and be tested before any
pipeline pass drives it (#150).

The seam questions: whether the write calls join the existing
read-only `ScanSource` trait or stand beside it; whether the
two-tier read cache wraps them the way it wraps reads; how the
setters name their target function; and how a write the bridge
refused — as `200 OK` prose, like every other bridge failure —
reaches the caller as a named error without disturbing the read
side's handling of the same words.

The tension: one trait would be a friendlier surface, but the cache
must never serve a write, and a trait the cache implements for reads
is a trait someone can accidentally hand to a write-back pass.

## Decision

- **A separate write-side trait.** `TypeWriteSource` lives in
  `type_write_source.rs`, sibling to `scan_source.rs`, carrying the
  six v6.0.0 calls: `set_function_prototype`, `set_local_variable_type`,
  `create_struct`, `create_enum`, `create_typedef`, `add_struct_field`.
  Same RPITIT style as `ScanSource` (`-> impl Future + Send`), same
  delegation shape: `GhidraClient` implements it by calling its own
  inherent `#[instrument]` methods.
- **The read cache never implements it.** `CachedGhidraSource` stays
  a `ScanSource`-only type; a write-back pass is handed the raw client.
  The contract is guarded by a compile-time coherence tripwire inside
  the crate: a blanket `WriteSourceProbe` impl over every
  `TypeWriteSource` plus a concrete impl for the cached source's
  probe — the moment anyone writes `impl TypeWriteSource for
  CachedGhidraSource`, the two collide (E0119) and the crate stops
  compiling. The guard lives inside the crate because coherence's
  negative reasoning is only available where the trait is defined;
  an integration test rejects the pair unconditionally.
- **Both setters address the function by address.** The bridge parses
  `function_address` with `parseAddress` and refuses a name, so the
  trait takes `function_address: u64` and sends it as bare hex — the
  same rendering every address-carrying read call already uses.
  Naming by prototype text would have been a friendlier API; it is
  not what the bridge accepts.
- **Payload keys follow the v6.0.0 `@RequestBody` maps verbatim**,
  verified against the bridge source: `{function_address, prototype}`,
  `{function_address, variable_name, new_type}`, `{name, fields:
  [{name, type, offset?}]}`, `{name, values: {NAME: value}, size}`,
  `{name, base_type}`, `{struct_name, field_name, field_type,
  offset?}`. Enum values ride as a JSON object, not an array — the
  bridge maps them as `Map<String, Integer>` — and an omitted offset
  is absent from the payload, never null.
- **Prose refusals join the classifier; the not-found sentinel does
  not.** The write endpoints' refusal openings (`Failed to set
  function prototype`, `Structure with name`, `Could not resolve base
  type`, …) join `SERVER_ERROR_PREFIXES`, so a refused write surfaces
  as `Reported` instead of a silent success. `Structure not found: X`
  is deliberately excluded: the read side already recognizes that
  sentinel itself and turns it into `NotFound`, and a classifier
  prefix would intercept it before either site could. Both the read
  and the write path now share one `structure_not_found` helper, so
  the sentinel is spelled once.

## Consequences

- The write seam is uncacheable by construction: no future pass can
  be handed a cached `TypeWriteSource`, because no such type exists —
  the type system enforces what the function-tag precedent only
  demonstrated at runtime.
- The write-back pass (#150) takes `&GhidraClient` (or any future
  `TypeWriteSource` implementer) beside its `ScanSource` reads; the
  two seams compose at the call site rather than in one trait.
- A refused write is an error the caller sees: every write response
  goes through `classify`, so prose refusals raise `Reported` and the
  structure-not-found sentinel raises `NotFound`. The success bodies
  the write endpoints answer with are pinned by a classifier test so
  a new prefix can never swallow one.
- The trait is currently implemented once and driven by nothing —
  deliberate per the ticket — so the fake-server payload tests are
  the whole behavioral contract until #150 exercises it for real.
