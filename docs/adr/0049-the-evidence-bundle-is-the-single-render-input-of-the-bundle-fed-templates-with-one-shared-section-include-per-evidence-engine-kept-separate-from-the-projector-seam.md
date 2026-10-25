# ADR-0049: The evidence bundle is the single render input of the bundle-fed templates, with one shared section include per evidence engine, kept separate from the projector seam

- **Status:** Accepted
- **Date:** 2026-10-25 (P36 shipped, issues #317–#321, spec #316)
- **Deciders:** Arthur (solo project)

## Context

ADR-0048's projector fills the 21-field `EvidenceBundle`, and its ADR
explicitly deferred the consumption side: "P36 render[s] the bundle while
knowing nothing of scan machinery." The **render** side had never been
treated as a seam at all. A new engine's finding list was re-declared
~8–10 times before any template could read it: `EscalateTemplate` held 17
of the bundle's lists as its own fields, `ModuleContextTemplate` 12, and
the two prompt-data twins (`ModuleContextPromptData`,
`FullModulePromptData`) re-declared 12 each again; every constructor moved
the same fields one by one (the escalate constructor alone, ~20). On the
template side, each evidence engine's prompt-section body was hand-copied
per template — the escalate and module-context section bodies were already
byte-identical modulo their heading lines for roughly twelve sections, and
CONTROL FLOW / TYPE INFORMATION repeated again in the full-module, rich,
and detailed templates. Adding one engine meant touching five prompt sites
plus a renders/omits test pair per site, and nothing caught the copies
drifting apart: they agreed only because nobody edited one alone (spec
#316, architecture review 2026-10-24, candidate 3).

The unification question sat right beside ADR-0048's seam: the projector
already knows every engine and its projection — why not let it render too,
handing templates a pre-projected list of (heading, rendered body) strings
and leaving the templates as dumb splats? The open questions were what the
render input is, where section bodies live, whether per-template heading
wording survives, and whether the projector seam and the render side merge
into one table.

## Decision

Invert the rendering: the bundle is the seam and the templates adapt at
it.

- **The bundle is every bundle-fed template's render input.**
  `EscalateTemplate`, `ModuleContextTemplate`, and `FullModuleTemplate`
  each hold the gathered `EvidenceBundle` as a single evidence field
  (borrowed `&EvidenceBundle` where the caller keeps ownership, moved
  otherwise) and keep only genuinely tier-specific fields — escalate the
  function identity, failing code, and failure history; module-context the
  disassembly/decompiler context and baseline-test results; full-module
  those plus shim layers and PAL traits. Which evidence sections a prompt
  shows is a property of which includes that template calls, never of any
  struct's field list.
- **One shared section include per evidence engine, parameterized by
  (findings list, heading text).** Sixteen `templates/sections/*.j2`
  includes, their bodies lifted verbatim from the pre-refactor templates
  so renders stay byte-identical, called through Askama import + macro
  call with each consumer passing its own heading (`ADDITIONAL CONTEXT —
  GLOBAL STATE` in escalate, `GLOBAL STATE` in module-context); templates
  stay compile-time-checked. Twenty-five (template × section) call pairs
  today: escalate 13, module-context 7, full-module 1, rich 2, detailed 2.
  The include takes the findings list, not the bundle, so the rich and
  detailed tiers — which render from the translation request, not a
  gathered bundle — call the same type-information and control-flow
  includes directly.
- **A pre-projected (heading, body) string list was explicitly
  rejected.** It would move prompt formatting out of the templates, give
  up compile-time template checking, and make the projector seam know
  every template's identity — the exact coupling ADR-0048's seam split
  exists to prevent. The bundle, not rendered strings, crosses the seam.
- **The prompt-data twins are deleted from the prompts crate's public
  API.** The module-context and full-module builders take `(request,
  bundle)` — plus shim layers and PAL traits for full-module — and
  construct their template internally; the escalate builders pass the
  bundle through as one field. Constructors that existed to fill the twins
  with empty lists disappear; callers with no gathered context pass
  `EvidenceBundle::default()`. Translator call sites stay mechanical:
  context tiers keep gathering through the P35 projector, keep the
  bespoke fills (call-graph neighbors, neighboring context, call-graph
  context, control-flow hints, shim/PAL extraction), and hand the filled
  bundle to the builders as-is.
- **The render side stays separate from the projector seam.** The
  projector fills the bundle from persisted analysis documents and knows
  nothing of templates; the templates render the bundle and know nothing
  of documents, persistors, or scan machinery. `EvidenceBundle` is the
  whole contract between them — ADR-0048's separation extended, not
  merged.
- **Identity is verified, not assumed.** The error-handling section pair
  was diffed and found *not* byte-identical between escalate and
  module-context, and deliberately stays per-template; the shared include
  and its roster row exist only for sections that genuinely share one
  body.

## Consequences

- A new evidence engine's end-to-end prompt surface is four places, one
  per seam: its own crate with a P34 scan row (write), a P35 projection
  adapter + row (read), one section include (render), and one
  section-suite/roster row (proof). No prompt-site sweep.
- The parametrized section suite drives every registered (section ×
  consuming template) pair through populated and empty renders, and the
  include roster pins the exact (template × section) set — P35's
  projector-roster pattern moved to the render side. A forgotten or
  accidentally dropped include fails CI loudly instead of silently
  shrinking a prompt; a registering engine comes covered automatically.
- Rendered prompts are byte-identical across the restructure: the
  pre-existing renders/omits pairs pass unmodified (modulo constructor
  signatures), empty-bundle renders pin every evidence section absent
  with no stray blank lines, so the blank-line contract and LLM behavior
  provably did not change — the P35 identical-before/after acceptance
  bar, met track-wide.
- The degradation contract carries through at render time: a missing or
  corrupt scan document leaves its bundle list empty (P35's rule), the
  empty list omits the section at the include, and the prompt still
  renders — absent context degrades a prompt, never fails it.
- The bundle is now public render vocabulary. A finding list with a
  template audience joins as one include plus one roster row — the shape
  later Evidence tracks (P19–P21, P28) will use — and a bundle field
  rename touches that list's include call arguments and nothing else.
- Accepted price: three tables now name the engines — the scan registry,
  the projection rows, and the include roster — each with its own roster
  test. That duplication is the accepted cost of keeping the write, read,
  and render seams three; any future merging of tables needs its own ADR,
  as with P34/P35.
- The minimal/signature/with-tests/edge-case/failure-fix templates carry
  no evidence-body copies, were confirmed untouched, and may adopt shared
  includes later only if trivially free.
