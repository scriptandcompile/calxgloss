# ADR-0050: The pipeline is only ever assembled — assembly lives in the pipeline context, the settings fold lives in the CLI, and the constructor is assembly-internal

- **Status:** Accepted
- **Date:** 2026-10-25 (P37 shipped, issues #323–#329, spec #322)
- **Deciders:** Arthur (solo project)

## Context

Issue #265 unified every `TranslationPipeline` construction *shape* — each
site called its `with_*` setters in one unconditional sequence — but left
the **construction** itself at four sites: `auto`, `translate`,
`batch_translate`, and the web server's patch-retry. Four sites re-deciding
the same questions is four answers that drift, and they had drifted: only 3
of the 4 built an LLM client — the web path read `OPENROUTER_API_KEY` from
the environment and re-implemented the CLI's `resolve_llm_client` fallback
chain inline, a third copy; only 3 wired the test generator, the git
accepted-attempt port, user-supplied `api_mappings`, and the retry ladder
(the web pipeline held `ApiMappings::default()`, silently dropping
mappings, and its analysis engine load ignored the configured Kuna budgets
— two loads honored the budgets and one ignored them); `RetryConfig` was
assembled by hand at 3 sites plus one `RetryConfig::default()`, and the
review UI's retry settings reached only one of them. The `auto` build
sequence alone was fifteen setter calls, thirteen wrapped in `if let`
conditions.

The drift had already done real damage: `serve` passed `actions: None` to
its router, so the review UI's **Retry patch** button ran through a stub
handler that made up a "Patch requested" response with a plausible branch
name — the patch-retry machinery existed, was tested, and was never
constructed in production. A user who set an option in `calxgloss.toml`
could not predict which machinery would honor it, and a fix to one
construction fixed none of the others (spec #322, architecture review
2026-10-24, candidate 4).

The shape decisions worth fixing were: where assembly lives, who converts
the settings record into a pipeline description, what happens to the public
constructor, and how many adapters over the seam make it real rather than
hypothetical.

## Decision

One description, one settings fold, one assembly — enforced by the
compiler, not by review comments.

- **Assembly lives in the pipeline context.**
  `crates/pipeline/calxgloss-translator/src/assembly.rs` owns the whole
  build-up: `PipelineSpec` — a pass described as data (LLM selection,
  workspace, patch mode, target binary, Kuna budget, API mappings, retry
  policy, call-graph and cache flags, injected events/stop/control/scope/
  override/accepted-attempt handles) — plus `assemble(&spec, &engine) ->
  AssembledPass { pipeline, verifier, retry }` and `assemble_patch(&spec)`
  for a pass that loads its own analysis engine. The module is public on the
  crate path, but the seam types are *not* re-exported at the crate root:
  the root surface stays unchanged, and new hand-rolled constructions cannot
  reach through it.
- **The settings fold lives in the CLI.** The CLI's settings module holds
  the one conversion, `settings::pipeline_spec(&Settings) -> PipelineSpec`.
  It copies the resolved LLM endpoint/model/key pair — with context window,
  temperature, and timeout — verbatim into the LLM description; it passes
  the workspace and the Kuna budgets through the existing settings fold;
  and it passes retry attempts and strategy through the shared retry
  ladder. Unknown strategy names are refused by the fold itself, and unset
  values are left to assembly's default. The settings crate stays a leaf
  that never names pipeline types, and the orphan rule forbids
  `From<Settings> for PipelineSpec` across crates anyway; a fold living
  inside the settings crate was explicitly rejected. Each command adds its
  run options on top of the description (`command_pass_spec`: resolved
  workspace, call-graph flags, cache-refresh escape hatch, target binary),
  and each patch request adds its run-scoped fields on the *same*
  description — never a second construction.
- **The pipeline constructor is assembly-internal.**
  `TranslationPipeline::new` and the sixteen `with_*` setters the assembly
  actually calls became `pub(crate)`: hand-building a pipeline outside the
  pipeline context does not compile, and keeping the constructor public
  under review-comment convention was explicitly rejected. Three builder
  setters that no production code called and that no test tied to real
  behavior are deleted with their fields — `with_exports`,
  `with_fault_logger`, `with_call_graph`. The compiler cannot enforce this
  fact *inside* the crate, so a source-check test does:
  `tests/source_pins.rs` walks every `crates/*/src` tree, cuts each file at
  its first `#[cfg(test)]` line, ignores comments, and asserts that the
  literal constructor call appears in exactly one production module —
  `assembly.rs`, once. A fourth builder sequence cannot reappear
  unnoticed.
- **Two adapters make the seam real: the CLI's `auto` and the web's
  `serve`.** `handle_auto` runs the settings fold once on the resolved
  settings, adds the run's live control handles, clones the description per
  binary with only the binary identity and the git accepted-attempt port
  added, and calls `assemble` once per pass. `serve` and `live` fold
  through the same `pipeline_spec`, into a settings-backed actions backend
  wired into both routers. A patch request adds its run-scoped fields (repo
  as workspace, patch mode, the unit's binary under the target directory),
  and the handler calls `assemble_patch` before anything is created — LLM
  checked first, so a server started without LLM settings meets the
  `MissingLlm` refusal at request time with no branch record or task left
  behind. The canned stub response is deleted; a router without the backend
  honestly refuses. `translate` and `batch_translate` use the same seam as
  its third and fourth adapters — every production call site that builds a
  translation pass now goes over the seam.
- **LLM ownership is the adapter's choice; construction stays the seam's.**
  The description includes either the caller's prebuilt client (the CLI's
  client resolution chain keeps its fallback chain and `ConfigError`
  semantics exactly) or an endpoint description — endpoint, model, API key,
  context window, temperature, timeout — whose client assembly builds. The
  web path now honors settings where it once read environment variables.
  Assembly returns the crate's existing error type: no LLM in the
  description is `TranslatorError::MissingLlm`, and an unbuildable
  description converts `LlmError` into the existing `TranslatorError::Llm`
  — no new error enum.
- **Patch-mode analysis engine loads honor the configured budgets.**
  `assemble_patch` loads the pass's own `KunaSource` under the spec's Kuna
  budget — the budget-blind web load went away with the duplicated builder
  sequence. Analysis engine loading itself stays a facade concern (P39's
  territory): entry points keep loading their analysis engine and passing
  it in, and per-binary budget selection stays with the CLI's load.
- **The description holds real options only.** Every `PipelineSpec` field
  corresponds to a behavior that exists in the code; the epic text named
  spec fields with no implementation counterpart anywhere — a target
  dialect, an LLM-call-budget cap, toolchain paths, a testgen toggle, a
  `no_tests` flag, git policy and author — and those are deliberately
  absent. A spec field that only passed through assembly unused would be a
  hidden test of a behavior that does not exist; each joins the description
  on the ticket that builds the behavior.

## Consequences

- The user-facing capability is one sentence with a proof: configured
  settings now reach every translation pass — LLM endpoint, model, key,
  window, temperature, timeout, workspace, Kuna budgets, retry policy —
  including the review UI's patch retry, which was never actually running
  until now. "Is this option wired?" has exactly one answer: `PipelineSpec`
  is the one record of what settings the pipeline honors.
- The web server's shape: `serve`/`live` start even with no LLM configured
  — the review surface stays served — and a patch request meets the
  missing-LLM assembly error at request time, creating no branch record and
  leaving no task behind. An unknown retry-strategy name stops the command
  or the server at startup instead of being silently defaulted.
- Contributor contract: a new entry point that translates describes one
  pass and calls assembly once — the full option set comes free with it; an
  option edit is one edit site, not four builder sequences each remembering
  it differently; command bodies read as run logic (the LLM-config
  resolution chain, the hand-built verifier, the retry ladder, and the
  setter sequence all left `auto`, `translate`, and `batch_translate`).
  Hand-building a pipeline outside the pipeline context is a compile error,
  and the source-check test catches a second in-crate builder sequence; the
  crate's `no_run` doctests build passes through the seam, doubling as the
  contract's usage documentation.
- Accepted costs, recorded honestly: the assembly module is crate-path
  public, so the contract is enforced at the constructor boundary plus the
  source-check test, not by the visibility of its types; the source-check
  test lives in the seam's own test suite (`tests/source_pins.rs`) because
  the `workspace-hygiene` suite the spec predicted for it does not exist in
  this repo; the mode/dialect builder re-exports the spec expected to
  retire were already gone from the context root.
- Carried forward: P38 receives a complete `AssembledPass` for the
  retry-loop deepening; the line this record carries forward — "P39 folds
  engine loading" — lands as one shared place that loads the analysis
  engine; the shim pipeline (`ShimRunConfig`) may grow a spec
  entry on its own ticket; on-disk paths and formats are untouched
  (ADR-0043's cache-key discipline stands), and ADR-0004's in-process
  control handles pass through the description's injected fields unchanged
  (Kuna alone per ADR-0041).
