# Coding Standards

How code in this repo should be written. The Standards axis of the
`code-review` skill checks diffs against these rules. Rules already enforced
by tooling (`cargo fmt`, clippy, `cargo check`) are not repeated here.

## Workspace & crates

- One crate per domain concern. Name it `calxgloss-<domain>` (kebab-case) and
  put it in its context directory: `crates/<context>/calxgloss-<domain>`. The
  contexts are the five groups of `GLOSSARY-MAP.md` (pipeline, evidence,
  integrations, interface, shared). The meta-lib is at `crates/calxgloss`.
  The `[workspace] members` list in the root `Cargo.toml` contains the
  meta-lib plus one glob per context.
- Package metadata is inherited: `version`, `edition`, `license`, `repository`
  use `workspace = true`. Every crate declares its own `description` — it is
  intentionally not a workspace field.
- Shared dependency versions live in `[workspace.dependencies]` in the root
  `Cargo.toml`; member crates reference them with `{ workspace = true }`.
  Pin a version directly in a member crate only for dev-only deps (e.g.
  `tempfile`).
- Any lint allowance (`[lints.cargo]` / `#[allow(...)]`) must have a comment
  explaining why it is needed.

## Crate anatomy

Every library crate follows the same shape:

- `lib.rs` starts with crate-level `//!` docs: a short description of what the
  crate does, then an `# Architecture` section that lists every module and
  gives one line for each. Keep this section current when modules are added or
  renamed.
- Conventional module names: `types.rs` (core data model), `engine.rs` (scan /
  orchestration), `persist.rs` (JSON persistence), `error.rs` (error type).
  Domain detectors/analyzers get their own module.
- Modules are `pub mod` unless purely internal, in which case
  `pub(crate) mod`.
- A production module that outgrows one file splits into private submodules
  under a directory named for it (`pipeline.rs` plus `pipeline/<seam>.rs`),
  one submodule per seam. The struct and its constructor stay in the parent;
  method `impl` blocks and free items move to the seam files, which pull the
  parent in with `use super::*;`. Moved private items widen to
  `pub(super)`, and the parent re-globs every seam (`use <seam>::*;`) so the
  parent's own methods, the seams, and the test submodule all resolve names
  through one scope.
- `lib.rs` re-exports the crate's error type and `Result` alias:
  `pub use error::{Result, XxxError};`

## Error handling

- Each crate defines its own error enum in `error.rs`, based on `thiserror`
  (`#[derive(Debug, Error)]`). Name it `<Domain>Error` (e.g. `TypeInferError`).
  Give it one variant per failure mode, and give each variant a `///` doc
  comment and an `#[error("...")]` message that says what failed.
- `error.rs` also defines the crate-wide alias
  `pub type Result<T> = std::result::Result<T, XxxError>;`
- Pass-through errors use `#[from]`. Map errors between crates (e.g.
  `calxgloss_types::persist::PersistError` → `TypeInferError`) with a
  hand-written `From` impl, and give it a doc comment that explains how each
  variant is converted.
- Use `anyhow` only at binary entry points (`fn main() -> anyhow::Result<()>`
  in `calxgloss-cli`). Library crates never expose `anyhow` in their public
  API.
- No `unwrap()` / `expect()` in library code. They are allowed only in tests,
  doc examples, and test helpers — and in tests they should have a message
  (`expect("log should exist")`).

## Documentation style

- Every file starts with a `//!` module doc saying what the module is for.
- Every public item — and every enum variant — gets a `///` doc comment.
- Docs explain *why* and the behavior contract (ordering guarantees, tie
  rules, what gets persisted), not just restate the signature.
- Write in plain English: short, direct sentences describing what the code
  does and when, the way you would explain it to a colleague new to the
  project. No clever phrasing, no stacked technical adjectives.
- When a doc names a domain concept, use the exact term from that context's
  glossary (`GLOSSARY-MAP.md` → `crates/<context>/GLOSSARY.md`), and use the
  same word consistently across doc comments, log messages, and error text —
  never a synonym or invented variant. Follow the map's word-ownership and
  banned-word rules (bare "engine" is banned: say *evidence engine* or
  *analysis engine*). Plain English is preferred everywhere a glossary term
  is not actually needed.

## API & construction style

- Constructors: `new()` takes the required inputs. Optional configuration is
  added through chainable `with_*()` methods (`with_config`, `with_cache_dir`,
  `with_patterns`).
- Domain concepts get their own small types (enums, newtypes), not strings
  or integers used in their place. Closed sets of cases are enums.
- Conversions between layers are `From`/`Into` impls, not ad-hoc conversion
  functions at call sites.
- Prefer deterministic, diff-friendly output ordering: results that get
  persisted or compared across runs should preserve scan/input order.

## Persistence

- A `<Domain>Persistor` struct in `persist.rs` writes JSON artifacts. It uses
  the shared JSON store in `calxgloss-types::persist`
  (`JsonStore` / `PersistError`), not raw `serde_json` + `fs` calls.
- Artifacts live under `<workspace_root>/re/analysis/<domain>/`
  (e.g. `re/analysis/typeinfer/`). The persistor takes the workspace root in
  `new()` and allows overriding the directory via `with_cache_dir()` for tests.
- Persisted types derive `serde::Serialize`/`Deserialize`; persisted records
  include scan metadata (`ScanMetadata`) so results are traceable.

## Logging & output

- Library crates log with `tracing` macros (`debug!`, `info!`, `warn!`,
  `error!`). Annotate pipeline entry points with `#[instrument(...)]` and
  useful fields. No `println!` in library code.
- Only `calxgloss-cli` and `calxgloss-reports` may write user-facing console
  output.

## Testing

- Unit tests live in `#[cfg(test)] mod tests` at the bottom of the file they
  test. Once a test module outgrows the file it tests, move its body to a
  sibling submodule: `#[cfg(test)] mod tests;` in the file, the tests in
  `src/<file-stem>/tests.rs` (the crate root's go in `src/tests.rs`).
- Cross-module / end-to-end flows go in `tests/integration_tests.rs`. A test
  binary that outgrows one file keeps its fixture helpers in its root and
  splits its scenarios into modules under a directory named for it
  (`tests/e2e.rs` plus `tests/e2e/<scenario>.rs`, wired with `#[path]`),
  which reach the helpers through `use super::*;`.
- Tests that need a live external service (an LLM endpoint) are kept in
  separate files (e.g. `tests/live.rs`) so they can be run independently of
  the offline suite. The analysis engine needs no external service: Kuna
  loads in-process, so analysis engine tests run offline (issue #214).
- Test fixtures are built by named helpers, not inline literals:
  `sample_*`, `make_*`, `*_fixture`, `temp_workspace()` (a `tempfile::TempDir`
  for anything touching the filesystem).
- New detectors and evidence engines get unit tests in the same commit, plus
  an integration test that runs them over a canned program.

## Changelog

`CHANGELOG.md` records features and bug fixes, not the development log:

- Describe what the change does for a user of the project — the capability
  added or the behavior repaired — not how it was implemented. Do not
  enumerate the structs, functions, templates, or fields a feature happened
  to introduce. Mention an identifier only when it is itself user-facing (a
  CLI command or flag, a config key, a persisted file path, a public concept
  like a context tier).
- Never mention the project's own test suite: no test counts, no "N unit
  tests / integration tests / live tests" tails, no entries for test-only
  changes. Testing *features* (baseline tests, the WithTests tier, test
  generation) are product behavior and do get entries.
- One bullet per feature, not per commit: group the pieces of one feature
  into a single entry, and merge repeated boilerplate across features (e.g.
  one entry covering all the evidence pre-analysis scans).
- Do not record chores: clippy fixes, formatting passes, and dependency
  tweaks get no entry. Module splits get at most one summary line under
  `Refactored`.
- Bug fixes state the symptom and the fix, and keep the issue reference
  (`Fixes #54.`).

## Process

- Commit messages are lowercase imperative, scoped to the change:
  `add <thing> to <crate>`, `fix <thing> in <crate>`,
  `record <feature> in changelog and checklist`. One commit per tracer-bullet
  step.
- Every user-visible change gets a `CHANGELOG.md` entry (Keep a Changelog
  format, under `[Unreleased] → Added/Changed/Fixed`, written to the
  Changelog standard above) **and** a checkbox tick in `docs/roadmap.md`'s
  checklist, in the same commit.
- New crates get a scaffold commit (manifest + lib.rs + error.rs) before any
  feature commit.
- After big code changes, refresh the graft graph (`graft build`).
