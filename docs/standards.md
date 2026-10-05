# Coding Standards

How code in this repo should be written. The `code-review` skill's Standards
axis checks diffs against these rules; where a rule is already enforced by
tooling (`cargo fmt`, clippy, `cargo check`), it is not repeated here.

## Workspace & crates

- One crate per domain concern, named `calxgloss-<domain>` (kebab-case), living
  under its context directory: `crates/<context>/calxgloss-<domain>`, where the
  contexts are the five groups of `GLOSSARY-MAP.md` (pipeline, evidence,
  integrations, interface, shared). The meta-lib sits at `crates/calxgloss`.
  `[workspace] members` in the root `Cargo.toml` lists the meta-lib plus one
  glob per context.
- Package metadata is inherited: `version`, `edition`, `license`, `repository`
  use `workspace = true`. Every crate declares its own `description` — it is
  intentionally not a workspace field.
- Shared dependency versions live in `[workspace.dependencies]` in the root
  `Cargo.toml`; member crates reference them with `{ workspace = true }`.
  Pin a version directly in a member crate only for dev-only deps (e.g.
  `tempfile`).
- Any lint allowance (`[lints.cargo]` / `#[allow(...)]`) must carry a comment
  explaining why it is needed.

## Crate anatomy

Every library crate follows the same shape:

- `lib.rs` opens with crate-level `//!` docs: a short description of what the
  crate does, then an `# Architecture` section listing every module and one
  line on each. Keep this section current when modules are added or renamed.
- Conventional module names: `types.rs` (core data model), `engine.rs` (scan /
  orchestration), `persist.rs` (JSON persistence), `error.rs` (error type).
  Domain detectors/analyzers get their own module.
- Modules are `pub mod` unless purely internal, in which case
  `pub(crate) mod`.
- `lib.rs` re-exports the crate's error type and `Result` alias:
  `pub use error::{Result, XxxError};`

## Error handling

- Each crate defines its own error enum in `error.rs`: `thiserror`-based
  (`#[derive(Debug, Error)]`), named `<Domain>Error` (e.g. `TypeInferError`),
  one variant per failure mode, each variant with a `///` doc comment and an
  `#[error("...")]` message that names what failed.
- `error.rs` also defines the crate-wide alias
  `pub type Result<T> = std::result::Result<T, XxxError>;`
- Pass-through errors use `#[from]`. Cross-crate error mapping (e.g.
  `calxgloss_types::persist::PersistError` → `TypeInferError`) is a hand-written
  `From` impl with a doc comment explaining how each variant folds.
- `anyhow` belongs only at binary entry points (`fn main() -> anyhow::Result<()>`
  in `calxgloss-cli`). Library crates never leak `anyhow` in their public API.
- No `unwrap()` / `expect()` in library code. They are allowed only in tests,
  doc examples, and test helpers — and in tests they should carry a message
  (`expect("log should exist")`).

## Documentation style

- Every file starts with a `//!` module doc saying what the module is for.
- Every public item — and every enum variant — gets a `///` doc comment.
- Docs explain *why* and the behavior contract (ordering guarantees, tie
  rules, what gets persisted), not just restate the signature. Prose is plain
  and specific; jargon from the domain glossary is fair game.

## API & construction style

- Constructors: `new()` takes the required inputs; optional configuration is
  added through chainable `with_*()` methods (`with_config`, `with_cache_dir`,
  `with_patterns`).
- Domain concepts get their own small types (enums, newtypes) rather than
  strings or integers standing in for them. Closed sets of cases are enums.
- Conversions between layers are `From`/`Into` impls, not ad-hoc conversion
  functions at call sites.
- Prefer deterministic, diff-friendly output ordering: results that get
  persisted or compared across runs should preserve scan/input order.

## Persistence

- JSON artifacts are written by a `<Domain>Persistor` struct in `persist.rs`,
  built on the shared JSON store in `calxgloss-types::persist`
  (`JsonStore` / `PersistError`), not raw `serde_json` + `fs` calls.
- Artifacts live under `<workspace_root>/re/analysis/<domain>/`
  (e.g. `re/analysis/typeinfer/`). The persistor takes the workspace root in
  `new()` and allows overriding the directory via `with_cache_dir()` for tests.
- Persisted types derive `serde::Serialize`/`Deserialize`; persisted records
  include scan metadata (`ScanMetadata`) so results are traceable.

## Logging & output

- Library crates log with `tracing` macros (`debug!`, `info!`, `warn!`,
  `error!`); pipeline entry points carry `#[instrument(...)]` with useful
  fields. No `println!` in library code.
- User-facing console output belongs to `calxgloss-cli` and
  `calxgloss-reports` only.

## Testing

- Unit tests live in `#[cfg(test)] mod tests` at the bottom of the file they
  test. Cross-module / end-to-end flows go in `tests/integration_tests.rs`.
- Tests that need a live external service (GhidraMCP, an LLM endpoint) are
  kept in separate files (e.g. `tests/live.rs`) so they can be run
  independently of the offline suite.
- Test fixtures are built by named helpers, not inline literals:
  `sample_*`, `make_*`, `*_fixture`, `temp_workspace()` (a `tempfile::TempDir`
  for anything touching the filesystem).
- New detectors/engines get unit tests in the same commit and an integration
  test that runs them over a canned program.

## Process

- Commit messages are lowercase imperative, scoped to the change:
  `add <thing> to <crate>`, `fix <thing> in <crate>`,
  `record <feature> in changelog and checklist`. One commit per tracer-bullet
  step.
- Every user-visible change gets a `CHANGELOG.md` entry (Keep a Changelog
  format, under `[Unreleased] → Added/Changed/Fixed`) **and** a checkbox tick
  in `docs/roadmap.md`'s checklist, in the same commit.
- New crates get a scaffold commit (manifest + lib.rs + error.rs) before
  feature commits land on top.
- After big code changes, refresh the graft graph (`graft build`).
