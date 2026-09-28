# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [Unreleased]

### Added

#### `calxgloss-config`
- `LlmSection.strategy` — retry strategy configuration (compile_fix, test_fix,
  escalate, edge_case_fix, auto) via CLI flag, environment variable
  (`CALXGLOSS_LLM_STRATEGY`), or config file

#### `calxgloss-translator`
- **Failure-informed retry prompts** — all retry
  strategies (`CompileFix`, `TestFix`, `Escalate`, `EdgeCaseFix`) now
  inject a "PREVIOUS ATTEMPT HISTORY" section into LLM prompts when
  prior attempts have failed. Includes
  `build_failure_informed_compile_fix_prompt()`,
  `build_failure_informed_test_fix_prompt()`,
  `build_failure_informed_escalate_prompt()`, and
  `build_failure_informed_edge_case_fix_prompt()`.

#### `calxgloss-cli`
- `--strategy` flag — select the initial retry strategy or `auto` for
  automatic cycling through all strategies
- `retry_strategy` displayed in `config` command output

### Added

#### `calxgloss-types`
- **Complexity-based prompt selection** (`calxgloss-types::complexity`) —
  `FunctionComplexity` enum (Minimal / Standard / Rich / Detailed) and
  `detect_complexity()` function that classifies functions by instruction
  count, branch density, call depth, and API-category diversity.
  `PromptVariant` struct for strategy selection and `FailureHint` for
  recording previous attempt failures.
- `ApiCategoryMapping` and `ApiMappingItem` — types for grouping Windows
  API mappings by category in rich and detailed translation prompts.

#### `calxgloss-prompts`
- **Complexity-aware prompt builder** (`build_complexity_prompt`) — selects
  the appropriate template based on function complexity: `MinimalTemplate`
  (≤30 instructions, disassembly + decompiler only), `TranslateTemplate` /
  `Standard` (31–100, adds API mappings + tests), `RichTemplate` (101–300,
  adds API category context + advanced guidelines), `DetailedTemplate`
  (>300, adds call graph + neighbors + data structures + type info).
- **New template files** — `minimal_translate.j2`, `rich_translate.j2`,
  `detailed_translate.j2` with complexity-appropriate context and guidance.
- `ComplexityPromptData` — aggregates all analysis data for use with the
  complexity-based prompt builder.

#### `calxgloss-analysis`
- `Analyzer::detect_complexity()` — detects function complexity from
  disassembly and tagged API calls.
- `Analyzer::build_prompt_variant()` — builds a `PromptVariant` with
  complexity classification and API awareness.

#### `calxgloss-translator`
- `TranslationPipeline::translate()` now uses complexity-based prompt
  selection, routing simple functions to minimal prompts and complex
  functions to rich or detailed prompts with extra Ghidra context.

#### `calxgloss-prompts`
- **Failure-informed retry prompts** (Phase 2, step 2.3) — `FixTemplate`,
  `EscalateTemplate`, and `EdgeCaseTemplate` all now accept a
  `failure_history: Vec<FailureHint>` field. When non-empty, each template
  renders a "PREVIOUS ATTEMPT HISTORY" section so the LLM can learn from
  specific past mistakes. Dedicated `with_history()` constructors and
  updated `build_escalate_prompt()` / `build_edge_case_prompt()` helpers.
  Embedded templates (`failure_fix.j2`, `escalate.j2`, `edge_case.j2`)
  updated to render the history section.

### Added

#### `calxgloss-types`
- **Prompt variant benchmarking types** (`calxgloss-types::benchmark`) —
  `PromptStrategyEntry` (single attempt outcome), `PromptStrategyLog`
  (collectible entries), `PromptStrategyStats` with `CategoryStats` and
  `StrategyStats` (aggregate pass/fail rates), and
  `current_timestamp()` helper. Full serde serialization for disk
  persistence.

#### `calxgloss-analysis`
- **Prompt strategy logger** (`PromptStrategyLogger`) — persists benchmark
  entries to `<workspace>/re/analysis/prompt_strategy_log.json` with
  `record()`, `load()`, `compute_stats()`, and `log_path()` methods.
  Auto-creates directory structure; handles corrupted-file recovery by
  starting fresh.

#### `calxgloss-translator`
- **Benchmark logging integration** — `try_translate_with_retry()` now
  accepts an optional workspace path; `TranslationPipeline` gains
  `with_workspace()` builder method. Every retry attempt is recorded
  (DLL name, auto-classified category, strategy label, success/fail,
  attempt number, timestamp). Skipped silently when no workspace is set.

### Fixed

#### `calxgloss-config`
- `test_a_missing_optional_file_is_not_an_error` and `test_a_found_file_is_reported` — both tests now temporarily neutralize `HOME` and `XDG_CONFIG_HOME` so a user-global `~/.config/calxgloss/config.toml` on the developer machine cannot be picked up during test execution, breaking `loaded.is_empty()` and config-precedence assertions.

### Phase 3 — Terminal Review Dashboard

#### `calxgloss-types`
- **Dashboard data model** (`calxgloss-types::dashboard`) — new module with all
  review dashboard types, replacing the duplicate scaffolding in `calxgloss-web`:
  `WorkUnitKind` (7 unit types), `ReviewStatus` (7 statuses), `UnitOfWork`
  (full metadata struct with timestamps, test counts, confidence, dependencies,
  known gaps), `DependencyNode` / `DependencyEdge` / `DependencyGraph` (DAG with
  `roots()`, `dependents()`, `dependencies()` traversal), `StatusCounts` (aggregated
  counts with `total()`), `ReviewDashboard` (assembles units into a viewable
  dashboard with dependency-sorted queue, recent activity, and status counts), and
  `ReviewAction` / `ReviewActionKind` (human review actions). All types derive
  `serde::Serialize` and `serde::Deserialize`.
- `chrono` dependency — added to `calxgloss-types` for `DateTime<Utc>` fields
  in `UnitOfWork` timestamps.

#### `calxgloss-web`
- **Re-exported from `calxgloss-types`** — the domain data types
  (`UnitOfWork`, `ReviewDashboard`, `DependencyGraph`, `ReviewStatus`, etc.)
  are no longer defined locally; this crate re-exports them from
  `calxgloss-types` so downstream consumers get a single source of truth.
  The axum server scaffold (behind `server` feature) and tests are preserved.

#### `calxgloss-reports`
- **Terminal rendering** (`render_dashboard`) — flat text report with horizontal
  dividers (`═` / `─`), no vertical borders or corners. Color-coded status
  summary, dependency-sorted review queue table, blocked units section, and
  recent activity. Auto-refresh follow mode via `render_dashboard_follow`.

#### `calxgloss-cli`
- **`dashboard` subcommand** — reads all `re/*` git branches, patch records from
  `re/patches/`, and baseline files from `re/baseline/` to build and render a
  structured review dashboard. Supports `--follow` (continuous watch) and
  `--interval <secs>` (refresh cadence, default 2).
- **`dashboard view <target>`** — per-unit quick-view subcommand showing
  justification, diff summary, test results, and attempt history for a
  single translation unit. Target format: `<dll>/<function>` or
  `<dll>/<function>/vN` (e.g., `game_logic/DrawPrimitive/v3`).

#### `calxgloss-reports`
- **`render_unit_view()`** — renders a detailed single-unit view with
  sections: unit info (kind, status, confidence, dependencies), branch
  status (merged/unmerged), DLL classification, diff summary (files
  changed, insertions, deletions), baseline and verification test
  results, and attempt history loaded from patch records.
- `ViewTarget` — parses `dll/function` or `dll/function/vN` target strings
- `UnitViewData` — collects all data for a unit view (unit info, branch
  name, merge status, diff summary, attempt history, baseline tests,
  DLL classification)
- **Dependency diff summary** — computes `git diff` stats between branch
  and main (files changed, insertions, deletions)
- Clippy `filter_next` — replaced `.filter(...).into_iter()...next()`
  with `.find(...)` on branch list iteration
- Clippy `unnecessary_closure` — replaced `.or_else(|| { Some(...) })`
  with `.or(Some(...))` for static default values
- **Table column alignment** — switched from format-width specifiers (which
  counted invisible ANSI escape codes as characters) to hardcoded column
  widths per element, so colored headers no longer shift data columns.

#### `calxgloss-git`
- **`is_branch_merged_into_main()`** — checks if a branch is an ancestor
  of `main` via `graph_ahead_behind()`

### Changed

#### all crates
- Removed references to implementation phases and steps from
  doc-comments and inline comments. The planning document
  (`step_by_step.md`) remains as the planning reference; source
  comments now describe what the code does, not which phase it came
  from. Affected crates: `calxgloss-analysis`, `calxgloss-pal`,
  `calxgloss-prompts`, `calxgloss-reports`, `calxgloss-translator`,
  `calxgloss-types`.

## [0.1.0] — 2025-09-27

### Added

#### `calxgloss-translator`
- **Batch translation** (`batch-translate` CLI subcommand) — translate multiple functions from a single DLL in one invocation; enumerates all exported functions via `--all-functions` or accepts a comma-separated list via `--functions`; per-function pass/fail reporting with a summary showing success/failure counts and pass rate; `--skip-git` for dry-run mode; automatically commits and merges each successful function to a git branch
- `batch_translate()` method on `TranslationPipeline` for batch-iterating the full pipeline + retry loop across many functions; `BatchTranslationResult` and `FunctionResult` types for aggregated and per-function outcomes
- Full translation pipeline: `TranslationPipeline` struct with end-to-end GhidraMCP → analysis → test generation → LLM → Rust code workflow, `Translator` struct for direct translation from pre-collected data, `Translation` result type, `TranslatorError` error type with 6 variants, parameter estimation from decompiler output, and 9 unit tests + 4 doc-tests
- **Retry logic** — `RetryConfig`, `RetryStrategy` (CompileFix / TestFix / Escalate), `TranslationAttempt`, `RetryResult`; `try_translate_with_retry()` with strategy escalation on failure; `FixTemplate` with embedded `fix.j2` for compile-fix and test-fix prompts; 7 unit tests

#### `calxgloss-ghidra`
- GhidraMCP HTTP client with session management, DLL queries (list, info, imports, exports), function queries (disassembly, decompiler, call graph, full analysis), error types, response mapping structs, and `Session` tracking
- Tracing instrumentation and comprehensive test coverage (10 tests)

#### `calxgloss-llm`
- Local LLM client (Ollama/vLLM compatible): `LlmClient` with non-streaming and SSE streaming completions, `LlmConfig` with builder pattern, `LlmMessage` with System/User/Assistant roles, `strip_code_fences()` utility, OpenAI-compatible `chat/completions` API, serde request/response structs, `LlmError` with 6 variants, tracing instrumentation, and 13 tests

#### `calxgloss-prompts`
- Full implementation with askama template engine: `TranslateTemplate` struct for building translation prompts, embedded `templates/translate.j2` covering disassembly, decompiler output, Windows API mappings, and baseline tests; `build_translate_prompt()` convenience function; `FixTemplate` for compile-fix and test-fix prompts; `PromptError` type; `ApiCategory` implements `Display` for template rendering

#### `calxgloss-pal`
- Platform abstraction layer with full Windows API → Rust equivalent mapping table: 100+ mappings across 10 categories (Win32 Core, GDI, DirectX, Win32 GUI, Audio, COM, Win32 Networking, Win32 Registry, VB6 Runtime), `ApiMappings::lookup()` / `for_category()` API, lazy-initialized category index, 19 tests, `iter()` method for full-table iteration

#### `calxgloss-analysis`
- DLL classification, call graph analysis, and Windows API tagging: `Analyzer` struct with `classify_dll()`, `classify_target()`, `analyze_function()`, `tag_windows_apis()`, and `classify_dll_info()` methods; classification heuristics with lookup tables for 70+ Windows OS DLLs, 15 Microsoft SDK DLLs (→ wgpu/tiny-skia/skrifa), and 40 known third-party DLLs (→ fmod-rs/cpal/mlua/pyo3/flate2/vb6runtime etc.); `Strategy` enum (`PalMapping`, `CrateReplacement`, `ReverseEngineer`); `DllClassification` and `FunctionAnalysis` types; `AnalysisError` error type with `Ghidra` variant; disassembly scanning for dynamically-loaded APIs; 30 unit tests covering all classification paths, deduplication, and API tagging

#### `calxgloss-testgen`
- FFI stub generation with comprehensive Windows type parsing (60+ type mappings, calling conventions, pointer handling), `FfiStubBuilder` for manual stub construction, test input generation with signature-based and disassembly-driven edge case detection (`cmp eax, 0`, `test ecx, 256` patterns), `BaselineRunner` for temporary Cargo project compilation and execution, JSON baseline save/load to `re/baseline/{dll}/{function}/baseline.json`, full module-level documentation and 18 unit tests

#### `calxgloss-verify`
- Full `Verifier` implementation: `Verifier::new()` creates sandboxed work directory, `Verifier::compile()` scaffolds temporary Cargo project and runs `cargo check`, `Verifier::verify()` performs full compilation + behavioral verification against baseline tests, `CompileResult` with error/warning capture, test harness generator with input pattern matching for array/number/null/object inputs, JSON baseline save/load, `parse_cargo_output()` and `parse_test_results()` helpers, `Stubs` module with `GraphicsDeviceStub`, `AudioDeviceStub`, `FileSystemStub`, `WindowManagerStub`, `ThreadStub` and common types (`Color`, `Font`, `Sample`, `Texture`, `RenderTarget`, etc.), 19 unit tests

#### `calxgloss-git`
- Git automation for translation workflow: `GitManager` with `init_repo`, `open`, `create_branch`, `commit`, `merge_to_main`, `list_branches`, `delete_branch`, `revert_commit`, `current_branch`, `current_commit`, `list_translation_branches`, `working_dir_status`, and `store_failure`; branch naming `re/{dll}/{function}v{N}`; fast-forward and 3-way merge strategies; patch record JSON files for failed translations; 17 unit tests

#### `calxgloss-reports`
- Terminal report formatting: colored ANSI output with `print_translation_summary`, `print_verification_results`, `print_git_status`, `print_success`, `print_failure`, `prompt_acceptance`, and `print_classification_report` functions; box-drawing characters for success/failure headers; pass rate color-coding (green/yellow/red); DLL classification report with strategy color-coding and summary counts
- `print_batch_summary()` for colored terminal output of batch translation results with per-function checkmarks/crosses and an overall pass-rate summary

#### `calxgloss-web`
- Web UI data models: `UnitOfWork`, `WorkUnitKind`, `ReviewStatus`, `DependencyGraph`, `ReviewDashboard`, `ReviewAction`; axum API router scaffold behind `server` feature flag, leptos component placeholders behind `leptos` feature flag; dependency-sorted review queue with status counts; 7 unit tests

#### `calxgloss` (meta-lib)
- Meta-lib re-exporting all workspace crates: `calxgloss-types`, `calxgloss-ghidra`, `calxgloss-llm`, `calxgloss-prompts`, `calxgloss-pal`, `calxgloss-analysis`, `calxgloss-testgen`, `calxgloss-translator`, `calxgloss-verify`, `calxgloss-git`, and `calxgloss-reports`

#### `calxgloss-config`
- Configuration crate with multi-source config loading (file, env, flag precedence), section validation, typed settings, and searched-path diagnostics

#### `calxgloss-types`
- Shared data structures with module organization: DLL analysis, function metadata, test cases, translation, verification, and Git automation (with `serde`/`thiserror` derive and doc comments)
- `ApiCategory` derives `Hash` for use as `IndexMap` key

#### `calxgloss-cli`
- Full CLI binary implementation: `clap`-based argument parsing with `classify`, `translate`, and `verify` subcommands; `handle_classify` wires GhidraMCP + `Analyzer` → classification report; `handle_translate` implements the full translation pipeline (Ghidra → analysis → test generation → LLM prompt → code → write → verify → git branch/commit/merge → report) with configurable retries, LLM config (URL/model/key/temperature/max-tokens), output directory, and skip-git flag; `handle_verify` loads existing Rust source + baseline JSON → runs `Verifier` → colored pass/fail output; `tracing-subscriber` logging with `RUST_LOG` support and text/json/pretty format options; ANSI-colored terminal formatting with box-drawing headers and pass-rate color-coding

#### Infrastructure
- Project scaffolding with 14 workspace crates
- Workspace root `Cargo.toml` with shared dependencies
