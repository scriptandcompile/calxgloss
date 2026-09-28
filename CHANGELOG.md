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
- **Escalate retry strategy** — on verification failure, injects call graph
  neighbors, neighboring function context, data structures, and type
  information from Ghidra into the LLM prompt
- **EdgeCaseFix retry strategy** — targets boundary-value test failures with
  a dedicated prompt focused on zero/max/negative/null handling
- **Auto strategy** — cycles through `[compile_fix → test_fix → escalate →
  edge_case_fix]` on each failure until success or max attempts
- `TranslationAttempt.tokens_used` — tracks LLM token consumption per attempt
- `Translation.function_address` and `Translation.call_graph` — carry Ghidra
  context for use during escalate retries
- `is_edge_case_failure()` heuristic — detects boundary-value test failures
  using word-boundary indicators (zero, null, overflow, i32::, etc.)
- Ghidra context extraction helpers — `extract_call_graph_neighbors()`,
  `extract_neighboring_context()` (data structures and type info are stubs
  for future GhidraMCP integration)

#### `calxgloss-prompts`
- **Escalate prompt** (`escalate.j2`) — includes call graph neighbors,
  neighboring function disassembly/decompiler output, data structures,
  and type info alongside the original failure description
- **Edge case prompt** (`edge_case.j2`) — presents failing boundary-value
  tests with disassembly hints and explicit requirements for edge-case
  handling (zero checks, overflow guards, etc.)

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
- **Failure-informed prompt stubs** (`failure_fix.j2` template,
  `build_failure_informed_compile_fix_prompt()`,
  `build_failure_informed_test_fix_prompt()`,
  `build_failure_informed_escalate_prompt()`) — Phase 2, step 2.3
  scaffolding that currently falls back to standard prompts.

### Fixed

#### `calxgloss-config`
- `test_a_missing_optional_file_is_not_an_error` and `test_a_found_file_is_reported` — both tests now temporarily neutralize `HOME` and `XDG_CONFIG_HOME` so a user-global `~/.config/calxgloss/config.toml` on the developer machine cannot be picked up during test execution, breaking `loaded.is_empty()` and config-precedence assertions.

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
