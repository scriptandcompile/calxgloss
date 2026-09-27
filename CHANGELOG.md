# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Project scaffolding with 14 workspace crates
- Workspace root `Cargo.toml` with shared dependencies
- `calxgloss-types` — shared data structures (scaffolded)
- `calxgloss-types` — implemented all shared types with module organization: DLL analysis, function metadata, test cases, translation, verification, and Git automation (with `serde`/`thiserror` derive and doc comments)
- `calxgloss-types` — `ApiCategory` derives `Hash` for use as `IndexMap` key
- `calxgloss-ghidra` — GhidraMCP HTTP client
- `calxgloss-ghidra` — `GhidraClient` with session management, DLL queries (list, info, imports, exports), function queries (disassembly, decompiler, call graph, full analysis), error types, response mapping structs, and `Session` tracking
- `calxgloss-ghidra` — tracing instrumentation and comprehensive test coverage (10 tests)
- `calxgloss-llm` — local LLM client (Ollama/vLLM compatible): `LlmClient` with non-streaming and SSE streaming completions, `LlmConfig` with builder pattern, `LlmMessage` with System/User/Assistant roles, `strip_code_fences()` utility, OpenAI-compatible `chat/completions` API, serde request/response structs, `LlmError` with 6 variants, tracing instrumentation, and 13 tests
- `calxgloss-prompts` — prompt template engine shell
- `calxgloss-pal` — platform abstraction layer with full Windows API → Rust equivalent mapping table: 100+ mappings across 10 categories (Win32 Core, GDI, DirectX, Win32 GUI, Audio, COM, Win32 Networking, Win32 Registry, VB6 Runtime), `ApiMappings::lookup()` / `for_category()` API, lazy-initialized category index, 19 tests, `iter()` method for full-table iteration
- `calxgloss-analysis` — DLL classification, call graph analysis, and Windows API tagging: `Analyzer` struct with `classify_dll()`, `classify_target()`, `analyze_function()`, `tag_windows_apis()`, and `classify_dll_info()` methods; classification heuristics with lookup tables for 70+ Windows OS DLLs, 15 Microsoft SDK DLLs (→ wgpu/tiny-skia/skrifa), and 40 known third-party DLLs (→ fmod-rs/cpal/mlua/pyo3/flate2/vb6runtime etc.); `Strategy` enum (`PalMapping`, `CrateReplacement`, `ReverseEngineer`); `DllClassification` and `FunctionAnalysis` types; `AnalysisError` error type with `Ghidra` variant; disassembly scanning for dynamically-loaded APIs; 30 unit tests covering all classification paths, deduplication, and API tagging
- `calxgloss-testgen` — FFI stub and test generation shell
- `calxgloss-translator` — translation pipeline shell
- `calxgloss-verify` — compilation and test verification shell
- `calxgloss-git` — Git branch/commit automation shell
- `calxgloss-reports` — terminal report formatting shell
- `calxgloss` — meta-lib re-exporting all crates
- `calxgloss-cli` — CLI entry point shell
- `calxgloss-web` — web UI scaffold (not implemented in MVP)
- `calxgloss-prompts` — full implementation with askama template engine: `TranslateTemplate` struct for building translation prompts, embedded `templates/translate.j2` covering disassembly, decompiler output, Windows API mappings, and baseline tests; `build_translate_prompt()` convenience function; `PromptError` type; `ApiCategory` implements `Display` for template rendering
- `calxgloss-types` — all module-level doc comments converted to inner-doc-comments (`//!`) to fix clippy `empty_line_after_doc_comments` lint
- `calxgloss-llm` — suppressed dead-code warnings on scaffolded streaming-struct fields with `#[allow(dead_code)]`
