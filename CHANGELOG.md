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
- `calxgloss-ghidra` — GhidraMCP HTTP client
- `calxgloss-ghidra` — `GhidraClient` with session management, DLL queries (list, info, imports, exports), function queries (disassembly, decompiler, call graph, full analysis), error types, response mapping structs, and `Session` tracking
- `calxgloss-ghidra` — tracing instrumentation and comprehensive test coverage (10 tests)
- `calxgloss-llm` — local LLM client (Ollama/vLLM compatible): `LlmClient` with non-streaming and SSE streaming completions, `LlmConfig` with builder pattern, `LlmMessage` with System/User/Assistant roles, `strip_code_fences()` utility, OpenAI-compatible `chat/completions` API, serde request/response structs, `LlmError` with 6 variants, tracing instrumentation, and 13 tests
- `calxgloss-prompts` — prompt template engine shell
- `calxgloss-pal` — platform abstraction layer shell
- `calxgloss-analysis` — DLL classification and API tagging shell
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
