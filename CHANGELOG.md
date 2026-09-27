# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Project scaffolding with 14 workspace crates
- Workspace root `Cargo.toml` with shared dependencies
- `calxgloss-types` — shared data structures shell
- `calxgloss-ghidra` — GhidraMCP HTTP client shell
- `calxgloss-llm` — local LLM client shell
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
