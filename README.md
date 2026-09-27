# Calxgloss

Reverse Engineering Harness

## Overview

Calxgloss reverse engineers project executables and DLLs, transforming disassembled code into **cross-platform Rust source code** through a test-driven decompilation workflow. The output runs on Windows, macOS, and Linux with identical observable behavior.

**Name etymology:** *Calx* (the pure, calcined residue left after burning away impurities) + *gloss* (the layer of translation and interpretation between languages). In alchemy, calcination burns away everything non-essential, leaving only the irreducible form. That is what this harness does: it burns away the assembly to reveal the essential logic, then adds a gloss — a Rust translation layer — to make it readable, buildable, and cross-platform.

## Core Principles

1. **Functional equivalence over binary precision** — reproduce observable behavior, not instruction sequences
2. **Cross-platform by default** — Windows APIs and libraries map to their closest cross-platform Rust equivalents
3. **Test-driven decompilation** — tests capture original behavior; Rust code must pass those tests
4. **Incremental restitching** — swap in Rust implementations one at a time, verifying each swap
5. **LLM-first, discard-when-wrong** — the LLM is the primary engine. Use it aggressively and freely. Throwing away incorrect LLM output is cheap when hosted locally; the cost of not using it is far higher
6. **Source-control backed reversibility** — every unit of work is a branch and a commit. The system is always restorable, diffable, and reviewable. No state is lost.
7. **Human-in-the-loop review** — a web UI provides structured review of every unit of work, its justification, and its dependency relationships

## Architecture

```
┌───────────────────────────────────────────────────────────────────────────────┐
│                        Agent Harness                                          │
│                                                                               │
│  ┌───────────┐   ┌───────────┐   ┌──────────────────────┐                    │
│  │  GhidraMCP │──▶│ Decompiler│──▶│  Disassembly/IR      │                    │
│  │   Bridge   │   │ Pipeline  │   │  Extraction           │                    │
│  └───────────┘   └───────────┘   └──────────┬───────────┘                    │
│                                              │                                 │
│  ┌───────────┐    ┌───────────┐              ▼                                │
│  │ Git Branch │◀───│  LLM      │    ┌──────────────────────┐                   │
│  │  Manager   │    │  Pipeline │    │  Behavior Testing     │                   │
│  │            │    │           │    │  Layer                │                   │
│  └───────────┘    └───────────┘    └──────────┬───────────┘                   │
│       │              │                         │                                │
│       │              ▼                         ▼                                │
│       │    ┌─────────────────┐       ┌─────────────────┐                       │
│       │    │  Fault          │       │  Rust Code      │                       │
│       │    │  Detection &    │       │  Generation      │                       │
│       │    │  Recovery       │       │                  │                       │
│       │    └─────────────────┘       └────────┬────────┘                       │
│       │                                        │                                │
│       │              ┌─────────────────────────▼───────────────────┐            │
│       │              │         LLM Orchestration Engine             │            │
│       │              │  - Prompt scheduling, context management     │            │
│       │              │  - Token tracking, retry/fallback logic      │            │
│       │              │  - Branch per function, commit per unit      │            │
│       │              └─────────────────────────────────────────────┘            │
│       │                                        │                                │
│       │                                        ▼                                │
│  ┌──────────────────────────────────────────────────────────┐                  │
│  │  Restitch Engine ──▶ Compilation ──▶ Verification Loop   │                  │
│  └──────────────────────────────────────────────────────────┘                  │
│                                                                               │
│  ┌─────────────────────────────────────────────────────┐                       │
│  │              Web Review UI                           │                       │
│  │  - Unit diff view with justifications                │                       │
│  │  - Dependency graph visualization                     │                       │
│  │  - Accept/reject/work-on-it actions                   │                       │
│  └─────────────────────────────────────────────────────┘                       │
└───────────────────────────────────────────────────────────────────────────────┘
```

## MVP

The MVP proves the core concept: **can an LLM reliably translate disassembled functions to Rust that passes behavior tests?**

Translate a single function from a single DLL from disassembly to working Rust that compiles and passes baseline tests.

See [`Documentation/step_by_step_mvp.md`](Documentation/step_by_step_mvp.md) for the full step-by-step plan.

## Quick Start

```bash
cargo run --bin calxgloss-cli -- translate \
    --target myapp.exe \
    --dll game_logic.dll \
    --function DrawSprite \
    --ghidra-url http://localhost:8080 \
    --llm-url http://localhost:8081/v1 \
    --llm-model qwen3-235b-a22b
```

## Workspace Structure

| Crate | Purpose |
|-------|---------|
| `calxgloss-types` | Shared data structures |
| `calxgloss-ghidra` | GhidraMCP HTTP client |
| `calxgloss-llm` | Local LLM client (Ollama/vLLM) |
| `calxgloss-prompts` | Prompt templates |
| `calxgloss-pal` | Windows API → Rust mappings |
| `calxgloss-analysis` | DLL classification, call graphs, API tagging |
| `calxgloss-testgen` | FFI stubs, test inputs, baseline execution |
| `calxgloss-translator` | Ghidra → LLM → Rust pipeline |
| `calxgloss-verify` | Compile and test verification |
| `calxgloss-git` | Git branch/commit/merge automation |
| `calxgloss-reports` | Terminal output formatting |
| `calxgloss` | Meta-lib, re-exports all public APIs |
| `calxgloss-cli` | CLI entry point |
| `calxgloss-web` | Web review UI (scaffolded) |

## License

MIT — see [`LICENSE`](LICENSE)
