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

Write your server addresses to a config file once:

```toml
# ~/.config/calxgloss/config.toml
[ghidra]
url = "http://127.0.0.1:8080"

[llm]
url   = "http://127.0.0.1:1919/v1"
model = "Qwen3.6-35B-A3B-FP8"
```

Then translate without repeating them:

```bash
cargo run --bin calxgloss-cli -- translate \
    --target myapp.exe \
    --dll game_logic.dll \
    --function DrawSprite
```

`calxgloss config` prints every setting in force and which layer supplied it, so
a value you did not expect can be traced to its source:

```
ghidra
  url          http://127.0.0.1:8080              (config file)

llm
  url          http://127.0.0.1:1919/v1           (config file)
  model        Qwen3.6-35B-A3B-FP8                (environment)
  api_key      <not set>
```

### Configuration

Settings are resolved in this order, most specific first:

1. a command-line flag (`--ghidra-url`, `--llm-model`, ...),
2. an environment variable (`CALXGLOSS_GHIDRA_URL`, `CALXGLOSS_LLM_MODEL`, ...),
3. a TOML file,
4. a built-in default.

The file is looked for at, in order: the path given to `--config`,
`./calxgloss.toml`, then `$XDG_CONFIG_HOME/calxgloss/config.toml` (or
`~/.config/calxgloss/config.toml`). A file named with `--config` must exist; the
others are optional.

Ghidra's URL has a default, because GhidraMCP has a well-known port. The LLM URL
and model have none — a local inference server has no conventional address — so
`translate` reports them as unset, listing all three ways to provide one, rather
than failing later with a connection error to a port nothing is listening on.

## Workspace Structure

| Crate | Purpose |
|-------|---------|
| `calxgloss-types` | Shared data structures |
| `calxgloss-config` | Layered configuration (flags, environment, TOML) |
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
