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
6. **Source-control backed reversibility** — every unit of work lands as a commit on its function's attempt branch. The system is always restorable, diffable, and reviewable. No state is lost.
7. **Human-in-the-loop review** — a web UI provides structured review of every unit of work, its justification, and its dependency relationships

## Architecture

```
  ┌────────────────────────────────────────────────────┐      ┌──────────────────────────────────┐
  │                   calxgloss-cli                    │      │          calxgloss-web           │
  │ translate · batch · classify · auto · serve · live │      │accept · send back · request patch│
  └────────────────────────────────────────────────────┘      └──────────────────────────────────┘
                             │                                               ▲
                             │                                               │
                             ▼                                               │
  ┌────────────────────────────────────────────────────────────────────────────────────────┐
  │                    calxgloss-translator — the translation pipeline                     │
  │                  fetch ▸ prompt ▸ translate ▸ verify ▸ retry ▸ commit                  │
  │                    compile-fix retries · failure-informed prompting                    │
  └────────────────────────────────────────────────────────────────────────────────────────┘
           ▲                        ▲                        ▲                    ▲
           │                        │                        │                    │
           │                        │                        │                    │
  ┌────────────────┐   ┌────────────────────────┐  ┌──────────────────┐  ┌────────────────┐
  │                │   │    evidence engines    │  │                  │  │                │
  │calxgloss-ghidra│   │  analysis · callgraph  │  │calxgloss-prompts │  │ calxgloss-llm  │
  │  HTTP client   │   │  typeinfer · typesdb   │  │  calxgloss-pal   │  │ fault monitors │
  │                │   │   algorithm · memory   │  │                  │  │                │
  └────────────────┘   └────────────────────────┘  └──────────────────┘  └────────────────┘
           │                                                                      │
  ┌────────────────┐                                                     ┌────────────────┐
  │     Ghidra     │                                                     │Local LLM server│
  │GhidraMCP bridge│                                                     │ Ollama · vLLM  │
  └────────────────┘                                                     └────────────────┘

  Foundation: calxgloss-types (shared types) · calxgloss-config (layered settings) ·
  calxgloss-testgen (FFI bindings & baseline tests) · calxgloss-verify (compile & test) ·
  calxgloss-git (branch per function attempt) · calxgloss-reports (terminal output)
```

## Quick Start

Write your directories and server addresses to a config file once:

```toml
# ~/.config/calxgloss/config.toml
target_dir = "/path/to/binaries"   # DLLs and EXEs, read-only
workspace  = "/path/to/workspace"  # where the translated Rust, re/, scratch, and the git repo live

[ghidra]
url = "http://127.0.0.1:8080"

[llm]
url   = "http://127.0.0.1:1919/v1"
model = "Qwen3.6-35B-A3B-FP8"
```

Then run the pipeline and the review UI together — `live` classifies and
translates in the foreground while you review units in the browser at
`http://localhost:3000` (`--port` to change it). Ctrl+C stops both:

```bash
cd /path/to/workspace
cargo run --bin calxgloss-cli -- live
```

`live` always works on the current directory — `cd` into the workspace first;
only `--workspace <dir>` overrides it. The `workspace` setting applies to the
other commands, like translating a single function:

```bash
cargo run --bin calxgloss-cli -- translate \
    --target myapp.exe \
    --dll game_logic.dll \
    --function DrawSprite
```

`calxgloss config` prints every setting in force and which layer supplied it, so
a value you did not expect can be traced to its source:

```
target_dir
  path         /path/to/binaries                  (config file)

workspace
  path         /path/to/workspace                 (config file)

ghidra
  url          http://127.0.0.1:8080              (config file)

llm
  url          http://127.0.0.1:1919/v1           (config file)
  model        Qwen3.6-35B-A3B-FP8                (environment)
  api_key      <not set>
```

### Configuration

Settings are resolved in this order, most specific first:

1. a command-line flag (`--target-dir`, `--ghidra-url`, `--llm-model`, ...),
2. an environment variable (`CALXGLOSS_TARGET_DIR`, `CALXGLOSS_GHIDRA_URL`, `CALXGLOSS_LLM_MODEL`, ...),
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
`target_dir` has no default either: commands that do real work fail fast and
print the three ways to set it. `workspace` defaults to the current directory —
and `live`/`serve` always use the current directory, ignoring config and
environment unless you pass `--workspace`.

### Ghidra Read Cache

Batch runs (`batch-translate`, `auto`, `live`) cache every Ghidra read under
`re/ghidra-cache/<binary>/<sha256>/`, keyed on the target binary's file bytes,
the Ghidra program name, and the cache format version. A second batch over
unchanged bytes replays from the cache with zero live reads; changed bytes hash
to a different directory, so stale entries never need invalidating.

One case the cache cannot detect: the *program inside Ghidra* changed —
re-analysis, applied types, renames — while the binary's bytes stayed the same
(the bridge reports no Ghidra version to notice it with). Two ways out:

- run with `--refresh-ghidra-cache` — the run wipes the cache directory for
  that binary's current bytes (`re/ghidra-cache/<binary>/<sha256>/`), reads
  everything live once, and rewrites the cache for the next run;
- delete `re/ghidra-cache/<binary>/` by hand — every byte version of the
  binary at once.

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
| `calxgloss-callgraph` | Root/leaf detection, translation ordering, context enrichment |
| `calxgloss-typesdb` | Ghidra type library scanning, vtable detection, struct inference |
| `calxgloss-typeinfer` | This-pointer detection, parameter size detection, type propagation |
| `calxgloss-algorithm` | Control-flow signature matching, string-guided hints, callback patterns |
| `calxgloss-memory` | Allocation/deallocation pair tracking, handle lifecycle, refcount detection |
| `calxgloss-testgen` | FFI bindings, test inputs, baseline execution |
| `calxgloss-translator` | Ghidra → LLM → Rust pipeline |
| `calxgloss-verify` | Compile and test verification |
| `calxgloss-git` | Git branch/commit/merge automation |
| `calxgloss-reports` | Terminal output formatting |
| `calxgloss` | Meta-lib, re-exports all public APIs |
| `calxgloss-cli` | CLI entry point |
| `calxgloss-web` | Web review UI (scaffolded) |

## License

MIT — see [`LICENSE`](LICENSE)
