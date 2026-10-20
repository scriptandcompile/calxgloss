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
  ┌────────────────────────────────────────────────────┐     ┌────────────────────────────────┐
  │                   calxgloss-cli                    │     │         calxgloss-web          │
  │ init · doctor · classify · translate · auto · live │     │ review: accept · send back ·   │
  │ batch-translate · serve · dashboard · verify · gc  │     │ patch · skip · override        │
  │ typesdb · typeinfer · algorithm · memory · sync    │     │ pipeline: pause · resume ·     │
  │ consts · callback · controlflow · stringctx        │     │ stop · start · cancel-current  │
  │ apidetect · serialize · config · auto-shim         │     │ Axum + React SPA               │
  └────────────────────────────────────────────────────┘     └────────────────────────────────┘
                             ▲                                               ▲
                             │                                               │
                             ▼                                               ▼
  ┌───────────────────────────────────────────────────────────────────────────────────────────┐
  │                      calxgloss-translator — the translation pipeline                      │
  │ read cache ▸ evidence warmup ▸ fetch ▸ prompt ▸ translate ▸ verify ▸ retry ▸ commit       │
  │ batch warmup: the 11 evidence scans · failure-informed retries · tier escalation          │
  │ Windows API calls mapped through calxgloss-pal                                            │
  └───────────────────────────────────────────────────────────────────────────────────────────┘
           ▲                          ▲                          ▲                    ▲
           │                          │                          │                    │
           │                          │                          │                    │
  ┌────────────────┐   ┌────────────────────────────┐  ┌──────────────────┐  ┌────────────────┐
  │calxgloss-decomp│   │      evidence engines      │  │calxgloss-prompts │  │calxgloss-llm   │
  │ engine seam:   │   │ analysis · callgraph       │  │ 5 context tiers  │  │ fault monitors:│
  │ ScanSource ·   │   │ typesdb · typeinfer        │  │ askama templates │  │ hallucination, │
  │ TypeWriteSource│   │ algorithm · memory         │  │                  │  │ infinite loop, │
  │ + read cache   │   │ sync · consts · callback   │  │                  │  │ divergence,    │
  │calxgloss-kuna  │   │ controlflow · stringctx    │  │                  │  │ exhaustion     │
  │ the engine     │   │ apidetect · serialize      │  │                  │  │                │
  └────────────────┘   └────────────────────────────┘  └──────────────────┘  └────────────────┘
            │                          │                                         │
            │       loads the target PE in-process (ADR-0041)                    │
            ▼                                                                    ▼
  ┌────────────────┐                                                         ┌────────────────┐
  │ target PE file │                                                         │Local LLM server│
  │  (read-only)   │                                                         │ Ollama · vLLM  │
  └────────────────┘                                                         └────────────────┘

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

llm
  url          http://127.0.0.1:1919/v1           (config file)
  model        Qwen3.6-35B-A3B-FP8                (environment)
  api_key      <not set>
```

### Configuration

Settings are resolved in this order, most specific first:

1. a command-line flag (`--target-dir`, `--llm-model`, ...),
2. an environment variable (`CALXGLOSS_TARGET_DIR`, `CALXGLOSS_LLM_MODEL`, ...),
3. a TOML file,
4. a built-in default.

The file is looked for at, in order: the path given to `--config`,
`./calxgloss.toml`, then `$XDG_CONFIG_HOME/calxgloss/config.toml` (or
`~/.config/calxgloss/config.toml`). A file named with `--config` must exist; the
others are optional.

The LLM URL and model have no default — a local inference server has no
conventional address — so
`translate` reports them as unset, listing all three ways to provide one, rather
than failing later with a connection error to a port nothing is listening on.
`target_dir` has no default either: commands that do real work fail fast and
print the three ways to set it. `workspace` defaults to the current directory —
and `live`/`serve` always use the current directory, ignoring config and
environment unless you pass `--workspace`.

### Scan Read Cache

Batch runs (`batch-translate`, `auto`, `live`) cache every engine read under
`re/cache/<binary>/<sha256>/` (the directory was `re/ghidra-cache/`, then
`re/decomp-cache/`, until ADR-0043), keyed on the target binary's file
bytes, the loaded program name, and the cache format version. A second batch
over unchanged bytes replays from the cache with zero engine reads; changed
bytes hash to a different directory, so stale entries never need
invalidating. Opening the cache also ensures `re/cache/` is listed in the
workspace's `.gitignore` — the cache is regenerable and large, and it should
never ride the workspace repo's commits.

One case the cache cannot detect: the *analysis state* changed — re-analysis,
applied types, renames — while the binary's bytes stayed the same. Two ways
out:

- run with `--refresh-cache` — the run wipes the cache directory for that
  binary's current bytes (`re/cache/<binary>/<sha256>/`), reads
  everything from the engine once, and rewrites the cache for the next run;
- delete `re/cache/<binary>/` by hand — every byte version of the
  binary at once.

## Workspace Structure

| Crate | Purpose |
|-------|---------|
| `calxgloss-types` | Shared data structures |
| `calxgloss-config` | Layered configuration (flags, environment, TOML) |
| `calxgloss-decomp` | Engine seam: `ScanSource`/`TypeWriteSource` + scan read cache (ADR-0041) |
| `calxgloss-kuna` | Kuna analysis engine — PE loading, decompilation, the only engine (ADR-0041) |
| `calxgloss-llm` | Local LLM client (Ollama/vLLM) |
| `calxgloss-prompts` | Prompt templates |
| `calxgloss-pal` | Windows API → Rust mappings |
| `calxgloss-analysis` | DLL classification, call graphs, API tagging |
| `calxgloss-callgraph` | Root/leaf detection, translation ordering, context enrichment |
| `calxgloss-typesdb` | Type Manager scanning, vtable detection, struct inference |
| `calxgloss-typeinfer` | This-pointer detection, parameter size detection, type propagation |
| `calxgloss-algorithm` | Control-flow signature matching, string-guided hints, callback patterns |
| `calxgloss-memory` | Allocation/deallocation pair tracking, handle lifecycle, refcount detection |
| `calxgloss-sync` | Mutex/lock pair tracking, atomic operation detection, threading patterns |
| `calxgloss-consts` | Bitflag group detection, sequential enum candidates, magic-number frequency analysis |
| `calxgloss-callback` | Function-pointer array calls, callback registration sites, jump-table dispatches |
| `calxgloss-controlflow` | Switch-shaped if-else chains, self-recursive functions, state-variable chains |
| `calxgloss-stringctx` | Nine-category string classification, per-function string maps, format-string inference |
| `calxgloss-apidetect` | Import-table extraction, library-to-Rust-crate mapping, per-function API summaries |
| `calxgloss-serialize` | Byte-swap call matching, bit-packing pattern recognition, magic-byte format sniffing |
| `calxgloss-libmatch` | Known-library function identification: body-signature matching of statically linked CRT/STL code |
| `calxgloss-testgen` | FFI bindings, test inputs, baseline execution |
| `calxgloss-translator` | Engine scan → LLM → Rust pipeline |
| `calxgloss-verify` | Compile and test verification |
| `calxgloss-git` | Git branch/commit/merge automation |
| `calxgloss-reports` | Terminal output formatting |
| `calxgloss` | Meta-lib, re-exports all public APIs |
| `calxgloss-cli` | CLI entry point |
| `calxgloss-web` | Web review UI (REST API, live events, accept/send-back/patch) |

## License

MIT — see [`LICENSE`](LICENSE)
