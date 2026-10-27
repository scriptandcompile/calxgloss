# Calxgloss

Reverse Engineering Harness

## Overview

Calxgloss reverse engineers a project's executables and DLLs. It turns disassembled code into **cross-platform Rust source code** through a test-driven decompilation workflow. The output runs on Windows, macOS, and Linux with identical observable behavior.

**Name etymology:** The name joins two words. *Calx* is the pure residue left after a fire burns away impurities. *Gloss* is the layer of translation and interpretation between languages. In alchemy, calcination burns away everything non-essential and leaves only the irreducible form. This harness does the same thing: it reduces the assembly to its essential logic, then adds a gloss — a Rust translation layer — to make the logic readable, buildable, and cross-platform.

## Core Principles

1. **Functional equivalence over binary precision** — reproduce observable behavior, not instruction sequences
2. **Cross-platform by default** — Windows APIs and libraries map to their closest cross-platform Rust equivalents
3. **Test-driven decompilation** — tests capture original behavior; Rust code must pass those tests
4. **Incremental restitching** — swap in Rust implementations one at a time, and verify each swap
5. **LLM-first, discard-when-wrong** — the local LLM does the primary translation work. Use it aggressively and freely. Throwing away incorrect LLM output is cheap when the LLM is hosted locally. The cost of not using it is far higher.
6. **Reversible through source control** — every unit of work becomes a commit on its function's attempt branch. Everything stays restorable, diffable, and reviewable. No state is lost.
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
  │ batch warmup: the 13 evidence scans · failure-informed retries · tier escalation          │
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

Set your directories and server addresses once, in a config file:

```toml
# ~/.config/calxgloss/config.toml
target_dir = "/path/to/binaries"   # DLLs and EXEs, read-only
workspace  = "/path/to/workspace"  # where the translated Rust, re/, scratch, and the git repo live

[llm]
url   = "http://127.0.0.1:1919/v1"
model = "Qwen3.6-35B-A3B-FP8"
```

Then run the pipeline and the review UI together. `live` classifies and
translates in the foreground while you review units in the browser at
`http://localhost:3000`. Use `--port` to change the port. Ctrl+C stops both:

```bash
cd /path/to/workspace
cargo run --bin calxgloss-cli -- live
```

`live` always uses the current directory, so `cd` into the workspace first.
Only `--workspace <dir>` overrides this. The `workspace` setting applies to
the other commands, for example translating a single function:

```bash
cargo run --bin calxgloss-cli -- translate \
    --target myapp.exe \
    --dll game_logic.dll \
    --function DrawSprite
```

`calxgloss config` prints every setting in force and the layer each value came
from. If a value is not what you expected, this shows where it came from:

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

Calxgloss looks for the file at, in order: the path given to `--config`,
`./calxgloss.toml`, then `$XDG_CONFIG_HOME/calxgloss/config.toml` (or
`~/.config/calxgloss/config.toml`). The file named by `--config` must exist.
The others are optional.

The LLM URL and model have no default, because a local inference server has no
conventional address. When they are unset, `translate` reports them as unset
and lists all three ways to provide one, instead of failing later with a
connection error to a port nothing is listening on. `target_dir` also has no
default: commands that do real work fail immediately and print the three ways
to set it. `workspace` defaults to the current directory. `live` and `serve`
always use the current directory and ignore config and environment, unless you
pass `--workspace`.

### Scan Read Cache

Batch runs (`batch-translate`, `auto`, `live`) cache every analysis engine
read under `re/cache/<binary>/<sha256>/`. (Until ADR-0043 this directory was
named `re/ghidra-cache/`, then `re/decomp-cache/`.) Each cache entry is keyed
on the target binary's file bytes, the loaded program name, and the cache
format version. A second batch run over unchanged bytes replays everything
from the cache and makes zero analysis engine reads. Changed bytes hash to a
different directory, so stale entries never need invalidating. Opening the
cache also ensures `re/cache/` is listed in the workspace's `.gitignore`: the
cache is large, it can always be rebuilt, and it should never be committed to
the workspace repo.

One case the cache cannot detect: the binary's bytes stayed the same, but the
*analysis state* changed — a re-analysis, applied types, or renames. Two ways
to fix this:

- run with `--refresh-cache` — the run deletes the cache directory for that
  binary's current bytes (`re/cache/<binary>/<sha256>/`), reads everything
  from the analysis engine once, and rewrites the cache for the next run;
- delete `re/cache/<binary>/` by hand — this removes every byte version of
  the binary at once.

## Workspace Structure

| Crate | Purpose |
|-------|---------|
| `calxgloss-types` | Shared data structures |
| `calxgloss-config` | Layered configuration (flags, environment, TOML) |
| `calxgloss-decomp` | Analysis engine seam: `ScanSource`/`TypeWriteSource` + scan read cache (ADR-0041) |
| `calxgloss-kuna` | Kuna analysis engine — PE loading, decompilation, the only analysis engine (ADR-0041) |
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
| `calxgloss-translator` | Evidence engine scans → LLM → Rust pipeline |
| `calxgloss-verify` | Compile and test verification |
| `calxgloss-git` | Git branch/commit/merge automation |
| `calxgloss-reports` | Terminal output formatting |
| `calxgloss` | Meta-lib, re-exports all public APIs |
| `calxgloss-cli` | CLI entry point |
| `calxgloss-web` | Web review UI (REST API, live events, accept/send-back/patch) |

## License

MIT — see [`LICENSE`](LICENSE)
