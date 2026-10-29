# KRAKEN complete inventory + calxgloss-relevance triage

> Part of the [KRAKEN overview](README.md). This is the fixed surface map every
> `3x-*` domain file compares against. Sources: the clone at
> `/tmp/opencode/kraken` @ `68718c6` (2026-10-28), measured directly — every
> LOC figure is `find … -name '*.rs' | xargs wc -l` run on the clone today,
> every command count is counted out of `docs/reference/commands.md`. KRAKEN
> claims cite clone-relative `path:line`. The grouping follows the repo's own
> crate map (`CLAUDE.md:12-36`), not an invention.

**Triage legend** (relevance to comparing against calxgloss's automated
PE→Rust pipeline): ● high — directly comparable or a source of stealable
ideas; ◐ medium — adjacent, worth a paragraph; ○ low — recorded for
completeness.

## 1. Workspace shape and scale

- Workspace (`Cargo.toml:3`): `members = ["crates/*", "xtask"]`,
  `exclude = ["spikes"]`; edition 2024, version 0.1.0, GPL-3.0-or-later
  (`Cargo.toml:5-9`). Status: **pre-alpha 0.1a** (`README.md:37`); Linux
  x86_64 is the one fully working platform (`README.md:39-48`).
- **Measured scale**: `crates/` holds **31 crates** (not 30 as the
  [scope file](00-scope-and-method.md) says — verified: `ls crates | wc -l`
  = 31, 31 `Cargo.toml`s), **263,757 lines** of Rust, of which **44,442**
  live under `tests/` directories. Plus `xtask` 2,913 (266,670 total — this
  is where the "~267k" comes from), `spikes/` 646 (excluded workspace), the
  Java Ghidra bridge 5,081, the C# .NET sidecar 980, the C++ shim 1,096.
- `rust-toolchain.toml`: `channel = "stable"` + rustfmt/clippy — a moving
  stable, despite `CLAUDE.md:7` saying "stable toolchain pinned".
- Five biggest crates: `kraken-viewmodel` 41.6k, `kraken-rewrite` 30.2k,
  `kraken-gui` 29.9k, `kraken-registry` 23.2k, `engine-native` 22.2k.

## 2. The 31 crates

LOC includes each crate's own tests. Notable modules are the largest files
measured in `crates/<name>/src/`.

### 2.1 Engines

| Crate | LOC | For | Notable modules | T |
|---|---|---|---|---|
| `kraken-engine` | 2,155 | Engine capability traits (dyn-compatible, async) + reusable contract test suite; feature `testing` | `traits.rs` (231), `testing.rs` (722), `testing_data.rs` (624) | ● |
| `engine-ghidra` | 3,960 | Full-Ghidra engine: confined Ghidra JVM sidecar over JSON-RPC | `engine.rs` (1,073), `supervisor.rs` (479), `tests.rs` (997) | ● |
| `engine-native` | 22,240 | JVM-free engine: ELF/PE loading, Sleigh, Ghidra's C++ decompiler in a confined worker (`kraken-native-worker`) | `engine.rs` (1,899), `objfile.rs` (1,750), `discover.rs` (1,333); `pe.rs`, `dwarf.rs`, `demangle.rs`, `refs.rs`, `win32.rs` (`CLAUDE.md:21`) | ● |
| `engine-native-sys` | 1,518 Rust (+1,096 C++ in `shim/`, not in the Rust count) | Builds Ghidra's decompiler + Sleigh (Apache-2.0) as a static lib, cxx-bridges a KRAKEN shim | `src/lib.rs` (1,083), `shim/kraken_shim.cc` (1,016), `build.rs` (235), `licenses/` | ● |
| `engine-dotnet` | 2,549 | Managed (.NET) engine backed by a confined ILSpy C# sidecar; `Managed` locators, renames replayed at render time | `engine.rs` (802), `annotate.rs` (589), `launch.rs` (298) | ○ |
| `engine-fake` | 2,740 | In-memory engine replaying JSON fixtures recorded from real Ghidra, for tests and CI without Ghidra | `engine.rs` (946), `data.rs` (667) | ● |
| `kraken-sidecar` | 2,225 | Shared sidecar plumbing: JSON-RPC framing/multiplexing client, confined spawner (Landlock/seccomp/netns, Windows job object), log sink | `sandbox.rs` (1,172), `rpc.rs` (680), `log.rs` (159) | ◐ |

### 2.2 Workbench data model and GUI

| Crate | LOC | For | Notable modules | T |
|---|---|---|---|---|
| `kraken-model` | 3,961 | Project database: SQLite edit log, versions, read-sets, undo, proposals, snapshots, patch overlay, AI-usage ledger | `store.rs` (772), `patches.rs` (437), `ai_usage.rs` (411) | ● |
| `kraken-viewmodel` | 41,612 | All GUI state/logic behind a `Backend` trait, no egui — the repo's largest crate | `vm.rs` (1,995), `infer/setup.rs` (1,831), `tests.rs` (1,815) | ◐ |
| `kraken-gui` | 29,895 | egui desktop workbench (functions, decompiler, listing, hex, graph, history, rewrite wizard, assistant tab) | `app.rs` (2,345), `assist/chat.rs` (1,096), `rewrite/wizard.rs` (1,059) | ◐ |
| `kraken-gui-widgets` | 4,012 | Reusable egui widgets: theme, virtual list, hex view, decompiler token text, listing, CFG graph | `graph_view.rs` (1,039), `token_text.rs` (536), `hex_view.rs` (506) | ◐ |
| `kraken-layout` | 1,115 | Deterministic layered (Sugiyama-style) CFG layout | `component.rs` (576), `lib.rs` (227) | ○ |

### 2.3 Automation surface

| Crate | LOC | For | Notable modules | T |
|---|---|---|---|---|
| `kraken-registry` | 23,223 | The one command registry: 78 typed commands (`CLAUDE.md:24`), sessions, mutation pipeline, jobs | `session.rs` (1,350), `commands/rewrite.rs` (1,258), `commands/probe.rs` (897); 25 files under `src/commands/` | ● |
| `kraken-cli` | 13,757 | `kraken` binary: one subcommand per registry command + `kraken mcp`, `--json` | `app.rs` (1,403), `render.rs` (1,381), `infer_cmd.rs` (978) | ● |
| `kraken-mcp` | 2,734 | MCP server (`rmcp`): one tool per command, MCP prompts + resources, jobs/progress/approvals | `resources.rs` (735), `prompts.rs` (550), `server.rs` (365) | ● |
| `krakend` | 5,260 | Daemon owning project sessions + engine sidecars; serves the registry over local IPC | `host.rs` (798), `handler.rs` (729), `approvals.rs` (349) | ◐ |
| `kraken-ipc` | 3,136 | Daemon IPC: runtime paths, auth token, framing, server/client, single-instance, idle exit | `paths.rs` (459), `server.rs` (414), `idle.rs` (300) | ○ |
| `kraken-host` | 14,017 | Shared hosting glue: config, engine factory (`ghidra|native|auto|.NET` selection in `native.rs`), daemon client, `InferManager`, `kraken setup` provisioning | `infer/serving.rs` (1,764), `infer.rs` (1,470), `provision.rs` (1,213) | ● |
| `kraken-py` | 1,512 | Python module `kraken` (PyO3, PyPI `kraken-workbench`): daemon client + in-process fallback; `python` cargo feature gates PyO3 | `conn.rs` (543), `schema.rs` (441), `py.rs` (291) | ◐ |

### 2.4 AI layer

| Crate | LOC | For | Notable modules | T |
|---|---|---|---|---|
| `kraken-assist` | 10,999 | Assistant core: registry tool host, tasks (explain, overview, auto-name), RE glossary, `AssistBackend` (model API or terminal agent), `Meter` cost ledger | `acp.rs` (1,228), `shell/policy.rs` (1,032), `tasks.rs` (846) | ● |
| `kraken-agent` | 5,457 | Built-in agent loop: chat providers, tool-host abstraction, prompt-injection-safe tool plumbing | `agent.rs` (584), `low_context.rs` (469), `tests.rs` (810) | ● |
| `kraken-acp` | 6,319 | Terminal-agent host over ACP: launches Claude Code / Codex / Gemini CLI pre-connected to KRAKEN's MCP; fake ACP agent for tests | `host.rs` (1,218), `fake_agent.rs` (832), `confine.rs` (525) | ◐ |
| `kraken-infer` | 8,649 | Supervised local inference: llama.cpp + manifest-driven OpenAI-compatible engines ("Strata"), hardware/fit checks, VRAM stats | `hardware.rs` (993), `stats.rs` (992), `strata.rs` (791) | ◐ |
| `kraken-eval` | 3,313 | Eval harness `kraken eval`: scripted corpus tasks scored against DWARF ground truth, any backend, cassette replay in CI | `report.rs` (581), `score.rs` (498), `suite.rs` (470) | ● |

### 2.5 Emulation and rewrite

| Crate | LOC | For | Notable modules | T |
|---|---|---|---|---|
| `kraken-rewrite` | 30,175 | The rewrite pipeline (ADR 0013): icicle-emu oracle, translation/spec tasks, sandboxed differential tests, `rewrite.sqlite`, planner, repair loop, export, whole-program mode | `runtime/rt.rs` (2,405 — the libc→Rust runtime shim), `service.rs` (1,761), `store.rs` (1,606); `blame.rs`, `abi.rs`, `process.rs` | ● |
| `kraken-emu` | 8,368 | Emulation layer on icicle's SLEIGH CPU: x86/x86-64/ARM-Thumb/AArch64/RISC-V 32+64, C calling conventions, own Linux user-mode syscall layer, stepping API; never parses DWARF (guarded test) | `linux/mod.rs` (1,918), `call.rs` (1,116), `session.rs` (661) | ● |

### 2.6 Safety

| Crate | LOC | For | Notable modules | T |
|---|---|---|---|---|
| `kraken-confine` | 1,241 | Confinement of children running untrusted code: Landlock read-only view, no network, scrubbed env, `Limits`, `run_captured*` with deadline | `lib.rs` (830), `tests.rs` (411) | ● |
| `kraken-procguard` | 206 | Child-process lifetime guards (Windows job object, macOS parent-death watchdog), physical-memory probe | `lib.rs` (111) | ○ |

### 2.7 Support and tests

| Crate | LOC | For | Notable modules | T |
|---|---|---|---|---|
| `kraken-proto` | 3,817 | Wire/schema types only — engine-neutral, no runtime or FFI deps; JSON Schema via schemars | `ai.rs` (550), `program.rs` (427), `untrusted.rs` (387); `locator`, `logop`, `types`, `page`, `hex`, `error`, `meta`, `progress` | ● |
| `kraken-record` | 1,415 | Records `engine-fake` fixtures from real Ghidra and checks them for drift (the nightly drift job) | `record.rs` (435), `check.rs` (427), `main.rs` (195) | ● |
| `kraken-e2e` | 2,177 | End-to-end safety and exit-criterion tests (test-only crate, no `src/`) | e.g. `tests/exit_criterion_native.rs` (named in `docs/design/0014-native-engine.md:85`) | ● |
| `xtask` (not in `crates/`) | 2,913 | Repo build/automation: 12 subcommands, see §6 | dispatch in `src/main.rs:67-77` | ◐ |

## 3. Command registry surface

`docs/reference/commands.md` (14,931 lines) is generated by `cargo xtask
docs` from the registry ("Do not edit by hand", `docs/reference/commands.md:3`).
Counted from its summary table: **78 commands** (matches `CLAUDE.md:24`),
each with kind, permission class, typed args and an inlined output JSON
Schema.

| Axis | Breakdown |
|---|---|
| Kind | **query 47 · mutation 23 · job 8** (a `Stream` kind exists in the design, ADR 0003, unused in these 78) |
| Permission | **safe 43 · mutating 34 · dangerous 1** — the only `dangerous` command is `patch_export` |
| Quirks | 4 query commands are *mutating* (`local_model_hold/release/start/stop`); 1 job is *safe* (`patch_from_source`) |

All 78 names, grouped by area (kind=job, permission=mutating marked ⚠; everything else is query/safe):

- **Project & engine (5)**: `project_create`⚠(mut) · `project_open`⚠ ·
  `project_close`⚠ · `project_info` · `rebuild`⚠(job; "recreate the engine
  project from the log and report drift")
- **Analysis & listing (17)**: `analyze`⚠(job) · `binary_probe` ·
  `list_functions` · `get_function` · `decompile` · `disassemble` · `cfg` ·
  `xrefs` · `callers` · `callees` · `exports` · `imports` · `strings` ·
  `memory_map` · `read_bytes` · `search` · `assemble`
- **Edits & annotations (11)**: `rename_symbol`⚠ · `set_comment`⚠ ·
  `set_type`⚠ · `set_function_bounds`⚠ · `set_calling_convention`⚠ ·
  `create_function`⚠ · `delete_function`⚠ · `apply_edits`⚠ (bulk rename/
  comment/retype in one call) · `bookmark_add/list/remove`⚠(add/remove)
- **History, undo, proposals (10)**: `history` · `undo`⚠ · `undo_entry`⚠ ·
  `undo_preview` · `undo_run`⚠ (undo a whole agent run) ·
  `tainted_list` / `tainted_clear`⚠ (stale marks after undo) ·
  `proposals_list` · `proposal_accept/reject`⚠
- **Byte patching (5)**: `patch_set`⚠ · `patch_list` · `patch_remove`⚠ ·
  `patch_export`⚠(dangerous) · `patch_from_source`(job, plans a patch from
  edited decompiled C)
- **Emulation (1)**: `emulate_run` (run the program in the sandboxed
  emulator with given stdin/args)
- **Rewrite pipeline (10)**: `rewrite_plan` · `rewrite_status` ·
  `rewrite_unit` · `rewrite_function`⚠(job) · `rewrite_spec`⚠(job) ·
  `rewrite_build`⚠(job; "build and test an exported Rust rewrite inside the
  sandbox") · `rewrite_accept`⚠(users only) · `rewrite_export`⚠(job) ·
  `rewrite_program`⚠(job) · `rewrite_program_status`
- **Jobs (3)**: `job_status` · `job_await` · `job_cancel`⚠
- **AI & local models (12)**: `ai_jobs` · `ai_usage` · `kraken_help` ·
  `local_model_list/devices/recommend/status` ·
  `local_model_setup`(safe, approval) · `local_model_start/stop/hold/
  release`⚠(mutating)
- **GUI driving (4)**: `ui_state` · `ui_action` · `ui_highlight` ·
  `gui_navigate`

Registry implementation mirrors this in 25 files:
`crates/kraken-registry/src/commands/{ai,bookmarks,bulk,data,edit,emulate,
gui_navigate,help,history,infer,jobs,local_model,mod,patch,patch_source,
probe,project,query,rebuild,rewrite,rewrite_build,rewrite_program,search,
ui,undo_entry}.rs`.

## 4. Docs book (`docs/`, mdBook)

35 markdown pages + `book.toml` + 22 PNG screenshots. User guide:
`introduction.md` (29) · `tutorial.md` (268, first RE session) ·
`install.md` (141) · `getting-started.md` (168) · `gui.md` (390, menu by
menu) · `concepts.md` (43) · `rewrite.md` (134) · `mcp.md` (98) ·
`assistant.md` (708) · `local-models.md` (501) · `dotnet.md` (165) ·
`native-engine.md` (316) · `emulation.md` (86) · `patching.md` (127) ·
`performance.md` (382) · `cli.md` (88) · `python.md` (185) ·
`security.md` (53). Reference: `reference/commands.md` (14,931, generated).
Design: 14 records + README (below).

### The 14 design decisions (`docs/design/`, the ADR equivalents)

1. **Ghidra sidecar now, native engine later** (0001, 2026-10-15). Ghidra
   runs as a sidecar process with a small Java extension speaking JSON-RPC;
   the Rust side depends only on capability traits (`Loader`, `Analyzer`,
   `Lifter`, `Decompiler`, `TypeStore`, `Emulator`), never Ghidra types. A
   `FakeEngine` replays recorded fixtures and passes the same contract tests.
2. **The edit log is the source of truth; the Ghidra project is a cache**
   (0002). SQLite with an append-only log (operation, anchor, old/new value,
   author, run id, provenance, read-set, status `applied/rejected/orphaned`)
   plus a droppable engine-facts layer. Anchors are address + function entry
   + hash of original bytes; byte patches live in a separate overlay. A
   Ghidra crash costs time, not work; rebuilds replay the log and report
   drift.
3. **One command registry** (0003). A `#[kraken_command]` macro records
   name, kind, permission class, typed args/results; CLI, MCP, GUI palette
   and the docs are all generated from it. Queries are paginated and
   size-capped for MCP token budgets; approval falls back from MCP elicitation
   to attached GUI/CLI, else denial. A contract test runs every command
   through the CLI JSON mode and an MCP client and requires identical results.
4. **Process model** (0004). 0.1a = each CLI/MCP spawns its own sidecar, no
   daemon; 0.1b = `krakend` owns projects, sidecars, one ordered write queue,
   cursor-based change events, priority lanes (interactive/agent/bulk),
   deadlines with "timeout, partial" results. IPC is local-only today,
   TLS-ready by design.
5. **Agent safety** (0005). Additive-only auto-apply (names on unnamed
   symbols, new comments, types on untyped items) with a per-run cap;
   overwrites become proposal batches. Dangerous tools always ask.
   Binary-derived text is always marked untrusted data, sanitized for control
   / bidi characters, with provenance `user|agent|agent-from-binary-text`.
   Canary-string tests prove binary text never triggers a tool call. ACP
   agents are explicitly outside KRAKEN's safety model (one-time warning).
6. **Undo and concurrency** (0006). Undo writes a compensating log entry;
   never rewrites history. Every edit records a read-set (versions of target,
   types, callees seen); writes are compare-and-set against the whole
   read-set. Human edits beat agent edits (agent attempt logged rejected).
   Staged undo: last-edit / whole-run first, dependency-aware listing in 0.2.
7. **Sidecar confinement** (0007). The Ghidra sidecar gets a scrubbed env,
   Landlock read-only JDK/Ghidra/binary/system-libs, RW only throwaway home +
   project, TCP denied via Landlock ABI v4 plus new user/net namespaces
   (Landlock misses UDP); non-enforced ruleset = hard error. Channel is a
   socketpair as the child's stdin with 4-byte big-endian length-prefixed
   JSON-RPC 2.0.
8. **AI integration paths and inference backends** (0008). Four paths: MCP
   server; built-in agent (OpenAI-compatible HTTP + Anthropic/OpenAI/Gemini
   via `genai`); ACP terminal agents (Node adapters, npm-pinned); supervised
   local inference (`InferenceBackend` trait, supervised hash-pinned
   `llama-server`; in-process llama.cpp as a cargo feature). MCP prompts and
   resources front-load program context for agents. `kraken eval` scores
   assistants against corpus ground truth, CI mode = offline cassettes.
9. **Platforms and distribution** (0009). Tier 1 = Linux x86_64, macOS
   arm64, Windows x86_64; other arches return only with the native engine.
   KRAKEN auto-downloads one pinned Ghidra + jlink JRE with hashes compiled
   in; the Rust workspace builds/tests offline via `FakeEngine`.
10. **GUI framework** (0010). egui/eframe/egui_dock pinned 0.36, glow+wgpu
    run-time fallback, AccessKit. GUI state lives in the headless
    `kraken-viewmodel`, tested without egui; `egui_kittest` + Xvfb smoke
    tests + eframe `inspection` (which also lets an agent drive the UI).
11. **License and dependency allowlist** (0011). GPL-3.0-or-later; a closed
    allowlist (MIT/Apache-2.0/BSD/ISC/MPL/Zlib/Unicode-3.0/OFL) enforced by
    `cargo-deny` + a Gradle check. Ghidra/JRE are separate downloaded
    components — except `engine-native-sys`, which compiles Ghidra's C++ in,
    with committed license texts, `cargo xtask notices`, and failing tests
    when they go stale.
12. **Milestones** (0012). Spike → 0.1a vertical slice (with an explicit
    exit criterion: an MCP agent renames/retypes/undoes on a corpus ELF and
    a rebuilt-from-log Ghidra project matches) → 0.1b daemon → 0.2 GUI +
    built-in agent → 0.3 CFG/ACP/auto-name → 0.4 inference + Python → 0.5+
    rewrite pipeline → 1.0 managed code. Corpus + contract tests +
    recorded-fake-drift checks from day one.
13. **The rewrite pipeline** (0013, 259 lines, revised 5×). Two modes on one
    unit record: incremental test-verified (strangler, FFI shim export) and
    spec-then-reimplement (cited spec, `[@0xADDR]` citations mandatory).
    Lifecycle `planned→translated→verified→accepted` / `failed`; bounded
    repair loop fed with compile output, lint rejection or smallest
    counterexample; accepted-callee reuse with version checks; stale marks
    from decompile hashes. Oracles: `icicle-emu/x86-64-sleigh` (implemented),
    `compile-only`, `process` (whole-program difftest); reserved
    `ghidra-pcode` and `native-process`. Model-written code is built and run
    only in a Landlock+seccomp sandbox that **fails closed** — macOS/Windows
    refuse to rewrite at all. Whole-program mode runs bottom-up with the
    `rt` libc shim, program-level repair that traces the first differing byte
    and re-translates suspected functions (`blame`). Measured on real C++
    audio sims `sim03`/`sim04`: **program verdict `pass`, 11/11 cases,
    `.wav` outputs identical** (`docs/design/0013-rewrite-pipeline.md:185-192`)
    — model: Claude Code via ACP, ~30-50 min model time per run.
14. **The native engine** (0014, 210 lines; phases 1-6c done). Ghidra
    12.1.4's `libdecomp`+Sleigh built from source, cxx shim, Rust loaders
    (ELF, PE32/32+, objects, archives, import libs) and Rust rewrites of the
    Java-only parts: discovery, references, CFGs, strings, DWARF types,
    demanglers, library prototype tables (~240 libc + ~130 Win32). Runs in a
    confined worker with a hard watchdog. Agreement vs real Ghidra on
    fixtures: functions 98-100%, bodies 92-99%, names 89-100% by arch;
    100% truth recall on all corpus binaries. ARM/AArch64/RISC-V (phase 6c)
    found all 452 truth functions of 68 cross binaries.

## 5. Engine bridge sources

- **`java/kraken-ghidra`** — the Ghidra extension: 11 files, 5,081 lines of
  Java. `KrakenSidecar.java` (Ghidra extension entry), `Engine.java`,
  `Dispatcher.java`, `Wire.java`/`Proto.java` (JSON-RPC wire), `TypeConv.java`
  (Ghidra type system ↔ neutral model), `Assemble.java` (the SLEIGH
  assembler behind `assemble`), `Inspect.java`, `SelfTest.java`. Built by
  `cargo xtask ghidra-ext`; pinned Ghidra 12.1.4 + Temurin JDK 21.0.12.1+1
  with SHA-256s in `spikes/NOTES-S2.md`.
- **`dotnet/kraken-dotnet`** — C# ILSpy sidecar: 5 files, 980 lines
  (`Program.cs`, `Dispatcher.cs`, `Assembly.cs`, `Tokens.cs`, `Wire.cs`).
  Confined like the Ghidra one; SDK installed by `dotnet/install-sdk.sh`,
  built by `cargo xtask dotnet-ext`; corpus in `corpus/dotnet` (1 assembly +
  truth), docs `docs/dotnet.md`.
- **`crates/engine-native-sys`** — what the JVM-free path compiles in:
  `cargo xtask native-src` fetches GitHub's `Ghidra_12.1.4_build` source
  archive (URL + SHA-256 `2a858300…6cec` pinned at
  `xtask/src/native_src.rs:15-20`), extracts only
  `Ghidra/Features/Decompiler/src/decompile/{cpp,zlib}` + LICENSE to
  `~/.cache/kraken-dev/ghidra-src`; `build.rs:1-235` compiles the Makefile's
  CORE/DECCORE/SLEIGH sets + `sleigh_arch` as C++17 via `cc`; missing sources
  build a stub (`available()==false`) so normal workspace builds never need a
  C++ toolchain. **`kraken setup --native`** does *not* download Ghidra: it
  runs the `native-sla` step — builds Ghidra's Sleigh compiler from the same
  pinned archive and compiles x86/ARM/AArch64/RISC-V `.slaspec` files; all
  24 compiled `.sla` are byte-identical to Ghidra 12.1.4's
  (`docs/design/0014-native-engine.md:29`). Release binaries ship the native
  engine + spec tree (`require-native` build, `docs/design/0014-native-engine.md:105`);
  release archives need no Java at all (`README.md:52`). The Ghidra engine's
  `kraken setup` (no flag) is what downloads Ghidra + trimmed JRE (~3 GB,
  `docs/native-engine.md:32`).

## 6. Automation, infra, policy

- **`xtask`** (2,913 LOC) — 12 subcommands (`src/main.rs:67-77`):
  `ghidra-ext`, `ghidra-ext-test`, `dotnet-ext`, `native-src`, `native-sla`,
  `emu-sysroots` (sysroots for `kraken-emu`), `bench`, `schema`
  (regenerates `schema/kraken-proto.schema.json`), `samples`
  (regenerates `schema/samples/`), `docs` (regenerates
  `docs/reference/commands.md`), `notices` (refreshes license texts), plus
  `gui-docs.rs`.
- **CI** (`.github/workflows/`): `ci.yml` — jobs `fmt`, `clippy`, `test`
  (workspace, headless, no Ghidra), `deny`, `docs`, `real-ghidra` (one cached
  Ghidra+Temurin job running the `#[ignore]` tests), `python` (wheel build +
  pytest + "no daemon left behind"), `test-other-os` (build-only macOS/
  Windows) (`ci.yml:17-197`). `drift.yml` — scheduled `kraken-record` fixture
  drift check; `docs.yml` — mdBook to GitHub Pages; `release.yml` —
  `version`, `assets`, `package`, `release` (290 lines).
- **`deny.toml`** (110 lines) — license allowlist matching ADR 0011;
  advisory ignores each carry a reasoned essay, e.g. ruzstd via icicle is
  proven unreachable from KRAKEN and guarded by
  `crates/kraken-emu/tests/no_debug_info.rs` (`deny.toml:14-23`); icicle-emu
  is an allow-listed git dependency (`deny.toml:51-65`, ADR 0013:77 —
  Unicorn rejected as GPL-2.0-only).
- **`scripts/`** — `install.sh` (curl-pipe installer, SHA256SUMS-checked, no
  sudo; the minisign release key is **not yet generated** — the script says
  so plainly, `scripts/install.sh:13-16`), `package.sh` (refuses to package
  without the committed license texts; ships `licenses/` +
  `kraken-native-worker`), `appimage.sh`, `dev-env.sh`, `INSTALL.txt`; plus
  the AUR package `kraken-workbench-bin` (`README.md:58`).
- **`CLAUDE.md`** (61 lines) — the agent brief: conventions (edition 2024,
  clippy `-D warnings`, `thiserror` in libs / `anyhow` only in binaries, no
  `unwrap()` outside tests, **"Do not commit; the main loop commits"**,
  `CLAUDE.md:10`), the crate map (§2's grouping source), test-env rules
  (`KRAKEN_RUNTIME_DIR` / `KRAKEN_NO_DAEMON=1` so tests never touch the real
  daemon), 12 condensed key decisions.
- **Packaging** — `packaging/linux/` only (AppImage/desktop integration);
  signing is on the ADR 0009 timeline (unsigned 0.2.x, Apple ID + SignPath
  from 0.3).

## 7. `spikes/` (workspace-excluded, 646 LOC)

| Spike | What it proved | Became |
|---|---|---|
| `mcp-echo/` + `NOTES-S1.md` (74) | rmcp 3.5.1 + eframe 0.36.2 pins; egui_dock forces egui 0.36, not 0.37 | the MCP + GUI stack (ADR 0010) |
| `gui-hello/` | dockable egui window | `kraken-gui` |
| `sidecar-echo/` + `NOTES-S2.md` (119) | a JVM sidecar echoing under Landlock; Ghidra 12.1.4 + Temurin 21 pins with SHA-256 | `kraken-sidecar`/`engine-ghidra` (ADR 0007) |
| `native-engine/NOTES.md` (265) | phases 1-4 of the JVM-free engine: fetch/build, shim, discovery, worker | ADR 0014 + `engine-native*` |
| `rewrite-loop/NOTES.md` (277) | the loop on 4 corpus functions: lift→translate→verify against ORIGINAL machine code under emulation→record; "it passed has to mean something" | ADR 0013 + `kraken-rewrite` (store became `rewrite.sqlite`, not their `units.json` proposal) |
| `dotnet-engine/NOTES.md` (177) | a second engine kind fits the traits (`Managed` locators, C# with tokens) | `engine-dotnet` + `corpus/dotnet` |

## 8. Support bits

- **`kraken-proto`** (3.8k) is the single neutral vocabulary: locators
  (address space + offset; `Native`/`Managed`/`Banked` anchors),
  `logop` (the versioned edit-log operation enum), `untrusted.rs` (the
  untrusted-text wrapper types that make "binary text is data, never
  instructions" a type-level property), paging, hex, errors, progress.
- **`schema/`** — `kraken-proto.schema.json` (77 KB, generated) + **53
  sample JSONs** in `schema/samples/` covering every wire shape: anchors in
  all three kinds, ~10 `log_op.*` cases, `untrusted_string.json`,
  completeness states, sync states, provenance variants.
- **Licenses** — `LICENSE` GPL-3.0-or-later; `THIRD-PARTY-NOTICES.md` is
  generated and includes IBM Plex fonts (bundled assets,
  `THIRD-PARTY-NOTICES.md:11`), **Ghidra 12.1.4 decompiler + Sleigh compiled
  into the binaries** (`:133`), zlib 1.3.1 (`:392`), components downloaded at
  setup but not redistributed (`:433`), and the full per-license crate dump.

## 9. calxgloss-relevance triage (every crate + subsystem)

| Subsystem | T | One-line reason |
|---|---|---|
| `kraken-engine` (traits + contract suite) | ● | Direct counterpart of calxgloss's `ScanSource` seam (ADR-0039/0040); same contract-test discipline, opposite process answer |
| `engine-native` + `engine-native-sys` | ● | Ghidra decompiler without a JVM — the mirror of calxgloss deleting the Ghidra JVM (ADR-0007/0041); loads PE32/32+ x86/x64, calxgloss's exact target |
| `engine-ghidra` + `java/kraken-ghidra` | ● | The engine model calxgloss abandoned; also the only *many-processor* option, vs calxgloss x86-only |
| `engine-fake` + `kraken-record` | ● | Recorded-from-Ghidra fixtures + nightly drift check — the pattern calxgloss lacks (roadmap P33 test ground) |
| `engine-dotnet` + `dotnet/kraken-dotnet` | ○ | Managed code, which calxgloss detects and parks (ADR-0044); value is proof the seam generalizes |
| `kraken-proto` / `schema/` | ● | Neutral wire/anchor/untrusted types = vocabulary comparison with `calxgloss-types` records; `untrusted.rs` has no calxgloss equivalent |
| `kraken-registry` | ● | The unified command surface calxgloss has nothing like (three hand-written surfaces); 78 commands / kind / permission classes |
| `kraken-cli` · `kraken-mcp` · `krakend` · `kraken-ipc` · `kraken-py` | ◐ | calxgloss is CLI+web only; MCP, daemon, Python are its roadmap absences — comparison material for ch. 33 |
| `kraken-host` | ● | Engine selection + `setup` provisioning: calxgloss has one engine, no selection; provisioning contrast matters |
| `kraken-model` (edit log) | ● | calxgloss's git-branches + overlays solve the same problem (authorship, undo, engine-as-cache) differently — ch. 32 head-to-head |
| `kraken-rewrite` | ● | The head-to-head: plan callee-first, translate, difftest under emulation, accept by hand, export workspace — calxgloss's queue→attempt→verify→merge in mirror |
| `kraken-emu` | ● | The differential *execution* oracle calxgloss only gets via Wine FFI baselines (P22/P24 gaps) |
| `kraken-confine` + `kraken-sidecar` + `kraken-procguard` | ◐ | Fail-closed sandbox doctrine (no generated code without Landlock) vs calxgloss's scratch-project verify; ch. 34/35 |
| `kraken-assist` + `kraken-agent` | ● | Interactive/assistant LLM layer vs calxgloss's pipeline LLM loop; the untrusted-data and additive-write rules are stealable |
| `kraken-acp` | ◐ | Terminal agents as *translation backends* for the pipeline — a model-source option calxgloss (Ollama only) doesn't have |
| `kraken-infer` | ◐ | Local-model supervision/hardware fit vs calxgloss's config-endpoints-only stance; supports the local-model premise |
| `kraken-eval` + `corpus/` | ● | The ground-truth eval layer calxgloss explicitly lacks (roadmap P33); truth JSON ↔ calxgloss baseline records |
| `corpus/` PE sets | ● | `corpus/pe` (PE32/32+, TLS callbacks, ordinals, thunks, DLL exports) is the closest external test grid to calxgloss's single fixture DLL |
| `kraken-viewmodel` + `kraken-gui` + widgets + layout | ◐ | Interactive review vs calxgloss's web review UI; only the viewmodel-is-headless + token-map ideas transfer |
| `kraken-layout` | ○ | CFG layout; no calxgloss use |
| `kraken-proto ai` / `ai_usage` + `Meter` | ◐ | Per-run model cost accounting: calxgloss logs `token_usage.json` but no cost/budget caps |
| `docs/` book + 14 design records | ● | Same genre as calxgloss's 55 ADRs; ch. 31-37 lean on them per the file index |
| `xtask`, CI (`ci.yml`/`drift.yml`), `deny.toml`, `scripts/` | ◐ | Repo-engineering discipline worth a paragraph: offline FakeEngine CI, drift checks, reasoned deny waivers |
| `spikes/` | ◐ | Spike-before-ADR practice; rewrite-loop NOTES is ADR 0013's prehistory |
| `CLAUDE.md` | ◐ | Agent-facing repo brief; calxgloss has `AGENTS.md` + glossaries for the same job |
| packaging / AppImage / AUR / signing | ○ | Distribution note only (out of scope per `00-scope-and-method.md`) |
