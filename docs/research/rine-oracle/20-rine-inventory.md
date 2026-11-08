# rine inventory — execution model, dispatch seam, testing, observability, hooking

> Part of the [rine-oracle overview](README.md). Every claim verified against
> rine at **`da46c32` (v0.1.4)**. "Missing" items were confirmed by grep/read,
> not inferred from absence of docs — see
> [00 §stale-document traps](00-scope-and-method.md) for why that matters.

## 1. Execution and memory model — native, in-process, no syscall layer

- Guest code runs **natively in the loader process**:
  `crates/rine-runtime-core/src/loader/entry.rs:40` `execute()` dispatches to
  a naked-asm trampoline (`entry.rs:118` `trampoline_x64`,
  `core::arch::naked_asm!`) that sets up the 32-byte Windows shadow space. No
  interpreter, no VM, no seccomp/SIGSYS interception anywhere in the tree.
- Arch gate: PE32+ needs x86_64 host, PE32 needs i686 host
  (`entry.rs:26` `EntryError::HostArchMismatch`); 32-bit guests are handed to
  a separate `rine32` binary (`crates/rine/src/commands/run.rs:365,607,689`,
  env override `RINE_RINE32_HELPER` at `run.rs:675`).
- Image loading: `loader/memory.rs:83` `LoadedImage::load` → `alloc_image:175`
  (`mmap` at the **preferred base** with `MAP_FIXED_NOREPLACE`),
  `copy_sections:210`, `apply_relocations:273`, `protect:155` (page
  protections applied after IAT patching).
- A run never returns normally: `run.rs:546` ends in `std::process::exit`;
  guest threads are real host threads; a fault in guest code kills the
  process via SIGSEGV-class handlers that `_exit(128 + signal)`
  (`crates/platform/win-common/rine-common-kernel32/src/process.rs:597-623`).

## 2. The dispatch seam — load-time IAT patching, nothing at call time

- `crates/rine-runtime-core/src/loader/resolver.rs:79` `resolve_imports`
  looks each import up in the registry and writes the **host Rust function
  pointer directly into the guest IAT** (`write_iat_entry:288`). After load, a
  guest call is a plain direct call — no trampoline, proxy, or interposer
  sits between guest and implementation.
- Hard failure on gaps: `ResolverError::UnimplementedImports`
  (`resolver.rs:19`, raised at `:228`) aborts before the entry point runs.
  Delay imports are **not implemented** — `resolve_delay_imports:252` only
  warns (goblin 0.10 doesn't parse the delay directory).
- Registry: `crates/rine-dlls/src/registry.rs` — `WinApiFunc` (`:22`,
  `extern "win64"`), `DllRegistry` (`:31`), `LookupResult {Found, Partial,
  Stub, Unimplemented}` (`:104`), `register_plugin_factory:142`,
  `register_dynamic_provider_library:163`. The unimplemented fallback
  `stub_function` (`:488,494`) prints a message and calls **`abort()`**
  (`:490,496`).
- Layering: `crates/platform/win-common/rine-common-<dll>` hold plain Rust
  implementations; `win64-dll/rine64-<dll>` and `win32-dll/rine32-<dll>` are
  thin calling-convention shims (`rlib` + `cdylib`).
- Codegen is the keystone: the attribute macros in `crates/rine-dll-attrs`
  are passthroughs; `crates/rine-dll-build/src/lib.rs:19`
  `generate_metadata_code()` `syn`-parses the attributes in build scripts and
  emits `OUT_DIR/dll_plugin_generated{,_stubs,_partials}.rs`, which plugin
  crates `include!` (e.g. `rine64-kernel32/src/lib.rs:18-36`) and register
  via `rine_dlls::export_dynamic_provider!`. **Every API crosses this one
  generated seam** — that is where recording wrappers and spy wrappers would
  attach.
- Stub representation: zero `todo!()`/`unimplemented!()`/Wine-style `fixme:`.
  Stubs are `#[stubbed]` functions that `tracing::warn!` and return 0
  (examples: `rine64-kernel32/src/process.rs:40,87,135,193,294,337`;
  `rine-common-kernel32/src/process.rs:356,387` — `load_library` and
  `get_proc_address` **return 0**).
- Attribute counts at HEAD: `implemented` 214, `partial` 328, `stubbed` 74,
  **`ordinal` 0** — `#[ordinal]` is parsed (`rine-dll-build/src/lib.rs:597`)
  but never emitted, so **ordinal exports are effectively unsupported**.
- Published coverage (`docs/data/dll-support.json`, generated 2026-05-29, so
  stale-low): **308 functions across 8 DLLs — 107 implemented / 164 partial /
  37 stubbed**. kernel32 124, user32 89, msvcrt 48, gdi32 16, advapi32 9,
  shell32 8, **ntdll 8**, comdlg32 6. There is **no syscall/Zw layer** — the
  README's "translates Windows NT syscalls to Linux syscalls" describes the
  *shape* (DLL impls call `nix`/`libc`), not an ntdll interception layer.

## 3. Testing story today

- Integration tests are **subprocess + exit code + exact stdout**:
  `crates/rine/tests/integration/` (~515 lines; `common.rs:58` `run_rine`,
  `:118` `assert_run`). Fixtures are 36 C programs
  (`tests/fixtures/src/{core,system,ui}`) built by
  `scripts/build-integration-prereqs.sh`, arch via `RINE_FIXTURE_ARCH`.
  `tests/fixtures/src/rine_test.h:1-3` admits fixtures avoid `printf`
  "because of locale machinery that rine doesn't yet support" — **the
  fixtures are written to rine's limitations, not to Windows semantics**, and
  the expected string lives in the Rust test while the fixture printed `ok`
  about itself.
- Unit tests are plentiful per crate (user32 195, kernel32 165, rine 86, …)
  but process-global state forces serialization (`serial_test`/`TEST_MUTEX`).
- CI (`​.github/workflows/ci.yml`): clippy `-D warnings`, unit tests, then
  `xvfb-run` integration (GUI needs a display), x86 subset. `Cargo.toml:52-71`
  excludes `rine-runtime-core`, `rine32`, `rine-dll-build`, `rine-dev-bridge`
  and all `win-common` crates from `default-members` — a bare root `cargo
  test` skips them.
- **Missing:** no conformance-suite runner, no Wine-conformance port, no
  golden API-trace baselines, no differential runner against real Windows or
  Wine.
- The unmerged `golden-harness` branch (tip `140ff05`) adds
  `crates/rine-test-utils` — byte-exact PNG goldens plus canonical-env knobs
  (`RINE_CANONICAL_OS_BUILD`, `RINE_DPI_SCALE_PERCENT`,
  `RINE_CANONICAL_LOCALE` in that branch's `environment.rs:59-66`). Right
  instinct (named, stampable inputs), but it is a **theming regression
  harness**, not an API oracle.

## 4. Observability — lifecycle events exist, no per-call telemetry

- The one hook interface: `crates/rine-types/src/dev_hooks.rs:46` `trait
  DevHook`, a process-wide `OnceLock` slot (`:74`), fired by the
  `dev_notify!` macro (`:94`). Methods are **lifecycle only**: handle
  create/close, thread create/exit, TLS alloc/free, memory alloc/free,
  dialog open/result, registry metrics, process exit. **No hook anywhere
  carries an API name, arguments, or return value.**
- Transport exists and is good: `crates/rine-channel/src/lib.rs:16`
  `enum DevEvent` (`PeLoaded`, `ConfigLoaded`, `ImportsResolved`,
  `DllRegistryMetrics`, handle/thread/TLS/memory/snapshot/dialog,
  `ProcessExited`, `OutputData`) over a Unix socket, 4-byte length prefix +
  JSON. **No `ApiCall` variant.** `RINE_DEV_SOCKET` +
  `crates/rine-dev-bridge/src/lib.rs:51` wire it into a run.
- Dev-only memory dump: `run.rs:242` `write_memory_snapshot_files` →
  `$TMPDIR/rine-memory-snapshot-<pid>-<ts>/{snapshot.bin,snapshot.json}`,
  format `rine-memory-snapshot-v1` (`run.rs:296`) — a prototype for state
  queries, not a query API.
- `crates/rine-dev` and `crates/rine-config` are Tauri desktop apps; `--dev`
  re-execs the dev app which supervises `rine` as a child
  (`rine-dev/src/main.rs:310,335`). Nothing persists an event trace to disk.
- Logging gap: `crates/rine/src/main.rs:18` (and `rine32/src/main.rs`) build
  a `tracing_subscriber` **with no `EnvFilter`** — `RUST_LOG` has no effect on
  the runtime.
- GUI seam: `rine-common-user32/src/backend/contracts.rs:3` `WindowBackend`,
  features `backend-native` (winit/x11rb) vs `backend-emulated` (a separate
  window-host process over `RINE_WINDOW_HOST_SOCKET`,
  `crates/rine/src/commands/window_host.rs:22`) — but the host uses winit, so
  **even emulated mode needs a display**; CI is always under `xvfb-run`.

## 5. Mocking, interposition, hooking — one real seam, and only one

**Exists:**

- **Dynamic provider `.so`s** — the only interposition mechanism:
  `crates/rine-dlls/src/dynamic_provider.rs`, ABI constant
  `DYNAMIC_PROVIDER_ABI_VERSION = 1` (`:12`), entrypoint symbol
  `rine_dynamic_provider_v1` (`:13`), `#[repr(C)]` descriptor (`:56-67`),
  `libloading` with ABI/arch validation (`:316-331`), discovered from
  `RINE_PLUGIN_DIR` (`crates/rine/src/commands/run.rs:45,118`) and registered
  per imported DLL (`run.rs:157`). This is out-of-tree wrapping of a whole
  DLL — genuinely nicer ergonomics than Wine's builtin/native overrides.
- In-process substitution via `DllRegistry::register_plugin_factory`
  (`registry.rs:142`) — a wrapper export can call through to the real one,
  but only for imported DLLs and only at load time.
- The repo's one behavioral mock: env `RINE_DIALOG_TEST_PATH` short-circuits
  common dialogs (`rine-common-comdlg32/src/pick.rs:14`), plus theme/debug
  env knobs (`RINE_DIALOG_THEME`, `RINE_USER32_DEBUG`, …).

**Missing:**

- No runtime module loading to mock *against*: `LoadLibraryA/W`,
  `GetProcAddress`, `FreeLibrary`, `GetModuleHandleA/W` are stubs returning 0
  (`rine64-kernel32/src/process.rs:40-337`,
  `rine-common-kernel32/src/process.rs:356,387`). No search path, no
  `DllMain` attach/detach, no forwarded exports.
- No import-table re-patching after load, no Detours-style hook API, no IAT
  walk utility exposed to tests.
- `DllConfig { search_order, force_stub }` (`crates/rine-types/src/config.rs:181`)
  is parsed but **never read outside tests** — you cannot force a DLL to
  stub mode from config.

## 6. Hard blockers for oracle use (state, not coverage)

- **State leaks to `$HOME` keyed by the guest's absolute path**:
  `config_path`/`registry_path`/`app_hash` hash the canonicalized absolute exe
  path (`crates/rine-types/src/config.rs:240-277`), and defaults are written
  to disk on first run (`shared/registry-runtime/src/lib.rs:256`
  `REGISTRY_STORE: OnceLock` + save helpers). Re-running a clean baseline
  means deleting `~/.rine`.
- **Path translation is hardcoded**: `rine-common-kernel32/src/file.rs:632`
  `translate_win_path` maps `X:\rest` → `~/.rine/drives/x/rest` (`:654`); the
  configurable `PathTranslator` (`crates/rine/src/subsys/filesystem.rs:51`)
  is dead code, so `[filesystem.drives]` and `case_insensitive` are ignored.
- **Process-wide singletons make one process = one guest**: `HANDLE_TABLE`
  (`crates/rine-types/src/handles/handle_tables.rs:91`), version globals
  (`crates/rine-types/src/os.rs`), window registries, GDI state
  (`rine-common-gdi32/src/state.rs`), `TLS_BITMAP`, environment runtime,
  `VIRTUAL_REGIONS`/`DEFAULT_HEAP` (`rine-common-kernel32/src/memory.rs:60,65`) —
  plus `std::process::exit` and the `OnceLock` hook slot.
- No clock/RNG control (`chrono` used directly), no `EnvFilter`, GUI fixtures
  need Xvfb.

## 7. What a harness could use today, ranked

1. Out-of-tree interposition via a provider `.so` in `RINE_PLUGIN_DIR` —
   works without touching rine's source, records name/args/return if the
   provider wraps the real impl.
2. Subprocess harness exactly as `tests/integration/common.rs:58-152` does.
3. A custom in-process runner assembled from `rine-runtime-core` +
   `rine-dlls` + `rine-types`, replicating `run.rs:347-546` (config, registry
   store, TEB, window host, dynamic providers, version info).
4. Telemetry extension: `DevHook` methods + a `DevEvent::ApiCall` variant —
   the socket plumbing already carries records; it lacks the event.

**Bottom line:** a real, inspectable PE loader, a documented registry, and a
working `dlopen` interposition ABI — enough to build an API-call recorder.
No call-time interception, no per-API tracing, no embedding API, no hermetic
runs, and not enough implemented surface to run a real harness EXE's import
set. rine today is a *narrow* behavioral harness for ~107 implemented APIs;
[30](30-oracle-gap-analysis.md) lays out what closes that.
