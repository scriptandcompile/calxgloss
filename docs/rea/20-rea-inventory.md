# REA complete inventory + native-relevance triage

> Part of the [REA overview](README.md). Every capability REA ships, as a triage
> table for the comparison. Sources: `README.md` "What you can analyze" table,
> `docs/index.md`, `.agents/skills/`, `src/cliCommandNames.ts` (272 lines: CLI
> command ↔ MCP tool mapping), `docs/mcp-contracts.md`. REA clone:
> `/tmp/opencode/rea` @ `28a33ca` (2026-10-23).

**Triage legend**: ● = in comparison scope (native + relevant), ◐ = adjacent,
worth a paragraph, ○ = out of scope.

## 1. Skills (`.agents/skills/`)

| Skill | Lines | What it is | Triage |
|-------|-------|-----------|--------|
| `reverse-engineer-anything/SKILL.md` | 452 | The user-facing RE skill (v45): when to use REA, connect/recovery discipline, target routing, evidence rules. +6 reference files (~1200 lines): `connection-and-recovery`, `evidence-workflows`, `native-and-artifacts` (532), `javascript-applications`, `android-applications`, `runtime-observation` | ● |
| `rea-tool-design` | 20 | Dev skill: pointer to `docs/tool-design.md` philosophy | ◐ |
| `rea-ci-tests-audit` | 112 | Dev skill: audit REA's own CI/test measurement | ○ (dev-only) |
| `rea-changelog-update` | 134 | Dev skill: REA release-notes workflow | ○ (dev-only) |
| `rea-analysis-optimization` | 113 | Dev skill: optimize REA's analysis performance; +`kuna-case-study.md` reference | ◐ (Kuna overlap with calxgloss!) |

## 2. Deep native analysis (the engine/provider surface) — ●

MCP tools (from `src/cliCommandNames.ts`): `open_binary`, `close_binary`,
`binary_session`, `binary_overview`, `analyze`, `analyze_function`,
`decompile`/`procedure_pseudo_code`, `batch_decompile`, `procedure_assembly`,
`read_function_instructions`, `instructions`, `list_procedures`,
`search_procedures`, `procedure_info`, `procedure_address`,
`resolve_containing_procedure`, `list_segments`, `list_names`,
`get_navigation_context`, `goto_address`, `current_address`, `next_address`,
`prev_address`, `procedure_callers`, `procedure_callees`, `procedure_references`,
`find_xrefs_to_name`, `get_call_graph`, `build_call_path`, `trace_call_path`,
`trace`, `list_strings`, `search_strings`, `inspect_address_context`,
`address_name`, `set_address_name(s)`, `comment`/`set_comment`,
`inline_comment`/`set_inline_comment`, `list_bookmarks`, `set/unset_bookmark`,
`list_documents`, `current_document`.

Providers: **Hopper** (default, can auto-install), **Ghidra** (+ arch guides:
DOS 16-bit, MIPS, PPC, RISC-V, PSP, NativeAOT), **IDA** (+ optional native MCP
bridge), **Kuna** (`docs/kuna-provider.md`), **Cutter** bridge
(`list_cutter_sessions`, `cutter_command`), **Rizin** (`execute_rizin_command`),
**objdump** (`inspect_with_objdump`), **GDB** (`debug-with-gdb`).
Docs: `native-investigation.md`, `ghidra-provider.md`, `kuna-provider.md`,
`ida-provider.md`, `reverse-engineering-tools.md`, `ghidra-*.md`,
`windows-ghidra-p0.md`.

## 3. Native artifact intelligence — ●

`binary_overview`; ELF offline layout (`binary-diagnostics.md`, pwntools);
recorded Linux crashes (`recorded-crashes.md`, GDB/pwndbg); Go embedded module
metadata (`go-binaries.md`); Rust cargo-auditable crate graph (`rust-binaries.md`);
PE Authenticode certificates (`pe-certificates.md`); ELF notes/build-id
(`elf-notes.md`); IL2CPP `global-metadata.dat` decoding (`il2cpp-metadata.md`);
GPU code objects CUDA/HIP/PTX (`gpu-code-objects.md`); Godot PCK archives
(`godot-pck.md`); Erlang BEAM chunks (`erlang-beam.md`); Mach-O + bundles +
plists + ObjC metadata (`apple-application-analysis.md`, `inspect_macho`,
`get_objc_classes`, `inspect_plist`, `demangle_swift`); firmware regions via
Binwalk/Unblob (`firmware-analysis.md`); raw binaries (`raw-binary.md`);
model artifacts GGUF/safetensors (`model-artifacts.md`, ◐); SQLite (○).

## 4. Reconstruction & evidence workflow — ●

Evidence contract (findings always carry evidence + limitations + unknowns;
`mcp-contracts.md`); `export_evidence_bundle` / `import_evidence_bundle` /
`get_evidence_bundle`; unknown tracking `list_unknowns` / `record_unknown` /
`update_unknown` / `verify_unknown_resolution`; `compare_functions`,
`compare_artifacts`, `find_changed_behavior`, `compare` (version diffing);
`verify_reconstruction`; `native-function-matching.md`;
`reconstruction-coverage.md`, `reconstruction-readiness.md`,
`reconstruction-obligation-ledgers.md` + CLI
`build-reconstruction-obligation-ledger`, `evaluate-reconstruction-coverage`;
showcases: DX-Ball sound-pan, TH04 DOS bullet-ring (`website/`, `README.md`).

## 5. Runtime observation — ●

Frida: `start_frida_session`, `list_frida_devices/processes`,
`instrument_with_frida`, `load_frida_script`, `resume_frida_session`,
`frida_session_status`, `close_frida_session` + `frida-instrumentation.md` +
`src/frida/`. Debuggers: `gdb_console`, `gdb_session_status`,
`rizin_debug_command`, `rizin_debug_session_status`. Process behavior:
`capture_process_scenario`, `compare_process_captures` (PTY runs, output,
interactions, filesystem effects; `process-capture.md`). Native desktop:
`observe-native-ui`, `observe-native-calls`, `capture-native-ui-scenario`
(`desktop-applications.md`). Correlation: `correlate_static_and_runtime`,
`runtime-observation` reference file. Linux crash forensics (see §3).

## 6. Managed/other ecosystems — ○ (inventory only)

- **JavaScript/Electron/web**: ~25 tools — `analyze-javascript-application`,
  ASAR, source maps, routes, IPC, fuses, `observe-javascript-runtime`,
  `reconcile-javascript-runtime`, `trace-javascript-semantics`,
  `compare-source-to-bundle`, browser tools (`inspect-web-page`,
  `capture-web-screenshot`…), HAR/SAZ captures. 8 docs.
- **.NET**: `inspect-managed-members`, `inspect-managed-native-boundaries`,
  `compare-managed-members`, `import-managed-reconstruction`; NativeAOT via Ghidra.
- **Android**: JADX class/method inspection, Apktool resources, ADB (30+
  commands), APK signature verification, Flutter AOT identification, JEB bridge,
  HarmonyOS graph projection.
- **App graphs**: `project-android/apple/harmony/managed-application-graph`,
  `trace-application-feature`, `compare-application-versions`.
- **Captures**: mitmproxy, tshark/pcap, packet field filters, sigrok logic
  signals, EVM bytecode, WASM artifacts (`compare_wasm_interfaces`).

## 7. Agent-layer & product plumbing — ● (shapes harness design)

`npx rea-agents setup` (registers MCP + skill for 14+ agents: Claude Code,
Codex, Cursor, Gemini CLI, opencode…), `rea doctor --client X`,
connection/recovery ladder in the skill, compact-vs-full MCP input schema
profiles, `capabilities`/`providers`/`server.json` discovery, MCP prompts
(`docs/mcp-prompts.md`), error contract schema
(`docs/user-visible-errors.csv`, `error-contract.schema.json`),
`docs/agent-environments.md`, `docs/design/limits-and-recovery.md`.

## 8. Repo engineering (REA's own quality machinery) — ◐

`docs/testing.md`, `docs/tool-design.md`, `docs/limits-and-recovery.md`,
`docs/roadmap.md`, mutation-testing configs (stryker), `docs/verification/`
(28 dated verification reports as json+md pairs), `experiments/analysis-efficiency/`
(benchmark harness: question files, measure.mjs, oracles), `CHANGELOG.md`,
release-please.
