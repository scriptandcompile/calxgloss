# KRAKEN ↔ calxgloss comparison — scope and method

> Part of the [KRAKEN overview](README.md). Read this first for what is being
> compared and how.

## What KRAKEN is

**KRAKEN** ([Adam-AtlasSoftware/kraken](https://github.com/Adam-AtlasSoftware/kraken))
is an open-source (GPL-3.0-or-later) **reverse-engineering workbench** in Rust,
self-described as "RE Rust rewrites on steroids". It is built on Ghidra's
decompiler behind two engines — a **Java-free native engine** (their own
loader/disassembler over Ghidra's decompiler + Sleigh, ELF and PE, x86/x86-64)
and an optional **full Ghidra engine** (many processors). Its stated long-term
goal is *Rust rewrites of binaries, function by function, checked against the
original* — the same mission as calxgloss.

Key structural facts (as of the revision below):

- **~267k lines of Rust** across **31 crates** in `crates/` (biggest:
  `kraken-viewmodel` 41.6k, `kraken-rewrite` 30.2k, `kraken-gui` 29.9k,
  `kraken-registry` 23.2k, `engine-native` 22.2k);
- **one command registry** (`kraken-registry`) drives the CLI, the MCP server,
  the GUI, the Python module and the agents — one set of commands, with
  **safe / mutating / dangerous permission classes**;
- an **edit log as source of truth**: every rename/type/comment/patch edit is
  logged with its author and is undoable per-change or per-agent-run; the
  Ghidra/native project is treated as a cache;
- **built-in AI assistant** (local models via Ollama/LM Studio/llama.cpp, or
  cloud providers) + **terminal agents** (Claude Code, Codex, Gemini CLI) via
  MCP or ACP;
- a **sandboxed emulator** (`kraken-emu`) used to run originals and patched
  builds side by side, plus Landlock confinement (`kraken-confine`,
  `kraken-procguard`) around the engines;
- a **rewrite pipeline** (`kraken-rewrite`, ~30k lines): plan callee-first
  order, translate one function at a time, differential-test the Rust against
  the original *under emulation*, accept verified functions by hand, export a
  Cargo workspace;
- a **corpus** (`corpus/`) of purpose-built test binaries (C/C++/Rust/dotnet,
  x86/x86-64/ARM/AArch64/RISC-V, O0/O2, stripped/unstripped) with **JSON
  ground truth** (`corpus/truth/`) used by an eval harness (`kraken-eval`);
- **pre-alpha status (0.1a)**, 41 stars, 171 commits, Linux-first
  (Landlock-dependent features refuse to run on macOS/Windows).

## Comparison scope

calxgloss only works on **native Windows PE/DLL targets decompiled to
cross-platform Rust**. KRAKEN covers native ELF+PE (x86/x86-64 native engine;
more via Ghidra engine) plus an experimental .NET engine. Following the same
pattern as the [REA comparison](../rea/00-scope-and-method.md):

**In scope** (every part of KRAKEN, since the whole tool bears on the shared
"binary → verified Rust" mission):

- Analysis engines: native engine, Ghidra engine, .NET engine, fake engine,
  and the engine seam/trait.
- The workbench data model: edit log, undo/attribution, viewmodel, GUI views.
- Automation surface: command registry, CLI, MCP, daemon, IPC, Python.
- AI layer: assistant, model backends, terminal agents (ACP), safety model
  (confinement, untrusted-data rules, additive-write agent policy).
- Emulation and byte patching.
- The rewrite pipeline end to end (the head-to-head chapter).
- Inference helpers, the corpus/truth eval harness, e2e tests, spikes,
  packaging.

**Out of scope** (recorded only):

- GUI pixel-level detail beyond what informs calxgloss's review UI.
- Packaging/AppImage mechanics except as a distribution note.

## Method

1. **Baselines first**: `10-calxgloss-baseline.md` (this repo's capabilities)
   and `20-kraken-inventory.md` (complete KRAKEN surface).
2. **Per-domain files** (`3x-*.md`): each covers one capability domain. First
   they state what KRAKEN does concretely — naming crates, files, commands and
   design decisions — then they give a direct **calxgloss comparison**
   section: overlap, calxgloss-only, KRAKEN-only, verdict.
3. **Master index** (`README.md`): executive summary, capability matrix, and a
   gap analysis of ideas worth stealing (and what KRAKEN's choices confirm
   about calxgloss's own).

Every claim points to a `file:line` or doc path. KRAKEN claims use the clone
at `/tmp/opencode/kraken` (revision below); calxgloss claims use this repo
(ADRs, crates, docs).

## KRAKEN revision reviewed

```
git clone --depth 50 of https://github.com/Adam-AtlasSoftware/kraken
commit 68718c6ab461925849668363a339e75b462041d2  (2026-10-28)
"Give emulated programs only their own libraries, not the host file system"
```

Upstream history at review time: 171 commits, `main` branch, pre-alpha 0.1a.
The clone is shallow (last 50 commits); history older than that was checked
only via GitHub where needed.

Facts below cite KRAKEN paths relative to that clone root.

## File index

| File | Domain |
|------|--------|
| `00-scope-and-method.md` | this file |
| `10-calxgloss-baseline.md` | calxgloss capability inventory (comparison baseline) |
| `20-kraken-inventory.md` | complete KRAKEN surface (crates, commands, docs, corpus) |
| `31-analysis-engines.md` | native/Ghidra/.NET engines, the engine seam |
| `32-edit-log-undo-gui.md` | edit log as source of truth, undo, viewmodel, GUI |
| `33-automation-command-registry.md` | one registry, CLI, MCP, daemon, Python |
| `34-ai-assistant-agents-safety.md` | assistant, models, agents, safety model |
| `35-emulation-patching.md` | sandboxed emulator, patching, differential runs |
| `36-rewrite-pipeline.md` | binary → Rust: plan, translate, difftest, accept, export |
| `37-inference-corpus-eval.md` | kraken-infer, corpus/truth, eval harness, spikes |
| `README.md` | executive summary, capability matrix, gap analysis |
