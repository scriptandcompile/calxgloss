# Calxgloss

Reverse Engineering Harness

**Name etymology:** *Calx* (the pure, calcined residue left after burning away impurities) + *gloss* (the layer of translation and interpretation between languages). In alchemy, calcination burns away everything non-essential, leaving only the irreducible form. That is what this harness does: it burns away the assembly to reveal the essential logic, then adds a gloss — a Rust translation layer — to make it readable, buildable, and cross-platform.

## Objective

Build an agent harness that leverages GhidraMCP to reverse engineer project executables and DLLs, transforming disassembled code into **cross-platform Rust source code** through a test-driven decompilation workflow. The output runs on Windows, macOS, and Linux with identical observable behavior.

## Core Philosophy

1. **Functional equivalence over binary precision** — reproduce observable behavior, not instruction sequences
2. **Cross-platform by default** — Windows APIs and libraries map to their closest cross-platform Rust equivalents
3. **Test-driven decompilation** — tests capture original behavior; Rust code must pass those tests
4. **Incremental restitching** — swap in Rust implementations one at a time, verifying each swap
5. **LLM-first, discard-when-wrong** — the LLM is the primary engine. Use it aggressively and freely. Throwing away incorrect LLM output is cheap when hosted locally; the cost of not using it is far higher
6. **Source-control backed reversibility** — every unit of work lands as a commit on its function's attempt branch. The system is always restorable, diffable, and reviewable. No state is lost.
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

## LLM Orchestration & Fault Tolerance

**The LLM is the primary engine.** It is locally hosted, so the marginal cost of asking it to try, fail, and retry is near-zero. The system is designed to use the LLM constantly, aggressively, and without restraint — discarding failed work is the normal path.

### LLM-First Principle

- **Ask, don't guess.** Every translation decision goes through the LLM. Even simple `mov` → `+` mappings are confirmed.
- **Fail fast, discard freely.** If the LLM produces incorrect code (tests fail, compilation fails, behavior diverges), the branch is abandoned and a new attempt is made. This is the expected flow, not an exception.
- **Multiple attempts per function.** A single function may go through 3–10+ LLM rounds: initial translation, first test run, fix attempts, refactoring, edge-case handling. Each round is a new branch, a new commit.
- **Context window management.** The LLM's context window is a resource to be managed, not a constraint to be avoided. When context is exhausted, the system splits the work and retries.

### Fault Detection & Recovery

The harness continuously monitors LLM interactions and detects common failure modes:

| Fault | Detection | Recovery |
|-------|-----------|----------|
| **Context window exceeded** | LLM returns error / truncated response | Split the function into smaller chunks; retry with focused context (only the relevant basic block or control-flow region) |
| **LLM hallucination** (invents non-existent APIs, wrong function signatures) | Test failure, compilation error, Ghidra cross-reference mismatch | Branch off from the last known good commit; prompt the LLM with Ghidra's actual symbols and disassembly as ground truth |
| **Infinite compilation-fix loops** | Same prompt → same bad output repeated 3+ times | Escalate to a different prompt strategy (e.g., ask for pseudo-C from Ghidra decompiler instead of raw disassembly; or ask for a minimal reproducer first) |
| **Wrong behavior but passes tests** | Tests are insufficient / missing edge cases | Enrich the test suite with Ghidra-derived edge cases (branch conditions, boundary checks); retry with expanded test coverage |
| **LLM produces code that compiles but diverges on input X** | Test suite covers more inputs than the LLM saw | Feed the failing test case back to the LLM as a concrete example; ask it to patch |
| **Resource exhaustion** (local LLM OOM, GPU swap) | System monitoring detects high memory/CPU | Reduce context size, switch to smaller model, or queue work for later |
| **Slow responses** (large context, model overloaded) | Latency exceeds threshold | Stream the prompt into smaller chunks; use the smaller/faster model for simple tasks, reserve large-context model for complex translations |
| **Prompt corruption / formatting errors** | JSON parse failure, missing fields in LLM output | Retry with stricter output schema; use structured output enforcement |

### Context Management Strategy

The harness manages LLM context in tiers:

| Tier | Content | When Used |
|------|---------|-----------|
| **Tier 0 — Function stub** | Function name, signature, call graph neighbors | Initial translation attempt, simple functions |
| **Tier 1 — Disassembly + decompiler** | Full disassembly, Ghidra pseudo-C, type info | Main translation path |
| **Tier 2 — Disassembly + decompiler + tests** | Tier 1 + baseline test results + failing test cases | Debugging failures, fixing incorrect translations |
| **Tier 3 — Module context** | Tier 2 + neighboring functions + shared data structures | Complex inter-function translations, data flow analysis |
| **Tier 4 — Full module + crate shims** | Tier 3 + shim layer code + PAL trait definitions | Restitching, integration-level work |

**Rule:** Always start with the smallest tier that can do the job. Escalate only when the LLM reports failure.

### Branching Strategy for LLM Work

```
main
│
├── re/phase1_dll_classification          # DLL classification unit
├── re/phase1_shim_wgpu                   # wgpu shim layer unit
├── re/phase1_shim_cpal                   # cpal shim layer unit
├── re/phase2_directx_render_function     # DirectX render function RE unit
│   ├── re/phase2_directx_render_function # initial attempt (LLM attempt 1)
│   ├── re/phase2_directx_render_function/v2 # context split retry (LLM attempt 2)
│   └── re/phase2_directx_render_function/v3 # test enrichment retry (LLM attempt 3)
├── re/phase2_game_logic_function         # Game logic function RE unit
│   └── re/phase2_game_logic_function/v2  # LLM attempt 2 (original failed)
└── re/phase2_audio_function              # Audio function RE unit
```

Every LLM attempt is a branch. Failed branches are kept (they are not deleted) because they may contain useful patterns for future attempts. Only after a human approves the final version does the work get merged.

## Source-Control Backed Reversibility

**Every unit of work is version-controlled. Nothing is ever lost.**

### Unit of Work Definition

A **unit of work** is the smallest atomic piece of the reverse engineering process. Each unit produces:
- A Git branch (named by phase + target + attempt)
- A commit (or series of commits if the LLM needed multiple fixes)
- A review artifact (justification document, diff, test results)

| Unit Type | Description | Example Branch |
|-----------|-------------|----------------|
| DLL classification | Classification output for one DLL | `re/classify_msvbvm60` |
| Shim layer | One crate shim implementation | `re/shim_wgpu` |
| Function translation | One function translated to Rust | `re/func_DrawPrimitive` |
| Test case addition | New baseline test discovered | `re/test_DirectX_present_0x80070005` |
| PAL trait addition | New abstraction trait | `re/pal_trait_GraphicsDevice` |
| Integration step | Restitching a batch of functions | `re/restitch_batch_001` |
| Bug fix | Fixing incorrect translation | `re/fix_game_logic_loop_002` |

### Dependency-Aware Branching

Branches are created with awareness of their dependencies:

1. **Shim layers branch first.** All shim layer branches (`re/shim_wgpu`, `re/shim_cpal`) are created and merged before functions that depend on them.
2. **PAL trait branches precede function branches.** A trait must exist before functions that call it.
3. **DLL classification branches precede all.** Classification determines what gets shimmed vs. reverse engineered.
4. **Dependent functions branch from their dependencies.** A function that calls another function in the same DLL branches from the translated dependency.

```
Dependency Graph → Branch Creation Order:

    [DLL Classify] → [Shim wgpu] → [PAL GraphicsDevice] → [func DirectX_CreateDevice]
                                                         → [func DirectX_Present]
                                                         → [func DirectX_DrawPrimitive]
                                                              ↓
    [DLL Classify] → [Shim cpal] → [PAL AudioDevice] → [func Audio_Play]
                                                         → [func Audio_Stop]
```

### Commit Message Convention

Every commit follows a structured format for traceability:

```
re/<phase>/<unit>: <brief description>

Attempt: <N> of <total-attempts> (or "last" if not known)
Prompt tier: <tier>
Dependencies: <list of merged branches this depends on>
Tests: <count> baseline tests, <count> verification tests
Passing: <yes/no> — if no, reason for branch continuation
LLM model: <model name and version>
Context size: <N> tokens
```

Example:
```
re/func/DirectX_DrawPrimitive: translate DrawPrimitive to wgpu encoder.draw()

Attempt: 3 of last
Prompt tier: 2
Dependencies: re/pal/trait_GraphicsDevice, re/shim/wgpu
Tests: 47 baseline tests, 12 verification tests
Passing: yes
LLM model: qwen3-235b-a22b
Context size: 128k tokens
```

### No Deletion Policy

- **Failed branches are never deleted.** They remain as historical record and may contain useful patterns.
- **Revert commits are preferred over force-push.** Changes are undone via revert commits, preserving the full history.
- **The main branch always contains only reviewed, accepted work.** Unreviewed work lives exclusively on feature branches.

## Web Review UI

A web-based interface provides structured human review of every unit of work. The LLM is used relentlessly; the human is the quality gate.

### UI Layout

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  RE_compile Review Dashboard                                                │
│                                                                             │
│  ┌─────────────────┐  ┌───────────────────────────────────────────────────┐ │
│  │  Dependency      │  │  Unit of Work Details                             │ │
│  │  Graph           │  │                                                   │ │
│  │                  │  │  Function: DirectX_DrawPrimitive                  │ │
│  │  ● DLL Classify  │  │  Branch: re/func/DirectX_DrawPrimitive/v3        │ │
│  │    │             │  │  Status: ✅ Accepted                              │ │
│  │    ├─ shim/wgpu  │  │                                                   │ │
│  │    ├─ shim/cpal  │  │  ┌─ Justification ─────────────────────────┐     │ │
│  │    └─ PAL traits │  │  │ • Disassembly shows 47 instructions     │     │ │
│  │                  │  │  │ • Ghidra decompiler output matches       │     │ │
│  │  [Expand/Collapse]│  │    wgpu encoder.draw() parameters          │     │ │
│  │                  │  │  • 47 baseline tests pass                   │     │ │
│  │  ┌─ Queued       │  │  • 12 verification tests pass               │     │ │
│  │     Work Queue    │  │  • Attempt 3 — failed at v1 (missing      │     │ │
│  │    ● func_023     │  │      texture view), failed at v2 (wrong   │     │ │
│  │    ● func_047     │  │      shader constant mapping)              │     │ │
│  │    ● shim_fmod    │  │  └────────────────────────────────────────┘     │ │
│  │                  │  │                                                   │ │
│  │  ┌─ Recent       │  │  ┌─ Diff View ────────────────────────────┐     │ │
│  │     Activity      │  │  │ +fn draw_primitive(...) {              │     │ │
│  │  ● func_022       │  │  │     encoder.draw(...);                 │     │ │
│  │     accepted ✓    │  │  │     // Maps: SetTexture → bind_group   │     │ │
│  │  ● func_023       │  │  │     // 47 instructions → 23 lines Rust │     │ │
│  │     pending ◉     │  │  │ }                                      │     │ │
│  │  ● shim_cpal      │  │  └────────────────────────────────────────┘     │ │
│  │     merged ──     │  │                                                   │ │
│  │                  │  │  ┌─ Test Results ─────────────────────────┐     │ │
│  │                  │  │  │ Baseline:  47/47 passed ✅              │     │ │
│  │                  │  │  │ Verifier:  12/12 passed ✅              │     │ │
│  │                  │  │  │ CI Linux:  build + tests passed ✅      │     │ │
│  │                  │  │  │ CI macOS:  build + tests passed ✅      │     │ │
│  │                  │  │  └────────────────────────────────────────┘     │ │
│  │                  │  │                                                   │ │
│  │                  │  │  [✅ Accept] [🔀 Send Back] [✏️ Request Patch]   │ │
│  └─────────────────┘  │  [📋 View All Attempts] [📝 View Ghidra Context] │ │
│                        └───────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Review Actions

| Action | Effect |
|--------|--------|
| **Accept** | Merge branch into `main`. Unit is complete. |
| **Send Back** | Return to LLM with reviewer comments. New attempt created on new branch. |
| **Request Patch** | Ask LLM to fix a specific issue (identified in the UI). New attempt on new branch. |
| **View All Attempts** | See the full sequence of LLM attempts for this unit, including diffs from each. |
| **View Ghidra Context** | See the original disassembly, decompiler output, and Ghidra annotations that informed the translation. |

### Justification Requirements

Every unit of work must present the following to the human reviewer:

1. **What was translated** — original function address, name, disassembly size, decompiler output reference
2. **How it was translated** — which PAL traits, which crate shims, which Rust idioms were used
3. **Evidence of correctness** — test results (baseline pass rate, verification pass rate, CI status)
4. **Attempt history** — how many LLM attempts were needed, what failed at each stage
5. **Confidence assessment** — the LLM's own confidence score (based on test coverage and disassembly clarity)
6. **Known gaps** — any behavior that could not be verified (e.g., undocumented side effects)

### Dependency Visualization

The UI renders a dependency graph showing:
- Which shim layers each function depends on
- Which PAL traits each function uses
- Which translated functions call other translated functions (vs. FFI)
- The merge path: how each branch traces back to its base commits

This lets the reviewer understand not just whether one unit is correct, but how it fits into the whole.

### Review Queue Management

- Units are presented in dependency order (no function is reviewed before its dependencies are accepted)
- The reviewer can reorder the queue manually for batch review
- Units that have been sitting in the queue >24 hours are highlighted as stale
- A global "Accept All Pending" button accepts everything in dependency order

## Cross-Platform Translation Strategy

The harness maintains a **Platform Abstraction Layer (PAL)** that maps Windows APIs to cross-platform Rust equivalents. During translation, every Windows API call is tagged and replaced with the appropriate PAL trait method.

### Windows Library → Rust Crate Mapping

| Windows Library | API Category | Cross-Platform Rust Equivalent | PAL Trait |
|----------------|-------------|-------------------------------|-----------|
| **DirectX 9** | 3D Graphics | `wgpu` (Vulkan/Metal/DX12 backend) | `GraphicsDevice` |
| **DirectX 10/11/12** | 3D Graphics | `wgpu` | `GraphicsDevice` |
| **Direct2D/DirectWrite** | 2D Graphics, Text | `tiny-skia` + `rusttype`/`skrifa` | `Graphics2D`, `FontRenderer` |
| **GDI/GDI+** | 2D Graphics, BitBlt | `tiny-skia`, `image` crate | `GraphicsDevice` (2D path) |
| **Win32 GUI** | Windows, Controls, Messages | `winit` + `egui`/`slint`/`iced` | `WindowManager`, `Widget` |
| **DirectSound** | Audio Playback | `cpal`, `rodio` | `AudioDevice` |
| **XAudio2** | Audio Playback | `cpal` | `AudioDevice` |
| **COM** | Component Object Model | `comfy` crate, direct vtable calls | `ComObject` |
| **Win32 Core** | Threading, Sync, Memory | `std::thread`, `std::sync`, `mmap` | `Thread`, `Mutex`, `MemoryPool` |
| **Win32 File/Registry** | File I/O, Registry | `std::fs`, `directories` crate | `FileSystem`, `SettingsStore` |
| **Win32 Networking** | Sockets, WinSock | `tokio`, `std::net` | `NetworkStack` |
| **VB6 Runtime** (`msvbvm60.dll`) | VB6 Objects, Strings, Variants, Form Model | `vb6runtime` crate | `VB6Object`, `VB6String`, `VB6Variant` |

### DirectX → wgpu Translation Reference

| DirectX Concept | wgpu Equivalent |
|----------------|-----------------|
| `IDirect3D9::CreateDevice()` | `wgpu::Instance::request_adapter()` + `request_device()` |
| `IDirect3DDevice9::Present()` | `queue.submit()` + `surface.get_current_texture()` |
| `IDirect3DTexture9` | `wgpu::Texture` + `TextureView` |
| `IDirect3DSurface9` (back buffer) | `surface.get_current_texture().texture.create_view()` |
| `DrawPrimitive()` | `encoder.draw()` with render pipeline |
| `SetTexture(stage, tex)` | `encoder.set_bind_group()` |
| `SetRenderState()` | Pipeline configuration (`PipelineDescriptor`) |
| `SetVertexShader()` | `RenderPipeline` vertex stage |
| `SetPixelShader()` | `RenderPipeline` fragment stage |
| `StretchBlt()` / `BitBlt()` | Texture resize + blit pass, or `tiny_skia` |
| `CreateOffscreenPlainSurface()` | `wgpu::Texture` with `Storage` usage |

### GDI → tiny-skia Translation Reference

| GDI Call | tiny-skia Equivalent |
|----------|---------------------|
| `CreateDC("DISPLAY", ...)` | `tiny_skia::Pixmap::new(width, height)` |
| `BitBlt(dest, x, y, w, h, src, ...)` | `pixmap.blit_rect(&src, src_rect, dest_point)` |
| `CreateCompatibleBitmap()` | `Pixmap::from_pixel()` |
| `SelectObject(hdc, bitmap)` | Use `Pixmap` directly as target |
| `Rectangle()`, `Ellipse()` | `pixmap.fill_rect()` with path |
| `LineTo()`, `MoveToEx()` | `pixmap.stroke_path()` |
| `TextOut()` | `pixmap.drawString()` + `rusttype` font |
| `SetTextColor()`, `SetBkColor()` | `skia_safe::Color` |
| `CreateBrushIndirect()` | `tiny_skia::Color` fills |
| `CreatePen()` | `tiny_skia::Pen` |

### Win32 → Rust Standard Library Mapping

| Win32 API | Rust Equivalent |
|-----------|----------------|
| `CreateFile()` | `std::fs::File::create()` / `open()` |
| `ReadFile()` / `WriteFile()` | `File::read()` / `write()` |
| `CloseHandle()` | `File::drop()`, `Drop` trait |
| `CreateThread()` | `std::thread::spawn()` |
| `WaitForSingleObject()` | `JoinHandle::join()` |
| `Sleep()` | `std::thread::sleep()` |
| `VirtualAlloc()` / `VirtualFree()` | `mmap` crate / `std::alloc` |
| `LoadLibrary()` / `GetProcAddress()` | `libloading::Library::load()` / `symbol()` |
| `CreateEvent()` / `SetEvent()` | `std::sync::Condvar` / `AtomicBool` |
| `CreateMutex()` | `std::sync::Mutex` / `RwLock` |
| `GetTickCount()` / `GetSystemTime()` | `std::time::Instant` / `SystemTime` |
| `RegOpenKey()` / `RegQueryValue()` | `directories::ConfigDir` + `serde_json` |
| `MessageBox()` | `rfd::MessageBox` or `egui` dialog |
| `CreateWindowEx()` | `winit::Window::new()` |

## Phases

### Phase 1: Project Ingestion & Platform Analysis

**Goal:** Enumerate all binaries and catalog every Windows-specific dependency for cross-platform translation.

1. **Binary Inventory**
   - Scan the project directory for all `.exe` and `.dll` files
   - Record dependencies between binaries (import tables, referenced DLLs)
   - Build a dependency graph for ordered processing

2. **DLL Classification & Strategy**

   **Goal:** Categorize every DLL the binary depends on into a strategy category. This determines whether we reverse engineer the DLL from disassembly, find a crate equivalent, or use a PAL mapping.

   Classify each DLL into one of these categories:

   | Category | Description | Strategy | Examples |
   |----------|-------------|----------|----------|
   | **Windows OS** | Core Windows system DLLs | PAL → std lib / winit / etc. | `kernel32.dll`, `user32.dll`, `gdi32.dll`, `advapi32.dll`, `shell32.dll` |
   | **Microsoft SDK** | Official Microsoft libraries with known Rust equivalents | Crate replacement + shim layer | `d3d9.dll`, `d3d11.dll`, `d2d1.dll`, `dwrite.dll`, `dxgi.dll` |
    | **Known Third-Party Libraries** | Sound systems, physics engines, game engines, charting libraries, compression, etc. with existing Rust crates | Crate replacement + shim layer for API compatibility | `openal32.dll` → `cpal`, `fmod.dll` → `fmod-rs`, `bullet.dll` → `rapier`, `chipmunk.dll` → `chipmunk2d-rs`, `qt5*.dll` → `iced`/`slint`, `cairo.dll` → `cairo-rs`/`skia-safe`, `zlib1.dll` → `flate2`/`miniz_oxide`, `lua51.dll` → `mlua`, `python3.dll` → `pyo3` |
    | **Microsoft VB6 Runtime** (`msvbvm60.dll`) | VB6 object model, COM automation, BSTR/VARIANT types, form/control infrastructure | Crate replacement — `vb6runtime` crate implements VB6 runtime semantics | `msvbvm60.dll` → `vb6runtime` crate |
| **Project-Specific DLLs** | DLLs built from this project's source, or DLLs that are part of the application's own codebase | **Reverse engineer from disassembly** — these are the target of our main pipeline | `project_renderer.dll`, `game_logic.dll`, `ui_framework.dll` |
| **Third-Party Program DLLs** | DLLs from unknown/proprietary third parties with no Rust crate equivalent | **Reverse engineer from disassembly** — treat as opaque libraries to replicate | Custom plugin DLLs, vendor-specific SDKs |
| **VB6 Runtime** (`msvbvm60.dll`) | Microsoft Visual Basic 6 runtime — COM objects, BSTR strings, Variants, form model, `IUnknown` vtables | **Crate replacement** — use `vb6runtime` crate to replicate the VB6 runtime DLL | `msvbvm60.dll` → `vb6runtime` crate |

   For each DLL:
   - Record DLL name, version, digital signature (if present)
   - Extract all exported functions and their signatures
   - Extract all imported functions (what the DLL depends on)
   - Build a classification report: which DLLs need reverse engineering vs. which can be replaced

   **Key Principle:** We are reverse engineering the *entire program structure* but we do NOT reverse engineer libraries that have crate equivalents. Even if a crate needs a shim layer to match the original library's API exactly, that is vastly easier than reverse engineering from disassembly.

3. **Windows API Cataloguing**
   - Extract every imported function from every DLL
   - Classify imports into categories using the mapping table above:
     - DirectX (9/10/11/12) → wgpu
     - GDI/GDI+ → tiny-skia
     - Win32 GUI → winit/egui
     - Audio APIs → cpal/rodio
     - COM → comfy crate
     - Win32 Core → std library
     - VB6 Runtime → vb6runtime crate
   - For each import, record: API name, source DLL, called functions, translation target crate

4. **GhidraMCP Initialization**
   - Launch GhidraMCP server pointing to the target binary
   - Establish session for the executable
   - Load all associated DLLs into the analysis context

5. **Symbol & Structure Extraction**
   - Extract all symbols: exports, imports, global variables
   - Extract data structures, structs, and unions
   - Catalog function entry points and their signatures
   - Map call graph: which functions call which
   - **Tag Windows API calls** in each function with their PAL target

6. **Baseline Snapshot**
   - Record current binary behavior through sample I/O for later verification
   - Capture any known test cases or expected behaviors

### Phase 2: Disassembly & Platform API Recognition

**Goal:** Break down binaries and tag every Windows API call for cross-platform translation.

1. **Function-Level Disassembly**
   - For each function, extract the full disassembly listing from GhidraMCP
   - Extract the decompiler output (pseudo-C) for reference
   - Preserve: instruction addresses, operands, comments, cross-references

2. **Windows API Call Tagging**
   - For each function, identify all calls to Windows APIs and external DLLs
   - Tag each call with:
     - API name (e.g., `Direct3DCreate9`, `CreateFile`, `MessageBox`)
     - Category from mapping table (e.g., `directx9`, `win32_file`, `win32_gui`)
     - Cross-platform target crate (e.g., `wgpu`, `std::fs`, `egui`)
     - PAL trait method to use (e.g., `GraphicsDevice::create_texture`, `FileSystem::open`)
   - Build an API usage map: which functions use which Windows APIs

3. **Control Flow Analysis**
   - Build control flow graphs (CFG) from disassembly
   - Identify basic blocks, loops, conditionals, and branches
   - Label function boundaries and internal structure

4. **Dependency Mapping**
   - For each function, identify external calls (to other functions in same binary or imported DLLs)
   - Flag functions that are self-contained vs. those requiring context
   - Categorize dependencies: DirectX setup code, GDI drawing code, Win32 message handling, etc.

### Phase 2.5: Platform Abstraction Layer (PAL) Design

**Goal:** Design and implement the abstraction layer that hides platform differences from translated code.

1. **PAL Module Structure**

   ```
   src/
   ├── pal/                    # Platform Abstraction Layer
   │   ├── mod.rs              # Re-exports current-platform implementations
   │   ├── traits.rs           # All PAL trait definitions
   │   ├── win/                # Windows-specific implementations (for comparison)
   │   ├── unix/               # Linux implementations (wgpu, cpal, std)
   │   └── macos/              # macOS implementations (wgpu/Metal, std)
   ```

2. **Core PAL Traits** (examples)

   ```rust
   // Graphics (DirectX/GDI → wgpu/tiny-skia)
   trait GraphicsDevice {
       type Texture;
       type RenderTarget;
       fn create_texture(&mut self, width: u32, height: u32) -> Self::Texture;
       fn blit(&mut self, src: &Self::Texture, dest: &mut Self::RenderTarget);
       fn present(&mut self);
       fn draw_line(&mut self, x1: f32, y1: f32, x2: f32, y2: f32, color: Color);
       fn draw_rect(&mut self, x: f32, y: f32, w: f32, h: f32, color: Color);
       fn draw_text(&mut self, x: f32, y: f32, text: &str, font: &Font, color: Color);
   }

   // Audio (DirectSound/waveOut → cpal)
   trait AudioDevice {
       fn play_sample(&mut self, sample: &Sample);
       fn stop(&mut self);
       fn set_volume(&mut self, vol: f32);
   }

   // File System (CreateFile/ReadFile → std::fs)
   trait FileSystem {
       type Handle;
       fn open(&self, path: &str, mode: FileMode) -> Result<Self::Handle>;
       fn read(&self, handle: &Self::Handle, buf: &mut [u8]) -> usize;
       fn write(&self, handle: &Self::Handle, buf: &[u8]) -> usize;
       fn close(&self, handle: Self::Handle);
   }

   // Windowing (CreateWindowEx → winit)
   trait Window {
       fn create(title: &str, width: u32, height: u32) -> Self;
       fn show(&self);
       fn process_events(&mut self);
       fn get_client_size(&self) -> (u32, u32);
   }
   ```

3. **PAL Implementation Selection**
   - Compile-time feature flags: `--features linux`, `--features macos`, `--features windows`
   - `pal::mod.rs` uses `#[cfg(target_os = "...")]` to select correct backend
   - All translated code calls PAL traits, never raw Windows APIs directly

### Phase 3: Behavior-Driven Test Generation

**Goal:** Create tests that verify the current behavior of each disassembled function.

1. **Stub Creation**
   - For each function, create a FFI stub in Rust that calls the original binary
   - Map original types to Rust equivalents (integers, pointers, structs)
   - Generate a harness that can invoke the original function with controlled inputs

2. **Input Space Exploration**
   - For each function, identify parameters and their types
   - Generate diverse test inputs covering:
     - Boundary values (zero, max, negative, null)
     - Typical/expected values
     - Edge cases identified in the disassembly (comparisons, checks)
   - Use Ghidra's analysis hints (type information, comments) to guide inputs

3. **Output Observation**
   - For each test input, invoke the original function via FFI
   - Capture: return value, modified output parameters, side effects
   - Record all observations as test assertions

4. **Test Assembly**
   - Compile the test harness
   - Run all tests against the original binary
   - Store results in a structured test database per function

### Phase 4: Rust Code Generation

**Goal:** Write Rust functions that replicate the observed behavior.

1. **Translation Strategy**
   - Map disassembly patterns to Rust idioms:
     - `mov` + arithmetic → Rust arithmetic operators
     - `cmp` + `je`/`jne` → if/else branches
     - Loop patterns (decrement + branch) → for/while loops
     - Stack operations → Rust local variables
     - Pointer dereferences → Rust references/unsafe blocks
   - Preserve function signatures with FFI-compatible types

2. **Function-by-Function Translation**
   - For self-contained functions: direct translation from disassembly
   - For dependent functions: generate trait-based interfaces for external calls
   - Generate Rust code incrementally, respecting dependency order

3. **Type Refinement**
   - Use Ghidra type information as starting point
   - Refine types based on usage patterns in disassembly
   - Replace raw pointers with safe Rust types where possible
   - Use `enum` for tagged unions, `struct` for records

4. **Intermediate Compilation**
   - After generating Rust code for a function, attempt to compile
   - Fix compilation errors (type mismatches, missing imports)
   - Iterate until the function compiles in isolation

### Phase 5: Behavior Verification Loop

**Goal:** Prove the Rust implementation matches original behavior on all target platforms.

1. **Run Verification Tests**
   - Execute the stored test suite against the Rust implementation
   - Compare output against the baseline captured in Phase 3
   - Flag mismatches for manual review

2. **Cross-Platform PAL Verification**
   - For each PAL trait implementation (linux, macos, windows):
     - Build the project with each target platform's feature flag
     - Run the test suite against the PAL implementation for that platform
     - Compare outputs: must match the original Windows behavior
   - For graphics APIs (DirectX → wgpu):
     - Verify rendered output matches across Vulkan (Linux), Metal (macOS), and DX12 (Windows)
     - Compare frame buffers or screenshot checksums
   - For audio APIs (DirectSound → cpal):
     - Verify sample output is identical across platforms
   - For file/system APIs:
     - Verify I/O behavior matches (file contents, registry settings)

3. **Discrepancy Resolution**
   - If a test fails:
     - Analyze the failing case
     - Compare Rust behavior vs. disassembly behavior
     - Check if PAL implementation diverges from original Windows API behavior
     - Patch Rust code or PAL implementation
     - Re-run verification
   - Iterates until all tests pass on all platforms

4. **Regression Guard**
   - Once passing, the test suite becomes a permanent regression guard
   - Tests run in CI on Linux, macOS, and Windows
   - Future refactors must pass these tests on all platforms

### Phase 6: Restitching Engine

**Goal:** Combine the Rust implementations with the remaining assembly to produce a functional whole.

1. **Remaining Assembly Preservation**
   - Functions not yet translated remain as inline assembly (using Rust `asm!` or `include!`)
   - Preserve the original binary layout for any position-dependent code

2. **Hybrid Linking Strategy**
   - **Option A: Runtime FFI bridge**
     - Rust code calls original functions via FFI where no Rust implementation exists
     - Gradually replaces FFI calls with direct Rust calls
   - **Option B: Static link with mixed object files**
     - Assemble remaining disassembly to object files
     - Link with Rust-compiled object files
     - Resolve symbols across the boundary
   - **Option C: Full Rust rewrite with assembly fallbacks**
     - Inline assembly blocks for untranslatable fragments
     - Use `cfg` attributes to switch between pure-Rust and hybrid modes

3. **Boundary Verification**
   - After restitching, verify the combined binary behaves identically
   - Run integration-level tests against the original executable
   - Fix any boundary-condition issues at Rust/assembly interfaces

4. **Iterative Expansion**
   - As more functions are translated to Rust, reduce the assembly footprint
   - Each iteration reduces the FFI/linkage surface area
   - Target: fully Rust implementation with minimal assembly residue

### Phase 7: Documentation & Artifacts

**Goal:** Produce maintainable output and clear provenance.

1. **Mapping Documentation**
   - For each Rust function, record: original address, original symbol name, translation confidence
   - Maintain a function registry: original binary location → Rust module

2. **Test Suite Preservation**
   - All generated tests become part of the Rust project
   - Organized by original binary and function

3. **Build Integration**
   - Provide a Cargo.toml that can build the Rust portions
   - Document how to link with remaining assembly/DLLs

## Agent Workflow

```
─────────────────────────────────────────────────────────
STAGE 0: DLL Classification (Phase 1, Step 2)
─────────────────────────────────────────────────────────
For each DLL in the binary's import table:
    1. Identify DLL (name, version, signature)
    2. Classify: Windows OS / Microsoft SDK / Known Third-Party / Project-Specific / Unknown Third-Party
    3. Assign strategy:
       - Windows OS → PAL mapping (no reverse engineering needed)
       - Microsoft SDK → find wgpu/tiny-skia/etc. crate equivalent
       - Known Third-Party → find Rust crate, plan shim layer
       - Project-Specific → REVERSE ENGINEER (target of main pipeline)
       - Unknown Third-Party → REVERSE ENGINEER (treat as opaque library)

─────────────────────────────────────────────────────────
STAGE 1: Crate Replacement Setup (parallel with Stage 2)
─────────────────────────────────────────────────────────
For each classified Microsoft SDK / Known Third-Party DLL:
    1. Find the equivalent Rust crate
    2. Analyze API differences between original DLL and crate
    3. Design shim layer: translate original DLL's API surface to crate's API
    4. Implement shim as a transparent wrapper module
    5. Write tests: shim calls → crate API → verify same behavior

─────────────────────────────────────────────────────────
STAGE 2: Reverse Engineering (Phase 2–6)
─────────────────────────────────────────────────────────
For each function in project-specific / unknown third-party DLLs:
    1. Pull disassembly from GhidraMCP
    2. Identify Windows API calls and crate-replacement calls in the disassembly
    3. Windows API calls → translate to PAL trait methods
    4. Crate-replacement DLL calls → translate to shim/crate calls
    5. Generate stubs and run baseline tests (Phase 3)
    6. Translate to Rust (Phase 4)
    7. Compile and fix errors
    8. Run verification against baseline (Phase 5)
    9. If all pass: mark as translated
    10. If fail: debug, patch, re-verify (loop)
    11. After all functions: restitch (Phase 6)

─────────────────────────────────────────────────────────
STAGE 3: Integration
─────────────────────────────────────────────────────────
    1. Combine crate shims + translated Rust code + PAL layer
    2. Verify cross-platform build on Linux, macOS, Windows
    3. Verify behavioral equivalence against original binary
```

## Key Design Decisions

1. **DLL classification drives strategy**: Every DLL is classified before work begins. Only project-specific and unknown third-party DLLs are reverse engineered. Known libraries (Windows SDK, DirectX, sound/physics/game engines, charting libs) are replaced with Rust crates.

2. **Crate-first, shim always**: When a Rust crate equivalent exists, use it. Write a shim layer to translate the original DLL's API surface to the crate's API. This is orders of magnitude easier than reverse engineering.

3. **Test-driven decompilation**: Tests are the ground truth. If the Rust code passes the tests, it's correct by definition of the observed behavior.

4. **Incremental restitching**: Never replace the entire binary at once. Swap in Rust functions one at a time, verifying each swap.

5. **Ghidra as single source of truth**: Disassembly, decompiler output, and type info from GhidraMCP are the authoritative reference. No guessing.

6. **Safety boundary**: All unsafe FFI calls to the original binary are isolated in a dedicated module. The translation target is to eliminate each unsafe block.

7. **No binary reconstruction**: We do not attempt to rebuild the original executable format. The output is a Rust project that functionally replaces the original.

8. **Reverse engineer program structure, not libraries**: The goal is to reverse engineer the entire application architecture and program-specific logic, while replacing known library dependencies with their crate equivalents.

9. **LLM-first, discard-when-wrong**: The locally-hosted LLM is the primary translation engine. Use it aggressively and without restraint. Every failed attempt is cheap — branch, try, fail, discard, retry. The cost of incorrect output is a few git branches; the cost of not using the LLM is a project that never gets translated.

10. **Source-control backed reversibility**: Every unit of work is a Git branch and commit. No state is lost. Failed branches are kept as historical record. The system is always restorable, diffable, and reviewable. Human review gates what reaches `main`.

11. **Human-in-the-loop review via web UI**: The LLM does the work; the human validates it. Every unit of work is presented with justification, test results, attempt history, and dependency context. The reviewer accepts, sends back, or requests patches.

12. **Context-tiered LLM usage**: Always start with the smallest LLM context that can do the job. Escalate from function stub → disassembly → disassembly+tests → module context → full module only when lower tiers fail. This minimizes token usage while maximizing LLM effectiveness.

## Risk Mitigation

| Risk | Mitigation |
|------|-----------|
| Ghidra misidentifies function boundaries | Cross-reference decompiler output with CFG; manual override capability |
| Non-deterministic behavior (timing, memory layout) | Focus tests on observable I/O; avoid timing-dependent tests |
| Complex calling conventions | Use Ghidra's calling convention analysis; verify with FFI stubs |
| Position-independent code | Handle relative addressing in translation; test with varied load addresses |
| Anti-reversing techniques | Note in translation confidence; may require manual intervention |
| Data segment ambiguity | Use Ghidra data type analysis; verify with usage-pattern tests |
| Misclassified DLL (false positive for crate replacement) | Verify shim layer passes all original behavior tests before removing FFI; fallback to RE if shim fails |
| Crate API diverges from original DLL | Implement comprehensive shim tests covering all observed call patterns; patch shim iteratively |
| No crate exists for known third-party DLL | Fall back to reverse engineering; treat as unknown third-party category |
| LLM context window exhausted | Tiered context strategy; split functions into smaller chunks; retry with focused context |
| LLM produces incorrect code consistently | Multiple retry strategies escalate: context split → different prompt template → different model → manual intervention |
| Human reviewer becomes bottleneck | Web UI batch actions, dependency-ordered queue, and clear justifications keep review throughput high |
| Branch sprawl (hundreds of failed branches) | Automated cleanup of branches older than 7 days with no reviewer interaction; archived to `refs/archive/` |

## Tooling Requirements

- **GhidraMCP**: Server providing disassembly, decompiler, and symbol queries via MCP protocol
- **Rust toolchain**: `cargo`, `rustc` with unstable features for inline assembly if needed
- **FFI bindings**: `bindgen` or manual FFI definitions for original binary interface
- **Test framework**: `cargo test` with arbitrary test generation capabilities
- **Binary analysis**: `ldd`/`objdump` for supplementary dependency and format info
- **Local LLM**: Locally-hosted model (e.g., vLLM, Ollama, llama.cpp) with sufficient context window (128k+ tokens)
- **Git**: Version control for all work units; branch naming automation
- **Web UI framework**: Rust-based web server (e.g., `axum` or `actix-web`) serving a plain HTML/JS/CSS frontend for the review interface
- **LLM client library**: `reqwest` + JSON parsing for local LLM API communication (OpenAI-compatible or Ollama API)
- **Prompt template engine**: Handle structured prompt generation with context-tier variables
- **Dependency graph visualization**: Render graph of branches, dependencies, and merge paths (e.g., `d3-graph` or `vis.js` in the web UI)

## Output Structure

```
recompiled_project/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── main.rs
│   ├── pal/                    # Platform Abstraction Layer
│   │   ├── mod.rs
│   │   ├── traits.rs
│   │   ├── win/
│   │   ├── unix/
│   │   └── macos/
│   ├── shims/                  # Crate wrappers for replaced DLLs
│   │   ├── wgpu_shim.rs        # DirectX → wgpu shim
│   │   ├── cpal_shim.rs        # DirectSound → cpal shim
│   │   └── vb6runtime_shim.rs  # msvbvm60 → vb6runtime shim
│   ├── foreign_mod.rs          # Remaining FFI to un-replaced binaries
│   ├── tests/
│   │   ├── baseline/           # Auto-generated test suite
│   │   │   └── mod.rs
│   │   └── verification/       # Cross-platform verification tests
│   │       └── mod.rs
│   └── modules/                # Translated functions organized by original binary
│       └── original_exe.rs
├── assembly/                   # Preserved inline assembly fragments
│   └── critical_regions.asm
├── review-ui/                  # Web review UI (separate crate or embedded)
│   └── src/
├── docs/
│   └── function_registry.json  # Mapping of original → translated functions
└── scripts/
    ├── git-branch-auto.sh      # Automated branch naming
    └── llm-fault-monitor.sh    # LLM fault detection and recovery
```

## Minimal Viable Product

Before building the full system with web UI, fault detection, tiered context management, and dependency-aware branching, the MVP delivers a working reverse engineering loop with the absolute minimum infrastructure. The MVP proves the core concept: **can an LLM reliably translate disassembled functions to Rust that passes behavior tests?**

### MVP Goals

1. Translate a single function from a single DLL from disassembly to working Rust
2. Generate baseline tests that capture the original behavior
3. Verify the Rust implementation matches the original
4. Commit the result to git with a readable diff
5. **No web UI, no fault detection, no tiered context, no dependency graph** — just the loop working

### MVP Architecture

```
┌───────────────────────────────────────────────────┐
│                    MVP Harness                     │
│                                                    │
│  GhidraMCP → disassembly → LLM → Rust code        │
│      ↓                      ↓       ↓             │
│  DLL imports          baseline tests    cargo test │
│                        ↓                     ↓     │
│              original vs rust compare         ✓/✗  │
│                        ↓                         │
│              git commit on success               │
└───────────────────────────────────────────────────┘
```

### MVP Components

#### 1. CLI-Only Interface

No web UI implementation in the MVP. The web UI crate (`calxgloss-web`) is scaffolded in the workspace but all review happens via terminal output (stdout). The harness outputs to stdout and writes files.

```bash
# Classify DLLs
re_compile classify --target myapp.exe

# Translate a single function
re_compile translate --target myapp.exe --dll game_logic.dll --function DrawSprite

# Run verification
re_compile verify --target myapp.exe --dll game_logic.dll --function DrawSprite

# Batch translate
re_compile translate --target myapp.exe --dll game_logic.dll --all
```

Output is plain text or JSON. A human reads the terminal to review.

#### 2. Minimal LLM Integration

- Single prompt template per translation task
- No context tiers — always send full function disassembly + decompiler output + test results
- No fault detection — if the LLM fails, the harness exits with an error and the human retries
- No retry logic — manual intervention for failures
- Single model, no model switching

#### 3. Git Automation (Minimal)

- Every successful translation creates a branch: `re/<dll>/<function>/v1`
- On retry: `re/<dll>/<function>/v2`
- On success: merge to `main`
- On failure: branch kept, no cleanup
- No structured commit messages, no dependency tracking, no queuing

#### 4. Test Generation (Minimal)

- Generate FFI stubs for the target function
- Generate 10-20 test inputs (boundaries, typical values, null/zero)
- Run against original binary, capture outputs
- Run against Rust implementation, compare
- Pass/fail is binary — no confidence scores, no attempt history tracking

#### 5. PAL (Minimal)

- Windows OS DLLs → std lib (no abstraction, just use std)
- DirectX/GDI → manual mapping table, no trait system
- One file: `src/platform_mapping.rs` with `cfg_if!` macros selecting std vs wgpu

#### 6. No Shim Layer Infrastructure

- For crate replacements (wgpu, cpal, etc.), the MVP does NOT build shim layers
- Instead, the MVP marks these as "manual shim needed" and skips them
- Only project-specific DLLs are translated in the MVP

### MVP Workflow

```
1. User runs: re_compile translate --target myapp.exe --dll game_logic.dll --function DrawSprite

2. Harness:
   a. Calls GhidraMCP for disassembly of DrawSprite
   b. Calls GhidraMCP for decompiler output
   c. Identifies Windows API calls in the function
   d. Writes FFI stub to call original DLL
   e. Generates 20 test inputs, runs against original
   f. Sends disassembly + tests to LLM with prompt:
      "Translate this function to Rust. It calls [APIs].
       These tests must pass: [test cases + expected outputs].
       Output ONLY valid Rust code."
   g. Receives Rust code, writes to src/modules/game_logic/DrawSprite.rs
   h. Compiles with cargo check
   i. If compile fails: report error, stop
   j. If compile succeeds: run tests against Rust impl
   k. If tests pass: git branch, commit, merge to main, print summary
   l. If tests fail: report failures, stop (human retries manually)
```

#### 7. Review (Minimal)

No web UI. The human reviews via:

- `git diff` on the branch before merge
- Test output in terminal
- The Rust source file in their editor

A simple acceptance prompt:

```
Translation of DrawSprite:
  Compiled: yes
  Tests: 18/20 passed
  Failed: test_input_7 (expected 42, got 43), test_input_15 (panicked)
    Branch: re/game_logic/DrawSprite/v1
  Status: FAIL - fix required

Accept (y/n): n
```

### MVP Success Criteria

| Criterion | Threshold |
|-----------|-----------|
| Function translated to Rust | Compiles without errors |
| Baseline tests generated | ≥ 10 test inputs per function |
| Test pass rate | ≥ 90% on first successful attempt |
| Git commit | Every translated function has a branch + commit |
| Manual review | Human can read diff and test output to judge correctness |
| End-to-end | One complete translation from GhidraMCP to merged git commit |

### MVP What's NOT Included

| Feature | Reason for Exclusion | When to Add |
|---------|---------------------|-------------|
| Web UI | Not needed if terminal review works | After MVP proves the loop is reliable |
| Fault detection | Adds complexity; human can spot failures | After MVP, when scaling to many functions |
| Context tiers | Full function context works for MVP scope | When functions get too large for one prompt |
| Dependency-aware branching | MVP targets single functions, not full DLLs | After MVP, when translating multi-function DLLs |
| Shim layer infrastructure | MVP skips crate replacements | After MVP, when replacing DirectX/GDI |
| Retry logic | Manual retry is acceptable for MVP | After MVP, to reduce human overhead |
| Confidence scoring | Binary pass/fail is sufficient for MVP | After MVP, for large-scale review |
| Branch cleanup | Not needed until branches accumulate | After MVP, when history gets messy |
| CI/CD integration | MVP targets local development | After MVP, for production readiness |

### MVP Extensions (Post-MVP)

Once the MVP proves the core loop works, add features in this order:

1. **Retry logic** — automatic retry with different prompts on test failure (saves human time)
2. **Prompt templates** — refine prompts based on what works (improves LLM accuracy)
3. **Batch translation** — translate all functions in a DLL, not just one at a time
4. **Simple dependency tracking** — link branches when one function calls another
5. **Terminal-based review dashboard** — text-based UI showing queue, status, test results
6. **Shim layer generation** — start replacing DirectX/GDI with crate equivalents
7. **Web UI** — replace terminal review with proper interface
8. **Context tiers** — optimize token usage for large functions
9. **Fault detection** — automate recovery from common LLM failures
10. **CI integration** — add cross-platform verification builds

### MVP Tech Stack

| Component | Technology |
|-----------|-----------|
| Harness CLI | Rust with `clap` for argument parsing |
| GhidraMCP | Existing GhidraMCP server, `reqwest` for HTTP calls |
| LLM | `reqwest` + JSON parsing for OpenAI-compatible API (Ollama, vLLM, etc.) |
| Git | `git2` crate or subprocess calls to `git` |
| Compilation | `cargo check` + `cargo test` subprocess calls |
| Test generation | Rust code generation from function signatures |
| Output | stdout (text/JSON), files in project structure |
| No web framework needed | No HTTP server, no frontend |

### MVP File Structure

```
re_compile_mvp/
├── Cargo.toml
├── src/
│   ├── main.rs               # CLI entry point, argument parsing
│   ├── ghidra.rs             # GhidraMCP client
│   ├── llm.rs                # LLM client, prompt builder
│   ├── testgen.rs            # FFI stub + test generation
│   ├── translator.rs         # Prompt → LLM → Rust code flow
│   ├── verify.rs             # Compile, test, compare results
│   ├── git.rs                # Branch, commit, merge operations
│   └── report.rs             # Terminal output formatting
├── prompts/
│   └── translate.txt.j2      # Jinja2 prompt template for translation
└── tests/
    └── integration.rs        # End-to-end test on a sample DLL
```

### MVP Timeline (Estimated)

| Phase | Duration | Deliverable |
|-------|----------|-------------|
| GhidraMCP client + disassembly extraction | 2-3 days | Can pull function disassembly + decompiler output |
| LLM client + prompt → Rust code | 2-3 days | Can send disassembly, receive Rust code |
| Test generation + verification loop | 3-4 days | Can generate tests, run, compare |
| Git automation | 1-2 days | Branch, commit, merge on success |
| CLI + end-to-end wiring | 2-3 days | Single `re_compile translate` command works |
| Polish + sample DLL testing | 2-3 days | One complete translation end-to-end |
| **Total** | **~3-4 weeks (22-32 days)** | **MVP delivering one verified translation** |

### MVP Risk

The MVP has one critical risk: **if the LLM cannot reliably translate a function to Rust that passes tests, the entire MVP fails to deliver value.** Mitigations:

- Start with a simple DLL (low function complexity, few external dependencies)
- Choose a function with clear input/output behavior (not graphics/audio)
- If the LLM fails on the first target, analyze why and adjust the prompt before retrying
- Accept that the MVP may only succeed on a subset of functions — that's still proof of concept

If the MVP succeeds on even one function, the full system (with web UI, fault detection, dependency tracking, etc.) is justified. If it fails on all functions, the core approach needs rethinking before investing in the full system.

## Workspace and Directory Structure

The harness manages two distinct directory sets. Understanding this separation is critical to how the system operates.

### Source Directory

The **source directory** is the original project being reverse engineered. It contains:
- Executables (`.exe`) and DLLs to be translated
- Associated data files, configuration files, resource files
- Text files, scripts, documentation from the original project
- Any ancillary files the original program depends on at runtime

The harness **never modifies** the source directory. It reads from it, copies what is needed for testing and verification, but the source directory is treated as an immutable artifact — the ground truth from which all analysis flows.

### Resultant Directory

The **resultant directory** is the output workspace where all reverse engineering work lives. It is:
- A Rust workspace under full git source control
- The destination for all translated code, test artifacts, analysis documents, and review materials
- The place where the project is rebuilt, tested, and verified

The resultant directory is created fresh for each reverse engineering target. It contains everything needed to build, test, and run the translated version of the original project.

#### Resultant Directory Layout

```
<project_name>_re/
├── Cargo.toml                    # Workspace manifest
├── .git/
├── .gitignore
├── workspace_config.json         # Harness configuration, mapping metadata
├── source/                       # Mirror of relevant source directory contents
│   ├── original_exe.exe          # Copy of original executable (for FFI/testing)
│   ├── dlls/                     # Copies of original DLLs (for FFI/testing)
│   │   ├── game_logic.dll
│   │   ├── renderer.dll
│   │   └── audio_engine.dll
│   ├── resources/                # Resource files needed for testing
│   │   ├── assets/
│   │   ├── config/
│   │   └── data/
│   ├── scripts/                  # Original project scripts (build, test, etc.)
│   └── documentation/            # Original documentation (reference only)
├── re/                           # Reverse engineering work
│   ├── classification/           # DLL classification reports
│   │   ├── original_exe.md       # Classification analysis for this binary
│   │   ├── game_logic.md
│   │   └── renderer.md
│   ├── analysis/                 # Ghidra-derived analysis artifacts
│   │   ├── call_graphs/          # Exported call graphs per DLL
│   │   ├── data_structures/      # Extracted struct/type definitions
│   │   └── function_profiles/    # Per-function Ghidra analysis summaries
│   ├── baseline/                 # Test baselines per function
│   │   └── game_logic/
│   │       ├── DrawSprite.json   # Test inputs + expected outputs
│   │       ├── LoadTexture.json
│   │       └── index.md          # Function summary with Ghidra references
│   ├── shims/                    # Crate shim implementations
│   │   ├── wgpu_shim.rs          # DirectX → wgpu
│   │   ├── cpal_shim.rs          # DirectSound → cpal
│   │   └── vb6runtime_shim.rs    # msvbvm60 → vb6runtime
│   └── patches/                  # LLM retry patches (what was tried, why it failed)
│       └── game_logic/DrawSprite/
│           ├── v1.diff
│           ├── v2.diff
│           └── v3.diff     # Accepted version
├── src/                          # Translated Rust code (the deliverable)
│   ├── lib.rs                    # Workspace lib root
│   ├── main.rs                   # Rebuilt entry point
│   ├── pal/                      # Platform Abstraction Layer
│   │   ├── mod.rs
│   │   ├── traits.rs
│   │   ├── win/
│   │   ├── unix/
│   │   └── macos/
│   ├── modules/                  # Translated functions organized by source DLL
│   │   ├── game_logic.rs         # All translated functions from game_logic.dll
│   │   ├── renderer.rs           # All translated functions from renderer.dll
│   │   └── original_exe.rs       # Translated functions from the main EXE
│   ├── tests/
│   │   ├── baseline/             # Auto-generated test suite
│   │   │   ├── game_logic/
│   │   │   │   ├── draw_sprite.rs
│   │   │   │   └── load_texture.rs
│   │   │   └── renderer/
│   │   │       └── present.rs
│   │   └── verification/         # Cross-platform verification tests
│   │       └── mod.rs
│   └── foreign_mod.rs            # FFI to original binaries (decreasing as RE progresses)
├── projects/                     # Additional crates created during restructuring
│   ├── game_logic_lib/           # Extracted from game_logic.dll functions
│   │   ├── Cargo.toml
│   │   └── src/
│   ├── renderer_core/            # Extracted from renderer.dll
│   │   ├── Cargo.toml
│   │   └── src/
│   └── shared_types/             # Shared structs/enums extracted across DLLs
│       ├── Cargo.toml
│       └── src/
├── docs/                         # Review docs, analysis, plans
│   ├── review/                   # Human review artifacts
│   │   ├── game_logic_DrawSprite.md      # Review doc for one function
│   │   ├── renderer_present.md
│   │   └── classification_original_exe.md
│   ├── analysis/                 # Analysis documents
│   │   ├── dll_dependency_map.md       # Full dependency analysis
│   │   ├── call_flow_analysis.md       # Key call flow diagrams
│   │   └── data_flow_analysis.md       # Data flow between modules
│   ├── plans/                    # Work plans for ongoing/future work
│   │   ├── phase1_classification.md
│   │   ├── phase2_game_logic_translation.md
│   │   └── phase3_integration.md
│   ├── decisions/                # Architecture/translation decisions
│   │   └── decision_log.md         # Running log of key decisions
│   └── reference/                # Reference material from source
│       └── original_doc_summary.md
├── resources/                    # Project-specific resources needed to build/test
│   ├── assets/                   # Copied from source, needed at runtime
│   ├── test_data/                # Test fixtures derived from source data
│   └── build_scripts/            # Adapted build scripts for Rust project
└── scripts/                      # Harness scripts, utility scripts
    ├── run_tests.sh
    ├── run_verification.sh
    └── import_ghidra_data.sh
```

#### Project Per DLL Principle

The resultant workspace contains **at least one Rust project per EXE/DLL** in the original. This maps directly to the source:

| Source | Resultant |
|--------|-----------|
| `original.exe` | `projects/original_exe/` (or integrated into main crate) |
| `game_logic.dll` | `projects/game_logic_lib/` |
| `renderer.dll` | `projects/renderer_core/` |
| `audio_engine.dll` | `projects/audio_core/` |

**However**, if analysis reveals duplication across DLLs (shared utilities, common data structures), the harness may create **additional projects** to consolidate:

| Situation | Action |
|-----------|--------|
| `game_logic.dll` and `renderer.dll` both define `Vector3` struct | Extract to `projects/shared_types/` crate |
| `audio_engine.dll` and `input_handler.dll` both implement event queues | Extract to `projects/event_system/` crate |
| `ui_framework.dll` is entirely independent | Keep as its own project |
| Multiple small DLLs with few functions each | Consolidate into a single crate |

The decision to split or consolidate is documented in `docs/plans/` and recorded in `workspace_config.json`.

#### Git Source Control in Resultant Directory

The resultant directory is **always under git**. The harness:
- Initializes a fresh git repo for each reverse engineering target
- Configures `.gitignore` to exclude build artifacts, binaries, and LLM cache
- Uses the branch naming convention defined in the Source-Control section
- Every harness operation (classification, test generation, translation, review) creates commits

```bash
# Initial setup creates:
git init <project_name>_re
git commit -m "init: workspace structure, source mirror copied"

# After DLL classification:
git add docs/analysis/dll_dependency_map.md
git add re/classification/*.md
git commit -m "re/classify: completed DLL classification for original_exe"

# After first successful translation:
git add src/modules/game_logic.rs
git add src/tests/baseline/game_logic/
git add docs/review/game_logic_DrawSprite.md
git commit -m "re/func/game_logic_DrawSprite: translate DrawSprite to Rust (v3)"
```

#### Documentation Folder

The `docs/` directory is the living record of all reverse engineering work. It contains:

| Subdirectory | Contents |
|--------------|----------|
| `docs/review/` | Human review documents for each unit of work. Each function that is translated gets a review doc that explains what was found, how it was translated, test results, and reviewer decisions. |
| `docs/analysis/` | Technical analysis: dependency maps, call flow diagrams, data flow analysis, control flow summaries from Ghidra, structural insights |
| `docs/plans/` | Work plans for ongoing and future work. Each phase of translation gets a plan document that outlines scope, strategy, and dependencies |
| `docs/decisions/` | Architecture and translation decisions. A running decision log records key choices, their rationale, and any trade-offs considered |
| `docs/reference/` | Reference material copied or derived from the source directory. Original documentation summaries, resource file catalogs, configuration file documentation |

##### Review Document Format

Each review document in `docs/review/` follows a standard format:

```markdown
# Review: <dll>/<function>

## Metadata
- **Original Address:** 0x00401234
- **Original DLL:** game_logic.dll
- **Ghidra Function:** `sub_00401234` (renamed: `DrawSprite`)
- **Branch:** `re/game_logic/DrawSprite/v3`
- **Commit:** `a1b2c3d`
- **Date:** 2025-01-15
- **LLM Model:** qwen3-235b-a22b
- **Prompt Tier:** 2
- **Status:** Accepted

## Translation Summary
Translated `DrawSprite` from 47 instructions to 23 lines of Rust.
The function takes a sprite coordinate, texture index, and render target
and issues a draw call.

## Windows API Calls
- `GetDC(hwnd)` → `winit` window context (PAL)
- `BitBlt(...)` → `tiny_skia::Pixmap::blit_rect()` (PAL)
- `GetTickCount()` → `std::time::Instant` (PAL)

## Crate Dependencies
- `wgpu` → for render target abstraction
- `tiny-skia` → for 2D blit operations

## Test Results
- Baseline: 47/47 passed
- Verification: 12/12 passed
- CI (Linux): passed
- CI (macOS): passed

## Attempt History
| Attempt | Result | Reason |
|---------|--------|--------|
| v1 | Failed (12/47 tests) | Missing texture view creation |
| v2 | Failed (38/47 tests) | Wrong shader constant mapping |
| v3 | Passed (47/47 tests) | Accepted |

## Confidence Assessment
High. All baseline tests pass. Function has clear input/output. No complex
control flow or external state mutation observed.

## Known Gaps
- Could not verify behavior when texture index is out of bounds (original
  DLL may crash, behavior undocumented)
- No test for sprite coordinates at negative values (original never called
  with these, unlikely in practice)

## Reviewer Notes
[Reviewer fills in decisions, concerns, or corrections]
```

##### Analysis Document Format

Technical analysis documents are structured as:

```markdown
# DLL Dependency Analysis: <dll_name>

## Summary
- **Exports:** 23 functions, 5 data structures
- **Imports:** 12 from user32.dll, 8 from gdi32.dll, 3 from game_logic.dll
- **Category:** Project-Specific (requires reverse engineering)
- **Strategy:** Full translation to Rust + PAL

## Exported Functions
| Address | Name (Ghidra) | Parameters | Return Type | Notes |
|---------|--------------|------------|-------------|-------|
| 0x00401234 | DrawSprite | x: i32, y: i32, tex: u32 | void | Calls BitBlt |
| 0x00401456 | LoadTexture | path: *const u8 | u32 | Calls CreateFile |
...

## Import Analysis
| DLL | Functions Imported | Used By |
|-----|-------------------|---------|
| user32.dll | GetDC, ReleaseDC | DrawSprite |
| gdi32.dll | BitBlt, CreateCompatibleBitmap | DrawSprite, LoadTexture |
| game_logic.dll | GetSpriteData | LoadTexture |

## Call Graph
[ASCII or mermaid diagram showing inter-function calls]

## Data Structures
[Extracted struct definitions from Ghidra]

## Cross-References
[Key XREFs that reveal how this DLL integrates with others]
```

#### Source Mirror Policy

The `source/` directory in the resultant workspace contains **selective copies** from the source directory, not the entire tree:

| Copied | Purpose |
|--------|---------|
| Original executables and DLLs | FFI testing, behavior comparison |
| Resource files needed at runtime | Testing requires same assets |
| Configuration files | Tests may need same config structure |
| Build/test scripts from original | May need adaptation for Rust build |
| Documentation files | Reference for understanding original behavior |

| Not Copied | Reason |
|------------|--------|
| Build artifacts (`.obj`, `.lib`, `.ilk`) | Not needed for testing |
| Temporary files, caches | Noise |
| User data, personal files | Privacy |
| Dependencies already classified as crate replacements | Not needed if we have the crate |

The harness automates this selection using the DLL classification results and Ghidra's import/export analysis to determine what is actually required for testing and verification.

#### Workspace Configuration

The `workspace_config.json` file tracks harness state and decisions:

```json
{
  "target": {
    "name": "my_project",
    "executable": "myapp.exe",
    "source_directory": "/path/to/original_project",
    "resultant_directory": "/path/to/my_project_re"
  },
  "dlls": {
    "game_logic.dll": {
      "category": "project_specific",
      "strategy": "reverse_engineer",
      "exports_count": 23,
      "imports": ["user32.dll", "gdi32.dll", "game_logic.dll"],
      "status": "in_progress",
      "translated_functions": 18,
      "total_functions": 23,
      "branch": "re/game_logic/DrawSprite/v3"
    },
    "d3d9.dll": {
      "category": "microsoft_sdk",
      "strategy": "crate_replacement",
      "crate": "wgpu",
      "shim_status": "completed",
      "status": "shim_complete"
    },
    "msvbvm60.dll": {
      "category": "microsoft_vb6_runtime",
      "strategy": "crate_replacement",
      "crate": "vb6runtime",
      "shim_status": "in_progress",
      "status": "shim_in_progress"
    }
  },
  "workspace": {
    "projects": [
      {"name": "game_logic_lib", "source_dll": "game_logic.dll", "functions": 18},
      {"name": "renderer_core", "source_dll": "renderer.dll", "functions": 31},
      {"name": "shared_types", "type": "extracted", "purpose": "consolidated Vector3, Color, Rect types"}
    ]
  },
  "llm": {
    "model": "qwen3-235b-a22b",
    "api_endpoint": "http://localhost:8080/v1",
    "default_context_tier": 2
  }
}
```

This file is updated by the harness after each major operation and is also human-editable for overriding harness decisions (e.g., changing a DLL's strategy from "reverse_engineer" to "crate_replacement" if the human discovers a crate the harness missed).

1. All selected functions have Rust implementations that pass their behavior tests
2. The combined system (Rust + FFI/assembly) produces identical output to the original binary for all tested inputs
3. The project builds successfully on Windows, macOS, and Linux with `cargo build --target <target>`
4. The PAL abstraction produces identical observable behavior across all three platforms
5. The translation confidence is documented per function, including which Windows APIs were replaced
6. The restitched build compiles and runs on all target platforms
7. Every unit of work has a Git branch, a structured commit, and a review entry in the web UI
8. LLM fault detection catches and recovers from context exhaustion, hallucination, and infinite retry loops automatically
9. The web UI presents every unit in dependency order with justification, test results, and attempt history
10. Failed LLM branches are preserved (not deleted) and available for pattern analysis
