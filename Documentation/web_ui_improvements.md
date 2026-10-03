# Web UI Improvements — What's Missing & What to Add

This document catalogs everything that the **current web UI does not expose** about the translation pipeline and recommends additions to give the reviewer full visibility into what's happening, why decisions are being made, and how to exercise fine-grained control over the translation process.

---

## Table of Contents

1. [Current State Summary](#current-state-summary)
2. [Missing Information — Status & Visibility](#1-missing-information--status--visibility)
3. [Missing Information — Process Control](#2-missing-information--process-control)
4. [Missing Information — Historical & Analytical Data](#3-missing-information--historical--analytical-data)
5. [Proposed New Views](#4-proposed-new-views)
6. [Proposed Enhancements to Existing Views](#5-proposed-enhancements-to-existing-views)
7. [Implementation Priority Matrix](#6-implementation-priority-matrix)
8. [API Endpoints Reference](#7-api-endpoints-reference)

---

## Current State Summary

### What the UI currently shows

| View | Content |
|------|---------|
| **Dashboard** | Status cards (queued, pending, in_progress, accepted, send_back, blocked, merged), pipeline progress panel, review queue list, recent activity |
| **Review Queue** | Full queue list with status filter, inline detail with overview (kind, binary, function, attempt, model, confidence, staleness), test results, diff summary, diff viewer, Ghidra context tabs, action buttons (accept/send-back/patch) |
| **Dependency Graph** | Interactive node/edge graph with zoom, pan, hover tooltip, click-to-highlight neighbors |
| **Branch Cleanup** | Stale branch scanning (configurable threshold), select-and-archive table |
| **LLM I/O Log** | WebSocket-streamed request/response/error entries with clear/expand |

### What's fundamentally missing

The UI is a **review gate** — it shows you the *result* of each translation unit so you can accept or reject it. What it does **not** show is:

- **Where we are in the overall pipeline** beyond per-binary classification/batch status
- **Why the LLM produced the output it did** (what context tier was used, what prompt variant)
- **What went wrong and how it was recovered** (faults, escalations, retry strategies)
- **How much we're spending** (token counts, cost awareness)
- **How to influence the pipeline** (skip functions, force tiers, exclude binaries, set priorities)

---

## 1. Missing Information — Status & Visibility

### 1.1 Overall Pipeline Progress

**What's missing:** A high-level view showing the translation pipeline's state across all 7 phases described in `Calxgloss.md`:

| Phase | What to show | Current gap |
|-------|-------------|-------------|
| **Phase 1** — Project Ingestion | Binary inventory, classification counts by category (WindowsOs, MicrosoftSdk, KnownThirdParty, ProjectSpecific, UnknownThirdParty) | Pipeline panel shows per-binary status but not a phase-level summary |
| **Phase 2** — Disassembly & Tagging | Functions analyzed, APIs tagged, call graph built | Not shown at all |
| **Phase 3** — Test Generation | Total baseline tests generated, per-binary breakdown | Only visible per-unit, not aggregate |
| **Phase 4** — Rust Code Generation | Functions translated, LLM attempts, token usage | Only visible per-unit detail |
| **Phase 5** — Behavior Verification | Baseline pass rate, verification pass rate, cross-platform results | Only per-unit, no aggregate |
| **Phase 6** — Restitching | Remaining assembly count, FFI bridge entries, integration batches | Not tracked or exposed |
| **Phase 7** — Documentation | Function registry completeness, mapping coverage | Not tracked or exposed |

**Recommendation:** Add a **Pipeline Dashboard** view or expand the existing dashboard to show:

```
┌─────────────────────────────────────────────────────────────────┐
│  Pipeline Overview                                              │
│                                                                 │
│  Project: myapp.exe             Targets: 3 binaries, 842 funcs  │
│  Started: 2025-06-15 14:32      Elapsed: 6h 23m                │
│                                                                 │
│  ── Binary Classification ───────────────────────────────────── │
│  Project-Specific:  3 ████████████████░░ 85%                   │
│  Microsoft SDK:     1 ████░░░░░░░░░░░░ 15%                     │
│  Known Third-Party: 0 ░░░░░░░░░░░░░░░░ 0%                      │
│                                                                 │
│  ── Function Translation ────────────────────────────────────── │
│  Total functions:    842                                       │
│  Translated:         312  ██████████████████████░░░░ 37%       │
│  In Progress:         18  ██░░░░░░░░░░░░░░░░░░░░  2%          │
│  Queued:             487  ████████████████████████████░░ 58%  │
│  Failed:               5  █░░░░░░░░░░░░░░░░░░░░░  1%          │
│  Skipped (runtime):   20  ██░░░░░░░░░░░░░░░░░░░░  2%          │
│                                                                 │
│  ── Quality Metrics ─────────────────────────────────────────── │
│  Average confidence:   87%                                     │
│  Baseline pass rate:   94.2%                                   │
│  Verification pass:    91.8%                                   │
│  Token budget used:    4.2M / 10M tokens (42%)                 │
└─────────────────────────────────────────────────────────────────┘
```

### 1.2 Binary-Level Breakdown

**What's missing:** The pipeline progress panel currently shows per-binary status (classified / translating / complete), but it doesn't show:

- **Binary classification strategy** — Is this binary going through crate replacement (shim layer), PAL mapping, or full reverse engineering?
- **Per-binary function counts** — Total, translated, in-progress, queued, failed
- **Per-binary token consumption** — How many tokens has this binary cost so far?
- **Per-binary success rate** — What fraction of functions succeeded on first attempt?
- **Shim layer status** — For Microsoft SDK / Known Third-Party binaries, is the shim layer built, tested, and accepted?
- **PAL trait status** — For binaries with Windows API calls, have the required PAL traits been implemented?

**Recommendation:** In the pipeline panel (or a new "Binaries" tab), show:

```
┌─────────────────────────┬──────────┬───────┬──────┬──────┬───────┬──────────┐
│ Binary                  │ Strategy │ Funcs │ Done │ InPr │ Queued│ Tokens   │
├─────────────────────────┼──────────┼───────┼──────┼──────┼───────┼──────────┤
│ game_logic.dll          │ RE       │ 234   │ 98   │ 3    │ 133   │ 1.8M     │
│ └─ shim: none needed    │          │       │      │      │       │          │
│ directx_render.dll      │ RE+Shim  │ 156   │ 87   │ 1    │ 68    │ 2.1M     │
│ └─ wgpu shim: accepted  │          │       │      │      │       │          │
│ audio_engine.dll        │ Crate    │ 89    │ 89   │ 0    │ 0     │ 0.3M     │
│ └─ fmod-rs shim: accepted│         │       │      │      │       │          │
│ unknown_plugin.dll      │ RE       │ 42    │ 5    │ 0    │ 37    │ 0.3M     │
│ └─ shim: none needed    │          │       │      │      │       │          │
└─────────────────────────┴──────────┴───────┴──────┴──────┴───────┴──────────┘
```

### 1.3 In-Flight Translation Status (Real-Time)

**What's missing:** The pipeline panel shows "translating" status, but it doesn't show:

- **Current phase per function** — Ghidra fetch → API tagging → test gen → context tier → LLM call → compile → test → review
- **Elapsed time per function** — How long has this function been translating?
- **Context tier selection** — Which tier was chosen and why (complexity + API count + history)
- **Retry strategy** — Which strategy is active (initial, compile_fix, test_fix, escalate)

**Recommendation:** Enhance the live WebSocket stream to emit and display per-function phase progress. In the pipeline panel or a new "Live" view:

```
┌──────────────────────────────────────────────────────────────┐
│  Live Translation                                            │
│                                                              │
│  game_logic.dll — FunctionCompleted (12/234)                │
│                                                              │
│  ┌─ DrawSprite ─────────────────────────────────────────────┐│
│  │ [████████████████████████████████████] Complete (3/5s)   ││
│  │ Tier: T2 (with_tests) | Strategy: compile_fix | v3       ││
│  │ Baseline: 47/47 | Verification: 12/12 | Confidence: 92%  ││
│  └──────────────────────────────────────────────────────────┘│
│                                                              │
│  ┌─ ComputeValue ───────────────────────────────────────────┐│
│  │ [████████████████████████████████░░░░] LLM Call (47s)    ││
│  │ Tier: T3 (module_context) | Strategy: test_fix | v2      ││
│  └──────────────────────────────────────────────────────────┘│
│                                                              │
│  ┌─ ProcessInput ───────────────────────────────────────────┐│
│  │ [████████████████████░░░░░░░░░░░░░░] Compiling (8s)      ││
│  │ Tier: T1 (disassembly) | Strategy: initial | v1          ││
│  └──────────────────────────────────────────────────────────┘│
└──────────────────────────────────────────────────────────────┘
```

---

## 2. Missing Information — Process Control

### 2.1 Translation Scope Control

**What's missing:** There is no way for the human reviewer to influence **what** gets translated. The pipeline is fully automatic once started. The user wants to be able to:

| Control | Why it matters |
|---------|---------------|
| **Skip specific functions** | Some functions are known runtime entry points, hooks, or callback stubs that don't need translation |
| **Skip specific binaries** | A misclassified binary or a binary that's causing persistent failures can be excluded |
| **Translate only priority functions** | Focus on the most critical functions first (entry points, rendering path, core algorithms) |
| **Force context tier** | If the automatic tier selection is too aggressive (starting too low), the user can force a higher tier |
| **Set retry limits** | Control the maximum number of LLM attempts per function to prevent runaway token consumption |

**Recommendation:** Add a **Translation Controls** section:

```
┌──────────────────────────────────────────────────────────────┐
│  Translation Controls                                        │
│                                                              │
│  ── Scope ────────────────────────────────────────────────── │
│  [ ] Skip runtime functions (WinMain, DllMain, CRT startup)  │
│  [x] Translate all project-specific binaries                  │
│  [x] Translate known third-party binaries                     │
│  [ ] Translate unknown third-party binaries                   │
│                                                              │
│  ── Priority Functions (manual override) ─────────────────── │
│  Add function: [____________] [Add]                         │
│                                                              │
│  • DrawSprite — Priority: HIGH (currently queued)           │
│  • ComputeValue — Priority: HIGH (currently queued)         │
│  • ProcessInput — Priority: NORMAL (currently queued)       │
│                                                              │
│  ── Constraints ──────────────────────────────────────────── │
│  Max LLM attempts per function: [5]                         │
│  Max context tier: [FullModule (T4)]                        │
│  Token budget (remaining): [5,800,000] tokens               │
│  [Apply & Restart]                                          │
└──────────────────────────────────────────────────────────────┘
```

### 2.2 Per-Function Override Panel

**What's missing:** On the unit detail panel, there's no way to override the pipeline's decisions for a specific function. The user should be able to:

- **Force a context tier** for the next attempt
- **Override the retry strategy** (e.g., force "escalate" instead of "compile_fix")
- **Add custom failure hints** beyond what the system auto-generates
- **Manually mark a function as Skip** without waiting for the classifier

**Recommendation:** In the unit detail panel, add a **"Overrides"** tab:

```
┌──────────────────────────────────────────────────────────────┐
│  Overrides for: game_logic!DrawSprite                        │
│                                                              │
│  ── Context Tier ─────────────────────────────────────────── │
│  Current: T2 (with_tests)                                    │
│  Force tier: [Disassembly ▼]  [Apply]                       │
│                                                              │
│  ── Retry Strategy ───────────────────────────────────────── │
│  Current: compile_fix                                        │
│  Force strategy: [escalate ▼]  [Apply]                      │
│                                                              │
│  ── Custom Failure Hints ─────────────────────────────────── │
│  Previous attempt (v2) had wrong shader constant mapping.   │
│  The LLM mapped D3DRS_LIGHTING to a fixed value instead     │
│  of reading from the shader constant buffer.                │
│  [Add Hint]                                                 │
│                                                              │
│  ── Function Classification ──────────────────────────────── │
│  Current: Function Translation                               │
│  Change to: [Function Translation ▼] (also: Skip, Test Case)│
│                                                              │
│  ── Notes ────────────────────────────────────────────────── │
│  [Add reviewer notes for the LLM ──────────────────────────]│
│  [Submit to Queue]                                          │
└──────────────────────────────────────────────────────────────┘
```

### 2.3 Pipeline Lifecycle Control

**What's missing:** There is no UI mechanism to control the overall translation pipeline lifecycle. Once the pipeline starts, it runs autonomously. The user has no way from the UI to:

| Control | Why it matters |
|---------|---------------|
| **Pause translation** | Temporarily halt the pipeline (e.g., to review accumulated results, fix a config issue, or reduce costs) without losing progress |
| **Resume translation** | Continue from where the pipeline paused, picking up the next queued function |
| **Stop / abort translation** | Gracefully stop the pipeline — complete the current function, then halt |
| **Restart translation** | Restart the pipeline from a specific phase (e.g., re-run test generation for a binary, or re-translation from scratch after config changes) |
| **Force cancel current function** | Abort the function currently being processed (e.g., if the LLM call is stuck or producing bad output) |
| **Graceful shutdown** | Stop the web server and all translation processes cleanly |

**Recommendation:** Add a **Pipeline Controls** header bar (always visible, fixed at the top or in a dedicated "Controls" view):

```
┌──────────────────────────────────────────────────────────────────────────────────────┐
│  Pipeline Controls                                                                    │
│                                                                                      │
│  Pipeline: [Running  |  Paused  |  Complete  |  Stopped]  Target: game_logic.dll     │
│                                                                                      │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────────────┐  │
│  │  ▶ Start  │  │  ⏸ Pause │  │  ⏹ Stop  │  │  ↻ Restart│  │  ⏻ Shut Down Server │  │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘  └──────────────────────┘  │
│                                                                                      │
│  Restart options (shown when Restart is clicked):                                     │
│  ┌────────────────────────────────────────────────────────────────────────────────┐  │
│  │  Restart from phase: [Function Translation (Phase 4) ▼]                        │  │
│  │  Target:          [All queued functions ▼]   [From specific binary ▼]            │  │
│  │  Scope:           [All functions]  [Only queued]  [Only failed]                │  │
│  │  ──────────────────────────────────────────────────────────────────────────── │  │
│  │  ┌─ Confirm ────────────────────────────────────────────────────────────────┐  │  │
│  │  │ This will restart the pipeline from Phase 4. Current progress will be   │  │  │
│  │  │ preserved, but functions from Phase 4 onward will be re-evaluated.      │  │  │
│  │  │ [Cancel]  [Confirm Restart]                                             │  │  │
│  │  └─────────────────────────────────────────────────────────────────────────┘  │  │
│  └────────────────────────────────────────────────────────────────────────────────┘  │
│                                                                                      │
│  Graceful shutdown (shown when Shut Down Server is clicked):                         │
│  ┌────────────────────────────────────────────────────────────────────────────────┐  │
│  │  Shutting down will:                                                            │  │
│  │  1. Pause the pipeline                                                        │  │
│  │  2. Complete the current function (up to 2 min)                                │  │
│  │  3. Save all state to disk                                                     │  │
│  │  4. Stop the web server                                                        │  │
│  │  ──────────────────────────────────────────────────────────────────────────── │  │
│  │  [Cancel]  [Shut Down Now]                                                     │  │
│  └────────────────────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────────────────┘
```

**API endpoints required:**

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/pipeline/pause` | `POST` | Pause the pipeline at next safe point |
| `/api/pipeline/resume` | `POST` | Resume the paused pipeline |
| `/api/pipeline/stop` | `POST` | Stop the pipeline (complete current, then halt) |
| `/api/pipeline/restart` | `POST` | Restart from a specified phase |
| `/api/pipeline/cancel-current` | `POST` | Abort the currently processing function |
| `/api/server/shutdown` | `POST` | Graceful shutdown of the web server + pipeline |
| `/api/server/health` | `GET` | Health check endpoint (for external monitoring) |
| `/api/server/status` | `GET` | Returns pipeline status + server uptime |

**State machine for pipeline:**

```
                  ┌─────────┐
                  │ Idle    │◄──────────────────────────┐
                  └────┬────┘                            │
                       │ start()                         │
                  ┌────▼────┐                            │
               ┌──│ Running │────────────┐               │
               │  └────┬────┘            │ pause()       │
               │       │ pause()         ▼               │
               │  ┌────▼────┐                     ┌──────▼──────┐
               └─ │ Paused  │◄────────────────────│ Stopping    │
                  └────┬────┘   resume()          └──────┬──────┘
                       │ stop()                           │ stop_current()
                  ┌────▼────┐                            │
               ┌──│ Complete│───────────────────────────┘
               │  └─────────┘
               │
               └──► ┌─────────┐
                    │ Error   │
                    └─────────┘
```

**Safety considerations:**

- **Pause** must be atomic: wait for the current LLM call to finish (or timeout), save state, then set pipeline state to `Paused`
- **Stop** should clean up any temporary branches, abort in-flight LLM calls, and save the pipeline state so it can be resumed or restarted
- **Restart** must validate the target phase is valid (can't restart Phase 1 if binaries have already been classified and accepted)
- **Shutdown** must ensure all state is persisted — the web server and the translation backend should both flush to disk before exiting
- All lifecycle operations should emit a `ProgressEvent` so the WebSocket stream remains consistent

### 2.4 Web Server Management

**What's missing:** There is no documented or UI-exposed mechanism for managing the web server lifecycle. In production or long-running scenarios, the user may need to:

- **Start the web server** — Run the server with configurable options (host, port, log level)
- **Restart the web server** — Reload configuration, apply updates, or recover from a crash
- **Graceful shutdown** — Stop accepting new requests, finish in-flight requests, then exit
- **Health monitoring** — Know if the server is healthy, what the uptime is, any errors
- **Resource monitoring** — Memory usage, open file handles, active WebSocket connections

**Recommendation:** Add a **System** view or a **System** section on the dashboard:

```
┌──────────────────────────────────────────────────────────────┐
│  System                                                      │
│                                                              │
│  ── Server Status ────────────────────────────────────────── │
│  Server:         Running                                     │
│  Uptime:         3d 14h 22m                                 │
│  Version:        0.1.0-dev                                  │
│  Host:           0.0.0.0:8080                               │
│  Log level:      [Info ▼]                                   │
│                                                              │
│  ── Resources ────────────────────────────────────────────── │
│  Memory:         1.2 GB / 8.0 GB  ████████░░ 15%            │
│  CPU:            2 cores busy (12% overall)                 │
│  WebSocket conns: 3                                           │
│  Open files:     142                                         │
│                                                              │
│  ── Actions ──────────────────────────────────────────────── │
│  [↻ Restart Server]  [⏻ Shut Down Server]                   │
│                                                              │
│  ── Recent Server Events ─────────────────────────────────── │
│  [Info]  14:32:01  Pipeline resumed by user                  │
│  [Info]  14:30:15  Pipeline paused by user                   │
│  [Warn]  12:15:44  WebSocket connection dropped (client)     │
│  [Info]  10:00:01  Server started on 0.0.0.0:8080           │
│  [Info]  10:00:00  Loading project state...                  │
│  [Info]  09:59:58  Version: 0.1.0-dev                        │
└──────────────────────────────────────────────────────────────┘
```

**API endpoints required:**

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/server/status` | `GET` | Server status, uptime, version, resources |
| `/api/server/restart` | `POST` | Graceful restart of the web server |
| `/api/server/shutdown` | `POST` | Graceful shutdown |
| `/api/server/log-level` | `PATCH` | Change log level at runtime |
| `/api/server/health` | `GET` | Simple health check (`{"status": "ok"}`) |
| `/api/server/metrics` | `GET` | Prometheus-style metrics endpoint (optional) |

**Restart behavior:**
- A restart should fork a new server process, wait for it to be ready, then send SIGTERM to the old process
- This ensures zero downtime — existing WebSocket connections reconnect to the new process
- The pipeline state is persisted before restart so it can resume automatically

---

### 2.5 Binary Classification Override

```
┌──────────────────────────────────────────────────────────────┐
│  Binary: unknown_plugin.dll                                  │
│                                                              │
│  Current classification: UnknownThirdParty                   │
│  → Strategy: Reverse engineer from disassembly               │
│                                                              │
│  Override classification:                                    │
│  [WindowsOs] [MicrosoftSdk] [KnownThirdParty]               │
│  [ProjectSpecific] [UnknownThirdParty] [RuntimeLibrary]     │
│                                                              │
│  If crate replacement: target crate [__________]             │
│                                                              │
│  [Apply Override]                                            │
└──────────────────────────────────────────────────────────────┘
```

---

## 3. Missing Information — Historical & Analytical Data

### 3.1 Fault / Error Tracking

**What's missing:** The system has rich fault detection types (`ContextWindowFault`, `Hallucination`, `InfiniteLoop`, `BehaviorDivergence`, `ResourceExhaustion`, `SlowResponse`, `PromptCorruption`) stored in a `FaultLog`, but the UI shows **nothing** about faults. The user has no visibility into:

- How many faults occurred across the pipeline
- Which binaries or functions generate the most faults
- What recovery actions were taken
- Whether fault rates are improving over time

**Recommendation:** Add a **Faults & Errors** view:

```
┌──────────────────────────────────────────────────────────────┐
│  Faults & Errors                                             │
│                                                              │
│  ── Summary ──────────────────────────────────────────────── │
│  Total faults: 47 | Warnings: 31 | Errors: 12 | Critical: 4 │
│  Hallucinations: 3 | Context Overflows: 18 | Loops: 2       │
│  Divergence: 15 | Resource Exhaustion: 6 | Slow: 3          │
│                                                              │
│  ── By Binary ─────────────────────────────────────────────── │
│  game_logic.dll      ████████████████████░░  23              │
│  directx_render.dll  ██████████████░░░░░░░░  14              │
│  audio_engine.dll    █████░░░░░░░░░░░░░░░░   6              │
│  unknown_plugin.dll  ████░░░░░░░░░░░░░░░░   4               │
│                                                              │
│  ── Recent Faults ────────────────────────────────────────── │
│  [Error] context_window_exceeded  │ game_logic!DrawSprite v3 │
│         Response 150k chars exceeded 131k limit             │
│         → Split into 7 chunks, retrying                      │
│                                                              │
│  [Error] hallucination        │ directx_render!InitShaders v2│
│         Referenced non-existent: D3DRS_FOOBAR               │
│         → Branch from last good commit                      │
│                                                              │
│  [Warning] behavior_divergence│ game_logic!ComputeValue v2   │
│         5/5 baseline pass, 2/4 edge cases fail (conf: 8/10) │
│         → Enrich test suite, retrying                       │
│                                                              │
│  ── Trend ────────────────────────────────────────────────── │
│  [Line chart: faults per day — 3 day avg]                  │
│                                                              │
│  [Export to CSV]  [Filter by category]  [Filter by binary] │
└──────────────────────────────────────────────────────────────┘
```

### 3.2 Token Usage & Cost Tracking

**What's missing:** Token usage is tracked per-attempt in `TokenUsageLog` with per-binary and per-function breakdowns, but this is invisible in the UI. The user wants to see:

- Total tokens consumed across the pipeline
- Per-binary token breakdown
- Per-function token breakdown
- Tokens consumed by successful vs. failed attempts
- Context tier vs. token cost correlation
- Token budget remaining (if a budget is set)

**Recommendation:** Add a **Token Usage** view or tab:

```
┌──────────────────────────────────────────────────────────────┐
│  Token Usage                                                 │
│                                                              │
│  ── Overall ──────────────────────────────────────────────── │
│  Total tokens:     4,234,567                                 │
│  Successful:       3,456,789 (81.6%)                         │
│  Failed:           777,778  (18.4%)                          │
│  Budget:          10,000,000  (42.3% used)                   │
│                                                              │
│  ── By Binary ─────────────────────────────────────────────── │
│  game_logic.dll       1,823,456  (43.0%) ██████████         │
│  directx_render.dll   1,234,567  (29.2%) ██████             │
│  audio_engine.dll      456,789  (10.8%) ████                │
│  unknown_plugin.dll    312,000  (07.4%) ██                  │
│  Other binaries            407,755  (09.6%) ███                 │
│                                                              │
│  ── By Context Tier ──────────────────────────────────────── │
│  T0 Stub                     12,345  (0.3%)                 │
│  T1 Disassembly              234,567  (5.5%)                │
│  T2 WithTests              1,456,789  (34.4%)               │
│  T3 ModuleContext          1,890,123  (44.6%)               │
│  T4 FullModule               640,743  (15.2%)               │
│                                                              │
│  ── Strategy Breakdown ───────────────────────────────────── │
│  initial          1,234,567  (29.2%)  Success rate: 62.3%  │
│  compile_fix      1,456,789  (34.4%)  Success rate: 45.1%  │
│  test_fix         1,123,456  (26.5%)  Success rate: 38.7%  │
│  escalate          419,755  (09.9%)   Success rate: 22.4%  │
│                                                              │
│  ── Cost Estimate ────────────────────────────────────────── │
│  Estimated cost: $12.47 (based on $2.95/1M input tokens)    │
└──────────────────────────────────────────────────────────────┘
```

### 3.3 Experiment / Strategy Analytics

**What's missing:** The `PromptStrategyLog` tracks pass rates per strategy per binary category, but this data is never displayed. The user should be able to see:

- Which retry strategies are most effective
- Whether the current strategy selection logic is working
- Whether certain strategies are overused or underused
- Comparative pass rates by binary category (to identify hard categories)

**Recommendation:** Add a **Strategy Analytics** view:

```
┌──────────────────────────────────────────────────────────────┐
│  Strategy Analytics                                          │
│                                                              │
│  ── Pass Rate by Strategy ────────────────────────────────── │
│  Strategy       | Attempts | Success | Fail | Pass Rate     │
│  ───────────────┼──────────┼─────────┼──────┼────────────── │
│  initial        |    312   |    194  |  118 │    62.2%  █████│
│  compile_fix    |    245   |    110  |  135 │    44.9%  ████  │
│  test_fix       |    198   |     76  |  122 │    38.4%  ███   │
│  escalate       |     87   |     19  |   68 │    21.8%  ██    │
│                                                              │
│  ── Pass Rate by Binary Category ──────────────────────────── │
│  Category            | Attempts | Success | Pass Rate         │
│  ────────────────────┼──────────┼─────────┼────────────────── │
│  ProjectSpecific     |    567   |    412  │    72.7%  ██████│
│  MicrosoftSdk        |    123   |     98  │    79.7%  ███████│
│  KnownThirdParty     |     45   |     38  │    84.4%  ███████│
│  UnknownThirdParty   |     34   |     12  │    35.3%  ██    │
│                                                              │
│  ── Complexity vs. Pass Rate ─────────────────────────────── │
│  Complexity  | Attempts | Success | Pass Rate                 │
│  Minimal     |     89   |     78  │    87.6%  ████████       │
│  Standard    |    234   |    178  │    76.1%  ███████        │
│  Rich        |    267   |    167  │    62.5%  █████          │
│  Detailed    |    291   |    147  │    50.5%  ████           │
│                                                              │
│  [Export CSV]  [Time range: [Last 7 days ▼]]                │
└──────────────────────────────────────────────────────────────┘
```

### 3.4 LLM Performance Metrics

**What's missing:** The system tracks LLM call timing, response sizes, and timeout events, but the UI doesn't aggregate this information. The user should see:

- Average response time per call
- P50/P95/P99 response latencies
- Timeout frequency
- Model-specific performance (if multiple models are used)
- Correlation between context tier and response time

**Recommendation:** Add a **LLM Performance** section within the Token Usage view or as a separate view.

---

## 4. Proposed New Views

### 4.1 Binaries View

A dedicated view for managing binary classification, shim layer status, and per-binary translation progress.

**Sections:**

1. **Binary Summary Table** — Name, category, strategy, functions (total/done/queued/failed), token usage, shim status, PAL status
2. **Binary Detail Panel** (click to expand) — Exports, imports, classification reasoning, override classification, per-function list
3. **Shim Layer Tracker** — Which shims exist, their test pass rate, whether they're accepted
4. **PAL Trait Tracker** — Which traits are defined, which are needed but missing

### 4.2 Faults View

A dedicated view for all fault events (see section 3.1 above for mockup).

### 4.3 Token Usage View

A dedicated view for token tracking and cost analysis (see section 3.2 above for mockup).

### 4.4 Strategy Analytics View

A dedicated view for experiment data and strategy comparison (see section 3.3 above for mockup).

### 4.5 Pipeline Dashboard (Enhanced)

A high-level view showing overall progress across all 7 phases. This could be the default landing page instead of the current dashboard.

---

## 5. Proposed Enhancements to Existing Views

### 5.1 Dashboard View — Additions

| Addition | Description |
|----------|-------------|
| **Phase progress bar** | Horizontal bar showing progress through all 7 phases |
| **Time estimate** | Based on average function translation time × remaining functions |
| **Quick actions** | "Start Translation", "Pause", "Configure" buttons |
| **Binary count cards** | Breakdown of binaries by category (instead of just status counts) |
| **Quality summary** | Average confidence, baseline pass rate, verification pass rate |
| **Token budget** | Visual indicator of token consumption vs. budget |

### 5.2 Unit Detail Panel — Additions

| Addition | Description |
|----------|-------------|
| **Context tier info** | Which tier was used, why it was selected (complexity, API count, history) |
| **Retry strategy** | Current strategy, previous strategies used, success rate per strategy |
| **Fault history** | Any faults detected for this unit, with severity and recovery |
| **Token count** | Tokens consumed for this unit across all attempts |
| **Attempt comparison** | Side-by-side diff of code across attempts (not just latest vs. main) |
| **Overrides tab** | Per-function overrides for tier, strategy, skip, hints |
| **Call graph context** | Who calls this function, what this function calls (from call graph analysis) |
| **Windows API mapping** | Which Windows APIs were identified and their PAL/crate mappings |

### 5.3 Queue View — Additions

| Addition | Description |
|----------|-------------|
| **Priority column** | Show priority level (HIGH/NORMAL/LOW) for each queued function |
| **Skip column** | Checkbox to mark a unit for skipping |
| **Multi-select** | Select multiple units and take batch action (accept all, skip all, send back all) |
| **Reorder** | Drag-and-drop to reorder the queue |
| **Estimate column** | Estimated time to translate based on historical data |

### 5.4 Graph View — Enhancements

| Enhancement | Description |
|-------------|-------------|
| **Filter by kind** | Show only function translations, or only shim layers, etc. |
| **Filter by status** | Show only failed units, only pending, etc. |
| **Filter by binary** | Show only nodes from a specific binary |
| **Node size by token usage** | Larger nodes = more tokens consumed |
| **Node color by confidence** | Red = low confidence, green = high confidence |
| **Edge labels** | Show edge type (call, dependency, data flow) |
| **Export graph** | Save as SVG/PNG or shareable URL |

### 5.5 LLM I/O Log — Enhancements

| Enhancement | Description |
|-------------|-------------|
| **Filter by binary** | Show only events for a specific binary |
| **Filter by function** | Show only events for a specific function |
| **Filter by attempt** | Show only events for a specific attempt number |
| **Filter by strategy** | Show only events for a specific strategy |
| **Search prompt content** | Full-text search through prompts |
| **Collapsible entries** | Expand to read full prompt/response, collapsed shows metadata |
| **Copy prompt/response** | One-click copy for debugging |
| **Token count per entry** | Show tokens consumed per LLM call in the log |

---

## 6. Implementation Priority Matrix

### Phase 1 — Essential Visibility (Weeks 1-2)

These changes give the reviewer the most critical information gaps:

| # | Feature | Impact | Effort |
|---|---------|--------|--------|
| 1 | Unit detail: context tier info | High — explains LLM decision | Low |
| 2 | Unit detail: fault history | High — explains failures | Low |
| 3 | Pipeline overview phase progress | High — big-picture status | Medium |
| 4 | Unit detail: token count | Medium — cost awareness | Low |
| 5 | Pipeline panel: binary strategy | Medium — explains per-binary approach | Medium |
| 6 | Server status card on dashboard | Medium — know if server is alive | Low |

### Phase 2 — Process Control (Weeks 3-4)

These changes give the reviewer active control:

| # | Feature | Impact | Effort |
|---|---------|--------|--------|
| 7 | Unit detail: overrides tab | High — direct control | High |
| 8 | Translation controls (scope, limits) | High — pipeline influence | High |
| 9 | Binary classification override | Medium — fix misclassifications | Medium |
| 10 | Queue: skip checkboxes | Medium — quick control | Low |
| 11 | Queue: multi-select batch actions | Medium — efficiency | Medium |
| 12 | Pipeline pause/resume/stop controls | High — pipeline lifecycle | High |
| 13 | Pipeline restart with phase selector | High — recover from bad state | High |
| 14 | Server shutdown & restart endpoints | High — operational control | Medium |

### Phase 1.5 — Server Management (Week 2-3)

These changes enable operational control of the web server itself:

| # | Feature | Impact | Effort |
|---|---------|--------|--------|
| 15 | Health check endpoint | High — external monitoring | Low |
| 16 | Server status/metrics endpoint | Medium — resource awareness | Low |
| 17 | System view (server status, restart, shutdown) | Medium — operational UX | Medium |
| 18 | Zero-downtime server restart | Medium — production readiness | High |
| 19 | Runtime log level change | Low — debugging convenience | Low |

### Phase 3 — Analytics (Weeks 5-6)

These changes provide historical insight:

| # | Feature | Impact | Effort |
|---|---------|--------|--------|
| 20 | Faults view | High — understand failure patterns | Medium |
| 21 | Token usage view | Medium — cost management | Medium |
| 22 | Strategy analytics view | Medium — improve strategy selection | Medium |
| 23 | LLM performance metrics | Low — operational insight | Medium |
| 24 | Binaries view | Medium — comprehensive binary management | High |

### Phase 4 — Polish (Weeks 7-8)

These are nice-to-have enhancements:

| # | Feature | Impact | Effort |
|---|---------|--------|--------|
| 25 | Graph: advanced filtering | Medium — better graph navigation | Medium |
| 26 | LLM log: search & filters | Medium — better debugging | Medium |
| 27 | Unit detail: attempt comparison | Medium — see iteration history | High |
| 28 | Dashboard: time estimates | Low — planning aid | Low |
| 29 | Pipeline: quick actions | Low — convenience | Low |
| 30 | Pipeline: cancel current function | Low — emergency abort | Low |

---

## 7. API Endpoints Reference

### Pipeline Lifecycle Endpoints

| Endpoint | Method | Request Body | Description |
|----------|--------|-------------|-------------|
| `/api/pipeline/pause` | `POST` | `{}` | Pause the pipeline at the next safe point |
| `/api/pipeline/resume` | `POST` | `{}` | Resume a paused pipeline |
| `/api/pipeline/stop` | `POST` | `{}` | Stop the pipeline (complete current function, then halt) |
| `/api/pipeline/restart` | `POST` | `phase: string, scope: string, target?: string` | Restart from a specified phase with optional scope |
| `/api/pipeline/cancel-current` | `POST` | `{}` | Abort the currently processing function |
| `/api/pipeline/status` | `GET` | — | Returns pipeline state, current function, elapsed time |

### Server Management Endpoints

| Endpoint | Method | Request Body | Description |
|----------|--------|-------------|-------------|
| `/api/server/status` | `GET` | — | Server status, uptime, version, resource usage |
| `/api/server/restart` | `POST` | `{}` | Graceful restart (zero-downtime) |
| `/api/server/shutdown` | `POST` | `{}` | Graceful shutdown of server + pipeline |
| `/api/server/log-level` | `PATCH` | `{level: string}` | Change log level at runtime |
| `/api/server/health` | `GET` | — | Simple health check (`{"status": "ok"}`) |
| `/api/server/metrics` | `GET` | — | Prometheus-style metrics (optional) |

### Pipeline Status Response

The `GET /api/pipeline/status` and `GET /api/server/status` endpoints should return:

```json
{
  "pipeline": {
    "state": "running",
    "currentPhase": 4,
    "currentPhaseName": "Function Translation",
    "currentBinary": "game_logic.dll",
    "currentFunction": "ComputeValue",
    "startedAt": "2025-06-15T14:32:00Z",
    "elapsedMs": 22980000,
    "functions": {
      "total": 842,
      "translated": 312,
      "inProgress": 1,
      "queued": 487,
      "failed": 5,
      "skipped": 20
    },
    "binaries": {
      "total": 3,
      "classified": 3,
      "translating": 1,
      "complete": 2
    }
  },
  "server": {
    "uptimeMs": 3600000,
    "version": "0.1.0-dev",
    "logLevel": "info",
    "memoryUsageMB": 1228,
    "openFileHandles": 142,
    "activeWebSocketConnections": 3
  }
}
```

---

## Appendix: Data Sources Reference

For implementers, here's where the data comes from:

| Data | Source Type | File |
|------|------------|------|
| Fault events | `FaultLog.entries` | `types/src/fault.rs` |
| Token usage | `TokenUsageLog.entries` | `types/src/token_usage.rs` |
| Strategy experiments | `PromptStrategyLog.entries` | `types/src/experiment_log.rs` |
| Context tier selection | `select_context_tier()` + `ProgressEvent::ContextTierSelected` | `types/src/context_tier.rs` |
| Function complexity | `FunctionComplexity` | `types/src/complexity.rs` |
| DLL classification | `DllInfo.category` + `ProgressEvent::ClassificationComplete` | `types/src/dll.rs` |
| Translation progress | `ProgressEvent` variants | `types/src/progress.rs` |
| Batch summaries | `ProgressEvent::BatchSummary` | `types/src/progress.rs` |
| Unit details | `ReviewDashboard` + `UnitOfWork` | `types/src/dashboard/review.rs`, `types/src/dashboard/work_unit.rs` |
| Git branches | `calxgloss_git::GitManager` | `crates/calxgloss-git/` |
| Ghidra context | `GhidraContext` | `web/src/server/types.rs` |
| API server | axum handlers | `crates/calxgloss-web/src/server/` |
| Pipeline state | `PipelineState` (new type) | `types/src/pipeline_state.rs` (proposed) |
| Server state | `ServerManager` (new type) | `web/src/server/server_manager.rs` (proposed) |
