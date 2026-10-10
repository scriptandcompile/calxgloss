# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Queue multi-select & batch actions** — the review queue can now act on many units at once: every queue row carries a selection checkbox, the list header gained a select-all checkbox (indeterminate when only part of the visible queue is selected), and the queue toolbar a batch-action dropdown — Accept All, Send Back All, Skip All. `POST /api/batch/{accept,send-back,skip}` (registered in the shared routes, so every mode answers them) take a set of unit IDs and run each one through exactly the same logic the per-unit endpoints use — no duplicated state transitions — answering 200 with a per-unit success/failure report even when some units fail; an empty selection is rejected with 400. The UI reports the outcome honestly: a summary toast names how many succeeded and how many failed with the first failure's reason, a send-back batch requires a reason, and the selection clears once the batch runs (issue #78, W1-4).

- **Server-side LLM I/O log** — every LLM request, response, and failed call a live run emits is now persisted server-side to `re/analysis/llm_io/log.jsonl` the moment it happens, carrying its binary, function, attempt, strategy, and token count. `GET /api/llm-io` (registered in the shared routes, so both `serve` and `live` answer it) serves the retained window oldest-first with that metadata; a workspace that has never run live honestly answers with an empty payload. Growth stays bounded: the log keeps the newest 500 entries and rotates the older ones out, so a long run's log file never grows without limit. The prompt/response history a page reload used to wipe is now on disk — the prerequisite for the log UI's search and filters (issue #77, W1-7).

- **Dependency graph filters & visual encoding** — the graph payload (`GET /api/graph`) now carries display enrichment on every node — its binary, token usage (summed from the pipeline's usage log with the same binary+function join the unit detail uses), and confidence — plus a relationship type on every edge (`dependency`, `call`, `data_flow`); artifacts with no value leave each field absent rather than fabricating one, and old artifacts without edge types deserialize as plain dependencies. The graph view puts it to work: Kind/Status/Binary filter selects combine with AND and report what survives as an "X of Y nodes" summary, node height encodes token usage (sqrt scale — unmeasured units keep the base size, never zero), node color encodes confidence (red low → green high, neutral when unmeasured), and every edge is labeled with its type (issue #76, W1-5).
- **WS phase events — live view driven by pushed records** — after applying each unit-scoped pipeline event, the live server pushes a `unit_phase` record over the existing WebSocket: the unit's full live state — current phase, phase history in event order, context tier, retry strategy, attempt, baseline/verification evidence, confidence, and elapsed time. The Live tab updates rows in place from these records instead of refetching `/api/progress/enhanced` on every event, and the phase chip's tooltip shows the path the unit walked (a tier escalation appears twice in it). Raw pipeline events keep flowing unchanged for every other consumer, and after a WebSocket reconnect the live view resyncs from a fresh snapshot rather than trust stale rows (issue #55, W0 Phase 2 tail).
- **Queue plan in the pipeline table** — the live loop now announces its ordered plan with a new `QueuePlanned` event before the first pass starts, and the pipeline table follows it: rows appear in the exact order the run will process them (the auto loop's order — EXEs first, then DLLs, each alphabetical), with the whole queue visible as rows even before a binary's pass begins and unplanned binaries after it, alphabetical. The row order finally answers "what's next" instead of leaving it to the terminal.
- **Analysis-pass heartbeat** — the pre-translation passes (call-graph extraction and the evidence scans) now beat per function while they walk their work list: a new `BatchProgress` progress event names the pass ("type inference", "call graph", … — a free string, so new evidence crates need no new event), the function being pulled, and the position in the pass's own work list. The Ghidra client carries the heartbeat (armed around each pass, throttled to ~2 beats/sec, work-list size as the total), `/api/pipeline` surfaces the latest beat as `activity` on the processing binary's row, and the pipeline table renders it as a full-width strip under the row — e.g. `type inference · FUN_1929282 · 1 of 22,143` — so minutes of Ghidra-bound analysis are visible instead of mysterious. Passes with no per-item granularity beat with just their name; unknown position renders as nothing rather than a fake counter.
- **Per-binary progress panel** — the dashboard's pipeline panel now shows one row per target binary: classification strategy (PAL Mapping / Crate Replacement / Reverse Engineer), function counts (total, translated, in-progress, queued, failed), token consumption, success rate, and shim-layer / PAL trait status — all derived from the live event stream, with unknown totals, tokens, queued counts, and rates rendered as "—" rather than fabricated zeros. Quick-action buttons (Start Translation, Pause, Configure) are clearly-marked placeholders that announce pipeline control arrives in W2; they touch no pipeline state.
- **Pipeline phase progress bar** — the dashboard now shows where the whole effort stands against the master plan: a horizontal bar across all 7 pipeline phases plus Phase 2.5 (PAL Design), derived from live progress data, each segment honestly marked not started / in progress / complete — or, for Restitching and Documentation which have no backing data source yet, "no data source" rather than fabricated progress. `GET /api/pipeline` reports these phase states and per-binary function counts, and plain `calxgloss serve` now answers it with an honest empty payload instead of 404, so the bar renders in every mode.
- **Server lifecycle control** — the operator can stop and retune the running server without killing work, in both `serve` and `live`: `POST /api/server/shutdown` stops the server gracefully and pauses a live pipeline at the current unit boundary (the unit in flight finishes and is saved first); `POST /api/server/restart` saves state the same way, stops the process, and returns a manual-restart signal — the server never forks a replacement process; `PATCH /api/server/log-level` changes the running process's log verbosity (`off`/`error`/`warn`/`info`/`debug`/`trace`, invalid names rejected, nothing persists across restarts). The dashboard gained a server control panel with shutdown/restart buttons and a log-level selector.
- **Server status & enhanced health probe** — `GET /api/server/status` reports how the server itself is doing: pipeline state (no pipeline / idle / running), uptime, version, host, log level, memory and CPU usage, live WebSocket connection count, and open file handles — gathered cross-platform on Windows/macOS/Linux, and available in both `serve` and `live`. The `/health` probe now also reports workspace accessibility, uptime, and version, and the dashboard gained a server status card rendering these values.
- **Unit detail process telemetry** — the unit detail endpoint (`GET /api/units/{id}`) now carries a `process` object: the context tier the unit was translated at (with escalation flag, per-attempt tier/strategy history, and a rationale recomputed from the Ghidra artifact — complexity and Windows API call count), fault history from `re/analysis/fault_log.json`, token totals and a per-attempt breakdown from `re/analysis/token_usage.json`, and per-strategy retry success rates. The review UI renders these as four new detail sections: Context Tier, Fault History, Token Usage, and Retry Strategies. Everything is derived from artifacts the pipeline already writes — no new persistence — and missing or corrupt artifacts degrade to empty sections, never errors.
- **Unit detail analysis context** — the unit detail endpoint (`GET /api/units/{id}`, shared by every router) now carries an `analysis` object: the Windows API calls identified for the unit's function, each with its category and PAL/crate mapping (read from the per-function analysis artifact at `re/analysis/{binary}/{function}.json`), and the function's call-graph context — who calls it and what it calls, by name (read from the per-binary call-graph record at `re/analysis/{binary}_call_graph.json`; caller addresses resolve to function names through the graph, unresolvable ones show as hex addresses). The review UI renders these as two new detail sections: Windows API Mappings and Call Graph Context. No new persistence — both sections read artifacts the pipeline already writes, and missing or corrupt ones degrade to empty sections, never errors (issue #73).
- **In-flight translation phases** — during a live run every translating unit reports the pipeline step it is in (Ghidra fetch, API tagging, baseline-test generation, context-tier selection, LLM call, compiling, testing, review). `/api/progress` now carries the current phase, the phase history in event order (context-tier escalations stay visible), and elapsed time per unit.
- **Per-attempt durations, pipeline time estimate, queue effort column** — every retry-loop attempt now records its wall-clock duration (`duration_secs`) into `re/analysis/token_usage.json`; old logs without durations load honestly as unmeasured. `GET /api/pipeline` derives a time estimate (average attempt duration × remaining functions) and omits it entirely when nothing has been measured, and the dashboard's pipeline panel renders it; `/api/dashboard` attaches per-unit effort estimates (the unit's own average, else the global average) and the review queue shows them in a new effort column, `—` when no durations exist (issue #64).
- **Live translation view** — a dedicated Live tab shows one progress bar per in-flight unit, labeled with its current pipeline phase and a live elapsed clock, plus context tier, retry strategy, attempt, baseline/verification pass status, and unit confidence. `GET /api/progress/enhanced` (registered in the live router only) serves the records, which live in the shared types crate so later tracks can consume them without the web crate; unit confidence is derived from evidence — the baseline pass share of the latest verified attempt, `0.0` when that attempt did not compile, absent until any attempt is verified — and unmeasured values render as `—` or "not run", never fabricated zeros. Rows update live over the existing WebSocket (issue #65).
- **Dashboard enhancements: category cards, quality summary, token budget, landing view** — the dashboard now speaks in categories and quality, not just statuses: cards counting the workspace's binaries in each classification category (tallied from the `re/classify` artifacts, all six categories always shown), a quality summary of average unit confidence plus baseline and verification pass rates across the dashboard units (each rendered `—` when no unit carries the underlying data, pass rates weighted by test count rather than averaged per unit), and a token budget visual comparing consumed tokens — read from the pipeline's usage log, honestly "no usage recorded" when there is none — against a user-set budget kept in the browser. The pipeline overview moved to its own tab, and a topbar landing-view select lets it be the view the dashboard opens on, a preference persisted client-side (issue #66).
- **Queue order & priority persistence, drag-and-drop reordering** — the review queue now remembers how the reviewer arranged it: a manual order plus a per-unit priority (HIGH/NORMAL/LOW) persist to `re/review/queue_overlay.json` and survive restarts. The queue gained a priority column — clicking a unit's chip cycles NORMAL → HIGH → LOW — and rows can be dragged to a new position. Dependency ordering still dominates: the overlay only breaks ties between units at the same dependency depth, so no manual arrangement can ever put a unit ahead of its prerequisites. `GET`/`PUT /api/queue/overlay` (registered in the shared routes, so both `serve` and `live` answer them) read and write the overlay and return the effective queue order, letting an illegal drag snap back to the legal position (issue #74).
- **Skip state for review units** — a unit the reviewer doesn't want to look at right now can be set aside: every queue row carries a skip checkbox, and checking it takes the unit out of the active queue — it leaves the sidebar count, the dependency-ordered queue, and the next-unit flow, and is tallied separately as Skipped with its own status card and filter option. `POST /api/units/{id}/skip` and `POST /api/units/{id}/unskip` (registered in the shared routes, so every mode answers them) update a skip set persisted at `re/review/skips.json`; the dashboard builder applies it on every rebuild, so skips survive restarts and show in the CLI dashboard too. A merged (Accepted) unit refuses the skip — branch state is authoritative — and unchecking restores the unit's artifact-derived status and queue position (issue #75).

### Changed

- **Fast-forward merge logs once** — the git fast-forward merge path printed its `Fast-forward merge` debug line twice per merge; it now logs once (issue #87).
- **Bounded run-telemetry logs** — the run telemetry logs (`re/analysis/token_usage.json`, `re/analysis/fault_log.json`, `re/analysis/prompt_strategy_log.json`) no longer grow without bound: each keeps at most 10,000 newest entries, and as new entries arrive past that cap the oldest are dropped, so a long run's log file and its per-entry rewrite cost stay bounded. The trimmed-away history keeps counting where it matters — dashboard token totals, fault counts, strategy pass rates, and pipeline time estimates still cover the whole run — while the unit panel's per-attempt detail honestly covers only the retained window. Logs written before the cap load unchanged (issue #82).
- **Pseudo-C scanning lives in one place** — the byte scanners every evidence crate restated (call-site walking, argument splitting, paren matching, string/char-literal skipping, cast stripping, line lookup) now live in one `cscan` module in the shared types crate, configured per crate through `ScanOptions` (name continuation: plain / `::`-qualified / demangled-dot; preceding-byte rejection; keyword filter). Eleven files across five crates dropped ~2,000 lines of near-identical copies for one tested implementation, so a scanner fix — like the char-literal fix below — lands once.
- **Pipeline rows are fixed columns** — the per-binary pipeline progress rows now lay their items out as aligned columns (Binary, Total, Translated, In progress, Queued, Failed, Tokens, Success, Classification, Actions) with a header row, instead of flex items that expanded and contracted with their content; long filenames ellipsize instead of overflowing. The redundant strategy column and "Classified" badge are gone — one Classification column carries the state: PAL trait, Shim → crate, Full RE, or Unclassified. The status badge (In pipeline / Translating / Batch done) left the binary's name and moved into the Success column, where a real success rate replaces it once terminal outcomes exist.
- **Working-binary indicator** — a new `BatchStarted` progress event fires when the live pipeline begins a binary's pass (function enumeration, analysis recovery, test generation, translation), and `GET /api/pipeline` marks that binary `processing` until its batch summary lands. The pipeline table shows it as **Working** in the Success column — so a binary being prepared, before any function-level progress exists, is visibly different from one merely queued ("In pipeline").
- **Binary identity is the verbatim filename** — a target binary's identity is now its filename exactly as spelled, extension included (`game_logic.dll`, `eqgame.exe`), used unchanged in translation branch names (`re/{file}/{function}v{N}`), unit keys (`{file}/{function}`) and the API payloads that carry them, artifact directories (`re/baseline/{file}/…`), classification records (`re/classify/{file}.json`), and the review UI. Previously branch names dropped `.dll` while artifacts kept it, so every consumer joining the two worlds had to guess which convention a string followed, and a workspace holding both `foo.dll` and `foo.exe` was fragile. Dots need no escaping anywhere these strings live. Places that derive Rust identifiers from a binary name (crate and shim file names) keep using the stem — that is naming, not identity. No backwards compatibility: branches, refs, and workspaces from earlier runs are not migrated (issue #68).
- **Binary identity and unit key are types** — a binary's identity (the verbatim filename, `game_logic.dll`) and a unit's key (`{binary}/{function}`) now travel as their own small types through git branches, units of work, progress events, and the review UI, instead of bare strings every consumer re-parsed by hand; JSON payloads are unchanged. The branch-name grammar (`re/{file}/{function}v{N}`) was restated by three ad-hoc parsers that stayed in sync by hand — the CLI's accept parser, the dashboard builder's, and the live view's — and one shared parser now owns it. The CLI follows the vocabulary: `--binary` replaces `--dll`, `--binaries` replaces `--dlls`. Places deriving Rust identifiers from a binary name keep using the stem. No backwards compatibility (issue #69).

### Removed

- **Orphaned prompt templates deleted** — two prompt templates that sat unreferenced in the prompts crate are gone; the renderer already covers both jobs with other templates, and every shipped template now has a live reference (issue #87, closes roadmap X2).

### Fixed

- **Review actions can no longer silently disagree with git** — clicking Accept then Send Back fast on one unit let both actions read the unit's state at start, do their git work, and overwrite the unit's single action record — last write won. The dashboard could show SendBack while the code sat merged on main, and the pipeline might re-translate an accepted function. Each review action (accept, send-back, patch) now captures the unit's persisted action state at start and re-checks it before writing its own record: if a different action landed in the meantime, the action fails with a conflict error naming the state that won (HTTP 409) and leaves the record untouched, with an in-process lock making the re-check and the write atomic. Send-back and patch on an already-accepted unit are now refused outright — the code is merged and there is no un-merge path. Fixes #86.
- **A stalled browser tab no longer freezes live updates** — one hidden or background-throttled tab that stopped draining its WebSocket could block the broadcast loop on its full send buffer: every other tab's live view stalled with it, the server's own in-memory progress state waited in the same loop, and the upstream event channel overflowed and dropped events ("Lagged"), leaving rows stale until a reconnect. Delivery is now non-blocking — each message is handed to every client's buffer without ever waiting on a client — and a client whose buffer is full is disconnected instead; the browser reconnects and resyncs from a fresh snapshot like after any other drop. Fixes #85.
- **Double patch clicks no longer double the retry** — clicking "Request Patch" twice on the same unit computed the same next attempt twice, created the same v{N+1} branch twice, and spawned two background retry loops racing on one branch — double LLM cost and commits overwriting each other. The patch action now reads the unit's persisted action record first: if the next attempt already records a patch request, the response says `patch_already_in_progress` and nothing new is created — one branch, one record, one retry. A request after a previous patch attempt *finished* (the unit back in review at the new attempt) still starts a fresh attempt as before. Fixes #84.
- **Accepting a conflicting unit fails honestly** — accepting a unit whose branch can no longer merge cleanly onto main died deep in the merge and surfaced as an opaque internal error, and the web accept path could still record the unit as Accepted even though none of its code landed on main. The merge now checks for conflicts before committing anything: the reviewer is told exactly which files conflict, main is left untouched, the unit keeps its pre-accept status, and the accept record under `re/accepts/` says `conflicts:` instead of claiming a merge happened. Clean merges are unchanged — and the 3-way path, which previously failed at the tree-write step for every diverged branch, now actually produces the merge commit. Fixes #83.
- **Run logs survive a crash mid-save** — killing the process while a JSON artifact (token-usage log, fault log, experiment log, call graph, analysis cache, work-unit document) was being written could leave a half-written file where a valid document used to be; the next read failed to parse it, the logger logged "starting fresh", and the run's entire token/fault history was overwritten. Every persisted JSON document is now written atomically: the new document lands in a temp file beside the target and is renamed onto it, so a reader — or a crash — always sees either the previous complete document or the new one, never a truncated mix. Fixes #81.
- **Phantom-clean evidence scans when every decompile failed** — with several Ghidra CodeBrowser windows open the bridge can answer a scan's function listing from one program and its decompiles from another; every decompile then fails, and the evidence scans used to skip every function and finish "successfully", persisting an empty record under the target binary's name that was indistinguishable from a genuinely clean scan. The nine evidence scans now carry a skip-rate breaker: once more than half the function listing fails to decompile, the scan aborts with an error naming the counts ("Ghidra failed to decompile N of M functions — is the right program open?") and nothing is persisted. A few genuine failures — thunks, bad entry points — still skip with warnings as before. Fixes #71.
- **Function-name hints never invent a `.dll`** — the dependency graph's function-to-binary detector appended `.dll` to every extension-less name prefix it matched, so a hint from an `.exe` target (e.g. `eqgame_RunLoop`) could never resolve to `eqgame.exe`, and only a hardcoded allowlist of four names was recognized. The detector now resolves candidates against the workspace's classified binaries — verbatim or by stem, any extension — and returns the inventory's spelling verbatim; an extension-less candidate matching no real binary resolves to nothing rather than a fabricated identity. Fixes #70.
- **Dashboard baseline test counts never showed** — the review queue's baseline columns, the CLI dashboard, and the quality summary's baseline pass rate all rendered `—` even when baseline artifacts existed on disk: the dashboard's baseline scan looked for `baseline.json` directly under each binary directory instead of the per-function subdirectory the test generator writes, and the unit-side lookup cut the unit key at the wrong path segment, so the two sides never joined. Baseline artifacts under `re/baseline/{file}/{func}/baseline.json` now attach to their units on the verbatim `{binary filename}/{function}` identity, keeping `foo.dll` and `foo.exe` workspaces distinct. Fixes #67.
- **Dashboard bounce and graph reshuffle during live runs** — every progress event kicked off a full git-backed dashboard rebuild: the status-card row was wiped and rebuilt (the server status card living inside it was removed and re-added every time), and the dependency graph's node order followed the builder's filesystem input order, so the graph view re-ran its layered layout with reshuffled binaries every few seconds. WS-triggered refreshes are now coalesced into one rebuild per short window, status cards and the server card update in place only when their values change, and the dashboard's dependency graph orders its nodes and edges deterministically — the layout stays put unless the data actually moved.
- **Crate-replacement classifications read back honestly** — the `classify` command serializes `Strategy` as an enum: `PalMapping`/`ReverseEngineer` land as bare strings, but `CrateReplacement` lands as a tagged object (`{"CrateReplacement": {"crate_name": "steamworks"}}`). Both readers of `re/classify/*.json` assumed a string: the pipeline tab hydrated those binaries with an empty strategy — rendering them "Unclassified" after a restart despite correct records on disk — and the dashboard's unit view failed the whole record parse, losing even the category. Both now read the variant name from either form, so steam_api64.dll and the v8 family keep their Crate Replacement classification across restarts.
- **Empty pipeline table after restarting a live run** — the per-binary rows were derived only from the current process's event stream, so restarting `calxgloss live` over a workspace with prior work showed "No binaries discovered yet": already-classified binaries emit no classification events on a second run, and the binary being worked on had no row for the Working badge to sit on until its first function event (minutes of enumeration and analysis recovery away). `/api/pipeline` now hydrates classifications from the persisted `re/classify` artifacts (live events still supersede them) and counts the batch-started binary as discovered on `BatchStarted` alone.
- **Debug-build crash on char literals in decompiled bodies** — the argument splitter counted a `]` as a nesting closer but the paren matcher ignored brackets, so a char literal like `']'` (common in config-parsing code, e.g. `if (*pc == ']')`) underflowed the depth counter and panicked debug builds of `calxgloss-cli live`. The shared scanner now skips char literals when matching parens, splitting arguments, and finding call sites, and the depth counter saturates rather than wrapping on malformed input.
- **Stale cached UI assets** — the web server served static files with no cache headers, so browsers heuristically kept old CSS/JS and mixed it with new: the pipeline rows rendered with more columns than the header because an old script met a new stylesheet. Static responses now carry an ETag and `no-cache` revalidation (304 when the browser's copy is current), so an edited asset takes effect on the next reload.
- **Recent activity cycled and claimed "just now"** — the dashboard's Recent activity panel re-listed every accepted unit as freshly accepted on each refresh, in an order that shuffled between polls: the builder stamped units with the build clock instead of when the work happened, and the list was never sorted, so it followed filesystem order. Accepted units now carry their branch tip's commit time (classification units, their record file's mtime), and recent activity is ordered newest-first with a stable id tie-break.
- **Live progress events applied out of order** — the live server spawned one task per progress event to update its in-memory progress state; the tasks raced for the state lock, so events could land out of order or be dropped entirely (a unit whose start event lost the race lost the attempt and strategy reported by later events). Events now flow through a single ordered consumer task, and any unit-scoped event may create the unit's record rather than be silently discarded (issue #65).

- **Retry loop accepted non-compiling first attempts** — `TranslationAttempt::is_successful` ignored the `compiled` flag, so a first attempt that failed to compile (with no tests to run) counted as successful and no retry strategy ever ran; the CLI's per-function PASS/FAIL printed PASS for it too. Success now requires compilation plus all tests passing (issue #64).

### Refactored

- **Web router table consolidation** — the review UI's plain-`serve` and live (`calxgloss live`) surfaces are now assembled from one shared route table plus a live-only table, so the two can't drift apart and live pipeline endpoints answer only in live mode.
- **Frontend split into ES modules** — the review UI's monolithic ~2,250-line `app.js` is now one module per view plus shared fetch/format helpers, loaded natively by the browser with no build step.

## [0.2.0] — 2026-10-06

### Added

#### Output & pipeline

- **Crate-based output layout** — `translate` and `batch-translate` now produce `crates/<dll_stripped>/Cargo.toml` and one `src/<function>.rs` per function (DLL/EXE extension stripped, e.g. `EqGame.exe` → crate `EqGame`), with an auto-generated `mod.rs` registering every translated function.
- **Complexity-based prompt selection** — functions are classified by instruction count, branch density, call depth, and API-category diversity, and routed to a Minimal, Standard, Rich, or Detailed prompt with matching Ghidra context.
- **Failure-informed retry prompts** — every retry strategy injects a "PREVIOUS ATTEMPT HISTORY" section into the prompt when prior attempts failed, so the LLM can learn from specific past mistakes.
- **Per-attempt token usage logging** — every LLM call (initial, retry, and tier-escalated attempts) records token counts with DLL, function, attempt, strategy, context tier, and outcome to `re/analysis/token_usage.json`; the batch summary prints a total-tokens line.
- **Experiment logging** — each retry attempt is recorded to `re/analysis/prompt_strategy_log.json` with category, strategy, and outcome, and aggregate pass/fail stats can be computed from it.

#### Context tiers

- **Context tier selection** — five context tiers (`Signature`, `Disassembly`, `WithTests`, `ModuleContext`, `FullModule`) define how much context is sent to the LLM per function; the starting tier is chosen automatically from function complexity and API call count. Each tier has its own prompt, from a minimal signature-only prompt up to full-module context with neighboring functions, shared data structures, shim layer source, and PAL trait definitions.
- **Automatic context tier escalation** — a failed retry can bump the context tier to the next level and rebuild the prompt with escalated context, independently of strategy escalation.

#### Fault detection & analysis logging

- **Fault logging** — detected faults are persisted to `re/analysis/fault_log.json` with aggregate statistics.
- **Context-window detection** — LLM responses are checked against the model limit for truncation markers and oversized prompts are pre-checked; disassembly can be split into chunks for the LLM.
- **Hallucination detection** — generated code is cross-referenced against Ghidra symbols and the PAL catalogue; non-existent API references are logged and emitted as progress events.
- **Infinite-loop detection** — repeated identical (prompt, output) pairs across retries are detected before more tokens are wasted on a dead-end path.
- **Behavior-divergence detection** — code that passes baseline tests but fails generated edge-case inputs is flagged in the retry loop with confidence scoring and recovery advice.
- **Resource-exhaustion monitoring** — repeated failures and timeouts (OOM, swap thrash, HTTP 429/503/507) are tracked; the retry loop backs off, logs faults, and can suggest queueing work or switching models.

#### New analysis crates

All evidence results are saved as per-binary JSON documents under `re/analysis/<name>/<dll>.json`, carry shared scan provenance (binary name, finish timestamp, duration), and score findings with a shared 0–100 `Confidence` type.

- **`calxgloss-typesdb` — data structure recovery**: recovers named types from the Ghidra Type Manager, detects vtables (resolving method pointers and the MSVC RTTI chain to class and base-class names, flagging COM interfaces), and infers struct candidates from string literals.
- **`calxgloss-typeinfer` — type inference**: detects C++ `this` pointers from vtable dispatch, narrows parameter types from string-function usage and integer bit patterns, and propagates types from known signatures (`malloc`, `strlen`, `CreateFileW`, …); competing readings are resolved by confidence.
- **`calxgloss-algorithm` — algorithm recognition**: recognizes algorithm families (sorting, hashing, checksums, compression, …) from control-flow signatures, string markers, and callback contracts (e.g. a `qsort` compare function).
- **`calxgloss-memory` — memory lifecycle / RAII detection**: pairs allocations with releases (suggesting `Box<T>`/`Vec<T>`, or stack allocation for short-lived blocks), handle opens with closes (RAII guard suggestions), and reference-count bumps with drops (`Rc<T>`, narrowed to `Arc<T>` when shared across threads).
- **`calxgloss-sync` — concurrency detection**: pairs lock acquires with releases (`Mutex`/`RwLock`), detects interlocked/atomic calls (`AtomicU32`/`AtomicU64`), and thread spawns with or without joins (`std::thread::spawn` vs `tokio::spawn`).
- **`calxgloss-callback` — callback & function-pointer detection**: finds calls through function-pointer arrays, registration→callback pairs, and jump-table dispatches, suggesting `Vec<Box<dyn Fn(...)>>`, `Box<dyn Fn(...)>`, or `match`/dispatch tables.
- **`calxgloss-controlflow` — control-flow pattern recognition**: detects switch-shaped if-else chains, self-recursion (with tail-call detection), and state-machine patterns, suggesting `match`, loops, or `enum State`.
- **`calxgloss-stringctx` — string & configuration context**: classifies strings into nine categories (format strings, paths, error messages, …), maps strings to functions through body parsing and xrefs, and infers argument types from format specifiers.
- **`calxgloss-apidetect` — library & API identification**: identifies linked libraries from the import table and maps them to Rust crates (DirectX 9, SDL2, zlib, PNG, the C runtime, …), and summarizes which APIs each function reaches directly or through its callees.
- **`calxgloss-consts` — constant & enum recovery**: recovers bitflag groups from bitwise operations, enum candidates from contiguous switch cases, and repeated literals as named constants.
- **`calxgloss-serialize` — endianness & serialization detection**: detects byte-swap calls, bit-packing shift/mask chains, and magic-byte comparisons (PNG, gzip, ZIP), suggesting `byteorder` readers, field masking, or format decoders.

#### `calxgloss-ghidra`

- **New bridge capabilities** — auto-paged string, data-type, and data-item listings, struct layout and enum value lookups, raw memory reads, function tagging, and multi-program support (list open programs and switch which one queries run against).

#### `calxgloss-cli`

- **On-demand analysis commands** — `typesdb`, `typeinfer`, `algorithm`, `memory`, `sync`, `controlflow`, `callback`, `stringctx`, `apidetect`, `consts`, and `serialize` each run their scan against the program open in Ghidra and save the result to the matching `re/analysis/<name>/<dll>.json` cache the batch pipeline consumes. `--show` prints a cached result (counts, confidence, findings) without connecting to Ghidra; `--no-tag` keeps the vtable scan read-only.
- **`auto` subcommand** — detects project state and continues the workflow automatically: scans the target directory for DLLs, runs classification when records are missing, then batch-translates. Running with no subcommand is equivalent to `auto`. Supports `--target`, `--dlls`, `--all-functions`, `--classify-only`, `--skip-git`.
- **`init` subcommand** — creates a `calxgloss.toml` with a fully commented template of every `[ghidra]` and `[llm]` key.
- **`auto-shim` subcommand** — generates shim layers for all crate-replacement DLLs: API mappings (LLM) → source code → tests → verify → persist to `re/shims/<dll>/`, committed to git.
- **`dashboard` subcommand** — builds and renders a review dashboard from git branches and records, with `view`, `accept`, `reject`, and `accept-all` (dependency-ordered batch acceptance) and a `--follow` watch mode.
- **`serve` subcommand** — starts the web review UI HTTP server (port 3000 by default).
- **`live` subcommand** — runs batch translation and the web UI concurrently in one process, streaming progress over WebSocket.
- **`gc` subcommand** — archives stale unmerged translation branches to `refs/archive/…` instead of deleting them, with `--days` and `--dry-run`.
- **Config-driven directories** — `target_dir` and `workspace` can be set in `calxgloss.toml` or overridden by the global `--target-dir` / `--workspace` flags; `live` and `serve` use CWD unless explicitly overridden.
- **Incremental git commits during batch translation** — each function is committed and merged as soon as it succeeds, rather than deferring all git work to the end of the batch.
- **`classify` generates shim layer suggestions** — complexity estimates for crate-replacement DLLs are persisted to `re/shims/suggestions.json`.

#### Git & review workflow

- **Review records** — accepting a branch writes an acceptance record to `re/accepts/`, sending it back writes a rejection record to `re/rejections/`, and archiving renames a stale branch to `refs/archive/…` so it stays reachable.
- **Shim-layer dependency enforcement on branch creation** — branch creation can check that required shim layers (e.g. `d3d9.dll` → `re/shim/wgpu`) are already merged, in `Skip`/`Warn`/`Enforce` modes.
- **Dependency graph** — a DAG of DLL classifications → shim layers → function translations is built from classifications and call graph data, persisted to `re/analysis/dependency_graph.json`, and topologically ordered (level-aware) for batch operations.
- **Shim layer generation** — API mappings are generated by the LLM, shim source code (complete or skeletal) and per-mapping tests with mock call recorders are generated from the mapping table, and shim layers are verified in a sandboxed Cargo project.

#### Web review UI

- **Axum API server** (`server` feature) — dashboard, unit detail, dependency graph, dependency-sorted queue, line-by-line diff, Ghidra context, and health endpoints, plus accept / send-back / patch review actions wired into git and the translation pipeline (a patch request spawns a retry translation).
- **WebSocket progress streaming** — pipeline milestones, per-attempt status, and full LLM request/response events stream to the UI; a live "LLM I/O" tab shows the log.
- **Dependency-sorted review queue** — queue endpoints and the dashboard report dependency-ordered units with queue metadata and position; `Blocked` units are flagged.
- **Diff & Ghidra context viewers** — tabbed detail panel with line-by-line highlighted diffs against `main` and decompiler/disassembly context from on-disk analysis artifacts.
- **Interactive dependency graph** — layered layout with Bézier edges, hover tooltips, click-to-select with neighbor highlighting, click-to-detail, status dots, fit-to-view, wheel zoom toward cursor, and keyboard shortcuts.
- **Live progress panel** — per-DLL classification/strategy, in-progress translation with progress bar, and batch completion counts; completed functions mark their unit `Complete` in real time.
- **Stale branch cleanup** — a "Stale Branches" dashboard card and a "Branch Cleanup" view list unmerged branches past a staleness threshold and archive them from the UI.

#### `calxgloss-types`

- **Review dashboard data model** — work units, review statuses, dependency graph, status counts, and review actions shared across reports, web, and CLI, replacing the duplicate scaffolding in `calxgloss-web`.
- **Dependency-ordered queueing** — units carry processing levels (classification → shim → PAL → test → function → integration → fix), the dependency graph topologically sorts with level tie-breaking, and the dashboard auto-blocks units whose dependencies are in a failing state.
- **Typed progress events** — a serializable `ProgressEvent` enum (translation milestones, per-attempt completion, context tier selection, fault detections, LLM request/response) published over a broadcast channel for WebSocket transport.
- **Shim layer types** — API mappings, layers, complexity scores, and per-DLL shim suggestions with estimated complexity and confidence, produced from classification data without an LLM call.

### Changed

#### Vocabulary

- **Unified on *workspace*** — one directory, one name: `--repo-dir` is now `--workspace`, the config key `repo_dir` is now `workspace`, and `CALXGLOSS_REPO_DIR` is now `CALXGLOSS_WORKSPACE`. `translate`/`batch-translate` lost `--output-dir` (output always lands in the resolved workspace), and dead per-command `--repo` flags are gone.
- **Terminology corrections** — `ContextTier::Stub` → `Signature` ("stub" is reserved for mocks); FFI *stub* → FFI *binding* (the generated block calls the real DLL); `WorkUnitKind`/`WorkUnitLevel` → `WorkKind`/`WorkLevel`; `ReviewStatus::Merged` dropped (merging is the git effect of Accept, not a second verdict); the scratch PAL package renamed `calxgloss-pal` → `calxgloss-verify-pal`.
- **Confidence scales disambiguated** — evidence confidence (0–100, shared `Confidence` type), unit confidence (`unit_confidence`, 0.0–1.0), and fault-diagnosis confidence (`fault_confidence`, 0–10) now have distinct names.

#### Workspace layout

- **Reorganized `crates/` into the 5-context layout from `GLOSSARY-MAP.md`** — `crates/pipeline/`, `crates/evidence/`, `crates/integrations/`, `crates/interface/`, and `crates/shared/`, with the meta-crate re-exporting every library crate except `calxgloss-web`.

#### GhidraMCP 6.x migration

- **Migrated `calxgloss-ghidra` to the bethington GhidraMCP bridge** (v6.0.0, replacing the deprecated LaurieWired extension): snake_case endpoint surface, JSON response and error support, and name-based decompilation resolved through `search_functions`.

#### Pipeline & prompts

- **Evidence pre-analysis in batch translation** — `batch_translate` and `batch_translate_from_callgraph` run each evidence scan (type database, type inference, algorithm, memory, sync, callback, control flow, string context, API, constants, serialization) at the start of a batch when its cache file is missing; a missing workspace, unreachable Ghidra server, or failed save only logs a warning and the batch proceeds.
- **Analysis context in prompts** — the escalate prompt (and, for control flow, the ModuleContext and FullModule translation tiers) reads the persisted evidence caches and renders sections for recognized algorithms, memory lifecycle, concurrency, callbacks, control flow, strings, APIs, and constants; a missing or corrupt cache degrades to no context rather than failing the prompt.
- **Type and data-structure context from persisted caches** — the previously stubbed prompt context extractors now load the type inference and type database caches and keep the records tied to the target function.
- **Translation attempts record their context tier**, enabling post-hoc analysis of which context scope yields the best pass rates.
- **Boxed pipeline futures** — the retry loop's futures are boxed so downstream `Send` checks stop at the boundary instead of overflowing the compiler's trait-evaluation recursion limit.
- **`classify_dlls` reads PE headers** for accurate per-DLL export/import counts instead of the stale counts from whichever program happens to be open in Ghidra.
- **Classification records persisted to disk** — `classify` writes `re/classify/{dll}.json` and commits to `main`; later `auto` runs skip re-classification.

### Fixed

- **Wrapped decompiler signatures parse** — Ghidra's multi-line signature lines failed to parse, so every engine that scans all functions silently skipped those functions (~41 of eqmain.dll's 4,358). Signatures are now joined until the parameter list or body begins. Fixes #54.
- **Dashboard dependency edges (issue #10)** — the builder now wires the shim→function dependency edge the branch-creation policy already checks, so a sent-back shim cascades `Blocked` to everything translating on top of it; the classify edge's DLL matching and shim unit classification were also corrected. The `Blocked` cascade no longer leaves `StatusCounts` stale.
- **Review verdict durability (issue #9)** — the dashboard builder now reads send-back and patch-request records, so `SendBack`/`PatchRequested` survive rebuilds and failing roots can cascade `Blocked`. Patch records written before this change read unchanged.
- **`read_all_patch_records` walked the wrong tree depth** — it never found records at `re/patches/{dll}/{function}/vN.json`, leaving `PendingReview` unreachable in built dashboards.
- **Review actions 500'd on slashed unit ids** — accept/send-back/patch failed at the audit-trail write because nested parent directories under `re/actions/` were not created.
- **Default allocator names missed Ghidra's underscore-form `operator_new`/`operator_delete`** — the live 6.x decompiler writes the underscore form in function bodies, so whole-name matching never fired and allocation findings were missed. The default sets now carry both spellings. Fixes #6.
- **`println_content` blanked lines carrying multi-byte characters** — the report-line padding helper compared byte length against the column width while truncation counted characters, printing some short lines empty. It now counts visible characters.
- **Axum 0.8 route syntax** — routers used the legacy `:id` capture syntax that panicked on startup; all routes now use `{id}`.
- **Static file serving** — assets resolved against the process CWD instead of the crate directory, and the fallback extractor was incompatible with `fallback_service`, so JS and CSS returned 404.
- **Live units 404'd in the unit detail endpoint** — the endpoint now consults the live progress state and creates synthetic in-progress units.
- **LLM request/response log rendered HTML-entity-encoded** — content now renders as raw text with minimal escaping, so JSON and code display correctly.
- **`showDetail` body scope** — the error handler could not reference `body`; the declaration moved outside the `try/catch`.
- **`merge_to_main` stale main reference** — a cached ref handle caused merged branch file changes to be lost on hard reset.
- **Empty cross-reference responses** — a 200 with empty body from GhidraMCP (no callers/callees) is now treated as a valid empty result instead of an error.
- **Trims leading/trailing whitespace** from disassembly and decompiler output before sending to the LLM, keeping prompts cleaner and avoiding wasted tokens.

### Removed

- **Left sidebar dependency graph in the web UI** — the collapsible sidebar panel holding a small dependency graph, and its toggle button, are gone; the full graph view covers it.

### Refactored

- **Shared JSON persistence plumbing** (`calxgloss-types::persist`) — `save_json`/`load_json`/`analysis_dir` and a generic `JsonStore<T>` now back every evidence persistor and the analysis log persistors, replacing hand-written I/O in each crate.
- **Module splits across the workspace** — oversized files were split into focused modules: the CLI binary, the Ghidra/LLM/testgen clients, prompt templates/builders, the reports dashboard, the translator pipeline, the verify engine, the git manager, the analyzer, config, the dashboard types, the PAL crate, and the web handlers.
- **Shared CLI output helpers** — crate-setup and function-writing logic extracted into `utils.rs`, eliminating duplication between `translate` and `batch-translate`.
- **Shared types** — the duplicated `WindowsApiCall` collapsed into one type; a `display_serde_label!` macro replaces `Display` boilerplate on snake_case serde enums; Ghidra wire shapes and persisted recovered shapes now convert through `From` impls instead of scattered field-by-field copies.

### Documentation

- **Docs restructure** — `step_by_step.md` split into `docs/roadmap.md`, an archived frozen plan, and `docs/adr/0001-bethington-ghidra-mcp-bridge.md`; the `Documentation/` folder merged into `docs/`.
- **`docs/standards.md`** — documented coding standards (workspace/crate conventions, error handling, persistence, logging, testing, commit/process rules) for the `code-review` skill's Standards axis.
- **Ghidra docs split by lifespan** — the v6.0.0 endpoint mapping and record-format reference moved to `docs/ghidra_endpoint_map.md`; `ghidra_integration.md` stays the lifecycle-integration design doc.
- **Removed internal-roadmap references** from doc-comments and inline comments across the workspace; Rustfmt reformatting pass.

## [0.1.0] — 2025-09-27

### Added

#### `calxgloss-translator`
- **Batch translation** (`batch-translate` CLI subcommand) — translate multiple functions from a single DLL in one invocation; enumerates all exported functions via `--all-functions` or accepts a comma-separated list via `--functions`; per-function pass/fail reporting with a summary showing success/failure counts and pass rate; `--skip-git` for dry-run mode; automatically commits and merges each successful function to a git branch
- Full translation pipeline: end-to-end GhidraMCP → analysis → test generation → LLM → Rust code workflow, direct translation from pre-collected data, and parameter estimation from decompiler output
- **Retry logic** — strategy escalation on failure (CompileFix / TestFix / Escalate) with compile-fix and test-fix prompts

#### `calxgloss-ghidra`
- GhidraMCP HTTP client with session management, DLL queries (list, info, imports, exports), function queries (disassembly, decompiler, call graph, full analysis), and tracing instrumentation

#### `calxgloss-llm`
- Local LLM client (Ollama/vLLM compatible): non-streaming and SSE streaming completions via the OpenAI-compatible `chat/completions` API, builder-pattern config, code-fence stripping, and tracing instrumentation

#### `calxgloss-prompts`
- Prompt templates with the Askama template engine: translation prompts covering disassembly, decompiler output, Windows API mappings, and baseline tests, plus compile-fix and test-fix prompts

#### `calxgloss-pal`
- Platform abstraction layer with full Windows API → Rust equivalent mapping table: 100+ mappings across 10 categories (Win32 Core, GDI, DirectX, Win32 GUI, Audio, COM, Win32 Networking, Win32 Registry, VB6 Runtime)

#### `calxgloss-analysis`
- DLL classification, call graph analysis, and Windows API tagging: classification heuristics with lookup tables for 70+ Windows OS DLLs, 15 Microsoft SDK DLLs (→ wgpu/tiny-skia/skrifa), and 40 known third-party DLLs (→ fmod-rs/cpal/mlua/pyo3/flate2/vb6runtime etc.); `PalMapping` / `CrateReplacement` / `ReverseEngineer` strategies; disassembly scanning for dynamically-loaded APIs

#### `calxgloss-testgen`
- FFI binding generation with comprehensive Windows type parsing (60+ type mappings, calling conventions, pointer handling), test input generation with signature-based and disassembly-driven edge case detection, baseline runner for temporary Cargo project compilation and execution, and JSON baseline save/load to `re/baseline/{dll}/{function}/baseline.json`

#### `calxgloss-verify`
- Sandboxed verification: scaffolds a temporary Cargo project, runs `cargo check`, and verifies behavior against baseline tests; test harness generator and `cargo test` output parsing; PAL stub types for graphics, audio, filesystem, window, and thread abstractions

#### `calxgloss-git`
- Git automation for the translation workflow: branch naming `re/{dll}/{function}v{N}`, fast-forward and 3-way merges, patch record JSON files for failed translations, and branch/commit/merge/revert operations

#### `calxgloss-reports`
- Terminal report formatting: colored ANSI output for translation, verification, and classification reports with pass-rate color-coding, and batch summary output with per-function checkmarks/crosses

#### `calxgloss-web`
- Web UI data models and axum API router scaffold behind the `server` feature flag; dependency-sorted review queue with status counts

#### `calxgloss` (meta-lib)
- Meta-lib re-exporting all workspace crates

#### `calxgloss-config`
- Configuration crate with multi-source config loading (file, env, flag precedence), section validation, typed settings, and searched-path diagnostics

#### `calxgloss-types`
- Shared data structures with module organization: DLL analysis, function metadata, test cases, translation, verification, and Git automation

#### `calxgloss-cli`
- Full CLI binary: `clap`-based `classify`, `translate`, and `verify` subcommands wiring the full pipeline (Ghidra → analysis → test generation → LLM prompt → code → write → verify → git branch/commit/merge → report), with configurable retries, LLM config, and `tracing-subscriber` logging

#### Infrastructure
- Project scaffolding with 14 workspace crates and a workspace root `Cargo.toml` with shared dependencies
