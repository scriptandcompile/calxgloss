# ReVa's MCP tool surface — the core claim to competence

> Part of the [ReVa overview](README.md). How ReVa builds its 88-tool MCP surface: the Java
> server and Ghidra concurrency story, ~10 deep tool dissections, the "small tools / context
> rot" doctrine, and the job + diff-session machinery. Citations are `path:line` relative to
> clone root `/tmp/opencode/cyberkaida-rea` @ `a2fcd94` ([inventory](20-reva-inventory.md)).

## 1. The Java MCP server

Registration is one funnel: `McpServerManager`'s constructor builds config → `GThreadPool("ReVa")` →
transport → capabilities → tools (`server/McpServerManager.java:144-201`). Prompts are advertised but
**no prompt is ever registered** (`:162-166`); the single resource is `ghidra://programs` — path,
language, compiler, size per open program (`resources/impl/ProgramListResource.java:41-42, 57-80`).
Every tool goes through `AbstractToolProvider.registerTool()` (`tools/AbstractToolProvider.java:139-194`),
which adds request-id logging and converts `IllegalArgumentException` / `ProgramValidationException`
thrown by handlers into MCP error results — the thrown message is what the LLM reads (`:166-177`).
Providers are constructed/disposed per enabled group (`McpServerManager.java:218-263`);
`unregisterTools()` removes tools by name live (`AbstractToolProvider.java:82-87`) — the toggling basis (§5).

**SDK and transport.** MCP Java SDK `mcp-bom:2.1.0` (`build.gradle:111-113`), Jetty 12 ee10 +
jakarta servlet 6.1 (`:114-117`); endpoint `/mcp/message` (`McpServerManager.java:85`). The
transport is a fork of the SDK's servlet transport: upstream kills the session on any message
failure; the fork keeps it alive across serialization failures and dead SSE GET-streams, keyed
by `Mcp-Session-Id`, replaying via `Last-Event-ID` (`server/ResilientStreamableServerTransportProvider.java:1-18`).
It is created *exactly once* per lifetime — the SDK wires its session factory into that precise
instance; a restart-time replacement caused issue #366 (`McpServerManager.java:157-159, 625-631,
638-647`). Jackson disables `FAIL_ON_UNKNOWN_PROPERTIES` for newer protocol revisions from VS Code
(SDK issue #724, `:648-655`); keep-alive 30 s, idle 10 min (`:358,660`); stdio clients get a
Python facade proxying to the authenticated HTTP endpoint (`src/reva_cli/stdio_bridge.py:80,145`).

**Concurrency against Ghidra — deliberately no global lock.** Handlers run on Jetty request
threads; safety rests on Ghidra's contract: `Program` is safe for concurrent reads, and *every*
mutation is wrapped in `startTransaction/endTransaction` — apply-data-type
(`DataToolProvider.java:137-166`), create-function (`FunctionToolProvider.java:1408-1465`),
set-comment (`CommentToolProvider.java:102-105`), rename-variables (`DecompilerToolProvider.java:1148`).
Long reads get `TimeoutTaskMonitor.timeoutIn(...)` (`DataFlowToolProvider.java:644`). Overlapping
work is serialized *structurally*: `DiffSessionManager` is all-`synchronized` static (`:68,125,185`);
the analysis worker is one thread (`AnalysisJobManager.java:37`) behind a synchronized
single-flight `startOrAttach` whose comment names the check-then-act race it kills (`:151-170`).

**Auth.** `ApiKeyAuthFilter` checks `X-API-Key` when enabled
(`server/ApiKeyAuthFilter.java:42,69-89`); key/host changes restart the server
(`McpServerManager.java:711-726`). A *public-binding guard* refuses non-localhost binds
without a key: headless refuses outright, GUI shows a consent dialog naming the RCE risk
while scripting is on, and a refused runtime change reverts the option and leaves the
running server untouched (`:409-455, 736-765`).

## 2. Deep dissection of the representative tools

All tools are kebab-case (zero snake_case matches repo-wide): decompile_function→`get-decompilation`,
get_xrefs_to→`find-cross-references` (one tool, `direction` param), decompile_all→`get-callers-decompiled`
(bounded), import_from_json→`import-file` / `parse-c-header`, get_function_by_name→the name ladder below.

**One input ladder, everywhere.** `AddressUtil.resolveAddressOrSymbol` tries symbol first, then hex
with or without `0x` (`util/AddressUtil.java:99-117, 60-77`); `getFunctionFromArgs` layers
containing-function-of-address → exact-name → case-insensitive (`AbstractToolProvider.java:729-776`);
`get-decompilation` adds a fourth rung — an address in executable memory with an instruction but no
function runs Ghidra's `UndefinedFunction.findFunction` for a *temporary* preview function
(`DecompilerToolProvider.java:769-805`). Responses echo which rung matched — `resolvedFrom:
"address/symbol" | "name-exact" | "name-case-insensitive" | "undefined-function"`
(`:733,749,762,797`) — so the model learns what ReVa thought its input meant. Coercion is forgiving:
any value stringifies, numbers parse from strings, "true"/"false" strings coerce (`:239-246, 293-310, 421-439`).

**`get-decompilation` — the flagship** (`DecompilerToolProvider.java:636-974`). `offset`/`limit`
window decompilation *lines*, default 50, output numbered `%4d\t<line>` (`:1359-1361, 1433-1437`);
`signatureOnly` returns metadata without body, "Saves output tokens". Metadata reinforces every
answer: signature, return type, convention, thunk, params name/type/ordinal, body start/end/size
(`:824-854`). `includeCallers/Callees` fold two tools into one call — capped rows with
`totalCallerCount`/`*Limited` flags so the model sees truncation (`:677-907`). By default
`includeIncomingReferences` + `includeReferenceContext` are **true**: the first 10 incoming xrefs
arrive *with code snippets decompiled from the calling functions* (`util/DecompilationContextUtil.java:205-287`),
and past the cap the payload says verbatim "Use 'find-cross-references' tool with location=...
direction='to' to see all" (`DecompilerToolProvider.java:1369-1398`); `includeDisassembly` emits
`synchronizedContent`: per-line objects pairing each C line with its assembly (`:1400-1429`).
Errors redirect: non-executable address names the block; a no-instruction address suggests disassembly or
mid-instruction; a temporary function carries "Use create-function to define it permanently" (`:777-821`).

**`get-functions` / `get-function-count` — the count-first pattern** (`FunctionToolProvider.java:355-470`).
`filterDefaultNames=true` hides `FUN_`/`DAT_` noise; `verbose=false` returns compact rows {name,
address, sizeInBytes, tags, callerCount, calleeCount} with "-1 if computation timed out" documented
in the schema; the description routes: "use get-function-count to determine the total count" (`:446`).
Pagination uses the shared envelope `paginationResult` — startIndex, requestedCount, actualCount,
nextStartIndex, totalProcessed (`AbstractToolProvider.java:613-679`).

**`find-cross-references`** (`CrossReferencesToolProvider.java:61-255`). `direction ∈ {to, from,
both}`; `limit` clamped 1..1000; stack/register addresses drop the "to" leg (`:139-157`).
Reinforcement is dense: `locationInfo` carries symbol, type, **namespace for non-global symbols**,
containing function, `isFunctionEntry` (`:220-238`); each ref row carries
isCall/isJump/isData/isRead/isWrite, operandIndex, sourceType, isPrimary, plus symbol+namespace
at *both* endpoints (`:283-330`). "from" on an address inside a function returns the *whole
function body's* outgoing refs — the unit is the function, not the point (`:184-198`).

**Read-before-write: `rename-variables` and the write gate** (`DecompilerToolProvider.java:1059-1160`).
A `ConcurrentHashMap` records every `get-decompilation` read keyed `program:function-entry`
(`:85, 961`); rename, datatype, and comment writes refuse unless that function was read first —
"You must read the decompilation ... ensures you understand the current state of the code"
(`:1117-1120, 1259, 1885`; cleared on program close `:105-107`). Wrong-address errors teach the fix:
"this address has code but no defined function ... Use create-function to define it first, then
retry the rename"; name misses warn about mangled names and namespaces (`:1104-1111`). Writes run
in one transaction over `HighFunctionDBUtil.updateDBVariable`; results carry a before/after
decompilation diff (`:1144-1160`). `set-comment` (`CommentToolProvider.java:70-105`) is simpler:
address-or-symbol plus a free-string `commentType` whose invalid value errors with the valid list.

**`get-data` / `apply-data-type` / structures.** Interior addresses resolve — `getContainingData`
checks `getDataAt` then `getDataContaining`, so struct fields work (`util/AddressUtil.java:141-156`).
`apply-data-type` takes C-ish strings ("char**", "int[10]") and on failure redirects to *which tools
to call next*: "Try using the get-data-type-archives and get-data-types tools"
(`DataToolProvider.java:127-135`). `get-structure-info` returns a C representation of the layout and
distinguishes "not found" from "Data type is not a structure or union"
(`StructureToolProvider.java:250-285`); `parse-c-header` is the inline-markup import: whole-string
parse, then a line-accumulating fallback per failed definition (`:571-660`).

**`create-function` + `get-undefined-function-candidates`** (`FunctionToolProvider.java:1353-1470, 1169+`).
create-function refuses over an existing function *naming it* (`:1400-1406`), **disassembles on demand**
for never-disassembled imports (stripped relocatables), auto-detects signatures via `CreateFunctionCmd`,
and tolerates duplicate names by keeping Ghidra's default. The candidates tool scans every CALL *and
DATA* reference (function pointers, callbacks, exception handlers) and flags `earlyTermination` — "Scan
stopped early due to memory limits. Results may be incomplete" is an honesty marker, not silent
truncation (`:1150-1255`). Bulk decompilation stays bounded: `get-callers-decompiled` defaults to 10
callers with call-site highlighting (`DecompilerToolProvider.java:1971-2005`); `search-decompilation`
refuses programs over the configured 1000-function limit unless overridden, suggesting the cheaper
xref tools in the same breath (`:1011-1053`).

**`import-file`** (`ProjectToolProvider.java:1420-1560`). File, directory, or archive, `maxDepth` 10,
a 120 s timeout; analysis is *not* bundled — imports return `analyzed=false, analysisRecommended=true`
so the model follows up with `analyze-program`, where progress and analyzer choices are visible.

## 3. Design doctrine, as stated and as coded

The README is the manifesto: "tool driven approach… a variety of small tools… providing the LLM with a
schema but tolerating other input… redirecting correctable mistakes back to the LLM, and including
extra output to guide the next decision… smaller, critical fragments with reinforcement and links to
other relevant information… report additional context like the namespace and cross references along
with the decompilation, this is a small nudge to make the LLM explore the binary in the same way a
human would" (`README.md:6-27`). Every mechanic above is that paragraph compiled. Reinforcement is
cross-tool: tool-name-naming limit messages, "did you mean" program suggestions
(`util/ProgramLookupUtil.java:68-96`), correlator trade-offs written into the schema itself
(`DiffToolProvider.java:1109-1120`). The `diff-summary` under-analysis guard is the purest
error-redirect: when most matched functions have 1-address bodies it injects `analysisWarning` —
"'changed' will read near-0 … Run analyze-program on both programs" — instead of letting the agent
conclude "no changes" (`:279-302`). Output shaping everywhere: defaults (50 decompile lines, 50
search results, 100 list rows, 10 incoming refs, 10 callers); `CappedWriter` hard-caps script output
(65536 chars) with `truncated=true` + offset/limit re-read (`PythonScriptExecutor.java:86-115`).
Responses are flat-ish JSON maps in a single TextContent (`AbstractToolProvider.java:123-132`) — no
MCP `structuredContent`. House rules are codified: REQUIRED utilities, always transactions,
pagination for large datasets, progress only when `progressToken` present (`CLAUDE.md:200-245`).
Descriptions double as the routing table — "start with small chunks (10-20 lines)", "use
get-function-count first", "try the cross reference tools first".

## 4. Jobs and diff sessions (the v7.3-era machinery)

One job model serves analysis and diff. `JobStatus` is a 6-state enum with `isTerminal()`
(`services/JobStatus.java:4-24`); `JobLog` is a synchronized, sequence-numbered ring
(`services/JobLog.java:52-103`). `AnalysisJobManager` assigns deterministic `analysis-N` ids, prunes
to 50 terminal jobs (`:27-92`), runs on one worker thread, and pumps each running job's auto-analysis
message log into its JobLog on a 1 Hz ticker built to survive `Throwable`s (`:193-228`).
`analyze-program` is the **hybrid** shape: inline `waitSeconds` (default 10; schema says keep it under
your MCP client's tool-call timeout) — small programs finish in one call, long ones return
`{status:running, jobId, log}` for `analysis-status` (`ProjectToolProvider.java:640-760`). Per-call
analyzer overrides are validated ("no dots — use list-analyzers") and snapshot/restored
(`AnalysisJobRunner.java:72-97`); `persist ∈ auto/save/none` decides save vs. checkin. The shared wait
loop `awaitWithProgress` (`AbstractToolProvider.java:828-871`) ticks at 250 ms emitting MCP progress
notifications when the client sent a `progressToken` — "so long waits survive" the client's idle timeout.

Diff sessions are *durable*: correlation persists as a VersionTracking `VTSessionDB` DomainFile
under `ReVaDiffSessions/` in the project, reopens on demand, is reused unless `force=true` or the
correlator selection changes, and is staged — each correlator runs over only the still-unmatched
residual, saving after each stage (`DiffSessionManager.java:28-75, 125-215`). `diff-create-session`
resolves scope identifiers eagerly — "so a bad identifier errors before the job starts"
(`DiffToolProvider.java:1176-1182`); `diff-status` long-polls with a `sinceLogSeq` cursor +
`maxLogEntries` 50 and returns the full summary the instant the job terminates (`:940-1050`);
`diff-cancel` is async, "A cancelled markup transfer rolls back (all-or-nothing)" (`:1060-1101`).
`DiffJobManager.startOrAttach` repeats the single-flight guarantee (`:116`).

## 5. Discovery and the 88-tool context bill

Discovery is plain `tools/list`; nothing is compacted. Measured from source: 88 `.name()`
registrations, 14,754 chars of tool-level descriptions, 12,738 chars across 140 property
descriptions → a rendered payload around 55–65 KB ≈ **15–20k tokens**. The only budget lever is
tool groups: 6 booleans (`plugin/ToolGroup.java:26-32`; `ConfigManager.java:674-684`), toggled
*live* via the config-change listener → `enableGroup`/`disableGroup`: construct providers,
register/unregister tools, catch new providers up on already-open programs
(`McpServerManager.java:269-300, 687-703`); CLI `--disable-tool-group` / `--tool-group` hit the
same switch (`src/reva_cli/__main__.py:140-154`). Disabling SCRIPTING is even named inside the
public-binding security warning as removing the RCE risk (`McpServerManager.java:446-452`) —
context control is exactly as granular as the six groups.

## Comparison with calxgloss

### The same job, opposite surfaces

ReVa is an **interactive query surface**: 88 small stateful tools over a live Ghidra database, built
for an agent that asks one question per call and re-asks with the answer in hand. calxgloss is a
**batch evidence pipeline**: 15 registered scans fan out (cap 4) over the whole program before any
function is translated, producing a deterministic record tree (`pipeline-record.json`,
`scan-records.json`; `10-calxgloss-baseline.md:40-57`). ReVa spends tokens at *query time* — windows,
count-first pairs, reinforcement in every payload; calxgloss spends compute at *evidence time* and
hands the translator pre-digested records through 5 context tiers (`context_tier.rs:59-84`). ReVa's
per-call freshness (live mutating DB) buys exploration; calxgloss's determinism buys reproducibility.

### Input tolerance & error redirect vs. fault monitors

ReVa's ladder plus `resolvedFrom` echo, the read-before-write gate, and tool-naming errors form a
*conversational* retry loop: the tool teaches the model the fix, the model re-calls. calxgloss's
analogue is *programmatic*: fault monitors classify translator failures and 4 retry strategies
(`SignatureRepair`, `TypeEnrichment`, `Escalate`, …; max 3 attempts, `10-calxgloss-baseline.md:47-51`)
rerun phases with mutated inputs — the model never sees an error, it sees a better-context second
attempt. The two are duals: ReVa redirects mistakes to the LLM because the LLM holds the session;
calxgloss redirects them to the pipeline because the pipeline holds the evidence. What transfers
directly is the *verbal* half — "did you mean" / "use X first" payloads could ride calxgloss fault
records.

### Token budgeting: tiers vs. output shaping

calxgloss budgets by *selection*: context tiers decide which evidence reaches the prompt, fixed per
phase. ReVa budgets by *shaping*: everything reachable, each call a default-small slice with
continuation handles (`offset/limit`, `nextStartIndex`, `sinceLogSeq`). But ReVa pays a fixed schema
tax (~15–20k tokens) a scripted harness never pays — and the 846k-token catalog
case recorded for the sister project morluto/rea (`docs/research/rea/31-deep-native-analysis.md:149-157`)
suggests that tax can dominate any interactive surface. Six coarse groups are ReVa's whole answer.

### Verdict

As an MCP surface, ReVa is the most thoroughly engineered example of LLM-facing API design in this space:
input ladders that never fail silently, errors that name the fixing tool, pagination as a universal
grammar, hybrid wait/poll jobs that survive client timeouts, durable diff sessions making second diffs cheap.
For calxgloss's unattended PE→Rust pipeline none of it replaces the batch engine — but the surface
philosophy transfers to every place calxgloss talks to a model or a human. What calxgloss could steal:
(1) **the identifier ladder + `resolvedFrom` echo** — accept name/address for function selectors,
report which rung matched, fail with block/executable disambiguation instead of "not found";
(2) **error payloads that name the next step** — fold `ProgramLookupUtil`'s "did you mean" and "use X
first" into fault-monitor output so retries carry readable causes; (3) **hybrid wait-then-handle jobs
with progress ticks** — `awaitWithProgress` (`AbstractToolProvider.java:845-871`) is a tiny complete
primitive; (4) **count-first + the 5-field pagination envelope** (`paginationResult`) as the schema for
any calxgloss list endpoint; (5) **read-before-write gating** if calxgloss ever exposes write-back
tools — the tracker is ~3 lines of state and structurally prevents blind edits; (6) **the
under-analysis warning** — when a lens reads near-zero because input is unanalyzed, say so instead of
emitting a trustworthy-looking zero; (7) **durable diff sessions** (`ReVaDiffSessions/`, staged
correlators, log-cursor polling) as the model for calxgloss-bdiff resumability.
