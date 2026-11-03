# 31 — The Ghidra bridge and backends: the Java plugin, the two clients, and the tool surface

> Part of the [OGhidra overview](README.md). The Ghidra layer end to end:
> the `OGhidraMCP` Java extension and what the fork actually changed over
> LaurieWired/GhidraMCP, the HTTP backend client, the headless PyGhidra
> backend, the two MCP-shaped paths (one live, one dead), the full *tool
> surface* the LLM may call, multi-instance handling, and Ghidra version
> support — then the direct comparison against calxgloss's single in-process
> seam, three-tier read cache, and no-write-back doctrine
> ([10-calxgloss-baseline](10-calxgloss-baseline.md); ADR-0001/0007/0020/0021/
> 0039–0043/0055). OGhidra claims cite the clone at `6224d26`, paths relative
> to the clone root; upstream claims are pinned to LaurieWired/GhidraMCP
> commit `865bf483` and the GitHub API as recorded 2026-11-01.

## What OGhidra does

### 1. The Java extension: one class, an HTTP server inside the Ghidra GUI

The Ghidra side of the *http* backend is one 2,028-line class,
`OGhidraMCP/src/main/java/com/lauriewired/GhidraMCPPlugin.java` (the package
name is still LaurieWired's — the inventory's Java area is 2,261 lines across
13 files, [20 §5](20-oghidra-inventory.md)). On plugin `read()` it picks a
port and starts a `com.sun.net.httpserver.HttpServer` **inside the running
Ghidra process**: `HttpServer.create(new InetSocketAddress(this.currentPort),
0)` (`:134`). That bind is the wildcard interface — every route on the
machine can reach it — and there is **no authentication of any kind** on any
endpoint; the README only ever *shows* localhost URLs
(`README.md:149,181`). The port choice is fork-added: `DEFAULT_PORT = 8080`
and `DYNAMIC_PORT_START = 8192` (`:86-92`), try 8080 explicitly, then the
8192+ range skipping 8081–8089, up to `MAX_PORT_ATTEMPTS = 10` tries
(`:443-456`); a non-default user-specified port is respected exactly
(`:435-441`). `server.setExecutor(null)` (`:410`) means the JDK default — a
single dispatch thread, one request at a time — and the server itself runs on
a plain background `new Thread` (`:411`).

Every read handler dereferences the *live GUI state*: `getCurrentProgram()`
is `ProgramManager.getCurrentProgram()` of the plugin's tool
(`:1992-1995`), used by all 30 endpoints. The GUI-cursor tools
`/get_current_address` and `/get_current_function` (`:254-259`) call
`CodeViewerService.getCurrentLocation()` and degrade to "Code viewer service
not available" (`:893-926`). Mutations (`renameFunction` `:677-690`,
`renameData` `:705-723`, `renameVariable` `:791-807`,
`rename_function_by_address` `:1127-1142`, `set_function_prototype`
`:1213-1273`, `set_local_variable_type` `:1295-1418`) marshal onto the Swing
EDT with `SwingUtilities.invokeAndWait` and wrap the edit in a named Ghidra
transaction (`startTransaction("Rename function via HTTP")` `:678`).
Decompilation runs on the HTTP dispatch thread: a fresh `DecompInterface`
per call, `decompileFunction(func, 30, …)` — 30 s — for
`/decompile`/`/decompile_function` (`:655-661`, `:975-983`), 60 s for the
full re-decompile inside `set_local_variable_type` (`:1384-1390`).

Two response-shape facts matter for both clients. Operational endpoints
return **`text/plain` bodies, not JSON** — `sendResponse` writes the raw
string (which may itself be paginated text) with a 200 regardless of whether
the text says "Function not found" or "No program loaded" (`:668,1997-2004`);
only the two fork-added discovery endpoints answer JSON via
`sendJsonResponse` (`:2006`). And list-shaped endpoints get fork-added
pagination: `paginateList`/`paginateString` (`:1907-1965`) emit a first-line
header `[Total: N] [Showing: A-B] [Next: offset=E, limit=L]` (`:1913-1925`,
`:1944-1955`) at 16 call sites (`:482-1605`).

### 2. What the fork added over upstream GhidraMCP

The fork base is pinned: the current file is upstream's single-file plugin at
the *end of the single-file era*. Upstream LaurieWired/GhidraMCP at commit
`865bf483` ("Fixed for Ghidra 11.3.2", 2025-06-20) — file identical at the
era's closing merge `27f316f8` (2025-06-23) — was one 1,651-line class
registering 27 endpoints; the fork's diff against it is +634/−257 lines
(+507/−130 ignoring whitespace). Substantive changes:

- **added** `/read_bytes` (hex dump default, base64 for `format=raw`, hard
  clamp 1–4096 bytes — `:402-408`, `:1768-1800`) — already present in the
  fork's first plugin import (`ac3b453`, 2025-12-24: a 1,750-line file =
  the base's 27 endpoints plus `/read_bytes`) — plus `/plugin-version`
  (hard-coded `{"plugin_version": "Custom-OGhidraMCP", "api_version": "1.0"}`
  — `:139-143`) and `/program` (`name` + `programId =
  projectLocator:name` — `:145-152`), the fork's two own discovery contexts;
- **removed nothing**: all 27 base endpoints survive verbatim —
  `/xrefs_to`/`/xrefs_from`/`/function_xrefs` come from the base, not the
  fork;
- **multi-instance port allocation** — the fork's comment says "Multi-instance
  port allocation logic adapted from GhydraMCP project:
  https://github.com/starsong/GhydraMCP" (`:426-427`, and `:5`, `:136`).
  That repo returns **404 on the GitHub API as of 2026-11-01** (private or
  deleted), so the starsong lineage exists only as attribution comments;
- **richer list output**: `listImports` annotates every external symbol with
  `[Refs: N]` and up to five caller names (`:515-561`); `getFunctionXrefs`
  now resolves a name against external symbols and any symbol, not just
  functions (`:1504-1560`);
- **pagination** as above, and camelCase→`/snake_case` naming for the newer
  endpoints (the file mixes both styles — `/renameFunction` at `:180` sits
  beside `/rename_function_by_address` at `:299`).

`extension.properties` keeps `author=LaurieWired (Original), Modified by
ezrealenoch`, `createdOn=2025-03-22`, `version=12.0.3` (`:3-6`); upstream
meanwhile refactored to a multi-file extension with a headless backend and
sits at 11,695★, pushed 2026-10-10 — the fork never rebased that. The fork's
build story is Ghidra's own `buildExtension.gradle`:
`OGhidraMCP/build.gradle` pins `ext.ghidraVersion = "12.0.3"` (`:28`) and
Java 21 (`:31-34`); `build_ghidra_plugin.sh/.bat` wraps `gradlew
buildExtension` and drops the zip in `OGhidraMCP/dist/`
([20 §5](20-oghidra-inventory.md)).

### 3. The endpoint surface as actually registered

The plugin registers **30 endpoints** (`createContext`, `:139-402`): 28 back
tools the Python client can call, 2 are discovery only.

| Group | Endpoints |
|---|---|
| discovery | `/methods` (`:158` — returns *function names*, not the API: it calls `getAllFunctionNames`), `/classes` (`:165`), `/plugin-version` (`:139`), `/program` (`:145`) |
| program reads | `/decompile` (POST by name), `/decompile_function` (GET by address), `/disassemble_function`, `/list_functions`, `/searchFunctions`, `/get_function_by_address`, `/strings`, `/segments`, `/imports`, `/exports`, `/namespaces`, `/data`, `/read_bytes` |
| GUI state | `/get_current_address`, `/get_current_function` |
| xrefs | `/xrefs_to`, `/xrefs_from`, `/function_xrefs` |
| mutating | `/renameFunction`, `/renameData`, `/renameVariable`, `/rename_function_by_address`, `/set_function_prototype`, `/set_local_variable_type`, `/set_decompiler_comment`, `/set_disassembly_comment` |

### 4. The http backend: `GhidraMCPClient`

`src/ghidra_client.py` (2,822 lines, [20 §2](20-oghidra-inventory.md)) is the
backend seam of OGhidra itself: an ABC `AbstractGhidraClient` (`:21`) with
**7 lifecycle abstracts** (health_check/check_health/instances_\*/
get_current_program_info, `:38-62`), **28 tool abstracts** — exactly the 28
endpoint-backed tools — and three **backend-agnostic composites** defined on
the ABC: `analyze_function` (`:298`, decompile + referenced-function
summaries, truncating its own inputs at `[:4000]`/`[:2000]`/`[:500]`,
`:402-440`), `scan_function_pointer_tables` (`:452`), and its formatter
(`:732`). A shared bulk-read discipline caps naive list calls:
`MAX_SAFE_LIMIT = 20` (`:70`) with a warning template ("Capping to
MAX_SAFE_LIMIT") applied at eight list call sites (four in the HTTP client,
`:1147-1190`; four more in the PyGhidra client, `:2157-2284`); offset/limit
coercion and client-side pagination helpers live at `:96-113`.

`GhidraMCPClient` (`:762`) speaks to the plugin with `httpx`, one
`Client(timeout=config.timeout)` — `GHIDRA_TIMEOUT` default 30 s
(`config.py:1368`) — against `GHIDRA_BASE_URL`, default
`http://localhost:8080` (`config.py:1364-1367`). Construction probes the
server via `_detect_api` — a GET of `/methods` with `limit=1` (`:811-824`) —
then auto-discovers instances (§8). All traffic funnels through one method,
`_http_request_text` (`:837-881`), serialized by `self._request_lock`
(`:797`, held at `:854`): "Thread-safety: serialize all HTTP requests for
future parallel workers" — today there is one worker, and a tool call that
finds the server dead **retries nothing**; it returns the literal string
`"Request failed: {exc}"` (`:874`) or `"Error {status}: {body}"` (`:881`).
Errors are *data*, typed nowhere; every caller downstream (bridge, prompt)
sees a string that may or may not start with "Error".
`health_check`/`check_health` (`:898`, `:912`) are the same `/methods?limit=1`
probe. Endpoint names mirror Java's mixed casing verbatim —
`rename_function` POSTs `renameFunction` (`:1139`), `decompile_function`
POSTs `decompile` (`:1131`), `set_local_variable_type` POSTs the snake_case
route (`:1285`); `list_functions` caps at 10,000 (`:1244`).

### 5. The pyghidra backend: the same surface, headless

The *pyghidra* backend swaps the socket for an in-process JVM. Selection is
`config.ghidra.backend` (`config.py:1373-1376`, env `GHIDRA_BACKEND`,
validated to `{http, pyghidra}` at `:1413-1419`) or `--ghidra-backend
{http,pyghidra}` on the CLI (`main.py:1313-1317`, applied `:1379-1380`);
`select_ghidra_client_class` returns the class plus a label
(`src/bridge.py:66-78`). The CLI gains four pyghidra-only flags:
`--pyghidra-project`, `--pyghidra-program`, `--pyghidra-binary`,
`--pyghidra-projects-dir` (`main.py:1322-1346`, `:1389-1390`).

`PyGhidraClient` (`:1322`) imports PyGhidra and starts a JVM in-process,
first normalizing a Windows `GHIDRA_INSTALL_DIR` like `C:\...` to WSL's
`/mnt/c/...` if that is what the runtime needs (`:1426-1446`); failure to
start raises with the install dir in the message (`:1480`). Program loading
is one constructor path, `_init_pyghidra` (`:1418-1754`), with two modes:
*import a fresh binary into a generated project* (when `pyghidra_binary` is
set) or *open an existing project/program* — trying both
`open_project(path)` and `open_project(dir, name)` signatures
(`:1600-1612`), auto-selecting the sole program in the project, erroring
verbosely on multiple or zero candidates (`:1700-1706`), then holding the
program open via `consume_program` → `program_context` → legacy
`project.open_program` in preference order (`:1712-1740`). Mutations run in
a pyghidra transaction and save the program after each one, best-effort
(`_run_program_transaction`, `:1964-1981`). Where the tool surface meets
headlessness, it degrades *explicitly*: `get_current_address` and
`get_current_function` return canned errors — "does not track the live
Ghidra GUI cursor" (`:2426-2437`) — and `instances_*` collapse to
single-instance stubs (`:1784-1797`). Decompiles use a 60 s timeout
(`:2093`, `:2467`), double the http path. The branch that built this backend
and its Docker fallout are [21 §3/§6](21-history-and-releases.md); the
staleness question — a PyGhidra-opened project shows only *saved* state —
is the same chapter's.

### 6. Two MCP-shaped paths: one live proxy, one corpse

OGhidra also speaks MCP itself, in two unrelated places.
`src/bridge_mcp_ghidra.py` (387 lines, PEP-723 inline deps) is a live
`FastMCP("ghidra-mcp")` server (`:14`, `:20`) exposing **exactly 28
`@mcp.tool()` functions** — the same 28 names as the ABC's tool abstracts —
each proxying the raw HTTP server via internal `safe_get`/`safe_post` helpers
(`:26`, `:46`; `requests`, 5 s timeout). `list_strings` defaults to
`limit=2000` here (`:303`), unlike the agent path's cap of 20. It connects an
*outside* MCP client (Claude Desktop et al.) straight to the Ghidra plugin —
MCP → HTTP → GUI — with no OGhidra agent, cache, or gate in between.
`src/ghidra_mcp_client.py` (509 lines) is the older hand-written client of
the same server (`:19`): still `requests`-based (`:12`), still parsing
`response.json()` envelopes (`:174-244`) that the plugin's `text/plain`
`sendResponse` no longer sends, and loading tool signatures from
`ghidra_knowledge_cache/function_signatures.json` (`:44`) — a path that no
longer exists (the live file is `src/cag/knowledge/function_signatures.json`).
Nothing imports it; branch `delete-ghidra_mcp_client` / open PR **#62**
removes it ([20 §2](20-oghidra-inventory.md),
[21 §7](21-history-and-releases.md)).

### 7. The tool surface: what the LLM can actually call

The agent in `src/bridge.py` (ch. 32) does not use function-calling schemas.
The system prompt embeds `ai_ghidra_capabilities.txt` — 45 lines, 34 tool
bullets, hand-written ([20 §9](20-oghidra-inventory.md)) — loaded by path
relative to the repo root (`src/bridge.py:684-700`), with a
`search_function_summaries` bullet injected only when hybrid search is on
(`:709-719`). The LLM emits `EXECUTE: tool(args)` text lines; dispatch is
pure introspection: normalize camelCase→snake_case against the live client
object (`:1185-1204`), then the valid command set is **every public
attribute of the client object**: `[name for name in dir(client) if not
name.startswith("_") and callable(...)]` (`:1222`), and execution is
`getattr(client, normalized)(**params)` (`:1797`). Two pseudo-tools are
intercepted before dispatch and are bridge-owned, not client methods:
`get_cached_result` (`:1697`; body `:1302`) and `search_function_summaries`
(`:1702`).

Measured counts (public methods, regex over the clone):
`GhidraMCPClient` presents **38 public callables** — 28 endpoint-backed tool
methods, 7 lifecycle/instance/health methods, and the 3 ABC composites — so
the LLM's *Ghidra tool surface* is **31 tool methods** (28 + 3 composites),
**8 of them mutating** (the renames, prototype, variable type, two comment
writers). `PyGhidraClient` presents 39 (same surface plus `close`). The
*prompt-declared* surface is a third number: `ai_ghidra_capabilities.txt`
(45 lines, injected as `capabilities_text` at `bridge.py:826-827`, on by
default via `main.py:1372`) carries **34 hand-written bullets** — 28 endpoint
tools, `scan_function_pointer_tables`, the 4 `instances_*` managers, and the
`get_cached_result` pseudo-tool — omitting `analyze_function`,
`format_table_scan_results` and the health/program-info methods; when hybrid
search is on, the bridge appends a 35th bullet for `search_function_summaries`
(`bridge.py:711-724`). 5 of the 34 touch no Ghidra program read: the pseudo-
tool and the four instance managers.

The docs describing this surface are **stale in both directions**:
`docs/enabled_tools.md` carries a "Disabled Tools" list —
`rename_variable`, `set_decompiler_comment`, `set_disassembly_comment`,
`set_function_prototype`, `set_local_variable_type` (`:93-103`) — yet all
five exist as ABC abstracts, client methods, live endpoints, and prompt
bullets; nothing disables them. `tool_capabilities.md` (1,334 lines) is
machine-generated from the ABC docstrings and regenerates rarely
([20 §9](20-oghidra-inventory.md)). Gating is minimal: the *execution gate*
(ch. 32) names only two of the eight mutating tools as high risk
(`rename_function`, `rename_function_by_address`,
`src/execution_gate.py:37-40`), and `GATE_ON_HIGH_RISK_TOOL` defaults to
**false** (`config.py:193`) — unattended analysis renames and comments the
live program by default.

Compaction of tool *output* is a separate layer: the bridge wraps results in
a `ResultCompactor` (`src/result_compactor.py`, 181 lines; wired at
`bridge.py:173-178`) that drops lines but keeps pagination headers
(`:91`) and appends "use `get_cached_result(...)` for full output" markers
(`:132`, `:169`, `:181`).

### 8. Multi-instance: a port registry inside one client

The README sells "**Multi-Instance Analysis** — Run multiple Ghidra
instances for parallel analysis" (`README.md:27`); what the code does is
smaller and real. Each plugin instance self-assigns a port (8080 → 8192+,
§1). The http client keeps an `active_instances` port→info dict (`:778`) and
probes `[8080, 8081] + range(8192, 8200)` (`:946`) with a 0.2 s GET of
`/plugin-version` (`:1074`), filling program/project from `/program` — the
Java `projectLocator:name` id split back apart (`:1104-1106`).
`instances_list`/`instances_discover`/`instances_use`/`instances_current`
(`:937-1037`) are **also LLM-callable tools**: the model can enumerate which
Ghidra GUIs hold which programs and retarget every subsequent request to
another port (`instances_use`, `:983`). The pyghidra backend exposes the same
four names as single-instance stubs (§5). There is no server-side registry,
no contention control, and no parallelism — the agentic loop issues one tool
call per step regardless, and the per-client `_request_lock` (`:797`)
serializes even that.

### 9. Ghidra and Java version support

`README.md:54-57` states the support story: Ghidra **12.0.3 recommended**,
"Tested with: Ghidra 11.0.3, 11.3.2, 12.0.2, 12.0.3", Java 21 required to
build the 12.0.3 extension; the build steps target 12.0.3 (`:78-115`). The
plugin's own pins agree: `ext.ghidraVersion = "12.0.3"`
(`OGhidraMCP/build.gradle:28`), `version=12.0.3` in
`extension.properties:5`. The pyghidra backend has **no equivalent pin** —
it uses whatever Ghidra the installed `pyghidra` wheel wraps, with only
`GHIDRA_INSTALL_DIR` needed (`:1457`); the version coupling lives in the
wheel, not in any OGhidra test matrix (no test CI exists at all —
[21 §8](21-history-and-releases.md)).

## Comparison with calxgloss

### Posture: attach to the human's live program vs load a disposable one

This is the root difference the rest follows from. OGhidra's whole design
attaches to *whatever the analyst already has open*: the plugin reads
`ProgramManager.getCurrentProgram()` and the `CodeViewerService` cursor of a
running GUI (`GhidraMCPPlugin.java:893-926,1992-1995`); the pyghidra backend
opens a Ghidra project the analyst may have built by hand, saved state and
all; even `/program` exists so the model can see *which* program it is
looking at. The LLM therefore sees unsaved GUI state, human renames, human
comments, and can write into that same live program. calxgloss has the exact
inverse property, fixed in ADRs: no attach, no install, no connect — Kuna
runs in-process against the binary itself and the loaded program is
disposable, re-loadable from binary + engine + records
([10 §The analysis engine's seam](10-calxgloss-baseline.md), :126-141);
"no MCP server or any MCP surface — the only 'MCP' text is the deleted
GhidraMCP client's historical note" (:261-263,
`calxgloss-decomp/src/lib.rs:5`). calxgloss's LLM never sees a human's
Ghidra session, and a human's Ghidra session never sees calxgloss's work
except through `re/` artifacts. That is a choice calxgloss made
deliberately (the Ghidra HTTP bridge and JVM lifecycle were *deleted*,
ADR-0001/0007/0041), and OGhidra demonstrates what the choice costs and
buys: OGhidra gets the analyst's entire working context for free — a rename
done at 15:00 is visible at 15:01 — but its results live *inside* someone's
Ghidra project, with no provenance, no replay, and no way to answer "what
was true before the last mutation". calxgloss's program state is derived
data with an identity-bearing cache and a record tree under it
(:143-149, :165-181); OGhidra's is whoever-saved-last.

### Transport: an unauthenticated wildcard HTTP server vs the compile-time seam

| | OGhidra (http backend) | calxgloss seam |
|---|---|---|
| boundary | socket: wildcard bind, no auth (`GhidraMCPPlugin.java:134`) | trait boundary in one process (`ScanSource`, `type_write_source.rs:222-227` tripwire) |
| concurrency | one JDK dispatch thread (`:410`), client lock per process (`ghidra_client.py:797`) | one engine thread, one call at a time (ch. 10 :139-140) |
| failures | string-typed: `"Request failed: …"` / `"Error 500: …"`, no retry (`ghidra_client.py:874,881`) | typed refusals; per-function budgets "refuse loud overspend" (ch. 10 :140-141) |
| timeouts | fixed per call-site (30 s/60 s in Java `:659,1390`; 30 s httpx `config.py:1368`; 5 s in the MCP proxy) | settings-driven instruction/seconds/memory budgets |
| who can reach it | anything on the network (§1) | nothing — in-process by construction |

Both are honest about single-threadedness (one JDK executor thread; one
engine thread) — that convergence is not a coincidence, it is what talking
to a Ghidra-shaped mutable program forces. The failure-handling contrast is
the sharp one: in OGhidra, a timeout or a dropped socket is a *plausible
tool output string* that goes into the next prompt cycle, where the model
must notice the word "Error"; an empty or failed decompile ("Decompilation
failed", `GhidraMCPPlugin.java:663`) is indistinguishable, at the type
level, from a decompile that legitimately produced nothing. calxgloss's seam
makes unavailability a declared fact per query family
(`answerable`/`unavailable` capability reports, ADR-0054/0055, ch. 10 :155-160,
:271-272) — the tier ladder *drops* unavailable steps rather than feeding
the model an error string to interpret. And the wildcard bind with zero
auth on a server whose endpoints rename, comment, create transactions, and
save a malware analyst's project is a security posture calxgloss's
nothing-to-connect-to design simply cannot have.

### Tool surface: 31 introspected methods vs declared query families

OGhidra's tool surface is a grab-bag found by `dir()`: anything public on
the client object becomes callable (`bridge.py:1222`), the prompt is a
hand-written 34-bullet text file that drifts from the code (its own repo's
`docs/enabled_tools.md:93-103` promises tools are disabled that are not),
and arguments are `**params` splatted into Python signatures with no schema
check before the call. calxgloss declares its surface the other way round:
the seam answers **only its declared query families**, each with a capability
report and an admission line when a facet fell short (ch. 10 :271-272,
ADR-0052–0055); there are no arbitrary user questions against the program,
and ad-hoc call-path/def-use is a roadmap item (P29), not a `getattr` away.
The mutating half of OGhidra's surface (8 tools; §7) has no calxgloss
counterpart at the LLM layer at all: in calxgloss, program mutations happen
**only** as scan-record *write-back* — typed, confidence-floored,
narrow-only, never over a hand-typed slot (ADR-0020/0021, no-write-back
doctrine, ch. 10 :124-127, :164-171) — and "humans never rename or comment
at an address, so there is nothing an edit log could log" (:160-168). The
contrast is total: OGhidra's LLM renames the program directly and its own
docs claim two of those renames are risky enough to gate (default: not
gated); calxgloss's LLM cannot touch the program, and the one automated
writer in the system is bound by narrowing rules and a compile-time
read/write trait split. OGhidra also *is* an MCP server for outside agents
(`bridge_mcp_ghidra.py`, §6) — the same endpoints, exposed to any MCP client
with the 5-second-timeout `safe_get`/`safe_post` escape hatches that can
POST *any* path the plugin serves, mutations included.

### Response caching: keyless in-memory dicts vs identity-keyed cache

Both systems cache Ghidra-shaped reads for repeat calls, and calxgloss's
ADRs read like a rebuttal of OGhidra's implementation, written a year
earlier. The bridge's cache is two process-memory dicts
(`decompilation_cache`/`function_cache`, `bridge.py:646-648`) keyed by
command + name/address/params (`_generate_cache_key`, `:1856-1896`); an
allowlist skips a few volatile commands (`NO_CACHE_COMMANDS`, `:1911-1920`:
the list_* reads, `get_current_address`, health) — but **not**
`get_current_function`, which gets the static key `get_current_function:session`
(`:1887-1889`), i.e. the GUI cursor is *pinned* to the value first seen.
There is no invalidation on mutation: `clear_cache` exists (`:1982`) but no
caller in the repo ever invokes it, so after `rename_function` the stale
decompile of the old name keeps answering. Nothing in the key says *which
binary, which instance, or which backend* produced the entry — switch
instances with `instances_use` and the same key now means a different
program under it. calxgloss's scan read cache is the checklist OGhidra
failed: file-level identity (binary SHA-256) + `CACHE_FORMAT_VERSION` +
**the identity of the engine build that produced the entry**
(ADR-0042/0043/0055; ch. 10 :146-154, `cache.rs:16-23,140`), persisted as
JSON documents, read-through so a miss is just a cold re-run. OGhidra's
cache is also strictly process-local — restart the bridge and it is gone —
whereas calxgloss's cache doubles as a durable artifact of the run
(`re/cache/{identity}/{sha256}/`, ch. 10 :184). The one genuinely thoughtful
OGhidra gesture is the NO_CACHE allowlist: it shows the authors *knew*
which reads are state-dependent — they just had no mechanism (watermark,
identity, or invalidation hook) to make that knowledge systematic.

### Discovery and breadth: instance registry + every Ghidra format vs one engine, PE only

OGhidra's multi-instance registry (§8) gives the model something calxgloss
structurally lacks: *awareness of which analyses are open where* — a
session-awareness tool, live in the prompt. calxgloss's counterpart is
durable bookkeeping (record tree, session state, bdiff version pairing by
binary SHA-256, ch. 10 :162-205), which survives restarts and merges but
never answers "what is the human looking at right now". Conversely on
breadth: OGhidra inherits **Ghidra's entire format and processor support** —
PE, ELF, anything the loader eats, any Sleigh arch — with zero bridge-specific
work; the bridge never branches on format. calxgloss is deliberately narrow:
native Windows PE/DLL for the pipeline
([00 §Comparison scope](00-scope-and-method.md), :63-65), with the engine
layer's whole job being *depth* on that one shape (15 evidence scans,
ch. 10 :93-115) that no Ghidra MCP surface has. OGhidra is broad and
shallow *at the bridge level*; calxgloss is narrow and deep; neither spent
engineering effort on the axis the other cares about.

### Overlap / calxgloss-only / OGhidra-only

- **Overlap:** a single-threaded, one-call-at-a-time engine boundary on both
  sides; pagination with absolute totals on list-shaped reads (Java
  `[Total:]` headers vs calxgloss's paginated cache documents); pagination
  headers *survive output compaction* in both systems
  (`result_compactor.py:91`); bounded raw-byte reads with an explicit cap
  (1–4096 `GhidraMCPPlugin.java:1778` vs `memory/{addr}-{len}.json`
  documents); a read cache in front of a mutable engine on both sides (with
  radically different keys); named per-call budgets/timeouts (30/60 s vs
  seam budgets); transaction discipline on every mutation (Ghidra
  `startTransaction` names each edit).
- **calxgloss-only:** identity-keyed, durable, engine-build-versioned cache
  (ADR-0042/0043/0055); capability reports per query family with admission
  lines (ADR-0054/0055); compile-time read/write split of the seam;
  write-back bound by narrow-only rules (ADR-0020/0021); typed refusals and
  loud budget overspend; zero network surface; 15 evidence scans (the thing
  a Ghidra tool list can *become* but never is).
- **OGhidra-only:** the live-GUI coupling (cursor tools, `ProgramManager`,
  unsaved human state visible to the LLM); an LLM-callable mutating surface
  over the live program (8 tools) with an optional, off-by-default gate; a
  port-probing multi-instance registry with `/program` identity; a second
  backend (pyghidra) offering the same 31-method surface headless; an
  outward FastMCP proxy for third-party agents; `tool_capabilities.md` as a
  generated API doc (drifting, but generated).

### Verdict

The bridge layer is where the two projects' premises collide hardest, and
calxgloss's ADR history is effectively a pre-emptive review of OGhidra's
bridge: delete the HTTP bridge and JVM lifecycle (ADR-0041 — OGhidra keeps
both and inherits a wildcard-bind, no-auth, GUI-dependent server); put
engine identity in the cache key (ADR-0055 — OGhidra's cache has none, pins
the GUI cursor on read #1, and never invalidates across renames or instance
switches); keep the LLM out of the program (ADR-0020/0021 no-write-back —
OGhidra hands the LLM 8 mutating tools and gates 2 of them, off by
default). What OGhidra's side proves is the value calxgloss gave up: the
analyst's live context — cursor, unsaved renames, "which Ghidra holds which
binary" — is *irreplaceable for interactive work*, and the fork's quiet
enrichments (per-import caller lists, external-symbol xref resolution,
`[Total:]` pagination) show what a real analyst needed that neither upstream
nor the prompt provided. The steal list, in priority order:
(1) **enriched import/export rows**: Ghidra's `[Refs: N] [Callers: ≤5]` on
every import (`GhidraMCPPlugin.java:515-561`) is exactly the one-line-per-
import digest calxgloss's `libmatch`/imports scan could stamp into its filed
documents — CAL exports with caller counts are the same query pointed at
exports; (2) **the absolute-total pagination header**,
`[Total: N] [Showing: A-B] [Next: …]` + "compaction never eats it" as an
invariant (`result_compactor.py:91`), adopted verbatim as the prompt-facing
list shape for paginated `--show` output; (3) **`read_bytes` UX**: one tool,
hex-dump default with base64 "raw" mode, hard 1–4096 clamp, named
`MemoryAccessException` on unmapped addresses (`:1768-1802`) — calxgloss's
memory cache wants the same clamp-at-the-edge rule; (4) **external-symbol
xref resolution**: resolve a name as function → *external symbol* → any
symbol before answering xref queries (`:1525-1549`), the same fallback
ladder calxgloss's caller scans should apply to import thunks;
(5) **a probe handshake** — a versioned identity endpoint (`/plugin-version`
+ `/program`, `:139-152`) checked before the first real call, generalized to
"advertise engine build id at seam open and fail loud on mismatch", which
pairs naturally with ADR-0045's pinned engine and ADR-0055's cache identity;
(6) **generated tool docs with a regeneration check**: `tool_capabilities.md`
generated from the code (ch. 20 §9) is right *when regenerated* — calxgloss's
capability/query-family docs should get the same generator plus a CI
freshness gate, because OGhidra's `docs/enabled_tools.md` shows how a
hand-written tool doc rots (a "disabled" list describing a build nobody
runs); (7) **named transactions**: every mutation names its transaction
("Rename function via HTTP", `:678`) — calxgloss write-back commits should
carry the scan + record id as the transaction name into Kuna's program
mutation, tying program state to provenance; (8) **an explicit
degrade-with-message pattern**: pyghidra's canned "does not track the live
GUI cursor, use an explicit address" (`ghidra_client.py:2426-2437`) is the
right *shape* for an unavailable query family — the admission line calxgloss
already has, but phrased as a next-action suggestion the consumer can act
on.

What calxgloss should *not* copy: the network surface at all (wildcard bind,
no auth, any endpoint that mutates state without provenance); `dir()`-based
dispatch — a valid-command set derived from Python introspection instead of
a declared capability report, with `**params` splat and no schema; a read
cache without invalidation, identity, or a caller on its `clear_cache`;
*errors-as-strings* leaking into the model's input (OGhidra has to hope the
model notices "Error 500" is not decompiled output — calxgloss's typed
refusals remove the hope); the MCP proxy with raw `safe_get`/`safe_post`
escape hatches; and the two-decade-old habit of documenting tools in prose
files that drift from the dispatch reality. The one architectural idea worth
serious consideration is narrower than "add Ghidra": OGhidra's *focus
signal* — which function a human is standing in right now — could reach a
calxgloss interactive surface as a **focus pointer** (a function name
hint for queue priority or prompt selection, `re/review/` overlay material,
ADR-0003-adjacent) without ever coupling calxgloss to a running Ghidra
process. State from a live session, once; engine coupling, never.

## Sources

- OGhidra clone at `6224d26` (branch `main`):
  `OGhidraMCP/src/main/java/com/lauriewired/GhidraMCPPlugin.java` (2,028
  lines; all `:line` cites above; re-extracted from the committed git blob
  `f98fb8f`, endpoint registration count 30 via regex over
  `createContext`); `OGhidraMCP/{build.gradle,extension.properties,
  build_ghidra_plugin.sh}`; `src/ghidra_client.py` (2,822), `src/bridge.py`
  (7,845, dispatch/cache/capabilities cited above), `src/config.py`,
  `main.py`, `src/execution_gate.py`, `src/bridge_mcp_ghidra.py` (387; 28
  decorated tools counted by script), `src/ghidra_mcp_client.py` (509;
  import-finder empty across `src/` + `main.py`), `src/result_compactor.py`
  (181); `ai_ghidra_capabilities.txt` (45 lines, 34 bullets),
  `docs/enabled_tools.md` (143), `README.md` (`:27,54-57,78,149,181`).
- Counts measured by script on the clone (regex over `def` lines, cross-checked
  against the class bodies): public callables 38 (`GhidraMCPClient`) / 39
  (`PyGhidraClient`); 35 `@abstractmethod` on the ABC = 7 lifecycle + 28
  tools; 8 mutating tools; fork-vs-upstream diff +634/−257 lines raw,
  +507/−130 ignoring whitespace.
- LaurieWired/GhidraMCP via GitHub API 2026-11-01: 11,695★, pushed
  2026-10-10 (current tree is a refactored multi-file extension — not what
  the fork descends from); commit `865bf483` dated 2025-06-20, message
  "Fixed for Ghidra 11.3.2"; its single-file plugin fetched at 1,651 lines /
  27 endpoint registrations and diffed against the fork blob.
  starsong/GhydraMCP: **404 on the API** (2026-11-01) — the lineage claim
  rests on the fork's own attribution comments (`:5`, `:426-427`) only.
- calxgloss side: [10-calxgloss-baseline](10-calxgloss-baseline.md)
  (seam :129-160; cache :146-154, :184; no-write-back :124-127, :164-171;
  no-MCP :264-272); ADR-0001/0007/0020/0021/0039–0043/0045/0052–0055;
  `crates/integrations/calxgloss-decomp/{scan_source,type_write_source,
  cache}.rs`; `calxgloss-decomp/src/lib.rs:5`.
- Sibling chapters: [20](20-oghidra-inventory.md) (file sizes, Java area,
  docs inventory), [21](21-history-and-releases.md) (pyghidra branch/#23,
  PR #62, no test CI, Docker staleness), [32](32-agentic-core-and-context.md)
  (execution gate, agentic loop, compaction wiring),
  [33](33-knowledge-rag-and-sessions.md) (CAG, session caches — a different
  cache than the bridge's Ghidra-response dicts).
