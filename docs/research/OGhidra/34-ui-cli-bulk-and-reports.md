# 34 — The workbench surfaces: a Tkinter window mostly hidden behind menus, a CLI with one real trick, and a report the LLM writes about itself

> Part of the [OGhidra overview](README.md). The human-facing layer end to end:
> `main.py`'s entry flags and the interactive REPL, the Tkinter window and what it
> actually puts on screen, the nine *smart tool buttons* and their exact LLM-call
> cost, the *bulk rename workflow* and its three *enumeration modes*, the *Analyzed
> Functions* panel and whether any accept/reject/undo of a rename exists, the
> *daemon thread pool executor* and the `max_workers` fiction, the report pipeline
> (`generate_software_report` → six analysis prompts → one JSON prompt →
> `report_template.py`), and the *analysis dump* observability module — then the
> comparison against calxgloss's web *verdict* surface, *attempt*-branch
> reversibility, and computed-on-demand analytics
> ([ch. 10](10-calxgloss-baseline.md); ADR-0002/0003/0005/0006). All `:line` cites
> are to the clone at `6224d26` (branch `main`); LOC re-measured with `wc -l`;
> quoted UI and dialog text is verbatim. GUI file tables live in
> [ch. 20](20-oghidra-inventory.md) §2.8; the plugin server and
> `get_current_function` backend degradation are ch. 31; the agentic loop, its
> prompts and task modes are ch. 32; sessions, `ui_state`, the memory panels and
> the Load Vectors flow are ch. 33.

## What OGhidra does

### 1. Entry surfaces: one `main.py`, three modes, and what is *not* on port 8080

`main.py` (1,426) exposes exactly three modes: `--interactive/-i` (`main.py:1302`), `--query/-q` for a single
fire-and-print query (`main.py:1303`, executed at `:1421-1423`), and `--ui` (`:1305-1309`), which the README
calls "GUI Mode (recommended)" — and which the code makes the default: if no mode flag is passed,
`args.ui = True` (`:1368-1369`). Backend selection is a flag, not a config key:
`--ghidra-backend={http,pyghidra}` (`:1312-1317`) plus `--pyghidra-project/-program/-binary`
(`:1321-1347`); `--no-capabilities` (`:1350`) and `--disable-cag` (`:1356`) trim the bridge. One dead
flag: `:1389` reads `args.pyghidra_projects_dir` via `getattr`, but no argparse call ever registers
`--pyghidra-projects-dir` — verified, that branch can never fire. The startup banner (`:31`) points
the user at "README-ARCHITECTURE.md", a file the repo does not contain.

The README's GUI connectivity tip invites a confusion worth nailing down: "If you launched GUI mode,
use: `curl http://localhost:8080/methods`" (`README.md:179-181`). Port 8080 is not the OGhidra GUI —
the Tk window is a plain desktop process and serves no HTTP anywhere in `src/gui/` (verified). 8080 is
the GhidraMCP Java extension's HTTP server *inside the Ghidra GUI process* (the `OGhidraMCP/` plugin,
[ch. 31](31-ghidra-bridge-and-backends.md) §1), whose base URL is the config default
`http://localhost:8080` (`src/config.py:1367`). The curl is a bridge liveness check; the sentence
makes it sound like a web UI and there is none. Neither mode is a daemon (as in calxgloss, ch. 10):
closing the window runs `_quit_application` (`src/gui/ui.py:1185-1203`) — save CAG session, close
Ghidra client, tear down Tk.

### 2. The Tkinter window: what is on screen, and what is only in code

The window is a `ttkbootstrap` dark-theme `tb.Window`, "darkly", 1400×900 (`src/gui/ui.py:42-46`).
Immediately after the root exists, `ui_thread.install(self.root)` (`:51`) starts the thread-safety
pump: a single 30 ms `after()` loop draining a command queue, with the `@ui_safe` decorator queuing
widget mutations from worker threads onto the Tk main loop (`src/gui/ui_thread.py:34-73`). This
primitive is the scar of PR #44 — ch. 21's "Fix Linux UI crash" (`93a4380`, squashing
`fix/session-loading-ui-freeze` and the orphaned `19-gui-crashes-on-linux` branch) — three years of
widget mutation from background threads before anyone fixed it.

Layout is one horizontal `PanedWindow` with weights 4:1 (`src/gui/ui.py:108-117`). The left column:
the *QueryInputPanel* ("AI Query", `query_input_panel.py`) and the *AI Response Panel*
(`ai_response_panel.py`), which receives `generate_callback=self._menu_generate_report` at
construction (`src/gui/ui.py:133`). The right sidebar: the *Workflow Diagram* — a canvas showing four
stages, "Planning / Execution / Analysis / Review" (`src/gui/workflow_diagram.py:27`) — above the
*Renamed Functions Panel* (LabelFrame titled "Analyzed Functions",
`src/gui/renamed_functions_panel.py:24`).

The interesting part is what never appears. `MemoryInfoPanel` is constructed into an unpacked frame
with the comment "Hidden components (memory panel — accessed via Tools > System Info menu)"
(`src/gui/ui.py:161-164`) — but the System Info menu (`:195`) opens a *different*, inline-built dialog
(`:902-1045`); the panel itself is unreachable chrome, its only live role the refresh hook
`bridge._ui_memory_panel_refresh`. And `ToolButtonsPanel` — the "Smart Tools" LabelFrame holding the
nine famous smart-tool buttons — is likewise constructed-but-unpacked, with its own honest comment:
"Tool panel (hidden — accessed via Analysis menu)" (`:169-170`). The README, meanwhile, documents
"Smart Tool Buttons (GUI)" as a visible one-click panel (`README.md:238-249`). Doc drift, verified
against the layout code.

So what a user can actually click: File Save/Load Session (`src/gui/ui.py:186-187`, handlers
`:245`/`:541`, streaming load in ch. 33 §9); Tools Health Check / System Info / Server Configuration /
Clear Session (`:194-198`). Analysis: all nine smart tools (`:205-222`) as one-line delegations to `src/gui/ui.py:1122-1164`; the response panel's visible "Generate Report" (the callback above — the
one smart tool with an on-screen button) and "Export JSON" (`src/gui/ai_response_panel.py:36-38`); and
the query panel's quick actions "Analyze Function"/"Rename Function"
(`src/gui/query_input_panel.py:144-147`), wired post-construction via `query_panel.tool_panel`
(`src/gui/ui.py:176`).

The About dialog (`src/gui/ui.py:1166-1183`) still says "Version 1.0 … © 2024" and calls CAG
"Cache-Augmented Generation (CAG)" (`:1175`) while System Info (`:902-1045`, with Enable CAG/RAG
checkboxes at `:937`/`:980` and psutil stats) labels it "Context-Augmented Generation (CAG)" (`:920`)
— the ch. 33 naming census inside a single file.

### 3. The smart-tool buttons: full inventory, and what each one *really* costs

`ToolButtonsPanel.__init__` registers nine buttons in a list (`src/gui/tool_buttons_panel.py:50-59`)
gridded two-per-row (`:62-64`), plus a status label, an *indeterminate* progress bar, and a Stop
button (`:69-83`). There are three execution styles in the class, and the most important fact about
the first is that it is dead: `_run_ai_agent_query` — the full `bridge.process_query` agentic run — is
defined (`:88-115`) and called from nowhere (verified by grep). Every smart button is instead a
**hardcoded workflow**: a fixed sequence of Ghidra tool calls plus one fixed prompt. The agentic loop
is *never* used for a smart tool; the README's "one-click access to common reverse engineering tasks"
table describes canned micro-workflows, not agent runs.

Cost per button, from the code (LLM = one `bridge.ollama.generate` unless noted):

| Entry point | Ghidra calls | LLM calls |
|---|---|---|
| Analyze Current Function (`_run_hardcoded_analyze_current_function`, `src/gui/tool_buttons_panel.py:1920-2075`) | `get_current_function` → regex-parse `"Function: X at ADDR"` (`:1946`) → `decompile_function(name)` (`:1964`) → `get_xrefs_to/from` (`:1997-1999`) | 1 (`:2024`) |
| Rename Current Function (`_run_hardcoded_rename_workflow`, `:304-607`) | same cursor+decompile prefix, then `rename_function` (`:478-480`) | 1 (`:387`) |
| Analyze Imports / Exports / Strings (`_run_hardcoded_workflow`, `:149-302`) | paginated `list_imports/exports/strings` collection; strings variant enriches with xrefs + two decompiles (`:211-262`) | 1 (`:269`) |
| Search Strings (`:2478-2488`) | `list_strings` with `{"filter": query}` | 1 |
| Scan Function Tables (`:2492-2579`) | `scan_function_pointer_tables(min_table_entries=3, pointer_size=8, max_scan_size=65536)` — algorithmic detection, no LLM (`:2511-2513`) | 1, *streamed* via `bridge.ollama_client.stream_generate`, the only streaming GUI path; the stop flag breaks the chunk loop (`:2541-2547`) |
| Rename All Functions (bulk) | see §4 | 1 per processed function |
| Generate Software Report | see §6 | 7 |

Two honesty notes fall straight out of this table. The "Analyze Current" and "Rename Current" flows
hang off `get_current_function` — the Ghidra GUI cursor — which under the pyghidra backend returns a
canned "does not track the live Ghidra GUI cursor" error (ch. 31 §5,
`src/ghidra_client.py:2426-2437`), so two of the nine smart tools silently degrade to errors headless.
And the cost column is the whole cost-control story: there is no tier, no budget check, no cap; a
button is exactly as expensive as the prompt hard-coded into it.

The prompts themselves are security-shaped: `_get_analysis_prompt` (`src/gui/tool_buttons_panel.py:2382-2439`) bakes in the
malware-hunter framing — imports analysis naming "VirtualAllocEx, WriteProcessMemory, and
CreateRemoteThread … strong indicators of process injection" (`:2427`), strings analysis hunting C2
and credentials. They are static text; the LLM never chooses them.

Two Stop buttons exist, and they work at different levels of reality. The tool panel's Stop
(`src/gui/tool_buttons_panel.py:2444-2450`, initially disabled and enabled by `_set_tool_running`, `:2451-2457`) sets
`should_stop`, and the *bulk* loop honors it at every future-completion boundary (`:1628`) and in the
stream-chunk loop (`:2541-2547`) — but a single long `ollama.generate` (analyze-current, the hardcoded
workflows) has no check inside it, so for six of nine buttons Stop is best-effort at best. The query
panel's Stop is worse: `_stop_query` sets `query_panel.should_stop`
(`src/gui/query_input_panel.py:297-302`) and nothing in `bridge.process_query` ever reads that
attribute (verified) — pressing Stop mid-agent-run re-enables the UI (`_set_query_running(False)`,
`:304-308`) while the agent keeps burning steps in its daemon thread. Same flag-shaped placebo pattern
as ch. 33's dead reload path.

### 4. The bulk machinery: Rename All, the three enumeration modes, and five daemons

Rename All gates itself twice. First a modal warning whose text contains the chapter's key admission:
"The operation cannot be easily undone — consider saving your current session first" (`src/gui/tool_buttons_panel.py:2099`), gated
by `messagebox.askyesno` (`:2106`). Then an 800×650 `Toplevel` dialog (`:2109-2223`) offering the
three modes as radios — **Rename Only** (default; generic names only), **Full Enumeration** ("Process
ALL functions … complete coverage", `:2160-2168`), **Smart Enumeration** ("Recommended", `:2171-2180`)
— plus a "Skip functions already analyzed in the loaded session (N found)" checkbox that is checked
and enabled only when the panel already has rows (`:2183-2195`).

`_run_bulk_rename_workflow` (`src/gui/tool_buttons_panel.py:1448-1911`) then runs on one worker thread:

1. **Freeze the UI**: `renamed_functions_panel.batch_operation_in_progress = True` pauses the panel's 15 s auto-refresh (`src/gui/tool_buttons_panel.py:1465`).
2. **Advertise, then not quite do it.** Before any work, the run prints "⚡ Performance
   Enhancements: • Batch processing (size: 50) • Deferred RAG vector creation • Optimized AI
   prompts" (`:1476-1479`). `batch_size = 50` (`:1470`) appears in no other line of the file — the
   pool submits every function at once (`:1613-1621`). The only real batching is `rag_batch_size =
   25` in the vector step (`:1066`).
3. **Collect the function list** via `list_functions(offset, 200)` paging, parsing the server's
   `[Total: N]` / `[Next: offset=…]` metadata lines to decide when to stop (`src/gui/tool_buttons_panel.py:1483-1552`).
4. **Skip-analyzed filter** (`:1558-1588`): keys = canonicalized addresses + old/new names from
   `_collect_analyzed_keys` (`:1420-1446`, panel row snapshot, else
   `bridge.function_address_mapping`) — the ch. 33 session story wired into throughput: resume
   enumeration where the loaded prose left off. "Analyzed" here means presence in that row model —
   LLM-harvested state, not any verification.
5. **Fan out** across a pool: `max_workers = 5` — a literal (`:1595`), with a comment claiming
   "(configurable)". It is not: no `max_workers` key exists in `src/config.py` (verified). The
   README's troubleshooting advice "Reduce parallel workers: Set `max_workers=2` in bulk
   operations" (`README.md:507`) is **false**; there is nothing to set. `DaemonThreadPoolExecutor`
   (`src/gui/tool_buttons_panel.py:1612`; `src/gui/daemon_thread_pool_executor.py:7-38`) spawns daemon workers, so closing the
   window abandons in-flight LLM calls — throughput over completion, on purpose.
6. **Per-function worker** `_process_single_function_for_bulk_rename` (`src/gui/tool_buttons_panel.py:609-1049`) returns a dict
   with a four-valued `result_type`: renamed / enumerated / skipped / failed (`:620`). Mode filters
   come first — Rename Only accepts only the five generic prefixes `FUN_/sub_/loc_/unk_/j_`
   (`:643-647`); Smart skips thunk/stub/wrapper names (`:707-713`), import/export stubs
   `__imp_/__exp_/_imp_` (`:715-716`), short get/set/is accessors (`:720-725`), C-runtime patterns
   `_crt_/__cxa_/__std_…` (`:728-733`), always keeps generic names (`:735-736`), and otherwise
   demands one of ~46 `important_keywords` (`:656-702`). Then `decompile_function_by_address`
   through the FIFO `_decompilation_cache` (1000 entries, hit stats — `:39-42`, `:1124-1162`) — and
   only *after* the decompile does Smart drop bodies of ≤3 code lines or <50 chars (`:757-778`).
   That ordering is the finding: the filters save the **LLM** call, not the Ghidra work — every
   surviving function is paid for in full. Then `_gather_function_context` (`:1184-1302`): ≤5 xrefs
   each way, decompiles of the top 3 each way (cached, 1000 chars each), the caller list finally
   trimmed to 2 (`:1290-1291`), 8000 chars total; **one** `ollama.generate` (`:839`) with the
   four-section rename-suggestion prompt (structurally the CLI's, §7), retried on an empty reply
   up to three attempts total (`max_retries = 2` + loop, `:792-796`; retry branch `:1028-1042`).
   Name recovery from the prose is a three-level
   regex lottery: the `**Suggested Name:**` line (`:849-857`), then any camelCase token
   (`:859-878`), then *any* lowercase word over 6 characters not in a 15-word blocklist
   (`:880-899`) — the last of which can rename a function after a word lifted from the model's own
   explanation prose. The rename gate: **only generic-named functions ever get renamed, in all
   three modes** (`:903-949`); everything else is "enumerated" (`new_name == old_name`,
   `:905-908`). The rename fires through `bridge.execute_command("rename_function", {old_name,
   new_name})` (`:916`, `:937`) — into the live Ghidra program at that instant. Metadata comes from
   `FunctionMetadataExtractor.extract_all_metadata` run locally over the decompile (`:956-966`, ch. 33 §5), the LLM supplying only prose and a name; summary + address mapping are stored on the bridge
   under the panel's `dict_lock` (`:994-1010`).
7. **Account as they complete**: the `as_completed` loop tallies skipped/failed/renamed/enumerated
   per future (`:1626-1716`), logs each failure per-function and keeps going (no abort threshold),
   and every tenth completion prints a genuinely honest line: `x/y (pct%) | [OK] … | [ERR] … |
   [SKIP] … | [ETA] …`, the ETA from wall-clock throughput (`:1708-1724`, `_format_eta`
   `:1411-1418`). What is *not* honest is the skip accounting: `result_type = "skipped"` carries no
   reason field (`:649`, `:710-776`), so the "Functions Skipped Breakdown" (`:1745-1758`) is
   mode-derived boilerplate — and its closing tip, "Use 'Enumerate All Functions' to process ALL
   functions" (`:1755`), names a tool that exists nowhere in the GUI (verified). Stop cancels
   unstarted futures and keeps collected data (`:1627-1644`).
8. **The fake leg**: `_create_batch_rag_vectors` (`:1051-1122`) announces "Creating RAG vectors for
   N processed functions…", drives a RAG progress bar, sleeps 10 ms per item "to make progress
   visible" (`:1090-1092`), counts `rag_success_count += 1` — while the actual vector-add call is
   commented out: "RAG integration removed — use 'Load Vectors' button" (`:1078`). "Successfully
   created N/N RAG vectors" (`:1109-1111`) is arithmetic over nothing — ch. 33's
   commented-out-work-as-success, now with a progress bar.
9. **Auto-save a session** (`:1761-1848`): always a *new* `EnhancedSessionManager` session named
   `BulkRename_{mode}_{ts}`, containing the panel's analyzed functions, the vector store's
   *documents* (ch. 33 §9: not vectors), and a `performance_stats` block (counts,
   `avg_time_per_function`, mode). Then the final summary block (`:1857-1885`): counts,
   total/average time, worker count, and cache stats including "Ghidra calls saved: {hits}" — then
   it clears the decompile cache.

The only pacing control is `request_delay` — a per-backend client setting (`OLLAMA_REQUEST_DELAY`,
`EXTERNAL_REQUEST_DELAY`, `CUSTOM_API_REQUEST_DELAY`; `src/config.py:1165,1215,1319`) that makes the
client `time.sleep` before each HTTP call (`src/ollama_client.py:306-309`,
`src/custom_api_client.py:417-419`). The sleep lives *inside* each client call, so it paces each of
the five workers independently, not the run — the README sells it as the bulk throttle
(`README.md:509`); it is a per-thread metronome.

### 5. The "Analyzed Functions" panel: a listing surface with no *verdict*

The panel is the best-engineered file in the GUI (`renamed_functions_panel.py`, 1,173). Its thread-safety design is the kraken study's edit-log pattern (kraken ch. 32) done voluntarily: an authoritative row model
`_rows_model` updated synchronously under a lock, all Tk mutations queued and drained by a 50 ms
main-thread poller (`src/gui/renamed_functions_panel.py:21-49`, `:123-164`), `get_rows_snapshot()` as the only cross-thread read
(`:689`), `_compute_desired_rows` reconciling from the bridge's `analysis_state["functions_renamed"]`
+ `function_address_mapping` + `function_summaries` (`:541-604`), and a 15 s auto-refresh that pauses
during batch operations (`:1086-1104`).

Its affordances are where the comparison sharpens. Columns: Address / Old Name / New Name / Behavior
Summary (`src/gui/renamed_functions_panel.py:85-99`). Right-click: **Edit Summary** (a full modal editor), Copy Address, Copy Name,
**Remove Function** (`:740-771`). Buttons: Refresh, Export (JSON or TXT of the rows, `:1021-1064`),
Clear All, Load Vectors (`src/gui/renamed_functions_panel.py:57-64`; the vectors story is ch. 33 §11). Double-click opens the summary
editor (`:723-738`).

Nowhere in the panel — or anywhere in `src/gui/` — is there an accept, reject, confirm, revert, or
undo of a *rename* (verified: no undo/revert machinery in the GUI; the bulk dialog says so itself,
§4). The rename is applied to the live Ghidra program the moment the LLM's suggestion passes the
name-shape regexes; by the time a human sees the row, the mutation is done. "Remove Function" deletes
the entry from `analysis_state` bookkeeping only (`src/gui/renamed_functions_panel.py:996-1019`); Clear All zeroes `functions_renamed`
(`:1066-1084`) — in both cases the renames remain baked in the Ghidra program. Reverting a bad AI
rename means Ghidra's own checkpoint/undo inside CodeBrowser — a capability OGhidra never touches and
the reviewer is never told about. The panel is therefore a **listing with an editable annotation**,
not a review queue — the only "reject" available is bookkeeping amnesia.

### 6. The report: seven LLM calls, one 1,490-line renderer, and a self-report with invented timestamps

The GUI button ("Generate Software Report", also the response panel's visible button) confirms first
(`src/gui/tool_buttons_panel.py:2248-2274`) — promising "Executive Summary with risk assessment / Attack vectors and exploitation
flow diagrams / AI investigation steps timeline / Critical imports and string artifacts / Security
recommendations" — then runs `_run_software_report_workflow` (`:2280-2374`), whose entire payload is
one call: `bridge.generate_software_report("html")` (`:2310`). Nothing is written automatically; a
follow-up `askyesno` + save dialog writes `vulnerability_report_{timestamp}.html` only if the user
says yes and names a path (`:2326-2357`).

There are two progress mechanisms here and only one of them is live. The bridge *does* publish stages
— `current_workflow_stage = "planning" / "analysis" / "review"` (`src/bridge.py:5435-5459`) — and both panels read them: each runs a `_monitor_workflow_stage` loop, the query panel's at `src/gui/query_input_panel.py:329-346`, the tool panel's at `src/gui/tool_buttons_panel.py:130-147`; its widget writes
go through `@ui_safe` (`:2458-2476`). What the report workflow layers on top is a script: its "Phase 1 / Phase 2 / Phase 3"
lines are printed before the single call that performs all three phases (`:2295-2306`; call at
`:2310`), on a plain daemon `threading.Thread` (`:2374`) rather than the pool.

Inside the bridge (`src/bridge.py:5415-5460`), three phases:

- **Collect** (`_collect_comprehensive_binary_data` `src/bridge.py:5462-5587`): full pagination of functions,
  imports, exports, segments, classes, namespaces, data items, and strings through
  `_collect_all_paginated_list_results` (`:1633`); plus `analysis_state` renames,
  `function_summaries`, real program info (`binary_name` from `get_current_program_info`, `:5579`),
  and — the interesting one — the text after "AI AGENT RESPONSE" in the newest `analysis_dump_*.md`
  in `logs/` (`_get_latest_agent_analysis_text`, `:5371-5413`).
- **Analyze**: **six** sequential `ollama.generate` calls (`:5589-5634`) — software classification
  (its prompt demands a `SOFTWARE_TYPE` enum and an `EVIDENCE` line that "MUST include specific
  function addresses … `String 'Y' found at Z`", `:5667-5698`), security assessment (wants
  `SUSPICIOUS_INDICATORS` "at address 0x…" plus `IOCS` "with specific addresses and strings found",
  `:5700-5739`), function categorization, behavioral patterns, architecture, and a final
  risk-assessment prompt that sees the other five's outputs (`:5845`). One `try` wraps all six: the
  first exception aborts the rest and stores `analysis["error"]` ("Return partial analysis with
  error noted", `:5631-5634`) — no per-section retry, and the renderer never looks at that key. What
  the prompts *display* is thin: 10 imports, 10 exports, 10 sample function names, summaries capped
  at 10 (`:5675-5681`, `_format_summaries_for_prompt` `:5875-5900`); the string list collected above
  is never passed to any of them (`data["strings"]` is written at `:5565,5567` and read nowhere in
  the file) — while every prompt demands string-based evidence. When no agent dump exists,
  `_format_agent_analysis_context` (`:5636-5665`) tells the model "You may SPECULATE … Do NOT refuse
  to analyze"; when one exists it is the "PRIMARY SOURCE of truth". The instruction to speculate is,
  to its credit, explicit.
- **Render** (`:6877-6886` dispatch): for HTML, a **seventh** LLM call (`_generate_html_report`,
  `:7026-7115`) whose prompt is a config constant (`src/config.py:1022-1140`) demanding "ONLY valid
  JSON" with sections `executive_summary / statistics / key_findings / attack_vectors (legacy) /
  vulnerability_discovery / security_imports / investigation_steps / string_artifacts /
  recommendations` plus dynamic sections and a CSS-class cheat sheet. `_parse_html_report_response` (`src/bridge.py:7166-7315`) maps each section's `content_type` to a template builder (`build_stats_grid`,
  `build_timeline`, `build_vulnerability_discovery`, `build_key_findings`, `build_security_imports`,
  `build_table`…); parse failure degrades to a raw `<pre>` dump or the static
  `_generate_fallback_html_report` (`:7316-7380`, executive summary + three stat cards — no LLM).

The data the seventh call is actually shown (`src/bridge.py:7042-7085`) is: the counts, the six earlier answers'
fields, 15 import names, up to 10 function summaries clipped to 200 chars
(`_build_html_report_context`, `:7117-7128`) — and an "Evidence with Addresses" block built by
`_format_address_evidence` (`src/bridge.py:7136-7151`) out of the `addresses` arrays the *previous LLM answers*
invented. Real strings, real segments, real data items: collected, then dropped. So the schema's
`string_artifacts` table ("Interesting strings with addresses", `src/config.py:1100-1104`) has no
string input at all, and hallucinated addresses from call #1 are laundered into "evidence" for call
#7.

`report_template.py` (1,490 LOC) is mostly stylesheet: `ReportSection` + `ReportMetadata`
dataclasses (`src/report_template.py:19-38`), a ~990-line `REPORT_CSS_STYLES` constant (`:46-1037`),
and `generate_html_report` (`:1050`) assembling dark-theme HTML (ch. 20's WiseDiskCleaner-descendant
template) with per-section rendering (`_render_section`, `:1131-1142`). It is deterministic and
mostly escaped — but the section *content* is inserted **unescaped** (`:1139`): the LLM's HTML goes
raw into the browser.

Two claims to correct. The README's report list (`README.md:403-412`) promises a "Function Inventory
(renamed functions with behavior)" section — the closest thing is the *markdown* format's `## 🎯
Function Analysis` → `### Renamed Functions` (`_generate_markdown_report`, `src/bridge.py:6888`,
prints it at `:6946`), which the GUI button never requests; the HTML schema has no inventory section
at all, and function summaries reach it only as hidden context (top 10 × 200 chars). And the "AI
investigation steps timeline" promised in the confirmation dialog
(`src/gui/tool_buttons_panel.py:2260`) is the most dishonest artifact in the project: the
`vulnerability_discovery` schema wants per-step tool names *and wall-clock timestamps* (`{"tool":
"list_imports", "time": "07:36:13", "params": …}` — `src/config.py:1068-1072`), there is a whole
`investigation_steps` section that is just "Timeline of AI analysis" (`:1100-1105`), and rule 6
demands "the ACTUAL investigation steps that led to finding the vulnerability" (`:1135`) — while no
tool log and no timestamp reaches the prompt. The renderer draws those invented steps as an accordion
card with a per-step timeline (`build_vulnerability_discovery`, `src/report_template.py:1385-1444`)
and the invented reasoning through `build_timeline` (`:1199-1224`); everything is `html.escape`d
except the step `result` (`:1419`) and the section body (`:1139`).

`analysis_dump.py` (292) is the honesty counterpart. The *analysis dump* module records every agentic
tool execution — full untruncated result, CoT reasoning, `was_truncated` flag, char count, loop/step
numbers (`DumpEntry` `src/analysis_dump.py:24-36`; `add_execution`, `:88-112`) — into `logs/analysis_dump_{ts}.md`
(`save`, `:184-200`), driven from `process_query` (`src/bridge.py:2993-2995, 3284, 3675-3683`). Its
docstring says it plainly: visibility "before any truncation or summarization is applied… manual
review of what data the agent is processing". No UI surface ever opens it; its only programmatic
consumer is the report's "AI AGENT RESPONSE" scrape above — the tool calls, addresses and params are
thrown away and only the model's own prose comes back as the "primary source of truth". OGhidra built
the real record — and then reported from the LLM's memory of it instead. Housekeeping while we are
here: `src/bridge.py` defines four helpers twice inside the one `Bridge` class
(`_format_summaries_for_categorization` `:6255` and `:6677`; `_format_renamed_functions` `:6260` and
`:6682`; `_format_behavioral_data` `:6274` and `:6696`; `_format_architecture_data` `:6510` and
`:6700`) — the later definition wins, the earlier copy is dead code, and nothing in the file tells you
which one you just edited.

### 7. The interactive CLI: one real workflow, and the README's claims against it

`run_interactive_mode` (`main.py:43-1294`) is a REPL with a modest command set: `health` (`:112`),
`vector-store` status (`:166`), `models` (`:207`), `tools` (`:217`), `cag` (`:268`), `run-tool
tool(args)` — a direct tool call that, for 7 named tools, appends a canned AI-analysis prompt to the
raw result (`:333-345`); `analyze-function [address]` (refuses address-less under pyghidra,
`:597-600`); `review-session` — one prompt over the *in-memory* run log (`:1212`); `clear_log`
(`:1262`); and any other line — slash commands included, since no `handle_command` exists anywhere in
this snapshot — straight into `bridge.process_query`, the full agent (`:1272`). No `save/load
session`, no report generation, no task-mode control, no cancel. The flag set is nine entries
(`:1302-1359`, §1) and there is no `--report`: the CLI cannot produce the report at all. And
`if not args.interactive and not args.query and not args.ui: args.ui = True` (`:1368-1370`) — a bare
`uv run main.py` opens Tkinter, which is how the flagship GUI ends up as the default product surface.

`enumerate-binary` (`main.py:684-1210`) is the CLI's one bulk workflow — a REPL command, not a flag — and a
good honest sample: it prints "Expect ~3-8 seconds per function (includes context gathering)" (`:695`)
and requires a typed yes (`:697-700`); then **one sequential loop, one worker, no pool, no decompile
cache, no skip-analyzed, no stop** — per function: decompile, gather caller/callee context, one
`bridge.ollama.generate` with the same four-section prompt as the GUI (`:878-915`), rename **only**
generic names — the `FUN_/sub_/loc_/unk_/j_` prefix test at `main.py:1002` — via `rename_function_by_address`
(`:1016-1023`, address-based, so it works on both backends). Its fixed behavior is the GUI's *Full
Enumeration* equivalent — descriptive names are "analyzed but NOT renamed" (`:693`) — and unlike the
GUI it *does* load results into the local vector store, in batches of 50 (`BATCH_SIZE`, `:1118-1140`),
doing the work the GUI commented out. Then it all evaporates: the results live in
`current_session_log` and the vector store; no attempt-shaped record, and the REPL has no session
commands. Ctrl-C is the only Stop.

The README's claims, checked. `--interactive` then `health` (`README.md:170-176`) — **true**. "If you
launched GUI mode, use `curl http://localhost:8080/methods`" (`README.md:179-181`) — that port is the
GhidraMCP *plugin* inside Ghidra (`base_url` default `http://localhost:8080`, `src/config.py:1367`);
the GUI serves nothing, and the sentence invites readers to debug the wrong process. The Smart Tool
Buttons table (`README.md:238-249`) lists six of the nine buttons and presents the panel as a visible
feature — it is unpacked, §1. `# In CLI: set task_mode <mode>`, `task_mode general`
(`README.md:251-261`) — **false**, extending ch. 32 §8: zero `task_mode` strings in `main.py`
(verified), and `general` is not a mode anywhere — the combo offers `purpose_id/malware/vuln/custom`
(`src/gui/query_input_panel.py:53,62,78`, sticky via `bridge.get_task_mode_state`). The Task-Mode
checkbox + combo and the "Enable Hybrid Search" toggle (`:100-114`, wired to
`bridge.set_grep_layer_enabled`, `:226-262`, ch. 33 §7) exist **only** in the GUI, and the status
label learns the truth by post-hoc wiring into the analyzed-functions panel (`src/gui/ui.py:151-157`).
The Smart-Enumeration trio (`README.md:275-285`) is GUI-dialog-only; the CLI has no mode choice.
`max_workers=2` (`README.md:507`) — false, §4. The one thing not to miss: `main.py:1389-1390` reads
`args.pyghidra_projects_dir` through a defensive `getattr`, but that flag is never registered — a
config override that silently does nothing, invisible precisely *because* of the defensive style. And
the GUI-crash history — ch. 21's `19-gui-crashes-on-linux` branch and PR #44 (`93a4380`, 9 files,
+716/−503) — is verified by what it delivered: `ui_thread.py`, the daemon pool, the skip-analyzed
option, and the ETA line all trace to that one squash.

## Comparison with calxgloss

### Touchpoints and the bulk *run*: verdicts before mutation, versus renames before review

calxgloss's reviewer steers "at the level of runs, queues, and verdicts, never per address" (ch. 10
:24-25): accept / send-back / patch / skip / unskip and the batch actions operate on a *unit of work*
**before** it becomes recorded truth, reviewer intent lands in *overlay* files (ADR-0003), and every
view is read-only over artifacts (ADR-0006). OGhidra's touchpoint is the mirror image: human and LLM
edit the *live Ghidra program* through the same object, and the rename lands at
`src/gui/tool_buttons_panel.py:916` before a human sees a row. There is no *verdict* object for a
rename anywhere — the closest is a bookkeeping removal that does not undo. So the bulk run has a fine
throughput skeleton (daemon pool, `as_completed` accounting, OK/ERR/SKIP/ETA lines, cache stats,
skip-analyzed resume, auto-save checkpoint) and no accountability skeleton at all: no gate between
suggestion and rename, no order or priority (Ghidra's listing order, top to bottom), no reviewer in
the loop, one failure policy for the whole run. Reversibility follows: calxgloss has git, every *unit
of work* a commit on its *attempt* branch (ch. 10, principle 6); OGhidra has nothing of its own, its
own dialog admitting "The operation cannot be easily undone" (`:2099`) with a yes/no *before* the run
(`:2105`) as the only consent gate — recovery is Ghidra's own undo, a safety net in a host OGhidra
never talks to. The skip-analyzed dedup is the seam-cache / *coverage* idea from ch. 33 §4 keyed on
displayable rows instead of *coverage* records: resume over prose, not stamped ground truth.

### Cost control: a per-thread metronome versus tier escalation with an operator cap

calxgloss caps the *attempt* budget (operator-set cap, stop routing on the *verdict*, token/fault
analytics computed on demand, ADR-0005). OGhidra's bulk cost is one LLM call per surviving function,
up to three attempts each: a 2,000-function binary under Smart Enumeration is comfortably thousands of
calls before the first row appears, with no budget check anywhere in the path, and the only dial,
`request_delay`, is a per-client sleep that five workers dilute back into 5-way concurrency (§4). The
report multiplies the same problem vertically: seven prompts, each carrying a full paginated binary
listing, on one button. What OGhidra does better is price *transparency* — the measured ETA lines and
the CLI's "~3-8 seconds per function" pre-flight estimate are a habit calxgloss's queue UI could copy.

### Effort honesty, *coverage* honesty, and the report artifact

OGhidra's progress artifacts (%, counts, ETA, cache hit rate, avg time/function) are real arithmetic
over real wall-clock — more than calxgloss exposes, because calxgloss deliberately refuses
progress-as-truth and reports *coverage* instead: which *scans* ran, their coverage records,
*admission lines*, "unknown, never absent" (ADR-0052/0053). OGhidra has no coverage concept, and its
effort honesty leaks exactly where effort is passed off as result: the RAG-vector count over
commented-out calls with a 10 ms-per-item fake-progress sleep, the Stop flag nobody reads, and the
report's invented investigation timeline. Effort meters answer "how busy am I"; *coverage* answers
"what is known". The same split explains the report: ADR-0005 computes analytics from records on
demand and stores no prose, while OGhidra spends seven LLM calls turning a data collection into JSON
prose that a deterministic template then escapes everywhere except where it pastes the LLM's HTML raw.
Yet the *form* is what calxgloss lacks — `calxgloss-reports` prints, JSON output is still P52. A
generated *function-inventory* report with OGhidra's section grammar and severity badges
(`report_template.py`), every number computed from the record tree, coverage stamps inline, every row
linking to its *unit of work*, would put OGhidra's form to calxgloss's evidence. OGhidra's hardcoded
workflows are the other half of the P32 *skill/manual* angle: frozen recipes — fixed tool calls, fixed
prompt, deterministic collection, no agent — which is what a contributor manual's runnable commands
look like.

### Surfaces: Tkinter as the process, versus Axum+React with honest degradation

Both run foreground; neither has a daemon. calxgloss's review surface is a web server and SPA over
artifacts, degrading honestly when the live half is absent (ch. 10). OGhidra's is a desktop Tk window
whose flagship surface is constructed and never packed, whose history includes a three-year
Linux-crash threading bug fixed by bolting a marshalling queue onto a toolkit that forbids worker
threads by design (ch. 21, PR #44), whose quick actions duplicate through post-hoc attribute wiring
(`src/gui/ui.py:170-176`), and whose README documents UI that isn't rendered and knobs that don't
exist. The `@ui_safe` queue + `_rows_model` snapshot + poller design in `renamed_functions_panel.py`
is good engineering deployed against the grain of the toolkit; the web stack gets that property from a
protocol designed for it.

### Overlap / calxgloss-only / OGhidra-only

- **Overlap (same problem, different answer):** progress reporting (ETA lines vs `/api/progress*`);
  batch checkpointing (auto-saved `BulkRename_*` session in CWD-relative `analysis_sessions/`
  (`src/enhanced_session_manager.py:73,85`) vs attempt-branch commits + the attempt ledger);
  resume-dedup (skip-analyzed vs seam cache / *coverage*); config-edit GUI (`ServerConfigDialog`
  writing `.env` and calling `reload_llm_client`, `src/gui/ui.py:1052-1075` vs layered
  `calxgloss.toml` + `doctor`); canned workflows (hardcoded smart buttons vs P32 skills/manual
  recipes).
- **calxgloss-only:** the *verdict* surface (accept/send-back/patch/skip, batch actions, ADR-0006
  read-only views); *overlay* intent files; attempt-branch git reversibility; the verification gate
  between model output and record; *coverage* records with *admission lines*; cost caps and fault
  analytics; evidence-computed confidence (P51); ADR-0005's report discipline.
- **OGhidra-only:** an enumeration-mode dial (Rename Only / Smart / Full) with a real filter
  vocabulary (`:656-736`, `:757-778`); the `DaemonThreadPoolExecutor` + `as_completed` +
  OK/ERR/SKIP/ETA loop shape; the decompile cache with hit-rate reporting; the *analysis dump*
  pre-truncation record; a polished single-file HTML template (sections, severity badges, CSS);
  "Test Connections" live probes; bulk enumeration as a first-class product mode with auto-save
  afterward.

### Verdict

A layer that hides more than it shows: the nine-button flagship panel never renders, the agentic path
for smart tools is dead code (`_run_ai_agent_query`), the query panel's Stop flag is written three
times and read zero, the RAG-vector count tallies commented-out work, the "configurable" worker count
is the literal 5, and a security report's "ACTUAL investigation steps" are invented by the LLM because
the real record — the *analysis dump* in `logs/`, the one genuinely honest artifact here — reaches it
only as the previous model's prose, its tool calls, addresses and params discarded. Meanwhile the
throughput plumbing is real, and the honest numbers (ETA, cache stats, "~3-8s per function") show the
authors knew exactly which meters were honest and shipped both kinds. The gap with calxgloss is not
taste: OGhidra's human surface has no *verdict* — the rename lands in the live program before the
reviewer exists, and the undo lives in a program neither project controls.

**Steal, in priority order.** (1) The *rename-suggestion listing* as a review surface:
`renamed_functions_panel`'s row model + queue/poller is the right skeleton for a calxgloss
suggestions-from-write-back queue *where the verdict comes before the mutation*, displayed confidence
evidence-computed (P51) rather than `ai_confidence`; take the row shape (address / old / new / summary
+ JSON export) and fix the order of operations. (2) The bulk-loop posture — `as_completed` accounting
with `[OK]/[ERR]/[SKIP]/[ETA]`, per-item failure isolation, auto-save checkpoint after every batch —
onto the calxgloss *run* status and the P52 JSON analytics surface. (3) The *function-inventory
report* as a `calxgloss-reports` section: OGhidra's template grammar, every number computed from the
record tree, every row linking to its *unit of work*, nothing stored that the records cannot recompute
(ADR-0005). (4) The enumeration-mode dial and its filter vocabulary (thunks, import stubs, CRT
patterns, generic-name prefixes, keyword gating) as tunable scan-queue filters, and the
hardcoded-workflow pattern itself as P32 skill commands. (5) Cheaply: "Test Connections" probes as a
`doctor`-adjacent web affordance, and the *analysis dump* habit — a pre-truncation execution record
beside the attempt ledger, recording what the model was actually shown. **Do not copy:** Tkinter and
its thread-marshalling scars; coupling an automated flow to the GUI cursor (`get_current_function`);
an LLM-fabricated investigation timeline or any LLM-written executive summary shipped as a findings
artifact; counted no-ops (`_create_batch_rag_vectors`) and decorative Stop flags; knobs hard-coded in
the source that the documentation advertises as tunable; renames applied to the live program ahead of
any human *verdict*; and seven unbounded LLM calls on one button.

## Sources

- Clone `/tmp/opencode/OGhidra` @ `6224d26` (branch `main`, clean). Read in full; LOC via `wc -l`:
  `src/gui/tool_buttons_panel.py` 2,579 · `src/report_template.py` 1,490 · `main.py` 1,426 ·
  `src/gui/ui.py` 1,228 · `src/gui/renamed_functions_panel.py` 1,173 ·
  `src/gui/server_config_dialog.py` 544 · `src/gui/memory_info_panel.py` 391 ·
  `src/gui/query_input_panel.py` 350 · `src/analysis_dump.py` 292 · `src/gui/ai_response_panel.py`
  184 · `src/gui/workflow_diagram.py` 133 · `src/gui/session_load_dialog.py` 107 (imported nowhere —
  dead) · `src/gui/ui_thread.py` 74 · `src/gui/daemon_thread_pool_executor.py` 38.
  Targeted `src/bridge.py` spans: `src/bridge.py:2993-2995, 3284, 3675-3683` (analysis-dump writes),
  `src/bridge.py:5371-5413` (`_get_latest_agent_analysis_text`), `src/bridge.py:5415-5460` (report
  entry), `src/bridge.py:5462-5587` (collection), `src/bridge.py:5589-5665` (six-call analysis +
  context formatter), `src/bridge.py:5667-5902` (prompt builders), `src/bridge.py:6255-6700` (the
  four duplicate formatters), `src/bridge.py:6877-7128` (dispatch, markdown and HTML builders),
  `src/bridge.py:7136-7165` (address evidence, LLM call), `src/bridge.py:7166-7380` (parse,
  fallback). Targeted `src/config.py`: `src/config.py:1022-1140` (`html_report_generation_prompt`,
  schema `src/config.py:1066-1077`, `investigation_steps`/`string_artifacts`
  `src/config.py:1100-1105`, rule 6 `src/config.py:1135`), `src/config.py:1165, 1215, 1319`
  (request delays), `src/config.py:1367` (`base_url` `http://localhost:8080`). Also
  `src/ollama_client.py:185-188, 306-309`, `src/custom_api_client.py:75, 417-419, 639-641`,
  `src/enhanced_session_manager.py:73-90`.
- Census greps (clone): `max_workers` (5 hits, all GUI-internal; zero in `src/config.py`);
  `handle_command` (zero, repo-wide); `--report` as a CLI flag (zero); `task_mode` in `main.py`
  (zero); `_run_ai_agent_query` (def + log string only); `pyghidra_projects_dir` in `main.py` (one
  `getattr`, zero registrations); `should_stop` in
  `src/gui/query_input_panel.py` (written ×3 at `:24, 300, 308`, read ×0); `request_delay` (only in
  `src/config.py`, `src/ollama_client.py`, `src/custom_api_client.py`); "Enumerate All Functions"
  (one tip string, `src/gui/tool_buttons_panel.py:1755`); `batch_size` in `src/gui/tool_buttons_panel.py` (2 hits, both
  non-functional); rename undo/revert in `src/gui/` (zero — the two "Revert checkbox" comments in
  `src/gui/memory_info_panel.py:197, 267` are unrelated).
- Repo anchors: [ch. 10](10-calxgloss-baseline.md) (review surface:
  accept/send-back/patch/skip/batch, ADR-0002/0003/0006; analytics: ADR-0005, P52,
  `calxgloss-reports`; principles 1-6: steering level, git reversibility); [ch.
  20](20-oghidra-inventory.md) §2.8, §9; [ch. 21](21-history-and-releases.md) (PR #44 `93a4380`,
  `19-gui-crashes-on-linux`, `fix/session-loading-ui-freeze`); [ch.
  31](31-ghidra-bridge-and-backends.md) §1/§5/§7 (plugin server on 8080, `get_current_function`
  headless degradation); [ch. 32](32-agentic-core-and-context.md) §8 (task modes, README drift), §10
  (result cache), and its "Work records" note that a bad *attempt* has no undo; [ch.
  33](33-knowledge-rag-and-sessions.md) §4-5 (skip logic, metadata extractor), §9 (session JSON,
  `ui_state`, streaming load), §11 (Load Vectors, coverage tracker) and its CAG-naming census.

