# 33 — Knowledge, RAG & sessions: an in-memory vector store, session files of harvested prose, and a checklist that marks itself

> Part of the [OGhidra overview](README.md). The knowledge layer end to end: what *CAG
> (Cache-Augmented Generation)* is, the two `SimpleVectorStore` classes and the reload
> path that never fires, the cache-side *skip logic*, the *function metadata extractor*
> and the dead *RAG document builder* + *function graph*, the `search_function_summaries`
> tool, the 14-technique *malware pattern library* with its MITRE-tagged *pattern alerts*,
> the three parallel session stores, the memory subsystems, and the *coverage*/*lead
> trackers* — then the comparison against calxgloss's *record tree*, *coverage ledger*
> with *admission lines*, and evidence-computed confidence ([ch.
> 10](10-calxgloss-baseline.md); ADR-0052/0053, P51). All `:line` cites are to the clone
> at `6224d26` (`main`); LOC via `wc -l`; quoted prompt text is verbatim. File tables live
> in [ch. 20](20-oghidra-inventory.md) §2.5/2.6/2.9; the tool-memo cache is ch. 31, the
> `ResultCache`/context engine ch. 32 §10.

## What OGhidra does

### 1. What *CAG* actually is, and what the *CAG manager* does per cycle

The package docstring names it: **Cache-Augmented Generation** — "a knowledge management
system that replaces traditional RAG … instead of performing real-time vector search on
each query, CAG uses a persistent knowledge cache built at startup"
(`cag/__init__.py:1-6`; same wording `manager.py:20-33`). Three expansions ship in the
product: the Memory panel frame says "Context-Augmented Generation (CAG)"
(`gui/ui.py:920`), the help text and toggle dialog say "Cache-Augmented"
(`gui/ui.py:1175`, `gui/memory_info_panel.py:192`), and the health report prints
"Context-Aware Generation" (`memory_health.py:240`).

The *CAG manager* (`cag/manager.py`, 1,067 LOC) is built whenever CAG is on —
`CAGManager(config, session=self.session)` plus a `_bridge_ref` backlink
(`bridge.py:186-193`). Per LLM call the bridge asks it to `enhance_prompt`
(`manager.py:84-146`):

- **Pattern alerts get absolute priority.** If `_last_pattern_check_result` exists (§8)
    its text is *prepended*, token-boxed, then `delattr`'d — a one-shot injection living
    for exactly one prompt build (`:95-107`).
- **Knowledge retrieval is phase-budgeted:** planning 0.4 / execution 0.3 / analysis 0.5
    of `cag_token_limit` (default 2000, `config.py:1475`), `:112-119`; Hybrid Search in
    the GUI switches retrieval to `search_hybrid` (§7) (`:121-133`).
- **Session context re-injected pruned:** last 10 messages; prior analysis results with
    Jaccard word overlap > 0.4 against the query; decompiled functions *named in the
    query* recovered from tool executions; the rename map (`:832-891`), rendered as "##
    Prior Context / Previously Decompiled Functions / Entity Renames Performed / Previous
    Analyses", decompilations head-tail-trimmed to 30 lines (`:893-943`).
- **Command *skip logic*** (§4) — the "Cache-Augmented" half.

The manager's vector store is lazy and gated: construction probes Ollama over TCP
(`:53-64`), the `vector_store` property initializing only if the probe passed (`:69-78`).
At init it embeds exactly the hardcoded markdown: four *workplan* files +
`knowledge_base.md` under the getattr-default `knowledge_base/` dir (`:480-512`; no
`knowledge_base` config field — grep `config.py`). A restart is a full re-embed (ch. 20
§2.9).

### 2. Two vector stores, one shared dir, and a reload that can never fire

Two **unrelated classes both named `SimpleVectorStore`** (ch. 20 flags the pair; here,
storage mechanics):

| | `src/cag/vector_store.py` (393) | `src/vector_store.py` (204) |
|---|---|---|
| Serves | function summaries + workplan docs (RAG path) | session embeddings (MemoryManager path) |
| Storage | process-live `list`s of docs + `np.ndarray` embeddings — **no persistence at all** | numpy 2-D matrix + metadata list, saved per add to `data/vector_db/vectors.npy` + `metadata.json` (`:33-36,101-143`) |
| Search | brute-force cosine loop, dimension mismatches warn-and-skip (`:84-109`); optional **FAISS** via try-import (`:10-16`), declared nowhere (ch. 20 §2.9) so normally the numpy path | cosine dot over the matrix (`:144-180`) |
| Used by | CAGManager, GUI Load Vectors, hybrid search | `MemoryManager` only (`memory_manager.py:49`) |

The FAISS path is `IndexFlatIP` after `normalize_L2` — plain cosine
(`cag/vector_store.py:335-344`). The class docstring's storage story is fiction ("numpy
memmap … a JSON file", `:24-31`): there is no memmap and no save method in the file. The
cross-module bug: `CAGManager._load_existing_vector_db` reads `data/vector_db/vectors.npy`
+ **`documents.json`** (`manager.py:450-478`), but the only writer into that dir emits
**`metadata.json`** (`src/vector_store.py:36`) and grep finds no other `documents.json`
mention in `src/` — **nothing writes the file the loader needs**, so "load existing
knowledge on boot" has never, silently, worked. Each boot's CAG store is workplan markdown
+ whatever the user pushed through Load Vectors.

### 3. Embeddings: the model, and who embeds what

One funnel: `Bridge.get_embeddings(texts, model=None)` (`bridge.py:591-631`), default
**`nomic-embed-text`** (`:614`; README `:158` says `ollama pull` it), per-provider in
config — Ollama `nomic-embed-text` (`config.py:37-38`), Google `gemini-embedding-1.0`
(`:1159-1160`), external `""` (`:1211`). Ollama dual-falls back `/api/embed` →
`/api/embeddings` for old servers (`bridge.py:528-559`); `OllamaClient.embed` chunks at
8192 tokens (`ollama_client.py:21`). The embedded text, on the live paths:

- **Function summaries as the panel displays them** — the harvested prose of §5, not code,
    not metadata. Load Vectors snapshots panel rows, skips empty summaries, batches 50
    (`gui/renamed_functions_panel.py:172-300`).
- **Workplan/knowledge-base markdown** at CAG init (§1).
- **Session records** at end_session (task + tool calls + outcome + summary,
    `session_utils.py:37-72`); when Ollama is down `embed_session` falls back to a
    **seeded random 384-D vector** (`np.random.seed(hash % 10000); np.random.random(384)`,
    `:101-109`) — content-free vectors persisted with no placeholder flag,
    indistinguishable to consumers.

### 4. The cache side: *skip logic*, `RESULT_CACHE_ENABLED`, and what a re-ask does

Does re-asking about a function skip the LLM? **No — it skips the Ghidra round-trip; the
LLM still runs every cycle.** The manager's *skip logic* is textual dedup, not semantic
recall:

- `should_skip_command` builds a signature `name(sorted(params))` and scans the **last 10
    session messages** for an identical `EXECUTE:` line; one hit → skip
    (`manager.py:593-634`). Leniency: `get_current_function` skips after 3 similar calls
    in the window (`:636-638`); any `decompile_function` of something in
    `analysis_state.functions_decompiled` skips (`:640-645`).
- `get_cached_command_result` recovers the payload by searching `session.tool_executions`
    for that tool + function (`:652-680`); the bridge calls both before dispatch
    (`bridge.py:1782-1790`, `:2565`) and re-injects the cached text as the tool result.

Same posture as ch. 31's tool-memo / `get_cached_result` anti-pattern: dedup by exact
command identity over the session transcript. `RESULT_CACHE_ENABLED` (default `true`,
`config.py:119,1191`) gates a different mechanism entirely:
`ContextManager(enable_caching=…)` (`bridge.py:163`) — the *ResultCache* /
`get_cached_result(result_id)` machinery of ch. 32 §10. It does not gate RAG, which hangs
on `CAG_ENABLED` + the Ollama probe + the GUI "Enable RAG" toggle; the README's "flip
`RESULT_CACHE_ENABLED` to disable vector embeddings" (`README.md:431-433`, `:508`) is
wrong about its own config surface.

### 5. The *function metadata extractor*: regex metrics over pseudo-C

**Live**, but narrower than advertised. During bulk enumeration the GUI calls
`FunctionMetadataExtractor().extract_all_metadata` on each function's decompiled text
(`gui/tool_buttons_panel.py:957-970`) and stores the result in
`bridge.function_address_mapping[address]` (`:1000-1021`). Everything is regex/keyword
over decompiler output — deterministic, no LLM (`function_metadata_extractor.py:86-208`):

- **Metrics** (`:118-162`): `code_lines` (excluding comments/braces), `size_bytes`,
    `cyclomatic_complexity` as a regex count of `if/else if/while/for/case/&&/||/?:` over
    the **text**, `complexity_tier` at 5/15, `estimated_instructions = code_lines * 2` (a
    made-up factor, `:161`). No API-call counter.
- **Operations** (`:163-206`): keyword sets tagging
    crypto/network/file_io/memory/string/validation/registry/process, plus authentication
    from the *function name*; `primary_domain` and `security_relevant` derived
    (`:439-468`).
- **Signature** (`:209-256`), **patterns** (`:257-299`), **security indicators**
    (`:300-353`), **data flow** (`:354-390`), **dependencies** (`:391-431`) — dependencies
    read a caller/callee `context` dict passed in by the caller; the extractor never asks
    Ghidra itself.

The metadata joins retrieval **nowhere on the live path**: Load Vectors embeds the
harvested summary text (§3), not metadata; metadata reaches prompts only through the dead
builder of §6. Live effect: richer panel rows and tooltips. Those summaries come from
`_capture_function_summary` — harvested from the AI's *own recent reasoning output* after
decompile/analyze/rename (`bridge.py:4744,4772,4834` → `_extract_function_summary`,
`bridge.py:4667-4717`): longest "descriptive" line under 150 chars, else the literal
`"Analysis performed"`. The knowledge substrate is unstructured AI prose, harvested,
embedded verbatim (ch. 31's posture for tool results).

### 6. The *RAG document builder* and *function graph*: the dead knowledge-graph layer

`rag_document_builder.py` (619) is the most polished artifact in the layer and the most
thoroughly unreachable. `build_primary_document` (`:32-101`) assembles a hierarchical
markdown doc (quick reference, Key Operations, dependencies, technical details, security,
patterns — `:196-391`) plus semantic tags (`:570-599`). `build_multi_vector_documents`
(`:106-141`) is the README's "multi-vector support": always purpose + implementation +
dependencies vectors, conditionally security (criticality high/critical) and data-flow
(complexity > 5) — up to five per function (`:392-568`).

Its **only consumer is `Bridge._add_function_to_rag`** (`bridge.py:4532-4613`), and all
four call sites are commented out with "RAG integration removed – use 'Load Vectors'
button": `bridge.py:4518`, `gui/renamed_functions_panel.py:938-941`,
`gui/tool_buttons_panel.py:512,1079-1080`. Same for the *function graph*:
`FunctionGraph()` is constructed at boot with a cheerful "[OK] Knowledge Graph
initialized" (`bridge.py:215-221`), but its single `add_function` call sits inside dead
`_add_function_to_rag` (`bridge.py:4548`) — the graph is empty for the entire life of
every process. The graph itself (`function_graph.py`, 406) is a reasonable design: call
edges from `metadata.dependencies` with stub nodes for unknown callees (`:78-128`), BFS
neighborhoods (`:134-182`), domain clusters (`:188-205`), degree centrality (`:207-241`),
a dedicated `expand_context_for_rag` (`:257-291`), DFS execution paths to depth 5
(`:293-332`), and entry/leaf heuristics (`:334-380`) — the same roots/leaves primitive
calxgloss's *callgraph reader* computes, pointed at retrieval instead of scheduling. The
hybrid-search path wires the expansion (graph neighbors added to results at
centrality-scaled 0.3–0.6, `bridge.py:1550-1596`) behind a `len(graph) > 0` guard that is
never true.

Claim check (README `:290-291`: "Intent-based context assembly", "Multi-vector support for
precise retrieval"): the **code** exists (intent-shaped vector selection,
`rag_document_builder.py:143-189`), the **runtime** does not. The `use_multi_vector_rag`
flag read at `bridge.py:4570` via `getattr(config, "use_multi_vector_rag", False)` is
**not a config field anywhere** (grep `config.py`, `.env.example`, `README.md`: zero hits)
— even re-enabling the call sites would silently pick the single-vector path (verified).

### 7. The retrieval entry point: `search_function_summaries`

The AI's only query path into the knowledge layer is a bridge-pseudo-tool (never reaches
Ghidra), registered only with "Enable Hybrid Search" on (`bridge.py:1702-1718`,
`search_type ∈ {hybrid, keyword, semantic, name}`). `_search_function_summaries`
(`:1378-1428`) does **not** search the vector store's corpus: it rebuilds candidate docs
from the live renamed-functions rows / `function_address_mapping` each call.

- `keyword`: token-frequency scoring in a throwaway `SimpleVectorStore._keyword_search`
    (`:1423-1448`; cag-store scoring `cag/vector_store.py:164-204`) — **works with zero
    embeddings**.
- `semantic`: embed the query, cosine against the CAG store — needs Load Vectors to have
    run (`:1497-1506`).
- `hybrid`: keyword + semantic merged at weights 0.4/0.6 (`:1456-1534`), then the dead
    graph expansion of §6.

Keyword-over-harvested-prose is therefore the default posture; the semantic path is the
same tool, only better. The store's own `search_hybrid` (`cag/vector_store.py:206-261`)
doubles as the manager's knowledge-section selector under Hybrid Search
(`manager.py:121-133`), and `get_relevant_knowledge` budgets retrieval at `token_limit *
4` chars (`cag/vector_store.py:291-333`).

### 8. The *malware pattern library*: 14 weighted-regex detectors, ATT&CK-tagged

The library (`cag/malware_patterns.py`, 934) is fully static — regex over Ghidra pseudo-C
and disassembly; no LLM in detection. Registry `PATTERNS` (`:532-547`) as coded — 14
techniques, not the README's vague "12+" (`:24`):

| id | name | sev | category | MITRE (as coded) | thr |
|---|---|---|---|---|---:|
| `peb_walking` | PEB Walking (Manual DLL Resolution) | HIGH | evasion | T1055.001 | 5.0 |
| `dynamic_api_resolution` | Dynamic API Resolution | HIGH | evasion | T1027 | 4.0 |
| `process_injection_remote` | Remote Process Injection | HIGH | injection | T1055 | 6.0 |
| `process_injection_local` | Local Process Injection / Code Unpacking | MEDIUM | injection | T1055 | 4.0 |
| `anti_debug` | Anti-Debugging Checks | HIGH | evasion | T1622 | 4.0 |
| `anti_vm` | Anti-VM Checks | MEDIUM | evasion | T1497 | 3.5 |
| `string_obfuscation` | String Obfuscation / Decryption | MEDIUM | obfuscation | T1027 | 3.0 |
| `api_hashing` | API Hashing | HIGH | evasion | T1027 | 3.5 |
| `privilege_escalation` | Privilege Escalation | HIGH | elevation | T1548 | 4.0 |
| `registry_persistence` | Registry Persistence | MEDIUM | persistence | T1547.001 | 4.0 |
| `file_system_hooks` | File System Hooks / Rootkit Behavior | MEDIUM | persistence | T1014 | 3.5 |
| `network_c2` | Network C2 Communication | HIGH | c2 | T1071 | 4.0 |
| `encoded_file_path` | Stack-Based Encoded String Construction | MEDIUM | obfuscation | T1027.009 | 4.0 |
| `hidden_path_string` | Hidden File Path String (Format String Obfuscation) | HIGH | obfuscation | T1027.009 | 3.5 |

Detection = weighted indicator scoring (`_check_pattern`, `:555-605`): each regex hit adds
its weight (code indicators over pseudo-C + asm indicators over disassembly, ~0.5–4.0,
offset-specific entries like `MOV.*GS:\[0x60\]` for x64 PEB access, `:139-144`); match
needs total ≥ threshold, and `confidence = min(1.0, total / (2 × threshold))` — the
threshold *is* the 50%-confidence point (`:598-603`). Each hit contributes the actual
50-char matched text to `indicators_found`, prefixed `Code:`/`ASM:` (`:570-596`). Two
detectors add `context_apis` boosts (exec*/CreateProcess/fopen…): confidence ×1.15
(`:748-765`) or ×1.2 (`:823-838`), appending `Context: Near <api>() API`;
`encoded_file_path` also reports `detection_method ∈ {hybrid, assembly, decompiled_only}`
and warns "Assembly analysis recommended" when decompile-only (`:767-784`).
`analyze_all_patterns` runs all 14, sorted HIGH→LOW then confidence (`:876-898`). Wiring
is narrow: detection fires **only in malware *task mode*** with CAG on, and only after
`decompile_function`, `decompile_function_by_address` (which also fetches disassembly for
the asm pass, `bridge.py:3338-3356`), `disassemble_function`, or `list_strings`
(`:3321-3331`). Alerts reach the model two ways: **(1) one-shot** — the alert is parked on
`cag_manager._last_pattern_check_result` (`:3359-3362`) and prepended to the very next
prompt (§1), printing severity, confidence %, *intent*, the `MITRE ATT&CK: T1055 - Process
Injection` string, an `Evidence:` line with matched snippets, and "RECOMMENDATION:
Investigate this function immediately!" (`manager.py:1019-1058`); **(2) persistent, HIGH
only** — `session.analysis_state.pattern_detections[address]` (`bridge.py:3364-3368`)
re-injects as "## Malware Patterns Detected (HIGH Severity)" into every later prompt
rebuild (`manager.py:934-941`); grep shows the map is only ever written, clearing when a
new binary replaces the session.

False-positive posture: the *alert* carries no hedge — escalation language by
construction; the hedges ("Common in both malware and legitimate software … Context
matters", `:720-725`) live in docstrings the model never sees. Mapping nit (*inferred*):
`peb_walking` is tagged T1055.001 (DLL injection) while its own `intent` says import
hiding — T1106/T1027 territory; with T1622/T1014 on-target, the slip is confined to one
tag.

### 9. Sessions: three parallel stores, one live JSON workbench

Three session systems coexist sharing no code.

**(a) The live bridge session** — `SessionModel`/`AnalysisState` with
`functions_analyzed`, `pattern_detections`, the tool-result cache — ch. 31/32;
process-only.

**(b) The JSON workbench** — `EnhancedSessionManager` (669) behind File → Save/Load
Session. A session is `analysis_sessions/{id}/session.json`, plain JSON (`json.dump`,
`enhanced_session_manager.py:495-501` — **not** pickle, a common assumption). Id =
`session_{unixtime}_{sha256(name)[:8]}` (`:105-106`); it stamps `binary_hash = sha256(file
bytes)` (`:112-119`) — the same identity anchor calxgloss keys caches and *bdiff* pairings
on. Contents (`:136-147`): `metadata` (name, id, binary path + hash, dates, function
counts, description, tags); `analyzed_functions` — address → {old_name, new_name,
*behavior_summary*, function_hash, `ai_confidence`, processing_time} (`:24-35`), §5's
harvested prose plus a self-reported `ai_confidence` scalar with no formula (verified; the
GUI fills it from rename-suggestion fields); `rag_vectors` — **the store's documents, not
embeddings**: save pulls `cag_manager.vector_store.documents` (`gui/ui.py:492`) and the
dialog claims "Saved … {N} RAG vectors", while restore replies "{N} RAG vectors available
(use 'Load Vectors' button)" (`ui.py:851`) — text persists, vectors re-derived on demand;
then `ui_state`, `analysis_log`, `performance_stats`. Auto-save after bulk enumeration
(`:156-172`); a genuine nicety — streaming load for >10 MB files (optional `ijson`,
chunked fallback, `:520-628`); export/import wraps the structure in `"export_version":
"1.0"` with **no migration logic** (`:390-468`).

**(c) The JSONL session history** — `SessionHistoryStore` appends pydantic `SessionRecord`
lines to `data/ollama_ghidra_session_history.jsonl` (`session_store.py:20-27`; path
`config.py:1427`) — written only by the inert stack of §10.

Two more storage modules are **orphans** (verified: no construction site in `src/`):
`cag/session_cache.py`'s `SessionCache` (`:60-88`) — whose shape the manager's
prune/format code reimplements internally — and `cag/knowledge_cache.py`'s
`GhidraKnowledgeCache` (`:52-74`), the actual "knowledge cache" the
`CAG_KNOWLEDGE_CACHE_ENABLED` flag (`config.py:1474`) claims to enable (read only by the
health report, `memory_health.py:65,244`). Even the *data* path is inert:
`init_dirs.py:26-34` would copy `cag/knowledge/function_signatures.json` +
`common_workflows.json` into `ghidra_knowledge_cache/`, but
`ensure_cag_directories` has no caller in `src/` — its only invocation sits in
init_dirs' own `__main__` block (`:50`), so the copy happens only if the
module is run as a script. The single reader of `ghidra_knowledge_cache/` is
`ghidra_mcp_client.py:34-46` (API descriptions for the older hand-written
client), which itself has no importers (§ ch. 31, PR #62 pending) and whose
fresh-checkout `FileNotFoundError` is swallowed by its `except` returning an
empty dict (`:47-49`). The shipped copies under `src/cag/knowledge/` are read
by nothing at runtime.

### 10. The memory subsystem: one live structure, one chrome-grade stack

**Live:** `SessionMemory` (`models/memory.py:353-485`), created at bridge init
(`bridge.py:136-139`), reset per new task (`:2211-2219`): current query + *analysis phase*
enum, last 10 tool calls, ≤20 analysis summaries, discovered patterns, and a
function-memory LRU (≤100) keyed `(function_name, binary_hash, function_hash)` carrying
prior AI decisions "across sessions" — meaning *across tasks inside one GUI process*;
nothing serializes to disk (verified: `to_dict` has no writer). `CAGContext` exposes it to
prompts (`bridge.py:159-177`): the planning prompt gains phase, last 5 tool calls, prior
decisions for the same function, and "You have ALREADY seen these patterns … do not repeat
tool calls that led to these patterns" (`:633-667`); malware runs mine it for a pattern
block (`:824+`).

**Chrome:** the `MemoryManager` stack (`memory_manager.py` +
`session_store`/`active_session`/`session_utils`/`memory_models`) is constructed —
CAGManager builds it (`manager.py:44-50`), the bridge aliases it (`bridge.py:191-192`) —
but its output is boilerplate: `end_session` always builds
`SessionSummarizer(llm_client=None)`, so every summary is the canned "Successfully
completed the task using N tool calls…" template, with a literal `time.sleep(0.1) # Small
delay to simulate real processing` (`session_utils.py:180-201`), and embeddings fall back
to §3's seeded-random vectors. `get_similar_sessions` — the cross-session recall this
stack exists to provide — has **zero production callers** (grep: definition + tests only;
verified). `memory_health.py` (334) is a status dashboard (config echo, outcome
distribution, tool counts, vector norms, a 5×5 cosine sample matrix, `:149-165`) whose
"healthy/issues_detected" verdict (`:184-197`) cannot flag the placeholders it sits on;
the GUI "Memory & System Info" panel is CAG/RAG toggles plus auto-refreshing stats
(`gui/memory_info_panel.py:13-59,270-283`).

### 11. The *coverage tracker* and *lead tracker*: a checklist that marks itself

The *coverage tracker* (`coverage_tracker.py`, 225) is not coverage of the binary — it is
a fixed 8-area Windows-security checklist (service_management, process_creation,
privilege_escalation, file_operations, registry_persistence, dll_loading, network_comms,
crypto_operations) with API + string lists per area (`:34-82`), born from a named
post-mortem: "the WiseBootAssistant investigation, where the AI never searched for
service-related APIs or strings because nothing reminded it" (`:8-10`). Auto-marking scans
the concatenated `tool_name + tool_params + result` text, case-insensitive substring; ≥1
hit → area *covered*, summary "N matches found" (`:123-165`). The concatenation **includes
the tool's own parameters** (`:139`): asking for `CreateServiceW` and getting an empty
result still counts a hit — the echo of the search term marks the area covered, and the
prompt reads "✅ service_management: 1 matches found". `covered` means "something mentioned
this area", not "looked", let alone "found".

Auto-marking runs unconditionally after every tool call (`bridge.py:3382-3387`), but the
checklist reaches the prompt only in task mode, ❌-areas-first with "Search for: APIs=[…]"
hints (`:3510-3512`; `coverage_tracker.py:183-216`). The *lead tracker* (122) keeps a
priority queue whose entries are **harvested from the AI's own prose**: a regex over each
cycle's analysis dump for `- [HIGH] 0xADDR: text` bullets (`lead_tracker.py:69-94`),
injected as "## 🔍 Active Investigation Leads (Prioritized) — You MUST address all HIGH
priority leads before starting new searches" (`:107-122`; `bridge.py:3514-3522`). Both
trackers reset per goal cycle (`bridge.py:2028-2034`). Defect: the MEDIUM/LOW lead icon is
the literal `"bf"` — a mangled emoji escape (`lead_tracker.py:117`).

### 12. What the README promises vs what runs

| README claim | line | runtime truth (verified) |
|---|---|---|
| "Smart Enumeration — Build queryable knowledge graphs" | `:26`, `:544` (arch diagram) | `FunctionGraph` + `RAGDocumentBuilder` fully dead (§6); nothing queryable, nothing a graph |
| "Structured metadata extraction (LOC, complexity, operations)" | `:289` | live (§5) but feeds panel rows, not retrieval |
| "Intent-based context assembly" / "Multi-vector support" | `:290-291` | dead code + a config flag that does not exist (§6) |
| "Sessions include … RAG vectors for semantic search" | `:305-308` | half-true: documents persist, vectors re-derived (§9b) |
| RAG enabled by `RESULT_CACHE_ENABLED` / `TIERED_CONTEXT_ENABLED` | `:431-433`, `:508` | wrong knobs — context-engine flags (ch. 32 §10); RAG gates are `CAG_ENABLED` + Ollama + GUI toggle |
| "Malware Detection — 12+ evasion and injection techniques" | `:24` | true, understated: 14 as coded (§8) |
| CAG block: "Vector Store / Knowledge Cache / Session Store / Pattern Alerts" | `:542-547` | vector store + pattern alerts live; knowledge cache class orphaned; MemoryManager session store inert |

## Comparison with calxgloss

### Evidence quality: records vs prose, with one honest exception

calxgloss knowledge is *records*: 15 scan rows + 3 readers write typed, provenance-stamped
documents into the *record tree*; claims resolve by strongest evidence; coverage is
stamped at scan time and absent coverage reads as **unknown, never absent** (ch. 10
§Evidence engines/§Data model, ADR-0052/0053). OGhidra's artifacts come in three kinds
with wildly different honesty. **Regex metadata** (§5): deterministic, but keyword-hit
labels ("crypto" because a word matched), no evidence pointers, no persistence outside
panel rows. **Harvested AI prose** (§5): 150-char extracts of the model's own reasoning,
fallback literal `"Analysis performed"`, embedded verbatim — the knowledge base of record
is confabulation-adjacent text with zero provenance links. **Pattern alerts** (§8): the
one artifact with real provenance — each indicator is the actual matched 50-char snippet,
confidence computed (if crude); structurally a calxgloss *scan* with evidence attached.

**Where OGhidra is genuinely valuable and calxgloss has nothing comparable**: semantic
recall. `search_function_summaries` semantic/hybrid over embedded function descriptions,
persisted across restarts through session files (§7, §9b), answers "which function feels
like a credential dumper" — calxgloss's record tree answers "what was proven" and has no
cross-run similarity query at all. The direction calxgloss would take: embed *its own*
descriptions and record claims — already evidence-grounded — so the semantic layer
inherits provenance instead of manufacturing it, with P51's *evidence-computed confidence*
attached; OGhidra's `ai_confidence` scalar (§9b) shows what confidence without computation
becomes: decoration.

### Persistence discipline: right anchor, wrong payload, three stores

calxgloss keys everything by *identity*: scan caches under
`re/cache/{identity}/{sha256}/`, *bdiff* pairings keyed by old/new SHA-256, the *attempt*
ledger crash-replays from committed records (ch. 10 §Data model). OGhidra's session files
use the **same anchor** — SHA-256 of the binary (`enhanced_session_manager.py:112-119`) —
then get three things wrong. **Payload:** analyzed functions carry harvested prose and a
decorative `ai_confidence`; "rag_vectors" are documents pretending to be vectors (§9b);
nothing is replayable — no record of which commands produced which summary, so a restored
session is UI state, not evidence state. **Multiplicity:** three session stores that never
interoperate plus two orphaned cache modules (§9) — the store-sprawl a single record tree
avoids by construction. **Cross-module keying:** the CAG loader wants `documents.json`,
the writer produces `metadata.json`, same directory (§2) — the exact failure class
write/read-same-identity-key layouts make impossible. No version migration despite
`export_version: "1.0"`. Credit: JSON-not-pickle keeps restore safe against hostile files,
and the >10 MB streaming loader (`:520-628`) is better engineering than the rest of the
layer.

### Pattern recognition: two static-detector philosophies

calxgloss's algorithm-recognition scan matches constant/S-box signatures with a
correlation detector, claims resolved by strongest evidence (ADR-0022–0025). The malware
library (§8) is the same species — static, deterministic, no LLM — with three borrowable
output habits: weighted multi-indicator scoring with the threshold as the confidence
midpoint (`malware_patterns.py:598-603`), context-API boosts logged as their own indicator
(`:748-765`), and a stable public vocabulary (severity × category × ATT&CK id × intent ×
evidence snippet) that turns detection output into prompt-grade evidence. calxgloss has no
ATT&CK-style output vocabulary anywhere (its findings stay internal, ADR-0044 posture). FP
posture differs sharply: OGhidra's alert language is pure escalation (§8); calxgloss's
strongest-evidence/counterexample discipline (P49) is the antidote the library lacks.

### Coverage honesty, measured

calxgloss's ledger answers the uncomfortable question on purpose: every scan stamps
coverage, gaps get *admission lines*, admitted unknowns are named records, "empty findings
under complete coverage and under an admission line must never render alike" (ch. 10 §Data
model, quoting ADR-0053). OGhidra's only coverage concept is the 8-area checklist (§11),
and it fails ADR-0053's first test *mechanically*: because the marker concatenates the
tool's own parameters into the scored text (`coverage_tracker.py:139`), an
attempted-but-empty search renders as "✅ … 1 matches found" — searched-looking state
indistinguishable from found state, precisely the "must never render alike" violation. It
also has no unknown bucket: the ratio is areas/8, nothing ties areas to the function set,
and the only function-level number in the whole system is the `functions_analyzed` set
(ch. 31). Yet the tracker's *intent* — WiseBootAssistant's failure was "never thought to
look" (`coverage_tracker.py:8-10`), not "looked and reported badly" — targets a real
weakness calxgloss's pipeline must also survive; reporting honesty and attention nudging
are orthogonal, and only OGhidra builds the nudge.

### Call graph: scheduling vs Q&A

calxgloss's callgraph reader exists to *drive the pipeline*: roots/leaves/translation
order feed callee-first merge and next-target selection (ch. 10,
`re/analysis/{binary}_call_graph.json`). `function_graph.py` computes the same primitives
— degree centrality, entry/leaf heuristics (`:334-380`), bounded DFS paths — aimed at
retrieval expansion and "architectural understanding" prompt context: which functions to
*talk about* next, not which to *translate* next (§6). The design mirrors calxgloss's; the
wiring undercuts it — calxgloss's reader always has an edge list because warmup always
builds one, while OGhidra's graph is empty by construction every run.

### Overlap / calxgloss-only / OGhidra-only

- **Overlap (same problem, different answer):** the binary-SHA-256 identity anchor
    (session files vs caches + bdiff pairing); tool-memo / result cache vs `re/cache` (ch.
    31/32); static signature detection (algorithm scan vs malware library); "don't redo
    this call" logic (skip-logic vs the seam cache); prompt-injected planning state
    (coverage/lead sections vs the *strategy ladder* queue).
- **calxgloss-only:** record tree + per-engine persistors; coverage ledger / admission
    lines / named unknowns; evidence-computed confidence (P51); identity-keyed crash
    replay; *attempt*/*verdict* discipline and the verification pipeline; per-function
    analysis artifacts; bdiff version pairing; overlay files for reviewer intent.
- **OGhidra-only:** an embedding store over function descriptions + a semantic/hybrid Q&A
    tool the model itself calls; the ATT&CK-tagged malware pattern library with evidence
    snippets and prompt-delivered *pattern alerts*; the coverage-checklist + lead-queue
    attention nudge injected every cycle; JSON session save/restore with binary-hash
    anchor and streaming load; the regex *function metadata extractor*; the multi-vector /
    graph-expanded retrieval design (dead, but a design).

### Verdict

The knowledge layer is two systems stitched together: a live half that is
honest-but-narrow (regex metadata, regex malware patterns with code-provenance) and a
flagship half that is broad-but-dead or broad-but-prose (knowledge graphs unreachable,
summaries harvested from the LLM, the memory stack on canned templates, a cross-restart
vector reload that has never once worked). Its coverage artifact inverts ADR-0053: it
manufactures "covered" from the echo of the AI's own search terms. The soul of calxgloss —
records with provenance, confidence with arithmetic, unknowns with names — is what this
layer lacks; and its soul — semantic recall, ATT&CK-tagged detection vocabulary, attention
nudges, session restore UX — is what calxgloss lacks.

**Steal, in priority order:** (1) the *pattern-alert evidence format* — severity ×
confidence × public-vocabulary tag × intent × verbatim matched snippet — as the render
shape for injecting scan rows (algorithm, library-api, string-context) into translate
prompts, paired with a real ATT&CK-style tag vocabulary for the malware-adjacent rows. (2)
*Semantic function memory*: embed descriptions and record claims from the record tree
(already evidence-grounded, P51 confidence attached), keyed by binary hash + function hash
the way the `(name, binary_hash, function_hash)` LRU already does (`models/memory.py`,
§10) — cross-run "which function is like X" without ever embedding unverified prose. (3)
The *coverage/lead nudge*, fixed to ADR-0053 rules: mark areas only from the result
payload (never the parameters), render "searched, found nothing" as a state distinct from
"searched, found" and "not searched", and feed it from the coverage ledger so areas map to
function sets. (4) Session-restore UX with a binary-SHA-256 gate — restore refuses when
the hash moved — a nice rule for opening any record tree against a re-fetched binary. Also
trivially: the >10 MB streaming JSON loader idiom. **Do not copy:** LLM prose as the
knowledge base of record (§5); embedding retrieval with no provenance link to records;
"confidence" scalars with no computation (`ai_confidence`); seeded-random placeholder
embeddings (§3); three parallel session stores (one JSONL + one JSON workbench over the
record tree is enough); storing documents and calling them vectors; and a "covered" state
a tool call can mark by mentioning its own argument (§11).

## Sources

- Clone `/tmp/opencode/OGhidra` @ `6224d26` (branch `main`, clean). Read in full, LOC via
    `wc -l`: `cag/manager.py` 1,067 · `cag/malware_patterns.py` 934 ·
    `enhanced_session_manager.py` 669 · `rag_document_builder.py` 619 · `models/memory.py`
    556 · `function_metadata_extractor.py` 555 · `cag/session_cache.py` 551 ·
    `cag/knowledge_cache.py` 410 · `function_graph.py` 406 · `cag/vector_store.py` 393 ·
    `memory_health.py` 334 · `memory_manager.py` 264 · `coverage_tracker.py` 225 ·
    `session_utils.py` 211 · `vector_store.py` 204 · `lead_tracker.py` 122 ·
    `active_session.py` 135 · `memory_models.py` 83 · `session_store.py` 52 ·
    `cag/init_dirs.py` 51. Targeted `bridge.py` (7,845) spans: :100-221, :1782-1790,
    :2025-2040, :3300-3390, :3508-3525, :4496-4613, :4667-4790, :1378-1596, :1698-1725,
    :7490-7576; plus spot-reads of `gui/ui.py`, `gui/memory_info_panel.py`,
    `gui/renamed_functions_panel.py`, `gui/tool_buttons_panel.py`, `config.py`,
    `context_manager.py`, `ghidra_mcp_client.py` as cited.
- Census greps (clone): `documents.json` (one read, no writes); `_add_function_to_rag`
    (def + 6 commented sites); `use_multi_vector_rag` (one `getattr`, zero config
    definitions); `pattern_detections` (one writer, zero clearers); `SessionCache(`,
    `GhidraKnowledgeCache(` (zero constructors); `get_similar_sessions` (def + tests
    only); CAG-naming census (`Context-Augmented` ×1, `Cache-Augmented` ×4,
    `Context-Aware` ×1).
- Repo anchors: [ch. 10](10-calxgloss-baseline.md) §Evidence engines, §Data model &
    persistence (record tree, `re/cache/{identity}/{sha256}/`, *admission line*, "unknown,
    never absent"), §Known gaps (P51); [ch. 20](20-oghidra-inventory.md) §2.5/2.6/2.9
    (file tables, FAISS undeclared); [ch. 31](31-ghidra-bridge-and-backends.md) (tool-memo
    cache, `functions_analyzed`); [ch. 32](32-agentic-core-and-context.md) §10
    (ResultCache, tiered context, `get_cached_result`) and §11 (dead context-assembly
    seam); ADR-0052/0053, ADR-0022–0025, ADR-0044; P49/P51.
