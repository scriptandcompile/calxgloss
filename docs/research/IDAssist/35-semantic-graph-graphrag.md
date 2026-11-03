# 35 — The semantic knowledge graph: GraphRAG pipeline, analyses, query engine, UI

> Part of the [overview](README.md). Clone HEAD 09dd910d…, written 2026-11-02.

Scope: the Semantic Graph tab subsystem — `src/controllers/semantic_graph_controller.py` (1019 LOC),
`src/services/graphrag/*` (5,919 LOC across 14 modules; 5,221 excluding the MCP-facing `graphrag_tools.py` (698); *corrected 2026-11-02 — earlier draft said ≈4000*), `src/views/semantic_graph_tab_view.py` (1409 LOC),
`src/views/semantic_graph/manual_analysis_panel.py` (229 LOC), plus the docs
`docs/tabs/semantic-graph-tab.md` and `docs/workflows/semantic-graph-workflow.md`. Storage facts
(graph tables in analysis.db, FTS5, security risk scoring) were verified in earlier chapters and are
reused here. The 9 LLM-facing tools in `graphrag_tools.py` are covered in ch34; this chapter only
notes where they share the query engine.

Headline: the subsystem's name promises GraphRAG with embeddings; what actually ships is a
**structural SQLite graph** (call graph from IDA xrefs) plus **one LLM summary per function**, with
"semantic search" implemented as SQLite FTS5 keyword search, "similar functions" implemented as
call-graph topology, and "community detection" implemented as plain **label propagation** — no
Leiden, no vectors, despite enums and docs claiming both.

---

## 1. What the docs promise

`docs/tabs/semantic-graph-tab.md` documents: four sub-views (List, Visual Graph, Search, Manual
Analysis) (semantic-graph-tab.md:32-143); bottom controls Reset / ReIndex / Semantic Analysis with
RAG / MCP / Force checkboxes (:21-28); "seven search types" (:103-116); visual graph as an
interactive `QGraphicsView` with **Graphviz `dot` layout when available, BFS fallback** (:72-98);
and a 6-phase pipeline "Structure extraction → Semantic analysis → Security feature extraction →
Network flow analysis → Taint analysis → Community detection" (:145-154). It also claims an IDB
hook `renamed()` keeps node labels in sync (:162). The workflow doc repeats the pipeline as manual
steps (semantic-graph-workflow.md:22-73) and repeats the Graphviz claim (:133).

Every one of these is verified against code below; three are drift (Graphviz, `renamed()`, Leiden
in code comments).

## 2. Pipeline orchestration — controller and workers

`SemanticGraphController` (semantic_graph_controller.py:33) wires the view's signals
(`_connect_signals` :51) to five `QThread` workers, each with a `cancel()` that flips a flag on the
underlying service — every long operation is stoppable, and re-clicking the running button cancels
it (e.g. `handle_reindex` :149-155 toggles "ReIndex Binary" ↔ cancel):

| Worker | LOC line | What it runs |
|---|---|---|
| `ReindexWorker` | :897 | `StructureExtractor.extract_all_parallel` (:923-937) |
| `SemanticAnalysisWorker` | :794 | `asyncio.run` → `SemanticExtractor.summarize_stale_nodes` (:822-856) |
| `SecurityAnalysisWorker` | :862 | `TaintAnalyzer.find_taint_paths(max_paths=100, create_edges=True)` + `create_vulnerable_via_edges()` (:881-894) |
| `NetworkFlowAnalysisWorker` | :987 | `NetworkFlowAnalyzer.analyze` (:1007-1016) |
| `CommunityDetectionWorker` | :946 | `CommunityDetector.detect_communities(min_size=2, force)` (:968-981); worker docstring says "using Label Propagation" (:947) |

Progress is Qt-signal based: each worker emits `progress/completed/cancelled/failed`; the
controller relays to the tab status label, a bottom progress bar, and the manual panel
(`_update_panel_status/_update_panel_progress` :747-765).

**The actual chain is not the documented one.** ReIndex completion auto-triggers
Security → Network → Community: `_on_reindex_complete` calls `_start_security_chain` (:704-710),
`_on_security_complete(chain=True)` starts network flow (:616-626, :780-791), network completion
starts community detection (:646-657), and community completion closes the chain (:678-688).
**Semantic Analysis is not in the chain** — it is a separate button (:177-215), so the documented
phase order (:145-154) is roughly right in effect, but "Security feature extraction" is *not* a
pipeline stage: per-function static security scoring happens inline inside structure extraction and
semantic analysis (§5), and the pipeline's "Security Analysis" step is actually **taint analysis**
(SecurityAnalysisWorker instantiates `TaintAnalyzer`, semantic_graph_controller.py:883; the manual
panel tooltip confirms: "Find taint paths from sources to sinks, create TAINT_FLOWS_TO and
VULNERABLE_VIA edges", manual_analysis_panel.py:96).

Threading discipline: all IDA API access is marshalled onto IDA's main thread via
`execute_on_main_thread` (e.g. structure_extractor.py:81, 154, 238, 289;
function_signature_generator.py:55), while SQLite writes happen on the worker thread behind
`GraphStore._db_lock` (graph_store.py:185).

## 3. ReIndex Binary — whole-function structural extraction, two phases

`ReindexWorker.run` is explicitly non-destructive: "do NOT delete_graph() … The upsert logic will
update changed fields while preserving semantic data" (:919-922). It runs
`extract_all_parallel` = Phase 1 `extract_structure` + Phase 2 `enrich_all`
(structure_extractor.py:474-490):

- **Phase 1** (:217-339): enumerates the *entire binary* via `idautils.Functions()` (:236) — no
  sampling, no caps, no chunking at this level (chunked push is the SymGraph transport, ch21, not
  here). Per function it gathers name and call targets on the main thread — callees = dedup
  `idautils.CodeRefsFrom(item, 0)` over `idautils.FuncItems`, resolved to containing functions
  (:269-285) — then queues nodes + `CALLS` edges in batches flushed every 500 functions
  (`queue_node_for_batch`/`queue_edge_for_batch`, flush at :304-333, graph_store.py:613-680). It
  first dedupes leftovers (:248-251) and preloads the node-id cache (:253).
- **Phase 2** `enrich_all` (:341-425): for every stale node, decompiles with
  `ida_hexrays.decompile` (:499-508), collects disassembly line-by-line (:510-533), generates a
  byte signature (:396), runs static security features (:399-412), then sets `is_stale = False`
  (:413). No LLM is involved in either phase — matching workflow doc :31.
- There is also a single-function path, `extract_function` (:66-118), used by
  `GraphRAGService.index_function` (graphrag_service.py:46-48) — the upsert the Explain tab triggers
  per ch32/verified context — which additionally creates **caller-side** `CALLS` edges from
  `idautils.CodeRefsTo` and `CALLS_VULNERABLE` edges when a callee carries any `*_RISK` flag
  (:192-213, :179-190). The batch Phase-1 path only creates callee-side edges, and the caller-side
  backfill appears only in the one-function path.
- `GraphStore.upsert_node` is what makes reindex non-destructive: `llm_summary` and `embedding`
  survive via `COALESCE(excluded.x, graph_nodes.x)`, `user_edited` is *never* reset, and
  `is_stale = excluded.is_stale` is written through (graph_store.py:197-226, 254-255).

`GraphRAGService` itself is a thin facade — 53 lines, self-described as "a minimal skeleton"
(graphrag_service.py:14-53): store accessor plus `index_function` and
`summarize_stale_nodes` delegating to the extractors. All real logic is in the extractors and the
controller.

## 4. Semantic Analysis — per-function LLM loop

`SemanticExtractor.summarize_stale_nodes` (semantic_extractor.py:53-97):

- **Selection**: without Force, `GraphStore.get_stale_nodes` — SQL
  `WHERE binary_id = ? AND (is_stale = 1 OR llm_summary IS NULL OR llm_summary = '')`
  (graph_store.py:872-896). With Force, all `FUNCTION` nodes (semantic_extractor.py:64-68).
  `limit` defaults to 0, which the store turns into `LIMIT 1000000` (:875). So the doc line
  "summaries for all unsummarized functions" (tab md:25) is accurate: a summarized node that
  isn't stale is skipped even without Force.
- **Loop shape**: strictly sequential `for` loop, one `await self._summarize_node(node)` per
  function (:80-93). The "batch" concept is pacing only: `DEFAULT_BATCH_SIZE = 3`,
  `DEFAULT_DELAY_MS = 500` — sleep 500 ms every 3 calls (:28-29, :92-93). No prompt batching, no
  concurrency, no cost cap.
- **Per node** (:99-139): skip if `user_edited` (:103) or no FUNCTION; lazily (re-)fetch
  pseudocode/disassembly via `BinaryContextService` (:105-116); run static security refresh
  (:118, :180-206); build the prompt; one non-streaming `chat_completion` (:214-227); then store
  `llm_summary = response.strip()`, `category = extract_category(response)`, **fixed
  `confidence = 0.85`**, `is_stale = False`, `user_edited = False` (:131-138).
- **Prompt**: when a `FunctionSummaryService` is present (the worker always builds one,
  semantic_graph_controller.py:832-847), it uses `generate_full_query(address,
  view_level=PSEUDO_C, rag_enabled, mcp_enabled)` (semantic_extractor.py:149-161) — i.e. the
  unified Explain prompt from ch32, honoring the tab's RAG/MCP checkboxes
  (semantic_graph_controller.py:197-199; view checkboxes manual_analysis_panel.py:71-81). Fallback
  is the legacy `function_summary_prompt` with name, pseudocode-or-disasm, top-5 callers/callees
  (:166-178).
- **Header parsing**: `extract_category(response)` → `_extract_section(response, "Category:")`
  looks for a `**Category:` markdown header, falls back to plain `Category:`, and ends the section
  at the next `\n**` header or a blank line followed by another header (extraction_prompts.py:241-
  243, 246-287). The legacy prompt requests exactly `"**Category:** [REQUIRED - One of:
  initialization, data_processing, io_operations, …]"` (extraction_prompts.py:133).
- **Cost, concretely**: a 10k-function binary means **10,000 separate LLM calls** — one per stale/
  unsummarized function — with ≥500 ms sleep per 3 functions (≈28 minutes of pure sleep) plus LLM
  latency; nothing samples or caps the function set (limit defaults to 0). Re-running without Force
  skips already-summarized nodes (the stale query above), and user-edited nodes are never
  overwritten (:103). Cancel flips `self.cancelled`, checked per iteration (:81).
- **Explain-tab interaction (the payoff):** the Explain tab reads a fresh node summary as its cache
  — `if node and node.llm_summary and not node.is_stale: "Using cached GraphRAG function
  analysis"` and returns without any LLM call (explain_controller.py:229-237; same check in the
  auto-load path :1509-1515). So a completed Semantic Analysis run pre-warms the Explain tab.

## 5. `is_stale` and `user_edited` in practice

Grepping `is_stale` across `src/` (verified negative: the only setters are below — there is no
rename-driven staleness, see §9):

- **Set to 1**: structure extraction — `extract_function` after refreshing code/features
  (structure_extractor.py:113), Phase-1 nodes and callee stubs (:302, :314); and Explain's
  "delete cached analysis" action, which nulls the summary and marks stale
  (explain_controller.py:466-472).
- **Set to 0**: after successful structural enrichment (structure_extractor.py:413), after an LLM
  summary lands (semantic_extractor.py:136), after the user saves an edited summary
  (semantic_graph_controller.py:298-312, `user_edited=True, confidence=0.95, is_stale=False`;
  explain save path explain_controller.py:559-561; Explain's own LLM completion also sets
  `is_stale=False, confidence=0.85` :944-946).
- **Double duty**: `is_stale` means both "needs Phase-2 decompilation" (`enrich_all` iterates
  `get_stale_nodes`, structure_extractor.py:353) and "needs an LLM summary" (§4) — the same flag
  drives both, saved only by the stale query also matching `llm_summary IS NULL`.
- **`user_edited`**: set on any manual summary save; `upsert_node` refuses to reset it
  (`user_edited = graph_nodes.user_edited`, graph_store.py:226); semantic analysis skips such nodes
  (:103) but, for nodes it *does* summarize, rewrites `user_edited=False` (:137). SymGraph export
  reads it as provenance: `confidence = 0.95 if node.user_edited else 0.85`
  (symgraph_controller.py:1952, 1965).

## 6. Structure model — node/edge kinds actually produced

`models.py` defines a 4-level type hierarchy — `FUNCTION/EXTERNAL/THUNK` (level 0),
`MODULE/COMMUNITY` (level 1), `BINARY` (level 2) (models.py:8-59) — and 16 edge types in four
groups (structural/semantic/security/community, models.py:70-192; *count corrected 2026-11-02 — earlier draft said 17*). What the IDA pipeline *actually
creates* is a subset:

- **Nodes**: `FUNCTION` only. `grep -n "EXTERNAL|THUNK" src/services/graphrag/*.py` shows the
  strings appear only in the enum and in `<EXTERNAL>::` prefix-stripping helpers imported from the
  SymGraph round-trip (network_flow_analyzer.py:285-286, taint_analyzer.py:331) — no EXTERNAL/
  THUNK/MODULE/COMMUNITY/BINARY nodes are ever inserted by this pipeline (ch21's EXTERNAL nodes
  come from the chunked symbol/graph push path, not from ReIndex).
- **Edges and weights** (all from code): `calls` weight 1.0 (structure_extractor.py:170-176,
  318-320); `calls_vulnerable` weight 1.0 + `CALLS_VULNERABLE_FUNCTION` flag on the caller
  (:179-190); `taint_flows_to` weight 1.0 (taint_analyzer.py:143-153); `vulnerable_via` weight 1.0
  (taint_analyzer.py:155-162, 251-263); `network_send` weight 1.0 entry-point→sender and 0.5
  direct-caller→sender (network_flow_analyzer.py:402-434). Community membership is **not** edges —
  it is `community_members` rows with score 1.0 (community_detector.py:282-285). The
  `similar_purpose`/`references`/`contains`… semantic/structural enums are never written by this
  subsystem (grep `SIMILAR_PURPOSE|REFERENCES|CONTAINS` in `src/services/graphrag/` → models.py
  plus two tool-description strings in `graphrag_tools.py:118,121` — which explicitly forbid
  writing structural types — and unrelated `CONTAINS_HARDCODED_IPS/_URLS/_DOMAINS` flags in
  `security_features.py:293-297`; `grep -rn "EdgeType.CONTAINS|EdgeType.SIMILAR_PURPOSE|EdgeType.REFERENCES" src/`
  outside models.py → zero hits, so no writer anywhere; *grep claim corrected 2026-11-02 —
  earlier draft said "only models.py and the view's edge-type filter lists"; the view is outside
  the grepped path*). `models.py:100` even carries a tombstone: "DATA_DEPENDS
  removed - too noisy". The workflow claim that ReIndex identifies "Data flow edges"
  (workflow:28) has no code behind it.

**Signatures** are not LLM output: `IDAFunctionSignatureGenerator` builds a static
**masked byte-prefix** — up to `MAX_SIGNATURE_BYTES = 64` instruction bytes with `?` wildcards over
branch/call displacement bytes and operand bytes matching markers like `offset`, `sub_`, `0x`,
`cs:` (function_signature_generator.py:17-106). Invoked during `extract_function` (:97) and every
`enrich_all` pass (structure_extractor.py:396). It exists for cross-tool binary matching (SymGraph),
not for search.

## 7. Semantic search: what it really is

- **The `embedding BLOB` is dead weight in the graph.** `grep -rn "\.embedding"
  src/services/graphrag/` returns only the two plumbing sites: `upsert_node`'s column binding and
  its `COALESCE(excluded.embedding, …)` clause (graph_store.py:223, 239, 704, 761) and the
  dataclass default. Nothing in the graph subsystem ever computes or assigns an embedding. *(In
  the pipeline as shipped, `graph_nodes.embedding` is always NULL.)*
- Provider embedding support exists but serves the RAG-document pipeline only: capability flag
  `supports_embeddings` (llm_models.py:139; True for OpenAI platform, Ollama, and Anthropic
  `supports_embeddings=True,  # Via TF-IDF fallback` — openai_platform_api_provider.py:552,
  ollama_provider.py:495, anthropic_platform_api_provider.py:655), consumed by
  `llm_service.py:203` and used by `rag_service.py`, which keeps a TF-IDF vocabulary/corpus on disk
  for non-API providers (rag_service.py:73-75, 203-235). *(Inference: TF-IDF bag-of-words vectors
  with cosine-style similarity in RAG search; graph nodes never touch any of it.)*
- **GraphRAG "Semantic Search" = FTS5.** `GraphStore.search_nodes` runs
  `node_fts MATCH ?` joined to `graph_nodes`, with a `LIKE` fallback over
  `name/signature/llm_summary` on syntax errors (graph_store.py:843-861);
  `GraphRAGQueryEngine.search_semantic` wraps it and returns `score: None` — no ranking at all
  (query_engine.py:54-64).
- **"Similar Functions" = call-graph topology, then keyword FTS** (query_engine.py:66-113):
  siblings sharing callers (score 0.7, "SHARED_CALLERS"), then siblings sharing callees
  (0.6, "SHARED_CALLEES"), then top-5 non-stopword keywords extracted from the source's own
  summary joined with ` OR ` into an FTS query (0.5, "FTS_MATCH", keywords :347-364).
- `get_semantic_analysis` is a node dump with code truncated to 2000 chars and hardcoded
  `confidence: 0.8` when a summary exists (query_engine.py:14-52); `_extract_category` is a
  keyword-substring ladder over the summary ("crypto"/"network"/… → `utility` default)
  (:328-344) — the fallback for the header-parsed category.

## 8. The analysis services

**Static features (per function, no LLM).** `SecurityFeatureExtractor`
(security_feature_extractor.py:29) harvests call targets (IDA xrefs :359-387, or a regex
`\b([A-Za-z_@][A-Za-z0-9_@!:.]*)\s*\(` = `CALL_PATTERN`, defined :31 and applied over pseudocode
:389-402; *regex corrected 2026-11-02 — earlier draft wrote it as `\bname\s*\(`*) and string operands (:404-443), classifies them against
class-level catalogs, and regex-classifies strings into IPs/URLs/paths/domains/registry keys
(:476-529). Catalogs are huge literal sets, e.g. `NETWORK_APIS` includes `"socket"`, `"WSARecv"`,
`"SSL_write"`, `"WinHttpSendRequest"`, `"getaddrinfo"`, `"curl_easy_perform"` (:37-94);
`FILE_IO_APIS` spans POSIX `open/read/mmap` to Win32 `CreateFileW/MoveFileEx` (:96-161);
`CRYPTO_APIS` covers CryptoAPI/BCrypt/OpenSSL (`"CryptEncrypt"`, `"AES_encrypt"`, `"SHA256_Final"`)
(:162-181); `PROCESS_APIS` (:182-197) includes `"CreateRemoteThread"`, `"WriteProcessMemory"`; and
`DANGEROUS_FUNCTIONS` is a `name → risk flag` dict: `"strcpy": "BUFFER_OVERFLOW_RISK"`, `"printf":
"FORMAT_STRING_RISK"`, `"system": "COMMAND_INJECTION_RISK"`, `"gets": "BUFFER_OVERFLOW_RISK"`
(:198-274). The result object `SecurityFeatures` (security_features.py:8) is the scoring layer
already verified in the earlier context — `calculate_activity_profile` (:125),
`calculate_risk_level` (:207, score ≥6 HIGH / ≥3 MEDIUM), and `generate_security_flags` (:251-316)
emitting e.g. `USES_CRYPTO`, `ENCRYPTS_DATA`, `CALLS_DANGEROUS_FUNCTIONS`,
`CONTAINS_HARDCODED_IPS`, `ENCRYPTED_NETWORK_COMMS`, `HIGH_RISK`. So the split is *not*
per-function vs binary-level: **both files are per-function** — extractor = catalog matching,
features = flag/risk derivation; the only binary-level view is
`GraphRAGQueryEngine.get_binary_security_analysis`, which just unions per-node flags
(query_engine.py:176-192). Static scoring runs inline during ReIndex (structure_extractor.py:98-108,
399-412) and before each LLM summary (semantic_extractor.py:180-206) — never as its own pipeline
worker.

**Network flow** (network_flow_analyzer.py): builds a `CALLS`-only adjacency cache (:176-183);
finds send/recv functions by intersecting each node's stored `network_apis` (or normalized name)
with `NETWORK_SEND_APIS` (`"send"`, `"WSASend"`, `"SSL_write"`, `"WinHttpSendRequest"`,
`"HttpSendRequest"`, `"curl_easy_send"`) and `NETWORK_RECV_APIS` (`"recv"`, `"read"`, `"SSL_read"`,
`"WinHttpReadData"`, `"InternetReadFile"`, `"curl_easy_recv"`) (:54-95, :196-266); entry points are
nodes flagged `ENTRY_POINT`/`EXPORTED` or named in `ENTRY_POINT_NAMES` (`"main"`, `"DllMain"`,
`"_start"`, …) (:87-95, 306-330). Edge creation is a **reachability product, not dataflow**: for
each entry point × sender pair, a BFS bounded by `MAX_PATH_LENGTH = 10` (:51, 331-360) and, if a
call path exists, a `network_send` edge weight 1.0 with metadata
`{"path_length":N,"send_api":…,"entry_point":…}`; plus direct-caller edges at weight 0.5
(:361-438); recv is mirrored (:440+). No arguments, no aliasing — *(inference: this over-approximates
data flow; any caller on some path to a send API is marked).* Cost is O(entries × senders × BFS),
which is the quadratic step in the chain.

**Taint** (taint_analyzer.py): sources/sinks come from catalogs (`TAINT_SOURCES`: `"recv"`,
`"ReadFile"`, `"getenv"`, `"mmap"`, `"gets"`… :29-38; `TAINT_SINKS`: `"strcpy"`, `"system"`,
`"CreateProcess"`, `"mysql_query"`, `"memcpy"`… :40-53) plus flag tiers
(`SOURCE_FLAGS` = `NETWORK_CAPABLE`, `READS_FILES`…; `SINK_FLAGS` = `*_RISK`,
`CALLS_VULNERABLE_FUNCTION` :55-71), matched in four tiers: flags → network_apis → file_io_apis →
name → callee names (:164-233). Search is **DFS over `CALLS` edges**, max path length 10, capped at
`max_paths` (default 100 from the controller, semantic_graph_controller.py:867-884); each found
path emits consecutive `taint_flows_to` edges (:115-153) and a source→sink `vulnerable_via` edge
(:155-162). A second pass, `create_vulnerable_via_edges` (:234-264), BFS-connects every entry point
to every node with a `*_RISK`/`VULN_*` flag, metadata `{"path_length":…,"vuln_type":"…"}` — this is
where the c54ab1b-era VULNERABLE_VIA improvement lives (ch34 context).

**Community detection is label propagation, full stop.** Module docstring: "Label Propagation
algorithm for function clustering" (community_detector.py:4); class docstring details the algorithm
(:46-53): init unique labels (:161-163), iterate "each node adopts the most frequent label among
neighbors" up to 100 iterations with ties keeping the current label (:165-203), merge communities
smaller than `min_size` (=2 from the controller, semantic_graph_controller.py:275) into their most-
connected neighbor (:205-243). Input graph: FUNCTION nodes joined by undirected
`CALLS` + `CALLS_VULNERABLE` edges (:141-159). Output: flat `level: 0` rows in
`graph_communities` (:272-279) — **no hierarchy, `parent_community_id` is never populated by this
path**, despite the schema (ch-context) and the `MODULE/COMMUNITY` node levels. Names/summaries are
keyword heuristics over member *function names* — `PURPOSE_PATTERNS` like
`'crypto': ['crypt','aes','sha','md5','rsa',…]` → "Cryptography Module #N" (:19-41, 294-376). No
LLM. **Drift:** `models.py:14, 29-35` claims "Leiden-detected" / "Leiden algorithm" and
`graphrag_tools` descriptions echo modules; `grep -rn "leiden|louvain" src/ --include=*.py` finds
nothing — Leiden exists only in comments.

## 9. UI layer

`semantic_graph_tab_view.py` is one module with four widget classes plus the tab shell
(`SemanticGraphTabView` :41 wires Manual/Current/Status controls :66-167).

- **List View** (`SemanticGraphListView` :268): callers/callees lists, an edges table with a
  type-filter combo (:320-325, :426-439), `KNOWN_FLAGS` — exactly the 13 documented flags, from
  `"BUFFER_OVERFLOW_RISK"` to `"AUTHENTICATION"` (:277-291; *corrected 2026-11-02 — earlier draft said :276-290*) as toggle checkboxes (:441-492), a
  custom-flag prompt (:480), and an Edit/Save summary toggle (:464-478). Double-click navigates
  (:494-498).
- **Visual Graph** (`SemanticGraphGraphView` :500): plain **`QGraphicsView`/`QGraphicsScene` with
  hand-drawn items** — rounded-rect `QGraphicsPathItem` nodes with label+address text and a
  `[VULN]` tag (:733-766), curved bezier `QGraphicsPathItem` edges with polygon arrowheads
  (:710-732, 921-939), selection-driven summary panel (:971-1013). N-Hops spinner 1–5, default 2
  (:566-569); zoom controls (:1061-1085). **There is no Graphviz anywhere**: `grep -rn
  "graphviz|dot -T|subprocess" src/views/semantic_graph_tab_view.py` → no matches; layout is a
  custom layered BFS — direct callers pinned at level −1, callees leveled 1..N from the center,
  each level centered horizontally (:859-919). The doc claims at tab md:98 and workflow:133 ("Graphviz
  improves layout") are **false for this HEAD** — a documented-binary claim not in code. The
  neighborhood itself is controller-side: `_collect_graph` BFS over any edge type set, **hard-capped
  at 50 nodes** (semantic_graph_controller.py:502-555).
- **Search View** (`SemanticGraphSearchView` :1087): exactly 7 radio query types —
  `ga_search_semantic`, `ga_get_semantic_analysis`, `ga_get_similar_functions`,
  `ga_get_call_context`, `ga_get_security_analysis`, `ga_get_module_summary`,
  `ga_get_activity_analysis` (:1091-1099) — dispatched in
  `SemanticGraphController._execute_query` to `GraphRAGQueryEngine` (:380-419), i.e. the UI Search
  tab and the ch34 MCP/LLM tools share one engine. Params: Query / Address (+Use Current) /
  Limit 1–100 default 20 / Depth 1–5 default 1 / Direction both-callers-callees / Scope
  function-binary (:1125-1164); results table `#, Function, Address, Score, Summary` (:1166-1167),
  Go-To navigation (:1344-1352). "Call Context" surfaces the query engine's depth-limited BFS
  `_collect_context` (query_engine.py:282-305) flattened per depth (:1273-1302). No filters for
  risk/category beyond scope/flag inspection — there is no graph-wide filter UI; filtering exists
  only per-node (edge type, flag checkboxes).
- **Manual Analysis panel** (`manual_analysis_panel.py`): the control surface for the whole
  pipeline — ReIndex + Semantic (Primary, with Enable RAG / Enable MCP / Force checkboxes :67-84)
  and Security / Network Flow / Community Detection / Refresh Names (Individual :88-131), each with
  a tooltip that states the true mechanism ("Group related functions into communities using Label
  Propagation algorithm", :116 — the panel is more honest than the docs), plus status label and a
  0–100 progress bar (:135-148, 177-197). Every button doubles as a Stop button while running
  (:199-217).
- **Refresh Names** is the only name-sync mechanism: a synchronous loop over `idautils.Functions()`
  updating changed node names (semantic_graph_controller.py:284-296). The tab doc's claim of an
  IDB `renamed()` hook keeping labels in sync (tab md:162) is **dead**: `grep -rn "renamed" src/
  --include=*.py` matches 13 hits in `analysis_db_service.py` (local `renamed = False/True`
  DB-path migration bookkeeping, :116-137), 4 in `db_migrations.py` (same pattern) and 1 in
  `symgraph_controller.py:838` (`is_llm_renamed` bookkeeping) — `grep -rn "def renamed" src/` →
  zero: no hook handler exists (consistent with ch31's dead-hook finding; *hit-list corrected
  2026-11-02 — earlier draft called the analysis_db_service hits "migration log strings"; they
  are migration bookkeeping variables*).
- View refresh cadence: navigation events flow through `set_current_offset`/`refresh_current_view`
  (:79-119) re-querying store-backed fields per selection; stats come from
  `GraphStore.get_graph_stats` feeding "X nodes | Y edges | Z stale | Last: …" (graph_store.py:439;
  view `update_stats` :195).

## 10. Cost & effectiveness notes

- **LLM cost scales linearly with function count**: ReIndex is LLM-free (§3); Semantic Analysis is
  one call per stale/unsummarized FUNCTION, no sampling, default limit effectively unbounded
  (semantic_extractor.py:64-70; graph_store.py:875). For 10k functions ≈10k calls plus ~28 min of
  mandated sleep (:28-29, 92-93). The workflow doc's advice — "1000+ functions, consider running
  overnight" (workflow:129) — matches the implementation.
- **Re-run semantics**: Semantic without Force processes only `is_stale=1 OR llm_summary empty`
  (graph_store.py:885); Force re-summaries everything except user-edited nodes
  (semantic_extractor.py:64-68, 103). Reindex never deletes summaries
  (semantic_graph_controller.py:919-922; graph_store.py:221-226) but does mark every node stale
  again (§5), so the next Semantic run re-LLMs the whole binary — every ReIndex invalidates all
  summaries as candidates, even if nothing changed.
- **Deterministic passes are cheap but superlinear in parts**: taint DFS capped at 100 paths and
  length 10; network flow and `create_vulnerable_via_edges` are entry×sink reachability products
  with BFS≤10 (network_flow_analyzer.py:374-414; taint_analyzer.py:234-264); label propagation ≤100
  iterations (community_detector.py:71, 113-127). Visual graph is capped at 50 nodes
  (semantic_graph_controller.py:503).
- **Every worker is cancelable** (§2) with per-step progress on the status label + panel bar
  (:592-765).
- Effectiveness ceiling: search recall is FTS-recall, similarity is topology, categories come from
  one keyword header, and risk flags are static API presence — the "knowledge graph" is strongest as
  a cached, queryable call-graph + flag store, and as the Explain-tab cache (§4), weakest precisely
  where the marketing language implies vector semantics.

## Gaps

- Did not re-verify the schema DDL (ch-context reused for `graph_nodes`/`graph_communities` columns
  and FTS triggers); `analysis_depth` semantics unexplored.
- `graphrag_tools.py` internals untouched (ch34); only the shared `GraphRAGQueryEngine` dispatch
  was confirmed (semantic_graph_controller.py:380-419 mirrors tool names `ga_*`).
- EXTERNAL-node creation lives in the SymGraph push path (ch21); this chapter verified only its
  absence from the IDA-local pipeline.
- `rag_service`'s exact similarity math (cosine vs dot) not read — labeled *(inference)* in §7.
- View internals: `_node_style`/`_edge_style` colors not line-checked against the doc's hex table
  (tab md:86-96); `_find_network_send_nodes` tiers (:196-254) skimmed at header level.
- Whether Force + MCP-enabled prompts actually attach graph tools (mcp_enabled wiring inside
  `FunctionSummaryService`, ch32) not re-verified here.

## Sources

- `/tmp/opencode/IDAssist/docs/tabs/semantic-graph-tab.md`:21-28, 32-143, 145-154, 156-162
- `/tmp/opencode/IDAssist/docs/workflows/semantic-graph-workflow.md`:22-73, 104-116, 126-133
- `src/controllers/semantic_graph_controller.py`:33-51, 70-86, 138-155, 171-232, 234-296, 298-343,
  352-419, 435-466, 502-555, 592-765, 767-791, 794-860, 862-895, 897-945, 946-986, 987-1019
- `src/services/graphrag/graphrag_service.py`:14-53
- `src/services/graphrag/structure_extractor.py`:47-118, 120-215, 217-339, 341-425, 427-490,
  492-533
- `src/services/graphrag/function_signature_generator.py`:17-106
- `src/services/graphrag/semantic_extractor.py`:27-139, 141-227, 265-288
- `src/services/graphrag/extraction_prompts.py`:106, 133, 141-149, 189, 201-209, 216-243, 246-287
- `src/services/graphrag/models.py`:8-59, 70-192, 196-222 (fields incl. `embedding`, `is_stale`
  defaults :221-222)
- `src/services/graphrag/graph_store.py`:74-116, 163-260, 439, 613-680, 833-896, 898-919,
  956-1115
- `src/services/graphrag/query_engine.py`:9-113, 115-146, 148-192, 194-232, 234-305, 307-374
- `src/services/graphrag/security_feature_extractor.py`:29-94, 96-161, 162-197, 198-274, 275-402,
  404-529, 530-556
- `src/services/graphrag/security_features.py`:8-125, 125-207, 207-251, 251-316, 318-326
- `src/services/graphrag/network_flow_analyzer.py`:40-95, 51, 110-194, 196-266, 285-286, 306-360,
  361-438, 440-513
- `src/services/graphrag/taint_analyzer.py`:26-162, 164-233, 234-264, 266-303, 303-320, 331, 345-350
- `src/services/graphrag/community_detector.py`:4, 19-41, 44-53, 68-139, 141-243, 245-292,
  294-376
- `src/services/graphrag/graphrag_tools.py`: referenced only (covered in ch34)
- `src/controllers/explain_controller.py`:225-245, 455-480, 545-575, 935-955, 1495-1515
- `src/views/semantic_graph_tab_view.py`:14-16, 24-28, 41-59, 66-167, 169-266, 268-300, 320-340,
  377-500, 500-568, 603, 634-657, 660-766, 768-836, 844-919, 921-939, 945-1013, 1014-1085,
  1087-1171, 1186-1302, 1315-1395
- `src/views/semantic_graph/manual_analysis_panel.py`:17-30, 43-131, 135-148, 153-197, 199-229
- `src/services/function_summary_service.py`:135 (`generate_full_query`)
- `src/services/llm_service.py`:203; `src/services/models/llm_models.py`:139, 151;
  `src/services/llm_providers/openai_platform_api_provider.py`:552;
  `src/services/llm_providers/anthropic_platform_api_provider.py`:655;
  `src/services/llm_providers/ollama_provider.py`:495
- `src/services/rag_service.py`:73-75, 203-235
- Verified negatives by grep: `grep -rn "renamed" src/ --include=*.py` (no IDB rename hook);
  `grep -rn "graphviz" src/views/semantic_graph_tab_view.py` (no Graphviz);
  `grep -rni "leiden|louvain" src/` (only models.py comments); `grep -rn "\.embedding"
  src/services/graphrag/` (store plumbing only);
  `grep -n "EXTERNAL|THUNK" src/services/graphrag/*.py` (no node creation in pipeline);
  `grep "SIMILAR_PURPOSE|REFERENCES|CONTAINS" src/services/graphrag/` (no writers outside models — hits are models.py, tool-description strings, and `CONTAINS_*` security flags; see §Edges).
