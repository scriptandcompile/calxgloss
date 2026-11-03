# IDAssist ↔ calxgloss — the full comparison

> Part of the [IDAssist overview](README.md). Every IDAssist claim below cites
> this dossier's chapters ([20](20-idassist-inventory.md)–[38](38-symgraph-platform.md),
> clone-relative `path:line` at HEAD `09dd910d…`, v2.4.0); every calxgloss
> claim cites the fixed baseline ([10](10-calxgloss-baseline.md), verified at
> HEAD `40fbf91f`, 2026-10-31). Chapter 38's claims were additionally verified
> line-by-line by the lead on 2026-11-02 after a first draft was rejected for
> fabricated paths — the numbers quoted here are the surviving, re-verified ones.

**Bottom line up front: IDAssist is the largest open "AI inside IDA" surface
examined in this research line — 55,326 lines of Python, seven feature tabs (*tab count corrected 2026-11-02 — `idassist_form.py:104-110` constructs 7 tabs; docs/index.md:16 says "seven tabs"*), a
ReAct agent, MCP, a GraphRAG store, a document RAG engine, a rename pipeline,
and a cloud sync service — and it is the only one whose absence of verification
is total: not one artifact the LLM produces is mechanically checked, including
by validators the author wrote and never called.** calxgloss (≈279k LOC Rust,
MIT) is the inverse object: a narrow, automated PE→Rust translation factory in
which the mechanical gate (compile + Wine-captured values + ordered API-trace
containment, ADR-0057) *is* the product, and everything assistive — naming,
ad-hoc querying, interactive chat — is deliberately excluded by doctrine
(ADR-0020/0021, ADR-0054/0055) ([10](10-calxgloss-baseline.md)). The
comparison's center of gravity is therefore not feature count — IDAssist wins
that on every row of an assistant checklist — but *what a feature's output
is*: an unverified suggestion applied to a live IDB, or a scored claim, or a
verified unit of work. IDAssist's chief value to calxgloss is as the demand
side of the market (901 stars in seven months for exactly the surface calxgloss
legislated away) and as the densest catalogue yet of *shipped-but-unwired*
shortcuts: an RLHF table with no reader, validators with no callers, an
embedding column never computed, a right-click action calling a method that
does not exist ([32](32-explain-and-query.md), [37](37-actions-renames.md),
[35](35-semantic-graph-graphrag.md), lead verification 2026-11-02).

## Snapshot

| | IDAssist | calxgloss |
|---|---|---|
| What it is | Interactive plugin suite inside IDA Pro 9.x (dockable Qt panel, 7 tabs; manifest `idaVersions` 9.1–9.4 — no 8.x support; corrected 2026-11-02) | Automated pipeline + review harness for a directory of Windows PEs |
| Size | 154 tracked files, 128 `.py` (116 under `src/`; *corrected 2026-11-02 — earlier draft said 99*), 55,326 LOC Python ([20](20-idassist-inventory.md)) | 34 crates, 475 `.rs`, ≈279k LOC Rust ([10](10-calxgloss-baseline.md)) |
| Language / license | Python 3.11+ (docs/getting-started.md:9; corrected 2026-11-02 — earlier draft said 3.12+), MIT | Rust, MIT |
| Heritage | port of a Binary Ninja predecessor ("BinAssist") — provenance strings still in the macro expander (`query_controller.py:1157`, [32](32-explain-and-query.md) §1.5) | designed from scratch, 57 ADRs |
| Age / cadence | 76 commits 2026-02-26→2026-09-20; 67/76 in Feb–Apr, then maintenance tail; 68/76 by one author ([21](21-history-and-releases.md)) | active; P21+P22 shipped the day before the baseline HEAD |
| Distribution | IDA plugin dir + `ida-plugin.json` marketplace manifest; no pyproject, no package ([20](20-idassist-inventory.md)) | CLI (29 subcommands) + Axum/React review UI + `live` process |
| Traction | 901 stars / 95 forks (2026-11-01); re-homed from a personal account to the `symgraph` org in `1eb7456` — commercialization around the plugin ([21](21-history-and-releases.md)) | pre-adoption (single-operator project) |

## Capability matrix

Winner in **bold**. "—" = absent. "split" = different jobs, no honest winner.

| Capability domain | IDAssist | calxgloss | Verdict | Ch. |
|---|---|---|---|---|
| Mission | Assist a human *sitting in IDA*: explain, chat, suggest renames, graph, search docs, sync analysis — every output lands in the user's live IDB or panel | Translate whole binaries to verified Rust: one `{binary}/{function}` unit at a time, human adjudicates verdicts | split — opposite ends of the autonomy spectrum; IDAssist automates nothing end to end, calxgloss automates everything except the verdict | [32](32-explain-and-query.md), [10](10-calxgloss-baseline.md) |
| Target breadth | Whatever IDA opens: any architecture, any file format IDA supports, PE/ELF/firmware/mobile — IDAssist's code never gates on format (no format checks in the context services, [31](31-plugin-foundation.md), [32](32-explain-and-query.md)) | Windows PE32/PE32+ only; managed PEs parked do-not-translate (ADR-0044); Kuna in-process as the sole engine (ADR-0039-41) | **IDAssist, decisively** — this is its biggest structural advantage and calxgloss's honest scope line | [20](20-idassist-inventory.md), [10](10-calxgloss-baseline.md) |
| Integration surface | One dockable Qt panel, 7 tabs, hotkeys `Ctrl+Shift+A/E/Q`, right-click menu actions; legacy `plugin_t` + `PLUGIN_KEEP` residency (`idassist_plugin.py:192-199`); MCP **client** to external servers; no headless mode, no CLI, no public API | 29 CLI subcommands, web review UI (two routers by design, ADR-0002), WebSocket progress; **no MCP, no plugin surface, no interactive address-level queries at all** | split — IDAssist is where a human works today; calxgloss's surface is where verdicts get adjudicated; neither can serve the other's seat today | [31](31-plugin-foundation.md), [34](34-agent-mcp-and-tools.md), [10](10-calxgloss-baseline.md) |
| Model layer | 12 `ProviderType` members (`src/services/models/provider_types.py:26-47`: Anthropic Platform/Claude-CLI, OpenAI Platform/OAuth, Gemini Platform/OAuth, Bedrock, LiteLLM, LM Studio, Ollama, OpenWebUI, xAI — *roster corrected 2026-11-02; earlier draft listed Azure/OpenRouter/llama.cpp, which are not members*); defaults `max_tokens=4096`, 90 s timeout, rate-limit retry 50×10-30 s ([33](33-llm-providers-and-context.md) §1, §10) | one `LlmClient`, OpenAI-compatible HTTP, local-first (llama.cpp/Ollama/vLLM named), **no default endpoint/model — unset fails loudly**; per-attempt token/strategy/model telemetry | **IDAssist on range** (12 providers, OAuth, streaming quirks vs one seam); **calxgloss on posture and instrumentation** (no cloud default, token ledger per tier/strategy; IDAssist has none — [33](33-llm-providers-and-context.md)) | [33](33-llm-providers-and-context.md), [10](10-calxgloss-baseline.md) |
| Context engineering | Explain prompt = function header + callers/callees + code at current view level; **no strings, no imports injected** though the service can extract them (`binary_context_service.py:712, 754` unused by Explain, [32](32-explain-and-query.md) §2.2); RAG injection top-3@0.3; Query macros (`#line`, `#func`, `#range` — actually a hex dump, doc drift) | 15 registry scans → coverage-stamped evidence bundle (ADR-0052/0053) → 5 context tiers with pruning + named unknown records (ADR-0055/0056); imports, strings, constants, types, algorithms all rendered with admission lines | **calxgloss, by an enormous margin** — IDAssist's flagship prompt reads *less structured evidence about the function* than a calxgloss Signature-tier prompt | [32](32-explain-and-query.md), [36](36-rag-document-search.md), [10](10-calxgloss-baseline.md) |
| Agent / tool layer | ReAct orchestrator: plan→act→reflect→synthesize; caps: 15 iterations (+2 per reflection task), 10 tool rounds/iteration, 150k-token compression at 75%, 10k-token tool results, 3 concurrent tools, same-tool escalating prompt warning at 3 failures — warning text only, no mechanical block (`react_orchestrator.py:341-348`; *corrected 2026-11-02 — earlier draft called it a hard block*); ~30 built-in IDA/graph tools via MCP plumbing; plan approval + per-tool Allow Once/Session/Deny — **gating only on the plain Query path; Explain's tool round-trip and Actions bypass it** ([34](34-agent-mcp-and-tools.md), lead spot-check) | no agent at all by design: deterministic pipeline; "strategies" (`compile_fix`, `test_fix`, `escalate`, …) are retry adapters at one seam (ADR-0051); ad-hoc queries refused except declared seam families (ADR-0054/0055) | split — IDAssist's agent is real and bounded (the caps table is honest engineering), but its tools **write to the live IDB**; calxgloss has no agent because its loop is already scripted and every write is verified | [34](34-agent-mcp-and-tools.md), [10](10-calxgloss-baseline.md) |
| Interactive knowledge store | SQLite `analysis.db`: semantic graph (nodes/edges/communities/summaries), FTS5, Explain cache, RAG index, `llm_renames` audit, `feedback` table; staleness + `user_edited` flags on nodes ([35](35-semantic-graph-graphrag.md), [31](31-plugin-foundation.md)) | git attempt branches + JSON artifacts + SQLite cache; the call graph drives queue order (topological, tested, `callgraph.rs:964-1032`) but is not user-browsable | **IDAssist** — a genuine queryable per-binary knowledge store is what calxgloss structurally lacks (ad-hoc call-path/def-use is open P29) | [35](35-semantic-graph-graphrag.md), [10](10-calxgloss-baseline.md) |
| …and its honesty | the "semantic graph" **never computes an embedding**: `graph_nodes.embedding` exists in schema and is INSERTed, but its value is always NULL — `embedding: Optional[bytes] = None` (`graphrag/models.py:208`) and nothing computes one (write sites `graph_store.py:192,223,239,704,761` all pass NULL; *corrected 2026-11-02 — earlier draft said "no writer anywhere"*); "semantic search" = FTS5 + LIKE; "similarity" = topology; risk flags = static API-name presence; every ReIndex marks all nodes stale, so the next Semantic run re-LLMs the whole binary ([35](35-semantic-graph-graphrag.md) §7, §10) | vocabulary is legislated: absent coverage = *unknown, never absent* (ADR-0053); six named unknown kinds; claims carry confidence + version-admission lines | **calxgloss** — IDAssist's marketing vocabulary ("semantic", "GraphRAG") outruns its machinery; calxgloss's whole honesty layer exists to prevent exactly that gap between word and mechanism | [35](35-semantic-graph-graphrag.md), [10](10-calxgloss-baseline.md) |
| Document retrieval | "Hybrid" RAG = Whoosh BM25 + hand-rolled TF-IDF (top-1000 vocab, `\b\w+\b` tokenization that drops underscore-containing symbol names), fused 0.6/0.4, 500-char chunks no overlap; no PDF parser despite docs; index is global, not per-binary; combine step doesn't dedup despite the fetch-2× comment ([36](36-rag-document-search.md) §4, §10) | none, by design: retrieval is replaced by 15 deterministic scans over the binary itself; external docs never enter prompts | split — different problems (corpus Q&A vs whole-binary evidence); IDAssist's implementation is also quietly weak: symbol-name queries lean entirely on the 0.6-weight BM25 half | [36](36-rag-document-search.md), [10](10-calxgloss-baseline.md) |
| Naming authority | Actions tab: one-shot tool call proposes renames/types with model-self-reported confidence; applied to the IDB via `set_name`/`set_type`; **`validate_function_name`/`validate_variable_name`/`validate_variable_type` exist and have zero call sites** (exhaustive grep, [37](37-actions-renames.md) §9); collision safety is only IDA's `SN_CHECK`; the right-click "Rename Suggestions" entry calls a nonexistent `analyze_function()` (`idassist_plugin.py:75`, lead-verified AttributeError) | no rename feature *by doctrine*: identity is binary-side verbatim; write-back is types-only (`calxgloss-decomp/src/lib.rs:13-14`, ADR-0020/0021); names exist only as scored, prompt-fed evidence (P51 extends scoring) | split by design — but note the asymmetry IDAssist proves: it ships the validator layer **and fails to wire it**, i.e. its "gates" are aspirational; calxgloss has no gates because the one write path is mechanically checked | [37](37-actions-renames.md), [10](10-calxgloss-baseline.md) |
| Verification of LLM output | **none, end to end** — no post-apply re-decompile, no compile check, no second pass; confidence is model self-report; the dead validators above are the entire (unexecuted) validation surface; ReAct "verification" is the model reflecting on its own tool results | the gate *is* the product: `cargo check` + behavioral tests vs Wine-captured baselines + ordered API-trace containment (ADR-0057); missing traces read unassessed, never passing | **calxgloss, non-negotiable** — the axis the entire comparison turns on | [37](37-actions-renames.md) §9, [34](34-agent-mcp-and-tools.md) §9, [10](10-calxgloss-baseline.md) |
| State & reversibility | IDB mutations recorded in an `llm_renames` audit table + IDA's own undo; transcripts logged; settings in a separate SQLite DB with per-table migrations; SQLite `api_key` stored **plaintext** ([31](31-plugin-foundation.md), [37](37-actions-renames.md) §7) | git attempt branches per unit, failure branches archived never deleted, justification commits carry model + context size; verdicts persisted as typed state | **calxgloss** — an audit *table* records that a change was applied, not whether it was kept or correct; git-with-justification is a decision substrate | [37](37-actions-renames.md), [10](10-calxgloss-baseline.md) |
| Cloud sync | SymGraph: SHA-256-keyed revisions of symbols/graph/documents/fingerprints over 14 `/api/v1` routes, `X-API-Key` auth (`symgraph_service.py:156-165`), no client-side license code (grep-verified); **publish uploads the complete raw binary** (`symgraph_controller.py:958-966`, `:1228-1233`); malformed default URL `https://api.SymGraph` — endpoint is pure configuration ([38](38-symgraph-platform.md), lead-verified) | none: local-only vault; no sync roadmap item | split — the SHA-256→revisions→typed-bundles data model is genuinely good (and replicable locally); the sample-upload trust cost is disqualifying for calxgloss's target material | [38](38-symgraph-platform.md), [10](10-calxgloss-baseline.md) |
| Evaluation & QA | 10 test files, 1,400 LOC — providers/settings only; **no CI** (verified absence of `.github/`); no eval/benchmark vocabulary anywhere (literal `eval` greps hit only Ollama's token counters `eval_count`/`prompt_eval_count`, `ollama_provider.py:203-212,388-395` — no harness semantics); RLHF feedback table has zero readers (`get_feedback_entries`/`get_feedback_stats` uncalled, [32](32-explain-and-query.md) §5) → no accept-rate substrate exists in practice | no CI either (open P42); one fixture DLL, no scored eval (open P33); but per-unit mechanical proof exists *by construction* and 59 provider-side analogs don't apply — engine harnesses + CLI pairing tests pin the scans | split, and IDAssist is the sharper negative: it **built the feedback substrate and never consumed it**; calxgloss at least files both gaps on its roadmap | [20](20-idassist-inventory.md), [32](32-explain-and-query.md), [33](33-llm-providers-and-context.md) §9, [10](10-calxgloss-baseline.md) |
| Security & data posture | plaintext API keys in `settings.db`; 50-retry×30 s cloud retry storms; sync uploads whole samples; OAuth into consumer ChatGPT/Gemini plans; four providers run blocking HTTP on the UI event loop; but per-call **tool approval UI** and private-network awareness ([31](31-plugin-foundation.md), [33](33-llm-providers-and-context.md) §10, [38](38-symgraph-platform.md)) | data never leaves the machine (local LLM, local Wine); but **no OS sandbox** around verify/Wine (open P43) and untrusted binary data enters prompts (open P45) | split — IDAssist moves hostile data *to the cloud*, calxgloss moves the hostile *execution* in-process; different risks, both real | [31](31-plugin-foundation.md), [33](33-llm-providers-and-context.md), [10](10-calxgloss-baseline.md) |
| Documentation | 12 docs files, thorough — and measurably stale: `rlhf.db` path, PDF support, `#range` semantics, `anthropic_oauth` listed but absent from `src/`, broken right-click entry presented as working; a chapter's first draft was rejected for citing files that don't exist even though the docs describe them ([21](21-history-and-releases.md), [32](32-explain-and-query.md) §1, [36](36-rag-document-search.md) §1, [37](37-actions-renames.md) §1) | design doc 1,387 LOC + data-flow 973 LOC + 57 ADRs + per-context glossaries; roadmap staleness is *declared* (`README.md:38` "13 scans" known-stale vs 15 pinned by test) | **calxgloss** — IDAssist's docs-code drift is systematic (six verified instances across four chapters); calxgloss pins its prose to tests | [10](10-calxgloss-baseline.md) |
| Maintenance | solo, decelerating: 4/1/0/2/2 commits May–Sep after the Feb–Apr sprint; org re-home signals the plugin is the funnel for SymGraph the service; 1 open issue | active factory; roadmap P23–P52; two tracks shipped the day before HEAD | **calxgloss** — solo-sprint-then-tail is the classic pattern; treat IDAssist as a snapshot, not a moving partner | [21](21-history-and-releases.md), [10](10-calxgloss-baseline.md) |

## Effect: asserted vs established

**IDAssist asserts a great deal and has never measured any of it.** The README
sells "automatic security analysis including risk level, activity profile,
security flags, and API detection" (`README.md:18`) — ch 32 verified the
feature is real but *not LLM-derived*: flags are static API-name presence.
The Semantic Graph "learns" function semantics — ch 35 verified one LLM call
per function with keyword-header categories and an embedding column that is
never populated. Renames come back with confidence numbers — ch 37 verified
they are model self-report, that the 0.5 threshold only recolors a table, and
that no suggestion is ever filtered, verified, or post-checked before hitting
the IDB. No eval harness, no benchmark, no accept-rate anywhere in 55k lines
(verified negative across the clone, [20](20-idassist-inventory.md)); the one
substrate that *could* compute an accept rate — the RLHF `feedback` table —
is written and never read ([32](32-explain-and-query.md) §5). IDAssist's
measurable effect is adoption-shaped: 901 stars, 19 releases in seven months,
a marketplace manifest, and an org built around it ([21](21-history-and-releases.md)).

**calxgloss establishes per-unit truth and still can't score itself.** Every
merged unit compiles, passes behavioral tests against Wine-captured values,
and contains the original's ordered API-call trace; missing evidence reads
unknown-never-absent ([10](10-calxgloss-baseline.md)). But there is no
aggregate score (P33 open), one fixture instead of a corpus, no whole-binary
verdict (P26 open), no CI (P42 open). Same BLUF as the ReverserAI chapter,
sharper here: **neither project scores itself, but calxgloss's output is a
measurement substrate while IDAssist's is not** — IDAssist records that a
rename was *applied* (`llm_renames`) and that a human *thumbs-upped* an
answer, but never joins them, never re-checks, and never publishes a number;
calxgloss's `VerificationResult` records are already typed, joinable, and
P33-ready.

**One asymmetry deserves its own paragraph.** IDAssist proves that the
substrates for evaluation are cheap to build — feedback table, rename audit,
transcripts all shipped — and that **they rot without a consumer**. Dead
validators, an unread feedback table, an uncomputed embedding column, an
unexecuted dedup comment: four independent instances, in four subsystems, of
code that exists as a *promise* rather than a mechanism. calxgloss's discipline
of pinning counts to tests (15 scans pinned by the CLI pairing test; ADR-0053
coverage records) is the vaccine; IDAssist is the exposure.

## Where the ideas converge

- **Deterministic evidence passes feeding LLM passes.** IDAssist's ReIndex is
  entirely LLM-free structural extraction, and the LLM summarization layer
  consumes its node/edge store ([35](35-semantic-graph-graphrag.md) §3-4) —
  calxgloss's 15 scans → evidence bundle → translate loop is the same shape,
  with far more passes and admission lines ([10](10-calxgloss-baseline.md)).
- **Bottom-up, call-graph-aware processing.** IDAssist's callees/callers
  injection, graph-tool ordering for agent queries, and the "propagated
  summaries" story ([32](32-explain-and-query.md) §2.2,
  [34](34-agent-mcp-and-tools.md) §7) restate the insight calxgloss pins with
  tests and a merge gate ([10](10-calxgloss-baseline.md) §Pipeline anatomy).
  Third independent confirmation after ReverserAI.
- **Cache-with-staleness for LLM artifacts.** IDAssist's `is_stale` +
  `user_edited` + "process only stale-or-empty" re-run semantics
  ([35](35-semantic-graph-graphrag.md) §5) are calxgloss's read-cache +
  coverage-record concern; note IDAssist's bug-shaped wrinkle — every ReIndex
  marks *everything* stale again, so invalidation is coarser than the change
  that caused it — which is exactly what calxgloss's per-function staleness
  hashes (open P47) are for.
- **Local runtimes are first-class, not exotic.** llama.cpp/Ollama/LM Studio
  sit in IDAssist's provider enum beside GPT-5 and Claude ([33](33-llm-providers-and-context.md) §1);
  calxgloss names the same three and defaults to them ([10](10-calxgloss-baseline.md)
  §Model layer). The whole ecosystem has converged here; nobody serious bets
  on cloud-only.
- **Audit trails as product.** `llm_renames` ([37](37-actions-renames.md) §7),
  transcripts, RLHF rows: IDAssist keeps reaching for a decision record even
  without a consumer. calxgloss's justification commits are the finished form
  of the same instinct.

## What calxgloss can honestly steal

Argued for and against, honestly. IDAssist is MIT — unlike the ReverserAI set,
*code* import is legally on the table, though little is worth taking as code.

1. **An MCP server over calxgloss artifacts — the one architecturally
   important steal.** IDAssist shows 901 stars' worth of demand for
   exactly the queries calxgloss refuses: interactive, address-level, tool-
   mediated ([34](34-agent-mcp-and-tools.md), [10](10-calxgloss-baseline.md)
   §Surface "no MCP surface"). calxgloss could stand up a read-only MCP server
   (declared seam families only — ADR-0054/0055 already names the allowed
   query shapes; P29 would widen them) exposing unit state, evidence bundles,
   verdicts, and decomp to an IDA/Ghidra-side agent. Argue for: it makes the
   pipeline's output interactive *without* giving calxgloss an interactive UI
   or rename authority; the seam discipline already designed for CLI
   (`--json`, P31/P52) is the same substrate. Argue against: it invites the
   IDAssist failure mode — a remote LLM consuming calxgloss evidence and
   writing names into some other tool's database, laundering calxgloss's
   scored claims into someone else's unverified pipeline. Mitigation is
   mandatory: serve evidence and verdicts, never suggestion endpoints.
2. **The applied-decision ledger, wired to a consumer.** IDAssist's
   `llm_renames` + feedback tables are the accept-rate substrate it never
   joined ([37](37-actions-renames.md) §7, [32](32-explain-and-query.md) §5).
   For calxgloss's P33/P51: every verdict (accept/send-back/patch/skip) is
   already persisted — the missing join is *outcome*: did the merged unit
   survive later scans/retries against it, did a patch invalidate it. Steal
   the pattern (a queryable applied-vs-kept ledger), not the implementation
   (SQLite sidecar tables with no FK to the mutation they describe).
3. **Per-function semantic summaries as prompt fuel — cheap, and adjacent to
   what P41 already does.** IDAssist's cached per-function LLM summaries,
   re-computed only when stale ([35](35-semantic-graph-graphrag.md) §4) are a
   retrieval-free way to give *neighbor context* to a caller's prompt.
   calxgloss gets similar effects from the ModuleContext/FullModule tiers; a
   summary cache keyed by callee would enrich Signature-tier prompts for
   cheap. Argue against: summaries are unverified LLM output — feeding one
   into a prompt as unlabeled context is precisely what the honesty vocabulary
   forbids; it would have to ride in as an admission-lined `LibmatchInfo`-style
   section, and IDAssist's whole-binary re-stale bug is the caution on
   invalidation cost. Keep it behind a measurement: only worth it if P33 can
   show the section changes pass rates.
4. **Bounded-agent numbers as a reference table.** IDAssist's caps — 15
   iterations, 10 tool rounds, 75% compression trigger, 10k tool-result
   truncation, 3-way concurrency, escalating prompt warning (not a block) at 3 same-tool failures
   ([34](34-agent-mcp-and-tools.md) §9) — are the most concrete published
   numbers of their kind in this research line. If calxgloss ever grows any
   tool loop (P29's ad-hoc queries could), copy the *shape*: explicit caps +
   self-repetition blocking. calxgloss's fault monitors already do the
   sibling job (loops, divergence, exhaustion) — this is confirmation, not new
   machinery.
5. **Negative evidence, denser than ReverserAI's.** Four shipped-but-unwired
   subsystems (validators, RLHF reader, embeddings, dedup), a broken
   right-click action shipped through at least one release, and six verified
   doc-drift instances — all in a 901-star project with **zero CI and zero
   behavior tests for exactly those surfaces** ([20](20-idassist-inventory.md),
   [37](37-actions-renames.md)). This is the concrete brief for P42
   (CI substrate): "the ecosystem's largest open IDA-AI suite ships dead
   safety code and broken entry points because nothing is ever re-run" — and
   calxgloss currently has *less* test coverage of its settings/provider
   equivalents. Also a brief for the standards doc: any calxgloss validation
   function must have a call site *in the same change that adds it*.

## What IDAssist confirms about calxgloss's choices

- **There is a large market for exactly what calxgloss refuses to be.** 901
  stars for interactive chat + renames + graph inside IDA, achieved in seven
  months by one author ([21](21-history-and-releases.md)) — the assistive
  surface is where practitioners spend money and attention. calxgloss's choice
  to exclude it (ADR-0054/0055, no interactive surface) is therefore a real
  strategic cost, not a neutral one; the MCP steal above is how to capture the
  demand without selling the doctrine.
- **Marketing outruns machinery when nothing checks it.** "Semantic" with no
  embeddings, "hybrid" that's 0.6/0.4 BM25+TF-IDF, "security analysis" that's
  API-name presence ([35](35-semantic-graph-graphrag.md), [36](36-rag-document-search.md),
  [32](32-explain-and-query.md)) — no deception was intended, but with no
  eval and no CI, nobody would have noticed either way. calxgloss's honesty
  vocabulary (unknown-never-absent, admission lines) is the institutional
  answer; IDAssist is the case study justifying it.
- **Cloud OAuth is what users actually want, and it's a trust liability.**
  IDAssist wired ChatGPT/Gemini consumer-plan OAuth ([33](33-llm-providers-and-context.md) §7)
  because users demand it; it also ships plaintext API keys and whole-sample
  upload. calxgloss's local-only posture looks austere next to that feature
  list, but for the malware/firmware/contract material calxgloss targets,
  IDAssist's sync model is a disqualifier — and it confirms calxgloss's
  "hostile data stays home" line as the defensible position, not the purist one.
- **Solo-sprint projects rot toward their service.** Plugin → org → closed
  service with a free client is a known gravity path (ch 21 re-home, ch 38's
  configuration-only endpoint). calxgloss, if it ever grows a service story,
  faces the same fork; the SHA-256-keyed revision model in ch 38 shows the
  good half (dedup, typed bundles, per-revision import) and the sample-upload
  shows the half that should never cross calxgloss's threat model.

## What IDAssist would have to become to reach calxgloss's effect

Not a refactoring — a different product:

- **An oracle.** Renames/explanations have no mechanical truth condition; the
  unit of work would have to become translation, with compile + behavioral
  baselines + trace containment (ch 37's apply pipeline would need to grow
  into `calxgloss-testgen`/`calxgloss-verify` from nothing).
- **Identity discipline.** IDAssist writes suggestions over the host tool's
  names; calxgloss's entire reversibility substrate (branch names, output
  paths, Wine locator parsing `FUN_` as RVA) requires binary-side identity to
  never move ([10](10-calxgloss-baseline.md) §Naming & typing #1).
- **Batch evidence, not per-query context.** 15 registry scans with coverage
  records vs per-prompt caller/callee lists is a category change
  ([10](10-calxgloss-baseline.md) §Pipeline anatomy).
- **Verdict review at unit granularity.** IDAssist's human adjudicates
  individual suggestions live, at the keyboard; the factory needs
  accept/send-back verdicts over persisted verification artifacts — the review
  UI plus attempt branches ([10](10-calxgloss-baseline.md) §Surface & state).

The symmetric question again answers itself: **for calxgloss to produce
IDAssist's effect it would need an interactive address-level surface and write
authority over names — both deliberately legislated away** (no rename
write-back in any crate; seam answers only declared families; identity
verbatim). The one honest bridge is steal #1: serve calxgloss's *reads* over
MCP and let someone else own the interactive seat.

## Verdict

IDAssist is the assistive extreme, fully realized and quietly fragile: the
most feature-complete open IDA AI suite this research line has examined —
six tabs, 12 providers, a bounded ReAct agent, MCP plumbing, a per-binary
knowledge store, hybrid document search, a rename pipeline, and a cloud
service keyed by binary SHA-256 that will upload your sample to get it — built
in one seven-month solo sprint and already decelerating. Its outputs are never
verified: confidence is self-report, the only validators were never called,
the embeddings were never computed, the feedback was never read, and the
right-click shortcut was broken on arrival. calxgloss is the verified extreme,
deliberately narrow: no chat, no renames, no interactive seat, and nothing
leaves the machine — with a mechanical gate that makes "this unit is
equivalent" a different kind of claim than "the model says 0.9 confidence."
The steal list is one architectural move (read-only MCP over the seam's
declared families), two substrate patterns (joined applied-vs-kept ledger,
admission-lined summary sections), one reference table (agent caps), and the
densest negative-evidence package yet for P42/P33: a 901-star project where
four subsystems shipped as promises rather than mechanisms, which is precisely
what a CI substrate and a scored eval exist to make impossible. IDAssist's
deepest confirmation of calxgloss's doctrine is unintentional: it built the
evaluation substrate and let it rot — proof that records without consumers are
decoration, and that calxgloss's rule ("mechanism or nothing, and the test
that proves the mechanism wired") is the difference between a feature and a
figure of speech.

## Sources

Dossier files (this directory):
- [00-scope-and-method.md](00-scope-and-method.md) — scope, clone provenance
  (HEAD `09dd910d…`), repo facts verified 2026-11-01.
- [10-calxgloss-baseline.md](10-calxgloss-baseline.md) — calxgloss anchor at
  HEAD `40fbf91f…`, incl. ADRs 0002/0003/0020/0021/0039-41/0044/0048-0057 and
  roadmap P23-P52.
- [20-idassist-inventory.md](20-idassist-inventory.md) — layout, LOC, tests,
  CI/eval absences; [21](21-history-and-releases.md) — history, releases,
  stars, org re-home, docs-vs-code divergence note.
- [31-plugin-foundation.md](31-plugin-foundation.md) — entry/residency,
  threading, dual SQLite, plaintext keys; [32](32-explain-and-query.md) —
  Explain/Query prompts, macros, RLHF write-only, doc drift, BinAssist
  heritage.
- [33-llm-providers-and-context.md](33-llm-providers-and-context.md) — 12
  providers, thinking-budget truth, OAuth plumbing, retry/timeout numbers;
  [34](34-agent-mcp-and-tools.md) — ReAct phases, caps table, MCP
  fresh-connection-per-call, approval gating gap.
- [35-semantic-graph-graphrag.md](35-semantic-graph-graphrag.md) — ReIndex vs
  Semantic phases, unused `embedding` column, FTS "semantic search",
  re-stale-everything semantics; [36](36-rag-document-search.md) — hybrid
  fusion math, tokenization weakness, global index, no PDF parser.
- [37-actions-renames.md](37-actions-renames.md) — one-shot suggestion tools,
  dead validators, `llm_renames`, broken right-click entry;
  [38](38-symgraph-platform.md) — 14-route API, `X-API-Key`, full raw-binary
  upload, no client-side license/OAuth (lead-verified 2026-11-02 after
  rejecting a first draft's fabricated paths).

Lead spot-checks for this chapter (2026-11-02, `/tmp/opencode/IDAssist` @
`09dd910d…`): `symgraph_service.py:156-165` (`X-API-Key`), `:361-392`
(`upload_binary`); `symgraph_controller.py:958-966` (`_build_binary_upload_payload`
reads `ida_nalt.get_input_file_path()`), `:1224-1247` (PushWorker full-binary
payload + failure string), PushWorker call chain upload→revision→metadata→
symbols→graph→documents→fingerprints; `settings_service.py:899-918`
(malformed default URL, `symgraph_api_key`); `0603274` diff (deleted
`symgraph_enabled`, old default `'0'`); grep-verified absences:
`isSymgraphLicenseActive`, `licensing/`, files named wizard/pkce/license, `auth/google`,
`auth/github`, `accessToken` — all zero hits. (Bare tokens `wizard` and `pkce` DO occur —
the SymGraph pull-wizard UI, `symgraph_controller.py:1499-1547` + README.md:28, and OAuth
PKCE utilities, `settings_controller.py:1161-1168`, `oauth_codex_utils.py:71` — there are
just no such *modules*; *absence list tightened 2026-11-02 after the fact-check flagged the
over-broad grep*).
