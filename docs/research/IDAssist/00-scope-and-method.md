# IDAssist ↔ calxgloss comparison — scope and method

> Part of the [overview](README.md). Read this first for what is being
> compared and how.

## What IDAssist is

**IDAssist** ([symgraph/IDAssist](https://github.com/symgraph/IDAssist),
MIT, by Jason Tang / symgraph.ai) is an **IDA Pro 9.0+ plugin** — a dockable
PySide6 panel (`Ctrl+Shift+A`) that integrates LLM-powered analysis into the
reverse engineer's interactive workflow. It talks to many LLM backends
(Anthropic, OpenAI, Bedrock, Ollama, LiteLLM, OpenWebUI, Claude-CLI, OAuth
flows), explains decompiled functions, answers questions about the binary,
proposes renames the human can accept, builds a semantic knowledge graph of
the binary (GraphRAG: call graph, security flags, network flow, community
detection), indexes reference docs for RAG context, runs an autonomous ReAct
agent with MCP tool integration, and syncs names/types to the commercial
**SymGraph** collaboration platform. Python, ~55.3k lines (55,326) across 128 tracked
`.py` files (154 tracked files total; *counts corrected 2026-11-02 — earlier draft said 141*), ~53.9k of it is the plugin (src/ 53,613 + `idassist_plugin.py` 313), ~1.4k is tests.

## Why compare it to calxgloss

Both consume decompiled output of real binaries and use LLMs to turn binary
knowledge into named, structured understanding. They sit at opposite ends of
the autonomy/verification spectrum: IDAssist is an **interactive assistive
panel inside a disassembler** with a human on every click; calxgloss is an
**automated pipeline + review harness** that translates whole DLL trees to
verified cross-platform Rust. The comparison covers **every part of
IDAssist** — packaging, all six tabs, the agent layer, the graph layer, the
provider layer — and compares its features and *effect* against calxgloss's
pipeline, evidence, verification, and review model.

## Comparison scope

**In scope**

- Complete repository inventory: every file at HEAD, IDA Plugin Manager
  packaging (`ida-plugin.json`, `hcli plugin install idassist`), dependency
  list, test suite, docs tree, CI (verified: none).
- Full git history and release archaeology: 76 commits, v1 → v2.4.0; what
  each capability was added when, contributor mix, issue tracker activity.
- The plugin foundation: entry point, IDA/Qt version compat shims, threading
  model (`execute_on_main_thread`, daemon worker), SQLite persistence +
  migration system, settings management.
- Every tab: Explain, Query (+ chat macros, transcripts, RLHF feedback),
  Actions, Semantic Graph, RAG, Settings, SymGraph.
- The model layer: 12 provider types (`provider_types.py:26-47`; *corrected 2026-11-02 — earlier draft said 8*), OAuth/browser auth, extended thinking
  budgets, streaming renderer, context-window management, message format
  adaptation.
- The agent layer: ReAct orchestrator, plan approval, todo/findings state,
  MCP (SSE/streamable-HTTP/stdio) clients and tool orchestration, built-in
  internal IDA tools, function calling.
- The semantic graph subsystem: structure/semantic/security extraction,
  graph store schema, network-flow and taint analysis, community detection,
  query engine, tool surface.
- RAG document search: upload → chunking → Whoosh hybrid text+vector search.
- Actions: rename/type suggestion generation, confidence model, apply-back
  to the IDB.
- SymGraph platform integration: push/pull API, conflict-resolution wizard,
  what the companion service is.
- Whatever the project itself reports about effectiveness (none expected —
  verified per-chapter, recorded as negative findings if absent).

**Out of scope**

- IDA Pro and Hex-Rays internals as such — cited only where the plugin's
  behavior depends on them.
- symgraph.ai the company/product beyond what the plugin's integration
  surface requires.
- Broader LLM-for-RE literature; this dossier is IDAssist ↔ calxgloss, not
  a survey.

## Method and sources

- **Primary code source:** a full clone at `/tmp/opencode/IDAssist`, HEAD
  `09dd910d70016c7b3f7e8bc01a4d5bc1035ec302` (2026-09-20, "Update model
  guidance to current LLM families"), 76 commits, `ida-plugin.json` version
  2.4.0. Claims about IDAssist code cite clone-relative `path:line` at that
  commit; claims about older states cite `<sha> <path>`.
- **Secondary:** the repo's own `docs/` (tab references + workflows, part of
  the clone), the GitHub repo pages (stars/forks/issues/releases), and
  https://symgraph.ai where the SymGraph platform is concerned — all cited
  by URL. Marketing claims from any source are labeled as such and not
  treated as evidence of effect.
- **calxgloss side:** [10-calxgloss-baseline.md](10-calxgloss-baseline.md)
  is the fixed anchor; its claims cite this repo's docs, ADRs, and crates.
- **Verification protocol:** each chapter is written by a sub-agent reading
  the clone, with every factual claim carrying a `path:line` citation; the
  lead agent spot-checks citations and negative findings against the clone
  before a chapter is marked *done* in the index. Absences ("no CI", "no
  eval") are recorded as verified negatives with the search that proved
  them.
- Repo facts at HEAD (verified 2026-11-01, amended 2026-11-02): 76 commits; latest release
  tag `2.4.0` at `3c7b184` (2026-09-12), HEAD one commit past it (`git describe` =
  `2.4.0-1-g09dd910`) — *corrected: earlier draft said "2.3.0-era"*; 1 open issue; 901 stars /
  95 forks (GitHub page, 2026-11-01); 154 tracked files (corrected from "141"); 55,326 lines of
  Python; no `.github/` directory (grep-verified absence of CI config);
  10 test files, 1,400 LOC, covering providers/settings/Qt-compat only.

## File index

| File | Domain | Status |
|------|--------|--------|
| [00-scope-and-method.md](00-scope-and-method.md) | this file | done |
| [10-calxgloss-baseline.md](10-calxgloss-baseline.md) | calxgloss capability inventory (comparison anchor) | done |
| [20-idassist-inventory.md](20-idassist-inventory.md) | complete repo surface: files, packaging, tests, docs, CI | done |
| [21-history-and-releases.md](21-history-and-releases.md) | commit archaeology, releases, contributors, community | done |
| [31-plugin-foundation.md](31-plugin-foundation.md) | entry, compat, threading, persistence, settings | done |
| [32-explain-and-query.md](32-explain-and-query.md) | Explain & Query tabs, RLHF | done |
| [33-llm-providers-and-context.md](33-llm-providers-and-context.md) | providers, OAuth, thinking, context mgmt | done |
| [34-agent-mcp-and-tools.md](34-agent-mcp-and-tools.md) | ReAct agent, MCP, internal tools | done |
| [35-semantic-graph-graphrag.md](35-semantic-graph-graphrag.md) | GraphRAG subsystem end to end | done |
| [36-rag-document-search.md](36-rag-document-search.md) | document RAG with Whoosh | done |
| [37-actions-renames.md](37-actions-renames.md) | Actions tab: renames → apply | done |
| [38-symgraph-platform.md](38-symgraph-platform.md) | SymGraph platform integration | done |
| [40-comparison.md](40-comparison.md) | feature & effect comparison, what-calxgloss-can-learn | done |
