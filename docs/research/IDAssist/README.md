# IDAssist ↔ calxgloss — research dossier

A complete overview of **IDAssist** ([symgraph/IDAssist](https://github.com/symgraph/IDAssist),
MIT, "AI-Powered Reverse Engineering Plugin for IDA Pro", 901 stars) and a
feature-and-effect comparison with calxgloss. Start with
[00-scope-and-method.md](00-scope-and-method.md).

| File | Domain | Status |
|------|--------|--------|
| [00-scope-and-method.md](00-scope-and-method.md) | what is compared, clone used, citation rules | done |
| [10-calxgloss-baseline.md](10-calxgloss-baseline.md) | calxgloss capability inventory (comparison anchor) | done |
| [20-idassist-inventory.md](20-idassist-inventory.md) | complete repo surface: files, packaging, marketplace, tests, docs, CI | done |
| [21-history-and-releases.md](21-history-and-releases.md) | 76-commit archaeology, releases v1→v2.4, contributors, issues, community | done |
| [31-plugin-foundation.md](31-plugin-foundation.md) | entry point, IDA/Qt compat, threading, SQLite persistence, settings management | done |
| [32-explain-and-query.md](32-explain-and-query.md) | Explain & Query tabs: prompts, context macros, streaming, transcripts, RLHF feedback | done |
| [33-llm-providers-and-context.md](33-llm-providers-and-context.md) | 12 provider types, OAuth flows, extended thinking budgets, message-format adapters | done |
| [34-agent-mcp-and-tools.md](34-agent-mcp-and-tools.md) | ReAct agent, plan approval, MCP clients, internal IDA tools, function calling | done |
| [35-semantic-graph-graphrag.md](35-semantic-graph-graphrag.md) | GraphRAG subsystem: extraction, store schema, security/network/taint/community analyses, query engine, UI | done |
| [36-rag-document-search.md](36-rag-document-search.md) | RAG tab: uploads, chunking, Whoosh hybrid search | done |
| [37-actions-renames.md](37-actions-renames.md) | Actions tab: rename/type suggestions, confidence, apply-to-IDB pipeline | done |
| [38-symgraph-platform.md](38-symgraph-platform.md) | SymGraph closed cloud service: client integration, API surface, raw-binary upload, auth | done |
| [40-comparison.md](40-comparison.md) | full feature & effect comparison vs calxgloss | done |

Method note: every IDAssist claim below cites the local clone
(`/tmp/opencode/IDAssist`, HEAD `09dd910d70016c7b3f7e8bc01a4d5bc1035ec302`)
as `path:line`; the lead agent spot-checks citations per chapter. No claim in
these files rests on memory of the README alone.
