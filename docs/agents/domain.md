# Domain Docs

How the engineering skills should use this repo's domain documentation while exploring the codebase.

## Before exploring, read these

- **`GLOSSARY-MAP.md`** at the repo root: it points at one `GLOSSARY.md` per context. Read each one relevant to the topic.
- **`docs/adr/`**: read ADRs that touch the area you're about to work in. Also check `crates/<context>/docs/adr/` for context-scoped decisions.

If any of these files don't exist, **proceed silently**. Don't flag their absence. Don't suggest creating them upfront. The `/domain-modeling` skill (run through `/grill-with-docs` and `/improve-codebase-architecture`) creates them only when terms or decisions actually get resolved.

## File structure

This repo is multi-context (it has `GLOSSARY-MAP.md` at the root). The contexts here are groups of crates within the Cargo workspace:

```
/
├── GLOSSARY-MAP.md
├── docs/adr/                              ← system-wide decisions
└── crates/
    ├── pipeline/
    │   ├── GLOSSARY.md
    │   ├── docs/adr/                      ← context-specific decisions
    │   └── calxgloss-translator/  · verify · testgen · git
    ├── evidence/
    │   ├── GLOSSARY.md
    │   └── calxgloss-analysis/  · callgraph · typeinfer · typesdb · algorithm · memory
    └── ...                                ← integrations · interface · shared
```

## Use the glossary's vocabulary

When your output refers to a domain concept (in an issue title, a refactor proposal, a hypothesis, a test name), use the term as defined in `GLOSSARY.md`. Don't use synonyms that the glossary explicitly avoids.

If the concept you need isn't in the glossary yet, that's a signal: either you're inventing language the project doesn't use (reconsider) or there's a real gap (note it for `/domain-modeling`).

## Flag ADR conflicts

If your output contradicts an existing ADR, say so explicitly instead of silently overriding it:

> _Contradicts ADR-0007 (event-sourced orders), but worth reopening because…_
