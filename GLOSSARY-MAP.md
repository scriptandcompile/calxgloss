# Glossary Map

Calxgloss reverse-engineers target binaries into cross-platform Rust. Its domain language lives in one glossary per context; contexts are crate groups within the Cargo workspace.

## Contexts

- [Pipeline](./crates/pipeline/GLOSSARY.md): the translate ▸ verify ▸ retry ▸ commit loop that turns units of work into verified Rust
- [Evidence](./crates/evidence/GLOSSARY.md): engines that extract facts about target binaries — classification, call graphs, types, algorithms, memory *(pending)*
- [Integrations](./crates/integrations/GLOSSARY.md): bridges to external tools and mappings — Ghidra, local LLMs, prompt templates, Windows-API mappings *(pending)*
- [Interface](./crates/interface/GLOSSARY.md): the human touchpoints where work is run and reviewed — CLI, web review UI, reports *(pending)*
- [Shared](./crates/shared/GLOSSARY.md): the records and settings every context exchanges *(pending)*

## Relationships

- **Pipeline → Evidence**: the pipeline consumes classification strategies, evidence confidence, and call-graph orderings to plan and prompt translation
- **Pipeline → Integrations**: the pipeline fetches decompiled context from Ghidra, translates through the local LLM, and applies prompt templates and PAL mappings
- **Interface → Pipeline**: the review dashboard acts on units of work using the pipeline's verdicts — accept, send back, request patch
- **Evidence → Integrations**: evidence engines read the open Ghidra program
- **All → Shared**: `calxgloss-types` carries the records every context exchanges
