# Glossary Map

Calxgloss reverse-engineers target binaries into cross-platform Rust. Each context — a group of crates in the Cargo workspace — keeps its own glossary of domain words.

## Contexts

- [Pipeline](./crates/pipeline/GLOSSARY.md): the translate ▸ verify ▸ retry ▸ commit loop that turns units of work into verified Rust
- [Evidence](./crates/evidence/GLOSSARY.md): the evidence engines that extract facts about target binaries — classification, call graphs, types, algorithms, memory
- [Integrations](./crates/integrations/GLOSSARY.md): the analysis engine and tool mappings — the Kuna analysis engine, local LLMs, prompt templates, Windows-API mappings
- [Interface](./crates/interface/GLOSSARY.md): the human touchpoints where work is run and reviewed — CLI, web review UI, reports
- [Shared](./crates/shared/GLOSSARY.md): the records and settings every context exchanges

## Relationships

- **Pipeline → Evidence**: the pipeline uses classification strategies, evidence confidence, and call-graph orderings to plan translation work and to build prompts
- **Pipeline → Integrations**: the pipeline fetches decompiled context from the analysis engine, translates through the local LLM, and applies prompt templates and PAL mappings
- **Interface → Pipeline**: the review dashboard acts on units of work using the pipeline's verdicts — accept, send back, request patch
- **Evidence → Integrations**: evidence engines read the loaded program
- **All → Shared**: `calxgloss-types` holds the records every context exchanges
- **Pipeline ↔ Evidence (scan scheduling)**: Pipeline owns the schedule-table words — descriptor row, fan-out, cached-hit short-circuit, warn-and-continue. Evidence owns what a row means: scan row name, per-binary document, facets.
- **Evidence → Pipeline (evidence bundle)**: the bundle and its projector seam are Pipeline's words. Evidence's findings pass through them.
- **Parking is Evidence's**: parking is the classification act that keeps a do-not-translate target binary out of work. Shared stores its record; Interface renders it.
- **Bare "engine" is banned**: say *evidence engine* (the fifteen scans, Evidence's word) or *analysis engine* (Kuna at the seam, Integrations' word).
