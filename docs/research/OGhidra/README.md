# OGhidra — complete overview & calxgloss comparison

> **OGhidra** ([LLNL/OGhidra](https://github.com/LLNL/OGhidra), BSD-3-Clause +
> commercial alternative, LLNL-CODE-2013290) is an LLM↔Ghidra bridge from
> Lawrence Livermore National Laboratory: an agentic Python loop (plan →
> tool-calls → review → replan) drives Ghidra over an HTTP MCP plugin or a
> headless PyGhidra backend, against local Ollama models or external APIs,
> with a RAG knowledge store, a 14-pattern MITRE ATT&CK-tagged malware
> library, bulk renaming, and a benchmark that scores AI-written function
> summaries against reference prose. Its mission overlaps calxgloss's ("LLM
> understands a binary") but its output is *analysis inside Ghidra*, not
> reconstructed Rust. OGhidra reviewed at `6224d26` (branch `main`,
> 2026-10-28); the orchestrator branch at `aa03aa8` (2026-05-08); see
> [scope and method](00-scope-and-method.md).

## Executive summary

**OGhidra is a cockpit; calxgloss is a factory with a quality gate.**
OGhidra puts an analyst (or the model itself) in the driver seat of a *live
Ghidra program*: 31 LLM-callable Ghidra tools (8 of them mutating — renames,
comments) over an unauthenticated HTTP server inside the CodeBrowser, a
plan→execute→review agent loop with a tiered context budget, a vector
store over harvested AI summaries, and one-click bulk rename sweeps.
calxgloss never lets the LLM steer: a fixed pipeline (scan ▸ prompt ▸
translate ▸ verify ▸ retry ▸ commit) feeds it a prepared evidence bundle
and its output must survive compile + Wine-captured baselines + an ordered
API-call trace before a human verdict accepts it. OGhidra optimizes
interactive breadth; calxgloss optimizes unattended reproducibility with
proof.

**The whole comparison hangs on the oracle axis, and OGhidra has none.**
Its stop conditions are model-graded ("GOAL ACHIEVED", completion-marker
words, counters); its security report even invents its own investigation
timeline; and its benchmark — the one place scores could live — has zero
published results, measures prose similarity to *LLM-written* reference
summaries, and no longer imports at HEAD (a `callable | None` annotation
regression from 2026-10-22). calxgloss has the opposite gap: a hard
behavioral oracle chain (ADR-0057) but no whole-task measurement at all
(P33/P42 unstarted). Each misses the other's failure class: OGhidra cannot
detect *wrong*, calxgloss cannot yet detect *quality or closure* (P26).
([32](32-agentic-core-and-context.md), [35](35-benchmark-and-effect.md),
[40](40-comparison.md))

**The study's most transferable lesson is OGhidra's failure mode: machinery
built and wired to itself.** An execution gate that logs "Phase 2 will
truly block" and always continues; an ASK_USER chain unwired on *both*
branches; a flagship smart-buttons panel constructed but never packed into
the GUI; a knowledge graph whose only writer callsite is commented out; a
CAG boot loader that reads a file nothing writes; a coverage tracker that
marks areas covered by echoing the tool's own parameters (`coverage_tracker.py:139`);
and README claims (task_mode CLI, `max_workers`, Docker build, GitHub
Discussions) contradicted by the code. calxgloss's doctrine layer —
coverage honesty (ADR-0053), named unknown records (ADR-0056), capability
reports with admission lines, orphan-deletion (ADR-0008) — is a vaccine
against exactly this pattern. The check for both repos: trust the call
graph, not the README.
([31](31-ghidra-bridge-and-backends.md)–[34](34-ui-cli-bulk-and-reports.md),
[36](36-orchestrator-branch.md))

**What OGhidra genuinely does better** (per the full
[matrix](40-comparison.md)): interactive per-address analysis of a live
program a human is editing; Ghidra's entire format/ISA breadth; semantic
recall over function summaries; an external *detection vocabulary*
(severity × confidence × ATT&CK id × intent × verbatim snippet — 14
patterns, delivered as prompt alerts); attention nudging (coverage
checklist + lead queue re-injected each cycle, born from a named
post-mortem); context craft (age-tiered history with fetch-back pointers);
cost transparency (measured ETA lines, a CLI "~3–8 s per function"
pre-flight estimate); and provider breadth (three client stacks, phase-keyed
model routing). Notably, OGhidra's own maintainers *reverted* their
multi-agent orchestrator from main (+16,969/−4,640 four weeks later) — the
model-authored-control-flow experiment failed on its own terms, which is
independent evidence for calxgloss's ADR-0051 rails.
([33](33-knowledge-rag-and-sessions.md), [34](34-ui-cli-bulk-and-reports.md),
[36](36-orchestrator-branch.md), [21](21-history-and-releases.md))

**Health, stated without gloating**: 465 stars but **3 watchers**; the
author stopped writing code 2026-03-04; 11 of 147 commits are bots; one
PyPI release (`0.0.0`); zero CI on *either* project (OGhidra's test
workflow PR was closed unmerged; calxgloss's gap is P42). OGhidra reads as
a strong lab artifact in upkeep decline; calxgloss as a kept
plan-of-record (57 ADRs, living roadmap) that must earn its own scores.
Top five steal ideas for the restitch mission: ATT&CK-tagged pattern-alert
evidence rows (new, → P30/P51), the branch's address-evidence admission
rule (→ P27), workplans as methodology-as-data (→ P29/P32),
rejection-inclusive run narrative (→ P26/P27), and a corrected
coverage/lead nudge built to ADR-0053 honesty ([40](40-comparison.md)).

## Capability matrix

Winner in **bold**. "—" = absent. Full 33-row matrix with per-cell evidence
in [40-comparison](40-comparison.md).

| Capability domain | OGhidra | calxgloss | Verdict | Ch. |
|---|---|---|---|---|
| Mission / deliverable | analysis inside a live Ghidra project | restitched verified Rust workspace | different missions | 00, 10 |
| Equivalence oracle | none — model-graded stop words | compile + Wine baselines + trace containment (ADR-0057) | **calxgloss** | 32, 35, 36 |
| Effect measurement | benchmark exists, zero scores, broken at HEAD | no harness (P33) | **neither** | 35 |
| Interactive live-program analysis | cursor tools, 8 mutating, human state visible | — by doctrine | **OGhidra** | 31 |
| Human review of AI output | rename lands before any reviewer row exists | accept/send-back/patch/skip verdict surface | **calxgloss** | 34 |
| Work history / reversibility | Ghidra undo only; "cannot be easily undone" | attempt branches per unit, failures kept forever | **calxgloss** | 32, 34 |
| Wiring honesty of shipped machinery | gates/questions/panels built but unwired | coverage-honesty + unknown-records doctrine (ADR-0053/0056) | **calxgloss** | 31, 32, 36 |
| Engine attachment | live Ghidra over HTTP/PyGhidra, zero provenance | in-process seam, identity-keyed cache (ADR-0042/0043/0055) | different purposes | 31 |
| Tool-surface declaration | `dir()`-introspected grab-bag | declared query families + capability report | **calxgloss** | 31 |
| Program-mutation model | LLM mutates the live program, gate off | narrow-only typed write-back (ADR-0020/0021) | **calxgloss** | 31 |
| Evidence depth | regex metadata + harvested LLM prose | 15 scan rows + 3 readers, provenance-stamped | **calxgloss** | 33 |
| Semantic recall over functions | embedding store + Q&A tool | — | **OGhidra** | 33 |
| Detection vocabulary | 14 ATT&CK-tagged malware patterns in prompts | internal only | **OGhidra** | 33 |
| Coverage honesty | "covered" via parameter echo | unknown-never-absent + admission lines | **calxgloss** | 33, 36 |
| Context management craft | age-tiered history + retrieval pointers | 5 tiers, lossless projection rows | **OGhidra** (cleverer); calxgloss never lies about cuts | 32 |
| Token accounting | `len(text)//4` | real provider counts in `llm_io` | **calxgloss** | 32 |
| Fault handling | socket retries + errors-as-strings | named fault monitors + recovery guidance | **calxgloss** | 32 |
| Multi-binary handling | instance port registry; multi-binary work on an open PR | whole `target_dir` + version pairing | **calxgloss** | 31, 10 |
| Bulk throughput + cost meters | real OK/ERR/SKIP/ETA pool; honest ETA estimates | queue + attempts; no ETA surface (P50) | **OGhidra** | 34 |
| Reporting artifact | polished HTML; invented evidence trail | computed-from-records analytics, honest (ADR-0005) | **calxgloss** on honesty, OGhidra on form | 34 |
| Format / ISA breadth | Ghidra's whole loader + Sleigh matrix | PE32/PE32+ x86 only, managed PE parked | **OGhidra** | 31, 10 |
| Multi-agent orchestration | branch experiment, reverted by its own authors | one loop, verdict-routed (ADR-0051) | **calxgloss** | 21, 36 |
| Test posture / CI | 134 tests, no CI ever | workspace tests + fixture e2e, also no CI (P42) | **neither has CI** | 35, 10 |
| Project health | 465★/3 watchers; author left the keyboard 2026-03-04 | solo-maintained; 57 ADRs; living roadmap | different styles | 21, 10 |

## Chapters

| # | File | Covers | Status |
|---|------|--------|--------|
| 00 | [scope and method](00-scope-and-method.md) | what is compared, revisions pinned, method, premise correction | ✅ |
| 10 | [calxgloss baseline](10-calxgloss-baseline.md) | the fixed comparison anchor (re-verified 2026-11-01) | ✅ |
| 20 | [OGhidra inventory](20-oghidra-inventory.md) | repo layout, module map + LOC, dependencies, packaging, Docker, CI, config system, branches map | ✅ |
| 21 | [history and releases](21-history-and-releases.md) | commit history, contributors, releases/PyPI/versioning, research branches, doc-drift ledger | ✅ |
| 31 | [Ghidra bridge & backends](31-ghidra-bridge-and-backends.md) | OGhidraMCP Java extension, http vs PyGhidra backends, 31-tool surface, multi-instance | ✅ |
| 32 | [agentic core & context](32-agentic-core-and-context.md) | bridge.py plan/execute/review loop, execution gate, context budget/compaction, task modes | ✅ |
| 33 | [knowledge, RAG & sessions](33-knowledge-rag-and-sessions.md) | CAG manager, vector store, metadata extractor, malware patterns, sessions/caches, coverage tracker | ✅ |
| 34 | [UI, CLI, bulk & reports](34-ui-cli-bulk-and-reports.md) | Tkinter GUI, smart buttons, interactive CLI, bulk rename/enumeration, security report | ✅ |
| 35 | [benchmark & effect](35-benchmark-and-effect.md) | ground-truth harness, ROUGE/BERTScore/Sentence-BERT/LLM-judge, what is actually measured | ✅ |
| 36 | [orchestrator branch](36-orchestrator-branch.md) | Claude-inspired orchestrator/worker agents, blackboard, recipes, what it changes | ✅ |
| 40 | [comparison](40-comparison.md) | whole-project feature matrix, philosophy, effect, steal ideas | ✅ |

## Method

Primary sources: full clone at the pinned revisions above (`/tmp/opencode/OGhidra`,
plus an `orchestrator` worktree), GitHub API facts recorded 2026-11-01, and
every code claim cited `file:line`. The calxgloss side is fixed at the
[baseline](10-calxgloss-baseline.md). Study method details:
[00-scope-and-method](00-scope-and-method.md).
