# llm-reverse-engineering — complete overview & calxgloss comparison

> **llm-reverse-engineering** ([mjurzak/llm-reverse-engineering](https://github.com/mjurzak/llm-reverse-engineering),
> MIT) is a ~1,700-line Python Streamlit app: a stock LangChain tool-calling
> agent given eight radare2 tools decompiles ELF C/C++ binaries into
> "compilable C" in a chat UI, with session persistence, a
> compile-the-code-block button, crude binary metrics, AI compile-error
> fixing, tool-call flow graphs, a CSmith+Joern-CPG CLI comparison path, and
> the author's own spreadsheet-based evaluation. An AGH student project,
> 13 commits, one author, dormant since 2025-06-13. Reviewed at `aa74f48`;
> see [scope and method](00-scope-and-method.md).

## Executive summary

**LRE is decompilation-as-chat; calxgloss is decompilation-as-factory with a
quality gate.** One human, one binary, one conversation: the model steers 8
radare2 commands (`pdc` pseudocode, function/string/import tables, one
hexdump), and the entire verification story is a Streamlit button that
`gcc -O0`s the extracted code block, prints an ELF-surface scorecard (size
diff, **MD5 equality — a tautological "No"**, string-set stats, first-10k-
byte similarity), then offers an AI fix the human must manually recompile.
calxgloss never lets the model steer: 15 evidence scans pre-compute the
bundle, the LLM translates, and output must survive compile + Wine-captured
baselines + an ordered API-call trace before a human verdict.
([31](31-agent-loop-and-radare2-tool-surface.md),
[32](32-streamlit-ui-recompile-metrics-and-sessions.md),
[40](40-comparison.md))

**The comparison's headline is a mirror-image gap — each project holds
exactly one of the two halves.** LRE has *published whole-tool effect*
(qualitative but real): a 3-tier Polish spreadsheet grading simple →
static-lib → external-lib targets, committed alongside its own failure
exhibits — `print_array` mangled into `putchar` with the LLM's analysis
then "confirming" the fake behavior, a JSON parser stubbed to `return true`
with an invented "SAX" explanation, and two auto-generated READMEs for the
same binary, one accurate and one complete fabrication (XOR crypto,
`-lcrypto`, `-p S3cur3P@ss` for a factorial demo). calxgloss has the hard
unit oracle but has **never published a whole-task number** (roadmap P33,
one fixture DLL). LRE's confounds (−O0, *unstripped* symbols, toy scale)
are not flagged by its author and are flagged here.
([34](34-evaluation-corpus-and-effect.md), [10](10-calxgloss-baseline.md))

**The design degrades exactly along the seams calxgloss's evidence layer
names** — and LRE's own author documented it more candidly than any sibling
study's maintainers: success where symbols + familiar algorithms carry the
model ("Doskonałe przekształcenie"), black-box stubbing + confabulation
where semantics live in external libraries, architecture loss (files
merged to one) as the reported norm. Two structural facts explain most of
it: tool outputs **die at the end of each UI turn** (history replays prose,
not evidence; and the prompt template renders history *after* the current
scratchpad), and one-chat-per-binary with no decomposition
([31](31-agent-loop-and-radare2-tool-surface.md)).

**What LRE genuinely has that calxgloss lacks:** a difficulty-ladder
evaluation corpus (20 examples spanning control flow → data structures →
pthread/sockets/signals → C++ vtables → four CWE-graded vuln demos, plus
three tier projects), a wired **CSmith randomized-program generator**
(the only unbounded-eval idea in the whole sibling family), provider
breadth (Ollama `qwen2.5-coder:7b` vs hardcoded `o4-mini` in one radio
click), an evidence-column XAI prompt, and 233 Docker-Hub pulls of
accessibility. Top steal ideas, in order: (1) the ladder + 3-tier corpus
as P33's design (with behavioral ground truth, stripped *and* unstripped
runs), (2) CSmith→PE randomized corpus with CPG similarity demoted to an
admission-honest screen, (3) a **bound-evidence** explanation table in the
review UI (LRE shipped the shape unbound and got the `putchar`-confirmed-
itself exhibit), (4) the overall/problems/strengths rubric shape rendered
from records, (5) an evidence-flow visualization from `llm_io`. The
anti-steal ledger — MD5 oracles, ELF-surface scorecards, cross-turn
amnesia, silent metric collapse — is catalogued in
[40](40-comparison.md) §6.

**Verdict in one line:** LRE is the *same composition family* as calxgloss
(external analyzer, compiler-as-judge, human final authority, local-model
option, zero LLM-as-judge) minus decomposition, durable evidence, a
behavioral oracle, and mechanical honesty — which makes it the best
available demonstration of what that composition *cannot* do, and its
spreadsheet the cheapest seed for calxgloss's unstarted P33.

## Capability matrix (condensed)

Full 28-row matrix with evidence in [40-comparison](40-comparison.md).
Winner in **bold**.

| Capability domain | LRE | calxgloss | Verdict |
|---|---|---|---|
| Mission / deliverable | chat-run ELF → merged single-file C | PE/DLL directory → verified Rust workspace | different missions |
| Behavioral-equivalence oracle | compile + ELF-surface metrics | Wine baselines + api-trace containment (ADR-0057) | **calxgloss** |
| Whole-task effect measurement | 3-sheet rubric xlsx, published | none (P33) | **LRE** (non-zero vs zero) |
| Evidence depth / analysis engine | 8 r2 commands, `pdc` only | 15 scans + Kuna seam | **calxgloss** |
| Evidence persistence across turns | tool outputs die with the turn | read cache + bundle projection | **calxgloss** |
| Work history / reversibility | chat JSON + `_v{N}` files | attempt branches + justification blocks | **calxgloss** |
| Human review surface | chat verdict | accept/send-back/patch/skip over records | **calxgloss** |
| Corpus for evaluation | 20 + 3 projects + CSmith | one fixture DLL | **LRE** |
| Provider breadth | Ollama + OpenAI | local-only doctrine | **LRE** |
| Cost/token transparency | none | token_usage + llm_io logs | **calxgloss** |
| Metric honesty (empty ≠ zero) | silent drops, 0.0 sentinels | admission-lines doctrine | **calxgloss** |
| Project health | dormant ~17 months, student artifact | living roadmap, 57 ADRs | **calxgloss** |

## Chapters

| # | File | Covers | Status |
|---|------|--------|--------|
| 00 | [scope and method](00-scope-and-method.md) | what is compared, revisions pinned, method, premise correction | ✅ |
| 10 | [calxgloss baseline](10-calxgloss-baseline.md) | the fixed comparison anchor (2026-11-01 facts) | ✅ |
| 20 | [LRE inventory](20-llm-reverse-engineering-inventory.md) | repo layout, LOC map, dependencies, config, Docker, dead scaffolding, committed artifacts, README-claims-vs-code ledger | ✅ |
| 21 | [history and releases](21-history-and-releases.md) | commit timeline, authorship/provenance, account rename, GitHub stats, Docker Hub presence | ✅ |
| 31 | [agent loop & radare2 tool surface](31-agent-loop-and-radare2-tool-surface.md) | prompt, LangChain wiring, history replay, the r2 tool table, analysis modes, project mode | ✅ |
| 32 | [Streamlit UI, recompile, metrics, sessions](32-streamlit-ui-recompile-metrics-and-sessions.md) | chat/session JSON store, extract→compile→metrics→AI-fix loop, README gen, tool-call graphs, XAI table | ✅ |
| 33 | [CLI, CSmith & CPG metrics](33-cli-csmith-cpg-and-metrics.md) | Typer CLI, CSmith loop, Joern CPG similarity (GED/SimRank), binary metrics, oracle analysis | ✅ |
| 34 | [evaluation corpus & effect](34-evaluation-corpus-and-effect.md) | 20-example + 3-project corpus, project_analysis.xlsx, demo_code artifacts, author's published strengths/weaknesses | ✅ |
| 40 | [comparison](40-comparison.md) | whole-project feature matrix (28 rows), philosophy, effect, steal + anti-steal ledgers | ✅ |

## Method

Primary sources: full clone at `aa74f48` (`/tmp/opencode/llm-reverse-engineering`),
entire 1,696-line Python surface read directly by the lead agent, GitHub +
Docker Hub API facts recorded 2026-11-01, every code claim cited
`file:line`. The xlsx corpus was extracted by a sub-agent (stdlib parser)
and spot-verified verbatim by the lead agent. The calxgloss side is fixed
at the [baseline](10-calxgloss-baseline.md). Study method details:
[00-scope-and-method](00-scope-and-method.md).
