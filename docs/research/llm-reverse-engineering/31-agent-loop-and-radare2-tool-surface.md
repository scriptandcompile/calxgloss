# 31 — llm-reverse-engineering: agent loop & radare2 tool surface

> Part of the [overview](README.md). All `file:line` cite the clone at
> `aa74f48`. Companion chapters: [20](20-llm-reverse-engineering-inventory.md)
> (deps/config), [32](32-streamlit-ui-recompile-metrics-and-sessions.md) (UI),
> [33](33-cli-csmith-cpg-and-metrics.md) (CLI).

## 1. The agent is 30 lines of LangChain

`agents/reverse_engineering_agent.py` (140 L, the largest "AI" file) contains
no reasoning machinery at all. Composition:

- **Model selection** (`:20-31`): `llm_type == "local"` →
  `ChatOllama(model=os.getenv("OLLAMA_MODEL","qwen2.5-coder:7b"), base_url
  =…)`; anything else → `ChatOpenAI(model="o4-mini")` — the OpenAI model is
  **hardcoded**; "flexibility" is only local-vs-API plus one env-selected
  local model.
- **One system prompt for every task** (`:33-91`): output contract =
  "complete, compilable C source … + Semantic Analysis (overview, functions,
  algorithms, security)" (`:39-52`); an *ordered analysis recipe* naming the
  real tools (`analyze() → list_functions() → decompile() → search_strings()
  → get_imports()/get_exports()`, `:53-58`); a free-text `ANALYSIS MODE:
  {analysis_mode}` line; a compilation-error-fixing recipe (`:62-67`); README
  generation rules (`:69-76`); anti-verbosity rules (`:78-89`). The same
  prompt serves translation, compile-fix, README, and XAI-explanation turns.
- **Agent wiring** (`:93-129`): LCEL chain
  `dict | ChatPromptTemplate | llm.bind_tools | OpenAIToolsAgentOutputParser`
  → stock `AgentExecutor(verbose=True, return_intermediate_steps=True)`. A
  **new executor is built for every UI turn** (`app.py:622`; the CLI builds
  one per process); the agent object only stores `history`.

### Two wiring quirks that shape every run

1. **Prompt order** (`:95-100`): the template is
   `[system, user {input}, MessagesPlaceholder("agent_scratchpad"),
   MessagesPlaceholder("history")]` — the current turn's tool-call scratchpad
   renders **before** the older conversation. Chronology inverts: the model
   sees this turn's tool results, then last week's chat.
2. **Tool outputs are ephemeral in the UI path.** `update_history`
   (`:131-141`, used only by the CLI) does re-inject `ToolMessage`s; the UI
   instead keeps `llm_history` of Human/AI messages only
   (`app.py:599-600,657`) and reconstructs it dropping everything else
   (`app.py:226-233`). Net effect: **radare2's evidence survives a single
   turn**; the next question the user asks is answered from the model's own
   prose memory of the code, not from the decompiler's bytes. A wrong first
   decompile can never be re-checked without re-running tools — and nothing
   forces that.

Guardrails are LangChain defaults: `max_iterations=15` per invoke, no
timeout, no cost accounting, errors surface as one UI string
(`app.py:659-665`). There is no stop condition beyond the model deciding.

## 2. The radare2 tool surface — 8(+2) commands

`tools/radare2_tools.py` (363 L) wraps one `r2pipe` session (`:52,:62`) and
registers tools at `:125-195`:

| Tool | r2 command(s) | Notes |
|---|---|---|
| `analyze` | `aaa`/`aaaa`/`aaaaa` by mode (`:133-138`) | README claims `aaa`; UI hardcodes `standard`= `aaaa`; a *state-changing* tool the model must remember to call first |
| `list_functions` | `aflj` (+`~main/~imp/~exp/~sym` greps, `:215-224`); by default filters to "used" functions via per-function `axtj`+`axfj` (N×2 queries, `:230-250`); sorts by size desc, cap 50 | returns name/size/type/address/is_used |
| `decompile` | `pdc @ {name}` (`:291`) | radare2 **microcode pseudo-C** — not r2ghidra/r2dec; unbounded output, no chunking |
| `search_strings` | `izj` raw JSON (`:306`) | full list, no cap — blows context on real binaries |
| `get_imports` / `get_exports` | `iij` / `iEj` (`:318,:330`) | raw lists |
| `read_memory` | `px {size} @ {addr}` (`:342`) | hexdump passthrough |
| `close` | `r2.quit()` (`:357`) | — |
| project mode only: `list_project_files`, `analyze_project_file` | dir scan via `file` output (`:35-43`), opens first `main`/`app`/`program`-named binary (`:49-52`); per-file `aaaa`+`ij` in a throwaway second r2 instance (`:163-166`) | see §4 |

Two implemented-but-unregistered methods — `get_call_graph` (`:95-114`,
per-function `axtj`) and `get_binary_info` (`:116-123`, `ij`) — are **dead
code** (`:177-195` omits them; grep confirms no callers). The author built a
call-graph capability and then left it off the tool table.

### What the LLM can never ask

No raw disassembly (`pdf`/`pd`) — if `pdc` fails on a function (common for
optimize/odd code; corpus here is `-O0` so it mostly works), the model has no
fallback view. No CFG, no xrefs outside `list_functions`' internal filter,
no type application (`afvt`), no struct building, no data-flow, no demangling
control, no relocator/binary-info beyond the dead method. The surface is
*read-only over radare2's high-level tables* plus one pseudocode printer.

## 3. What the agent actually does (loop semantics)

One user turn = one `AgentExecutor.invoke({input, history})`: model picks
tools ReAct-style, observations enter the scratchpad, final text is returned
as markdown; extraction of "the decompiled program" is **regex on ```c
fences** (`main.py`→`code_generator.py:56-63` takes the *first* block; the UI
extractor `app.py:36-56` *concatenates all* blocks — inconsistent, and any
snippet-style code block in prose pollutes the build). Nothing is verified
inside the loop; correctness work happens *outside*, in the UI's compile
button ([32](32-streamlit-ui-recompile-metrics-and-sessions.md)) or the CLI's
metrics ([33](33-cli-csmith-cpg-and-metrics.md)).

The whole-binary-per-conversation design means **no decomposition**: one chat
session is expected to reconstruct an entire program; queueing, per-function
units, and translation order simply don't exist. `demo_code/chat_output.md`
shows the failure mode at *toy* scale: the model mis-reads the original's
5-row loop cap and invents a two-phase pattern while "explaining" it.

Scale, from the one logged full run (`testing/1.log`, 431 KB, read directly):
**263 LLM calls and 1,024 tool executions for a single binary**, total cost
1.41 USD, 581,575,541 tokens processed across the session against only
2,920,128 recorded prompt+completion tokens — the gap is the cost of replaying
a growing message history at every step (this session kept only prose history,
§1; the tool outputs were dropped). calxgloss's queue + compact context
exists precisely to bound that line item.

## 4. Project-directory mode (thin)

Introduced late (`6c4da60`) for the xlsx's multi-binary projects: the scan
keys on the Unix `file` tool saying elf/executable/object/shared (fragile;
breaks in the Docker image where `file` isn't installed —
[20](20-llm-reverse-engineering-inventory.md) §4), and **all decompile/
search tools still talk to the single primary r2 session** (`:52`);
`analyze_project_file` only yields `ij` info of one other file at a time.
A 4-binary project is analyzed as 1 binary + N info calls — the agent can
*discover* architecture but not *decompile* any of it separately. The
xlsx's "merged files into one" complaint
([34](34-evaluation-corpus-and-effect.md)) is partly a *tool-surface*
limitation, not only a model tendency.

## 5. Comparison with calxgloss

**Overlap.** Both agree the LLM should work through structured binary facts
(function listings, pseudo-C, imports/strings), both treat prompt/tool
coherence as important (LRE's recipe names its real tools; calxgloss's
capability report declares what its queries can answer), both prefer cheap
retries over caution (LRE: rerun the chat; calxgloss: ADR-0051 strategy
ladder), and both put a human decision gate after generation (chat verdict vs
review verdict).

**calxgloss-only.** Everything that makes evidence *durable and sufficient*:
15 scans + 3 readers vs 8 shallow commands (no types, no call graph exposed,
no data structures, no error-handling/concurrency/serialization evidence at
all); the **scan read cache + tiered context (5 tiers)** vs history replay
that *forgets tool outputs after one turn*; unit-of-work decomposition +
call-graph-ordered queue vs one chat per binary; named fault monitors vs
LangChain defaults; token/prompt/IO logging vs nothing; attempt-branch
history vs a chat transcript; seam capability report vs "whatever r2pipe
returns". Most fundamentally: calxgloss's LLM *never steers analysis* (the
pipeline pre-computes the bundle; ADR-0051), while LRE's LLM chooses which
of 8 commands to fire and whether the recipe was followed — an agency calxgloss
deliberately removed after seeing what it costs.

**LRE-only.** (a) Provider breadth — `o4-mini` API and Ollama side-by-side,
with cloud-class reasoning available in one radio click; calxgloss is
local-only by doctrine. (b) An actual **tool-call flow visualization** per
turn (see [32](32-streamlit-ui-recompile-metrics-and-sessions.md)). (c)
Model *self-organizing* analysis: nothing pre-computes evidence, so on an
easy target the whole cost is what the model chose to ask — worth admiring
only in the sense that the fixed pipeline pays 15 scans up front. In practice
LRE pays it back: `list_functions` alone fires 2N r2 queries per call
(`:230-250`) and repeated turns re-run tools (outputs forgotten), so
"adaptive" analysis here is *less* economical, not more.

**Verdict.** This axis is a study in what calxgloss's evidence layer is for.
LRE demonstrates the *ceiling of the thin-evidence design*: pdc-only
pseudocode + tables + strings, on `-O0` unstripped toys, at 50–300 LOC — and
the xlsx results ([34](34-evaluation-corpus-and-effect.md)) degrade exactly
where calxgloss's scans exist (types/print semantics/library behavior). The
one idea worth taking is (b), visualizing evidence flow — calxgloss already
has the records (`llm_io`, scan provenance) to render an honest version.
The anti-pattern to document: cross-turn amnesia of tool outputs — a reason
calxgloss's read cache and bundle projection exist.

## Sources

Clone `aa74f48`: `agents/reverse_engineering_agent.py`,
`tools/radare2_tools.py`, `app.py:226-233,622`, `main.py:99-105`,
`demo_code/chat_output.md`; grep sweeps for dead methods (`:95,:116`).
