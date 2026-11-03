# 32 — llm-reverse-engineering: Streamlit UI, recompile loop, metrics, sessions

> Part of the [overview](README.md). All `file:line` cite `app.py` (670 L) in
> the clone at `aa74f48` unless noted.

## 1. The UI *is* the product

The Streamlit app is where phase-2 (see
[21](21-history-and-releases.md)) put the whole value story: file/dir
picker sidebar, chat loop, session manager, and a set of checkboxes that
each switch one advertised feature — Tool-Call Visualization, Advanced
Details (raw agent JSON), Auto-Generate README, **Explain in Detail** (XAI
table). LLM mode is a radio with **`openai` first/default** (`:324`) — the
Docker flow, not the local model.

Sidebar "Analysis Mode" (Single File / Project Directory, `:334-338`) is a
*target-shape* switch and collides in name with the r2 analysis modes
(quick/standard/deep) — which the UI never surfaces: `"standard"` is
hardcoded at `:371` and `:374`. Users of the product can't even choose
`aaaaa`.

## 2. The extract → compile → metrics → AI-fix loop (the verification story)

When any assistant message contains ` ```c `, the UI renders *Extract and
Compile* (`:476`):

1. **Extract**: concatenate *all* C blocks in the message (`:36-56`) —
   snippet blocks included.
2. **Compile**: `gcc -O0` next to the original binary,
   `{name}_decompiled_v{N}` (`:59-80,491`); `N` is a **session-scoped**
   counter (`:490`, comment says "for this code block" — it isn't).
3. **On success**: append a metrics blob to the chat *and into
   `llm_history` as an AI message* (`:501-504`) — the model can see its own
   scorecard next turn — and, if enabled, run a **README-generation agent
   turn** (tools are still bound but the prompt tells it not to use them,
   `:509-518`), writing `README_{name}_v{N}.md` (`:524-526`).
4. **On failure**: the GCC error is appended **as an AIMessage** (`:540`,
   role-choice oddity — errors enter the model's context as if the model
   said them), and while attempts < 3 (`:542`) an **AI-fix turn** runs with a
   strict "return only corrected code in one ```c block" prompt (`:545`).
   Crucially the fix is *not recompiled automatically* — the human must click
   Extract-and-Compile on the new message. The loop is human-gated, and one
   careless click (no auto-rerecompile) ends the "verification".

This is the closest thing LRE has to an oracle: **does it compile**, plus
step-3 metrics. Compare calxgloss: compile is one third of the gate
(`calxgloss-verify`: scratch cargo project + `cargo check` + behavioral
tests + ordered API-trace containment, ADR-0057). Compile-success-only is
exactly LRE's own demo corpus's failure mode —
`decompiled_chat_output.c` compiles and *differs behaviorally* from the
original (pattern loop moved into `else`, 5-row cap dropped;
[34](34-evaluation-corpus-and-effect.md)).

### The metrics themselves (`generate_metrics`, `:82-136`)

For original binary vs recompiled binary: size difference %, **MD5 equality**,
string-set Jaccard/overlap/coverage, SequenceMatcher ratio of the **first
10k bytes**, plus an `overall_assessment` with thresholds (size within 10%,
Jaccard > 70%, first-10k similarity > 0.7).

Oracle-quality read (mirrors [33](33-cli-csmith-cpg-and-metrics.md) §4): MD5
of two separately compiled binaries is a **tautological "No"** — the tool's
own UI prints it; string sets are dominated by libc/loader noise; the first
10k bytes are ELF headers and interlinker tables. These numbers measure
*ELF surface similarity*, not behavior. The author clearly knew this — the
real evaluation is the manual spreadsheet ([34](34-evaluation-corpus-and-effect.md)) —
but the UI ships these metrics as the visible scorecard.

## 3. XAI "Explain in Detail" (`:582-597`)

Checkbox appends a fixed prompt demanding a markdown table with columns
**Aspect | Explanation | Evidence**, pre-seeded with the aspects
(Decompilation Approach, Key Functions, Data Structures, Control Flow,
Security Considerations) and ordering "each row contains specific evidence
from the binary analysis". A genuinely good idea — *the model must cite*.
But the Evidence column is **unbound**: nothing cross-checks cited snippets
against r2 output or read-cache documents, and the tool has forgotten the
r2 outputs after the turn ([31](31-agent-loop-and-radare2-tool-surface.md)
§1). The corpus shows the failure precisely: after mangling `print_array`
into `putchar`, the LLM's own analysis "confirmed" the fake ASCII semantics
(xlsx sheet 2 — [34](34-evaluation-corpus-and-effect.md)). An evidence
column the model writes from imagination is worse than none.

## 4. Tool-call flow visualization (`:147-204`)

Per assistant turn: `intermediate_steps` → a **linear** `networkx.DiGraph`
(node per call labeled `tool(args)`, edge i−1→i) → graphviz layout → PNG
under `visualizations/` (`:189-198`), stored per message, deleted with the
chat. Simple and honest about order — but linear only: no branching/repeats
beyond sequence, requires **pygraphviz** (`:12`; absent from requirements →
silent `spring_layout` fallback `:183-187`, [20](20-llm-reverse-engineering-inventory.md) §2).

## 5. Sessions (`:236-306`)

Auto-save of the *UI transcript* (messages + `current_file`/`selected_file`
+ viz paths + optional raw agent JSON) to `chat_history/chat_{ts}.json`
after every exchange (`:667-669`); load/delete/list from the sidebar. On
load, `reconstruct_llm_history_from_ui` (`:226-233`) maps *only* user/
assistant dicts back into LangChain messages — **all tool evidence is gone**
(again [31](31-agent-loop-and-radare2-tool-surface.md) §1). The load path
*does* re-initialize the r2 session when the recorded file still exists
(`:427-434`) — a fix the README still lists under "Future Development"
(README claims ledger, [20](20-llm-reverse-engineering-inventory.md) §6).

A session is a **transcript, not a work record**: no per-attempt identity,
no diff, no verdict, no dependency info, no failure archive. Intermediate
artifacts survive only as `*_decompiled_v{N}.c` files and the demo dir's
graveyard of outputs (`decompiled.c`, `decompiled_1.c`,
`decompiled_chat_output.c`, … — [34](34-evaluation-corpus-and-effect.md)).

## 6. Trust-and-safety surface

The UI compiles and *leaves* model-produced binaries next to the user's
inputs (`:493`) and runs `strings`/`file` on them; nothing sandboxed, no
hash-pinning, no "don't run this" posture. (calxgloss has the analogous gap
on its roadmap as P43 — fail-closed sandbox for model output — but its
verify path never *executes* translated code standalone: it runs tests in a
scratch cargo project, and only the *original* DLL executes, under Wine in
testgen.) Also: raw `agent_response_struct` is dumped into session JSON under
Advanced mode (`:639-642`) — good debugging, and a prompt-injection surface
retained in plaintext.

## 7. Comparison with calxgloss

**Overlap** (concept-level): a human review surface over AI output; visible
metrics per attempt; explanation demands; artifact versioning per attempt
(`_v{N}` files ≈ proto-attempt branches); both know prose alone is not
proof — LRE added the compile button *because* the author distrusted the
chat output.

**calxgloss-only**: verdict taxonomy (accept/send-back/patch/skip/batch)
with overlays for steering vs "continue the chat"; patch is a first-class
record (`re/patches/`) vs human pastes code in an editor; diff + attempts +
decomp views per unit; analytics computed from records with honest-empty
rules (ADR-0005); pipeline controls (pause/resume/cancel at unit boundary);
the review UI reads persisted artifacts, so *anything* in it is
cross-checkable, while LRE's chat is the only memory.

**LRE-only**: (1) the **Evidence-column XAI prompt** — calxgloss has no
per-attempt explanation artifact for the reviewer beyond the justification
commit block (attempt N, deps, tests, model, context size — a *factual*
block, not an argument); an Aspect/Explanation/**bound**-Evidence table
rendered from scan records would give reviewers exactly what LRE attempted
unbound. (2) **Per-turn tool/evidence flow graph** — calxgloss's llm_io +
scan provenance could render the honest equivalent for a run. (3) The
metrics JSON *injected into model history* trick — calxgloss already does
the principled version (Tier `WithTests` re-feeds failing-test results into
the next prompt, `context_tier.rs:59-84`).

**Verdict.** The UI is a *review theater with real stakes but weak props*:
it gives the human compile results, a scorecard, and a citation table,
none of which bind to behavior; calxgloss gives the human diff, tests,
trace verdicts, and attempt history, none of which are narrated. Steal list
(this chapter only): #1 bound-evidence explanation table; #2 evidence-flow
graph for runs; #3 keep the `_v{N}` intuition but as branches — LRE's own
demo directory is the cautionary tale that unmanaged attempt files turn into
an archaeology site.

## Sources

Clone `aa74f48`: `app.py` (whole file), README feature list and Future
Development (README.md:23-33,195-204), xlsx citations via
[34](34-evaluation-corpus-and-effect.md) (cells verified verbatim),
calxgloss anchors: `docs/data_flow.md`, `calxgloss-web` routes table in the
[baseline](10-calxgloss-baseline.md).
