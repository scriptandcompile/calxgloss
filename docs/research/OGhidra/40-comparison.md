# OGhidra ↔ calxgloss — whole-project comparison

> Part of the [OGhidra overview](README.md). Capstone of the study: the
> feature & effect matrix, the philosophy contrast, and the aggregated steal
> ledger. The evidence lives in the domain chapters — [20](20-oghidra-inventory.md)
> (inventory), [21](21-history-and-releases.md) (history),
> [31](31-ghidra-bridge-and-backends.md) (bridge/seam),
> [32](32-agentic-core-and-context.md) (*agentic loop*),
> [33](33-knowledge-rag-and-sessions.md) (knowledge/CAG),
> [34](34-ui-cli-bulk-and-reports.md) (human surface),
> [35](35-benchmark-and-effect.md) (benchmark/effect),
> [36](36-orchestrator-branch.md) (orchestrator branch) — and this file
> deliberately re-derives nothing; it stitches. Where a load-bearing number
> was re-verified for this chapter, that is marked. The calxgloss side is
> the fixed [10 baseline](10-calxgloss-baseline.md); roadmap P-numbers cite
> `docs/roadmap.md`. Revisions: OGhidra `main` @ `6224d26` (2026-10-28) and
> `origin/orchestrator` @ `aa03aa8` (2026-05-08); GitHub/PyPI facts recorded
> 2026-11-01.

One-sentence identities, established in [00](00-scope-and-method.md) and
argued across the chapters: **OGhidra makes an LLM a diligent analyst inside
a human's live Ghidra program**; **calxgloss makes the binary a verified
record and the machine verdict the stop condition**. Everything below is a
consequence of that difference, and neither sentence is a joke at the other's
expense: OGhidra attempts the harder interaction (free-form exploration of a
mutable program) with no way to know when it is wrong; calxgloss attempts the
harder completion (binary → working Rust) with a fixed pipeline that can
check itself but cannot roam.

## Feature & effect matrix

Verdict marks which side's machinery actually closes the capability domain;
"—" means absent, not merely thin. Ch. column points at the chapter that
establishes the cells (20 = inventory, 21 = history). Re-counted for this
chapter: test-function count (**134**, `grep -c 'def test_' tests/*.py` in
the clone — [20 §4](20-oghidra-inventory.md) is right;
[35 §6](35-benchmark-and-effect.md)'s "138" is a miscount) and the malware
pattern registry (**14** patterns in `PATTERNS`, `src/cag/malware_patterns.py:532-547`
re-read — the "12+" of [00](00-scope-and-method.md)/[20 §2.9](20-oghidra-inventory.md)
is a floor, [33 §8](33-knowledge-rag-and-sessions.md)'s 14 is exact).

| Capability domain | OGhidra | calxgloss | Verdict | Ch. |
|---|---|---|---|---|
| Mission / deliverable | analysis *inside* the Ghidra project: renames, comments, findings, LLM-written report | restitched Rust workspace with identical observable behavior | **calxgloss** (different mission; OGhidra never claims "back to source") | 00, 10 |
| Equivalence oracle — "did it work?" | none: stop conditions are model-graded ("GOAL ACHIEVED", *task-mode* completion markers, counters) | compile + Wine-captured baselines + ordered API-call trace containment (ADR-0057) | **calxgloss** | 32, 35, 36 |
| Effect measurement | benchmark package exists; zero published scores; does not import at HEAD | no eval harness; roadmap P33 unstarted | **neither** — OGhidra has shape, calxgloss has honesty-of-intent | 35 |
| Ground-truth source | LLM prose summarizing source (`llm_source_summary`); name axis = exact string equality | behavioral baselines captured by executing the original under Wine + human facts | **calxgloss** | 35, 10 |
| Interactive analysis of a live program | yes — cursor tools, unsaved human state visible to the LLM, 8 mutating tools | — (by doctrine: the LLM never sees or touches a human session) | **OGhidra** | 31 |
| Human review of AI output | rename lands in the live program before any reviewer row exists; no verdict object; undo lives in Ghidra | accept / send-back / patch / skip web verdict surface before anything becomes recorded truth | **calxgloss** | 34 |
| Work history / reversibility | no attempt record of its own; sessions + Ghidra undo only; "cannot be easily undone" (its own dialog) | every unit of work = commit on attempt branch `re/{binary}/{function}v{N}`, failures kept forever | **calxgloss** | 32, 34 |
| Wiring honesty of shipped machinery | gates fire but never stop ("Phase 2 will truly block"); orphaned 381-LOC builder; UI callbacks never assigned; flagship button panel never packed | wiring doctrine (ADR-0053/0056), capability reports per query family, orphan deletion (ADR-0008) | **calxgloss** | 31, 32, 36 |
| Engine attachment model | attach to the analyst's running Ghidra (HTTP plugin, pyghidra backend) — live context for free, zero provenance | Kuna in-process against a disposable loaded program, re-loadable from binary + engine + records | **different**: OGhidra for interactivity, **calxgloss** for reproducibility | 31 |
| Tool-surface declaration | `dir()`-introspected grab-bag, `**params` splat, prose tool docs that drift | seam answers only declared query families; capability report + admission lines (ADR-0054/0055) | **calxgloss** | 31 |
| Per-import call-site enrichment | fork adds `[Refs: N] [Callers: ≤5]` per import row (`GhidraMCPPlugin.java:515-561`) | — at that granularity | **OGhidra** | 31 |
| Read-cache discipline | keyless process dicts; GUI cursor pinned to first read; `clear_cache` never called; no identity in key | identity-keyed durable cache: binary SHA-256 + format version + engine-build identity (ADR-0042/0043/0055) | **calxgloss** | 31 |
| Program-mutation model | LLM holds 8 mutating tools over the live program (2 "risky" ones gated, off by default); human edits the same object | only writer is typed scan-record write-back: narrow-only, confidence-floored, never over a hand-typed slot (ADR-0020/0021) | **calxgloss** | 31 |
| Security / network surface | wildcard-bind no-auth HTTP server inside Ghidra + outward FastMCP proxy with `safe_get`/`safe_post` escape hatches | zero network surface by construction (in-process seam); confinement of local runs still open (P43) | **calxgloss** | 31 |
| Provider layer | three LLM client stacks (Ollama / Gemini-first / OpenAI-compatible) + per-phase model routing + throttle knobs | one OpenAI-compatible client over local Ollama/vLLM; phase-keyed routing is a steal below | **OGhidra** (breadth); calxgloss's local-model premise is deliberate | 32, 10 |
| Ask-the-user escalation | `ASK_USER:` designed both trees; main's pause is cleared with "log and continue", the branch's whole chain ships unwired | — (no loop-level escalation needed: the human answers at the verdict surface) | **neither** (OGhidra's is worse than none — it advertises) | 32, 36 |
| Multi-binary handling | multi-instance registry (`/program` identity, port-probing) with multi-binary session work still on an open branch/PR #46 | whole `target_dir` of binaries is the input; per-binary identity records + version pairing | **calxgloss** | 31, 10 |
| Context management craft | tiered history + `get_cached_result` retrieval escape hatch + keyword-priority compaction preserving `[Total:]` | 5 context tiers, evidence bundle as sole render input, lossless-by-construction projection rows (ADR-0048/0049) | **OGhidra** (manages context more cleverly; calxgloss never lies about what was cut) | 32 |
| Token accounting | `len(text)//4` fiction drives budgets | real counts from provider logs in `llm_io` | **calxgloss** | 32 |
| Fault handling | socket retries + errors-as-strings into the next prompt; doom-loop detector whose brake is unwired | fault monitors end an attempt on named signatures (overflow, hallucination, divergence…) with recovery guidance | **calxgloss** | 32 |
| Semantic recall over functions | embedding store + `search_function_summaries` Q&A tool the model calls; persisted via session files | — (record tree answers "what was proven", no similarity query) | **OGhidra** | 33 |
| Detection vocabulary | 14-pattern malware library: severity × category × ATT&CK id × intent × matched 50-char snippet, delivered as prompt *pattern alerts* | algorithm-recognition scan has no public vocabulary anywhere (findings stay internal, ADR-0044 posture) | **OGhidra** | 33 |
| Coverage honesty | 8-area checklist marked by matching the tool's own **parameters** (`coverage_tracker.py:139`) — attempted-but-empty renders as covered | coverage stamped per scan, admission lines, "unknown, never absent" (ADR-0053), named unknown records (P21/ADR-0056) | **calxgloss** | 33, 36 |
| Attention nudging | coverage checklist + lead queue re-injected every cycle (born from a named post-mortem) | — (pipeline needs no attention nudge; an interactive calxgloss would) | **OGhidra** | 33 |
| Persistence discipline | right anchor (binary SHA-256 session gate), wrong payload (harvested prose, decorative `ai_confidence`); three non-interoperating stores; CAG loader/writer disagree on filenames | one record tree under `re/`, per-engine persistors, crash-replay from identity-keyed records | **calxgloss** | 33 |
| Bulk throughput plumbing | real: daemon pool, `as_completed` OK/ERR/SKIP/ETA accounting, skip-analyzed resume, auto-save checkpoints | run status + attempt ledger; no ETA/count surface of this shape | **OGhidra** | 34 |
| Cost control | no budget anywhere in bulk path; "configurable" worker count is the literal `max_workers = 5` (`tool_buttons_panel.py:1595`); one dial is a per-client sleep | operator cap on the ladder, stop routing on the verdict; per-attempt cost metering planned (P50) | **calxgloss** | 34 |
| Cost transparency | honest meters: measured ETA lines, CLI "~3–8 s per function" pre-estimate | — (queue UI shows no ETA/price; P50's pre-run estimate is the roadmap answer) | **OGhidra** | 34 |
| Reporting artifact | polished single-file HTML + severity badges — but 7 unbounded LLM calls and an *invented* investigation timeline | `calxgloss-reports` prints, computes analytics from records on demand (ADR-0005); JSON output still P52 | **calxgloss** on honesty, OGhidra on form — combine: **calxgloss** | 34 |
| Format / ISA breadth | inherits Ghidra's entire loader + Sleigh matrix, zero bridge-specific work | PE32/PE32+ x86 native Windows only; managed PEs parked (ADR-0044) | **OGhidra** | 31, 10 |
| Evidence depth | regex metadata with keyword-hit labels + harvested LLM prose | 15 evidence-scan rows + 3 readers, provenance-stamped records, confidence by evidence (P51 planned) | **calxgloss** | 33 |
| Test posture | 134 unittest-style test functions; zero CI (test-workflow PR #50 closed unmerged); zero tests over benchmark or CAG | workspace tests + fixture-DLL e2e, all run by hand; **also no CI at all** (P42) | **neither has CI** — calxgloss runs its suite locally; OGhidra's runs nobody-knows-when | 35, 10 |
| Project health / maintenance | 465★/50 forks/3 **watchers**; author stopped coding 2026-03-04; last push 2026-10-28; 12 remote branches incl. a 44,742-line rewrite (`dspy-plugin-vibes`, PR #63); PyPI single release `0.0.0` from the tag on the release-workflow commit | solo-maintained, 57 ADRs, living roadmap, no CI either | **different styles** — lab handoff vs kept plan-of-record; no gloating | 21, 10 |
| Session / state staleness | restore gated by binary SHA-256 + streaming >10 MB loader; but no invalidation story inside a session | cache identity keys; per-unit staleness by content hash still open (P47) | **calxgloss** (and steal the SHA-256 gate) | 33 |
| Multi-agent orchestration | orchestrator branch: 13 worker classes, model-authored next task, marker-word completion, four counters as stops — reverted on main (`d5dec8a` +16,969/−4,640 → `c62ec6e`; branch 0 ahead / 39 behind) | one loop, verdict-routed (ADR-0051); no model-authored control flow | **calxgloss** — and OGhidra's own maintainers agree (they reverted it) | 21, 36 |
| Working-memory admission rule | branch notebook: no address evidence, no entry (`orchestrator.py:1681-1685`) | records carry readable addresses by construction | **tie** — the branch rule is the closest external statement of calxgloss's own doctrine | 36 |

## Philosophy

### The oracle axis — where the whole comparison hangs

OGhidra has **no equivalence oracle anywhere** — not in the product, not in
the benchmark, not on the branch. The product stops when the model says so:
the evaluation phase parses a "GOAL ACHIEVED" self-verdict, the execution
loop gates on FINAL-RESPONSE regexes, and the orchestrator branch stops on
`COMPLETION_MARKERS = ("INVESTIGATION COMPLETE", "TASK COMPLETE", "GOAL
ACHIEVED")` (`src/agents/worker_agent.py:78`) plus four counters over the
model's own bookkeeping (ch. 32 §6–7, ch. 36 §4/§6). The benchmark, the one
artifact built to *measure*, scores against `llm_source_summary` — another
model's paraphrase of the source — with its name axis on exact string
equality, and at HEAD it does not even import: three lowercase-`callable`
annotations crash `import benchmark` on the project's own required Python
3.12 (`ground_truth/summary_generator.py:149`,
`runners/benchmark_runner.py:153`, `runners/oghidra_runner.py:238`;
re-verified, ch. 35 §4). Its LLM judge has never loaded once — a renamed
attribute behind a swallowed `AttributeError` (`evaluator.py:120/:155/:159/:162`)
— and a judge that *did* run would fabricate fake 3/5 scores on parse
failure. Not one score has ever been published or committed (ch. 35 §5).

calxgloss has the **full behavioral oracle and no text-quality eval**:
compile, Wine-captured baselines, ordered-trace containment (ADR-0057), with
zero model-graded judgment on any decision path. Each side misses a failure
class the other's machinery would catch: OGhidra's loop cannot fail in a way
that falsifies a wrong answer — it misses *wrongness* (a rename that sounds
right is forever); calxgloss's gate says nothing about whether a merged
name/summary reads well or whether a whole binary is done (P26/P33 open) —
it misses *quality and closure*. The matrix rows above resolve every domain
against these two blind spots.

### The wiring-honesty axis

OGhidra ships detectors with the brake cut: the execution gate triggers,
emits, logs "🚧 Pre-execution gate paused loop", and executes anyway —
`# Phase 1: Log and continue (Phase 2 will truly block)`
(`src/bridge.py:3090-3093`, re-read for this chapter);
`_ui_gate_callback`/`_ui_question_callback` are never assigned;
`IntelligentContextBuilder` is 381 LOC with zero importers; all four
`_add_function_to_rag` callsites are commented out, so the function graph is
always empty; the CAG loader wants `documents.json` while the only writer
emits `metadata.json` (ch. 33 §2); a coverage ✅ can be manufactured by a
tool call mentioning its own search term (`coverage_tracker.py:139`,
re-read); the RAG-vector counter tallies the commented-out calls with a
`time.sleep(0.1)` fake-progress loop; the Stop flag is written three times
and read zero. README promises coexist with features that cannot run —
GitHub Discussions is linked but switched off, the Dockerfile clones a
deleted branch, and issue #16 ("how does analysis with OGhidra compare to
analysis without?") sits unanswered as of 2026-11-01.

calxgloss's doctrine is precisely an inoculation against this list:
capability is live session state declared per query family (ADR-0054/0055),
absent coverage reads as unknown-never-absent (ADR-0053), admitted gaps are
named records (P21/ADR-0056), orphans are deleted not parked (ADR-0008),
and the plain-English sweep that produced P40–P41 exists because the project
treats "docs promise, code delivers" as an auditable obligation. The sharpest
single lesson from the losing side, from ch. 36: **an unwired escalation
feature is worse than none, because it makes the README able to lie.**

### The evidence axis — records vs prose, with one honest exception

The chapters sort OGhidra's knowledge artifacts into three kinds of wildly
different honesty (ch. 33 §Evidence quality): **regex metadata** —
deterministic but keyword-hit labels ("crypto" because a word matched), no
evidence pointers, no persistence outside panel rows; **harvested AI prose**
— 150-char extracts of the model's own reasoning with a literal
`"Analysis performed"` fallback, embedded verbatim into the knowledge base
of record; and **pattern alerts** — the one artifact with real provenance,
where every indicator is the actual matched 50-char snippet and the
confidence is computed (crude, but arithmetic). Structurally that last kind
*is* a calxgloss *scan* with evidence attached — which is why steal #1 is a
render shape, not new machinery. calxgloss's side of the axis is uniform by
design: every evidence-engine output is a typed, provenance-stamped *scan*
record with a coverage stamp and an admission line, resolved by strongest
evidence (ADR-0022–0025/0053). The axis predicts the rest of the comparison:
where OGhidra was prose, it drifted (sessions, reports, the benchmark corpus
— all three chapters found the same laundering); where it was a record, it
still rots without identity (the CAG loader/writer filename mismatch,
`documents.json` vs `metadata.json`).

### The scale & health axis — contrast without gloating

OGhidra: 147 commits on `main` (re-counted: `git rev-list --count main` =
147), 465 stars / 50 forks / **3 watchers** (GitHub API, 2026-11-01) —
attention outruns care by two orders of magnitude. The creator stopped
committing code 2026-03-04; the repo then ran on PR discipline, bot
hygiene, and one revert incident; four months of 4/3/1/2 commits against a
growing community queue (ch. 21 §1/§6). PyPI holds a single `0.0.0` release
born of VCS versioning pointed at the only tag, which itself names the
release-workflow commit (ch. 21 §5). **calxgloss shares the headline
symptom — no CI at all** (P42 sits in its own roadmap) — so the contrast is
about maintenance *style*, not health: OGhidra's knowledge lives in branches
+ open PRs + an off-GitHub founder's head, with a rewrite (`dspy-plugin-vibes`,
44,742 lines deleted, PR #63 open) that may void this whole study's maps
overnight; calxgloss's lives in 57 ADRs, per-context glossaries, and a
roadmap where every known gap is a named P. A lab artifact mid-handoff vs a
kept plan-of-record: both are honest about different things.

### Symmetric inventories

**calxgloss has that OGhidra does not:** machine verdicts; the attempt seam
with git-backed branches and re-playable failures; a durable record tree
with identity keys, coverage stamps, admission lines, and named unknowns;
15 evidence-engine scan rows on a disposable program; a capability-declared
seam with a compile-time read/write split; the verification gate between
model output and record; PAL mapping DB + generated shims; cost caps and
real token accounting; human verdicts *before* mutation.

**OGhidra has that calxgloss does not:** free-form LLM exploration of a live
mutable program; the analyst's cursor and unsaved state as context; semantic
recall over function descriptions the model can query; an ATT&CK-tagged
detection vocabulary with evidence snippets; coverage/lead attention nudges;
session save/restore UX with a binary-hash gate; bulk-throughput meters
(ETA, cache hit-rate); a polished report *form*; Ghidra's entire format/ISA
breadth; per-phase model routing and a throttled API client; *workplan*
playbooks as data.

## Where each is stronger

**OGhidra is stronger at**: interaction (cursor-coupled live analysis,
multi-instance registry, `/program` identity — irreplaceable for interactive
work, ch. 31); *context craft* (tiered history with retrieval pointers,
result compaction that preserves `[Total:]` headers, per-phase model maps —
ch. 32's verdict stands: it manages context more cleverly than calxgloss
manages prompt assembly); *recognition vocabulary* (the pattern-alert
render shape and ATT&CK tags, ch. 33 §8); throughput plumbing and honest
effort meters (ETA/cache arithmetic, ch. 34); breadth by inheritance
(everything Ghidra loads); and, on the branch, three genuine deterministic
escapes inside the agentic loop — recipes, correlation hooks, and the
notebook admission test (ch. 36).

**calxgloss is stronger at**: everything downstream of "is this true" —
verdicts, records, ledgers, reversibility, coverage honesty, cache identity,
seam declaration; at *knowing when to stop and whether to believe itself*
(ch. 32's verdict, mirrored by ch. 35's: OGhidra "never can"); at depth on
one shape (15 scans, no Ghidra tool list reaches); at completion vocabulary
(unknowns with names where OGhidra has areas/8); and at intent-to-code
fidelity (every ADR-verified promise audited by the sweep that produced
P40–P41).

The honest summary is ch. 32's sentence inverted onto itself: OGhidra is
rich where it counts least — freedom to roam with no check — and calxgloss
is rich where it counts most, yet OGhidra's *steals* are real because they
cluster in exactly the domains calxgloss's roadmap already admits are open.

**Both are weak in the same places**, and the study's method — measuring
both sides, not comparing PRs — found four shared weaknesses worth naming
before any victor is declared. **Neither has CI**: OGhidra's sole workflow
is release-only and its test-workflow PR #50 died unmerged (ch. 20 §8, 21
§6); calxgloss has no `.github/` at all and puts that fact on its own
roadmap as P42 (ch. 10 §Known gaps). **Neither ships a multi-binary truth
corpus**: calxgloss has one source-built fixture DLL; OGhidra tells users
to bring their own and documents a run against a `corpora/test_corpus`
directory that does not exist (ch. 35 §2). **Both premise local models** —
"asking again is the normal path" is calxgloss doctrine and OGhidra's README
recommends models by RAM (ch. 35 §7) — so both live with the same
quality ceiling. **Both run one engine call at a time** by deliberate
design: one JDK dispatch thread vs one Kuna engine thread — convergence,
not coincidence; a Ghidra-shaped mutable program forces it (ch. 31 §transport).
The difference is what each weakness costs: OGhidra's no-CI killed its
benchmark silently at HEAD; calxgloss's no-CI is a named, ranked track
whose first job is a build/clippy/test/e2e gate that already exists as a
local ritual.

## Steal ideas

Aggregated from all six domain chapters, merged and deduped (several
chapters independently converged on the same idea; source spans carried
from the chapter that measured them). Ranked by movement per unit of work.
"Duplicates" = already covered by an existing roadmap track; **NEW** = not
on the roadmap yet.

| # | Idea (one line) | Lands in | Duplicates / NEW | Source (file:line from chapter) |
|---|---|---|---|---|
| 1 | **Pattern-alert evidence format**: severity × confidence × public tag × intent × verbatim matched snippet — plus a real ATT&CK-style tag vocabulary — as the render shape for algorithm/libray/string-context scan rows into translate prompts | evidence rows → prompt rendering; feeds **P30** and **P51** | **NEW** (no public output vocabulary anywhere) | 33 §8: `malware_patterns.py:598-603, 748-765` |
| 2 | **Address-evidence admission rule**: no finding/hypothesis recorded without an address the engine can re-read — every P27 entry names its offsets | **P27** hypothesis ledger | strengthens P27 | 36: `orchestrator.py:1681-1685` (re-read) |
| 3 | **Workplan / task-mode playbooks as prose methodology** (DISCOVER→LOCATE→TRACE→VERIFY, limit≤20, vuln checklists) — data, not code | **P29** ad-hoc queries; **P32** skill recipes | folds into P29/P32 | 32: `config.py:775-799`, `cag/workplans/*.md` (6 files, 576 lines) |
| 4 | **Rejection-inclusive run narrative**: rejected attempts + reasons logged/flushed beside accepted ones, as queryable records | **P27** + **P26** obligation ledger | duplicates (P27 wants exactly this shape, as records) | 36: `orchestrator_logger.py:1-16` |
| 5 | **Age-tiered history with retrieval pointers**: full this attempt, summary last attempt, one-line + record-id older — drops staleness, keeps every byte fetchable from attempt records | llm_io/prompt context for the retry loop | **NEW** | 32: `context_manager.py:614-654` + step-id sidecar |
| 6 | **Semantic function memory** keyed `(name, binary_hash, function_hash)` over the record tree's own evidence-grounded descriptions, P51 confidence attached — cross-run "which function is like X", never embedding unverified prose | new query layer on **P51**'s confidence | **NEW** (confidence half = P51) | 33: `models/memory.py` LRU, §7/§10 |
| 7 | **Coverage/lead attention nudge, fixed to ADR-0053**: mark areas only from the result payload; render "searched, found nothing" ≠ "found" ≠ "not searched"; feed from the coverage ledger so areas map to function sets; adopt `encountered` vs `analyzed` depth, never assignment-by-tool-class | coverage ledger (ADR-0053) extension + loop prompt section | **NEW** (nudging absent from roadmap; honesty half already doctrine) | 33 §11: `coverage_tracker.py:139`; 36: `coverage_tracker.py:37-47, 238-247` |
| 8 | **Bulk-loop posture + cost meters**: `as_completed` [OK]/[ERR]/[SKIP]/[ETA] accounting, per-item failure isolation, auto-save checkpoint; the "~3–8 s per function" pre-flight estimate before each batch | run status + **P50** pre-run estimate + **P52** JSON surface | folds into P50/P52 | 34: `tool_buttons_panel.py:1595` region, `main.py` estimate (~:695) |
| 9 | **Enumeration-mode filters**: thunk / import-stub / CRT / generic-prefix / keyword filters as tunable scan-queue filters; hardcoded-workflow recipes as P32 skill commands | queue filters + **P32** | filter half **NEW**; recipe half P32 | 34: `tool_buttons_panel.py:656-736, 757-778` |
| 10 | **Seam enrichment cluster**: `[Refs: N] [Callers: ≤5]` per-import rows; absolute-total pagination header + "compaction never eats it" invariant; one `read_bytes` tool with hard 1–4096 clamp; external-symbol→function→any-symbol xref fallback ladder; versioned probe handshake at seam open | seam query primitives (P28/P29-shaped) + **P46** identity handshake + **P52** caps | partial duplicates | 31: `GhidraMCPPlugin.java:515-561, 1525-1549, 1768-1802`, `result_compactor.py:91` |
| 11 | **Session-restore binary-SHA-256 gate**: opening any record tree against a re-fetched binary refuses when the hash moved (+ the >10 MB streaming JSON loader idiom) | record-tree open discipline (P44/P47-adjacent) | **NEW** | 33: `enhanced_session_manager.py:112-119, 520-628` |
| 12 | **Doom-loop / artifact *detection* as fault-monitor signals**: 3-identical-call signatures beside `infinite_loop.rs`, detect-and-log first | fault monitors (calxgloss-llm) | **NEW** signal (monitors exist, signals don't) | 32: `execution_gate.py:61-84`, `bridge.py:483-485` comment |
| 13 | **Phase-keyed `model_map` + `throttle_state` telemetry**: config-level routing (cheaper model for digest calls) and Retry-After-aware pacing for shared local-model deployments | `calxgloss-llm` / config | **NEW** | 32: `config.py:244-261`, `custom_api_client.py:74-135` |
| 14 | **Scored harness, CI-first**: fixture-DLL eval arriving with the job that runs it; the four-criteria judge rubric as a *prompt template only*, never on a verdict path | **P33** + **P42** (exactly their existing shape; KRAKEN already set the pattern) | duplicates | 35: `llm_judge.py:21-68`, `evaluator.py:41-58` |

Also cheap, unranked:

- **"Already done" banners on ladder re-entry** — show a later *attempt*
  what earlier attempts already asserted, instead of silently swapping the
  tier (ch. 32, `bridge.py:3108-3134`). **NEW.**
- **"Test Connections" live probes** as a web affordance beside `doctor`
  (P31-shaped; ch. 34).
- **The *analysis-dump* habit** — a pre-truncation record of exactly what
  the model was shown, filed beside the attempt ledger; the one genuinely
  honest artifact in OGhidra's whole UI layer (ch. 34 §verdict). **NEW.**
- **A *focus pointer*** — a human's currently-selected function as a
  queue-priority / prompt-selection hint in `re/review/` overlay material:
  state from a live session once, engine coupling never (ch. 31). **NEW.**
- **Generated tool-doc files + a CI freshness gate** — `tool_capabilities.md`
  is right when regenerated and ~8 months stale when not; the hand-written
  `docs/enabled_tools.md` shows the prose alternative rotting (ch. 31
  steal 6, ch. 20 §9). P42/P52-adjacent.
- **Named write-back transactions** — every Kuna program mutation names the
  scan + record id behind it ("Rename function via HTTP" discipline,
  `GhidraMCPPlugin.java:678`), tying program state to provenance (ch. 31
  steal 7).

**The five that move calxgloss most, given its restitch mission** (P23–P33
is the restitch block):

1. **#1 pattern-alert evidence format + tag vocabulary** — one record type
   strengthens three scan rows and the P30/P51 evidence story at
   near-zero mechanism cost.
2. **#2 address-evidence admission rule** — turns P27 hypotheses from
   prose into re-readable addresses; that is the ledger's whole epistemic
   job, and the rule is a five-line predicate.
3. **#3 workplan playbooks** — P29's methodology as data, field-tested RE
   craft (the vuln checklists) delivered free.
4. **#4 rejection-inclusive narrative** — the P26/P27 ledgers must record
   what was rejected and why, or they repeat OGhidra's "queue empty =
   done" error in a new table.
5. **#7 fixed attention nudge + depth ladder** — the only steal in the
   volume that targets calxgloss's known completion blind spot: P26's
   "binary done" verdict needs areas that map to function sets and states
   that never collapse into each other.

#14 (harness + CI) is excluded from the five not because it is wrong — it
is exactly P33/P42 — but because the roadmap already ranks it first
independently; OGhidra only adds the cautionary tail to it.

## What calxgloss should not learn from OGhidra

Consolidated across the chapters; each with the evidence that makes it a
anti-pattern, not a taste call:

1. **LLM self-review as any stop condition.** "GOAL ACHIEVED" evaluation,
   the FINAL-RESPONSE regex gatekeeping, and the branch's
   `COMPLETION_MARKERS` magic words (ch. 32 §6–7, 36 §4) bound the *cost*
   of confabulation and nothing its *correctness*; calxgloss's verdict-routed
   loop (ADR-0051) and ADR-0057 trace containment exist precisely so the
   model never grades its own exam.
2. **Prose as the knowledge base of record.** OGhidra's CAG summaries are
   150-char extracts of the model's own reasoning, fallback literal
   `"Analysis performed"`, embedded verbatim (ch. 33 §5); calxgloss's rule —
   records with provenance, prose only as prompt input — is the cure.
3. **Sessions/caches without invalidation or identity.** A cache whose
   `clear_cache` has no caller, whose key pins the GUI cursor to read #1,
   and whose loader and writer disagree on filenames (ch. 31 §caching,
   33 §2). Steal the SHA-256 gate (#11); refuse the rest.
4. **`char//4` token math as accounting** (`context_manager.py:96-97`,
   re-read: `token_estimate = len(result) // 4`). calxgloss gets real counts
   from its provider logs — never budget in fake tokens.
5. **Gate-theater / unwired safety.** Detectors that fire, log, and proceed
   — "Phase 2 will truly block" shipped forever — plus never-assigned
   callbacks and dead flagship UI (ch. 32 §9, 36 §13). A safety feature's
   README line is not its wiring; ADR-0008's delete-orphans rule is the
   vaccine.
6. **Mutating the live program ahead of any verdict, with no undo record of
   its own.** Renames land before the reviewer exists and the only
   undo lives in a host neither project controls (ch. 34 §touchpoints). If
   calxgloss ever grows an interactive surface, verdict precedes mutation
   — the P51 suggestions-queue steal (ch. 34 steal 1) takes the row shape
   and fixes that order.
7. **LLM-generated ground truth + an LLM judge on a verdict path.** The
   benchmark's `llm_source_summary` measures agreement between two models,
   and its judge fabricates 3/5s on failure (ch. 35 §2/§3). Truth stays
   behavioral or human-fact; a judge may decorate triage prose, never gate
   a merge.
8. **Tkinter + GUI-cursor coupling for automated flows.** Automated work
   that reads `get_current_function` inherits a toolkit whose threading
   history includes a three-year crash fixed by bolting a queue onto the
   grain (ch. 21 PR #44, ch. 34 §surfaces). calxgloss gets those properties
   from a protocol designed for it — keep the web surface.
9. **README-as-spec with no CI to force the tell.** Discussions links that
   go nowhere, advertised knobs hard-coded in source, a Dockerfile cloning
   a deleted branch, a benchmark that doesn't import — and exactly one
   workflow, release-only (ch. 20 §8/§10, 21 §5–6, 35 §4). calxgloss has no
   CI either (P42): the lesson OGhidra prices in blood is that *anything
   not run rots*, and P42 must land before the scored-eval/drift-check
   tracks can gate anything.

Two structural refusals, from ch. 36, close the list: the **agentic control
flow** — model-authored next tasks, counters over self-bookkeeping as stops
— which ADR-0051 excludes by design, and the **multi-agent narrative UI**
that renders sequential loops as parallel workers. The same authors who
shipped the orchestrator reverted it on main; take the working-memory
discipline, refuse the control flow.

## Sources

- Domain chapters of this study, which carry all file:line evidence:
  [20](20-oghidra-inventory.md) (scale, config surface, packaging, docs),
  [21](21-history-and-releases.md) (147-commit history, revert saga, releases,
  branch map, 465★/3-watchers API battery),
  [31](31-ghidra-bridge-and-backends.md) (seam posture, caches, tool surface,
  steal cluster),
  [32](32-agentic-core-and-context.md) (loop, gates, context engine,
  observability),
  [33](33-knowledge-rag-and-sessions.md) (CAG, patterns, coverage, sessions),
  [34](34-ui-cli-bulk-and-reports.md) (bulk run, reports, surfaces),
  [35](35-benchmark-and-effect.md) (benchmark forensics, test/CI posture),
  [36](36-orchestrator-branch.md) (orchestrator branch, admission rule).
- Anchor: [10-calxgloss-baseline](10-calxgloss-baseline.md) (fixed calxgloss
  facts + ADR map); [00-scope-and-method](00-scope-and-method.md) (revisions,
  vocabulary rules, premise correction).
- Roadmap cross-references: `docs/roadmap.md` — P23–P33 (restitch block),
  P40–P52 (KRAKEN block); re-read 2026-11-01 to verify every P-number cited
  above.
- Re-verified for this chapter (clone batteries, 2026-11-01): test-function
  count 134 (`grep -c 'def test_' tests/*.py` summed — corrects
  [35 §6](35-benchmark-and-effect.md)'s 138); `PATTERNS` registry = 14
  malware patterns (`src/cag/malware_patterns.py:532-547`); gate comment
  (`src/bridge.py:3090-3093`); coverage echo from `combined_text`
  (`src/coverage_tracker.py:139`); `len(result) // 4`
  (`src/context_manager.py:96-97`); `max_workers = 5`
  (`src/gui/tool_buttons_panel.py:1595`); `git rev-list --count main` = 147.
  Orchestrator worktree (`aa03aa8`): branch 0 ahead / 39 behind main
  (`git rev-list --left-right --count main...HEAD` = 39/0);
  `COMPLETION_MARKERS` at `src/agents/worker_agent.py:78`;
  notebook admission rule at `src/orchestrator.py:1681-1685`;
  address→code cache at `src/blackboard.py:79, 284-315`;
  revert `d5dec8a` numstat +16,969/−4,640, mirrored by `c62ec6e`.
- GitHub/PyPI API facts (2026-11-01, recorded in [21 §5/§7](21-history-and-releases.md)):
  465 stars, 50 forks, 3 subscribers; 0 GitHub Releases; one tag `v0.0.0`
  pointing at the PyPI-workflow commit; single PyPI release `0.0.0`
  (2026-08-14); PR ledger 22 merged / 7 closed-unmerged / 8 open; issue #16
  open and unanswered.
