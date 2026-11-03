# Master comparison — calxgloss ↔ ReVa

> Part of the [ReVa overview](README.md). This chapter synthesizes the deep dives
> ([31](31-mcp-tool-surface.md), [32](32-headless-cli-and-automation.md),
> [33](33-skills-and-agent-layer.md), [34](34-analysis-workflows-and-effect.md))
> against the [calxgloss baseline](10-calxgloss-baseline.md), merges their
> steal-lists, and adjudicates the factual tensions between chapters (§7).
> Where a chapter overstated, the correction lives here.

## 1. Difference of kind

The two projects answer the same question — "how does a machine turn a binary
into trustworthy code?" — with opposite authorities.

**calxgloss is an unattended factory.** Its output is a *verified claim*: a
whole-program semantic graph (functions, call graph, signatures, structs, field
flow) rendered to a git-committed wiki, with Rust judged by executing the
original DLL under Wine against baseline tests
([34 §5 overlap](34-analysis-workflows-and-effect.md);
`crates/pipeline/calxgloss-verify/src/engine.rs`,
`crates/pipeline/calxgloss-testgen/src/wine/harness.rs`,
`verification.rs:75-104` — `compiled` + `tests_passed/tests_total` +
`trace_assessed_tests`, "Silence never counts as a pass" `:100`). Kuna is
compiled in, the pipeline is deterministic, nobody is watching — so the gate has
to be code ([10 baseline](10-calxgloss-baseline.md);
[32 §Comparison](32-headless-cli-and-automation.md)).

**ReVa is an interactive (optionally headless) workbench.** Its 88 MCP tools
give a live LLM Ghidra powers — query, decompile, rename, retype, diff, script —
against a mutating program database, the model as orchestrator
([31 §2](31-mcp-tool-surface.md); [20 §2](20-reva-inventory.md)). Headless mode
("unattended Ghidra + LLM") still runs *the model as the loop*: it ends when the
model decides it is done, its temp project is `rmtree`'d, and no run carries a
verdict a pipeline could consume
([32 §3, §7](32-headless-cli-and-automation.md)).

Neither has the other's gate. ReVa certifies **tool correctness** — 267+231 Java
`@Test` and 172 Python `def test_` assert ground-truth answers on a self-authored
fixture, but the analysis output (Ghidra state + LLM prose) is never compiled,
tested, or replayed ([34 §5, §Verdict](34-analysis-workflows-and-effect.md)).
calxgloss certifies the **translation** by running the target, yet has no CI at
all, nothing testing that its evidence commands answer correctly
([10 baseline:104-105](10-calxgloss-baseline.md)) — "tool lies to the agent" vs
"translation misbehaves", each blind to the other's failure mode
([34 §Verdict](34-analysis-workflows-and-effect.md)).

## 2. Capability matrix

Winner is per-domain, judged against what that domain is *for*. "—" = absent.

| Capability domain | ReVa | calxgloss | Winner — why | Ref |
|---|---|---|---|---|
| Analysis engine & architecture breadth | Ghidra engine: any loader format, any ISA, 12.0–12.2 CI matrix | Kuna compiled in: PE only, x86-32/64 only | **ReVa** — orders-of-magnitude wider floor; cost is the install/match dance | [20 §1], [32 §6]; baseline:64-67,114-117 |
| Interactive query surface | 88 tools over live DB; input ladders, reinforcement, error redirect | — (29 batch subcommands, no per-address query) | **ReVa** — the axis it exists for | [31 §1-3] |
| Batch evidence scanning | auto-analysis whole program; results live only in the Ghidra DB | 15-row scan registry, fan-out cap 4, machine-readable record tree | **calxgloss** — evidence persists as records, not session state | baseline:40-46; [34 §1] |
| Type/rename write-back | ≥9 transactional writers (rename, retype, prototype, structures, `parse-c-header`), before/after diff | confidence-floored writes only: `typeinfer --write-back` (floor 70), typesdb vtable tags (`cli_types.rs:296-303,255-256`) | **ReVa** on surface; calxgloss's narrow writes are evidence-gated instead | [34 §2] |
| Whole-binary reconstruction | none — output is Ghidra state + prose, temp project deleted | whole-program graph → rendered wiki + Rust, committed and replayable | **calxgloss**, unconditionally | [32 §3, §7] |
| Verification & correctness gates | none per run; ground truth exists only in its own test suite | compile + Wine baseline tests + assessed API-call traces; verify is a hard pipeline stage | **calxgloss**, unconditionally | [34 §5]; `verification.rs:75-104` |
| Diffing | 13 diff tools on VersionTracking: durable `ReVaDiffSessions/` sessions, staged correlators, markup transfer, under-analysis refusal | `bdiff` pairing docs + review command; stale-doc detection; no correlator pipeline, no markup transfer | **ReVa** — resumable, multi-lens, applies the result | [34 §4] |
| Runtime observation | — (static only; ctf-rev skill defers to external debuggers) | Wine harness executes the real DLL (`DllMain` first, IAT interposer stubs, x86-64); oracle role only; P22 trace lane parked | **calxgloss** — real, though as test oracle, not analyst surface | [33 §2]; baseline:76-85 |
| Unknown/gap tracking | honesty flags in payloads (`earlyTermination`, `analysisWarning`); no ledger | 6 unknown kinds, versioned corrections (v3), parked tracks as named ADR records | **calxgloss** — gaps are durable artifacts | baseline:54-56; [31 §2], [34 §4] |
| Agent layer (skills vs pipeline code) | 6 skills (~7,900 lines) + marketplace + hooks; discipline is prose, nothing enforced | workflow in Rust: retry cycle, fault categories, context tiers — enforced by types | **split** — ReVa wins open-ended jobs; calxgloss wins the one fixed job it runs | [33 §6] |
| Automation / headless | `mcp-reva`: one-prompt unattended generality; LLM in loop; deletes its database | `calxgloss auto` deterministic and replayable; but zero CI, no JSON out | **split** — ReVa scope, calxgloss trustworthiness | [32 §7] |
| UI & human review | Ghidra GUI + follow-me; **no reviewer construct** ("accepted" = markup applied or a human watched chat) | 9-state `ReviewStatus` queue, dashboard, hyperlinked HTML wiki, accept/send-back loop | **calxgloss** for structured review; ReVa for live manipulation | [34 §Comparison]; `dashboard/types.rs:135-167` |
| Security posture | per-session API key, public-binding refuse/revert, scripting capability cut — but `String.equals` key compare, no TLS, no SECURITY.md | offline, no network; web on loopback axum; no auth (surface tiny by design) | **ReVa** as engineered exposed-server policy; calxgloss has less surface to defend | [32 §5] |
| Tool/context budgeting | tool groups (6 booleans, live toggle); pays fixed ~15–20k-token schema bill per session | 5 context tiers select per-phase evidence; zero schema bill (no agent loop) | **calxgloss** for the factory; ReVa's shaping grammar best-in-class for live sessions | [31 §5] |
| Extensibility | `run-script` escape hatch = full Ghidra/PyGhidra API; provider API + per-package docs | 34 member crates, 18 evidence crates — but Ghidra-family scan sources modeled-not-wired (`calxgloss-decomp/src/scan_source.rs:7-14`); no ad-hoc query path | **ReVa** — today's escape hatch beats tomorrow's wiring | [32 §4]; baseline:68-72 |
| Community / maintenance | 887★/82 forks, 20 releases, 6 CI workflows, dependabot, AI-agent commits; bus factor ≈1 | no `.github`, no CI; 57 ADRs, 4.7k test fns; single-harness `just test` | **ReVa** — objectively maintained; calxgloss objectively untested-by-CI | [21 §4-5]; baseline:100-105 |

## 3. Where ReVa beats calxgloss (ranked)

1. **ISA/format floor.** Everything Ghidra loads and disassembles vs PE+x86;
   ReVa's CI proves the product across 5 Ghidra versions × 2 OSes, calxgloss
   cannot gate its own builds ([32 §6]; baseline:114-117).
2. **A query surface an agent (or human) can drive.** 88 tools that never fail
   silently: name/address ladders with `resolvedFrom` echo, errors naming the
   fixing tool, count-first pagination, reinforcement everywhere ([31 §2-3]) —
   calxgloss has no per-address question to ask at all.
3. **The diff toolchain.** Durable staged sessions, per-stage checkpoints,
   confidence-floored markup transfer with rollback, under-analysis refusal
   ([34 §4]). calxgloss-bdiff ships pairing docs plus one review command.
4. **`run-script` — the escape hatch.** No tool? Drop into the full Ghidra API
   in-process, with caps/timeouts. calxgloss's 15 scans are the only questions
   it can ask; decomp-source families remain unwired ([32 §4]; baseline:68-72).
5. **Long-job machinery.** Hybrid wait-then-poll, single-flight attach, ring-log
   cursors, cancel, progress ticks — a complete, tested primitive
   ([31 §4], [34 §1]).
6. **Headless packaging.** stdio↔HTTP bridge, random port, per-session key,
   capability cut, refuse-to-bind ([32 §2, §5]).
7. **CI that tests the product path with right-answer fixtures.** One
   `mcp-reva` boot per pytest worker driving real MCP calls against a compiled
   fixture with asserted callees ([32 §6], [34 §5]).
8. **Skills/marketplace layer.** Install → MCP auto-registered + six workflow
   skills naming exact tools ([33 §1-2]).
9. **Write-back breadth.** Prototypes with custom storage, C-header struct
   import, function creation with on-demand disassembly — beyond calxgloss's two
   confidence-floored lanes ([34 §2]).
10. **Maintenance reality.** Releases, CI matrix, dependabot, PyPI vs a no-CI
    tree ([21 §5]).

## 4. Where calxgloss beats ReVa (ranked)

1. **The verify gate.** The original DLL is executed (Wine harness, `DllMain`
   first, interposer stubs), the Rust must compile and pass baseline tests, and
   traces are *assessed* only where expected values exist — silence never passes
   ([34 §Comparison]; `verification.rs:91-101`). Nothing in a ReVa run compiles
   or tests recovered logic ([34 §5 ceiling]).
2. **Artifacts that survive the run.** Record tree, decompile cache, corrections
   store, git wiki, attempt branches ([32 §Comparison]; baseline:57-61) — vs a
   headless ReVa run deleting its entire database ([32 §3]).
3. **Determinism.** Same binary+version+seed ⇒ identical output; ReVa has
   "nothing; the run is deleted with the project" ([32 §Comparison]).
4. **Evidence spend-once.** 15 scans compute once, later passes *read records*
   through 5 context tiers; ReVa pays ~15–20k schema tokens per session plus LLM
   cost per question ([31 §5], [32 §7]).
5. **Honesty machinery.** 6 unknown kinds, versioned corrections, parked tracks
   as ADR records; ReVa's `earlyTermination`/`analysisWarning` are per-payload
   flags with no ledger (baseline:54-56; [31 §2], [34 §4]).
6. **A structured review queue.** `ReviewStatus{Queued…DoNotTranslate}` with
   accept/send-back/patch is a typed review protocol; ReVa has "no reviewer
   construct" ([34 §Comparison]; `dashboard/types.rs:135-167`).
7. **Zero-install engine.** Kuna compiled in vs `$GHIDRA_INSTALL_DIR`, a zip
   rebuilt per Ghidra version, JVM boots, and a dedicated *setup agent*
   ([32 §1, §6, §7]; `cli_types.rs:206-208`).
8. **Enforced discipline.** The retry cycle (`CompileFix → TestFix → Escalate →
   EdgeCaseFix`, ≤3 attempts) and fault categories run in code; ReVa's skill
   budgets and loops are prose nothing enforces ([33 §2, §6]; [34 §5]).
9. **No ungated prose.** calxgloss emits nothing it cannot re-derive
   (baseline:132-133); ReVa's deliverable includes ungated LLM prose ([34 §5]).
10. **Offline surface.** No network by design; ReVa must engineer auth, binding
    guards and RCE containment because it exposes a server ([32 §5]).

## 5. Consolidated steal ledger

Source lists: [31] 7 items, [32] 5, [33] 5, [34] 4 → **21 merged, 15 after
dedup** (read-before-write 31+34; diff sessions 31+34; hybrid jobs 31+34;
e2e/fixture tests 32+34; error-teaching + under-analysis guard 31+34). Ranked
by leverage on the factory mission.

| # | Steal | Build it as | Why | Effort | Src |
|---|---|---|---|---|---|
| 1 | **Right-answer e2e suite on CI** | GitHub Actions matrix booting `calxgloss` once per job, driving the real CLI/REST client against fixture DLLs from checked-in C (seam: `crates/integrations/calxgloss-testfixtures`), asserting per-command *answers* (known callees, strings, signatures) — never exit codes; independent read-back after every write ("reports success without writing" trap) | calxgloss has **no CI**; 4.7k unit tests never touch the product path; ReVa's `test_workflow_correctness.py` is the ready template | M–L, mechanical | [32 steal 1-2], [34 steal 1] |
| 2 | **Durable diff sessions** | `calxgloss-bdiff`: reusable session dir under `re/analysis/bdiff/sessions/`, staged matchers over the unmatched residual with per-stage checkpoint, `force`-vs-reuse, and a summary that *refuses* near-zero when inputs look un-paired | today's bdiff is a pure report; staged resumability makes second-and-later diffs cheap, matching the wiki-republish loop | M | [31 steal 7], [34 steal 2] |
| 3 | **Hybrid wait + single-flight job primitive** | one `JobStatus`/`JobLog` primitive (6-state enum, ring log, `sinceLogSeq` cursor) behind `verify`, `testgen`, `auto` and both axum routers: short inline wait, else `{jobId, log}`; concurrent callers attach, never stack | long Wine runs today have no handle, no cancel, no attach; ReVa's primitive is ~complete and tested | S–M | [31 steal 3], [34 steal 4] |
| 4 | **Identifier ladder + `resolvedFrom` echo** | shared selector in `calxgloss-types`/CLI: symbol → exact → case-insensitive → address-in-function, echoing which rung matched and naming the block on miss | `translate --function`, corrections and review all take identifiers today; silent near-misses are the top LLM-input hazard ReVa kills structurally | S | [31 steal 1] |
| 5 | **Errors that teach the next step** | ride `FaultCategory` records: "did you mean", "use X first", and the under-analysis guard — any lens reading near-zero over unanalyzed input says so loudly in the record | fault monitors already classify; the verbal half ReVa added is what makes retries (and human triage) converge | S | [31 steal 2,6], [34 §4] |
| 6 | **Read-before-write gate** | per-function expiring read-tracker keyed `program:function`; refuse *any* write-back (today `typeinfer --write-back`, typesdb tags; tomorrow corrections/review mutations) unless current state was read; pin the error text in tests | three lines of state structurally prevents blind edits — by any LLM or lens; calxgloss's confidence floors gate *what*, never *whether you looked* | S | [31 steal 5], [34 steal 3] |
| 7 | **Capability cut at startup** | a CLI/server capability allowlist (`--allow write-back` / read-only default) resolved *before* commands run, not runtime checks | pairs with #6; makes "factory mode vs agent mode" an enforced deployment choice | S | [32 steal 3] |
| 8 | **Count-first + pagination envelope** | adopt `paginationResult` (startIndex, requestedCount, actualCount, nextStartIndex, totalProcessed) for dashboard/`/api` list endpoints and wiki tables | house grammar ReVa proved; calxgloss list outputs vary today | S | [31 steal 4] |
| 9 | **Refuse-to-bind policy for `calxgloss-web`** | port the public-binding guard quadrants: loopback-or-auth, refuse on non-loopback bind, revert-on-runtime-change | web runs today with no auth; ReVa's tested policy is ~60 lines | S | [32 steal 4] |
| 10 | **`calxgloss-triage`/`calxgloss-review` contributor skill** | short SKILL.md routing `classify` vs `translate` vs `auto` vs the evidence commands, progressive `references/`, named exact subcommands — no end-user skill needed, the 29-command CLI is the product | closes the "no driver for the CLI" gap 33 names, for agents *operating* the factory; mirrors ReVa's binary-triage→deep-analysis economy gates | S | [33 steal 1] |
| 11 | **Ephemeral scratch / durable artifact separation (as a rule)** | codify: session/work dirs are throwaway; outputs persist only via explicit record-tree writes | ReVa's `rmtree` with the answers is the cautionary tale; calxgloss already does this — make it a rule any new front end must keep | policy | [32 steal 5] |
| 12 | **Declarative client wiring** | ship the config convention (an installed file that auto-registers the CLI/web for Claude Code / opencode — root `opencode.json` is the seed) | ReVa's `.mcp.json` makes install == integration; calxgloss integration is hand-doc today | S | [33 steal 2] |
| 13 | **Patterns-catalog progressive disclosure** | split per-domain rules (PE lanes, managed-PE parking, xref conventions) out of `docs/standards.md` into on-demand refs | keeps standards lean while agent-reachable; mirrors ReVa's SKILL.md→patterns.md split without shipping skills to users | S | [33 steal 4] |
| 14 | **Env self-check on entry (SessionStart analogue)** | cheap AGENTS.md/hook check: graft fresh? cargo? web endpoint up? — seeded by `doctor`, which already loads the target in-process | ReVa's hook value is *environment self-check*, not the remote installer; calxgloss `doctor` is the ready primitive | S | [33 steal 3] |
| 15 | **Anti-trigger line** | one sentence in `AGENTS.md`: "do not script around X when command Y exists" — the prose twin of fault monitors | ReVa's pyghidra anti-trigger is the cheapest discipline in the set | trivial | [33 steal 5] |

Explicit non-steals: advertised-but-never-registered prompts, the ~15-20k schema
bill, the zip-per-Ghidra-version ladder, missing undo/`rename-function` ([20 §2], [34 §2], [32 §6]).

## 6. Confirmation, not change

ReVa's existence validates choices calxgloss already made — these need no action:

1. **Engine in-process.** ReVa's unattended fragility *is* the external engine:
   `$GHIDRA_INSTALL_DIR`, a zip per Ghidra version, JVM boots, a dedicated setup
   agent, deleted docs still cited by four files ([32 §1, §6]). Kuna vendored at
   a commit sidesteps every one of them (`cli_types.rs:206-208`).
2. **Durable artifacts over session state.** ReVa's headless story ends with
   `rmtree` deleting the database and "output is prose in a terminal" ([32 §3,
   §7]) — exactly why the record tree + git wiki exist.
3. **Tiered context beats per-call shaping for a factory.** ReVa's fixed schema
   bill is ~15–20k tokens per session ([31 §5]); context tiers pay it zero times.
4. **Workflow-in-code where the job is fixed.** ReVa *must* encode workflow in
   prose — and pays for it (skills hand-code 88 tool names, budgets unenforced,
   no `allowed-tools`) ([33 §2, §6]). calxgloss's single PE→Rust job is the case
   where workflow compiles into retry/fault types.
5. **Verdict-as-stop-condition.** ReVa's loop ends on model satisfaction with
   nothing checking it ([32 §Comparison]); the compile+test+trace gate answers
   the same problem.
6. **Certify by side effect.** ReVa's read-back after writes (`get-data` after
   `apply-data-type`) is the same epistemology as "Silence never counts as a pass" ([34 §Comparison]).
7. **Honest degradation markers.** `earlyTermination`, `analysisWarning`,
   refuse-to-bind — "say so, don't emit a trustworthy zero" — confirm the
   unknowns/corrections doctrine as load-bearing ([31 §2], [32 §5]).
8. **Per-package agent docs.** 33 CLAUDE.md files are the same bet as `AGENTS.md`
   + graft indexing ([33 §4]).

## 7. Cross-chapter discrepancies — adjudicated

Verified against the ReVa clone (`/tmp/opencode/cyberkaida-rea` @ `a2fcd94`) and
this repo's tree on 2026-10-31. **Follow-up pass (same day): items 1–7 and 12
were fixed in place in the cited chapters; this ledger now records what changed.**

1. **ReVa LOC.** [00:10-11](00-scope-and-method.md) "~46k LOC under `src/main`"
   vs [20](20-reva-inventory.md) **27,773** — recount agrees; 00 conflated the
   with-tests total.
2. **Retry strategy names (baseline stale).**
   [10:47-51](10-calxgloss-baseline.md) lists `SignatureRepair / TypeEnrichment /
   TypeEnrichmentAndConstraintRepair / ConstraintRepairOnly` — names existing
   **nowhere** in the tree (grep 0). Actual:
   `RetryStrategy{Default, CompileFix, TestFix, Escalate, EdgeCaseFix}`
   (`retry_strategy.rs:31-42`), auto cycle `CompileFix→TestFix→Escalate→EdgeCaseFix`,
   `max_attempts: 3` (`calxgloss-translator/src/retry/config.rs:24,42-47`).
   [33:161-165](33-skills-and-agent-layer.md) cites the correct enum; "four
   escalating strategies per auto cycle" survives, the names don't.
3. **Verification verdict names (baseline stale).**
   [10:9-10,30-31](10-calxgloss-baseline.md) claims verdict labels
   `Confirmed / Confirmed (Degraded) / Unresolved` at `verification.rs:83-115` —
   no such enum exists. `verification.rs` holds the `VerificationResult` *struct*
   (`compiled`, `tests_passed/tests_total`, `failed_tests`,
   `trace_assessed_tests`, silence-never-passes `:91-101`). The gate [34]
   describes is real and correctly cited there; treat it as "compile + baseline
   tests + assessed traces," not three-valued verdict labels.
4. **Templates & layers (baseline stale).** [10:24-27](10-calxgloss-baseline.md)
   claims ~60 `.j2` incl. 11 root-level `templates/` + `templates/sections/`:
   there is **no root `templates/`**; 29 `.j2`, all under
   `calxgloss-prompts/templates/`. Crate count 34 checks out, but that is
   **six** `crates/` layer dirs, not "five layers" — `evidence/` (18 crates) is
   a layer of its own.
5. **CLI command count.** [33:188](33-skills-and-agent-layer.md) "23-command
   CLI" vs **29** `Command` variants (`cli_types.rs:197`+) — baseline right, 33 stale.
6. **Wrong calxgloss paths in ch. 34.** [34:164-167,217-218](34-analysis-workflows-and-effect.md)
   cites `crates/execution/{calxgloss-verify,calxgloss-testgen}` — no such
   layer; it is `crates/pipeline/…` (line refs right, prefix wrong).
7. **CLAUDE.md census.** [20:172](20-reva-inventory.md) "31 total — one per
   package under `src/main/java/reva/`" vs [33:121](33-skills-and-agent-layer.md)
   "33 files, 11,755 lines". Counted: **33 repo-wide, 29 under
   `src/main/java/`** — 33 right, 20's "31 total, one per package" off
   (corrected in [20:172-174]).
8. **ReVa python suite count.** 20 §8 "17 pytest files" vs 34 §5 "(20)" — both
   bases true: 17 `test_*.py` modules, 20 `.py` incl. conftest/helpers/`__init__`.
9. **Tool/provider counts.** 88 tools / 19 providers / 6 groups consistent across
   20/31/33/34 (`.name()` recount matches). ReVa's DEVELOPER.md says 17 providers
   — its own doc lag, flagged by [33 §4]; `mcp-reva --version` `3.0.0` vs PyPI
   7.3.1 is ReVa's internal drift, flagged by [32 §2].
10. **BoSSViePl3x lineage.** [21 §2](21-history-and-releases.md) proves the
    claimed succession fabricated (404s, no fork, monogenetic history). One
    citation sloppiness inside the folder: 21:31-32 says 00 "calls this repo the
    maintained successor", but [00:28-31](00-scope-and-method.md) already reports
    the claim as unverifiable. Both agree: **no lineage**.
11. **`.reva/projects/` vs temp projects.** ReVa's `README.md:149` promises
    `.reva/projects/<cwd>`; the stdio flow uses `mkdtemp` + `rmtree`
    (`launcher.py:73-85,164-173`), `tests/test_cli_e2e.py:146-185` pins `.reva`
    never appears, and `ProjectManager.import_binary` is never called. [32 §3]'s
    three-models table is the correct model; the overstatement is ReVa's README.
12. **The "846k-token" citation in 31.** [31:218-220](31-mcp-tool-surface.md)
    attributes an "846k-token catalog dominating a whole task" to "ReVa's own
    case history", citing bare `31-deep-native-analysis.md:149-157` — actually
    `docs/research/rea/31-deep-native-analysis.md`, the *morluto/rea* folder,
    quoting its `kuna-case-study.md`, not the ReVa clone. **Corrected:** token-
    dominance is cross-project evidence from the rea set; ReVa's ~15–20k schema
    bill *is* measured from ReVa source ([31 §5]) and stands on its own.
13. **Checked out:** 88 tools, 6 groups + live toggle, the 3-tool
    read-before-write gate ([34 §3] refines [31 §2]), job/diff-session
    machinery, security quadrants, suite sizes (267+231 Java `@Test`), release
    ladder — and calxgloss's 15 scan rows (`scan_rows()`, `scan_registry.rs:606`+;
    baseline's `ScanRecordKind::all_records()` name stale, count right), 5
    context tiers, 29 subcommands, no CI, `doctor` in-process.

**Net effect on this chapter:** the ranking, matrix, and ledger hold; where they
depend on §7.2/§7.3, this chapter uses the actual enum names and struct-level gate wording.
