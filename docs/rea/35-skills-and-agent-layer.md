# REA's skills and agent-integration layer

> Part of the [REA overview](README.md). How REA teaches a *general* coding
> agent to drive its ~150-tool MCP surface — skill + references, setup/doctor
> for 24 clients, MCP prompts, compact profiles, tool-design philosophy —
> against calxgloss, which encodes its workflow in the harness instead.

## What REA does

### Anatomy of the `reverse-engineer-anything` skill (v45)

452 lines; frontmatter `version: "45"` (`SKILL.md:4`). The description
doubles as trigger *and* anti-trigger (`:3`): use REA for shipped-artifact
or runtime-evidence claims, "**Skip REA for ordinary source-repository
architecture analysis**" — stated twice (`:3, :10–14`): skills fire by
description-matching and "analyze this codebase" is the common false trigger.

| Lines | Section |
|---|---|
| 1–14 | frontmatter + use boundary: shipped binary / decompilation / runtime evidence / comparison beyond source; skip for source repos |
| 16–93 | *Connect only when needed*: skill install ≠ MCP registration (`:18–19`); proceed directly when tools work — never diagnostics-before-everything (`:21–22`); version-skew rule, a repo-main skill "may describe capabilities absent from an older npm release" (`:24–26`); inline 4-step recovery ladder (`:45–71`) with 14 client IDs; "setup never installs Node/Homebrew/Java/Ghidra/Kuna…" (`:72–77`); CLI fallback recipe (`:78–93`) |
| 95–345 | *Route the target first*: ~30-entry target→first-tool table (`:101–295`): ASAR/JS, archives, Apple bundles, Android, managed PE, firmware, NativeAOT, browser, Fiddler, HAR/SAZ/qlog, Electron, packets, decoders, WASM, APK sigs, EVM, Go, GPU objects, model artifacts, IL2CPP, Rust binaries, PE certs, ELF notes, pyc, BEAM, SQLite, ELF layout, crash cores, PE resources/exports, native (`:293–295`); IDA (`:297–307`) and Kuna (`:309–321`) sub-protocols; "never choose an example app on the user's behalf" (`:323–327`); probe `binary_session {}` for `tool_availability`, don't call unadvertised tools (`:329–339`); Ghidra deadline pointer (`:341–345`) |
| 347–396 | *Work summary-first*: default result + inline Evidence; `detail:"summary"` → `inspect_analysis_view` paging via retained `parent_evidence_id`; "do not repeat an identical analysis or rejected call without a changed input or resolved blocker" (`:355–356`); transport-`resource_constraint` remedy (`:361–367`); client-truncation handling (`:379–385`); observations vs inferences vs unknowns, cite Evidence IDs, never imply static saw execution (`:387–390`); REA needs no per-call approval, the client's is separate (`:392–396`) |
| 398–431 | *Plan broader investigations*: 7-step staged workflow — question checklist, reuse session state, smallest overview first, format-aware resources, evidence-type corroboration (runtime only when static can't answer), parallelize independent questions, finding ledger; bounded negatives stay bounded (`:428–431`) |
| 433–452 | *Read only the relevant guide* (5 reference files) + *Finish the task*: plain language tied to evidence; reconstruction guidance terse — "use normal coding tools and separate observed behavior from design choices"; `close_binary` |

**Reference-file split** (6 files, ~1,200 lines more): SKILL.md keeps what
must be true *before the first tool call* — boundary, connect discipline,
routing, summary-first economy, evidence honesty; deferred is situational
depth: recovery (205), per-format (`native-and-artifacts.md`, 532), JS (240),
Android (37), runtime observation (84), evidence recipes (106). Progressive
disclosure: routing stays (you need the first tool name now), qlog heap
settings load only on demand; the skill degrades gracefully when "that server
does not advertise retained references" (`:25–26`).

### Connection & recovery discipline — an error-recovery state machine

SKILL.md:16–93 is the always-loaded fast path; the reference loads *only on
an observed blocker* (`connection-and-recovery.md:3–5`). States:

1. **Healthy** (`SKILL.md:21–22`): tools present, registration not known
   stale → straight to the target; diagnostics-before-everything is banned.
2. **Classify the blocker** (recovery `:12–22` symptom→remedy table): no
   tools → `rea doctor --client X --json`; missing/malformed/stale
   registration → scoped setup plan; *aligned registration but no connected
   tools* → restart ("doctor checks registration; it cannot establish the
   current agent's connection", `:18`); approval-policy rejection → client
   policy; `provider_unavailable` → remediation from
   `binary_session.tool_availability`. Doctrine: per-blocker remedies, never
   blanket-setup (`SKILL.md:31–32`).
3. **Deadline distinction** (`:38–82`): client timeout (no REA result — work
   may still be running) vs server `provider_timeout` (REA's budget — follow
   `remediation.action` literally; change fields or `REA_*` settings *only
   when the text names it*).
4. **Retry automaton** (`:92–113`): drop → one retry if safe or
   known-not-started, else restart the client; startup failure → one retry,
   then restart + `rea doctor`; never retry a failure returning "the same
   unchanged result"; `cleanup_incomplete` → retry the *exact cleanup owner*,
   block dependent work; retryable `resource_constraint` → wait and retry
   within limits, don't restart to free the slot; `configuration_invalid` →
   fix named setting → restart → doctor; `invalid_request` → fix fields from
   the current schema, never resend unchanged.
5. **Repair protocol** (`:115–137`): doctor → dry-run setup plan → show
   paths/backups/skill replacement → approve → `setup --yes` → restart →
   *verify tools appear* → resume; still absent → inspect the launch error,
   don't loop setup.
6. **Continue past the blocker** (`:174–205`): CLI fallback recipes; "only
   actual REA output supplies REA Evidence" (`:35–36`).

### Setup & installation machinery

`npx rea-agents setup` (installation.md:14–60): multi-select agents —
"detection gives setup context, not permission" (`:39–40`); read-only
dry-run plans list exact config paths, backups, bundled-skill replacement,
every write approval-gated; it registers MCP **and
installs the matching bundled skill by default** (`--skill=false` omits);
skill+server versions deliberately paired (`:43–44`). `rea doctor`
(`:328–370`) is read-only and scopable (`--provider/--client/--skill/
--target`): `scope_checks` decide `healthy` and exit status, the rest are
`informational_checks`. Doctor inspects host engines + registration files (`src/doctorRuntime.ts:21–106`: Ghidra, IDA,
JADX, Kuna, Linux Hopper/Xvfb probes), never a live connection. `rea
uninstall` removes only REA-owned files, with an ownership preflight
(`:387–414`); `server.json` is the MCP Registry descriptor
(`io.github.morluto/rea`, `rea-agents@6.7.0`, npx stdio + `mcp` arg).

**Supported agents**: 24 client IDs (`:549–585`) — Claude Code, Codex,
Cursor, Gemini CLI, Windsurf, Devin, **opencode**, Copilot CLI, Qwen Code and
more (Grok Bot: chat-registration only); the ID lists already drift — SKILL.md
names 14, the recovery reference 23, the doc table 24. **Skill-only install**
(`:519–547`): instructions + references, *not* registration or engines.
**Version skew is a doc section** (`:486–517`): registrations pin to the
version that ran setup — "installing newer instructions does not update a
running server"; the npm release is dated and pinned (6.4.0 @ 2026-10-11),
seven IDs requiring 6.5.0. (Aside: `docs/agent-environments.md` is *not* this
layer — product surface.)

### Context budget: compact schema profiles + MCP prompts

`REA_MCP_INPUT_SCHEMA_PROFILE=compact` (the default) renders every advertised
input schema under a 13,312-byte budget — measured against Moonshot-family
rejections — dropping nested descriptions/examples/defaults and flattening
oversized or depth->10 schemas to names/types + first-level guidance, while
**canonical server-side validation is unchanged** and boundary tests pin the
budget (mcp-contracts.md:1058–1111); an output profile can drop output schemas
from `tools/list` (`src/config/mcpOutputSchemaProfile.ts:14`). Above them sits
summary/`detail` paging (ch. 33).

**MCP prompts** (`docs/mcp-prompts.md`): six provider-neutral guided
workflows — `investigate_feature`, `compare_application_versions`,
`verify_reconstruction`, `trace_crash`, `audit_residual_unknowns`,
`prepare_bounded_process_capture` (`:10–16`) — as *optional starting points*
(agents may call tools directly); arguments render as untrusted selection data
(`:18–23`). `completion/complete` supplies session-aware argument values
(documents, Evidence IDs, unknown heads) capped at 100, empty lists on failure
rather than invented IDs; prompts stay optional by design
(tool-design.md:38–39).

### The four dev skills — meta-skills about the tool, not the RE target

None touches an RE target: **`rea-tool-design`** (20 lines) is a pointer
skill → read `docs/tool-design.md`; before implementing, return a boundary
proposal, tool shape, Evidence semantics, nearest alternative, verification
plan. **`rea-ci-tests-audit`** (112): audits REA's own CI/test suites
for fixture drift, false passes and removable cost — pin the baseline SHA,
prove findings with the smallest reproduction or a mutation ("a test may
merely repeat its mock", `:53–56`), classify findings reproduced/cost/
hypothesis/unavailable, never "add blanket retries, raise timeouts, or delete
distinct assertions solely to make CI green" (`:98–100`).
**`rea-changelog-update`** (134): release notes via `scripts/release-notes.mjs`
— pinned tag baseline, verified human credits
with bot/agent accounts excluded ("unknown handles stay unknown; they are not
fabricated credit", `:77`), Release Please sync via a finalization label, "never retag or republish a package to
correct release prose" (`:134`). **`rea-analysis-optimization`** (113):
optimize providers and workflows for agent context, latency, CPU and memory
while preserving Evidence — oracle independent of the changed implementation
(`:30–36`), cost→correction table (`:46–53`), every cache states
key/owner/invalidation/size/lifetime, token claims must count schemas,
discovery, retries and continuations (`:102–105`); ref `kuna-case-study.md`,
a Kuna lookup win labeled non-generalizable — same engine as ch. 31. Two of
four carry `agents/openai.yaml` — display name, description, `default_prompt`
invoking `$rea-…`, for Codex-style discovery and launch.

### REA's tool-design philosophy (`docs/tool-design.md`)

Design around the **analyst question**; inspect the nearest existing tool
before widening the surface; provider-neutral names with per-provider
coverage (`:3–12`). Keep the catalog complete — "report capability/session
availability instead of truncating schemas" (`:11–12`). Six task shapes —
`inspect` / `search`·`list` / `trace` / `compare` / `workflow` /
`observe`·`capture` (`:16–27`). Prefer primitives and edge composition over
orchestration languages (`:29–44`).
Strict inputs; inline results with identity/coverage/limitations;
observed·derived·inferred distinct; "missing coverage is unknown, not
absence"; limits only where measured (`:46–71`). A deep
**lifecycle-ownership** chapter: exit ≠ output closure, cleanup bound to
exact owners, "client cancellation alone does not prove native work stopped"
(`:73–165`). Discoverability is evaluated on real agents, not schema validity
or keyword heuristics (`:192–196`).

## Comparison with calxgloss

### Two agent-layer strategies

**REA: the agent is the orchestrator; the skill is the control plane.** Its
product is a huge tool surface plus a manual turning a generalist agent into
a safe operator; every skill rule targets an agent failure mode (tabulated
below). calxgloss ships none of this: no MCP surface, no user skill — the
workflow never runs inside a context window, it *is* Rust code
(pipeline + review UI, ch. 10), stages written as prose in
`docs/Calxgloss.md` §"Agent Workflow" (`:653–701`).

**calxgloss: skills shape the *development* of the harness, never its
operation.** The installed suite (`docs/skills-review.md`) is the mattpocock
development-workflow set — `grill-with-docs → to-spec → to-tickets →
implement (tdd + code-review) → retro`, plus standing `diagnosing-bugs`,
`research`, `handoff` — and `AGENTS.md` is the navigation/process layer:
graft-first code context, GitHub Issues tracker, domain docs,
`docs/standards.md` feeding the code-review Standards axis. Nothing teaches an
agent to *run* calxgloss's 23-command CLI. REA's dev skills are the same
genre pointed at REA — the only genuine overlap between the two agent layers:
bespoke and scope-limited ("an investigation alone does not authorize edits",
ci-tests-audit:15–17) vs a generic suite adopted and pruned with written
verdicts.

| Failure mode | REA (agent-side) | calxgloss (harness / dev side) |
|---|---|---|
| Context bloat | progressive disclosure, compact profiles, summary+view paging, optional prompts | prompt built by code: 5 tiers + evidence digests; nothing to bloat during translation |
| Stale registrations/knowledge | doctor, dry-run plans, version-skew rules, follow-the-connected-server rule | near-zero surface (nothing to go stale); the analog is stale docs/graft vs code — AGENTS.md mandates `graft build`; CHANGELOG+roadmap tick per commit |
| Tool misuse | routing table, availability probe, banned unadvertised calls, never guess targets | tools are crate calls in the pipeline; misuse is a bug → `diagnosing-bugs` + tdd red test |
| Bad LLM output | self-policed evidence rules | **fault monitors** (hallucination, infinite loop, divergence, exhaustion) + FFI baseline gate + human review UI |
| Unsafe retry | don't-repeat rules, remediation-literalism, retry-to-test-transient only | named strategies (`compile_fix`/`test_fix`/`escalate`/`edge_case_fix`/`auto`) always change inputs, so "repeat unchanged" is unrepresentable |

### Error recovery: ladder vs monitors

**REA's ladder is a *judgment* automaton** run at each observed error — it
exists because REA breaks on what it doesn't own: client
approval policy, PATH, host deadlines, engine installs. calxgloss needs none
of that vocabulary; its don't-repeat doctrine is mechanical: every retry
strategy alters inputs, and fault monitors stop loops that make no progress —
the compiled mirror of "do not retry a failure that returns the same
unchanged result." The gap: REA's diagnose→continue→resume discipline has no
calxgloss analog — with an LLM endpoint down the pipeline has no
partial-work path; a failure record could encode "keep answering with
available evidence, name what you can't."

### Context budget

REA budgets the *catalog and transport* (13.3 KB compact schemas, output-
schema profile, summary/retained-view paging, completion capped at 100);
calxgloss budgets the *per-function prompt* (5 tiers, escalated on failure —
mapped in chs. 31/33). Same axis, opposite ends: shrink the 150-tool catalog
vs grow per-function context only where the cheap attempt failed. REA's optimization skill supplies the
measurement discipline both should hold — count discovery, retries and
continuations in any token claim (`:102–105`).

### calxgloss-only / REA-only (this layer)

**calxgloss-only:** a navigation layer for its own source (graft — REA has no
indexed graph of its own repo); a reviewed skills inventory with pruning
verdicts; fault monitors + named retries + review-UI gate as recovery; zero
user-facing agent surface by design — nothing can go stale. **REA-only:** shipped user skill with
anti-trigger + progressive disclosure; dry-run plans, backups,
ownership-aware config writes for 24 clients; scoped
read-only doctor (scope/informational split, `--json`, exit statuses);
`server.json` registry discovery; MCP prompts + session-aware completion;
schema profiles tuned to named provider caps with boundary-tested budgets; a
dated version-skew section; the recovery state machine.

### Verdict

One question, opposite answers: *who orchestrates?* REA answers "the agent,
armored by skill + server-side contracts" — its job, arbitrary analyst
questions across ~30 artifact families, cannot be pre-encoded. calxgloss
answers "the pipeline" — its job, one deterministic PE→Rust conversion
unattended at scale, must not depend on an agent behaving.
Each is weakest where the other is strong: REA can't finish a whole-binary
translation by itself and its recovery ladder is prose an agent may ignore;
calxgloss can't answer a novel runtime question, can't self-diagnose its
environment (doctor loads Kuna on one target and stops —
`calxgloss-cli/src/commands/doctor.rs:18–41`), and gives operators no driver
for its 23-command surface beyond hand-written docs.

### Steal ideas

1. **A "drive the calxgloss harness" skill for contributors** — REA's shape
   inward: short SKILL.md (when to run `classify` vs `translate` vs `auto` vs
   one evidence command; routing analogue: managed PE → parked (ADR-0044),
   EXE vs DLL → which lane) + `references/` for per-engine recipes and the
   failure playbook — progressive disclosure beats a 1,390-line design doc.
2. **Deepen `calxgloss doctor` REA-style** — read-only but scopable
   (`--target/--endpoint/--config`), checking what actually breaks runs: LLM
   endpoint reachability (Ollama/vLLM), config validity, `target_dir` PE
   magic, `re/` cache writability, git/cargo presence, graft freshness; emit `scope_checks` vs `informational_checks` + JSON + exit
   codes (installation.md:344–363) so CI and agents gate on the task's scope.
3. **Copy don't-repeat / remediation-literalism into `AGENTS.md`** — "retry
   only to test a specific transient explanation; a passing retry does not
   establish a root cause" (rea-ci-tests-audit:70–72).
4. **Version-skew discipline for docs** — calxgloss's analog of "repo-main
   skill vs older npm release" is "AGENTS.md/skills/graft describe main, the
   built binary says otherwise": date-pin doc claims à la
   installation.md:493–506; `graft build` + CHANGELOG rules are already its
   paired-install equivalent.
5. **`agents/openai.yaml`-style machine interfaces** on calxgloss's own
   skills (tdd, code-review, diagnosing-bugs) — machine-discoverable trigger
   prompt + scope limits.

## Sources

REA (`/tmp/opencode/rea` @ `28a33ca`): `.agents/skills/reverse-engineer-anything/SKILL.md` (452) + `references/connection-and-recovery.md` (205) + `evidence-workflows.md` (full; ch. 33) + format references (headings only; chs. 32/34); the 4 dev skills (20/112/134/113), `agents/openai.yaml` ×2, refs (skim); `docs/installation.md:14–60, 328–414, 486–585`; `docs/mcp-prompts.md` + `docs/tool-design.md` (full); `docs/mcp-contracts.md:1045–1114`; `docs/agent-environments.md` (skim); `server.json`; `src/doctorRuntime.ts:1–120`; `src/main.ts:98–99`; `src/config/mcpOutputSchemaProfile.ts:14`.

calxgloss: `docs/rea/10-calxgloss-baseline.md`, `20-rea-inventory.md` §1/§7,
chs. 31/33/34 comparison sections (cross-referenced, not repeated);
`docs/skills-review.md` (full); `AGENTS.md`; `docs/standards.md` (full);
`docs/Calxgloss.md:653–722`; `crates/interface/calxgloss-cli/src/commands/doctor.rs:18–41`,
`crates/interface/calxgloss-reports/src/doctor.rs:1–53`.
