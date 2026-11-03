# ReVa's skills and agent layer — marketplace, skills, subagents, hooks

> Part of the [ReVa overview](README.md). How ReVa packages its 88-tool MCP
> surface for Claude Code — marketplace + plugin, the six `ReVa/skills/`, the two
> dev subagents and the SessionStart hook, and the CLAUDE.md/AGENTS.md/DEVELOPER.md
> scaffolding for agents working *on* ReVa — against calxgloss, which ships no
> end-user skill and encodes its workflow in Rust. Citations are `path:line`
> relative to clone root `/tmp/opencode/cyberkaida-rea` @ `a2fcd94`.

## 1. Marketplace and plugin packaging

Two nested `.claude-plugin` dirs split *marketplace* from *plugin*.

- **Marketplace** — repo-root `.claude-plugin/marketplace.json:1-14`:
  `name:"reva"`, owner `CyberKaida`, one entry `name:"ReVa", source:"./ReVa"`.
  `claude plugin marketplace add cyberkaida/reverse-engineering-assistant`
  registers the repo as a marketplace; `claude plugin install ReVa` installs the
  `./ReVa` sub-package (`README.md:181-184`).
- **Plugin manifest** — `ReVa/.claude-plugin/plugin.json:1-8`: `name:"ReVa"`,
  `version:"0.1.0"`.
- **What ships** — `ReVa/` holds only `.claude-plugin/`, `LICENSE`, `.mcp.json`,
  `skills/`. **No `commands/` or `agents/` in the plugin dir**: an installed user
  gets the *six skills* + an *MCP registration*. The `.claude/` agents/hooks (§3)
  and root `marketplace.json` are **repo/dev config, not the shipped plugin**.

**`.mcp.json` auto-wiring.** `ReVa/.mcp.json:1-11` declares `mcpServers.ReVa` as
`command:"uv", args:["run","mcp-reva"]`, `env.UV_WORKING_DIRECTORY =
${CLAUDE_PLUGIN_ROOT}/../`. Under the plugin convention a plugin-root `.mcp.json`
is registered automatically on install, so **installing the plugin auto-configures
the MCP server**, `${CLAUDE_PLUGIN_ROOT}/../` pointing back at the repo for
`pyproject.toml`. This registers the **stdio/headless** `mcp-reva` CLI, not the
GUI HTTP server; GUI mode is wired by hand via `claude mcp add --scope user
--transport http ReVa -- http://localhost:8080/mcp/message` (`README.md:102,144`).
Skills are discovered under `skills/` and fire by frontmatter `description`.

## 2. The six skills — anatomy

| Skill | SKILL.md | extra assets | shape | names exact tools? |
|---|---|---|---|---|
| `binary-triage` | 155 | — | breadth-first survey (8 steps) | yes |
| `deep-analysis` | 607 | `patterns.md` 720, `examples.md` 733 | depth-first loop | yes |
| `ctf-crypto` | 323 | `patterns.md` 630 | 4-phase crypto-in-binaries | yes |
| `ctf-pwn` | 532 | `patterns.md` 948 | exploitation *thinking* framework | yes |
| `ctf-rev` | 548 | `patterns.md` 906 | comprehension-under-constraints | yes |
| `pyghidra-scripting` | 240 | `references/` ×5 (1,568 lines) | scripting escape hatch | yes |

SKILL.md total = 2,405 lines; assets add 5,505 more (~7,900 total). Frontmatter is
only `name`+`description` — **none uses `allowed-tools`** (verified repo-wide).
Every skill hard-codes the real kebab-case tool names (`get-decompilation`,
`find-cross-references`, `rename-variables`, `change-variable-datatypes`,
`search-decompilation`, `set-bookmark`, `checkin-program`…), so skill text and the
88-tool surface (ch. 31) are kept manually in sync — no generated tool index.

**Analysis workflows.** `binary-triage` enforces a fixed 8-step breadth survey —
program → memory blocks → strings (paginated 100–200) → symbols/imports →
functions (named/unnamed ratio = stripped) → xrefs on findings → *selective*
decompilation capped `limit=20-30` ("**Do not do deep analysis yet**",
`binary-triage/SKILL.md:92`) → a `TodoWrite` task list; its gate is *economy*
(pagination, "speed over depth", `includeContext=true`, `:148-155`).
`deep-analysis` is the depth-first mirror: a 6-beat **Investigation Loop** READ →
UNDERSTAND → IMPROVE → **VERIFY (re-read)** → FOLLOW → TRACK, plus an "ON-TASK
CHECK every 3–5 calls" (`deep-analysis/SKILL.md:18-73`). Read-before-modify is a
*process* rule here (VERIFY re-decompiles to confirm the rename helped, `:48-51`) —
prose echo of the server-side tracking in ch. 31. Quality gates: every claim needs
**Address + Code + Context** (`:260-285`); assumptions logged High/Med/Low
(`:287-315`); a **10–15 tool-call budget** with "partial results OK" (`:454-470`);
structured JSON handoff `question/answer/confidence/evidence/improvements/
unanswered_threads` (`:340-397`).

**CTF skills** (rev/pwn/crypto) share a shape — Purpose → Conceptual Framework →
Methodologies → Flexible Workflow → Pattern Recognition → ReVa Tool Usage →
Integration → Remember — deferring signature catalogs to `patterns.md`:
`ctf-crypto` = Detect→Identify→Analyze→Extract, fenced to "crypto **embedded in
binaries**, not pure mathematical challenges" (`ctf-crypto/SKILL.md:19`); `ctf-pwn`
= a thinking framework (data-flow/memory-safety/exploitation layers; 7 questions
`:36-74`) that repeatedly pushes the payload off-Ghidra — "This happens **outside
Ghidra** using Python/pwntools" (`:285`), "Ghidra doesn't have built-in gadget
search" → ROPgadget (`:376`) — deliverable "Document enough information in Ghidra
to write the exploit script" (`:532`); `ctf-rev` = the "Three Questions"
(`:26-45`), *sufficient not full* understanding (`:46-72`), four strategies
(top-down / bottom-up / pattern / constraint-solve to z3), static-vs-dynamic
("ReVa focuses on static analysis … use external debuggers", `:137`).

**Tooling skill.** `pyghidra-scripting` documents the *five scripting tools*
(`run-script`/`list-scripts`/`read-script`/`write-script`/`edit-script`), not an
analysis workflow. Strongest anti-trigger in the set — "Do **NOT** use this skill
for plain ReVa tool calls that already have a dedicated MCP tool"
(`pyghidra-scripting/SKILL.md:3`) — plus an execution contract (pre-bound globals;
**no automatic transaction**, mutations need manual `startTransaction`, `:50-60`;
cooperative `monitor.isCancelled()`; 64K stdout/stderr cap), a PyGhidra-only
runtime gate (`:33-42`), and a `references/` tree that is **progressive
disclosure** — "Load only the one(s) relevant" (`:218-230`).

## 3. Two dev subagents and the SessionStart hook (repo `.claude/`, not shipped)

- **`ghidra-api-expert.md`** (71) — `model: sonnet`; answers Ghidra *Java API /
  plugin-architecture* questions, cites package paths, warns on threading/
  transactions/EDT. Its `tools:` carry the **GitHub MCP** set + Kagi + WebSearch
  (`:4`) — a *research* agent for ReVa's *developers*, not for RE targets.
- **`reva-setup-installer.md`** (91) — DevOps: clone Ghidra source to `../ghidra`,
  install the Ghidra *binary* to `GHIDRA_INSTALL_DIR` ("must NEVER point to the
  git clone", `:35`), `uv venv`, install local PyGhidra; success = green `gradle`.

**Hook** — `.claude/settings.json:10-22` registers **one** event: `SessionStart`
(matcher `startup`) → `.claude/hooks/setup-remote-env.sh`; it also grants
`permissions.allow` `Search`/`Read(../ghidra/**)` (`:2-8`). The script is
**guardrail-by-mode**: locally it only *logs* Ghidra/Java/Gradle presence and
`exit 0` (`setup-remote-env.sh:23-50`); on `claude.ai/code` (`CLAUDE_CODE_REMOTE=
true`) it clones source + downloads the binary *in parallel*, exports and persists
`GHIDRA_INSTALL_DIR` via `CLAUDE_ENV_FILE` (`:136-143`); because the JVM ignores
`https_proxy` it launches `gradle-proxy.py`, a local unauthenticated CONNECT proxy
on `127.0.0.1:18080` re-injecting the upstream `Proxy-Authorization` header
(`gradle-proxy.py:49-101`), then warms the Gradle cache. **No formatting or
file-protection hook** exists; the only invariant is `GHIDRA_INSTALL_DIR ≠
git-clone`. `.claude/launch.json` pre-declares the headless + CLI stdio run configs.

## 4. CLAUDE.md / AGENTS.md / DEVELOPER.md — agents *editing* ReVa

Dev-workflow scaffolding, distinct from the *using* skills. Unusually layered:
**33 CLAUDE.md files, 11,755 lines** — a `src/CLAUDE.md` index (`src/CLAUDE.md:183-201`)
linking a CLAUDE.md per package (e.g. `tools/decompiler/CLAUDE.md`, 593 lines,
lists that package's tools + patterns). Head docs: **CLAUDE.md** (331) build/test
(`gradle` not `./gradlew`; `pytest -m unit|integration|e2e`), three run modes,
"ALWAYS use ReVa utilities" table (`CLAUDE.md:208-216`), JUnit 4 only; **AGENTS.md**
(85) style (Java 21, Javadoc required), JSON error shape, must-use utilities;
**DEVELOPER.md** (440) architecture + the *17 tool providers* table
(`DEVELOPER.md:79-85`) + adding-tool recipes; `.github/copilot-instructions.md` is
the Copilot/Cursor variant. Count drift: docs say "17 providers" while the tree has
19 tool packages / ~88 tools (ch. 31) — docs lag code, the version-skew hazard the
sibling `rea/` chapter formalizes.

## 5. `.continue/docs` — the Continue IDE path (placeholder)

`new-doc.yaml:1-6` indexes the **MCP Java SDK docs**
(`modelcontextprotocol.io/sdk/java/mcp-overview`); `new-doc-1.yaml` is a bare stub
at `docs.continue.dev`. These feed Continue's docs-embedding (codebase-context
sources), so a Continue user gets SDK docs *retrieved* at query time. Unlike the
Claude Code path, Continue has **no skills, no hooks, no `.mcp.json`** — retrieval
only; Claude Code gets skills + auto MCP registration + SessionStart provisioning.

## 6. Meta — how skills and the 88 tools partition knowledge

A clean **workflow/facts split**: the 6 SKILL.md files carry *sequencing and
discipline* (triage order, the read→improve→verify loop, CTF strategies, when to
drop into `run-script`); the 88 tools carry *facts* (one-shot Ghidra ops, forgiving
schemas); the 33 nested CLAUDE.md carry *facts about the code*. Each skill stays
short (155–607 lines) and defers recognition catalogs to sibling `patterns.md` —
cyberkaida encodes **RE domain** knowledge there. Contrast the sibling in
`docs/research/rea/35`: **morluto/rea** concentrates one 452-line skill + ~90
reference docs and heavy *product-operating* machinery (recovery, `doctor`,
`setup`, 24 clients, anti-triggers). cyberkaida's skills assume the tools already
work — **no recovery or version-skew section** — betting on the model's RE
knowledge plus the tool schemas; depth lives in crypto/pwn/rev signature catalogs,
not client plumbing. Same progressive-disclosure principle, opposite content axis:
*what RE to do* vs *how to keep the product running*.

## Comparison with calxgloss

**Two placements of domain knowledge.** ReVa puts the workflow *in the skill*, so
the orchestrator is a general coding agent reading SKILL.md at prompt time.
calxgloss puts it *in Rust*: the pipeline, `RetryStrategy { Default, CompileFix,
TestFix, Escalate, EdgeCaseFix }`
(`crates/shared/calxgloss-types/src/retry_strategy.rs:31-42`), the five
`ContextTier` Signature→FullModule (`…/context_tier.rs:59-69`), and `FaultCategory`
ContextWindowExceeded/Hallucination/InfiniteLoop/BehaviorDivergence/
ResourceExhaustion/SlowResponse/PromptCorruption (`…/fault.rs:43-100`). **No
end-user skill, no MCP surface** — prompts live in crates and never run in a user's
context window. ReVa *must* encode in skills (analyst questions can't be
pre-compiled); calxgloss *can* encode in code (one deterministic PE→Rust job).

- **Overlap.** Only the *dev* layer: ReVa's CLAUDE.md/AGENTS.md/DEVELOPER.md +
  two dev subagents are the genre of calxgloss's `AGENTS.md` + `docs/standards.md`
  + graft nav (`AGENTS.md:39,47`) — how to build/test/extend the project.
- **calxgloss-only.** An indexed source graph (graft, `graft build`); a pruned
  skills inventory (`docs/skills-review.md`); fault monitors + named retries as
  runtime recovery; and by design zero user surface, so nothing can go stale.
- **ReVa-only (this layer).** A shippable marketplace + plugin with auto MCP
  registration via `.mcp.json`; six end-user skills naming exact tools; a
  SessionStart hook that *provisions the environment*; per-package CLAUDE.md;
  `patterns.md` RE catalogs.

**Verdict.** This is the axis of sharpest divergence, and calxgloss is thin on
purpose. ReVa's skills are a *product* turning a generalist into an RE operator —
what calxgloss refuses to need. ReVa's weakness is the flip side: skills are prose
an agent may drift from, hand-code 88 tool names (drift risk), and impose
"budgets" nothing enforces; calxgloss enforces the same discipline (retry-always-
changes-input, don't-repeat, fault-stop) *in the type system*. calxgloss has no
driver for its 29-subcommand CLI beyond hand docs; ReVa has skills but no
self-diagnosis — its `doctor` loads Kuna in-process and needs `--binary`
(`crates/interface/calxgloss-cli/src/commands/doctor.rs:18-41`).

**Steal-list.**
1. **A `calxgloss-triage`/`calxgloss-review` skill as a *contributor* driver** —
   modeled on binary-triage→deep-analysis: short SKILL.md routing "`classify` vs
   `translate` vs `auto` vs one evidence command," progressive disclosure into
   `references/`, closing calxgloss's "no CLI driver" gap without a user skill.
2. **`.mcp.json`-style declarative client wiring** — mirror the convention (a file
   that *auto-configures* the tool for a client, `${CLAUDE_PLUGIN_ROOT}` relative
   paths) as a `calxgloss.mcp.json`/opencode config so editors auto-register the CLI.
3. **SessionStart-hook idea for `AGENTS.md`** — value is *environment self-check on
   entry*; calxgloss's dev analog is a cheap "graft fresh? / cargo? / endpoint up?"
   check (`doctor` is the seed), not ReVa's remote installer.
4. **Patterns-catalog progressive disclosure** — keep `docs/standards.md` lean,
   split per-domain RE rules (PE lanes, managed-PE parking) into on-demand refs.
5. **Anti-trigger discipline** — pyghidra's "do NOT use when a dedicated tool
   exists" is the prose twin of calxgloss's fault monitors; restate once in `AGENTS.md`.

## Sources

ReVa (`/tmp/opencode/cyberkaida-rea` @ `a2fcd94`): `.claude-plugin/marketplace.json`;
`ReVa/.claude-plugin/plugin.json`; `ReVa/.mcp.json`; all six `ReVa/skills/*/SKILL.md`
+ `patterns.md`/`examples.md`/`references/`; `.claude/{settings.json,launch.json,README.md}`,
`.claude/agents/*`, `.claude/hooks/{setup-remote-env.sh,gradle-proxy.py}`;
`CLAUDE.md`(331)/`AGENTS.md`(85)/`DEVELOPER.md`(440)/`src/CLAUDE.md`/nested CLAUDE.md
(33 files, 11,755 lines)/`.github/copilot-instructions.md`; `.continue/docs/*`;
`README.md:95-191`. Tool surface cross-referenced (ch. 31), not repeated.
calxgloss: `crates/shared/calxgloss-types/src/{retry_strategy,context_tier,fault}.rs`;
`crates/interface/calxgloss-cli/src/commands/doctor.rs:18-41`; `AGENTS.md:39,47`;
`docs/standards.md`; `docs/skills-review.md`; contrasts drawn with
`docs/research/rea/35-skills-and-agent-layer.md` (morluto/rea).
