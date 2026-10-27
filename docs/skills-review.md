# Skills Review — calxgloss

> **Current as of 2026-10-05 (post-setup, post-cleanup).** 26 of the original
> 38 skills from [`mattpocock/skills`](https://github.com/mattpocock/skills)
> are still installed in `.agents/skills/`. That directory is the only project
> directory OpenCode discovers skills from. `.agents/` is gitignored, the same
> as `.claude/`, `.gemini/`, and `AGENTS.md`. `skills-lock.json` and the root
> `skills/` symlink shim are gone.
>
> `setup-matt-pocock-skills` has run: tracker = **GitHub Issues** via `gh`
> (`scriptandcompile/calxgloss`), triage labels = the five defaults, domain
> docs = **multi-context** — see `docs/agents/issue-tracker.md`,
> `docs/agents/triage-labels.md`, `docs/agents/domain.md`, and the
> `## Agent skills` block in `AGENTS.md`.
>
> Verdicts are against **this repo's actual context**: a solo Rust workspace,
> a test-driven decompilation harness, graft as the code-navigation layer, and
> an existing planning process (`docs/roadmap.md` + `CHANGELOG.md`).

---

## 1. How the collection fits together

The collection is not 26 independent tools — it is one ecosystem (see
`.agents/skills/ask-matt/SKILL.md`, the router):

- **Main flow (idea → ship):** `grill-with-docs` → *(optional detour:
  `handoff` + `prototype`)* → `to-spec` → `to-tickets` → `implement`
  (which runs `tdd` + `code-review`) → `retro`.
- **On-ramps:** `triage` (incoming issues), `diagnosing-bugs` (something is
  broken), `wayfinder` (effort too big for one session).
- **Vocabulary layer running underneath:** `grilling`, `domain-modeling`,
  `codebase-design` — other skills invoke these internally.
- **Precondition (done):** `setup-matt-pocock-skills` has run, so `to-spec`,
  `to-tickets`, `triage`, `implement-spec`, and `domain-modeling` all have a
  configured tracker and doc layout to read from.

## 2. Basic usage and workflow suggestions

**Invoking skills.** Most skills trigger automatically when your request
matches their description ("debug this" → `diagnosing-bugs`, "review since
main" → `code-review`). To choose deliberately, write the skill's name in
your prompt (`/implement`, "use the tdd skill on this ticket"). When you are
unsure which skill fits, ask `ask-matt` — it is the router.

**One-time follow-ups still open:**

1. **Create the glossary files.** The multi-context layout is configured
   (`GLOSSARY-MAP.md` → per-context `GLOSSARY.md`) but no files exist yet.
   `grill-with-docs` and `domain-modeling` will fill them in as you use them.
   `wait-what` does nothing until at least the root file exists.
2. **Decide on `pr` and `setup-pre-commit`** — see §4.

**Per unit of work** (a phase from `docs/roadmap.md`, or a new
crate/feature):

1. **`grill-with-docs`** — sharpen the phase plan. It adds entries to
   `GLOSSARY.md` and ADRs, which suits this repo well: its domain language
   (disassembly, IR, restitching, PAL, per-crate methodologies) is genuinely
   essential.
2. **`to-spec` → `to-tickets`** only when a phase is multi-session (they
   publish to GitHub Issues). For the smaller crate increments you already
   do (recent history: one crate feature per commit), go straight to
   **`implement`**. It runs **`tdd`** and **`code-review`** for each ticket,
   which matches the repo's "test-driven decompilation" principle almost
   exactly.
3. Keep the existing repo conventions as the record of *what shipped*:
   `CHANGELOG.md` and the `docs/roadmap.md` checklist stay
   authoritative; specs/tickets on the tracker are the *planning* layer,
   not the changelog.
4. **`retro`** at the end of a build that went badly — it improves the
   harness (checks, standards, steering files), and improving the harness is
   exactly the point of a harness project.

**Standing usage:**

- **`diagnosing-bugs`** for the hard ones (analysis engine integration bugs,
  nondeterministic LLM output, regressions between known-good commits).
- **`research`** for Kuna/PE/LLM primary-source questions — it runs as a
  background agent and leaves a cited Markdown file.
- **`code-review`** per commit unit: give it a fixed point ("review since
  `<sha>`"). Both axes now check against real documents: the Standards axis
  reads `docs/standards.md` (plus `AGENTS.md`), and the Spec axis reads
  the originating issue from the tracker.
- **`improve-codebase-architecture`** periodically; its "deepening
  opportunities" scan pairs naturally with graft and the multi-crate layout.
- **`handoff`** between sessions instead of ad-hoc summaries.

## 3. Verdicts

### Keep — core (use regularly)

| Skill | Why |
|---|---|
| `ask-matt` | Router; cheap, manual-only. |
| `setup-matt-pocock-skills` | Precondition — already run; re-run only to change tracker/label/domain config. |
| `grill-with-docs` + `grilling` + `domain-modeling` | Main-flow entry. It invokes `grilling`/`domain-modeling`, and `triage`/`wayfinder` invoke them too, so all three stay. Domain glossary discipline fits this repo's vocabulary. |
| `to-spec`, `to-tickets`, `implement` | Multi-session build flow; `implement` also covers the small increments you do most often. |
| `tdd` | Direct match for core principle #3 (test-driven decompilation). |
| `code-review` | Standards+Spec review of each commit unit. The Standards axis now reads `docs/standards.md` (error handling, crate anatomy, persistence, testing) — linked from `AGENTS.md`. |
| `diagnosing-bugs` | Strong fit: it forces a tight red-test loop before theorising — ideal for LLM-pipeline and analysis engine bugs. |
| `retro` | Harness-improvement loop — the same idea as what calxgloss does to binaries. |
| `research` | Primary-source reading for analysis engine and API questions; it runs in the background. |
| `prototype` | Throwaway code to settle state-model questions (e.g. callgraph data shapes). |
| `handoff` | Session hygiene; used by the main flow's prototype detour. |
| `codebase-design` | Deep-module vocabulary that `tdd` and `improve-codebase-architecture` use; pairs with graft. |
| `improve-codebase-architecture` | Keeps the multi-crate workspace agent-navigable. |
| `writing-for-agents` | You maintain `AGENTS.md`, graft nodes, and now skills — this is the reference for all of it. |

### Keep — situational (use occasionally, don't expect them)

| Skill | Why situational |
|---|---|
| `wayfinder` | For efforts too big or unclear to plan. `roadmap.md` already *is* your wayfinder output — keep it for the next greenfield-scale effort only. Do not run it on already-mapped work. |
| `implement-spec` | Whole-spec orchestration with parallel implementer subagents. Powerful but heavy; try it once on a well-partitioned phase before adopting. |
| `triage` | Kept because the tracker is now GitHub Issues — useful once the repo gets external issues/PRs. Solo today, so expect light use. |
| `wizard` | Useful for genuinely human-only steps (API keys for hosted LLM fallbacks). Otherwise ignore. |
| `wait-what` | Tiny, manual-only; does nothing until `GLOSSARY-MAP.md`/`GLOSSARY.md` exist (see §2 follow-ups). |
| `to-questionnaire` | Solo project — no stakeholders to interview. Keep only if you ever collaborate; otherwise remove. |

## 4. Still installed, flagged for removal

These were kept in the cleanup, but the original objections still apply:

| Skill | Reason |
|---|---|
| `setup-pre-commit` | Husky / lint-staged / Prettier — a JS toolchain. The Rust equivalent is `cargo fmt` + `cargo clippy` + `cargo test` in a hook; this skill would add unused Node tooling. Remove unless you port the idea to Rust hooks. |
| `pr` | A GitHub remote now exists, but work is still committed directly to local `master` as commit units — there is no PR workflow in use. Remove it until you actually adopt PRs; reinstalling is cheap. |

## 5. Conflicts and overlaps to watch

1. **`roadmap.md` vs `to-spec`/`to-tickets`** — the roadmap already
   decomposes work into phases with a checklist. Don't re-spec existing
   phases; let `to-tickets` decompose *one phase at a time* when you pick
   it up.
2. **graft stays primary** — several skills tell the agent to explore the
   codebase, and `AGENTS.md` already requires graft-first. There is no
   conflict, but do not let skill instructions take navigation back to
   raw grep.

## 6. Resolved since the original review

- **Setup precondition** — `setup-matt-pocock-skills` has run, so the old
  "no tracker / no remote / local-markdown" description is obsolete.
- **`code-review` Standards axis** — `docs/standards.md` now
  documents the repo's conventions and is linked from `AGENTS.md`.
- **Grill overlap** — the user-level `grill` skill at
  `~/.config/opencode/skills/grill` has been deleted; only the project-level
  `grilling`/`grill-with-docs` remain.
- **Cleanup executed** — 12 of the 15 removals were carried out
  (`migrate-to-shoehorn`, `setup-ts-deep-modules`, `scaffold-exercises`,
  `claude-handoff`, `git-guardrails-claude-code`, `writing-beats`,
  `writing-fragments`, `writing-shape`, `teach`, `loop-me`, `chief-of-staff`,
  `grill-me`); `triage` was deliberately kept (GitHub tracker). The
  `skills-lock.json` record-keeping no longer applies — the lockfile is gone.
