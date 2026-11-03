# GameFrame vs calxgloss: full comparison

> Part of the [game-frame overview](README.md). GameFrame at `f195a074` (2026-10-30); calxgloss at `40fbf91f` (2026-10-31).

## 1. The comparison frame

GameFrame's bet is that a translation program is a *pipeline with a
harness*: deterministic Rust engines, a launcher that owns their
lifecycle, and a test suite that proves the tools fail correctly. Its
unit of work is a *slice* — narrow, typed, independently proven, landed
one at a time by one person [21 §3]. calxgloss's bet is that a
translation program is a *harness with doctrine*: a 2,360-line design
bible (`docs/Calxgloss.md` 1,387 + `docs/data_flow.md` 973) plus 57
ADRs in markdown, an honesty protocol where every gap is a named
record, and a git ledger where every attempt is kept. Its unit of work
is an *attempt* — prompt → LLM call → verification → record against one
function, graded by Wine replay against the original
[10 §Pipeline anatomy, §Verification & evidence; ADR-0051].

They nevertheless rest on the same two commitments:

- The ground truth for understanding a binary is *running the original*
  — GameFrame against real game processes and original DLLs [34 §5, 35
  §8], calxgloss against Wine-captured per-function baselines [10 §2].
- Neither ships a whole-program conformance verdict for any real target.

Both decline that verdict for the same reason — principle 1: an
incomplete inventory must be reported as unknown, never as success —
and the interesting part of this chapter is the *machinery* each has
built for that honesty. So the comparison asks two questions: where does
each machine disagree, and which parts of each machine would move the
other forward.

## 2. Feature-by-feature

| Capability domain | game-frame | calxgloss | Verdict |
|---|---|---|---|
| Who translates | An AI coding agent (Claude Code, Codex, Gemini, Copilot, Cursor or OpenCode) works the slice inside the checkout; the human is the sole lander [21 §1, §2; 32 §5] | `calxgloss live` runs the Rust loop — read cache ▸ evidence warmup ▸ fetch ▸ prompt ▸ translate ▸ verify ▸ retry ▸ commit — with a locally hosted LLM behind an OpenAI-compatible seam [10 §Pipeline anatomy, §Model layer] | **Genuine split.** GameFrame ships no translator at all — it curates the *conditions* for a third-party agent; calxgloss ships the whole loop and owns the model relationship |
| Where method knowledge lives | 16 markdown skills + 23 agent role cards, read by whatever vendor agent is present; "the method is in the docs" [31 §8; 32 §2] | the 2,360-line design bible (`docs/Calxgloss.md`, `docs/data_flow.md`) + roadmap + 57 ADRs + per-context glossaries — doctrine for whoever *builds* the harness; the method the shipped loop follows is compiled into Rust and 29 `.j2` prompt templates [10 §Model layer] | **Genuine split** — the deepest in the comparison: markdown read by anyone's agent vs markdown that only ever feeds its own Rust loop |
| Analysis engine | Ghidra: headless export + one-off jobs (`scripts/ghidra-run.sh`), plus standalone question-tools over the export — `decomp_query.py`'s nine commands, `sigscan.py` [33 §1–2] | Kuna in-process (`calxgloss-kuna`) — the only analysis engine (ADR-0041); the seam answers only declared scan/query families, and each scan stamps a coverage record (ADR-0053) [10 §Pipeline anatomy] | **Genuine split — GameFrame's biggest advantage.** calxgloss has no ad-hoc query path at all (P29): no way to ask "who calls this" without a full scan |
| Evidence into the translator | `./gameframe find WORD` and `advise` route to prior evidence and known failures (`tools/gameframe/__main__.py:15-17`); per-address answers on demand via `decomp_query.py` (`fn/callers/strings/writers…`, `tools/triage/decomp_query.py:7-15`) [33 §1] | the evidence bundle — one `.j2` section per scan engine (ADR-0048/0049), five context tiers, and open unknowns fed into retries via `open_unknowns.j2` [10 §Model layer] | **Even.** Both learned that an agent without a queryable view of prior evidence redoes it |
| Ground truth capture | GameFrame launches the real product and replays saved games against real DLLs [34 §5]; wrappers record WRAPPER_CALLS against the live original DLL [35 §8] | Wine-captured baselines under `re/baseline/*/baseline.json` — recorded return values plus the original's ordered API-call sequence (ADR-0057) [10 §Verification & evidence] | **Same shape.** Same oracle philosophy, different rigs: live game session vs Wine replay |
| Verification placement | Verification is *throughout*: gates before writes, conformance tests on engines, proof ladders per crate, human acceptance at the end [32 §5; 35 §9] | Verification is *terminal*: every attempt is graded before anything merges (ADR-0051), and the trace gate judges ordered containment (ADR-0057) [10 §Verification & evidence] | **Genuine split — GameFrame's second advantage:** verification is a property of the toolchain, not a stage; its negative controls have no calxgloss counterpart — zero negative-control tests, verified at `40fbf91f` |
| Naming and typing doctrine | Names are evidence to recover and record: findings must name the original (`templates/project/AGENTS.md:65`), rebuilt names go into `labels/names.tsv`, "read by the tools" (`:78, :112`) [31 §6; 20 §17] | no renaming anywhere: binary-side identity is verbatim in branch, output path, log join key and Wine locator; write-back is types-only (ADR-0020/0021); names stay evidence that rides into prompts, never applied | **Genuine split** — the one philosophy difference that must stay: GameFrame is reconstructive, calxgloss evidential |
| Honesty records | 356-line GAPS.md with 149 checked / 29 unchecked; a ledger of unclosed claims where release notes are the acceptance record [36 §6.2; 21 §1] | 6-kind typed UnknownRecord ledger (ADR-0053/0056); unresolved facts join at read time and route to owners [10 §4] | **Same idea, different media** — machine-readable ledger vs a human checkbox ledger |
| Per-unit git ledger | History rewrite banned; `update-project.sh` refuses to touch anything dirty; completed slices land as commits [34 §4.3; 21 §3] | Branch ledger `re/{binary}/{function}v{N}`, kept forever; accepted work drains through the web review queue, mirrored by `calxgloss dashboard` actions [10 §Surface & state] | **Same idea** — different retention: GameFrame keeps decisions, calxgloss keeps every attempt |
| Review surface | VitePress site generated from the repo's own catalogs — "it holds no copies of their content" (`AGENTS.md:86`, [20 §16]) — the README is the human entry point mapping every surface [20 §1]; evidence labels bind claims to their sources [31 §2] | the Axum+React review UI — unit detail/diff/attempts, unknown chips, accept · send-back · patch — with `dashboard` mirroring it in the CLI [10 §Surface & state] | **Even.** Both built a first page a reviewer lands on |
| Throughput / scaling | No throughput numbers; scaling is team templates (7/5/4/3 lanes) with a measured 6–10 skills loaded per task [32 §4] | No throughput numbers; whole-task measurement is open roadmap P33 [10 §Current state & open gaps]; scaling is a scan fan window capped at 4 over one serial `live` pipeline [10 §Pipeline anatomy] | **Even — both silent.** An empty row in both columns is itself a finding |
| Models / economics | The user's agent subscription is the economics — zero model-layer code in the repo [20 §18] | one OpenAI-compatible seam (`calxgloss-llm` — Ollama, vLLM, llama.cpp), endpoint in config with no defaults; economics *logged, not budgeted*: token/strategy/fault logs per attempt; metering + budgets open (P50) [10 §Model layer] | **Genuine split** — GameFrame externalizes the entire model relationship |
| Artifacts produced | Rebuilt headers, wrappers, ports, probes — things that load, link and run; each crate ships its own docs and tests [35 §1] | restitched cross-platform Rust — merged units land at `src/modules/{function}/translated.rs` — plus attempt branches, `re/baseline` captures, typed unknown records and token/strategy telemetry [10 §Pipeline anatomy, §Verification & evidence] | **Different artifact classes** — runnable drop-ins vs a translation corpus. Not reconcilable, and not meant to be |
| Target scope | Real shipped games, run live: Windows x64 (Banished), 16-bit DOS Pascal (Tyrian), Watcom Win95 (POD, Hardwar) across four platforms [36 §9 — `docs/case-studies/README.md:7-14`] | A `target_dir` of Windows EXEs/DLLs; ground truth is one source-built x86-64 PE fixture — no shipped corpus yet [10 §2] | **Genuine split** — both are Windows-first; GameFrame already spans DOS↔Win and 16↔32-bit, calxgloss is PE32/PE32+ only [10 anchors] |
| Corpus and routing | A folder contract in prose plus a gate blocklist of game binaries/artifacts (`gates/checks.py:24-30`) [32 §7]; routing is markdown discipline — the first tool you reach for is `gameframe` [31 §3, §9] | Records *are* the protocol: a closed six-kind unknown roster (ADR-0056), two documents one per owner joined at read time, typed coverage records per scan (ADR-0053) [10 §Verification & evidence] | **Complementary** — GameFrame guards the layout, calxgloss types the content |
| Instrument self-proof | `tests/run.sh`: 2,128 lines, 36 groups, negative controls that fail on purpose (`tests/run.sh:581-583`) [33 §12–13] + ~240 crate tests, 54 files in 18 `tests/` dirs [35 §9] | 4,692 `#[test]`/`#[tokio::test]`/`#[rstest]` attributes across 34 crates (counted at `40fbf91f`); no CI runs them (P42); zero negative-control tests [10 §8] | **GameFrame's clearest single advantage** — an immune system vs a test suite nothing runs |
| Distribution | `clients.py` config emit for six vendors (claude, codex, gemini, copilot, cursor, opencode, `scripts/clients.py:46`); one Claude Code plugin + marketplace entry (`.claude-plugin/marketplace.json`) [34 §4.4; 32 §7] | CLI (29 subcommands) + web UI; no MCP surface, no plugin channel — zero MCP matches in `crates/` [10 §Surface & state] | **GameFrame is ahead** — calxgloss ships nothing an outside agent can consume; P32's contributor skill is the first step |

## 3. Effects compared

1. **Analysis evidence culture.** GameFrame's evidence grammar is four
named labels — *observed*, *measured*, *inferred*, *unknown* — printed
inline next to the claim they qualify ("Label every claim with how you
know it", `skills/re-start/SKILL.md:43-48`), with a hard wall between
static reading and run-time claims ("Never write that the game 'does'
something at run time from static reading alone", `:48`) [31 §2]. The
consequence shows up in the artifacts: recovered names are first-class
records — `labels/names.tsv` and `labels/fields.tsv` are designed to be
"read by the tools" — though in the tracked tree they are header-only
TSVs, a name ledger kept as a contract rather than a filled database
[20 §17]. calxgloss
keeps confidence machine-only — the 6-kind ledger, per-scan coverage records (ADR-0053), admission lines rendered beside the evidence they qualify (ADR-0048/0049) — and deliberately leaves it out of the translated prose (principle 1). The effect differs more in audience than
in intent: GameFrame's labels serve the human reviewing a slice right now;
calxgloss's ledger serves the machine that has to route the gap and the
retry that has to consume it.

2. **Naming and evidence.** GameFrame assumes names are *usually gone* —
"Ghidra … has no original names: a function is `FUN_1400be770`"
(`skills/re-ghidra/SKILL.md:8`) — recovers them where evidence exists
(debug info gives "the original names of every procedure, global and
type", `skills/re-inventory/SKILL.md:109`) and records the rebuilt ones in
`labels/names.tsv`. Where a name *is* load-bearing it is shipped: each
replacement DLL "has the original's file name and exports, so the
unchanged game loads it" (`wrappers/README.md:5-7`) [35 §8]. calxgloss has no renaming at all: identity is verbatim everywhere —
branch, output path, log join key, Wine locator
(`calxgloss-git/src/lib.rs:4-5`) — and write-back onto the program is
types-only; no rename write-back exists in any crate
[10 §Naming & typing]. Neither approach is measurably better in the raw
data: GameFrame's own docs treat pseudocode names as guesses to be
confirmed — "guesses from pseudocode. Confirm each one as `re-trace`
does" (`docs/working/api-credits.md:181`) — and calxgloss's own doctrine keeps names as evidence: libmatch
findings, algorithm claims and RTTI ride into prompts with confidence
scores and admission lines and are never applied [10 §Naming & typing]. It is a difference in what the *artifact* is for — a
port you link against, versus a record of how you know.

3. **Throughput model.** GameFrame scales *horizontally with people and
lanes*: team templates sized 7/5/4/3, each lane with its own lanes.md,
verification contract, and the measured finding that a task loads 6–10
method skills [32 §4]. calxgloss scales *vertically with attempts*:
attempt branches `re/{binary}/{function}v{N}` under a serial pipeline
[10 §3, §6]. Both are honest about not measuring — neither has a public
throughput number — but only GameFrame built the machine that could
produce one: its ledger of unclosed claims is structured enough that
completion rates are computable from GAPS.md, while calxgloss has the
richer raw ledger (every attempt, kept forever) and no aggregation story.
The asymmetry is tooling, not data.

4. **Trust in the instrument.** This is the sharpest practical divide, and
it is not about tests — it is about *adversarial* tests. GameFrame's
harness ships negative controls: the Banished port test asserts that a
deliberately naive port *fails* the replay checks, and the check catches
20 of 20 seeded regressions (`tests/run.sh:581-583`) [33 §13] — the harness
proves the instrument detects wrongness, not just rightness. calxgloss has
4,692 test attributes and no CI to run them (P42), and zero
negative-control tests (verified at `40fbf91f`) — a test that passes when the method is broken
is not in its test taxonomy at all. The effect compounds: GameFrame's
conformance tests pin tool *behavior* — every group re-runs real tools
against a real built sample game and fails on any missing output string
[33 §12]; calxgloss's tests mostly pin types and
parsing. Same instinct, one order of magnitude apart in paranoia.

5. **Economics.** GameFrame carries zero model-layer code — no provider
pool, no budgets, no pricing [20 §18]; the coding agent's subscription is
the cost model. That is not carelessness: a coding agent manages its own
context and spend, so there is nothing for the repo to meter. calxgloss owns its
spend: a locally hosted model behind the `calxgloss-llm` seam, with
every attempt's tokens, strategy and raw LLM I/O logged to
`re/analysis/` and surfaced in web analytics — but logging is not
budgeting: cost metering and stop rules are open P50 [10 §Model layer]. The costs that land are the ones GameFrame externalizes:
calxgloss pays for retries with tokens and owns the cost of a bad step;
GameFrame pays for retries with *wall-clock and reviewer attention*, which
shows up in its obsessive gate design instead — the guard, the dirty-rule,
the delete gate (`scripts/hooks/gates/deletes.py`, 196 lines) — because a wasted agent
session can burn a *user's* subscription before any human notices.

6. **What the verification inversion actually protects.** GameFrame's
dossier calls its design a verification inversion [31 §10], but read
closely, the inversion adjudicates *prose claims*, not shipped artifacts:
the strongest rung of every wrapper's proof ladder is live execution of
the original DLL with WRAPPER_CALLS recorded [35 §8], and every
deterministic engine carries conformance tests with fixture vectors [33
§13]. The LLM sits exactly where calxgloss's LLM sits — the gap-filling
layer between deterministic engines, graded by running the original. What
the inversion adds is the *guard culture* around the agent — write-back guard-rails:
`game_folder.py` marks game folders with a
`GAME-FILES-NOT-BUILD-OUTPUT.txt` sentinel (`:30`) and `deletes.py`
blocks rm/mv/clean over them — the game folder is "the user's own copy
of the game, which git does not keep" (`deletes.py:4-5`) [32 §7; 34 §2.5] —
plus the dirty-rule in update-project.sh, and
warn-and-allow gates that trust the human's judgment over a hardcoded
block [32 §5; 34 §3.3, §4.3]. That is the half calxgloss can reuse without
touching its own agent boundary.

7. **Honesty records.** Both projects arrived at the same conclusion from
opposite ends. GameFrame's GAPS.md (356 lines,
149 checked / 29 unchecked) is "the list of topics found missing from
GameFrame's guides and tools, and where each one is now covered"
(`GAPS.md:3-4`) — including an *out of scope* block that keeps refusals
listed with their reason "so they are not proposed again" (`:6`) [36
§6.2]. It is a docs-completeness ledger, not a release gate: nothing in
the release machinery consults it — but its shape (tick when the guide
section lands, never delete a gap) makes incompleteness a first-class
artifact.
calxgloss went machine-first: an admitted gap is a named record, not prose
(ADR-0056), joined at read time and routed to an owner, and
the web UI already renders it — unknowns surface as chips and `Unk`
columns with resolve/dismiss/reopen as API-only routes (ADR-0056)
[10 §Honesty vocabulary]. The effect GameFrame buys is
cheapness — a checkbox ledger a single author can maintain by hand; the
effect calxgloss buys is consumption — a retry loop can *act* on a gap.
GameFrame's own history shows the cost of the cheap version: its prose
ledger drifted (GAPS.md's "nine stored forms" vs the eight-row merged table
it closes, [36 §2, §7]; `AGENTS.md:68` "twelve task agents" vs the README's
"Fourteen", [21 §7]) — drift a typed ledger makes structurally harder. Neither has yet built the thing both would want: a ledger
that is simultaneously machine-consumed and human-legible.

## 4. What calxgloss should adopt

1. **The no-CI harness shape — negative controls first.** calxgloss has
4,692 test attributes and nothing runs them (P42). GameFrame's harness is the working
template: `tests/run.sh` (2,128 lines, 36 groups) runs the *shipped*
entrypoints end-to-end — `./gameframe doctor`, the guard, the launcher —
not just unit code [33 §12]. The load-bearing pattern for calxgloss:
assert that the instrument *detects wrongness*. GameFrame's Banished
harness asserts that a `--naive` port (deliberately wrong translation)
fails the replay checks, and catches 20/20 seeded regressions
(`tests/run.sh:573-583`; the naive-port check at `tests/run.sh:583`)
[33 §13]. calxgloss's fixture set has **no**
deliberately WRONG-translated variant yet (verified absent at `40fbf91f`:
`calxgloss-testfixtures` ships `fixture_plain.c`, `fixture_target.c` and a
smoke suite only) — creating one and making the gates required to catch it
IS the pattern. Landing site: a `run.sh` in the repo
root plus a GitHub Actions job (P42); the negative-control assertion
belongs in `crates/pipeline/calxgloss-verify`'s test group as a
fixture-driven harness test.
2. **Fixity manifests and the never-clobber updater rule.** GameFrame
records each original media file's size and SHA-256 in the per-game
`game.json` (`tools/gameframe/games.py:21`) and re-verifies the
installed copy with `./gameframe home doctor --hashes`
(`tools/gameframe/__main__.py:147`) before any work trusts the binary
[34 §3.1–3.2] — because the replay oracle is only as good as the bytes
it replays. calxgloss has no fixity manifest at all; roadmap P44 (stamp
DLL sha256 and Wine version onto `baseline.json`) and P47 (per-function
"made-from" digests) name exactly this gap (`docs/roadmap.md:67-70`).
Landing: those two P's, built in game-frame's shape — a manifest that
doctor checks, not a fact in docs. And import their updater rule: every
provided file classified missing→add, identical→keep, old→replace,
project-changed→**keep and list** (`scripts/update-project.sh:11-17` at
f195a074) — for any future calxgloss script that writes into a
user-owned directory.
3. **Failure *knowledge* as a queryable layer.** GameFrame keeps a curated
failure corpus — `docs/knowhow/`, e.g.
`game-folder-deleted-as-build-output.md` — and `./gameframe advise`
matches the current situation ("an error message, a log or a topic",
`tools/gameframe/__main__.py:17,60`) against it [31 §7]. calxgloss has
the *data* loop already wired, ahead of game-frame: `fault_log.json` is
a live input — the retry loop carries a `FaultLogger`
(`calxgloss-translator/src/retry/retry_loop.rs:47`) and the web analytics
surface it (`calxgloss-web/src/server/handlers/analytics.rs`) — but
`trace_divergence_index` (on `FailedTest`, `calxgloss-types/src/
verification.rs`) has *no consumer*: outside the verifier itself, only a
`None` placeholder in `calxgloss-reports` mentions it. What calxgloss
lacks is game-frame's second half: a curated knowhow layer mapping
failure classes to fixes, and one command that answers "what does this
error mean" from it. Landing: wire the divergence index into the retry
prompt (the verifier already emits it), surface it in the web unit view,
and build the knowhow corpus as typed records — the record design beats
game-frame's flat directory once it is queried rather than read.
4. **A public gap ledger — with the lesson attached.** GameFrame ships
GAPS.md in the repo root, public on the GitHub front page: the list of
topics found missing from its guides and tools, 149 closed / 29 open,
with out-of-scope refusals kept listed beside their reasons [36 §6.2]. calxgloss's unknowns ledger is entirely internal — records live in
the shared JSON store behind the web UI's unknown chips; nothing
public shows gap status. Landing: render the open
UnknownRecord roster (the 6 kinds exist, ADR-0053/0056) into a
generated, per-binary public gap page. But carry the warning too: GameFrame's own documentation audit caught its
prose counts drifting ("twelve task agents" at `AGENTS.md:68` vs the
README's "Fourteen", [21 §7]; GAPS.md's "nine stored forms" vs the
eight-row table it closes, [36 §2]) — a hand-written gap page must be generated from
the typed ledger, never maintained beside it. calxgloss's machine-first
media is exactly the cure for the disease GameFrame caught in itself.
5. **Project the evidence grammar onto human surfaces.** GameFrame prints
"verified: replayed on the original" *next to the claim it qualifies*,
inline and unskippable [31 §2]. calxgloss has the same confidence data,
machine-only, and never renders it where a human reviews. Landing:
the web review queue (and `calxgloss dashboard`) should carry each
claim's confidence tier beside it — the evidence that computes it
already rides in the bundle sections and unknown records, and P51
scores it — and attempt-branch commit messages should name the
verification rung that passed (P25's receipts file exactly that). The same projection closes
P51's display side — name/type confidence is *computed from evidence*
there as an open item (`docs/roadmap.md:74`), but today nothing renders a
confidence tier where a human reviews; one mechanism serves both.
6. **An ad-hoc query surface (P29).** The cleanest import in the
comparison. GameFrame's doctrine is in the tool's first line: answer
questions about a Ghidra export "without reading it whole"
(`tools/triage/decomp_query.py:2`) — nine commands (`fn`, `callers`,
`callees`, `find`, `strings`, `writers`, `layout`, `biggest`, `stats`;
`:7-15`) that merge the export with `labels/names.tsv`, so identification
compounds: "add a row every time you identify a function, and every
later answer is easier" (`:21-22`). `exportcov.py` closes the loop — it
computes how much of the binary the export covers "and where the
functions it missed probably start" (`tools/triage/exportcov.py:2-3`),
with a `--min PERCENT` exit-code gate (`:16`) that makes coverage a
machine-checkable claim [33 §1]. calxgloss's Kuna scans are batch and
all-or-nothing; P29 — "ad-hoc call-path / def-use primitive at the
seam… without a full re-scan" (`docs/roadmap.md:58`) — is the shared
diagnosis. Landing: `UnknownKind::ExportUncovered`
(`crates/shared/calxgloss-types/src/unknowns.rs:88`) already types the
gap record; what's missing are question-shaped verbs beside the batch
scan and a consumer that walks ExportUncovered records back into scans.
7. **"What it does not do" docstrings + a `--json` catalog.** GameFrame's
tool rule: every tool's docstring names the mode it deliberately refuses,
so reachability lives in the tool, not agent memory — and `--json` on
`steps/skills/agents/tools/tool/find/advise`
(`tools/gameframe/__main__.py:51`) makes every entrypoint
machine-readable, the
same posture its AGENTS.md states as a law: "Every tool documents
itself. A module docstring or header comment with usage, inputs, outputs
and what it does not do" (`AGENTS.md:38-39` at f195a074), and every tool
gets a check in `tests/run.sh` against the sample game (`AGENTS.md:36-37`)
[31 §6]. calxgloss has no machine-readable tool
registry yet; P52 files exactly one — a command reference generated
from the clap enum + ADR-0052 scan-registry rows, with `--json`
printing the result structs — and P31 gives `doctor` JSON output and
exit codes. Adopt the refusal-naming rule as a lint: no public command
registers without a stated "does not" line. It pairs with P46's
`reason:` beside every engine/capability decision — capability
knowledge in records and docs, not agent memory.
8. **Gates as data, not policy.** GameFrame's guard configures itself:
extension allowlists in `checks.py:24`'s `GAME_EXTS` set, a
game-folder sentinel (`GAME-FILES-NOT-BUILD-OUTPUT.txt`,
`game_folder.py:30`), and the delete gate (`deletes.py`)
refusing rm/mv/clean over the user's own game copy; the runtime
identity the gates enforce — the agent name — is carried by one
env var (`GAMEFRAME_AGENT`), and gates use warn-and-allow severity
instead of hardcoded blocks [32 §5; 34 §2]. calxgloss has no guard yet: P43
files a fail-closed sandbox for model output, replacing today's
scratch-dir convention. Landing: when that sandbox is built, its rules
should load from per-target config files (a guard profile beside the
target's `baseline.json`) rather than being baked into the sandbox
code — the game-folder-protection idea tracks theirs: calxgloss's Wine
baselines and the user's original binaries are exactly as irreplaceable
as GameFrame's game installs.
9. **Multi-client and plugin distribution — low priority.** GameFrame's launcher writes config for six coding-agent vendors from one source of
truth (`scripts/clients.py:46`, driven by `scripts/new-project.sh:53`) and ships exactly
one plugin marketplace entry — for Claude Code, whose marketplace.json
serves the repo itself as the plugin (`"source": "./"`) [32 §7]. There
is no Devin or OpenCode marketplace entry at this snapshot; the
skills/agents trees themselves stay vendor-neutral [34 §4.4]. calxgloss ships no MCP surface and no plugin at this snapshot —
zero MCP matches in `crates/` outside the deleted GhidraMCP note —
and P32's contributor skill is still an unwritten SKILL.md. If
distribution ever matters, the clap enum and ADR-0052 registry rows
(P52's generated reference) are the natural generation source for any
vendor config or MCP emit. Note it, don't schedule it.
10. **Case-study-as-evidence-vehicle for the first full-binary runs.**
GameFrame's strongest documentation move is
`docs/case-studies/`: five real projects built with the method —
Un-Banished, Tyrian 2026, Frontier, POD, Hardwar — each page naming its
route, its capture tooling, and how output was compared to the original
("All five aim for the same results as the original for the same
inputs", `docs/case-studies/README.md:3-4`) [36 §9]. calxgloss has the same evidence at a distance
from humans: for its first real full-binary runs, the shape to copy is the
post-run REPORT — which Kuna facets fired, which Unknowns were admitted,
which baselines matched, where the trace diverged — published beside the
target's record. The baselines and divergence indexes exist; no artifact assembles
them into a per-binary story yet — P25's verification receipts and
P26's closure digest are the roadmap pieces that would.

**What NOT to adopt:**

- **Applying names into the analysis artifact.** GameFrame's reconstructive
naming fits a port-first project; it would break calxgloss's identity contract at the root:
no rename write-back exists anywhere, write-back is types-only
(ADR-0020/0021), and verbatim binary-side names are what keep the
branch, log-key and Wine-locator join intact so provenance survives
[10 §Naming & typing]. Take the *discipline* (names as evidence, recorded),
never the *write-back*.
- **A markdown-only method without the machine half.** GameFrame's 16
skills work because 2,128 lines of harness and negative controls stand
behind them [33 §12–13]. A no-CI project (P42) that imports only the prose
gets the vocabulary without the immune system — and an LLM fluent in
verification vocabulary can produce prose that *looks* verified. That is
exactly the failure GameFrame's negative controls were built to catch.
Ordering matters: CI first, skills after.
- **Bit-identical parity against the original game as the bar.**
GameFrame's strongest proof runs at that bar: the port "matches the
original bit for bit (20 seeds x 600 steps)" (`tests/run.sh:581`), and
`opl2`'s output is "identical sample for sample to the original driver"
(`crates/opl2/README.md:17-19`) [33 §13; 35 §3]. calxgloss's principle 1
buys "functional equivalence over binary precision" and its architecture
(PE32/PE32+ only, Wine as the single oracle) is built around not needing
bit-exactness [10 §2]; chasing bit-exactness would spend calxgloss's scarce
ground-truth budget (one fixture DLL today) re-winning a fight the
method already decided not to enter.
- **Wrapper DLLs as a distribution medium.** GameFrame ships rebuilt DLLs
that load into the original game [35 §8]; calxgloss's PAL is a mapping
database that is deliberately never compiled [10 §1]. The two models
collide head-on [35 §10]; adopting wrappers would undo calxgloss's own
decision to keep the PAL a mapping database: PAL table rows render
into the prompt as an "API MAPPING REFERENCE" and the translation
carries `[PAL placeholder]` notes (`data.rs:75-111`) — not a
compiled dependency [10 §Naming & typing]. Keep the PAL-as-database.

## 5. Confirmations and challenges

(a) **Confirmed — the run-the-original oracle.** Both projects stake their
final word on running the real thing: calxgloss's Wine baselines and
ordered-containment verdict (ADR-0057: the trace "proves presence and
order, never absence") [10 §2] and GameFrame's replay
groups — `bitcompare` of state and `seqdiff` of call traces, plus
WRAPPER_CALLS logged against the live original DLL [33 §13; 35 §8] —
are the same philosophy at different altitudes. The model's memory of the program is
never the oracle, in either codebase. The ADR-0057 containment rule also
matches GameFrame's observed practice — `seqdiff` grades the naive port
on draw *order* ("the port draws random numbers in the original's
order", `tests/run.sh:582`), not on a locked instruction sequence
[33 §13].

(b) **Confirmed — honesty as records, not prose.** calxgloss's "an
admitted gap is filed as a named record, not left as prose" (ADR-0056)
and GameFrame's checkbox gap ledger are the same idea arrived at
independently within days. Two unrelated codebases converging on the same
ledger discipline is evidence the discipline is project-independent —
the disagreement is only over media (typed JSON vs hand-written markdown),
and §4.4's warning is what each teaches the other about its medium.

(c) **Confirmed — per-unit git ledger, single lander, no CI, no
unmeasured claims.** Both keep the ledger in git per unit of work
(`re/{binary}/{function}v{N}` vs the completed-slice commit [10 §3; 21
§3]); both are single-authored with one human lander (all 383 of
GameFrame's commits are one author's, 251 co-authored with Claude
[21 §1]; calxgloss's ADRs list "Arthur (solo project)"); neither runs CI
beyond something minimal (site.yml for GameFrame [20 §19], nothing at all
for calxgloss, P42); and both refuse to advertise what they have not
measured — the site "refuses the count it cannot prove" [34 §7]
corresponds word-for-word to calxgloss's refusal of whole-program claims.
The ch.10 anchors' intuitions all survive contact with the source.

(d) **Challenged — the "verification inversion" is narrower than the
rhetoric.** GameFrame's own artifact proof leans deterministic: the
strongest rung of every wrapper is live execution, every engine carries
conformance tests, and the negative controls are pure machine behavior
[33 §13; 35 §8, §9]. The inversion LLMs bring is adjudicating *prose and
routing decisions* — the domain where calxgloss already places its LLM
between deterministic engines [10 §1]. As architectures, the two projects
are closer than either dossier's framing suggests; the distance is in
audience (the method serves third-party agents there, its own loop here)
and in paranoia engineering, not in the epistemic skeleton.

(e) **Challenged — the sharpest asymmetry is proof-of-scale, and it cuts
both ways.** GameFrame's headline — Un-Banished, "a 1:1
reimplementation of the game Banished" (`README.md:16-17`) — is
author-local evidence: the in-repo harness proves the tools against a
synthetic sample game, never against Banished's binary, and the only CI
(site.yml) never runs it [20 §16; 33 §12]. In
mirror, calxgloss has no public full-binary success story at all: the pipeline is live with Wine baselines and the ADR-0057 gate, but no
end-to-end artifact has been published, and the fail-closed
whole-binary verdict that would make "done" a checkable claim is
still open (P26). Neither is being
dishonest — both refuse claims their records don't support — but the
comparison would be incomplete without naming it: GameFrame's evidence
culture produces stories a stranger can check: five case studies with
the route each project took and how its output was compared
(`docs/case-studies/README.md:1-14`) — while calxgloss's evidence stays
private inside its own workspace. What to borrow is the *story form*, not the
emulation bar: the first full-binary run should end with a published
REPORT in the §4.10 shape, generated from the gates that already fire.

(f) **Challenged — the one-way borrowing trap.** The features that look
most portable in GameFrame — 16 skills, method docs everywhere, "the
method is in the docs" — are exactly the features that depend on the
features calxgloss lacks: the skills are cheap to write because the
harness catches their violations, and the docs stay honest because
conformance tests and the ledger-drift audit re-check them [31 §3; 33
§12–13; 20 §21]. If calxgloss imports the playbook before CI (P42),
adversarial checks (nothing on the roadmap yet — P52's one-exit-test-
per-P discipline is the nearest hook) and generated docs (P32's
contributor skill, P52's generated command reference), the playbook
itself becomes the failure mode — fluent unverified prose wearing the
vocabulary of verification. Everything §4 adopts is therefore sequenced
behind the instrument work; and the one item that should NOT be sequenced
behind anything is the ad-hoc query surface (§4.6), which GameFrame
itself treats as a precondition for everything else it does [33 §1].

## 6. Verdict

GameFrame is calxgloss's methods section with the ownership reversed: it
is what the calxgloss doctrine looks like when it exists for someone
else's agent and therefore had to grow machine-checkable teeth — negative
controls, conformance tests, fixity manifests, guard-as-config, gap
ledgers that never delete a gap. The direction of adoption runs strongly
one way — harness before playbook, gates as data, failure corpora as
first-class inputs, gap ledgers on the public surface, the query verbs
that P29 was already asking for — while calxgloss's counter-contributions
are real but quieter: the typed unknown ledger GameFrame maintains by
hand, the machine-consumed honesty records whose drift GameFrame just
documented in itself, and a token/strategy/fault telemetry layer GameFrame is free to
skip only because it owns no translator at all (and would need P50
to budget one). The deepest shared finding is
that both projects, alone and within a week of each other, converged on
the same three pillars — run-the-original ground truth, honesty filed as
records rather than prose, and a git ledger per unit of work — which is
the strongest available evidence that the comparison's real conclusion is
not "copy the other's stack" but that this shape of program is the one
both are already building.
