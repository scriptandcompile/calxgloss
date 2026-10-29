# KRAKEN's AI layer — the built-in assistant, model backends, terminal agents, and the safety machine

Chapter 33 covered the automation surface the AI rides on (registry, MCP, daemon, credentials as
plumbing). This chapter covers what sits on top of it: KRAKEN's built-in assistant, how it reaches
models, how third-party coding agents are wired in and confined, and the safety machinery —
untrusted-data typing, write gates, OS sandboxes — that wraps all of it.

Two conventions to read citations here with:

- **Code comments cite "decision NN"** (decision 61, 71, 94, ...). Those numbers refer to KRAKEN's
  internal, gitignored planning documents — they are *not* the fourteen published ADRs in
  `docs/design/`, which are numbered independently and do not use that phrasing. Where a design
  ADR does say the thing, this chapter cites the ADR itself.
- **The crate `kraken-model` is not model infrastructure.** It is the project database store — e.g.
  the usage ledger types come from it (crates/kraken-registry/src/commands/ai.rs:5). Model *backends*
  live in `kraken-agent` (providers), `kraken-infer` (local inference hosting), and `kraken-acp`
  (agents as backends).

## Where the AI lives

| crate | job |
|---|---|
| `kraken-assist` | assistant core: registry-backed tool host, tasks, cost meter, provider config, shell tool |
| `kraken-agent` | built-in agent loop: chat providers, prompt-injection hardening, compaction |
| `kraken-acp` | terminal-agent host over the Agent Client Protocol (Claude Code, Codex, Gemini CLI) |
| `kraken-infer` | supervised local inference: llama.cpp hosting, hardware recommendation, pinned downloads |
| `kraken-proto` | `Untrusted<T>` wrapper and the sanitizer for binary-derived text |
| `kraken-registry` | the commands the AI calls, their permission class, the mutation pipeline |
| `krakend` | credential-class enforcement, per-credential quota, AI job board events, `infer_*` methods |
| `kraken-confine` / `kraken-sidecar` / `kraken-procguard` | the OS confinement stack (Landlock, seccomp, namespaces, parent-death cleanup) |
| `kraken-rewrite` | model-written Rust: allowlist lint before compile-and-run |
| `kraken-emu` | interpreter for running guest code while rewrites are unproven |

All four AI entry points are one product: KRAKEN describes its own safety model to the user as
covering exactly these paths — confined decompiler processes, everything from the binary handed to
models as marked untrusted data, agent writes additive-or-proposal, model-written code built and run
only in a sandbox (README.md:99-101).

## 1. The built-in assistant — a paired human, never unattended

The assistant explains functions, runs a guided overview, proposes names for `FUN_...`-style symbols,
and chats (docs/assistant.md:3). It is "a client like any other": it reads and edits through the same
registry commands as the CLI and MCP server, so everything lands in the edit log and every run is
undoable (docs/assistant.md:5). One assistant core, two backends answering it — a model API loop or a
terminal agent over ACP, both producing the same event stream (crates/kraken-assist/src/lib.rs:3-8).

**Tools come from the registry, never from the model.** The tool host builds the tool list from the
registry's command specs and the task's subset; calls run as the assistant agent so the registry's
own policy applies unchanged: additive edits auto-apply up to the per-run cap, overwrites become
proposals, dangerous commands are not exposed at all (crates/kraken-assist/src/host.rs:1-7). The
registry holds 78 commands total (`register_all` at crates/kraken-registry/src/commands/mod.rs:187-188
registers exactly 78), but the assistant sees 53 — and the full tool descriptions cost about 17,000
tokens of a small model's window (docs/assistant.md:259). Some commands are never offered to the
assistant at all: a default exclusion list and a "person's own" list keep project lifecycle,
proposal decisions, undo and rewrites out of reach except via the explicit Automate task
(crates/kraken-assist/src/host.rs:34, crates/kraken-assist/src/host.rs:57, docs/assistant.md:589).

**Bounds are numeric and enforced in code.** The per-run cap on auto-applied agent edits defaults to
200 (crates/kraken-registry/src/session.rs:176-178, crates/kraken-registry/src/session.rs:194-196,
docs/assistant.md:590). A run is also bounded by a step budget (`max_steps`,
crates/kraken-agent/src/agent.rs:27-28) and a token budget per task
(crates/kraken-assist/src/tasks.rs:1) — explaining one function is capped at an 80,000-token budget
and the task prompt tells the model it cannot change the project
(crates/kraken-assist/src/tasks.rs:325, crates/kraken-assist/src/tasks.rs:331-332). The Automate
flow adds "at most 60 edit calls" per run (docs/assistant.md:565).

**Danger mode is opt-in per user, deny-by-default in code.** Dangerous registry commands are gated by
a `DangerMode` (`deny | ask | yolo`): the GUI's config surface defaults to `ask`
(docs/assistant.md:339) while the host's own `HostOptions` default is `Deny`
(crates/kraken-assist/src/host.rs:105, crates/kraken-assist/src/host.rs:182,
crates/kraken-assist/src/host.rs:340-342). Reversible edits never ask in any mode
(docs/assistant.md:339). Additive writes apply immediately; anything that overwrites a person's work
becomes a proposal the person decides — agents can never accept their own proposals
(docs/concepts.md:40-41, docs/assistant.md:515).

**The assistant is not a free chat against the binary.** Each task fixes the tool subset; the shell
tool is the only model-invokable way to run anything, and it runs *outside* the agent loop: the model
never executes a command line itself (crates/kraken-assist/src/shell/host.rs:16-17). The shell tool
is decided by a three-way policy — Allow for a pipeline of known-harmless programs, Deny for
never-here, Ask for the rest — with the OS sandbox, not the policy, as the real boundary
(crates/kraken-assist/src/shell/policy.rs:1-6); config can deny but never lift a built-in refusal or
make shell syntax like `;` or `$(` run unasked (crates/kraken-assist/src/shell/policy.rs:8-13).

**Model output is demoted everywhere.** Structured answers arrive inside `<kraken-result>` tags
(crates/kraken-assist/src/output.rs:16-18); the model's self-reported confidence is ignored — the
confidence label is computed by KRAKEN from how many independent kinds of evidence agree
(crates/kraken-assist/src/output.rs:399, crates/kraken-assist/src/output.rs:489,
docs/assistant.md:518).

## 2. Model backends — local-first, cloud opt-in, and metered like electricity

The design ADR lays out four integration paths — MCP server, built-in agent, ACP terminal agents,
supervised local inference — sharing one provider abstraction so the agent loop never knows which
backend answers (docs/design/0008-ai-integration-and-inference.md:12-19,
docs/design/0008-ai-integration-and-inference.md:23). The built-in agent is OpenAI-compatible first
(Ollama, LM Studio, llama-server, vLLM) plus Anthropic/OpenAI/Gemini
(docs/design/0008-ai-integration-and-inference.md:15, crates/kraken-agent/src/provider/openai.rs:1,
crates/kraken-agent/src/provider/mod.rs:20-21). **One honest drift note:** design 0008 names the `genai`
crate for the API paths; the shipped code does not use it — `kraken-agent` pulls `reqwest`
(crates/kraken-agent/Cargo.toml:14) and hand-rolls the Chat Completions client
(crates/kraken-agent/src/provider/openai.rs:18).

Local-first in the same posture as calxgloss: KRAKEN never downloads a model by itself
(docs/local-models.md:16); a `kind = "local"` model is named in config but its host/port/key are
asked fresh per run and never stored (crates/kraken-agent/src/provider/local.rs:1-5). Secrets are
references, never config values — env var or OS keyring (`SecretRef`), with the GUI able to store a
pasted key in a mode-0600 `secrets.toml` (crates/kraken-agent/src/config.rs:3-9,
crates/kraken-agent/src/config.rs:28-32, docs/assistant.md:90).

**`kraken-infer` hosts the inference itself.** An `InferenceBackend` launches an engine as a
supervised child exposing an OpenAI-compatible server on 127.0.0.1 — the same URL the agent provider
talks to (crates/kraken-infer/src/lib.rs:1-7). llama.cpp's `llama-server` is the first engine and is
always an upstream binary, never bundled (crates/kraken-infer/src/llama.rs:1). Recommendation is
pure hardware detection against a bundled, hash-pinned catalog: every download carries a SHA-256 and
a mismatching file is deleted (crates/kraken-infer/src/recommend.rs:31), setup is pinned to reviewed
revisions (crates/kraken-infer/src/strata.rs:262-264), asks approval first with download sizes, and
only ever fetches catalog ids, never URLs (crates/kraken-registry/src/commands/local_model.rs:3-7,
crates/kraken-registry/src/commands/local_model.rs:246-248). The daemon hosts the model lifecycle
itself (`infer_*` methods, model counts as work against idle exit —
crates/krakend/src/lib.rs:6-9).

**Cost is a first-class product surface.** Design 0008 requires every backend to publish a capability
descriptor and settings schema, and the UI to always show which provider a request goes to
(docs/design/0008-ai-integration-and-inference.md:21,
docs/design/0008-ai-integration-and-inference.md:25). The meter counts, prices and limits every call
of one piece of AI work, feeding the project ledger and daily totals, and refuses calls that would
cross the run's max-cost or the daily budget (crates/kraken-assist/src/meter.rs:7-12,
crates/kraken-assist/src/meter.rs:271-288, crates/kraken-assist/src/meter.rs:314-316). Limits live
in `[ai_limits]` (`max_calls_per_run = 200`, `daily_budget`, low-context switch) with built-in list
prices in `[pricing]` overriding them (crates/kraken-assist/src/ai_config.rs:1-2,
crates/kraken-assist/src/ai_config.rs:6-12, crates/kraken-assist/src/ai_config.rs:26-30,
crates/kraken-assist/src/pricing.rs:1-5). Two read commands expose it — `ai_usage` (calls and
estimated cost, project/day/run scoped) and `ai_jobs` (running and recent AI work and who started
it) (crates/kraken-registry/src/commands/ai.rs:1,
crates/kraken-registry/src/commands/ai.rs:93-95, crates/kraken-registry/src/commands/ai.rs:210-212) —
with an explicit honesty note baked in: figures are estimates from reported tokens and the price
table; terminal agents report no tokens at all (billed by their subscription); local models are free
(crates/kraken-registry/src/commands/ai.rs:70-73). The daemon publishes `ai_started`,
`ai_progress`, `ai_done` for the activity chip and job board
(crates/krakend/src/host.rs:579-581, docs/assistant.md:237, docs/assistant.md:239). KRAKEN never
calls a model unprompted (docs/assistant.md:221).

For small local models, *low context mode*: tools are listed by name and one line, the model asks
for schemas by name, and results are paged and capped — permissions, approvals and limits
unchanged (crates/kraken-agent/src/low_context.rs:1-9,
crates/kraken-agent/src/low_context.rs:12-15, crates/kraken-assist/src/ai_config.rs:43). History
compaction runs at 85%/60% watermarks of the window (crates/kraken-agent/src/compact.rs:12-16).

## 3. Terminal agents — ACP as the third-party path, with honest limits

ACP is the **Agent Client Protocol**, pinned exactly: `agent-client-protocol = "=3.4.0"`
(crates/kraken-acp/Cargo.toml:19). KRAKEN acts as the ACP *client*: it launches Claude Code, Codex or
Gemini CLI pre-connected to its own MCP server, answers permission requests, and streams everything
back as events for the chat UI (crates/kraken-acp/src/lib.rs:2-12,
crates/kraken-acp/src/host.rs:3-6). Supply chain is pinned all the way down: adapters are installed
from an embedded, integrity-hashed lockfile with `npm ci --ignore-scripts`
(crates/kraken-acp/src/adapter.rs:1-4, crates/kraken-acp/src/profile.rs:110-116), and if Node is
missing KRAKEN downloads a pinned LTS with SHA-256 checks and zip-slip-proof extraction
(crates/kraken-acp/src/node.rs:1-6). Profiles pin each agent's visible environment with "no API
keys" in the header and a name-based deny guard that beats any allowlist
(crates/kraken-acp/src/profile.rs:1, crates/kraken-acp/src/profile.rs:14,
crates/kraken-acp/src/profile.rs:191).

The honest part: **KRAKEN advertises no file-system and no terminal capability, so the agent keeps
using its own shell and file tools — and KRAKEN does not sandbox those**
(crates/kraken-acp/src/host.rs:3-6, docs/design/0005-agent-safety.md:24). The stance is "warn only":
a one-time notice titled "Terminal agents work outside KRAKEN's safety net", remembered as shown,
never blocking (crates/kraken-acp/src/notice.rs:1-7). What KRAKEN *does* confine is the agent's
relationship to KRAKEN itself: on Linux the agent (and the `kraken mcp` server it spawns) starts in
an unprivileged namespace sandbox — user namespace with no capabilities, a mount namespace where an
empty tmpfs replaces the runtime directory with only `daemon.sock`, `daemon.json` and the *agent*
token bind-mounted back, a PID namespace with fresh `/proc`, `no_new_privs` — so `daemon.token`
simply does not exist for it (crates/kraken-acp/src/confine.rs:1-15,
crates/kraken-acp/src/confine.rs:44-46, docs/security.md:24). Home, tools and network stay normal —
this is credential isolation, not a cage. If the kernel refuses unprivileged namespaces, KRAKEN
withholds daemon access entirely and tells the user the agent runs unconfined
(crates/kraken-acp/src/host.rs:690-696, crates/kraken-acp/src/host.rs:737, docs/security.md:24).

Through KRAKEN's own tools the agent is an ordinary agent-class client: writes go through the same
registry policy, over KRAKEN tools the registry's permission policy answers the agent's permission
requests, and requests for the agent's *own* tools go to the person
(crates/kraken-assist/src/acp.rs:3-5, crates/kraken-assist/src/acp.rs:15-16). Tool titles from every
naming dialect (`mcp__kraken__decompile`, `kraken:decompile`, ...) are classified back to command
names (crates/kraken-assist/src/acp.rs:216-217). External MCP clients that skip KRAKEN's launcher are
outside the safety model entirely — the docs tell *their* owners to treat binary text as data,
stripping is done but "this reduces the risk; it does not remove it" (docs/mcp.md:96).

## 4. The confinement stack — everywhere code executes

The strongest single artifact in the whole AI layer is the shared confinement machinery.

- **Sidecar** (Ghidra/engine child): scrubbed environment (`.env_clear()`), `PR_SET_PDEATHSIG`,
  Landlock with ABI-v4 TCP denial, ABI-v6 scoping, ABI-v9 unix-socket resolution denial, a seccomp
  filter refusing `socket(2)`/`socketpair(2)` except the inherited AF_UNIX pair — which closes UDP
  and ICMP that Landlock cannot — plus `CLONE_NEWUSER | CLONE_NEWNET` where allowed; spawn *fails*
  if confinement cannot be enforced (crates/kraken-sidecar/src/sandbox.rs:1-16,
  crates/kraken-sidecar/src/sandbox.rs:351). Read-only system dirs include `/dev/random` and
  `/dev/urandom` for the JVM's SecureRandom (crates/kraken-sidecar/src/sandbox.rs:381-386). macOS and
  Windows have no confinement yet and refuse to spawn rather than run naked
  (crates/kraken-sidecar/src/sandbox.rs:13-16). The policy, environment and namespace choices are
  spelled in docs/design/0007-sidecar-confinement.md:12-21.
- **kraken-confine** (shared vocabulary): one policy type for "what a confined child may touch" —
  Landlock ABI floor of 4, two read scopes (Toolchain vs SystemLibraries-only for compiled
  runners), `setrlimit` caps applied before exec (crates/kraken-confine/src/lib.rs:1-16,
  crates/kraken-confine/src/lib.rs:42, crates/kraken-confine/src/lib.rs:46-52,
  crates/kraken-confine/src/lib.rs:55). Its framing: *what a model wrote, or what a sample does, is
  untrusted code* (crates/kraken-confine/src/lib.rs:1-3).
- **The assistant's shell tool** runs in it with a 4,000-char output cap, 10s default / 60s max
  timeout, 2 GiB address space, 30 CPU-seconds, 64 MiB file size, +256 process headroom — "room for
  pipelines, not for a fork bomb" (crates/kraken-assist/src/shell/sandbox.rs:1,
  crates/kraken-assist/src/shell/sandbox.rs:12-23).
- **Model-written Rust** must pass an allowlist lint *before* it may compile: parsed with `syn`,
  restricted to a computing-only subset; `std::fs`, `std::net`, `std::env`, `std::os`,
  `std::thread`, `std::process` paths refused; even `println!("{}", include_str!(..))` refused
  (crates/kraken-rewrite/src/lint.rs:1-14). Builds and runs of rewrite candidates are refused
  outright when the sandbox is not enforced (crates/kraken-rewrite/src/service.rs:862-864).
- **Guest code never runs natively** while KRAKEN is rewriting: every instruction is interpreted, and
  the guest reaches the host only through syscalls `kraken-emu` answers itself
  (crates/kraken-emu/src/lib.rs:20-24).
- **Parent-death hygiene** everywhere: `PR_SET_PDEATHSIG` on Linux, a kill-on-close job object on
  Windows (crates/kraken-procguard/src/lib.rs:1-8).

## 5. Untrusted data and the write gate — the type system as the last line

The core primitive is `Untrusted<T>` in `kraken-proto`: binary-derived strings are serialized as
`{"untrusted": true, "value": ...}` and *deserialization fails if the flag is missing* — so a view
type cannot silently launder sample text into a plain string
(crates/kraken-proto/src/untrusted.rs:9-14). The sanitizer strips C0/C1 controls, ANSI escapes, and
the bidi/format invisibles (U+202A–2E, U+2066–69, U+200E/F, U+061C, zero-widths) — characters that
hide from the person but still reach the model — and cuts at 64 KiB with a visible ellipsis; JSON
values are walked and every string sanitized (crates/kraken-proto/src/untrusted.rs:31-32,
crates/kraken-proto/src/untrusted.rs:115-116, crates/kraken-proto/src/untrusted.rs:126,
crates/kraken-proto/src/untrusted.rs:141). Registry view types carry it in their field signatures —
function names, decompiled text, warnings — and construct it via `Untrusted::sanitized`
(crates/kraken-registry/src/views.rs:65, crates/kraken-registry/src/views.rs:101,
crates/kraken-registry/src/views.rs:411, crates/kraken-registry/src/validate.rs:70). The rule the
agent loop enforces: tool output is passed to the model inside a delimited `<tool_result>` block and
*never interpolated into the system prompt*; which tools may run is decided by the host's
`ToolSpec::permission`, never by model or tool output; dangerous tools need approval every call;
user-facing text goes through `sanitize` (crates/kraken-agent/src/lib.rs:3-11,
crates/kraken-agent/src/safety.rs:1, crates/kraken-agent/src/safety.rs:6,
crates/kraken-agent/src/safety.rs:18, crates/kraken-agent/src/safety.rs:23-24 — and even the docs
admit streamed sanitization is per-chunk, a disclosed limitation,
crates/kraken-agent/src/lib.rs:9-11). Design ADR: docs/design/0005-agent-safety.md:18-20 spells the
provenance tags (`user`, `agent`, `agent-from-binary-text`) and the ingest-again-at-render
sanitization rule.

The write gate is the same everywhere: every edit goes through one `submit` pipeline — read-set,
validate, classify (agents only), log, push (crates/kraken-registry/src/mutate.rs:1-5). A command
carries one of three permission classes (`Safe | Mutating | Dangerous`) declared at registration
(crates/kraken-registry/src/command.rs:33-40), and `Dangerous` always asks
(crates/kraken-registry/src/command.rs:225-227) — though in practice exactly one command wears that
label (`patch_export`, crates/kraken-registry/src/commands/patch.rs:445-447); execution-shaped danger
is instead expressed as explicit in-command approval requests, e.g. running the original program
(crates/kraken-registry/src/commands/rewrite_program.rs:430,
crates/kraken-registry/src/commands/rewrite_program.rs:451-452) or exporting a rewrite
(crates/kraken-registry/src/commands/rewrite.rs:985-987). Agents and the MCP surface are asked where
a person never would be (`needs_user_approval`,
crates/kraken-registry/src/context.rs:151-153, crates/kraken-registry/src/context.rs:167-169).
Overwrite-class edits and past-cap edits become proposals, never silent writes
(crates/kraken-registry/src/mutate.rs:247-256). Path policy refuses *by location* even when a person
would approve: hidden home directories (`~/.ssh` and friends), `/proc`, `/sys`, `/dev`, anything
that is not an ordinary file (crates/kraken-registry/src/trust.rs:1-8,
crates/kraken-registry/src/trust.rs:71-73, crates/kraken-registry/src/trust.rs:87-88,
docs/security.md:22). And the daemon decides *who is an agent* from the credential the connection
presented, never from what the client claims: agent-class connections get a forced MCP surface, their
"approved" flag ignored, their approvals routed to a board only person-connections can answer, their
per-run quota keyed to the credential so reconnecting does not reset the budget
(crates/krakend/src/handler.rs:146-150, crates/krakend/src/handler.rs:162-168,
crates/krakend/src/handler.rs:32-33, crates/krakend/src/handler.rs:661-667,
crates/krakend/src/lib.rs:6-9, docs/security.md:20, docs/security.md:26).

## calxgloss comparison

**(a) Paired assistant vs unattended factory worker.** KRAKEN's AI is built for a human sitting
next to it: five beginner-facing tasks, a chat tab, an activity chip, per-run caps, everything
undoable (docs/assistant.md:3, docs/assistant.md:5). calxgloss has no assistant, no chat, no agent
session at all — its LLM contact is one attempt seam inside the retry loop: prompt, LLM,
verification, record, with the loop keeping only policy (docs/adr/0051-an-attempt-is-one-seam-prompt-llm-verification-and-record-the-loop-keeps-only-policy-strategies-are-adapters-at-the-existing-door-and-the-failing-verdict-routes-into-the-next-prompt.md:1,
crates/pipeline/calxgloss-translator/src/retry/attempt.rs:1-13). The human reviews *artifacts after
the fact*, not model turns in flight.

**(b) Model backends.** Same premise, different breadth. Both are local-first with cloud opt-in,
both speak OpenAI-compatible HTTP to Ollama/vLLM-class servers, and calxgloss even has the same
"discard and ask again" economics (docs/Calxgloss.md:74,
crates/integrations/calxgloss-llm/src/lib.rs:1-5, crates/integrations/calxgloss-llm/src/client.rs:591-593).
Where KRAKEN has four paths (provider APIs, supervised llama.cpp hosting with hash-pinned downloads,
ACP agents, MCP) calxgloss has one base-URL seam — deliberately, since its analysis engine, Kuna, is
an in-process function call with nothing to host (crates/integrations/calxgloss-kuna/src/lib.rs:1-7,
docs/adr/0041-kuna-is-the-only-analysis-engine-the-ghidra-bridge-and-its-lifecycle-are-deleted-and-the-seam-stays.md:1).
KRAKEN's low-context mode and 85%-watermark compaction answer the same small-window problem
calxgloss solves with five context tiers and escalation-on-failure
(crates/shared/calxgloss-types/src/context_tier.rs:59, crates/shared/calxgloss-types/src/context_tier.rs:78,
crates/pipeline/calxgloss-translator/src/retry/config.rs:5-19,
crates/shared/calxgloss-types/src/retry_strategy.rs:31-42).

**(c) Third-party agent surface — the biggest gap.** KRAKEN hands 78 permission-classed commands to
any MCP client and launches pinned third-party agents over ACP; the whole safety machine exists to
make that safe. calxgloss exposes *zero* agent surface: the only bridge it ever had was deleted
(see chapter 33), and there is no ACP, no plugin API. Adopting either path later would mean
importing the governance with it, not just the transport (chapter 33).

**(d) Metering.** KRAKEN meters per *work*: a call ledger with provider/model/feature/job attribution,
estimated USD from a price table, per-run and daily budgets the meter enforces mid-run, and two
commands (`ai_usage`, `ai_jobs`) plus live events to read it out
(crates/kraken-assist/src/meter.rs:7-12, crates/kraken-registry/src/commands/ai.rs:1). calxgloss
records per *attempt*: `TokenUsageEntry` rows in a persisted log, aggregated on demand by analytics
handlers that maintain nothing incrementally (docs/adr/0005-analytics-computed-on-demand-from-persisted-logs.md:1,
crates/shared/calxgloss-types/src/token_usage.rs:49,
crates/interface/calxgloss-web/src/server/handlers/analytics.rs:1-13). calxgloss has no cost
estimation, no budget, and no mid-run kill for spend: its retry config stops at `max_attempts` and a
context-tier cap and says nothing about money
(crates/pipeline/calxgloss-translator/src/retry/config.rs:5-19). With local models that is defensible
— KRAKEN itself prices local calls at free (crates/kraken-registry/src/commands/ai.rs:70-73) — but
calxgloss has no metering seam at all if a cloud endpoint is ever configured.

**(e) Prompt-injection typing.** KRAKEN types untrusted text: `Untrusted<T>` with a
deserialization-enforced flag, a bidi/ANSI/zero-width sanitizer, length cuts with visible ellipsis,
delimited `<tool_result>` blocks, and a system prompt that never interpolates binary text.
calxgloss has none of it: the strings "untrusted" / "Untrusted" do not occur anywhere in the repo
(verified by search over `crates/` and `docs/`, 2026-10-28). Its only sanitizers build *crate and
file names* for the scratch project — `sanitize_crate_name`, `sanitize_identifier` — not
prompt-injection defense (crates/pipeline/calxgloss-verify/src/helpers.rs:4,
crates/pipeline/calxgloss-verify/src/helpers.rs:9). Worse, the prompt templates render with askama
`autoescape = "none"` (crates/integrations/calxgloss-prompts/Cargo.toml:19) — fine for code prompts,
but it means nothing between a hostile DLL export name and the model's context: the evidence bundle
is the single render input of every bundle-fed template (crates/integrations/calxgloss-prompts/src/templates.rs:876,
docs/adr/0049-the-evidence-bundle-is-the-single-render-input-of-the-bundle-fed-templates-with-one-shared-section-include-per-evidence-engine-kept-separate-from-the-projector-seam.md:1)
and carries exactly the fields KRAKEN wraps — names, strings, decompiled text. calxgloss's mitigation
is downstream and total: whatever the model emits must compile and pass behavioral tests, so an
injected instruction can waste an attempt but cannot write anything (crates/pipeline/calxgloss-verify/src/lib.rs:1-5,
crates/pipeline/calxgloss-verify/src/engine.rs:28-30). KRAKEN's compile/run-sandboxed rewrite is the
same downstream posture plus the upstream typing.

**(f) OS confinement.** KRAKEN sandboxes everything that executes, by default, on Linux: decompiler
children, the assistant shell, model-written builds and runs, terminal-agent credential isolation —
spawn fails rather than run unconstrained (section 4 above). calxgloss has no OS sandbox anywhere:
"sandboxed scratch project" means a generated Cargo directory under the workspace that is compiled
and run plainly, and the Wine harness executes the original binary as an ordinary child
(docs/Calxgloss.md:17, crates/pipeline/calxgloss-testgen/src/lib.rs:17,
crates/pipeline/calxgloss-testgen/src/wine.rs:1); a grep for landlock/seccomp/namespace primitives
across `crates/` returns zero hits (2026-10-28). calxgloss's blast radius is smaller — the Wine run
touches a DLL in a temp tree and the compile runs only *validated* translations — but a malicious
DLL export body executed under the baseline harness has the user's full environment. KRAKEN's
sidecar posture (refuse to spawn if the sandbox cannot be enforced) is the idea with no calxgloss
equivalent.

### Steal

1. **`Untrusted<T>`-style typing for bundle text.** A wrapper whose serialization fails without the
   flag, applied to the evidence-bundle fields that templates render, plus the
   control/bidi/zero-width sanitizer and visible truncation — one small crate, closes the (e) gap
   without touching the pipeline shape.
2. **Cost metering on the attempt record.** KRAKEN's per-call ledger fields (feature, job/run,
   estimated cost) map cleanly onto calxgloss's existing attempt records, and a config-level budget
   with a clean stop (crates/kraken-assist/src/meter.rs:271-288 pattern) is cheap insurance for any
   future cloud endpoint.
3. **Evidence-computed confidence, model self-assessment ignored.** KRAKEN counts independent
   evidence kinds agreeing on a name suggestion and discards the model's own confidence
   (crates/kraken-assist/src/output.rs:489). calxgloss could score name/type suggestions from its
   own engines the same way instead of parsing the model's confidence claims out of the response.
4. **Refuse-to-spawn confinement for the Wine harness.** `kraken-confine`'s policy vocabulary —
   read-only system paths, one read-write run dir, rlimits, network denied, fail-if-unavailable — is
   directly applicable to `testgen`'s Wine runs on Linux (crates/kraken-confine/src/lib.rs:1-16).

### Confirm

- Local-first economics with cloud as a configured extra — both repos land on the same premise
  (docs/Calxgloss.md:74; docs/local-models.md:16).
- Verification of model output as the real safety net: compile + behavioral tests in calxgloss,
  lint + sandboxed build/run in KRAKEN (crates/kraken-rewrite/src/lint.rs:1-14).
- Hash-pinned supply chains: KRAKEN pins npm lockfiles, Node LTS archives, llama-server releases and
  model files by SHA (crates/kraken-acp/src/adapter.rs:1-4, crates/kraken-infer/src/recommend.rs:31);
  calxgloss pins Kuna to a release tag (crates/integrations/calxgloss-kuna/src/lib.rs:4) — same
  instinct, KRAKEN just carries it further.
- Quotas that survive reconnects and surface that fact to the user (docs/security.md:26) — validates
  calxgloss's ADR-0005 "persist the log, compute on demand" choice; KRAKEN's read-out commands are
  the same idea exposed as CLI.

### Don't copy

- **The terminal-agent host and its governance.** calxgloss has no interactive session, no daemon, no
  credential classes — the ACP host, namespace sandbox, approval board and 53-tool palette exist
  only because KRAKEN invites third-party agents to drive a live project. Importing the surface means
  importing all of it; the correct calxgloss answer stays "the pipeline is the agent".
- **The provider zoo** (Anthropic/OpenAI/Gemini adapters, pricing tables, `genai`-then-reqwest
  drift). calxgloss's single base-URL seam is the right size for a factory that runs one model class.
- **Low-context tool-schema negotiation** — meaningless without a tool-calling loop; calxgloss's
  context tiers already play that role.

## Sources

- KRAKEN at `68718c6` (clone at `/tmp/opencode/kraken`); all `path:line` cites verified 2026-10-28.
- KRAKEN docs: `README.md`; `docs/assistant.md`; `docs/security.md`; `docs/mcp.md`;
  `docs/concepts.md`; `docs/local-models.md`; `docs/design/0005-agent-safety.md`,
  `docs/design/0007-sidecar-confinement.md`, `docs/design/0008-ai-integration-and-inference.md`.
- KRAKEN crates: `kraken-assist` (lib, host, tasks, meter, ai_config, pricing, acp, output,
  shell/policy, shell/sandbox, shell/host), `kraken-agent` (lib, safety, agent, compact,
  low_context, config, provider/*), `kraken-acp` (lib, host, confine, profile, notice, adapter,
  node, Cargo.toml), `kraken-infer` (lib, llama, recommend, strata), `kraken-proto` (untrusted),
  `kraken-registry` (commands/mod, commands/ai, commands/help, commands/local_model,
  commands/patch, commands/rewrite, commands/rewrite_program, mutate, command, context, trust,
  session, views, validate), `krakend` (lib, handler, host), `kraken-confine`, `kraken-sidecar`
  (sandbox), `kraken-procguard`, `kraken-rewrite` (lint, service), `kraken-emu`.
- calxgloss: `docs/Calxgloss.md`; ADRs 0005, 0041, 0049, 0051;
  `calxgloss-translator` (retry/attempt, retry/config), `calxgloss-types` (retry_strategy,
  context_tier, token_usage), `calxgloss-llm` (lib, client), `calxgloss-kuna`,
  `calxgloss-prompts` (Cargo.toml, templates), `calxgloss-verify` (lib, engine, helpers),
  `calxgloss-testgen` (lib, wine), `calxgloss-web` (handlers/analytics).
- Absence checks in calxgloss (2026-10-28): no `untrusted`/`Untrusted` hits in `crates/` or `docs/`;
  no Landlock/seccomp/namespace primitives anywhere; no ACP/MCP surface outside historical ADR notes.
