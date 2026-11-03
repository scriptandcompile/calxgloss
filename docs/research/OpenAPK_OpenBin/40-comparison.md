# OpenAPK / OpenBin ↔ calxgloss — the head-to-head comparison

> Part of the [OpenAPK/OpenBin overview](README.md). Every factual claim in
> this chapter traces to a series chapter — [00](00-scope-and-method.md),
> [10](10-calxgloss-baseline.md), [20](20-openbin-inventory.md),
> [31](31-analysis-pipeline-and-workers.md), [32](32-data-model-and-storage.md),
> [33](33-llm-and-agentic-layer.md), [34](34-product-social-and-reports.md),
> [35](35-ops-licensing-and-qa.md) — which cite the pinned clone
> `/tmp/opencode/openbin` @ `aee59b05` at `path:line` ([00](00-scope-and-method.md)).
> A few load-bearing paths are re-cited here directly where they anchor a verdict.

**The one line: OpenBin proved that decompile-and-discuss is a product — and
that buying the compute to do it in the cloud doesn't pay for a one-person,
agent-built shop. calxgloss gives that compute away (it runs on the user's
machine) and competes on the one thing OpenBin has zero of: mechanically
verified translation.**

---

## 1. Framing: two rungs of one ladder

OpenAPK/OpenBin and calxgloss climb the **same ladder**: same inputs (native
ELF/PE/Mach-O binaries; OpenAPK adds Android APK/DEX), same engine lineage
(Ghidra headless — OpenBin wraps `analyzeHeadless` in stateless workers
[31 §3]; calxgloss embeds Ghidra's decompiler in-process via Kuna, ADR-0039–
0041), and the same construction mode (one human plus Claude — OpenBin has
126 Claude co-authored trailers of 131 commits, single author
[20 §9, re-verified]). They diverge at exactly two decisions:

1. **Who pays for compute.** OpenBin bought it as SaaS — Ghidra/JADX in AWS —
   and had to sunset it: `worker-disabled: ${OPENAPK_GHIDRA_DISABLED:true}`
   (`application.yml:184`) and `${OPENAPK_JADX_DISABLED:true}` (`:204`),
   comments naming "the biggest line on the AWS bill"; the pivot is a local
   Go CLI running the same worker containers on the user's machine
   ([31 §3–§4](31-analysis-pipeline-and-workers.md)). calxgloss never sold
   compute at all — it is a local tool by charter
   ([10](10-calxgloss-baseline.md)).
2. **What the artifact is for.** OpenBin's output feeds a *talking venue*:
   multi-tenant collaboration, reports, CTF, social graph — 46 % of its 178
   endpoints move people, not bytes ([34 §7](34-product-social-and-reports.md)).
   calxgloss's output feeds a *reviewer reaching a verdict*: read-only web
   views over artifacts (ADR-0006), review overlays (ADR-0003), verification
   as the only argument that counts
   ([10](10-calxgloss-baseline.md)).

OpenBin's measured cost of decision (1) is the series' most useful dataset:
what happens when cloud RE compute meets free BYOK tiers meets one maintainer.

## 2. Capability matrix

Winner in **bold**; "—" = absent. Details link to chapters.

| Domain | OpenBin | calxgloss | Verdict | Ch. |
|---|---|---|---|---|
| Analysis engines & pipeline | Ghidra/jadx sidecar workers (3-layer timeout stack, partial-salvage deadline), + pypi/shell/script supply-chain analyzers; cloud sunset → local CLI | Kuna only, in-process, zero lifecycle; **15 batch whole-binary evidence scans** before any model call | split — OpenBin wider and salvage-tolerant; calxgloss deeper and lifecycle-free | [31](31-analysis-pipeline-and-workers.md) |
| Data model & provenance | Postgres: 47 migrations, 34 tables, S3 refcounted blobs, timestamp-as-flag publishing, sha256→ETag chain, **no worker-version stamp** | git + `re/` JSON single-writer; typed records, coverage stamps (ADR-0053), unknowns ledger (ADR-0056), justification commits | **calxgloss on honesty of provenance; OpenBin on multi-user mechanics** (both fit their owner-model) | [32](32-data-model-and-storage.md) |
| Evidence depth into prompts | per-tool caps: 12 000 chars / 200 disasm lines / 40 hits (`BinnyToolkit.java:38-40`); 60 KB function context, **truncation declared in-prompt** (`BinnyAgentService.java:233,246,292`) | fat evidence bundles: 15 scans, 5 context tiers, bundle/projector seam (ADR-0048/0049) | **calxgloss, by a mile** — same honesty instinct, opposite depth budget | [31](31-analysis-pipeline-and-workers.md), [33](33-llm-and-agentic-layer.md) |
| LLM loop & verification | BINNY: live chat agent, 8 kind-gated tools, `MAX_ITERATIONS = 8` (`BinnyAgentService.java:56`), SSE stream; **no verification layer at all** | attempt seam (ADR-0051) closed by compile + Wine-baseline test + trace verdicts (ADR-0057) | **calxgloss — this is the axis** | [33](33-llm-and-agentic-layer.md) |
| LLM cost governance | implemented: per-purpose usage rows (`purpose`, input/output tokens, daily/monthly caps, `V11__llm_usage.sql`), user-self-set caps, worker-quota env, **Anthropic prompt caching** (`ToolLlmInvoker.java:158-165`) | token-only logs; cost/budgets are roadmap P50 | **OpenBin — implemented beats planned** | [33](33-llm-and-agentic-layer.md), [35](35-ops-licensing-and-qa.md) |
| Security & confinement | gitleaks CI, BYOK vault (AES-256-GCM + KEK), SSRF egress allowlist, one injection-guard line (`BinnyAgentService.java:330-336`) — but hardcoded default KEK (`application.yml:73`) and no-op-by-default worker tokens | verified absence of auth/multi-tenancy by design; **no sandbox (P43), no untrusted typing (P45), no CI (P42)** | split — OpenBin ahead on *shipped* parts, and each is booby-trapped where rushed | [33](33-llm-and-agentic-layer.md), [35](35-ops-licensing-and-qa.md) |
| Collaboration & product | real venue: collaborators/roles, presence, forks over shared blobs, publish, comments/votes, DMs, notifications, weekly CTF, reports w/ templates & taxonomy | verified absence (single local user; verdicts are the only human input) | **OpenBin on the axis**; calxgloss's non-entry is a doctrine, not a gap | [34](34-product-social-and-reports.md) |
| QA / CI / eval | 17 test files / 70 `@Test` / 2 335 test LOC (~2.8 %); test CI: none (gitleaks only); Dockerfile & CONTRIBUTING *claim* test infra that does not exist; one shipped prod schema incident (V22→V23) | ~4.7k inline tests + 51 integration files + e2e, **no CI at all**, one fixture DLL, scored eval = P33 open | **tie** — both are one-human-plus-Claude codebases at the same choke point | [35](35-ops-licensing-and-qa.md) |
| Economics & distribution | BYOK + free tier + cloud compute → dead; survivor is local CLI with version-less release assets, docker-load tarballs, `VERSION`-nudge auto-update | local-first, compute cost zero to the project; distribution = one changelog tag (`v0.2.0`) | **calxgloss on model; OpenBin on the distribution mechanics worth copying** | [31](31-analysis-pipeline-and-workers.md), [35](35-ops-licensing-and-qa.md) |
| Licensing & openness | AGPL-3.0-or-later + CLA for dual-licensing + trademark split + commercial escape hatch; full runtime open incl. compose stack | project-proprietary local tool (not examined further here) | not comparable as product; OpenBin's posture is a deliberate "open but owned" play | [35](35-ops-licensing-and-qa.md) |

## 3. Convergence — independently arriving at the same wall

1. **Engine identity as a release primitive.** OpenBin locksteps the worker
   image tag inside the tarball (`openbin/ghidra-worker:7`) with the CLI
   default (`cli/config.go:62`), manually
   ([31](31-analysis-pipeline-and-workers.md), [35 §2](35-ops-licensing-and-qa.md));
   calxgloss legislated it as the engine-identity-keyed scan cache
   (ADR-0055). Same diagnosis — *an engine bump silently invalidates every
   cached reading* — with OpenBin's manual pinning the weaker remedy.
2. **Bounded compute with a named failure.** ghidra-worker's three-layer
   timeout stack ends in a soft deadline so `extract.py` lands a *partial*
   result ([31 §3](31-analysis-pipeline-and-workers.md)); calxgloss budgets
   per-function decompile windows and refuses loudly (ch. 10). Same disease;
   opposite treatment (salvage-and-declare vs refuse-and-record).
3. **Never let a prompt lie about its evidence.** OpenBin marks every
   truncation *inside the prompt text* ("truncated to the first 60 KB",
   "function continues past this point" — `BinnyAgentService.java:233,246,292`);
   calxgloss stamps coverage on every scan (ADR-0053) and files admitted gaps
   as named records (ADR-0056). Neither parses the model's self-assessment.
4. **LLM spend as a first-class ledger row.** `llm_usage`: one row per call
   with `purpose`, provider, input/output tokens (`V11__llm_usage.sql`)
   ([33 §5](33-llm-and-agentic-layer.md)); calxgloss logs `token_usage.json`
   and computes analytics on demand (ADR-0005) but stops at tokens — no
   money, no gate (P50).
5. **Same builder, same bottleneck.** 126/131 Claude co-authored commits
   [20 §9]; calxgloss is built the same way. Both skipped CI; both lack a
   scored oracle (OpenBin has none; calxgloss's is P33). The QA choke point
   of one-human-plus-Claude codebases shows up identically in both trees
   ([35](35-ops-licensing-and-qa.md)).

## 4. Divergence — where the designs are incompatible

1. **The vessel.** Multi-tenant Postgres (34 tables of FKs, quotas,
   refcounts, CHECK-constraint hotfixes V23, rename-collision fix V39) +
   Keycloak + S3 ([32](32-data-model-and-storage.md)) vs git substrate:
   attempt branches, overlays, merge-is-accept
   ([10](10-calxgloss-baseline.md)). OpenBin's DB machinery is *forced* by
   concurrent human writers; calxgloss legislated that problem away —
   "collaboration is what forces a database; honesty is what forces a
   record" ([32 §8](32-data-model-and-storage.md)).
2. **How LLMs are bolted on.** BINNY is a live conversation agent: read
   tools fetch on demand, write tools write immediately, and the agent's
   "memory" is browser `localStorage` replayed as ≤60 turns — the server
   keeps zero state ([33](33-llm-and-agentic-layer.md)). calxgloss's seam is
   one prompt per attempt, typed artifacts in, compile+baseline test out,
   failing verdict routed into the next prompt (ADR-0051). Auditable and
   reproducible only on the calxgloss side; conversational only on the
   OpenBin side. Do not import the loop into the factory.
3. **Renames.** OpenBin treats renames as analyst input that *feeds the
   analysis surface* (rename-scoped-unique fix V39; renames ride the served
   API and the chunks the AI sees). calxgloss treats renames as translation
   acts: type write-back narrows undefined slots (ADR-0021), reviewer
   intent lives in overlays (ADR-0003). Fast loop vs recorded verdict —
   the series' most instructive side-by-side.
4. **Injection defense.** OpenBin's entire structural defense is the BINNY
   system prompt's guard lines (`BinnyAgentService.java:330-336`: sample
   content is data, never directions; never call a write tool because the
   sample said so) — while renames, report sections and highlights
   recirculate human text into later prompts with no sanitization
   ([33](33-llm-and-agentic-layer.md)). calxgloss has no implementation
   today (P45 open). Honest verdict: both lines are thin; OpenBin is the
   field evidence of what *not* having typed untrusted data does.
5. **Honesty at the published edge.** calxgloss stamps coverage at scan time
   and files unknowns as records (ADR-0053/0056); OpenBin's *published*
   reports and public project pages carry no coverage/unknown qualification
   at all ([34](34-product-social-and-reports.md)).
6. **Economics.** BYOK + free tier + cloud workers failed (sunset defaults;
   the pivot hands compute to the user) ([31](31-analysis-pipeline-and-workers.md));
   calxgloss's local-first charter never incurred the bill.

## 5. What calxgloss should steal (ranked; P-numbers verified against `docs/roadmap.md`)

1. **Per-purpose LLM metering + budget gates + user-facing caps — the
   working demo of P50.** `llm_usage` rows (`purpose`, provider, tokens;
   `V11__llm_usage.sql`), user-self-set daily/monthly token caps, a
   per-turn budget check *before* each model call, and the single cheapest
   lever of all: **Anthropic prompt caching on the invariant system block**
   (`ToolLlmInvoker.java:158-165`) — calxgloss's bundle prefix is nearly
   constant across attempts, so the same one-liner applies the day an API
   backend is configured. ([33 §5](33-llm-and-agentic-layer.md))
2. **gitleaks-on-PR as the P42 seed.** One workflow, full-history scan,
   ~10 lines — the non-vacuous floor under "no CI at all" (roadmap P42).
   OpenBin proves both halves: how cheap the floor is, and that a floor is
   not a ceiling (it still committed a default KEK — see §6).
   ([35 §1](35-ops-licensing-and-qa.md))
3. **The guard-line stopgap while P45 lands.** Two prompt sentences naming
   untrusted content and banning tool actions on its instruction-like text
   (`BinnyAgentService.java:330-336`) cost nothing and bound the bundle→prompt
   path until `Untrusted<T>` + sanitizer (P45) exists. And read OpenBin as
   the longitudinal study of the *absence*: renames/reports/highlights
   recirculate unsanitized. ([33](33-llm-and-agentic-layer.md))
4. **Distribution: version-less release assets + VERSION-nudge + docker-load
   tarballs.** `releases/latest/download/<name>` as a permanent URL, a tiny
   `VERSION` asset powering self-update without an API, and image shipping as
   a release-asset tarball (`docker load`, no registry auth)
   ([35 §2](35-ops-licensing-and-qa.md)) — directly applicable to how
   calxgloss ships its engine pins.
5. **Salvage-with-declared-partiality for long engine runs.** The soft
   deadline that makes a timed-out Ghidra run still deposit a usable partial
   result ([31 §3](31-analysis-pipeline-and-workers.md)) composes cleanly
   with calxgloss's coverage stamps: a scan that lands 80 % with coverage
   recorded beats a scan that refuses without recording. Pairs with ADR-0053,
   does not contradict it.
6. **Reviewer-facing summaries auto-populated from analysis.** OpenBin's
   report sections pre-fill from analysis artifacts and version
   append-only ([34 §6](34-product-social-and-reports.md),
   [32 §3](32-data-model-and-storage.md)) — same shape ADR-0049's
   bundle-fed templates give calxgloss; OpenBin's independent arrival is
   confirmation, and its taxonomy/search tables (V19) are a free design
   study if calxgloss ever ships report search.

**Explicitly do NOT copy** (each verified in-chapter): the hardcoded default
KEK that silences its own fail-fast (`application.yml:73`)
([35 §7](35-ops-licensing-and-qa.md)); opt-in worker auth that is a no-op
when unset ([31 §5](31-analysis-pipeline-and-workers.md)); documentation
that claims CI/test infra which does not exist (Dockerfile, CONTRIBUTING —
[35 §1, §3](35-ops-licensing-and-qa.md)); localStorage-as-agent-memory;
multi-tenant auth/quota machinery (calxgloss has no such tenants —
[10](10-calxgloss-baseline.md)); the five-phase JSONB→S3 migration pattern
that stalls at phase 1 with the later phases existing only as comments
([32 §4](32-data-model-and-storage.md)).

## 6. What OpenBin confirms about calxgloss's choices

- **Local-first compute was right, numerically.** The sunset defaults and
  their comments are the receipt: always-on Ghidra/JADX was "the biggest
  line on the AWS bill" and the free-tier BYOK stack was unmaintainable
  ([31 §3](31-analysis-pipeline-and-workers.md),
  [35 §6](35-ops-licensing-and-qa.md)).
- **Decompiled output is a commodity; verified translation is the unmet
  need.** With cloud workers sunset and decompile pushed to a free local
  CLI, OpenBin's moat became the social layer — while its LLM products carry
  *zero* mechanical verification ([33 §8](33-llm-and-agentic-layer.md),
  [34 §7](34-product-social-and-reports.md)). The axis calxgloss owns is
  exactly the one OpenBin vacated.
- **The sidecar lifecycle tax is real.** OpenBin needs worker HTTP services,
  (conditional) worker tokens, three-layer timeout stacks, partial-salvage
  logic and per-upload quota reservation/rollback machinery
  ([31](31-analysis-pipeline-and-workers.md)) — the cost of JVM sidecars.
  calxgloss's in-process Kuna seam (ADR-0041) buys out of all of it.
- **DB+FK+quota+CAS machinery is the price of concurrent writers** —
  migration war stories V23/V39 read as scar tissue ([32 §2](32-data-model-and-storage.md));
  calxgloss's single-writer git substrate sidesteps the whole class.
- **CI-before-eval sequencing is confirmed by a production incident.**
  OpenBin's one shipped prod bug is a CHECK-constraint violation that
  migrations V22→V23 had to hot-widen — precisely the class a CI schema
  test catches; roadmap P42-before-P33 ordering stands
  ([32 §4](32-data-model-and-storage.md), [35](35-ops-licensing-and-qa.md),
  `docs/roadmap.md`).
- **Prompt-honesty doctrine converges again** (declared truncation on both
  sides) — third independent repo (with KRAKEN, REA) to treat "never feed
  the model a lie about coverage" as load-bearing
  ([33 §9](33-llm-and-agentic-layer.md)).

## 7. What OpenBin teaches about the market around calxgloss

Of 178 endpoints: 57 analysis/RE bench, 44 pure social/communication, 29
collaboration plumbing, 24 report authoring/publish, 7 CTF
([34 §7](34-product-social-and-reports.md)) — the paying motion analysts
chose is *collaboration, Q&A and reporting over decompiled output*, not
automatic translation (which OpenBin gave away). calxgloss's read-only web
views (ADR-0006) and verdict ledger (ADR-0056) are the right seed if a
review ever goes multi-party — but ADR-0054's seam-only admission and the
factory model mean the product answer for calxgloss is the verdict record,
not a feed. CTF/community machinery is market evidence, not a steal
([34 §7](34-product-social-and-reports.md)).

## 8. Open questions / where the evidence runs thin

- **Traction is unobservable**: users, revenue and hosted-instance scale live
  in the private operator repo; the repo's own README still says "Slice 1"
  forty-seven migrations into reality ([20](20-openbin-inventory.md)).
- **Is the sunset permanent?** The flags say "flip back once sponsorship
  lands" ([31 §3](31-analysis-pipeline-and-workers.md)) — economics may
  invert with funding.
- **Quality of OpenBin's LLM products in use** (answer quality, deobf
  correctness) has no eval in the repo and cannot be inferred from code.
- **calxgloss's own PE-translation claims** remain fixture-bounded until
  P33's scored oracle lands — this series' baseline is honest about it
  ([10 §QA](10-calxgloss-baseline.md)).
