# ReverserAI ↔ calxgloss — the full comparison

> Part of the [ReverserAI overview](README.md). Every ReverserAI claim below
> cites this dossier's files ([20](20-reverser-ai-inventory.md)–[33](33-ai-layer-and-prompts.md),
> clone-relative `path:line` at `1d572da`/v1.2); every calxgloss claim cites
> the fixed baseline ([10](10-calxgloss-baseline.md), verified at HEAD `40fbf91f`,
> 2026-10-31).

**Bottom line up front: ReverserAI and calxgloss answer the same question —
"can a locally-hosted LLM do reverse engineering on consumer hardware?" — from
opposite ends of every design axis, and the comparison is worth doing precisely
because neither can borrow much from the other.** ReverserAI (v1.2, 1,028 LOC
of Python, GPL-2.0+, a Binary Ninja plugin, frozen since 2026-05) is an
assistive single-task tool: it proposes names for anonymous `sub_*` functions
from HLIL plus static-analysis context, applies them unconditionally, and
verifies nothing ([20](20-reverser-ai-inventory.md), [32](32-binary-ninja-plugin.md),
[33](33-ai-layer-and-prompts.md)). calxgloss (≈279k LOC Rust, MIT) is an
automated full-pipeline factory: PE → Rust per unit, each attempt mechanically
verified (compile + Wine-captured values + API-trace containment) and
human-reviewed at the verdict, with naming deliberately *never applied* — unit
identity is the binary-side name, write-back is types-only by doctrine
(ADR-0020/0021) ([10](10-calxgloss-baseline.md)). This is not two tools
competing for one job; it is one doctrine ("assist and let a human eyeball the
result") versus the opposite doctrine ("automate, but prove mechanically").
ReverserAI's chief value to calxgloss is confirmatory — local GGUF inference is
a UX people actually adopt, bottom-up context propagation is "simple but
effective", and fine-tuning was a bet its own author declined to make — plus a
cautionary tale: its flagship bulk-rename feature shipped broken for ~23 months
under zero tests and (until v1.2) zero CI, which is exactly the failure mode
calxgloss's new P42 exists to prevent ([21](21-history-and-releases.md),
[32](32-binary-ninja-plugin.md)).

## Capability matrix

Winner in **bold**. "—" = absent.

| Capability domain | ReverserAI | calxgloss | Verdict | Ch. |
|---|---|---|---|---|
| Mission & target | Rename anonymous `sub_*` functions in an open Binary Ninja view — one function (C1), a whole binary bottom-up (C2), or a string/import-triaged subset (C3) | Rewrite whole directories of Windows PE32/PE32+ into behaviorally equivalent Rust, one unit of work at a time | split — different jobs entirely; calxgloss has no standalone naming feature to even compare against | [32](32-binary-ninja-plugin.md), [10](10-calxgloss-baseline.md) |
| Integration surface | BN plugin: 3 menu commands + 6 BN settings + marketplace manifest (`plugin.json`, min BN build 2487); no PyPI, no CLI on user input (the demo script names a hard-coded XOR function) | pipeline + `live` process + 29 CLI subcommands + Axum/React review UI (two REST routers, ADR-0002); no interactive address-level surface | split — ReverserAI is where a human sits today; calxgloss's surface is where a verdict gets adjudicated | [20](20-reverser-ai-inventory.md), [32](32-binary-ninja-plugin.md), [10](10-calxgloss-baseline.md) |
| Analysis engine | none of its own — rents BN's HLIL decompiler (`f.hlil_if_available` guard, `f.hlil.root.lines`); MLIL/LLIL/disasm never used | Kuna, in-process, behind the engine seam (ADR-0039/0040/0041); 15 batch scans + read cache on top | **calxgloss** — ReverserAI has no analysis engine to compare; it parses decompiler text | [32](32-binary-ninja-plugin.md), [10](10-calxgloss-baseline.md) |
| Evidence into prompts | function header + full HLIL dump; "context enrichment" = preselecting string/import-xref functions + bottom-up ordering — no callee/string/symbol list ever appended | 15 registry-driven scans → coverage-stamped evidence bundle (ADR-0052/0053) → 5 context tiers with `unavailable`-family pruning (ADR-0055) and named unknown records (ADR-0056) | **calxgloss, by orders of magnitude** — ReverserAI enriches by *which* functions and *which order*; calxgloss enriches *what the model reads* | [32](32-binary-ninja-plugin.md), [33](33-ai-layer-and-prompts.md), [10](10-calxgloss-baseline.md) |
| Model layer | embedded llama-cpp-python, `Llama(...)` singleton; pinned TheBloke GGUFs (Mistral-7B-Instruct-v0.2 Q4_K_M default ~5 GB, Mixtral Q4_K_M ~25 GB, mythomax vestigial); raw completion, hand-rolled Mistral template, one-shot, `n_ctx=4000` hard-coded; template byte-identical v1.0→v1.2 | ADR-0051 attempt seam over `LlmClient` — OpenAI-compatible HTTP to llama.cpp/Ollama/vLLM; no default endpoint/model, unset fails loudly; 5-tier ladder; per-attempt token/strategy/model telemetry | split — ReverserAI is reproducible but fossilized (frozen template, inert knobs: `max_tokens=5000` > `n_ctx=4000`); calxgloss pluggable and instrumented but pins no reference model | [33](33-ai-layer-and-prompts.md), [31](31-ml-model-and-training.md), [10](10-calxgloss-baseline.md) |
| Function naming | applied unconditionally to `sub_*` via the BN `Function.name` setter; zero validation (empty string, sentence, or regenerated `sub_…` all accepted); undoable only by BN Ctrl+Z | never applied, by doctrine: 4 named-evidence layers (import names via apidetect+PAL, libmatch body-match symbol claims, algorithm claims, mangling/RTTI/consts) feed prompts with confidence + admission lines; the seam's write side writes **types, never names** (`calxgloss-decomp/src/lib.rs:13-14`; ADR-0020/0021) | split by design — calxgloss's no-rename rule is a doctrine, not a gap (see *Naming & typing* in [10](10-calxgloss-baseline.md)); this is the axis the whole comparison turns on | [32](32-binary-ninja-plugin.md), [33](33-ai-layer-and-prompts.md), [10](10-calxgloss-baseline.md) |
| Call-graph ordering | `nx.DiGraph` + `dfs_postorder_nodes` callee-before-caller (`binary_ninja/utils.py:58`) — convention only; C3 iterates plain `bv.functions` while its docstring promises bottom-up ([32](32-binary-ninja-plugin.md) §5) | topological dependency order pinned C≺B≺A by test (`callgraph.rs:964-1032`); queue never puts a dependent first; merges pass a callee-first gate (`calxgloss-git/src/dependency.rs:80-87`) | same principle, opposite enforcement — **calxgloss**: it enforces the ordering and tests it; ReverserAI documents it in one command and breaks it in another | [32](32-binary-ninja-plugin.md), [10](10-calxgloss-baseline.md) |
| Verification of model output | none — acceptance condition is "current name matches `^sub_[0-9a-f]+$` and the model returned"; no identifier-charset/length check, no dedup, no confirmation; oversized input → one `log_warn` line, soft silent skip | the gate *is* calxgloss: `cargo check` + behavioral tests vs Wine-captured baselines + ordered API-trace containment (ADR-0057); missing traces read unassessed, never passing | **calxgloss, non-negotiable** — this is the axis that separates the two projects' categories of output | [32](32-binary-ninja-plugin.md), [33](33-ai-layer-and-prompts.md), [10](10-calxgloss-baseline.md) |
| State & reversibility | BN in-memory undo history + bndb autosave; renames issued from a background thread, recorded nowhere but the Log window; no per-decision record at all | git attempt branches `re/{binary}/{function}v{N}`; failure branches kept forever, unmerged ones archived by `gc` never deleted; justification commits carry model + context size; verdicts (accept/send-back) are persisted state | **calxgloss** — Ctrl+Z in a GUI session is not a state substrate | [32](32-binary-ninja-plugin.md), [10](10-calxgloss-baseline.md) |
| Evaluation & QA | zero tests in any of 25 commits; CI only at v1.2 and only lint/metadata/AST (`ci.yml`); the only numbers ever published are latencies (deck slide 40) + one self-scored 7-row table (slide 44, no rubric, scale direction undefined); the inverted `hlil_if_available` guard shipped through v1.1 and disabled bulk renaming for ~23 months (2024-06→2026-05) — what zero-CI looks like when nobody re-runs the flagship path | no CI at all (verified absence; open P42); one fixture DLL, no scored eval (open P33); but every merged unit carries per-unit mechanical proof by construction | split — calxgloss only wins because its verification stands in for an eval layer; on raw QA infrastructure both are weak, and calxgloss files the gap on its roadmap while ReverserAI does not | [20](20-reverser-ai-inventory.md), [21](21-history-and-releases.md), [31](31-ml-model-and-training.md), [10](10-calxgloss-baseline.md) |
| Local-model economics | ~5 GB Mistral Q4_K_M auto-downloaded on first use; measured 5–8 s/query on M1 MBP, 10 s on M3 MBA, 20–30 s CPU-only (README hardware envelope: 16 GB RAM, 12 threads); no telemetry beyond a log line | local-first is principle 5 ("throwing away incorrect LLM output is cheap when the LLM is hosted locally"); tokens logged per attempt/tier/strategy (`token_usage.json`, `/api/token-usage/*`); cost budgets open at P50 | split — same discard-when-wrong philosophy; ReverserAI proves the consumer-hardware envelope works, calxgloss has the instruments but no budget number yet | [31](31-ml-model-and-training.md), [33](33-ai-layer-and-prompts.md), [10](10-calxgloss-baseline.md) |
| Human's role | ad-hoc right-click (C1) or fire-and-forget bulk runs; human discovers results by scrolling the BN Log window and undoing what looks wrong (verified: zero `InteractionHandler`/`TextDialog` in the repo) | structured verdict review of every unit in the web UI (accept · send-back · patch · skip · override · batch) plus CLI `dashboard accept/send-back`; the human adjudicates units, never addresses | **calxgloss** — eyeballing a log window is not a review workflow | [32](32-binary-ninja-plugin.md), [10](10-calxgloss-baseline.md) |
| Maintenance | frozen: 23-month silence ended 2026-05-20 by two packaging/CI commits; 1,168★ / 94 forks vs 14 watchers; one outside contribution ever; 0 open issues — a citable reference implementation, not a tool being developed | active factory: P21 (unknown records) and P22 (trace gate) shipped within the day before HEAD; 57 ADRs; open roadmap P23–P52 | **calxgloss** | [21](21-history-and-releases.md), [20](20-reverser-ai-inventory.md), [10](10-calxgloss-baseline.md) |
| License | GPL-2.0+ (`LICENSE` is GPL-2.0 text; `plugin.json:15` says "or any later version") — copyleft inside a proprietary host | MIT (`LICENSE:1` + `Cargo.toml` `license = "MIT"`, verified at HEAD `40fbf91f`, 2026-10-31) | split — ReverserAI's GPL blocks any code import into calxgloss outright; MIT costs calxgloss nothing here and makes the *ideas* freely stealable, which matters for the steal list below | [20](20-reverser-ai-inventory.md), repo `LICENSE` |

## Effect, measured vs asserted

**ReverserAI has never measured its actual capability.** Everything the project
itself ever reported, verified in [31](31-ml-model-and-training.md) §4: query
latencies (deck slide 40: "<2s GPT; Mistral 7B on M1 Macbook Pro: 5-8s; …
M3 Macbook Air: 10s"), a hardware envelope (README: 16 GB RAM, 12 threads,
20–30 s/query CPU, 2–5 s on Apple-silicon GPU), one RAM correction
(45 GB→25 GB, `456bc1e`), and one self-scored 7-use-case × 2-model table
(slide 44, "(Unfair) Comparison to GPT4") with no rubric, no dataset, no
defined scale direction. The deck grades its own subject at the top of the
scale on *function renaming* (Mistral 3, Mixtral 3) and the deck's own interim
conclusion (slide 31) says why that number means little: "answers sometimes
generic or wrong… **no real (code) understanding**". Its asserted effects —
naming "quickly sorts" the 23-function Triton malware stub, "it's possible to
automatically identify standard functions like memcpy and strlen"
(examples/README, promised follow-up "never provided through v1.2",
[20](20-reverser-ai-inventory.md) §4) — have no published ground truth. No
accuracy, top-k overlap, or accept-rate number exists; no eval script or test
suite ever existed in any of 25 commits; no third-party quantitative study of
ReverserAI exists either (the NDSS 2026 "Decompiling the Synergy" paper cites
it as lineage ref [13] and validated its own prompt design against it, but did
not benchmark it) ([31](31-ml-model-and-training.md)). What ReverserAI's real
measurable effect is, is *workflow*: 1,168 stars, a BN marketplace listing,
same-day mirrors, a third-party IDA port, and a malware-triage example people
actually cite ([20](20-reverser-ai-inventory.md), [31](31-ml-model-and-training.md)).

**calxgloss has per-unit proof but no aggregate score.** Every merged unit
compiles in a scratch Cargo project, passes behavioral tests against
Wine-captured return values, and (since ADR-0057 shipped at the baseline HEAD)
must contain the original's ordered API-call trace; the verdict is a
data-only `VerificationResult` and missing evidence is *unknown, never absent*
(ADR-0053) ([10](10-calxgloss-baseline.md)). That is mechanical proof *by
construction*, per unit — but there is no scored eval (P33 open), one fixture
DLL instead of a corpus, no whole-binary conformance verdict (P26 open), and no
CI to even hold the line (P42 open, new). So calxgloss can currently claim:
"every unit on `main` passed these checks", and cannot yet claim: "the pipeline
achieves X% on Y binaries".

**Verdict: neither project scores its own quality, but only one of them
can.** calxgloss's verification output *is* a measurement substrate —
per-unit pass/fail + trace-divergence data already exists as typed records and
P33 just aggregates it. ReverserAI's design actively resists measurement:
unconditional apply means there is no accept/reject record, no ground-truth
fixture beyond one 2 KB malware fragment, and no oracle to grade a name
against ([32](32-binary-ninja-plugin.md) §10, [20](20-reverser-ai-inventory.md) §4).
A tool that never records whether a human kept a suggestion can never compute
an accept rate, even later.

## Where the ideas converge

Genuine independent convergence — two teams, same era, no shared code (GPL
aside, calxgloss's design predates the comparison), same conclusions:

- **Local GGUF inference on consumer hardware as the default posture.**
  ReverserAI embeds llama.cpp via llama-cpp-python and auto-downloads Q4_K_M
  GGUFs; calxgloss's `LlmClient` names llama.cpp/Ollama/vLLM and has no
  cloud default at all ([33](33-ai-layer-and-prompts.md), [10](10-calxgloss-baseline.md)).
  Same "LLM-first, discard-when-wrong… cheap when the LLM is hosted locally"
  economics (calxgloss principle 5) and the same privacy framing.
- **Static-analysis context engineering beat learned models — both ways.**
  ReverserAI's author listed fine-tuning only as future work
  (`README.md:156`; deck slide 53 "Things to improve") and *never shipped a
  fine-tune* — verified absent in git history, HF, arXiv, Zenodo
  ([31](31-ml-model-and-training.md)); the method it actually shipped is
  context engineering, and its only visible research-era debt is a **non-ML
  heuristic** (the 2023-08-02 API-functions post feeding its function
  preselection). calxgloss made the same bet structurally: a generalist model
  flooded with 15 evidence-engine scans and admission-stamped claims, zero
  fine-tuning, ADR-driven ([10](10-calxgloss-baseline.md)).
- **Callee-before-caller ordering.** ReverserAI moved from a
  callee-count heuristic to networkx post-order DFS specifically "to propagate
  contextual information from leaves to roots" (`d488e82`,
  [21](21-history-and-releases.md) §2.3); calxgloss pins topological
  callee-first order with tests and a merge gate ([10](10-calxgloss-baseline.md)
  §Pipeline anatomy). Same insight, discovered independently — the difference
  is enforcement, not theory.
- **Name-from-context propagation.** ReverserAI's cheapest trick: because the
  prompt is *current* HLIL and callees are renamed first, learned names flow
  into later caller prompts for free — the deck's slide 48 "Context-sensitive
  Annotations: Bottom-up Propagation", self-annotated "simple but effective"
  ([31](31-ml-model-and-training.md), [33](33-ai-layer-and-prompts.md) §8).
  calxgloss achieves the same effect differently: prior units' knowledge
  reaches later prompts via the context-tier ladder (ModuleContext,
  FullModule) and — this is the calxgloss form of the trick — via **type
  write-back**, which narrows undefined slots so later decompiles render
  richer (ADR-0020/0021, [10](10-calxgloss-baseline.md) §Naming & typing #2).
- **String/API xref triage.** `collect_symbol_related_functions` +
  `collect_string_related_functions` preselect the functions worth querying
  (`binary_ninja/utils.py:61-135`, [32](32-binary-ninja-plugin.md) §9) —
  heir of the author's 2022–2023 most-called-API heuristic
  ([31](31-ml-model-and-training.md) §1); calxgloss runs string-context and
  library-api scans over the whole binary for the same underlying belief:
  import/string xrefs are where a name's evidence lives ([10](10-calxgloss-baseline.md)
  §Pipeline anatomy).

## What calxgloss can honestly steal

Small list, argued for and against, honestly. ReverserAI is 1,028 LOC
([20](20-reverser-ai-inventory.md)); there is little machinery here to take.

1. **Propagate completed units' evidence into the decompile text fed to later
   prompts — mostly already stolen.** ReverserAI's single best idea is that
   renamed callees enrich caller HLIL *for free* ([32](32-binary-ninja-plugin.md)
   §5). calxgloss already does the safe half: the seam's `TypeWriteSource`
   writes prototypes and variable types (calxgloss-decomp/src/lib.rs:13-14),
   narrowing slots in program order, so later scans and decompiles see a
   better-typed program — the same enrichment, without touching names
   (ADR-0020/0021, [10](10-calxgloss-baseline.md)). Should calxgloss go
   further and write **names** back? Argue against: names in calxgloss are
   evidence-derived *claims*, not address-bound facts — libmatch and algorithm
   claims carry confidence scores and version-admission lines precisely because
   they can be wrong, and P51's whole point is to *score* such claims by
   counting independent agreeing evidence kinds, "model self-assessment
   ignored" ([10](10-calxgloss-baseline.md) §Naming & typing #7, roadmap).
   Materializing an unverified LLM/libmatch name into the decompile text would
   launder a scored claim into the model's input as fact — poisoning exactly
   what P51 is designed to measure — while unit identity (branches, output
   paths, log join keys, the Wine locator that parses `FUN_` names as RVAs)
   is binary-side verbatim and must never move ([10](10-calxgloss-baseline.md)
   §Naming & typing #1). **Steal the principle, reject the mechanism: types
   are write-back-able because they are mechanically verified by the same
   compile that consumes them; names are not.**
2. **String/import-xref preselection as a triage signal — cheap, and already
   ~covered.** calxgloss's string-context and library-api scan rows compute the
   same xref sets over the whole binary ([10](10-calxgloss-baseline.md));
   ReverserAI's twist is using them to *order/prioritize* which functions get
   queried first (C3, [32](32-binary-ninja-plugin.md) §5). Since calxgloss
   queues by dependency order and eventually queries everything, there is
   little to add — at most a triage *display* for `doctor`/dashboard ("which
   units touch imports/strings") for humans skimming queue depth. Low value;
   say so rather than pretend otherwise.
3. **ReverserAI as negative evidence for the roadmap.** The inverted
   `hlil_if_available` guard (`cf8e449`, introduced 2024-06-20) shipped through
   v1.1 and disabled *both bulk commands* — the flagship feature — for ~23
   months, through a ruff pass that made it read canonically correct
   (`!= None` → `is not None`, still inverted) and was fixed only in the v1.2
   release commit ([21](21-history-and-releases.md) §2.3–2.4,
   [32](32-binary-ninja-plugin.md) §8). Zero tests, zero CI for the repo's
   first two years; v1.2's CI gates lint/format/metadata/AST and still runs no
   behavior ([20](20-reverser-ai-inventory.md) §3). That is the concrete
   citation calxgloss's **P42 (CI substrate)** and **P33 (eval)** need:
   "a 1,168★ project's headline feature was broken for 23 months and nobody
   noticed, because nothing was ever re-run" — and calxgloss currently has
   *no* CI at all. Free ammunition; no code to import.
4. **The GGUF pinning pattern, as an eval baseline.** ReverserAI pins exact HF
   repos + quantized filenames (`TheBloke/Mistral-7B-Instruct-v0.2-GGUF`,
   `mistral-7b-instruct-v0.2.Q4_K_M.gguf`, `models.py:29-32`) and froze one
   prompt template byte-identical from v1.0 to v1.2
   ([33](33-ai-layer-and-prompts.md) §2, §4). Frozen-ness aside (the template
   was never tunable, not reproducibly-good — see
   [33](33-ai-layer-and-prompts.md) §7's inert knobs), the *pin* is a real
   reproducibility baseline: when P33's eval runs local models, calxgloss has
   no default model at all ("no defaults; unset values fail loudly",
   [10](10-calxgloss-baseline.md) §Model layer), so eval cassettes need a
   named reference model + quant + template hash to be comparable across runs.
   Adopt: pinned reference-model registry rows for eval, not for production.

**The rest of ReverserAI is a lesson, not a source of steals** — and the honest
reasons are structural: the scale mismatch (1,028 LOC over one prompt vs a
279k-LOC workspace with 15 evidence engines — there is no ReverserAI subsystem
large enough to port), the license (GPL-2.0+ vs MIT: any *code* import is
off the table; only patterns and prose are portable), and the missing oracle
(ReverserAI has nothing that produces a verifiable artifact — no verification,
no records, no eval — so there is no machinery for calxgloss's verification
layer to plug into).

## What ReverserAI confirms about calxgloss's choices

- **Local llama.cpp is viable UX, proven at adoption level.** 1,168 stars, a
  BN marketplace listing, real users running 5 GB Q4_K_M GGUFs on laptops at
  5–8 s/query ([20](20-reverser-ai-inventory.md), [31](31-ml-model-and-training.md)
  §4). calxgloss's "local-first, no cloud default, endpoint is pure config"
  posture is not a purity tax — ReverserAI is evidence that this exact posture
  is what practitioners adopt when it exists ([10](10-calxgloss-baseline.md)
  §Model layer).
- **A naming tool without verification is a convenience toy whose output a
  human re-reviews manually.** ReverserAI applies unvalidated strings
  (empty, sentences, regenerated `sub_…`) and relies on BN Ctrl+Z plus human
  eyeballing of the Log window ([32](32-binary-ninja-plugin.md) §10, §6).
  That is precisely why calxgloss puts naming *inside* the compile+test+trace
  loop instead of beside it: names-as-evidence ride into prompts with
  confidence and admission lines, and the only write-back is the
  mechanically-checkable kind (types) ([10](10-calxgloss-baseline.md)
  §Naming & typing).
- **Interactive BN-plugin workflows stop at "better labels."** ReverserAI's
  entire ceiling is names on a database a human already owns; its own deck
  concedes "no real (code) understanding" (slide 31,
  [31](31-ml-model-and-training.md) §4). The pipeline endgame — Rust rewrite
  with per-unit equivalence proofs — cannot be reached from an in-GUI undo
  substrate and one-shot queries; it needs the factory shape: batch evidence,
  attempt branches, verdicts ([10](10-calxgloss-baseline.md) §Surface & state).
- **One-shot prompting has a hard quality ceiling — which makes context
  tiers, not model choice, the lever.** ReverserAI's prompt is byte-identical
  across its whole public history (`git log -S add_two_values` → only
  `cfa9908`, [33](33-ai-layer-and-prompts.md) §2), its only "model
  improvement" was swapping Mistral for Mixtral (`c318f28`,
  [21](21-history-and-releases.md) §2.3), and its one real enrichment moves
  (preselect + ordering) work by changing *what the model sees* — while the
  deck itself concludes "adding context often helps" (slide 31). That is
  calxgloss's 5-tier ladder and evidence-bundle doctrine confirmed from the
  opposite direction.
- **"No fine-tuned model ever" validates retrieval/context-engineering as a
  defensible bet.** Verified across git history, HF, arXiv, Zenodo, and the
  author's own surfaces: fine-tuning was listed and *never done*
  ([31](31-ml-model-and-training.md) verdict + §2–3). The strongest public
  artifact of "LLM-for-RE with local models" as actually practiced is a
  generalist model plus static-analysis context — which is exactly calxgloss's
  architecture minus the verification.

## What ReverserAI would have to become to reach calxgloss's effect

Honest list — it is re-inventing calxgloss, minus the BN view:

- **A verification oracle.** Names have no mechanical oracle; to produce
  calxgloss-grade claims it must retarget from labels to translation and grow
  compile + behavioral baselines + trace containment (or an emulator thereof)
  — i.e., `calxgloss-testgen`/`calxgloss-verify` from nothing ([10](10-calxgloss-baseline.md)).
- **A state substrate deeper than Ctrl+Z.** Per-attempt branches, persisted
  verdicts, never-deleted failure records, per-decision provenance (model,
  context, justification) — BN's bndb undo + Log window carries none of it
  ([32](32-binary-ninja-plugin.md) §10).
- **Batch whole-binary evidence.** One-shot HLIL plus xref-set membership is
  not an evidence layer; 15 registry scans, coverage stamps, and tiered
  bundles are ([10](10-calxgloss-baseline.md) §Pipeline anatomy).
- **A review workflow at unit granularity.** Accept/send-back verdicts,
  retry-with-failure-context loops, token/fault telemetry ([10](10-calxgloss-baseline.md)
  §Surface & state) — versus one indeterminate BN progress bar and a logger
  ([32](32-binary-ninja-plugin.md) §3, §12).

The symmetric question answers itself: **for calxgloss to produce
ReverserAI's effect it would need an interactive address-level UI and rename
authority — and it has deliberately legislated both away**: identity is
binary-side verbatim, there is "no rename write-back path in any crate", human
rename authority is "deliberately excluded", and even the design doc's
illustrative `sub_00401234 (renamed: DrawSprite)` header assumes renaming
happened *upstream in the analysis tool*, never in the harness
([10](10-calxgloss-baseline.md) §Naming & typing #1, #4, #7). Neither project
can become the other without un-writing its core doctrine.

## Verdict

ReverserAI is the existence proof and the counterexample in one project: it
proved local GGUF llama.cpp naming-assist is a UX people adopt (1,168 stars,
marketplace, ports) and simultaneously proved, by shipping its flagship
feature broken for 23 months under zero tests, that assistive output without
verification or evaluation never becomes an engineering claim. calxgloss is
the inverse bet — automate the whole pipeline, but only inside a mechanical
gate (compile + Wine baselines + trace containment) with humans adjudicating
verdicts, and naming kept strictly as scored, prompt-fed, never-applied
evidence per ADR-0020/0021. The honest steal list is nearly empty — the
propagation principle it already implements as type write-back, triage triads
it already runs as scan rows, a pinned-GGUF pattern worth copying only for
P33's eval, and a free negative-evidence package for P42/P33 — because
ReverserAI's real contribution to this dossier is confirmation: bottom-up
ordering, context engineering over fine-tuning, and local-model economics are
independently converged-on, load-bearing choices, and the absence of any
verification layer in the ecosystem's best-known assistive tool is exactly
the gap calxgloss's whole design exists to close.

## Sources

Dossier files (this directory):
- [00-scope-and-method.md](00-scope-and-method.md) — comparison scope, clone
  provenance (HEAD `1d572da`), repo meta verified 2026-10-31.
- [10-calxgloss-baseline.md](10-calxgloss-baseline.md) — calxgloss anchor at
  HEAD `40fbf91f1815c1eb0207d05c3c2d7a58cb3bc7f0` (2026-10-31), incl. ADRs
  0002/0003/0004/0006/0009/0010/0012/0018/0020/0021/0023/0024/0039-0041/
  0048-0057, roadmap P23-P52, and the crate `path:line` spans cited above.
- [20-reverser-ai-inventory.md](20-reverser-ai-inventory.md) — file/LOC
  inventory, packaging, CI, examples, deps, project meta, code-layer notes.
- [21-history-and-releases.md](21-history-and-releases.md) — 25-commit
  history, tag archaeology, inverted-guard timeline, model-per-release table,
  release cadence and maintenance status.
- [31-ml-model-and-training.md](31-ml-model-and-training.md) — research
  lineage, verified absences (paper, HF, fine-tunes), effectiveness evidence
  (slides 31/40/44/53), NDSS 2026 lineage.
- [32-binary-ninja-plugin.md](32-binary-ninja-plugin.md) — commands, settings,
  HLIL layer, traversal, filters, rename application, failure handling.
- [33-ai-layer-and-prompts.md](33-ai-layer-and-prompts.md) — generation
  config, prompt archaeology, output filtering, agent/model registry, token
  budget, reconstructed final prompt.

Newly checked for this chapter (2026-10-31):
- calxgloss `LICENSE` (MIT, "Copyright (c) 2025 calxgloss contributors") and
  `Cargo.toml` (`license = "MIT"`); calxgloss HEAD still `40fbf91f…` (matches
  the [10](10-calxgloss-baseline.md) anchor).
- `/tmp/opencode/reverser_ai` @ `1d572da` spot-checks of load-bearing cites:
  corrected HLIL guard at `reverser_ai/binary_ninja/__init__.py:141-146`,
  `n_context = 4000` at `reverser_ai/gpt/function_name_gpt.py:27`,
  `nx.dfs_postorder_nodes` at `reverser_ai/binary_ninja/utils.py:58`.
- `crates/integrations/calxgloss-decomp/src/lib.rs:1-14` — the
  `TypeWriteSource` "setting prototypes and variable types" write-side seam
  the [10](10-calxgloss-baseline.md) cite (`calxgloss-decomp/src/lib.rs:13-14`)
  resolves to.
