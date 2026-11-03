# LLM_Decompiler ↔ calxgloss — the full comparison

> Part of the [LLM_Decompiler overview](README.md). Every LLM_Decompiler claim
> below cites this dossier's files ([20](20-llm-decompiler-inventory.md)–[34](34-results-effectiveness-and-hygiene.md),
> clone-relative `path:line` at `c242671`); every calxgloss claim cites the
> fixed baseline ([10](10-calxgloss-baseline.md), verified at HEAD `40fbf91f`,
> 2026-10-31).

**Bottom line up front: LLM_Decompiler is calxgloss's null hypothesis — the
same pipeline with every load-bearing part surgically removed, and 27 months
of results for having removed them.** Both projects start identically:
Ghidra-headless batch-decompiles a binary into per-function C, then feeds that
C to an LLM ([20](20-llm-decompiler-inventory.md), [10](10-calxgloss-baseline.md)).
From there, LLM_Decompiler keeps nothing calxgloss considers doctrine: the
evidence substrate is eight hardcoded prompt strings, the context model is one
whole-file `system`-role message, the queue order is Ghidra's address order,
model-invented renames are pasted back verbatim into `.c` files, and the
verification oracle is **zero** — nothing the tool writes is ever re-read by
the tool ([31](31-ghidra-harness-and-core-pipeline.md), [32](32-large-codebase-reconstruction.md)).
The measured outcome of that null configuration: 12 code-as-written breakages
in 1,390 lines ([20](20-llm-decompiler-inventory.md) §11), four of eight model
endpoints dead as of 2026-10-23
([34](34-results-effectiveness-and-hygiene.md) §3), an API key committed twice
and surviving its own deletion ([21](21-history-and-releases.md) §5), and
3 stars, zero issues, zero PRs after 69 days of life frozen 27 months ago —
the one genuine external citation calls it "wrong output target… tactical
fallback on top of Ghidra C, not as a primary pipeline"
([34](34-results-effectiveness-and-hygiene.md)). Against the LLM4Decompile
dossier's verdict — *measurement without provenance rots* — this dossier adds
the other control arm: **assertion without measurement rots faster and more
visibly**. calxgloss, which currently has no aggregate score at all (P33 open),
stands between the two controls with per-attempt receipts that are at least
real — and this repo is the quantified cost of every gate calxgloss has.

## Capability matrix

Winner in **bold**. "—" = absent.

| Capability domain | LLM_Decompiler | calxgloss | Verdict | Ch. |
|---|---|---|---|---|
| Mission & artifact | A personal **Ghidra-headless + GPT prompt pipeline**: 30 tracked files, 1,390 lines that decompile → filter → enhance → detect vulnerabilities in stripped binaries, plus a late CTF pivot; the deliverable is a shell-script chain ([20](20-llm-decompiler-inventory.md) §1–§2) | A **verified whole-binary rewrite factory**: 34 crates, ≈279k LOC driving a local LLM over Windows PE units in a call-graph queue, gated by compile + Wine baselines + trace containment; the deliverable is verdict-bearing Rust rewrites ([10](10-calxgloss-baseline.md) §Pipeline anatomy) | split — not competitors: LLM_Decompiler is what the task looks like with zero infrastructure; calxgloss is the same task with the infrastructure as the product | [20](20-llm-decompiler-inventory.md), [10](10-calxgloss-baseline.md) |
| Decompilation front end | **Ghidra headless**, pinned `GHIDRA_PATH=./ghidra_11.0.1_PUBLIC` (`Decompiler/gd_decomp.sh:5`); a 39-line Java postScript dumps every function, marker-wrapped (`decompiler.py:21-22`) or as JSON (`large_decompiler.py:15-19`); two major Ghidra lines past the pin, the pinned line EOL, and the README's download instruction never matched a real asset name ([34](34-results-effectiveness-and-hygiene.md) §3) | The same idea refined: Ghidra-derived pseudo-code per `{binary}/{function}` unit, then 15 registry scans decorate each unit with typed evidence before any prompt ([10](10-calxgloss-baseline.md) §Decompile substrate) | split — **the one genuine commonality**, and it ends exactly at the dump: LLM_Decompiler stops at raw pseudo-C, calxgloss treats the dump as the weakest evidence tier | [31](31-ghidra-harness-and-core-pipeline.md), [10](10-calxgloss-baseline.md) |
| Where knowledge lives | In **eight hardcoded prompt strings** inside the `.py` drivers — no database, no xref, no call graph, no prior scans; task knowledge is prose edited by hand ([20](20-llm-decompiler-inventory.md) §4) | In readable, versioned artifacts: 15 scan rows, PAL/pattern/libmatch DBs, 57 ADRs; prompts are generated from evidence, and the model stays generic (ADR-0051) ([10](10-calxgloss-baseline.md) §Pipeline anatomy) | **calxgloss, by construction** — LLM_Decompiler is the control case: the same author-intent knowledge, left as string literals in eight files with no substrate to correct or extend | [31](31-ghidra-harness-and-core-pipeline.md), [10](10-calxgloss-baseline.md) |
| Context into the model | **The whole input file, one shot**, embedded in a single `system`-role message — no chunking, no context arithmetic, no token budget anywhere in 1,390 lines ([10](10-calxgloss-baseline.md) §Anchors; [31](31-ghidra-harness-and-core-pipeline.md) §6); on the JSON path the *entire* accumulated name map is re-embedded in every call (`large_code_base_reconstruction.py:29-30`), so total prompt volume is Θ(N²) in function count ([32](32-large-codebase-reconstruction.md)) | 5-tier context ladder with `unavailable`-family pruning and named unknown records (ADR-0055/0056); cost metering and pre-run estimates are open P50 ([10](10-calxgloss-baseline.md) §Model layer) | **calxgloss** — unbounded single-blob prompting is not a simpler design, it is an unbudgeted one; LLM_Decompiler demonstrates the ceiling (silent truncation risk, quadratic name-map relay) that tiering + P50 exist to prevent | [32](32-large-codebase-reconstruction.md), [10](10-calxgloss-baseline.md) |
| Inter-procedural ordering | **Ghidra enumeration order** (listing/address order) — callees may arrive after callers; the only cross-function memory is the name-map prose relayed forward (`large_code_base_reconstruction.py:84`, loop over JSON order) ([31](31-ghidra-harness-and-core-pipeline.md), [32](32-large-codebase-reconstruction.md)) | Queue ordered **call-graph-topologically, callees before callers**; merges gated by dependency order ([10](10-calxgloss-baseline.md) §Anchors) | **calxgloss** — same unit granularity, structurally absent ordering; the name map shows the author *needed* cross-function identity state and solved it with a string instead of a graph | [32](32-large-codebase-reconstruction.md), [10](10-calxgloss-baseline.md) |
| Naming doctrine | Instructs the model to **rename every function and variable**, pastes the renamed code verbatim back into `.c` files (`llm_r.py:29-30,47-48`), and relays renames to later functions by pasting a name-map JSON string into the next prompt (`large_code_base_reconstruction.py:29-30,33`) — no symbol table, no consistency check, nothing re-reading the result ([31](31-ghidra-harness-and-core-pipeline.md), [32](32-large-codebase-reconstruction.md)) | Never applies names, by doctrine: names are scored, admission-stamped evidence; write-back is **types-only** (ADR-0020/0021); P51 scores name claims by independent evidence kinds ([10](10-calxgloss-baseline.md) §Naming & typing) | split by doctrine, but asymmetric in consequence — both invent names; only calxgloss has an oracle that would notice if an invented name broke semantics. LLM_Decompiler's renames are claims that pass straight into the next stage as if they were facts | [32](32-large-codebase-reconstruction.md), [10](10-calxgloss-baseline.md) |
| Verification oracle | **Zero.** Nothing written is ever re-read: no compile, no run, no test, no diff anywhere in the repo (`llm_d.py:61-62`, `llm_r.py:47-48`); the only failure path is `except` → silently return the original body (`large_code_base_reconstruction.py:68-70`); "does it work?" is a human reading an output file ([10](10-calxgloss-baseline.md) §Anchors; [33](33-security-ctf-and-datasets.md) §8) | The oracle *is* the product: `cargo check` + behavioral tests vs Wine-captured baselines + ordered API-trace containment (ADR-0057), every attempt; missing evidence reads *unknown*, never passing (ADR-0053) ([10](10-calxgloss-baseline.md) §Verification & evidence) | **calxgloss — this is the null-hypothesis row**: every calxgloss gate, minus every gate, one repo, 27 months of observable consequences | [31](31-ghidra-harness-and-core-pipeline.md), [10](10-calxgloss-baseline.md) |
| Retry, state & git discipline | One-shot and stateless: no retries, no attempt records, no unknown ledger, no review UI; the 26-commit linear history is the only state, and `results/` held nothing but its own naming-convention README at every commit ([20](20-llm-decompiler-inventory.md) §2, [21](21-history-and-releases.md) §7) | git attempt branches `re/{binary}/{function}v{N}` kept forever; failure-informed retries (ADR-0051); persisted accept/send-back verdicts; named `UnknownRecord`s (ADR-0056) ([10](10-calxgloss-baseline.md) §Surface & state) | **calxgloss, non-negotiable** — a pipeline that fails silently (`:68-70`) and keeps no record has no failure analysis to do at all; LLM_Decompiler cannot even answer "how often did this break?" | [32](32-large-codebase-reconstruction.md), [10](10-calxgloss-baseline.md) |
| Model layer | **Eight hosted-model literals pinned in code** (`gpt-4-turbo` ×3, `gpt-4o` ×4, `gpt-3.5-turbo` ×1; [20](20-llm-decompiler-inventory.md) §4), never changed at any commit; **four of the eight are dead endpoints as of 2026-10-23** and the rest have a published shutdown date (2027-01-14) ([34](34-results-effectiveness-and-hygiene.md) §3); no sampling params, no cost tracking, one env var, one API key committed twice ([21](21-history-and-releases.md) §5) | Local endpoint, **no defaults**, pure config, fail-loud on unset values (`README.md:130-134` per baseline); per-attempt token/strategy telemetry (`re/analysis/token_usage.json`); P50 budgets; P51 ignores model self-assessment ([10](10-calxgloss-baseline.md) §Model layer) | **calxgloss** — the control case ran the experiment calxgloss refuses to run: pin a hosted vendor and wait. The literals survived 26 commits; the endpoints did not survive the market | [34](34-results-effectiveness-and-hygiene.md), [10](10-calxgloss-baseline.md) |
| Scale handling | Two paths, both unbounded: whole-file prompts with **no truncation logic**, and a per-function JSON loop whose name-map relay grows prompt payloads quadratically; the file-name contract breaks mid-relay on inputs like `a.out` ([20](20-llm-decompiler-inventory.md) §11 item 4); the whole-binary question (does the rewritten set still link and behave?) is never asked ([32](32-large-codebase-reconstruction.md)) | Per-unit queue with tiered, budgeted context; whole-binary equivalence is an explicit open question (P26 restitch), not an unasked one ([10](10-calxgloss-baseline.md) §Pipeline anatomy) | **calxgloss** — both face Θ(batch); only calxgloss counts the batch, budgets it, and admits the whole-binary verdict is unfinished business | [32](32-large-codebase-reconstruction.md), [10](10-calxgloss-baseline.md) |
| Evaluation substrate | The Juliet *gesture*: corpus-prep scripts that **blind labels** — `good()`/`bad()` banners obfuscated in processed copies (`dataset_scripts/process_juliet_suite.py:25-30`) and paired bad/good binary sampling per CWE (`dataset_scripts/select_from_cwe.py:26-42`) — but no corpus build step, no scorer, no control arm, and the README's "across all evaluated metrics" backed by zero artifact ([33](33-security-ctf-and-datasets.md) §7–§8); "the scorer was a human at a desk" | **None** (open P33): one fixture DLL, asserted by engine harnesses; no scored eval, no corpus; per-unit verification data exists but has never been aggregated ([10](10-calxgloss-baseline.md) §Current state) | split — both at zero, the only domain where calxgloss cannot simply win; LLM_Decompiler at least drafted the corpus-prep substrate, and its corpus-prep scripts sketch the corpus, the paired-case control, and a scorer hook that P33 must turn into the four-leg protocol | [33](33-security-ctf-and-datasets.md), [10](10-calxgloss-baseline.md) |
| Operational hygiene | **12 verified breakages in 1,390 lines** at HEAD: zero exec bits while README says `./script`, README setup pointing at the file HEAD deleted, dead `rm` after `mv`, `~/Desktop/sp_new` burned into two shipped scripts, undeclared deps, a CTF pipeline broken on arrival for 16 hours ([20](20-llm-decompiler-inventory.md) §11); no CI ever, no deps manifest ever, no tags, no releases ([21](21-history-and-releases.md) §7) | No CI **today** (open P42 — the roadmap's own words: "calxgloss has no CI at all"); but build/clippy/workspace tests exist locally, HEAD hygiene verified per-chapter, and secrets never enter the repo by design ([10](10-calxgloss-baseline.md) §Current state) | **calxgloss, with the honest caveat**: LLM_Decompiler is what decay-without-mechanical-checks looks like at 1,390 lines; calxgloss at 475 `.rs` files without P42 is the same accident waiting at 200× the mass | [20](20-llm-decompiler-inventory.md) §11, [10](10-calxgloss-baseline.md) |
| License & distribution | **No license at all** (`license → null`, [21](21-history-and-releases.md) §7) — the code cannot legally be reused, forked, or folded into any product; 3★, 3 verbatim post-freeze forks, 2 watchers, zero issues, zero PRs in 27 months ([34](34-results-effectiveness-and-hygiene.md)) | MIT throughout, no weights, no inherited clauses ([10](10-calxgloss-baseline.md) §Current state) | **calxgloss** — unlicensed is a distribution kill-switch before a single user reads the README; the LLM4Decompile dossier had a license *tangle*, this one has no license at all | [21](21-history-and-releases.md) §7, [10](10-calxgloss-baseline.md) |
| Measured effect | **Asserted, never measured**: "outperformed traditional methods across all evaluated metrics" (`README.md:21-22`) entered the README whole in `cd00540` (+33/−1) and was never backed by one artifact in any commit ([34](34-results-effectiveness-and-hygiene.md) §2, [21](21-history-and-releases.md) §6); 27-month reception: one survey citation, and it recommends *against* using the tool ([34](34-results-effectiveness-and-hygiene.md)) | No aggregate score and no claim to one: per-unit proof exists by construction (ADR-0057 on every merged unit), aggregate measurement is an open roadmap item (P33), not a published boast ([10](10-calxgloss-baseline.md) §Current state) | **calxgloss, by honesty posture** — the control arm: an unsupportable superlative bought 3 stars and a rejection; calxgloss's honest "not yet measured" is the only stance that compounds | [34](34-results-effectiveness-and-hygiene.md), [10](10-calxgloss-baseline.md) |

## Effect, measured vs asserted

**LLM_Decompiler asserts one superlative and built none of the four legs that
would support it.** The claim chain, per
([34](34-results-effectiveness-and-hygiene.md) §2): the README's
"Enhanced decompiled binary analysis using LLMs outperformed traditional
methods across all evaluated metrics" (`README.md:21-22`) was born whole in
one commit (`cd00540`, 2024-05-09 19:30, `+33/−1`), pickaxes prove no
measurement vocabulary ever appeared in any code blob, and the experiment the
README itself prescribes — Juliet-suite benchmarking against a static-analyzer
control — has exactly one leg shipped:

- **corpus prep** — present (`dataset_scripts/process_juliet_suite.py`,
  58 lines, [33](33-security-ctf-and-datasets.md) §7);
- **corpus build** — absent: the processed tree cannot be built as committed
  (ch.33 §7);
- **scorer** — absent from all 26 commits; "the scorer was a human at a
  desk" ([33](33-security-ctf-and-datasets.md) §8);
- **results** — `results/` held only its own naming-convention README at every
  commit, forever ([20](20-llm-decompiler-inventory.md) §2).

The claim is not underdetermined — it is unbacked at every level the repo's own
documentation specifies ([34](34-results-effectiveness-and-hygiene.md) §2).

**The rest of the effect ledger is negative space.** Time-currency: four of
eight model call sites hit API shutdowns on 2026-10-23, eight days before this
dossier's audit date, and the surviving four (the `gpt-4o` family) are
scheduled for 2027-01-14; there is no version of "run the pipeline today" that
does not start by editing model strings
([34](34-results-effectiveness-and-hygiene.md) §3). The Ghidra pin sits two
major lines back on an EOL line, and the README's download instruction never
matched any asset name, even for the version it pins
(ch.34 §3). Hygiene: 12 verified breakages at HEAD
([20](20-llm-decompiler-inventory.md) §11), one legacy-format OpenAI key
committed twice, surviving its own deletion, with zero rotation evidence
([21](21-history-and-releases.md) §5). Reception: 3★/3 forks/2 watchers, zero
issues, zero PRs, zero code references; the single genuine external citation
(modforge's prior-art survey) lists it among tools with the "wrong output
target" and recommends it only as "a tactical fallback on top of Ghidra C, not
as a primary pipeline" — the repo's one honest external assessment was
performed by a 1-star project that rejected it
([34](34-results-effectiveness-and-hygiene.md)).

**calxgloss has per-unit receipts but no aggregate score** — the same posture
the LLM4Decompile dossier recorded, now measured against a *lower* control:
every merged unit compiles, passes Wine-captured behavioral tests, and
contains the ordered API trace (ADR-0057), but there is no scored eval (P33
open), one fixture DLL instead of a corpus, and no CI to hold the line (P42
open) ([10](10-calxgloss-baseline.md) §Current state). The three-dossier
triangle is now complete: LLM4Decompile *measured and still rotted*
(same-checkpoint contradictions, `content-fix` forensics); ReverserAI shipped
a flagship broken for 23 months; LLM_Decompiler **asserted without measuring
anything and was answered in kind** — 27 months, one rejection citation. The
lesson ordering it permits: no-measurement < bad-measurement < provenance-
typed receipts without aggregation < provenance-typed receipts plus P33
scores.

## Where the ideas converge

Genuine convergence is thinner than in any previous dossier — which is itself
the point — but three real handshakes exist:

- **The same front end, for the same reason.** Both pipelines open with
  Ghidra-headless dumping per-function C for an LLM ([31](31-ghidra-harness-and-core-pipeline.md),
  [10](10-calxgloss-baseline.md)). LLM_Decompiler's marker-dump
  (`decompiler.py:21-22`) and calxgloss's per-unit pseudo-code are the same
  substrate; the dossiers' disagreement is entirely about everything after the
  dump. For calxgloss's own positioning, this is the strongest data point that
  Ghidra-dump + LLM is the ecosystem consensus *starting point* — and this
  repo is the counterexample for what happens with no next stage.
- **Provenance-aware prompting, intuited in prose and never mechanized.**
  `llm_d.py:32` tells the analyzer that the input "may contain artifacts
  introduced by the enhancements from another language model" and to ignore
  vulnerabilities arising from them; `llm_d.py:34-36` demands certainty-grade
  findings only, explicitly legitimizes the null answer ("situations where you
  are given the code of a bug after it was fixed"), and prefers false
  negatives to false positives — i.e. *mark unresolved when evidence is
  insufficient*, in prose. That is calxgloss's typed-verdict + honest-unknown
  posture (ADR-0053/0056) discovered independently and left as an instruction
  nobody enforces ([10](10-calxgloss-baseline.md) §Verification & evidence).
  Same insight; the delta is that calxgloss *gates on it*.
- **The paired-corpus, blinded-label instinct for Juliet.** Burying
  `good()`/`bad()` markers in processed corpus copies
  (`dataset_scripts/process_juliet_suite.py:25-30`) and drawing paired bad/good
  samples per CWE (`dataset_scripts/select_from_cwe.py:26-42`) is an early,
  unexecuted version of calxgloss's P33 game: ground truth deliberately hidden
  from anyone scoring the run ([33](33-security-ctf-and-datasets.md) §7). The
  repo that never shipped a scorer still drafted the anti-gaming measure a
  scorer needs.

## What calxgloss can honestly steal

Ranked, argued — and honestly short: an unlicensed, 1,390-line, zero-oracle
pipeline has almost nothing to give a gated factory. What is stealable is
*substrate fragments and negative specs*, and legal reuse is off the table
entirely — the repo has no license ([21](21-history-and-releases.md) §7), so
everything below is stolen as *shape and lesson*, never as code:

1. **The Juliet bad/good paired corpus + label-blinding as P33 substrate
   shape.** Juliet itself is public (NIST); the *curation pattern* is the
   steal: per-CWE bad/good binary pairs (`select_from_cwe.py:26-42`) and
   label-obfuscating preprocessing so neither model nor scorer can cheat on
   banner names (`process_juliet_suite.py:25-30`)
   ([33](33-security-ctf-and-datasets.md) §7). P33's corpus format should carry
   the pair axis (bad/good per weakness class) and its preprocessing should
   blind identifiers that leak the label. The companion lesson is the more
   valuable one: this repo shipped the prep script and none of the other three
   legs (build, scorer, results), which is exactly how "across all evaluated
   metrics" became folklore — **P33 must ship corpus + build step + scorer as
   one unit, in-repo** ([33](33-security-ctf-and-datasets.md) §Steal: "the
   scorer is the experiment").
2. **modforge's survey line as market-positioning intel.** The one genuine
   external citation reads the whole genre (c0ral1ne, Lami99, HKalbasi) as
   "All emit C. Closest architectural match but wrong output target. Useful as
   a tactical fallback on top of Ghidra C, not as a primary pipeline"
   ([34](34-results-effectiveness-and-hygiene.md)). The survey was written
   2026-05-14 — recent, independent, and it diagnoses the exact niche gap:
   nobody ships LLM decompilation with a *different output target* (calxgloss:
   Rust, whole-binary, gated) as a primary pipeline. When calxgloss writes its
   own prior-art section (post-P33), this sentence is the map of what the
   ecosystem already tried and rejected — with three named case studies to
   cite (this dossier, LLM4Decompile's, c0ral1ne's).
3. **A battery of P42 CI checks, each reverse-engineered from one verified
   defect** ([20](20-llm-decompiler-inventory.md) §11): (a) exec-bit sweep —
   every documented `./script` command must have mode 755 (LLM_Decompiler:
   0/30 files executable while README runs five of them); (b) README-command
   smoke test — every command line in docs must execute at least to its usage
   output (the setup guide points at a file the HEAD commit deleted); (c)
   name-contract algebra — the file name a producer writes must equal the name
   the consumer opens (`a.out` → `a_decompiled.c` mismatch is the worked
   example); (d) repo-wide grep gate for absolute personal paths —
   `~/Desktop/sp_new` in two shipped scripts is the fingerprint class;
   (e) dead-constant check — marker strings declared and never emitted
   (`large_code_base_reconstruction.py:8-9`); (f) history pickaxe for secret
   shapes in CI (the key that was committed twice and outlived its own
   deletion, [21](21-history-and-releases.md) §5, is the existence proof).
   Calxgloss has no CI at all today (P42), so each check has a named specimen
   and a named fix.

**Explicitly not stolen**:

- **Whole-file single-shot prompting** — embedding the entire input in one
  `system` message with no chunking or budget is the pathology P50 exists to
  prevent, and the Θ(N²) name-map relay (`large_code_base_reconstruction.py:29-30`)
  shows the quadratic cost of the same instinct at scale
  ([32](32-large-codebase-reconstruction.md)).
- **Paste-back renames and the name-map relay** — model-invented identifiers
  written verbatim into source are the exact laundering ADR-0020/0021 forbid;
  LLM_Decompiler can get away with it only because its consumer is a human
  eyeball, which is precisely the review channel calxgloss's gates replace
  ([31](31-ghidra-harness-and-core-pipeline.md)).
- **Silent `except` fallbacks** — returning the original body on API failure
  (`large_code_base_reconstruction.py:68-70`) is the anti-pattern of calxgloss's
  fail-loud posture; it converts failures into invisible successes
  ([32](32-large-codebase-reconstruction.md)).
- **Hosted-model pinning and hygiene folklore** — eight literals in code,
  direct-key auth, one env var, a key committed twice: everything in
  [21](21-history-and-releases.md) §5 / [34](34-results-effectiveness-and-hygiene.md)
  §3 is a lesson, reusable only as negative spec.

## What LLM_Decompiler confirms about calxgloss's choices

- **Every gate has its control arm now priced.** The null configuration — same
  Ghidra dump, same per-function granularity, same cheap-iteration economics,
  zero oracle — produces a 12-item breakage ledger, a pipeline that died with
  its vendor's model names, and zero adoption
  ([20](20-llm-decompiler-inventory.md) §11, [34](34-results-effectiveness-and-hygiene.md) §3,
  [34](34-results-effectiveness-and-hygiene.md)). calxgloss's ADR-0057 gate
  wall, attempt branches, and unknown ledgers (ADR-0051/0056) are the named
  deltas between the two outcomes. This is the strongest "why the gates are
  load-bearing" evidence available: it is not hypothetical, it is one repo and
  27 months of follow-up.
- **The local-model bet is confirmed by the inverse experiment.** Eight pinned
  hosted literals survived every commit of the repo's life — and four of the
  endpoints are dead as of 2026-10-23, the rest scheduled
  ([34](34-results-effectiveness-and-hygiene.md) §3). calxgloss's inversion
  (endpoint in config, no defaults, fail-loud when unset — baseline §Model
  layer) turns vendor churn into an operator config edit. LLM_Decompiler paid
  the opposite: its model strings were *code*, so fixing them requires
  forking.
- **Config-vs-code doctrine has now been run as a controlled test.** The
  literals never changed across 26 commits while the model layer's ground
  truth moved twice ([34](34-results-effectiveness-and-hygiene.md) §3); the
  baseline's observation that the eight literals "never change at any commit"
  is, read next to the shutdown ledger, the cost column of the choice calxgloss
  made with `CALXGLOSS_LLM_*` config precedence and ADR-0051's
  model-agnostic attempt seam ([10](10-calxgloss-baseline.md) §Model layer).
- **Adoption is substrate, not cleverness.** Three stars and one rejection
  citation after 27 months is not a quality signal — it is a distribution
  channel signal: no license, no artifacts, no docs that execute, no scores
  ([21](21-history-and-releases.md) §7, [34](34-results-effectiveness-and-hygiene.md)).
  That prices calxgloss's currently-open P33/P42 pair as adoption
  prerequisites, not polish, and its MIT license as an already-won advantage
  over two of the three surveyed projects (this one has none at all).
- **Honesty compounds; superlatives don't.** `README.md:21-22` bought nothing;
  the survey that even mentioned the repo recommended against it
  ([34](34-results-effectiveness-and-hygiene.md)). calxgloss's
  unknown-when-missing semantics (ADR-0053) and its current posture — no
  aggregate claim, receipts per unit — is the stance this control case
  empirically supports.

## What LLM_Decompiler would have to become to reach calxgloss's effect

Uncomfortable and short: **adding the parts that produce calxgloss's effect
would turn LLM_Decompiler into calxgloss's architecture.** There is no
intermediate point, which is exactly why the comparison works as a control.

- **An oracle that re-reads the tool's own output.** A compile step on the
  enhanced `.c` files, a run/test layer, a diff-vs-input gate — i.e. grow
  `calxgloss-verify`/`calxgloss-testgen` around the dump. The Ghidra pin, the
  script chain, and the prompts would all survive; the *trust* in their output
  begins only when something downstream re-reads it ([31](31-ghidra-harness-and-core-pipeline.md)).
- **An evidence substrate under the prompts.** xrefs, a symbol table,
  call-graph data, and per-unit scans feeding generated prompts — replacing the
  eight hand-edited strings and the prose name map with queryable artifacts.
  The moment the name map becomes a graph, call-graph-topological ordering
  (callees first) is forced by the data structure — the ordering calxgloss
  gets for free ([32](32-large-codebase-reconstruction.md)).
- **A state substrate.** Attempt records with model/context/token provenance,
  kept failure branches, persisted verdicts, an unknown ledger — everything
  the silent `except` and the stateless one-shot design currently preclude.
  Without it there is no failure analysis, no cost model (P50), and no
  evaluation data to aggregate.
- **Measurement, honestly wired.** The Juliet legs it started to ship —
  blinded paired corpus, build step, in-repo scorer, results directory with
  real artifacts — plus a control arm (any static analyzer, run mechanically).
  That is P33's shape, and this repo is P33's *minimal failing example*:
  three of four legs missing, one commit from a folk legend.
- **A review surface and a license.** Verdict-bearing review (accept/send-back
  with context) is what "human reads the output file" becomes once the human's
  decisions are recorded; and the license question has no clever answer —
  MIT-or-equivalent or the work stays unadoptable
  ([21](21-history-and-releases.md) §7).

The symmetric question answers faster: for calxgloss to produce LLM_Decompiler's
*effect* it would only have to delete its gates — a batch pipeline that asks an
LLM to prettify Ghidra output and never verifies it is ~1,400 lines of shell
and Python, trivially buildable, and explicitly legislated away by the
oracle-wall doctrine. The fact that calxgloss *could* ship LLM_Decompiler as a
side project and *chooses not to even as an exit hatch* is the cleanest single
statement of the difference between the projects: LLM_Decompiler is not a
simpler calxgloss; it is calxgloss minus the product.

## Verdict

LLM_Decompiler is the ecosystem's null hypothesis, run in public and completed:
the same Ghidra-headless + LLM pipeline calxgloss starts from, stripped of
oracle, evidence substrate, state, measurement, and license, followed through
27 months to its terminal state — 12 verified breakages in 1,390 lines, four
of eight model endpoints dead and the rest dying, one OpenAI key committed
twice and outliving its own deletion, one README superlative born in a single
commit and backed by zero artifacts in every commit, and a reception of 3
stars, zero issues, zero PRs, and a single external citation that classifies
the whole genre as "wrong output target… tactical fallback… not as a primary
pipeline." Against the LLM4Decompile dossier's finding — measurement without
provenance rots — this dossier contributes the lower control arm: assertion
without measurement rots faster, and a project can be *legally* unadoptable
before it is technically wrong. calxgloss sits above both controls with
per-attempt receipts (ADR-0057) and honest nulls (ADR-0053/0056) but still
without aggregate scores (P33 open) or CI (P42 open) — and this dossier's
value to it is therefore pricing, not gifts: the steal list is tiny (the
Juliet paired-corpus/blinding shape for P33's format, modforge's survey
sentence as positioning intel, and a six-item P42 CI battery each named by
one verified defect), while the confirmations are large — the local-model and
config-vs-code bets won by inverse experiment, the gates' necessity shown by
their absence, and the honest-nil posture empirically outearning the
unsupportable superlative. What LLM_Decompiler would have to become to reach
calxgloss's effect is, precisely, calxgloss — which is what a control case is
for.

## Sources

Dossier files (this directory):

- [00-scope-and-method.md](00-scope-and-method.md) — scope, method, pinned
  HEADs (`c242671` / `40fbf91f`), verified repo metadata.
- [10-calxgloss-baseline.md](10-calxgloss-baseline.md) — calxgloss anchor at
  HEAD `40fbf91f` (2026-10-31), incl. the "Anchors for the LLM_Decompiler
  comparison" bullets this chapter expands, ADRs 0020/0021/0051–0057, roadmap
  P-numbers cited per status at that HEAD.
- [20-llm-decompiler-inventory.md](20-llm-decompiler-inventory.md) — §1–§4
  surface + model/prompt ledger, §9 negative findings, §11 12-item staleness
  ledger.
- [21-history-and-releases.md](21-history-and-releases.md) — §2 chronology,
  §5 key forensics, §6 README-as-release, §7 API metadata battery (3★/3 forks/
  0 tags/0 releases/license null).
- [31-ghidra-harness-and-core-pipeline.md](31-ghidra-harness-and-core-pipeline.md)
  — Ghidra harness anatomy, core single-shot pipeline, per-stage file relay.
- [32-large-codebase-reconstruction.md](32-large-codebase-reconstruction.md)
  — JSON twin path, name-map relay mechanics, silent-fallback forensics.
- [33-security-ctf-and-datasets.md](33-security-ctf-and-datasets.md) — §7
  Juliet corpus forensics, §8 scorer absence ("the scorer was a human at a
  desk"), §Steal "the scorer is the experiment".
- [34-results-effectiveness-and-hygiene.md](34-results-effectiveness-and-hygiene.md)
  — §2 claims-block forensics (`cd00540`), §3 time-currency audit (model
  shutdowns, Ghidra pin, zip-name finding), reception/modforge survey citation.
- [../LLM4Decompile/40-comparison.md](../LLM4Decompile/40-comparison.md) —
  the measurement-without-provenance control arm this dossier pairs against.

Newly checked for this chapter (2026-10-31):

- Full dossier citation sweep re-run at assembly: every backticked
  `path:line` token in [00](00-scope-and-method.md)–[34](34-results-effectiveness-and-hygiene.md)
  + this chapter resolved mechanically against the clone at `c242671`
  (worktree == HEAD, clean) and calxgloss at `40fbf91f`: **255 tokens
  resolved in range, 0 out-of-range**; the single unresolved path
  (`falcon-printer/docs/survey.md:60` — a third-party `abix-/modforge` repo
  path, appearing in ch.34 and here) resolves via the raw fetch recorded in
  ch.34 §"reception". Bare `:NN` continuations and `<sha>` history references
  were checked manually against the clone (spot-list below).
- Assembly corrections applied in the same pass: ch.21 §6's README-burst
  table/paragraph now attributes the claims block to `cd00540` and the Setup
  Guide/usage skeleton to `9c64ffc` (matching ch.34 §2's forensics), the §3
  "4-commit" burst count fixed to 5, and ch.10 anchors' name-map cite retargeted
  to `large_code_base_reconstruction.py:29-30,33`, the "llm_d code drifts"
  clause replaced (the eight literals never changed), and the per-function loop
  scoped to the JSON path.
- Remote provenance note: the clone's origin is `Lami99/LLM_Decompiler` (the
  repo was renamed from `itsgizmo`; the legacy URL returns 404); remote HEAD,
  file count (30), and repo size (49 KB) re-verified via `gh api` at assembly.
- Direct spot-checks for load-bearing cites in this chapter: name-map relay
  span (`large_code_base_reconstruction.py:29-30,68,84`), dead marker
  constants (`:8-9`), provenance-prompt lines (`llm_d.py:32,34-36`), exec-bit
  claim (`git ls-tree -r HEAD` → zero 100755 modes),
  `analyze_and_fix.sh:10` (`basePath=~/Desktop`), `README.md:21-22` wording,
  `Decompiler/gd_decomp.sh:5` pin string.
