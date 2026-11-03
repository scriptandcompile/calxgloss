# ML model & training lineage — what the 2023 "research phase" actually was, and the 2024 pivot to off-the-shelf GGUFs

> Part of the [ReverserAI overview](README.md). Establishes, from primary
> sources only, what was ever published or shipped of ReverserAI's model story;
> whether fine-tuned models/datasets ever existed publicly; what the project
> itself measured; and how the 2024 Binary Ninja plugin (Mistral/Mixtral GGUFs)
> differs from the alleged 2023 research-era approach. All web sources fetched
> 2026-10-31; clone claims verified at `/tmp/opencode/reverser_ai` @ `1d572da`.

**Verdict up front:** every public, primary artifact of ReverserAI — repo,
README, blog, talks page, slides, HF, PyPI — documents an **off-the-shelf
local-LLM engineering project** (GGUF instruct models + one-shot prompt +
static-analysis context injection). **No fine-tuned model, training corpus,
training pipeline, dataset, paper, or 2023 "ML for RE" blog series exists
anywhere findable.** The 2023 research era left *zero* public trace outside
retrospective wording in the 2024 release ("a culmination of research into
viable configurations", `cfa9908:README.md`). Fine-tuning is explicitly listed
as **not yet done** in every primary source (README future-work; REcon 2024
slides). The widely-repeated "arXiv:2304.02000" attribution and a "2023
CodeGen fine-tune program" remain unverifiable — see §5.

## Timeline

| Date | Event | Source |
|---|---|---|
| 2022–2023 | Author's public RE work is heuristic "code detection" (REcon 2023 talk; blog post), not ML — this lineage is what later feeds ReverserAI's function preselection | https://synthesis.to/talks.html ; https://synthesis.to/2023/08/02/api_functions.html |
| 2023-05-08 | Wayback snapshot of synthesis.to homepage: complete "Latest Blog Posts" list (2021-03→2023-01), **no ML/LLM post, no ReverserAI mention** | http://web.archive.org/web/20230508140240/https://synthesis.to/index.html |
| "2023 ML-for-RE blog series" | **No trace anywhere** — full blog listing has no such posts; Wayback CDX of synthesis.to has no ml/llm post URLs; emproof blog mirrors synthesis.to slugs only; mrphrazer.com never archived and does not resolve | https://synthesis.to/blog.html ; CDX queries below §5 |
| 2024-02-25 | Wayback snapshot of homepage: still no ReverserAI mention at all (9 days before release) | http://web.archive.org/web/20240225221000/https://synthesis.to/index.html |
| 2024-03-17 | **v1.0 squashed release** (`cfa9908`, "initial release"); repo `created_at` 2024-03-17T07:14:56Z; ships TheBloke Mistral-7B-Instruct-v0.2 Q4_K_M, hard-pinned | GitHub API (21-history §2.1); clone |
| 2024-03-17 | Same-day mirrors appear (gmh5225/reverser_ai, gmh5225/reverserai) | api.github.com/search/repositories?q=reverser_ai |
| 2024-06-21 | v1.1 tagged (Mixtral added, context-enriched renaming); author's LinkedIn post: "New version of ReverserAI, shortly before our talk at REcon Montreal…" (activity ID decodes to 2024-06-21 09:00 UTC) | clone tags; DDG snippet of https://www.linkedin.com/posts/tim-blazytko_github-mrphrazerreverserai-provides-activity-7209842542132039681-EPNT |
| late Jun 2024 | **REcon 2024 talk** "The Future of Reverse Engineering with Large Language Models" (Blazytko + Moritz Schloegel) — the only ReverserAI talk ever; fine-tuning framed as *future work* | https://synthesis.to/presentations/recon24_llm_reversing.pdf ; recording https://www.youtube.com/watch?v=UbkVuwGTljI (YouTube oembed, Recon Conference channel) |
| 2024-06-22 | Issue #7 commenter *claims to remember* a blogpost saying the author "finetuned Mistral at Q4" — the only fine-tuning hearsay in the entire record; no URL, no confirmation | https://github.com/mrphrazer/reverser_ai/issues/7 |
| 2025-05-26 | Third-party IDA Pro port appears (twistedwiresio/ida_reverser_ai; manual copy, not a GitHub fork; README description copies ReverserAI's verbatim) | api.github.com/repos/twistedwiresio/ida_reverser_ai |
| 2026-05-20 | v1.2 (packaging+CI only); author closes issue #7: "most of the parts are already outdated… many design decisions were made based on thinks that just worked after some experiments" | issues #7, #8 comments; clone tag |
| 2026 | NDSS 2026 "Decompiling the Synergy" (Basque et al.) cites ReverserAI as ref [13] in the LLM-for-SRE tool lineage and studies its prompt pattern | https://www.ndss-symposium.org/ndss-paper/decompiling-the-synergy-an-empirical-study-of-human-llm-teaming-in-software-reverse-engineering/ ; PDF https://www.ndss-symposium.org/wp-content/uploads/2026-f380-paper.pdf |

## 1. The 2023 research program — as far as primary sources go

There is **no primary-source documentation of any 2023 ReverserAI research
program at all.** What is established, per surface:

- **Author's blog (synthesis.to, the only live blog).** Full post list at
  https://synthesis.to/blog.html (8 posts, 2021-03→2026-03) contains **zero
  ML/LLM/model-training posts**. The only 2023 post,
  https://synthesis.to/2023/08/02/api_functions.html (2023-08-02, companion to
  the REcon 2023 talk; slides /presentations/recon23_code_detection.pdf,
  recording https://www.youtube.com/watch?v=y95MNr2Xu-g), is a **statistical
  heuristic** for identifying statically-linked API functions by call-graph
  structure. Text scan of the post: 0 occurrences of "LLM", "machine
  learning", "neural", "codegen", "fine-tun", "GPT", "ReverserAI". This post
  is nonetheless the **only 2023-era material linked from inside the repo**
  (examples/README.md:19, identical at `cfa9908`), where it justifies the
  static-analysis preselection idea ("specific API calls often fall among the
  most-called functions… By filtering for these functions and consulting an
  LLM, it's possible to automatically identify standard functions like
  `memcpy` and `strlen`") — i.e., the repo's only visible research-era debt is
  a *non-ML heuristic*, not a model.
- **Alternate domains.** `mrphrazer.com` does not resolve (empty `dig +short`,
  2026-10-31; curl timeout) and has **zero Wayback captures**
  (CDX `url=mrphrazer.com&matchType=domain` → empty). `blazytko.to` resolves
  (46.38.243.234) but serves a Domainpark parking page — the domain is an
  email domain only (author contacts: `tim@blazytko.to`). Any 2023 blog that
  supposedly lived there is not retrievable and, on the archive record, never
  existed.
- **emproof (author's company).** Current tech-blog index
  (https://emproof.com/en/blogs) lists 11 posts, all obfuscation/anti-tamper
  RE topics — including mirrors of synthesis.to posts ("identification of API
  functions in binaries"); **no ML post**. Wayback CDX of the old
  `emproof.io/blog/*` (2022-05 captures) shows the same synthesis.to slugs
  mirrored, nothing ML-related.
- **Homepage snapshots bracket the gap.** 2023-05-08 and 2024-02-25 Wayback
  snapshots of synthesis.to both show the full then-current blog list; neither
  mentions ML/LLM work or ReverserAI. As of 2024-02-25 the project did not
  exist publicly.
- **What "research" then meant, per the author's own words.** v1.0 README:
  "This project represents a culmination of research into **viable
  configurations**, offering a stable foundation with acceptable performance"
  plus the disclaimer "**My expertise in machine learning and LLMs is
  limited.** There may exist more efficient models or methods…"
  (`cfa9908:README.md`; still at HEAD `README.md:18`). The REcon 2024 deck
  (§3) lists "fine-tuned models" under **"Things to improve"** (slide 53) and
  praises aIDAPal (https://github.com/atredispartners/aidapal, created
  2024-06-03) as third-party evidence that "fine-tuning works well" (slide 55)
  — i.e., the author did **not** claim fine-tuning experience himself.
  Issue #7's closing reply: design decisions "were made based on thinks that
  just worked after some experiments" (mrphrazer, 2026-05-20).

Reading: the "2023 research phase" was, on all available primary evidence,
**private prompt/model-configuration experimentation (which generalist model,
which quantization, which context) plus reuse of the author's 2022–2023
heuristic code-detection work — not a published fine-tuning program.** No
task definition, corpus pipeline, base-model grid, eval methodology, or
results from 2023 exist in public. Any specific numbers about 200M CodeGen
fine-tunes (as in `00-scope-and-method.md:34-38`) have **no found source** and
should be treated as unestablished.

## 2. Artifacts inventory

| Artifact | URL / search | Status | Notes |
|---|---|---|---|
| Blog post "Identification of API Functions in Binaries" (2023-08-02) | https://synthesis.to/2023/08/02/api_functions.html | **exists** | Heuristic (most-called functions), not ML; companion to REcon 2023 talk; the repo's only 2023 link (examples/README.md:19); mirrored at emproof.com/en/blogs |
| REcon 2024 talk "The Future of RE with LLMs" | slides https://synthesis.to/presentations/recon24_llm_reversing.pdf; recording https://www.youtube.com/watch?v=UbkVuwGTljI | **exists** | Only ReverserAI talk ever; also linked from https://synthesis.to/talks.html with code= reverser_ai repo |
| 2023 "ML for RE part 1/2" blog series (claimed) | blog.html full list; Wayback CDX synthesis.to (domain match, ml filter); DDG `"ml-for-re" OR "ml_for_re" reverserai OR blazytko` → "No results found" | **verified absent** | Never existed on synthesis.to, emproof.io, mrphrazer.com (zero captures) |
| Paper "REverserAI: … auto-symbolication" / arXiv:2304.02000 | arXiv export API `all:"ReverserAI"`, `all:"auto-symbolication"` → 0 entries (2026-10-31); Crossref `query=ReverserAI` → 0; Zenodo `"ReverserAI"` → 0; publications page lists **no** ReverserAI work (https://synthesis.to/publications.html) | **verified absent** | arXiv:2304.02000 = Baldoni & Vergne math paper (see 21-history §2.1); never cite it |
| HF models/datasets (mrphrazer or blazytko) | https://huggingface.co/mrphrazer → **HTTP 404 (no account)**; `api/models?author=mrphrazer`, `?author=blazytko`, `api/datasets?author=…`, `search=reverserai` (models+datasets) → `[]` | **verified absent** | No HF presence at all; the tool only *downloads* TheBloke GGUFs (`reverser_ai/gpt/models.py:18,30,43`) |
| Training pipeline repo (e.g. reverser_ai_training) | full repo list `api.github.com/users/mrphrazer/repos` (37 repos) + gists (7) | **verified absent** | LLM-adjacent repos only: reverser_ai (2024-03-17), Monocle (2024-04-10, NL search over compilations), 2026 MCP/agentic repos; 2023 gist is a Keybase proof |
| PyPI package | https://pypi.org/pypi/reverser-ai/json → 404; …/reverser_ai/json → 404 | **verified absent** | Installed from git via setup.py only |
| "reverser.ai" domain | http://reverser.ai → body "OK" (health-check style page) | **not a project artifact** | Unrelated to ReverserAI content |
| Hacker News coverage | hn.algolia.com `query=reverser_ai` / `ReverserAI` | **verified absent** | No story ever submitted — the tool never hit HN |
| IDA Pro port | https://github.com/twistedwiresio/ida_reverser_ai (2025-05-26, 1★, fork=False; description copies ReverserAI's README) | **exists, third-party** | Not mrphrazer's; secondary lineage claim only |
| Ghidra port | api.github.com `search/repositories?q=reverser_ai+ghidra` → 0; `q="reverserai" in:readme,description` → no Ghidra port | **verified absent** | HEAD README:158 lists Ghidra/IDA extension as future work |
| Same-day mirrors | gmh5225/reverser_ai, gmh5225/reverserai (both created 2024-03-17) | **exist** | Unmodified copies (secondary) |
| aiDAPal (comparison fine-tune) | https://github.com/atredispartners/aidapal (2024-06-03, 393★) "fine-tuned for Hex-Rays pseudo-code" | **exists** | Cited in REcon 2024 slide 55 as the fine-tuned counterexample the author did *not* build |
| Citing third-party study | NDSS 2026 "Decompiling the Synergy" (Basque, Doria, Soneji, Gibbs, Doupe, Shoshitaishvili, Losiouk, Wang, Aonzo; DOI 10.14722/ndss.2026.240380) | **exists (secondary)** | Cites ReverserAI as ref [13] among LLM-SRE plugins; did not benchmark it |
| Author's LinkedIn post (v1.1 era) | https://www.linkedin.com/posts/tim-blazytko_github-mrphrazerreverserai-provides-activity-7209842542132039681-EPNT | **exists (snippet only, login-walled)** | "supports a second, more powerful local LLM · applies static analysis to enhance results of GPT-based function renaming"; ID→2024-06-21 |
| X/Twitter era posts | twitter.com/mr_phrazer (linked from every README revision) | **inconclusive** | X not fetchable anonymously on 2026-10-31; no archived trace found |

## 3. Research era vs shipped tool — the concrete diffs

Primary technical record of the shipped tool (clone @ `1d572da`):

- Models: **off-the-shelf instruct GGUFs, always** — `mythomax-l2-kimiko-v2-13b.Q6_K` (roleplay model, vestigial), `mistral-7b-instruct-v0.2.Q4_K_M` (default), `mixtral-8x7b-instruct-v0.1.Q4_K_M` — all `TheBloke/*` repos (`reverser_ai/gpt/models.py:18-19,30-31,43-44`; all versions per 21-history §3: zero hits for `codegen`/`tinyllama`/`ReverserAI-` across all 25 commits).
- Prompt: frozen Mistral-v0.1 one-shot template
  (`<s>[INST]…[/INST] add_two_values</s> [INST]Here's the code:\n{code}[/INST]`,
  `reverser_ai/gpt/function_name_gpt.py:57-63`) + raw llama.cpp completion;
  vestigial `\n### Response:` Llama-2 suffix in `build_prompt`
  (`reverser_ai/gpt/agent.py:83`) — the one fingerprint of an earlier
  Llama-era experimentation phase, left in dead code rather than documented.
- The *method* the tool does ship, per the deck and README: **context
  engineering** — bottom-up call-graph propagation of learned names into
  caller queries (slide 48 "Context-sensitive Annotations: Bottom-up
  Propagation", annotated "simple but effective"; `d488e82`/`eb940ea`), HLIL
  decompiler output as model input (not
  disassembly/MLIL), function preselection via string/API/symbol references
  (`collect_symbol_related_functions`, `collect_string_related_functions` —
  the direct heir of the 2023-08-02 heuristic post).

The claimed 2023-era approach vs the plugin:

| Dimension | "2023 research era" (claimed) | Shipped 2024–2026 tool (verified) |
|---|---|---|
| Model | small fine-tunes (CodeGen-350M-class, per `00-scope-and-method.md:34-38`) | generalist instruct models, 7B/8×7B, Q4_K_M/Q6_K GGUF, ~5 GB / ~25 GB |
| Training | corpus from compiled code; name-prediction fine-tune | **no training code, data, or artifacts exist anywhere** (repo, HF, GitHub, Zenodo, PyPI) |
| Evidence | blog-reported top-k name overlap (claimed) | nothing: no eval harness, no tests, no benchmark in any commit |
| Hosting | Hugging Face model repos (claimed) | HF user itself returns 404 |
| What the plugin added beyond it | — | BN integration (UI commands, settings, plugin manager), bottom-up renaming, context preselection, model selection, GGUF runtime via llama-cpp-python |

The 2024 pivot is stated, not inferred: v1.0 README presents the tool as
"the culmination of research into **viable configurations**" — configuration
of off-the-shelf models — and simultaneously defers fine-tuning to the future
(`cfa9908:README.md` disclaimer; HEAD `README.md:156` "Fine-tuning existing
models or developing specialized models" under *Limitations and Future
Work*; slide 53 "Things to improve: … fine-tuned models" — whose other two
bullets are "better queries (prompt engineering)" and "better models:
https://github.com/eugeneyan/open-llms", a catalogue of ready-made models
rather than any training recipe). No primary source
narrates a decision "to abandon fine-tunes for Mistral" — because no primary
source mentions fine-tunes in the project at all. The only fine-tuning
mention inside the repo's own orbit is a **user's hazy recollection** in
issue #7 (2024-06-22: "according to your blogpost(don't have the URL handy)…
I also finetuned Mistral at Q4… I would assume") which the author never
confirmed — and which is fully consistent with the user misremembering the
*aIDAPal* passage from the REcon slides.

## 4. Effectiveness evidence

Everything ever measured or asserted by the project itself:

**Measured (thin, engineering metrics only — never RE quality):**
- Query latency, REcon 2024 slide 40 ("Anecdotally, for some function
  renaming queries"): "GPT query: <2s; Mistral 7B on M1 Macbook Pro: 5-8s;
  Mistral 7B on M3 Macbook Air: 10s".
- Hardware envelope, `cfa9908:README.md`: "at least 16 GB of RAM and 12 CPU
  threads, with queries taking about 20 to 30 seconds. GPU optimizations,
  especially on Apple silicon devices, can reduce this to 2 to 5 seconds per
  query." Model download ~5 GB (mistral Q4_K_M); v1.1 corrected mixtral RAM
  claims 45 GB→25 GB (`456bc1e`).
- A qualitative 7-use-case × 2-model table, REcon 2024 slide 44
  "(Unfair) Comparison to GPT4", scale unspecified (extracted via
  `pdftotext -layout`): function renaming — Mistral 7B: 3, Mixtral 8x7B: 3;
  identify library functions — 3/3; enhance decompiler output — 7/3; annotate
  assembly — 7/3; explain code logic — 7/3; helper script development — 7/3;
  verification oracle — 7/3. No rubric, no dataset, no inter-rater procedure
  given anywhere; direction of the scale is not defined in the deck.
- Interim conclusion, slide 31: "good for approximations and high-level
  understanding; answers sometimes generic or wrong; adding context often
  helps; **no real (code) understanding**".

**Asserted (examples/README, identical at `cfa9908` and HEAD):**
- "LLM-based function naming **quickly sorts**" the 23 functions of the
  Triton PowerPC stub `triton_inject.bin`, "notably identifying those doing
  data copying and implementing complex code patterns" (examples/README.md §
  Triton) — no ground truth published; the samples.zip (password "infected")
  is the closest thing to a benchmark the project ever provided.
- "it's possible to automatically identify standard functions like memcpy and
  strlen" (examples/README.md:19) — "Detailed examples will be provided in
  future updates" (never were).

**Never: accuracy/top-k overlap/accept-rate numbers; no eval script, no test
suite, no human study** ("No CI, no tests" at v1.0, 21-history §2.1; v1.2 CI
adds lint only). Third-party: **no quantitative study of ReverserAI found**;
the NDSS 2026 paper cites it only in tool lineage ("practitioners integrate
these initial findings into binary decompilers … [12]–[15]") and validated
their own prompt design against "other related open-source prompts
[12]–[15], [40]" — ReverserAI's one-shot pattern appears in the wild's design
space, nothing more.

## 5. Verified absences (search → result, all run 2026-10-31)

| What | How searched | Result |
|---|---|---|
| arXiv paper | export.arxiv.org `all:"ReverserAI"` → 0 `<entry>`; `all:"auto-symbolication"` → 0 (re-run today; also 21-history §2.1); arXiv:2304.02000 = math paper (Baldoni & Vergne) | absent; the "2304.02000" attribution is a citation-of-a-citation error |
| Peer-reviewed venue paper | publications page (https://synthesis.to/publications.html — complete list, none from 2023-2024 ML); Crossref `query=ReverserAI` → 0 total; OpenAlex `search=ReverserAI` → 1 hit (the NDSS citing paper, not a ReverserAI paper); Zenodo `"ReverserAI"` → 0; Semantic Scholar API → HTTP 429 (inconclusive); DBLP API → anti-bot page (inconclusive, but author's own publications list is complete and has no such entry) | absent |
| Conference talk (Black Hat / DEF CON AI Village / SysCan / VirusBulletin) | complete talks page https://synthesis.to/talks.html lists every talk with links — only LLM talk is REcon 2024; DDG `"reverser_ai" OR "ReverserAI" blackhat OR "def con" OR syscan OR virusbulletin OR "AI village"` → "No results found" | absent (REcon 2024 is the sole one) |
| 2023 ML-for-RE blog series | full blog index (blog.html, 8 posts); Wayback CDX synthesis.to domain listing 2021-2026 (no ml/llm post URL ever archived); emproof.io/blog CDX + emproof.com/en/blogs (no ML post); DDG `"ml-for-re" OR "ml_for_re" reverserai OR blazytko` → "No results found" | absent — the "part 1 / part 2 March 2023" premise has no support on any author surface |
| HF models/datasets/account | huggingface.co/mrphrazer → 404 (2026-10-31); api models/datasets `author=mrphrazer`, `author=blazytko`, `search=reverserai` → `[]`; `search=ReverserAI` → models `[]` + datasets `[]`; `search=reverser_ai` → 1 model (`reverseroot/aisha-ai`, 2025-02-05, a FLUX.1-dev text-to-image LoRA — unrelated org, unrelated task); (21-history: `search=ReverserAI` → 0) | absent — no HF account ever existed under these names on the current record; the only fuzzy name match is an unrelated image LoRA |
| Training pipeline repo | full GitHub user repo list (37 repos, `per_page=100&sort=created`) + 7 gists + DDG `mrphrazer "fine-tune" … codegen` → "No results found" | absent |
| PyPI | pypi.org/pypi/{reverser-ai,reverser_ai}/json → 404/404 | absent |
| Ghidra port | GitHub repo search `reverser_ai ghidra` → 0; README:158 keeps Ghidra as future work | absent |
| IDA port by author | none in mrphrazer's repo list | absent; only third-party twistedwiresio/ida_reverser_ai (2025-05-26) |
| HN coverage | hn.algolia.com search API `reverser_ai`, `ReverserAI` | no story ever submitted |
| Research-era URLs in the repo itself | `git grep -h -o 'https\?://…' $(git rev-list --all)` → exactly 9 distinct non-binary URLs (gnu license, twitter, synthesis.to/2023-08-02, github repo, gitignore, pdm, poetry, wikipedia Triton) — **no paper/blog/model link in any revision ever** | the repo's only external research-era pointer is the heuristic api_functions post |

## Sources

Web (all fetched/queried 2026-10-31):
- https://synthesis.to/ (homepage), /blog.html, /talks.html, /publications.html, /projects.html — author's canonical surfaces (mrphrazer.com and blazytko.to do not serve content: dig empty / Domainpark page)
- https://synthesis.to/presentations/recon24_llm_reversing.pdf (fetched, 2.3 MB; `pdftotext -layout` extraction of slides 31, 40, 44, 51, 53, 55)
- https://www.youtube.com/watch?v=UbkVuwGTljI via https://www.youtube.com/oembed (Recon Conference recording metadata)
- https://synthesis.to/2023/08/02/api_functions.html (keyword scan: 0 ML terms)
- http://web.archive.org/web/20230508140240/… and /web/20240225221000/… (synthesis.to snapshots); CDX queries `url=synthesis.to&matchType=domain…`, `url=synthesis.to/tools.html…` (captures only 2026+), `url=emproof.io/blog*…`, `url=mrphrazer.com…` (empty)
- https://www.emproof.com/ and /en/blogs (11-post index)
- https://huggingface.co/mrphrazer (404); https://huggingface.co/api/{models,datasets}?author=mrphrazer|blazytko&search=reverserai; `models?search=ReverserAI|reverser_ai` (the one `reverser_ai` hit is `reverseroot/aisha-ai`, an unrelated FLUX LoRA)
- http://export.arxiv.org/api/query (ReverserAI, auto-symbolication, "Decompiling the Synergy"); https://api.crossref.org/works?query=ReverserAI; https://api.openalex.org/works (search=ReverserAI; work W7132846387); https://zenodo.org/api/records?q="ReverserAI"; api.semanticscholar.org (429), dblp.org (anti-bot)
- https://api.github.com/users/mrphrazer/{repos,gists}; api.github.com/repos/{twistedwiresio/ida_reverser_ai, twisterwiresio/reverser_ai, gmh5225/reverser_ai, atredispartners/aidapal}; search/repositories?q=reverser_ai|reverserai|reverser_ai+ghidra|"reverserai" in:readme,description; api.github.com/repos/mrphrazer/reverser_ai/{issues,issues/7,issues/8,issues/7/comments,discussions} (discussions disabled, HTTP 410)
- https://www.ndss-symposium.org/ndss-paper/decompiling-the-synergy-…/ + PDF https://www.ndss-symposium.org/wp-content/uploads/2026-f380-paper.pdf (ref [13], prompt-design passage)
- https://hn.algolia.com/api/v1/search?query=reverser_ai / ReverserAI; https://pypi.org/pypi/reverser-ai/json; https://html.duckduckgo.com/html/?q=… (four queries: tool mentions / conference mentions / fine-tuning claims / ml-for-re series — results recorded above); https://lite.duckduckgo.com (bot-challenge); gist raw f0d13c15… (Keybase proof); https://synthesis.to/linkedin post activity-7209842542132039681 (DDG snippet; ID decoded 2024-06-21)

Clone `/tmp/opencode/reverser_ai` @ `1d572da`:
- `git grep -h -o 'https\?://…' $(git rev-list --all)` (9 URLs ever);
  `git grep -i -E 'fine.?tun|2023|codegen|train|corpus|lora|epoch' $(git rev-list --all)` (only README future-work + models.py "pre-trained" comment)
- `git show cfa9908:README.md` (disclaimer, hardware envelope, auto-download); `git show cfa9908:examples/README.md` ≡ HEAD
- `README.md:18,156`; `README.md:158` (IDA/Ghidra future work); `examples/README.md:19`
- `reverser_ai/gpt/models.py:18-19,30-31,43-44`; `reverser_ai/gpt/function_name_gpt.py:57-63`; `reverser_ai/gpt/agent.py:83`
- 21-history cross-refs: [21-history-and-releases.md](21-history-and-releases.md) §2.1 (created_at, squashed start, arXiv:2304.02000 resolution), §3 (model-per-release), §4 (release bodies)
