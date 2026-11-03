# LLM4Decompile research lineage and papers — three real records, one phantom

> Part of the [LLM4Decompile overview](README.md). The paper record behind the repo: the full
> version history and publication trail of arXiv:2403.05286, the SK²Decompile preprint
> (arXiv:2509.22114), the previously unmentioned Decompile-Bench paper (arXiv:2505.12668), and
> the pre-LLM → LLM lineage both papers cite. Central negative finding: **the "name collision"
> the repo is rumored to have — arXiv:2403.17246 as a second "LLM4Decompile" by Huang et al.,
> with a NeurIPS-2024 DecompBench follow-up — does not exist on any queryable record.** 2403.17246
> is a multi-agent robotics planning paper. All paper claims cite fetched arXiv / ACL Anthology /
> OpenAlex / Semantic Scholar URLs; artifact cross-references cite clone `path:line` at HEAD
> `85b364b`. Score-contradiction bookkeeping lives in [20-llm4decompile-inventory.md](20-llm4decompile-inventory.md)
> §9, the release ladder in [21-history-and-releases.md](21-history-and-releases.md); harness critique
> of the numbers is chapter 32's job, not this one's.

## 1. The paper record, complete

Three arXiv records belong to this project; a fourth is commonly conflated with it and is not real.

| Paper | arXiv | Versions | Publication record (fetched) | Role for the repo |
|---|---|---|---|---|
| LLM4Decompile: Decompiling Binary Code with Large Language Models | 2403.05286 | v1 2024-03-08, v2 2024-06-19, v3 2024-10-22 | **EMNLP 2024 main**, pp. 3473–3487, DOI `10.18653/v1/2024.emnlp-main.203`, bibkey `tan-etal-2024-llm4decompile` (ACL Anthology, fetched); OpenAlex primary location = published version, CC-BY, cited-by 67 | V1/V1.5/V2 models; the `85b364b` repo's founding paper |
| Decompile-Bench: Million-Scale Binary-Source Function Pairs for Real-World Binary Decompilation | 2505.12668 | v1 2025-05-19, v2 2025-10-19 | OpenAlex records **published version** in *Advances in Neural Information Processing Systems 38* (NeurIPS 2025 volume numbering), DOI `10.52202/085713-0177`; cited-by 2 | the `decompile-bench*` dataset family + v1.6 "DCBench" models |
| SK²Decompile: LLM-based Two-Phase Binary Decompilation from Skeleton to Skin | 2509.22114 | v1 only, 2025-09-26 | no venue record (OpenAlex: `submittedVersion`, `is_accepted: false`, cited-by 1) | `sk2decompile/` directory (51 files) |
| "LLM4Decompile: Reverse Engineering Binary Code with LLMs" (Huang et al.) | 2403.17246 | — | **does not exist** — 2403.17246 is "TwoStep: Multi-agent Task Planning…" (Bai/Singh/Traum/Thomason; v1 2024-03-25, v2 2025-03-25, fetched via arXiv API + abs page) | none; phantom, §6 |

The 2403.05286 v3 abstract (fetched): "the first and largest open-source LLMs (ranging from 1.3B to
33B parameters) fine-tuned on 15 billion tokens for decompilation". The repo homepage still says
"1.3 billion and 33 billion parameters" (`README.md:66`). A 33B artifact *did* exist — the v1-era
`arise-sustech/llm4decompile-33b` repo carries full weights (7 safetensors shards plus 7 pytorch-bin
mirrors, 133 GB used storage; card: "finetuned from Deepseek-Coder on 4B tokens of assembly-C pairs
compiled from AnghaBench", i.e. the v1 recipe; HF API, fetched) — but no 33B model is in the LLM4Binary
org or the README table, and the v3-era 33B runs (200M-token budget, Table-3 footnote) were never
released; the current lineup is all ≤22B (ch.33 §1).

## 2. 2403.05286 — version archaeology and the EMNLP trail

Version drift tells the training story better than any README:

- **v1 (2024-03-08)** — abstract (fetched) claims "1B to 33B pre-trained on 4 billion tokens",
  a "21%" re-executability for the 6.7B, and "over 50% improvement over GPT-4", on a benchmark
  named **Decompile-Eval**. None of these numbers survive to v3: final figures are 15B tokens,
  45.4%, and a 162% framing over the Ghidra baseline. The `-uo` model (`arise-sustech/llm4decompile-6.7b-uo`,
  created 2024-03-16) is the v1-era artifact; the repo still quotes its v1-era number unchanged
  (`README.md:32`: "average re-executability is around 0.219").
- **v2 (2024-06-19)** — coincides with the V2/Ref model releases on HF (ch.21 ladder).
- **v3 (2024-10-22)** — current text; adds the 9B/22B base-model ablation (Appendix D, Table 11)
  right before 9b-v2/22b-v2 exist on HF (2024-09-23 / 2024-06-23; HF API dates, ch.21).

Publication record, verified twice against independent registries:

- ACL Anthology `2024.emnlp-main.203` (fetched): Hanzhuo Tan, Qi Luo, Jing Li, Yuqun Zhang;
  Miami, Nov 2024; pages 3473–3487; abstract identical to arXiv v3.
- OpenAlex `doi:10.48550/arXiv.2403.05286` (fetched): merged preprint+ACL record, `version:
  publishedVersion`, license CC-BY, venue EMNLP, `cited_by_count: 67` at fetch date.
- Semantic Scholar API: **HTTP 429 on every attempt** (keyless, several retries with 20–25 s
  backoff); citation counts above therefore come from OpenAlex, and the S2 record is recorded
  as *not independently consulted* rather than as a gap.

Affiliations from the paper (v3, fetched): Tan — SUSTech + PolyU; Luo — SUSTech; Li — PolyU;
Zhang — SUSTech (corresponding). The SUSTech unit matches the `arise-sustech` HF org and the
`/share/luoqi/models/deepseek-coder-1.3b-base` path baked into the shipped `config.json` of
`llm4decompile-1.3b-v1.5`/`-1.3b-v2` (ch.33 §2) — paper, org, and weights share one lab.

## 3. What 2403.05286 v3 publishes (numbers, not critique)

Method split: **LLM4Decompile-End** (asm→C, direct) and **LLM4Decompile-Ref** (Ghidra
pseudo-code→C refinement). Both use template `# This is the assembly code: … # What is the
source code?` with loss on output tokens only — implemented verbatim in `train/finetune.py:16-22`
(prompt) and `train/finetune.py:95-97` (label masking), verified in ch.33.

Training sets and compute (v3 §4.1.1 + Appendix, fetched):

- End: ExeBench-derived; compilable stage 7.2M samples ≈7B tokens, executable stage 1.6M samples
  ≈572M tokens; MinHash-LSH dedup + >10-token filter (§3.1); LLaMA-Factory, batch 2048, lr 2e-5,
  2 epochs ≈15B tokens; 12 days (1.3B) / 61 days (6.7B) on 8×A100-80GB; 33B limited to 200M tokens.
- ExeBench reconciliation (Appendix): only 443K of 797K ExeBench train samples re-compiled by the
  authors; eval uses 2,621 of 5,000 test functions.
- Ref: 400K functions × O0–O3 = 1.6M samples ≈1B tokens of *data*, 2B tokens of *training*
  (2 epochs); 2 days (1.3B) / 8 days (6.7B) on 8×A100; 33B again 200M tokens (10% of the others'
  budget, per the Table-3 footnote).
- Epochs (Appendix D, Table 9): 1 epoch is "a strong baseline", 2 epochs optimal, more overfits.

Headline tables (all values fetched from v3 HTML):

| Table | Key rows (avg re-executability unless noted) |
|---|---|
| 1 — End vs baselines | DeepSeek-Coder-6.7B **0.00**; GPT-4o 16.01 HumanEval / 3.78 ExeBench; End-1.3B 27.32 / 14.49; End-6.7B 45.37 / 17.98; End-33B 31.54 / 15.40 |
| 2 — data ablation | Compilable-only 6.7B: 37.50 HumanEval / 6.83 ExeBench; Executable-only 6.7B: 23.78 / 26.69 |
| 3 — Ref on HumanEval-Decompile | Ghidra 20.12; +GPT-4o 35.22; +Ref-1.3B 46.04; +Ref-6.7B 52.74; +Ref-33B 50.91; +Ref-22B 64.18 |
| 4 — GPT-judged readability (1–5) | GPT-4o 2.4436; Ghidra 2.5716; End-6.7B 3.5442 |
| 5 — obfuscation | Ref-6.7B drops **90.2%** under control-flow flattening (0.5274→0.0519) and **78.0%** under bogus control flow (0.5274→0.1159) |
| 11 (App. D) — base-model ablation | DeepSeek-Coder-6.7B 52.74 → LLM-Compiler-7B 54.57 → Yi-Coder-9B **64.94** → "CodeStral-22B" 64.18 |

Two of these rows are load-bearing for the artifact family: the Yi-Coder-9B and Codestral-22B
rows *became* `llm4decompile-9b-v2` and `-22b-v2` on HF (base verified from shipped configs in
ch.33 §2), and the README's 63.6% for 22b-v2 (`README.md:75`) matches neither Table 11 nor
Table 3 (both 64.18) — skew recorded in inventory §9, never reconciled.

Safety framing worth noting: the paper asserts its own obfuscation result (Table 5) as the reason
"concerns about unauthorized use for infringement of intellectual property" are mitigated (§4.2.2).
The claim is *empirical self-defense*: basic CFF/BCF already collapses the models. calxgloss meets
the same fact from the other side — obfuscated input is our adversarial case, not our shield.

## 4. SK²Decompile 2509.22114 — method and record

v1 only, dated 2025-09-26, cs.SE, no venue record anywhere queried (OpenAlex shows the arXiv
deposit, one citation). Author list `Tan, Weihao Li, Xiaolong Tian, Siyi Wang, Jiaming Liu, Jing
Li, Yuqun Zhang` (fetched) — exactly the corrected author string the repo bibtex adopted in
`2169186` (ch.21 §6). It cites Tan et al. 2024 as its own predecessor (ref bib44), so the
lineage inside the research group is explicit, not inferred.

Method (from the fetched full text): phase 1 "Structure Recovery" rewrites IDA/Ghidra pseudo-code
into an **obfuscated intermediate representation** with generic placeholders (`type1`, `func1`,
`var1`, `field1`), motivated by an Information-Bottleneck objective (Eq. 2; Tishby citations
bib50/51); placeholder renaming is Algorithm 1 over an AST. Phase 2 "Identifier Naming" maps the
IR back to readable source. RL via GRPO in veRL; rewards: Eq. 3 (compilability gate + placeholder
overlap) and Eq. 4 (embedding cosine, Qwen3-Embedding-0.6B) — the shipped reference implementations
and their deviations from the equations are audited in ch.33 §7. Data: ExeBench + Decompile-Bench,
GCC and Clang O0–O3, stripped binaries, IDA pseudocode, R2I-normalized, ≈5M samples ≈2B pseudocode
+ 1.5B IR + 1.5B source tokens; headers via Psyche-C; H800 cluster; both models initialized from
the LLM4Decompile-6.7B checkpoint (matches `pseudo2norm-example.yaml:2`, which starts from
`LLM4Binary/llm4decompile-6.7b-v2`).

Published results (fetched): Table 1 re-executability AVG — SK² 69.00 HumanEval (O0 86.59) /
59.63 MBPP vs GPT-5-mini 56.75 / 47.23, **LLM4Decompile 41.71 / 43.05**, Idioms 29.81 / 24.01.
Table 2 R2I — SK² GitHub2025 74.99 vs Idioms 57.97, LLM4Decompile 47.95. Table 4 ablation —
pseudo-src 54.86 → pseudo-ir 62.56 → pseudo-ir-src 63.75 → pseudo-ir-src-rl 69.00 (HumanEval AVG).
Headline claims: "+21.6% over GPT-5-mini", "+29.4% R2I over Idioms" (paper §4.1), also mirrored
in `sk2decompile/README.md:219-220`. Note the baseline label: "LLM4Decompile" in their tables is
*their own predecessor*, scored at 41.71 — lower than the 52.74 the 2024 paper advertised, because
SK²'s harness runs C *and* C++ with a different pipeline; the contradiction ledger is inventory §9
item 9 and chapter 32.

Appendix (A.1–A.4 in the fetched v1 HTML): A.1 defines stripping (`sub_FFB80`-style names); A.2
defines the three metrics and — this is the part that matters for re-scoring debates — records a
**modified R2I protocol**: original R2I drops a whole sample if any decompiler's output fails
pycparser parsing; SK² injects Psyche-C headers and scores unparsable outputs **0 instead of
discarding the sample**, which changes comparisons against rule-based decompilers systemically.
A.3 holds Tables 5–6 (R2I / GPT-judge ablations); A.4 is the LLM-used-for-writing statement. The
repo, however, cites "Section A.6" for BringUpBench (`sk2decompile/README.md:44,207`) and v1's
appendix ends at A.4 — SK² has no v2 (arXiv API), so the repo points at a section the only
version does not contain.

## 5. The benchmark papers — two are real, and only one is theirs

- **Decompile-Bench** (2505.12668, the group's own): 2M binary-source pairs condensed from 100M
  collected pairs, 450GB of binaries from permissively licensed GitHub projects; a
  **GitHub2025** eval split "compiled from GitHub repositories released after 2025 to mitigate
  data leakage" (abstract, fetched); "fine-tuning with Decompile-Bench causes a 20% improvement"
  on re-executability. OpenAlex additionally records a *published* NeurIPS-Proceedings-38 (i.e.
  NeurIPS 2025) version with DOI `10.52202/085713-0177` — the group does have a NeurIPS datasets
  record, which the phantom-collision story (§6) never needed. Author list includes **Hanrui Qi**,
  the repo contributor `7Sageer` (ch.21 §1). Repo-side claims: `README.md:26` ("two million … and
  70K function pairs for evaluation").
- **DecompileBench** (Gao/Cui/Wang et al., arXiv:2505.11340 published 2025-05-16, ACL *Findings*
  2025 `10.18653/v1/2025.findings-acl.1194`; both records fetched): "A Comprehensive Benchmark for
  Evaluating Decompilers in Real-World Scenarios" (vul337/DecompileBench). Different project,
  singular-word name. This — not any Huang paper — is the *actual* naming collision in this corner
  of the literature: `DecompBench` (phantom), `Decompile-Bench` (SUSTech datasets track), and
  `DecompileBench` (Imperial/KCL group) are three names for two things, none from Huang.

## 6. The phantom: "Huang et al., arXiv:2403.17246" examined and refuted

The premise handed to this dossier was that a *second* "LLM4Decompile: Reverse Engineering Binary
Code with LLMs" by Huang et al. (arXiv:2403.17246) sits at EMNLP-adjacent NeurIPS 2024 with a
"DecompBench" benchmark follow-up. Every element fails verification:

1. **arXiv:2403.17246 is not a decompilation paper.** Fetched via arXiv API and abs page:
   "TwoStep: Multi-agent Task Planning with New Environments for Training and Evaluation" —
   Bai, Singh, Traum, Thomason; v1 2024-03-25, v2 2025-03-25. No overlap in authors, topic, or venue.
2. **No such title exists anywhere.** Exhaustive query log (all performed 2026-10-31):

| Query | Result |
|---|---|
| arXiv API `all:"LLM4Decompile"` | 6 hits, all in this lineage: 2403.05286, Idioms 2502.04536, 2505.12668, 2509.14646, plus two 2026 works (2604.23940, 2608.27889) citing it |
| arXiv API `ti:"LLM4Decompile"` | 1 hit (2403.05286) |
| arXiv search UI, "large language models binary decompilation" | 33 hits, zero Huang-et-al. papers |
| arXiv API `all:"DecompBench"` | 1 hit — unrelated 2026 agent-safety paper (2606.13994) |
| arXiv API `all:"Eval4Decompile"`, `all:"pseudo code refinement"` | 0 hits |
| OpenAlex `title.search:LLM4Decompile` | 1 hit: Tan et al. |
| Crossref query "LLM4Decompile" | only the EMNLP DOI `10.18653/v1/2024.emnlp-main.203` |
| NeurIPS 2024 proceedings listing (3.1 MB fetched) | **zero** title matches for `decomp*` |
| GitHub `search/repositories?q=DecompBench` | 0 repos |
| GitHub search "LLM4Decompile" (10 hits) | forks/copies of `albertan017` only — no second project |
| Hacker News Algolia "LLM4Decompile" | 1 story (the repo itself, 412 pts, 2024-03-17) |
| Semantic Scholar / DBLP / Mojeek / Bing | inconclusive (429 / captcha / bot walls) — recorded as performed, not skipped |

3. **The rest of the claimed chain is also wrong.** The companion arXiv IDs quoted in the same
   premise (2405.09240, 2406.18797, 2411.04960 — "LLM4Decompile-Rev", "Eval4Decompile",
   NeurIPS-24 DecompBench) resolve on arXiv to unrelated condensed-matter/physics papers.
4. **Likely genealogy of the myth:** a real fact pattern got re-narrated — the SUSTech group *did*
   get a NeurIPS datasets track record (Decompile-Bench, NeurIPS-2025 volume, §5), *did* have an
   EMNLP 2024 main paper, and *did* keep the same project name across artifacts. A "different
   group, same name, NeurIPS 2024" story fits none of the records; it fits zero authors named Huang
   and zero 2024 NeurIPS decompilation papers. Verdict: **false premise**, treat all Huang-attributed
   claims about this project as unsupported.

## 7. Lineage as the two papers cite it

From the fetched related-work and bibliography sections of 2403.05286 v3 and 2509.22114 v1
(SK²'s bibliography is the richer of the two; IDs verified via arXiv API id_list where quoted):

- **Pre-LLM neural decompilation:** Katz et al. SANER 2018 (RNN decompilation); CoDA NeurIPS 2019
  (end-to-end neural decompiler); Lacomis et al. ASE 2019 (Dire, identifier naming);
  Patrick-Evans et al. ACSAC 2020 (probabilistic naming); David et al. OOPSLA 2020 (augmented
  CFGs); DnD USENIX Sec 2022 (cross-architecture); Hosseini & Dolan-Gavitt 2022 (BTC, NMT beyond C);
  HexT5 ASE 2023; CLAP ISSTA 2024. The 2024 paper's positioning line: "the largest open-source
  model in this domain is limited to 200M" (Slade/BTC era) — its own contribution is scaling that
  to 1.3B–33B.
- **LLM-refinement wave (the "Ref" gene):** REF/DecGPT (Wong et al., arXiv:2310.06530, cited as
  raising IDA output re-executability "over 75%" by feeding error messages back); DeGPT NDSS 2024
  (−24.4% cognitive load on Ghidra output); SCDE EMNLP 2024; LLM-Compiler NeurIPS 2024
  (arXiv:2407.02524 — a *compilation* foundation model that turned out to be a better decompilation
  base, Table 11).
- **Binary-LLM / symbol-recovery gene:** Nova ICLR 2025; ReSym CCS 2024; Xu et al. NDSS 2025
  (variable-name generation); HexT5 again; "Beyond the Edge of Function" (arXiv:2503.07243,
  type recovery); Su et al. NeurIPS 2024 (source models as binary knowledge bases).
- **Same-wave successors of LLM4Decompile itself:** Idioms (arXiv:2502.04536, Dramko et al. —
  joint code+type-definition decompilation, SK²'s Table-1 baseline at 29.81); ReF Decompile
  (arXiv:2502.12221); D-LiFT (arXiv:2506.10125, code-quality-driven fine-tuning of a decompiler
  backend); ALT4Decompile (arXiv:2509.14646) — cited inside SK² as "Salt4decompile: Inferring
  Source-Level Abstract Logic Tree", while the arXiv record (v2 title, fetched) is "ALT4Decompile:
  Inferring C-aligned Abstract Loop Tree": SK²'s own bibliography misquotes the title/acronym of
  a same-month sibling paper, a small reminder that even this group's reference hygiene slips.
- **The group's own chain:** 2403.05286 → Decompile-Bench 2505.12668 (data) → SK² 2509.22114
  (method), with GPT-Judge lineage shared across all three (Table 4 in 2024; A.2/Figure 5 in
  SK²; the repo's own judge code discussed in inventory §9 item 12).

## 8. Claims vs artifacts — cross-check index

To avoid duplicating the staleness ledger (inventory §9) and the release ladder (ch.21), only the
paper-side mismatches are listed here:

- **33B** — promised in v3 abstract; the *v1-era* 33B is on HF under the old org
  (`arise-sustech/llm4decompile-33b`, weights present, 4B-token AnghaBench recipe), but the v3-era
  33B (200M tokens) never was, and neither appears in the current org or README table
  (`README.md:66` echoes the v1 claim; inventory §9 item 8 says "no 33 B model exists … on HF",
  which needs updating in light of the v1-era repo — correction logged in ch.33 §1).
- **v1-era numbers frozen in READMEs** — `-uo` 0.219 (`README.md:32`) is a v1-paper figure; the v1
  abstract's "4 billion tokens / 21% / 50% over GPT-4" were superseded in v3 but the artifacts
  never were.
- **"outperforms the 6.7B-V1.5 by an additional 40.1%"** (`README.md:30`) — not a paper number; it
  reproduces only from README-internal math (63.6 ÷ 45.4 − 1 ≈ 40.1%), so it silently depends on
  the unreconciled 63.6 (paper: 64.18, Table 3/11).
- **"over 100% improvement" for V1.5** (`README.md:31,77`) — traceable to the 2024 paper's own
  "160% increase" framing for Ref-6.7B over Ghidra; misapplied to the End-series V1.5 delta.
- **SK² "Section A.5/A.6" pointers** (`sk2decompile/README.md:44,207`) — v1 appendix ends at A.4;
  no v2 exists.
- **Base-model claims** — "fine-tuned based on Yi-Coder-9B" (`README.md:29`) is *verified* in the
  shipped config (`_name_or_path = 01-ai/Yi-Coder-9B`); the 22b base is never stated in any
  README but matches Codestral-22B-v0.1's config fingerprint exactly (ch.33 §2). The one *wrong*
  direction found: HF model tags say `license:mit` for DeepSeek-derived weights while the repo's
  `LICENSE-MODEL` is DeepSeek's own restricted license (ch.33 §3).

## Steal ideas for calxgloss

- **Version-history auditing as a credibility tool** — diffing v1/v2/v3 abstracts exposed the
  frozen-README numbers instantly. calxgloss reports (P-series eval writeups) should carry the
  same version discipline: one canonical numbers table, regenerable, cited by report version.
- **The obfuscation result is our adversarial-test citation**: Table 5 (90.2%/78.0% collapse under
  CFF/BCF) is citable evidence that fine-tuned decompilers break on obfuscated input — motivates
  calxgloss keeping obfuscated scenarios in the eval substrate rather than only in the road map.
- **The modified-R2I protocol (SK² A.2)** — "score 0 instead of discarding the sample" is exactly
  the adjudication question calxgloss faces for unparseable translations: punish, exclude, or
  mark unresolved. Ours (ADR-backed) is mark-unresolved; their choice shows why the rule must be
  *stated in the harness paper*, not assumed.
- **Phantom-premise procedure** — the §6 query log (arXiv API fields, OpenAlex, Crossref,
  proceedings grep, GitHub repo search, HN Algolia; 429/captcha recorded as inconclusive) is the
  reusable template for any "project X shares the name with Y" claim; fold it into the dossier
  method file's descendants.
- **NeurIPS datasets-track record** — Decompile-Bench's published data-paper status is the
  template for publishing calxgloss's own scenario corpus (evidence-labeled, leak-controlled via
  the GitHub2025-after-2025 split trick).

## Sources

- arXiv (all fetched 2026-10-31): `https://arxiv.org/abs/2403.05286` (+v1 abstract text; full v3
  HTML with all tables/appendices), `https://arxiv.org/abs/2505.12668`,
  `https://arxiv.org/abs/2509.22114` (full v1 HTML incl. refs and A.1–A.4),
  `https://arxiv.org/abs/2403.17246` (TwoStep), id_list lookups
  `2509.14646,2502.04536,2502.12221,2506.10125,2503.07243,2310.06530,2505.11340`;
  arXiv API query strings and hit counts per §6 table.
- ACL Anthology: `https://aclanthology.org/2024.emnlp-main.203/` (pages 3473–3487, DOI, bibkey);
  `https://aclanthology.org/2025.findings-acl.1194/` (DecompileBench, DOI
  `10.18653/v1/2025.findings-acl.1194`, recorded via SK² v1 bibliography + arXiv id_list title match).
- OpenAlex (fetched): `https://api.openalex.org/works/doi:10.48550/arXiv.2403.05286`
  (cited_by_count 67, EMNLP publishedVersion, CC-BY), `…arXiv.2509.22114` (cited 1,
  submittedVersion), `…arXiv.2505.12668` (cited 2, "Advances in Neural Information Processing
  Systems 38", DOI `10.52202/085713-0177`).
- Semantic Scholar `graph/v1` API: HTTP 429 on all attempts (2403.05286, 2509.22114, 2505.12668,
  2403.17246) — negative result recorded with retry detail.
- NeurIPS 2024 proceedings index fetched; GitHub search API, HN Algolia, Crossref, OpenAlex
  title search, Mojeek/Bing/DBLP (bot-walled) per §6.
- Clone `/tmp/opencode/LLM4Decompile` @ `85b364b` for the cross-check lines: `README.md:26,29,30,31,32,66,75,77`;
  `sk2decompile/README.md:44,207,219-220`; `sk2decompile/LLaMA-Factory/SK2DECOMPILE/train/pseudo2norm-example.yaml:2`;
  `train/finetune.py:16-22,95-97` (template + masking match with the paper).
