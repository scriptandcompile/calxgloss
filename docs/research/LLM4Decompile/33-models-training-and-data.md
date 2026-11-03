# LLM4Decompile model family, training stacks, and data (artifacts ledger)

> Part of the [LLM4Decompile overview](README.md). What the project *shipped* rather than
> *described*: every Hugging Face model and dataset the orgs own, with API-verified creation dates,
> licenses, and download counts; what the shipped `config.json` files reveal about base models that
> no README names; the three training stacks checked into `train/`; SK²Decompile's SFT (LLaMA-Factory)
> and RL (VERL/GRPO) recipe line by line, including where the shipped code deviates from the paper's
> equations; the `Preprocess/` data pipeline and its prompt inconsistencies; and an as-published
> effectiveness ledger of every number the project attaches to each checkpoint. Code claims cite
> clone-relative `path:line` against `/tmp/opencode/LLM4Decompile`, HEAD `85b364b`. HF claims come
> from `huggingface.co/api` and raw-card fetches (2026-10-31). Release *ordering* is ch.21's ladder;
> the staleness ledger is inventory §9; harness critique is chapter 32. Nothing here re-derives them.

## 1. The artifact ledger — every repo the orgs own

`LLM4Binary` owns eleven models (HF models API, fetched 2026-10-31 → dates below; downloads/likes
at fetch). The older `arise-sustech` namespace still hosts the v1-era line (§1 tail) — two orgs for
one lab, and the READMEs mix both namespaces in their links.

| Model | Created | DL / likes | Status |
|---|---|---|---|
| `llm4decompile-1.3b-v1.5` | 2024-05-10 | 632 / 6 | open |
| `llm4decompile-6.7b-v1.5` | 2024-05-10 | 314 / 15 | open |
| `binaryLLM` | 2024-05-31 | 0 / 1 | open but card is literally `TBD` — an abandoned placeholder |
| `llm4decompile-1.3b-v2` | 2024-06-18 | 682 / 11 | open |
| `llm4decompile-6.7b-v2` | 2024-06-18 | 656 / 10 | open |
| `llm4decompile-22b-v2` | 2024-06-23 | 376 / 34 | open |
| `llm4decompile-9b-v2` | 2024-09-23 | 130 / 25 | open |
| `llm4decompile-1.3b-v1.6` | 2025-05-21 | 45 / 5 | open (v1.6 = "DCBench" line, §9) |
| `llm4decompile-6.7b-v1.6` | 2025-06-29 | 37 / 3 | open |
| `sk2decompile-struct-6.7b` | 2025-10-02 | 276 / 8 | open; re-touched 2026-01-25 (ch.21 ladder) |
| `sk2decompile-ident-6.7b` | 2025-10-02 | 277 / 5 | open; re-touched 2026-01-25 |

The V1 checkpoints are **gated**: `LLM4Binary/llm4decompile-1.3b-v1` and `-6.7b-v1` return HTTP 401
to anonymous API fetches (verified by response, 2026-10-31) — the only embargo in the family, and it
hides the v1-era artifacts the README's oldest news bullets (`README.md:32`) still advertise.

**Pre-rename org (`arise-sustech`) still hosts the v1 line** (models API search, fetched):
`llm4decompile-1.3b` (41 DL), `-6.7b` (0 DL), `-6.7b-nsp` (16 DL, a next-statement-prediction
variant never mentioned in the current README), `-6.7b-uo` (created 2024-03-16, 184 / 23 — the
model behind `README.md:32`'s 0.219 figure), and — materially — **`llm4decompile-33b`**: full weights,
7 safetensors shards (~66 GB) plus a second set of 7 `pytorch_model-*.bin` mirrors, 133 GB used
storage (tree API). Its card: "finetuned from Deepseek-Coder on 4B tokens of assembly-C pairs
compiled from AnghaBench" — the **v1-paper recipe** (4B tokens, AnghaBench), matching the v1 abstract
that ch.31 §2 reconstructs. This **corrects inventory §9 item 8**, which states no 33 B model exists
"on HF": it does exist, in the old org, with weights. What does *not* exist anywhere on HF is the
v3-era 33 B checkpoint (the 15B-token line, 200M-token budget per the Table-3 footnote) and any 33 B
in the current org or README model table (`README.md:70-75` — max 22B).

**Community mirrors dominate distribution.** mradermacher GGUF conversions (models API, fetched):
`1.3b-GGUF` 894 DL, `-6.7b-GGUF` 327, `-6.7b-nsp-GGUF` 388, `-6.7b-uo-GGUF` 325, **`-33b-GGUF` 237**
(mirroring the orphaned 33B), `-22b-v2-GGUF` 727 / `-i1-GGUF` 571, **`-9b-v2-GGUF` 5,638** (43× the
official repo), `-1.3b-v1.6-GGUF` 173, `-6.7b-v1.6-GGUF` 198. For SK², the wrong-name rot
(inventory §9 item 7) propagated into the mirrors: `mradermacher/sk2decompile-ident-6.7-GGUF`
(1,099 DL — mirroring the broken name from `sk2decompile_inf.py:24`, §8) has **4× the downloads of
the official `ident-6.7b` repo (277)**, alongside a correct `-6.7b-GGUF` (328);
`Neo111x/sk2decompile-ident-6.7b` (3 DL) is an unofficial full-weights copy. GGUF-mirror downloads
exceed the official org family's totals.

## 2. Base-model forensics — what the configs confess

No README names the 6.7B or 22B bases; the shipped `config.json` files do (`_name_or_path` and
architecture fields, raw fetch per repo):

| Checkpoint | `config.json` evidence | Verdict |
|---|---|---|
| `1.3b-v1.5`, `1.3b-v2` | `_name_or_path: /share/luoqi/models/deepseek-coder-1.3b-base` | an *unpublished local path* leaked into the upload — the lab's private DeepSeek base copy (matches the SUSTech author line, ch.31 §2) |
| `6.7b-v1.5`, `6.7b-v2` | `_name_or_path: deepseek-ai/deepseek-coder-6.7b-base` | public DeepSeek-Coder base, stated by the artifact itself |
| `arise-sustech/llm4decompile-6.7b-uo` | `_name_or_path: deepseek-ai/deepseek-coder-6.7b-base` | same base as v1.5/v2 despite "-uo" marketing as the v1 model |
| `9b-v2` | `_name_or_path: 01-ai/Yi-Coder-9B` | confirms `README.md:29` ("fine-tuned based on Yi-Coder-9B") — the one base claim that verifies first try |
| `22b-v2` | `_name_or_path: null`, but architecture fields identical to `mistralai/Codestral-22B-v0.1`'s published config: `MistralForCausalLM`, hidden 6144, 56 layers, 48 heads / 8 KV, `intermediate_size` 16384, 32768 ctx, `rope_theta` 1e6, vocab 32768 | fingerprint match is exact; paper Table 11 ("CodeStral-22B", ch.31 §3) corroborates. Config cannot prove weight identity, but every architectural field plus the paper's own base ablation points one way — and no README ever says it |
| `1.3b-v1.6`, `6.7b-v1.6` | `_name_or_path: null`; Llama-shaped 4096/32 (6.7B), vocab **32256**, ctx 8192 (6.7B config fetched) | the v1.6 line returned to the DeepSeek-Coder family (32256 is DeepSeek's vocab) without documentation |
| `sk2decompile-struct/ident-6.7b` | raw `config.json` returns 401 to anonymous raw fetches (2026-10-31; repo itself not gated per list API — file-level fetch refused under anonymous limits); safetensors metadata from the model API earlier the same session shows parameter counts equal to the DeepSeek-Coder 6.7B size and **F32** storage dtype | trained from `llm4decompile-6.7b-v2` (paper §4 + yaml, §6); F32 upload is unusual and inflates the repo ~2× over BF16 |

Takeaways: the family is *overwhelmingly DeepSeek-Coder-derived* (every 1.3B/6.7B artifact, both SK²
checkpoints included); the two non-DeepSeek bases (Yi-Coder-9B, Codestral-22B) trace to the paper's
own Table 11 ablation, and only the 9B is admitted in a README; and `_name_or_path: null` scrubbing
lands on exactly the repos where documentation is thinnest (22B, v1.6, SK²).

## 3. License ledger — the org tag contradicts the repo

- Every open `LLM4Binary` model carries HF tag **`license:mit`** (`cardData.license: "mit"` for all
  eleven, list API with `expand[]=cardData`) — including all DeepSeek-derived weights.
- The GitHub repo ships **`LICENSE` and `LICENSE-MODEL`** at the root (verified `ls` at `85b364b`);
  `LICENSE-MODEL` is the **DeepSeek License Agreement v1.0** ("DEEPSEEK LICENSE AGREEMENT / Version
  1.0, 23 October 2023 / Copyright (c) 2023 DeepSeek" — head lines) with use restrictions and PRC
  governing law (full anatomy in inventory §9 item 6).
- The contradiction is direct: MIT-tagged redistributions of weights the repo itself licenses under
  DeepSeek's restricted terms. HF's tag governs nothing legally, but it is what most downstream users
  read, and the wrong-named, MIT-flavored GGUF mirrors (§1) compound it.
- Datasets split two ways (dataset API): **CC0** — `decompile-bench`, `decompile-eval`,
  `decompile-bench-makefile`; **MIT** — `decompile-ghidra-100k`, `decompile-bench-raw`,
  `decompile-bench-bins`, `decompile-bench-raw-address`. CC0 over corpora mechanically compiled from
  arbitrary MIT/BSD/Apache GitHub projects is itself a stretch (the paper's own license story is the
  permissive-licensing filter, ch.31 §5); the MIT-tagged siblings are the more honest half of the set.

## 4. Paper-stated training budget (for reconciliation against the stacks)

Numbers here are ch.31 §3's, restated only where they bind an artifact: End-line global batch 2048,
lr 2e-5, 2 epochs ≈ 15B tokens; Ref-line ≈ 2B tokens. SK² paper §4 (fetched, verbatim): SFT "for one
epoch using the LLaMA-Factory library … batch size of 128 and a learning rate of 3e-6", RL via "GRPO
… in the veRL library" on "a random subset of 50,000 samples", Psyche-C-generated headers, semantic
reward via qwen-embedding-0.6B, H800-80GB clusters, vLLM greedy decoding at inference. Each stack
below is checked against these numbers *and its own runnable defaults*.

## 5. The 2024-era stack — three checked-in training routes, one shared core

**a) Homegrown DeepSpeed trainer** — `train/finetune.py` is the canonical path (`train/README.md`
documents it). Prompt template `build_instruction_prompt` at `train/finetune.py:16-22` is
`# This is the assembly code:\n{asm}\n# What is the source code?\n` — identical to the paper's
template. Loss masking keeps labels only on the output span: `label[:source_len] = IGNORE_INDEX`
(`train/finetune.py:95-97`); targets are `f"{output}\n{eos_token}"` (`:132`); weights load as
bf16 (`:171`). The shipped `model_max_length` default is **512** (`train/finetune.py:46-51`) —
far below the paper's 4,096 — but the documented example (`train/README.md:31-52`) overrides to
`--model_max_length 1024` with bs 16 × grad-accum 16 (global 256 on one GPU), lr 2e-5, 2 epochs: an
eighth of the paper's global batch, a quarter of its context. `train/run_training.sh` defaults tell the more
interesting story: `model_name_or_path=${MODEL_PATH:-"${ROOT_DIR}/models/llm4decompile-1.3b-v1.5"}`
(`:26`) — the maintained script fine-tunes **a fine-tune** (the v1.5 checkpoint, not the base);
dataset label `llm4binary_v1` and experiment id `deepseek-1.3b-llm4decompile-v15-llm4binary-v2`
(`:27-28`) — the *v2*-era script consumes the *v1*-named dataset; cutoff 4096 (`:48`), lr **5e-6**
(`:53`), 1 epoch (`:62`) — none of which match any published recipe. This is the script that exists
today, and it reproduces no paper number.

**b) ColossalAI stack** — `train/colossalai_llm4decompile/`. `run_llm4decompile_train.sh`:
`PROJECT_NAME="llm4decompile-6.7b-v2"` (`:12`), `colossalai run --nproc_per_node 8` (`:29`),
`--plugin "zero2"` (`:32`), 2 epochs / micro-batch 8 / accumulation 8 / lr 2e-5 (`:37-40`, global
batch 8×8×8 = 512 — not the paper's 2048), `--max_length 4096` (`:47`). The stack is **broken as
shipped**: `prepare_pretrain_dataset.py:13-17` imports
`colossal_llama.dataset.spliced_and_tokenized_dataset` — a submodule that is not in the repo (vendored
`colossal_llama/dataset/` contains only `__init__.py` and `loader.py`; `git ls-files | grep -i spliced`
→ zero hits). The entry script cannot import. Curiosity: `train.py:22,333` activate **NEFTune** noise
embedding on the model — a regularization trick never mentioned in the paper.

**c) LLaMA-Factory bridge** — `train/llama_factory_llm4decompile/README.md`: clone the external fork
`http://github.com/7Sageer/llama-factory-example` (`:11` — 7Sageer = Hanrui Qi, ch.31 §5), then clone
upstream `hiyouga/LLaMA-Factory` as `../LLaMA-Factory` (`:16`). Nothing of the fork is vendored —
the route that produced the flagship 15B-token artifacts (paper used LLaMA-Factory, ch.31 §3) is
instructions pointing outside the repo.

## 6. SK² SFT — two chained LLaMA-Factory examples

`sk2decompile/LLaMA-Factory/SK2DECOMPILE/train/pseudo2norm-example.yaml`: initializes from
**`LLM4Binary/llm4decompile-6.7b-v2`** (`:2`) — SK² is built on the v2 6.7B, the lineage the paper
confirms ("initialized from the LLM4Decompile-6.7B checkpoint", §4 fetched); `template:
sk2decompile` (`:13`) — a template *undefined anywhere in this repo* (it lives only in the external
7Sageer fork, §5c); `cutoff_len: 2048` (`:14`); `max_samples: 100` (`:15`) — the shipped examples are
toy data files, not corpora; `per_device_train_batch_size 8` × `gradient_accumulation_steps 8` =
global **64**, `learning_rate 3.0e-6`, `num_train_epochs 2.0`, `cosine_with_min_lr` min 3e-7
(`:30-35`). Against the paper (1 epoch, batch 128, lr 3e-6): lr matches exactly; epochs **2×**, batch
**half**, plus an unlisted scheduler. `norm2code-example.yaml:2` chains the second phase from
`SK2DECOMPILE/saves/pseudo2norm-example` — skeleton→naming is sequential fine-tuning, not parallel
heads; cutoff/max_samples again 2048/100 (`:14-15`).

The example corpora show the task prompts and the placeholder grammar:
`data/pseudo2norm-examples.jsonl:1` — input `# This is the pseudo code:` + IDA-style pseudo-C
(`sub_4E05`, `v1/v2/v3`); `data/norm2code-examples.jsonl:1` — input `# This is the normalized code:`
with identifiers systematically renamed `func1`, `type1`, `var1`, `var2`, `field1/field2`, output the
original named source (`checkprotoprefix`, `SessionHandle`). Phase 1 output = phase 2 input: the
"skeleton" is this placeholder dialect.

## 7. SK² RL — VERL/GRPO scripts and four reward functions

**Scripts** (`sk2decompile/verl/SK2DECOMPILE/scripts/`). `run_struct_rl.sh`: `REWARD_VARIANT="exe_type"`
(options `exe_type`/`sim_exe`, `:23`), `NUM_NODES=2` (`:37`), `KL_COEF=0.01` (`:39`), Hydra
`--config-name='ppo_trainer-lm4dc.yaml'` (`:74`) — **this config file is not in the repo**
(`find . -name "*ppo_trainer*"` → zero hits), so the RL command as written cannot run;
`train_batch_size=128`, `max_prompt_length=1024`, `max_response_length=2048` (`:78-80`), actor lr
1e-6 (`:84`), `ppo_mini_batch_size=32` (`:86`), GRPO `rollout.n=16` (`:99`). `run_ident_rl.sh`:
embedding variant `gte` (options `gte`/`qwen3`, `:26`), 1 node (`:40`), `KL_COEF=0.02` (`:42`).
VERL is pinned: "based on VERL … v0.4.1" (`verl/SK2DECOMPILE/README.md:68`), `git checkout v0.4.1`
(`:73`; echoed at `sk2decompile/README.md:126,131`). The verl README's integration recipe: copy each
reward file into `verl/utils/reward_score/` (`:83-86`) and branch on the parquet `data_source`
field; parquet fields `prompt` (chat messages), `data_source`, `reward_model.ground_truth`,
`reward_model.style: "rule"`, `extra_info.header` (C headers for the compilability check, Structure
Recovery only) (`:111-115`); its hyperparameter table (`:156-165`) matches the scripts exactly
(batch 128 / 1024+2048 lengths / lr 1e-6 / KL 0.01 vs 0.02 / rollout 16 / 2 epochs); `:180` warns
about reward timeout when generated code loops forever (the 5 s `gcc` timeout below).

**Paper equations** (SK² v1, fetched): Eq. (3) — `r_placeholder = |I_gen ∩ I_IR| / |I_gen ∪ I_IR|`
(union Jaccard over placeholder-identifier sets), `r_structure = 0.0` if uncompilable else
`1.0 + r_placeholder`. Eq. (4) — `r_identifier = cos(e_gen, e_src)` (plain cosine on embeddings).

**Rewards as shipped** (`sk2decompile/verl/SK2DECOMPILE/reward_functions/`):

- `exe_type.py` (Structure Recovery): `compute_score` returns **0.0** if uncompilable, else
  `type_score + compileable_score` (`:21-28`) — structurally faithful to Eq. (3)'s gate. Placeholder
  scoring is regex-based: patterns `[r'\bfunc\w*\b', r'\btype\w*\b', r'\bvar\w*\b', r'\bfield\w*\b']`
  (`:39`) then Jaccard over the **union** (`:50-53`) — matches the paper's Eq. (3) denominator.
  Compilability is `gcc -c` with `timeout=5` (`:76-81`), and the paper's header protocol *is*
  wired: `extra_info.get('header','')` is prepended to the generated code before compiling
  (`:71-74`) — faithful to the dataset's `extra_info.header` field. One silent edge: the regex
  placeholder grammar only fires for the `funcN/typeN/varN/fieldN` dialect of §6, awarding 0
  placeholder reward to any other naming.
- `sim_exe.py` — a *second* Structure-Recovery reward not present in the paper at all: word-level
  Jaccard similarity of whole outputs plus compile score, **paid only if `sim_score > 0.5`**, else 0
  (`:19-25`). The script's `REWARD_VARIANT` switch chooses between paper-faithful and unpublished
  reward; which one produced the released weights is not documented.
- `embedding_qwen3.py` / `embedding_gte.py` (Identifier Naming): embedding-similarity rewards calling
  an OpenAI-compatible server, defaults `Qwen3-Embedding-0.6B` at `http://127.0.0.1:8000/v1`
  (`embedding_qwen3.py:36-38`) and `gte-large-en-v1.5` (`embedding_gte.py:36-38`); both parse
  identifiers with **tree-sitter** (`import … from tree_sitter`, e.g. `embedding_qwen3.py:31`) —
  the only Python that uses tree-sitter anywhere in the repo. Deviation: `embedding_qwen3.py:189`
  ends `return name_score * name_score` — the **square of the cosine**, sharpening the reward toward
  near-identical names versus the paper's plain Eq. (4) cosine. Same embedding model the paper names
  (qwen-embedding-0.6B), different objective.

So: the RL *hyperparameters* are triple-documented and consistent (scripts = verl README table =
compatible with the paper); the *objectives* deviate (squared cosine), compete (undocumented
`sim_exe` variant), and the entry config is missing — reproducing SK²'s RL from the repo alone fails
at the first command line.

## 8. The SK² data pipeline — one script, two copies, and a broken command

`sk2decompile/Preprocess/normalize_src_basedonpseudo.py` (212 lines) implements the pipeline in
`process_code` (`:134-141`): strip comments → hex→decimal → scrub compiler keywords (`__cdecl` etc.,
`remove_keywords` `:60-69`) → replace ~35 IDA typedefs with plain C (`replace_typedefs` `:115`, whose
static `typedef_map` spans `:74-114`) → clang-format (Google style, `format_with_clang` `:22`). **Nothing here
renames identifiers.** The `func1/type1/var1/field1` placeholder dialect of §6 is produced *nowhere*
in checked-in code — `grep -rn` for `re.sub`/rename/`func1`-style generators across every `.py` under
`sk2decompile/Preprocess/` and `sk2decompile/evaluation/` hits only comment-stripping and
clang-format wrappers (verified at `85b364b`) — the paper's skeleton-generation step has no shipped
implementation, and the example jsonl's dialect implies one that stayed closed.

File identity check: `sk2decompile/evaluation/normalize_pseudo.py` and
`sk2decompile/Preprocess/normalize_src_basedonpseudo.py` are **md5-identical**
(`7140bcfb712d1f4848c1a0d16f2c1414`, `md5sum` at HEAD) — the "two-step" pipeline in
`sk2decompile/README.md:82-93` (Step 1 `normalize_pseudo.py … --key_name pseudo`, Step 2
`normalize_src_basedonpseudo.py … --top`, Step 3 `format.py`, Step 4 `inf_type.py --generator
../psychec/psychecgen --solver …`, Psychec at `:61` only for reward-header inference) is **one
script run twice**. And Step 2 **fails as written**: the argparse block (`:204-209`, description
"并行处理 IDA 伪代码字符串列表") accepts exactly `--input_json`, `--output_json`, `--key_name`,
`--workers`, `--remove` — `--top` (README `:86`) is not among them, so the documented pipeline
crashes at Step 2 (Step 1's flags do parse).

**Prompt skew across the three surfaces** — the same task gets three different instruction strings:

| Surface | Prompt prefix | Cite |
|---|---|---|
| SFT training data (phase 1) | `# This is the pseudo code:` | `LLaMA-Factory/SK2DECOMPILE/data/pseudo2norm-examples.jsonl:1` |
| Inference, phase 1 (`sk2decompile_inf.py`) | `# This is the assembly code:` | `sk2decompile/evaluation/sk2decompile_inf.py:31-32`, fed `sample[args.decompiler]` (`:56`) — i.e. the *pseudo-code* column (`ida_pseudo`/`ghidra_pseudo`) is labeled "assembly code" |
| Inference, phase 2 (recovery) | `# This is the normalized code:` | `sk2decompile/evaluation/sk2decompile_inf.py:81-82,85` |

Phase 1's prompt matches the *2024* End-line template (`train/finetune.py:16-22`), not SK²'s own
training data — inference is calling its fine-tuned model with the wrong task name. Also in that
file: `--temperature 0` default (`:20`, greedy, per the paper) and `--recover_model_path` default
`'LLM4Binary/sk2decompile-ident-6.7'` (`:24`) — the broken repo name (HF is `-ident-6.7b`, §1), so
the shipped inference script cannot fetch its own default model (inventory §9 item 7; the community
mirror even adopted the broken name, §1).

## 9. Dataset ledger — seven repos, dates from the HF API

| Dataset | Created | License (card) | DL / likes | Substance |
|---|---|---|---|---|
| `decompile-ghidra-100k` | 2024-10-17 | MIT | 422 / 14 | 100k assembly↔Ghidra-pseudo pairs, 25k per -O level (`README.md:27`); V2/Ref training corpus |
| `decompile-bench` | 2025-05-12 | CC0 | 1036 / 16 | the DCBench training/eval condensate (2M pairs, 70K eval per `README.md:26`) |
| `decompile-eval` | 2025-05-13 | CC0 | 390 / 6 | eval corpus: splits `humaneval`, `mbpp`, `github2025` (card spells the first "huameval"); 75,610 rows / ~731 MB arrow (datasets-server info); columns incl. `asm`, `ida_asm`, `ida_pseudo`, `ghidra_asm`, `ghidra_pseudo`, `language`, `opt`, `test`; **C and C++** ("earlier models … were limited to C only", card) — this is the paper's evaluation set, re-released as an artifact 2025-05-13, five days after the bench |
| `decompile-bench-bins` | 2025-05-22 | MIT | 221 / 2 | the 450 GB of compiled binaries (§4 of ch.31) |
| `decompile-bench-raw` | 2025-06-05 | MIT | 746 / 4 | pre-condensation raw pairs (the paper's "100M collected") |
| `decompile-bench-makefile` | 2025-07-29 | CC0 | 30 / 1 | build harness that produced the corpus |
| `decompile-bench-raw-address` | 2025-09-05 | MIT | 34 / 1 | raw pairs with address/offset info (post-paper add-on) |

Two artifact-side facts: the v1.6 *models* carry one-line cards — the 6.7B one verbatim: "LLM4Decompile-DCBench, a 6.7 billion-parameter model trained on 10% of the Decompile-Bench, specifically designed to decompile C/C++ code" (raw card fetch) — and "10% of the Decompile-Bench" is the only training-data statement these repos contain, with no report anywhere of *which* 10%. README announcement dates drift from API creation dates by 1–8 days (V1.5 news `[2024-05-13]` vs created 2024-05-10; decompile-bench news `[2025-05-20]` vs created 2025-05-12) — the ladder (ch.21) uses README dates; this table uses HF dates. The 100k line's replication pitch —
"~3.5 hours on a single A100 40G GPU … 0.26 re-executability rate … under $20" (`README.md:27`) —
is a *separate, weaker* number than the same family's headline scores; it has never been updated in
either direction.

## 10. Effectiveness ledger — every number the project stands behind

As-published per checkpoint; contradictions are already itemized in inventory §9 (items 8–10) and
re-analyzed in chapter 32 — this table only pins *where each number lives* and which paper figure it
does or does not match:

| Artifact | Published claim | Source | Paper counterpart (2403.05286 v3, ch.31 §3) |
|---|---|---|---|
| 1.3b-v1.5 | 27.3% | `README.md:70` | 27.32 (End-1.3B) ✓ |
| 6.7b-v1.5 | 45.4% | `README.md:71` | 45.37 (End-6.7B) ✓ — but 16.22% under the DCBench harness (`decompile-bench/readme.md:65`, inventory §9 item 9) |
| 1.3b-v2 | 46.0% | `README.md:72` | 46.04 (Ref-1.3B) ✓ |
| 6.7b-v2 | 52.7% | `README.md:73` | 52.74 (Ref-6.7B) ✓ |
| 9b-v2 | 64.9% | `README.md:74`, and 0.6494 in the news bullet `README.md:29` | 64.94 (Yi-Coder base ablation, Table 11) ✓ |
| 22b-v2 | **63.6%** | `README.md:75` | 64.18 (Table 3 and 11) — **never reconciled** |
| 6.7b-uo | 0.219 | `README.md:32` | v1-era figure, superseded in v3 but never re-run |
| V2 line | "+40.1% over V1.5" | `README.md:30` | not a paper number; README-internal math (63.6 ÷ 45.4 − 1), inherits the 63.6 problem |
| V1.5 line | "over 100% improvement" | `README.md:31`, Note 3 `:77` | distorted echo of the paper's 160% Ref-vs-Ghidra framing |
| SK² (paper) | HumanEval re-exec AVG 69.00; GitHub2025 R2I 74.99; "+21.6% over GPT-5-mini", "+29.4% R2I over Idioms" | SK² Tables 1/2/4 (fetched); mirrored at `sk2decompile/README.md:219-220` | its own baseline "LLM4Decompile" scored **41.71 / 43.05** re-exec (Table 1) — far below the 52.74 the 2024 README advertises for 6.7b-v2, because the SK² harness runs C **and** C++ (§9's `decompile-eval` card); this gap is inventory §9 item 9 territory |
| SK² (repo) | BringUpBench 42.3% compile / 27.0% re-exec vs IDA Pro 23.6% / 21.7% | `sk2decompile/README.md:209` | no paper counterpart — BringUpBench appears only in the repo (and its Avg row doesn't average, inventory §9 item 10); the compared "IDA Pro" is not this project's artifact |

The shape of the ledger: the **v1.5/v2 README table reproduces the paper to two decimals** (except
22b's 63.6), while everything added after the paper — 40.1%, 100%, SK²'s own baseline row, the
BringUpBench numbers — is where the drift lives: three independent scoring harnesses (2024
HumanEval-Decompile, DCBench 2025, SK² 2025 C+C++) score the same checkpoints into different ranges,
and no artifact ever gets re-scored into a canonical table.

## Steal ideas for calxgloss

- **Artifact-ledger discipline** — one table binding every checkpoint to base config evidence,
  license source, creation date, and download reality (official vs mirror). calxgloss models/adapters
  should carry the same row set the day they are published, including the "config scrubbed" warning
  column.
- **Ship the run config or don't ship the script** — `ppo_trainer-lm4dc.yaml` and the
  `spliced_and_tokenized_dataset` module show how a dead import or missing Hydra config silently
  kills reproduction. Every script in calxgloss must resolve every path it names, asserted by a
  smoke test in CI (calxgloss has no CI today either — this is exactly what open P42 would buy).
- **Prompt-surface equality test** — the three-prompt skew (§8) is a one-line assertion in a test:
  the instruction string used in training data, inference, and docs must be byte-identical. Cheap,
  mechanical, and it is exactly how LLM4Decompile's SK² silently mislabels its own task.
- **Reward-as-code audit** — squared cosine vs paper cosine, undocumented `sim_exe` variant: when
  publishing RL results, calxgloss should diff reward implementations against the paper equations
  in the eval report itself.
- **HF tags are not licenses** — mirror their own `LICENSE-MODEL` pattern for weight reuse, but
  *contradict it nowhere*: cardData, repo LICENSE, and model card must state one license story; and
  community GGUFs out-download official weights 4:1 while propagating broken names, so release notes
  should pre-announce the exact canonical ID and expect mirrors.

## Sources

- Clone `/tmp/opencode/LLM4Decompile` @ `85b364b` — all `path:line` citations re-opened at that HEAD
  (2026-10-31): `README.md:27,29,30,31,32,70-77,79`; `train/finetune.py:16-22,46-51,95-97,132,171`;
  `train/README.md:31-52`; `train/run_training.sh:26-28,48,53,62`;
  `train/colossalai_llm4decompile/{run_llm4decompile_train.sh:12,29,32,37-40,47; prepare_pretrain_dataset.py:14-17; train.py:22,333}` (+ `ls colossal_llama/dataset/`,
  `git ls-files | grep -i spliced` → empty); `train/llama_factory_llm4decompile/README.md:11,16`;
  `sk2decompile/README.md:61,80,82-93,126,131,209,219-220`;
  `sk2decompile/LLaMA-Factory/SK2DECOMPILE/train/{pseudo2norm-example.yaml:2,13-15,30-35;
  norm2code-example.yaml:2,14-15}`; `sk2decompile/LLaMA-Factory/SK2DECOMPILE/data/{pseudo2norm,norm2code}-examples.jsonl:1`;
  `sk2decompile/verl/SK2DECOMPILE/README.md:68,73,83-86,111-115,156-165,180`;
  `sk2decompile/verl/SK2DECOMPILE/scripts/{run_struct_rl.sh:23,37,39,74,78-80,84,86,99;
  run_ident_rl.sh:26,40,42}`; `sk2decompile/verl/SK2DECOMPILE/reward_functions/{exe_type.py:21-28,39,50-53,71-74,76-81;
  sim_exe.py:19-25; embedding_qwen3.py:31,36-38,189; embedding_gte.py:36-38}`;
  `sk2decompile/evaluation/sk2decompile_inf.py:20,24,31-32,56,81-85`;
  `sk2decompile/Preprocess/normalize_src_basedonpseudo.py:22,60-69,78-114,134-141,204-209` (+ `wc -l` = 212);
  md5 comparison `evaluation/normalize_pseudo.py` ≡ `Preprocess/normalize_src_basedonpseudo.py`
  (`7140bcfb712d1f4848c1a0d16f2c1414`); `decompile-bench/readme.md:65`; absence checks:
  `find . -name "*ppo_trainer*"` → empty, tree-sitter imports confined to the two embedding rewards.
- Hugging Face (fetched 2026-10-31): `api/models?author=LLM4Binary` (+`expand[]=gated,cardData,…`),
  `api/models?author=arise-sustech&search=llm4decompile`, `api/models?author=mradermacher&search=llm4decompile`,
  `api/models?search=sk2decompile` (mradermacher wrong-name mirrors, Neo111x copy);
  `api/models/arise-sustech/llm4decompile-33b[/tree/main]` (133 GB, 14 weight files, card text);
  raw config fetches `LLM4Binary/llm4decompile-22b-v2`, `-6.7b-v1.6`, `_name_or_path` values for
  1.3b-v1.5/1.3b-v2/6.7b-v1.5/6.7b-v2/9b-v2/6.7b-uo, `mistralai/Codestral-22B-v0.1`;
  raw cards `LLM4Binary/llm4decompile-6.7b-v1.6`, `LLM4Binary/binaryLLM` ("TBD");
  gated 401s on `LLM4Binary/llm4decompile-{1.3b,6.7b}-v1` and anonymous 401 on SK²/33b/v1.6 raw-file
  fetches late in the session (list API remained open; numbers quoted from successful earlier fetches
  the same day).
- Hugging Face datasets: `api/datasets?author=LLM4Binary` (creation dates, `cardData.license`,
  downloads/likes for the seven §9 repos), `datasets-server.huggingface.co/info?dataset=LLM4Binary/decompile-eval`
  (75,610 rows, column list), raw card `datasets/LLM4Binary/decompile-eval` (splits, C/C++ statement).
- SK²Decompile arXiv v1 (saved fetch): Eq. (3) union-Jaccard + compilability gate, Eq. (4) plain
  cosine, §4 implementation paragraph (SFT 1 epoch / batch 128 / lr 3e-6; GRPO in veRL; 50K-sample
  RL subset; Psyche-C headers; qwen-embedding-0.6B; H800; vLLM greedy), Tables 1/2/4 (all SK² numbers
  quoted here re-read from the saved text).
- Cross-references, not re-derived here: ch.21's release ladder, inventory §9 items 7–10, ch.31 §3/§5.
