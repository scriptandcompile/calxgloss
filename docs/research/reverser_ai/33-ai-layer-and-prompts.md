# ReverserAI AI layer — LLM_Agent, prompts, models, sampling, token budget

> Part of the [ReverserAI overview](README.md). The LLM-facing half end to
> end: `gpt/function_name_gpt.py` (prompt + generation config),
> `gpt/agent.py` (model download + llama-cpp-python inference),
> `gpt/models.py` (GGUF registry), the two CLI scripts, the TOML config path,
> the context/token budget, and the reconstructed final prompt string the
> model actually sees. The BN-facing half is in
> [32 — Binary Ninja plugin](32-binary-ninja-plugin.md). All `path:line` cites
> are clone-relative at HEAD `1d572da` (tag v1.2, clone at
> `/tmp/opencode/reverser_ai`) unless a tag/commit is given.

## 1. Layering

```
FunctionNameGPTWrapper (BN side)      gpt/function_name_gpt.py   gpt/agent.py
  reads BN Settings, builds HLIL  →    hardcodes generation     →  LLM_Agent: hf_hub_download +
  text, applies rename                 config + prompt              llama_cpp.Llama raw completion
```

`LLM_Agent` is constructed at `gpt/function_name_gpt.py:44`
(`self.agent = LLM_Agent(config)`) and nowhere else; `FunctionNameGPT` is
constructed only by the wrapper (`binary_ninja/function_name_gpt_wrapper.py:25`)
and the two scripts. Despite the name, **`agent.py` contains no agent**: no
loop, no tools, no multi-turn state — one prompt in, one completion out
(§3). It shipped in the initial squashed release `cfa9908` (`git ls-tree
cfa9908` lists `reverser_ai/gpt/agent.py`); the v1.1 feature commit `eb940ea`
added context-enriched *naming* (see file 32 §5), not the agent. `cfa9908→HEAD`
diff on agent.py is cosmetic except one line (5597fb7, below).

## 2. `gpt/function_name_gpt.py` (123 lines)

### Generation config — hardcoded overrides

`FunctionNameGPT.__init__` mutates the caller's config dict
(lines 15-44):

- `config["n_context"] = 4000` (line 27) — llama-cpp context window.
- `config["generation_kwargs"]` (lines 30-41), quoted verbatim:

```python
"max_tokens": 5000,      # line 32
"stop": ["</s>"],        # line 34
"min_p": 0.1,            # line 36
"temperature": 0.8,      # line 38
"repeat_penalty": 1,     # line 40
```

`max_tokens` (5000, line 32) **exceeds** `n_ctx` (4000, line 27):
llama-cpp-python v0.2.56 clamps `max_tokens` to `n_ctx - len(prompt_tokens)`
inside `_create_completion`, so the real generation budget is the remaining
window, and 5000 is inert. Unset sampling knobs stay at llama-cpp defaults
(`top_k=40`, `top_p=0.95`); `repeat_penalty: 1` *disables* the llama-cpp
default 1.1 penalty. Comments call these "empirically determined values"
(line 29). Identical numbers shipped in v1.0 (`v1.0:gpt/function_name_gpt.py:33-44`).

### Prompt construction — `build_prompt(code)`, lines 46-64

```python
user_prompt = (
    f"<s>[INST]Given the following decompiler output for a function, "
    f"analyze its operations, logic, and any identifiable patterns to suggest a suitable function name. "
    f"Your response should strictly be the function name suggestion and up to 20 characters. "
    f"Discard all explanations or content, only the suggested name.[/INST] add_two_values</s> "
    f"[INST]Here's the code:\n {code}[/INST]"
)
return self.agent.build_prompt(user_prompt)
```

That is a **one-shot** Mistral `[INST]` dialogue: instruction turn 1, whose
"assistant answer" is the literal `add_two_values` (line 61) — a format
example only, with no example code attached — then instruction turn 2
carrying the HLIL (`code` is inserted after `Here's the code:\n `, line 62,
one space + the tab-indented HLIL lines). The string is byte-identical to
v1.0 (`v1.0:gpt/function_name_gpt.py:60-66`) — the prompt has **never been
tuned in the public history** (`git log -S "add_two_values"` → only
`cfa9908`). No callee names, strings, or symbols are ever appended — the
"context enrichment" of v1.1 works by *selection and ordering*, and by
renamed callee names already appearing inside BN's HLIL text (file 32 §5).

### Error path — `get_function_name_suggestion(code)`, lines 79-98

```python
try:
    suggested_name = self.query_gpt_for_function_name_suggestion(code)
    return self.filter_output(suggested_name)
except Exception as exc:
    raise ValueError(
        "Failed to query the LLM for a name suggestion. The input code may exceed the maximum token limit supported by the LLM."
    ) from exc
```

Any exception → one `ValueError` (lines 94-98), caught upstream by the BN
wrapper which logs a warning and skips the rename (file 32 §10). v1.0 behaved
differently: signature `get_function_name_suggestion(self, original_name,
code)` with a **bare `except:` returning the original name**
(`v1.0:gpt/function_name_gpt.py:82, 97-99`) — silent failure; fixed in
`aeb265c` ("Do not silently fail in case of too long code inputs; catch error
about too much tokens", which also introduced the wrapper's try/except +
BN logging).

### Output normalization — `filter_output(output)`, static, lines 100-123

Entire cleaning, in order: `output.strip()` → take **first line only** via
`split("\n")[0]` (line 119) → `.replace("\\_", "_")` (unescape markdown'd
underscores) and `.replace("`", "")` (strip code fences/inline backticks)
(line 121). History: v1.0 lacked backtick stripping; `2ec64bb` ("added
documentation to filter/normalization function") both documented and added
the backtick rule while reformatting.

**There is no validation of the suggestion**: no identifier charset check, no
length check (despite the prompt's "up to 20 characters"), no rejection of
empty strings, sentences, or a regenerated `sub_…` name — whatever survives
lines 119-121 is handed to the BN rename (file 32 §10 applies it whenever the
target function was anonymous `sub_*`). Determinism comes only from
`seed: 0` default + fixed sampling.

## 3. `gpt/agent.py` (97 lines) — "LLM_Agent"

Class `LLM_Agent` (line 7), constructed once by the BN singleton (file 32
§4). Three methods plus `__init__`:

- **`__init__` (18-56)** reads exactly these config keys: `n_context` (28),
  `use_mmap` (30), `n_threads` (32), `n_gpu_layers` (34),
  `model_identifier` (36), `seed` (38), `verbose` (40), `generation_kwargs`
  (42). Line 36 is the one semantic change since `cfa9908`: v1.0 received an
  already-resolved `(repo, file)` tuple from `FunctionNameGPT`
  (hardcoded, `v1.0:gpt/function_name_gpt.py:28`); `5597fb7` ("added model
  selection") changed agent.py to `MODEL_IDENTIFIERS[config["model_identifier"]]`
  — a *key string* lookup, matching the BN settings enum value.
- **Model download, `get_model_path` static (58-70)**:
  `hf_hub_download(model_name, filename=model_file)` (line 70) — side effect
  of construction (line 45); default HF cache; no checksum/pinning beyond the
  filename, no offline mode, no resumable pre-check. `from huggingface_hub
  import hf_hub_download` (line 1) and `from llama_cpp import Llama` (line 2).
- **`Llama(...)` (48-56)** maps repo config to llama-cpp-python params:

| `Llama` kwarg (line) | Value source | Default path |
|---|---|---|
| `model_path` (49) | `hf_hub_download` result | first-use download |
| `use_mmap` (50) | `reverser_ai.use_mmap` / TOML | `true` |
| `n_ctx` (51) | hardcoded 4000 (fn:27) | not user-tunable |
| `n_threads` (52) | `…​.n_threads` | `0` → llama-cpp-python: `n_threads or max(cpu//2, 1)` = half the cores |
| `n_gpu_layers` (53) | `…​.n_gpu_layers` | `99` (offload everything) |
| `seed` (54) | `…​.seed` | `0` = fixed seed (context params; llama.cpp's "random" is `LLAMA_DEFAULT_SEED`, not 0) |
| `verbose` (55) | `…​.verbose` | `false` |

  No `n_batch`, `chat_format`, `use_mlock`, `low_vram`, or vocab overrides —
  all llama-cpp defaults (file 32 §7 notes the misleading `n_threads=0`
  description).
- **`build_prompt` static (72-83)**: the last piece of the template —
  `return f"{user_prompt}\n### Response:"` (line 83). This `### Response:`
  suffix is a **Llama-2-era leftover**: the prompt from `function_name_gpt`
  is Mistral-format and already ends with the assistant-start marker
  `[/INST]`, so `\n### Response:` lands *inside* turn 2 as stray user text
  before generation. It shipped this way in `cfa9908` and was never removed.
- **`generate_response` (85-97)**: raw **completion**, not chat:

```python
res = self.llm(prompt, **self.generation_kwargs)   # line 96 — Llama.__call__ → create_completion
return res["choices"][0]["text"]                   # line 97
```

  No `create_chat_completion`, no `chat_format` configured — the chat
  template the model was trained with is hand-rebuilt in Python (lines
  57-63 + 83). `stop=["</s>"]` plus llama-cpp's built-in EOS break both
  terminate at `</s>`. Multi-query KV prefix reuse works incidentally via
  llama-cpp's longest-prefix cache in `generate` (the shared one-shot header
  stays in cache across calls within one Llama instance).

## 4. `gpt/models.py` (46 lines) — the GGUF registry

Plain dict `MODEL_IDENTIFIERS` (lines 9-46), values `(HF repo, filename)`
tuples — no dataclasses, no enums. Quoted exactly:

| Key | HF repo | File | Lines |
|---|---|---|---|
| `mythomax_13b` | `TheBloke/MythoMax-L2-Kimiko-v2-13B-GGUF` | `mythomax-l2-kimiko-v2-13b.Q6_K.gguf` | 17-20 |
| `mistral-7b-instruct` | `TheBloke/Mistral-7B-Instruct-v0.2-GGUF` | `mistral-7b-instruct-v0.2.Q4_K_M.gguf` | 29-32 |
| `mixtral-8x7b-instruct` | `TheBloke/Mixtral-8x7B-Instruct-v0.1-GGUF` | `mixtral-8x7b-instruct-v0.1.Q4_K_M.gguf` | 42-45 |

- `mythomax_13b` is **dead from the plugin's point of view**: the BN settings
  enum only offers the two instruct keys (`__init__.py:111-114`) — but it is
  still reachable through the TOML path (any string key passes
  `load_user_config` → `MODEL_IDENTIFIERS[...]`, agent:36). Its comment
  (lines 10-16) recommends it for "offensive language or requests… not
  censored" — an uncensored chat model with no code-naming rationale; it is
  the only non-instruct entry and no prompt in the repo is tuned for it.
- RAM footprints are **documentation claims, not code facts**: ~5GB
  (mistral) and ~25GB (mixtral, models.py line 36 comment "approximately 25
  GB"). The 25 figure replaced "approximately 45 GB" — mixtral was added in
  `c318f28` ("added more powerful model to model file -- not yet
  configurable", with the 45GB comment) and corrected in `456bc1e` ("fixed
  documentation of model size: 25 gb instead of 45 gb") across
  `README.md`, root `__init__.py` enum description, `example_config.toml`,
  and the models.py comment. The instruct comments (21-28, 33-41) are prose
  marketing ("ideal choice for generating function names…") with no
  measurable basis in the repo.
- Quat choice (Q4_K_M / Q6_K) is baked into the tuples; users cannot pick a
  quantization without editing this file.

## 5. Scripts

### `scripts/gpt_function_namer.py` (62 lines) — not a typer CLI

Despite `typer>=0.11` being a declared dependency since `845626f` ("added
typer requirement"), **`typer` is imported nowhere** in the repo (grep: 0
hits in `*.py`). The script is hand-rolled: `sys.argv[1]` = path to a TOML
config, with a manual length check and `sys.exit(1)` (lines 36-43). It takes
**no binary, no BN database, no function** at all — the "target" is a
*hardcoded synthetic C function* `generate_xor_c_function()` (lines 6-24:
`unsigned int example(...) { result = param_1 ^ param_2; return result; }`,
deliberately Ghidra-styled) to smoke-test model quality. Flow:
`load_user_config` (46) → `FunctionNameGPT(config)` (49, triggers
download+load) → suggestion (55) → `print(f"Suggested name: {suggested_name}")`
(58). README "Parameter Tuning" shows the demo output (`xor_two_numbers`).
v1.0/v1.1 bug fixed in `84b1a3e` (issue #5): line 55's argument was the
string literal `"c_function_code"` — the demo was prompting the model with
those 15 characters instead of the XOR function until then.

### `scripts/model_download.py` (38 lines) — pre-fetch helper

An inline config dict (lines 18-31) with `model_identifier =
"mistral-7b-instruct"` (line 20) → `FunctionNameGPT(config)` (line 34), whose
constructor chain performs the `hf_hub_download` (agent:45,70) before the
wastefully-real `Llama(...)` load. It pre-fetches **only the model literally
written in the file** — switching to mixtral means hand-editing line 20 (the
comment there lists the two options). Runs at import: bare
`initiate_download()` call at line 38. Quirk: line 22 sets `"use_mmap":
False` under the comment "Enables partial on-demand loading of the model into
memory using mmap" — the comment contradicts the value (False *disables*
mmap, forcing a full ~5GB read into RAM for the throwaway load); `n_threads:
0` / `n_gpu_layers: 0` comments likewise describe intent at odds with
llama-cpp defaults.

## 6. `config.py` + `example_config.toml` — the second, plugin-bypassed config system

- `reverser_ai/config.py` (22 lines): `load_user_config(config_path)` = `open`
  + `toml.load` (lines 17-22). No schema validation, no defaults for missing
  keys, no path handling — a missing key later raises `KeyError` inside
  `LLM_Agent.__init__` (agent:28-42).
- Consumers: **only** `scripts/gpt_function_namer.py:46`. The BN plugin uses
  the BN Settings API exclusively (file 32 §7) — no code anywhere joins the
  plugin directory with `example_config.toml`. The intended lookup helper
  `get_plugin_directory()` (`reverser_ai/utils.py:4-19`, returns the plugin
  root two `os.path.dirname` levels up from `utils.py`) has **zero callers**
  — dead evidence of an earlier TOML-based plugin config. `reverser_ai/utils.py`
  contains *only* that function; it is not a logging setup.
- `example_config.toml` (24 lines) keys/defaults: `model_identifier =
  "mistral-7b-instruct"` (9), `use_mmap = true` (12), `n_threads = 0` (15),
  `n_gpu_layers = 99` (18), `seed = 0` (21), `verbose = false` (24) — same six
  knobs as the BN settings, with the same RAM comments (~5GB line 11,
  ~25GB line 6) and the header comment block (3-8) describing the two models.
  v1.0 shipped it without `model_identifier` (added by `5597fb7`).
- Model keys and RAM footprints are documented in three parallel places
  (BN enum descriptions `__init__.py:115-118`, `example_config.toml:3-8`,
  models.py comments) — a drift hazard; `456bc1e` had to touch all four
  surfaces at once.

## 7. Context/token budget — what happens to a big function

Fixed numbers: window `n_ctx = 4000` (`function_name_gpt.py:27` →
`agent.py:51`); requested `max_tokens = 5000` (line 32, clamped by
llama-cpp-python to `n_ctx - prompt_tokens`); fixed prompt overhead
(instruction + one-shot + `### Response:` suffix) ≈ 60-70 tokens, plus the
BN function-header line and tab-indented HLIL (`wrapper:64-66`).

For an HLIL dump whose tokenization pushes total prompt tokens ≥ 4000,
llama-cpp-python v0.2.56 raises `ValueError("Requested tokens (N) exceed
context window of 4000")` from `_create_completion` — the repo performs **no
truncation, chunking, or summarization anywhere**. The exception path
(`function_name_gpt.py:94-98` → `ValueError` → `binary_ninja/function_name_gpt_wrapper.py:96-97`)
logs `Function sub_XXXX: Failed to query the LLM…` and the function is simply
left unnamed. So oversized functions fail *soft and silently at scale*
(one log line), and note `n_ctx=4000` is well under the models' native
windows (Mistral v0.2: 8k, Mixtral: 32k) — a self-imposed ceiling, not a
hardware one. `max_tokens > n_ctx` and the inert `repeat_penalty: 1` are two
more signs the knobs were set once and never revisited.

## 8. The actual final prompt string (reconstructed)

Composed from `function_name_gpt.py:57-63` (one-shot dialogue) +
`agent.py:83` (`\n### Response:`) + `wrapper:64-66` (header + HLIL lines). For
a function BN has not yet named, whose callee was renamed earlier by the
bottom-up order (file 32 §5), the model sees literally:

```text
<s>[INST]Given the following decompiler output for a function, analyze its operations, logic, and any identifiable patterns to suggest a suitable function name. Your response should strictly be the function name suggestion and up to 20 characters. Discard all explanations or content, only the suggested name.[/INST] add_two_values</s> [INST]Here's the code:
 Function sub_20a0 @ 0x20a0
	if (arg1 == arg2)
		return 0
	int32_t v0 = copy_buffer_2100(arg1, arg2)
	return v0 ^ 0x2b
[/INST]
### Response:
```

(Header line text is BN's `Function.__str__`; body lines are HLIL with the
wrapper's tab prefix — reconstructed, structure and literal framing from the
cited lines.) Notes:

- No system message, no chat API — raw completion against a hand-rolled
  **Mistral v0.1-style** template (`<s>[INST] … [/INST]`), while the default
  model is Mistral-7B-**Instruct-v0.2** (GGUF chat template is `<|im_start|>`-
  based). The explicit `<s>`/`</s>` literals work because llama-cpp-python
  tokenizes completions with `special=True`, mapping them to the BOS/EOS
  control tokens; an automatic BOS is prepended on top (double-BOS-ish
  redundancy).
- `[/INST]` of turn 2 *is* the assistant-start marker; everything after it —
  including the stray `\n### Response:` from `agent.py:83` — is model input
  the completion then follows.
- Context enrichment is visible only as `copy_buffer_2100(...)` in the HLIL:
  a callee's freshly-applied name flows into the parent's prompt because BN
  renders callee names in HLIL, and C2 renames callees first
  (`binary_ninja/__init__.py:139`). Nothing else marks callees, symbols, or
  strings as "context".
- Sampling at generation time: temperature 0.8, min_p 0.1, repeat_penalty 1,
  stop `</s>`, with llama-cpp defaults top_k 40 / top_p 0.95 —
  **non-greedy**, so the "deterministic" promise (`seed` description,
  `__init__.py:82`) rests on the fixed seed only.

## 9. Absences (factual, for later judgment)

- No identifier validation, length cap, dedup, or collision check on model
  output (§2; wrapper applies whatever `filter_output` returns).
- No output-parsing beyond "first line"; multi-line ramblings become their
  first line, possibly a sentence.
- No use of llama-cpp's `chat_format`/grammar/logprobs; no temperature/top_p
  surfaced to users; no token counting before the call.
- `typer` declared, never imported (§5); `get_plugin_directory()` dead (§6);
  `mythomax_13b` unreachable from the UI (§4); `n_context`/`max_tokens` not
  user-configurable despite the "parameter tuning" story.
- Model download/load happens inside the first command's background task
  (file 32 §4) — a 5-25GB fetch with no progress UI beyond BN's indeterminate
  bar.

## Sources

- Clone `/tmp/opencode/reverser_ai`, HEAD `1d572da` (v1.2):
  `reverser_ai/gpt/{function_name_gpt,agent,models}.py`,
  `reverser_ai/{config,utils}.py`, `scripts/{gpt_function_namer,model_download}.py`,
  `reverser_ai/binary_ninja/function_name_gpt_wrapper.py`,
  `example_config.toml`, `requirements.txt`, `README.md` — every file read in
  full; grep for `typer`/`get_plugin_directory` callers.
- Historical states via `git show`: `v1.0:gpt/function_name_gpt.py:28,31-42,57-63,82,97-99`,
  `v1.0:gpt/agent.py:36`; commits `cfa9908` (initial squashed release,
  includes agent.py per `git ls-tree`), `c318f28`, `aeb265c`, `2ec64bb`,
  `eb940ea`, `5597fb7`, `845626f`, `84b1a3e`, `456bc1e`; `git log -S` for
  `add_two_values` (never changed) and backtick stripping.
- llama-cpp-python v0.2.56 `llama_cpp/llama.py` (pinned upstream source):
  `Llama.__init__` (`n_threads or max(cpu_count()//2, 1)`, context-params
  `seed`), `_create_completion` ("Requested tokens (…) exceed context window
  of …", `max_tokens` clamp to `n_ctx - len(prompt_tokens)`), `generate`
  prefix-cache.
- Related dossiers: [20 — inventory](20-reverser-ai-inventory.md),
  [21 — history](21-history-and-releases.md),
  [32 — Binary Ninja plugin](32-binary-ninja-plugin.md).
