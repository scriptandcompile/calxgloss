# 33 — LLM provider layer: 9 transports, OAuth, extended thinking, message formats

> Part of the [overview](README.md). Clone HEAD 09dd910d…, written 2026-11-02.

All line numbers verified against `/tmp/opencode/IDAssist` at `09dd910d70016c7b3f7e8bc01a4d5bc1035ec302`.

## 1. The ProviderType enum at HEAD

`src/services/models/provider_types.py` (234 LOC) defines **12 members**, each with a display name (`get_display_names`, :49-71), a default URL (`get_default_urls`, :73-95), a default-model list (`get_default_models`, :97-150), and membership in five capability sets (`supports_embeddings` :152-161, `supports_tool_calls` :163-179, `supports_streaming` :181-197, `requires_api_key` :199-207, `uses_oauth` :209-215).

| Member (value) | Display name | Default URL | Default models (:98-150) | embeddings / tools / stream / api_key / oauth |
|---|---|---|---|---|
| `ANTHROPIC_CLI` = `"anthropic_cli"` (:26) | "Anthropic CLI (Claude Code)" | `""` (CLI-based, :78) | `sonnet, opus, haiku` (:102-104) | – / ✔ / **✘** / – / – |
| `ANTHROPIC_PLATFORM` (:27) | "Anthropic Platform API" | `https://api.anthropic.com` | `claude-3-5-sonnet-20241022`, `claude-3-5-haiku-20241022`, `claude-3-opus-20240229`, `claude-3-sonnet-20240229` | – / ✔ / ✔ / ✔ / – |
| `LITELLM` (:30) | "LiteLLM Proxy" | `http://localhost:4000` | *(empty list — "models are dynamic", :125-127)* | ✔ / ✔ / ✔ / – / – |
| `LMSTUDIO` (:31) | "LM Studio" | `http://localhost:1234/v1` | `microsoft/DialoGPT-medium`, `microsoft/DialoGPT-large` | ✔ / ✔ / ✔ / – / – |
| `OLLAMA` (:32) | "Ollama" | `http://localhost:11434` | `llama3.1:8b/70b, codellama:7b, mistral:7b, phi3:mini, qwen2:7b` | ✔ / ✔ / ✔ / – / – |
| `OPENWEBUI` (:33) | "Open WebUI" | `http://localhost:3000` | `gpt-4o, claude-3-5-sonnet, llama3.1:8b` | ✔ / ✔ / ✔ / – / – |
| `GEMINI_OAUTH` (:36) | "Gemini OAuth (Gemini CLI)" | `https://cloudcode-pa.googleapis.com` | `gemini-2.5-flash/-pro, gemini-2.0-flash/-lite` | – / ✔ / ✔ / – / ✔ |
| `GEMINI_PLATFORM` (:37) | "Gemini Platform API" | `https://generativelanguage.googleapis.com/v1beta/openai/` | same as GEMINI_OAUTH | – / ✔ / ✔ / ✔ / – |
| `OPENAI_OAUTH` (:40) | "OpenAI OAuth (ChatGPT Pro/Plus)" | `https://chatgpt.com/backend-api/codex/responses` | `gpt-5.2-codex, gpt-5.1-codex-max, gpt-5.1-codex-mini, gpt-5.2` | – / ✔ / ✔ / – / ✔ |
| `OPENAI_PLATFORM` (:41) | "OpenAI Platform API" | `https://api.openai.com/v1` | `gpt-4o, gpt-4o-mini, gpt-4-turbo, gpt-3.5-turbo` | ✔ / ✔ / ✔ / ✔ / – |
| `BEDROCK` (:44) | "AWS Bedrock" | `""` — "Uses boto3 client, no URL needed" (:81) | `anthropic.claude-sonnet-4-6`, `anthropic.claude-haiku-4-5`, `anthropic.claude-opus-4-5`, `amazon.nova-pro-v1:0`, `amazon.nova-lite-v1:0`, `meta.llama3-3-70b-instruct-v1:0` | – / ✔ / ✔ / – / – |
| `XAI_PLATFORM` (:47) | "xAI Platform API" | `https://api.x.ai/v1` | `grok-3-mini, grok-3` | – / ✔ / ✔ / ✔ / – |

The stream set explicitly excludes the CLI: "Note: ANTHROPIC_CLI does NOT support true streaming" (:185).

### Divergences vs README.md:126-135 and docs/tabs/settings-tab.md:55-61 — both directions

| Direction | Finding |
|---|---|
| Docs claim, code lacks | `anthropic_oauth` still listed at README.md:130 and docs/tabs/settings-tab.md:58 — no such enum member at HEAD (removed in e2e5529; `grep -n "ANTHROPIC_OAUTH" src/` returns nothing). |
| Docs claim, code lacks (name mismatch) | Both docs say the type string is `anthropic_claude_cli` (README.md:131, settings-tab.md:59); the enum value is `anthropic_cli` (provider_types.py:26). A `llm_providers.provider_type` row containing `anthropic_claude_cli` would fail factory construction with "Unsupported provider type" (provider_factory.py:74-75). |
| Docs claim, code lacks (capability) | settings-tab.md:59 marks `anthropic_claude_cli` Streaming = "Yes"; provider_types.py:185 says it does **not** support true streaming (the provider *simulates* it — see §5.4). |
| Code has, docs lack | `GEMINI_OAUTH`, `GEMINI_PLATFORM`, `LMSTUDIO`, `OPENWEBUI`, `XAI_PLATFORM` are all registered in the factory (provider_factory.py:164-186) but appear in **neither** README.md:126-135 nor the settings-tab provider table (`grep -n "gemini\|openwebui\|lmstudio\|xai" README.md docs/tabs/settings-tab.md` → zero hits; ditto case-insensitive — those provider names appear nowhere in the two docs; *corrected 2026-11-02 — earlier draft's "only the two stale rows above match" wrongly implied the grep matched them; the two stale `anthropic_claude_cli` rows are a separate finding*). |

*(inference)* The docs table predates the Gemini/OpenWebUI/LMStudio/xAI expansion and was never refreshed after the `anthropic_oauth` removal — consistent with [ch21 §6](21-history-and-releases.md)'s finding that the README lags the code.

## 2. The abstract contract (`base_provider.py`, 574 LOC) and `llm_models.py`

The interface is **not** `chat()`/`chat_stream()`. Abstract methods (:227-330):

- `async chat_completion(request, native_message_callback=None) -> ChatResponse` (:228)
- `async chat_completion_stream(request, native_message_callback=None) -> AsyncGenerator[ChatResponse, None]` (:250)
- `generate_embeddings`, `test_connection`, `get_capabilities`, `get_provider_type`; plus an overridable `discover_available_models` returning `ProviderModelDiscoveryResult` (:311-320).

**Streaming callback contract**: there are no per-chunk callbacks. A provider yields *partial* `ChatResponse` deltas (text-only, `is_streaming=True`, `finish_reason="incomplete"` or `""`), then a final `ChatResponse` with `is_streaming=False`, real `usage`, `tool_calls`, and the mapped finish reason (see bedrock_provider.py:403-410, openai_oauth_provider.py:962-972). The **only** callback parameter is `native_message_callback(native_message: Dict, provider_type: ProviderType)` (:229-236 docstring), used once per completion to hand the provider-native message shape to storage. Base helpers:

- `DEFAULT_PROVIDER_TIMEOUT_SECONDS = 90.0` (:20), normalized by `_normalize_timeout_seconds` (:61-70).
- Rate-limit retry: `_with_rate_limit_retry` / `_with_rate_limit_retry_stream` (:109-225) — defaults **50 retries**, random delay **10-30 s** (`rate_limit_max_retries`, `rate_limit_min_delay`, `rate_limit_max_delay`, :57-59); non-rate-limit errors propagate immediately (:160-162).
- `_persist_oauth_api_key` (:72-103): writes a refreshed credential blob back to the provider row (`update_llm_provider(id, api_key=…)` or by name).
- Tool-surface defaults: `prepare_tool_enabled_request` (:346-380, sets `tool_choice=request.tool_choice or "auto"`), `parse_tool_calls`, `get_stop_reason` (returns `response.finish_reason`, :400-410), `format_tool_results_for_continuation` (OpenAI `role:"tool"` shape, :412-437).
- Fallback token counting: character-based `len//4` (:456-518).

`llm_models.py`: `ChatRequest` defaults `max_tokens=4096, temperature=0.7, top_p=1.0, stream=False` (:67-80); `ChatMessage.native_content` (:58) and `ChatResponse.native_content` (:102) carry "provider-specific structured content (e.g., Anthropic content blocks)"; `ToolCall.call_id` aliases `id` (:27-32); `stopped_for_tool_calls` treats `finish_reason=="stop"` + tool calls as a tool stop (:110-112); `ProviderCapabilities.max_tokens` also defaults 4096 (:142). Exception hierarchy `LLMProviderError / APIProviderError / AuthenticationError / RateLimitError / NetworkError` at base_provider.py:552-574.

## 3. Factory mapping (`provider_factory.py`, 229 LOC)

`LLMProviderFactory._register_default_factories` (:96-188) registers, each guarded by `try/except ImportError: pass`:

| ProviderType(s) | Implementation |
|---|---|
| `ANTHROPIC_CLI` | `AnthropicClaudeCliProvider` (:101-108) |
| `ANTHROPIC_PLATFORM` | `AnthropicPlatformApiProvider` (:110-118) |
| `BEDROCK` | `BedrockProvider` (:120-128) |
| `LITELLM` | `LiteLLMProvider` (:130-137, local `LiteLLMProviderFactory` :204-214) |
| `OLLAMA` | `OllamaProvider` (:139-147) |
| `OPENAI_OAUTH` | `OpenAIOAuthProvider` (:149-157) |
| `OPENAI_PLATFORM` **and** `LMSTUDIO`, `XAI_PLATFORM`, `GEMINI_PLATFORM` | **one shared** `OpenAIPlatformApiProviderFactory` (:159-168: "handles OpenAI-compatible APIs with /v1 bases") |
| `OPENWEBUI` | `OpenWebUIPlatformApiProvider` (:170-178) |
| `GEMINI_OAUTH` | `GeminiOAuthProvider` (:180-188) |

Unknown string → `LLMProviderError("Unsupported provider type: …")` (:74-75); default `provider_type` when the key is missing is `"openai_platform"` (:67). Global singleton `get_provider_factory()` (:224-229).

## 4. Per-provider matrix

| Provider (LOC) | Transport | Sync/async | Auth | Tool-call accumulation | Thinking request/capture |
|---|---|---|---|---|---|
| `openai_platform_api_provider.py` (761) | OpenAI SDK (`OpenAI(...)`, :62-68) with custom `httpx.Client` (:79-92) | **sync SDK inside async defs** — `self._client.chat.completions.create(...)` :194 and :353 called directly (no `to_thread` in the chat path; `to_thread` appears once, at :602 for `models.list`) | Bearer API key; placeholder `"not-needed"` for keyless bases (:60) | index-keyed `delta.tool_calls` accumulation (:382 comment "properly accumulate across chunks") | `reasoning_effort` string for non-o\* models (:182-187); o\*/gpt-5 use `max_completion_tokens` (:164-166) |
| `openai_oauth_provider.py` (1128) | **raw aiohttp SSE** to `chatgpt.com/backend-api/codex` | true async | ChatGPT OAuth bearer + forged Codex CLI headers (:348-355) | final only: `response.output_item.done` items (:913-928); argument deltas are `pass` (:909-911) | none — no `reasoning_effort`/thinking params (grep over file) |
| `anthropic_platform_api_provider.py` (1092) | `anthropic` SDK, `messages.create` / `messages.stream` | sync SDK **wrapped in `asyncio.to_thread`** (:151, :308, :858) | Bearer API key (:54-55 requires it) | `building_tool_calls: Dict[str, Dict]` keyed by tool id (:312) | `thinking:{type:"enabled",budget_tokens}` (:144-147); thinking blocks + signatures captured (:368-401, :440-447) |
| `anthropic_claude_cli_provider.py` (549) | **subprocess** `claude --print --model …` via `asyncio.create_subprocess_exec`, prompt on stdin (:264-276) | async subprocess | whatever the CLI has logged in; no key handling | post-hoc text scraping: `_extract_tool_calls(response_text)` (:422) | none; usage is `len//4` estimates (:321-325) |
| `ollama_provider.py` (717) | raw `httpx.AsyncClient` NDJSON to `/api/chat` (:65-69, payload `"stream": False/True` :89, :249) | true async | none | complete `tool_calls` arrive in streamed `message` chunks; final `done:true` flush (:370-407) | `payload["think"]` at TOP LEVEL: effort string for gpt-oss, else `True` (:101-111) |
| `litellm_provider.py` (957) | **subclasses `OpenAIPlatformApiProvider`** (:28) — OpenAI SDK against the proxy URL; the `litellm` package is never imported (`import openai` :12-14) | same sync-SDK quirk as openai_platform (`self._client.chat.completions.create` inside `_create_completion_with_compatibility`, :465-482) | proxy key via OpenAI SDK | `_normalize_nonstream_response` (:164-221) | model-family dispatch: OpenAI family → `reasoning_effort` string; Anthropic family → `extra_body["thinking"]={type,budget_tokens}`; other families skipped (:272-298) |
| `bedrock_provider.py` (706) | **boto3 `converse`/`converse_stream`** (:273, :384); sync boto3 inside async defs — `grep -c "to_thread" bedrock_provider.py` → 0 | sync in async | AWS credential chain: explicit keys → profile → default (:77-97); `aws_region` default `us-east-1` (:42) | `tool_input_buffers[contentBlockIndex] += toolUse.input` string concat (:412-420); `tool_use` blocks start at `contentBlockStart` | none — `_build_inference_config` only maps maxTokens/temperature/topP/stopSequences (:153-166) |
| `gemini_oauth_provider.py` (817) | raw aiohttp POST to Code Assist RPC: `https://cloudcode-pa.googleapis.com/v1internal:generateContent` / `:streamGenerateContent?alt=sse` (:52-53, :233, :502, :561), request wrapped in `{model, project, user_prompt_id, request:{…}, session_id}` envelope (:409-424) | true async; client-side throttle `MIN_REQUEST_INTERVAL_S = 2.0` (:59, :204-212) | Google OAuth bearer + faked UA `GeminiCLI/1.0.0/<model> (plat; arch)` (:190-201) | per-part `functionCall` parts, id minted locally `call_{uuid}` (:613-620) | no thinkingConfig requested; replay stamps `"thoughtSignature": SYNTHETIC_THOUGHT_SIGNATURE` = `"skip_thought_signature_validator"` (:56, :306) |
| `openwebui_platform_api_provider.py` (**78**, not ~7xx) | inherits OpenAI SDK provider; only overrides URL plumbing — appends `/api` (configurable `api_base_path`) to the base URL (:23-68) | as openai_platform | Bearer key via SDK | as openai_platform | as openai_platform |

## 5. Provider notes and telling quotes

**5.1 openai_platform (761)** — `OpenAI(api_key=…, base_url=…, timeout=…, max_retries=0,  # We handle retries ourselves` (:65-67); `_is_reasoning_model` matches `o1/o2/o3/o4/gpt-5` prefixes (:94-101) and then switches to `completion_kwargs["max_completion_tokens"]` while dropping temperature (:164-166). `bypass_proxy` maps to `httpx.Client(trust_env=not bypass_proxy)` (:79-92). Model discovery tries several `/models` candidates (:599-670).

**5.2 openai_oauth (1128)** — mimics the official Codex CLI, verbatim: "CRITICAL: These headers must match what the official Codex CLI sends: - originator: \"codex_cli_rs\" (NOT \"opencode\")" (:333-336), plus `"OpenAI-Beta": "responses=experimental"` (:349) and lowercase `chatgpt-account-id` from the JWT (:355, `extract_account_id` oauth_codex_utils.py:172). Payload pins the Responses API: `# CRITICAL: Codex API requires store=false AND stream=true` (:731) — the non-streaming `chat_completion` still sends `"stream": True` and *collects* the SSE into one dict (`_collect_streaming_response` :601, `_collected_text` fallback :573-576). It even pastes the entire Codex agent system prompt: `CODEX_INSTRUCTIONS = """You are Codex, based on GPT-5. You are running as a coding agent in the Codex CLI on a user's computer.` (:63) and always injects it as `instructions` (:728). Default models are `gpt-5.2-codex`-era names (provider_types.py:139-142); model discovery sends client version `CODEX_MODELS_CLIENT_VERSION = "0.116.0"` (:58).

**5.3 anthropic_platform (1092)** — extended thinking forces temperature: thinking blocks are accumulated with signatures — `building_thinking[event.index]["signature"] = event.content_block.signature` (:400) — and replayed verbatim via `native_content` (:918-928: "Use native_content if available (preserves thinking blocks, etc.)"). `count_tokens` override calls the native endpoint via `asyncio.to_thread` (:857-858). Quirk: `generate_embeddings` returns **local TF-IDF vectors**, not API embeddings (:601 → `_generate_tfidf_embeddings` :1000).

**5.4 anthropic_claude_cli (549)** — spawns the actual `claude` binary: `cmd = [cli_path, '--print', '--model', self.model]` (:240), prompt via stdin, killed on `self.timeout` (:277-281). Tools are **not** passed as schemas — instead an MCP config file is generated and `cmd.extend(['--mcp-config', mcp_config_path])` (:249) plus `cmd.append('--dangerously-skip-permissions')` (:251, "Auto-approve MCP tool calls (required for non-interactive mode)" :250). Streaming is fake: "Claude CLI doesn't support true streaming, so we: 1. Get the complete response … 2. Yield it in chunks to simulate streaming" (:353-357), chunked by `stream_chunk_size=50` chars and `stream_chunk_delay=0.01` s (:53, :56; corrected 2026-11-02 — earlier draft cited :250/:252/:251/:52-55, each 1-3 lines off). Usage is `len//4` guesswork with comment "CLI doesn't provide actual token counts" (:321).

**5.5 ollama (717)** — `/api/chat` NDJSON; tool definitions are pre-simplified (`_simplify_parameters`/`_simplify_property` :629-683) because "Ollama may have limited support" (:304 comment in the *format service*). Usage from `eval_count`/`prompt_eval_count` on the `done:true` chunk (:395-399).

**5.6 litellm (957)** — despite the name, **no litellm dependency**; it subclasses the OpenAI provider and pins the model family itself (`_detect_model_family` :102-147, `_is_bedrock_model` :148-156 — tests pin dotted `bedrock/…` names). The signature feature is param-negotiation on 400s: `"""Retry unsupported optional parameters without masking other 400s."""` (docstring of `_create_completion_with_compatibility`, :466; *corrected 2026-11-02 — it is a docstring, not a `#` comment*) dropping `reasoning_effort`/`temperature` etc. up to 3 times (:467-482, `_compatibility_retry_kwargs` :414-464), and a tool-history repair pass `_sanitize_tool_history` (:309-413) that guarantees one result per adjacent call and synthesizes missing calls.

**5.7 bedrock (706)** — boto3 only; stopReason map at :216-222 (`'end_turn':'stop', 'tool_use':'tool_calls', 'max_tokens':'length', 'content_filtered':'content_filter', 'stop_sequence':'stop'`). Credentials: "explicit keys take precedence, then named profile, then default boto3 chain" (:79-81). `generate_embeddings` raises (tested: `test_embeddings_not_supported`). Its `prepare_tool_enabled_request` override exists because "Bedrock Converse API handles tools via toolConfig rather than embedding them in the message body" (:657-659).

**5.8 gemini_oauth (817)** — the only provider using Google's internal Code Assist RPC (`v1internal:generateContent`), with a session id in the Gemini-CLI format (`_generate_session_id` :795) and default model `DEFAULT_MODEL = "gemini-2.5-flash"` (:63). Model discovery gates a hard-coded CLI catalog (`_CLI_VISIBLE_*_MODELS` :64-79) by preview-access buckets (:241-266).

**5.9 openwebui (78)** — smallest by far; its only real job is URL plumbing: "OpenWebUI exposes its OpenAI-compatible API below /api by default" (:16-17) via `_append_api_base_path` (:38-57) with configurable `api_base_path` default `"/api"` (:58-68).

### 5.10 Model discovery — five transports list live models, differently

| Provider | Discovery mechanism |
|---|---|
| openai_platform (+4 aliases, openwebui) | `await asyncio.to_thread(self._client.models.list)` (:602) then HTTP fallback `_discover_available_models_via_http` against multiple candidate endpoints (`_get_models_endpoint_candidates` :641-661); openwebui restricts candidates to `{base}/models` under the `/api` path (openwebui_platform_api_provider.py:30-37) |
| anthropic_platform | `self._client.models.list, limit=1000` via to_thread (:665) + HTTP candidates (:715-735) |
| bedrock | `client.list_foundation_models(byInferenceType='ON_DEMAND')` (:584-585), pinned by `test_discover_available_models` (test_bedrock_provider.py:371) |
| litellm | inherits openai_platform discovery but with dotted `bedrock/…` model names preserved (tests :51-58) |
| openai_oauth | `/codex/models`-style discovery with `Authorization: Bearer` + `ChatGPT-Account-ID` header (:359-373, `_get_models_endpoint` :397) and client version header `0.116.0` (:408-414) |
| gemini_oauth | not live: returns the hard-coded Gemini-CLI catalog filtered by preview-access buckets from the credentials (`_build_visible_catalog` :252-266, `_has_preview_access_from_buckets` :241) |
| ollama | live `GET {url}/api/tags` (:519, body :516-551) |
| anthropic_claude_cli | none — `discover_available_models` left at the base failure stub (base_provider.py:311-320); default models are CLI shortcuts `sonnet/opus/haiku` |

*(inference)* gemini_oauth's static catalog is deliberate: the cloudcode-pa backend has no public model-list RPC in this flow.

### 5.11 Finish-reason normalization — every provider maps to the OpenAI vocabulary

| Provider | Native signal → normalized `finish_reason` |
|---|---|
| openai_platform / litellm / openwebui / lmstudio / xai / gemini_platform | SDK passthrough with fallback: `finish_reason=response.choices[0].finish_reason or "stop"` (openai_platform_api_provider.py:271; stream :407, :460) |
| anthropic_platform | `_map_stop_reason`: `"end_turn"→"stop", "max_tokens"→"length", "stop_sequence"→"stop", "tool_use"→"tool_calls"` (anthropic_platform_api_provider.py:990-999) |
| bedrock | `finish_reason_map = {'end_turn': 'stop', 'tool_use': 'tool_calls', 'max_tokens': 'length', 'content_filtered': 'content_filter', 'stop_sequence': 'stop'}` (bedrock_provider.py:216-222; stream copy :454-461) |
| gemini_oauth | non-stream maps `MAX_TOKENS→length`, `STOP→stop` (:467-472); stream final yield is just `finish_reason="tool_calls" if tool_calls else "stop"` (:635) — the stream path never reads `finishReason` |
| openai_oauth | state-derived, not a map: tool calls → `"tool_calls"`; `status == "incomplete"` → `incomplete_details.reason` (default `"length"`); else `"stop"` (:956-960, non-stream twins :539-597) |
| ollama | `"stop" if data.get('done', True) else "incomplete"` (:220); stream final yield `"tool_calls" if accumulated_tool_calls else "stop"` (:405) |
| anthropic_claude_cli | synthesizes `"tool_calls" if tool_calls else "stop"` (:347) |

Mid-stream delta sentinel is **not** standardized: anthropic and bedrock and gemini mark deltas `finish_reason="incomplete"` (anthropic :333, bedrock :407, gemini :611) while openai_platform and openai_oauth use the empty string `""` (openai_platform :376, openai_oauth :906). Callers must key off `is_streaming`, not the sentinel.

## 6. Extended-thinking truth-check

README.md:43-47 and settings-tab.md:44-49 promise "Low ~2K / Medium ~10K / High ~25K tokens". The numbers come from **one hard-coded dict**: `ANTHROPIC_BUDGETS = {NONE: 0, LOW: 2000, MEDIUM: 10000, HIGH: 25000}` (`src/services/models/reasoning_models.py:42-47`; grep `2048|2_048|25_000` finds nothing — budgets are round thousands). What each provider type actually sends per effort level (UI combo offers only None/Low/Medium/High, settings_tab_view.py:128-131; stored as `reasoning_effort` string on the provider row, settings_controller.py:1882-1890):

| Provider | What `reasoning_effort` produces |
|---|---|
| `anthropic_platform` | `payload["thinking"] = {"type":"enabled","budget_tokens": budget}` (:144-147, stream :293-296) **with `temperature` forced to 1** (:121-123). Budget = `min(effort_budget, max(1024, min(request.max_tokens, self.max_tokens) − 1000))` (:140-141 + reasoning_models.py:87-91). **With the default `max_tokens=4096` the effective budget is capped at 3096** — "High ~25K" is unreachable unless the user raises max_tokens above ~26K. |
| `litellm` (Anthropic-family model) | same shape but smuggled through the proxy: `completion_kwargs["extra_body"]["thinking"] = {"type":"enabled","budget_tokens": budget}` (:284-295); **no `max_tokens` rebinding**, so the clamp uses the `ReasoningConfig` default 4096 → always ≤3096. |
| `litellm` (OpenAI-family) | `completion_kwargs["reasoning_effort"] = "low|medium|high"` (:275-281) — no token budgets at all. Other families: "Skipping reasoning_effort param" (:297-298), and a 400 mentioning `reasoning_effort` strips it and retries (:435-442). |
| `openai_platform` (+LMSTUDIO/xAI/GEMINI_PLATFORM, and OPENWEBUI) | `completion_kwargs["reasoning_effort"] = effort` for non-o\* models (:182-187, stream :337); forced `temperature=1` when enabled (:171-175); for o\*/gpt-5 models the effort block still applies (it sits outside the `_is_reasoning_model` branch, :181). |
| `ollama` | top-level `payload["think"]`: the effort **string** only for `gpt-oss` models, otherwise boolean `True` — effort level is discarded for everything else (:101-111; stream :261-270). |
| `openai_oauth`, `bedrock`, `gemini_oauth`, `anthropic_claude_cli`, `openwebui`-specific | **nothing** — `grep -rn "reasoning_effort|get_ollama_think|think\b|effort"` across those five files returns zero hits (*corrected 2026-11-02 — earlier draft said "returns hits only in ollama_provider.py"; that file isn't one of the five — Ollama's thinking handling §5.7 is the odd one out*). |

So the "~2K/10K/25K" table is **only Anthropic `thinking.budget_tokens`** (and silently clamped to ~3K at default settings); everywhere else it's OpenAI-style effort strings, an Ollama boolean, or ignored entirely.

## 7. OAuth plumbing

Three near-identical util modules + a shared callback server + Qt workers:

| Module | Client ID | Auth / token endpoints | Scopes | Callback ports |
|---|---|---|---|---|
| `oauth_codex_utils.py` (469) | `app_EMoamEEZ73f0CkXaXp7hrann` (:41, "from opencode/Claude Code Codex plugin" :40) | `auth.openai.com/oauth/authorize|token` (:44-45) | `openid profile email offline_access` (:51) | 1455-1460 (:50), path `/auth/callback` (:49) |
| `oauth_gemini_utils.py` (479) | Google public client `681255809395-…` **with hard-coded `OAUTH_CLIENT_SECRET = "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"`** (:42-43) | `accounts.google.com/o/oauth2/v2/auth`, `oauth2.googleapis.com/token` (:45-46) | `cloud-platform` + userinfo email/profile (:47) | 1462-1467 (:54), path `/callback`; also headless mode redirecting to `https://codeassist.google.com/authcode` (:50) |
| `oauth_utils.py` (367) | Anthropic UUID (:40) | `claude.ai/oauth/authorize` + `console.anthropic.com/v1/oauth/token` (:43-44) | `user:profile user:inference user:sessions:claude_code` (:50) | 1456-1461 (:49) |

The browser flow, end to end (per `oauth_codex_utils.py` + `oauth_callback_server.py` + `oauth_worker.py`):

1. QThread worker starts; it launches `OAuthCallbackServer` on `localhost` picking the first free port from its list (oauth_callback_server.py:105-119).
2. `generate_pkce()` produces verifier + S256 challenge (oauth_codex_utils.py:71-86), `generate_state()` for CSRF (:88).
3. `build_authorize_url(...)` embeds scope, `redirect_uri=http://localhost:<port>/auth/callback`, challenge, state (oauth_codex_utils.py:93-123) and `webbrowser`-opens it (`open_auth_browser` :125).
4. `_handle_callback` (:190) captures `?code=` and serves success HTML; `wait_for_callback()` (:135) returns the params to the worker.
5. `exchange_code_for_tokens(code, verifier, redirect_uri)` POSTs to the token endpoint (oauth_codex_utils.py:231); `extract_account_id` decodes the JWT (`parse_jwt_claims` :145).
6. `create_credentials_json(tokens, account_id)` (:312) becomes the provider row's `api_key`; refresh on expiry later re-signs via `refresh_access_token` (:273) and `_persist_oauth_api_key`. If the port bind failed, the user manually pastes the code from the browser URL bar (oauth_codex_utils.py:46-47 comment).

- **PKCE everywhere**: `generate_pkce()` in all three; Codex authorize URL sends `code_challenge_method=S256` plus Codex-specific params `"id_token_add_organizations": "true", "codex_cli_simplified_flow": "true", "originator": "codex_cli_rs"` (oauth_codex_utils.py:115-120). Gemini's PKCE is "for headless mode only" (oauth_gemini_utils.py:64-66); the browser flow is plain code+state.
- **Callback server**: `oauth_callback_server.py` — an aiohttp `web` server bound to `('localhost', port)`, trying each port in order and returning `(redirect_uri, port)` (:105-119); `wait_for_callback()` (:135) and friendly success/error HTML (:258, :348); convenience `run_callback_server_with_timeout(...)` (:446). Users can also paste the code manually when no server binds (oauth_codex_utils.py:46-47 comment).
- **Workers**: `oauth_worker.py` runs the flows off the UI thread: `OAuthWorkerBase(QThread)` (:33), `OpenAIOAuthWorker` (:112), `GeminiOAuthWorker` (:263); consumed by `settings_controller.py:1057` and :1241.
- **Token storage & refresh**: refreshed tokens are persisted **into the provider row's `api_key` column as JSON** — `self._persist_oauth_api_key(json.dumps(self._credentials))` (openai_oauth_provider.py:321; gemini_oauth_provider.py:158; *corrected 2026-11-02 — earlier draft cited :320/:163*) — with expiry checked on every request with a 300 s buffer (openai_oauth_provider.py:290 passes it explicitly; gemini relies on the `buffer_seconds=300` default of its own `is_token_expired`, oauth_gemini_utils.py:467; gemini call site :141). Gemini additionally runs a `loadCodeAssist`/`onboardUser` project-setup dance (llm_providers/oauth_gemini_utils.py:331, :378) and stores `project_id` in credentials — it is *read* from there (`gemini_oauth_provider.py:224-229`, `:415`); it is written into the credentials JSON during the controller's OAuth setup via `create_credentials_json(..., project_id=…)` (`settings_controller.py:1417-1421`; *corrected 2026-11-02 — earlier draft said "stores project_id in credentials (:296)"; :296 is an unrelated tool-call conversion block*).
- **Two orphans.** (a) `oauth_utils.py` (Anthropic OAuth) is **dead code at HEAD**: `grep -rn "oauth_utils import" src/ --include=*.py` returns no importers — only `oauth_codex_utils`/`oauth_gemini_utils`/`oauth_worker` are imported (settings_controller.py:1057, :1160, :1241, :1353) — the residue of the removed `anthropic_oauth` provider. (b) the `oauth_credentials` **table** exists with full CRUD (`settings_service.py:761-827`, migration `add_oauth_credentials`, invoked from `settings_service.py:155` (import) and `:162` (call)) but has **no callers outside settings_service** (`grep -rn "store_oauth_credentials|get_oauth_credentials" src/ --include=*.py` → only settings_service lines; tests add none) — the providers use the `api_key` column instead. *(inference)* the table was an earlier storage scheme superseded by per-provider api_key JSON.

## 8. Message-format service (`message_format_service.py`, 459)

Adapters per provider family (`MessageFormatService.__init__` :380-403): one **Anthropic content-block** adapter (`text`/`tool_use`/`tool_result` blocks, :45-128), one **OpenAI** adapter (function-style `tool_calls` + `tool_call_id`, :170-265), a distinct **Ollama** shape (flat `{id,name,arguments}`, :294-372), and everything else mapped to the OpenAI adapter: `GEMINI_OAUTH`, `GEMINI_PLATFORM`, `LMSTUDIO`, `OPENWEBUI`, `OPENAI_OAUTH`, `XAI_PLATFORM` all share `openai_adapter` with comments like "Storage uses OpenAI format; provider handles Gemini-native conversion" (:391-402); `BEDROCK` reuses it "converting … to Converse API payloads at request time" (:275-284). `convert_between_providers` round-trips through `ChatMessage` (:426-434).

Crucially, **this service's Anthropic adapter does not model `thinking` blocks** — `from_native_format` only handles `text|tool_use|tool_result` (:101-117). Thinking survives replay only through the *providers'* native path: `ChatMessage.native_content` is replayed verbatim by `AnthropicPlatformApiProvider._prepare_messages` (:918-928), LiteLLM persists `reasoning_content`/`thinking_blocks` in `native_content` (litellm_provider.py:212-221) and re-injects them on replay (:505-510), and Gemini fakes a `"thoughtSignature": "skip_thought_signature_validator"` on replayed function calls (gemini_oauth_provider.py:306). *(inference)* cross-provider conversation switching (`convert_between_providers`) therefore silently drops thinking blocks — only same-provider replay preserves them.

## 9. What the tests actually pin (7 provider test files, 59 tests)

- `tests/test_provider_types.py` (9): every enum member has display name/URL/model list, no duplicate values, Bedrock defaults & capabilities, "existing providers unchanged" (:15-69).
- `tests/test_bedrock_provider.py` (18): converse payload & system prompt, usage, **stream tool-input accumulation** (`test_chat_completion_stream_accumulates_tool_input` :212), native callback saves OpenAI tool shape (:258), credential validation & error mapping (`test_no_credentials_maps_to_authentication_error` :339, `test_rate_limit_error` :417), model discovery (:371), embeddings unsupported (:450). Plus `test_bedrock_factory.py` (8), `test_bedrock_message_format.py` (3), `test_bedrock_migration.py` (6).
- `tests/test_litellm_provider.py` (7): dotted-bedrock family detection (:51), temperature omitted for dotted Bedrock GPT reasoning models (:59), thinking metadata **not** forwarded to OpenAI family (:73), tool-history sanitizer (:89, :115), "thinking rejection removes reasoning and stored metadata" (:130), 400-retry drops temperature (:154).
- `tests/test_openwebui_provider.py` (8): `/api` path append/no-double-append, custom `api_base_path`, bypass_proxy ≠ disable_tls (:75), empty completion proves connectivity, factory registration.

*(inference)* Matching ch20: Bedrock is the most heavily pinned provider (35 tests across 4 files) while the OAuth providers (`openai_oauth` 1128 LOC, `gemini_oauth` 817 LOC — the two most quirk-laden transports) have **zero dedicated tests** (`ls tests/ | grep -i "oauth|openai|gemini|anthropic"` → no such provider test files; only the grep shown above over `ls tests/`).

## 10. Effectiveness-relevant facts

- Every `ChatRequest`/`ProviderCapabilities` defaults `max_tokens=4096` (llm_models.py:71, :142; base_provider.py:49), matching the settings-DB default — and that 4096 is what clamps Anthropic thinking budgets (§6).
- Provider timeout default 90 s (base_provider.py:20), applied to SDK clients (openai :62-68, anthropic :75-79), httpx (`OllamaProvider._create_async_client` — `httpx.AsyncClient(timeout=self.timeout)` ollama_provider.py:65-69; *method name corrected 2026-11-02 — `_create_client_session` is the gemini_oauth provider's aiohttp method, gemini_oauth_provider.py:214*) and aiohttp (`aiohttp.ClientTimeout(total=self.timeout)` gemini_oauth_provider.py:214-222).
- Rate-limit retries default to 50 × 10-30 s — worst case ~25 min of silent retry before `RateLimitError` (base_provider.py:57-59).
- Default model strings per provider live in provider_types.py:98-150 (§1 table); Bedrock's list includes `anthropic.claude-sonnet-4-6` (:111), OpenAI-OAuth's includes `gpt-5.2-codex` (:140); Gemini defaults to `gemini-2.5-flash` (gemini_oauth_provider.py:63), Claude CLI to `sonnet` (anthropic_claude_cli_provider.py:49-50).
- `stream=False` is the request default (llm_models.py:74); the notable inversion is openai_oauth, whose *blocking* path still streams on the wire (`"stream": True,  # REQUIRED by Codex API` openai_oauth_provider.py:737) and de-streams client-side.
- Bedrock `get_capabilities` advertises `max_tokens=8192` (bedrock_provider.py:636).
- Sync-in-async transports (openai_platform, litellm, openwebui, bedrock) run blocking HTTP calls on the event-loop thread — UI stalls under load are plausible on those four. *(inference)*

## Gaps / not verified

- UI provider-edit dialog behavior (reasoning_effort widget already cited, but the OAuth "Authenticate" button wiring beyond settings_controller imports) not fully read.
- `openai_oauth` lines 444-502 (`_translate_messages_to_input` native replay details) and 658-692 (`_build_openai_native_message`) read only at grep-summary level.
- `litellm_provider.py` `_chat_completion_stream_impl` body (:700-957) not fully read (only the error-path hints at :739, :946).
- anthropic streaming tail (:460-595) and openai_platform stream tail (:395-500) skimmed, not line-by-line.
- Whether `bypass_proxy`/`disable_tls` are honored in the ollama/claude-cli test_connection paths — spot-checked only for openai/openwebui.

## Sources

- `src/services/models/provider_types.py:17-234`; `src/services/models/llm_models.py:1-175`; `src/services/models/reasoning_models.py:15-172`
- `src/services/llm_providers/base_provider.py:20-574`; `provider_factory.py:96-229`
- `openai_platform_api_provider.py:62-194,353-395,599-602`; `openai_oauth_provider.py:54-63,198-328,345-400,527-600,601-692,693-979`
- `anthropic_platform_api_provider.py:56-151,243-455,595-601,816-999`; `anthropic_claude_cli_provider.py:41-65,218-305,305-420`
- `ollama_provider.py:65-111,230-407`; `litellm_provider.py:12-28,102-156,164-298,309-482,505-510,574-650`
- `bedrock_provider.py:5-15,38-97,153-223,237-302,352-494,636,651-679`; `gemini_oauth_provider.py:52-79,95-233,296-320,409-433,480-671`
- `openwebui_platform_api_provider.py:15-68`; `message_format_service.py:18-459`
- `oauth_utils.py:40-328`; `oauth_codex_utils.py:40-120,145-231,312-421`; `oauth_gemini_utils.py:42-66,96-141,164-414`; `oauth_callback_server.py:31-133,348,446-484`; `oauth_worker.py:33-112-263`
- `README.md:43-47,126-135`; `docs/tabs/settings-tab.md:44-51,55-61`; `src/controllers/settings_controller.py:1057,1160,1241,1353,1683-1890`; `src/views/settings_tab_view.py:128-133`
- `tests/test_provider_types.py`, `test_bedrock_{provider,factory,message_format,migration}.py`, `test_litellm_provider.py`, `test_openwebui_provider.py` (test names cited inline)
