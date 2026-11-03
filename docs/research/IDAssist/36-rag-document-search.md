# 36 — Document RAG: uploads, chunking, Whoosh+vector hybrid search

> Part of the [overview](README.md). Clone HEAD 09dd910d…, written 2026-11-02.

This chapter traces IDAssist's reference-document RAG from the upload button to the
text that lands in an LLM prompt. The headline: the "hybrid text+vector" search is
**BM25 (Whoosh) plus a hand-rolled TF-IDF cosine search, and the vector half is
computed with TF-IDF at query time regardless of whether real provider embeddings
were stored at ingest time** (`src/services/rag_service.py:607-608`). "Vector
search" in this plugin is mostly TF-IDF wearing a cosine-similarity costume.

## 1. What the docs claim — and where they drift

`README.md:26`:

> **RAG Document Search** — Upload reference documents (`.txt`, `.md`, `.rst`, `.pdf`) and use them as context during LLM queries. Supports hybrid text+vector search via Whoosh indexing.

`docs/tabs/rag-tab.md` documents the tab fully (75 lines): document management
buttons, a docs/chunks counter, a documents table (Name/Size/Chunks), a search-test
box with a **Hybrid / Text / Vector** dropdown (`docs/tabs/rag-tab.md:31-38`), the
four extensions (`.txt/.md/.rst/.pdf`, :40-47), and storage at
`~/.idapro/idassist/rag_index/` "as a Whoosh search index directory … persists
across IDA sessions" (:69). It describes the integration flow: enable a RAG
checkbox on Explain/Query, the plugin searches and injects "the top matching
chunks" (:57-65).

Drift vs. code, in order of severity:

1. **PDF support is a lie.** There is no PDF parser anywhere in `src/`: a
   case-insensitive grep for `pypdf|PyPDF2|pdfminer|fitz|pdf2|camelot` over
   `/tmp/opencode/IDAssist/src` returned zero matches. Ingestion reads *every* file
   as text: `with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:`
   (`src/services/rag_service.py:420`). A real PDF gets its binary bytes decoded
   lossily into garbage that is then chunked and indexed. The file-picker even
   offers a `"PDF Files (*.pdf)"` name filter (`src/controllers/rag_controller.py:77`).
   *(inference: PDFs would produce mojibake chunks rather than an error — the read
   cannot fail because of `errors='ignore'`.)*
2. **Vector search does not embed the query.** The docs describe "Embedding
   similarity" for Vector mode (`docs/tabs/rag-tab.md:55`); the query side always
   uses the service's own TF-IDF embedding (§4).
3. **"Refresh" does not reload from disk.** Docs say "Reload the index from disk"
   (:19); the controller calls `rag_service.list_documents()` which returns the
   in-memory dict (`rag_service.py:825-828`). Disk loads happen only at service
   init (`rag_service.py:78-80`).
4. The docs' "Docs / Chunks" counter omits the third stat the UI shows: the view
   label is `"Documents: {n} | Chunks: {n} | Embeddings: {n}"`
   (`src/views/rag_tab_view.py:217`).
5. Storage claim is accurate but understated: besides the Whoosh files, three
   sidecar files live *inside* the index directory — `embeddings.pkl`,
   `metadata.json`, `vocabulary.json` (`rag_service.py:98-101`).

## 2. Service shape and storage

`RAGService` is a singleton (`rag_service.py:44-50`) instantiated at import time —
module bottom: `rag_service = RAGService()` (`rag_service.py:949`), with a
comment "Global instance for easy access throughout the application". Paths come
from `get_user_data_dir()` + `rag_index` (`rag_service.py:91-104`). There are **no
SQL tables** for RAG — the grep for `CREATE TABLE` relevant to RAG finds nothing in
rag_service.py (it never touches `analysis_db`; verified by full read of the file).
State is: one Whoosh index dir + `embeddings.pkl` (pickle) + `metadata.json` +
`vocabulary.json`, all under the index path (`:98-101`). Thread-safety via an
`RLock` (`:65`).

Whoosh is imported **unguarded** at module top (`rag_service.py:13-17`) and is a
hard dependency listed in `requirements.txt:9`. If the import fails, the plugin's
import chain fails — *(inference: `rag_service` is imported by
`explain_controller.py:12`, `query_controller.py:13`, `function_summary_service.py:13`,
`rag_controller.py:7`, so a missing Whoosh package would break those tabs at
import; no try/except around the import was seen in any of these)*.

## 3. Ingestion and chunking

Flow: **Add Documents** button (`rag_tab_view.py:100-101`) → `QFileDialog` with
`ExistingFiles` mode and name filters ("Text Files (*.txt *.md *.rst)",
"PDF Files (*.pdf)", "All Files (*.*)") (`rag_controller.py:73-79`) — picker only,
**no drag-and-drop** in the view code. Ingestion runs on a `QThread`
(`rag_controller.py:13-43`) with `generate_embeddings=True` (`rag_controller.py:95`)
and an explicit `chunk_size=500, max_snippet_length=500` (`:31-32`), matching the
service defaults (`rag_service.py:86-87`; `IngestRequest` dataclass defaults are
identical, `src/services/models/rag_models.py:57-63`).

Per file (`rag_service.py:415-478`):

- read whole file as text with `errors='ignore'` (`:420`);
- `sha256` first-16-hex file hash, falling back to a timestamp-salted hash if the
  file can't be read (`:276-286`);
- chunking (`_chunk_content`, `:239-269`): fixed 500-**character** window; it then
  hunts a paragraph break `\n\n` after the window end — accepting it if it's within
  1.5× the window — else backs up to the last `.` (if ≥0.5× window), else hard-cuts.
  **No chunk overlap.** Structure-aware only in this weak paragraph/sentence sense.
- Whoosh `add_document(filename, chunk_id, content, doc_hash, file_path,
  ingested_at)` (`:441-448`); `doc_hash = md5(f"{filename}_{chunk_id}")`
  (`:271-274`). Since `doc_hash` is a `unique=True` ID field (`:115`), re-ingesting
  a file with the same basename replaces its old chunks rather than duplicating
  them *(inference from Whoosh's unique-ID semantics)*; two different files with
  the same basename collide — metadata is keyed by filename (`:467`).

The TF-IDF corpus is updated on **every** ingest, "regardless of embeddings"
(`:431-432` comment). `_update_tfidf_corpus` (`:288-314`) tokenizes with
`re.findall(r'\b\w+\b', text.lower())`, counts document frequency, and keeps the
**top 1000** most common words as the vocabulary (`:306-309`) — this caps the
"vector" dimensionality at ≤1000. Everything is then committed to Whoosh and the
three sidecar files saved (`:481-491`).

## 4. The two halves of "hybrid"

### Whoosh/BM25 half

Schema (`rag_service.py:109-118`): `filename` TEXT (stored, `phrase=False`),
`chunk_id` NUMERIC, `content` TEXT stored with Whoosh's `StandardAnalyzer`,
`doc_hash` ID unique, `file_path` TEXT, `ingested_at` DATETIME. Searches run with
`weighting=BM25F()` (`:566`) via `QueryParser("content", ...)`; a bare `except:`
retries unparseable queries as a quoted phrase (`:569-573`). Scores are normalized
by the max hit score to a 0–1 "percentage" (`:582`, `:590`). Snippets come from
`_generate_snippet`, which windows 500 chars around the first occurrence of any
query term (`:795-823`).

### Vector half — three separate TF-IDF layers

1. **Ingest embeddings.** If the active provider instance has a `get_embeddings`
   attribute (`:405`), chunks are batch-embedded via
   `provider_instance.get_embeddings(texts)` (`:510`) and cached as
   `EmbeddingData(embedding=…, provider_name=…, model_name=…)` keyed
   `"{filename}_{chunk_id}"` (`:514-523`). **Only one provider actually satisfies that
   hasattr check**: `grep -rn "def get_embeddings" src/services/llm_providers/` matches exactly
   `anthropic_platform_api_provider.py:621` — and that is the TF-IDF shim below. The Ollama and
   OpenAI providers define `generate_embeddings(request) -> EmbeddingResponse` (the tab-level
   "list models/test" surface, `ollama_provider.py:434`, `openai_platform_api_provider.py:500`) —
   a **different name**, so RAG's `hasattr(provider, 'get_embeddings')` is False for them and they
   fall through to the local TF-IDF path. The endpoints exist but are only reached from the
   provider-settings UI, not from RAG ingest (`POST {url}/api/embeddings` `ollama_provider.py:448`;
   `self._client.embeddings.create` `openai_platform_api_provider.py:508`). Notably the
   **Anthropic** provider also exposes `get_embeddings` — as a shim that returns
   its *own TF-IDF embeddings*: `return self._generate_tfidf_embeddings(texts)`
   (`src/services/llm_providers/anthropic_platform_api_provider.py:621-628`). *(corrected
   2026-11-02 — earlier draft claimed those Ollama/OpenAI endpoints sat behind the RAG
   `get_embeddings` call; they do not)*
2. **TF-IDF fallback at ingest.** With chunks pending but no provider instance, the
   service embeds locally: `provider_name="tfidf_direct"`, `model_name="tfidf"`
   (`rag_service.py:458-462` → `_generate_tfidf_embeddings_batch` `:530-551`,
   tag at `:542-543`). The embedding is a sparse TF-IDF vector over the shared
   ≤1000-word vocabulary, L2-normalized (`:316-362`, normalization at `:357-360`).
3. **Query side is always TF-IDF.** `_search_vector_with_query` carries the comment
   "Use our own TF-IDF embedding generation for consistency"
   and calls `self._generate_tfidf_embedding(query_str)` (`:603-608`); a zero
   vector returns no results (`:611-613`).

Consequence *(inference)*: when the ingest path stored **provider** embeddings
(e.g. hypothetical 1536-dim OpenAI vectors — after the §1 correction above this
scenario cannot occur at HEAD, since no provider supplies real vectors through
`get_embeddings`), the TF-IDF query vector (≤1000 dims) hits the
dimension guard in `_cosine_similarity` — `if len(vec_a) != len(vec_b): … return
0.0` (`rag_service.py:734-738`) — so every cached provider embedding scores 0,
falls under the similarity threshold, and the vector half contributes nothing.
The vector half "works" end-to-end mainly when both sides are TF-IDF (no
embedding-capable provider, or the Anthropic-style shim). Provider embeddings
stored at ingest are effectively dead weight unless the model's dimension happens
to equal `min(1000, vocab_size)`.

Similarity math is **pure Python** (no numpy anywhere in rag_service.py — verified
by full read of all 949 lines): `sum(a*b …)/ (norms)` cosine (`:734-749`) over a
**linear scan of the whole embeddings cache** (`:635-644`), filter
`similarity > threshold`, sort, take top-k (`:650-652`). Snippet text is fetched
back out of Whoosh by `_get_content_from_index`, which parses `"*"` and scans up
to 500 stored chunks comparing filename/chunk_id (`:751-771`) — O(index) per hit.

### Fusion — what "hybrid" mechanically is

`search_hybrid` (`rag_service.py:672-686`) always runs text search, always runs
the TF-IDF vector search, then `_combine_search_results` (`:688-732`): re-normalize
text scores by their max (vector "scores are already normalized (cosine
similarity)", comment at `:699`), then a **fixed linear blend —
`text_weight = 0.6`, `vector_weight = 0.4`** (`:702-703`) — applied by scaling each
side's scores, concatenating (explicitly *without* deduplication, comment at
`:705`), sorting by weighted score, truncating to `max_results` (`:730-732`). No
RRF, no reranker, no learned weights.

## 5. API surface and defaults

Public API (from full read of `rag_service.py`):
`search(SearchRequest)` dispatch (`:553-561`), `search_text(query_str,
max_results=10)` (`:563`), `search_vector(query_embedding, max_results=5,
threshold=0.2)` (`:621-622`), `search_hybrid(query_str, max_results=10)` (`:672`),
`list_documents` (`:825`), `delete_document`/`delete_documents` (`:830`, `:865`,
Whoosh `delete_by_term("filename", …)` at `:839` + cache/metadata pruning
`:846-856`), `get_stats` (`:872`), `clear_index` (`:906`), `close` (`:936`).
There is **no `search_with_relevance`** — that name appears nowhere in the file.
`SearchRequest` defaults: HYBRID, `max_results=10`, `similarity_threshold=0.5`
(`rag_models.py:66-73`).

**Per-binary scoping: none.** `binary_hash` never appears in `rag_service.py`
(verified by full read of all 949 lines); the index is a single global store under
the plugin data dir, shared by every IDB *(and every user of the machine, per the
docs path `~/.idapro/idassist/rag_index/`, `docs/tabs/rag-tab.md:69`)*.

Lifecycle: the index opens/creates at service construction, i.e. first import
(`rag_service.py:120-132`); nothing re-indexes on IDA start — files persist and are
re-loaded from `metadata.json`/`embeddings.pkl`/`vocabulary.json` (`:78-80`,
`:134-237`). On init `_verify_cache_consistency` clears a stale cache when the
Whoosh index is empty but the cache isn't (`:364-386`), and merely logs on any
other count mismatch (`:382-383`). `clear_index` closes and recreates the Whoosh
index and wipes all caches (`:906-934`). There is no update-in-place: to refresh a
changed document you delete it or re-upload (same filename, same chunk IDs — see
§3 ID-field note).

## 6. RAG tab UI

Signals: `add_documents_requested`, `refresh_requested`,
`delete_documents_requested(list)`, `search_requested(query, type)`,
`clear_index_requested` (`rag_tab_view.py:11-15`); buttons wired at `:100-150`;
multi-select table of Name/Size/Chunks (`:111-131`); search-test box with Hybrid/
Text/Vector combo (`:76-79`) and read-only HTML results pane (`:89-92`). There is
**no progress bar** — the controller's progress hook literally comments "Could
update a progress bar here if we add one to the UI" (`rag_controller.py:103`);
user feedback is modal QMessageBoxes: "Ingesting N documents. This may take a
while…" (`:92`), success/error on completion (`:115-121`), confirmation dialogs for
delete (`:165-172`) and clear (`:223-230`). The search-test path uses
`max_results=5` and a two-tier threshold — 0.2 for Vector, 0.5 for text/hybrid,
with the code comment "20% for TF-IDF vector search" (`:260-268`) — confirming the
author knows Vector mode is TF-IDF. Results render as HTML cards showing
`Score: {percent}% | Type | Chunk` (`:300-308`). A leftover
`populate_sample_data` shows fake PDF rows (`rag_tab_view.py:228-233`).

## 7. How RAG results reach the LLM

Three consumers, all HYBRID, all top-3, threshold 0.3:

- **Explain** — gated on the RAG checkbox (`explain_controller.py:89-90`), query is
  the *decompiled code text* (`:96-97`, assembled at `:736-747`), `max_results=3,
  similarity_threshold=0.3` (`:99-100`). The block appended to the prompt
  (`:114-124`, verbatim ≤8 lines):

  ```
  rag_context = "\n## Additional Reference Context\n"
  rag_context += "The following related documentation may provide helpful context:\n\n"
  for i, result in enumerate(results, 1):
      score_percent = int(result.score * 100)
      rag_context += f"### Reference {i} (Relevance: {score_percent}%)\n"
      rag_context += f"**Source:** {result.filename}, Chunk {result.chunk_id}\n"
      rag_context += f"**Content:** {result.snippet}\n\n"
  ```

  Then a trailer: "Please use this reference context to enhance your analysis, but
  focus primarily on the specific code provided." (`:123-124`). If empty/failed, the
  prompt instead gets explicit fallback lines like
  `"\n\n**RAG Context**: No relevant documentation found for this code context."`
  (`:748-756`).
- **Query** — `_enhance_query_with_context` appends `_get_rag_context(query_text)`
  after the user query (`query_controller.py:2879-2887`); `_get_rag_context`
  (`:2897-2926`) is the same HYBRID/3/0.3 request, formatted as `## Additional
  Reference Context` + `### Reference i (Relevance: N%)` + `**Source:**` +
  `**Content:**` (no chunk id here, `:2913-2920`). Placement: end of the *user*
  message, before the MCP line (`:2889-2893`).
- **Function summaries** — `function_summary_service.py:228-262` replicates the
  Explain template nearly verbatim (third copy of the same formatter).

Snippet length into prompts is bounded by `max_snippet_length=500` chars
(`rag_service.py:87`, truncation at `:664`), so RAG adds at most ~3×500 chars.

## 8. The `document` internal tool — a red herring for RAG

`DOCUMENT_CHAT_TOOL_NAME = "ga_add_document"` (`internal_tools.py:37`), tool
definition at `:143-154` — its description:

> "Create a new chat document with custom markdown content. Use this to produce standalone analysis reports, summaries, or findings separate from the current conversation."

Schema is `{title, content}` required (`:148-153`). Handler `_ga_add_document`
(`:456-466`) calls the injected handler or returns
"Error: document chat handler not registered" (`:459`); registered in the dispatch
map at `:192`. QueryController registers it via `set_document_chat_handler(self._create_document_chat)`
(`query_controller.py:629`); `_create_document_chat` (`:1486-1539`) creates a chat
whose single assistant message is the markdown, metadata `chat_type="notes"`
(`DEFAULT_DOCUMENT_DOC_TYPE`, `:534`) + `is_document_chat=True`
(`DOCUMENT_CHAT_METADATA_KEY = "is_document_chat"`, `:533`), persisted via
`save_edited_message(..., provider_type="symgraph_document")` (`:1519-1526`).

So a "document chat" is **not** a RAG document and not whole-doc-in-context RAG:
it's an artifact/report object in the Query history. Document chats render as flat
markdown instead of the transcript (`:789-795`), get no transcript rendering/backfill
(`:721-722`; guards like `not self._is_document_chat()` at `:3075`, `:3189`,
`:3560`), and are directly editable (`:708-710`). The transcript kind
`DOCUMENT_SNAPSHOT = "document_snapshot"` exists (`transcript_models.py:22`) and
`transcript_service.append_document_snapshot` is defined
(`transcript_service.py:311-312`) — but a grep for `append_document_snapshot(`
across `src/**/*.py` matched **only the definition**: the event is written nowhere.
Verified negative.

## 9. Failure behavior — fail-open almost everywhere

- **No embedding provider at ingest:** `hasattr` check demotes to TF-IDF fallback
  (`rag_service.py:405-413`, `:458-462`); failure is a log line, ingestion
  succeeds. Fail-open.
- **Embedding call raises:** caught and logged in `_generate_embeddings_batch`
  (`:527-528`) — chunks still get indexed in Whoosh; some cache entries simply
  absent. Fail-open.
- **One bad file in a batch:** `except … continue` per file (`:476-478`); the
  batch still commits and returns `True`, so the UI says "Successfully ingested N
  documents" even if a file was skipped — silent partial failure
  (`rag_controller.py:38` vs `rag_service.py:493-494` — `return True` actually at :494; corrected 2026-11-02).
- **Corrupt/empty vocabulary:** retry-load then a zero vector of 1000 dims
  (`:322-328`), which vector search treats as "no results" (`:611-613`). Fail-open.
- **Unparseable search query:** bare `except:` → quoted-phrase fallback
  (`:571-573`). Search exceptions in controllers surface as UI text:
  `"<p><b>Error:</b> …"` in the results pane (`rag_controller.py:288`) or empty
  string into prompts (`explain_controller.py:128-130`,
  `query_controller.py:2924-2926`). RAG never blocks an LLM call.
- **Whoosh missing:** fail-*closed* at import (no guard, §2).
- **Large PDFs:** no size cap anywhere in the ingest path (full read; none found) —
  a huge PDF is slurped into one string and chunked into many junk chunks.

## 10. Effectiveness numbers (and absence of evaluation)

All tunables, collected: chunk 500 chars, no overlap (`rag_service.py:86`,
`:239-269`); snippet cap 500 (`:87`); TF-IDF vocab top-1000 words (`:306-309`);
vector scan defaults top-5/threshold-0.2 (`:621-622`); hybrid top-10 (`:672`);
fusion 0.6 text / 0.4 vector (`:702-703`); UI test top-5 with 0.5/0.2 thresholds
(`rag_controller.py:260-268`); prompt injection top-3 at 0.3 (`explain_controller.py:
99-100`, `query_controller.py:2903-2904`). Everything is hardcoded per call site;
no settings keys were seen feeding RAG tuning (the settings doc only pins the index
path, `docs/tabs/settings-tab.md:144`). There is **no retrieval evaluation** in the
repo — per ch20's verified negative, IDAssist ships no eval harness; nothing in the
files read here contradicts that.

Quality red flags visible in code: the query-vs-provider dimension mismatch (§4);
`re.findall(r'\b\w+\b')` tokenization drops any symbol name with underscores or
punctuation for the vector half while BM25 keeps it, so API-name queries lean
entirely on the 0.6-weight text half; `search_text` fetches `max_results*2`
"for deduplication" (`:576`) but the combine step explicitly does not dedup
(`:705`) — multiple chunks of one document can flood the 3 prompt slots; the
500-word-per-doc DF scan is O(corpus·vocab) per query (`:348`).

## Gaps

- `get_user_data_dir()` was not opened; the `~/.idapro/idassist` path rests on the
  docs (`rag-tab.md:69`, `settings-tab.md:144`), not on ida_compat source read here.
 - LiteLLM/LMStudio/OpenWebUI `get_embeddings` endpoints (provider_types.py:152-161
   from ch-context) were not individually opened; only Ollama, OpenAI Platform and
   the Anthropic shim were verified. *(Resolved during the 2026-11-02 fact-check:
   `grep -rn "def get_embeddings" src/services/llm_providers/` matches ONLY the
   Anthropic shim — no other provider class has the attribute, so all of these
   demote to the TF-IDF path; see §1.)*
- Whether anything else in the UI (e.g. symgraph tab) also writes document chats
  besides `ga_add_document` — not exhaustively traced.
- `docs/tabs/query-tab.md` "RAG checkbox" wording not re-read; Explain/Query gating
  was read from code only.

## Sources

All from clone `/tmp/opencode/IDAssist` @ 09dd910d…, read in full or at cited spans:

- `README.md:9,26`
- `docs/tabs/rag-tab.md:1-75` (full); `docs/tabs/settings-tab.md:144`
- `requirements.txt:9`
- `src/services/rag_service.py:1-949` (full read)
- `src/services/models/rag_models.py:1-73`; `src/services/models/transcript_models.py:22`
- `src/controllers/rag_controller.py:1-337` (full read)
- `src/views/rag_tab_view.py:1-233` (full read)
- `src/controllers/explain_controller.py:11,88-130,728-762`
- `src/controllers/query_controller.py:13,532-536,629,663-669,708-721,789-795,1486-1539,2879-2926`
- `src/services/function_summary_service.py:13,225-264`
- `src/services/internal_tools.py:36-47,143-154,158-178,192,456-466`
- `src/services/transcript_service.py:311-312`
- `src/services/llm_providers/ollama_provider.py:438-472`;
  `openai_platform_api_provider.py:508`; `anthropic_platform_api_provider.py:618-628`
- Verified negatives (greps named in text): PDF parsers (`pypdf|PyPDF2|pdfminer|fitz|pdf2|camelot` in `src/`, 0 hits);
  `binary_hash` absent from `rag_service.py` (full read);
  `append_document_snapshot(` defined-only (grep in `src/**/*.py`);
  numpy absent from `rag_service.py` (full read).
