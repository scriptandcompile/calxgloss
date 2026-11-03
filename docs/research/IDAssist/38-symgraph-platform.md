# Chapter 38 — SymGraph: the cloud side (client integration only)

> Part of the [IDAssist overview](README.md). This chapter describes what
> SymGraph *is* as seen from the plugin. Important scope note: **SymGraph is a
> closed commercial service** (https://www.SymGraph.com — the marketing site is
> Cloudflare-gated), and no server code exists in the repo. Everything here is
> derived from the client integration code in the local clone (HEAD
> `09dd910d…`) and the repo's own docs.
>
> Verification note: a first draft of this chapter was rejected because it
> cited files, classes and endpoints that do not exist in the clone (a
> licensing module, an OAuth-sync flow, a login wizard). It has been rewritten
> from direct line-level verification; only what the code actually contains is
> claimed.

## What SymGraph is

SymGraph is IDAssist's collaboration feature: a cloud **analysis-sharing
service keyed by binary SHA-256**. Per the docs, it lets you "compare the
current IDA database against SymGraph, import shared analysis, and publish
your own names, graph data, and document chats back to the service"
(`docs/tabs/symgraph-tab.md:1-3`), and it is one of the plugin's headline
features ("collaborative symbol sharing through SymGraph", `docs/index.md:10`).
The client also derives a **web UI** URL from the API URL — replacing an
`api.` host prefix and stripping `/api/v1`, then linking to `/binaries/{sha}`
(`symgraph_service.py:126-143`) — so a companion web app exists, but nothing
in the clone reveals how it is built.

There is **no IDA-side licensing code for SymGraph at all** in the current
tree: no `isSymgraphLicenseActive`, no activation, no entitlement checks
(repo-wide grep: no matches). The whole feature is gated by one thing you can
see: an **API key you paste into Settings**.

## Configuration and auth

- **API URL setting** `symgraph_api_url`, default literally
  `'https://api.SymGraph'` (`settings_service.py:209, 899-901`) — a
  placeholder-looking value, not a resolvable hostname. This corroborates that
  the real deployment endpoint is not intended to be hardcoded in the open
  plugin; users point the client at their SymGraph deployment.
- **API key setting** `symgraph_api_key`, free-text in Settings (`:909-918`);
  the Settings tab has a **connection-test worker** ("Testing SymGraph API
  connection…", `settings_controller.py:429-455`).
- Auth is one header: `X-API-Key: <key>` on authenticated calls
  (`symgraph_service.py:156-165`). `_check_auth()` raises otherwise (`:172`);
  per the docs, `Refresh` works without a key while upload/import/publish
  require one (`docs/tabs/symgraph-tab.md:16-17`; *corrected 2026-11-02 — :14-15 is the section heading*).
- History: an early `symgraph_enabled` boolean feature flag (default `'0'`,
  `git show 0603274~1:src/services/settings_service.py`) was **deleted** in
  `0603274` "Always enable SymGraph UI" (2026-04-19; *date corrected 2026-11-02 — earlier draft said "Oct 2025", ~18 months off*) — the UI is now
  unconditionally constructed (`idassist_form.py:108, 269-282`).
- Private-network handling exists (`_is_private_network`, `:177`), implying
  self-hosted deployments are expected.

## The API surface (as used by the client)

Fourteen distinct `/api/v1` route templates (`symgraph_service.py`, grep of
`base_url`):

```
POST   /api/v1/analysis/upload                       raw-binary upload (:361-392)
GET    /api/v1/binaries/{sha256}                     existence/info + stored-binary flag (:255, :325)
GET    /api/v1/binaries/{sha256}/stats               remote counts (:287)
GET    /api/v1/binaries/{sha256}/versions           revision list (:394)
GET    /api/v1/binaries/{sha256}                     query w/ versions (:427)
GET    /api/v1/binaries/{sha256}/symbols             symbol pull (:482)
GET    /api/v1/binaries/{sha256}/documents           + /{identity_id} doc pull (:539, :579)
POST   /api/v1/binaries/{sha256}/versions           create revision (create_binary_revision :621, posts :631)
POST   /api/v1/binaries/{sha256}/import             import symbols payload (import_symbols :890, posts :904)
PATCH  /api/v1/binaries/{sha256}                     binary metadata (update_binary_metadata :662, `client.patch` :691; *verb/cites corrected 2026-11-02 — earlier draft said PUT/:662 and mislabeled /import as revision creation*)
POST   /api/v1/binaries/{sha256}/symbols/bulk        symbol push (push_symbols_bulk :709; chunked variant push_symbols_chunked :759)
POST   /api/v1/binaries/{sha256}/graph/import       graph push (:990)
POST   /api/v1/binaries/{sha256}/documents/bulk     document push (:809)
POST   /api/v1/binaries/{sha256}/fingerprints       fingerprint add (:1101)
GET    /api/v1/binaries/{sha256}/export  and  /graph/export   (server-side export support)
```

So the server model is: **binary (by SHA-256) → revisions → symbols,
documents, graph, fingerprints**, plus raw-binary storage. Everything the
plugin computes locally (semantic graph, document chunks, renames) has an
upload path; nothing about the analysis is done server-side that the client
reveals.

## Push semantics — the notable finding: full raw-binary upload

`PushWorker` (the "Publish/Push to SymGraph" action) runs, in order
(`symgraph_controller.py:129-262`; *span corrected 2026-11-02 — `PushWorker` class :129, `run()` :160-262, the 7-step call sequence :168-243; :75/:101 are QueryWorker/UploadWorker*):

1. `upload_binary(filename, upload_bytes)` — if the server doesn't already
   store the raw binary (`ensure_binary_upload` / `_last_has_stored_binary`,
   `:1218-1246`);
2. `create_binary_revision(...)`;
3. `update_binary_metadata(...)`;
4. `push_symbols_chunked(...)`;
5. `import_graph_chunked(...)` (semantic graph);
6. `push_documents_bulk(...)` (RAG document chunks + Q&A pairs);
7. `add_fingerprint(...)` per selected symbol (the "apply symbols" fingerprint
   mechanism).

The bytes come from `_build_binary_upload_payload`: it opens
**`ida_nalt.get_input_file_path()` — the complete original input file — and
reads it whole** (`symgraph_controller.py:958-972`; def :958, path read :963, `open(...).read()`
:969-970; *span corrected 2026-11-02 — earlier draft's :958-966 excluded the actual read*); if the original file is gone from disk, push
fails with "unable to access raw binary bytes for upload" (`:1228-1233`, message at :1232), and
the docs repeat the caveat (`docs/tabs/symgraph-tab.md:18-19`). A manual
"Upload Binary" button does the same without publishing (`symgraph-tab.md:37`; *cite corrected
2026-11-02 — :31 is a different bullet*).

**Security/privacy implication:** publishing analysis to SymGraph means, by
default, uploading the **entire sample** to the service (deduped by SHA-256,
with a stored/not-stored status surfaced in the UI). For malware, leaked
firmware, or client work, that is a hard policy question. Visibility is a
push parameter (`visibility=visibility` at `symgraph_controller.py:1241`; *corrected 2026-11-02 — was cited as :1240*) — presumably private/shared
scoping — but the *service-side* meaning of that flag is unknowable from the
clone, and the marketing site is inaccessible, so data handling, retention,
and the ToS must be checked directly with the vendor before anyone
reverse-engineers sensitive material with this feature.

## What's deliberately (or accidentally) missing client-side

- **No OAuth, no login flow, no token exchange of any kind** in the current
  tree for SymGraph — the earlier draft's `anthropic_pkce.py` /
  `syncAnthropicOAuthToSymGraph` story does not exist in the clone (verified
  by repo-wide grep). IDAssist's OAuth features (OpenAI/Codex/Gemini, ch 33)
  stay entirely local to the LLM providers; nothing LLM-related flows to
  SymGraph through the client.
- **No license/entitlement checks** for SymGraph (grep-verified) — the
  commercial gating is entirely server-side behind the API key.
- **No encryption at rest client-side**; transport is plain HTTPS via httpx
  (`_client_kwargs`, `:195`).
- The malformed default URL (`'https://api.SymGraph'`) means a fresh install
  with a pasted key still needs a correctly entered URL — practical evidence
  the hosted endpoint is configuration, not code.

## What SymGraph is, in one paragraph

A SHA-256-keyed, API-key-authenticated **analysis-sync backend**: the plugin
ships the raw binary, versioned symbol sets, the semantic graph, document/RAG
chunks, and per-symbol fingerprints to it, and can pull any of them back into
another IDA database (pull call sites: `symgraph_controller.py:91` query, `:307` `get_symbols`,
`:323` `list_documents`, `:335` `export_graph`, `:1613` `get_document`; *cites corrected
2026-11-02 — ":228, :244" pointed at push-side payload code in both files*). Its
apparent purpose is team/personal analysis continuity — "someone (or an
earlier session of you) already reverse-engineered this binary" — with a web
console whose internals are not public. Its trust surface is the sample
upload, which is larger than the analysis upload itself.

## Findings for calxgloss

1. **The binary-upload-plus-analysis-sync model is the real differentiator.**
   calxgloss's vault is strictly local and text-only (glossaries,
   call/signature indexes — see `10-calxgloss-baseline.md`). IDAssist+SymGraph
   betrays the sample to gain cross-session/cross-machine continuity. If
   calxgloss ever wants sync, the honest options are E2E-encrypted analysis
   (never the raw binary) or BYO-storage; the sample-upload model is a
   non-starter for the malware/firmware audiences calxgloss targets.
2. **Binary identity as the join key** (SHA-256 → revisions → typed bundles)
   is a clean, replicable data model for a *local* multi-DB calxgloss vault:
   the same binary opened in two `.i64`s today gets two disconnected
   projection layers (ADR-0004, DB sidecar).
3. **Fingerprints for "already applied" tracking** is a pragmatic pattern
   IDAssist uses to make re-applying remote symbols idempotent (ch 37's
   apply path); calxgloss's projection layer makes re-application a
   non-event, so this is a pattern calxgloss gets for free rather than needs.
4. **Negative result as product boundary:** no OAuth-to-cloud, no license
   checks, no LLM traffic in the SymGraph path — the cloud feature and the AI
   feature are cleanly separated. That separation is worth copying in spirit:
   if calxgloss ever ships sync, keep it orthogonal to the analysis engines.

## Sources

- Local clone `/tmp/opencode/IDAssist` @ `09dd910d…`, read line-level for
  this chapter: `symgraph_service.py` (settings-backed properties 121-152,
  headers 156-165, `_check_auth` 172, `_is_private_network` 177,
  `get_stored_binary_flag` 325-331, `upload_binary` 361-392,
  `create_binary_revision` 621, `update_binary_metadata` 662-687,
  `push_symbols_chunked` 759 (bulk twin 709; *corrected 2026-11-02 — the controller's only call, :197, is the chunked method*), documents bulk 809, graph import 990,
  fingerprints 1101); `symgraph_controller.py` (PushWorker call sequence
  129-262, `_get_original_binary_metadata` 909-925,
  `_build_binary_upload_payload` 958-972, push gating 1218-1246);
  `settings_service.py` (209, 899-918); `settings_controller.py` (429-455);
  `idassist_form.py` (108, 269-282).
- Git: `0603274` diff (deleted `symgraph_enabled` flag, default `'0'`).
- Docs: `docs/tabs/symgraph-tab.md:1-31`, `docs/index.md:10, 25-26`.
- Negative (grep-verified over the whole clone): no `isSymgraphLicenseActive`,
  no `licensing`/`wizard`/`pkce` modules, no `accessToken`/`auth/google`/
  `auth/github` routes, no OAuth sync flow.
- External: https://www.SymGraph.com (fetch returned Cloudflare 403 on
  2026-11-02; no product claims can be sourced from it).
