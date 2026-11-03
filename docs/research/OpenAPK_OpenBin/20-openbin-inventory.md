# OpenAPK / OpenBin complete surface inventory

> Part of the [OpenAPK/OpenBin overview](README.md). This is the fixed
> surface map every later domain file compares against. Source: the clone
> at `/tmp/opencode/openbin` @ `aee59b05` (2026-10-12, "feat(ctf): weekly
> CTF…"), branch `master`. Every LOC figure is `find … | xargs wc -l` run
> on the clone today; every route/mapping is grepped out of the Java
> annotations; the 47 migrations were each read in full. Claims cite
> clone-relative `path:line`. Counts for tables/endpoints/commands/workers
> are exhaustive greps, not estimates.

**Repo one-liner** (`README.md:1-9`): two SaaS products — **OpenAPK**
(openapk.ai, Android RE: APK → JADX decompile → AI Q&A → MAR/VRR reports)
and **OpenBin** (openbin.ai, native RE: ELF/PE/Mach-O → Ghidra decompile
via a local CLI) — sharing one Spring Boot backend, one Keycloak realm, one
Postgres, one repo. AGPL-3.0-or-later + CLA dual-license
(`CONTRIBUTING.md:23-33`).

## 1. Component scale (measured)

| Component | Lang | Files | LOC | What |
|---|---|---|---|---|
| `core/` | Java 21, Spring Boot **4.0.6** (`core/pom.xml:5-9`) | 361 main + 9 test | **32,558** main / 1,625 test | Monolith: REST, JPA/Postgres, Flyway, OIDC resource server, S3/CloudFront, SES, BYOK LLM clients |
| `core/src/main/resources/db/migration/` | SQL | 47 | 1,245 | Flyway V1–V47 (§4) |
| `core/src/main/resources/application.yml` | YAML | 1 | 307 | entire runtime config incl. self-host switches (§3.3) |
| `cli/` | Go 1.18, cobra + bubbletea (`cli/go.mod:7-11`) | 25 (3 test) | **5,134** (297 test) | `openbin` CLI: local Docker Ghidra/jadx + S3 ingest (§6) |
| `ghidra-worker/` | Python (Jython script) | 4 py | **1,163** | FastAPI wrapper around `analyzeHeadless`; Ghidra **11.2.1** pinned (`ghidra-worker/Dockerfile:6-7`) |
| `jadx-worker/` | Python | 2 py | **315** | FastAPI wrapper around `jadx` CLI under prlimit |
| `script-worker/` | JS (Node 22 Lambda) | 8 src+test js | **1,428** src + 240 test | NPM supply-chain analyzer + deobfuscation engines |
| `shell-worker/` | Python 3.12 Lambda | 4 py | **596** | regex analyzer for .ps1/.sh droppers |
| `pypi-worker/` | Python 3.12 Lambda | 5 py | **1,140** | PyPI supply-chain analyzer (AST, 8 rules) |
| `openapk-frontend/` | TS/TSX, React 19 + Vite + Tailwind 4 | 57 ts/tsx | **13,859** (7,104 in `src/pages`, 19 pages) | openapk.ai web app |
| `openbin-frontend/` | TS/TSX, React 19 + Vite + Tailwind 4 | 56 ts/tsx | **19,916** (15,711 in `src/pages`, 30 pages) | openbin.ai web app |
| `shared/` | TS/TSX | 52 | **6,119** | API client, OIDC, feature components shared by both apps (§5.3) |
| `openbin-landing/` | TS/TSX, React + GSAP/motion | 5 src | **1,407** | marketing site (Vite/React, *not* static/Astro) |
| `dev.sh` | bash | 1 | 257 | starts core + both Vites, tails logs (`dev.sh:3-18`) |

Measured totals: **32,558** Java main · **5,134** Go · **4,882** worker
Python/JS (incl. script-worker's 240 test LOC) · **41,301** TS/TSX (both
apps + shared + landing) · **1,245** SQL. Main-language total ≈ **84k
LOC** excluding configs/lockfiles/assets (87k with core tests + SQL).

## 2. `core/` package-by-package map

34 packages under `core/src/main/java/ai/openapk/core` (+ root
`CoreApplication.java`, 12 LOC). LOC includes each package's `dto/`
subpackage. "Tables" = JPA repositories/tables the package touches
(grepped `*Repository` usage per package).

| Package | LOC | Files | Controllers → base path | Key services/classes | Tables |
|---|---|---|---|---|---|
| `account` | 398 | 3 | `AccountController` → `/api/account` | `AccountDeletionService` (anonymize + Keycloak admin delete), `KeycloakAdminClient` (Admin REST, no admin-client dep) | users (+cascade) |
| `analysis` | 4,548 | 12 (+agent 12) | `AnalysisController` → `/api/projects/{id}`; `agent/BinnyController` → `/api/projects/{id}/binny` | `AnalysisService`, `PromptBuilder`, `StaticDigestService`+`BinaryDigestService` (no-token pre-scans), `IoCExtractor`, `LlmInvoker`/`StreamingLlmInvoker` (BYOK dispatch incl. Bedrock SigV4), `AnalysisMode` (MALWARE/VULN_RESEARCH); `agent/`: **BINNY light** agent loop — `BinnyAgentService` ("no sandbox, no sample bytes" :1-8), `ToolLlmInvoker`, `BinnyToolkit` with **8 tools**: `get_function` (:101), `find_functions` (:139), `list_strings` (:179), `read_file` (:209), `search_code` (:247), `create_highlight` (:277), `write_report_section` (:306), `save_script` (:337) | projects, llm_credentials, project_scripts, project_highlights, project_reports (via tools) |
| `auth` | 345 | 4 | `UserController` → `/api/users/me` | `User` entity, `CurrentUserService` (JIT provisioning from JWT), `UserRepository` | users |
| `blog` | 764 | 7 | `BlogController` → `/api/blog`; `BlogPublicController` → `/api/community/blog` | `BlogService` (slug frozen at first publish) | blog_posts, post_votes, report_comments (post_id) |
| `bundles` | 347 | 4 | `BundleController` → `/api/bundles` | `BundleService` (groups standalone BIN projects; creation CLI-only in v1, V37) | bundles, projects |
| `callchain` | 813 | 2 | `CallChainController` → `/api/projects/{id}/callchains` | `CallChainService` — walks `project_usages` up/down bounded by depth+fan-out; optional LLM narration | project_usages (+ llm via credentials) |
| `config` | 427 | 5 | — | `SecurityConfig` (resource-server chain, §3.2), `CryptoConfig` (AES-256-GCM KEK), `AsyncConfig`, `AsyncStreamingConfig` (SSE), `OpenApkProperties` | — |
| `credentials` | 1,197 | 16 | `LlmCredentialController` → `/api/credentials` | `LlmCredentialEncryptionService` (AES-256-GCM, per-record IV, KEK from `OPENAPK_KEK_B64`), `LlmCredentialPayloadCodec`, `LlmCredentialTester`, `LlmModelCatalog` (dynamic model discovery), `EgressUrlPolicy` (SSRF denylist: loopback, 169.254/16 IMDS, v6-mapped IPv4 unwrapped, :36-38,120-132), `OutboundLlmHttp` (no-redirect), `EgressAllowlistConfigurer`; 8 providers (`anthropic,openai,bedrock,gemini,deepseek,qwen,kimi,openai_compat`, V36) | llm_credentials |
| `crypto` | 732 | 2 | `CryptoController` → `/api/projects/{id}/crypto` | `CryptoService` — finds crypto constants/IOCs in decompiled output, generates recreator code ("generate" Java→Python; "generate-bin" for Ghidra C) | llm_credentials |
| `ctf` | 1,046 | 8 | `CtfController` → `/api/ctf`; `CtfPublicController` → `/api/public/ctf` | `CtfService` (flag = `sha256(salt:flag)`, rank/points), `CtfScheduler` (`@Scheduled fixedDelay=60s`, weekly windows), `DiscordNotifier` (webhook announcements) | ctf_challenges, ctf_solves, ctf_submissions, projects, users |
| `dbschema` | 323 | 2 | `DbSchemaController` → `/api/projects/{id}/dbschemas` | `DbSchemaService` — mines SQLite `CREATE TABLE` literals + Android Room `@Entity` classes out of the decompiled tree (:1-10) | — (scans project storage) |
| `deobf` | 423 | 2 | `DeobfuscationController` → `/api/projects/{id}/deobfuscations` | `DeobfuscationService` — LLM-cleaned versions of obfuscated Ghidra functions (view-layer only, never rewrites index) | function_deobfuscations |
| `dm` | 888 | 9 | `DmController` → `/api/dm` | `DmService` (1:1 + project group chat, per-member read cursors), `DmPolicy` (EVERYONE/FOLLOWING/NOBODY) | dm_conversations, dm_members, dm_messages, follows, users |
| `highlights` | 334 | 5 | `ProjectHighlightController` → `/api/projects/{projectId}/highlights` | `ProjectHighlightService`, `HighlightType` FUNCTION/FILE/VISUAL (V32) | project_highlights |
| `jnibridge` | 655 | 2 | `JniBridgeController` → `/api/projects/{id}/jni-bridge` | `JniBridgeScanService` — matches `System.loadLibrary` call sites ↔ `.so` exports ↔ `native` declarations | projects (jni_bridge_jsonb), native_analyses |
| `manifest` | 346 | 2 | `ManifestController` → `/api/projects/{id}/manifest` | `ManifestService` — parses JADX `AndroidManifest.xml`: permissions, 4 component kinds, intent filters, effective exported | — (project storage) |
| `media` | 277 | 2 | `MediaController` → `/api/projects/{id}/media` | `MediaService` — gallery store per project; serves via presigned 302 (S3) or streams file (fs) | projects |
| `nativeanalysis` | 1,239 | 10 | `NativeAnalysisController` → `/api/projects/{id}/native` | `NativeAnalysisService`/`Runner`/`TxOps`/`JsonLoader` (per-`.so` Ghidra lifecycle), `NativeAnalysisIngestService` (S3 presign flow), `GhidraWorkerClient` | native_analyses |
| `network` | 234 | 2 | `NetworkController` → `/api/projects/{id}/network` | `NetworkService` — line-regex scan of decompiled tree for **Retrofit** `@GET/@POST`, **OkHttp** `.url(…)`+verb pairing, **HttpURLConnection** `new URL(...)`→`openConnection()` (:27-38) | — |
| `notifications` | 736 | 6 | `NotificationController` → absolute paths under `/api/me/email-preferences` + `/api/notifications*` | `NotificationService` (bell + same-event transactional email; kinds NEW_FOLLOWER, COMMENT_ON_MY_REPORT, REPLY_TO_MY_COMMENT, COLLABORATOR_INVITE — V29) | notifications, user_email_preferences |
| `projects` | 6,469 | 34 (+sub-pkgs 17) | `ProjectController` → `/api/projects`; `ingest/IngestController` → `/api/projects/ingest`; `samples/ProjectSampleController` → `/api/projects/{id}/samples` | `ProjectService` (upload, file tree, rename-on-read serving, delete w/ shared-blob refcount), `ProjectAccessGuard` (owner-OR-collaborator single query + `ProjectRole` VIEWER/EDITOR), `ProjectPublicGuard` (404-everything-private), `ProjectCollaboratorService`, `DedupService` (sha256 → PUBLIC projects only, CLI fork-first flow), `BinaryDecompileService`/`JadxDecompileService`+`GhidraWorkerClient`/`JadxWorkerClient`, `GhidraSunsetMessage`/`JadxSunsetMessage` (cloud decompute sunset), presence; `analysis/`: `AnalysisStorageService`+`AnalysisStorageConfig` (dedicated analysis bucket), `BinaryAnalysisLoader` (single JSONB-or-S3 read path), `AnalysisMetadataExtractor`, `CloudFrontUrlSigner`; `storage/`: `ProjectStorage` iface + `FilesystemProjectStorage` + `S3ProjectStorage` + `CacheEvictor` (LRU, disk-pressure); `samples/`: multi-sample rows | projects, project_collaborators, project_presence, project_samples, bundles, users, dm_members |
| `publicread` | 116 | 1 | `PublicProjectController` → `/api/public/projects/{id}` | anonymous read surface: metadata, highlights, report, media; code view (`/binary-analysis`) requires auth (`SecurityConfig:47-51`) | (reads via other pkgs) |
| `renames` | 1,091 | 5 | `RenameController` → `/api/projects/{id}/renames` | `RenameService` — SUGGESTED/APPLIED renames replayed at file-serve time; LLM suggest per-function/global; manual; scoped-unique (project, original, source_path) since V39 | project_renames |
| `reports` | 2,929 | 15 | `ProjectReportController` → `/api/projects/{id}/report`; `ReportTemplateController` → `/api/report-templates`; `CommunityController` → `/api/community` | `ProjectReportService` (sections JSONB, publish/unpublish, community publish, populate-from-analysis, Markdown export), `ReportTemplateService` (`TemplateMode` MALWARE/VULN_RESEARCH/ANY), `CommunityService` (feed + tsvector search + abuse reports), `ReportContributorService` (byline snapshot LEAD/CONTRIBUTOR), `MalwareTypes` (STIX 2.1 `malware-type` vocabulary, 22 values, V19), `EmailService` (AWS SESv2) | project_reports, report_templates, report_contributors, follows/votes/comments (joins), projects |
| `script` | 1,588 | 9 | `ScriptAnalysisController` → `/api/projects/script` | `ScriptAnalysisService` (SCRIPT kind upload→Lambda), `ScriptEcosystemDetector` (sniffs npm/pypi/shell by magic bytes+paths), `ScriptWorkerInvoker` iface + `HttpScriptWorkerInvoker` (self-host RIE) + `LambdaInvoker` (AWS SDK), `ScriptDeobfuscationRepository` | script_analyses, script_deobfuscations, projects |
| `scripts` | 246 | 4 | `ProjectScriptController` → `/api/projects/{projectId}/scripts` | `ProjectScriptService` — saved analyst/BINNY scripts, never executed server-side (V46) | project_scripts |
| `search` | 176 | 2 | `SearchController` → `/api/projects/{id}/search` | `SearchService` — regex walk of decompiled tree (SDK-path filtering via `util/SdkPaths`) | — |
| `social` | 1,576 | 9 | `SocialController` → `/api/social` | `SocialService` (follows, upvotes, feed per kind), `CommentsService` (threaded, soft-deleted, notifications wired) | follows, report_votes, report_comments, project_reports, blog_posts, users |
| `symbols` | 1,186 | 6 | `SymbolController` → `/api/projects/{id}/symbols` | `SymbolService` + `LookupIndex` (declarations cached in `projects.symbol_index_jsonb`); `usages/`: `UsageIndexerService` (post-JADX one-pass reverse-index), `ProjectUsageRepository` (JdbcTemplate, not JPA — `project_usages` has no entity) | projects, project_usages |
| `tos` | 295 | 4 | `TosController` → `/api/me/tos`, `/api/me/tos/accept`, `/api/tos.md` | `TosService` (version gate, current `2026-06-05`), `TosAcceptanceFilter` (HTTP 412 + JSON body on mismatch, :25-97) | users (tos_accepted_*) |
| `usage` | 656 | 6 | `LlmUsageController` → `/api/usage` | `LlmUsageService` (audit + daily/monthly summaries), `WorkerQuotaService` (Phase-0 hardcoded daily cap, default 5, `application.yml:244`) | llm_audit_log, llm_user_limits, worker_runs |
| `util` | 33 | 1 | — | `SdkPaths` (Android SDK package prefixes for SDK-vs-app filtering) | — |
| `web` | 113 | 2 | `MeController` → `/api/me` (GET/PATCH profile incl. V40 social fields); `PublicConfigController` → GET `/api/public/config` (self-host runtime config discovery) | — | users |

Sub-package LOC: `analysis/agent` 1,512 · `projects/analysis` 745 ·
`projects/ingest` 415 · `projects/samples` 704 · `projects/storage` 977 ·
`symbols/usages` 431.

## 3. REST surface

**39 `@RestController`s, 178 method mappings** (counted: `grep -rh -E
'@(Get|Post|Put|Patch|Delete)Mapping' --include='*Controller.java' | wc -l`
= 178; per-controller sums below match). Paths = class `@RequestMapping` +
method mapping.

### 3.1 Controller table

| Controller | Base | Endpoints (verb path) |
|---|---|---|
| `AccountController` | `/api/account` | DELETE `/` (deletion) |
| `AnalysisController` | `/api/projects/{id}` | POST `/analyze` · GET `/analysis` · POST `/digest/rescan` · POST `/ask` · POST `/ask/stream` (SSE) · POST `/ask-function/stream` (SSE) |
| `BinnyController` | `/api/projects/{id}/binny` | POST `/stream` (SSE agent turn) |
| `UserController` | `/api/users/me` | GET · PATCH |
| `BlogController` | `/api/blog` | GET · POST · PUT `/{id}` · POST `/{id}/publish` · DELETE `/{id}` · POST `/{id}/upvote` |
| `BlogPublicController` | `/api/community/blog` | GET · GET `/authors/{authorId}` · GET `/{slug}` · GET `/{slug}/comments` |
| `BundleController` | `/api/bundles` | GET · GET `/{id}` · POST · PATCH `/{id}` · DELETE `/{id}` |
| `CallChainController` | `/api/projects/{id}/callchains` | POST `/build` · POST `/narrate` · POST `/narrate-bin` |
| `LlmCredentialController` | `/api/credentials` | GET · POST · DELETE `/{id}` · POST `/{id}/test` · GET `/{id}/models` |
| `CryptoController` | `/api/projects/{id}/crypto` | GET `/hits` · POST `/generate` · POST `/generate-bin` |
| `CtfController` | `/api/ctf` | POST `/challenges/{slug}/submit` · POST `/challenges/{slug}/writeup` · GET `/me` |
| `CtfPublicController` | `/api/public/ctf` | GET (current) · GET `/challenges` · GET `/challenges/{slug}` · GET `/leaderboard` |
| `DbSchemaController` | `/api/projects/{id}/dbschemas` | GET |
| `DeobfuscationController` | `/api/projects/{id}/deobfuscations` | GET · POST · DELETE |
| `DmController` | `/api/dm` | GET `/conversations` · GET+PUT `/settings` · GET `/unread-count` · POST `/conversations/with/{userId}` · POST `/conversations/for-project/{projectId}` · GET `/conversations/{id}` · GET+POST `/conversations/{id}/messages` · POST `/conversations/{id}/read` |
| `ProjectHighlightController` | `/api/projects/{projectId}/highlights` | GET · POST · PATCH `/{highlightId}` · DELETE `/{highlightId}` |
| `JniBridgeController` | `/api/projects/{id}/jni-bridge` | GET · POST `/rescan` |
| `ManifestController` | `/api/projects/{id}/manifest` | GET |
| `MediaController` | `/api/projects/{id}/media` | POST · GET · GET `/{name}` · DELETE `/{name}` |
| `NativeAnalysisController` | `/api/projects/{id}/native` | GET `/libraries` · POST `/analyze` · GET `/result` · POST `/ingest/initiate` · POST `/ingest/finalize` |
| `NetworkController` | `/api/projects/{id}/network` | GET |
| `NotificationController` | — (absolute) | GET+PATCH `/api/me/email-preferences` · GET `/api/notifications` · GET `/api/notifications/unread-count` · POST `/api/notifications/{id}/read` · POST `/api/notifications/read-all` |
| `IngestController` | `/api/projects/ingest` | POST `/` · POST `/initiate` · POST `/finalize` |
| `ProjectController` | `/api/projects` | GET · GET `/dedup` · POST · GET+PATCH+DELETE `/{id}` · PUT+DELETE `/{id}/public` · POST `/{id}/fork` · GET `/{id}/files` · GET `/{id}/file` · GET `/{id}/source-bundle` · GET `/{id}/file/raw` · GET `/{id}/members` · POST `/{id}/presence` · GET+POST `/{id}/collaborators` · DELETE `/{id}/collaborators/{userId}` · GET `/{id}/binary-analysis` |
| `ProjectSampleController` | `/api/projects/{id}/samples` | GET · GET `/{sampleId}/binary-analysis` · POST `/ingest/initiate` · POST `/ingest/finalize` · POST `/move-from` · PATCH+DELETE `/{sampleId}` |
| `PublicProjectController` | `/api/public/projects/{id}` | GET · GET `/binary-analysis` (auth-gated) · GET `/highlights` · GET `/report` · GET `/media/{name}` |
| `RenameController` | `/api/projects/{id}/renames` | GET · POST `/suggest` · POST `/suggest-function` · POST `/apply` · POST `/manual` · DELETE |
| `CommunityController` | `/api/community` | GET `/apk/reports` · GET `/bin/reports` · GET `/users/{userId}/profile/{kind}` · GET `/users/{userId}/followers` · `…/following` · GET `/users/search` · GET `/reports/{id}` · GET `/reports/{id}/comments` · POST `/reports/{id}/abuse` · GET `/reports/{reportId}/media/{filename}` |
| `ProjectReportController` | `/api/projects/{id}/report` | GET · PUT · POST `/populate` · `/publish` · `/unpublish` · `/community/publish` · `/community/unpublish` · `/apply-template` · `/save-as-template` · GET `/export.md` |
| `ReportTemplateController` | `/api/report-templates` | GET · GET `/{id}` · POST · PUT `/{id}` · DELETE `/{id}` |
| `ScriptAnalysisController` | `/api/projects/script` | POST `/` · POST `/{projectId}/ask/stream` · GET `/{projectId}/bundle-url` · POST `/{projectId}/deobfuscate` · GET+DELETE `/{projectId}/deobfuscations` · GET `/{projectId}/findings` |
| `ProjectScriptController` | `/api/projects/{projectId}/scripts` | GET · GET `/{scriptId}` · POST · DELETE `/{scriptId}` |
| `SearchController` | `/api/projects/{id}/search` | GET |
| `SocialController` | `/api/social` | PUT `/profile/{kind}` · POST+DELETE `/follows/{userId}` · POST+DELETE `/votes/{reportId}` · GET `/feed/{kind}` · POST `/comments` · DELETE `/comments/{commentId}` |
| `SymbolController` | `/api/projects/{id}/symbols` | GET · POST `/rebuild` · GET `/definition` · GET `/usages` |
| `TosController` | — (absolute) | GET `/api/me/tos` · POST `/api/me/tos/accept` · GET `/api/tos.md` |
| `LlmUsageController` | `/api/usage` | GET `/summary` · GET `/audit` · PUT `/limits` |
| `MeController` | `/api/me` | GET · PATCH |
| `PublicConfigController` | — (absolute) | GET `/api/public/config` |

(Per-controller sums 1+1+6+2+6+4+5+3+5+3+3+4+1+3+10+4+2+1+4+5+1+6+3+19+7+
5+6+10+10+5+7+4+1+8+4+3+3+2+1 = **178**; largest: `ProjectController` 19,
`ProjectSampleController` 7.)

### 3.2 Auth pattern

Spring OAuth2 **resource server** with JWT from the shared Keycloak realm
(`application.yml:27-29`, issuer `…/realms/openapk`); stateless, CSRF off,
`anyRequest().denyAll()` outside `/api/**`
(`config/SecurityConfig.java:29-68`): `/api/community/**` and
`/api/public/**` permitAll (public-read surface gated per-request by
`ProjectPublicGuard`, 404-no-existence-leak), but
`/api/public/projects/*/binary-analysis` is authenticated *before* the
permitAll (:47-58); `/api/tos.md` permitAll; everything else under
`/api/**` authenticated. On top: `TosAcceptanceFilter` returns **412** for
un-accepted TOS versions (`tos/TosAcceptanceFilter.java:39,97-101`), and
`@EnableMethodSecurity` is on (`SecurityConfig.java:23`). CORS allowlist
+ credentials (:72-85). No session/cookie auth anywhere.

### 3.3 BYOK + cloud-worker gates

All LLM calls are bring-your-own-key (`spring.ai.*.api-key:
disabled-byok-only`, `application.yml:41-45`), encrypted at rest with a
user-scoped AES-256-GCM vault (KEK env, `application.yml:73`, notes
`README.md:140-145`); egress is SSRF-guarded (`credentials/`, §2). Cloud
Ghidra **and** cloud JADX decompile are both **disabled by default**
(`application.yml:184,204`, sunset comments — "AWS compute cost outpaced
what a free OSS project can carry"); the desktop CLI replaced them, and
`usage/WorkerQuotaService` caps 5 cloud-worker dispatches/user/day
(:244). The three script analyzers run as Lambdas in prod / HTTP+RIE in
self-host mode (`application.yml:210-217`, transport `lambda|http`).
Script-analyzer, SES email, Keycloak-admin, analysis-S3 all degrade to
no-op/503 when unconfigured — deliberate self-host posture.

## 4. Database — all 47 Flyway migrations

`core/src/main/resources/db/migration/`, 1,245 SQL lines total; Postgres 16
(`core/compose.yaml:3`). **34 tables** created (grep `CREATE TABLE` = 34),
**33 JPA entities**, **33 Spring Data repositories**; `project_usages` is
the one table without an entity (JdbcTemplate in
`symbols/usages/ProjectUsageRepository.java`). `ddl-auto: validate` +
Flyway `out-of-order: true` (`application.yml:13-22`). Trigger: weighted
`tsvector` BEFORE-UPDATE trigger + GIN on `project_reports` (V19).

| V | File | Adds |
|---|---|---|
| V1 | `V1__init.sql` | `users` (keycloak_sub UNIQUE, email, display_name, last_seen_at); `llm_credentials` (provider CHECK anthropic/openai/bedrock, `payload_ciphertext`/`payload_iv` BYTEA, UNIQUE(user_id,label)) |
| V2 | `V2__projects.sql` | `projects` (user, original_filename, size, sha256, status CHECK UPLOADED/DECOMPILING/READY/FAILED, package_name); user+sha indexes |
| V3 | `V3__project_digest.sql` | projects + `digest_jsonb`, `latest_analysis_jsonb` |
| V4 | `V4__reports.sql` | `project_reports` (project UNIQUE 1:1, title, `sections_jsonb`) |
| V5 | `V5__projects_workflow.sql` | projects + `name` VARCHAR(200) NOT NULL (backfilled from filename), `workflow_status` (NEW/TRIAGING/ANALYZING/DRAFTING_REPORT/PUBLISHED); reports + `published_at` (NULL=draft) |
| V6 | `V6__renames.sql` | `project_renames` (original/suggested/scope/status SUGGESTED-APPLIED/confidence/source_path/rationale, UNIQUE(project,original)) + partial index on APPLIED |
| V7 | `V7__project_symbol_index.sql` | projects + `symbol_index_jsonb` (declarations only; usages were grep-at-query-time until V13) |
| V8 | `V8__native_analyses.sql` | `native_analyses` (per-(project,lib_path) `.so` Ghidra result: arch, size, status, `result_jsonb`; UNIQUE project+lib) |
| V9 | `V9__project_analysis_mode.sql` | projects + `analysis_mode` DEFAULT 'MALWARE' (drives MAR vs VRR template) |
| V10 | `V10__report_templates.sql` | `report_templates` (user, name, mode CHECK MALWARE/VULN_RESEARCH/ANY, `sections_jsonb`, UNIQUE(user,name)) |
| V11 | `V11__llm_usage.sql` | `llm_audit_log` (per-call: provider/model/purpose/tokens/success; project_id deliberately non-FK) + `llm_user_limits` (daily/monthly token caps, NULL=unlimited) |
| V12 | `V12__project_file_tree_cache.sql` | projects + `file_tree_jsonb` (pre-built tree at JADX completion; avoids 100k+ stats) |
| V13 | `V13__project_usages.sql` | `project_usages` (row per file,line,name: `enclosing_method`, `is_sdk` precomputed, kind method/ctor/ref; single-char identifiers skipped; lookup index (project,name,is_sdk)) |
| V14 | `V14__decompile_progress.sql` | projects + `decompile_phase` (OPENING_APK…INDEXING_USAGES), `decompile_started_at` |
| V15 | `V15__jni_bridge.sql` | projects + `jni_bridge_jsonb` |
| V16 | `V16__project_kind_and_binary_metadata.sql` | projects + `kind` DEFAULT 'APK' (**OpenBin groundwork**: APK vs BIN); + arch/executable_format/compiler/language_id/image_base; + `binary_analysis_jsonb` |
| V17 | `V17__function_deobfuscations.sql` | `function_deobfuscations` (per-function LLM-cleaned C + model + tokens, UNIQUE(project,original_name)) |
| V18 | `V18__community_publish.sql` | reports + `community_published_at` (separate from finalize) + partial DESC index |
| V19 | `V19__report_taxonomy_and_search.sql` | reports + `malware_type` TEXT (STIX 2.1 vocabulary, 22 values), `tags TEXT[]` (app caps 8×32), `search_tsv` + refresh trigger (weights A=title, B=tags/type, D=sections) + GIN/tags/type partial indexes |
| V20 | `V20__worker_runs.sql` | `worker_runs` (per cloud-worker dispatch audit + quota source) |
| V21 | `V21__user_email_preferences.sql` | `user_email_preferences` (opt-out booleans: decompile_complete, report_published, abuse_confirmation) |
| V22 | `V22__project_binary_analysis_s3.sql` | projects + `binary_analysis_s3_key/etag/size` — the **S3 ingest v2** migration (CLI presigned PUT; JSONB kept nullable as dual-read fallback; orphan sweep index on INGEST_PENDING) |
| V23 | `V23__projects_status_ingest_pending.sql` | projects status CHECK widened: + `INGEST_PENDING` (prod bugfix — V22 shipped the value before the constraint allowed it) |
| V24 | `V24__users_tos_acceptance.sql` | users + `tos_accepted_version VARCHAR(32)` (YYYY-MM-DD scheme), `tos_accepted_at` |
| V25 | `V25__native_analyses_s3.sql` | native_analyses + `analysis_s3_key/etag/size` + INGEST_PENDING index (same flow as V22, for attached `.so`s) |
| V26 | `V26__project_collaborators.sql` | `project_collaborators` (PK(project,user), role CHECK VIEWER/EDITOR — never OWNER, `invited_by` non-cascade; both-direction indexes) |
| V27 | `V27__follows_and_votes.sql` | `follows` (CHECK no self-follow) + `report_votes` (no downvotes by design — abuse flow covers negation) |
| V28 | `V28__comments_and_notification_prefs.sql` | `report_comments` (1-level nesting via parent, soft delete, 1-4000 char DB CHECK) + email-pref columns notify_new_follower / comment_on_my_report / reply_to_my_comment / collaborator_invite |
| V29 | `V29__in_app_notifications.sql` | `notifications` (kind TEXT, payload JSONB w/ actor_gravatar fields baked in, `link` = frontend route baked at write time, partial unread index) |
| V30 | `V30__script_analyses.sql` | `script_analyses` (PK=project, `findings_jsonb` in Postgres, `bundle_s3_key` in S3, `findings_text` + `'simple'` tsvector GIN, severity counts, package name/version) — SCRIPT project kind |
| V31 | `V31__project_presence.sql` | `project_presence` (PK(project,user), `last_active_at` heartbeat; covers owner too) |
| V32 | `V32__project_highlights.sql` | `project_highlights` (type CHECK FUNCTION/FILE/VISUAL, target_ref, media_key, tag, note, position, `created_by` SET NULL; CHECK anchors need target_ref) |
| V33 | `V33__report_contributors.sql` | renames + `applied_by`; reports + `updated_by`; users + `credit_publicly` opt-out; `report_contributors` byline snapshot (LEAD/CONTRIBUTOR, display_name+email_md5 frozen, UNIQUE(report,user)) |
| V34 | `V34__project_public_read.sql` | projects + `public_read_at` NULL=private + partial index (GitHub-style "browse the repo") |
| V35 | `V35__project_fork.sql` | projects + `forked_from` (SET NULL — deleting a source never destroys forks) + denormalized `fork_count` + index |
| V36 | `V36__llm_provider_expand.sql` | llm_credentials provider CHECK → 8 values (+gemini/deepseek/qwen/kimi/openai_compat) |
| V37 | `V37__bundles.sql` | `bundles` (user-owned name; creation CLI-only v1) + projects.`bundle_id` (SET NULL; BundleService deletes members explicitly for refcounting) |
| V38 | `V38__script_deobfuscations.sql` | `script_deobfuscations` (per(project,file,engine): engine asked vs `engine_used`, source TEXT, note/score/baseline_score/truncated, UNIQUE) |
| V39 | `V39__renames_scoped_unique.sql` | drops UNIQUE(project,original); unique index `(project_id, original, COALESCE(source_path,''))` — uVar1/param_1 collisions across functions were silently moving renames |
| V40 | `V40__blog_posts_and_profile_socials.sql` | `blog_posts` (slug UNIQUE frozen at publish, published_at NULL=draft) + `post_votes`; report_comments generalized: report_id nullable + `post_id` + `num_nonnulls=1` CHECK; users + bio/website_url/github_user/x_user/mastodon_url/linkedin_url (handles bare, URL-validated at API) |
| V41 | `V41__project_samples.sql` | `project_samples` (N extra samples per BIN project: label, sha256 UNIQUE per project, Ghidra metadata cols, status INGEST_PENDING/READY/FAILED, S3 cols; deliberately NOT wired into renames/highlights/reports — per-sample annotation scoping deferred) |
| V42 | `V42__direct_messages.sql` | `dm_conversations` (`pair_key` canonical `"<lesser uuid>:<greater uuid>"` UNIQUE, denormalized last-message) + `dm_members` (per-member `last_read_at`) + `dm_messages` (1-4000 char CHECK); group-ready shape |
| V43 | `V43__dm_policy.sql` | users + `dm_policy` CHECK EVERYONE/FOLLOWING/NOBODY (gates behavior, not channel) |
| V44 | `V44__project_description.sql` | projects + `description` TEXT |
| V45 | `V45__project_chat.sql` | dm_conversations + `project_id` UNIQUE-partial (group chat per project; membership checked live vs roster, dm_members row = read cursor only) |
| V46 | `V46__project_scripts.sql` | `project_scripts` (name/language/description/content TEXT hard-capped/source_ref/created_by; "Nothing here is ever executed server-side") |
| V47 | `V47__ctf.sql` | `ctf_challenges` (slug UNIQUE, kind BIN/APK, public `project_id`, `flag_hash sha256(salt:flag)` + salt + hint, starts/ends, season, `announced_at` = Discord sent) + `ctf_solves` (rank 1=first blood, 0=post-window; points; `ai_assisted`; `writeup_project_id`; team_id reserved) + `ctf_submissions` (every attempt, attempted text never stored) |

## 5. Frontends

Both apps: React 19 + Vite (+`babel-plugin-react-compiler`) + Tailwind 4 +
react-router-dom 7 + `react-oidc-context` 3 / `oidc-client-ts` 3 + shiki
for highlighting (`openapk-frontend/package.json:12-30`).

### 5.1 openapk-frontend — 19 page files, 27 `<Route>` elements (`src/App.tsx:34-87`)

`/` Landing · `/community` · `/community/researchers` ·
`/community/reports/:id` · `/public/projects/:id` · `/u/:id` (+
`/followers`, `/following`) · `/terms` · `/privacy` ·
`/projects/:id/report/print` (chrome-free) · `/dashboard` · `/projects` ·
`/messages(/:id)` · `/projects/:id` · `/projects/:id/report` ·
`/settings/{profile,api-keys,report-templates,usage}` · `*`→`/`.
Pages: ApiKeys, AuthorProfilePage, Community, CommunityReport,
FollowListPage, Home, Landing, Messages, Privacy, Profile, Projects,
ProjectView, PublicProject, Report, ReportPrint, ReportTemplates,
ResearcherSearch, Terms, Usage. 21 local `src/components`.

### 5.2 openbin-frontend — 30 page files, 38 `<Route>` elements (`src/App.tsx:56-134`)

Anonymous tier (same Layout chrome, no RequireAuth): `/blog(/:slug)` ·
`/community(/researchers,/reports/:id)` · `/ctf(/:slug)` ·
`/public/projects/:id` (code view auth-gated server-side) · `/u/:id(+/followers,/following)`
· `/terms` · `/privacy` · `/docs` + `/docs/cli` (in-app how-to guide).
Full-viewport no-Layout routes: `/projects/:id/report/print`,
`/projects/:id/graph` (call graph canvas). Authed tier (`RequireAuth` +
`TosGate accent="purple"`): `/` (=Home; **must render real content
because `/` is the OIDC redirect_uri**, `App.tsx:41-48`) · `/dashboard` ·
`/projects` · `/messages(/:id)` · `/blog/new`, `/blog/:id/edit` ·
`/projects/:id/overview` · `/projects/:id` (dispatched by kind —
`pages/ProjectViewRoute.tsx:10-19`: APK|BIN→legacy ProjectView,
SCRIPT→ScriptProjectView; hook-count rationale comment) ·
`/projects/:id/report` · `/bundles/:id` ·
`/settings/{profile,api-keys,report-templates,usage}` · `*`→`/`.
Extra pages vs openapk: Blog/BlogEditor/BlogPostPage, Ctf, Docs, CliDocs,
CallGraph, BundlePage, ProjectOverview, ScriptProjectView.

### 5.3 `shared/` (52 files, 6,119 LOC)

`api/` 20 modules (client.ts `useApi()` Bearer-injecting fetch hook;
blog/community/ctf/dm/highlights/notifications/renames/reportEvents/
scripts/social/streaming SSE helpers/askSessions/forkLink/markdownLang/
me/collaborators/comments + 3 `*.test.ts`); `auth/` `makeOidcConfig`
(Code flow, `response_type: 'code'`, scope `openid profile email`,
automaticSilentRenew, localStorage store, `RequireAuth`,
`StaleSessionRecovery`), `components/` 24 feature components (CommentsThread,
HighlightsPanel, ContributorByline, NotificationsBell, MembersBar,
ShareProjectModal, ForkButton, FollowButton, UpvoteButton,
RenameSymbolDialog, StringTools, BinnyToolCards, TosGate,
dm/MessagesPage+ProjectChatPanel+DmPrivacySettings+useDmUnread…),
`config/runtime.ts` (self-host override via `/openbin-config.js` →
`window.__OPENBIN_CONFIG__`, :7-33 — each app's public copy is an empty
placeholder), `theme/light.css` (light mode via palette remap).

### 5.4 openbin-landing

Vite + React + **GSAP/motion** marketing site (1,407 LOC, single-page
`src/App.tsx` + 3 animated components: DecryptedText, HexDrift,
TabbedShowcase) — *not* Astro/static despite `index.html` + `robots.txt`
+ `sitemap.xml`/`llms.txt` in the app publics. `openbin-landing/` has
`install.sh`/`install.ps1` helpers (served installers). openapk's landing
is instead `openapk-frontend/src/pages/Landing.tsx`
(`CONTRIBUTING.md:11`).

### 5.5 OIDC flow

Both apps are separate public PKCE clients of one Keycloak 26.6.2 realm
`openapk` (`core/compose.yaml:59-64`); dev realm import
(`core/docker/keycloak/import/realm-openapk.json`) registers only
`openapk-frontend` (redirect `http://localhost:5173/*`) + `openbin-cli`
(public, non-standard-flow off); the `openbin-frontend` client is added
out-of-band per `README.md:73`. Login = Code flow w/
`automaticSilentRenew`; backend validates the same realm's JWT (§3.2).
Keycloak login theme `openbin` under `core/docker/keycloak/themes/`.

## 6. Go CLI (`openbin`)

Single package `main`, 25 files, 5,134 LOC; cobra root `openbin`
(`cmd_root.go:9-27`, defaults `api.openapk.ai` / `auth.openapk.ai`,
`config.go:19-20`). **7 subcommands**:

| Command | File | What |
|---|---|---|
| `login` | `cmd_login.go` | OAuth 2.0 **device authorization grant** (RFC 8628) against Keycloak client `openbin-cli`; tokens + expiry in `~/.config/openbin/credentials.json` (`auth.go:16-27,73-135`) |
| `whoami` | `cmd_whoami.go` | token check |
| `apk <apk\|xapk>` | `cmd_apk.go` | local jadx-worker container → POST `/api/projects` multipart **two parts streamed together: APK + decompiled tree.tar.gz** — the tree part bypasses the cloud-JADX sunset gate, charges no quota (`apk_upload.go:13-24`); XAPK/splits fold into one project |
| `decompile <bin…\|dir…>` | `cmd_decompile.go` | local Ghidra-worker → S3 ingest v2; dir/`--bundle NAME` groups into a bundle (`cmd_decompile.go:26`); firmware arch detection (`firmdetect.go`, 344 LOC), `--processor`, dedup→fork-first (`dedup.go` + GET `/api/projects/dedup`) |
| `attach-native <so>` | `cmd_attach_native.go` | analyze a `.so` and attach it to an existing APK project (V8 flow via CLI) |
| `tui [binary]` | `cmd_tui.go` | 827-LOC bubbletea wizard (charmbracelet stack, `go.mod:8-10`) |
| `update` | `cmd_update.go` | CLI self-update from GitHub releases |

**Ingest v2** (`api.go:21-27`): CLI gzips worker JSON to disk →
`POST …/ingest/initiate` mints a presigned S3 PUT → streams gzip straight
to S3 → `POST …/ingest/finalize` extracts metadata server-side; 3 retries
w/ backoff on initiate/finalize and on the PUT. Three variants:
`ingestProjectV2` (:73), `ingestNativeLib` (:194,
`/api/projects/{apkId}/native/ingest/*`), `ingestSampleV2` (:299).

**Local worker images**: never `docker pull` — images ship as
version-LESS GitHub release assets (`ghidra-worker.tar.gz`,
`jadx-worker.tar.gz`, ~350/700 MB gzipped per `cli/README.md:13-15`);
`ensureDockerImage` checks `docker inspect`, then searches next-to-binary
/ XDG data dir / `/usr/local/share/openbin` / cwd, else downloads from
`releases/latest/download` and `docker load`s (:156-214); stale-cache
re-download on tag bump (:192-196); `dockerPreflight` verifies daemon
before starting (:219-229). Image tags `openbin/ghidra-worker:7` /
`openapk/jadx-worker:bundled-2` (`config.go:62,69`) must stay in lockstep
with `.github/workflows/release-cli.yml`. Container limits:
`GHIDRA_PER_FILE_TIMEOUT` etc. rendered as `-e` flags (`ghidra.go:21-58`);
ghidra-worker logs streamed + persisted (`cli/ghidra.go:106`). Windows
unsupported (WSL2 only, `cli/README.md:19,51`).

## 7. Workers

| Worker | LOC | Runs as | Analyzes | API/transport |
|---|---|---|---|---|
| `ghidra-worker` | 1,163 py (app/main.py 262, scripts/extract.py 841, preflight.py 60) | long-lived FastAPI container, Temurin 21 + Ghidra 11.2.1 (`Dockerfile:6-7`), non-loopback trust model | ELF/PE/Mach-O + APK `.so`s via `analyzeHeadless` | `GET /health`, `POST /analyze` multipart → JSON; `GHIDRA_ANALYZE_TIMEOUT` default 1500s (`app/main.py:40`) |
| `jadx-worker` | 315 py | FastAPI container, jadx CLI under **prlimit + 900s wall clock**, non-root uid 10001 (`jadx-worker/Dockerfile:63-65`, `app/main.py:53`); `X-Worker-Token` shared secret for its public ECS endpoint | APK/XAPK | `POST /decompile` multipart → `application/gzip` tar (sources/resources/manifest) + `X-OpenApk-Jadx-Returncode` partial-OK header; `GET /health` |
| `script-worker` | 1,428 src + 240 test js | **Lambda container** (nodejs:22 base, `Dockerfile:10`); `op: analyze\|deobfuscate` (README:20-70) | NPM tarballs, 8-rule Babel-AST analyzer: secret-theft, fs-traversal, known-c2, net-exfil, eval-surface, spawn, install-hook, entropy-blob (CRITICAL→INFO, `src/analyzer.js:1-13`) + deobfuscation engines **obfuscator-io / generic (ben-sb) / caesar-fromCharCode / auto-best-scoring** (`src/engines.js:9-19`) | S3 event in / findings+bundle keys out; real-world fixtures: javascript-obfuscator output + synthetic Caesar dropper ("Shai-Hulud, lottiefiles, the Red Hat campaign", `fixtures/obfuscated/README.md`) |
| `shell-worker` | 596 py | Lambda container (python:3.12) | loose `.ps1/.psm1/.sh/.bash/.zsh`; deliberately regex-not-AST (README:8-15): `POWERSHELL_RULES` (:79) + `POSIX_RULES` (:124), e.g. `curl \| sh`, `IEX(DownloadString)`, `base64 -d \| bash`, `-enc` | same event shape + `originalName` |
| `pypi-worker` | 1,140 py | Lambda container (python:3.12) | PyPI sdist/wheel/loose .py; 8-rule **Python-AST** twin of script-worker (`src/analyzer.py:4-14`) + `manifest_parser` install-hooks (setup.py/pyproject) | same event shape as script-worker (drop-in) |

ghidra-worker JSON shape (`ghidra-worker/scripts/extract.py:19-46`,
authoritative docstring): `functions[]` (name, address, size, signature,
`decompiled` C, `disassembly[]` per-instruction, `line_map` + `vars`
addr cross-highlighting, xrefs callers/callees, external/thunk flags),
`strings[]`, `imports[]`, `exports[]`, `entry_points[]`,
`tls_callbacks[]` ("anti-debug hook surface"), `data_symbols[]`,
`memory_blocks[]`, `listing[]` (full Ghidra-Listing-style per-section
disasm w/ hexdump rows for undefined bytes), `metadata{compiler,language,
executable_format,image_base,*_count}`; on failure always writes
`{"error": …}` (analyzeHeadless exit code lies, :10-14). `preflight.py`
enables Function-Start-Search analyzers for stripped libs (WhatsApp
`lib.so`: 10 functions on defaults) but NOT AIF (:1-13). Extract.py has a
soft deadline = timeout − reserve so extract still lands (:45-49).

## 8. Product surface map

- **Project kinds**: `APK` (JADX) · `BIN` (Ghidra) · `SCRIPT`
  (npm/PyPI/shell analyzers) — V16, V30; kind dispatch in
  `openbin-frontend` `ProjectViewRoute.tsx:10`.
- **Workflow**: dual status — pipeline (UPLOADED/DECOMPILING/
  INGEST_PENDING/READY/FAILED) × case-management (NEW→PUBLISHED)
  (V2/V5/V23) + phase chips (V14).
- **Collab slices** (commit-train "Slice 1-9"): members+presence (V31)
  → Highlights board (V32) → contributor byline + authorship (V33) →
  public read toggle + anon surface (V34) → fork over shared sha256 blob
  w/ refcounting (V35, V22) → dedup→fork-first in CLI (GET `/dedup`) →
  threaded comments + hot/new/top → samples.
- **Multi-binary**: bundles (V37, CLI-created) + multi-sample projects
  (V41, web-created + `/samples/move-from`).
- **CTF** (V47): weekly BIN/APK challenge, hashed flags, first-blood
  ranks, points, `ai_assisted` flag, writeup projects, leaderboards,
  `researcher of the week` (last commit, 2026-10-12), Discord announce
  webhook.
- **Blog** (V40): standalone posts w/ frozen slugs, upvotes, comments
  (report_comments generalized).
- **Social**: follows (no self-follow at DB), upvotes only, profiles w/
  github/x/mastodon/linkedin handles, researcher search, DMs w/
  EVERYONE/FOLLOWING/NOBODY policy, per-project group chat (V45),
  in-app bell + SES transactional emails sharing one opt-out matrix
  (V21/V28/V29).
- **Reports**: sections JSONB, per-mode templates (STIX malware
  taxonomy, tag chips, tsvector community search), populate-from-analysis,
  publish/community-publish split, Markdown export (`/export.md`) +
  print view.
- **AI**: BYOK vault, audit ledger + per-user token caps + worker quota,
  Ask panels (SSE, per-function + shared sessions), BINNY light tool
  agent, dynamic model discovery, crypto-constant recreator, call-chain
  narration, function deobfuscation, rename suggestion engine.
- **RE features**: file tree + file serving with rename replay
  (`renames`), raw file + source-bundle download, symbol index +
  persistent usages (V13: 5-30s → <100ms on WhatsApp-sized trees),
  search, network IOCs (Retrofit/OkHttp/HttpURLConnection), DB schema
  miner (SQLite+Room), manifest parser, JNI bridge, per-`.so` native
  analyses, crypto IOC hits, String Tools (frontend), call graph page,
  Ghidra-style side-by-side C+disasm w/ cross-highlight (line_map/vars),
  full program listing (V20-era worker feature), local-mode client-side
  APK serving (openapk commit "local mode").
- **Media/gallery**: per-project media store + annotated screenshots
  feeding VISUAL highlights; CloudFront signed URLs for BIN analysis
  reads.
- **Fork/public**: GitHub-style public read (`public_read_at`), forks
  share the immutable analysis blob by S3 key w/ refcount, `fork_count`,
  fork attribution.

## 9. Git history shape

- **131 commits, 2026-06-03 → 2026-10-12** (`git log --oneline | wc -l`
  = 131; first `Initial open-source release` 2026-06-03). Default branch
  `master`.
- **Contributors: exactly 1** author — Husam Abdalla
  (`81593002+husamabdel@users.noreply.github.com`), all 131 commits.
  Notable: **126/131 commits carry Claude co-author trailers**
  (47× Claude Fable 5, 40× Opus 4.7 1M-context, 32× Opus 4.8, 4× Opus 5,
  3× Fable 5.1 — `git log --format='%b' | grep Co-Authored | sort | uniq -c`).
  The entire platform was built agent-first in ~4.5 months.
- **15 tags**: `v0.1.0`, `cli-v0.1.0-alpha` (2026-06-03), then
  `openbin-v0.1.0-alpha` → `openbin-v0.10.0` (2026-09-04;
  0.2/0.3 2026-06-05, 0.4 06-11, 0.5/0.5.1 06-21, 0.6 07-18,
  0.7/0.7.1 07-22, 0.7.2+0.8.0 07-26, 0.9 07-30). CLI releases cut by
  tag pattern `openbin-v*` (`release-cli.yml:24-27`).
- Feature waves (from `git log --oneline`): CLI birth + cloud-Ghidra
  sunset (06-03) → S3 ingest + INGEST_PENDING fixes → TOS gate →
  social layers (follows/votes/comments/bell) → SCRIPT arc JS-1/2/3
  (npm, PyPI, shell) → "sunset" cloud JADX → collab Slices 1-9 →
  providers/model-picker → bundles → Windows CLI + XAPK + landing →
  security fixes (SSRF, redirect-following) → blog → multi-sample +
  sample-switcher → BINNY light + team chat/DMs + light mode →
  account deletion + self-host switches → CTF (HEAD).
- `chore(repo): remove ops tooling and deployment-specific names from
  the public tree` — the open-sourcing scrub commit.

## 10. Licensing, CLA, security, trademarks

- **AGPL-3.0-or-later** for the whole runtime (`LICENSE`, 661 lines;
  `README.md:151-168`); commercial/non-AGPL dual-license offered for
  enterprises (README.md:165-167).
- **CLA v1.0 (June 2026)** via CLA Assistant (`CLA.md:3`,
  `CONTRIBUTING.md:31-37`): contributions licensed AGPL **and** grant
  maintainers relicensing rights — otherwise external PRs would lock the
  codebase AGPL-only forever. Trivial fixes exempt.
- **Trademarks**: "OpenAPK"/"OpenBin" are trademarks of the authors —
  code is AGPL, names are not, forks must rename (`README.md:193-196`).
- **SECURITY.md** (58 lines): private disclosure to `husam@openbin.ai`,
  72h ack / 7d critical patch target, no paid bounty; scope covers
  hosted + repo code (`SECURITY.md:7-15,21-25`).
- Security-hardened code exists where the product demands: SSRF egress
  denylist w/ IPv4-mapped-IPv6 unwrapping + IMDS block
  (`credentials/EgressUrlPolicy.java:36-38,120-132`), no-redirect BYOK
  HTTP, credential crypto (§2 `credentials`), gitleaks over full history
  on push/PR (`.github/workflows/gitleaks.yml:1-24`), DB-level CHECKs
  (comment length, self-follow, char caps §4), 412 TOS gate.

## 11. Verified absences & test surface

- **CI = exactly 2 workflows**: `gitleaks.yml` (secret scan) +
  `release-cli.yml` (tag-triggered CLI/worker-image release). **No test
  CI at all** — no lint/build/typecheck/test job anywhere
  (`ls .github/workflows`).
- Tests that exist (all run manually): **9 core Java tests** (1,625 LOC:
  `dm/DmServiceTest`, `credentials/{OutboundRedirectPolicy,EgressUrlPolicy,
  LlmEndpoints}Test`, `projects/ProjectForkAccessTest`,
  `blog/{BlogSchema,BlogText}Test`, `ctf/CtfServiceTest`,
  `analysis/agent/ToolLlmInvokerTest` (399, the biggest)); **3 Go tests**
  (`cli/{config,dedup,firmdetect}_test.go`, 297 LOC); **script-worker
  only** has tests among workers (`test/engines.test.js` + `smoke.js`,
  240 LOC); **3 frontend tests** (`shared/api/{forkLink,renames,
  markdownLang}.test.ts`). No ghidra/jadx/shell/pypi-worker tests, no
  e2e, no CI harness.
- **No IaC / deployment configs in-repo** — confirmed: no terraform/k8s/
  helm; ECS task defs, Aurora endpoints, secret ARNs, ECR scripts live in
  a private operator repo, stated twice (`CONTRIBUTING.md:16-17`,
  `README.md:170-181`) + scrub commit (§9).
- No docs/ dir in the product repo; user docs are marketing-site pages +
  in-app `Docs`/`CliDocs` pages + per-component READMEs.
- Keycloak realm import lacks the `openbin-frontend` client (§5.5).
- Stale README: "Status: **Slice 1** — Auth + BYOK key vault is
  implemented" (`README.md:15-17`) is ~46 migrations behind HEAD — the
  product is fully built.
- No rate limiter beyond the TOS gate + worker/flag-submission checks at
  API edges; CTF submission rate-limiting is DB-counted, no HTTP 429
  infra. No KMS (KEK is env-var AES-GCM; KMS migration named as future
  work, `README.md:145`).

## 12. calxgloss-relevance triage

● high — directly comparable / stealable; ◐ medium; ○ low.

| Subsystem | T | One-line reason |
|---|---|---|
| `ghidra-worker` + extract JSON | ● | Ghidra-as-sidecar over HTTP w/ one rich JSON contract (functions+pseudocode+disasm+line_map+xrefs) — the wire-shape mirror of calxgloss's scan records; preflight stripped-binary tuning is stealable |
| `renames` + `function_deobfuscations` | ● | LLM rename suggestions w/ SUGGESTED/APPLIED states + replay-on-read; deobf kept as view-layer, index untouched — calxgloss ADR-0013 overlays vs their per-row replay |
| `analysis` + `analysis/agent` (BINNY light) | ● | BYOK multi-provider LLM loop (8 tools, no sandbox) vs calxgloss's local-model pipeline loop; audit ledger + per-user token caps |
| S3 ingest v2 (`api.go`, V22/V23/V25/V41) | ● | Presigned-PUT upload + finalize stream-parse for huge analysis JSON — the payload problem calxgloss dodges by staying local |
| `core` REST/JPA/Flyway monolith | ◐ | Same problem domain (samples, sha256 dedup, analysis results) but a hosted-product schema; migration comments document real Postgres failure modes |
| `cli/` local-worker Docker + release assets | ● | "Run the engine on the user's machine, ship the container as a release asset, no registry" — directly comparable to calxgloss's local-toolchain stance |
| script/shell/pypi analyzers | ◐ | Fixed rule-sets over AST/regex + deobfuscation engines w/ real fixtures; calxgloss has no supply-chain surface |
| `symbols/usages` + `callchain` | ◐ | Persistent reverse-usage index built once per decompile (V13 comments = exact perf numbers) — relevant to calxgloss xref storage |
| collab/social/CTF/blog | ◐ | Pure SaaS community layer, no calxgloss counterpart; the fork/blob-sharing model (V35) is the interesting bit |
| OIDC/Keycloak + TOS 412 gate | ○ | Hosted-platform plumbing; calxgloss is single-user |
| `jadx-worker` containment (prlimit, non-root, partial-OK returncode) | ◐ | Cheap worker-safety pattern |
| Landing/marketing, `dev.sh`, compose | ○ | Ops/marketing; compose stack (postgres+keycloak+workers+minio) doubles as self-host spec |
| CLA/AGPL dual-license, single-author Claude-co-authored history | ◐ | Licensing + build-process datapoint for the comparison chapter |
