# OpenAPK/OpenBin data model, storage, and project lifecycle

> Part of the [OpenAPK/OpenBin overview](README.md). The persistence layer end
> to end: the Postgres schema organized by domain (not version order), the S3
> vs filesystem storage seam, the project state machines and what gets computed
> when, the rename model, deletion and retention semantics, and the `dbschema`
> package. The per-migration summary table lives in
> [ch. 20 §4](20-openbin-inventory.md); this chapter verifies and deepens it —
> every migration was re-read in full at the clone `aee59b05`, paths are
> clone-relative. calxgloss claims reuse the verified citations from
> [ch. 10](10-calxgloss-baseline.md).

## 1. The Postgres schema by domain

Postgres 16 (`core/compose.yaml:3`), Flyway V1–V47 in
`core/src/main/resources/db/migration/`, `ddl-auto: validate` + Flyway
`out-of-order: true` (`application.yml:13-22`). Final state at HEAD: **34
tables**, 33 JPA entities; `project_usages` is the one table with no entity
(accessed via JdbcTemplate — ch. 20 §2). Below, each table is given as it
*exists at V47*, with column evolutions inline. All citations are to
`db/migration/V*__*.sql` line numbers in the clone.

### 1.1 Identity & account

- **`users`** (V1:2-8) — `id UUID PK gen_random_uuid()`, `keycloak_sub TEXT
  UNIQUE NOT NULL` (identity lives in Keycloak; this row is the JIT
  provisioning shadow, ch. 20 §2 `auth`), `email`, `display_name`,
  `created_at`, `last_seen_at`. Evolved by four later migrations: TOS gate
  columns `tos_accepted_version VARCHAR(32)` + `tos_accepted_at` (V24:10-12,
  version scheme = `YYYY-MM-DD` string, NULL for new accounts forces
  re-accept), `credit_publicly` opt-out (V33:20-21, counts internally but
  omitted from public bylines; owner exempt), six profile/social columns
  `bio/website_url/github_user/x_user/mastodon_url/linkedin_url` (V40:71-77
  — handles stored **bare, no @/scheme**, so a stored value can never carry
  its own scheme; free-URL fields validated http(s) at the API), and
  `dm_policy TEXT CHECK IN ('EVERYONE','FOLLOWING','NOBODY')` (V43:7-9 — on
  `users`, not prefs, "because it gates behaviour, not a channel").
- **`user_email_preferences`** (V21:8-19) — PK=`user_id`, row created
  lazily on first PATCH ("absence of a row means all defaults (everything
  ON)" — opt-out model); three V21 transactional flags
  (`notify_decompile_complete`, `notify_report_published`,
  `notify_abuse_confirmation`) + four V28:47-54 social flags
  (`notify_new_follower`, `notify_comment_on_my_report`,
  `notify_reply_to_my_comment`, `notify_collaborator_invite`). V28 bundles
  schema + prefs in one migration deliberately so there is never a window
  where a gating boolean exists before the table it gates (V28:4-7).
  Anti-abuse/security mail is deliberately *not* in this table (V21:6-7).
- **Account deletion** is anonymization + Keycloak admin delete
  (`AccountDeletionService`, ch. 20 §2) — users rows cascade everywhere
  (`ON DELETE CASCADE` on nearly every user FK), with two deliberate
  non-cascade exceptions (§1.8).

### 1.2 Projects & lifecycle

`projects` is the hub; its full HEAD column set (created V2, grown by 12
migrations):

| Columns | From | Notes (migration comment substance) |
|---|---|---|
| id, user_id FK CASCADE, original_filename, size_bytes, sha256, status, error_message, package_name, created_at, decompiled_at | V2:1-12 | sha256 is dedup/fork identity; indexes `(user_id, created_at DESC)` and `(user_id, sha256)` (V2:14-15) |
| digest_jsonb | V3 | static pre-scan cache — "so repeated /analyze calls don't re-scan thousands of files" |
| latest_analysis_jsonb | V4:3 | report editor populates without re-spending tokens per page load |
| name VARCHAR(200) NOT NULL; workflow_status VARCHAR(40) DEFAULT 'NEW' | V5:15-19 | name backfilled from filename; `original_filename` kept "for forensic traceability" (V5:3-4); workflow = case-management axis, explicitly "distinct from `status` which tracks the decompile pipeline" (V5:6-8) |
| published_at on reports | V5:20 | NULL=draft; "report becomes read-only until unpublished" |
| symbol_index_jsonb | V7 | declarations only; usages grep-at-query-time until V13 |
| analysis_mode DEFAULT 'MALWARE' | V9 | drives MAR-vs-VRR template + sticky mode dropdown; backfill default chosen so no existing report is disturbed |
| file_tree_jsonb | V12 | pre-built nested FileNode at JADX completion — serves tree from one row instead of "100k+ stat syscalls"; NULL for old rows, lazily populated on next tree request |
| decompile_phase TEXT, decompile_started_at | V14 | "free-form enum-ish string" written at milestones OPENING_APK/DECOMPILING/BUILDING_TREE/INDEXING_SYMBOLS/INDEXING_USAGES; started_at = first phase write, used for elapsed-time chip |
| jni_bridge_jsonb | V15 | loader call sites ↔ native declarations ↔ .so functions; built lazily on first Native tab open |
| kind TEXT DEFAULT 'APK'; arch, executable_format, compiler, language_id, image_base; binary_analysis_jsonb | V16:9-32 | the OpenBin groundwork; metadata "populated by the Ghidra worker's `metadata` block", NULL for APK; binary_analysis_jsonb is "one blob per project for v1… Slice 5 will shred this into a binaries/binary_functions schema" — the shredding never happened; V22's S3 route superseded it instead |
| binary_analysis_s3_key/etag/size_bytes + partial index on INGEST_PENDING rows with a key | V22 | the big one — §1.8 |
| public_read_at TIMESTAMPTZ NULL | V34:12-17 | GitHub-style "browse the repo"; a *separate* switch from report community-publish, deliberately mirroring the V18 pattern (nullable timestamp + partial index) |
| forked_from FK SET NULL; fork_count INT DEFAULT 0 | V35:11-18 | §3.3 |
| bundle_id FK SET NULL | V37:30-35 | "the DB never destroys member projects when a bundle row disappears"; deletion of members is explicit in `BundleService` so refcounting runs (V37:25-29) |
| description TEXT | V44 | analyst's one-paragraph "what is this and why"; separate from `name` and from the report |

Two status axes coexist on purpose: pipeline `status`
(UPLOADED/DECOMPILING/READY/FAILED +INGEST_PENDING via V23) and
case-management `workflow_status` (NEW/TRIAGING/ANALYZING/DRAFTING_REPORT/
PUBLISHED — "System auto-advances forward; user can manually set anything
except PUBLISHED", V5:8-10). There is **no CHECK on `workflow_status`,
`analysis_mode`, `kind`, `decompile_phase`, or `native_analyses.status`** —
those enums are application-validated; the CHECK-carrying columns are
`projects.status`, `llm_credentials.provider`, `report_templates.mode`,
`project_collaborators.role`, highlights type, `dm_policy`, credit kind,
and the comment/message length caps (§1.8).

- **`project_collaborators`** (V26:12-22) — PK (project_id, user_id),
  `role CHECK IN ('VIEWER','EDITOR')` — OWNER is *never* a valid value,
  because "having two sources of truth for ownership is the exact shape of
  bug this whole feature wants to avoid" (V26:4-6); ownership stays solely
  on `projects.user_id`. `invited_by` FK is NOT NULL with **no cascade** —
  "a deleted inviter forces a deliberate decision rather than silently
  dropping rows" (V26:16-18). Both-direction indexes (V26:26-32).
- **`project_presence`** (V31:12-20) — PK (project_id, user_id) +
  `last_active_at`; "covers the owner too… so a single table gives uniform
  presence for owner + collaborators + (later) the BINNY bot user"; written
  by frontend heartbeat, "deliberately not a write on every project read —
  presence is a coarse 'active 2m ago' signal, not an audit log" (V31:8-10).
- **`bundles`** (V37:12-17) — user-owned name only; members stay full
  project rows ("dedup/fork/publish/annotations are unchanged and
  per-project", V37:4-6); creation CLI-only in v1 (V37:8-10).
- **`project_samples`** (V41:15-45) — §3.4.

### 1.3 Analysis artifacts

- **`projects.binary_analysis_jsonb`** (V16) → **`binary_analysis_s3_key/
  etag/size_bytes`** (V22) — the same data moving out of Postgres;
  JSONB column stays nullable as the dual-read fallback (V22:13-15).
- **`native_analyses`** (V8:5-17 + V25:14-17) — one row per
  (project, `lib_path`) `.so`; `arch`/`size_bytes`/`status`/
  `error_message`/timestamps; `result_jsonb` → S3 trio; UNIQUE
  (project_id, lib_path) (V8:19). Status is free-form VARCHAR(32): the
  sunset cloud states PENDING/RUNNING stay valid for legacy rows,
  INGEST_PENDING added for the CLI flow "same name as on projects.status
  for symmetry" (V25:6-9).
- **`project_usages`** (V13:10-26) — the persistent reverse-usage index:
  BIGSERIAL id, one row per (file, line, name) with `snippet`,
  `enclosing_method` ("so CallChainService can attribute a usage to its
  caller without a second index lookup"), precomputed `is_sdk` ("so SDK
  filtering is a column read, not a pattern match per query"), `kind`
  method/ctor/ref. Single-char identifiers skipped at index time
  ("obfuscated a/b/c would dominate the table with no useful signal",
  V13:7-9). Perf claim in the header: 5–30s per usage lookup → <100ms on a
  WhatsApp-sized decompile (V13:3-4). Lookup index (project, name, is_sdk).
- **`script_analyses`** (V30:19-35) — PK=project (one row per project,
  re-analysis updates in place, V30:16-18); the storage split is the
  interesting part: `findings_jsonb` (5–50KB) **stays in Postgres** so the
  community feed can query/join without an S3 round-trip, while
  `bundle_s3_key` (1–10MB) lives in S3 served via presigned URL; plus
  severity counters (denormalized, indexable), `findings_text` with a
  `to_tsvector('simple')` GIN — no stemming "because finding text is hex /
  domains / function names, not prose" (V30:39-41).
- **`function_deobfuscations`** (V17:12-23) — per (project, original_name)
  cleaned C + `model` + token counts; UNIQUE so re-generating overwrites.
  Stored separately *on purpose*: "chain/xref/network/rename indexers
  continue to operate against the original — deobf is a view-layer concern
  only" (V17:4-6); lookups resolve renamed names through
  `RenameService.resolveOriginal` (V17:8-11).
- **`script_deobfuscations`** (V38:16-36) — per (project, file_path,
  asked-engine) with `engine_used` kept distinct so an 'auto' result stays
  addressable as 'auto' after auto resolved (V38:20-26); `source` is TEXT
  not an S3 pointer — "much closer in size to findings_jsonb than to the
  bundle tarball. TOAST compresses it out of line automatically"
  (V38:12-15); newest result *replaces* the old (deterministic re-runs
  bound growth to files×engines-used, V38:8-10).
- **`project_scripts`** (V46:10-21) — analyst/BINNY scripts, content TEXT
  hard-capped at write; "Nothing here is ever executed server-side; the
  platform stores and shows scripts, the analyst runs them" (V46:8-9);
  `source_ref` names where the script came from.
- **`jni_bridge_jsonb`** (V15) — on projects, not its own table; rebuilt
  on Rescan or after a new .so finishes analysis.

### 1.4 Renames & symbols

- **`project_renames`** (V6:13-25, V33:10-11, V39:17-20) — detailed in §4.
  Columns: original/suggested VARCHAR(500), scope VARCHAR(40), status
  VARCHAR(20) (SUGGESTED/APPLIED), confidence, source_path, rationale,
  `applied_by` (V33, SET NULL so a contribution survives the author
  leaving), created_at; partial index on APPLIED rows (V6:27).
- **`projects.symbol_index_jsonb`** (V7) — coarse class/method/field
  *declarations* cache; "Usages are NOT indexed here — they are recomputed
  via live grep at query time to keep this JSON small" — a design the very
  next migration reversed for scale (V13).
- **`projects.jni_bridge_jsonb`** (V15) — the Java↔native bridge map,
  cached per project.

### 1.5 Reports & community content

- **`project_reports`** (V4:7-14) — project_id NOT NULL **UNIQUE**
  (strict 1:1); title, `sections_jsonb` NOT NULL ("Sections live as JSON
  so the schema doesn't have to change every time we tweak the default
  section list", V4:5-6); then `published_at` (V5, finalize),
  `community_published_at` (V18 — "a user can finalize a report without
  making it public… Keeping the columns separate avoids a future migration
  to split them back apart", V18:5-9), taxonomy + FTS (V19), `updated_by`
  (V33:13-14).
- **V19 FTS mechanics** — `search_tsv` cannot be a generated column
  because `to_tsvector('english',…)` is STABLE, not IMMUTABLE, and STORED
  generated columns require IMMUTABLE (V19:15-20); the workaround is a
  plain column + BEFORE INSERT/UPDATE trigger with `setweight` A=title,
  B=tags/malware_type, D=`sections_jsonb::text` (V19:23-39), a backfill
  `UPDATE project_reports SET title = title` to fire it on old rows
  (V19:41-43), and GIN/tags/type indexes all **partial on
  community_published_at IS NOT NULL** — "no point indexing private rows"
  (V19:45-60). `malware_type` is STIX 2.1 `malware-type` vocabulary as
  plain TEXT — enum enforced at app layer "to keep the migration cheap to
  evolve later" (V19:3-8).
- **`report_templates`** (V10:7-15) — user-owned, mode CHECK
  MALWARE/VULN_RESEARCH/ANY, mode "informational only: a MALWARE template
  can still be applied to a VULN_RESEARCH project" (V10:3-4), UNIQUE
  (user,name).
- **`report_contributors`** (V33:27-38) — the byline **snapshot**, frozen
  at publish time "so later roster/name changes don't silently rewrite a
  published report's credits"; `display_name`/`email_md5` denormalized "so
  the credit renders stably even if the account is later renamed or
  deleted"; credit CHECK LEAD/CONTRIBUTOR; UNIQUE (report_id, user_id) as
  the rebuild upsert key; user_id FK SET NULL.

### 1.6 Social, DMs, CTF

- **`follows`** (V27:11-21) — PK (follower, followee) +
  `CHECK (follower_id <> followee_id)`: "Hard rule, not a service-layer
  check… a user cannot follow themselves" (V27:16-19). **No downvotes by
  design**: "the value signal for a research community is 'this is worth
  reading', not 'this is bad'. The latter is what the existing
  abuse-report flow is for" (V27:7-9). **`report_votes`** (V27:34-39) PK
  (user, report).
- **`report_comments`** (V28:20-31) — one-level nesting via
  parent_comment_id, top-level = NULL; reason: Slack-style replies are "the
  sweet spot for security-research discussion" and keep the email
  notify-on-reply path at one parent to ping (V28:12-16). Soft delete via
  `deleted_at` "preserves the row so reply chains stay intact" (V28:18-19).
  `body CHECK (length BETWEEN 1 AND 4000)` — "Enforced at the DB so a
  malicious client can't bypass the service-layer check" (V28:25-27). V40
  generalizes it: report_id drops NOT NULL, `post_id` added,
  `CHECK (num_nonnulls(report_id, post_id) = 1)` (V40:52-59) — comments
  generalized in place precisely *because* the table has a surrogate id,
  while votes could not be generalized the same way: "that table's primary
  key is (user_id, report_id) and a PK column can't be nullable"
  (V40:36-38), hence separate `post_votes`.
- **`blog_posts`** (V40:12-26) — a reaction to real misuse: "People were
  publishing essays by uploading them as SCRIPT projects, which is a
  terrible fit: it burns a worker run, files land in an analysis view, and
  the thing shows up in the community feed as malware analysis"
  (V40:3-5); slug UNIQUE "generated from the title at first publish and
  then frozen: a slug that moves breaks every link" (V40:16-17);
  published_at NULL=draft.
- **`notifications`** (V29:7-29) — kind free TEXT (whitelisted at service
  layer to avoid an enum migration per new kind, V29:10-15); payload JSONB
  always bakes in `actor_display_name` + `actor_email_md5` "so the
  bell-dropdown row can render an avatar + name without a follow-up user
  lookup" (V29:16-19); `link` = frontend route baked at write time so the
  read path never switches on kind (V29:21-23); `read_at` mirrors the
  soft-delete pattern, unread badge on a partial index (V29:36-41).
- **`project_highlights`** (V32:9-31) — CHECK
  `type IN ('FUNCTION','FILE','VISUAL')` + `CONSTRAINT highlight_anchor
  CHECK (type='VISUAL' OR target_ref IS NOT NULL)` (V32:12,26-27);
  `media_key` points at a file in the project media store ("a highlight can
  be text-only, and a screenshot can exist in the Gallery without one",
  V32:15-17); `created_by` SET NULL "so a highlight survives the author
  leaving; the project still owns it" (V32:22-23).
- **`dm_conversations`/`dm_members`/`dm_messages`** (V42:12-46) —
  deliberately conversation+members+messages rather than flat
  (sender,recipient) "so the same tables can carry group conversations
  later (CTF teams) without a rewrite" (V42:3-6); 1:1 identity via
  `pair_key` canonical `"<lesser uuid>:<greater uuid>"` UNIQUE
  (V42:14-16); read state is per-membership `last_read_at` — unread count
  is "one indexed range scan, no per-message read receipts" (V42:8-10);
  message body CHECK 1–4000. V45 adds `project_id` + partial UNIQUE —
  project group chat reuses the DM tables with membership *not synced*
  from `project_collaborators`: "Access is checked live against the roster…
  and a dm_members row is created lazily on first open (it only carries
  the per-user read cursor)" (V45:5-8).
- **`ctf_challenges`/`ctf_solves`/`ctf_submissions`** (V47:5-50) — flag
  stored only as `sha256(salt:flag)` + salt + hint (V47:13-15); rank 1 =
  first blood, 0 = post-window (V47:32); `ai_assisted` boolean on solves
  (V47:34); `team_id` "reserved for a later teams feature so the history
  never needs a backfill" (V47:1-3,30); submissions keep every attempt but
  "the attempted text is never stored" (V47:41-42); `CHECK (ends_at >
  starts_at)` (V47:22); `announced_at` doubles as the Discord-webhook-sent
  receipt (V47:19).

### 1.7 Credentials, usage & quota

- **`llm_credentials`** (V1:10-23) — envelope ciphertext + IV as BYTEA
  (key never in DB), UNIQUE (user,label), provider CHECK 3 values → drop/
  add to 8 in V36:7-13 including "the generic 'openai_compat' escape hatch
  so a new compatible provider needs no further migration" (V36:3-4);
  last-test columns for UX, last_used_at for hygiene.
- **`llm_audit_log`** (V11:4-18) — one row per LLM call, `purpose` free-form
  for per-feature slicing (analyze, ask, rename, crypto_analyze…);
  "Kept forever (no retention policy yet)… useful for cost forensics"
  (V11:1-3); **`project_id` deliberately NOT a FK so deleting a project
  doesn't drop its audit history** (V11:2-3) — a pattern copied by
  `worker_runs` (V20:9-10).
- **`llm_user_limits`** (V11:28-34) — PK=user, daily/monthly token caps,
  NULL=unlimited (existing users unaffected), "combined input + output
  tokens, since that's what users actually pay for and matches the audit
  rows" (V11:25-27).
- **`worker_runs`** (V20:11-21) — every cloud-worker dispatch logged
  because "these are the only operations the SaaS pays AWS for on the
  user's behalf (AI is BYOK)"; the same table backs the daily-cap quota
  gate by counting rows in a UTC window (V20:2-5); Phase 0 = hardcoded cap,
  "Phase 2 will swap this for a real credits ledger" (V20:7-8).

### 1.8 Notable constraints & migration war stories

The three stories ch. 20 flagged, verified in full:

1. **V23 CHECK widening** — V22 shipped the INGEST_PENDING enum value in
   Java *before* the V2 CHECK allowed it in Postgres; the failure surfaced
   in prod "only after V22 ran… (first /ingest/initiate call from the
   CLI)" as a check_constraint violation Hibernate couldn't see (V23:1-6).
   Fix = drop + re-add `projects_status_check` with the 5-value set
   (V23:8-10). Lesson shape: CHECK-constrained TEXT enums make every Java
   enum addition a migration.
2. **V39 rename-collision fix** — V6's UNIQUE (project_id, original) was
   "right for function/class names… but wrong for VARIABLES: Ghidra reuses
   uVar1/iVar2/param_1 in nearly every function"; the second rename of the
   same short name "updated the SAME row — the second rename silently
   moved the first (its source_path was overwritten), so function A
   quietly reverted" (V39:3-11). Fix: replace the constraint with a unique
   **index** on (project_id, original, COALESCE(source_path,'')) — the
   COALESCE keeps NULL (global) renames colliding with each other exactly
   as before, so "a project still cannot hold two competing global
   renames of the same symbol" (V39:13-16).
3. **V22 five-phase JSONB→S3 plan** — motivated by real failure modes: CLI
   POSTing the whole Ghidra JSON "Spring buffers it into a JsonNode tree
   (~5-10x heap)… For silentXMR-class binaries (50-200MB JSON) this brings
   the backend to its knees at 10 concurrent ingests, and the resulting
   JSONB row destroys Postgres autovacuum + replication" (V22:3-8). Phase 1
   (this migration) is "DUAL-WRITE-COMPATIBLE: binary_analysis_jsonb stays
   nullable and is still read as a fallback… Phase 5 drops it once
   dashboards confirm zero reads" (V22:13-15). V25 mirrors the same flow
   for native_analyses (V25:1-12), and V41 mirrors it a third time for
   samples (V41:3-7). The partial indexes on INGEST_PENDING rows with S3
   keys are the orphan-sweep targets (V22:22-25, V25:19-23, V41:47-50).

## 2. The storage seam

### 2.1 ProjectStorage interface and backends

`projects/storage/ProjectStorage.java` (171 LOC) is the single seam over
"where a project's bytes live". Two backends switch by
`openapk.storage.backend` (`application.yml:87-92`):

- **`fs`** (dev default): the workspace dir *is* the source of truth;
  survives a single host but not container recycle (`ProjectStorage.java:20-21`).
- **`s3`**: S3 is the source of truth; the workspace dir is "a per-task LRU
  cache" (`ProjectStorage.java:22-24`, `application.yml:84-86`).

The interface's five *location* methods (`projectDir`, `apkPath`,
`binaryPath`, `srcDir`, `mediaDir`) all return plain `Path`s — kept on
purpose because "~20 services walk source trees as plain Paths"; the S3
impl materializes content into the cache on demand so callers never learn
the backend (`ProjectStorage.java:27-31, 38-56`). Around them sit the
durability/optimization hooks, all defaulting to no-ops for fs:

| Hook | fs | s3 | Citation |
|---|---|---|---|
| `touch` — LRU signal from hot paths (file reads, symbol lookups), must not throw | no-op | bumps `.last-accessed` mtime sentinel | ProjectStorage.java:61-66; S3ProjectStorage.java:69-71 |
| `afterUpload` — after APK/binary write commits locally | no-op | persists the file to S3, synchronous "callers expect upload durability before returning" | ProjectStorage.java:68-74 |
| `afterDecompile` — after srcDir populated | no-op | tarballs the dir and uploads as one object, synchronous so a task recycle can't drop bytes | ProjectStorage.java:76-82 |
| `pushSrcTarball` — CLI ingest path | no-op | uploads the *received* tarball verbatim instead of re-tarring ~100k files just extracted (and marks the cache extracted) | ProjectStorage.java:84-92; ProjectService.java:453-465 |
| `presignMedia` / `presignSrcBundle` | return `null` → caller falls back to streaming through the app / server-side `/file`+`/search` | presigned GET | ProjectStorage.java:100-119 |
| `listMedia`/`openMedia`/`deleteMedia` | walk local dir (PNG-only filter) | list/delete against the bucket — "the local cache may not have every file post-task-recycle" | ProjectStorage.java:121-170 |

The whole decompiled tree is ONE S3 object (`src.tar.gz`), not N objects:
5-20k tiny files would be "brutal on cost + throughput", and the tar.gz is
what the jadx-worker already streams back, so packaging is free
(`S3ProjectStorage.java:48-57`).

### 2.2 S3 key layout, tagging, and CloudFront

**Key layout is discoverable and mirrors the filesystem exactly** — "a
cache entry is a literal mirror of the relevant S3 prefix"
(`S3ProjectStorage.java:48-50`). Media bucket
(`openapk.storage.s3.bucket`, optional `prefix` for dev/staging/prod
namespacing, `application.yml:103-106`):

```
{prefix}users/{userId}/projects/{projectId}/apk/original.apk   (APK projects)
{prefix}users/{userId}/projects/{projectId}/bin/original.bin   (BIN projects)
{prefix}users/{userId}/projects/{projectId}/src.tar.gz         (decompiled tree)
{prefix}users/{userId}/projects/{projectId}/media/<file>.png
```

(`S3ProjectStorage.java:99-105, 122-131, 160`; the separate `bin/` subdir
is deliberate so "a future cleanup tool can tell at a glance what's inside
without consulting the DB", `ProjectStorage.java:44-49` — the V32 highlight
comment independently confirms `users/<owner>/projects/<id>/media/<file>`,
V32:15-17.)

**Analysis bucket is deliberately separate** from the media bucket
(`openapk.analysis-storage`, `application.yml:116-133`;
`AnalysisStorageConfig.java:23-25`); an empty `bucket` disables
analysis-S3 entirely —
the Spring beans never load (`AnalysisStorageConfig.java:29`) and ingest
endpoints 503 (`IngestService.java:203-206`). Keys there
(`AnalysisStorageService.java:80-82`):

```
analysis/{userId}/{projectId}/result.json.gz            (primary BIN blob)
analysis/samples/{userId}/{projectId}/{sampleId}/result.json.gz   (V41 samples)
```

(`ProjectSampleService.java:349-350` for the sample key.) Objects are
`application/json` + `Content-Encoding: gzip`
(`AnalysisStorageService.java:52-53`).

**Tagging for the ingest handshake.** Every presigned PUT carries
`x-amz-tagging: status=pending` (`IngestService.java:241-256`;
identically for native and sample ingest,
`ProjectSampleService.java:176-188`). Finalize flips the tag to ready —
and the code is blunt about why this is load-bearing: if the re-tag fails,
"the rule deletes this good result ~24h later (project stays READY but the
CloudFront fetch 403s)"; the failure is logged, not raised, so an ops
re-tag can recover rather than blocking the user
(`IngestService.java:329-341`; `AnalysisStorageService.markReady` doc
:151-159 "CRITICAL: the bucket has a lifecycle [rule]"). The lifecycle
rules themselves are **not in the repo** (ops IaC scrubbed, ch. 20 §11) —
the ~24h window and `status=pending` predicate are known only from the
code + migration comments (`IngestService.java:236-238`, V41:47-49).
The presigned PUT also binds the expected `uploadSizeBytes` into the
signature (`InitiateIngestRequest.java:11-13`).

**TTLs.** Media presigns `openapk.storage.presigned-url-ttl` default
**PT15M** — "Short enough that a leaked URL [expires quickly]"
(`application.yml:99-101`; `MediaService.java:43-44`). Analysis presigned
PUT **PT15M**, presigned GET **PT5M** (`application.yml:131-132`; code
defaults match, `AnalysisStorageService.java:106, 217`).

**CloudFront fast path for analysis reads.** If a distribution domain is
configured (`OPENAPK_ANALYSIS_CF_DOMAIN`, `application.yml:133-136`),
reads are **CloudFront signed URLs using a canned policy** — one resource
path, one expiry; no custom policies "because we never want to restrict by
IP/CIDR or sign a wildcard path" (`CloudFrontUrlSigner.java:13-19, 54-63`).
Configured-but-key-missing is a *soft* error: `sign()` returns null, the
ProjectResponse builder omits the URL, "so the legacy JSONB inline path
stays usable" — Phase-1 bring-up resilient to misconfiguration
(`CloudFrontUrlSigner.java:20-23`). Without CloudFront, the same TTL
presigned GET goes straight against the bucket (self-hosted MinIO et al.)
(`AnalysisStorageService.java:211-225`). MinIO/self-host support is
first-class: endpoint override + path-style addressing are mandatory for
S3-compatibles, and the *presigner* uses `publicEndpoint` because presigned
URLs are consumed by browsers and the CLI (`StorageS3Config.java:49-56,
69-79`). Two S3 clients coexist: the media `@Primary` S3Client and a
`@Qualifier("analysisS3Client")` second bean, with an explicit comment on
the resolution rules (`StorageS3Config.java:37-41`,
`AnalysisStorageConfig.java:34-50`).

Media serving resolves to `Resolved.Presigned` (controller issues a 302 —
"works for a plain anonymous `<img src>`" on the public surface) or
`Resolved.Local` (streamed file) —
`MediaService.java:50-56, 135-152, 162-169`;
`PublicProjectController.java:101-102`,
`CommunityController.java:192-202`.

### 2.3 LRU cache and disk-pressure eviction

`CacheEvictor` (`projects/storage/CacheEvictor.java`, active only under
`s3`, :207-208): every 5 min (:223) it measures usable space at the cache
root; below `openapk.storage.cache-min-free-percent` (default **20**,
`application.yml:95-98`, `CacheEvictor.java:218-219`) it walks every
`users/*/projects/*` dir, reads the `.last-accessed` sentinel mtime (dir
mtime as fallback for never-touched projects, :290-302), sorts
oldest-first, and deletes project dirs until free space clears the
threshold by **+5 points of hysteresis** — "keeps us from oscillating
delete/re-fetch on every tick" (:196-200, :253-263). Evicted projects
re-materialize from S3 on next access: "a one-time multi-second pause as
the tar.gz is downloaded and extracted… the evictor never touches
recently-accessed ones" (:202-205). The fs backend installs no evictor at
all — "the cache IS the source of truth" (:192-194).

On the S3 side, two more sentinels and one mutex: `.src-ready` present iff
the full tree extraction succeeded (`S3ProjectStorage.java:70-72`), and a
per-project `srcLocks` map so that the first project-view load — which
fires N parallel requests (network, db, entry points, symbols… racing into
S3 and into the same cache dir) — has exactly one downloader+extractor
while the rest wait on the marker (:73-81).

## 3. Project lifecycle model

### 3.1 Kinds and dual status

`kind` (V16) — **APK / BIN / SCRIPT** — picks the pipeline and the
frontend view (ch. 20 §8). Every project carries two independent status
axes (V5:6-10): the pipeline `status` (UPLOADED→DECOMPILING→READY/FAILED,
+INGEST_PENDING via V23) and `workflow_status`
(NEW→TRIAGING→ANALYZING→DRAFTING_REPORT→PUBLISHED, advanced by
`advanceWorkflowIfBefore` — only forward, never past PUBLISHED,
`ProjectService.java:639-647`). During pipeline runs a third, cosmetic
signal updates: `decompile_phase` chips written per milestone
(V14:5-10; `markPhase` calls in `JadxDecompileService.java:76` and
throughout `ProjectService`) — note the CLI-tree path writes a
**PERSISTING** phase (`ProjectService.java:461`) that the V14 comment's
milestone list doesn't mention. A revealing comment at
`ProjectService.java:436-450`: the tree-ingest pipeline deliberately runs
**outside one big transaction** because wrapping it kept "each repo.save…
invisible to the polling frontend until the WHOLE pipeline committed" and
pinned a DB connection for minutes; each phase write lands in its own
short tx so the project "pops READY as soon as it's actually readable."

### 3.2 The three ingest state machines

**APK (web or CLI):** multipart upload streams the APK (or APK + tree
tar.gz from `openbin apk`) to storage while computing sha256 on the fly
(`DigestOutputStream`, `ProjectService.java:263-276`); the `sha256` column
is temporarily the literal `"pending"` placeholder until the stream
finishes (`ProjectService.java:256`). Cloud JADX is sunset; CLI-sourced
trees go through `runCliTreeIngest`: extract received tar.gz → PERSISTING
→ `pushSrcTarball` verbatim → `finishApkDecompile` — the shared tail:
package name + READY + `decompiled_at` + eager file-tree build + usage
index (`ProjectService.java:453-520`).

**BIN (CLI, ingest v2)** — the V22 five-phase plan's implemented phase 1:
1. `POST /ingest/initiate` (`IngestService.java:196-257`): schema-version
   negotiation (`SUPPORTED_SCHEMAS = {"1.0","2.0"}`, with 1.0 = legacy
   inline JSON and 2.0 = S3, documented at :52-63); pre-creates the
   project row INGEST_PENDING and **pre-sets the S3 key** so "a CLI crash
   between PUT and finalize still leaves a forensically-recoverable
   pointer"; mints the presigned PUT (pending-tagged, size-bound).
2. CLI gzips worker JSON to disk and PUTs straight to S3 (ch. 20 §6).
3. `POST /ingest/finalize` (`IngestService.java:262-355`): HEAD the object
   (etag+size recorded), stream-parse only the `metadata` block + array
   *lengths* out of the gzip via a Jackson token walk — "Body never lives
   in backend memory… Cheap on a 50k-function array"
   (`AnalysisMetadataExtractor.java:15-120`) — fill the V16 metadata
   columns, flip status READY + `decompiled_at`, re-tag pending→ready
   (best-effort), fire the decompile-complete notification.
   No worker dispatch, no quota: "This is the cost-stop path… moves the
   expensive Ghidra compute to the user's own machine"
   (`IngestService.java:38-41`).

**Native `.so` attached to APK projects** (`nativeanalysis/` + V8/V25) and
**extra samples** (V41) run the same three-step flow against their own
rows; native rows additionally keep the sunset cloud states PENDING/RUNNING
as legacy-valid (V25:8-9). Sample ingest is CLI-only; re-initiating an
existing (project, sha) resets the row INGEST_PENDING and overwrites the
old S3 object so an old presigned URL "can't overwrite a finalized newer
upload" (`ProjectSampleService.java:126-190`).

### 3.3 Forks and shared analysis blobs

Forks are **BIN-only, READY-only** and copy no bytes:
`ProjectService.fork` (`:732-781`) creates a new project row that
*copies the pointer trio* (`binary_analysis_s3_key/etag/size`) plus sha +
V16 metadata columns; a legacy inline JSONB blob gets a row-local copy
("legacy inline gets a row-local copy; the S3 path is a SHARED pointer
(refcounted on delete)", `:761-763`). "Working-layer + derived caches
(renames/highlights/report/digest/symbol/tree) start empty" (`:760-761`);
`forked_from` SET NULL + `fork_count++` on the source (`:771-777`). No
worker run, no quota — "the fork reuses the existing analysis"
(`:726-728`).

The refcount discipline lives in `ProjectService.delete` (`:651-717`,
§5): `countByBinaryAnalysisS3Key` runs *before* the row delete ("the row
still counts — refs <= 1 means only me") and the actual S3 delete is
registered `afterCommit` so a rolled-back delete can't destroy a live blob
(`ProjectRepository.java:83-88`, `ProjectService.java:655-705`). A
parenthetical admits this same code "fixes a pre-existing bug: delete never
used to remove the analysis blob at all, orphaning it in the bucket"
(`:662-664`). Fork access is owner/editor/viewer **or public-read**; the
guard calls use the *non-throwing* variants because the obvious "catch the
404 and fall back" spelling "shipped and 500'd on every fork of a public
project… the guard is itself @Transactional, so its 404 marked THIS
transaction rollback-only" — pinned by `ProjectForkAccessTest`
(`ProjectService.java:784-800`, `ProjectAccessGuard.java:34, 97`).

**Dedup feeds the fork funnel:** `GET /projects/dedup` matches sha256
against **public projects only** — "matching never reveals that some other
user privately holds the same sample" — ordered most-upvoted first, cap 10
(`DedupService.java:15-48`).

### 3.4 Collaboration, presence, samples, bundles

- **Collaborators** (V26): role VIEWER/EDITOR granted by the owner; the
  read path is one SQL hit joining owner-OR-collaborator
  (`ProjectAccessGuard`, V26:7-9); OWNER never stored here (V26:4-6).
- **Presence** (V31): frontend heartbeat `POST /projects/{id}/presence`
  (`ProjectController.java:178-193`) upserts `last_active_at` for any
  member including the owner; "coarse 'active 2m ago' signal, not an audit
  log" (V31:8-10).
- **Public read** (V34) and **community publish** (V18) are separate
  nullable-timestamp switches by design (see §1.5/§1.2).
- **Multi-sample** (V41): one primary binary on `projects` + N side
  samples; samples are "read-only side analyses, exactly like attached
  native libs", deliberately un-annotatable — renames/highlights/reports
  are keyed by symbol name and "two samples routinely share names like
  FUN_00401000" (V41:8-11). `/samples/move-from` is the one surgery
  allowed: it **copies** the source project's primary blob to a new
  per-sample key, re-parents the source's attached samples, then deletes
  the source project through the blessed delete path (refcount-safe: "our
  COPY is unaffected either way"), with an `afterCompletion` rollback hook
  that deletes the copy if the tx fails
  (`ProjectSampleService.java:330-390`).
- **Bundles** (V37): grouping pointer only; deleting the last member
  auto-removes the emptied bundle inside `ProjectService.delete`
  (`ProjectService.java:684-701`), and bundle deletion deletes members
  member-by-member through the same path so refcounting always runs
  (V37:25-29).

### 3.5 Derived indexes: who computes what, when, how refreshed

| Artifact | Built | Refreshed |
|---|---|---|
| `file_tree_jsonb` (V12) | eagerly at `finishApkDecompile`, "so the first project open is instant" (`ProjectService.java:499-506`) | lazy refill when NULL (`ProjectService.java:501-505` + V12:4-5); rebuild endpoint (`:827-841`) |
| `project_usages` (V13) | synchronously right after READY ("Done after the project is saved as READY so a failure here [can't block the project]", `ProjectService.java:510-516`) | `POST /symbols/rebuild` → `rebuildAsync` (`SymbolService.java:412`, `UsageIndexerService.java:108-171`) |
| `symbol_index_jsonb` (V7) | lazily on first symbol query, parse-failure → rebuild (`SymbolService.java:139-155`) | **nullified** whenever the APPLIED rename set changes — "any change to the active rename set makes the cached index lie. Null it out and let SymbolService.getOrBuild rebuild lazily" (`RenameService.java:423-437`) |
| usage-vs-rename coherence | no rebuild per rename: the query path translates pre-index raw names ↔ displayed names through `activeRenameMap` (deterministic LinkedHashMap order) (`RenameService.java:452-470`) | — |
| `digest_jsonb` (V3) | on demand (`/digest/rescan`) | — |
| `jni_bridge_jsonb` (V15) | lazily on first Native tab open | Rescan or new .so finished (V15:4-5) |
| native/sample analysis rows | finalize HEAD + stream-parse | re-initiate resets the row (§3.2) |

## 4. The renames model

`project_renames` rows are per-identifier rename instructions, not file
edits (V6:3-7): `status ∈ SUGGESTED` (proposed, sitting in the review
panel) `/ APPLIED` ("ProjectService.readFile rewrites this identifier on
the fly when serving any source file"); `scope` for APK suggestions is
class/method/field (`RenameService.java:79,122,129,676`), for BIN
function/variable (`:383-387`); variable rows carry
`source_path = 'function:<name>'`, global renames leave it NULL
(V39:13-14).

**V6's uniqueness mistake and the V39 fix** (full story §1.8.2): one row
per (project, original) collided Ghidra's reused local names (uVar1,
param_1) across functions; post-V39 uniqueness is
`(project_id, original, COALESCE(source_path,''))`, so one short name can
be renamed per function but never twice globally (V39:19-20). `apply`
accepts the whole row-set for a bare name since "the review panel sends
bare names… accept the whole set rather than an arbitrary one of them"
(`RenameService.java:400-414`); applying stamps `applied_by` (V33) and
**nullifies the symbol index** (`:413-415` + `:423-437`); `unapply` is a
hard delete of the rows (`:417-425`) — no tombstone; undo == remove the
overlay row.

**Replay at read time, not at write time.** Disk files and the analysis
JSON keep original identifiers; every serving path applies APPLIED renames
on the way out: file serving (`ProjectService.java:997`), the
BIN analysis-JSON fast path (`:896`), symbol queries
(`SymbolService.java:177`), network-IOC scan (`NetworkService.java:108`),
crypto context (`CryptoService.java:293`), db-schema miner
(`DbSchemaService.java:111`), call-chain bodies
(`CallChainService.java:307,325,535`). Apply semantics differ per scope
(`applyMapToBinaryAnalysisJson`, `RenameService.java:501-545`):
non-variable scopes get project-wide word-boundary regex, but variable
renames are applied *only inside their owning function's* `decompiled` +
`disassembly[].text` + `signature` + `vars[].name` fields — "applying
them globally would mass-rewrite identical placeholder names" — and
**order matters**: variables first, then the global function-name pass,
else the `function:<name>` tags on variable rows stop matching. The
honest caveat: "word-boundary substitution is not AST-aware. A class
named `a` gets renamed wherever `\ba\b` matches… The review-and-apply UX
is the safety net" (`:444-450`). Lookup from renamed names back to worker
names goes through `resolveOriginal` — first match wins on
suggested-name collisions, "we could add a unique-on-suggested constraint
later if it bites" (`:475-490`). `activeRenameMap` keeps raw↔display
translation cheap for the usage-index query path (`:452-470`).

Contrast with `function_deobfuscations` / `script_deobfuscations`: both
are likewise view-layer, never re-written into the indexed originals
(V17:4-6; tables §1.3) — the platform's consistent rule is
**annotations live beside the immutable analysis, replayed at read**.

## 5. What is NOT stored, and deletion semantics

**Original binaries.**
- *Web uploads*: the original bytes ARE kept — streamed to
  `{...}/apk/original.apk` or `{...}/bin/original.bin` while sha256 is
  computed on the fly (`ProjectService.java:263-276`); raw streaming back
  exists for the "Download .so / feed your local Ghidra" UX
  (`readFileRaw`, `ProjectService.java:928-940`).
- *CLI-ingest BIN projects*: **the binary never reaches the server.**
  initiate/finalize carry only metadata + the analysis JSON blob
  (`IngestService.java:196-355`); sha256/size come from the CLI's local
  computation (ch. 20 §6). So a CLI-created BIN project has analysis bytes
  but no sample bytes — consistent with BINNY's posture ("no sandbox, no
  sample bytes", `analysis/agent/` docstring, ch. 20 §2; the agent reads
  the *analysis JSON*, not the PE/ELF). *(Backend side verified from
  initiate/finalize code; the CLI upload-contents point rests on ch. 20
  §6's `api.go` reading.)*
- SCRIPT projects keep findings + the deobfuscated bundle only (V30);
  CTF submissions record every attempt but "the attempted text is never
  stored" (V47:41-42).

**Worker JSON lifecycle.** Fresh ingests land gzip + `status=pending`
tagged; finalize must re-tag to ready or the **~24h S3 bucket lifecycle
rule reaps the good object** (`IngestService.java:329-333`). The rule
itself is not in the repo (ops IaC scrubbed — unverified beyond comments;
ch. 20 §11). DB-side: the partial indexes on stale INGEST_PENDING rows
(V22:22-25, V25:19-23, V41:47-49) promise "a periodic job sweeps"; a
grep of `@Scheduled` components found only `CacheEvictor` and
`CtfScheduler` — **no DB reaper for orphan INGEST_PENDING rows exists in
this tree** (the rows appear to linger; their S3 objects do self-expire
via the tag). `llm_audit_log` is explicitly "kept forever (no retention
policy yet)" (V11:1-2).

**Project deletion** (`ProjectService.delete`, owner-only even for
EDITORs, `:651-717`) is the platform's one blessed teardown path:
1. refcount-check the shared analysis blob (`countByBinaryAnalysisS3Key`
   ≤ 1 → may delete);
2. collect sample-blob keys (rows cascade in the DB; blobs must be deleted
   explicitly; "sample blobs are never shared (fork copies only the
   primary blob), so no refcount");
3. capture parent + bundle ids, `storage.deleteProject` (recursive dir
   wipe), `repo.delete`;
4. fork_count-- on the source; auto-delete an emptied bundle
   (`countByBundleId==0` after the delete flush);
5. S3 object deletes registered **after commit** (a rolled-back tx can't
   destroy live bytes).

Everything else rides FK CASCADE: report, renames, highlights,
collaborators, presence, usages, native analyses, samples, project-chat
conversation. Non-cascading survivors: `llm_audit_log` and `worker_runs`
(project_id non-FK by design, V11/V20), and fork *rows* themselves
(`forked_from` SET NULL — "deleting a source must NOT destroy its forks",
V35:6-9).

**Account deletion** (`AccountDeletionService.java:20-133`): product-
decided split — "PRIVATE data is hard-deleted; PUBLIC contributions are
kept but anonymized"; unpublished projects go through
`ProjectService.delete` ("the only path that frees storage — a raw DB
delete would orphan [the blob]"); DM threads are deleted for both sides;
the users row is anonymized in place with `keycloak_sub` scrambled rather
than dropped, because S3/filesystem paths are keyed by the owner id; then
the Keycloak identity is deleted post-commit so the account "can't
auto-reprovision on its next request" (`:46-49, 92-133`).

## 6. The dbschema package

Not a dynamic-schema-query subsystem, and it stores nothing: `dbschema/`
(323 LOC, 2 classes) is an **Android app-DB schema miner**. `GET
/api/projects/{id}/dbschemas` triggers a live walk of the project's
decompiled tree looking for two local-storage patterns: classes extending
`SQLiteOpenHelper` — table DDL mined from `CREATE TABLE …(…)` string
literals, with all concatenated fragments joined first so split SQL still
parses — and Room `@Entity` classes, whose simple class name becomes the
table (`DbSchemaService.java:29-40`). It reads through `ProjectStorage`
(hence works identically on both backends) and pipes each file through
the rename map before matching (`:111`). Output is a transient `DbSchema`
DTO — no table, no cache; the answer is recomputed per request.

## 7. Data integrity & provenance

No checksum-verification pass, no generation stamping, no correctness
verdicts — integrity here is **operational**, not epistemic. What the
schema *does* have are four recurring patterns:

**Timestamp-as-flag.** Booleans that need an audit trail are stored as
nullable `TIMESTAMPTZ` and queried `IS NOT NULL`, so one column is
simultaneously the flag, the "since when", and the index key:

| flag | column | read as | cites |
|---|---|---|---|
| project publicly readable | `public_read_at` (V34:13, partial index V34:15-16) | `findByIdAndPublicReadAtIsNotNull` / `existsByIdAndPublicReadAtIsNotNull` | `ProjectRepository.java:64,81`; `ProjectPublicGuard.java:50`; `DedupService.java:20,44` |
| blog post live | `published_at` | `findAllByPublishedAtIsNotNullOrderBy…`, `isPublished()` | `BlogService.java:55,63`; `BlogPost.java:77` |
| report community-visible | `community_published_at` | raw SQL `WHERE r.community_published_at IS NOT NULL` | `CommunityService.java:136`; `SocialService.java:198,331,366` |

Fork visibility even ORs across the pair — a fork is public-readable
only if the **parent**'s flag is set (`forkParentIsPublic`,
`ProjectService.java:175-178`).

**Provenance chain: sha256 → S3 key + ETag → status.** The sample digest
(`projects.sha256`) is the dedup/collision key (§1.2); the analysis blob's
identity is the `(binary_analysis_s3_key, etag, size_bytes)` trio (V22).
`sha256` is seeded with the sentinel **`"pending"`** — not NULL, the column
is NOT NULL — and replaced when the digest lands
(`ProjectService.java:256`, `script/ScriptAnalysisService.java:141`).
Uploads enter the bucket tagged `status=pending` and `markReady` clears the
tag only after finalize (`AnalysisStorageService.java:101,159`), so an
object's tag and a row's status are two views of the same state machine
(§3.2). Caveat: the ETag is *recorded*, never *re-verified* — the loader's
own comment lists an ETag-keyed cache as the "right next step"
(`BinaryAnalysisLoader.java:27`), and no read path in the tree HEADs the
object and compares.

**No worker-version stamp anywhere.** `worker_runs` (V20) logs
`worker_type`/`success`/`error_message` but no version column
(V20:13-18); the only `*_version` columns in all 47 migrations are
`tos_accepted_version` (V24:11) and NPM `package_version` (V30:25). A blob
produced by `ghidra-worker:7` vs a future `:8` is **indistinguishable in
the DB** — the image pin lives in ops config, and in practice the
inline-vs-S3 split (which rows have `binary_analysis_jsonb` vs only an
S3 key) is the de-facto generation marker. If output format ever shifts,
there is no column to route on.

**Dual-read preference is inverted between the two tables of the same
migration family.** `BinaryAnalysisLoader` prefers the **legacy inline
JSONB** first, S3 second — "if both are somehow populated, the inline copy
wins" (`BinaryAnalysisLoader.java:44-49`); `NativeAnalysisService` prefers
the **S3 key** when set, `result_jsonb` otherwise (V25:11-12). V22's
comment calling JSONB a "dual-read fallback" (V22:13-15) is true only for
`native_analyses`; for projects the inline column is the primary.

JSONB mechanics: blobs are `String` fields with
`columnDefinition = "jsonb"` + `@JdbcTypeCode(SqlTypes.JSON)` — the cast
happens at write time to avoid Hibernate type dependencies, and values are
read back as raw JSON strings (`Project.java:169-182`). Vocabulary
enforcement philosophy is covered in §1.8 (CHECK-widening war stories:
V22 shipped `INGEST_PENDING` before V23's CHECK allowed it).

**Missing reapers.** The comments promise a "periodic orphan-cleanup job
(find projects with INGEST_PENDING status older than 24h)" backed by the
partial s3_key index (V22:22-24), but the only `@Scheduled` methods in the
tree are `CacheEvictor` and `CtfScheduler` — **no DB-side INGEST_PENDING
reaper exists in the clone** (§5). The real cleaner is the S3 lifecycle
rule that deletes `status=pending`-tagged objects after 1 day, repeatedly
described in code (`IngestService.java:236,330`;
`AnalysisStorageService.java:152`) but defined outside the repo —
unverifiable beyond the comments, same as the CloudFront config in §2.2.

## 8. calxgloss comparison

ADR paths below are `docs/adr/` in the calxgloss repo; citations reuse ch. 10.

**Overlap (same problem, different shape).**
- *Immutable engine output + replayed human intent*: OpenBin never rewrites
  the decompiled tree — applied renames are rows replayed when
  `ProjectService.readFile` serves a file (V6:6-8); calxgloss never
  mutates artifacts either — reviewer intent (skips, overrides,
  resolutions) lives in overlay files applied at read time (ADR-0003,
  `0003-reviewer-intent-lives-in-overlay-files-not-derived-artifacts.md`;
  ch. 10:199,220). Same move, one step apart: OpenBin replays from a
  Postgres table, calxgloss from JSON overlays.
- *Cache keyed to identity*: OpenBin's local project cache + LRU eviction
  (§2.3) vs calxgloss's three-tier scan-read cache under `re/cache/`
  (ADR-0042/0043, `0043-the-scan-read-cache-files-under-re-cache.md`) with
  the cache naming the engine build that answered (ADR-0055). Both know a
  cached analysis is only valid *as of* something.
- *Storage behind a thin seam*: `ProjectStorage` with Postgres-S3 vs
  local-FS backends (§2.1) vs calxgloss's file-layout-as-contract with
  per-engine persistors (ch. 10:501;
  `crates/shared/calxgloss-types/src/persist.rs`). Both hide bytes behind
  an interface keyed by owner/identity.
- *Assembly is contextual*: OpenBin assembles per-request guards
  (`ProjectPublicGuard`) and status machines around a shared mutable row;
  calxgloss keeps assembly inside the pipeline context, constructor
  assembly-internal (ADR-0050).

**calxgloss-only.** Everything that makes a *claim* re-checkable rather
than merely *stored*: scan-coverage stamped beside provenance at scan time
(ADR-0053,
`0053-scan-coverage-is-the-scans-own-record-stamped-at-scan-time-…`),
admitted gaps as named records with deterministic ids (ADR-0056,
`0056-an-admitted-gap-is-filed-as-a-named-record-…`), verification verdicts
(ch. 31 §7). OpenBin's flags answer "where is this in the pipeline"; they
never answer "is this blob right".

**OpenBin-only.** The entire multi-tenant apparatus: 47 migrations of
row-level guards, scoped-unique constraints (V39), CHECK-widened
vocabularies, refcounted shared blobs (§3.3), quota ledgers (V20), BYOK
credential vault (§1.7), moderation/report/DM/CTF tables — none of which
has any calxgloss counterpart because calxgloss deliberately has **no
daemon, no DB, no server substrate** (ch. 10:495).

**Verdict.** **Collaboration is what forces a database; honesty is what
forces a record.** OpenBin's schema exists so thousands of strangers can
mutate each other's projects safely — hence guards, refcounts,
timestamp-flags, CHECK gates. calxgloss's record tree exists so one
reviewer's claims can be re-checked years later — hence coverage records,
named gaps, build-identity caches. The two axes are orthogonal: neither
buys the other's good. What calxgloss should study is the *cost side*: if
its record tree ever went multi-tenant, OpenBin shows the schema bill —
and after 47 migrations OpenBin *still* has no column that could say
whether a stored analysis was correct, which is exactly the column
calxgloss's whole design exists to write.

## Corrections to the inventory chapter

Errata for ch. 20 (§4 migration table and §8), from the full re-read of all
47 migrations in this chapter:

1. **No orphan-cleanup job exists in the tree.** ch. 20:208 describes
   V22's partial index as "orphan sweep index on INGEST_PENDING" — the
   comment does promise a "periodic orphan-cleanup job" (V22:22-24), but a
   tree-wide grep for `@Scheduled` finds only `CacheEvictor.java` and
   `CtfScheduler.java`; the actual sweep is an S3 *bucket lifecycle rule*
   (`AnalysisStorageService.java:152`), outside the repo. The DB-side
   sweep is never run.
2. **V22's "dual-read fallback" inverts for projects.** ch. 20:208 calls
   `binary_analysis_jsonb` the fallback; `BinaryAnalysisLoader.java:44-49`
   prefers inline JSONB *first* for projects — only `native_analyses`
   reads S3-first (V25:11-12). Same family, opposite preference.
3. **V35 fork carve-out.** ch. 20:221,383 present forks as sharing the
   analysis blob "with refcounting"; a fork whose source has *legacy
   inline* `binary_analysis_jsonb` instead gets a **row-local copy** —
   only the S3-key path shares pointers (§3.3; `ProjectService.java:765-771`,
   refcount at `ProjectRepository.java:88`, `ProjectService.java:667`).
4. **Decompile phases are a superset of V14's comment.** ch. 20:200 lists
   `OPENING_APK…INDEXING_USAGES`; the column is free-form TEXT (no CHECK)
   and code also writes `EXTRACTING` (`JadxDecompileService.java:119`),
   `PERSISTING` (`ProjectService.java:461`), `ANALYZING`
   (`BinaryDecompileService.java:79,90`) — phases V14 predates by
   (BIN pipeline + ingest v2).
5. **V16's shred plan was superseded, not shelved.** V16:29-30 promises
   "Slice 5 will shred [binary_analysis_jsonb] into a binaries /
   binary_functions schema"; the shred never happened — V22 moved the
   blob to S3 instead. ch. 20:202's V16 row should note the plan died.
6. **V6 rename `scope` vocabulary unstated.** ch. 20:192 lists `scope`
   without its values: free-form `VARCHAR(40)` (V6:18), validated only in
   the app — APK suggestions use class/method/field/function/variable;
   BIN suggestions allow only "function" and "variable"
   (`RenameService.java:364-366`). No CHECK in any migration.
7. **"33 JPA entities" (ch. 20:179) is right but fragile as a grep
   count**: `grep -rl "@Entity"` returns **35** files — two are dbschema's
   Room-detection doc + regex strings (`DbSchemaService.java:39,67`;
   `DbSchema.java:8`), not entities (§6).
