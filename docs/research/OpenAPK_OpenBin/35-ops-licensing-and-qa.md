# 35. Ops, licensing, and QA — build, release, deploy, secure, test

> Part of the [OpenAPK/OpenBin overview](README.md). This chapter covers how
> the project is built, released, deployed, licensed, tested, and secured.
> Source: clone at `/tmp/opencode/openbin` @ `aee59b05` (verified intact,
> `git rev-parse HEAD` = `aee59b055a12a2e335c8bf50ec1df7be55ce8508`). All
> claims cite clone-relative `path:line`; counting commands are quoted where
> counts appear. Deployment topology claims about AWS are labeled **implied
> by repo** — the operator repo is private.

## 1. CI/CD: two workflows, fifteen tags, one release pipeline

`.github/` contains **exactly two workflows and nothing else** — no issue
templates, no PR template, no dependabot config
(`ls .github .github/workflows` → only `workflows/{gitleaks.yml,release-cli.yml}`).

### gitleaks.yml — the only check that runs on code

Triggers: `push` to `master` + all `pull_request`s
(`.github/workflows/gitleaks.yml:6-9`). One job: checkout with
`fetch-depth: 0` (full history, :18-20) then run
`zricethezav/gitleaks:latest detect --source /repo --no-banner --redact
--verbose` inside Docker (:21-25). The comment (:3-5) explains using the CLI
container instead of the marketplace action (org-repo license key). It scans
**history, not a diff** — secret hygiene only, never correctness. There is
no lint/build/typecheck/test job anywhere in the repo.

### release-cli.yml — the only pipeline that ships anything

Trigger: push of a tag matching `openbin-v*`, or `workflow_dispatch` with a
manual tag input (`.github/workflows/release-cli.yml:22-30`). Four jobs:

1. **build-images** (:36-79): buildx-builds `./jadx-worker` tagged
   `openapk/jadx-worker:bundled-2` and `./ghidra-worker` tagged
   `openbin/ghidra-worker:7`, `docker save | gzip` each into
   `jadx-worker.tar.gz` / `ghidra-worker.tar.gz`, with GHA layer caching so
   the ~600 MB Ghidra base is paid once (:45-46). The image *tag* is the
   versioned cache key — "MUST stay in lockstep with `ghidraWorkerImage` in
   cli/config.go" (:57-61), matching `cli/config.go:62,69`.
2. **create-release** (:81-94): creates the GitHub release *once* up front
   with `softprops/action-gh-release@v2` + `generate_release_notes: true`;
   the comment (:85-89) documents a fixed race where four matrix jobs raced
   to create the release and died with `already_exists (tag_name)`.
3. **release** (:96-166): 5-way matrix — linux/{amd64,arm64},
   darwin/{amd64,arm64} as `.tar.gz`, windows/amd64 as `.zip` (:107-112).
   Go 1.22 (`setup-go@v5`, :116-119 — note the repo's `cli/go.mod` declares
   go 1.18), `CGO_ENABLED=0` cross-compile with
   `-trimpath -ldflags="-s -w -X main.version=…"` (:127-134). The package
   is **SLIM**: CLI binary + `cli/README.md` only, no worker image inside
   (:5-6, :137-154). Asset names are intentionally **version-LESS** so
   `releases/latest/download/<asset>` is a stable URL the installer and CLI
   hardcode (:11-20, :139-141).
4. **attach-images** + **attach-version** (:168-206): attach the two worker
   tarballs, then a tiny version-less `VERSION` text asset that powers
   `openbin update`'s newer-release nudge without GitHub API/token/rate
   limits (:187-200).

So yes — **releases carry CLI binaries + worker docker-load tarballs**.
Per release, the asset set is: `openbin-linux-amd64.tar.gz`,
`openbin-linux-arm64.tar.gz`, `openbin-darwin-amd64.tar.gz`,
`openbin-darwin-arm64.tar.gz`, `openbin-windows-amd64.zip`,
`jadx-worker.tar.gz` (~350 MB), `ghidra-worker.tar.gz` (~700 MB)
(`release-cli.yml:4-15`, sizes per `cli/README.md:13-15`), plus `VERSION`.
The core Java app and the frontends are **not released by anything** —
cloud-side deploys are invisible here (operator repo, §3).

### The 15 tags

`git tag -l` → 15: `v0.1.0`, `cli-v0.1.0-alpha` (the two 2026-06-03
seed tags from the inventory ch. §9) then
`openbin-v0.1.0-alpha, 0.2.0, 0.3.0, 0.4.0, 0.5.0, 0.5.1, 0.6.0, 0.7.0,
0.7.1, 0.7.2, 0.8.0, 0.9.0, 0.10.0`. Only `openbin-v*` fires the release
workflow (:24-25); `v0.1.0` and `cli-v0.1.0-alpha` are pre-pipeline
artifacts. 13 releases were cut by tag between 2026-06-03 and 2026-09-04,
then silence for the ~5 weeks to HEAD — releases follow the CLI, not the
platform.

## 2. Dev tooling: dev.sh, compose, Dockerfiles, no Makefile

**No Makefile / justfile / makefile anywhere** (`ls Makefile justfile
makefile` → all "No such file"). The single entry point is **`dev.sh`
(257 LOC)**:

- Preflight (:64-121): defaults `JAVA_HOME` to
  `/usr/lib/jvm/java-21-openjdk-amd64` (:32, :65-73); **warns but proceeds**
  when `OPENAPK_KEK_B64` is unset, falling back to the dev default key in
  application.yml (:76-79); flips the prod-sunset JADX worker back on via
  `export OPENAPK_JADX_DISABLED="${OPENAPK_JADX_DISABLED:-false}"` — the one
  disabled-flag flip the script performs (:81-84); checks docker daemon +
  ports 5173/5174/8081 only, deliberately not the compose ports (:95-118).
- Startup (:221-231): explicit `docker compose up -d` in `core/` **before**
  Spring Boot, working around Spring Boot's all-or-nothing compose
  integration (:125-148), waits on `pg_isready` inside `openapk-postgres`
  (:137-146), then `./mvnw -q spring-boot:run` (core, 8081) + two Vite dev
  servers (openapk 5173, openbin 5174, auto `npm install` if
  `node_modules` missing, :162-179). **No data seeding** — nothing seeds
  users/projects; the Keycloak realm import (§inv. §5.5) is the only
  fixture.
- Teardown (:189-217): SIGTERM→SIGKILL per pidfile + defensive
  `docker compose down --remove-orphans` in case Spring's shutdown hook
  never registered. Prints the URL cheat-sheet incl. `actuator/health` and
  Keycloak `admin/admin` (:234-242). `--no-tail` mode for "CI/scripts"
  (:19, :45) — ironic given there is no CI.

**`core/compose.yaml` (124 lines)** — Postgres 16 (`openapk/openapk/openapk`,
:2-17); `ghidra-worker` + `jadx-worker` built from the sibling dirs, bound
**loopback-only** because "the worker has no auth of its own and trusts the
OpenAPK core to be the only caller. In prod we'd lock this down at the VPC
layer" (:24-28, :43-46); jadx gets cgroup `mem_limit: 6g / cpus 4.0` as the
real containment (prlimit `--as` is unusable for a JVM, :49-54); Keycloak
**26.6.2** `start-dev --import-realm` with bootstrap `admin/admin` (:62-81)
and no healthcheck (:83-86, with the reason spelled out); MinIO
`minio/minio:latest` (:102-119) for prod-parity S3 testing, off unless
`OPENAPK_STORAGE_BACKEND=s3` (:88-101). Healthchecks: pg `pg_isready`,
workers Python-urllib `/health` probes, MinIO curl.

**Dockerfiles (6).** `core/Dockerfile`: two-stage Temurin 21 JDK→JRE
(`eclipse-temurin:21-jdk-jammy` / `21-jre-jammy`, :22, :41), dependency-primed
Maven cache (:25-29), Spring Boot layered-jar extraction (:36-38), tini as
PID 1 for clean ECS SIGTERM (:45-47, :91), **non-root fixed uid/gid 10001**
user `openapk` (:52-58, :69), `HEALTHCHECK` on
`/actuator/health/liveness` (:88-89), JVM tuning comment names the ECS
2 GiB task (:73-82). Sharp edge: :31-32 asserts "tests run in CI before we
ever tag an image" — **no such CI exists** (§1); the claim is aspirational.
`ghidra-worker/Dockerfile`: Ghidra **11.2.1** pinned via `ARG
GHIDRA_VERSION/GHIDRA_BUILD` with *optional* `GHIDRA_SHA256` pin **defaulted
empty** (:6-11, :21-23); runs uvicorn **as root — no USER directive**
(:58). `jadx-worker/Dockerfile`: jadx **1.5.5** pinned, same optional-sha
pattern (:9-13), non-root uid 10001 `jadx` (:60-65), prlimit + util-linux
as the hostile-APK containment (:37-38). Script/shell/pypi workers: AWS
Lambda base images `public.ecr.aws/lambda/nodejs:22`
(`script-worker/Dockerfile:10`) and `python:3.12`
(`shell-worker/Dockerfile:10`, `pypi-worker/Dockerfile:10`); script-worker
uses `npm ci` against a committed lockfile for bit-reproducible images
(:15-18); pypi-worker is stdlib+boto3-only (:7-8). Pinning is real but
partial: base tags are OS-major-level (`jammy`, `16`, `3.12`), MinIO is
`:latest`, third-party zips are version-pinned but checksum-verified only
if the operator passes the sha by hand.

## 3. Deployment topology (implied by repo; operator repo private)

Everything below is labeled from repo evidence; the private operator repo is
named twice (`README.md:176-180`: "Not in: operator-specific deployment
configs (`infra/`), task-def overlays, **Aurora endpoints**, secret ARNs,
ECR push scripts"; `CONTRIBUTING.md:15-17`) and there is zero IaC in-tree
(inventory §11). So:

- **Hosted hosts are baked into defaults**: `api.openapk.ai`,
  `app.openbin.ai`, `openapk.ai`, auth host derives from the JWT issuer
  (`application.yml:281-285`); `SECURITY.md:22-23` scopes four hosts
  (adds `auth.openapk.ai`). Downloads come from
  `https://github.com/openbin-ai/platform/releases/latest/download`
  (`application.yml:289`) — revealing the private repo's GitHub org/name.
- **ECS**: `application.yml:207-208` says the script analyzers are "the only
  Lambda in the stack (**everything else runs on ECS Express**)" — the repo's
  own term for the hosted compute (also `:194` "the worker's ECS Express
  endpoint"). `core/Dockerfile:13-18,45-47,73-77` is written for ECS:
  tini-for-SIGTERM comment names ECS, "ECS task memory of 2 GiB",
  `SPRING_DOCKER_COMPOSE_ENABLED=false` "no Docker socket in ECS tasks",
  `aws ecs execute-command` (:44). `README.md:90` storage table: s3 backend
  = "prod / ECS"; `:109-110` "the ECS task role in prod". **Implied by repo:
  core + ghidra/jadx workers on ECS (task defs private), jadx's endpoint
  publicly reachable through it.**
- **Lambda**: only the three script analyzers — script/pypi/shell — invoked
  sync through the AWS SDK, functions named only by env var with no default
  (`application.yml:212-228`), scale-to-zero rationale at :206-207; the
  alternative `http` transport treats the same names as RIE container URLs
  for self-hosters (:213-217).
- **S3 + CloudFront**: two buckets — project storage (`:102-115`) and a
  dedicated analysis bucket (`:116-132`) — plus a CloudFront distribution
  *fronting the analysis bucket*: frontend fetches signed URLs
  `https://${distribution-domain}/${s3-key}` (`:133-136`), CloudFront
  keypair private key read from **Secrets Manager** in prod vs a file in dev
  (`:139-144`). Presigned URLs everywhere else: media 15-min GETs
  (`:99-101`), analysis 15-min PUTs / 5-min GETs ("a slow CLI upload
  (200MB on flaky wifi) needs a window", `:129-132`). The V22 header
  confirms the read path: "Frontend reads via a CloudFront signed URL minted
  at /api/projects/{id}" (`V22__project_binary_analysis_s3.sql:11-12`) —
  i.e. CloudFront is the analysis fast path, not the media path (media
  serves via S3 presigned 302 per inventory §2 `media`).
- **Aurora**: named only as a fact about the *private* repo
  (`README.md:177` "Aurora endpoints"); the in-tree datasource is plain
  Postgres (`application.yml:5-8`, postgres:16 in compose). **Implied:
  prod runs Aurora-Postgres-compatible; unverifiable from the clone.**
- **Keycloak**: hosted at `auth.openapk.ai` (`SECURITY.md:23`,
  `application.yml:283-285`); what it runs on is not stated anywhere —
  unverifiable, likely ECS like the rest but **unverified**. Admin-delete
  integration is a service-account confidential client with `manage-users`
  (`application.yml:145-164`), disabled by default.
- **Email**: SESv2, verified-identity sender, no-op when region blank
  (`:245-252`). **No-op-on-missing-config is the consistent posture**:
  analysis-S3 → 53 (`:120-121`), email → no-op, Keycloak admin → anonymize
  only (`:148-150`), script analyzers → off (`:212`).

## 4. Observability & ops hygiene

- **Health**: actuator is on (`core/pom.xml:40`) but exposure is trimmed to
  `health,info` with liveness/readiness probes enabled
  (`application.yml:294-302`); the core image healthchecks
  `/actuator/health/liveness` and notes "ECS will also hit /actuator/health
  on the target group" (`core/Dockerfile:86-89`); dev.sh prints the health
  URL (`dev.sh:237`). Workers expose bare `GET /health`
  (`ghidra-worker/app/main.py:56`, `jadx-worker/app/main.py:160`) wired as
  compose healthchecks (`core/compose.yaml:31-36,55-60`); **no** `/health`
  on the Lambda workers (no HTTP surface except under RIE); Keycloak gets
  no healthcheck, with the reason and mitigation written down
  (`core/compose.yaml:83-86`, `application.yml:35-39`).
- **Metrics**: none. No micrometer registry in the pom (`grep
  -n "micrometer" core/pom.xml` → empty), no Prometheus anywhere. LLM usage
  is a DB ledger instead (`llm_audit_log`, inventory §4 V11) — product-facing
  metering, not infra observability.
- **Logs**: level-only config — `org.springframework.security: INFO`,
  `ai.openapk: DEBUG` (`application.yml:304-307`); no appenders, no JSON
  layout, no log shipping config in-repo. Workers take a `LOG_LEVEL` env
  (`core/compose.yaml:30,48`); the CLI streams + persists ghidra-worker
  logs (inventory §6).
- **Error notification**: **none exists.** The only Discord wiring is the
  CTF announcement webhook (`application.yml:265-268`, `DiscordNotifier`
  per inventory §2 `ctf`) — it announces challenges/first-bloods, not
  errors. No Sentry/alerts/IAM alarm config in-tree. A prod outage would be
  discovered by users.
- **Migration discipline**: 47 files `V1`–`V47` (`ls
  core/src/main/resources/db/migration | wc -l` = 47), Flyway
  `out-of-order: true` justified as "standard hotfix posture for
  deployments that carry environment-specific migrations"
  (`application.yml:17-23`). The migrations read like an incident ledger —
  V23's header documents the real prod bug: V22 shipped the
  `INGEST_PENDING` status value before the CHECK constraint allowed it, and
  it only surfaced "after V22 ran in prod… first /ingest/initiate call from
  the CLI" (`V23__projects_status_ingest_pending.sql:1-7`). The V22
  **5-phase JSONB→S3 plan is visibly unfinished**: the header says the
  migration is "Phase 1… DUAL-WRITE-COMPATIBLE… **Phase 5 drops it once
  dashboards confirm zero reads**" (`V22__project_binary_analysis_s3.sql:1,13-15`),
  but `grep -rn "DROP COLUMN binary_analysis_jsonb" db/migration/` → empty:
  phases 2–5 never landed, the JSONB dual-read fallback is still live at
  HEAD (cross-ref ch.32; the "dashboards" that would confirm zero reads are
  the observability this repo doesn't have).

## 5. Testing: the full inventory, honestly characterized

17 test files, **2,335 test LOC against ~84k main LOC (~2.8%)**, none run by
any machine (`find … | xargs wc -l` totals quoted per group below).

**Core — 9 files, 1,625 LOC, 70 `@Test` methods**
(`find core/src/test -name '*.java' | xargs wc -l` = 1,625; per-file
`grep -c '@Test'` sums to 70):

| File | LOC | @Test | Covers |
|---|---|---|---|
| `analysis/agent/ToolLlmInvokerTest.java` | 399 | 8 | BINNY agent tool-dispatch loop (biggest test in the repo) |
| `projects/ProjectForkAccessTest.java` | 204 | 7 | fork read access through the real `ProjectAccessGuard` + `ProjectPublicGuard` (:68) |
| `dm/DmServiceTest.java` | 275 | 11 | DM service against real Postgres, incl. access guard (:55) |
| `ctf/CtfServiceTest.java` | 189 | 6 | flag hash/rank/points via `@DataJpaTest` (:46-48) |
| `blog/BlogSchemaTest.java` | 152 | 8 | V40 schema shape (comments generalization) |
| `credentials/EgressUrlPolicyTest.java` | 151 | 14 | SSRF denylist — the deepest security suite |
| `credentials/OutboundRedirectPolicyTest.java` | 121 | 4 | no-redirect BYOK HTTP |
| `blog/BlogTextTest.java` | 99 | 9 | slug/text helpers |
| `credentials/LlmEndpointsTest.java` | 35 | 3 | endpoint URL joining |

How they hit the DB: `@DataJpaTest` +
`@AutoConfigureTestDatabase(replace = Replace.NONE)`
(`CtfServiceTest.java:46-48`, `ProjectForkAccessTest.java:56`) — they
**require a live Postgres** (the compose one). `CONTRIBUTING.md:85-86`
claims "backend integration tests use Testcontainers… Don't mock the
database," but `grep -in testcontainers core/pom.xml core/src/test` is
**empty** — the claim is stale (marked verified, not theorized); the
manual loop is `compose up` + `./mvnw test` (checklist `CONTRIBUTING.md:91`).

**CLI — 3 files, 297 LOC, 13 Test funcs** (`find cli -name '*_test.go' |
xargs wc -l` = 297; `grep -c "func Test"` → config 1, dedup 6, firmdetect
6): config defaults, sha256-dedup/fork-first, firmware arch sniffing.
**Untested: login/device-auth, ingest v2, docker image plumbing, update.**

**Workers — only script-worker is tested** (`find … -name '*test*' | xargs
wc -l` = 240): `test/engines.test.js` (131) + `test/smoke.js` (109) against
real obfuscator fixtures (inventory §7). ghidra/jadx/shell/pypi workers:
**zero tests** — the two heaviest attack-surface components (a hostile APK
into jadx, arbitrary ELF into Ghidra) have no test file.

**Frontend — 3 files, 173 LOC**, all in `shared/api`:
`forkLink.test.ts` (32), `renames.test.ts` (106),
`markdownLang.test.ts` (35) — pure functions. Both apps, landing, and all
41k TS LOC: no tests, no e2e harness, no Playbook/Cypress anywhere.

**Hot-path characterization (sampled, honest):** the auth chain
(SecurityConfig, JWT issuance/validation, `TosAcceptanceFilter`), quota
(`WorkerQuotaService`), ingest (`IngestController`, presign), decompile
lifecycle, upload, reports, and the credential **encryption round-trip**
(`LlmCredentialEncryptionService`) have **no tests at all** —
`grep -rl "TosAcceptance|WorkerQuota|Ingest|SecurityConfig" core/src/test`
matches only the two access-guard files (via `ProjectAccessGuard`). What
*is* covered: egress/redirect policy (pure logic), fork/DM access guards,
schema pins, agent tool dispatch. Net: the 32.5k-LOC hosted product's
auth/quota/ingest hot paths — the ones that faced real prod incidents (V23!)
— rest on manual smoke via dev.sh + the CLI.

## 6. Security posture

- **SECURITY.md** (58 lines): email-only disclosure to `husam@openbin.ai`
  (:7), 72h ack / 7d critical patch, no paid bounty (:14-16), scope = 4
  hosted hosts + 7 repo dirs (:20-25), explicit out-of-scope: DoS,
  phished-BYOK-keys, and **findings that depend on a misconfigured
  self-host — "using the default dev KEK in production — that's documented
  as wrong"** (:33-35); AES-256-GCM notes + KMS migration named as future
  work, "losing the KEK irrevocably loses every stored credential"
  (:39-47); dated advisory timeline (:49-56).
- **The KEK default (sharp edge #1)**: `application.yml:69-73` comments
  "MUST be set via env. **App fails fast on startup if missing** or wrong
  length" — and line 73 supplies a **hardcoded default key**:
  `${OPENAPK_KEK_B64:THdUzn8QDb//mvCPHogD76/rO9cdfsAAlBkCIPnptRo=}`. The
  default defeats the stated fail-fast; every dev/self-host instance that
  skips the env var encrypts its BYOK vault with a key that is public in
  this repo. dev.sh only *warns* about it (`dev.sh:76-79`).
- **Worker auth (sharp edge #2)**: `jadx-worker` implements a constant-time
  `X-Worker-Token` check (`app/main.py:77-91`, `hmac.compare_digest`,
  enforced on `/decompile` :174,184) — but it is a **no-op unless the
  worker's `WORKER_TOKEN` env is set** (`:89`: empty token → check passes),
  and nothing in the repo sets it (compose has no `WORKER_TOKEN`; the
  release workflow bakes no default). Core only sends the header when
  `OPENAPK_JADX_WORKER_TOKEN` is non-empty (`application.yml:194-197`,
  "Blank = no header (local dev)"). So the "401 without the token" contract
  (`application.yml:194-196`) is only real if the private operator wired
  both sides — unverifiable from the clone. **ghidra-worker has no auth at
  all** (grep finds nothing; compose:24-27 owns it: "the worker has no auth
  of its own and trusts the OpenAPK core"; dev mitigates by loopback-only
  port binding, prod "we'd lock this down at the VPC layer").
- **Egress allowlist scope**: `EgressAllowlistConfigurer`
  (`credentials/EgressAllowlistConfigurer.java:8-25`) pushes
  `openapk.llm.egress-allowlist` (`application.yml:269-275`) into the static
  `EgressUrlPolicy` at boot and **logs a loud WARN when non-empty** ("it
  widens the SSRF boundary on purpose"). It confines *server-side BYOK LLM
  base URLs*: default policy blocks loopback/169.254/16-IMDS and unwraps
  v6-mapped IPv4 (inventory §2, `EgressUrlPolicy.java:36-38,120-132`,
  14-test suite); the allowlist lets self-hosters point BYOK at an internal
  model gateway (`llm-gateway.corp.example,10.40.0.0/16`, :273-274). It is
  an outbound-destination policy for the core's own HTTP, not a general
  network control.
- **Public endpoint surface**: `anyRequest().denyAll()` outside `/api/**`;
  permitAll on `/api/community/**`, `/api/public/**`, `/api/tos.md`;
  `public/projects/*/binary-analysis` authenticated *before* permitAll
  (`config/SecurityConfig.java:29-68,47-58`, inventory §3.2); TOS 412 gate
  on top; CORS allowlisted with localhost dev defaults + env extension
  (`application.yml:74-80`).
- **Secret scanning = gitleaks only** (full history on push/PR,
  `gitleaks.yml:18-25`); **no dependabot/renovate config** (`ls .github` →
  only `workflows/`), no CodeQL, no SAST. The "CLA bot" is external CLA
  Assistant (`CONTRIBUTING.md:31-33`, PR checklist "the bot will check"
  :94) — nothing about it lives in the repo. Supply-chain pinning is
  partial (§2: optional sha256 for Ghidra/jadx zips, `npm ci` lockfile for
  script-worker, unpinned `minio:latest`).
- **Quota/DoS posture**: 5 dispatch/user/day cap as an explicit "Phase 0
  emergency quota… stops the AWS bill from running away"
  (`application.yml:237-244`); multipart 200MB file / 400MB request caps
  (`:47-54`); script uploads capped 25MB (`:229-233`). SECURITY.md
  disclaims DoS as out of scope (:29). Rate limiting infra: none (inventory
  §11).

## 7. Licensing & business posture

- **AGPL-3.0-or-later over the whole runtime** (`LICENSE`, 661 lines;
  `README.md:151-161` explains §13 network-copyleft as "the whole point: a
  hosted fork must contribute back").
- **CLA dual-license mechanics** (`CONTRIBUTING.md:21-33`): contributions
  are AGPL *and* maintainers get relicensing-to-commercial permission —
  "without it, accepting any external PR would lock the entire codebase
  into AGPL-only forever" (:28-29, echoed `README.md:186-190`); trivial
  fixes exempted via manual apply + credit (:35-37). Commercial licensing
  contact is the same single address as security: `husam@openbin.ai`
  (`README.md:166-168`).
- **Trademarks**: names are the authors', code is AGPL, "forks are welcome
  under a different name" (`README.md:193-196`).
- **Repo vs not**: everything to run an instance is in-tree (runtime,
  compose, migrations, self-host switches); "operator-specific deployment
  configs (`infra/`), task-def overlays, Aurora endpoints, secret ARNs, ECR
  push scripts with embedded account IDs" are deliberately private — "not
  the product — an operations concern" (`README.md:170-180`,
  `CONTRIBUTING.md:15-17`; scrub commit, inventory §9).
- **The economics read straight off the config**: the cloud product was
  *sunset by cost* on the record — Ghidra 2026-06-03 "AWS compute cost
  outpaced what a free OSS project can carry… Flip back… once sponsorship
  lands" (`application.yml:180-184`), JADX 2026-06-11 "the always-on worker
  was the biggest line on the AWS bill" (:198-204). The pivot is visible in
  one diff-shaped story: kill always-on compute, ship the identical worker
  containers as **release-asset tarballs** run on the user's machine via
  the CLI (§1), keep only scale-to-zero Lambdas for the analyzers
  (:205-208), cap the residue at 5/user/day (:237-244), make BYOK the
  cost-transfer for LLM spend (`:41-45` + vault), and monetize the
  copyleft-incompatible enterprise via the CLA relicensing clause + email
  contact. Self-host is a first-class product surface, not an afterthought:
  `web.self-hosted` flag swaps hosted-only copy (`:290-292`),
  `downloads-base` lets an air-gapped install serve its own binaries
  (`:286-289`), TOS gate is toggleable for customer's-own-terms
  (`:261-264`), egress allowlist for internal gateways (:269-275), fs/MinIO
  storage backends (§3). (Cross-ref ch.31 for the sunset narrative in
  commit-train form.)

## 8. calxgloss comparison

Verified on the calxgloss repo (2026-10-31): `git tag -l` → exactly **1
tag**, `v0.2.0` (a changelog-cut tag, 2026-10-06, `git log -1 v0.2.0`) —
not zero, but no release *pipeline* behind it, nothing builds artifacts.
No CI at all: `ls .github Makefile justfile dev.sh` all absent; `find .
-name '*.yml' -o -name '*.yaml'` outside docs → empty — matching
roadmap P42's own words "calxgloss has no CI at all (no `.github/
anywhere)" (`docs/roadmap.md:65`). Test volume: `grep -rE
'#\[(tokio::)?test\]' crates --include='*.rs' | wc -l` = **4,692 inline
tests**; `find crates -path '*/tests/*.rs' | wc -l` = **51 integration
files** (ch.10 QA section).

The blunt symmetry: **both are one-human-plus-Claude codebases that skipped
CI entirely.** OpenBin's margin is exactly one workflow above zero —
gitleaks over history — plus a tag-triggered release pipeline. calxgloss
outranks OpenBin on test *volume* (~4.7k vs 70 core + 13 Go + ~15 JS
test functions) and owns e2e (`calxgloss-web/tests/e2e.rs`,
`kuna_scan_e2e.rs`, `calxgloss-testgen/tests/dll_e2e.rs`) — but calxgloss
has *no* machine-run gate for them (P42, `docs/roadmap.md:65`), while
OpenBin has no e2e at all. Neither has a scored oracle: P33
(`docs/roadmap.md:62`) is OpenBin's missing eval harness in calxgloss
clothes — OpenBin ships real deobfuscation fixtures
(`script-worker/fixtures/`) but never scores pipeline quality; both need
the KRAKEN-style scored corpus and neither built it.

What calxgloss should copy **despite OpenBin's own gaps**:

1. **The release-asset distribution model** (§1): version-less asset names
   behind `releases/latest/download`, a tiny `VERSION` marker asset driving
   the self-update nudge, and engine containers shipped as `docker load`
   tarballs instead of a registry (`release-cli.yml:11-20,187-200`). If
   calxgloss ever ships a binary distribution or bundles an external
   engine/toolchain, this is the cheapest proven pattern — and it inverts
   the failure: OpenBin's images are versioned by tag lockstep
   (`openbin/ghidra-worker:7` = `cli/config.go:62` = workflow :65), a
   discipline calxgloss's cache already half-owns via
   `CACHE_FORMAT_VERSION`/engine-build identity (`crates/integrations/calxgloss-decomp/src/cache.rs:140`)
   but nowhere else.
2. **Ordered schema history if a DB ever ships** — calxgloss has no DB and
   should keep git-as-history (ch.10 "Data model"); OpenBin's
   migration-as-incident-ledger discipline (V23's honest postmortem header,
   §4) is the format to steal *if* that ever changes, and V22's stalled
   5-phase plan is the counter-example: start a numbered migration
   campaign only if you'll finish it, and have a dashboard before claiming
   "zero reads" (§4).
3. **`dev.sh` as one-command boot** — verified absent in calxgloss
   (`ls dev.sh` → no such file). OpenBin's preflight/port-check/log-tail/
   teardown-trap pattern (`dev.sh:64-121,189-217`) is directly liftable for
   calxgloss's `live`/`serve` + web-UI loop; the lesson includes its bug —
   warn-loudly-about-insecure-defaults, never default them (§6 KEK).
4. **gitleaks as a one-file first CI job** — if calxgloss ever adds CI,
   OpenBin's `gitleaks.yml` is the smallest non-vacuous CI commit, and
   calxgloss *would* benefit: `re/` record trees and fixture DLLs are
   exactly what accidental secret commit lands in. It's not a substitute
   for P42's build/test gates (`docs/roadmap.md:65`), just its floor.
5. **What OpenBin's story confirms about P42/P33 sequencing**: OpenBin is
   the existence proof that a no-CI, no-e2e, 2.8%-tested codebase *can*
   ship a live product — until its one schema mistake surfaced in prod
   (V23) and its cost model broke (§7). calxgloss's P42-first ordering in
   the P42–P52 block ("starting with CI, because the QA-flavored ones ride
   on it", `docs/roadmap.md:87`) is validated from the negative side by
   OpenBin, and ADR-0041's already-designed CI hook — `doctor` "exits
   non-zero so CI can gate on it" (ch.10, `cli_types.rs` Doctor doc) — is
   sitting unused; OpenBin has no equivalent machine-gateable self-check
   to copy, it has the hole.

Divergences that should *not* be copied: the KEK-hardcoded-default
pattern, opt-in worker tokens as the entire service-to-service auth story,
and marketing copy that asserts CI the repo doesn't have
(`core/Dockerfile:31-32`, `CONTRIBUTING.md:85-86`).

## Corrections to the inventory chapter

1. **§11 "Tests that exist (all run manually)"** — add the CI-adjacent
   contradictions: `core/Dockerfile:31-32` claims "tests run in CI before
   we ever tag an image" (false — no test CI), and `CONTRIBUTING.md:85-86`
   claims backend tests use Testcontainers (no testcontainers dependency in
   `core/pom.xml`; tests use `@AutoConfigureTestDatabase(replace = NONE)`
   against the live compose Postgres). Both are stale claims, verified by
   grep, not inferred.
2. **§11 / §4 on V22–V23** — the V22 header states an explicit 5-phase
   JSONB→S3 plan ("Phase 5 drops it once dashboards confirm zero reads",
   `V22__project_binary_analysis_s3.sql:13-15`); `grep -rn "DROP COLUMN
   binary_analysis_jsonb" db/migration/` = empty: the plan is unfinished at
   HEAD, still dual-write. (Inventory §4 V22 already says "dual-read
   fallback" — this adds that the drop was *scheduled* and never shipped.)
3. **§10 gitleaks line** — correct scope: gitleaks is the only CI
   *check*, but note it scans **full history** (`fetch-depth: 0`) on every
   push to master and PR, and there is no dependabot/CodeQL config either.
4. **§2 `credentials` row** — `EgressAllowlistConfigurer` deserves its
   semantics: it *widens* the SSRF denylist (hostnames/CIDRs allowed to
   resolve private) for self-hosted LLM gateways, logs a WARN when
   non-empty (`EgressAllowlistConfigurer.java:22-24`); it is not itself a
   protection.
5. **§6 image tags** — confirm from the release side: the ghidra tag
   `openbin/ghidra-worker:7` is called out in
   `.github/workflows/release-cli.yml:57-61` as "MUST stay in lockstep with
   `ghidraWorkerImage` in cli/config.go", and release assets are exactly
   `openbin-{linux,darwin}-{amd64,arm64}.tar.gz` +
   `openbin-windows-amd64.zip` + `jadx-worker.tar.gz` +
   `ghidra-worker.tar.gz` + `VERSION` (:4-15) — plus the fact that
   `attach-images` uses `fail_on_unmatched_files: true` so a missing image
   tarball *does* fail the release (:185).
6. **§9 tags** — the two non-`openbin-v*` tags (`v0.1.0`,
   `cli-v0.1.0-alpha`) never fired the release workflow (trigger is
   `openbin-v*`, `release-cli.yml:24-25`); 13 tag-cut releases, not 15.
