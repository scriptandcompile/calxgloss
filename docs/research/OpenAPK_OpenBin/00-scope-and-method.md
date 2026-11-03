# OpenAPK / OpenBin ↔ calxgloss comparison — scope and method

> Part of the [OpenAPK/OpenBin overview](README.md). Read this first for what
> is being compared and how.

## What OpenAPK / OpenBin is

**OpenAPK / OpenBin** ([openbin-ai/platform](https://github.com/openbin-ai/platform),
AGPL-3.0-or-later with CLA-based dual licensing) is a **collaborative
web platform for reverse-engineering research**. Two hosted products share one
open backend:

- **OpenAPK** (openapk.ai) — Android RE: APK upload, JADX decompile, source
  navigation, agentic Q&A, MAR/VRR report authoring.
- **OpenBin** (openbin.ai / app.openbin.ai) — native RE: ELF / PE / Mach-O
  binaries analyzed via Ghidra, same agentic stack and report flow.

Structural facts (as of the revision below):

- **Polyglot web platform, ~82k LOC**: a Spring Boot 4 / Java 21 monolith
  (`core/`, ~35.5k LOC, ~33 domain packages) over **Postgres 16** (47 Flyway
  migrations) and **Keycloak 26** (OIDC); three React 19 frontends
  (`openapk-frontend`, `openbin-frontend`, `openbin-landing`); a **Go CLI**
  (`cli/`, ~5.3k LOC); stateless analysis workers (`ghidra-worker/`,
  `jadx-worker/`, plus `script-worker/`, `shell-worker/`, `pypi-worker/`);
  shared frontend packages (`shared/`).
- **Bring-your-own-key (BYOK) LLMs**: Anthropic / OpenAI / AWS Bedrock
  credentials encrypted at rest (AES-256-GCM under a user-supplied KEK).
- Self-hostable (compose stack with Postgres + Keycloak + MinIO), commercially
  dual-licensed; operator infra lives in a private repo.

## Comparison scope

calxgloss is a **local, automated pipeline**: Windows PE/DLL → evidence scans →
LLM translation attempts → verification → reviewer verdicts → Rust. OpenAPK/
OpenBin is a **hosted collaboration + AI-assistance platform over human-run
analyses**: the binary is decompiled once (server-side Ghidra/JADX, or locally
via the CLI), results are uploaded, and the platform provides browsing,
collaboration, agentic Q&A and report writing on top of that output. It does
**not** attempt to translate binaries to source automatically. Following the
pattern of the [KRAKEN comparison](../kraken/00-scope-and-method.md):

**In scope** (every part of the platform, since even product/surface choices
bear on calxgloss):

- Analysis pipeline end to end: CLI, ghidra-worker, jadx-worker, script/shell/
  pypi workers, ingest (S3 v2 flow), what the platform actually stores.
- Data model & storage: the 47-migration Postgres schema, project kinds,
  bundles, samples, fork/publish/public-read, symbol index, storage seam
  (`fs` vs `s3`).
- LLM/agentic layer: BYOK credential vault, agent tools, per-function
  deobfuscation (`deobf`), crypto auto-recreation (`crypto`), call-chain and
  JNI-bridge analyses, usage metering.
- Product/social layer: auth (Keycloak/OIDC JIT), projects & collaborators,
  reports (templates, taxonomy), CTF, blog, DMs/follows/votes, notifications,
  presence, public reads, frontend IA.
- Ops/QA: CI (only gitleaks + CLI release — verified absence), licensing/CLA
  posture, security posture (SECURITY.md), dev tooling (`dev.sh`).

**Out of scope** (recorded only):

- Pixel-level UI detail beyond what informs calxgloss's review UI.
- Hosted-instance operations (private `infra/` repo — not in this repo).
- Landing-page marketing copy beyond product claims worth testing against code.

## Method

1. **Baselines first**: `10-calxgloss-baseline.md` (this repo's capabilities,
   refreshed against current ADRs) and `20-openbin-inventory.md` (complete
   OpenBin surface: packages, workers, migrations, pages, endpoints).
2. **Per-domain files** (`3x-*.md`): each covers one capability domain. First
   they state what OpenBin does concretely — naming packages, files, endpoints,
   tables and design decisions — then give a direct **calxgloss comparison**
   section: overlap, calxgloss-only, OpenBin-only, verdict.
3. **Comparison** (`40-comparison.md`): head-to-head across domains, what
   calxgloss should steal, what OpenBin confirms about calxgloss's choices.
4. **Master index** (`README.md`): executive summary + capability matrix.

Every claim points to a `file:line` or doc path. OpenBin claims use the clone
at `/tmp/opencode/openbin` (revision below); calxgloss claims use this repo
(ADRs, crates, docs).

## OpenBin revision reviewed

```
git clone (full history) of https://github.com/openbin-ai/platform
commit aee59b055a12a2e335c8bf50ec1df7be55ce8508  (2026-10-12)
"feat(ctf): weekly CTF — challenges, flag submission, leaderboards, researcher of the week"
```

Upstream history at review time: 131 commits since 2026-06-03, `main` branch.
Facts below cite paths relative to that clone root.

## File index

| File | Domain |
|------|--------|
| `00-scope-and-method.md` | this file |
| `10-calxgloss-baseline.md` | calxgloss capability inventory (comparison baseline) |
| `20-openbin-inventory.md` | complete OpenBin surface (packages, workers, migrations, frontends, endpoints) |
| `31-analysis-pipeline-and-workers.md` | CLI, ghidra/jadx/script/shell/pypi workers, ingest v2, what becomes platform data |
| `32-data-model-and-storage.md` | Postgres schema, project kinds, bundles/samples, fork/publish, storage seam |
| `33-llm-and-agentic-layer.md` | BYOK vault, agent tools, deobf/crypto/callchain/JNI, usage metering |
| `34-product-social-and-reports.md` | auth, collaboration, reports/CTF/social, notifications, frontend IA |
| `35-ops-licensing-and-qa.md` | CI, license/CLA, security posture, dev tooling, deployment model |
| `40-comparison.md` | head-to-head synthesis: overlaps, divergences, steal list |
| `README.md` | executive summary, capability matrix, gap analysis |
