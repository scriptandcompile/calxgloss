# OpenAPK/OpenBin product surface — accounts, collaboration, reports, social, CTF

> Part of the [OpenAPK/OpenBin overview](README.md). This chapter covers the
> product/social layer — the stuff that makes OpenBin "the GitHub of reverse
> engineering": auth and accounts, projects as collaboration objects, report
> authoring and publishing, the social graph, DMs, notifications, CTF, and
> the two frontends' information architecture. Engine/analysis internals
> (workers, BINNY, renames replay, symbol indexes) live in the other 3x-*
> chapters; claims here cite the clone at `/tmp/opencode/openbin` @
> `aee59b05`, clone-relative `path:line`.

## 1. Auth & account lifecycle

**Identity is Keycloak, users are JIT-shadow rows.** The backend is a pure
OAuth2 resource server — no password, no session, no cookie anywhere. Every
authenticated request resolves the local `users` row inside
`CurrentUserService.current()` (`core/src/main/java/ai/openapk/core/auth/CurrentUserService.java:40-81`):
the stable key is the OIDC `sub`, with a deliberate tolerance ladder —
`sub → preferred_username → email` (:55-59, comment "some Keycloak configs
strip `sub` from access tokens") — and a first-writer insert
`users.insertIfNotExists(...)` races safely (:65-69). Each call refreshes
`last_seen_at` (the presence primitive behind "researcher online" surfaces,
:71) and syncs email, but display name is **user-owned once set**: it is
only seeded from the JWT when blank (:73-79), so PATCH `/api/users/me` wins
over the IdP claim forever. `currentOrNull()` (:32-37) exists so public
endpoints can personalize ("did you upvote this") without requiring auth.

**Sessions/logout** are entirely client + Keycloak side: tokens are bearer
JWTs (`config/SecurityConfig.java`), the SPAs use `react-oidc-context` code
flow with `automaticSilentRenew` (`shared/auth/`), the CLI uses the RFC-8628
device grant (`cli/auth.go`); there is no server-side logout state. Dev-realm
import (`core/docker/keycloak/import/realm-openapk.json`) registers exactly
two clients — `openapk-frontend` (:17, redirect `http://localhost:5173/*`
:29-34) and `openbin-cli` (:44) — **no `openbin-frontend` client** (verified
exhaustive grep of `"clientId"`), confirming the README's out-of-band
instruction quirk.

**ToS is a hard HTTP gate, not UI policy.** `tos/` versions the terms by
date string; `TosAcceptanceFilter` answers **428/412 Precondition Required**
(`PRECONDITION_REQUIRED`, `tos/TosAcceptanceFilter.java:97-102`) with a JSON
body describing the acceptance state for any authed call when the user's
`tos_accepted_version` (V24) is stale — the frontend's `TosGate` component
exists because the API literally refuses to serve anything else. `/api/tos.md`
is permitAll so the text is readable pre-acceptance.

**Email preferences (V21 + V28 columns)** are one opt-out matrix
(`user_email_preferences`: decompile_complete, report_published,
abuse_confirmation + notify_new_follower / comment_on_my_report /
reply_to_my_comment / collaborator_invite) shared by bell notifications and
SES transactional email — one table, both channels (`notifications/UserEmailPrefs.java`).
There is **no email verification flow** — email arrives from the Keycloak
claim, unverified by the app itself (verified: no verify token/table).
**Profile socials (V40)** add bio/website/github/x/mastodon/linkedin to
`users`, handled bare or as URL, validated at the API (`MeController` PATCH).

**Account deletion is the deepest product decision in the package**
(`account/AccountDeletionService.java:17-58` javadoc, `deleteOwnAccount` :96-158).
Policy: **private data hard-deleted, public contributions kept-but-anonymized.**
Unpublished projects are destroyed through `ProjectService.delete` so S3/disk
bytes and the shared analysis blob are actually freed (:102-110 — "a raw DB
delete would orphan the bucket"); 11 private leaf tables + follows + **both
sides of every 1:1 DM** are purged (:59-71, :113-125 — "the deleting user's
words should not outlive them"); community-published projects, reports, blog
posts, comments stay. The `users` row is **anonymized in place, never
deleted** — S3 paths are keyed by owner id, so deleting the row would orphan
published media (:20-26) — renamed to "Deleted researcher", `keycloak_sub`
scrambled to `deleted:<uuid>` no JWT can match (:136), byline snapshots
scrubbed (:129-131). The Keycloak user is deleted **after commit** via Admin
REST (`KeycloakAdminClient`, no spring admin-client dep) (:148-154).

## 2. Projects as collaboration objects

**The permission spine is one class.** `ProjectAccessGuard` answers
owner-OR-collaborator in a single query and exposes three tiers —
`requireRead` (OWNER/EDITOR/VIEWER), `requireEdit` (404s for VIEWER "to kill
existence probing"), `requireOwner` (`projects/ProjectAccessGuard.java:56-98`).
Roles are VIEWER/EDITOR only — **OWNER is never in the collaborators table**
(V26 CHECK), it's the `projects.user_id` column itself
(`ProjectCollaboratorService.java:129-131`). `ProjectPublicGuard`
(`projects/ProjectPublicGuard.java:23-35`) is the anonymous counterpart:
private and nonexistent answer identically 404.

**Collaborators (V26)** are added owner-only by **user id** (picked from
researcher search / follower graph — "the social DTOs never expose email
addresses", `:133-135`) **or by email** — the email path requires the invitee
to have signed in once, because users are JIT rows (`:140-142`). A fresh
invite fires `notifyCollaboratorInvite` (bell + email); **role edits don't
re-notify** ("promoting VIEWER → EDITOR shouldn't re-spam them",
`:163-168`). Removal also tidies the project-chat membership row (`:180-181`).

**Presence (V31) is a dumb heartbeat, not websockets.** The client pings
`POST /api/projects/{id}/presence` on mount and **every 60 s**
(`shared/components/MembersBar.tsx:13,20,95`), plus a separate interval
refreshes the roster while visible (`:96`); the server upserts
`project_presence(project,user,last_active_at)` — gated at the read tier "so
this can't be used to probe project existence" (`ProjectCollaboratorService.java:92-102`).
The `/members` response merges owner + collaborators + last-active
(`:69-90`). "Online" is derived client-side from staleness; there is no
server-side session registry.

**Public read (V34) is GitHub's "browse the repo" button**: PUT/DELETE
`/api/projects/{id}/public` flips `public_read_at`. Anonymous visitors get
metadata, highlights, report and media via `PublicProjectController` — but
**the decompiled code view (`/api/public/projects/{id}/binary-analysis`) is
authenticated before the permitAll rule** (`config/SecurityConfig.java:47-58`):
you can read the writeup logged out, you can't read the pseudocode.

**Forks (V35) share bytes, not compute.** `POST /api/projects/{id}/fork`:
BIN projects only (`projects/ProjectService.java:739`), requires the source's
analysis to be READY, copies **no worker output** — the fork row references the
source's S3 analysis blob, which is **refcounted** so deleting the source (or
the fork) frees storage only when the last consumer goes (`:658,670,686`; V22
flow). "No worker runs and no quota is charged" (`:726-731`). Attribution
renders "🍴 forked from X", and the link target flips between the authed and
public route depending on whether the source is publicly readable —
`shared/api/forkLink.ts:1-24` documents the original bug (forks of others'
private-but-since-forked projects 404'd the author's own view). `fork_count`
is denormalized on the source; deleting the fork decrements. Upstream, the
CLI runs **dedup → fork-first**: sha256 lookup (`GET /api/projects/dedup`)
matches only PUBLIC projects and offers to fork instead of re-analyzing.

**Multi-binary surfaces are two different objects.** *Samples* (V41 +
`projects/samples/`, 7 endpoints) attach N extra binaries to one BIN project
(sha256 unique per project, S3 ingest per sample, `/move-from` to migrate a
sample between projects); V41's migration comment records they are
**deliberately not wired into renames/highlights/report** — annotation
scoping deferred. *Bundles* (V37) group standalone BIN projects under a
name, creation CLI-only (`openbin decompile --bundle NAME`).

## 3. Reports: MAR/VRR authoring, publishing, community, media

**MAR / VRR = Malware Analysis Report / Vulnerability Research Report**
(`README.md:7` — the product's two flagship document types). The mode lives
on the project (`analysis_mode`, V9, default MALWARE) and selects a
`TemplateMode` of MALWARE / VULN_RESEARCH / ANY on user templates (V10,
`reports/TemplateMode.java`). A report is **1:1 with its project** with
`sections_jsonb` (V4) — section content is free-form markdown slabs, not a
schema.

**Two publishes, deliberately separate (V5 + V18).** `publish()` sets
`published_at` — an EDITOR-level "finalize/lock" action
(`reports/ProjectReportService.java:219-233`); `publishToCommunity()` is
**owner-only**, sets the distinct `community_published_at` that puts the
report in the anonymous `/api/community/{apk|bin}/reports` feed, **auto-locks
the report if it wasn't locked**, fires a live-email once (first publish only,
`:278`), **couples the project's public-read toggle to the publish action when
requested** (`:291` — "publish the writeup AND the repo" in one gesture), and
re-snapshots the contributor byline on every re-publish "so the owner can
re-curate credits by republishing after roster changes" (`:304-305`,
`ReportContributorService.snapshot` :46+). Unpublishing from community keeps
the report lock (`:314`).

**populate = analysis → report draft.** `POST /report/populate`
(`ProjectReportService.java:190`) switches on section name with explicit
"MAR-flow populate targets" vs "VRR-flow populate targets" comment blocks
(`:590-593`): findings/IoCs/crypto/constants/imports/strings are pulled from
the stored digest, static pre-scan, IoC extractor and analysis JSONB — the
analyst edits prose, the machine fills evidence sections. Markdown export
(`GET /export.md`, :361) **inlines referenced media as base64 data URLs** so
the standalone document survives outside the app (`:395`), plus a chrome-free
print route on both frontends.

**Taxonomy + search (V19).** `malware_type` is validated against the STIX
2.1 `malware-type` open vocabulary — deliberately *not* a Java enum because
the vocabulary is extensible (`reports/MalwareTypes.java:6-18`, set at :18);
`tags[]` capped 8×32 app-side; weighted `search_tsv` (A=title, B=tags/type,
D=sections) maintained by a BEFORE-UPDATE trigger + GIN. Community feed sorts:
default `new`, `trending` = upvotes DESC with recency tiebreaker "so a
brand-new 0-vote report isn't pinned to the bottom forever"
(`reports/CommunityService.java:153-157`).

**Contributors (V33) answer "who co-authored this?" with a snapshot, not a
join.** At publish, `ReportContributorService` freezes the byline:
project owner = **LEAD**; every distinct user who "materially worked" the
project — applied renames (`renames.applied_by`), report edits
(`reports.updated_by`) — = **CONTRIBUTOR**, unless they opted out via
`users.credit_publicly` (owner exempt from opt-out)
(`reports/ReportContributorService.java:19-26,58-93`). `display_name` +
`email_md5` (gravatar) are frozen into the row so the public byline is stable
and survives account deletion (which scrubs the snapshot to "Deleted
researcher", §1). **Moderation is deliberately thin: no admin UI, no
moderation queue.** An anonymous `POST /api/community/reports/{id}/abuse`
emails the configured admin via SES and records a notification
(`CommunityService.java:337-353`); takedown is a human reading mail.

**Media + annotation: verify the claim, it's real but small.** The `media/`
package is a flat per-project **PNG-only gallery, 10 MB cap**
(`media/MediaService.java:29-30`), served via presigned CloudFront/S3 302 or
filesystem stream. The annotation tooling is **client-side only**:
`openbin-frontend/src/components/Annotator.tsx` (422 LOC) is a canvas editor
with crop + exactly four tools — `rect | arrow | text | free`
(`Annotator.tsx:3-7`) — whose stroke list is re-rendered
and flattened to PNG on save (`:77-89`), then POSTed to the media gallery;
`captureScreen.ts` (56 LOC) grabs a region of the app's own code view.
Strokes are **not persisted as vectors** — the server stores the flattened
raster, so annotations are un-editable after save. Highlights close the loop:
`HighlightType` is FUNCTION / FILE (require `targetRef`, an address or path
anchor) vs **VISUAL** (a standalone annotated screenshot with `media_key`,
no anchor) (`highlights/HighlightType.java:5-12`,
`ProjectHighlightService.java:56-66`); `created_by` is SET NULL so the board
survives deletion. Highlights are created by humans (panel), by BINNY (its
`create_highlight` tool), shown on the project page, and appear on the
anonymous public-project surface — the curated "look here" layer between raw
code and the report prose.

## 4. The social layer: follows, votes, comments, notifications, DMs, blog

**Follows + votes (V27).** `social/SocialService.java`: follows are mutual-
graph rows with a DB CHECK against self-follow, double-enforced in code
("cannot follow yourself", `:97`); the follow notification fires **only on a
fresh follow** — repeat POSTs from a flaky client don't re-ping (`:111-116`).
Votes are **upvotes only, no downvotes by design** — "the abuse flow covers
negation" (V27 comment). Researcher profiles (`/u/:id` + followers/following
pages) expose display name, bio, V40 socials and public output; **emails are
never exposed in social DTOs** — the collaborator-add flow routes around that
by id (`ProjectCollaboratorService.java:133-135`). Researcher search is
`GET /api/community/users/search`.

**Comments (V28 + V40 generalization) are Reddit-style, not 1-level.**
`social/CommentsService.java:167-178` explicitly allows **arbitrary nesting
depth** ("Arbitrary nesting depth (Reddit-style)… the frontend caps the
*visual* indent and offers 'continue thread' past that"); the parent must
belong to the same report/post. Soft delete keeps threads readable. Comments
attach to either a community-published report or a blog post (V40's
`num_nonnulls(report_id, post_id) = 1` CHECK) — one table, two surfaces.
Commenting on a non-community-published report 404s (`:162-164`).

**Notifications (V29) are write-baked fan-out, one gate.**
`notifications/NotificationService.java` is "a thin orchestrator that wraps
EmailService" so the per-user opt-out matrix is enforced in exactly one
place (`:25-27`); kinds observed in code: DECOMPILE_COMPLETE,
REPORT_PUBLISHED, ABUSE_CONFIRMATION (+`notifyAbuseReceived`), NEW_FOLLOWER,
COMMENT_ON_MY_REPORT, REPLY_TO_MY_COMMENT, **COMMENT_ON_MY_POST,
REPLY_TO_MY_POST_COMMENT**, COLLABORATOR_INVITE (`:67-222`). The in-app bell
row stores a JSONB payload with the actor's gravatar hash baked in and a
**frontend route baked into `link` at write time** (`"/blog/"+slug`,
`"/projects/"+id` — V29 design; if routes move, old rows break, deliberately
accepted). Sends are best-effort post-persist: "a 'decompile done' email
shouldn't roll back the decompile itself" (`:33`), and reply-notify is
suppressed when it would duplicate the report-author notify
(`CommentsService.java:192-196`). Seven opt-out booleans in one PATCH
(`NotificationService.java:236-244`).

**DMs (V42/V43) + project team chat (V45) share one machinery.** 1:1
conversations are keyed by canonical `pair_key` (`"<lesser uuid>:<greater uuid>"`,
UNIQUE — two simultaneous first messages race safely,
`dm/DmService.java:159,173`). `DmPolicy` — EVERYONE / FOLLOWING / NOBODY —
gates **channel creation, not the channel**: "tightening the policy makes
existing threads read-only for the other side" (`:42-44,82-112`). Project
team chat (V45) is one conversation per project (`project_id` partial UNIQUE):
membership is **checked live against the collaborator roster** — the
`dm_members` row is a read cursor, not a membership grant — so a removed
collaborator loses the chat immediately and it drops from their inbox
(`:129,193-197,290`); the recipient's DmPolicy deliberately does **not**
apply to team chat. Unread state is per-member `last_read_at` cursors, and
both the bell and the DM badge are **polled**, not pushed (`:39` "polled
like the bell").

**Blog (V40)** is a second publishing surface: `blog/BlogService.java`
drafts are private and **404 exactly like nonexistent slugs** (`:74-80`),
publishing **freezes the slug forever** ("a post that returns doesn't come
back at a different URL", `:25-27`), slugs are title-derived + suffix-
uniquified (`:225-230`); posts get their own upvotes (`post_votes`) and
comment thread (the generalized `report_comments`). Public endpoints live
under `/api/community/blog` (anonymous feed, author pages, by-slug +
comments).

**What `network/` and `search/` actually are — neither is social or global.**
`network/NetworkService.java` is an **IOC extractor**: regex line-scans the
decompiled tree for Retrofit `@GET/@POST`, OkHttp `.url(…)` verb pairing and
`HttpURLConnection new URL(...)`→`openConnection()` call sites (its imports
are `ProjectStorage` + `RenameService` + `SdkPaths`, file:3-11) — "network"
means network indicators, not a social network. `search/SearchService.java`
is a **per-project regex walk** over that project's decompiled files
(`/api/projects/{id}/search`); cross-object search is Postgres tsvector in
`CommunityService` (reports) plus LIKE-based `/users/search` (researchers).
There is **no single global search endpoint**.

## 5. CTF: weekly challenges, flags, leaderboards

CTF (V47, HEAD feature) is a self-contained engagement loop under `ctf/`
(1,046 LOC, 8 classes). The rules docstring (`ctf/CtfService.java:49-60`) is
the spec: **flags are never stored or logged plaintext** — comparison is
`sha256(salt ':' normalized_flag)` (`hashFlag`, :121-124); **rank is arrival
order inside the window** (1 = first blood; post-window solves get rank 0 +
archive points "so old challenges stay worth doing without touching the
week's board"); **points = 100 − 10·(rank−1), floor 50, archive 20**
(`FIRST_BLOOD_POINTS/POINTS_STEP/FLOOR_POINTS/ARCHIVE_POINTS`, :74-77,
`pointsForRank` :106-108); **brute force is capped by a DB-counted rate
limit, 5 attempts / 10 min** "so the limit survives restarts and multiple
instances" (:58-59). Every attempt lands in `ctf_submissions` but the
attempted text is never stored (V47). Solves carry an `ai_assisted`
self-report checkbox, and a solver may attach **one of their published
projects as the writeup** (`POST /challenges/{slug}/writeup`, CtfService
:270+). Challenges are BIN or APK kind with a public (public_read) project
as the puzzle, a hint, season = quarterly points sum, and a
`ResearcherOfTheWeek` card surfaced on the public CTF home
(`CtfDtos.ResearcherOfTheWeek`, CtfHome DTO at :174 area).
`CtfScheduler` (`ctf/CtfScheduler.java:5-22`) is one `@Scheduled(fixedDelay
=60_000)` tick calling `announceStartedChallenges()`, which posts to a
Discord webhook (`ctf/DiscordNotifier.java:18-56`, disabled when
`openapk.discord.webhook-url` is empty) and marks `announced_at` so each
challenge announces exactly once (V47). Challenge authoring is an admin-side
`AdminUpsertRequest` DTO (:8) — there is no public challenge-creation API;
in production the operator authors challenges directly.

## 6. Frontend information architecture

Both apps are React 19 + Vite + Tailwind, separate deployments of one API.
Route enumeration verified from `App.tsx` (`path=` grep):

**openbin-frontend (`src/App.tsx:56-134`) — 29 page files** (verified `ls
src/pages`, correcting the inventory's "30"): public tier — `/`, `/blog`,
`/blog/:slug`, `/community` (+`/researchers`, `/reports/:id`), `/ctf`
(+`/:slug`), `/public/projects/:id`, `/u/:id` (+followers/following),
`/terms`, `/privacy`, `/docs` + `/docs/cli`; authed tier (RequireAuth +
TosGate) — `/dashboard`, `/projects`, `/projects/:id` (kind-dispatched via
`pages/ProjectViewRoute.tsx:10-19`: APK|BIN→ProjectView, SCRIPT→
ScriptProjectView), `/projects/:id/overview`, `/projects/:id/report`,
`/bundles/:id`, `/messages(/:id)`, `/blog/new|:id/edit`,
`/settings/{profile,api-keys,report-templates,usage}`; full-viewport
outliers `/projects/:id/report/print` and `/projects/:id/graph`. IA shape:
**three doors** — the tool (dashboard/projects), the feed (community/blog/
ctf), and the storefront (public project pages + landing app).

**openapk-frontend (`src/App.tsx:34-87`) — 19 page files**: same skeleton
minus CTF, blog, docs, bundles, overview, graph (older product line; keeps
in-app `Landing.tsx`).

**`shared/` split (52 files, verified dirs):** `api/` (20 modules — every
domain fetch hook incl. SSE streaming helpers, `forkLink.ts`, `collaborators.ts`),
`auth/` (`makeOidcConfig` PKCE code flow + `RequireAuth` +
`StaleSessionRecovery`), `components/` (24 feature components — the social
UI lives here, not in either app: `CommentsThread`, `NotificationsBell`,
`MembersBar`, `ShareProjectModal`, `ForkButton`, `FollowButton`,
`UpvoteButton`, `ContributorByline`, `HighlightsPanel`, `dm/MessagesPage`,
`dm/ProjectChatPanel`, `dm/DmPrivacySettings`, `TosGate`), `config/runtime.ts`
(self-host override via `window.__OPENBIN_CONFIG__`), `theme/light.css`.
Product-specific chrome (Layout, upload cards, annotator, gallery, sample
tab bars) stays in each app's `src/components`. Dev-realm quirk verified:
`core/docker/keycloak/import/realm-openapk.json` contains exactly two
clients, `openapk-frontend` (:17, redirect `http://localhost:5173/*` :29-34)
and `openbin-cli` (:44) — a fresh `docker compose up` gives openbin-frontend
no login until the operator creates the client by hand per `README.md:73`.

## 7. calxgloss comparison

**The baseline holds: calxgloss has none of this, by construction**
(baseline ch. 10, "Multi-user, collaboration & publishing — verified
absence"): no auth, no accounts, no projects/sharing/forks, no comments/
votes/notifications/DMs, no publish/export surface, unauthenticated
`0.0.0.0` web bind as a single-operator trust zone. The ADRs that pin that
posture are explicit: ADR-0002 (two-router web API over artifacts),
ADR-0006 (web views read-only over existing artifacts), ADR-0003 (reviewer
intent lives in overlay files, not derived artifacts), ADR-0004 (control is
a shared state machine over REST) — the web surface is a *review console*,
not a *place where people interact with each other*.

**Analogues in KIND, not scale.** Five genuine pairings survive honest
comparison:

1. **Reviewer verdicts ↔ upvotes/comments.** Both are human signals stamped
on machine output at unit/report granularity — but their authority is
inverted. A calxgloss verdict (`accepts/rejections/patches` records,
accept/patch POSTs) *changes the artifact*: accepted code merges to `main`.
An OpenBin vote *changes what other humans see* (trending sort,
`CommunityService.java:153-157`) and never touches the analysis. calxgloss
has no comments because the argument is already in the artifact: the
justification commit + baseline tests are the discussion, settled by
verification rather than replies.
2. **Justification commits ↔ contributor bylines.** `calxgloss-git` records
*why* each unit of work happened (attempt N, deps, tests, model, context
size, `calxgloss-git/src/lib.rs:10-31`) — machine-auditable provenance,
author = the run. OpenBin's V33 snapshot records *who* deserves credit
(LEAD/CONTRIBUTOR frozen at publish, `ReportContributorService.java:19-26`)
— a social contract, deliberately denormalized so it survives deletion.
Two answers to "who made this and how do we know": calxgloss answers via
git, OpenBin via byline; neither does both.
3. **re/review overlays ↔ highlights board.** Both are human curation layers
that never mutate machine output. But overlays (skips, queue order, unknown
resolutions) are **instructions to the pipeline** — what to work on, in what
order (ADR-0003) — while highlights (FUNCTION/FILE/VISUAL anchors, V32) are
**instructions to other humans** — where to look in the code. Same
shape, opposite audience.
4. **populate-from-analysis + report templates ↔ the evidence bundle +
bundle-fed templates (ADR-0048/0049).** Both auto-draft from structured
evidence with the same projector idea: assemble one bundle, render one
template, human/model edits the result. The consumer is inverted —
OpenBin's populate fills *markdown sections for a person to edit*
(`ProjectReportService.java:190,590-593`); calxgloss's bundle fills a
*prompt for the model to translate from*. If calxgloss ever shipped a
findings writeup, the projection rows are already written.
5. **Coverage stamps ↔ the public report's missing honesty.** Here calxgloss
is ahead, not behind. OpenBin's published report is unqualified prose —
nothing in `project_reports` records what the analysis *didn't* establish;
the honest artifact simply doesn't exist in that schema. calxgloss's ADR-0053
(coverage stamped at scan time, absent = unknown, never absent) and ADR-0056
(named unknown records with deterministic ids) are exactly the layer a
hosted report product would need before "published" means "complete." In
the GitHub-of-RE world every report renders as finished; calxgloss's
unknown ledger is the counter-design.

**If calxgloss ever wanted reviewers-in-parallel: say it plainly — nothing
helps today, and that's fine.** No P-threads, no queue claiming, no
per-record locks, no identity at the web edge (`server/mod.rs:1297` binds
open). The accidental-foundation observation: the record tree is already
unit-granular, git branches are already per-unit
(`re/{binary}/{function}v{N}`), and ADR-0056 already splits *document
ownership between two actors* (pipeline owns the ledger, reviewer owns
resolutions, joined at read time) — that read-time-join-of-separate-owner-documents
pattern is the seed a multi-reviewer design would grow from. But there is no
roadmap item for it, and importing OpenBin's social machinery would fight
ADR-0006 and the single-operator premise; the honest answer is "not a gap,
a different product."

**What the endpoint distribution says about the market around calxgloss.**
Verified bucketing of all 178 mappings (per-controller grep counts, sums
verified to 178): **analysis/RE bench = 57 (32%)** — the 15 analysis
controllers + ProjectController's 5 file-serving endpoints + 4 highlights;
**pure social/communication = 44 (25%)** — social 8, community 10, blog 6+4,
dm 10, notifications 6; **CTF = 7 (4%)**; **report authoring + publish +
public-read surface + media = 24 (13%)**; **collaboration & lifecycle
plumbing = 29 (16%)** — 9 collab/public/fork/presence/members + 5 mgmt +
samples 7 + ingest 3 + bundles 5; **account/auth/platform/BYOK = 17 (10%)**.
So ~46% of the API (social + CTF + community publishing + collab plumbing)
exists to move *people* around the binaries, while only a third touches the
decompile output itself. Read alongside the cloud-decompile sunset and
BYOK-only stance (inventory §3.3 — they gave away hosted translation
because it didn't pay), the market signal is: **automatic translation is a
commodity; the paid product is the collaboration/Q&A/reporting surface
around it.** calxgloss bets the opposite pole — full automation of the
translation itself — and ships the human at exactly one joint (unit
verdicts). The two are not competitors: OpenBin's deliverable is shared
understanding (a report + a community), calxgloss's is an executable
replacement (a Rust workspace that passes the original's tests). OpenBin
proves there is a large audience that wants to *read and discuss*
decompiled code; calxgloss is built for the audience that wants the code
*gone* — replaced by verified Rust — with the discussion already settled by
the gate.

## Corrections to the inventory chapter

Verified against this chapter's greps; rest of ch. 20 stands.

1. **§5.2 "30 page files" → 29.** `ls openbin-frontend/src/pages` returns
exactly 29 `.tsx` files. (The 38 `<Route>` count is plausible — several
routes are index routes without `path=`; my `path=` grep finds 34.)
2. **§4 V28 "1-level nesting via parent" is wrong at the service layer.**
`CommentsService.java:174-178` explicitly allows **arbitrary Reddit-style
depth**; only the visual indent is capped client-side. The DB CHECK was
length, not depth.
3. **§2 notifications row under-lists kinds.** The four V29-era kinds are
superseded: code also emits COMMENT_ON_MY_POST, REPLY_TO_MY_POST_COMMENT,
DECOMPILE_COMPLETE, REPORT_PUBLISHED, abuse confirmation/received — and
`email-preferences` PATCH covers all seven opt-outs
(`NotificationService.java:236-244`).
4. **§3.1 per-controller sums string mis-lists `CtfPublicController` as 3;
it is 4** (GET, challenges, challenges/{slug}, leaderboard). The 178 grand
total re-verified independently by per-file `grep -c` across all 39
controller files.
5. **§8 media bullet needs limits.** The gallery is **PNG-only, 10 MB cap**
(`MediaService.java:29-30`), and the annotator (`Annotator.tsx:3-7`: crop +
rect/arrow/text/free, 422 LOC) **flattens strokes to a raster on save** —
annotations are uneditable afterwards; vectors are never stored.
6. **§8 fork bullet: forks are BIN-only** ("only binary projects can be
forked", `ProjectService.java:739`) — APK projects have no fork path.
7. **CTF authoring has no public API.** `AdminUpsertRequest`/
`AdminChallengeRow` DTOs exist but are referenced only by `CtfService`/
`CtfDtos` — challenge create/update is not exposed by any controller in the
open tree (verified grep); §3.1's CTF rows are the complete HTTP surface.
Rate limit verified: 5 submissions/10 min, DB-counted
(`CtfService.java:58-59`).
8. **§5.5 dev-realm quirk confirmed**: realm import has exactly
`openapk-frontend` + `openbin-cli` clients (`realm-openapk.json:17,44`),
no `openbin-frontend`.
