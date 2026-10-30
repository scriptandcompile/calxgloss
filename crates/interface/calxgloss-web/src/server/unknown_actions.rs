//! Reviewer dispositions over unknown records (issue #374).
//!
//! The pipeline files the gaps it admitted into its ledger document
//! (`re/unknowns/<binary>.json`); the reviewer answers them in their own
//! resolutions document (`re/review/unknown_resolutions.json`). This module
//! wires those answers — resolve, dismiss, reopen — onto the review-action
//! seam: the same action lock as accept / send-back / patch, the same
//! capture-at-start / re-check-before-write conflict discipline, and the
//! same rule that a persisted record outlives every derived rebuild.
//!
//! A disposition action writes *only* the reviewer's document. The
//! pipeline's ledger is read here — to find the record and check the
//! revision the reviewer acted against — and never written, and no
//! disposition touches the unit's review status, its verdict, or its
//! branch: resolving an unknown is deliberately not a review status.
//!
//! The revision doctrine itself lives in the shared `UnknownResolutions`
//! type (issue #368). What this seam supplies is the unit scope — an
//! action addresses a record by unknown id, and the record must be filed
//! against this unit — the capture/re-check that makes a two-action race
//! land exactly one, and the ledger's absence rule: no filed ledger means
//! what is open on the binary is *unknown*, and nothing can be settled
//! against unknown.

use super::actions::{ActionResult, ActionsState, lookup_unit};
use calxgloss_types::scan::now_unix_secs;
use calxgloss_types::{
    EffectiveLedger, PersistError, UnknownActionError, UnknownRecord, UnknownResolution,
    UnknownResolutions, load_json, read_unknown_ledger, save_json, unknown_resolutions_path,
};
use tracing::info;

/// A disposition action found no record it could act on (issue #374): the
/// binary's ledger is unfiled (so what is open is *unknown*, never zero
/// gaps and never something to settle), the filed ledger names no such id,
/// or the record belongs to another unit. The action wrote nothing.
#[derive(Debug, thiserror::Error)]
pub enum UnknownReviewError {
    #[error(
        "No unknown disposition can act on record {unknown_id} for unit {unit_id}: {reason} \
         — nothing was written"
    )]
    NoRecord {
        /// The unit the reviewer addressed through the unit-scoped endpoint.
        unit_id: String,
        /// The unknown record the reviewer tried to settle or reopen.
        unknown_id: String,
        /// Why the record is out of the unit's action reach.
        reason: String,
    },
}

/// Settle a filed unknown record as *resolved*: the reviewer established
/// the fact the record asks about, on the grounds its reason line states
/// (issue #374). The settle lands in the reviewer's resolutions document
/// guarded by `expected_revision` — the record revision the reviewer had
/// read — and a stale view loses with a changed-underneath conflict naming
/// the landed state. None of this touches the unit: no review status,
/// verdict, or branch changes.
pub async fn resolve_unknown(
    state: &ActionsState,
    unit_id: &str,
    unknown_id: &str,
    reason: &str,
    expected_revision: u32,
) -> Result<ActionResult, anyhow::Error> {
    settle_unknown(
        state,
        unit_id,
        unknown_id,
        Disposition::Resolve {
            reason,
            expected_revision,
        },
    )
    .await
}

/// Settle a filed unknown record as *dismissed*: the reviewer judged the
/// question irrelevant and says so with a reason (issue #374). A dismissed
/// record still counts in the audit ledger — a disposition records what was
/// decided, never what was established — and the guard is exactly the
/// resolve guard.
pub async fn dismiss_unknown(
    state: &ActionsState,
    unit_id: &str,
    unknown_id: &str,
    reason: &str,
    expected_revision: u32,
) -> Result<ActionResult, anyhow::Error> {
    settle_unknown(
        state,
        unit_id,
        unknown_id,
        Disposition::Dismiss {
            reason,
            expected_revision,
        },
    )
    .await
}

/// Take a settled record back to open (issue #374): a resolution is a
/// revision, never a deletion. The settled entry leaves the reviewer's map —
/// it is their own intent they are taking back — and the reopen lands as a
/// durable mark naming the revision it was taken back from; the pipeline's
/// next ledger write appends one revision above the landed one at that
/// mark. This action never writes the ledger itself.
pub async fn reopen_unknown(
    state: &ActionsState,
    unit_id: &str,
    unknown_id: &str,
) -> Result<ActionResult, anyhow::Error> {
    settle_unknown(state, unit_id, unknown_id, Disposition::Reopen).await
}

/// The three dispositions, sharing one body: the same action lock, the
/// same ledger read, the same reviewer-document write.
enum Disposition<'a> {
    Resolve {
        reason: &'a str,
        expected_revision: u32,
    },
    Dismiss {
        reason: &'a str,
        expected_revision: u32,
    },
    Reopen,
}

/// What the reviewer's own document says about a record at action time —
/// the observed pre-state the capture/re-check compares, mirroring how
/// [`begin_action`](ActionsState::begin_action) captures the unit's
/// persisted action state before the lock for accept / send-back / patch.
struct CapturedState {
    settled: bool,
    revision: u32,
}

/// Names the state a refused action found landed, in the wording family the
/// shared unknown-type and the unit actions' `state_name` both keep: a
/// record without a settlement reads as open at its current revision, a
/// settled one names its disposition and the revision it was settled at.
fn landed_state(record: &UnknownRecord, entry: Option<&UnknownResolution>) -> String {
    match entry {
        Some(entry) => format!(
            "{} at record revision {}",
            entry.disposition, entry.expected_revision
        ),
        None => format!("open at record revision {}", record.revision),
    }
}

/// Find the record the action addresses, as the pipeline's ledger files it
/// for the unit's binary, together with the reviewer's resolutions document
/// as it stands right now. Unit-scoped by construction: the unit's binary
/// fixes which ledger is read, and the record must name this unit's
/// function to be in reach. The ledger is only ever read here.
fn locate_unknown(
    state: &ActionsState,
    unit_id: &str,
    unknown_id: &str,
) -> Result<(UnknownRecord, UnknownResolutions), anyhow::Error> {
    let unit = lookup_unit(state, unit_id)?;
    let workspace = state.repo_path();

    // The ledger's three readings never collapse: an unfiled ledger — or a
    // filed one whose records key is absent — is *unknown*, and unknown is
    // nothing a disposition can act on. A corrupt ledger fails loudly
    // rather than reading as unknown.
    let record = match read_unknown_ledger(workspace, &unit.binary)? {
        EffectiveLedger::Unknown => {
            return Err(UnknownReviewError::NoRecord {
                unit_id: unit_id.to_string(),
                unknown_id: unknown_id.to_string(),
                reason: format!(
                    "no unknown ledger is filed for {}, so what is open on it is unknown",
                    unit.binary
                ),
            }
            .into());
        }
        EffectiveLedger::Filed(records) => {
            let Some(record) = records.iter().find(|r| r.id == unknown_id) else {
                return Err(UnknownReviewError::NoRecord {
                    unit_id: unit_id.to_string(),
                    unknown_id: unknown_id.to_string(),
                    reason: format!("the filed ledger for {} names no such record", unit.binary),
                }
                .into());
            };
            // The endpoints are unit-scoped: a record naming another
            // function — or the binary itself, functionless — is out of
            // this unit's action reach, exactly as it never entered this
            // unit's prompts (issue #370).
            if record.function.as_deref() != unit.function.as_deref() {
                let named = match record.function.as_deref() {
                    Some(function) => format!("names the function {function}"),
                    None => "names the binary itself".to_string(),
                };
                return Err(UnknownReviewError::NoRecord {
                    unit_id: unit_id.to_string(),
                    unknown_id: unknown_id.to_string(),
                    reason: format!("the record {named}, not this unit"),
                }
                .into());
            }
            record.clone()
        }
    };

    // The reviewer's own document: its absence is simply no settled
    // answers yet, never a miss — but a corrupt one is never replaced by
    // an action, the same corrupt-never-reads-as-absent rule the ledger
    // keeps.
    let path = unknown_resolutions_path(workspace);
    let resolutions = match load_json::<UnknownResolutions>(&path) {
        Ok(landed) => landed,
        Err(PersistError::NotFound { .. }) => UnknownResolutions::default(),
        Err(source) => {
            return Err(anyhow::anyhow!(
                "the reviewer's unknown resolutions document at {} is unreadable \
                 — not overwriting it: {source}",
                path.display()
            ));
        }
    };
    Ok((record, resolutions))
}

async fn settle_unknown(
    state: &ActionsState,
    unit_id: &str,
    unknown_id: &str,
    action: Disposition<'_>,
) -> Result<ActionResult, anyhow::Error> {
    // Capture the reviewer's view before the lock — exactly the discipline
    // begin_action keeps for the unit actions: state that lands in between
    // is what the write-time re-check below must catch.
    let (captured_record, captured_resolutions) = locate_unknown(state, unit_id, unknown_id)?;
    let captured = CapturedState {
        settled: captured_resolutions.resolution_for(unknown_id).is_some(),
        revision: captured_record.revision,
    };

    // The same action lock accept / send-back / patch take (issue #374):
    // the whole read → settle → save below is atomic against a racing
    // review action on the server.
    let _action_guard = state.begin_unknown_action().await;

    // Re-check under the lock: a settle or reopen that landed in between —
    // including a reopen taking back the settlement a resolve action was
    // written against, which the landed entry alone cannot witness — fails
    // here naming the state that actually landed, instead of silently
    // overwriting or re-settling it. A racing settle lands exactly one of
    // resolve-vs-dismiss and exactly one of reopen-vs-resolve.
    let (record, mut resolutions) = locate_unknown(state, unit_id, unknown_id)?;
    let landed_entry = resolutions.resolution_for(unknown_id);
    let landed_settled = landed_entry.is_some();
    if landed_settled != captured.settled || record.revision != captured.revision {
        return Err(UnknownActionError::ChangedUnderneath {
            unknown_id: unknown_id.to_string(),
            current: landed_state(&record, landed_entry),
        }
        .into());
    }

    // The write-time settle itself — the shared type's own guard, which is
    // the cross-process discipline too: the reviewer's `expected_revision`
    // is checked against the record as the ledger now files it, so a fresh
    // batch run that re-derived the record since the reviewer read it
    // refuses the stale write without touching anything.
    let (action_name, message) = match action {
        Disposition::Resolve {
            reason,
            expected_revision,
        } => {
            resolutions.resolve(&record, reason, expected_revision, now_unix_secs())?;
            ("resolve", format!("unknown {unknown_id} resolved — {reason}"))
        }
        Disposition::Dismiss {
            reason,
            expected_revision,
        } => {
            resolutions.dismiss(&record, reason, expected_revision, now_unix_secs())?;
            (
                "dismiss",
                format!("unknown {unknown_id} dismissed — {reason}"),
            )
        }
        Disposition::Reopen => {
            resolutions.reopen(&record)?;
            (
                "reopen",
                format!(
                    "unknown {unknown_id} reopened — the settlement stands as a \
                     revision mark, never a deletion"
                ),
            )
        }
    };

    // The only write this action makes: the reviewer's document — the
    // pipeline's ledger and the unit's action record stay exactly as they
    // were, so the batch's next ledger write and every later dashboard
    // rebuild find the resolution right where it landed.
    save_json(&unknown_resolutions_path(state.repo_path()), &resolutions)
        .map_err(|source| anyhow::anyhow!("failed to persist the unknown resolution: {source}"))?;

    info!("Unit {unit_id} unknown {unknown_id} {action_name}");

    Ok(ActionResult {
        unit_id: unit_id.to_string(),
        action: action_name.to_string(),
        merge_hash: None,
        branch_name: None,
        message,
        rejection_path: None,
        translated_code: None,
    })
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::super::handlers::{api_dismiss_unknown, api_reopen_unknown, api_resolve_unknown};
    use super::super::{CombinedState, ServerError, ServerState, UnknownSettleRequest};
    use super::*;
    use axum::extract::{Json, Path, State};
    use calxgloss_git::GitManager;
    use calxgloss_translator::assembly::PipelineSpec;
    use calxgloss_types::{
        BinaryIdentity, EffectiveDisposition, UnknownDisposition, UnknownKind, UnknownLedger,
        UnknownOrigin, UnknownSeverity, load_json, unknown_ledger_path,
    };
    use std::collections::BTreeMap;

    const UNIT: &str = "game_logic.dll/DrawSprite/v1";

    fn spec_without_llm() -> PipelineSpec {
        PipelineSpec::default()
    }

    /// A repo with one review unit — branch `re/game_logic.dll/DrawSpritev1`
    /// with one translated commit, the same shape the `actions.rs` tests use
    /// — so the unit really exists on the dashboard and the branch's merge
    /// state can be checked against a disposition action doing nothing.
    fn make_repo_with_unit() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("temp dir");
        let git = GitManager::init_repo(dir.path(), None).expect("init git repo");
        git.create_branch("game_logic.dll", "DrawSprite", 1, None)
            .expect("create v1 branch");

        let branch =
            calxgloss_types::GitBranch::new("game_logic.dll", "DrawSprite", 1).expect("branch name");
        std::fs::create_dir_all(dir.path().join("src").join("modules")).expect("src dir");
        std::fs::write(
            dir.path().join("src").join("modules").join("game_logic.rs"),
            "pub fn draw_sprite() {}\n",
        )
        .expect("write translation");
        git.commit(
            &branch,
            "Translate DrawSprite",
            &["src/modules/game_logic.rs"],
        )
        .expect("commit translation");
        dir
    }

    /// One filed-shaped record for `game_logic.dll`, derived the way the
    /// batch's coverage fold derives it.
    fn record(function: Option<&str>, facet: &str) -> UnknownRecord {
        UnknownRecord::derive(
            "game_logic.dll",
            function.map(str::to_string),
            UnknownKind::CoverageFacet,
            UnknownSeverity::Material,
            format!("What is still not established about {facet} for this unit?"),
            format!("filed {facet} evidence"),
            UnknownOrigin::Document {
                document: "memory lifecycle result".to_string(),
                facet: facet.to_string(),
            },
            1_700_000_000,
        )
    }

    fn stage_ledger(repo: &std::path::Path, records: Vec<UnknownRecord>) {
        let ledger = UnknownLedger {
            binary: BinaryIdentity::new("game_logic.dll"),
            filed_at: 1_700_000_000,
            records: Some(records),
        };
        save_json(&unknown_ledger_path(repo, &ledger.binary), &ledger).expect("stage the ledger");
    }

    /// The ledger document's exact bytes — the pin every disposition action
    /// must leave untouched.
    fn ledger_bytes(repo: &std::path::Path) -> Vec<u8> {
        std::fs::read(unknown_ledger_path(
            repo,
            &BinaryIdentity::new("game_logic.dll"),
        ))
        .expect("the filed ledger document is on disk")
    }

    fn load_ledger(repo: &std::path::Path) -> UnknownLedger {
        load_json(&unknown_ledger_path(repo, &BinaryIdentity::new("game_logic.dll")))
            .expect("the filed ledger document parses")
    }

    fn load_resolutions(repo: &std::path::Path) -> UnknownResolutions {
        load_json(&unknown_resolutions_path(repo)).expect("the resolutions document parses")
    }

    // ── the two documents, one owner each ──────────────────────────────

    #[tokio::test]
    async fn a_resolution_lands_in_the_reviewers_document_and_leaves_the_ledger_byte_unchanged() {
        let dir = make_repo_with_unit();
        let settled = record(Some("DrawSprite"), "function-bodies");
        stage_ledger(dir.path(), vec![settled.clone()]);
        let before = ledger_bytes(dir.path());
        let state = ActionsState::new(dir.path().to_path_buf(), spec_without_llm());

        resolve_unknown(
            &state,
            UNIT,
            &settled.id,
            "the fact landed with the vtable evidence",
            1,
        )
        .await
        .expect("a settle against the current revision lands");

        // The reviewer's own document, beside the skip set and the overlay.
        let path = unknown_resolutions_path(dir.path());
        assert!(
            path.exists(),
            "the resolution lands in re/review/unknown_resolutions.json, keyed by unknown id"
        );
        let resolutions = load_resolutions(dir.path());
        let entry = resolutions
            .resolution_for(&settled.id)
            .expect("the resolution is keyed by the unknown id");
        assert_eq!(entry.disposition, UnknownDisposition::Resolved);
        assert_eq!(entry.reason, "the fact landed with the vtable evidence");
        assert_eq!(entry.expected_revision, 1);
        assert!(entry.at > 0, "the settlement carries its timestamp");

        // The pipeline's ledger document stays byte-for-byte what it was.
        assert_eq!(
            ledger_bytes(dir.path()),
            before,
            "a reviewer settle never writes the pipeline's ledger"
        );

        // The read-time join — nobody downstream stores its own copy.
        let joined = resolutions.join(&[settled]);
        assert_eq!(joined[0].disposition, EffectiveDisposition::Resolved);
    }

    #[tokio::test]
    async fn a_dismissal_lands_as_dismissed_and_says_so_to_the_join() {
        let dir = make_repo_with_unit();
        let out_of_scope = record(Some("DrawSprite"), "string-context");
        stage_ledger(dir.path(), vec![out_of_scope.clone()]);
        let before = ledger_bytes(dir.path());
        let state = ActionsState::new(dir.path().to_path_buf(), spec_without_llm());

        dismiss_unknown(
            &state,
            UNIT,
            &out_of_scope.id,
            "the reviewer ruled it out of scope",
            1,
        )
        .await
        .expect("the dismissal lands");

        let resolutions = load_resolutions(dir.path());
        let entry = resolutions
            .resolution_for(&out_of_scope.id)
            .expect("the dismissal is keyed by the unknown id");
        assert_eq!(entry.disposition, UnknownDisposition::Dismissed);
        assert_eq!(entry.reason, "the reviewer ruled it out of scope");
        assert_eq!(
            ledger_bytes(dir.path()),
            before,
            "the dismissal leaves the pipeline's ledger byte-unchanged"
        );

        let joined = resolutions.join(&[out_of_scope]);
        assert_eq!(joined[0].disposition, EffectiveDisposition::Dismissed);
    }

    #[tokio::test]
    async fn a_settle_without_its_reason_is_refused_and_no_document_lands() {
        let dir = make_repo_with_unit();
        let open = record(Some("DrawSprite"), "function-bodies");
        stage_ledger(dir.path(), vec![open.clone()]);
        let before = ledger_bytes(dir.path());
        let state = ActionsState::new(dir.path().to_path_buf(), spec_without_llm());

        let err = resolve_unknown(&state, UNIT, &open.id, "   ", 1)
            .await
            .expect_err("a settle without its reason is refused");
        let error = err
            .downcast_ref::<UnknownActionError>()
            .expect("the refuse names the shared unknown-action error");
        assert!(
            matches!(error, UnknownActionError::EmptyReason { .. }),
            "an answer that never states its grounds is refused: {error}"
        );
        assert!(
            !unknown_resolutions_path(dir.path()).exists(),
            "a refused settle writes nothing"
        );
        assert_eq!(ledger_bytes(dir.path()), before);
    }

    // ── unit scope and the ledger's absence rule ─────────────────────

    #[tokio::test]
    async fn a_record_naming_another_function_or_the_binary_itself_is_out_of_a_unit_actions_reach() {
        let dir = make_repo_with_unit();
        let foreign = record(Some("FUN_zzz"), "call graph");
        let binary_level = record(None, "exports");
        stage_ledger(dir.path(), vec![foreign.clone(), binary_level.clone()]);
        let state = ActionsState::new(dir.path().to_path_buf(), spec_without_llm());

        for id in [&foreign.id, &binary_level.id] {
            let err = resolve_unknown(&state, UNIT, id, "not mine to settle", 1)
                .await
                .expect_err("a unit-scoped action cannot reach another unit's record");
            let error = err
                .downcast_ref::<UnknownReviewError>()
                .expect("an out-of-reach record reads as no record here");
            assert!(
                matches!(error, UnknownReviewError::NoRecord { .. }),
                "{id} is out of {UNIT}'s reach: {error}"
            );
        }
        assert!(
            !unknown_resolutions_path(dir.path()).exists(),
            "the refused actions wrote nothing"
        );
    }

    #[tokio::test]
    async fn where_no_ledger_is_filed_what_is_open_is_unknown_and_nothing_can_be_settled() {
        let dir = make_repo_with_unit();
        // No ledger document at all: absence is unknown, never zero gaps —
        // and unknown is nothing a disposition can act on.
        let state = ActionsState::new(dir.path().to_path_buf(), spec_without_llm());

        let err = resolve_unknown(
            &state,
            UNIT,
            "game_logic.dll/DrawSprite/coverage_facet/memory lifecycle result#function-bodies",
            "no ledger was ever filed",
            1,
        )
        .await
        .expect_err("nothing can be settled against unknown");
        let error = err
            .downcast_ref::<UnknownReviewError>()
            .expect("the unfiled-ledger refuse is the no-record error");
        let message = error.to_string();
        assert!(
            message.contains("unknown"),
            "the refuse states the honest reading: {message}"
        );
        assert!(!unknown_resolutions_path(dir.path()).exists());
    }

    // ── the revision guard: same conflict discipline as the unit actions ──

    #[tokio::test]
    async fn a_stale_expected_revision_loses_naming_the_landed_open_state() {
        let dir = make_repo_with_unit();
        let mut moved_on = record(Some("DrawSprite"), "function-bodies");
        moved_on.revision = 2; // a later batch run re-derived the record.
        stage_ledger(dir.path(), vec![moved_on]);
        let before = ledger_bytes(dir.path());
        let state = ActionsState::new(dir.path().to_path_buf(), spec_without_llm());

        let err = resolve_unknown(
            &state,
            UNIT,
            "game_logic.dll/DrawSprite/coverage_facet/memory lifecycle result#function-bodies",
            "I read it at revision 1",
            1,
        )
        .await
        .expect_err("a write carrying a stale expected revision loses");
        let conflict = err
            .downcast_ref::<UnknownActionError>()
            .expect("a stale settle fails with the changed-underneath conflict");
        assert!(
            matches!(conflict, UnknownActionError::ChangedUnderneath { .. }),
            "the stale write surfaces as changed-underneath: {conflict}"
        );
        let message = conflict.to_string();
        assert!(
            message.contains("changed underneath you")
                && message.contains("open at record revision 2"),
            "the conflict names the landed state: {message}"
        );
        assert!(
            !unknown_resolutions_path(dir.path()).exists(),
            "the loser writes nothing"
        );
        assert_eq!(ledger_bytes(dir.path()), before);
    }

    #[tokio::test]
    async fn a_second_settle_over_a_landed_one_loses_naming_the_landed_settlement() {
        let dir = make_repo_with_unit();
        let settled = record(Some("DrawSprite"), "function-bodies");
        stage_ledger(dir.path(), vec![settled.clone()]);
        let state = ActionsState::new(dir.path().to_path_buf(), spec_without_llm());

        resolve_unknown(&state, UNIT, &settled.id, "resolved first", 1)
            .await
            .expect("the first settle lands");
        let err = dismiss_unknown(&state, UNIT, &settled.id, "now try to dismiss it", 1)
            .await
            .expect_err("a second settle over a landed one loses");
        let conflict = err
            .downcast_ref::<UnknownActionError>()
            .expect("the loser fails with the changed-underneath conflict");
        assert!(
            conflict
                .to_string()
                .contains("resolved at record revision 1"),
            "the loser names the landed settlement: {conflict}"
        );
        // The landed settlement is untouched.
        let resolutions = load_resolutions(dir.path());
        let entry = resolutions
            .resolution_for(&settled.id)
            .expect("the first settlement is still there");
        assert_eq!(entry.disposition, UnknownDisposition::Resolved);
    }

    #[tokio::test]
    async fn resolve_and_dismiss_race_exactly_one_wins_and_the_loser_names_the_settlement() {
        let dir = make_repo_with_unit();
        let contested = record(Some("DrawSprite"), "function-bodies");
        stage_ledger(dir.path(), vec![contested.clone()]);
        let before = ledger_bytes(dir.path());
        let state = ActionsState::new(dir.path().to_path_buf(), spec_without_llm());

        // Hold the action lock while both actions start, so each captures
        // its pre-state (nothing settled yet) and queues on the lock — the
        // two-reviewers scenario from the issue. Releasing it lets the
        // first-spawned settle land; the loser's write-time re-check must
        // then find the landed settlement and lose.
        let guard = state.begin_unknown_action().await;
        let id_resolve = contested.id.clone();
        let id_dismiss = contested.id.clone();
        let resolve_state = state.clone();
        let dismiss_state = state.clone();
        let resolve = tokio::spawn(async move {
            resolve_unknown(&resolve_state, UNIT, &id_resolve, "resolved on the evidence", 1).await
        });
        let dismiss = tokio::spawn(async move {
            dismiss_unknown(&dismiss_state, UNIT, &id_dismiss, "dismissed as irrelevant", 1).await
        });
        tokio::task::yield_now().await; // both tasks capture and queue on the lock
        drop(guard);

        resolve
            .await
            .expect("resolve task")
            .expect("the first settle (resolve) wins the race");
        let err = dismiss
            .await
            .expect("dismiss task")
            .expect_err("the losing settle must fail, not overwrite the landed one");
        let conflict = err
            .downcast_ref::<UnknownActionError>()
            .expect("the loser fails with the changed-underneath conflict");
        assert!(
            matches!(conflict, UnknownActionError::ChangedUnderneath { .. }),
            "the race loser surfaces as changed-underneath: {conflict}"
        );
        assert!(
            conflict
                .to_string()
                .contains("resolved at record revision 1"),
            "the loser names the landed settlement: {conflict}"
        );

        // Exactly one disposition landed, in the reviewer's document only.
        let resolutions = load_resolutions(dir.path());
        assert_eq!(resolutions.resolutions.len(), 1, "exactly one settlement");
        let entry = resolutions
            .resolution_for(&contested.id)
            .expect("the winner's settlement is keyed by the id");
        assert_eq!(entry.disposition, UnknownDisposition::Resolved);
        assert_eq!(
            ledger_bytes(dir.path()),
            before,
            "the race never touched the pipeline's ledger either"
        );
    }

    #[tokio::test]
    async fn reopen_and_resolve_race_exactly_one_wins() {
        let dir = make_repo_with_unit();
        let settled = record(Some("DrawSprite"), "function-bodies");
        stage_ledger(dir.path(), vec![settled.clone()]);
        // The record already landed settled — one reviewer's stale view is
        // about to try to settle it again while another takes the
        // settlement back.
        let mut pre = UnknownResolutions::default();
        pre.resolve(&settled, "settled earlier", 1, 1_700_000_500)
            .expect("stage the landed settlement");
        save_json(&unknown_resolutions_path(dir.path()), &pre).expect("stage resolutions");
        let state = ActionsState::new(dir.path().to_path_buf(), spec_without_llm());

        let guard = state.begin_unknown_action().await;
        let id_reopen = settled.id.clone();
        let id_resolve = settled.id.clone();
        let reopen_state = state.clone();
        let resolve_state = state.clone();
        let reopen = tokio::spawn(async move {
            reopen_unknown(&reopen_state, UNIT, &id_reopen).await
        });
        let resolve = tokio::spawn(async move {
            resolve_unknown(
                &resolve_state,
                UNIT,
                &id_resolve,
                "stale reviewer settles again",
                1,
            )
            .await
        });
        tokio::task::yield_now().await; // both capture the landed settlement and queue
        drop(guard);

        reopen
            .await
            .expect("reopen task")
            .expect("the first-spawned action (reopen) wins");
        let err = resolve
            .await
            .expect("resolve task")
            .expect_err("the losing settle must fail, not silently re-settle the record");
        let conflict = err
            .downcast_ref::<UnknownActionError>()
            .expect("the loser fails with the changed-underneath conflict");
        assert!(
            matches!(conflict, UnknownActionError::ChangedUnderneath { .. }),
            "the reopen-vs-resolve pairing needs the seam's re-check: {conflict}"
        );
        assert!(
            conflict
                .to_string()
                .contains("open at record revision 1"),
            "the loser names the state the reopen left landed: {conflict}"
        );

        let resolutions = load_resolutions(dir.path());
        assert!(
            resolutions.resolutions.is_empty(),
            "only the reopen landed: the settlement is taken back, nothing re-settled"
        );
        assert_eq!(
            resolutions.reopened.get(&settled.id),
            Some(&1),
            "the reopen stands as a durable mark at the revision it was taken back from"
        );
    }

    // ── a resolution is a revision, never a deletion, and survives ─────

    #[tokio::test]
    async fn reopening_appends_a_revision_on_the_next_filing_and_deletes_nothing() {
        let dir = make_repo_with_unit();
        let reopened = record(Some("DrawSprite"), "function-bodies");
        stage_ledger(dir.path(), vec![reopened.clone()]);
        let state = ActionsState::new(dir.path().to_path_buf(), spec_without_llm());

        resolve_unknown(&state, UNIT, &reopened.id, "settled by mistake", 1)
            .await
            .expect("the settle lands");
        reopen_unknown(&state, UNIT, &reopened.id)
            .await
            .expect("the reopen lands");

        let resolutions = load_resolutions(dir.path());
        assert!(
            resolutions.resolution_for(&reopened.id).is_none(),
            "the reviewer took their own settlement back"
        );
        assert_eq!(
            resolutions.reopened.get(&reopened.id),
            Some(&1),
            "the reopen marks the revision it was taken back from — the record is never deleted"
        );

        // The pipeline's next ledger write appends one revision above the
        // landed one at that mark: the reopen is a revision, and nothing
        // the pipeline owns is deleted or rewritten.
        let landed = load_ledger(dir.path());
        let derived = vec![record(Some("DrawSprite"), "function-bodies")];
        let refiled = UnknownLedger::file(
            "game_logic.dll",
            Some(&landed),
            &derived,
            &resolutions.reopened,
            1_700_000_900,
        );
        let record_after = refiled
            .record(&reopened.id)
            .expect("the record still lands");
        assert_eq!(
            record_after.revision, 2,
            "the reopen appended exactly one revision above the settled one"
        );
        save_json(&unknown_ledger_path(dir.path(), &refiled.binary), &refiled).expect("re-file");

        // The mark stops firing at a later revision: re-running never
        // re-numbers what already landed.
        let landed = load_ledger(dir.path());
        let refiled_again = UnknownLedger::file(
            "game_logic.dll",
            Some(&landed),
            &derived,
            &load_resolutions(dir.path()).reopened,
            1_700_001_000,
        );
        assert_eq!(
            refiled_again
                .record(&reopened.id)
                .expect("still derived")
                .revision,
            2,
            "a landed revision is never rewritten by a later filing"
        );

        // The join reads the reopened record open again.
        let joined = load_resolutions(dir.path()).join(&derived);
        assert_eq!(joined[0].disposition, EffectiveDisposition::Open);
    }

    #[tokio::test]
    async fn a_resolution_survives_every_dashboard_rebuild_and_a_later_batch_run_that_reworded_the_admission()
    {
        let dir = make_repo_with_unit();
        let settled = record(Some("DrawSprite"), "function-bodies");
        stage_ledger(dir.path(), vec![settled.clone()]);
        let state = ActionsState::new(dir.path().to_path_buf(), spec_without_llm());

        resolve_unknown(&state, UNIT, &settled.id, "the answer landed in the type database", 1)
            .await
            .expect("the resolution lands");

        // Dashboard rebuilds never touch reviewer intent.
        for _ in 0..2 {
            super::super::build_dashboard(dir.path()).expect("the dashboard rebuilds");
        }
        assert!(unknown_resolutions_path(dir.path()).exists());

        // A later batch run re-derives the same gap in other words. The
        // deterministic id pins are load-bearing here: re-worded admission
        // text keeps the id, and the resolution stays bound to the gap it
        // answered.
        let re_worded = UnknownRecord::derive(
            "game_logic.dll",
            Some("DrawSprite".to_string()),
            UnknownKind::CoverageFacet,
            UnknownSeverity::Material,
            "The scan never decompiled this body — what does the function do?",
            "decompiled function bodies for DrawSprite",
            UnknownOrigin::Document {
                document: "memory lifecycle result".to_string(),
                facet: "function-bodies".to_string(),
            },
            1_700_000_800,
        );
        assert_eq!(re_worded.id, settled.id, "the id excludes the wording");

        let landed = load_ledger(dir.path());
        let refiled = UnknownLedger::file(
            "game_logic.dll",
            Some(&landed),
            std::slice::from_ref(&re_worded),
            &BTreeMap::new(),
            1_700_000_800,
        );
        assert_eq!(
            refiled
                .record(&settled.id)
                .expect("the re-derived record lands")
                .revision,
            2,
            "the reworded admission appends a revision — and the resolution stays bound"
        );
        save_json(&unknown_ledger_path(dir.path(), &refiled.binary), &refiled).expect("re-file");

        super::super::build_dashboard(dir.path()).expect("the dashboard rebuilds again");
        let resolutions = load_resolutions(dir.path());
        let joined = resolutions.join(refiled.records.as_ref().expect("filed records"));
        assert_eq!(
            joined[0].disposition,
            EffectiveDisposition::Resolved,
            "the later batch run leaves the reviewer's answer attached to the record"
        );
        assert_eq!(
            joined[0]
                .resolution
                .as_ref()
                .expect("the settlement binds")
                .reason,
            "the answer landed in the type database"
        );
    }

    // ── a disposition is never a review status ─────────────────────────

    #[tokio::test]
    async fn no_disposition_touches_the_units_verdict_its_branch_or_review_state() {
        let dir = make_repo_with_unit();
        let first = record(Some("DrawSprite"), "function-bodies");
        let second = record(Some("DrawSprite"), "string-context");
        stage_ledger(dir.path(), vec![first.clone(), second.clone()]);

        let status_before = super::super::build_dashboard(dir.path())
            .expect("dashboard builds")
            .review_queue
            .iter()
            .find(|u| u.id == UNIT)
            .expect("the unit is in the review queue")
            .status
            .clone();

        let state = ActionsState::new(dir.path().to_path_buf(), spec_without_llm());
        resolve_unknown(&state, UNIT, &first.id, "settled", 1)
            .await
            .expect("resolve lands");
        reopen_unknown(&state, UNIT, &first.id)
            .await
            .expect("reopen lands");
        dismiss_unknown(&state, UNIT, &second.id, "ruled out of scope", 1)
            .await
            .expect("dismiss lands");

        // No review action record was ever written for the unit — a
        // disposition lives only in the reviewer's resolutions document.
        let action_record = dir
            .path()
            .join("re")
            .join("actions")
            .join("game_logic.dll")
            .join("DrawSprite")
            .join("v1.json");
        assert!(
            !action_record.exists(),
            "a disposition action never persists a review action record"
        );

        // The branch was never touched, merged or otherwise.
        let git = GitManager::open(dir.path()).expect("open git");
        assert!(
            !git
                .is_branch_merged_into_main("re/game_logic.dll/DrawSpritev1")
                .expect("merged check"),
            "a disposition never merges a branch"
        );

        // And the unit's derived review status is exactly what it was.
        let status_after = super::super::build_dashboard(dir.path())
            .expect("dashboard builds")
            .review_queue
            .iter()
            .find(|u| u.id == UNIT)
            .expect("the unit is still in the review queue")
            .status
            .clone();
        assert_eq!(
            status_before, status_after,
            "a disposition is not a review status: the derived verdict stands"
        );
    }

    // ── the endpoints at the seam: mapping to statuses, same surface ────

    fn combined_with(dir: &std::path::Path, with_actions: bool) -> CombinedState {
        CombinedState {
            server: ServerState::new(dir.to_path_buf()),
            manager: None,
            bridge: None,
            actions: with_actions
                .then(|| ActionsState::new(dir.to_path_buf(), spec_without_llm())),
            progress: None,
        }
    }

    #[tokio::test]
    async fn the_resolve_endpoint_lands_through_the_actions_seam_surface() {
        let dir = make_repo_with_unit();
        let settled = record(Some("DrawSprite"), "function-bodies");
        stage_ledger(dir.path(), vec![settled.clone()]);
        let before = ledger_bytes(dir.path());

        let body = api_resolve_unknown(
            State(combined_with(dir.path(), true)),
            Path((UNIT.to_string(), settled.id.clone())),
            Json(UnknownSettleRequest {
                reason: "established from the filed baseline document".to_string(),
                expected_revision: 1,
            }),
        )
        .await
        .expect("the endpoint settles the record");
        assert_eq!(body.0.action, "resolve");
        assert_eq!(body.0.unit_id, UNIT);
        assert_eq!(
            ledger_bytes(dir.path()),
            before,
            "the endpoint write stays on the reviewer's document"
        );
        assert!(unknown_resolutions_path(dir.path()).exists());
    }

    #[tokio::test]
    async fn the_endpoints_map_a_lost_race_to_a_named_conflict_and_an_absent_record_to_not_found() {
        let dir = make_repo_with_unit();
        let mut moved_on = record(Some("DrawSprite"), "function-bodies");
        moved_on.revision = 2;
        stage_ledger(dir.path(), vec![moved_on]);

        let err = api_resolve_unknown(
            State(combined_with(dir.path(), true)),
            Path((
                UNIT.to_string(),
                "game_logic.dll/DrawSprite/coverage_facet/memory lifecycle result#function-bodies".to_string(),
            )),
            Json(UnknownSettleRequest {
                reason: "stale view of the record".to_string(),
                expected_revision: 1,
            }),
        )
        .await
        .expect_err("the stale settle loses at the endpoint too");
        assert!(
            matches!(err, ServerError::Conflict(_)),
            "a changed-underneath conflict answers as 409: {err}"
        );
        assert!(err.to_string().contains("changed underneath you"));

        let err = api_reopen_unknown(
            State(combined_with(dir.path(), true)),
            Path((
                UNIT.to_string(),
                "game_logic.dll/DrawSprite/coverage_facet/memory lifecycle result#function-bodies".to_string(),
            )),
        )
        .await
        .expect_err("reopening a never-settled record loses at the endpoint");
        assert!(
            matches!(err, ServerError::Conflict(_)),
            "a reopen with nothing settled names the landed open state: {err}"
        );

        let err = api_dismiss_unknown(
            State(combined_with(dir.path(), true)),
            Path((
                UNIT.to_string(),
                "game_logic.dll/DrawSprite/coverage_facet/memory lifecycle result#absent-facet".to_string(),
            )),
            Json(UnknownSettleRequest {
                reason: "no such record".to_string(),
                expected_revision: 1,
            }),
        )
        .await
        .expect_err("settling an unknown id answers honestly");
        assert!(
            matches!(err, ServerError::NotFound(_)),
            "no record here reads as 404: {err}"
        );
    }

    #[tokio::test]
    async fn the_endpoint_refuses_a_reasonless_settle_as_a_bad_request() {
        let dir = make_repo_with_unit();
        let open = record(Some("DrawSprite"), "function-bodies");
        stage_ledger(dir.path(), vec![open.clone()]);

        let err = api_resolve_unknown(
            State(combined_with(dir.path(), true)),
            Path((UNIT.to_string(), open.id.clone())),
            Json(UnknownSettleRequest {
                reason: "  ".to_string(),
                expected_revision: 1,
            }),
        )
        .await
        .expect_err("a settle without its reason is refused");
        assert!(
            matches!(err, ServerError::BadRequest(_)),
            "a reasonless settle is the reviewer's to fix: {err}"
        );
    }

    #[tokio::test]
    async fn a_server_without_the_actions_backend_says_so_honestly() {
        let dir = make_repo_with_unit();
        let open = record(Some("DrawSprite"), "function-bodies");
        stage_ledger(dir.path(), vec![open.clone()]);

        let err = api_resolve_unknown(
            State(combined_with(dir.path(), false)),
            Path((UNIT.to_string(), open.id.clone())),
            Json(UnknownSettleRequest {
                reason: "would settle it".to_string(),
                expected_revision: 1,
            }),
        )
        .await
        .expect_err("a server built without the actions backend refuses the action");
        assert!(
            err.to_string().contains("actions backend"),
            "the honest message names the missing backend: {err}"
        );
        assert!(!unknown_resolutions_path(dir.path()).exists());
    }
}
