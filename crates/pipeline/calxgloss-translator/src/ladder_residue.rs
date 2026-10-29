//! Ladder residue: the unknown records the retry ladder's own pruned
//! decisions derive (issue #372, part of P21 #367).
//!
//! P20 gave the ladder its pruning evidence: a rung the held capability
//! report blocks is never a silent skip — the attempt record and the
//! failure hint carry the prune beside the unit's other failure evidence.
//! This module makes the ladder's decision itself a standing question:
//! every escalate rung the walk prunes files one `retry_pruned` record,
//! and every refused context-tier step files one `tier_refused` record,
//! each naming the question family the analysis engine admitted it cannot
//! answer. These are those kinds' only write sites: the decisions stay
//! entirely the ladder's (issue #356's prune arms), nothing here reads a
//! record back into the walk, and no new analysis happens here — only
//! families the engine itself declared `unavailable` at the decision
//! become records.
//!
//! The mapping the shared type's own docs pin (issue #368):
//!
//! * declared `unavailable` → [`UnknownSeverity::Blocking`] — the re-ask
//!   could only have re-produced the empty context the prune stands
//!   against, the same honest criterion the seam's own unavailable family
//!   already lands at, spelled for the decision that decision blocked;
//! * an escalate prune takes one record per blocked family, its origin
//!   `RetryDecision` naming the family the pruned escalate would have
//!   re-asked — the pruned path's question is that family's question, so
//!   the source slot is the family id itself;
//! * a refused tier step takes exactly one record for the step, its
//!   origin naming the tier the ladder refused to step onto — the refused
//!   step's question is the context that tier would have carried, and
//!   the question line names every blocked family's admission, exactly
//!   as the failure hint the same refusal pushes does;
//! * a ladder that prunes nothing derives nothing, and a family the
//!   report never declared — which reads *unknown* — never blocked the
//!   decision in the first place ([`unavailable_reask_families`]), so it
//!   can reach this producer as a blocked entry at all only by the
//!   engine's own declaration. P20's two-directional rule needs no extra
//!   gate here: the caller hands over exactly the entries it pruned on.
//!
//! The question lines are built on the blocked entries' own admission
//! wording (issue #355's doctrine): the engine's words stand, the bare
//! status word is the fallback when an entry gave no reason, and the
//! refused step's admissions join exactly as
//! [`reask_admission_lines`] spells them for the ladder's failure hints —
//! the same sentence, a different frame. Re-deriving the same decision
//! across attempts, batches, and runs folds the same id: a later escalate
//! rung pruned on the same family, and the same tier refused again after
//! another failed attempt, re-admit the standing question rather than
//! filing a second opinion.

use calxgloss_types::{
    ContextTier, FamilyCapability, UnknownKind, UnknownOrigin, UnknownRecord, UnknownSeverity,
};

use crate::retry::helpers::reask_admission_lines;

/// Derive one `retry_pruned` record for each family `blocked` — in the
/// blocked list's own order, the re-asked roster's order as
/// [`unavailable_reask_families`](crate::retry::helpers::unavailable_reask_families)
/// hands it over. `binary` and `function` name the unit whose escalate
/// rung was pruned, and `now` is the derivation stamp the ledger's filing
/// merge folds against what landed.
///
/// The origin's decision names the family the pruned escalate would have
/// re-asked, and the source slot is that family id, so the same family
/// pruning a later escalate rung re-derives this record's id — one
/// standing question, not a second prune event's duplicate.
pub fn escalate_prune_residue(
    binary: &str,
    function: &str,
    blocked: &[&FamilyCapability],
    now: u64,
) -> Vec<UnknownRecord> {
    blocked
        .iter()
        .map(|entry| {
            // The admission doctrine, per family: the entry's own
            // admission line stands, and the bare status word is the
            // fallback when it gave no reason — exactly what
            // `FamilyCapability::admission` spells for the whole entry.
            let admission = entry
                .admission()
                .unwrap_or_else(|| entry.status.to_string());
            UnknownRecord::derive(
                binary,
                Some(function.to_string()),
                UnknownKind::RetryPruned,
                UnknownSeverity::Blocking,
                format!(
                    "What is `{function}` really doing — the ladder pruned its escalate re-ask: analysis engine admitted `{admission}` for the `{}` family?",
                    entry.id
                ),
                format!(
                    "Full `{}` answers the pruned escalate would have re-asked",
                    entry.id
                ),
                UnknownOrigin::RetryDecision {
                    decision: entry.id.clone(),
                },
                now,
            )
        })
        .collect()
}

/// Derive the one `tier_refused` record for a refused context-tier step:
/// `refused_tier` is the tier the ladder refused to step onto, `blocked`
/// the families that held it, `binary` and `function` the unit whose
/// climb stopped, and `now` the derivation stamp the filing merge folds.
///
/// Exactly one record per refused step, origin naming the tier: the
/// refused step's question is the context that tier would have carried,
/// and its wording names every blocked family's admission joined exactly
/// as the ladder's own tier-hold hint does. The same step refused again
/// after another failed attempt re-derives this record's id.
pub fn tier_refusal_residue(
    binary: &str,
    function: &str,
    refused_tier: ContextTier,
    blocked: &[&FamilyCapability],
    now: u64,
) -> UnknownRecord {
    UnknownRecord::derive(
        binary,
        Some(function.to_string()),
        UnknownKind::TierRefused,
        UnknownSeverity::Blocking,
        format!(
            "What is `{function}` really doing — the ladder refused its context-tier step to `{}`: analysis engine admitted `{}`?",
            refused_tier.label(),
            reask_admission_lines(blocked),
        ),
        format!(
            "Full {} answers the refused `{}` tier step would have re-asked",
            blocked
                .iter()
                .map(|entry| format!("`{}`", entry.id))
                .collect::<Vec<_>>()
                .join(", "),
            refused_tier.label(),
        ),
        UnknownOrigin::RetryDecision {
            decision: refused_tier.label().to_string(),
        },
        now,
    )
}

/// File one escalate prune straight into the walk's residue set — the
/// derivation above, folded in by derived id: a later escalate rung
/// pruned on the same family re-derives the standing question already
/// there, it does not file a duplicate. This is where the ladder's
/// decision gets its record filed: the prune arm hands over the blocked
/// roster and walks on, and the residue never reads back into the walk.
pub fn file_escalate_prune(
    residue: &mut Vec<UnknownRecord>,
    binary: &str,
    function: &str,
    blocked: &[&FamilyCapability],
) {
    fold_by_id(
        residue,
        escalate_prune_residue(
            binary,
            function,
            blocked,
            calxgloss_types::scan::now_unix_secs(),
        ),
    );
}

/// File one refused tier step straight into the walk's residue set, the
/// same fold by derived id as [`file_escalate_prune`]: the same step
/// refused again after another failed attempt re-derives the standing
/// question already there.
pub fn file_tier_refusal(
    residue: &mut Vec<UnknownRecord>,
    binary: &str,
    function: &str,
    refused_tier: ContextTier,
    blocked: &[&FamilyCapability],
) {
    fold_by_id(
        residue,
        std::iter::once(tier_refusal_residue(
            binary,
            function,
            refused_tier,
            blocked,
            calxgloss_types::scan::now_unix_secs(),
        )),
    );
}

/// The accumulator's own fold rule: records are keyed by their derived
/// id and the first filing stands.
fn fold_by_id(
    residue: &mut Vec<UnknownRecord>,
    records: impl IntoIterator<Item = UnknownRecord>,
) {
    for record in records {
        if !residue.iter().any(|filed| filed.id == record.id) {
            residue.push(record);
        }
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use calxgloss_types::{AvailabilityStatus, DECLARED_UNKNOWN_KINDS, unknown_roster_faults};

    /// The blocked entries a prune arm hands over — every one declared
    /// `unavailable`, exactly as `unavailable_reask_families` leaves them,
    /// `None` meaning the entry admitted no reason.
    fn blocked(entries: &[(&str, Option<&str>)]) -> Vec<FamilyCapability> {
        entries
            .iter()
            .map(|(id, reason)| FamilyCapability {
                id: (*id).to_string(),
                status: AvailabilityStatus::Unavailable,
                reason: reason.map(str::to_string),
            })
            .collect()
    }

    fn residue(escalate: &[(&str, Option<&str>)], now: u64) -> Vec<UnknownRecord> {
        let entries = blocked(escalate);
        let blocked: Vec<&FamilyCapability> = entries.iter().collect();
        escalate_prune_residue("game_logic.dll", "DrawSprite", &blocked, now)
    }

    fn refused(tier: ContextTier, entries: &[(&str, Option<&str>)], now: u64) -> UnknownRecord {
        let entries = blocked(entries);
        let blocked: Vec<&FamilyCapability> = entries.iter().collect();
        tier_refusal_residue("game_logic.dll", "DrawSprite", tier, &blocked, now)
    }

    #[test]
    fn a_pruned_escalate_derives_one_record_per_blocked_family_with_the_pinned_shape() {
        let records = residue(
            &[("decompilation", Some("Zanthoxylum builds never produce a body"))],
            1_700_000_000,
        );
        assert_eq!(records.len(), 1, "one blocked family, one standing question");
        let record = &records[0];

        assert_eq!(record.kind, UnknownKind::RetryPruned);
        assert_eq!(
            record.severity,
            UnknownSeverity::Blocking,
            "the pruned re-ask could only re-produce what the engine says it cannot answer \
             — the same Blocking criterion the seam's own unavailable family already lands at"
        );
        assert_eq!(record.function.as_deref(), Some("DrawSprite"));
        assert_eq!(
            record.origin,
            UnknownOrigin::RetryDecision {
                decision: "decompilation".to_string(),
            },
            "the retry decision is the origin, naming the family the prune stood against"
        );
        assert_eq!(
            record.source_slot(),
            "decompilation",
            "the pruned path's question is that family's question — the slot is the family id"
        );
        assert_eq!(
            record.id,
            "game_logic.dll/DrawSprite/retry_pruned/decompilation",
            "the derivation is the shared one, and the kind segment keeps it apart from the \
             seam's analysis_family record on the same family"
        );
        assert_eq!(
            record.question,
            "What is `DrawSprite` really doing — the ladder pruned its escalate re-ask: \
             analysis engine admitted `unavailable — Zanthoxylum builds never produce a body` \
             for the `decompilation` family?",
            "the question is built on the entry's own admission line"
        );
        assert_eq!(
            record.required_evidence,
            "Full `decompilation` answers the pruned escalate would have re-asked",
            "the required evidence names what the blocked re-ask could not carry"
        );
        assert_eq!(record.revision, 1, "a fresh derivation starts at revision 1");
        assert_eq!(record.first_seen, 1_700_000_000);
        assert_eq!(record.last_seen, 1_700_000_000);
    }

    #[test]
    fn two_blocked_families_are_two_records_naming_each_family_in_blocked_order() {
        let records = residue(
            &[
                ("function-inventory", Some("the listing never came back")),
                ("decompilation", None),
            ],
            1_700_000_000,
        );
        assert_eq!(
            records
                .iter()
                .map(|r| r.source_slot())
                .collect::<Vec<String>>(),
            vec!["function-inventory".to_string(), "decompilation".to_string()],
            "one question per family the pruned escalate would have re-asked, in the \
             roster's own blocked order"
        );
        assert!(
            records
                .iter()
                .all(|r| r.kind == UnknownKind::RetryPruned
                    && r.severity == UnknownSeverity::Blocking),
            "every blocked family's question is its own record at the same honest level"
        );
    }

    #[test]
    fn an_unavailable_entry_with_no_reason_falls_back_to_its_bare_status_word() {
        let records = residue(&[("decompilation", None)], 1_700_000_000);
        assert!(
            records[0]
                .question
                .contains("`unavailable` for the `decompilation` family"),
            "a reason-free admission still names its family beside the bare status word: {:?}",
            records[0].question
        );
    }

    #[test]
    fn a_refused_tier_step_derives_one_record_naming_the_refused_tier() {
        let record = refused(
            ContextTier::ModuleContext,
            &[
                ("function-inventory", Some("the listing never came back")),
                (
                    "decompilation",
                    Some("Zanthoxylum builds never produce a body"),
                ),
            ],
            1_700_000_000,
        );

        assert_eq!(record.kind, UnknownKind::TierRefused);
        assert_eq!(record.severity, UnknownSeverity::Blocking);
        assert_eq!(record.function.as_deref(), Some("DrawSprite"));
        assert_eq!(
            record.origin,
            UnknownOrigin::RetryDecision {
                decision: "module_context".to_string(),
            },
            "the refused step is the origin, naming the tier the ladder refused to step onto"
        );
        assert_eq!(
            record.id,
            "game_logic.dll/DrawSprite/tier_refused/module_context",
            "one refused step is one question, whoever many families held it"
        );
        assert_eq!(
            record.question,
            "What is `DrawSprite` really doing — the ladder refused its context-tier step to \
             `module_context`: analysis engine admitted `function-inventory — unavailable — \
             the listing never came back; decompilation — unavailable — Zanthoxylum builds \
             never produce a body`?",
            "the question carries every blocked family's admission, joined exactly as the \
             ladder's tier-hold hint spells them"
        );
        assert_eq!(
            record.required_evidence,
            "Full `function-inventory`, `decompilation` answers the refused `module_context` \
             tier step would have re-asked",
            "the required evidence names the families whose answers the refused step needed"
        );
    }

    #[test]
    fn re_deriving_a_pruned_decision_lands_the_same_id() {
        // The same decision admitted twice — the next escalate rung pruned
        // on the same family, the same tier refused after another failed
        // attempt — is the same standing question, so a re-run never
        // duplicates a question a reviewer may already have answered.
        let first = residue(&[("decompilation", Some("no body"))], 1_700_000_000);
        let second = residue(&[("decompilation", Some("no body"))], 1_700_000_500);
        assert_eq!(
            first[0].id, second[0].id,
            "the id is the shared derivation, never the prune event"
        );
        let refused_first =
            refused(ContextTier::ModuleContext, &[("decompilation", None)], 1_700_000_000);
        let refused_second =
            refused(ContextTier::ModuleContext, &[("decompilation", None)], 1_700_000_500);
        assert_eq!(refused_first.id, refused_second.id);
        assert!(
            refused_first.content_matches(&refused_second),
            "only the stamp moves — the filing merge keeps the landed revision and first-seen"
        );
    }

    #[test]
    fn the_filing_fold_keeps_one_standing_question_per_decision() {
        let mut residue = Vec::new();
        let first = blocked(&[("decompilation", Some("no body"))]);
        let first: Vec<&FamilyCapability> = first.iter().collect();
        file_escalate_prune(&mut residue, "game_logic.dll", "DrawSprite", &first);
        // the same family prunes a later escalate rung — the same standing
        // question re-derived, not a second opinion filed
        file_escalate_prune(&mut residue, "game_logic.dll", "DrawSprite", &first);
        let later = blocked(&[("decompilation", None), ("function-inventory", None)]);
        let later: Vec<&FamilyCapability> = later.iter().collect();
        // a genuinely new family widens the set; the held family does not
        file_escalate_prune(&mut residue, "game_logic.dll", "DrawSprite", &later);
        assert_eq!(
            residue.iter().map(|r| r.source_slot()).collect::<Vec<String>>(),
            vec!["decompilation".to_string(), "function-inventory".to_string()],
            "folded by derived id, in first-filing order"
        );
        file_tier_refusal(
            &mut residue,
            "game_logic.dll",
            "DrawSprite",
            ContextTier::ModuleContext,
            &first,
        );
        file_tier_refusal(
            &mut residue,
            "game_logic.dll",
            "DrawSprite",
            ContextTier::ModuleContext,
            &later,
        );
        assert_eq!(residue.len(), 3, "the same refused step is one question");
        assert_eq!(
            residue[2].source_slot(),
            "module_context",
            "the refused step folds onto its own id, whoever many families held it"
        );
    }

    #[test]
    fn the_shared_checker_recognizes_this_kinds_write_site() {
        // The full pairing against every producer is the roster-sweep ticket
        // (#375); what is pinned here is that records derived at these two
        // write sites pair with the declared roster: the checker's verdict
        // has no fault naming `retry_pruned` or `tier_refused` — not "no
        // producer", not an undeclared kind, not a slot produced twice.
        let entries = blocked(&[
            (
                "decompilation",
                Some("Zanthoxylum builds never produce a body"),
            ),
            ("function-inventory", None),
        ]);
        let blocked: Vec<&FamilyCapability> = entries.iter().collect();
        let mut records =
            escalate_prune_residue("game_logic.dll", "DrawSprite", &blocked, 1_700_000_000);
        records.push(tier_refusal_residue(
            "game_logic.dll",
            "DrawSprite",
            ContextTier::ModuleContext,
            &blocked,
            1_700_000_000,
        ));
        let produced: Vec<(String, String)> = records
            .iter()
            .map(|r| (r.kind.to_string(), r.source_slot()))
            .collect();
        let produced: Vec<(&str, &str)> = produced
            .iter()
            .map(|(kind, slot)| (kind.as_str(), slot.as_str()))
            .collect();
        let faults = unknown_roster_faults(DECLARED_UNKNOWN_KINDS, &produced);
        assert!(
            faults
                .iter()
                .all(|fault| !fault.contains("retry_pruned") && !fault.contains("tier_refused")),
            "the ladder-residue write sites pair with the roster: {faults:?}"
        );
    }
}
