//! Confidence scoring and competing-match resolution.
//!
//! The confidence *score* itself is the shared [`calxgloss_types::Confidence`]
//! type (a 0–100 value) every engine rates evidence with; this module is
//! where the libmatch scan's scoring model lives.
//!
//! [`BODY_MATCH_CONFIDENCE`] is the standard score for a body-signature
//! match: the normalized body carried every line shape the signature
//! requires, which is real evidence, but a regex bundle over decompiled
//! pseudo-C approximates the routine rather than proves it — the finding
//! stays a hypothesis, flag-only, never written back to the program
//! (ADR-0020). A signature may override the standard score per entry.
//!
//! [`resolve_matches`] is the resolution half of the model, per
//! ADR-0022's strongest-evidence precedent. Two signatures can fit one
//! body — the `memcpy` loop and a broader copy-loop shape both claim a
//! byte-copy function — and one function is one function: resolution
//! collapses its claims to the single strongest. The highest confidence
//! wins, a tie keeps the claim the scan surfaced first, and the survivor
//! stands where the function first appeared, so the list keeps scan
//! order and two scans of the same program diff cleanly. Claims for
//! *different* functions never conflict.

use crate::types::LibmatchFinding;

/// Confidence of a body-signature match: the normalized body carries
/// every line shape the signature requires and clears its line floor,
/// which is real evidence, but a regex bundle over decompiled pseudo-C
/// approximates the routine rather than proves it — the finding stays a
/// hypothesis for review, not a fact applied to the program.
pub const BODY_MATCH_CONFIDENCE: u8 = 60;

/// The confidence a tail-call thunk pays to inherit its callee's match:
/// the thunk's whole body is one call line, which proves the wrapper
/// relationship but only relays the callee's identified shape, so the
/// claim sits a rung below the matched body's own score. The penalty
/// is paid once per chain, not per hop: a chain of thunks all stands
/// at one score, so the whole chain collapses into the same downstream
/// decision.
pub const TAIL_CALL_CONFIDENCE_PENALTY: u8 = 10;

/// Resolve competing claims down to one per function.
///
/// Where several signatures claim one function, the highest-confidence
/// claim wins and the rest drop; a tie keeps the claim the scan
/// surfaced first. The survivor stands where the function first
/// appeared in the list, so the resolved list keeps scan order exactly
/// as the raw scan did. Claims for different functions never conflict:
/// resolution drops duplicates of a claim, never a distinct function.
pub fn resolve_matches(findings: Vec<LibmatchFinding>) -> Vec<LibmatchFinding> {
    let mut winners: Vec<LibmatchFinding> = Vec::new();
    let mut positions = std::collections::HashMap::<String, usize>::new();
    for finding in findings {
        let function = finding.function().to_string();
        match positions.get(&function) {
            Some(&position) if finding.confidence() > winners[position].confidence() => {
                winners[position] = finding;
            }
            Some(_) => {}
            None => {
                positions.insert(function, winners.len());
                winners.push(finding);
            }
        }
    }
    winners
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Confidence, LibmatchMatch, LibraryFamily};

    fn claim(function: &str, symbol: &str, confidence: u8) -> LibmatchFinding {
        LibmatchFinding::BodySignature(LibmatchMatch {
            function: function.into(),
            symbol: symbol.into(),
            family: LibraryFamily::Crt,
            suggestion: "slice copy".into(),
            confidence: Confidence::new(confidence),
            evidence: format!("{symbol} evidence"),
            admission: None,
        })
    }

    #[test]
    fn the_stronger_claim_wins_and_the_weaker_drops() {
        let winners = resolve_matches(vec![
            claim("FUN_18003e750", "memcpy", 60),
            claim("FUN_18003e750", "wmemcpy", 70),
        ]);
        assert_eq!(winners.len(), 1);
        assert_eq!(winners[0].target(), "wmemcpy");
        assert_eq!(winners[0].confidence(), Confidence::new(70));
    }

    #[test]
    fn a_tie_keeps_the_claim_surfaced_first() {
        let winners = resolve_matches(vec![
            claim("FUN_18003e750", "memcpy", 60),
            claim("FUN_18003e750", "wmemcpy", 60),
        ]);
        assert_eq!(winners.len(), 1);
        assert_eq!(winners[0].target(), "memcpy");
    }

    #[test]
    fn a_winner_stands_where_the_function_first_appeared() {
        // The stronger claim for the second function arrives after the
        // first function's; the resolved list keeps listing order.
        let winners = resolve_matches(vec![
            claim("FUN_18003ab00", "memcpy", 60),
            claim("FUN_18003e750", "memcpy", 60),
            claim("FUN_18003e750", "wmemcpy", 70),
        ]);
        assert_eq!(winners.len(), 2);
        assert_eq!(winners[0].function(), "FUN_18003ab00");
        assert_eq!(winners[1].function(), "FUN_18003e750");
        assert_eq!(winners[1].target(), "wmemcpy");
    }

    #[test]
    fn different_functions_never_conflict_and_a_conflict_free_scan_passes_through() {
        let findings = vec![
            claim("FUN_18003ab00", "memcpy", 60),
            claim("FUN_18003e750", "strlen", 60),
        ];
        assert_eq!(resolve_matches(findings.clone()), findings);
        assert!(resolve_matches(Vec::new()).is_empty());
    }
}
