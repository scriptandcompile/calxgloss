//! Confidence scoring and conflict resolution.
//!
//! The confidence *score* itself is the shared [`calxgloss_types::Confidence`]
//! type (a 0–100 value) every engine rates evidence with; this module is
//! where the algorithm scan's scoring model lives.
//!
//! The standard scores — [`CFG_CONFIDENCE`], [`BODY_CONFIDENCE`],
//! [`LISTING_CONFIDENCE`], [`CALLBACK_CONFIDENCE`] — are the score
//! composition per detection method: each detector reads its standard
//! score from here, so tuning the model is a one-module change.
//!
//! [`resolve_conflicts`] is the cross-detector half of the model. Each
//! detector already reports one algorithm once per function, but the
//! detectors read a body independently, so a finished scan can still
//! carry several claims for one (function, algorithm) pair — the CRC
//! loop's own text and a program-wide listing marker both name `crc`.
//! Resolution collapses each pair to its single strongest claim: the
//! highest confidence wins, a tie keeps the claim the scan surfaced
//! first, and the survivor stands where that algorithm first appeared,
//! so the list keeps scan order and two scans of the same program diff
//! cleanly. Claims naming *different* algorithms for one function never
//! conflict — a function doing a hash lookup and a recursion reports
//! both.
//!
//! The engine's minimum-confidence floor
//! ([`with_min_confidence`](crate::engine::AlgorithmEngine::with_min_confidence))
//! applies to the resolved survivors, so a claim another detector
//! strengthened clears a threshold its first claim would have missed.
//!
//! [`calxgloss_types::Confidence`]: calxgloss_types::Confidence

use std::collections::HashMap;

use crate::types::AlgorithmHint;

// ============================================================
// Score composition per detection method
// ============================================================

/// Confidence of a control flow match: the body carries every shape the
/// signature requires and clears its line floor, which is real
/// evidence, but regexes over decompiled pseudo-C approximate the
/// algorithm rather than prove it — the hint stays a hypothesis for
/// the translation prompt, not a fact applied to the program.
pub const CFG_CONFIDENCE: u8 = 60;

/// Confidence of a string body match: the function's own decompiled
/// text carries the marker, so the algorithm's name sits right where
/// the function's behavior is spelled out — but a substring hit is
/// approximate, a `CRC` in a format string evidences use rather than
/// implementation, so the hint sits beside a control flow match as a
/// hypothesis for the translation prompt, not a fact applied to the
/// program.
pub const BODY_CONFIDENCE: u8 = 60;

/// Confidence of a string listing-only match: the marker appears
/// somewhere in the binary's string listing but not in this function's
/// body, so the evidence ties the program to the algorithm rather than
/// the function to its implementation — a weak lead worth carrying,
/// not one to weigh beside a body match or a control flow shape.
pub const LISTING_CONFIDENCE: u8 = 30;

/// Confidence of a callback detection: two independent signals agree —
/// the call graph shows one of the contract's hosts reaching the
/// function, and the function's own signature fits the contract's
/// arity and body shapes. A call-graph edge from a host like `qsort`
/// is close to proof that the function is the callback that host was
/// handed, but the reading still rests on regexes over decompiled
/// pseudo-C rather than a resolved indirect-call target, so it stands
/// above a lone control flow or string match and below a direct vtable
/// dispatch.
pub const CALLBACK_CONFIDENCE: u8 = 75;

// ============================================================
// Conflict resolution
// ============================================================

/// Resolve competing claims down to one per (function, algorithm) pair.
///
/// Where several detectors claim the same algorithm for one function,
/// the highest-confidence claim wins and the rest drop; a tie keeps
/// the claim the scan surfaced first. The survivor stands where that
/// algorithm first appeared in the list, so the resolved list keeps
/// scan order — function by function, algorithms in the order the scan
/// showed them — exactly as the raw scan did. Claims naming different
/// algorithms for one function, or the same algorithm in different
/// functions, never conflict: resolution drops duplicates of a claim,
/// never a distinct reading of the function.
pub fn resolve_conflicts(hints: Vec<AlgorithmHint>) -> Vec<AlgorithmHint> {
    let mut winners: Vec<AlgorithmHint> = Vec::new();
    let mut positions: HashMap<(String, String), usize> = HashMap::new();
    for hint in hints {
        let claim = (hint.function.clone(), hint.algorithm.clone());
        match positions.get(&claim) {
            Some(&position) if hint.confidence > winners[position].confidence => {
                winners[position] = hint;
            }
            Some(_) => {}
            None => {
                positions.insert(claim, winners.len());
                winners.push(hint);
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
    use crate::types::{AlgorithmCategory, Confidence, DetectionMethod};

    fn claim(
        function: &str,
        algorithm: &str,
        method: DetectionMethod,
        confidence: u8,
    ) -> AlgorithmHint {
        AlgorithmHint {
            function: function.into(),
            algorithm: algorithm.into(),
            category: AlgorithmCategory::Checksum,
            method,
            confidence: Confidence::new(confidence),
            evidence: format!("{method} evidence for {algorithm}"),
        }
    }

    #[test]
    fn the_stronger_claim_wins_and_the_weaker_drops() {
        let winners = resolve_conflicts(vec![
            claim("FUN_18003e750", "crc", DetectionMethod::StringHint, 30),
            claim("FUN_18003e750", "crc", DetectionMethod::CallbackPattern, 75),
        ]);
        assert_eq!(
            winners,
            vec![claim(
                "FUN_18003e750",
                "crc",
                DetectionMethod::CallbackPattern,
                75
            )]
        );
    }

    #[test]
    fn a_tie_keeps_the_claim_surfaced_first() {
        let winners = resolve_conflicts(vec![
            claim("FUN_18003e750", "crc", DetectionMethod::CfgPattern, 60),
            claim("FUN_18003e750", "crc", DetectionMethod::StringHint, 60),
        ]);
        assert_eq!(
            winners,
            vec![claim(
                "FUN_18003e750",
                "crc",
                DetectionMethod::CfgPattern,
                60
            )]
        );
    }

    #[test]
    fn a_winner_stands_where_the_algorithm_first_appeared() {
        // The stronger crc claim arrives after http's; the resolved
        // list keeps the order the scan showed the algorithms.
        let winners = resolve_conflicts(vec![
            claim("FUN_18003ab00", "crc", DetectionMethod::StringHint, 30),
            claim("FUN_18003ab00", "http", DetectionMethod::StringHint, 30),
            claim("FUN_18003ab00", "crc", DetectionMethod::CallbackPattern, 75),
        ]);
        assert_eq!(winners.len(), 2);
        assert_eq!(winners[0].algorithm, "crc");
        assert_eq!(winners[0].method, DetectionMethod::CallbackPattern);
        assert_eq!(winners[1].algorithm, "http");
    }

    #[test]
    fn different_algorithms_and_different_functions_never_conflict() {
        let winners = resolve_conflicts(vec![
            claim("FUN_18003ab00", "crc", DetectionMethod::StringHint, 30),
            claim("FUN_18003ab00", "http", DetectionMethod::StringHint, 30),
            claim("FUN_18003e750", "crc", DetectionMethod::StringHint, 60),
        ]);
        assert_eq!(winners.len(), 3);
    }

    #[test]
    fn a_conflict_free_scan_passes_through_unchanged() {
        let hints = vec![
            claim(
                "FUN_18003ab00",
                "comparison_sort",
                DetectionMethod::CfgPattern,
                60,
            ),
            claim("FUN_18003e750", "crc", DetectionMethod::StringHint, 60),
            claim(
                "FUN_1800412a0",
                "qsort_compare",
                DetectionMethod::CallbackPattern,
                75,
            ),
        ];
        assert_eq!(resolve_conflicts(hints.clone()), hints);
        assert!(resolve_conflicts(Vec::new()).is_empty());
    }
}
