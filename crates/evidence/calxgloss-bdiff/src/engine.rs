//! The pairing pass: pure text and structure over two in-memory scan
//! snapshots — documents in, one pairing document out.
//!
//! [`pair_versions`] is the crate's whole engine: it adds no `ScanSource`
//! methods (ADR-0026 untouched), reads no engine, writes nothing back
//! to any program (ADR-0020), and runs no LLM — a version diff costs
//! milliseconds, not dollars. The pass opens the match ladder with its
//! first family, name identity: an exported name or a demangled name
//! present in both versions pairs the old function to the new at
//! [`crate::types::NAME_IDENTITY_CONFIDENCE`]. A lone signal claims
//! nothing (ADR-0038): address equality pairs nothing on its own, and
//! neither does a matching address-derived `FUN_…` spelling — that
//! spelling *is* an address, so pairing on it would smuggle the
//! relocation signal the rail exists to refuse.
//!
//! Pairings resolve one-to-one: each function pairs at most once per
//! side, the best score wins (ADR-0022's strongest-claim-wins rule),
//! and a tie keeps the first-seen pairing in scan order (ADR-0028's
//! positional precedent), so two documents of one version pair diff
//! cleanly and a candidate's second-best pairing is dropped.

use std::collections::{HashMap, HashSet};

use crate::error::{BdiffError, Result};
use crate::types::{
    FunctionEntry, MatchFamily, NAME_IDENTITY_CONFIDENCE, PairingDocument, PairingRecord,
    ScanSnapshot,
};

/// Pair the old scan snapshot against the new one of one binary
/// identity and emit the pairing document.
///
/// The two snapshots must name the same [`calxgloss_types::BinaryIdentity`]
/// — the pass pairs *versions of one binary*, and mixing identities is a
/// caller error it refuses rather than a pairing it guesses at. The
/// emitted document names both snapshots' byte hashes and both full
/// function listings; its pairings stand in old scan order.
///
/// # Errors
///
/// Returns [`BdiffError::IdentityMismatch`] when the snapshots name
/// different binary identities.
pub fn pair_versions(old: &ScanSnapshot, new: &ScanSnapshot) -> Result<PairingDocument> {
    if old.binary != new.binary {
        return Err(BdiffError::IdentityMismatch {
            old: old.binary.as_str().to_string(),
            new: new.binary.as_str().to_string(),
        });
    }

    tracing::debug!(
        binary = %old.binary,
        old_hash = %old.bytes_sha256,
        new_hash = %new.bytes_sha256,
        old_functions = old.functions.len(),
        new_functions = new.functions.len(),
        "Pairing binary versions"
    );

    let candidates = name_identity_candidates(old, new);
    let pairings = resolve_one_to_one(candidates, &old.functions, &new.functions);
    Ok(PairingDocument {
        binary: old.binary.as_str().to_string(),
        old_bytes_sha256: old.bytes_sha256.clone(),
        new_bytes_sha256: new.bytes_sha256.clone(),
        old_functions: old.function_names(),
        new_functions: new.function_names(),
        pairings,
    })
}

/// A proposed pairing before one-to-one resolution: indices into the
/// snapshots' function listings (scan order is what ties resolve on),
/// beside the score and evidence the winning family would carry.
struct Candidate {
    old: usize,
    new: usize,
    confidence: u8,
    family: MatchFamily,
    evidence: Vec<String>,
}

/// Collect every name-identity candidate pair, in scan order.
///
/// A pair is a candidate when the two listings spell one function the
/// same name *and* that spelling is the binary's own — an export-table
/// name present in both versions, or a name carrying the demangler's
/// spelling. Address-derived `FUN_…` matches and plain internal symbol
/// matches stay out of the family: on this ladder they are lone
/// signals, and a lone signal claims nothing (ADR-0038).
fn name_identity_candidates(old: &ScanSnapshot, new: &ScanSnapshot) -> Vec<Candidate> {
    let shared_exports: HashSet<&str> = old
        .exports
        .iter()
        .map(String::as_str)
        .filter(|name| new.exports.iter().any(|export| export == *name))
        .collect();

    let mut new_by_name: HashMap<&str, Vec<usize>> = HashMap::new();
    for (index, entry) in new.functions.iter().enumerate() {
        new_by_name
            .entry(entry.name.as_str())
            .or_default()
            .push(index);
    }

    let mut candidates = Vec::new();
    for (old_index, entry) in old.functions.iter().enumerate() {
        let name = entry.name.as_str();
        let Some(new_indexes) = new_by_name.get(name) else {
            continue;
        };
        // The exported family claims first, so an exported name that
        // also reads as demangled keeps the export's evidence — the
        // same pair claimed twice still resolves to one record, the
        // stronger reading standing.
        if shared_exports.contains(name) {
            for &new_index in new_indexes {
                candidates.push(Candidate {
                    old: old_index,
                    new: new_index,
                    confidence: NAME_IDENTITY_CONFIDENCE,
                    family: MatchFamily::NameIdentity,
                    evidence: vec![format!("exported name {name}")],
                });
            }
        }
        if carries_demangled_spelling(name) {
            for &new_index in new_indexes {
                candidates.push(Candidate {
                    old: old_index,
                    new: new_index,
                    confidence: NAME_IDENTITY_CONFIDENCE,
                    family: MatchFamily::NameIdentity,
                    evidence: vec![format!("demangled name {name}")],
                });
            }
        }
    }
    candidates
}

/// Whether a listing name carries the demangler's spelling — the
/// `::`-qualified chains and spelled parameter lists the decompiler
/// writes for C++ and Rust symbols, the demangled `operator.` dot form,
/// and `~`-prefixed destructors. Name-shape reading rides the same
/// precedent as ADR-0012's flagging-by-name-shape pass.
///
/// An address-derived `FUN_…` spelling is refused outright: it is an
/// address in name clothing, and pairing on it would claim from the
/// lone relocation signal the rail refuses (ADR-0038).
fn carries_demangled_spelling(name: &str) -> bool {
    if name.starts_with("FUN_") {
        return false;
    }
    name.contains("::")
        || name.starts_with("operator")
        || name.starts_with('~')
        || (name.ends_with(')') && name.contains('('))
}

/// Resolve candidate pairs down to one pairing per function per side.
///
/// Highest score wins, and a tie keeps the first-seen pairing in scan
/// order — candidate generation stands in old-then-new scan order, and
/// the sort is stable, so a candidate earlier in the scan beats a later
/// one at the same score, and a candidate's second-best pairing is
/// dropped once its side is taken (ADR-0022's strongest-claim-wins,
/// ADR-0028's positional tie rule). Surviving records come back in old
/// scan order so two documents of one version pair diff cleanly.
fn resolve_one_to_one(
    candidates: Vec<Candidate>,
    old_entries: &[FunctionEntry],
    new_entries: &[FunctionEntry],
) -> Vec<PairingRecord> {
    let mut ordered = candidates;
    ordered.sort_by_key(|candidate| std::cmp::Reverse(candidate.confidence));

    let mut old_taken: HashSet<usize> = HashSet::new();
    let mut new_taken: HashSet<usize> = HashSet::new();
    let mut winners: Vec<(usize, usize, PairingRecord)> = Vec::new();
    for candidate in ordered {
        if old_taken.contains(&candidate.old) || new_taken.contains(&candidate.new) {
            continue;
        }
        old_taken.insert(candidate.old);
        new_taken.insert(candidate.new);
        winners.push((
            candidate.old,
            candidate.new,
            PairingRecord {
                old_function: old_entries[candidate.old].name.clone(),
                new_function: new_entries[candidate.new].name.clone(),
                family: candidate.family,
                confidence: candidate.confidence.into(),
                evidence: candidate.evidence,
            },
        ));
    }
    winners.sort_by_key(|(old, new, _)| (*old, *new));
    winners.into_iter().map(|(_, _, record)| record).collect()
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use calxgloss_types::BinaryIdentity;

    /// One listed function with a body that names itself, so body-
    /// related tests can spell "unrelated bodies" honestly.
    fn function(name: &str, address: u64) -> FunctionEntry {
        FunctionEntry {
            name: name.into(),
            address,
            body: format!("// body of {name}"),
        }
    }

    /// One version's snapshot with a stable stand-in hash.
    fn snapshot(
        binary: &str,
        hash: &str,
        functions: Vec<FunctionEntry>,
        exports: &[&str],
    ) -> ScanSnapshot {
        ScanSnapshot {
            binary: BinaryIdentity::new(binary),
            bytes_sha256: hash.into(),
            functions,
            exports: exports.iter().map(|name| (*name).to_string()).collect(),
        }
    }

    #[test]
    fn an_exported_name_present_in_both_versions_pairs_at_95() {
        // The exported name is the program's own spelling; its address
        // shifting between versions changes nothing.
        let old = snapshot(
            "game.dll",
            "old-hash",
            vec![
                function("fixture_init", 0x1000),
                function("FUN_10001200", 0x1200),
            ],
            &["fixture_init"],
        );
        let new = snapshot(
            "game.dll",
            "new-hash",
            vec![function("fixture_init", 0x4000)],
            &["fixture_init"],
        );

        let document = pair_versions(&old, &new).expect("one identity");
        assert_eq!(document.pairings.len(), 1, "the export pairs once");
        let record = &document.pairings[0];
        assert_eq!(record.old_function, "fixture_init");
        assert_eq!(record.new_function, "fixture_init");
        assert_eq!(record.confidence.value(), NAME_IDENTITY_CONFIDENCE);
        assert_eq!(record.confidence.value(), 95);
        assert_eq!(record.family, MatchFamily::NameIdentity);
        assert_eq!(record.evidence, ["exported name fixture_init"]);
    }

    #[test]
    fn a_demangled_name_present_in_both_versions_pairs_at_95() {
        // A `::`-qualified demangled name pairs even with no export
        // table entry behind it — the demangler's spelling is the
        // binary's own name for the function.
        let old = snapshot(
            "game.dll",
            "old-hash",
            vec![function("Widget::render(void)", 0x1000)],
            &[],
        );
        let new = snapshot(
            "game.dll",
            "new-hash",
            vec![function("Widget::render(void)", 0x9000)],
            &[],
        );

        let document = pair_versions(&old, &new).expect("one identity");
        assert_eq!(document.pairings.len(), 1);
        assert_eq!(
            document.pairings[0].evidence,
            ["demangled name Widget::render(void)"]
        );
    }

    #[test]
    fn a_demangled_operator_spelling_pairs() {
        // The demangled `operator.` dot form the decompiler writes for
        // C++ operators keeps its dot and brackets in the listing.
        let old = snapshot(
            "game.dll",
            "old-hash",
            vec![function("operator.new(unsigned long long)", 0x1000)],
            &[],
        );
        let new = snapshot(
            "game.dll",
            "new-hash",
            vec![function("operator.new(unsigned long long)", 0x2000)],
            &[],
        );
        assert_eq!(
            pair_versions(&old, &new)
                .expect("one identity")
                .pairings
                .len(),
            1
        );
    }

    #[test]
    fn an_equal_address_derived_spelling_claims_nothing() {
        // A `FUN_…` name match means the address held — the address-
        // derived spelling is the relocation signal itself, and a lone
        // signal claims nothing (ADR-0038).
        let old = snapshot(
            "game.dll",
            "old-hash",
            vec![function("FUN_140001000", 0x140001000)],
            &[],
        );
        let new = snapshot(
            "game.dll",
            "new-hash",
            vec![function("FUN_140001000", 0x140001000)],
            &[],
        );

        let document = pair_versions(&old, &new).expect("one identity");
        assert!(
            document.pairings.is_empty(),
            "a FUN_ spelling pairing is a lone address claim"
        );
    }

    #[test]
    fn equal_address_with_unrelated_bodies_pairs_nothing() {
        // The lone-signal gate, spelled out: two functions sit at the
        // same address with different names and unrelated bodies — and
        // both are even exported, under different names. Nothing pairs:
        // relocations lie, and equal addresses claim nothing alone.
        let old = snapshot(
            "game.dll",
            "old-hash",
            vec![function("old_entry", 0x140001100)],
            &["old_entry"],
        );
        let new = snapshot(
            "game.dll",
            "new-hash",
            vec![function("new_entry", 0x140001100)],
            &["new_entry"],
        );

        let document = pair_versions(&old, &new).expect("one identity");
        assert!(
            document.pairings.is_empty(),
            "a lone address equality claims nothing"
        );
    }

    #[test]
    fn a_plain_internal_name_match_claims_nothing_yet() {
        // A stripped private symbol that kept its name across versions
        // is not an export and not demangled: the ladder's first family
        // is exported-or-demangled, and this ticket claims no wider.
        let old = snapshot(
            "game.dll",
            "old-hash",
            vec![function("helper_parse", 0x1000)],
            &[],
        );
        let new = snapshot(
            "game.dll",
            "new-hash",
            vec![function("helper_parse", 0x3000)],
            &[],
        );

        let document = pair_versions(&old, &new).expect("one identity");
        assert!(document.pairings.is_empty());
    }

    #[test]
    fn a_second_best_pairing_is_dropped() {
        // One-to-one resolution over a mixed-strength candidate set —
        // the shape the whole ladder will hand resolution once #296 and
        // #297 land their families (scores here are synthetic stand-ins
        // for the body and topology families, the resolution rule is
        // the shipped one): A's best claim is X at 95, so A's 90 claim
        // on Y drops, and Y then pairs with B.
        let old = snapshot(
            "game.dll",
            "old-hash",
            vec![function("a", 1), function("b", 2)],
            &[],
        );
        let new = snapshot(
            "game.dll",
            "new-hash",
            vec![function("x", 3), function("y", 4)],
            &[],
        );
        let candidates = vec![
            Candidate {
                old: 0,
                new: 0,
                confidence: 95,
                family: MatchFamily::NameIdentity,
                evidence: vec!["best".into()],
            },
            Candidate {
                old: 0,
                new: 1,
                confidence: 90,
                family: MatchFamily::NameIdentity,
                evidence: vec!["second best".into()],
            },
            Candidate {
                old: 1,
                new: 1,
                confidence: 85,
                family: MatchFamily::NameIdentity,
                evidence: vec!["next".into()],
            },
        ];

        let records = resolve_one_to_one(candidates, &old.functions, &new.functions);
        assert_eq!(records.len(), 2);
        assert_eq!(
            (
                records[0].old_function.as_str(),
                records[0].new_function.as_str()
            ),
            ("a", "x")
        );
        assert_eq!(
            (
                records[1].old_function.as_str(),
                records[1].new_function.as_str()
            ),
            ("b", "y")
        );
        assert!(
            !records
                .iter()
                .any(|r| r.old_function == "a" && r.new_function == "y"),
            "a candidate's second-best pairing is dropped"
        );
    }

    #[test]
    fn a_tie_keeps_the_first_seen_pairing_in_scan_order() {
        // Two old functions compete for one new function at equal
        // strength: the one first seen in the old scan's listing wins,
        // the other stays unpaired (ADR-0028's positional precedent).
        let old = snapshot(
            "game.dll",
            "old-hash",
            vec![function("a", 1), function("b", 2)],
            &[],
        );
        let new = snapshot("game.dll", "new-hash", vec![function("x", 3)], &[]);
        let candidates = vec![
            Candidate {
                old: 0,
                new: 0,
                confidence: 95,
                family: MatchFamily::NameIdentity,
                evidence: vec!["first".into()],
            },
            Candidate {
                old: 1,
                new: 0,
                confidence: 95,
                family: MatchFamily::NameIdentity,
                evidence: vec!["later".into()],
            },
        ];

        let records = resolve_one_to_one(candidates, &old.functions, &new.functions);
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].old_function, "a",
            "the first seen in scan order keeps the pair"
        );
    }

    #[test]
    fn an_exported_demangled_name_keeps_the_export_evidence() {
        // A C++ export reads as both families at once; generation puts
        // the exported claim first and resolution drops the candidate's
        // second claim on the very same pair.
        let name = "ns::widget_draw(void)";
        let old = snapshot(
            "game.dll",
            "old-hash",
            vec![function(name, 0x1000)],
            &[name],
        );
        let new = snapshot(
            "game.dll",
            "new-hash",
            vec![function(name, 0x8000)],
            &[name],
        );

        let document = pair_versions(&old, &new).expect("one identity");
        assert_eq!(document.pairings.len(), 1, "one pair, one record");
        assert_eq!(
            document.pairings[0].evidence,
            [format!("exported name {name}")]
        );
    }

    #[test]
    fn pairings_stand_in_old_scan_order() {
        // Two scans of one version pair diff cleanly: records come back
        // in the old listing's order, not the order they were resolved.
        let old = snapshot(
            "game.dll",
            "old-hash",
            vec![function("zeta", 1), function("alpha", 2)],
            &["zeta", "alpha"],
        );
        let new = snapshot(
            "game.dll",
            "new-hash",
            vec![function("alpha", 3), function("zeta", 4)],
            &["alpha", "zeta"],
        );

        let document = pair_versions(&old, &new).expect("one identity");
        let old_side: Vec<&str> = document
            .pairings
            .iter()
            .map(|r| r.old_function.as_str())
            .collect();
        assert_eq!(old_side, ["zeta", "alpha"]);
    }

    #[test]
    fn the_document_names_both_hashes_and_both_full_listings() {
        // A stale document must be detectable — it names the exact byte
        // pair it was computed for — and the review side (the CLI
        // breakdown, #300) derives old-only and new-only from the two
        // complete listings.
        let old = snapshot(
            "game.dll",
            "aaa",
            vec![
                function("fixture_init", 0x1000),
                function("FUN_10001200", 0x1200),
            ],
            &["fixture_init"],
        );
        let new = snapshot(
            "game.dll",
            "bbb",
            vec![
                function("fixture_init", 0x4000),
                function("brand_new", 0x5000),
            ],
            &["fixture_init", "brand_new"],
        );

        let document = pair_versions(&old, &new).expect("one identity");
        assert_eq!(document.binary, "game.dll");
        assert_eq!(document.old_bytes_sha256, "aaa");
        assert_eq!(document.new_bytes_sha256, "bbb");
        assert_eq!(document.old_functions, ["fixture_init", "FUN_10001200"]);
        assert_eq!(document.new_functions, ["fixture_init", "brand_new"]);
        assert_eq!(document.pairings.len(), 1);
    }

    #[test]
    fn two_different_binary_identities_are_refused() {
        // The pass pairs versions of one binary; mixing identities is a
        // caller error it names, not a pairing it guesses at.
        let old = snapshot("a.dll", "aaa", Vec::new(), &[]);
        let new = snapshot("b.dll", "bbb", Vec::new(), &[]);
        match pair_versions(&old, &new) {
            Err(BdiffError::IdentityMismatch { old, new }) => {
                assert_eq!(old, "a.dll");
                assert_eq!(new, "b.dll");
            }
            other => panic!("expected the identity refusal, got {other:?}"),
        }
    }
}
