//! The cross-function rollup: the shared-globals index.
//!
//! The per-function walk says what one body touches; the rollup says
//! who shares what. It runs after that walk, over the same kept
//! bodies — the ADR-0027 precedent, so it adds no new reads from the
//! analysis engine. It groups the access records the scan already made
//! into one entry per global, naming the functions that read it and
//! the functions that write it. The entry is derived, not sighted: it
//! adds no reading of its own, so its confidence is the best band
//! among the accesses behind it and never rises above them.
//!
//! [`shared_globals`] answers in first-sighting order: the order in
//! which a global first appears among the per-function records, which
//! is listing order and then body order. Readers and writers come in
//! that same order, and each function is named once. So two scans of
//! one program produce the same index and diff cleanly.
//!
//! [`state_sharing_pairs`] reads that index back for the translation
//! orderer. In each entry, the first writer defines the global's
//! representation, and every other function the entry names reuses it.

use std::collections::HashMap;

use crate::types::{GlobalStateFinding, SharedGlobalRecord};

/// The shared-globals index for one scan's findings.
///
/// One entry per global the scan saw, in first-sighting order. A
/// function that reads and writes one global appears in both lists; a
/// function that touches it repeatedly appears in its list once. A
/// global only one function touches still gets an entry — the index is
/// the per-global picture of the binary's shared state, and consumers
/// that pair functions (the sync gate, the DAG orderer) skip the
/// degenerate entries themselves.
///
/// The input is the per-function records; index records already in
/// the list are skipped, so rolling up an already-rolled list changes
/// nothing.
pub fn shared_globals(findings: &[GlobalStateFinding]) -> Vec<SharedGlobalRecord> {
    let mut index: Vec<SharedGlobalRecord> = Vec::new();
    // Records which entry belongs to which global, so the grouping
    // stays one linear pass. First-sighting order is the order the
    // entries were pushed.
    let mut positions: HashMap<&str, usize> = HashMap::new();
    for finding in findings {
        let (record, is_write) = match finding {
            GlobalStateFinding::GlobalRead(record) => (record, false),
            GlobalStateFinding::GlobalWrite(record) => (record, true),
            GlobalStateFinding::SharedGlobal(_) => continue,
        };
        let position = *positions.entry(record.global.as_str()).or_insert_with(|| {
            index.push(SharedGlobalRecord {
                global: record.global.clone(),
                readers: Vec::new(),
                writers: Vec::new(),
                confidence: record.confidence,
            });
            index.len() - 1
        });
        let entry = &mut index[position];
        // The entry is no more confident than the best access behind
        // it — a shape-only global stays shape-only, and an exact
        // store raises its entry to the exact band.
        if record.confidence > entry.confidence {
            entry.confidence = record.confidence;
        }
        let functions = if is_write {
            &mut entry.writers
        } else {
            &mut entry.readers
        };
        if !functions.contains(&record.function) {
            functions.push(record.function.clone());
        }
    }
    index
}

/// The state-sharing pairs the index names for the translation orderer
/// (issue #256, part of #225).
///
/// For each entry with writers, the first writer in listing order defines
/// the global's representation and every other function the entry names —
/// writer or reader — reuses it, so each pair runs definer → reuser and
/// the orderer can queue the definer first. An entry no function writes
/// establishes no representation and contributes no pairs, and a definer
/// that also reads its own global is not its own reuser.
///
/// The pairs follow the index's own order: first-sighting order over
/// entries, and within one entry the writers in listing order first,
/// then the readers in listing order — so two scans of one program feed
/// the orderer the same pairs.
pub fn state_sharing_pairs(
    index: impl IntoIterator<Item = impl std::borrow::Borrow<SharedGlobalRecord>>,
) -> Vec<(String, String)> {
    let mut pairs: Vec<(String, String)> = Vec::new();
    for entry in index {
        let record = entry.borrow();
        // The definer is the first writer in listing order. A global
        // only ever read has no unit that establishes its
        // representation, so it shares no pairs.
        let Some((definer, other_writers)) = record.writers.split_first() else {
            continue;
        };
        for reuser in other_writers.iter().chain(record.readers.iter()) {
            if reuser != definer {
                pairs.push((definer.clone(), reuser.clone()));
            }
        }
    }
    pairs
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::GlobalAccess;

    fn access(function: &str, global: &str, write: bool, confidence: u8) -> GlobalStateFinding {
        let record = GlobalAccess {
            function: function.to_string(),
            global: global.to_string(),
            evidence: format!("{global} = param_1"),
            confidence: confidence.into(),
            suggestion: "model the program global as shared struct state".to_string(),
        };
        if write {
            GlobalStateFinding::GlobalWrite(record)
        } else {
            GlobalStateFinding::GlobalRead(record)
        }
    }

    fn entry<'a>(index: &'a [SharedGlobalRecord], global: &str) -> &'a SharedGlobalRecord {
        index
            .iter()
            .find(|entry| entry.global == global)
            .unwrap_or_else(|| panic!("the index names {global}: {index:?}"))
    }

    #[test]
    fn the_index_names_every_global_the_function_set_touches() {
        // The rollup contract: which globals the index names for a
        // given function set, readers and writers separated by kind.
        let findings = vec![
            access("FUN_18003ab00", "DAT_180064e80", true, 85),
            access("FUN_18003ab00", "g_counter", false, 60),
            access("FUN_18003e750", "g_counter", true, 85),
        ];
        let index = shared_globals(&findings);
        assert_eq!(
            index.iter().map(|e| e.global.as_str()).collect::<Vec<_>>(),
            vec!["DAT_180064e80", "g_counter"],
            "globals arrive in first-sighting order"
        );
        assert_eq!(
            entry(&index, "DAT_180064e80").writers,
            vec!["FUN_18003ab00"]
        );
        assert!(entry(&index, "DAT_180064e80").readers.is_empty());
        assert_eq!(entry(&index, "g_counter").readers, vec!["FUN_18003ab00"]);
        assert_eq!(entry(&index, "g_counter").writers, vec!["FUN_18003e750"]);
    }

    #[test]
    fn a_function_that_reads_and_writes_one_global_lands_both_lists() {
        let findings = vec![
            access("FUN_18003ab00", "DAT_flag", true, 85),
            access("FUN_18003ab00", "DAT_flag", false, 85),
        ];
        let index = shared_globals(&findings);
        assert_eq!(index.len(), 1, "one global, one entry");
        assert_eq!(index[0].readers, vec!["FUN_18003ab00"]);
        assert_eq!(index[0].writers, vec!["FUN_18003ab00"]);
    }

    #[test]
    fn repeated_accesses_name_a_function_once_in_its_list() {
        let findings = vec![
            access("FUN_18003ab00", "DAT_flag", false, 85),
            access("FUN_18003ab00", "DAT_flag", false, 85),
            access("FUN_18003e750", "DAT_flag", false, 85),
        ];
        let index = shared_globals(&findings);
        assert_eq!(
            index[0].readers,
            vec!["FUN_18003ab00", "FUN_18003e750"],
            "the reader list names each function once, in listing order"
        );
    }

    #[test]
    fn the_entry_scores_the_best_access_behind_it_and_never_upgrades() {
        // A global seen only shape-only stays at the shape band; one
        // with an exact store behind it scores at the exact band. The
        // rollup adds no reading, so it cannot score above the best
        // access it groups.
        let findings = vec![
            access("FUN_18003ab00", "g_shape", false, 60),
            access("FUN_18003e750", "g_exact", false, 60),
            access("FUN_18003e750", "g_exact", true, 85),
        ];
        let index = shared_globals(&findings);
        assert_eq!(entry(&index, "g_shape").confidence.value(), 60);
        assert_eq!(entry(&index, "g_exact").confidence.value(), 85);
    }

    #[test]
    fn a_global_one_function_touches_still_gets_an_entry() {
        // The index is the per-global picture of the binary's shared
        // state; pairing consumers skip the degenerate entries, the
        // index does not hide them.
        let findings = vec![access("FUN_18003ab00", "DAT_alone", true, 85)];
        let index = shared_globals(&findings);
        assert_eq!(index.len(), 1);
        assert_eq!(index[0].writers, vec!["FUN_18003ab00"]);
        assert!(index[0].readers.is_empty());
    }

    #[test]
    fn an_empty_finding_list_indexes_nothing() {
        assert!(shared_globals(&[]).is_empty());
    }

    #[test]
    fn index_records_are_not_rolled_up_again() {
        // Feeding an already-rolled list back in changes nothing: the
        // rollup reads accesses, not its own entries.
        let findings = vec![access("FUN_18003ab00", "DAT_flag", true, 85)];
        let mut rolled = findings.clone();
        rolled.extend(
            shared_globals(&findings)
                .into_iter()
                .map(GlobalStateFinding::SharedGlobal),
        );
        assert_eq!(shared_globals(&rolled), shared_globals(&findings));
    }

    #[test]
    fn the_state_sharing_pairs_run_from_the_first_writer_to_every_reuser() {
        // The DAG consumer's reading of the index (issue #256): the first
        // writer in listing order defines, and the other writers and the
        // readers reuse. A definer that also reads its own global is not
        // its own reuser. A global one function alone writes contributes
        // nothing.
        let findings = vec![
            access("FUN_writer_two", "DAT_flag", true, 85),
            access("FUN_writer_one", "DAT_flag", true, 85),
            access("FUN_reader", "DAT_flag", false, 85),
            access("FUN_writer_two", "DAT_flag", false, 85),
            access("FUN_writer_one", "DAT_alone", true, 85),
        ];
        let index = shared_globals(&findings);
        let pairs = state_sharing_pairs(&index);
        assert_eq!(
            pairs,
            vec![
                ("FUN_writer_two".to_string(), "FUN_writer_one".to_string()),
                ("FUN_writer_two".to_string(), "FUN_reader".to_string()),
            ],
            "DAT_flag pairs the first definer with each reuser; DAT_alone has none"
        );
    }

    #[test]
    fn a_readers_only_entry_shares_no_pairs() {
        // No writer means no unit establishes the representation — the
        // degenerate entry contributes no ordering constraint.
        let findings = vec![
            access("FUN_a", "DAT_readonly", false, 85),
            access("FUN_b", "DAT_readonly", false, 85),
        ];
        let index = shared_globals(&findings);
        assert!(state_sharing_pairs(&index).is_empty());
    }
}
