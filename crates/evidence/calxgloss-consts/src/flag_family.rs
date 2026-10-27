//! Program-level flag-family merging.
//!
//! [`merge_families`] is the scan's post-pass over the per-function
//! bitflag groups the scan just built. Groups that share at least one
//! bit — directly, or through a chain of shared bits — merge
//! transitively into one program-level [`FlagFamily`] record naming
//! the union of bits, the mask and width they span, and the
//! contributing functions. Families sharing no bits stay separate.
//! A group sharing no bit with any other forms no family of its own:
//! its per-function record already says everything that body shows.
//! The merge consumes the detector's final group contents: no bodies
//! are kept and no new reads are made.

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use crate::bitmask::flags_suggestion;
use crate::types::{BitflagGroup, Confidence, FlagFamily};

/// The fixed confidence of a merged family: above the per-function
/// group's 70. The same flag surface corroborated across several
/// functions is stronger evidence than one body's word alone.
const FAMILY_CONFIDENCE: u8 = 80;

/// The whole flag families among `groups`: every set of two or more
/// groups connected through shared bits, transitively, rendered as
/// one program-level record. Families come out sorted by mask, and
/// each record's bits and contributing functions are ascending, so
/// two scans of one program render identical families.
pub(crate) fn merge_families(groups: &[BitflagGroup]) -> Vec<FlagFamily> {
    // Union-find over the group indices: two groups sharing a bit are
    // connected, and the connections chain — a group sharing a bit
    // with either half of a pair joins the whole set.
    let mut parent: Vec<usize> = (0..groups.len()).collect();
    fn root(parent: &mut [usize], mut i: usize) -> usize {
        while parent[i] != i {
            parent[i] = parent[parent[i]];
            i = parent[i];
        }
        i
    }
    let mut bit_owner: BTreeMap<u32, usize> = BTreeMap::new();
    for (index, group) in groups.iter().enumerate() {
        for &bit in &group.bits {
            if let Some(other) = bit_owner.insert(bit, index) {
                let (a, b) = (root(&mut parent, index), root(&mut parent, other));
                parent[b] = a;
            }
        }
    }

    let mut clusters: BTreeMap<usize, Vec<&BitflagGroup>> = BTreeMap::new();
    for (index, group) in groups.iter().enumerate() {
        clusters
            .entry(root(&mut parent, index))
            .or_default()
            .push(group);
    }

    // A lone group is not a merge: what survives is what actually
    // merged — two or more groups connected through shared bits.
    let mut families: Vec<FlagFamily> = clusters
        .into_values()
        .filter(|members| members.len() > 1)
        .map(render_family)
        .collect();
    families.sort_by_key(|family| family.mask);
    families
}

/// Render one merged cluster of groups as the program-level record.
/// The record holds: the union of bits and mask, the width the
/// highest bit spans, the contributing functions ascending, and the
/// whole-family struct. Its evidence names each contributing group's
/// function and its own bits, so the merge can be checked against the
/// per-function records it consumed.
fn render_family(members: Vec<&BitflagGroup>) -> FlagFamily {
    let bits: Vec<u32> = members
        .iter()
        .flat_map(|group| group.bits.iter().copied())
        .collect::<BTreeSet<u32>>()
        .into_iter()
        .collect();
    let mask: u64 = bits.iter().fold(0u64, |acc, bit| acc | (1u64 << bit));
    let bit_width = bits[bits.len() - 1] + 1;
    let functions: Vec<String> = members
        .iter()
        .map(|group| group.function.clone())
        .collect::<BTreeSet<String>>()
        .into_iter()
        .collect();

    // Evidence follows the functions: ascending, each group naming
    // the bits it contributed.
    let mut members: Vec<&BitflagGroup> = members;
    members.sort_by(|a, b| a.function.cmp(&b.function));
    let evidence = members
        .iter()
        .map(|group| {
            let names: Vec<String> = group
                .bits
                .iter()
                .map(|bit| format!("{:#x}", 1u64 << bit))
                .collect();
            format!("{}: bits {}", group.function, names.join(", "))
        })
        .collect::<Vec<String>>()
        .join("; ");

    let suggestion = flags_suggestion(bit_width, &bits);
    FlagFamily {
        bits,
        mask,
        bit_width,
        functions,
        suggestion,
        confidence: Confidence::new(FAMILY_CONFIDENCE),
        evidence,
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// A hand-built per-function group over `bits`, exactly the shape
    /// the bitmask detector passes on to the scan.
    fn group(function: &str, bits: &[u32]) -> BitflagGroup {
        let mask: u64 = bits.iter().fold(0u64, |acc, bit| acc | (1u64 << bit));
        let bit_width = bits[bits.len() - 1] + 1;
        BitflagGroup {
            function: function.to_string(),
            bits: bits.to_vec(),
            mask,
            bit_width,
            suggestion: flags_suggestion(bit_width, bits),
            confidence: Confidence::new(70),
            evidence: String::new(),
        }
    }

    #[test]
    fn groups_sharing_a_bit_merge_into_one_family() {
        // FUN_a carries bits 8 and 10, FUN_b bits 10 and 11: the
        // shared bit 10 joins them into one family spanning bits
        // 8, 10, 11.
        let groups = [
            group("FUN_18003ab00", &[8, 10]),
            group("FUN_18003e750", &[10, 11]),
        ];
        let families = merge_families(&groups);

        assert_eq!(families.len(), 1, "the shared bit ties them into one");
        let family = &families[0];
        assert_eq!(family.bits, vec![8, 10, 11]);
        assert_eq!(family.mask, 0xd00);
        assert_eq!(family.bit_width, 12);
        assert_eq!(
            family.suggestion,
            "bitflags! struct Flags: u16 { /* bits: 0x100, 0x400, 0x800 */ }"
        );
        assert_eq!(family.confidence, Confidence::new(80));
    }

    #[test]
    fn contributing_functions_are_listed_ascending() {
        // The caller passes the groups in descending name order; the
        // family still names its contributors ascending.
        let groups = [
            group("FUN_18003e750", &[10, 11]),
            group("FUN_18003ab00", &[8, 10]),
        ];
        let families = merge_families(&groups);

        assert_eq!(families.len(), 1);
        assert_eq!(
            families[0].functions,
            vec!["FUN_18003ab00".to_string(), "FUN_18003e750".to_string()]
        );
    }

    #[test]
    fn a_transitive_chain_merges_into_one_family() {
        // No bit stands in all three groups, but each pair shares
        // one: the chain connects the whole set into a single
        // family.
        let groups = [
            group("FUN_18003ab00", &[8, 10]),
            group("FUN_18003e750", &[10, 12]),
            group("FUN_1800412a0", &[12, 13]),
        ];
        let families = merge_families(&groups);

        assert_eq!(families.len(), 1, "the chain merges transitively");
        assert_eq!(families[0].bits, vec![8, 10, 12, 13]);
        assert_eq!(families[0].mask, 0x3500);
        assert_eq!(families[0].bit_width, 14);
        assert_eq!(families[0].functions.len(), 3);
    }

    #[test]
    fn families_sharing_no_bits_stay_separate() {
        // Two pairs, each connected within itself and sharing nothing
        // with the other: two families, never one.
        let groups = [
            group("FUN_18003ab00", &[8, 10]),
            group("FUN_18003e750", &[10, 11]),
            group("FUN_1800412a0", &[20, 21]),
            group("FUN_180041f00", &[21, 22]),
        ];
        let families = merge_families(&groups);

        assert_eq!(families.len(), 2, "disjoint families stay separate");
        assert_eq!(families[0].mask, 0xd00, "sorted by mask");
        assert_eq!(families[0].bits, vec![8, 10, 11]);
        assert_eq!(families[1].mask, 0x700000);
        assert_eq!(families[1].bits, vec![20, 21, 22]);
    }

    #[test]
    fn a_group_sharing_no_bit_claims_no_family() {
        // A lone group — and a second group sharing no bit with it —
        // merge into nothing: each body's per-function record already
        // says all there is to say about that body's flags.
        let groups = [
            group("FUN_18003ab00", &[8, 10]),
            group("FUN_18003e750", &[20, 21]),
        ];
        assert!(
            merge_families(&groups).is_empty(),
            "nothing merged, so nothing joins at the program level"
        );
        assert!(
            merge_families(&groups[..1]).is_empty(),
            "a lone group forms no family"
        );
        assert!(merge_families(&[]).is_empty());
    }

    #[test]
    fn the_evidence_names_each_contributing_groups_bits_and_functions() {
        // The merge is checkable: every contributing group is named
        // with the bits it brought, ascending by function.
        let groups = [
            group("FUN_18003e750", &[10, 11]),
            group("FUN_18003ab00", &[8, 10]),
        ];
        let families = merge_families(&groups);

        assert_eq!(
            families[0].evidence,
            "FUN_18003ab00: bits 0x100, 0x400; FUN_18003e750: bits 0x400, 0x800"
        );
    }

    #[test]
    fn the_family_confidence_sits_above_the_per_function_tier() {
        // Corroboration across functions is stronger evidence than
        // one body's word alone.
        let groups = [
            group("FUN_18003ab00", &[8, 10]),
            group("FUN_18003e750", &[10, 11]),
        ];
        let families = merge_families(&groups);

        assert_eq!(families[0].confidence, Confidence::new(80));
        assert!(families[0].confidence.value() > groups[0].confidence.value());
    }

    #[test]
    fn two_merges_of_the_same_groups_render_identical_families() {
        // The persisted document must stay diffable: the merge is
        // deterministic, whatever order the groups arrive in.
        let groups = [
            group("FUN_1800412a0", &[20, 21]),
            group("FUN_18003ab00", &[8, 10]),
            group("FUN_18003e750", &[10, 11]),
            group("FUN_180041f00", &[21, 22]),
        ];
        let first = merge_families(&groups);
        let second = merge_families(&groups);
        assert_eq!(first, second);
    }
}
