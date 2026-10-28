//! The endianness profiler: the program-wide view of the byte-swap findings.
//! The [`FormatCombiner`](crate::format::FormatCombiner) already answers
//! "what order does *this function's* reads assume". But a real binary
//! swaps at several widths in several functions, and the analyst needs
//! one answer for the whole program: which widths have network-order
//! traffic, and which functions contribute each width. This module groups
//! the scan's byte-swap findings by entry width into one
//! [`EndiannessMap`] finding. The
//! [`SerializeEngine`](crate::engine::SerializeEngine) appends it after
//! the per-function findings.
//!
//! The map is deliberately conservative, like the composed format record.
//! An entry claims [`WireEndianness::BigEndian`] only when a
//! network-order name (`ntohl`/`ntohs`/`htons`/`htonl`) appears at that
//! width. A bare `bswap` says only that bytes get reversed somewhere;
//! the entry says exactly that, `reversal_only`, and claims no wire
//! order. The evidence confidence is fixed at
//! [`ENDIANNESS_MAP_CONFIDENCE`], one band above the raw byte-swap floor.
//! The map builds on the byte-swap findings, and a program-wide
//! aggregation is stronger evidence than any single call site.

use crate::format::{is_network_read, is_network_write};
use crate::types::{EndiannessEntry, EndiannessMap, SerializeFinding, WireEndianness};

/// The fixed evidence confidence of every [`EndiannessMap`] this profiler
/// produces. It sits above the byte-swap floor of 70, because the map
/// builds on the byte-swap findings and a program-wide aggregation is
/// stronger evidence than any single call site. It sits below the
/// lone-magic floor of 80, the same band as the composed format record.
const ENDIANNESS_MAP_CONFIDENCE: u8 = 75;

/// Aggregates the byte-swap findings of one scan into one program-wide
/// [`EndiannessMap`]: one entry per observed width, each naming the endianness
/// that width's swaps imply and every function that swaps at it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EndiannessProfiler;

impl EndiannessProfiler {
    /// A profiler with the standard honesty rules.
    pub fn new() -> Self {
        EndiannessProfiler
    }

    /// Builds the program-wide endianness map for one scan's findings.
    /// The byte-swap findings are grouped by swapped width, one map entry
    /// per width, sorted by width ascending. A width whose swaps include a
    /// network-order name — `ntohl`/`ntohs`/`htons`/`htonl`, the same names
    /// the [`FormatCombiner`](crate::format::FormatCombiner) reads — implies
    /// [`WireEndianness::BigEndian`]: one network-order spelling at a width
    /// says that width uses big-endian order somewhere on the wire, and
    /// claiming `be` on the strength of the family alone is also what the
    /// composed layout's per-field order does. A width whose swaps are all
    /// direction-neutral builtins (`__builtin_bswap*`) gets
    /// [`WireEndianness::ReversalOnly`], claiming no wire order.
    /// Contributing functions are deduped and kept in listing order — the
    /// order the findings appear in the scan. The evidence is each width's
    /// first swap line, and the suggestion names the widths and what each
    /// claims. Returns `None` when the scan has no byte-swap findings: no
    /// swaps observed, nothing to claim.
    pub fn profile(&self, findings: &[SerializeFinding]) -> Option<EndiannessMap> {
        // One accumulator per observed width: whether a network-order name
        // was seen at it, the functions that swap at it (deduped, listing
        // order), and the first swap evidence line seen for it.
        let mut widths: Vec<WidthRecord<'_>> = Vec::new();
        for finding in findings {
            let SerializeFinding::ByteSwap(swap) = finding else {
                continue;
            };
            let network = is_network_read(&swap.operation) || is_network_write(&swap.operation);
            match widths.iter_mut().find(|w| w.width == swap.width) {
                Some(record) => {
                    record.network |= network;
                    if !record.functions.contains(&swap.function) {
                        record.functions.push(swap.function.clone());
                    }
                }
                None => widths.push(WidthRecord {
                    width: swap.width,
                    network,
                    functions: vec![swap.function.clone()],
                    evidence: &swap.evidence,
                }),
            }
        }
        if widths.is_empty() {
            return None;
        }
        widths.sort_by_key(|w| w.width);

        let entries: Vec<EndiannessEntry> = widths
            .iter()
            .map(|w| EndiannessEntry {
                width: w.width,
                endianness: if w.network {
                    WireEndianness::BigEndian
                } else {
                    WireEndianness::ReversalOnly
                },
                functions: w.functions.clone(),
            })
            .collect();
        Some(EndiannessMap {
            function: String::new(),
            entries,
            suggestion: suggest(&widths),
            confidence: ENDIANNESS_MAP_CONFIDENCE.into(),
            evidence: widths
                .iter()
                .map(|w| w.evidence)
                .collect::<Vec<&str>>()
                .join(" "),
        })
    }
}

/// One width's accumulation while the findings are being grouped.
#[derive(Debug, PartialEq, Eq)]
struct WidthRecord<'a> {
    width: u32,
    network: bool,
    functions: Vec<String>,
    evidence: &'a str,
}

/// Builds the map's suggestion text: what each width claims. It lists
/// BE widths first with the byteorder fix, and names reversal-only
/// widths as claiming nothing.
fn suggest(widths: &[WidthRecord<'_>]) -> String {
    let list = |widths: &[&WidthRecord<'_>]| -> String {
        widths
            .iter()
            .map(|w| format!("u{}", w.width))
            .collect::<Vec<String>>()
            .join(", ")
    };
    let be: Vec<&WidthRecord<'_>> = widths.iter().filter(|w| w.network).collect();
    let reversal: Vec<&WidthRecord<'_>> = widths.iter().filter(|w| !w.network).collect();
    match (be.is_empty(), reversal.is_empty()) {
        (false, true) => format!(
            "program-wide BE wire order at {} (byteorder BE types)",
            list(&be)
        ),
        (true, false) => format!(
            "program-wide byte reversal at {} — no wire order claimed",
            list(&reversal)
        ),
        _ => format!(
            "program-wide BE wire order at {} (byteorder BE types); reversal-only at {}",
            list(&be),
            list(&reversal)
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ByteSwapOperation, Confidence};

    /// Hand-builds one byte-swap finding: `function` swapping a `width`-bit
    /// value through the `operation` spelling.
    fn swap(function: &str, operation: &str, width: u32) -> SerializeFinding {
        SerializeFinding::ByteSwap(ByteSwapOperation {
            function: function.to_string(),
            operation: operation.to_string(),
            width,
            suggestion: format!("byteorder::BE::read_u{width}"),
            confidence: Confidence::new(70),
            evidence: format!("uVar1 = {operation}(local_18);"),
        })
    }

    fn profile(findings: &[SerializeFinding]) -> EndiannessMap {
        EndiannessProfiler::new()
            .profile(findings)
            .expect("swaps are a map")
    }

    #[test]
    fn a_scan_with_no_swaps_gets_no_map() {
        let profiler = EndiannessProfiler::new();
        assert!(profiler.profile(&[]).is_none());
        let other = SerializeFinding::Magic(crate::types::MagicFormat {
            function: "FUN_18003ab00".to_string(),
            magic: 0x8950_4E47,
            format: "PNG".to_string(),
            suggestion: "png::Decoder".to_string(),
            confidence: Confidence::new(80),
            evidence: "if (uVar6 == 0x89504e47) {".to_string(),
        });
        assert!(profiler.profile(&[other]).is_none());
    }

    #[test]
    fn the_network_order_family_at_a_width_implies_be() {
        for name in ["ntohl", "ntohs", "htons", "htonl"] {
            let map = profile(&[swap("FUN_18003ab00", name, 32)]);
            assert_eq!(
                map.entries,
                vec![EndiannessEntry {
                    width: 32,
                    endianness: WireEndianness::BigEndian,
                    functions: vec!["FUN_18003ab00".to_string()],
                }],
                "{name}"
            );
        }
    }

    #[test]
    fn a_bswap_only_width_claims_reversal_and_no_order() {
        let map = profile(&[
            swap("FUN_18003ab00", "__builtin_bswap32", 32),
            swap("FUN_18003ab00", "__builtin_bswap16", 16),
        ]);
        assert_eq!(
            map.entries,
            vec![
                EndiannessEntry {
                    width: 16,
                    endianness: WireEndianness::ReversalOnly,
                    functions: vec!["FUN_18003ab00".to_string()],
                },
                EndiannessEntry {
                    width: 32,
                    endianness: WireEndianness::ReversalOnly,
                    functions: vec!["FUN_18003ab00".to_string()],
                },
            ]
        );
        assert_eq!(
            map.suggestion,
            "program-wide byte reversal at u16, u32 — no wire order claimed"
        );
    }

    #[test]
    fn one_network_name_at_a_width_makes_the_whole_entry_be() {
        let map = profile(&[
            swap("FUN_18003ab00", "__builtin_bswap32", 32),
            swap("FUN_18003e750", "ntohl", 32),
        ]);
        assert_eq!(map.entries.len(), 1);
        assert_eq!(map.entries[0].endianness, WireEndianness::BigEndian);
        assert_eq!(
            map.entries[0].functions,
            vec!["FUN_18003ab00".to_string(), "FUN_18003e750".to_string()]
        );
    }

    #[test]
    fn contributing_functions_stay_in_listing_order_and_dedup() {
        let map = profile(&[
            swap("FUN_18003e750", "ntohl", 32),
            swap("FUN_18003ab00", "htonl", 32),
            swap("FUN_18003e750", "ntohl", 32),
        ]);
        // FUN_18003e750 appears twice, but first: it leads the list, once.
        assert_eq!(
            map.entries[0].functions,
            vec!["FUN_18003e750".to_string(), "FUN_18003ab00".to_string()]
        );
    }

    #[test]
    fn unobserved_widths_are_absent() {
        let map = profile(&[swap("FUN_18003ab00", "htons", 16)]);
        assert_eq!(map.entries.len(), 1);
        assert_eq!(map.entries[0].width, 16);
    }

    #[test]
    fn the_map_is_one_record_per_scan_at_the_fixed_confidence() {
        let map = profile(&[
            swap("FUN_18003ab00", "ntohl", 32),
            swap("FUN_18003ab00", "htons", 16),
            swap("FUN_18003e750", "ntohl", 32),
        ]);
        // One record, every width, sorted ascending, at the fixed
        // evidence confidence.
        assert_eq!(map.confidence, Confidence::new(ENDIANNESS_MAP_CONFIDENCE));
        assert_eq!(ENDIANNESS_MAP_CONFIDENCE, 75);
        assert_eq!(map.function, "");
        assert_eq!(map.entries.len(), 2);
        assert_eq!(map.entries[0].width, 16);
        assert_eq!(map.entries[1].width, 32);
    }

    #[test]
    fn mixed_claims_name_each_width_and_the_be_fix_first() {
        let map = profile(&[
            swap("FUN_18003ab00", "ntohs", 16),
            swap("FUN_18003ab00", "__builtin_bswap32", 32),
        ]);
        assert_eq!(
            map.suggestion,
            "program-wide BE wire order at u16 (byteorder BE types); reversal-only at u32"
        );
    }

    #[test]
    fn the_evidence_is_each_widths_first_swap_line() {
        let map = profile(&[
            SerializeFinding::ByteSwap(ByteSwapOperation {
                function: "FUN_18003ab00".to_string(),
                operation: "ntohl".to_string(),
                width: 32,
                suggestion: "byteorder::BE::read_u32".to_string(),
                confidence: Confidence::new(70),
                evidence: "uVar1 = ntohl(local_18);".to_string(),
            }),
            swap("FUN_18003e750", "ntohl", 32),
            swap("FUN_180044d20", "htons", 16),
        ]);
        // u16 first (sorted), each width's first line only.
        assert_eq!(
            map.evidence,
            "uVar1 = htons(local_18); uVar1 = ntohl(local_18);"
        );
    }
}
