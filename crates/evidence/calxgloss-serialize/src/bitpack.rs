//! Manual bit-packing detection.
//!
//! This module provides [`BitPackDetector`], which reads decompiled
//! bodies for the two shapes a hand-rolled wire format leaves behind:
//! shift-and-or pack chains — bytes shifted to their offsets and ORed
//! into a word, the way Ghidra decompiles a hand-rolled big-endian
//! read — and shift-then-mask unpack chains — a word shifted right and
//! masked to pull one field back out.
//!
//! Unlike the call-name detectors there is no name set: the reading is
//! the expression shape itself. [`BitPackDetector::detect`] reports one
//! [`BitPackRecord`] per pack expression and per unpack chain, naming
//! the [`widths`](BitPackRecord::widths) of the fields the shifts and
//! masks carve out and suggesting the typed Rust stand-in — `bitvec`,
//! or named-field masking and shifting on a plain integer.

use crate::scan::literal_after_ws;
use crate::types::{BitPackPattern, BitPackRecord};
use calxgloss_ghidra::DecompiledFunction;

// ============================================================
// Detector
// ============================================================

/// Bit-packing pattern detection over decompiled functions.
///
/// The detector owns no name set — the pack and unpack shapes are the
/// whole configuration — and holds no Ghidra client of its own and
/// never writes back to the program; one detector serves an entire
/// scan and can be shared by reference across concurrent per-function
/// passes. It is swappable whole on the engine through
/// [`SerializeEngine::with_bitpack`](crate::engine::SerializeEngine::with_bitpack)
/// for a scan that wants the shape reading off.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BitPackDetector {}

impl BitPackDetector {
    /// A detector reading the standard pack and unpack shapes.
    pub fn new() -> Self {
        Self::default()
    }

    /// The bit-packing shapes one function's body carries.
    ///
    /// The reading walks the body line by line. A line that ORs shifted
    /// operands together — an unshifted operand counts as the bottom
    /// field — is one pack expression, and its
    /// field widths come from the gaps between the shift amounts — a
    /// field sits where the next-lower shift leaves room for it, and
    /// the unshifted operand (or the bare last one) closes the word at
    /// zero. Unpack extractions — a right shift followed by a mask —
    /// are collected across the body and reported as one chain when
    /// two or more pull fields from the word, their widths read from
    /// the masks' set bits. Findings come back in body order, so two
    /// scans of one body diff cleanly.
    pub fn detect(&self, func: &DecompiledFunction) -> Vec<BitPackRecord> {
        let mut records = Vec::new();
        let mut unpack_lines: Vec<String> = Vec::new();
        let mut unpack_widths: Vec<u32> = Vec::new();

        for line in func.body.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let chars: Vec<char> = line.chars().collect();

            // A pack expression: left shifts joined by `|`, with an
            // unshifted operand counting as the bottom field — one
            // explicit shift plus that field is already a two-field
            // pack. `||` is a boolean or, not a bit join, so a line
            // carrying one is not a pack chain.
            let mut amounts: Vec<u32> = shift_amounts(&chars);
            if !amounts.is_empty() && line.contains('|') && !line.contains("||") {
                records.push(BitPackRecord {
                    function: func.name.clone(),
                    pattern: BitPackPattern::ShiftOrPack,
                    widths: pack_widths(&mut amounts),
                    suggestion: BITPACK_SUGGESTION.to_string(),
                    confidence: BITPACK_CONFIDENCE.into(),
                    evidence: line.to_string(),
                });
                continue;
            }

            // An unpack extraction: `(w >> N) & mask`. One extraction
            // is a lone field read; two or more across the body are
            // the chain that says the word is a packed format.
            if let Some(mask) = unpack_extraction(&chars) {
                unpack_lines.push(line.to_string());
                unpack_widths.push(mask.count_ones());
            }
        }

        if unpack_lines.len() >= 2 {
            records.push(BitPackRecord {
                function: func.name.clone(),
                pattern: BitPackPattern::ShiftMaskUnpack,
                widths: unpack_widths,
                suggestion: BITPACK_SUGGESTION.to_string(),
                confidence: BITPACK_CONFIDENCE.into(),
                evidence: unpack_lines.join(" "),
            });
        }

        records
    }
}

// ============================================================
// The reading
// ============================================================

/// Confidence of a bit-packing reading from the expression shape
/// alone: the shifts and masks are explicit, but the shape is only a
/// hypothesis about *why* the code moves bits — ordinary arithmetic
/// shifts wear the same face — so the reading sits below the
/// call-name detectors, whose names carry the intent outright.
const BITPACK_CONFIDENCE: u8 = 60;

/// The Rust pattern a pack or unpack chain reads as: a typed field
/// view instead of the hand-rolled shifts, spelled as the two ways to
/// get one.
const BITPACK_SUGGESTION: &str = "bitvec or named-field masking/shifting";

/// The shift amounts of a `<< N` pack expression: every left shift by
/// a decimal or hex literal, the amount the expression parks each
/// field at.
fn shift_amounts(line: &[char]) -> Vec<u32> {
    let mut amounts = Vec::new();
    let mut i = 0;
    while i + 1 < line.len() {
        if line[i] == '<' && line[i + 1] == '<' {
            if let Some((amount, _)) = literal_after_ws(line, i + 2)
                && let Ok(amount) = u32::try_from(amount)
            {
                amounts.push(amount);
            }
            i += 2;
        } else {
            i += 1;
        }
    }
    amounts
}

/// The mask of a `(w >> N) & mask` extraction: a right shift by a
/// literal followed by an `&` and a literal — the extraction that
/// pulls one packed field back out. `&&` is a boolean and, not a
/// mask, so it does not count.
fn unpack_extraction(line: &[char]) -> Option<u64> {
    let mut i = 0;
    while i + 1 < line.len() {
        if line[i] == '>' && line[i + 1] == '>' {
            if let Some((_, end)) = literal_after_ws(line, i + 2) {
                let mut j = end;
                while j < line.len() && line[j].is_whitespace() {
                    j += 1;
                }
                // The extraction is usually parenthesised — `(w >> N)
                // & mask` — so a closing paren may sit between the
                // shift and the mask.
                if j < line.len() && line[j] == ')' {
                    j += 1;
                    while j < line.len() && line[j].is_whitespace() {
                        j += 1;
                    }
                }
                if j < line.len()
                    && line[j] == '&'
                    && line.get(j + 1) != Some(&'&')
                    && let Some((mask, _)) = literal_after_ws(line, j + 1)
                {
                    return Some(mask);
                }
            }
            i += 2;
        } else {
            i += 1;
        }
    }
    None
}

/// The field widths a pack expression carves, from its shift amounts:
/// sorted high to low with the implicit zero the unshifted operand
/// sits at, each field as wide as the gap down to the next shift, and
/// the top field as wide as the widest gap below it — the word's top
/// edge the decompiler never spells out.
fn pack_widths(amounts: &mut Vec<u32>) -> Vec<u32> {
    amounts.sort_unstable_by(|a, b| b.cmp(a));
    amounts.dedup();
    if amounts.last() != Some(&0) {
        amounts.push(0);
    }
    let mut widths: Vec<u32> = Vec::new();
    if amounts.len() >= 2 {
        // The top field's width is the first gap, repeated: the word's
        // top edge is never written, so the field at the highest shift
        // is read as wide as the field below it.
        widths.push(amounts[0].saturating_sub(amounts[1]));
        for pair in amounts.windows(2) {
            widths.push(pair[0].saturating_sub(pair[1]));
        }
    }
    widths
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_detector_starts_and_clones_freely() {
        let detector = BitPackDetector::new();
        assert_eq!(detector, BitPackDetector::default());
        assert_eq!(detector.clone(), detector);
    }

    #[test]
    fn a_detector_can_be_shared_across_scans() {
        // One detector is driven concurrently over a program's
        // functions, so sharing one by reference across tasks must
        // stay sound.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<BitPackDetector>();
    }

    #[test]
    fn a_bit_pack_pattern_displays_its_serde_label() {
        for pattern in [BitPackPattern::ShiftOrPack, BitPackPattern::ShiftMaskUnpack] {
            let label = serde_json::to_value(pattern).unwrap();
            assert_eq!(pattern.to_string(), label.as_str().unwrap());
        }
        assert_eq!(BitPackPattern::ShiftOrPack.to_string(), "shift_or_pack");
        assert_eq!(
            BitPackPattern::ShiftMaskUnpack.to_string(),
            "shift_mask_unpack"
        );
    }

    // ------------------------------------------------------------
    // Detection
    // ------------------------------------------------------------

    fn function(body: &str) -> DecompiledFunction {
        DecompiledFunction {
            name: "FUN_18003ab00".into(),
            signature: "undefined FUN_18003ab00(void)".into(),
            body: body.into(),
        }
    }

    fn detect(body: &str) -> Vec<BitPackRecord> {
        BitPackDetector::new().detect(&function(body))
    }

    #[test]
    fn a_shift_or_or_pack_chain_is_recognized_with_its_widths() {
        // The classic hand-rolled big-endian read: four bytes parked
        // at 0x18, 0x10, 8, and implicitly 0 — four 8-bit fields.
        let records = detect(
            "\
  uVar1 = (uVar2 << 0x18) | ((uint)uVar3 << 0x10) | (uVar4 << 8) | (uint)uVar5;",
        );
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].function, "FUN_18003ab00");
        assert_eq!(records[0].pattern, BitPackPattern::ShiftOrPack);
        assert_eq!(records[0].widths, [8, 8, 8, 8]);
        assert_eq!(
            records[0].suggestion,
            "bitvec or named-field masking/shifting"
        );
        assert_eq!(records[0].confidence, BITPACK_CONFIDENCE);
        assert!(
            records[0]
                .evidence
                .contains("(uVar2 << 0x18) | ((uint)uVar3 << 0x10)")
        );
    }

    #[test]
    fn a_pack_chain_with_decimal_shifts_reads_the_same() {
        let records = detect("  uVar1 = (a << 24) | (b << 16) | (c << 8) | d;");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].pattern, BitPackPattern::ShiftOrPack);
        assert_eq!(records[0].widths, [8, 8, 8, 8]);
    }

    #[test]
    fn a_two_field_pack_reads_two_widths() {
        // A 16-bit word out of two bytes: the gap at 8 and the
        // implicit zero below it.
        let records = detect("  uVar1 = (uVar2 << 8) | (uint)uVar3;");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].widths, [8, 8]);
    }

    #[test]
    fn a_shift_mask_unpack_chain_is_recognized_with_its_widths() {
        // The read side of the same format: three masked extractions
        // from one word, each field 8 bits wide by its mask.
        let records = detect(
            "\
  iVar2 = (uVar1 >> 0x18) & 0xff;
  iVar3 = (uVar1 >> 0x10) & 0xff;
  iVar4 = (uVar1 >> 8) & 0xff;",
        );
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].pattern, BitPackPattern::ShiftMaskUnpack);
        assert_eq!(records[0].widths, [8, 8, 8]);
        assert_eq!(
            records[0].suggestion,
            "bitvec or named-field masking/shifting"
        );
        assert_eq!(records[0].confidence, BITPACK_CONFIDENCE);
        assert!(records[0].evidence.contains("(uVar1 >> 0x18) & 0xff;"));
    }

    #[test]
    fn a_wider_mask_reads_a_wider_field() {
        let records = detect(
            "\
  uVar2 = (uVar1 >> 0x10) & 0xffff;
  uVar3 = (uVar1 >> 0x20) & 0xffff;",
        );
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].pattern, BitPackPattern::ShiftMaskUnpack);
        assert_eq!(records[0].widths, [16, 16]);
    }

    #[test]
    fn a_single_extraction_is_not_yet_a_chain() {
        assert!(detect("  iVar2 = (uVar1 >> 0x18) & 0xff;").is_empty());
    }

    #[test]
    fn ordinary_arithmetic_yields_nothing() {
        assert!(
            detect(
                "\
  uVar1 = uVar2 << 3;
  uVar3 = uVar4 >> 2;
  if (uVar1 > 0 && uVar3 < 10) { uVar5 = uVar1 + uVar3; }
  return;"
            )
            .is_empty()
        );
    }

    #[test]
    fn a_boolean_or_of_shifts_is_not_a_pack_chain() {
        // `||` is a boolean or; two shifts either side of it are
        // unrelated conditions, not fields of one word.
        assert!(detect("  if ((a << 0x18) || (b << 0x10)) { return; }").is_empty());
    }

    #[test]
    fn pack_and_unpack_chains_in_one_body_are_both_reported() {
        let records = detect(
            "\
  uVar1 = (uVar2 << 0x18) | ((uint)uVar3 << 0x10) | (uVar4 << 8) | (uint)uVar5;
  iVar6 = (uVar1 >> 0x18) & 0xff;
  iVar7 = (uVar1 >> 0x10) & 0xff;",
        );
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].pattern, BitPackPattern::ShiftOrPack);
        assert_eq!(records[1].pattern, BitPackPattern::ShiftMaskUnpack);
    }

    #[test]
    fn findings_come_back_in_body_order() {
        let records = detect(
            "\
  iVar1 = (uVar2 >> 0x10) & 0xff;
  iVar3 = (uVar2 >> 8) & 0xff;
  uVar4 = (a << 8) | b;",
        );
        // The unpack chain closes at the end of the body — the pack
        // line that came earlier still leads, because pack findings
        // are per line and the chain is per body.
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].pattern, BitPackPattern::ShiftOrPack);
        assert_eq!(records[1].pattern, BitPackPattern::ShiftMaskUnpack);
    }
}
