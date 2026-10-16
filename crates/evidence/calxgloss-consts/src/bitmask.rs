//! Bitflag group detection.
//!
//! [`BitmaskDetector`] reads a function's decompiled body for
//! power-of-two integer literals used in bitwise contexts — `x &
//! 0x400`, `x | 0x100`, `x &= ~0x20`, `1 << 3` — and collects the
//! distinct bits a function combines into one flag-group finding.
//! A function that tests and sets two or more separate bits is
//! reading a flags field through bare literals; the finding names the
//! bits and suggests the `bitflags!`-style struct that would name
//! them.
//!
//! A composite mask — a non-power-of-two literal in a bitwise
//! context, like `x &= 0x500` — completes the group rather than
//! sitting out: it decomposes into its set bits when every one of
//! those bits was independently observed as a single-bit literal in
//! the same body. A composite whose bits were never independently
//! seen claims nothing — a range mask is not a flag claim.

use std::collections::BTreeSet;

use crate::tokenize::{Token, evidence, tokenize};
use crate::types::{BitflagGroup, Confidence};

/// The bitwise operators a mask literal can sit beside: plain and
/// compound assignment — the default spelling set a
/// [`BitmaskDetector`] reads.
const BITWISE_OPERATORS: [&str; 6] = ["&", "|", "^", "&=", "|=", "^="];

/// Whether `value` is a power of two (and not zero).
fn is_power_of_two(value: u64) -> bool {
    value != 0 && value & (value - 1) == 0
}

/// The bit position a power-of-two mask occupies.
fn bit_of(value: u64) -> u32 {
    value.trailing_zeros()
}

/// The bit positions a composite mask carries, e.g. `0x300` → 9 and 8.
fn set_bits(value: u64) -> impl Iterator<Item = u32> {
    (0..u64::BITS).filter(move |bit| value & (1u64 << bit) != 0)
}

/// The integer width a flags field spanning `bit_width` bits fits.
fn flags_type(bit_width: u32) -> &'static str {
    match bit_width {
        0..=8 => "u8",
        9..=16 => "u16",
        17..=32 => "u32",
        _ => "u64",
    }
}

/// Collects the distinct flag bits one function combines through
/// bitwise operations.
///
/// The detector is stateless; [`with_default_threshold`] configures
/// the standard "at least two distinct bits" bar over the standard
/// operator spellings, [`with_min_bits`](Self::with_min_bits) swaps
/// the bar, and [`with_bitwise_ops`](Self::with_bitwise_ops) swaps the
/// bar and the operator spellings whole.
#[derive(Debug, Clone)]
pub struct BitmaskDetector {
    min_bits: usize,
    ops: Vec<String>,
}

impl BitmaskDetector {
    /// A detector reading groups at the standard threshold: two or
    /// more distinct bits make a flags field.
    pub fn with_default_threshold() -> Self {
        Self::with_min_bits(2)
    }

    /// A detector that reports a group once it sees `min_bits`
    /// distinct bits, beside the standard bitwise operator spellings.
    pub fn with_min_bits(min_bits: usize) -> Self {
        Self {
            min_bits,
            ops: BITWISE_OPERATORS
                .iter()
                .map(|op| (*op).to_string())
                .collect(),
        }
    }

    /// A detector reading masks beside the given operator spellings,
    /// reporting once it sees `min_bits` distinct bits.
    pub fn with_bitwise_ops(min_bits: usize, ops: &[&str]) -> Self {
        Self {
            min_bits,
            ops: ops.iter().map(|op| (*op).to_string()).collect(),
        }
    }

    /// The flag group in one decompiled body, if the function
    /// combines enough distinct bits.
    ///
    /// A bit counts when a power-of-two literal sits beside a bitwise
    /// operator (`x & 0x400`, `x &= ~0x400`) or heads a shift mask
    /// (`1 << 3`). One bit alone is a situational mask, not a flags
    /// field; two or more (at the configured threshold) read as one
    /// group.
    ///
    /// A composite mask — a non-power-of-two literal in a bitwise
    /// context, like `x &= 0x500` — contributes its set bits when
    /// every one of them was independently observed as a single-bit
    /// literal somewhere in the same body (a shift amount, like the
    /// 8 in `1 << 8`, shows the shifted bit rather than its own, and
    /// never counts as an independent sighting). The composite
    /// occurrence joins the evidence and the mask and bit width widen
    /// to cover the decomposed bits; a composite with any never-
    /// independently-seen bit claims nothing — a range mask is not a
    /// flag claim.
    pub fn detect(&self, function: &str, body: &str) -> Option<BitflagGroup> {
        let tokens = tokenize(body);
        let mut bits: BTreeSet<u32> = BTreeSet::new();
        let mut evidence_lines: BTreeSet<usize> = BTreeSet::new();
        // Bits the body shows on their own, as single-bit literals in
        // any position: the gate a composite mask must pass before its
        // bits count.
        let mut seen_singly: BTreeSet<u32> = BTreeSet::new();

        for (index, token) in tokens.iter().enumerate() {
            let Some(value) = token.int() else {
                continue;
            };
            if !is_power_of_two(value) {
                continue;
            }
            if self.bitwise_context(&tokens, index) {
                bits.insert(bit_of(value));
                seen_singly.insert(bit_of(value));
                evidence_lines.insert(token.line);
            } else if let Some(shift) = self.shift_mask(&tokens, index)
                && let Some(bit) = bit_of(value).checked_add(shift)
            {
                bits.insert(bit);
                seen_singly.insert(bit);
                evidence_lines.insert(token.line);
            } else if !self.is_shift_amount(&tokens, index) {
                // A single-bit literal outside every bitwise shape
                // still shows the bit was seen on its own; it claims
                // nothing itself, but it lets a composite carrying it
                // decompose.
                seen_singly.insert(bit_of(value));
            }
        }

        for (index, token) in tokens.iter().enumerate() {
            let Some(value) = token.int() else {
                continue;
            };
            if value == 0 || is_power_of_two(value) || !self.bitwise_context(&tokens, index) {
                continue;
            }
            let decomposed: BTreeSet<u32> = set_bits(value).collect();
            if decomposed.iter().all(|bit| seen_singly.contains(bit)) {
                bits.extend(decomposed);
                evidence_lines.insert(token.line);
            }
        }

        if bits.len() < self.min_bits {
            return None;
        }

        let bits: Vec<u32> = bits.into_iter().collect();
        let mask: u64 = bits.iter().fold(0u64, |acc, bit| acc | (1u64 << bit));
        let bit_width = bits[bits.len() - 1] + 1;
        let names: Vec<String> = bits
            .iter()
            .map(|bit| format!("{:#x}", 1u64 << bit))
            .collect();

        Some(BitflagGroup {
            function: function.to_string(),
            mask,
            bit_width,
            bits,
            suggestion: format!(
                "bitflags! struct Flags: {} {{ /* bits: {} */ }}",
                flags_type(bit_width),
                names.join(", ")
            ),
            confidence: Confidence::new(70),
            evidence: evidence(body, &evidence_lines),
        })
    }

    /// Whether the literal at `index` sits in a bitwise context:
    /// beside one of the detector's configured operators, or after
    /// the `~` of a complemented mask like `x &= ~0x400`.
    fn bitwise_context(&self, tokens: &[Token<'_>], index: usize) -> bool {
        let before = index
            .checked_sub(1)
            .map(|j| &tokens[j])
            .filter(|t| !t.is_punct(&["~"]))
            .or_else(|| index.checked_sub(2).map(|j| &tokens[j]));
        let after = tokens.get(index + 1);
        let beside_op = |token: Option<&Token>| {
            token.is_some_and(|t| self.ops.iter().any(|op| t.is_punct(&[op.as_str()])))
        };
        beside_op(before) || beside_op(after)
    }

    /// The shift amount when the literal at `index` heads a shift
    /// mask (`1 << 3`), i.e. `N` in `value << N`.
    fn shift_mask(&self, tokens: &[Token<'_>], index: usize) -> Option<u32> {
        let operator = tokens.get(index + 1)?;
        if !operator.is_punct(&["<<"]) {
            return None;
        }
        tokens.get(index + 2)?.int().map(|shift| shift as u32)
    }

    /// Whether the literal at `index` is a shift amount (`N` in
    /// `value << N` or `value >> N`) rather than a mask of its own —
    /// it shows the shifted bit, never its own. The compound spelling
    /// tokenizes as `<<` then `=`, so the amount sits behind both.
    fn is_shift_amount(&self, tokens: &[Token<'_>], index: usize) -> bool {
        let punct_before = |j: usize| tokens[j].is_punct(&["<<", ">>"]);
        index.checked_sub(1).is_some_and(punct_before)
            || index
                .checked_sub(2)
                .is_some_and(|j| tokens[j + 1].is_punct(&["="]) && punct_before(j))
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn detect(body: &str) -> Option<BitflagGroup> {
        BitmaskDetector::with_default_threshold().detect("FUN_18003ab00", body)
    }

    #[test]
    fn two_bits_combined_in_bitwise_contexts_read_as_one_group() {
        let group = detect(
            r#"  if ((uVar1 & 0x400) != 0) {
    uVar1 |= 0x100;
  }"#,
        )
        .expect("two flag bits should read as a group");
        assert_eq!(group.function, "FUN_18003ab00");
        assert_eq!(group.bits, vec![8, 10]);
        assert_eq!(group.mask, 0x500);
        assert_eq!(group.bit_width, 11);
        assert_eq!(group.confidence, Confidence::new(70));
        assert!(group.suggestion.contains("bitflags! struct Flags: u16"));
        assert!(group.evidence.contains("uVar1 & 0x400"));
        assert!(group.evidence.contains("uVar1 |= 0x100"));
    }

    #[test]
    fn shift_masks_count_as_flag_bits() {
        let group = detect(
            r#"  uVar2 = 1 << 3;
  if ((flags & (1 << 7)) != 0) {
    return;
  }"#,
        )
        .expect("two shift masks should read as a group");
        assert_eq!(group.bits, vec![3, 7]);
        assert_eq!(group.mask, 0x88);
    }

    #[test]
    fn complemented_masks_count_as_flag_bits() {
        let group = detect(
            r#"  param_1 &= ~0x10;
  param_1 |= 0x20;"#,
        )
        .expect("a cleared and a set bit should read as a group");
        assert_eq!(group.bits, vec![4, 5]);
    }

    #[test]
    fn one_bit_alone_is_not_a_group() {
        assert!(detect(r#"  if ((x & 0x400) != 0) { y = 1; }"#).is_none());
    }

    #[test]
    fn non_power_of_two_literals_do_not_count() {
        assert!(
            detect("  x &= 0x600;\n  x |= 0x300;").is_none(),
            "0x600 and 0x300 are not single bits, and no bit was seen singly"
        );
    }

    #[test]
    fn a_composite_decomposes_when_every_bit_was_seen_singly() {
        // 0x300 carries bits 9 and 8: bit 8 was seen singly in a
        // bitwise context, bit 9 as a lone literal. Every bit
        // independently seen, so the composite completes the group —
        // the mask and width widen to cover it — and its line joins
        // the evidence.
        let group = detect("  x &= 0x100;\n  y = 0x200;\n  x |= 0x300;")
            .expect("the composite completes the group");
        assert_eq!(group.bits, vec![8, 9]);
        assert_eq!(group.mask, 0x300);
        assert_eq!(group.bit_width, 10);
        assert!(group.evidence.contains("x |= 0x300"));
        assert!(
            !group.evidence.contains("y = 0x200"),
            "the lone literal gates the decomposition but is not itself flag evidence"
        );
    }

    #[test]
    fn composites_build_a_complete_group_when_their_bits_were_seen_singly() {
        // The ticket's shape: 0x500 and 0x300 combined in bitwise
        // contexts over a body that shows bits 8, 9, and 10 singly —
        // the group covers all three with the widened mask and width.
        let group =
            detect("  a = 0x100;\n  b = 0x200;\n  c = 0x400;\n  x &= 0x500;\n  x |= 0x300;")
                .expect("both composites decompose");
        assert_eq!(group.bits, vec![8, 9, 10]);
        assert_eq!(group.mask, 0x700);
        assert_eq!(group.bit_width, 11);
        assert!(group.evidence.contains("x &= 0x500"));
        assert!(group.evidence.contains("x |= 0x300"));
    }

    #[test]
    fn a_composite_with_a_never_singly_seen_bit_claims_nothing() {
        // 0xf00 carries bits 8..=11; bits 9 and 11 were never seen
        // singly, so the whole composite claims nothing — a field mask
        // is not a flag claim — and its line stays out of the evidence.
        let group = detect("  x &= 0x100;\n  x |= 0x400;\n  x &= 0xf00;")
            .expect("the two singly seen bits still read as a group");
        assert_eq!(group.bits, vec![8, 10]);
        assert_eq!(group.mask, 0x500);
        assert_eq!(group.bit_width, 11);
        assert!(
            !group.evidence.contains("0xf00"),
            "the rejected composite contributes no evidence"
        );
    }

    #[test]
    fn a_partly_seen_composite_leaves_the_group_below_the_threshold() {
        // 0xf00 over bits 8 and 9 seen singly: bits 10 and 11 were
        // never seen, so the composite claims nothing and one counted
        // bit alone is no group.
        assert!(detect("  x &= 0x100;\n  y = 0x200;\n  x &= 0xf00;").is_none());
    }

    #[test]
    fn a_shift_amount_never_reads_as_an_independently_seen_bit() {
        // The 8 in `1 << 8` shows bit 8 through the shift, not bit 3,
        // so 0x108's bit 3 was never independently seen and the
        // composite claims nothing.
        assert!(detect("  x = 1 << 8;\n  y &= 0x100;\n  y |= 0x108;").is_none());
    }

    #[test]
    fn a_compound_shift_amount_is_excluded_too() {
        // `x <<= 8` tokenizes as `<<` then `=`; the 8 behind them is
        // still a shift amount, never an independent sighting of bit 3.
        assert!(detect("  x <<= 8;\n  y &= 0x100;\n  y |= 0x108;").is_none());
    }

    #[test]
    fn a_complemented_composite_decomposes_like_any_other() {
        let group = detect("  x &= ~0x30;\n  x |= 0x10;\n  y = 0x20;")
            .expect("the cleared composite carries the two seen bits");
        assert_eq!(group.bits, vec![4, 5]);
        assert_eq!(group.mask, 0x30);
        assert!(group.evidence.contains("~0x30"));
    }

    #[test]
    fn literals_outside_bitwise_contexts_do_not_count() {
        assert!(
            detect("  size = 0x100;\n  count = 0x200;").is_none(),
            "plain assignments are not flag tests"
        );
    }

    #[test]
    fn string_contents_and_identifier_digits_never_read_as_bits() {
        assert!(
            detect(
                r#"  puts("set 0x10 | 0x20");
  local_10 |= local_20;"#
            )
            .is_none()
        );
    }

    #[test]
    fn the_suggestion_widths_the_flags_type_to_the_highest_bit() {
        let group = detect("  x &= 0x1;\n  x |= 0x2;").expect("two low bits");
        assert!(group.suggestion.contains("struct Flags: u8"));
    }

    #[test]
    fn a_custom_threshold_reaches_the_detector() {
        let body = "  x &= 0x1;\n  x |= 0x2;\n  x ^= 0x4;";
        let detector = BitmaskDetector::with_min_bits(3);
        let group = detector
            .detect("FUN_18003ab00", body)
            .expect("three bits clear a threshold of three");
        assert_eq!(group.bits, vec![0, 1, 2]);
        assert!(
            BitmaskDetector::with_min_bits(4)
                .detect("FUN_18003ab00", body)
                .is_none()
        );
    }

    #[test]
    fn custom_bitwise_op_spellings_reach_the_detector() {
        let body = "  x &= 0x1;\n  x |= 0x2;";
        let only_and = BitmaskDetector::with_bitwise_ops(2, &["&"]);
        assert!(
            only_and.detect("FUN_18003ab00", body).is_none(),
            "`|=` is not in the configured spelling set"
        );
        let both = BitmaskDetector::with_bitwise_ops(2, &["&=", "|="]);
        let group = both
            .detect("FUN_18003ab00", body)
            .expect("both operators are configured");
        assert_eq!(group.bits, vec![0, 1]);
    }
}
