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

use std::collections::BTreeSet;

use crate::tokenize::{Token, tokenize};
use crate::types::{BitflagGroup, Confidence};

/// The bitwise operators a mask literal can sit beside: plain and
/// compound assignment.
const BITWISE_OPERATORS: [&str; 6] = ["&", "|", "^", "&=", "|=", "^="];

/// Whether `value` is a power of two (and not zero).
fn is_power_of_two(value: u64) -> bool {
    value != 0 && value & (value - 1) == 0
}

/// The bit position a power-of-two mask occupies.
fn bit_of(value: u64) -> u32 {
    value.trailing_zeros()
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
/// the standard "at least two distinct bits" bar, and
/// [`with_min_bits`](Self::with_min_bits) swaps it whole.
#[derive(Debug, Clone)]
pub struct BitmaskDetector {
    min_bits: usize,
}

impl BitmaskDetector {
    /// A detector reading groups at the standard threshold: two or
    /// more distinct bits make a flags field.
    pub fn with_default_threshold() -> Self {
        Self { min_bits: 2 }
    }

    /// A detector that reports a group once it sees `min_bits`
    /// distinct bits.
    pub fn with_min_bits(min_bits: usize) -> Self {
        Self { min_bits }
    }

    /// The flag group in one decompiled body, if the function
    /// combines enough distinct bits.
    ///
    /// A bit counts when a power-of-two literal sits beside a bitwise
    /// operator (`x & 0x400`, `x &= ~0x400`) or heads a shift mask
    /// (`1 << 3`). One bit alone is a situational mask, not a flags
    /// field; two or more (at the configured threshold) read as one
    /// group.
    pub fn detect(&self, function: &str, body: &str) -> Option<BitflagGroup> {
        let tokens = tokenize(body);
        let mut bits: BTreeSet<u32> = BTreeSet::new();
        let mut evidence_lines: BTreeSet<usize> = BTreeSet::new();

        for (index, token) in tokens.iter().enumerate() {
            let Some(value) = token.int() else {
                continue;
            };
            if !is_power_of_two(value) {
                continue;
            }
            if self.bitwise_context(&tokens, index) {
                bits.insert(bit_of(value));
                evidence_lines.insert(token.line);
            } else if let Some(shift) = self.shift_mask(&tokens, index)
                && let Some(bit) = bit_of(value).checked_add(shift)
            {
                bits.insert(bit);
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
    /// beside a bitwise operator, or after the `~` of a complemented
    /// mask like `x &= ~0x400`.
    fn bitwise_context(&self, tokens: &[Token<'_>], index: usize) -> bool {
        let before = index
            .checked_sub(1)
            .map(|j| &tokens[j])
            .filter(|t| !t.is_punct(&["~"]))
            .or_else(|| index.checked_sub(2).map(|j| &tokens[j]));
        let after = tokens.get(index + 1);
        matches!(before, Some(t) if t.is_punct(&BITWISE_OPERATORS))
            || matches!(after, Some(t) if t.is_punct(&BITWISE_OPERATORS))
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
}

/// The decompiled lines a finding was read from, joined for evidence.
fn evidence(body: &str, lines: &BTreeSet<usize>) -> String {
    lines
        .iter()
        .filter_map(|line| body.lines().nth(line - 1))
        .map(str::trim)
        .collect::<Vec<&str>>()
        .join(" ")
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
            "0x600 and 0x300 are not single bits"
        );
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
}
