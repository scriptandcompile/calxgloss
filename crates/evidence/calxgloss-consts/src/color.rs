//! Color/RGB constant grouping.
//!
//! The frequency pass already tallies every literal the decompiled
//! bodies carry; this module reads that same tally for a shape it
//! throws away — *which tallied values are color-shaped*. A palette
//! of `0xRRGGBB` literals scattered across the program reads as
//! nothing today; grouped, it is one claim the scan can make: these
//! values are colors, and the translation should name them.
//!
//! The reading is pure and adds no Ghidra round trips:
//! [`color_palette`] walks the program-wide tally the engine built
//! during its single pass and reports at most one [`ColorConstant`]
//! record for the whole binary.
//!
//! The gates are the honesty bar: a qualifying literal fits in 24
//! bits — an `0xRRGGBB`-shaped value — and is not a power of two, so
//! flag bits are never read as colors; and the binary must show at
//! least two distinct qualifying values, since a lone `0x123456` may
//! be an offset and claims nothing. There is no color-name matching:
//! the claim is "these are colors", never "this one is red".

use std::collections::BTreeSet;

use crate::frequency::{ConstantOccurrences, ProgramTally};
use crate::types::{ColorConstant, Confidence};

/// The fixed confidence of a palette finding: at the named-constant
/// tier (60) — the color shape is as suggestive as a repeated
/// literal, no stronger; the claim is only "these are colors".
const COLOR_CONFIDENCE: u8 = 60;

/// The color shape's ceiling: an `0xRRGGBB` value fits in 24 bits;
/// anything wider — a mask, a pointer-sized magic — is no one's
/// color.
const MAX_COLOR_VALUE: u64 = 0x00FF_FFFF;

/// The honesty floor: a lone color-shaped literal may be an offset
/// and claims nothing; only two distinct qualifying values, side by
/// side in one binary, read as a palette.
const MIN_PALETTE_VALUES: usize = 2;

/// The program's one palette finding, if the tally holds one: the
/// distinct color-shaped values ascending, the functions they appear
/// in ascending, and at most one record per binary. Fewer than two
/// distinct qualifying values claim nothing.
pub(crate) fn color_palette(tally: &ProgramTally) -> Option<ColorConstant> {
    let qualified: Vec<(&u64, &ConstantOccurrences)> = tally
        .iter()
        .filter(|(value, _)| **value <= MAX_COLOR_VALUE && !value.is_power_of_two())
        .collect();
    if qualified.len() < MIN_PALETTE_VALUES {
        return None;
    }
    let values: Vec<u64> = qualified.iter().map(|(value, _)| **value).collect();
    let mut functions: BTreeSet<String> = BTreeSet::new();
    for (_, occurrences) in &qualified {
        functions.extend(occurrences.functions.iter().cloned());
    }
    Some(ColorConstant {
        suggestion: values
            .iter()
            .map(|value| format!("const COLOR_{value:#x}: u32 = {value:#x};"))
            .collect::<Vec<String>>()
            .join(" "),
        confidence: Confidence::new(COLOR_CONFIDENCE),
        values,
        functions: functions.into_iter().collect(),
        evidence: qualified
            .iter()
            .map(|(value, occurrences)| {
                format!(
                    "{value:#x} used {} times in {}",
                    occurrences.count,
                    occurrences
                        .functions
                        .iter()
                        .cloned()
                        .collect::<Vec<String>>()
                        .join(", ")
                )
            })
            .collect::<Vec<String>>()
            .join("; "),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tally(entries: &[(&str, &[u64])]) -> ProgramTally {
        let mut tally = ProgramTally::new();
        for (function, values) in entries {
            for value in *values {
                let entry = tally.entry(*value).or_default();
                entry.count += 1;
                entry.functions.insert((*function).to_string());
            }
        }
        tally
    }

    #[test]
    fn a_qualifying_palette_groups_into_one_finding() {
        // Two color-shaped literals across two functions: the tally
        // groups into one palette record naming both values and both
        // functions.
        let palette = color_palette(&tally(&[
            ("FUN_18003ab00", &[0x123456]),
            ("FUN_18003e750", &[0xff00ff]),
        ]))
        .expect("two color-shaped values make a palette");
        assert_eq!(palette.values, vec![0x123456, 0xff00ff]);
        assert_eq!(
            palette.functions,
            vec!["FUN_18003ab00".to_string(), "FUN_18003e750".to_string()]
        );
    }

    #[test]
    fn over_24_bit_values_are_never_read_as_colors() {
        // A 24-bit cap is the color shape: an `0xRRGGBB` value fits,
        // a wider literal — a mask, a pointer-sized magic — is no
        // one's color, and two wide values alone make no palette.
        let palette = color_palette(&tally(&[
            ("FUN_18003ab00", &[0x123456, 0x100_0000]),
            ("FUN_18003e750", &[0xff00ff, 0xdeadbeef]),
        ]))
        .expect("the two 24-bit values still make a palette");
        assert_eq!(
            palette.values,
            vec![0x123456, 0xff00ff],
            "the wide values stay out"
        );

        let wide_only = color_palette(&tally(&[
            ("FUN_18003ab00", &[0x100_0000]),
            ("FUN_18003e750", &[0xdeadbeef]),
        ]));
        assert!(wide_only.is_none(), "wide values claim no palette");
    }

    #[test]
    fn power_of_two_values_are_never_read_as_colors() {
        // Flag bits are not colors: a power-of-two literal joining a
        // qualifying pair stays out of the palette, and two
        // power-of-two values alone make no palette at all.
        let palette = color_palette(&tally(&[
            ("FUN_18003ab00", &[0x123456, 0x400]),
            ("FUN_18003e750", &[0xff00ff, 0x100, 0x100000]),
        ]))
        .expect("the two qualifying values still make a palette");
        assert_eq!(
            palette.values,
            vec![0x123456, 0xff00ff],
            "the flag bits stay out"
        );

        let flags_only = color_palette(&tally(&[
            ("FUN_18003ab00", &[0x100, 0x400]),
            ("FUN_18003e750", &[0x800]),
        ]));
        assert!(flags_only.is_none(), "flag bits claim no palette");
    }

    #[test]
    fn a_single_distinct_value_claims_nothing() {
        // The honesty floor: one color-shaped literal — even used
        // many times across many functions — may be an offset, and a
        // value seen twice is still one distinct value.
        let palette = color_palette(&tally(&[
            ("FUN_18003ab00", &[0x123456, 0x123456]),
            ("FUN_18003e750", &[0x123456]),
        ]));
        assert!(palette.is_none(), "one distinct value claims nothing");
        assert!(
            color_palette(&tally(&[("FUN_18003ab00", &[0x123456])])).is_none(),
            "an empty or single-value tally claims nothing"
        );
        assert!(color_palette(&ProgramTally::new()).is_none());
    }

    #[test]
    fn the_value_list_is_sorted_and_deduplicated() {
        // One palette per binary: a value seen in several functions
        // appears once in the value list, and the list reads
        // ascending however the tally was filled — two scans of one
        // program diff cleanly.
        let palette = color_palette(&tally(&[
            ("FUN_18003e750", &[0xff00ff, 0x123456]),
            ("FUN_18003ab00", &[0x0000ff, 0xff00ff]),
        ]))
        .expect("three distinct color-shaped values make a palette");
        assert_eq!(palette.values, vec![0x0000ff, 0x123456, 0xff00ff]);
    }

    #[test]
    fn the_functions_list_is_ascending_and_covers_every_color() {
        // The record names every function any palette value appears
        // in — the union across the colors — ascending, each
        // function once however many colors it uses.
        let palette = color_palette(&tally(&[
            ("FUN_18003e750", &[0xff00ff, 0x123456]),
            ("FUN_18003ab00", &[0x0000ff, 0xff00ff]),
        ]))
        .expect("the tally makes a palette");
        assert_eq!(
            palette.functions,
            vec!["FUN_18003ab00".to_string(), "FUN_18003e750".to_string()]
        );
    }

    #[test]
    fn the_record_suggests_named_colors_and_keeps_the_palette_as_evidence() {
        // The claim's shape: a named `const` per color in the
        // suggestion, the per-value usage summary as evidence, and
        // the fixed confidence at the named-constant tier.
        let palette = color_palette(&tally(&[
            ("FUN_18003ab00", &[0x123456, 0x123456]),
            ("FUN_18003e750", &[0xff00ff]),
        ]))
        .expect("the tally makes a palette");
        assert_eq!(
            palette.suggestion,
            "const COLOR_0x123456: u32 = 0x123456; const COLOR_0xff00ff: u32 = 0xff00ff;"
        );
        assert_eq!(
            palette.evidence,
            "0x123456 used 2 times in FUN_18003ab00; 0xff00ff used 1 times in FUN_18003e750"
        );
        assert_eq!(palette.confidence, Confidence::new(60));
    }

    #[test]
    fn two_scans_of_one_tally_group_identically() {
        // Determinism: the same tally always renders the same
        // palette, so a rescan diffs cleanly.
        let program = tally(&[
            ("FUN_18003ab00", &[0x123456, 0xff00ff, 0x400]),
            ("FUN_18003e750", &[0x0000ff]),
        ]);
        let first = color_palette(&program).expect("the tally makes a palette");
        let second = color_palette(&program).expect("the tally makes a palette");
        assert_eq!(first, second);
    }
}
