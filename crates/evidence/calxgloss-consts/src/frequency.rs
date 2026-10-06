//! Repeated magic-number frequency analysis.
//!
//! [`FrequencyAnalyzer`] counts the integer literals used across the
//! whole program — the same decompiled bodies the per-function
//! detectors read — and reports the values used often enough and in
//! enough functions to be named constants rather than situational
//! literals. A value repeated across the program is a constant the
//! translation should name once instead of transliterating at every
//! use site.

use std::collections::{BTreeMap, BTreeSet};

use crate::tokenize::tokenize;
use crate::types::{Confidence, NamedConstant};

/// Where one literal has been seen: how many times, and in which
/// functions.
#[derive(Debug, Default, Clone)]
pub struct ConstantOccurrences {
    /// Total uses across the program.
    pub count: usize,
    /// The functions that use the value, ascending.
    pub functions: BTreeSet<String>,
}

/// The program-wide literal tally the analyzer reads: each value to
/// its occurrences. The engine builds it during the single scan pass,
/// one [`literals`](FrequencyAnalyzer::literals) call per body.
pub type ProgramTally = BTreeMap<u64, ConstantOccurrences>;

/// Counts integer literals across the program and reports the values
/// that read as named constants.
///
/// The analyzer is stateless configuration; [`with_default_thresholds`]
/// sets the standard bar — three or more uses across two or more
/// functions, with the trivially small values `0`, `1`, and `2`
/// excluded — and [`with_thresholds`](Self::with_thresholds) swaps it
/// whole.
#[derive(Debug, Clone)]
pub struct FrequencyAnalyzer {
    min_occurrences: usize,
    min_functions: usize,
    ignored: Vec<u64>,
}

impl FrequencyAnalyzer {
    /// An analyzer at the standard thresholds: at least three uses in
    /// at least two functions, ignoring `0`, `1`, and `2`.
    pub fn with_default_thresholds() -> Self {
        Self {
            min_occurrences: 3,
            min_functions: 2,
            ignored: vec![0, 1, 2],
        }
    }

    /// An analyzer that reports a value once it reaches
    /// `min_occurrences` uses in `min_functions` functions, skipping
    /// the values in `ignored`.
    pub fn with_thresholds(
        min_occurrences: usize,
        min_functions: usize,
        ignored: impl IntoIterator<Item = u64>,
    ) -> Self {
        Self {
            min_occurrences,
            min_functions,
            ignored: ignored.into_iter().collect(),
        }
    }

    /// The integer literals in one decompiled body that the analyzer
    /// counts — every literal value, repeats included, with the
    /// ignored small values already dropped.
    pub fn literals(&self, body: &str) -> Vec<u64> {
        tokenize(body)
            .into_iter()
            .filter_map(|token| token.int())
            .filter(|value| !self.ignored.contains(value))
            .collect()
    }

    /// The named-constant findings for the program-wide tally, most
    /// used first and ties by ascending value, so two scans of the
    /// same program list the constants in a stable order.
    ///
    /// A value becomes a finding at [`min_occurrences`](Self::min_occurrences)
    /// uses across [`min_functions`](Self::min_functions) functions:
    /// one function repeating a literal is a local habit, a value
    /// carried across the program is a constant.
    pub fn constants(&self, tally: &ProgramTally) -> Vec<NamedConstant> {
        let mut qualified: Vec<(&u64, &ConstantOccurrences)> = tally
            .iter()
            .filter(|(_, occurrences)| {
                occurrences.count >= self.min_occurrences
                    && occurrences.functions.len() >= self.min_functions
            })
            .collect();
        qualified.sort_by(|(value_a, a), (value_b, b)| {
            b.count.cmp(&a.count).then_with(|| value_a.cmp(value_b))
        });

        qualified
            .into_iter()
            .map(|(value, occurrences)| {
                let functions: Vec<String> = occurrences.functions.iter().cloned().collect();
                let ty = if *value > u64::from(u32::MAX) {
                    "u64"
                } else {
                    "u32"
                };
                NamedConstant {
                    value: *value,
                    count: occurrences.count,
                    functions,
                    suggestion: format!("const VALUE_{:#x}: {} = {:#x};", value, ty, value),
                    confidence: Confidence::new(60),
                    evidence: format!(
                        "{:#x} used {} times in {}",
                        value,
                        occurrences.count,
                        occurrences
                            .functions
                            .iter()
                            .cloned()
                            .collect::<Vec<String>>()
                            .join(", ")
                    ),
                }
            })
            .collect()
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Tally canned bodies the way the engine does: one
    /// [`literals`](FrequencyAnalyzer::literals) read per function.
    fn tally(entries: &[(&str, &[u64])]) -> ProgramTally {
        let analyzer = FrequencyAnalyzer::with_default_thresholds();
        let mut tally = ProgramTally::new();
        for (function, values) in entries {
            let body = format!(
                "  x = {};",
                values
                    .iter()
                    .map(|v| format!("{:#x}", v))
                    .collect::<Vec<String>>()
                    .join("; x = ")
            );
            for value in analyzer.literals(&body) {
                let entry = tally.entry(value).or_default();
                entry.count += 1;
                entry.functions.insert((*function).to_string());
            }
        }
        tally
    }

    #[test]
    fn a_value_used_three_times_in_two_functions_becomes_a_constant() {
        let tally = tally(&[
            ("FUN_18003ab00", &[0x400, 0x400]),
            ("FUN_18003e750", &[0x400]),
        ]);
        let constants = FrequencyAnalyzer::with_default_thresholds().constants(&tally);
        assert_eq!(constants.len(), 1);
        let constant = &constants[0];
        assert_eq!(constant.value, 0x400);
        assert_eq!(constant.count, 3);
        assert_eq!(
            constant.functions,
            vec!["FUN_18003ab00".to_string(), "FUN_18003e750".to_string()]
        );
        assert_eq!(constant.confidence, Confidence::new(60));
        assert_eq!(constant.suggestion, "const VALUE_0x400: u32 = 0x400;");
        assert!(constant.evidence.contains("0x400 used 3 times"));
    }

    #[test]
    fn two_uses_are_not_enough() {
        let tally = tally(&[("FUN_18003ab00", &[0x400]), ("FUN_18003e750", &[0x400])]);
        assert!(
            FrequencyAnalyzer::with_default_thresholds()
                .constants(&tally)
                .is_empty()
        );
    }

    #[test]
    fn three_uses_in_one_function_are_not_enough() {
        let tally = tally(&[("FUN_18003ab00", &[0x400, 0x400, 0x400])]);
        assert!(
            FrequencyAnalyzer::with_default_thresholds()
                .constants(&tally)
                .is_empty()
        );
    }

    #[test]
    fn trivial_small_values_are_never_constants() {
        let tally = tally(&[
            ("FUN_18003ab00", &[0, 1, 1, 2]),
            ("FUN_18003e750", &[0, 1, 2, 2]),
            ("FUN_18003ffff", &[0, 1, 2]),
        ]);
        assert!(
            FrequencyAnalyzer::with_default_thresholds()
                .constants(&tally)
                .is_empty()
        );
    }

    #[test]
    fn literals_ignore_string_contents_and_identifier_digits() {
        let analyzer = FrequencyAnalyzer::with_default_thresholds();
        assert_eq!(
            analyzer.literals(r#"  puts("size 1000"); local_40 = FUN_180000100(8);"#),
            vec![8]
        );
    }

    #[test]
    fn constants_sort_by_use_then_value() {
        let tally = tally(&[
            ("FUN_a", &[0x10, 0x20, 0x20, 0x20]),
            ("FUN_b", &[0x10, 0x10, 0x20]),
        ]);
        let constants = FrequencyAnalyzer::with_default_thresholds().constants(&tally);
        let values: Vec<u64> = constants.iter().map(|c| c.value).collect();
        assert_eq!(values, vec![0x20, 0x10]);
    }

    #[test]
    fn a_custom_threshold_reaches_the_analyzer() {
        let tally = tally(&[
            ("FUN_18003ab00", &[0x400, 0x400]),
            ("FUN_18003e750", &[0x400]),
        ]);
        let analyzer = FrequencyAnalyzer::with_thresholds(2, 1, [4, 8]);
        let constants = analyzer.constants(&tally);
        assert_eq!(constants.len(), 1);
        assert_eq!(constants[0].count, 3);
    }

    #[test]
    fn a_wide_literal_suggests_a_u64_const() {
        let mut tally = ProgramTally::new();
        let wide = 1u64 << 40;
        for name in ["FUN_a", "FUN_b"] {
            let entry = tally.entry(wide).or_default();
            entry.count += 2;
            entry.functions.insert(name.to_string());
        }
        let constants = FrequencyAnalyzer::with_default_thresholds().constants(&tally);
        assert_eq!(
            constants[0].suggestion,
            "const VALUE_0x10000000000: u64 = 0x10000000000;"
        );
    }
}
