//! Repeated magic-number frequency analysis.
//!
//! [`FrequencyAnalyzer`] counts the integer literals used across the
//! whole program, reading the same decompiled bodies the per-function
//! detectors read. It reports the values used often enough, and in
//! enough functions, to be named constants rather than one-off
//! literals at a use site. A value repeated across the program is a
//! constant the translation should name once, not copy out at every
//! use site.
//!
//! The report also carries the name the bodies gave the value, when
//! they gave it one. [`constants`](FrequencyAnalyzer::constants)
//! takes the context names the naming reading (`naming`) derived from
//! those same bodies, puts them on the records, and renders the named
//! `const` form into the suggestion.

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

impl ConstantOccurrences {
    /// The shared usage-evidence phrase for one value: `0x… used N
    /// times in FUN_a, FUN_b`. The three program-level readings —
    /// named constants, protocol constants, and color palettes — all
    /// render their evidence through it, each appending only its own
    /// distinct part on top.
    pub(crate) fn usage_evidence(&self, value: u64) -> String {
        format!(
            "{value:#x} used {} times in {}",
            self.count,
            self.functions
                .iter()
                .cloned()
                .collect::<Vec<String>>()
                .join(", ")
        )
    }
}

/// The program-wide literal tally the analyzer reads: each value to
/// its occurrences. The scan builds it during the single pass, one
/// [`literals`](FrequencyAnalyzer::literals) call per body.
pub type ProgramTally = BTreeMap<u64, ConstantOccurrences>;

/// Counts integer literals across the program and reports the values
/// that read as named constants.
///
/// The analyzer holds no scan state — only its threshold settings.
/// [`with_default_thresholds`](Self::with_default_thresholds) sets the
/// standard bar: three or more uses across two or more functions, with
/// the trivially small values `0`, `1`, and `2` excluded.
/// [`with_thresholds`](Self::with_thresholds) replaces the thresholds
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
    /// A value becomes a finding at `min_occurrences` uses across
    /// `min_functions` functions: one function repeating a literal is
    /// a local habit, a value used across the program is a constant.
    ///
    /// `names` holds the context names the naming reading derived from
    /// the same bodies (`naming::context_names`). A qualified value
    /// the bodies named gets that name on its record, and its
    /// suggestion renders the named `const` form. A value the bodies
    /// never named keeps the mechanical `VALUE_0x…` spelling. A name
    /// for a value that never qualified is ignored.
    pub fn constants(
        &self,
        tally: &ProgramTally,
        names: &BTreeMap<u64, String>,
    ) -> Vec<NamedConstant> {
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
                let name = names.get(value).cloned();
                NamedConstant {
                    suggestion: NamedConstant::render_suggestion(name.as_deref(), *value),
                    name,
                    value: *value,
                    count: occurrences.count,
                    functions,
                    confidence: Confidence::new(60),
                    evidence: occurrences.usage_evidence(*value),
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

    /// Tally canned bodies the way the scan does: one
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

    /// Canned context names the way the scan passes them over: the
    /// value-to-name map the naming reading built from the bodies,
    /// empty when the bodies named nothing.
    fn names(entries: &[(u64, &str)]) -> BTreeMap<u64, String> {
        entries
            .iter()
            .map(|(value, name)| (*value, (*name).to_string()))
            .collect()
    }

    #[test]
    fn the_usage_evidence_phrase_renders_the_value_count_and_functions() {
        let tally = tally(&[
            ("FUN_18003ab00", &[0x400, 0x400]),
            ("FUN_18003e750", &[0x400]),
        ]);
        let occurrences = tally.get(&0x400).expect("0x400 is in the tally");
        assert_eq!(
            occurrences.usage_evidence(0x400),
            "0x400 used 3 times in FUN_18003ab00, FUN_18003e750"
        );
    }

    #[test]
    fn a_value_used_three_times_in_two_functions_becomes_a_constant() {
        let tally = tally(&[
            ("FUN_18003ab00", &[0x400, 0x400]),
            ("FUN_18003e750", &[0x400]),
        ]);
        let constants = FrequencyAnalyzer::with_default_thresholds().constants(&tally, &names(&[]));
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
                .constants(&tally, &names(&[]))
                .is_empty()
        );
    }

    #[test]
    fn three_uses_in_one_function_are_not_enough() {
        let tally = tally(&[("FUN_18003ab00", &[0x400, 0x400, 0x400])]);
        assert!(
            FrequencyAnalyzer::with_default_thresholds()
                .constants(&tally, &names(&[]))
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
                .constants(&tally, &names(&[]))
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
        let constants = FrequencyAnalyzer::with_default_thresholds().constants(&tally, &names(&[]));
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
        let constants = analyzer.constants(&tally, &names(&[]));
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
        let constants = FrequencyAnalyzer::with_default_thresholds().constants(&tally, &names(&[]));
        assert_eq!(
            constants[0].suggestion,
            "const VALUE_0x10000000000: u64 = 0x10000000000;"
        );
    }

    #[test]
    fn a_context_name_from_the_bodies_names_the_constant() {
        // The naming reading's result for the same bodies reaches the
        // record: the name lands on the record and the suggestion
        // renders the named `const` form instead of the mechanical one.
        let tally = tally(&[
            ("FUN_18003ab00", &[0x280, 0x280]),
            ("FUN_18003e750", &[0x280]),
        ]);
        let constants = FrequencyAnalyzer::with_default_thresholds()
            .constants(&tally, &names(&[(0x280, "SIZE_0x280")]));
        assert_eq!(constants[0].name.as_deref(), Some("SIZE_0x280"));
        assert_eq!(constants[0].suggestion, "const SIZE_0x280: u32 = 0x280;");
    }

    #[test]
    fn a_value_the_bodies_never_named_keeps_the_mechanical_form() {
        // The scan never loses a qualified constant over a missing
        // name: a qualified value with no qualifying sighting still
        // lands, un-named and mechanically suggested.
        let tally = tally(&[
            ("FUN_18003ab00", &[0x400, 0x400]),
            ("FUN_18003e750", &[0x400]),
        ]);
        let constants = FrequencyAnalyzer::with_default_thresholds()
            .constants(&tally, &names(&[(0x280, "SIZE_0x280")]));
        assert_eq!(constants.len(), 1);
        assert_eq!(constants[0].value, 0x400);
        assert_eq!(constants[0].name, None);
        assert_eq!(constants[0].suggestion, "const VALUE_0x400: u32 = 0x400;");
    }
}
