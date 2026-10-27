//! Protocol and format constant recovery.
//!
//! The frequency pass already tallies every literal the decompiled
//! bodies carry; this module reads that same tally for a fact the
//! repetition threshold throws away — *which tallied values are
//! recognised*. A literal equal to a well-known file-format magic or
//! sentinel — a PNG header, a `0xDEADBEEF` marker — is not just
//! another repeated number: it has a name and a protocol or format it
//! belongs to, and the scan can say so.
//!
//! The reading is pure and adds no analysis-engine reads:
//! [`protocol_constants`] walks the program-wide tally the scan built
//! during its single pass and reports one [`ProtocolConstant`] record
//! per tallied value that matches the built-in table. The match reads
//! the *full* tally before the frequency threshold applies, so a
//! magic-number check that appears exactly once in one parser still
//! reports. The repetition bar is a heuristic about arbitrary values,
//! not about recognised ones.
//!
//! The table is the honesty bar: it is small, built-in, and every
//! entry names a protocol or format a reviewer can check. A value
//! outside the table is untouched and stays an ordinary named
//! constant. A near-miss value — one bit off a known magic — claims
//! nothing. Each matched value produces exactly one finding: the
//! protocol claim is strictly stronger than the frequency-only
//! named-constant reading and carries the same usage data, so the
//! scan's frequency pass skips matched values.

use crate::frequency::{ConstantOccurrences, ProgramTally};
use crate::types::{Confidence, NamedConstant, ProtocolConstant};

/// The fixed confidence of a table-matched value: above the
/// frequency-only named-constant band (60) — the value is not merely
/// repeated, it is recognised, and the claim is checkable against the
/// table — and below the flag family's corroborated 80.
const PROTOCOL_CONFIDENCE: u8 = 75;

/// One built-in table entry: a well-known magic or sentinel value, the
/// constant name it suggests, and the protocol or format it belongs
/// to. The name is the spelling the suggestion renders the `const`
/// with. The protocol label is the claim a reviewer checks.
struct TableEntry {
    value: u64,
    name: &'static str,
    protocol: &'static str,
}

/// The built-in table of well-known protocol/format magics and
/// sentinels. The entries are listed in roughly value order, but that
/// order is decorative: [`protocol_constants`] walks the program-wide
/// tally, a `BTreeMap` keyed by value, so matched findings come out
/// in ascending value order regardless of how the table is arranged,
/// and two scans of one program name their constants identically.
///
/// The table is deliberately small: every entry is a value whose
/// meaning is settled enough to name — a file-format signature or a
/// sentinel the programming culture has agreed on — never a value
/// whose protocol reading would be a guess.
const PROTOCOL_TABLE: &[TableEntry] = &[
    TableEntry {
        value: 0x1f8b,
        name: "GZIP_MAGIC",
        protocol: "gzip compression format",
    },
    TableEntry {
        value: 0x4550,
        name: "PE_SIGNATURE",
        protocol: "PE binary format",
    },
    TableEntry {
        value: 0xc0ffee,
        name: "COFFEE_MARKER",
        protocol: "well-known sentinel value",
    },
    TableEntry {
        value: 0xffd8,
        name: "JPEG_SOI_MARKER",
        protocol: "JPEG image format",
    },
    TableEntry {
        value: 0x47494638,
        name: "GIF_MAGIC",
        protocol: "GIF image format",
    },
    TableEntry {
        value: 0x5045_0000,
        name: "PE_SIGNATURE",
        protocol: "PE binary format",
    },
    TableEntry {
        value: 0x504b0304,
        name: "ZIP_LOCAL_FILE_MAGIC",
        protocol: "ZIP archive format",
    },
    TableEntry {
        value: 0x7f454c46,
        name: "ELF_MAGIC",
        protocol: "ELF binary format",
    },
    TableEntry {
        value: 0x89504e47,
        name: "PNG_MAGIC",
        protocol: "PNG image format",
    },
    TableEntry {
        value: 0x8badf00d,
        name: "BAD_FOOD_WATCHDOG_MARKER",
        protocol: "iOS watchdog termination sentinel",
    },
    TableEntry {
        value: 0xbaadf00d,
        name: "BAADF00D_MARKER",
        protocol: "Microsoft uninitialised-memory marker",
    },
    TableEntry {
        value: 0xcafebabe,
        name: "JAVA_CLASS_MAGIC",
        protocol: "Java class file / Mach-O fat binary",
    },
    TableEntry {
        value: 0xdeadbeef,
        name: "DEAD_BEEF_MARKER",
        protocol: "debug sentinel value",
    },
    TableEntry {
        value: 0xfeedface,
        name: "MACHO_32_MAGIC",
        protocol: "Mach-O binary format",
    },
    TableEntry {
        value: 0xfeedfacf,
        name: "MACHO_64_MAGIC",
        protocol: "Mach-O binary format",
    },
];

/// The protocol-constant findings for the program-wide tally: one per
/// tallied value that matches the built-in table, ascending by value,
/// each carrying the table entry's name and protocol label beside the
/// usage data the tally holds.
///
/// The match reads the full tally before any frequency threshold
/// applies: a recognised value seen once in one function still
/// reports. A value outside the table is untouched here — the
/// frequency pass reads the same tally and reports it as an ordinary
/// named constant if it clears its own bar.
pub(crate) fn protocol_constants(tally: &ProgramTally) -> Vec<ProtocolConstant> {
    tally
        .iter()
        .filter_map(|(value, occurrences)| {
            PROTOCOL_TABLE
                .iter()
                .find(|entry| entry.value == *value)
                .map(|entry| render_constant(entry, occurrences))
        })
        .collect()
}

/// The record one table entry and its tally occurrences add up to:
/// the table's name and protocol label, the usage data, and a
/// suggestion naming the `const` after the table entry.
fn render_constant(entry: &TableEntry, occurrences: &ConstantOccurrences) -> ProtocolConstant {
    let functions: Vec<String> = occurrences.functions.iter().cloned().collect();
    ProtocolConstant {
        suggestion: NamedConstant::render_suggestion(Some(entry.name), entry.value),
        value: entry.value,
        name: entry.name.into(),
        protocol: entry.protocol.into(),
        count: occurrences.count,
        functions,
        confidence: Confidence::new(PROTOCOL_CONFIDENCE),
        evidence: format!(
            "{} — table match: {} ({})",
            occurrences.usage_evidence(entry.value),
            entry.name,
            entry.protocol,
        ),
    }
}

// ============================================================
// Tests
// ============================================================

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
    fn a_table_value_matches_on_a_single_use() {
        // The whole point of reading before the threshold: a
        // magic-number check in one parser, seen once, still reports.
        let findings = protocol_constants(&tally(&[("FUN_18003ab00", &[0xdeadbeef])]));
        assert_eq!(findings.len(), 1);
        let record = &findings[0];
        assert_eq!(record.value, 0xdeadbeef);
        assert_eq!(record.count, 1);
        assert_eq!(record.functions, vec!["FUN_18003ab00".to_string()]);
    }

    #[test]
    fn the_display_name_and_protocol_label_ride_the_finding() {
        // The claim is checkable: the record names the table entry and
        // the protocol or format it belongs to, and the suggestion
        // names the const after the entry.
        let findings = protocol_constants(&tally(&[("FUN_18003ab00", &[0x89504e47])]));
        assert_eq!(findings.len(), 1);
        let record = &findings[0];
        assert_eq!(record.name, "PNG_MAGIC");
        assert_eq!(record.protocol, "PNG image format");
        assert_eq!(record.suggestion, "const PNG_MAGIC: u32 = 0x89504e47;");
        assert!(
            record
                .evidence
                .contains("0x89504e47 used 1 times in FUN_18003ab00")
        );
        assert!(record.evidence.contains("PNG_MAGIC (PNG image format)"));
    }

    #[test]
    fn near_miss_values_claim_nothing() {
        // One bit off a known magic is not that magic: the table names
        // exact values, and an unknown value is no one's protocol.
        let findings = protocol_constants(&tally(&[(
            "FUN_18003ab00",
            &[
                0xdeadbeef ^ 1,
                0xcafebabe + 1,
                0x1f8c,
                0x89504e46,
                0xfeedface0,
            ],
        )]));
        assert!(findings.is_empty(), "a near miss is not a match");
    }

    #[test]
    fn one_finding_per_matched_value() {
        // Two recognised values in one program: two records, ascending
        // by value, each carrying its own usage data.
        let findings = protocol_constants(&tally(&[
            ("FUN_18003ab00", &[0xdeadbeef, 0x1f8b]),
            ("FUN_18003e750", &[0xdeadbeef]),
        ]));
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].value, 0x1f8b);
        assert_eq!(findings[0].name, "GZIP_MAGIC");
        assert_eq!(findings[1].value, 0xdeadbeef);
        assert_eq!(findings[1].count, 2);
        assert_eq!(
            findings[1].functions,
            vec!["FUN_18003ab00".to_string(), "FUN_18003e750".to_string()]
        );
    }

    #[test]
    fn the_matched_confidence_sits_above_the_frequency_only_tier() {
        // A recognised value is stronger evidence than a merely
        // repeated one: the fixed 75 beats the named constant's 60.
        let findings = protocol_constants(&tally(&[("FUN_18003ab00", &[0xcafebabe])]));
        assert_eq!(findings[0].confidence, Confidence::new(75));
        assert!(findings[0].confidence.value() > 60);
    }

    #[test]
    fn the_table_is_deterministic() {
        // Two scans of one tally name their constants identically, in
        // the same order — the persisted document diffs cleanly.
        let program = tally(&[
            ("FUN_18003ab00", &[0xcafebabe, 0x89504e47, 0x400]),
            ("FUN_18003e750", &[0x89504e47]),
        ]);
        let first = protocol_constants(&program);
        let second = protocol_constants(&program);
        assert_eq!(first, second);
        assert_eq!(
            first.iter().map(|record| record.value).collect::<Vec<_>>(),
            vec![0x89504e47, 0xcafebabe],
            "ascending by value, unrecognised values absent"
        );
    }
}
