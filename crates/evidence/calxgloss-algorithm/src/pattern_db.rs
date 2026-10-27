//! Dynamic pattern database: one JSON document holding the pattern sets
//! a scan reads against.
//!
//! The recognizable algorithm shapes normally live in the built-in
//! standard sets — `cfg_patterns::default_patterns` and its two
//! siblings. An operator who wants to teach the scan a new sort variant
//! or callback contract should not have to edit Rust and recompile. A
//! [`PatternDatabase`] is one JSON document with a section per
//! detector; a scan configured from it reads the file's sets instead of
//! the standard ones, whole.
//!
//! The entry format is exactly the existing serde shape of the pattern
//! types — [`AlgorithmPattern`], [`StringSignature`],
//! [`CallbackPattern`], and [`CorrelationRelationship`] — with one
//! addition each: an optional [`confidence`](AlgorithmPattern::confidence)
//! per entry that overrides the detector's standard score in
//! resolution, so a hand-tuned signature can outweigh a standard-score
//! claim for the same algorithm.
//! A section the document omits is an empty set: the database replaces
//! the standard sets whole rather than merging into them, so a file
//! that lists only control flow signatures leaves the string, callback,
//! and correlation detectors with nothing to read.
//!
//! [`load`](PatternDatabase::load) goes through the shared JSON
//! persistence layer. A missing, unreadable, or malformed file is a
//! hard error that names the path, so a typo never quietly reduces
//! recognition to a partial set — unknown section and entry field names
//! are rejected rather than ignored. Inside a well-formed entry the
//! lenient per-entry rules still apply: a regex that does not compile
//! matches nothing and excludes nothing, and the `{name}` placeholder
//! works exactly as in the built-ins.

use std::path::Path;

use calxgloss_types::persist::load_json;
use serde::{Deserialize, Serialize};

use crate::callback_db::CallbackPattern;
use crate::cross_function::CorrelationRelationship;
use crate::error::{AlgorithmError, Result};
use crate::string_hints::StringSignature;
use crate::types::AlgorithmPattern;

/// One JSON document holding all four detector sets a scan reads
/// against, in place of the built-in standard sets.
///
/// Each section holds its detector's entries in the order the file
/// lists them, and that order matters, as detector configuration order
/// always has: hint order follows configuration order, and a
/// resolution tie keeps the entry listed first. A section the document
/// omits reads as an empty set — the database replaces the standard
/// sets whole, never merges. An unknown section name is a hard error:
/// a typo in a section key would otherwise quietly reduce the scan to
/// a partial set.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatternDatabase {
    /// Control flow signatures the cfg matcher scans bodies against —
    /// the same [`AlgorithmPattern`] entries
    /// [`with_matcher`](crate::engine::AlgorithmEngine::with_matcher)
    /// would set.
    #[serde(default)]
    pub control_flow: Vec<AlgorithmPattern>,
    /// String signatures the string engine reads bodies and the string
    /// listing against — the same [`StringSignature`] entries
    /// [`with_string_engine`](crate::engine::AlgorithmEngine::with_string_engine)
    /// would set.
    #[serde(default)]
    pub string_signatures: Vec<StringSignature>,
    /// Callback contracts the callback database matches signatures and
    /// usage against — the same [`CallbackPattern`] entries
    /// [`with_callback_db`](crate::engine::AlgorithmEngine::with_callback_db)
    /// would set.
    #[serde(default)]
    pub callback_contracts: Vec<CallbackPattern>,
    /// Correlation relationships the cross-function detector matches
    /// the body-derived call map against — the same
    /// [`CorrelationRelationship`] entries
    /// [`with_cross_detector`](crate::engine::AlgorithmEngine::with_cross_detector)
    /// would set.
    #[serde(default)]
    pub correlation_patterns: Vec<CorrelationRelationship>,
}

impl PatternDatabase {
    /// Read the database document at `path`.
    ///
    /// The file is parsed through the shared JSON persistence layer. A
    /// missing, unreadable, or malformed document — including one with
    /// section or entry field names the types do not define — is a hard
    /// [`AlgorithmError::PatternDatabase`] that names the path: the run
    /// fails loudly instead of scanning with a quietly partial set.
    /// Entries keep the detectors' lenient rules: an uncompilable regex
    /// inside a well-formed entry matches nothing and excludes nothing.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        load_json(path).map_err(|source| AlgorithmError::PatternDatabase {
            path: path.to_path_buf(),
            source,
        })
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::callback_db::TypeHint;
    use crate::types::AlgorithmCategory;
    use tempfile::TempDir;

    /// A database with one entry per section, one of them with a
    /// per-entry confidence, so a round trip checks every section key
    /// and the added confidence field.
    fn database() -> PatternDatabase {
        PatternDatabase {
            control_flow: vec![AlgorithmPattern {
                exclude_patterns: vec![r"\bqsort\b".into()],
                min_lines: 12,
                confidence: Some(80),
                ..AlgorithmPattern::new(
                    "radix_sort",
                    AlgorithmCategory::Sorting,
                    ["for (", "bucket["],
                )
            }],
            string_signatures: vec![
                StringSignature::new("xxhash", AlgorithmCategory::Hashing, ["xxhash", "XXH"])
                    .case_insensitive(),
            ],
            callback_contracts: vec![
                CallbackPattern::new(
                    "my_qsort_compare",
                    AlgorithmCategory::Sorting,
                    [r"\bmy_qsort\b"],
                    2,
                )
                .body_patterns([r"[*&][^;]*<[^;]*[*&]"])
                .type_hints([TypeHint::return_value("int")]),
            ],
            correlation_patterns: vec![
                CorrelationRelationship::new(
                    "library_sort",
                    AlgorithmCategory::Sorting,
                    [r"\bmy_qsort\s*\("],
                )
                .with_partner_patterns([r"[*&][^;]*[^-](?:[<>]|==|!=)[^;]*[*&]"])
                .with_min_lines(4)
                .with_confidence(75),
            ],
        }
    }

    #[test]
    fn a_database_serde_round_trips_every_section() {
        let db = database();
        let json = serde_json::to_string(&db).expect("the database serializes");
        let back: PatternDatabase =
            serde_json::from_str(&json).expect("the serialized database reads back");
        assert_eq!(back, db);
    }

    #[test]
    fn the_document_keys_name_the_four_detector_sections() {
        // The file format is fixed here: one section per detector, and
        // each entry has exactly the serde shape of its pattern type.
        let json = serde_json::to_string(&database()).expect("the database serializes");
        let value: serde_json::Value =
            serde_json::from_str(&json).expect("the serialized database reads back");
        let mut keys: Vec<String> = value
            .as_object()
            .expect("the document is an object")
            .keys()
            .cloned()
            .collect();
        keys.sort();
        assert_eq!(
            keys,
            [
                "callback_contracts",
                "control_flow",
                "correlation_patterns",
                "string_signatures"
            ]
        );
        assert_eq!(value["control_flow"][0]["name"], "radix_sort");
        assert_eq!(value["control_flow"][0]["confidence"], 80);
        assert_eq!(value["string_signatures"][0]["case_insensitive"], true);
        assert_eq!(value["callback_contracts"][0]["param_count"], 2);
        assert_eq!(value["correlation_patterns"][0]["name"], "library_sort");
        assert_eq!(
            value["correlation_patterns"][0]["body_patterns"][0],
            r"\bmy_qsort\s*\("
        );
        assert_eq!(
            value["correlation_patterns"][0]["partner_patterns"][0],
            r"[*&][^;]*[^-](?:[<>]|==|!=)[^;]*[*&]"
        );
        assert_eq!(value["correlation_patterns"][0]["min_lines"], 4);
        assert_eq!(value["correlation_patterns"][0]["confidence"], 75);
    }

    #[test]
    fn an_entry_without_confidence_omits_it_and_reads_back_as_none() {
        let db = PatternDatabase {
            string_signatures: vec![StringSignature::new(
                "crc",
                AlgorithmCategory::Checksum,
                ["crc"],
            )],
            ..PatternDatabase::default()
        };
        let json = serde_json::to_string(&db).expect("the database serializes");
        assert!(!json.contains("\"confidence\""));
        let back: PatternDatabase =
            serde_json::from_str(&json).expect("the serialized database reads back");
        assert_eq!(back.string_signatures[0].confidence, None);
    }

    #[test]
    fn a_document_with_only_one_section_reads_the_others_empty() {
        // The database replaces the standard sets whole, so an omitted
        // section is an empty set, not the standard one.
        let json = r#"{
            "control_flow": [{
                "name": "crc_loop",
                "category": "checksum",
                "match_patterns": ["crc_table["],
                "min_lines": 5
            }]
        }"#;
        let db: PatternDatabase =
            serde_json::from_str(json).expect("a one-section document is well formed");
        assert_eq!(db.control_flow.len(), 1);
        assert_eq!(db.control_flow[0].name, "crc_loop");
        assert!(db.string_signatures.is_empty());
        assert!(db.callback_contracts.is_empty());
        assert!(db.correlation_patterns.is_empty());
    }

    #[test]
    fn an_empty_document_reads_as_four_empty_sets() {
        let db: PatternDatabase =
            serde_json::from_str("{}").expect("an empty document is well formed");
        assert!(db.control_flow.is_empty());
        assert!(db.string_signatures.is_empty());
        assert!(db.callback_contracts.is_empty());
        assert!(db.correlation_patterns.is_empty());
    }

    #[test]
    fn a_typo_in_a_section_name_fails_the_load_naming_the_path() {
        // This loud failure is what keeps a typo from quietly reducing
        // recognition to a partial set: a misspelled section is not an
        // omitted section, it is a malformed database.
        let dir = TempDir::new().expect("the temp dir is created");
        let path = dir.path().join("patterns.json");
        std::fs::write(
            &path,
            r#"{"control_flows": [{"name": "x", "category": "hashing", "match_patterns": ["h"], "min_lines": 1}]}"#,
        )
        .expect("the document is written");

        let error = PatternDatabase::load(&path).expect_err("a misspelled section fails the load");
        assert!(
            matches!(&error, AlgorithmError::PatternDatabase { path: p, .. } if p == &path),
            "{error}"
        );
        assert!(
            error.to_string().contains("patterns.json"),
            "the error names the file: {error}"
        );
    }

    #[test]
    fn a_typo_in_an_entry_field_name_fails_the_load_naming_the_path() {
        // Entries are as strict as sections: a field the entry type
        // does not define is a malformed file, not a field to ignore.
        let dir = TempDir::new().expect("the temp dir is created");
        let path = dir.path().join("patterns.json");
        std::fs::write(
            &path,
            r#"{"string_signatures": [{"name": "crc", "category": "checksum", "markerz": ["crc"]}]}"#,
        )
        .expect("the document is written");

        let error =
            PatternDatabase::load(&path).expect_err("a misspelled entry field fails the load");
        assert!(
            matches!(&error, AlgorithmError::PatternDatabase { path: p, .. } if p == &path),
            "{error}"
        );
        assert!(
            error.to_string().contains("patterns.json"),
            "the error names the file: {error}"
        );
    }

    #[test]
    fn a_typo_in_a_correlation_entry_field_name_fails_the_load_naming_the_path() {
        // The fourth section is as strict as the other three: a field
        // the relationship type does not define is a malformed file.
        let dir = TempDir::new().expect("the temp dir is created");
        let path = dir.path().join("patterns.json");
        std::fs::write(
            &path,
            r#"{"correlation_patterns": [{"name": "sort", "category": "sorting", "body_patternz": ["\\bqsort\\b"]}]}"#,
        )
        .expect("the document is written");

        let error = PatternDatabase::load(&path)
            .expect_err("a misspelled relationship field fails the load");
        assert!(
            matches!(&error, AlgorithmError::PatternDatabase { path: p, .. } if p == &path),
            "{error}"
        );
        assert!(
            error.to_string().contains("patterns.json"),
            "the error names the file: {error}"
        );
    }

    #[test]
    fn load_reads_a_document_from_disk() {
        let dir = TempDir::new().expect("the temp dir is created");
        let path = dir.path().join("patterns.json");
        let json = serde_json::to_string_pretty(&database()).expect("the database serializes");
        std::fs::write(&path, json).expect("the document is written");

        let loaded = PatternDatabase::load(&path).expect("a well-formed document loads");
        assert_eq!(loaded, database());
    }

    #[test]
    fn a_malformed_document_fails_the_load_naming_the_path() {
        let dir = TempDir::new().expect("the temp dir is created");
        let path = dir.path().join("patterns.json");
        std::fs::write(&path, "{ not json").expect("the broken document is written");

        let error = PatternDatabase::load(&path).expect_err("a malformed document fails the load");
        assert!(
            matches!(&error, AlgorithmError::PatternDatabase { path: p, .. } if p == &path),
            "{error}"
        );
        assert!(
            error.to_string().contains("patterns.json"),
            "the error names the file: {error}"
        );
    }

    #[test]
    fn a_document_of_the_wrong_shape_fails_the_load_naming_the_path() {
        // Valid JSON whose sections are not entry arrays is still a
        // malformed database: the run fails rather than scanning with
        // nothing.
        let dir = TempDir::new().expect("the temp dir is created");
        let path = dir.path().join("patterns.json");
        std::fs::write(&path, r#"{"control_flow": "not a list"}"#)
            .expect("the document is written");

        let error =
            PatternDatabase::load(&path).expect_err("a wrong-shaped document fails the load");
        assert!(
            matches!(error, AlgorithmError::PatternDatabase { .. }),
            "{error}"
        );
        assert!(error.to_string().contains("patterns.json"));
    }

    #[test]
    fn a_missing_file_fails_the_load_naming_the_path() {
        let dir = TempDir::new().expect("the temp dir is created");
        let path = dir.path().join("absent.json");

        let error = PatternDatabase::load(&path).expect_err("a missing file fails the load");
        assert!(
            matches!(error, AlgorithmError::PatternDatabase { .. }),
            "{error}"
        );
        assert!(error.to_string().contains("absent.json"));
    }
}
