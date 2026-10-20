//! Operator-supplied signature database: one JSON document carrying the
//! signature set a scan reads bodies against.
//!
//! The known-library shapes normally live in the built-in starter set —
//! [`default_signatures`](crate::signature::default_signatures) — but
//! an operator who wants to teach the matcher a new compiler or library
//! version should not have to edit Rust and recompile. A
//! [`SignatureDatabase`] is one JSON document carrying the set; a scan
//! configured from it reads the file's signatures instead of the
//! built-in set, whole.
//!
//! The entry format is exactly the existing serde shape of
//! [`LibmatchSignature`] — symbol, family, the required and forbidden
//! (match and exclude) bundles that gate callee references like "calls
//! `malloc`", the line-count floor, the optional per-entry confidence,
//! and the suggestion — and the document rides ADR-0023's
//! pattern-database contract whole: loading is strict
//! (`deny_unknown_fields` on the document and on every entry), and a
//! supplied file replaces the built-in set whole rather than merging
//! into it, so the file states exactly what the scan knows and a
//! misfiring built-in signature can be retired.
//!
//! A missing, unreadable, or malformed file is a hard error naming the
//! path, so a typo never silently degrades recognition to a partial
//! set. Inside a well-formed entry the lenient per-entry semantics
//! stay: a regex that will not compile can claim or veto nothing, and
//! the `{name}` placeholder keeps working exactly as in the built-ins.

use std::path::Path;

use calxgloss_types::persist::load_json;
use serde::{Deserialize, Serialize};

use crate::error::{LibmatchError, Result};
use crate::signature::LibmatchSignature;

/// One JSON document carrying the signature set a scan reads normalized
/// bodies against, in place of the built-in starter set.
///
/// Entries are kept in the order the file spells them, and that order
/// is load-bearing the way matcher configuration order always has
/// been: findings follow configuration order, and a resolution tie
/// keeps the entry listed first. An omitted `signatures` section reads
/// as an empty set — the database replaces the built-in set whole,
/// never merges. An unknown section name is a hard error: a typo in a
/// section key would otherwise silently degrade the scan to a partial
/// set.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureDatabase {
    /// The signatures the matcher reads normalized bodies against —
    /// the same [`LibmatchSignature`] entries
    /// [`with_signatures`](crate::matcher::LibmatchMatcher::with_signatures)
    /// would carry.
    #[serde(default)]
    pub signatures: Vec<LibmatchSignature>,
}

impl SignatureDatabase {
    /// Read the database document at `path`.
    ///
    /// The file is parsed through the shared JSON persistence plumbing,
    /// so a missing, unreadable, or malformed document — including one
    /// whose section or entry field names the types do not carry — is a
    /// hard [`LibmatchError::SignatureDatabase`] naming the path: the
    /// run fails loudly rather than scanning with a silently partial
    /// set. Entries keep the matcher's lenient semantics: an
    /// uncompilable regex matches nothing and vetoes nothing.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        load_json(path).map_err(|source| LibmatchError::SignatureDatabase {
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
    use crate::error::LibmatchError;
    use tempfile::TempDir;

    /// A database carrying two entries, one with a per-entry
    /// confidence and exclusions and one without, so a round trip
    /// pins the section key, the entry shape, and the optionals.
    fn database() -> SignatureDatabase {
        SignatureDatabase {
            signatures: vec![
                LibmatchSignature::new(
                    "memcpy",
                    crate::types::LibraryFamily::Crt,
                    [r"\*\([^;]*\) = \*\(", r"VAR = VAR \+ -1"],
                    "slice copy — `copy_nonoverlapping`",
                )
                .with_exclusions([r"\bif \(", r"\bmalloc\b"])
                .with_confidence(75),
                LibmatchSignature::new(
                    "strlen",
                    crate::types::LibraryFamily::Crt,
                    [r"while \(", r"!= '\\0'"],
                    "`str::len` / `CStr` count",
                ),
            ],
        }
    }

    #[test]
    fn a_database_serde_round_trips_its_section() {
        let db = database();
        let json = serde_json::to_string(&db).expect("the database serializes");
        let back: SignatureDatabase =
            serde_json::from_str(&json).expect("the serialized database reads back");
        assert_eq!(back, db);
    }

    #[test]
    fn the_document_key_names_the_signature_section() {
        // The file format is pinned: one `signatures` section, and the
        // entries carry exactly the signature type's serde shape.
        let json = serde_json::to_string(&database()).expect("the database serializes");
        let value: serde_json::Value =
            serde_json::from_str(&json).expect("the serialized database reads back");
        let keys: Vec<String> = value
            .as_object()
            .expect("the document is an object")
            .keys()
            .cloned()
            .collect();
        assert_eq!(keys, ["signatures"]);
        assert_eq!(value["signatures"][0]["symbol"], "memcpy");
        assert_eq!(value["signatures"][0]["family"], "crt");
        assert_eq!(value["signatures"][0]["confidence"], 75);
        assert_eq!(value["signatures"][0]["exclude_patterns"][1], r"\bmalloc\b");
        assert_eq!(value["signatures"][0]["min_lines"], 6);
        assert_eq!(value["signatures"][1]["symbol"], "strlen");
    }

    #[test]
    fn an_entry_without_confidence_omits_it_and_reads_back_as_none() {
        let db = SignatureDatabase {
            signatures: vec![LibmatchSignature::new(
                "strlen",
                crate::types::LibraryFamily::Crt,
                [r"while \("],
                "`str::len` count",
            )],
        };
        let json = serde_json::to_string(&db).expect("the database serializes");
        assert!(!json.contains("\"confidence\""));
        assert!(!json.contains("\"exclude_patterns\""));
        let back: SignatureDatabase =
            serde_json::from_str(&json).expect("the serialized database reads back");
        assert_eq!(back, db);
        assert_eq!(back.signatures[0].confidence, None);
    }

    #[test]
    fn an_empty_document_reads_as_an_empty_set() {
        // The database replaces the built-in set whole, so an omitted
        // section is an empty set, not the starter set: `{}` means the
        // scan knows nothing.
        let db: SignatureDatabase =
            serde_json::from_str("{}").expect("an empty document is well formed");
        assert!(db.signatures.is_empty());
    }

    #[test]
    fn a_typo_in_a_section_name_fails_the_load_naming_the_path() {
        // The loud failure is what keeps a typo from silently
        // degrading recognition: a misspelled section is not an
        // omitted section, it is a malformed database.
        let dir = TempDir::new().expect("the temp dir is created");
        let path = dir.path().join("signatures.json");
        std::fs::write(
            &path,
            r#"{"signaturez": [{"symbol": "x", "family": "crt", "match_patterns": ["w"], "min_lines": 1, "suggestion": "s"}]}"#,
        )
        .expect("the document is written");

        let error =
            SignatureDatabase::load(&path).expect_err("a misspelled section fails the load");
        assert!(
            matches!(&error, LibmatchError::SignatureDatabase { path: p, .. } if p == &path),
            "{error}"
        );
        assert!(
            error.to_string().contains("signatures.json"),
            "the error names the file: {error}"
        );
    }

    #[test]
    fn a_typo_in_an_entry_field_name_fails_the_load_naming_the_path() {
        // Entries are as strict as sections: a field the entry type
        // does not name is a malformed file, not a field to ignore.
        let dir = TempDir::new().expect("the temp dir is created");
        let path = dir.path().join("signatures.json");
        std::fs::write(
            &path,
            r#"{"signatures": [{"symbol": "strlen", "family": "crt", "match_patternz": ["while \\("], "min_lines": 6, "suggestion": "count"}]}"#,
        )
        .expect("the document is written");

        let error =
            SignatureDatabase::load(&path).expect_err("a misspelled entry field fails the load");
        assert!(
            matches!(&error, LibmatchError::SignatureDatabase { path: p, .. } if p == &path),
            "{error}"
        );
        assert!(
            error.to_string().contains("signatures.json"),
            "the error names the file: {error}"
        );
    }

    #[test]
    fn load_reads_a_document_from_disk() {
        let dir = TempDir::new().expect("the temp dir is created");
        let path = dir.path().join("signatures.json");
        let json = serde_json::to_string_pretty(&database()).expect("the database serializes");
        std::fs::write(&path, json).expect("the document is written");

        let loaded = SignatureDatabase::load(&path).expect("a well-formed document loads");
        assert_eq!(loaded, database());
    }

    #[test]
    fn a_malformed_document_fails_the_load_naming_the_path() {
        let dir = TempDir::new().expect("the temp dir is created");
        let path = dir.path().join("signatures.json");
        std::fs::write(&path, "{ not json").expect("the broken document is written");

        let error =
            SignatureDatabase::load(&path).expect_err("a malformed document fails the load");
        assert!(
            matches!(&error, LibmatchError::SignatureDatabase { path: p, .. } if p == &path),
            "{error}"
        );
        assert!(
            error.to_string().contains("signatures.json"),
            "the error names the file: {error}"
        );
    }

    #[test]
    fn a_document_of_the_wrong_shape_fails_the_load_naming_the_path() {
        // Valid JSON whose section is not an entry array is still a
        // malformed database: the run fails rather than scanning with
        // nothing.
        let dir = TempDir::new().expect("the temp dir is created");
        let path = dir.path().join("signatures.json");
        std::fs::write(&path, r#"{"signatures": "not a list"}"#).expect("the document is written");

        let error =
            SignatureDatabase::load(&path).expect_err("a wrong-shaped document fails the load");
        assert!(
            matches!(error, LibmatchError::SignatureDatabase { .. }),
            "{error}"
        );
        assert!(error.to_string().contains("signatures.json"));
    }

    #[test]
    fn a_missing_file_fails_the_load_naming_the_path() {
        let dir = TempDir::new().expect("the temp dir is created");
        let path = dir.path().join("absent.json");

        let error = SignatureDatabase::load(&path).expect_err("a missing file fails the load");
        assert!(
            matches!(error, LibmatchError::SignatureDatabase { .. }),
            "{error}"
        );
        assert!(error.to_string().contains("absent.json"));
    }
}
