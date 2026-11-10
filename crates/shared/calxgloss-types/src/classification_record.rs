//! The classification record: what a run recorded about one target
//! binary, filed by the `classify` command at `re/classify/{binary}.json`.
//!
//! This module owns the document the way the record tree rule asks. It
//! names where the record lives, and every consumer takes the reading
//! from here instead of joining the path and guessing the shape itself
//! (issue #457).
//!
//! The record keeps a lenient shape at read time: every field is
//! optional, because records filed before a field existed still read,
//! and a review surface must report what is actually on disk. A missing
//! document and a corrupt one come back as different named faults —
//! [`PersistError::NotFound`] and [`PersistError::Json`] — so a corrupt
//! document never reads as a clean absence.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::dll::DllCategory;
use crate::identity::BinaryIdentity;
use crate::persist::{PersistError, load_json, save_json};

/// The directory classification records are filed in:
/// `{workspace}/re/classify`.
pub fn classification_record_dir(workspace: impl AsRef<Path>) -> PathBuf {
    workspace.as_ref().join("re").join("classify")
}

/// The path of one binary's classification record inside the record tree.
///
/// The file name replaces `/` and `\` with `_` — the same sanitization
/// the `classify` command applied when it wrote the file — so a reader
/// that holds the binary's verbatim identity finds the writer's file.
pub fn classification_record_path(workspace: impl AsRef<Path>, binary: &BinaryIdentity) -> PathBuf {
    let sanitized: String = binary
        .as_str()
        .chars()
        .map(|c| match c {
            '/' | '\\' => '_',
            other => other,
        })
        .collect();
    classification_record_dir(workspace).join(format!("{sanitized}.json"))
}

/// One binary's classification record, as filed.
///
/// Every field reads as optional: a record filed before the field
/// existed loads with the field absent rather than failing the whole
/// document. A category string that is not one of the known categories
/// is a corrupt document, not a category-less one.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ClassificationRecord {
    /// The binary the record speaks for, named by the writer verbatim.
    #[serde(default)]
    pub binary: String,

    /// The strategy category the run chose for the binary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<DllCategory>,

    /// The recommended strategy as filed: a bare variant name
    /// (`"PalMapping"`), or a tagged object when the strategy carries
    /// data (`{"CrateReplacement": …}`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strategy: Option<serde_json::Value>,

    /// The exported-symbol count the classification was made against.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exports_count: Option<usize>,

    /// The imported-symbol count the classification was made against.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub imports_count: Option<usize>,

    /// The crate recommended as a replacement, when the strategy names
    /// one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crate_replacement: Option<String>,

    /// Whether the record marks the binary a known runtime library —
    /// never a translation target.
    #[serde(default)]
    pub known_runtime: bool,

    /// Why the classification was chosen, when the record stores one.
    /// Older records carry none, and the read invents nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Read one binary's classification record from the record tree.
///
/// The faults are named and distinct: no document at the record's path
/// is [`PersistError::NotFound`], and bytes that do not parse as a
/// record are [`PersistError::Json`]. A corrupt document never comes
/// back as a missing one, and neither reads as a clean classification.
pub fn read_classification_record(
    workspace: impl AsRef<Path>,
    binary: &BinaryIdentity,
) -> Result<ClassificationRecord, PersistError> {
    load_json(&classification_record_path(workspace, binary))
}

/// File one binary's classification record in the record tree, beside
/// the shared read (issue #467). The document is keyed by the record's
/// own `binary` name, sanitized exactly as [`classification_record_path`]
/// does, and written atomically like every other record document — so a
/// test that states what the record says cannot drift from the shape
/// the read expects.
pub fn save_classification_record(
    workspace: impl AsRef<Path>,
    record: &ClassificationRecord,
) -> Result<(), PersistError> {
    save_json(
        &classification_record_path(workspace, &(&record.binary).into()),
        record,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_classification_record_reads_as_missing() {
        // The obligation and unknown ledgers already name these two
        // faults apart (issue #417). No document at all is a missing
        // fault — never a clean reading, and never the fault a corrupt
        // document gets (issue #457).
        let workspace = tempfile::TempDir::new().expect("temp workspace");
        let err =
            read_classification_record(workspace.path(), &BinaryIdentity::new("game_logic.dll"))
                .expect_err("nothing has been filed");
        assert!(
            matches!(err, PersistError::NotFound { .. }),
            "absence is a named missing fault: {err}"
        );
    }

    #[test]
    fn a_corrupt_classification_record_stays_corrupt_and_never_reads_as_missing() {
        // The distinction the dashboard's lenient policy depends on
        // (issue #457): bytes that do not parse fail loudly as corrupt —
        // the same fault the ledgers raise, never the missing fault and
        // never an empty record.
        let workspace = tempfile::TempDir::new().expect("temp workspace");
        let binary = BinaryIdentity::new("game_logic.dll");
        let path = classification_record_path(workspace.path(), &binary);
        std::fs::create_dir_all(path.parent().expect("classify dir")).expect("create re/classify");
        std::fs::write(&path, "{ not json").expect("corrupt the document");

        let err = read_classification_record(workspace.path(), &binary)
            .expect_err("bytes that never parse");
        assert!(
            matches!(err, PersistError::Json { .. }),
            "corrupt is corrupt, never a clean absence: {err}"
        );
    }

    #[test]
    fn a_filed_record_reads_whole_through_the_shared_read() {
        // What the `classify` command files, the shared read hands back —
        // every field the record carries, read from the record tree path.
        let workspace = tempfile::TempDir::new().expect("temp workspace");
        let binary = BinaryIdentity::new("game_logic.dll");
        let path = classification_record_path(workspace.path(), &binary);
        std::fs::create_dir_all(path.parent().expect("classify dir")).expect("create re/classify");
        std::fs::write(
            &path,
            serde_json::json!({
                "binary": "game_logic.dll",
                "category": "KnownThirdParty",
                "strategy": {"CrateReplacement": {"crate_name": "fmod-rs"}},
                "exports_count": 12,
                "imports_count": 34,
                "crate_replacement": "fmod-rs",
                "known_runtime": false,
                "reason": "the import table matches fmod"
            })
            .to_string(),
        )
        .expect("file the record");

        let record =
            read_classification_record(workspace.path(), &binary).expect("the filed record reads");
        assert_eq!(
            record.binary, "game_logic.dll",
            "the writer's name rides through"
        );
        assert_eq!(
            record.category,
            Some(DllCategory::KnownThirdParty),
            "the category reads as a category"
        );
        assert_eq!(
            record.strategy,
            Some(serde_json::json!({"CrateReplacement": {"crate_name": "fmod-rs"}})),
            "a tagged strategy keeps its shape"
        );
        assert_eq!(record.exports_count, Some(12), "the counts read");
        assert_eq!(record.imports_count, Some(34), "the counts read");
        assert_eq!(record.crate_replacement.as_deref(), Some("fmod-rs"));
        assert!(!record.known_runtime, "the flag reads false, as filed");
        assert_eq!(
            record.reason.as_deref(),
            Some("the import table matches fmod")
        );
    }

    #[test]
    fn a_record_filed_through_the_shared_writer_reads_whole_through_the_shared_read() {
        // The writer lands beside the reader (issue #467): a test states
        // what the record says, and the matching shared read hands it back
        // with no fault — the fixture cannot drift from the read shape.
        let workspace = tempfile::TempDir::new().expect("temp workspace");
        let binary = BinaryIdentity::new("game_logic.dll");
        let record = ClassificationRecord {
            binary: "game_logic.dll".to_string(),
            category: Some(DllCategory::KnownThirdParty),
            strategy: Some(serde_json::json!({"CrateReplacement": {"crate_name": "fmod-rs"}})),
            exports_count: Some(12),
            imports_count: Some(34),
            crate_replacement: Some("fmod-rs".to_string()),
            known_runtime: false,
            reason: Some("the import table matches fmod".to_string()),
        };
        save_classification_record(workspace.path(), &record).expect("file the record");

        let read_back =
            read_classification_record(workspace.path(), &binary).expect("the filed record reads");
        assert_eq!(
            read_back, record,
            "what the writer files, the shared read hands back whole"
        );
    }

    #[test]
    fn unreadable_bytes_at_the_writer_path_read_as_a_corrupt_fault_naming_the_path() {
        // AC: unreadable bytes never read as an absent record (issue #467).
        let workspace = tempfile::TempDir::new().expect("temp workspace");
        let binary = BinaryIdentity::new("game_logic.dll");
        let path = classification_record_path(workspace.path(), &binary);
        std::fs::create_dir_all(path.parent().expect("classify dir")).expect("create re/classify");
        std::fs::write(&path, "\u{0}not a record").expect("file unreadable bytes");

        let err = read_classification_record(workspace.path(), &binary)
            .expect_err("bytes that never parse");
        match err {
            PersistError::Json { path: named, .. } => assert_eq!(named, path),
            other => panic!("unreadable bytes are a corrupt fault naming the path: {other}"),
        }
    }

    #[test]
    fn a_record_filed_before_the_optional_fields_existed_still_reads() {
        // The lenient shape is what older records depend on: a document
        // carrying only a category and a reason loads, with the rest
        // honestly absent rather than the whole document failing (issue #423).
        let workspace = tempfile::TempDir::new().expect("temp workspace");
        let binary = BinaryIdentity::new("managed_app.dll");
        let path = classification_record_path(workspace.path(), &binary);
        std::fs::create_dir_all(path.parent().expect("classify dir")).expect("create re/classify");
        std::fs::write(
            &path,
            serde_json::json!({
                "category": "DotNetManaged",
                "reason": "the plugin carries a managed runtime"
            })
            .to_string(),
        )
        .expect("file the partial record");

        let record =
            read_classification_record(workspace.path(), &binary).expect("a partial record reads");
        assert_eq!(record.category, Some(DllCategory::DotNetManaged));
        assert_eq!(
            record.reason.as_deref(),
            Some("the plugin carries a managed runtime")
        );
        assert_eq!(record.strategy, None, "an absent strategy stays absent");
        assert_eq!(record.exports_count, None, "an absent count stays absent");
        assert!(!record.known_runtime, "an absent flag reads false");
    }

    #[test]
    fn the_record_path_names_the_record_tree_location() {
        // One owner names the location, pinned verbatim (issue #457). The
        // file name follows the `classify` command's sanitization: `/` and
        // `\` become `_`, everything else stays verbatim.
        assert_eq!(
            classification_record_path("/ws", &BinaryIdentity::new("game_logic.dll")),
            PathBuf::from("/ws")
                .join("re")
                .join("classify")
                .join("game_logic.dll.json")
        );
        assert_eq!(
            classification_record_path("/ws", &BinaryIdentity::new("plugins\\dotnet/plugin.dll")),
            PathBuf::from("/ws")
                .join("re")
                .join("classify")
                .join("plugins_dotnet_plugin.dll.json")
        );
    }
}
