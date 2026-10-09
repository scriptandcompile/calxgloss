//! Shared JSON persistence plumbing for the workspace analysis artifacts.
//!
//! Every engine crate files its findings under the workspace analysis
//! directory as pretty-printed JSON documents — the type database and call
//! graph (one document per binary), the run logs (one fixed file each).
//! The mechanics were hand-written once per crate: create the directory
//! chain, `serde_json::to_string_pretty`, `fs::write`, read back, parse,
//! and tell a missing file apart from a corrupt one. This module holds
//! them once.
//!
//! Two layers:
//!
//! - [`save_json`] / [`load_json`] — the mechanics for one named file, plus
//!   [`analysis_dir`] for the `re/analysis/` convention.
//! - [`JsonStore<T>`] — a directory of per-key documents on top of those,
//!   for persistors that file one document per binary.
//!
//! Each persistor (`TypeDatabasePersistor`, `CallGraphPersistor`, the
//! analysis log loggers) keeps its own public API and wraps one of these.
//! That persistor API is the seam: it is document-oriented and storage-
//! agnostic, so a different backend (e.g. SQLite) replaces the store inside
//! a persistor without touching any caller. No shared store *trait* is
//! defined yet — with JSON as the only backend its shape would be guesswork,
//! and a row-oriented backend wants different granularity (incremental
//! queries, transactions) than whole-document save/load. Introduce the
//! trait when a second real backend exists to shape it.

use std::marker::PhantomData;
use std::path::{Path, PathBuf};

use serde::{Serialize, de::DeserializeOwned};
use thiserror::Error;

/// Errors from the shared JSON persistence helpers.
///
/// Persistors map these onto their own error types (a `From` impl for the
/// ones with a `thiserror` enum; `?` converts them for `anyhow` callers).
#[derive(Debug, Error)]
pub enum PersistError {
    /// No document is persisted at the requested path.
    #[error("no document persisted at {}", .path.display())]
    NotFound { path: PathBuf },

    /// Reading, writing, or creating the document's directory failed.
    #[error("I/O error for {}: {source}", .path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// The document exists but is not valid JSON for the expected type.
    #[error("invalid JSON in {}: {source}", .path.display())]
    Json {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

/// The shared analysis directory convention: `{workspace}/re/analysis`.
///
/// Every artifact the harness persists is filed under this directory —
/// directly (the run logs) or in a per-engine subdirectory (`typesdb/`).
pub fn analysis_dir(workspace: impl AsRef<Path>) -> PathBuf {
    workspace.as_ref().join("re").join("analysis")
}

/// Serializes `value` as pretty JSON and writes it to `path`.
///
/// Creates the parent directory chain if it does not exist; a previous
/// document at `path` is replaced.
pub fn save_json<T: Serialize>(path: &Path, value: &T) -> Result<(), PersistError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|source| PersistError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    }

    let json = serde_json::to_string_pretty(value).map_err(|source| PersistError::Json {
        path: path.to_path_buf(),
        source,
    })?;
    std::fs::write(path, json).map_err(|source| PersistError::Io {
        path: path.to_path_buf(),
        source,
    })
}

/// Reads the JSON document at `path` back into a `T`.
///
/// A missing file is [`PersistError::NotFound`]; a file that does not parse
/// as `T` is [`PersistError::Json`].
pub fn load_json<T: DeserializeOwned>(path: &Path) -> Result<T, PersistError> {
    if !path.is_file() {
        return Err(PersistError::NotFound {
            path: path.to_path_buf(),
        });
    }

    let json = std::fs::read_to_string(path).map_err(|source| PersistError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    serde_json::from_str(&json).map_err(|source| PersistError::Json {
        path: path.to_path_buf(),
        source,
    })
}

/// A directory of per-key JSON documents, one file per key.
///
/// The default naming files key `k` as `k.json`; [`with_naming`](Self::with_naming)
/// takes any key→file-name rule (e.g. `{key}_call_graph.json`). The store
/// knows nothing about the document's fields — the persistor wrapping it
/// picks the key (usually the binary name) and keeps its own logging and
/// error type.
///
/// # Example
///
/// ```no_run
/// use calxgloss_types::persist::JsonStore;
/// use serde::{Deserialize, Serialize};
///
/// #[derive(Serialize, Deserialize)]
/// struct Report { binary: String }
///
/// # fn main() -> Result<(), calxgloss_types::persist::PersistError> {
/// let store = JsonStore::<Report>::new("re/analysis/reports");
/// store.save("eqmain.dll", &Report { binary: "eqmain.dll".into() })?;
/// let report = store.load("eqmain.dll")?;
/// # Ok(())
/// # }
/// ```
pub struct JsonStore<T> {
    dir: PathBuf,
    name_for: Box<dyn Fn(&str) -> String + Send + Sync>,
    _doc: PhantomData<T>,
}

impl<T> JsonStore<T> {
    /// Creates a store filing documents directly under `dir` as `{key}.json`.
    pub fn new(dir: impl AsRef<Path>) -> Self {
        Self::with_naming(dir, |key| format!("{key}.json"))
    }

    /// Creates a store filing documents under `dir` with names from `name_for`.
    pub fn with_naming(
        dir: impl AsRef<Path>,
        name_for: impl Fn(&str) -> String + Send + Sync + 'static,
    ) -> Self {
        Self {
            dir: dir.as_ref().to_path_buf(),
            name_for: Box::new(name_for),
            _doc: PhantomData,
        }
    }

    /// The directory documents are filed under.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Returns the path the document for `key` is filed under.
    pub fn path_for(&self, key: &str) -> PathBuf {
        self.dir.join((self.name_for)(key))
    }

    /// Whether a document is persisted for `key`.
    pub fn exists(&self, key: &str) -> bool {
        self.path_for(key).is_file()
    }
}

impl<T: Serialize + DeserializeOwned> JsonStore<T> {
    /// Saves `value` as the document for `key`, replacing any previous one.
    pub fn save(&self, key: &str, value: &T) -> Result<(), PersistError> {
        save_json(&self.path_for(key), value)
    }

    /// Loads the document persisted for `key`.
    pub fn load(&self, key: &str) -> Result<T, PersistError> {
        load_json(&self.path_for(key))
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Doc {
        binary: String,
        count: u32,
    }

    fn doc(binary: &str) -> Doc {
        Doc {
            binary: binary.to_string(),
            count: 3,
        }
    }

    #[test]
    fn analysis_dir_appends_the_convention() {
        assert_eq!(
            analysis_dir("/workspace"),
            PathBuf::from("/workspace").join("re").join("analysis")
        );
    }

    #[test]
    fn save_json_creates_parents_and_writes_pretty_json() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("nested").join("deep").join("doc.json");

        save_json(&path, &doc("eqmain.dll")).unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        assert!(
            text.contains("\n  \"binary\""),
            "expected pretty JSON: {text}"
        );
    }

    #[test]
    fn save_then_load_round_trips() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("doc.json");

        save_json(&path, &doc("eqmain.dll")).unwrap();
        let loaded: Doc = load_json(&path).unwrap();

        assert_eq!(loaded, doc("eqmain.dll"));
    }

    #[test]
    fn load_json_of_a_missing_file_names_the_path() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("missing.json");

        let err = load_json::<Doc>(&path).unwrap_err();

        assert!(matches!(&err, PersistError::NotFound { path: p } if *p == path));
        assert!(err.to_string().contains("missing.json"));
    }

    #[test]
    fn load_json_of_a_corrupt_file_is_a_json_error() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("corrupt.json");
        std::fs::write(&path, "{ not json").unwrap();

        assert!(matches!(
            load_json::<Doc>(&path),
            Err(PersistError::Json { .. })
        ));
    }

    #[test]
    fn json_store_files_documents_as_key_json_by_default() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = JsonStore::<Doc>::new(dir.path());

        assert_eq!(
            store.path_for("eqmain.dll"),
            dir.path().join("eqmain.dll.json")
        );
        assert!(!store.exists("eqmain.dll"));

        store.save("eqmain.dll", &doc("eqmain.dll")).unwrap();

        assert!(store.exists("eqmain.dll"));
        assert_eq!(store.load("eqmain.dll").unwrap(), doc("eqmain.dll"));
    }

    #[test]
    fn json_store_with_naming_applies_the_custom_rule() {
        let dir = tempfile::TempDir::new().unwrap();
        let store =
            JsonStore::<Doc>::with_naming(dir.path(), |key| format!("{key}_call_graph.json"));

        assert_eq!(
            store.path_for("eqmain.dll"),
            dir.path().join("eqmain.dll_call_graph.json")
        );

        store.save("eqmain.dll", &doc("eqmain.dll")).unwrap();

        assert!(dir.path().join("eqmain.dll_call_graph.json").is_file());
        assert_eq!(store.load("eqmain.dll").unwrap(), doc("eqmain.dll"));
    }

    #[test]
    fn json_store_saves_replace_the_previous_document() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = JsonStore::<Doc>::new(dir.path());
        store.save("eqmain.dll", &doc("eqmain.dll")).unwrap();

        let fresh = Doc {
            binary: "eqmain.dll".into(),
            count: 9,
        };
        store.save("eqmain.dll", &fresh).unwrap();

        assert_eq!(store.load("eqmain.dll").unwrap(), fresh);
    }

    #[test]
    fn json_store_keys_stay_independent() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = JsonStore::<Doc>::new(dir.path());
        store.save("eqmain.dll", &doc("eqmain.dll")).unwrap();
        store.save("renderer.dll", &doc("renderer.dll")).unwrap();

        assert_eq!(store.load("eqmain.dll").unwrap().binary, "eqmain.dll");
        assert_eq!(store.load("renderer.dll").unwrap().binary, "renderer.dll");
        assert!(!store.exists("ghost.dll"));
    }

    #[test]
    fn json_store_creates_the_directory_chain_on_first_save() {
        let dir = tempfile::TempDir::new().unwrap();
        let nested = dir.path().join("re").join("analysis").join("typesdb");
        let store = JsonStore::<Doc>::new(&nested);

        store.save("eqmain.dll", &doc("eqmain.dll")).unwrap();

        assert!(nested.join("eqmain.dll.json").is_file());
    }
}
