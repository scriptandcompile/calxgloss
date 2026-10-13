//! Binary classification overrides — steering one target binary's category
//! (issue #97, W2.8).
//!
//! A misclassified binary silently skews every downstream report and routes
//! the binary down the wrong strategy. The operator corrects it from the
//! dashboard instead of a CLI re-run: the override names a category from the
//! full [`DllCategory`] set, optionally a target crate for crate-replacement
//! mode, and carries the `known_runtime` flag — per the Evidence glossary
//! rule, a runtime-library classification is never a translation target, so
//! both the category and the flag must be honored wherever the classification
//! is consulted.
//!
//! Two layers, mirroring [`overrides`](crate::overrides):
//!
//! * [`BinaryClassificationOverride`] is the plain serde record for one
//!   binary, and [`ClassificationOverrides`] is the keyed map — the shape
//!   persisted under the workspace's record tree and the shape the
//!   classification endpoints report.
//! * [`ClassificationOverrideControl`] is the shared handle — `Arc`-backed
//!   and cheaply cloneable, the same pattern as [`OverrideControl`] and
//!   [`ScopeControl`](crate::ScopeControl). The web router's classification
//!   endpoints drive it; the analyzer reads it before classification-strategy
//!   dispatch.
//!
//! Records are keyed by binary identity — the filename verbatim, the same
//! identity [`BinaryIdentity`](crate::BinaryIdentity) spells. Unlike the
//! per-unit override keys, the match is exact: two spellings of a filename
//! are two different binaries until the operator steers them so. When the
//! handle is opened over a workspace ([`ClassificationOverrideControl::open`])
//! every mutation persists the map to `re/analysis/classification_overrides.json`,
//! so a restarted run honors the overrides without re-entering anything.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use crate::dll::DllCategory;
use crate::persist::{PersistError, analysis_dir, load_json, save_json};

/// One binary's classification override.
///
/// The category is required — an override that names no category is not a
/// decision. The target crate applies only in crate-replacement mode
/// (`MicrosoftSdk` / `KnownThirdParty`); the `known_runtime` flag carries
/// the glossary rule: a runtime-library classification is never a
/// translation target, whatever the category alone suggests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinaryClassificationOverride {
    /// The category the operator wants this binary to carry.
    pub category: DllCategory,
    /// Target crate for crate-replacement mode; ignored otherwise.
    #[serde(default)]
    pub crate_replacement: Option<String>,
    /// Whether the binary is a known runtime library — never a translation
    /// target. An override to `RuntimeLibrary` always implies this.
    #[serde(default)]
    pub known_runtime: bool,
}

impl BinaryClassificationOverride {
    /// Whether the override marks the binary as never a translation target —
    /// the glossary rule, spelled once: the `known_runtime` flag or a
    /// `RuntimeLibrary` category.
    pub fn is_runtime(&self) -> bool {
        self.known_runtime || self.category == DllCategory::RuntimeLibrary
    }

    /// The strategy label the category routes to — the same dispatch the
    /// analyzer's `Strategy` enum performs, spelled as the display strings
    /// (`"PalMapping"`, `"CrateReplacement"`, `"ReverseEngineer"`) the
    /// dashboard already matches on.
    pub fn strategy_label(&self) -> &'static str {
        match self.category {
            DllCategory::WindowsOs => "PalMapping",
            DllCategory::MicrosoftSdk | DllCategory::KnownThirdParty => "CrateReplacement",
            DllCategory::ProjectSpecific
            | DllCategory::UnknownThirdParty
            | DllCategory::RuntimeLibrary => "ReverseEngineer",
        }
    }

    /// Whether this override routes to crate replacement — the modes where
    /// a target crate name means something, the same dispatch
    /// [`Self::strategy_label`] spells.
    pub fn is_crate_replacement(&self) -> bool {
        matches!(
            self.category,
            DllCategory::MicrosoftSdk | DllCategory::KnownThirdParty
        )
    }

    /// The reason the analyzer records when this override is the decision
    /// in force — spelled once so every reader (the analyzer's artifact,
    /// the dashboard's binary detail panel) gives the same honest account:
    /// an overridden classification is the operator's decision, not a
    /// heuristic with a borrowed reason (issue #132).
    pub fn override_reason(&self) -> String {
        let label = serde_json::to_value(&self.category)
            .ok()
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_else(|| "unknown".to_string());
        format!("operator override — {label} (category set from the dashboard)")
    }
}

/// The persisted override map, keyed by binary identity (filename verbatim).
///
/// A `BTreeMap` keeps the serialized record deterministic, so two runs that
/// steered the same binaries write byte-identical files.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassificationOverrides {
    /// Binary filename (verbatim) → its override record.
    #[serde(default)]
    pub overrides: BTreeMap<String, BinaryClassificationOverride>,
}

/// The persisted location of the classification override records under a
/// workspace.
pub fn classification_override_records_path(workspace: impl AsRef<Path>) -> PathBuf {
    analysis_dir(workspace).join("classification_overrides.json")
}

/// Shared, cheaply-cloneable classification-override handle (issue #97, W2.8).
///
/// The web router's classification endpoints mutate it; the analyzer reads
/// it before classification-strategy dispatch. Clones share the state,
/// exactly like [`OverrideControl`](crate::OverrideControl). Built with
/// [`new`](ClassificationOverrideControl::new) (in-memory only) or
/// [`open`](ClassificationOverrideControl::open) (loads the workspace's
/// persisted records and re-persists every mutation).
#[derive(Debug, Clone)]
pub struct ClassificationOverrideControl {
    inner: Arc<Mutex<ClassificationOverrideState>>,
}

#[derive(Debug)]
struct ClassificationOverrideState {
    records: ClassificationOverrides,
    /// Workspace to persist records under; `None` means in-memory only.
    workspace: Option<PathBuf>,
}

impl ClassificationOverrideControl {
    /// An empty, in-memory-only handle — the shape a run without a
    /// workspace-backed override tree gets.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(ClassificationOverrideState {
                records: ClassificationOverrides::default(),
                workspace: None,
            })),
        }
    }

    /// Open a handle over a workspace: the persisted override map is loaded
    /// when present (a missing record is an empty map, not an error — the
    /// run simply has nothing overridden yet), and every mutation
    /// re-persists.
    pub fn open(workspace: impl AsRef<Path>) -> Self {
        let workspace = workspace.as_ref().to_path_buf();
        let records = match load_json(&classification_override_records_path(&workspace)) {
            Ok(records) => records,
            Err(PersistError::NotFound { .. }) => ClassificationOverrides::default(),
            Err(e) => {
                // tracing is not a dependency of calxgloss-types (see
                // dashboard/review.rs) — the corrupt record is named on
                // stderr, then treated as un-overridden.
                eprintln!(
                    "warning: corrupt classification override records, starting un-overridden: {e}"
                );
                ClassificationOverrides::default()
            }
        };
        Self {
            inner: Arc::new(Mutex::new(ClassificationOverrideState {
                records,
                workspace: Some(workspace),
            })),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, ClassificationOverrideState> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Persist the current records when the handle is workspace-backed.
    /// A mutation that cannot persist still reports the error — the caller
    /// (an endpoint handler) must not silently claim success on a change
    /// that will not survive a restart.
    fn persist(state: &ClassificationOverrideState) -> Result<(), PersistError> {
        let Some(ws) = state.workspace.as_ref() else {
            return Ok(());
        };
        save_json(&classification_override_records_path(ws), &state.records)?;
        Ok(())
    }

    /// The override recorded for a binary, if any. Keyed by binary identity
    /// — the filename verbatim, matched exactly.
    pub fn get(&self, binary: &str) -> Option<BinaryClassificationOverride> {
        self.lock().records.overrides.get(binary).cloned()
    }

    /// Apply an override to a binary — the record is replaced wholesale (the
    /// classification endpoints pass the operator's form through as-is).
    pub fn set(
        &self,
        binary: &str,
        record: BinaryClassificationOverride,
    ) -> Result<(), PersistError> {
        let mut state = self.lock();
        state.records.overrides.insert(binary.to_string(), record);
        Self::persist(&state)
    }

    /// Drop a binary's override. Idempotent — removing an absent override is
    /// not an error; the binary falls back to its heuristic classification.
    pub fn remove(&self, binary: &str) -> Result<(), PersistError> {
        let mut state = self.lock();
        if state.records.overrides.remove(binary).is_some() {
            return Self::persist(&state);
        }
        Ok(())
    }

    /// A snapshot of the whole override map.
    pub fn records(&self) -> ClassificationOverrides {
        self.lock().records.clone()
    }
}

impl Default for ClassificationOverrideControl {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn override_record(
        category: DllCategory,
        crate_replacement: Option<&str>,
        known_runtime: bool,
    ) -> BinaryClassificationOverride {
        BinaryClassificationOverride {
            category,
            crate_replacement: crate_replacement.map(str::to_string),
            known_runtime,
        }
    }

    fn temp_workspace() -> tempfile::TempDir {
        tempfile::tempdir().expect("temp workspace")
    }

    #[test]
    fn binary_classification_override_serde_round_trip() {
        let record = override_record(DllCategory::KnownThirdParty, Some("mlua"), false);
        let json = serde_json::to_string(&record).expect("serializes");
        let back: BinaryClassificationOverride = serde_json::from_str(&json).expect("deserializes");
        assert_eq!(back, record);
    }

    #[test]
    fn classification_overrides_map_serde_round_trip() {
        let mut overrides = ClassificationOverrides::default();
        overrides.overrides.insert(
            "fmod.dll".into(),
            override_record(DllCategory::RuntimeLibrary, None, true),
        );
        let json = serde_json::to_string(&overrides).expect("serializes");
        let back: ClassificationOverrides = serde_json::from_str(&json).expect("deserializes");
        assert_eq!(back, overrides);
    }

    #[test]
    fn partial_records_deserialize_with_defaults() {
        // The crate and the runtime flag are defaulted; the category is not.
        let record: BinaryClassificationOverride =
            serde_json::from_str(r#"{"category": "WindowsOs"}"#)
                .expect("category-only record deserializes");
        assert_eq!(record.category, DllCategory::WindowsOs);
        assert_eq!(record.crate_replacement, None);
        assert!(!record.known_runtime);
        let map: ClassificationOverrides =
            serde_json::from_str("{}").expect("empty map deserializes");
        assert!(map.overrides.is_empty());
    }

    #[test]
    fn runtime_rule_is_spelled_once() {
        // A RuntimeLibrary category is never a translation target, flag or no flag.
        assert!(override_record(DllCategory::RuntimeLibrary, None, false).is_runtime());
        // The flag alone also holds the rule.
        assert!(override_record(DllCategory::UnknownThirdParty, None, true).is_runtime());
        assert!(!override_record(DllCategory::ProjectSpecific, None, false).is_runtime());
    }

    #[test]
    fn strategy_label_follows_the_category_dispatch() {
        let label = |category: DllCategory| {
            BinaryClassificationOverride {
                category,
                crate_replacement: None,
                known_runtime: false,
            }
            .strategy_label()
        };
        assert_eq!(label(DllCategory::WindowsOs), "PalMapping");
        assert_eq!(label(DllCategory::MicrosoftSdk), "CrateReplacement");
        assert_eq!(label(DllCategory::KnownThirdParty), "CrateReplacement");
        assert_eq!(label(DllCategory::ProjectSpecific), "ReverseEngineer");
        assert_eq!(label(DllCategory::UnknownThirdParty), "ReverseEngineer");
        assert_eq!(label(DllCategory::RuntimeLibrary), "ReverseEngineer");
    }

    #[test]
    fn control_is_shared_across_clones() {
        let control = ClassificationOverrideControl::new();
        let clone = control.clone();
        clone
            .set(
                "fmod.dll",
                override_record(DllCategory::WindowsOs, None, false),
            )
            .expect("in-memory set");
        assert!(control.get("fmod.dll").is_some(), "clones share the state");
    }

    #[test]
    fn set_replaces_and_remove_drops_idempotently() {
        let control = ClassificationOverrideControl::new();
        control
            .set(
                "a.dll",
                override_record(DllCategory::ProjectSpecific, None, false),
            )
            .expect("in-memory set");
        control
            .set(
                "a.dll",
                override_record(DllCategory::WindowsOs, None, false),
            )
            .expect("in-memory replace");
        assert_eq!(
            control.get("a.dll").map(|o| o.category),
            Some(DllCategory::WindowsOs),
            "set replaces the record wholesale"
        );

        control.remove("a.dll").expect("removal is fine");
        assert!(control.get("a.dll").is_none());
        control
            .remove("a.dll")
            .expect("removing an absent override is not an error");
    }

    #[test]
    fn lookup_is_keyed_by_binary_identity_verbatim() {
        let control = ClassificationOverrideControl::new();
        control
            .set(
                "Fmod.dll",
                override_record(DllCategory::WindowsOs, None, false),
            )
            .expect("in-memory set");
        assert!(
            control.get("fmod.dll").is_none(),
            "the key is the filename verbatim — a different spelling is a different binary"
        );
        assert!(control.get("Fmod.dll").is_some());
    }

    #[test]
    fn records_persist_under_the_workspace_record_tree() {
        let ws = temp_workspace();
        let control = ClassificationOverrideControl::open(ws.path());
        control
            .set(
                "fmod.dll",
                override_record(DllCategory::KnownThirdParty, Some("fmod-rs"), false),
            )
            .expect("override persists");

        assert!(
            ws.path()
                .join("re/analysis/classification_overrides.json")
                .exists(),
            "the record file lives under the analysis tree"
        );

        // A restarted run honors what was entered.
        let reopened = ClassificationOverrideControl::open(ws.path());
        let record = reopened
            .get("fmod.dll")
            .expect("the override survives a restart");
        assert_eq!(record.category, DllCategory::KnownThirdParty);
        assert_eq!(record.crate_replacement.as_deref(), Some("fmod-rs"));
    }

    #[test]
    fn removal_survives_a_restart() {
        let ws = temp_workspace();
        let control = ClassificationOverrideControl::open(ws.path());
        control
            .set(
                "fmod.dll",
                override_record(DllCategory::RuntimeLibrary, None, true),
            )
            .expect("override persists");
        control.remove("fmod.dll").expect("removal persists");

        let reopened = ClassificationOverrideControl::open(ws.path());
        assert!(
            reopened.get("fmod.dll").is_none(),
            "the removal survives a restart"
        );
    }

    #[test]
    fn open_over_a_never_overridden_workspace_is_clean_not_an_error() {
        let ws = temp_workspace();
        let control = ClassificationOverrideControl::open(ws.path());
        assert!(control.records().overrides.is_empty());
        assert!(control.get("fmod.dll").is_none());
    }
}
