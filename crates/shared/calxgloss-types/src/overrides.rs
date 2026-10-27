//! Per-unit reviewer overrides — the reviewer's decisions about one unit's
//! next attempt (issue #96, W2.7).
//!
//! A reviewer watching a live run can override how one unit is translated.
//! An override can force the context tier, when the automatic selector
//! handles it poorly. It can force the retry strategy, sending a failing
//! unit down a different recovery path. It can append custom failure hints:
//! what the reviewer knows about the function reaches the next attempt's
//! prompt. It can skip this single unit, so one hopeless function does not
//! block the rest of its binary's pass. And it can record reviewer notes,
//! which survive alongside the unit's justification.
//!
//! Two layers live here, mirroring [`scope`](crate::scope):
//!
//! * [`FunctionOverride`] is the plain serde record for one unit, and
//!   [`UnitOverrides`] is the keyed map. Both are the shape persisted under
//!   the workspace's record tree and the shape the override endpoints report.
//! * [`OverrideControl`] is the shared handle — `Arc`-backed and cheaply
//!   cloneable, the same pattern as [`ScopeControl`](crate::ScopeControl).
//!   The web router's override endpoints change it. The translator pipeline
//!   reads it in the translation context builder — for tier selection,
//!   retry-strategy selection, and hint append — and at queue selection
//!   (the skip flag).
//!
//! Records are keyed by unit key (`{binary}/{function}`, the same identity
//! [`UnitKey`](crate::UnitKey) describes). When the handle is opened over a
//! workspace ([`OverrideControl::open`]) every change saves the map to
//! `re/analysis/unit_overrides.json`, so a restarted run honors the
//! overrides without re-entering anything.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use crate::context_tier::ContextTier;
use crate::persist::{PersistError, analysis_dir, load_json, save_json};
use crate::retry_strategy::RetryStrategy;

/// One unit's reviewer override.
///
/// Every field defaults to "not overridden" — the automatic behavior a unit
/// with no override runs under. The retry-strategy override is the shared
/// [`RetryStrategy`] enum: the persisted snake_case labels are its serde
/// representation, so an unknown label is refused at deserialization and a
/// misspelled strategy can never be stored.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionOverride {
    /// Forced context tier — the automatic selector is bypassed.
    #[serde(default)]
    pub tier_override: Option<ContextTier>,
    /// Forced retry strategy — the automatic selection is bypassed.
    #[serde(default)]
    pub retry_strategy_override: Option<RetryStrategy>,
    /// Custom failure hints appended to the unit's prompts.
    #[serde(default)]
    pub custom_hints: Vec<String>,
    /// The unit leaves its binary's pass at the next queue selection.
    #[serde(default)]
    pub skip: bool,
    /// Reviewer notes — displayed alongside the unit's justification,
    /// never fed into a prompt.
    #[serde(default)]
    pub reviewer_notes: String,
}

impl FunctionOverride {
    /// Whether the record overrides nothing — what a removed override
    /// leaves behind.
    pub fn is_empty(&self) -> bool {
        self.tier_override.is_none()
            && self.retry_strategy_override.is_none()
            && self.custom_hints.is_empty()
            && !self.skip
            && self.reviewer_notes.is_empty()
    }
}

/// The persisted override map, keyed by unit key (`{binary}/{function}`).
///
/// A `BTreeMap` keeps the serialized record deterministic: two runs that
/// overrode the same units write byte-identical files.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnitOverrides {
    /// Unit key → its override record.
    #[serde(default)]
    pub overrides: BTreeMap<String, FunctionOverride>,
}

/// The unit key an override record is stored under.
pub fn unit_override_key(binary: &str, function: &str) -> String {
    format!("{binary}/{function}")
}

/// The persisted location of the override records under a workspace.
pub fn override_records_path(workspace: impl AsRef<Path>) -> PathBuf {
    analysis_dir(workspace).join("unit_overrides.json")
}

/// A shared, cheaply cloneable per-unit override handle (issue #96, W2.7).
///
/// The web router's override endpoints change it; the translator pipeline
/// reads it in the context builder and at queue selection. Clones share the
/// state, exactly like [`ScopeControl`](crate::ScopeControl). Build it with
/// [`new`](OverrideControl::new) (in-memory only, the plain CLI path) or
/// [`open`](OverrideControl::open) (loads the workspace's persisted records
/// and saves every later change).
#[derive(Debug, Clone)]
pub struct OverrideControl {
    inner: Arc<Mutex<OverrideState>>,
}

#[derive(Debug)]
struct OverrideState {
    records: UnitOverrides,
    /// Workspace to persist records under; `None` means in-memory only.
    workspace: Option<PathBuf>,
}

impl OverrideControl {
    /// An empty, in-memory-only handle — what a non-live run uses.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(OverrideState {
                records: UnitOverrides::default(),
                workspace: None,
            })),
        }
    }

    /// Open a handle over a workspace. The persisted override map is loaded
    /// when present (a missing record is an empty map, not an error — the
    /// run simply has nothing overridden yet), and every later change is
    /// saved again.
    pub fn open(workspace: impl AsRef<Path>) -> Self {
        let workspace = workspace.as_ref().to_path_buf();
        let records = match load_json(&override_records_path(&workspace)) {
            Ok(records) => records,
            Err(PersistError::NotFound { .. }) => UnitOverrides::default(),
            Err(e) => {
                // tracing is not a dependency of calxgloss-types (see
                // dashboard/review.rs). The corrupt record is named on
                // stderr, then treated as no override at all.
                eprintln!("warning: corrupt unit override records, starting unsteered: {e}");
                UnitOverrides::default()
            }
        };
        Self {
            inner: Arc::new(Mutex::new(OverrideState {
                records,
                workspace: Some(workspace),
            })),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, OverrideState> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Save the current records when the handle is workspace-backed. A
    /// change that cannot be saved still returns its error — the caller (an
    /// endpoint handler) must not report success for a change that would not
    /// survive a restart.
    fn persist(state: &OverrideState) -> Result<(), PersistError> {
        let Some(ws) = state.workspace.as_ref() else {
            return Ok(());
        };
        save_json(&override_records_path(ws), &state.records)?;
        Ok(())
    }

    /// Find the stored key for a unit: the exact unit key first, then a
    /// binary-case-insensitive match — the same matching rule the scope
    /// filters use, so a skip entered under one spelling still matches a
    /// queue item spelled another way.
    fn find_key(records: &UnitOverrides, binary: &str, function: &str) -> Option<String> {
        let exact = unit_override_key(binary, function);
        if records.overrides.contains_key(&exact) {
            return Some(exact);
        }
        records
            .overrides
            .keys()
            .find(|key| match key.split_once('/') {
                Some((key_binary, key_function)) => {
                    key_function == function && key_binary.eq_ignore_ascii_case(binary)
                }
                None => false,
            })
            .cloned()
    }

    /// The override recorded for a unit, if any.
    pub fn get(&self, binary: &str, function: &str) -> Option<FunctionOverride> {
        let state = self.lock();
        Self::find_key(&state.records, binary, function)
            .and_then(|key| state.records.overrides.get(&key))
            .cloned()
    }

    /// Set an override for a unit. The existing record is replaced entirely
    /// (the override endpoints pass the reviewer's form through unchanged).
    /// An empty record removes the entry rather than storing a do-nothing
    /// override.
    pub fn set(
        &self,
        binary: &str,
        function: &str,
        record: FunctionOverride,
    ) -> Result<(), PersistError> {
        let mut state = self.lock();
        let key = Self::find_key(&state.records, binary, function)
            .unwrap_or_else(|| unit_override_key(binary, function));
        if record.is_empty() {
            state.records.overrides.remove(&key);
        } else {
            state.records.overrides.insert(key, record);
        }
        Self::persist(&state)
    }

    /// Remove a unit's override. Removing an absent override is not an
    /// error; the unit then uses its automatic behavior again.
    pub fn remove(&self, binary: &str, function: &str) -> Result<(), PersistError> {
        let mut state = self.lock();
        if let Some(key) = Self::find_key(&state.records, binary, function) {
            state.records.overrides.remove(&key);
            return Self::persist(&state);
        }
        Ok(())
    }

    /// Whether the unit's override sets the skip flag. The queue selection
    /// filter reads this.
    pub fn is_skipped(&self, binary: &str, function: &str) -> bool {
        self.get(binary, function).is_some_and(|o| o.skip)
    }

    /// A snapshot of the whole override map.
    pub fn records(&self) -> UnitOverrides {
        self.lock().records.clone()
    }
}

impl Default for OverrideControl {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_workspace() -> tempfile::TempDir {
        tempfile::tempdir().expect("temp workspace")
    }

    #[test]
    fn function_override_serde_round_trip() {
        let record = FunctionOverride {
            tier_override: Some(ContextTier::ModuleContext),
            retry_strategy_override: Some(RetryStrategy::Escalate),
            custom_hints: vec!["reads the palette table".into()],
            skip: false,
            reviewer_notes: "looks like a blitter".into(),
        };
        let json = serde_json::to_string(&record).expect("serializes");
        let back: FunctionOverride = serde_json::from_str(&json).expect("deserializes");
        assert_eq!(back, record);
    }

    #[test]
    fn unit_overrides_serde_round_trip() {
        let mut overrides = UnitOverrides::default();
        overrides.overrides.insert(
            "game_logic.dll/DrawPrimitive".into(),
            FunctionOverride {
                tier_override: Some(ContextTier::Disassembly),
                skip: true,
                ..Default::default()
            },
        );
        let json = serde_json::to_string(&overrides).expect("serializes");
        let back: UnitOverrides = serde_json::from_str(&json).expect("deserializes");
        assert_eq!(back, overrides);
    }

    #[test]
    fn empty_records_deserialize_from_partial_json() {
        // Older/partial documents keep loading — every field is defaulted.
        let record: FunctionOverride =
            serde_json::from_str(r#"{"skip": true}"#).expect("partial record deserializes");
        assert!(record.skip);
        assert!(record.tier_override.is_none());
        assert!(record.custom_hints.is_empty());
        let map: UnitOverrides = serde_json::from_str("{}").expect("empty map deserializes");
        assert!(map.overrides.is_empty());
    }

    #[test]
    fn persisted_strategy_labels_load_unchanged() {
        // Workspaces wrote these exact records while the field was a plain
        // String. The typed field must read them byte-compatibly.
        let record: FunctionOverride =
            serde_json::from_str(r#"{"retry_strategy_override": "edge_case_fix"}"#)
                .expect("a pre-typing record still deserializes");
        assert_eq!(
            record.retry_strategy_override,
            Some(RetryStrategy::EdgeCaseFix)
        );
    }

    #[test]
    fn unknown_strategy_label_is_refused_at_deserialization() {
        // The web boundary gets its 4xx answer automatically: the record
        // itself rejects a misspelled strategy, so nothing downstream has to
        // re-check the label.
        let err =
            serde_json::from_str::<FunctionOverride>(r#"{"retry_strategy_override": "escalatte"}"#)
                .expect_err("a typo'd strategy label must not deserialize");
        assert!(
            err.to_string().contains("escalatte"),
            "error names the label: {err}"
        );
    }

    #[test]
    fn override_control_is_shared_across_clones() {
        let control = OverrideControl::new();
        let clone = control.clone();
        clone
            .set(
                "game_logic.dll",
                "DrawPrimitive",
                FunctionOverride {
                    skip: true,
                    ..Default::default()
                },
            )
            .expect("in-memory set");
        assert!(
            control.is_skipped("game_logic.dll", "DrawPrimitive"),
            "clones share the state"
        );
    }

    #[test]
    fn set_replaces_and_remove_drops_idempotently() {
        let control = OverrideControl::new();
        control
            .set(
                "a.dll",
                "F",
                FunctionOverride {
                    reviewer_notes: "first".into(),
                    ..Default::default()
                },
            )
            .expect("in-memory set");
        control
            .set(
                "a.dll",
                "F",
                FunctionOverride {
                    reviewer_notes: "second".into(),
                    ..Default::default()
                },
            )
            .expect("in-memory replace");
        assert_eq!(
            control.get("a.dll", "F").map(|o| o.reviewer_notes),
            Some("second".into()),
            "apply replaces the record wholesale"
        );

        control.remove("a.dll", "F").expect("removal is fine");
        assert!(control.get("a.dll", "F").is_none());
        control
            .remove("a.dll", "F")
            .expect("removing an absent override is not an error");
    }

    #[test]
    fn applying_an_empty_record_removes_the_entry() {
        let control = OverrideControl::new();
        control
            .set(
                "a.dll",
                "F",
                FunctionOverride {
                    tier_override: Some(ContextTier::Signature),
                    ..Default::default()
                },
            )
            .expect("in-memory set");
        control
            .set("a.dll", "F", FunctionOverride::default())
            .expect("empty apply persists");
        assert!(
            control.get("a.dll", "F").is_none(),
            "an all-defaults apply leaves no do-nothing record behind"
        );
    }

    #[test]
    fn lookup_matches_binary_case_insensitively_and_function_exactly() {
        let control = OverrideControl::new();
        control
            .set(
                "Game_Logic.dll",
                "DrawPrimitive",
                FunctionOverride {
                    skip: true,
                    ..Default::default()
                },
            )
            .expect("in-memory set");
        assert!(
            control.is_skipped("game_logic.dll", "DrawPrimitive"),
            "the binary part matches case-insensitively, like the scope filters"
        );
        assert!(
            !control.is_skipped("game_logic.dll", "Drawprimtive"),
            "the function part matches exactly"
        );
    }

    #[test]
    fn records_persist_under_the_workspace_record_tree() {
        let ws = temp_workspace();
        let control = OverrideControl::open(ws.path());
        control
            .set(
                "game_logic.dll",
                "DrawPrimitive",
                FunctionOverride {
                    tier_override: Some(ContextTier::FullModule),
                    custom_hints: vec!["uses SSE registers".into()],
                    reviewer_notes: "blitter candidate".into(),
                    ..Default::default()
                },
            )
            .expect("override persists");

        assert!(
            ws.path().join("re/analysis/unit_overrides.json").exists(),
            "the record file lives under the analysis tree"
        );

        // A restarted run honors what was entered.
        let reopened = OverrideControl::open(ws.path());
        let record = reopened
            .get("game_logic.dll", "DrawPrimitive")
            .expect("the override survives a restart");
        assert_eq!(record.tier_override, Some(ContextTier::FullModule));
        assert_eq!(record.custom_hints, vec!["uses SSE registers"]);
        assert_eq!(record.reviewer_notes, "blitter candidate");
    }

    #[test]
    fn removal_survives_a_restart() {
        let ws = temp_workspace();
        let control = OverrideControl::open(ws.path());
        control
            .set(
                "game_logic.dll",
                "DrawPrimitive",
                FunctionOverride {
                    skip: true,
                    ..Default::default()
                },
            )
            .expect("skip persists");
        control
            .remove("game_logic.dll", "DrawPrimitive")
            .expect("removal persists");

        let reopened = OverrideControl::open(ws.path());
        assert!(
            !reopened.is_skipped("game_logic.dll", "DrawPrimitive"),
            "the removal survives a restart"
        );
    }

    #[test]
    fn open_over_a_never_steered_workspace_is_unsteered_not_an_error() {
        let ws = temp_workspace();
        let control = OverrideControl::open(ws.path());
        assert!(control.records().overrides.is_empty());
        assert!(control.get("game_logic.dll", "DrawPrimitive").is_none());
    }
}
