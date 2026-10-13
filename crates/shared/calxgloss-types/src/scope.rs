//! Translation scope controls — what a run is allowed to touch (issue #93, W2.5).
//!
//! An operator steers a live run over REST: which target binaries to
//! translate, which functions to skip (runtime entry points, hooks, callback
//! stubs that never need translation), which functions to prioritize (entry
//! points, the rendering path, core algorithms sort ahead of the rest of the
//! queue), and constraints that bound consumption — max LLM attempt count,
//! max context tier, token budget.
//!
//! Two layers live here:
//!
//! * [`TranslationScope`] and [`TranslationConstraints`] are plain serde
//!   records — the shape persisted under the workspace's record tree and the
//!   shape the status endpoint reports.
//! * [`ScopeControl`] is the shared handle — `Arc`-backed and cheaply
//!   cloneable, the same pattern as [`StopSignal`](crate::StopSignal) and
//!   [`PipelineControl`](crate::PipelineControl). The web router's scope
//!   endpoints drive it; the translator pipeline observes it at queue
//!   selection, so a skip lands before a unit ever enters the queue plan.
//!
//! When the handle is opened over a workspace ([`ScopeControl::open`]) every
//! mutation persists the records to `re/analysis/translation_scope.json` and
//! `re/analysis/translation_constraints.json`, so a restarted run honors
//! them without re-entering anything. The token spend counter is per-run and
//! deliberately not persisted.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use crate::context_tier::ContextTier;
use crate::identity::BinaryIdentity;
use crate::persist::{PersistError, analysis_dir, load_json, save_json};

/// A reference to one function in one target binary.
///
/// Function names are only unique *within* a binary, so a scope entry names
/// its binary verbatim (the same identity rule the record tree uses).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionRef {
    /// The target binary, filename verbatim.
    pub binary: BinaryIdentity,
    /// The function name within that binary.
    pub function: String,
}

impl FunctionRef {
    /// Build a reference from a binary name and a function name.
    pub fn new(binary: impl Into<BinaryIdentity>, function: impl Into<String>) -> Self {
        Self {
            binary: binary.into(),
            function: function.into(),
        }
    }

    /// The one match rule for scope entries (issue #107) — every mutator
    /// and reader of the skip and priority lists asks this, so adding,
    /// checking, and removing the same (binary, function) pair always
    /// treat it as the same entry.
    ///
    /// The case policy is deliberate: the binary name matches ASCII
    /// case-insensitively — Windows binary names are case-insensitive, and
    /// the operator may spell the same DLL differently across panel and
    /// record — while the function name matches exactly: PE export names
    /// and Ghidra symbols are case-sensitive, so `DrawPrimitive` and
    /// `drawprimitive` are different functions.
    pub fn matches(&self, binary: &str, function: &str) -> bool {
        self.binary.as_str().eq_ignore_ascii_case(binary) && self.function == function
    }
}

/// What the run is allowed to touch.
///
/// Filtering is applied at queue selection: a skipped function never enters
/// the queue plan at all, and a priority function sorts ahead of the rest of
/// the queue. An empty `binaries` list means every discovered binary is in
/// scope.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranslationScope {
    /// Binaries to translate; empty means all discovered binaries.
    #[serde(default)]
    pub binaries: Vec<BinaryIdentity>,
    /// Functions that never enter the queue plan.
    #[serde(default)]
    pub skipped_functions: Vec<FunctionRef>,
    /// Functions that sort ahead of the rest of the queue.
    #[serde(default)]
    pub priority_functions: Vec<FunctionRef>,
}

impl TranslationScope {
    /// Whether the named binary is in scope for translation.
    pub fn admits_binary(&self, binary: &str) -> bool {
        self.binaries.is_empty()
            || self
                .binaries
                .iter()
                .any(|b| b.as_str().eq_ignore_ascii_case(binary))
    }

    /// Whether the named function is skipped in the named binary.
    pub fn is_skipped(&self, binary: &str, function: &str) -> bool {
        self.skipped_functions
            .iter()
            .any(|f| f.matches(binary, function))
    }

    /// Whether the named function is prioritized in the named binary.
    pub fn is_priority(&self, binary: &str, function: &str) -> bool {
        self.priority_functions
            .iter()
            .any(|f| f.matches(binary, function))
    }
}

/// Constraints that bound what the run consumes.
///
/// Every field is `None` for "no cap" — the default an un-steered run runs
/// under. The caps are read at queue selection and at each retry escalation,
/// so a change lands on the next unit boundary or the next escalation, never
/// mid-attempt.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranslationConstraints {
    /// Maximum LLM attempts per unit (including the first). Caps the retry
    /// config's `max_attempts` when it is lower.
    #[serde(default)]
    pub max_attempts: Option<u32>,
    /// Highest context tier automatic escalation may reach.
    #[serde(default)]
    pub max_context_tier: Option<ContextTier>,
    /// Token budget for the run. The batch loop stops at the next unit
    /// boundary once recorded spend reaches it.
    #[serde(default)]
    pub token_budget: Option<u64>,
}

/// The persisted location of the scope record under a workspace.
pub fn scope_record_path(workspace: impl AsRef<Path>) -> PathBuf {
    analysis_dir(workspace).join("translation_scope.json")
}

/// The persisted location of the constraints record under a workspace.
pub fn constraints_record_path(workspace: impl AsRef<Path>) -> PathBuf {
    analysis_dir(workspace).join("translation_constraints.json")
}

/// Shared, cheaply-cloneable scope handle (issue #93, W2.5).
///
/// The web router's scope endpoints mutate it; the translator pipeline reads
/// it at queue selection and at each unit boundary. Clones share the state,
/// exactly like [`PipelineControl`](crate::PipelineControl). Built with
/// [`new`](ScopeControl::new) (in-memory only, the plain CLI path) or
/// [`open`](ScopeControl::open) (loads the workspace's persisted records and
/// re-persists every mutation).
#[derive(Debug, Clone)]
pub struct ScopeControl {
    inner: Arc<Mutex<ScopeState>>,
}

#[derive(Debug)]
struct ScopeState {
    scope: TranslationScope,
    constraints: TranslationConstraints,
    /// Tokens spent by the current run — per-run, never persisted.
    tokens_spent: u64,
    /// Workspace to persist records under; `None` means in-memory only.
    workspace: Option<PathBuf>,
}

impl ScopeControl {
    /// An empty, in-memory-only handle — the shape a non-live run gets.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(ScopeState {
                scope: TranslationScope::default(),
                constraints: TranslationConstraints::default(),
                tokens_spent: 0,
                workspace: None,
            })),
        }
    }

    /// Open a handle over a workspace: the persisted records are loaded when
    /// present (a missing record is an empty scope, not an error — the run
    /// simply has nothing steered yet), and every mutation re-persists.
    pub fn open(workspace: impl AsRef<Path>) -> Self {
        let workspace = workspace.as_ref().to_path_buf();
        let scope = match load_json(&scope_record_path(&workspace)) {
            Ok(scope) => scope,
            Err(PersistError::NotFound { .. }) => TranslationScope::default(),
            Err(e) => {
                // tracing is not a dependency of calxgloss-types (see
                // dashboard/review.rs) — the corrupt record is named on
                // stderr, then treated as unsteered.
                eprintln!("warning: corrupt translation scope record, starting unsteered: {e}");
                TranslationScope::default()
            }
        };
        let constraints = match load_json(&constraints_record_path(&workspace)) {
            Ok(c) => c,
            Err(PersistError::NotFound { .. }) => TranslationConstraints::default(),
            Err(e) => {
                eprintln!(
                    "warning: corrupt translation constraints record, starting unsteered: {e}"
                );
                TranslationConstraints::default()
            }
        };
        Self {
            inner: Arc::new(Mutex::new(ScopeState {
                scope,
                constraints,
                tokens_spent: 0,
                workspace: Some(workspace),
            })),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, ScopeState> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Persist the current records when the handle is workspace-backed.
    /// A mutation that cannot persist still reports the error — the caller
    /// (an endpoint handler) must not silently claim success on a change
    /// that will not survive a restart.
    fn persist(state: &ScopeState) -> Result<(), PersistError> {
        let Some(ws) = state.workspace.as_ref() else {
            return Ok(());
        };
        save_json(&scope_record_path(ws), &state.scope)?;
        save_json(&constraints_record_path(ws), &state.constraints)?;
        Ok(())
    }

    /// A snapshot of the current scope.
    pub fn scope(&self) -> TranslationScope {
        self.lock().scope.clone()
    }

    /// A snapshot of the current constraints.
    pub fn constraints(&self) -> TranslationConstraints {
        self.lock().constraints.clone()
    }

    /// Replace the binaries-to-translate list. An empty list clears the
    /// restriction — every discovered binary is in scope again.
    pub fn set_binaries(&self, binaries: Vec<BinaryIdentity>) -> Result<(), PersistError> {
        let mut state = self.lock();
        state.scope.binaries = binaries;
        Self::persist(&state)
    }

    /// Skip one function: it never enters the queue plan. Idempotent —
    /// skipping an already-skipped function is not an error.
    pub fn skip_function(&self, binary: &str, function: &str) -> Result<(), PersistError> {
        let mut state = self.lock();
        if !state
            .scope
            .skipped_functions
            .iter()
            .any(|f| f.matches(binary, function))
        {
            state
                .scope
                .skipped_functions
                .push(FunctionRef::new(binary, function));
        }
        Self::persist(&state)
    }

    /// Prioritize one function: it sorts ahead of the rest of the queue.
    /// Idempotent — prioritizing an already-prioritized function is not an
    /// error.
    pub fn prioritize_function(&self, binary: &str, function: &str) -> Result<(), PersistError> {
        let mut state = self.lock();
        if !state
            .scope
            .priority_functions
            .iter()
            .any(|f| f.matches(binary, function))
        {
            state
                .scope
                .priority_functions
                .push(FunctionRef::new(binary, function));
        }
        Self::persist(&state)
    }

    /// Drop one function from the priority list — the operator's remove
    /// (issue #95, W2.6). Idempotent: removing a function that is not
    /// prioritized is not an error. The next queue selection no longer
    /// sorts it ahead.
    pub fn remove_priority_function(
        &self,
        binary: &str,
        function: &str,
    ) -> Result<(), PersistError> {
        let mut state = self.lock();
        state
            .scope
            .priority_functions
            .retain(|f| !f.matches(binary, function));
        Self::persist(&state)
    }

    /// Replace the run's constraints.
    pub fn set_constraints(&self, constraints: TranslationConstraints) -> Result<(), PersistError> {
        let mut state = self.lock();
        state.constraints = constraints;
        Self::persist(&state)
    }

    /// Record token spend from a completed attempt against the run budget.
    pub fn record_tokens(&self, tokens: u64) {
        self.lock().tokens_spent += tokens;
    }

    /// Tokens the current run has spent so far.
    pub fn tokens_spent(&self) -> u64 {
        self.lock().tokens_spent
    }

    /// Whether the run has reached its token budget. No budget means never
    /// exhausted.
    pub fn budget_exhausted(&self) -> bool {
        let state = self.lock();
        state
            .constraints
            .token_budget
            .is_some_and(|budget| state.tokens_spent >= budget)
    }
}

impl Default for ScopeControl {
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
    fn translation_scope_serde_round_trip() {
        let scope = TranslationScope {
            binaries: vec!["game_logic.dll".into()],
            skipped_functions: vec![FunctionRef::new("game_logic.dll", "DllMain")],
            priority_functions: vec![FunctionRef::new("game_logic.dll", "DrawPrimitive")],
        };
        let json = serde_json::to_string(&scope).expect("serializes");
        let back: TranslationScope = serde_json::from_str(&json).expect("deserializes");
        assert_eq!(back, scope);
    }

    #[test]
    fn translation_constraints_serde_round_trip() {
        let constraints = TranslationConstraints {
            max_attempts: Some(2),
            max_context_tier: Some(ContextTier::Disassembly),
            token_budget: Some(50_000),
        };
        let json = serde_json::to_string(&constraints).expect("serializes");
        let back: TranslationConstraints = serde_json::from_str(&json).expect("deserializes");
        assert_eq!(back, constraints);
    }

    #[test]
    fn empty_records_deserialize_from_partial_json() {
        // Older/partial documents keep loading — every field is defaulted.
        let scope: TranslationScope =
            serde_json::from_str(r#"{"binaries": ["a.dll"]}"#).expect("partial scope deserializes");
        assert_eq!(scope.skipped_functions.len(), 0);
        let constraints: TranslationConstraints =
            serde_json::from_str("{}").expect("empty constraints deserialize");
        assert_eq!(constraints.max_attempts, None);
    }

    #[test]
    fn scope_filters_match_binary_case_insensitively_and_function_exactly() {
        let scope = TranslationScope {
            binaries: vec![],
            skipped_functions: vec![FunctionRef::new("game_logic.dll", "DllMain")],
            priority_functions: vec![FunctionRef::new("eqmain.dll", "DrawPrimitive")],
        };
        assert!(scope.admits_binary("anything.dll"), "empty list admits all");
        assert!(scope.is_skipped("game_logic.dll", "DllMain"));
        assert!(
            !scope.is_skipped("other.dll", "DllMain"),
            "a skip is scoped to its binary"
        );
        assert!(scope.is_priority("eqmain.dll", "DrawPrimitive"));
        assert!(!scope.is_priority("eqmain.dll", "UpdateScene"));
        // The match rule's case policy (issue #107): binary names are
        // Windows filenames — case-insensitive. Function names are PE
        // exports / Ghidra symbols — case-sensitive.
        assert!(
            scope.is_skipped("GAME_LOGIC.dll", "DllMain"),
            "a differently-cased binary spelling still matches the skip"
        );
        assert!(
            scope.is_priority("EQMAIN.DLL", "DrawPrimitive"),
            "a differently-cased binary spelling still matches the priority"
        );
        assert!(
            !scope.is_skipped("game_logic.dll", "dllmain"),
            "a differently-cased function name is a different function"
        );
    }

    /// The one match rule (issue #107): adding, checking, and removing the
    /// same (binary, function) pair always land on one entry, however the
    /// operator cased the binary name.
    #[test]
    fn differently_cased_mutations_dedupe_and_remove_the_same_entry() {
        let control = ScopeControl::new();
        control
            .skip_function("game_logic.dll", "DllMain")
            .expect("first skip");
        control
            .skip_function("GAME_LOGIC.dll", "DllMain")
            .expect("differently-cased skip is not an error");
        assert_eq!(
            control.scope().skipped_functions.len(),
            1,
            "a differently-cased skip dedupes rather than duplicates"
        );

        control
            .prioritize_function("game_logic.dll", "DrawPrimitive")
            .expect("first priority");
        control
            .prioritize_function("GAME_LOGIC.DLL", "DrawPrimitive")
            .expect("differently-cased priority is not an error");
        assert_eq!(
            control.scope().priority_functions.len(),
            1,
            "a differently-cased priority add dedupes rather than duplicates"
        );

        control
            .remove_priority_function("Game_Logic.dll", "DrawPrimitive")
            .expect("differently-cased removal is not an error");
        assert!(
            control.scope().priority_functions.is_empty(),
            "a differently-cased removal drops the entry"
        );
    }

    #[test]
    fn scope_control_is_shared_across_clones() {
        let control = ScopeControl::new();
        let clone = control.clone();
        clone
            .skip_function("game_logic.dll", "DllMain")
            .expect("in-memory skip");
        assert!(
            control.scope().is_skipped("game_logic.dll", "DllMain"),
            "clones share the state"
        );
    }

    #[test]
    fn skip_and_priority_are_idempotent() {
        let control = ScopeControl::new();
        control
            .skip_function("a.dll", "DllMain")
            .expect("first skip");
        control
            .skip_function("a.dll", "DllMain")
            .expect("repeat skip is not an error");
        control
            .prioritize_function("a.dll", "Draw")
            .expect("first priority");
        control
            .prioritize_function("a.dll", "Draw")
            .expect("repeat priority is not an error");
        assert_eq!(control.scope().skipped_functions.len(), 1);
        assert_eq!(control.scope().priority_functions.len(), 1);
    }

    /// Removing a priority entry (issue #95, W2.6 — the panel's remove
    /// button) drops exactly that function, is idempotent, and persists.
    #[test]
    fn remove_priority_function_drops_the_entry_and_persists() {
        let ws = temp_workspace();
        let control = ScopeControl::open(ws.path());
        control
            .prioritize_function("game_logic.dll", "DrawPrimitive")
            .expect("first priority persists");
        control
            .prioritize_function("game_logic.dll", "UpdateScene")
            .expect("second priority persists");

        control
            .remove_priority_function("game_logic.dll", "DrawPrimitive")
            .expect("removal persists");
        let after = control.scope();
        assert!(
            !after.is_priority("game_logic.dll", "DrawPrimitive"),
            "the removed function leaves the priority list"
        );
        assert!(
            after.is_priority("game_logic.dll", "UpdateScene"),
            "the other priority entry is untouched"
        );

        control
            .remove_priority_function("game_logic.dll", "NeverPrioritized")
            .expect("removing an absent entry is not an error");

        // A restarted run honors the removal — the record was rewritten.
        let reopened = ScopeControl::open(ws.path());
        assert!(
            !reopened
                .scope()
                .is_priority("game_logic.dll", "DrawPrimitive"),
            "the removal survives a restart"
        );
        assert!(
            reopened
                .scope()
                .is_priority("game_logic.dll", "UpdateScene")
        );
    }

    #[test]
    fn records_persist_under_the_workspace_record_tree() {
        let ws = temp_workspace();
        let control = ScopeControl::open(ws.path());
        control
            .skip_function("game_logic.dll", "DllMain")
            .expect("skip persists");
        control
            .set_constraints(TranslationConstraints {
                max_attempts: Some(2),
                ..Default::default()
            })
            .expect("constraints persist");

        assert!(
            ws.path()
                .join("re/analysis/translation_scope.json")
                .exists()
        );
        assert!(
            ws.path()
                .join("re/analysis/translation_constraints.json")
                .exists()
        );

        // A restarted run honors what was entered.
        let reopened = ScopeControl::open(ws.path());
        assert!(reopened.scope().is_skipped("game_logic.dll", "DllMain"));
        assert_eq!(reopened.constraints().max_attempts, Some(2));
    }

    #[test]
    fn open_over_a_never_steered_workspace_is_unsteered_not_an_error() {
        let ws = temp_workspace();
        let control = ScopeControl::open(ws.path());
        assert!(control.scope().binaries.is_empty());
        assert!(control.scope().skipped_functions.is_empty());
        assert_eq!(control.constraints().token_budget, None);
    }

    #[test]
    fn set_binaries_replaces_the_list() {
        let control = ScopeControl::new();
        control
            .set_binaries(vec!["a.dll".into(), "b.dll".into()])
            .expect("in-memory set");
        assert!(control.scope().admits_binary("a.dll"));
        assert!(!control.scope().admits_binary("c.dll"));
        control
            .set_binaries(vec![])
            .expect("clearing restricts nothing");
        assert!(control.scope().admits_binary("c.dll"));
    }

    #[test]
    fn token_budget_tracks_spend_and_exhausts_once() {
        let control = ScopeControl::new();
        assert!(!control.budget_exhausted(), "no budget is never exhausted");
        control
            .set_constraints(TranslationConstraints {
                token_budget: Some(100),
                ..Default::default()
            })
            .expect("in-memory constraints");
        control.record_tokens(60);
        assert_eq!(control.tokens_spent(), 60);
        assert!(!control.budget_exhausted());
        control.record_tokens(40);
        assert!(control.budget_exhausted());
    }
}
