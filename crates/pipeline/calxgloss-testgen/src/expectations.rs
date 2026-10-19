//! Typed side-effect expectations supplied by the global-state artifact.
//!
//! The baseline harness captures return values, not side effects — reading
//! back what a Wine call mutated would need a per-type view of the
//! arguments. The global-state reference sets close that gap from the other
//! side: the persisted per-binary document already names every program
//! global the function reads and writes, so the test generator turns those
//! access records into typed [`SideEffectKind::GlobalRead`] /
//! [`SideEffectKind::GlobalWrite`] expectations carrying the global's name
//! in the detail string. A global side effect is therefore a named,
//! machine-comparable kind, never a free-form `Other` string.
//!
//! Capture mechanics stay untouched: the expectations are *supplied* by
//! the artifact, and the harness still only reports return values.

use std::path::Path;

use calxgloss_globalstate::persist::GlobalStatePersistor;
use calxgloss_globalstate::types::GlobalStateFinding;
use calxgloss_types::{SideEffect, SideEffectKind};
use tracing::debug;

/// The typed global side-effect expectations for one function.
///
/// Reads the global-state document persisted for `binary` under the
/// workspace (`re/analysis/globalstate/{binary}.json`) and turns the
/// target function's own access records into expectations: one
/// `GlobalRead` per global the function loaded and one `GlobalWrite`
/// per global it stored through, each naming the global in the detail
/// string. A global sighted many times in the body yields one
/// expectation of its kind — the expectation says *that* the function
/// touches the global, not how often — and the expectations keep the
/// document's finding order, so two runs over one document agree.
///
/// Returns an empty vector when no document is persisted for `binary`
/// (the scan has not run) or the document is unreadable: a missing
/// reading supplies no expectations, it never fails generation. Rollup
/// index records are about globals, not functions, and stay out.
pub fn global_state_expectations(
    workspace: &Path,
    binary: &str,
    function: &str,
) -> Vec<SideEffect> {
    let persistor = GlobalStatePersistor::new(workspace);
    let result = match persistor.load(binary) {
        Ok(result) => result,
        Err(e) => {
            debug!(
                binary,
                function,
                error = %e,
                "No usable global-state result; generating test cases without global expectations"
            );
            return Vec::new();
        }
    };

    let mut expectations: Vec<SideEffect> = Vec::new();
    for finding in result.for_function(function) {
        let kind = match finding {
            GlobalStateFinding::GlobalRead(_) => SideEffectKind::GlobalRead,
            GlobalStateFinding::GlobalWrite(_) => SideEffectKind::GlobalWrite,
            GlobalStateFinding::SharedGlobal(_) => continue,
        };
        let detail = finding.global().to_string();
        if !expectations
            .iter()
            .any(|effect| effect.kind == kind && effect.detail == detail)
        {
            expectations.push(SideEffect { kind, detail });
        }
    }
    expectations
}

#[cfg(test)]
mod tests {
    use super::*;
    use calxgloss_globalstate::types::{
        FunctionPurity, GlobalAccess, GlobalStateResult, SharedGlobalRecord,
    };
    use calxgloss_types::ScanMetadata;
    use tempfile::TempDir;

    fn access(function: &str, global: &str, write: bool) -> GlobalStateFinding {
        let record = GlobalAccess {
            function: function.to_string(),
            global: global.to_string(),
            evidence: format!("{global} = uVar2;"),
            confidence: 85.into(),
            suggestion: "hold the global in shared state".to_string(),
        };
        if write {
            GlobalStateFinding::GlobalWrite(record)
        } else {
            GlobalStateFinding::GlobalRead(record)
        }
    }

    fn persist_findings(workspace: &Path, binary: &str, findings: Vec<GlobalStateFinding>) {
        let mut result = GlobalStateResult::new(ScanMetadata::new(binary));
        result.findings = findings;
        GlobalStatePersistor::new(workspace)
            .save(&result)
            .expect("the document saves");
    }

    #[test]
    fn expectations_name_globals_with_the_typed_kinds() {
        // The acceptance shape: a function with a persisted global-state
        // document gets GlobalRead/GlobalWrite expectations naming the
        // globals — not Other(...) strings — in finding order.
        let dir = TempDir::new().expect("temp workspace");
        persist_findings(
            dir.path(),
            "eqmain.dll",
            vec![
                access("FUN_18003ab00", "DAT_180064e80", true),
                access("FUN_18003ab00", "g_counter", false),
                access("FUN_zzz", "DAT_180064e80", false),
            ],
        );

        let found = global_state_expectations(dir.path(), "eqmain.dll", "FUN_18003ab00");

        assert_eq!(
            found,
            vec![
                SideEffect {
                    kind: SideEffectKind::GlobalWrite,
                    detail: "DAT_180064e80".to_string(),
                },
                SideEffect {
                    kind: SideEffectKind::GlobalRead,
                    detail: "g_counter".to_string(),
                },
            ],
            "only the target function's globals, typed, with the global name as the detail"
        );
        assert!(
            !found
                .iter()
                .any(|e| matches!(e.kind, SideEffectKind::Other(_))),
            "a global side effect is never an Other string"
        );
    }

    #[test]
    fn one_global_sighted_many_times_yields_one_expectation_per_kind() {
        // The expectation says the function touches the global, not how
        // often; a read and a write of one global stay two distinct
        // expectations.
        let dir = TempDir::new().expect("temp workspace");
        persist_findings(
            dir.path(),
            "eqmain.dll",
            vec![
                access("FUN_a", "DAT_1", false),
                access("FUN_a", "DAT_1", false),
                access("FUN_a", "DAT_1", true),
            ],
        );

        let found = global_state_expectations(dir.path(), "eqmain.dll", "FUN_a");
        assert_eq!(found.len(), 2, "one read and one write for the one global");
        assert_eq!(found[0].kind, SideEffectKind::GlobalRead);
        assert_eq!(found[1].kind, SideEffectKind::GlobalWrite);
    }

    #[test]
    fn rollup_records_stay_out_of_the_expectations() {
        // The shared-globals index is about a global, not about the
        // function's own behavior — it supplies no expectation.
        let dir = TempDir::new().expect("temp workspace");
        let mut result = GlobalStateResult::new(ScanMetadata::new("eqmain.dll"));
        result
            .findings
            .push(GlobalStateFinding::SharedGlobal(SharedGlobalRecord {
                global: "DAT_180064e80".to_string(),
                readers: vec!["FUN_a".to_string()],
                writers: vec!["FUN_b".to_string()],
                confidence: 85.into(),
            }));
        GlobalStatePersistor::new(dir.path())
            .save(&result)
            .expect("the document saves");

        assert!(global_state_expectations(dir.path(), "eqmain.dll", "FUN_a").is_empty());
    }

    #[test]
    fn a_missing_or_corrupt_document_supplies_nothing() {
        // The feature degrades gracefully: no scan yet, or an unreadable
        // document, means no expectations — generation never fails.
        let dir = TempDir::new().expect("temp workspace");
        assert!(global_state_expectations(dir.path(), "eqmain.dll", "FUN_a").is_empty());

        let persistor = GlobalStatePersistor::new(dir.path());
        std::fs::create_dir_all(persistor.path_for("eqmain.dll").parent().expect("parent"))
            .expect("cache dir");
        std::fs::write(persistor.path_for("eqmain.dll"), "{ not json").expect("corrupt document");
        assert!(global_state_expectations(dir.path(), "eqmain.dll", "FUN_a").is_empty());
    }

    #[test]
    fn a_pure_function_gets_no_expectations() {
        // A function with a document but no access records of its own —
        // only a purity entry — touches no globals and gets nothing.
        let dir = TempDir::new().expect("temp workspace");
        let mut result = GlobalStateResult::new(ScanMetadata::new("eqmain.dll"));
        result.purity.push(FunctionPurity {
            function: "FUN_clean".to_string(),
            is_pure: true,
            reads: 0,
            writes: 0,
        });
        GlobalStatePersistor::new(dir.path())
            .save(&result)
            .expect("the document saves");

        assert!(global_state_expectations(dir.path(), "eqmain.dll", "FUN_clean").is_empty());
    }
}
