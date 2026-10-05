//! Confidence scoring and conflict resolution.
//!
//! The confidence *score* itself is the shared [`calxgloss_types::Confidence`]
//! type (a 0–100 value) now that every engine rates evidence the same way.
//!
//! [`resolve_conflicts`] is the cross-detector half of the model. Each
//! detector already resolves its own readings down to one record per
//! parameter, but the detectors read a body independently, so a finished
//! scan can still carry several records for one target — `strlen`'s
//! argument stands read by the size detector and by the known-signature
//! engine at once. Conflict resolution collapses each target — a
//! parameter, a local variable, or a call-site argument — to its single
//! strongest record: the highest confidence wins, a tie keeps the record
//! the scan showed first, and the survivor stands where its target first
//! appeared, so the list keeps scan order and two scans of the same
//! program diff cleanly.
//!
//! [`calxgloss_types::Confidence`]: calxgloss_types::Confidence

use std::collections::HashMap;

use crate::types::InferredType;

/// What a set of competing inferences is keyed on: one parameter, one
/// local variable, or one call-site argument.
///
/// The three record kinds identify their targets differently — a
/// parameter by position, a local by its decompiled name, a call-site
/// argument by the callee and position — so one key shape names all
/// three and records of different kinds never collide.
#[derive(Debug, PartialEq, Eq, Hash)]
enum Target {
    /// One parameter of one function, by position.
    Param {
        function: String,
        param_index: usize,
    },
    /// One local variable, by its decompiled name.
    Local {
        function: String,
        variable_name: String,
    },
    /// One argument of one call site, by callee and position.
    CallSite {
        function: String,
        callee: String,
        arg_index: usize,
    },
}

impl Target {
    /// The target an inference record is about.
    fn of(inference: &InferredType) -> Self {
        match inference {
            InferredType::Param(record) => Target::Param {
                function: record.function.clone(),
                param_index: record.param_index,
            },
            InferredType::Local(record) => Target::Local {
                function: record.function.clone(),
                variable_name: record.variable_name.clone(),
            },
            InferredType::CallSite(record) => Target::CallSite {
                function: record.function.clone(),
                callee: record.callee.clone(),
                arg_index: record.arg_index,
            },
        }
    }
}

/// Resolve competing inferences down to one per target.
///
/// Where several detectors read the same parameter, local, or call-site
/// argument differently, the highest-confidence record wins and the rest
/// drop; a tie keeps the record the scan showed first. The survivor
/// stands where its target first appeared in the list, so the resolved
/// list keeps scan order — function by function, targets in the order
/// the bodies showed them — exactly as the raw scan did.
pub fn resolve_conflicts(inferences: Vec<InferredType>) -> Vec<InferredType> {
    let mut winners: Vec<InferredType> = Vec::new();
    let mut positions: HashMap<Target, usize> = HashMap::new();
    for inference in inferences {
        let target = Target::of(&inference);
        match positions.get(&target) {
            Some(&position) if inference.confidence() > winners[position].confidence() => {
                winners[position] = inference;
            }
            Some(_) => {}
            None => {
                positions.insert(target, winners.len());
                winners.push(inference);
            }
        }
    }
    winners
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{
        Confidence, InferenceMethod, InferenceScope, InferredCallType, InferredLocalType,
        InferredParamType,
    };

    fn param(
        function: &str,
        param_index: usize,
        method: InferenceMethod,
        inferred_type: &str,
        confidence: u8,
    ) -> InferredType {
        InferredType::Param(InferredParamType {
            function: function.into(),
            param_index,
            param_name: Some(format!("param_{}", param_index + 1)),
            inferred_type: inferred_type.into(),
            method,
            scope: InferenceScope::Function,
            confidence: Confidence::new(confidence),
            evidence: format!("{method} evidence for param_{}", param_index + 1),
        })
    }

    fn local(function: &str, variable_name: &str, confidence: u8) -> InferredType {
        InferredType::Local(InferredLocalType {
            function: function.into(),
            variable_name: variable_name.into(),
            inferred_type: "char *".into(),
            method: InferenceMethod::KnownSignature,
            scope: InferenceScope::Function,
            confidence: Confidence::new(confidence),
            evidence: format!("{variable_name} = (char *)malloc(0x10);"),
        })
    }

    fn call(
        function: &str,
        callee: &str,
        arg_index: usize,
        inferred_type: &str,
        confidence: u8,
    ) -> InferredType {
        InferredType::CallSite(InferredCallType {
            function: function.into(),
            callee: callee.into(),
            arg_index,
            arg_name: Some("param_2".into()),
            inferred_type: inferred_type.into(),
            method: InferenceMethod::KnownSignature,
            scope: InferenceScope::Program,
            confidence: Confidence::new(confidence),
            evidence: format!("{callee}(param_2);"),
        })
    }

    #[test]
    fn the_highest_confidence_record_wins_across_detectors() {
        // The same parameter stands read by the size detector (`strlen`'s
        // `char *` at 70) and the known-signature engine (`CloseHandle`'s
        // `void *` at 75); the stronger reading survives.
        let winners = resolve_conflicts(vec![
            param("FUN_1800412a0", 0, InferenceMethod::StringFunction, "char *", 70),
            param("FUN_1800412a0", 0, InferenceMethod::KnownSignature, "void *", 75),
        ]);
        assert_eq!(
            winners,
            vec![param(
                "FUN_1800412a0",
                0,
                InferenceMethod::KnownSignature,
                "void *",
                75
            )]
        );
    }

    #[test]
    fn a_tie_keeps_the_record_the_scan_showed_first() {
        // `strlen` is a string-function call and a known signature at
        // once, both at 70; the scan showed the size detector first.
        let winners = resolve_conflicts(vec![
            param("FUN_1800412a0", 0, InferenceMethod::StringFunction, "char *", 70),
            param("FUN_1800412a0", 0, InferenceMethod::KnownSignature, "char *", 70),
        ]);
        assert_eq!(
            winners,
            vec![param(
                "FUN_1800412a0",
                0,
                InferenceMethod::StringFunction,
                "char *",
                70
            )]
        );
    }

    #[test]
    fn different_parameters_each_keep_their_own() {
        let winners = resolve_conflicts(vec![
            param("FUN_18003ab00", 0, InferenceMethod::VtableCall, "Widget *", 85),
            param(
                "FUN_18003ab00",
                1,
                InferenceMethod::StringFunction,
                "char *",
                70,
            ),
            param("FUN_18003ab00", 2, InferenceMethod::KnownSignature, "void *", 75),
        ]);
        assert_eq!(winners.len(), 3);
        assert_eq!(winners[0].inferred_type(), "Widget *");
        assert_eq!(winners[1].inferred_type(), "char *");
        assert_eq!(winners[2].inferred_type(), "void *");
    }

    #[test]
    fn the_same_parameter_in_two_functions_does_not_conflict() {
        let winners = resolve_conflicts(vec![
            param("FUN_18003ab00", 0, InferenceMethod::StringFunction, "char *", 70),
            param("FUN_18003e750", 0, InferenceMethod::KnownSignature, "void *", 75),
        ]);
        assert_eq!(winners.len(), 2);
        assert_eq!(winners[0].function(), "FUN_18003ab00");
        assert_eq!(winners[1].function(), "FUN_18003e750");
    }

    #[test]
    fn a_local_keys_on_its_name_and_a_different_name_does_not_conflict() {
        let winners = resolve_conflicts(vec![
            local("FUN_18003ab00", "local_8", 60),
            local("FUN_18003ab00", "local_10", 55),
            local("FUN_18003ab00", "local_8", 70),
        ]);
        assert_eq!(winners.len(), 2);
        let InferredType::Local(record) = &winners[0] else {
            unreachable!("local records stay local");
        };
        assert_eq!(record.variable_name, "local_8");
        assert_eq!(record.confidence, Confidence::new(70));
    }

    #[test]
    fn a_call_site_keys_on_callee_and_argument_position() {
        let winners = resolve_conflicts(vec![
            call("FUN_1800412a0", "CloseHandle", 0, "void *", 75),
            call("FUN_1800412a0", "CreateFileW", 0, "wchar_t *", 75),
            call("FUN_1800412a0", "CloseHandle", 0, "char *", 70),
        ]);
        assert_eq!(winners.len(), 2);
        assert_eq!(winners[0].inferred_type(), "void *");
        assert_eq!(winners[1].inferred_type(), "wchar_t *");
    }

    #[test]
    fn a_winner_stands_where_its_target_first_appeared() {
        // The stronger record for param_1 arrives after param_2's record;
        // the resolved list keeps the order the scan showed the targets.
        let winners = resolve_conflicts(vec![
            param("FUN_18003ab00", 0, InferenceMethod::IntegerBitPattern, "u32", 55),
            param("FUN_18003ab00", 1, InferenceMethod::PointerArithmetic, "void *", 65),
            param("FUN_18003ab00", 0, InferenceMethod::VtableCall, "Widget *", 85),
        ]);
        assert_eq!(winners.len(), 2);
        assert_eq!(winners[0].inferred_type(), "Widget *");
        assert_eq!(winners[1].inferred_type(), "void *");
    }

    #[test]
    fn a_conflict_free_scan_passes_through_unchanged() {
        let inferences = vec![
            param("FUN_18003ab00", 0, InferenceMethod::VtableCall, "Widget *", 85),
            local("FUN_18003ab00", "local_8", 60),
            call("FUN_1800412a0", "CloseHandle", 0, "void *", 75),
        ];
        assert_eq!(resolve_conflicts(inferences.clone()), inferences);
        assert!(resolve_conflicts(Vec::new()).is_empty());
    }
}
