//! Evidence confidence: scoring and conflict resolution.
//!
//! The confidence *score* itself is the shared [`calxgloss_types::Confidence`]
//! type, a 0–100 value: every evidence engine rates its findings the
//! same way.
//!
//! [`resolve_conflicts`] is the cross-detector half of the model. Each
//! detector already resolves its own readings down to one record per
//! parameter, but the detectors read a body independently. So a finished
//! scan can still hold several records for one target: `strlen`'s
//! argument may stand read by the size detector and by the
//! known-signature detector at once. Conflict resolution collapses each
//! target to its single strongest record. A target is a parameter, a
//! local variable, a call-site argument, a function's return value, a
//! function's calling convention, or a parameter's direction. The
//! highest evidence confidence wins. A tie keeps the record the scan
//! showed first. The survivor stands where its target first appeared, so the
//! list keeps scan order and two scans of the same program diff
//! cleanly.
//!
//! [`calxgloss_types::Confidence`]: calxgloss_types::Confidence

use std::collections::HashMap;

use crate::types::InferredType;

/// What a set of competing inferences is keyed on: one parameter, one
/// local variable, one call-site argument, one function's return, one
/// function's calling convention, or one parameter's direction.
///
/// The six record kinds identify their targets differently: a
/// parameter by position, a local by its decompiled name, a call-site
/// argument by the callee and position, a return and a convention by
/// the function alone, and a call-site convention view by the
/// caller-and-callee pair. A direction keys on the function and
/// parameter position in a key of its own, separate from the parameter
/// arm: that separation lets a direction reading stand beside the type
/// reading for one parameter instead of competing with it (issue
/// #274). One enum names all six key shapes, so records of different
/// kinds never collide.
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
    /// One function's return value — the function alone, since a
    /// function has exactly one return type.
    Return { function: String },
    /// One function's calling convention — the function alone, since a
    /// function is called one way. A caller's call-site view of its
    /// callee keys on the pair, so it stands beside the caller's own
    /// convention without colliding with it (issue #249).
    Convention {
        function: String,
        callee: Option<String>,
    },
    /// One parameter's direction — the function and parameter position,
    /// a key of its own beside the parameter arm. One parameter may
    /// have a type reading and a direction reading at once, but only
    /// one direction (issue #274).
    Direction {
        function: String,
        param_index: usize,
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
            InferredType::Return(record) => Target::Return {
                function: record.function.clone(),
            },
            InferredType::Convention(record) => Target::Convention {
                function: record.function.clone(),
                callee: record.callee.clone(),
            },
            InferredType::Direction(record) => Target::Direction {
                function: record.function.clone(),
                param_index: record.param_index,
            },
        }
    }
}

/// Resolve competing inferences down to one per target.
///
/// Where several detectors read the same parameter, local, call-site
/// argument, return value, calling convention, or parameter direction
/// differently, the record with the highest evidence confidence wins
/// and the rest drop; a tie keeps the record the scan showed first.
/// The survivor stands where its target first appeared in the list, so
/// the resolved list keeps scan order — function by function, targets
/// in the order the bodies showed them — exactly as the raw scan did.
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
        CallingConvention, Confidence, Direction, InferenceMethod, InferenceScope,
        InferredCallType, InferredConvention, InferredLocalType, InferredParamDirection,
        InferredParamType, InferredReturnType,
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

    fn ret(function: &str, inferred_type: &str, confidence: u8) -> InferredType {
        InferredType::Return(InferredReturnType {
            function: function.into(),
            inferred_type: inferred_type.into(),
            method: InferenceMethod::ReturnUsage,
            scope: InferenceScope::Function,
            confidence: Confidence::new(confidence),
            evidence: format!("local_8 = {function}();"),
        })
    }

    fn convention(function: &str, convention: CallingConvention, confidence: u8) -> InferredType {
        InferredType::Convention(InferredConvention {
            function: function.into(),
            callee: None,
            convention,
            method: InferenceMethod::MangledConvention,
            confidence: Confidence::new(confidence),
            evidence: function.into(),
        })
    }

    fn direction(
        function: &str,
        param_index: usize,
        direction: Direction,
        confidence: u8,
    ) -> InferredType {
        InferredType::Direction(InferredParamDirection {
            function: function.into(),
            param_index,
            param_name: Some(format!("param_{}", param_index + 1)),
            direction,
            method: InferenceMethod::ParamDirection,
            scope: InferenceScope::Function,
            confidence: Confidence::new(confidence),
            evidence: format!("*param_{} = x;", param_index + 1),
        })
    }

    #[test]
    fn the_highest_confidence_record_wins_across_detectors() {
        // The same parameter is read twice: by the size detector
        // (`strlen`'s `char *` at 70) and by the known-signature
        // detector (`CloseHandle`'s `void *` at 75). The stronger
        // reading survives.
        let winners = resolve_conflicts(vec![
            param(
                "FUN_1800412a0",
                0,
                InferenceMethod::StringFunction,
                "char *",
                70,
            ),
            param(
                "FUN_1800412a0",
                0,
                InferenceMethod::KnownSignature,
                "void *",
                75,
            ),
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
        // once. Both readings score 70, and the scan showed the size
        // detector first.
        let winners = resolve_conflicts(vec![
            param(
                "FUN_1800412a0",
                0,
                InferenceMethod::StringFunction,
                "char *",
                70,
            ),
            param(
                "FUN_1800412a0",
                0,
                InferenceMethod::KnownSignature,
                "char *",
                70,
            ),
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
            param(
                "FUN_18003ab00",
                0,
                InferenceMethod::VtableCall,
                "Widget *",
                85,
            ),
            param(
                "FUN_18003ab00",
                1,
                InferenceMethod::StringFunction,
                "char *",
                70,
            ),
            param(
                "FUN_18003ab00",
                2,
                InferenceMethod::KnownSignature,
                "void *",
                75,
            ),
        ]);
        assert_eq!(winners.len(), 3);
        assert_eq!(winners[0].inferred_type(), "Widget *");
        assert_eq!(winners[1].inferred_type(), "char *");
        assert_eq!(winners[2].inferred_type(), "void *");
    }

    #[test]
    fn the_same_parameter_in_two_functions_does_not_conflict() {
        let winners = resolve_conflicts(vec![
            param(
                "FUN_18003ab00",
                0,
                InferenceMethod::StringFunction,
                "char *",
                70,
            ),
            param(
                "FUN_18003e750",
                0,
                InferenceMethod::KnownSignature,
                "void *",
                75,
            ),
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
    fn one_function_never_keeps_two_return_types() {
        // Two callers read one helper's return differently: the
        // stronger reading survives, the weaker drops.
        let winners = resolve_conflicts(vec![
            ret("FUN_180051c00", "void *", 60),
            ret("FUN_180051c00", "char *", 65),
        ]);
        assert_eq!(winners.len(), 1);
        assert_eq!(winners[0].inferred_type(), "char *");
    }

    #[test]
    fn a_return_tie_keeps_the_reading_the_scan_showed_first() {
        let winners = resolve_conflicts(vec![
            ret("FUN_180051c00", "char *", 60),
            ret("FUN_180051c00", "void *", 60),
        ]);
        assert_eq!(winners.len(), 1);
        assert_eq!(winners[0].inferred_type(), "char *");
    }

    #[test]
    fn returns_of_two_functions_do_not_conflict() {
        let winners = resolve_conflicts(vec![
            ret("FUN_180051c00", "char *", 60),
            ret("FUN_18004b210", "void *", 60),
        ]);
        assert_eq!(winners.len(), 2);
    }

    #[test]
    fn one_function_never_keeps_two_conventions() {
        // For one symbol, a mangled letter says thiscall at 90 and an
        // `@N`-style reading says stdcall at 85. The stronger spelling
        // wins.
        let winners = resolve_conflicts(vec![
            convention("CreateFileA@28", CallingConvention::Stdcall, 85),
            convention("CreateFileA@28", CallingConvention::Thiscall, 90),
        ]);
        assert_eq!(winners.len(), 1);
        let InferredType::Convention(record) = &winners[0] else {
            unreachable!("convention records stay convention records");
        };
        assert_eq!(record.convention, CallingConvention::Thiscall);
    }

    #[test]
    fn a_convention_tie_keeps_the_reading_the_scan_showed_first() {
        let winners = resolve_conflicts(vec![
            convention("?paint@Widget@@QAEXXZ", CallingConvention::Thiscall, 90),
            convention("?paint@Widget@@QAEXXZ", CallingConvention::Cdecl, 90),
        ]);
        assert_eq!(winners.len(), 1);
        let InferredType::Convention(record) = &winners[0] else {
            unreachable!("convention records stay convention records");
        };
        assert_eq!(record.convention, CallingConvention::Thiscall);
    }

    #[test]
    fn conventions_of_two_functions_do_not_conflict() {
        let winners = resolve_conflicts(vec![
            convention("?paint@Widget@@QAEXXZ", CallingConvention::Thiscall, 90),
            convention("CreateFileA@28", CallingConvention::Stdcall, 85),
        ]);
        assert_eq!(winners.len(), 2);
    }

    #[test]
    fn a_caller_s_own_convention_and_its_view_of_a_callee_stand_apart() {
        // The call-site view keys on the (caller, callee) pair, so the
        // caller keeps its own convention record beside its view of the
        // callee. Two views of one callee inside one caller share the
        // same pair, so they resolve to the first seen.
        let site = |confidence: u8| {
            InferredType::Convention(InferredConvention {
                function: "FUN_18003ab00".into(),
                callee: Some("FUN_1800412a0".into()),
                convention: CallingConvention::Stdcall,
                method: InferenceMethod::CallSiteConvention,
                confidence: Confidence::new(confidence),
                evidence: "00401107  CALL FUN_1800412a0".into(),
            })
        };
        let winners = resolve_conflicts(vec![
            convention("FUN_18003ab00", CallingConvention::Cdecl, 70),
            site(80),
            site(80),
            convention("FUN_1800412a0", CallingConvention::Stdcall, 80),
        ]);
        assert_eq!(winners.len(), 3, "one view of the callee survives");
        let InferredType::Convention(record) = &winners[1] else {
            unreachable!("the call-site view is a convention record");
        };
        assert_eq!(record.callee.as_deref(), Some("FUN_1800412a0"));
    }

    #[test]
    fn a_convention_does_not_compete_with_the_same_function_s_return() {
        // Keyed differently on purpose: a function's return reading and
        // its convention reading are separate facts, and both survive.
        let winners = resolve_conflicts(vec![
            ret("?paint@Widget@@QAEXXZ", "char *", 60),
            convention("?paint@Widget@@QAEXXZ", CallingConvention::Thiscall, 90),
        ]);
        assert_eq!(winners.len(), 2);
    }

    #[test]
    fn a_direction_reading_does_not_compete_with_the_type_reading_for_one_parameter() {
        // The direction arm is keyed apart from the parameter arm on
        // purpose (issue #274). What a parameter *is* and which way it
        // *flows* are separate facts, and both survive: the type
        // record and the direction record stand side by side.
        let winners = resolve_conflicts(vec![
            param(
                "FUN_1800412a0",
                0,
                InferenceMethod::StringFunction,
                "char *",
                70,
            ),
            direction("FUN_1800412a0", 0, Direction::In, 60),
        ]);
        assert_eq!(winners.len(), 2);
        assert_eq!(winners[0].inferred_type(), "char *");
        assert_eq!(winners[1].inferred_type(), "in");
    }

    #[test]
    fn one_parameter_never_keeps_two_directions() {
        // Two direction readings compete for one parameter: a stronger
        // out and a weaker in. The stronger one wins, like every other
        // target.
        let winners = resolve_conflicts(vec![
            direction("FUN_1800412a0", 1, Direction::In, 60),
            direction("FUN_1800412a0", 1, Direction::Out, 75),
        ]);
        assert_eq!(winners.len(), 1);
        let InferredType::Direction(record) = &winners[0] else {
            unreachable!("direction records stay direction records");
        };
        assert_eq!(record.direction, Direction::Out);
        assert_eq!(record.confidence, Confidence::new(75));
    }

    #[test]
    fn a_direction_tie_keeps_the_reading_the_scan_showed_first() {
        let winners = resolve_conflicts(vec![
            direction("FUN_1800412a0", 1, Direction::Out, 75),
            direction("FUN_1800412a0", 1, Direction::InOut, 75),
        ]);
        assert_eq!(winners.len(), 1);
        let InferredType::Direction(record) = &winners[0] else {
            unreachable!("direction records stay direction records");
        };
        assert_eq!(record.direction, Direction::Out);
    }

    #[test]
    fn directions_of_two_functions_do_not_conflict() {
        // The key includes the function, so the same parameter position
        // in two functions is two targets — exactly as for the
        // parameter arm.
        let winners = resolve_conflicts(vec![
            direction("FUN_18003ab00", 0, Direction::Out, 75),
            direction("FUN_18003e750", 0, Direction::In, 60),
        ]);
        assert_eq!(winners.len(), 2);
        assert_eq!(winners[0].function(), "FUN_18003ab00");
        assert_eq!(winners[1].function(), "FUN_18003e750");
    }

    #[test]
    fn a_winner_stands_where_its_target_first_appeared() {
        // The stronger record for param_1 arrives after param_2's
        // record. The resolved list keeps the order the scan showed the
        // targets.
        let winners = resolve_conflicts(vec![
            param(
                "FUN_18003ab00",
                0,
                InferenceMethod::IntegerBitPattern,
                "u32",
                55,
            ),
            param(
                "FUN_18003ab00",
                1,
                InferenceMethod::PointerArithmetic,
                "void *",
                65,
            ),
            param(
                "FUN_18003ab00",
                0,
                InferenceMethod::VtableCall,
                "Widget *",
                85,
            ),
        ]);
        assert_eq!(winners.len(), 2);
        assert_eq!(winners[0].inferred_type(), "Widget *");
        assert_eq!(winners[1].inferred_type(), "void *");
    }

    #[test]
    fn a_conflict_free_scan_passes_through_unchanged() {
        let inferences = vec![
            param(
                "FUN_18003ab00",
                0,
                InferenceMethod::VtableCall,
                "Widget *",
                85,
            ),
            local("FUN_18003ab00", "local_8", 60),
            call("FUN_1800412a0", "CloseHandle", 0, "void *", 75),
            ret("FUN_180051c00", "char *", 60),
        ];
        assert_eq!(resolve_conflicts(inferences.clone()), inferences);
        assert!(resolve_conflicts(Vec::new()).is_empty());
    }
}
