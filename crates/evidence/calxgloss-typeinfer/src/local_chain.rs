//! Local-variable type inference via assignment chains.
//!
//! The inline detectors read parameters and call-site arguments; the
//! decompiler's stack slots — `local_8`, `uVar1` — stay `undefined` even
//! when the body plainly says what they hold: `local_8 = param_1;` where
//! `param_1` stands read as `char *`, or `local_10 = malloc(0x10);`
//! where the allocator's contract hands back a buffer.
//! [`LocalChainDetector`] walks one decompiled body's assignment lines
//! and types the target of each assignment whose source carries a
//! reading:
//!
//! - a parameter with a *surviving* inline reading takes that reading;
//! - a call to a known-signature routine takes the contract's return
//!   type ([`KnownTypePropagationEngine::return_type`]);
//! - another local already typed by one of those two sources propagates
//!   **one hop** — a local typed through a hop is never itself a source,
//!   so longer chains are not chased further.
//!
//! Because the parameter sources are the inline detectors' resolved
//! survivors, the pass runs after inline conflict resolution, like the
//! cross-function pass, and reads the bodies the scan already
//! decompiled. Records are the local kind the vocabulary already
//! defines — [`InferredLocalType`], keyed by function and decompiled
//! name, at [`ASSIGNMENT_CONFIDENCE`], with the assignment line as
//! evidence — so they flow through the scan's final conflict resolution,
//! persistence, and prompt rendering unchanged.
//!
//! [`KnownTypePropagationEngine::return_type`]: crate::known_type::KnownTypePropagationEngine::return_type
//! [`InferredLocalType`]: crate::types::InferredLocalType

use std::collections::{HashMap, HashSet};

use crate::cross_function::{call_callee, is_bare_identifier};
use crate::known_type::{KnownTypePropagationEngine, is_type_word};
use crate::types::{InferenceMethod, InferenceScope, InferredLocalType, InferredParamType};
use calxgloss_decomp::DecompiledFunction;

use calxgloss_types::strip_casts;

/// Confidence of an assignment-chain reading: the assignment itself is
/// direct body evidence, but the type is only as good as its source —
/// an inferred parameter reading or a library contract one step
/// removed — so it sits below every inline parameter family and at the
/// bottom of the ladder the spec sets for the new methods.
const ASSIGNMENT_CONFIDENCE: u8 = 60;

/// The surviving parameter readings of one function, by decompiled
/// parameter name — the sources an assignment can draw a type from.
/// A parameter the inline detectors never typed, or that carries no
/// usable name, is absent and lends nothing.
type ParamTypes<'a> = HashMap<&'a str, &'a str>;

/// Local-variable inference over one decompiled body.
///
/// The detector is stateless: every reading comes from the body it is
/// handed and the surviving parameter readings it is given, so one
/// detector serves an entire scan. It fetches nothing itself — the
/// engine hands it the same [`DecompiledFunction`] the inline detectors
/// already read, keeping the scan at one decompile per function.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LocalChainDetector {
    known: KnownTypePropagationEngine,
}

impl LocalChainDetector {
    /// A detector whose only contract source is the shared known-
    /// signature database; the parameter sources come in through
    /// [`detect_locals`](Self::detect_locals) at call time.
    pub fn new() -> Self {
        Self {
            known: KnownTypePropagationEngine::new(),
        }
    }

    /// The local records the body's assignment chains produce, in
    /// source order: one [`InferredLocalType`] per assignment target
    /// that a chain types, keyed by the variable's decompiled name.
    ///
    /// An assignment types its target only when the source carries a
    /// reading on its own: a bare identifier naming a parameter with a
    /// surviving reading, a call to a known-signature routine whose
    /// contract reports a return type, or a bare identifier naming a
    /// local an earlier line already typed directly (one hop, and that
    /// hop never chains further). A cast around the source —
    /// `(char *)param_1` — still names the value and is stripped.
    /// Anything else — a literal, an unknown callee, an untyped source —
    /// says nothing about the target, and an assignment shape that
    /// names no single variable (`*puVar5 = …`, `local_8[0] = …`, a
    /// comparison, a compound assignment, a write to a parameter) is
    /// not an inference about a local at all.
    ///
    /// Where one name is assigned twice, both candidate records are
    /// emitted and the scan's conflict resolution keeps the strongest,
    /// first-seen one for that target.
    pub fn detect_locals(
        &self,
        func: &DecompiledFunction,
        param_readings: &[&InferredParamType],
    ) -> Vec<InferredLocalType> {
        let params: ParamTypes = param_readings
            .iter()
            .filter_map(|record| {
                Some((record.param_name.as_deref()?, record.inferred_type.as_str()))
            })
            .collect();
        let param_names = func.parameter_names();
        let param_names: HashSet<&str> = param_names.iter().map(String::as_str).collect();

        // Locals typed directly from a parameter or a known call are
        // sources for one hop; locals typed through a hop are not
        // sources themselves, which is what caps the chain at one link.
        let mut direct: HashMap<&str, String> = HashMap::new();
        let mut records: Vec<InferredLocalType> = Vec::new();

        for line in func.body.lines() {
            let Some((target, source)) = assignment(line) else {
                continue;
            };
            if !is_bare_identifier(target) || param_names.contains(target) {
                continue;
            }
            let source = strip_casts(source, is_type_word);
            let inferred_type = if let Some(text) = params.get(source.as_str()).copied() {
                Some(text.to_string())
            } else if let Some(callee) = call_callee(&source) {
                self.known.return_type(callee).map(str::to_string)
            } else if let Some(text) = direct.get(source.as_str()) {
                // One hop from an already-typed local: the reading is
                // emitted, but the target never becomes a source.
                let text = text.clone();
                records.push(self.record(func, target, &text, line));
                continue;
            } else {
                None
            };
            if let Some(inferred_type) = inferred_type {
                direct
                    .entry(target)
                    .or_insert_with(|| inferred_type.clone());
                records.push(self.record(func, target, &inferred_type, line));
            }
        }
        records
    }

    /// Assemble one reading into its record: the assignment-chain
    /// method, function scope — the reading is about this body's slot,
    /// nothing beyond it — and the assignment line as evidence.
    fn record(
        &self,
        func: &DecompiledFunction,
        variable_name: &str,
        inferred_type: &str,
        line: &str,
    ) -> InferredLocalType {
        InferredLocalType {
            function: func.name.clone(),
            variable_name: variable_name.to_string(),
            inferred_type: inferred_type.to_string(),
            method: InferenceMethod::AssignmentChain,
            scope: InferenceScope::Function,
            confidence: ASSIGNMENT_CONFIDENCE.into(),
            evidence: line.trim().to_string(),
        }
    }
}

/// The target and source text of a plain `target = source;` assignment
/// line, or nothing when the line is not one. `==` comparisons,
/// compound assignments (`+=`, `<<=`), and declarations carry no plain
/// `=`; a line whose first plain `=` sits inside a control header or a
/// string leaves a target that is not a bare identifier, which the
/// caller rejects.
fn assignment(line: &str) -> Option<(&str, &str)> {
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'=' {
            let before = i.checked_sub(1).map(|j| bytes[j]);
            let after = bytes.get(i + 1).copied();
            let plain = after != Some(b'=')
                && !matches!(
                    before,
                    Some(
                        b'=' | b'<'
                            | b'>'
                            | b'!'
                            | b'+'
                            | b'-'
                            | b'*'
                            | b'/'
                            | b'%'
                            | b'&'
                            | b'|'
                            | b'^'
                    )
                );
            if plain {
                let target = line[..i].trim();
                let source = line[i + 1..].trim().trim_end_matches(';').trim();
                return Some((target, source));
            }
        }
        i += 1;
    }
    None
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Confidence, InferenceMethod, InferenceScope};

    fn function(signature: &str, body: &str) -> DecompiledFunction {
        DecompiledFunction {
            name: "FUN_18003ab00".into(),
            signature: signature.into(),
            body: format!("\n{signature}\n\n{{\n{body}}}\n"),
        }
    }

    fn param_reading(param_name: &str, inferred_type: &str) -> InferredParamType {
        InferredParamType {
            function: "FUN_18003ab00".into(),
            param_index: 0,
            param_name: Some(param_name.into()),
            inferred_type: inferred_type.into(),
            method: InferenceMethod::StringFunction,
            scope: InferenceScope::Function,
            confidence: Confidence::new(70),
            evidence: format!("{param_name} evidence"),
        }
    }

    fn detected(body: &str, readings: &[&InferredParamType]) -> Vec<InferredLocalType> {
        LocalChainDetector::new().detect_locals(
            &function(
                "undefined FUN_18003ab00(undefined8 param_1,undefined8 param_2)",
                body,
            ),
            readings,
        )
    }

    #[test]
    fn a_detector_carries_no_state() {
        assert_eq!(LocalChainDetector::new(), LocalChainDetector::new());
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<LocalChainDetector>();
    }

    #[test]
    fn a_local_assigned_a_typed_parameter_takes_its_reading() {
        let char_star = param_reading("param_1", "char *");
        let records = detected("  local_8 = param_1;\n", &[&char_star]);

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].variable_name, "local_8");
        assert_eq!(records[0].inferred_type, "char *");
        assert_eq!(records[0].method, InferenceMethod::AssignmentChain);
        assert_eq!(records[0].scope, InferenceScope::Function);
        assert_eq!(records[0].confidence, Confidence::new(60));
        assert_eq!(records[0].evidence, "local_8 = param_1;");
    }

    #[test]
    fn a_local_assigned_a_known_call_takes_the_contract_return() {
        // The allocator hands back a buffer, and the cast around the
        // call names no different a type — the contract's return wins.
        let records = detected("  local_8 = (char *)malloc(0x10);\n", &[]);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].variable_name, "local_8");
        assert_eq!(records[0].inferred_type, "void *");
        assert_eq!(records[0].evidence, "local_8 = (char *)malloc(0x10);");

        // A string routine's count, and a routine whose contract
        // reports no return, at one site each.
        let records = detected("  uVar1 = strlen(param_1);\n  CloseHandle(param_1);\n", &[]);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].variable_name, "uVar1");
        assert_eq!(records[0].inferred_type, "size_t");
    }

    #[test]
    fn a_local_assigned_an_untyped_source_gets_nothing() {
        // No parameter carries a surviving reading, the callee is not
        // in the database, and the literal says nothing.
        let records = detected(
            "  local_8 = param_2;\n\
             \x20 local_10 = FUN_18004b210(param_1);\n\
             \x20 local_18 = 0x10;\n",
            &[],
        );
        assert!(records.is_empty(), "no source carries a reading");
    }

    #[test]
    fn a_cast_around_the_source_still_names_the_value() {
        let char_star = param_reading("param_1", "char *");
        let records = detected("  local_8 = (char *)param_1;\n", &[&char_star]);

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].inferred_type, "char *");
    }

    #[test]
    fn a_local_assigned_another_typed_local_propagates_one_hop() {
        let char_star = param_reading("param_1", "char *");
        let records = detected(
            "  local_8 = param_1;\n\
             \x20 local_10 = local_8;\n\
             \x20 local_18 = local_10;\n",
            &[&char_star],
        );

        // The direct link and one hop; the second hop is not chased.
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].variable_name, "local_8");
        assert_eq!(records[1].variable_name, "local_10");
        assert_eq!(records[1].inferred_type, "char *");
        assert_eq!(records[1].evidence, "local_10 = local_8;");
    }

    #[test]
    fn a_hop_before_the_source_is_assigned_gets_nothing() {
        // The body reads top to bottom: at the hop line `local_8` is
        // still untyped, and the later direct assignment does not
        // reach back.
        let char_star = param_reading("param_1", "char *");
        let records = detected(
            "  local_10 = local_8;\n\
             \x20 local_8 = param_1;\n",
            &[&char_star],
        );

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].variable_name, "local_8");
    }

    #[test]
    fn two_names_in_one_function_each_get_their_own_record() {
        let char_star = param_reading("param_1", "char *");
        let records = detected(
            "  local_8 = param_1;\n\
             \x20 local_10 = malloc(0x10);\n\
             \x20 uVar1 = strlen(param_1);\n",
            &[&char_star],
        );

        assert_eq!(records.len(), 3);
        assert_eq!(records[0].variable_name, "local_8");
        assert_eq!(records[1].variable_name, "local_10");
        assert_eq!(records[2].variable_name, "uVar1");
        assert_eq!(records[2].inferred_type, "size_t");
    }

    #[test]
    fn assignment_shapes_that_name_no_local_are_skipped() {
        let char_star = param_reading("param_1", "char *");
        let records = detected(
            "  *puVar5 = param_1;\n\
             \x20 local_8[0] = param_1;\n\
             \x20 param_1 = local_8;\n\
             \x20 if (local_8 == param_1) {\n\
             \x20 local_10 += param_1;\n\
             \x20 for (uVar2 = 0; uVar2 < 3; uVar2 = uVar2 + 1) {\n",
            &[&char_star],
        );
        assert!(
            records.is_empty(),
            "a dereference, index, parameter write, comparison, compound \
             assignment, or control header types no local"
        );
    }

    #[test]
    fn one_name_assigned_twice_emits_both_candidates() {
        // Conflict resolution, not the detector, decides the winner —
        // the same target rule the cross-function pass follows.
        let char_star = param_reading("param_1", "char *");
        let records = detected(
            "  local_8 = param_1;\n\
             \x20 local_8 = malloc(0x10);\n",
            &[&char_star],
        );

        assert_eq!(records.len(), 2);
        assert_eq!(records[0].inferred_type, "char *");
        assert_eq!(records[1].inferred_type, "void *");
    }
}
