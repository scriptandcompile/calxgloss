//! Core data types for inferred type information.
//!
//! This module holds the serialized shape of everything the inference
//! detectors produce:
//!
//! - `InferredParamType`, `InferenceMethod`, `InferenceScope`: per-parameter
//!   inference records — the narrowed type, which detector produced it, and
//!   how far the inference reaches.
//! - `InferredType`, `InferredLocalType`, `InferredCallType`: inferred types
//!   for parameters, local variables, and call sites.
//! - `TypeInferenceResult`, `ScanMetadata`: the persisted per-binary result
//!   and its scan provenance.
//!
//! All types derive `Serialize`/`Deserialize`.

use calxgloss_types::Confidence;
use serde::{Deserialize, Serialize};

// ============================================================
// Inference method
// ============================================================

/// The technique that produced an inference.
///
/// Each detector contributes its own methods, and the method names the
/// evidence shape behind a narrowed type — a `vtable[index]` call reads
/// differently than a `strlen` call site — so conflict resolution and the
/// prompt rendering can weigh and explain inferences by how they were made.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InferenceMethod {
    /// A `vtable[index]` call through the parameter marks it as a `this`
    /// pointer of the class owning that table.
    VtableCall,
    /// First-parameter usage — field accesses and self-referential calls in
    /// the shape of a member function — marks it as a `this` pointer.
    FirstParamUsage,
    /// The parameter's vtable prefix spells the COM `IUnknown` trio
    /// (QueryInterface / AddRef / Release), so the parameter is an
    /// interface pointer.
    ComInterface,
    /// A string-function call (`strlen`, `strcpy`, `strcmp`, ...) narrows the
    /// parameter to a character pointer.
    StringFunction,
    /// Shift and mask usage suggests an integer of a particular width.
    IntegerBitPattern,
    /// Dereference and offset arithmetic suggest a pointer to something.
    PointerArithmetic,
    /// A known library signature (`malloc`, `CloseHandle`, ...) propagates
    /// the callee's parameter type to the argument.
    KnownSignature,
}

impl InferenceMethod {
    /// Whether the method infers a `this` pointer rather than a plain
    /// parameter type.
    pub fn is_this_pointer(&self) -> bool {
        matches!(
            self,
            InferenceMethod::VtableCall
                | InferenceMethod::FirstParamUsage
                | InferenceMethod::ComInterface
        )
    }
}

calxgloss_types::display_serde_label!(InferenceMethod {
    VtableCall => "vtable_call",
    FirstParamUsage => "first_param_usage",
    ComInterface => "com_interface",
    StringFunction => "string_function",
    IntegerBitPattern => "integer_bit_pattern",
    PointerArithmetic => "pointer_arithmetic",
    KnownSignature => "known_signature",
});

// ============================================================
// Inference scope
// ============================================================

/// How far an inference reaches beyond the function it was made in.
///
/// The scope says what else may be re-typed from one finding: a `this`
/// pointer is a property of the class, so every method of that class takes
/// the same first parameter, while a known library signature types the same
/// argument position at every call site in the program.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InferenceScope {
    /// Valid only for this function's parameter — the evidence lives in this
    /// decompiled body and reaches nowhere else.
    Function,
    /// Valid for the same parameter of every method of the recovered class —
    /// the inference came from a `this` pointer or vtable reading.
    Class,
    /// Valid at every call site carrying the same value — the inference came
    /// from a known signature that holds program-wide.
    Program,
}

calxgloss_types::display_serde_label!(InferenceScope {
    Function => "function",
    Class => "class",
    Program => "program",
});

// ============================================================
// Inferred parameter types
// ============================================================

/// One parameter's inferred type, with the evidence behind it.
///
/// A record is a hypothesis, not a fact applied to the program: the
/// narrowed type comes from how the decompiled body *uses* the parameter,
/// and the method, scope, confidence, and evidence together say how far the
/// body's reading supports it. Detectors emit these records; conflict
/// resolution keeps the highest-confidence one per parameter, and the
/// survivors are persisted and rendered into translation prompts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InferredParamType {
    /// The function the parameter belongs to, e.g. `FUN_18003ab00`.
    pub function: String,
    /// Parameter position, starting at 0.
    pub param_index: usize,
    /// The parameter's name in the decompiled output, e.g. `param_1`.
    /// `None` when the body gave the parameter no usable name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub param_name: Option<String>,
    /// The narrowed type as C text, e.g. `Widget *`, `char *`, `u32`.
    pub inferred_type: String,
    /// The technique that produced the inference.
    pub method: InferenceMethod,
    /// How far the inference reaches beyond this function.
    pub scope: InferenceScope,
    /// Confidence that the inference is right, 0–100.
    pub confidence: Confidence,
    /// The decompiled line or pattern that supports the inference — kept so
    /// a reviewer (or a translation prompt) can check the reasoning.
    pub evidence: String,
}

impl InferredParamType {
    /// Whether the inference narrows the parameter to a pointer type.
    pub fn is_pointer(&self) -> bool {
        self.inferred_type.ends_with('*')
    }

    /// Whether the record asserts the parameter is a `this` pointer.
    pub fn is_this_pointer(&self) -> bool {
        self.method.is_this_pointer()
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inferred_param_type_serde_round_trips() {
        let record = InferredParamType {
            function: "FUN_18003ab00".into(),
            param_index: 0,
            param_name: Some("param_1".into()),
            inferred_type: "Widget *".into(),
            method: InferenceMethod::VtableCall,
            scope: InferenceScope::Class,
            confidence: Confidence::new(85),
            evidence: "(*(code *)(**param_1))[3](param_1)".into(),
        };
        let json = serde_json::to_string(&record).unwrap();
        // Methods and scopes serialize snake_case, matching the workspace's
        // serde convention.
        assert!(json.contains("\"method\":\"vtable_call\""));
        assert!(json.contains("\"scope\":\"class\""));
        let back: InferredParamType = serde_json::from_str(&json).unwrap();
        assert_eq!(back, record);
        assert!(record.is_pointer());
        assert!(record.is_this_pointer());
    }

    #[test]
    fn an_unnamed_parameter_omits_its_name() {
        let record = InferredParamType {
            function: "FUN_1800412a0".into(),
            param_index: 1,
            param_name: None,
            inferred_type: "char *".into(),
            method: InferenceMethod::StringFunction,
            scope: InferenceScope::Function,
            confidence: Confidence::new(70),
            evidence: "strlen(param_2)".into(),
        };
        let json = serde_json::to_string(&record).unwrap();
        assert!(!json.contains("\"param_name\""));
        let back: InferredParamType = serde_json::from_str(&json).unwrap();
        assert_eq!(back, record);
        assert!(!back.is_this_pointer());
    }

    #[test]
    fn a_missing_optional_field_reads_back_as_none() {
        // Documents persisted before a field existed still load.
        let json = r#"{
            "function": "FUN_180052010",
            "param_index": 2,
            "inferred_type": "u32",
            "method": "integer_bit_pattern",
            "scope": "function",
            "confidence": 55,
            "evidence": "param_3 & 0xff00 >> 8"
        }"#;
        let back: InferredParamType = serde_json::from_str(json).unwrap();
        assert_eq!(back.param_name, None);
        assert_eq!(back.method, InferenceMethod::IntegerBitPattern);
        assert!(!back.is_pointer());
    }

    #[test]
    fn this_pointer_methods_are_grouped_apart_from_plain_narrowing() {
        assert!(InferenceMethod::VtableCall.is_this_pointer());
        assert!(InferenceMethod::FirstParamUsage.is_this_pointer());
        assert!(InferenceMethod::ComInterface.is_this_pointer());
        assert!(!InferenceMethod::StringFunction.is_this_pointer());
        assert!(!InferenceMethod::KnownSignature.is_this_pointer());
    }

    #[test]
    fn methods_and_scopes_display_their_serde_labels() {
        assert_eq!(InferenceMethod::VtableCall.to_string(), "vtable_call");
        assert_eq!(
            InferenceMethod::IntegerBitPattern.to_string(),
            "integer_bit_pattern"
        );
        assert_eq!(InferenceScope::Function.to_string(), "function");
        assert_eq!(InferenceScope::Program.to_string(), "program");
    }
}
