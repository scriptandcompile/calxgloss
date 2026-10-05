//! Core data types for inferred type information.
//!
//! This module holds the serialized shape of everything the inference
//! detectors produce:
//!
//! - `InferredParamType`, `InferenceMethod`, `InferenceScope`: per-parameter
//!   inference records — the narrowed type, which detector produced it, and
//!   how far the inference reaches.
//! - `InferredLocalType`, `InferredCallType`: the same record shape for
//!   inferred local variables and call-site arguments.
//! - `InferredType`: the union over the three record kinds — one inference
//!   wherever it lands.
//! - `TypeInferenceResult`, `ScanMetadata`: the persisted per-binary result
//!   and its scan provenance.
//!
//! All types derive `Serialize`/`Deserialize`.

// `ScanMetadata` is the shared per-binary scan provenance and `Confidence`
// the shared 0–100 evidence score; both are re-exported so consumers name
// them through this crate, matching the typesdb convention.
pub use calxgloss_types::{Confidence, ScanMetadata};
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
// Inferred local variables and call sites
// ============================================================

/// A local variable's inferred type, with the evidence behind it.
///
/// The sibling of [`InferredParamType`] for the decompiler's stack slots:
/// the same hypothesis shape — narrowed type, method, scope, confidence,
/// evidence — keyed by the variable's decompiled name instead of a
/// parameter position.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InferredLocalType {
    /// The function the variable belongs to, e.g. `FUN_18003ab00`.
    pub function: String,
    /// The variable's name in the decompiled output, e.g. `local_8`.
    pub variable_name: String,
    /// The narrowed type as C text, e.g. `Widget *`, `char *`, `u32`.
    pub inferred_type: String,
    /// The technique that produced the inference.
    pub method: InferenceMethod,
    /// How far the inference reaches beyond this function.
    pub scope: InferenceScope,
    /// Confidence that the inference is right, 0–100.
    pub confidence: Confidence,
    /// The decompiled line or pattern that supports the inference.
    pub evidence: String,
}

/// One call-site argument's inferred type, with the evidence behind it.
///
/// A known library signature types the argument sitting at one of its
/// positions; this record pins the reading to the site that produced it —
/// the enclosing function, the callee as spelled there, and the argument
/// position — so conflict resolution and the prompt rendering can tell
/// where the contract was seen, not just what it typed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InferredCallType {
    /// The function holding the call site, e.g. `FUN_18003ab00`.
    pub function: String,
    /// The callee as spelled at the site, e.g. `CloseHandle`.
    pub callee: String,
    /// Argument position at the call site, starting at 0.
    pub arg_index: usize,
    /// The argument's variable name when it is one, e.g. `param_2`.
    /// `None` when the argument is a literal, cast, or nested call.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arg_name: Option<String>,
    /// The narrowed type as C text, e.g. `void *`, `wchar_t *`.
    pub inferred_type: String,
    /// The technique that produced the inference.
    pub method: InferenceMethod,
    /// How far the inference reaches beyond this function.
    pub scope: InferenceScope,
    /// Confidence that the inference is right, 0–100.
    pub confidence: Confidence,
    /// The decompiled line carrying the call site.
    pub evidence: String,
}

// ============================================================
// Inference union
// ============================================================

/// One inferred type wherever it lands — a parameter, a local variable,
/// or a call-site argument.
///
/// The detectors emit the concrete records; the union is what the
/// persisted result carries, so one list can hold every inference for a
/// binary and conflict resolution can weigh records across kinds by
/// confidence. The serde `kind` tag names the record shape in the
/// persisted JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum InferredType {
    /// A narrowed function parameter.
    Param(InferredParamType),
    /// A narrowed local variable.
    Local(InferredLocalType),
    /// A narrowed call-site argument.
    CallSite(InferredCallType),
}

impl InferredType {
    /// The function the inference belongs to.
    pub fn function(&self) -> &str {
        match self {
            InferredType::Param(record) => &record.function,
            InferredType::Local(record) => &record.function,
            InferredType::CallSite(record) => &record.function,
        }
    }

    /// The narrowed type as C text.
    pub fn inferred_type(&self) -> &str {
        match self {
            InferredType::Param(record) => &record.inferred_type,
            InferredType::Local(record) => &record.inferred_type,
            InferredType::CallSite(record) => &record.inferred_type,
        }
    }

    /// Confidence that the inference is right.
    pub fn confidence(&self) -> Confidence {
        match self {
            InferredType::Param(record) => record.confidence,
            InferredType::Local(record) => record.confidence,
            InferredType::CallSite(record) => record.confidence,
        }
    }
}

// ============================================================
// Persisted result
// ============================================================

/// The inference result for one binary — the document persisted to
/// `re/analysis/typeinfer/{dll}.json`.
///
/// The inferences are the resolved outputs of the detectors: at most one
/// record per parameter, local, or call-site argument, highest confidence
/// winning where detectors competed. The list keeps scan order — function
/// by function, records in the order the bodies showed them — so two
/// scans of the same program diff cleanly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypeInferenceResult {
    /// Provenance of the scan that produced these inferences.
    pub metadata: ScanMetadata,
    /// Every surviving inference, in scan order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inferences: Vec<InferredType>,
}

impl TypeInferenceResult {
    /// An empty result for the binary described by `metadata`.
    pub fn new(metadata: ScanMetadata) -> Self {
        Self {
            metadata,
            inferences: Vec::new(),
        }
    }

    /// The inferences recorded for one function, e.g. `FUN_18003ab00`.
    pub fn for_function(&self, function: &str) -> impl Iterator<Item = &InferredType> {
        self.inferences
            .iter()
            .filter(move |inference| inference.function() == function)
    }

    /// Whether the scan inferred nothing at all.
    pub fn is_empty(&self) -> bool {
        self.inferences.is_empty()
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

    fn param_record() -> InferredParamType {
        InferredParamType {
            function: "FUN_18003ab00".into(),
            param_index: 0,
            param_name: Some("param_1".into()),
            inferred_type: "Widget *".into(),
            method: InferenceMethod::VtableCall,
            scope: InferenceScope::Class,
            confidence: Confidence::new(85),
            evidence: "(*(code *)(**param_1))[3](param_1)".into(),
        }
    }

    fn local_record() -> InferredLocalType {
        InferredLocalType {
            function: "FUN_18003ab00".into(),
            variable_name: "local_8".into(),
            inferred_type: "char *".into(),
            method: InferenceMethod::KnownSignature,
            scope: InferenceScope::Function,
            confidence: Confidence::new(60),
            evidence: "local_8 = (char *)malloc(0x10);".into(),
        }
    }

    fn call_record() -> InferredCallType {
        InferredCallType {
            function: "FUN_1800412a0".into(),
            callee: "CloseHandle".into(),
            arg_index: 0,
            arg_name: Some("param_2".into()),
            inferred_type: "void *".into(),
            method: InferenceMethod::KnownSignature,
            scope: InferenceScope::Program,
            confidence: Confidence::new(75),
            evidence: "CloseHandle(param_2);".into(),
        }
    }

    fn metadata() -> ScanMetadata {
        ScanMetadata {
            binary: "eqmain.dll".into(),
            scanned_at: 1_759_488_000,
            duration_secs: 12,
        }
    }

    #[test]
    fn a_local_inference_serde_round_trips() {
        let record = local_record();
        let json = serde_json::to_string(&record).unwrap();
        let back: InferredLocalType = serde_json::from_str(&json).unwrap();
        assert_eq!(back, record);
    }

    #[test]
    fn a_call_inference_serde_round_trips_and_an_unnamed_argument_omits_its_name() {
        let record = call_record();
        let json = serde_json::to_string(&record).unwrap();
        let back: InferredCallType = serde_json::from_str(&json).unwrap();
        assert_eq!(back, record);

        let literal_arg = InferredCallType {
            arg_name: None,
            ..call_record()
        };
        let json = serde_json::to_string(&literal_arg).unwrap();
        assert!(!json.contains("\"arg_name\""));
        let back: InferredCallType = serde_json::from_str(&json).unwrap();
        assert_eq!(back, literal_arg);
    }

    #[test]
    fn the_inference_union_tags_its_kind_in_json() {
        let inferences = vec![
            InferredType::Param(param_record()),
            InferredType::Local(local_record()),
            InferredType::CallSite(call_record()),
        ];
        let json = serde_json::to_string(&inferences).unwrap();
        assert!(json.contains("\"kind\":\"param\""));
        assert!(json.contains("\"kind\":\"local\""));
        assert!(json.contains("\"kind\":\"call_site\""));
        let back: Vec<InferredType> = serde_json::from_str(&json).unwrap();
        assert_eq!(back, inferences);
    }

    #[test]
    fn union_accessors_reach_through_every_variant() {
        let inferences = [
            InferredType::Param(param_record()),
            InferredType::Local(local_record()),
            InferredType::CallSite(call_record()),
        ];
        assert_eq!(inferences[0].function(), "FUN_18003ab00");
        assert_eq!(inferences[1].function(), "FUN_18003ab00");
        assert_eq!(inferences[2].function(), "FUN_1800412a0");
        assert_eq!(inferences[0].inferred_type(), "Widget *");
        assert_eq!(inferences[1].inferred_type(), "char *");
        assert_eq!(inferences[2].inferred_type(), "void *");
        assert_eq!(inferences[0].confidence(), Confidence::new(85));
        assert_eq!(inferences[2].confidence(), Confidence::new(75));
    }

    #[test]
    fn type_inference_result_serde_round_trips_all_three_kinds() {
        let result = TypeInferenceResult {
            metadata: metadata(),
            inferences: vec![
                InferredType::Param(param_record()),
                InferredType::Local(local_record()),
                InferredType::CallSite(call_record()),
            ],
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: TypeInferenceResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back, result);
        assert!(!back.is_empty());
    }

    #[test]
    fn a_metadata_only_result_omits_its_inferences_and_reads_back() {
        let result = TypeInferenceResult::new(metadata());
        let json = serde_json::to_string(&result).unwrap();
        assert!(!json.contains("\"inferences\""));
        let back: TypeInferenceResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back, result);
        assert!(back.is_empty());
    }

    #[test]
    fn a_result_without_an_inferences_field_reads_back_empty() {
        // Documents persisted before the field existed still load.
        let json = r#"{
            "metadata": {
                "binary": "eqmain.dll",
                "scanned_at": 1759488000,
                "duration_secs": 12
            }
        }"#;
        let back: TypeInferenceResult = serde_json::from_str(json).unwrap();
        assert_eq!(back.metadata.binary, "eqmain.dll");
        assert!(back.inferences.is_empty());
    }

    #[test]
    fn result_lookups_key_on_the_function_name() {
        let result = TypeInferenceResult {
            metadata: metadata(),
            inferences: vec![
                InferredType::Param(param_record()),
                InferredType::Local(local_record()),
                InferredType::CallSite(call_record()),
            ],
        };
        assert_eq!(result.for_function("FUN_18003ab00").count(), 2);
        assert_eq!(result.for_function("FUN_1800412a0").count(), 1);
        assert_eq!(result.for_function("FUN_180099999").count(), 0);
    }

    #[test]
    fn scan_metadata_new_stamps_the_current_time() {
        let meta = ScanMetadata::new("eqmain.dll");
        assert_eq!(meta.binary, "eqmain.dll");
        assert!(meta.scanned_at > 0);
        assert_eq!(meta.duration_secs, 0);
    }
}
