//! Cross-function type propagation, in both directions.
//!
//! The inline detectors read one body at a time, so a type recovered
//! inside a helper stops at its closing brace. [`CrossFunctionPropagator`]
//! carries those readings across the boundary in two directions:
//!
//! - **callee → caller** ([`propagate`](CrossFunctionPropagator::propagate)):
//!   when a function's *surviving* parameter readings describe a
//!   user-defined callee, the readings type the arguments sitting at that
//!   callee's call sites — emitted as the call-site record kind the
//!   vocabulary already defines — and when a typed argument is one of the
//!   caller's own parameters, that parameter gets a reading too, so the
//!   type climbs the call chain.
//! - **caller → callee** ([`propagate_to_callee`](CrossFunctionPropagator::propagate_to_callee)):
//!   what a function's callers actually pass at their call sites types
//!   that function's own parameters, so a helper whose body shows no
//!   interesting usage still gets typed from the contract its callers
//!   reveal.
//!
//! Unlike [`KnownSignature`] propagation, there is no database to look
//! the contract up in: it is what this very scan inferred, which is why
//! both passes run after the inline detectors and read only their
//! resolved survivors. A callee the scan never typed — or a library
//! routine it never decompiles — carries no readings and propagates
//! nothing.
//!
//! [`KnownSignature`]: crate::types::InferenceMethod::KnownSignature

use std::collections::HashMap;

use crate::known_type::{CHAR_STRING, KnownTypePropagationEngine, WIDE_STRING};
use crate::types::{
    InferenceMethod, InferenceScope, InferredCallType, InferredParamType, InferredType,
};
use calxgloss_decomp::DecompiledFunction;

use calxgloss_types::{
    CallSite, NON_CALL_KEYWORDS, NameContinuation, ScanOptions, call_sites, line_at,
};

/// The scan: plain-identifier callees, member accesses skipped, and C
/// keywords — `if (x)` — not calls. The same shape the known-signature
/// engine uses: this pass reads the same direct-call sites, just against
/// a different contract source.
const CALL_SCAN: ScanOptions = ScanOptions {
    continuation: NameContinuation::Ident,
    reject_preceding: b".>",
    skip_keywords: &NON_CALL_KEYWORDS,
};

/// Every direct call `name(args)` in the body — the shared pseudo-C
/// scan configured by [`CALL_SCAN`].
fn direct_calls(body: &str) -> Vec<CallSite<'_>> {
    call_sites(body, &CALL_SCAN)
}

/// Confidence of a reading propagated to a call-site argument: the
/// callee's contract is this scan's own inference, one step removed from
/// the direct body evidence the inline detectors carry, but the site is
/// concrete — this call, this argument — so the reading sits at the top
/// of the cross-function band, level with the C library's contracts.
const CALLSITE_CONFIDENCE: u8 = 70;

/// Confidence of the caller-parameter reading that rides along when the
/// typed argument is the caller's own parameter: one step further out
/// than the site itself — the parameter's type is only as good as the
/// assumption that the caller passes the same kind of value at every
/// site — so it sits at the bottom of the band, where it loses any tie
/// against a direct inline reading of the same parameter.
const PARAM_CONFIDENCE: u8 = 65;

/// Confidence of a reading propagated from a caller's argument back to
/// the callee's own parameter: the callee's type is inferred from what
/// its callers pass, one step removed from the callee's direct body
/// evidence and aggregated across call sites, so it sits at the bottom
/// of the cross-function band — level with the caller-parameter climb —
/// where it loses any tie against the callee's own inline reading and
/// every stronger inline reading outright.
const CALLER_PARAM_CONFIDENCE: u8 = 65;

/// The surviving parameter readings a scan propagates from, grouped by
/// the function that carries them: a callee name maps to its resolved
/// parameter records, one per typed position. The engine builds the map
/// from its resolved inline records; a callee absent from it — a library
/// routine, a thunk that never decompiled, a function no detector read —
/// carries no contract to propagate.
pub type CalleeParams<'a> = HashMap<&'a str, Vec<&'a InferredParamType>>;

/// Callee-to-caller propagation over one decompiled body.
///
/// The detector is stateless: every reading comes from the body it is
/// handed and the surviving-reading map it is given, so one detector
/// serves an entire scan and can be shared across concurrent per-function
/// passes. It fetches nothing itself — the engine hands it the same
/// [`DecompiledFunction`] the inline detectors already read, keeping the
/// scan at one decompile per function.
///
/// [`DecompiledFunction`]: calxgloss_decomp::DecompiledFunction
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CrossFunctionPropagator;

impl CrossFunctionPropagator {
    /// A propagator with no state and no contract table of its own — the
    /// contracts come in through [`CalleeParams`] at call time.
    pub fn new() -> Self {
        Self
    }

    /// The records the body's user-defined call sites propagate, in
    /// source order: one [`InferredType::CallSite`] per typed argument,
    /// plus an [`InferredType::Param`] for the enclosing function's own
    /// parameter when the typed argument names one.
    ///
    /// A call whose callee carries a surviving reading at position *i*
    /// reads the argument sitting at *i* as the callee's parameter type,
    /// at [`CALLSITE_CONFIDENCE`], with the call's own line as evidence
    /// and [`InferenceScope::Function`] — the reading is about this site,
    /// not every site carrying the value. When the argument is a bare
    /// identifier that names one of the enclosing function's parameters,
    /// that parameter also gets a record at [`PARAM_CONFIDENCE`], so the
    /// type climbs one step up the call chain. An argument that is a
    /// literal, a cast, or a nested call names no value to read and
    /// produces nothing, and a callee with no surviving reading at a
    /// position types nothing sitting there.
    ///
    /// Where two sites in one body share a target — the same callee at
    /// the same argument position — both records are emitted and the
    /// scan's conflict resolution keeps the strongest, first-seen one.
    pub fn propagate(
        &self,
        func: &DecompiledFunction,
        callee_params: &CalleeParams,
    ) -> Vec<InferredType> {
        let params = func.parameter_names();
        let mut records = Vec::new();
        for call in direct_calls(&func.body) {
            let Some(readings) = callee_params.get(call.callee) else {
                continue;
            };
            let evidence = line_at(&func.body, call.offset);
            for reading in readings {
                let Some(text) = call.args.get(reading.param_index) else {
                    continue;
                };
                if !is_bare_identifier(text) {
                    continue;
                }
                records.push(InferredType::CallSite(InferredCallType {
                    function: func.name.clone(),
                    callee: call.callee.to_string(),
                    arg_index: reading.param_index,
                    arg_name: Some(text.to_string()),
                    inferred_type: reading.inferred_type.clone(),
                    method: InferenceMethod::CrossFunction,
                    scope: InferenceScope::Function,
                    confidence: CALLSITE_CONFIDENCE.into(),
                    evidence: evidence.clone(),
                }));
                // The argument is the caller's own parameter: the
                // reading climbs one step up the call chain.
                if let Some(index) = params.iter().position(|p| p == text) {
                    records.push(InferredType::Param(InferredParamType {
                        function: func.name.clone(),
                        param_index: index,
                        param_name: Some(text.to_string()),
                        inferred_type: reading.inferred_type.clone(),
                        method: InferenceMethod::CrossFunction,
                        scope: InferenceScope::Function,
                        confidence: PARAM_CONFIDENCE.into(),
                        evidence: evidence.clone(),
                    }));
                }
            }
        }
        records
    }

    /// Read what `callers` pass at their call sites of `callee`, and type
    /// `callee`'s own parameters with it.
    ///
    /// This is the reverse direction of [`propagate`](Self::propagate):
    /// instead of a helper's contract reaching out to its callers, the
    /// values callers actually hand in reach back to the helper's
    /// parameters — so a function whose own body shows no interesting
    /// usage still gets typed from the contract its callers reveal.
    ///
    /// An argument types a parameter only when it carries a recognizable
    /// type on its own, without needing the callee's body to say so:
    ///
    /// - a bare identifier naming one of the *caller's* parameters, read
    ///   through that caller's surviving inline readings — the caller
    ///   passes along, untouched, something it was itself handed;
    /// - a string literal — `"…"` is a character string, `L"…"` a wide
    ///   one, whatever the callee then does with it;
    /// - a call to a known-signature routine — the allocator hands back
    ///   a buffer, `strlen` a byte count
    ///   ([`KnownTypePropagationEngine::return_type`]).
    ///
    /// Anything else — a numeric literal, a cast, an indexing or member
    /// operand, an identifier the scan never typed — says nothing about
    /// the parameter, and the position gets no reading. The call site
    /// itself may still be typed by the callee→caller pass when the
    /// callee's own contract says something; that is not this pass's
    /// business, and typing the callee's parameter from a bare literal
    /// would be.
    ///
    /// Readings land at [`CALLER_PARAM_CONFIDENCE`], the bottom of the
    /// cross-function band, so the callee's own inline evidence — a vtable
    /// call at 85, or any inline reading on a tie — still wins. A position
    /// only gets a record when the callee's signature actually has a
    /// parameter there; a caller passing more arguments than the callee
    /// declares (a decompiler prototype gap) types nothing.
    ///
    /// [`KnownTypePropagationEngine::return_type`]: crate::known_type::KnownTypePropagationEngine::return_type
    pub fn propagate_to_callee(
        &self,
        callee: &DecompiledFunction,
        callers: &[&DecompiledFunction],
        caller_readings: &CalleeParams,
    ) -> Vec<InferredType> {
        let params = callee.parameter_names();
        let known = KnownTypePropagationEngine::new();
        let mut records = Vec::new();
        for caller in callers {
            for call in direct_calls(&caller.body) {
                if call.callee != callee.name {
                    continue;
                }
                let evidence = format!("{} passes {}", caller.name, callee.name);
                for (position, arg) in call.args.iter().enumerate() {
                    if position >= params.len() {
                        continue;
                    }
                    let Some(inferred_type) =
                        self.argument_type(arg, caller, caller_readings, &known)
                    else {
                        continue;
                    };
                    records.push(InferredType::Param(InferredParamType {
                        function: callee.name.clone(),
                        param_index: position,
                        param_name: params.get(position).cloned(),
                        inferred_type,
                        method: InferenceMethod::CrossFunction,
                        scope: InferenceScope::Function,
                        confidence: CALLER_PARAM_CONFIDENCE.into(),
                        evidence: evidence.clone(),
                    }));
                }
            }
        }
        records
    }

    /// The type an argument text carries on its own, or nothing when it
    /// carries none. See [`propagate_to_callee`](Self::propagate_to_callee)
    /// for the three recognizable shapes.
    fn argument_type(
        &self,
        arg: &str,
        caller: &DecompiledFunction,
        caller_readings: &CalleeParams,
        known: &KnownTypePropagationEngine,
    ) -> Option<String> {
        if is_bare_identifier(arg) {
            // The caller passes along, untouched, one of its own
            // parameters: whatever the inline detectors settled on for
            // that parameter is what the callee receives. A parameter
            // the scan never typed, or a local or global the scan has no
            // reading for, carries nothing.
            let index = caller.parameter_names().iter().position(|p| p == arg)?;
            let readings = caller_readings.get(caller.name.as_str())?;
            readings
                .iter()
                .find(|r| r.param_index == index)
                .map(|r| r.inferred_type.clone())
        } else if let Some(text) = string_literal_type(arg) {
            Some(text.to_string())
        } else if let Some(callee) = call_callee(arg) {
            // A known routine's result: the signature database knows what
            // the call hands back.
            known.return_type(callee).map(str::to_string)
        } else {
            None
        }
    }
}

/// The type a string literal argument carries: `"…"` is a character
/// string, `L"…"` a wide one. Only a whole literal counts — an operand
/// that merely starts with a quote (`"name"[0]`) is an expression, not
/// a literal, and anything else reports nothing.
fn string_literal_type(arg: &str) -> Option<&'static str> {
    let text = arg.trim();
    if text.len() < 2 || !text.ends_with('"') {
        return None;
    }
    if text.starts_with('"') {
        Some(CHAR_STRING)
    } else if text.starts_with("L\"") {
        Some(WIDE_STRING)
    } else {
        None
    }
}

/// The callee name of a plain `name(...)` argument, or nothing when the
/// argument is not shaped like a direct call.
pub(crate) fn call_callee(arg: &str) -> Option<&str> {
    let open = arg.find('(')?;
    let name = arg[..open].trim();
    is_bare_identifier(name).then_some(name)
}

/// Whether the argument text is a plain variable name — the only shape
/// this pass reads. A literal (`"name"`, `0x10`), a cast (`(char *)x`),
/// an indexed or member operand (`a[0]`, `a.b`), or a nested call all
/// carry punctuation and name no single value to type.
pub(crate) fn is_bare_identifier(text: &str) -> bool {
    let mut bytes = text.bytes();
    matches!(bytes.next(), Some(b) if b.is_ascii_alphabetic() || b == b'_')
        && text.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn function(signature: &str, body: &str) -> DecompiledFunction {
        DecompiledFunction {
            name: "FUN_180051c00".into(),
            signature: signature.into(),
            body: body.into(),
        }
    }

    fn param_record(
        function: &str,
        param_index: usize,
        inferred_type: &str,
        confidence: u8,
    ) -> InferredParamType {
        InferredParamType {
            function: function.into(),
            param_index,
            param_name: Some(format!("param_{}", param_index + 1)),
            inferred_type: inferred_type.into(),
            method: InferenceMethod::StringFunction,
            scope: InferenceScope::Function,
            confidence: confidence.into(),
            evidence: format!("strlen(param_{});", param_index + 1),
        }
    }

    /// The canned contract: `FUN_18004b210`'s first parameter reads as
    /// `char *` and its second as `void *`.
    fn propagated(signature: &str, body: &str) -> Vec<InferredType> {
        let first = param_record("FUN_18004b210", 0, "char *", 70);
        let second = param_record("FUN_18004b210", 1, "void *", 75);
        let callee_params: CalleeParams = HashMap::from([("FUN_18004b210", vec![&first, &second])]);
        CrossFunctionPropagator::new().propagate(&function(signature, body), &callee_params)
    }

    /// The one-reading contract: only position 0 of `FUN_18004b210` is
    /// typed, so only the first argument of a call can take a reading.
    fn propagated_once(signature: &str, body: &str) -> Vec<InferredType> {
        let first = param_record("FUN_18004b210", 0, "char *", 70);
        let callee_params: CalleeParams = HashMap::from([("FUN_18004b210", vec![&first])]);
        CrossFunctionPropagator::new().propagate(&function(signature, body), &callee_params)
    }

    fn call_sites_of(records: &[InferredType]) -> Vec<&InferredCallType> {
        records
            .iter()
            .filter_map(|record| match record {
                InferredType::CallSite(record) => Some(record),
                _ => None,
            })
            .collect()
    }

    fn params_of(records: &[InferredType]) -> Vec<&InferredParamType> {
        records
            .iter()
            .filter_map(|record| match record {
                InferredType::Param(record) => Some(record),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn a_detector_carries_no_state() {
        let detector = CrossFunctionPropagator::new();
        assert_eq!(detector, CrossFunctionPropagator);
        assert_eq!(detector.clone(), detector);
    }

    #[test]
    fn a_detector_can_be_shared_across_scans() {
        // The detector is driven over a program's functions, so sharing
        // one by reference across tasks must stay sound.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<CrossFunctionPropagator>();
    }

    #[test]
    fn a_surviving_callee_reading_types_the_argument_at_its_call_site() {
        let records = propagated_once(
            "undefined FUN_180051c00(void)",
            "  FUN_18004b210(local_8, local_10);",
        );
        let sites = call_sites_of(&records);
        assert_eq!(sites.len(), 1);
        let record = sites[0];
        assert_eq!(record.function, "FUN_180051c00");
        assert_eq!(record.callee, "FUN_18004b210");
        assert_eq!(record.arg_index, 0);
        assert_eq!(record.arg_name.as_deref(), Some("local_8"));
        assert_eq!(record.inferred_type, "char *");
        assert_eq!(record.method, InferenceMethod::CrossFunction);
        // The reading is about this site, not every site carrying the
        // value: it reaches no further than this body.
        assert_eq!(record.scope, InferenceScope::Function);
        assert_eq!(record.confidence, CALLSITE_CONFIDENCE);
        assert_eq!(record.evidence, "FUN_18004b210(local_8, local_10);");
        assert!((65..=70).contains(&record.confidence.value()));
    }

    #[test]
    fn each_typed_position_types_its_own_argument() {
        // The callee reads positions 0 and 1; the call's second argument
        // stands at position 1 and takes the second reading.
        let records = propagated(
            "undefined FUN_180051c00(void)",
            "  FUN_18004b210(local_8, local_10);",
        );
        let sites = call_sites_of(&records);
        assert_eq!(sites.len(), 2);
        assert_eq!(sites[0].arg_index, 0);
        assert_eq!(sites[0].inferred_type, "char *");
        assert_eq!(sites[1].arg_index, 1);
        assert_eq!(sites[1].arg_name.as_deref(), Some("local_10"));
        assert_eq!(sites[1].inferred_type, "void *");
    }

    #[test]
    fn an_argument_that_is_the_caller_s_own_parameter_gets_a_parameter_record_too() {
        let records = propagated(
            "undefined FUN_180051c00(undefined8 param_1)",
            "  FUN_18004b210(param_1, 0x10);",
        );
        let sites = call_sites_of(&records);
        let params = params_of(&records);
        assert_eq!(sites.len(), 1);
        assert_eq!(params.len(), 1);
        let record = params[0];
        assert_eq!(record.function, "FUN_180051c00");
        assert_eq!(record.param_index, 0);
        assert_eq!(record.param_name.as_deref(), Some("param_1"));
        assert_eq!(record.inferred_type, "char *");
        assert_eq!(record.method, InferenceMethod::CrossFunction);
        assert_eq!(record.scope, InferenceScope::Function);
        // The climb sits below the site reading it came from.
        assert_eq!(record.confidence, PARAM_CONFIDENCE);
        assert!(record.confidence < sites[0].confidence);
        assert_eq!(record.evidence, "FUN_18004b210(param_1, 0x10);");
    }

    #[test]
    fn a_local_argument_gets_no_parameter_record() {
        // The site is still typed, but a local is not a parameter — the
        // climb only happens for the enclosing function's own parameters.
        let records = propagated(
            "undefined FUN_180051c00(undefined8 param_1)",
            "  FUN_18004b210(local_8, 0x10);",
        );
        assert_eq!(call_sites_of(&records).len(), 1);
        assert!(params_of(&records).is_empty());
    }

    #[test]
    fn literal_cast_and_nested_call_arguments_produce_no_records() {
        let records = propagated(
            "undefined FUN_180051c00(undefined8 param_1)",
            "  FUN_18004b210(\"name\", 0x10);\n\
             \x20 FUN_18004b210((char *)param_1, param_1);\n\
             \x20 FUN_18004b210(get_name(), param_1);",
        );
        // Only the second and third calls' *second* arguments are bare
        // names; every literal, cast, and nested call names nothing.
        let sites = call_sites_of(&records);
        assert_eq!(sites.len(), 2);
        assert!(sites.iter().all(|site| site.arg_index == 1));
    }

    #[test]
    fn an_unknown_callee_propagates_nothing() {
        // A callee the scan never typed — a library routine, a thunk, a
        // helper no detector read — carries no contract to propagate.
        let records = propagated(
            "undefined FUN_180051c00(undefined8 param_1)",
            "  strlen(param_1);\n  FUN_180099999(param_1, param_1);",
        );
        assert!(records.is_empty());
    }

    #[test]
    fn a_position_the_callee_does_not_read_gets_no_reading() {
        // The map holds only `FUN_18004b210`; a callee whose readings
        // sit past the call's arguments types nothing.
        let record = param_record("FUN_18004b210", 2, "char *", 70);
        let map: CalleeParams = HashMap::from([("FUN_18004b210", vec![&record])]);
        let records = CrossFunctionPropagator::new().propagate(
            &function("undefined FUN_180051c00(void)", "  FUN_18004b210(a, b);"),
            &map,
        );
        assert!(records.is_empty());
    }

    #[test]
    fn a_member_or_vtable_call_is_not_a_plain_call_site() {
        // A name reached through `.` or `->`, or a dispatch through an
        // expression, names no callee to look up.
        let records = propagated(
            "undefined FUN_180051c00(undefined8 param_1)",
            "  obj.FUN_18004b210(param_1, param_1);\n\
             \x20 (*(code *)(**param_1))(param_1);",
        );
        assert!(records.is_empty());
    }

    #[test]
    fn a_call_spelled_inside_a_string_literal_is_not_a_call_site() {
        let records = propagated(
            "undefined FUN_180051c00(undefined8 param_1)",
            "  printf(\"FUN_18004b210(param_1, param_1)\");",
        );
        assert!(records.is_empty());
    }

    #[test]
    fn two_sites_for_one_target_are_both_emitted_for_resolution() {
        // Same callee, same position, two bare arguments: the detector
        // does not resolve between them — the scan's conflict
        // resolution keeps the first-seen reading.
        let records = propagated(
            "undefined FUN_180051c00(undefined8 param_1)",
            "  FUN_18004b210(param_1, 0x10);\n  FUN_18004b210(local_8, 0x10);",
        );
        let sites = call_sites_of(&records);
        assert_eq!(sites.len(), 2);
        assert_eq!(sites[0].arg_name.as_deref(), Some("param_1"));
        assert_eq!(sites[1].arg_name.as_deref(), Some("local_8"));
    }

    #[test]
    fn a_propagated_call_site_renders_into_prompt_type_info() {
        let records = propagated(
            "undefined FUN_180051c00(undefined8 param_1)",
            "  FUN_18004b210(param_1, 0x10);",
        );
        let rendered = calxgloss_prompts::TypeInfo::from(&records[0]);
        assert_eq!(rendered.name, "FUN_18004b210(param_1)");
        assert_eq!(
            rendered.description,
            "char * (via cross_function, confidence 70)"
        );
    }

    // ----------------------------------------------------------
    // caller → callee
    // ----------------------------------------------------------

    /// The canned caller→callee scenario: `FUN_18004b210` is the callee,
    /// one caller `FUN_180051c00` calls it with `caller_body`, and the
    /// caller's own first parameter carries a surviving inline reading
    /// of `char *`.
    fn from_callers(callee_signature: &str, caller_body: &str) -> Vec<InferredType> {
        let callee = DecompiledFunction {
            name: "FUN_18004b210".into(),
            signature: callee_signature.into(),
            body: "  return;".into(),
        };
        let caller = DecompiledFunction {
            name: "FUN_180051c00".into(),
            signature: "undefined FUN_180051c00(undefined8 param_1)".into(),
            body: caller_body.into(),
        };
        let reading = param_record("FUN_180051c00", 0, "char *", 70);
        let caller_readings: CalleeParams = HashMap::from([("FUN_180051c00", vec![&reading])]);
        CrossFunctionPropagator::new().propagate_to_callee(&callee, &[&caller], &caller_readings)
    }

    #[test]
    fn a_typed_caller_parameter_types_the_callee_parameter() {
        // The caller hands along, untouched, a parameter it was itself
        // typed as holding: the callee receives a `char *`.
        let records = from_callers(
            "undefined FUN_18004b210(undefined8 param_1)",
            "  FUN_18004b210(param_1);",
        );
        let params = params_of(&records);
        assert_eq!(params.len(), 1);
        let record = params[0];
        assert_eq!(record.function, "FUN_18004b210");
        assert_eq!(record.param_index, 0);
        assert_eq!(record.param_name.as_deref(), Some("param_1"));
        assert_eq!(record.inferred_type, "char *");
        assert_eq!(record.method, InferenceMethod::CrossFunction);
        assert_eq!(record.scope, InferenceScope::Function);
        assert_eq!(record.confidence, CALLER_PARAM_CONFIDENCE);
        assert_eq!(record.evidence, "FUN_180051c00 passes FUN_18004b210");
    }

    #[test]
    fn a_string_literal_argument_types_the_callee_parameter() {
        // A literal says what it is no matter what the callee does with
        // it: `"…"` is a character string, `L"…"` a wide one.
        let narrow = from_callers(
            "undefined FUN_18004b210(undefined8 param_1)",
            "  FUN_18004b210(\"name\");",
        );
        assert_eq!(params_of(&narrow)[0].inferred_type, "char *");
        let wide = from_callers(
            "undefined FUN_18004b210(undefined8 param_1)",
            "  FUN_18004b210(L\"name\");",
        );
        assert_eq!(params_of(&wide)[0].inferred_type, "wchar_t *");
    }

    #[test]
    fn a_known_routine_result_types_the_callee_parameter() {
        // The signature database knows what the call hands back: an
        // allocator a buffer, `strlen` a byte count.
        let buffer = from_callers(
            "undefined FUN_18004b210(undefined8 param_1)",
            "  FUN_18004b210(malloc(0x10));",
        );
        assert_eq!(params_of(&buffer)[0].inferred_type, "void *");
        let count = from_callers(
            "undefined FUN_18004b210(undefined8 param_1)",
            "  FUN_18004b210(strlen(local_8));",
        );
        assert_eq!(params_of(&count)[0].inferred_type, "size_t");
    }

    #[test]
    fn an_unrecognizable_argument_types_nothing() {
        // A numeric literal, a cast, an indexed operand, an untyped
        // local, and an untyped call all say nothing about the callee's
        // parameter — the call site may be typed elsewhere, but this
        // pass lends no reading.
        let records = from_callers(
            "undefined FUN_18004b210(undefined8 param_1)",
            "  FUN_18004b210(0x10);\n\
             \x20 FUN_18004b210((char *)param_1);\n\
             \x20 FUN_18004b210(param_1[0]);\n\
             \x20 FUN_18004b210(\"name\"[0]);\n\
             \x20 FUN_18004b210(local_8);\n\
             \x20 FUN_18004b210(FUN_180099999(param_1));",
        );
        assert!(records.is_empty());
    }

    #[test]
    fn an_untyped_caller_parameter_types_nothing() {
        // Passing a typed-looking name is not enough: the reading only
        // travels when the scan actually typed the caller's parameter.
        let callee = DecompiledFunction {
            name: "FUN_18004b210".into(),
            signature: "undefined FUN_18004b210(undefined8 param_1)".into(),
            body: "  return;".into(),
        };
        let caller = DecompiledFunction {
            name: "FUN_180051c00".into(),
            signature: "undefined FUN_180051c00(undefined8 param_1)".into(),
            body: "  FUN_18004b210(param_1);".into(),
        };
        let records = CrossFunctionPropagator::new().propagate_to_callee(
            &callee,
            &[&caller],
            &HashMap::new(),
        );
        assert!(records.is_empty());
    }

    #[test]
    fn a_position_the_callee_does_not_declare_types_nothing() {
        // The callee declares one parameter; a caller passing two
        // arguments (a decompiler prototype gap) types only the first.
        let records = from_callers(
            "undefined FUN_18004b210(undefined8 param_1)",
            "  FUN_18004b210(param_1, \"name\");",
        );
        let params = params_of(&records);
        assert_eq!(params.len(), 1);
        assert_eq!(params[0].param_index, 0);
    }

    #[test]
    fn every_caller_contributes_and_the_scan_resolves_them() {
        // Two callers, two readings for the same callee parameter: the
        // detector emits both and conflict resolution picks between
        // them, so the detector itself does not aggregate.
        let callee = DecompiledFunction {
            name: "FUN_18004b210".into(),
            signature: "undefined FUN_18004b210(undefined8 param_1)".into(),
            body: "  return;".into(),
        };
        let first = DecompiledFunction {
            name: "FUN_180051c00".into(),
            signature: "undefined FUN_180051c00(void)".into(),
            body: "  FUN_18004b210(\"name\");".into(),
        };
        let second = DecompiledFunction {
            name: "FUN_180052000".into(),
            signature: "undefined FUN_180052000(void)".into(),
            body: "  FUN_18004b210(L\"name\");".into(),
        };
        let records = CrossFunctionPropagator::new().propagate_to_callee(
            &callee,
            &[&first, &second],
            &HashMap::new(),
        );
        let params = params_of(&records);
        assert_eq!(params.len(), 2);
        assert_eq!(params[0].inferred_type, "char *");
        assert_eq!(params[1].inferred_type, "wchar_t *");
    }

    #[test]
    fn a_call_to_another_function_does_not_type_the_callee() {
        // Only sites of the callee itself are read.
        let records = from_callers(
            "undefined FUN_18004b210(undefined8 param_1)",
            "  FUN_180099999(param_1, \"name\");",
        );
        assert!(records.is_empty());
    }
}
