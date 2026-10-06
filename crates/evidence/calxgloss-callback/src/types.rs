//! Core data types for callback and function-pointer table information.
//!
//! This module holds the serialized shape of everything the callback
//! detectors produce:
//!
//! - `FpArrayCall`: a call through an indexed function-pointer table —
//!   the shape Ghidra decompiles out of `*(handlers[i])(args)`.
//! - `CallbackRegistration`: a call to a recognized registration function
//!   with its callback argument bound — the `register_callback(fp)` shape.
//! - `JumpTable`: a call through a table of function addresses at a
//!   computed index — the shape Ghidra leaves behind for
//!   `jmp [table + index*N]`.
//! - `CallbackFinding`: the union over the three record kinds — one
//!   finding whichever detector made it — serde-tagged by `kind`.
//! - `CallbackResult`, `ScanMetadata`: the persisted per-binary result
//!   and its scan provenance.
//!
//! All types derive `Serialize`/`Deserialize`.

// `ScanMetadata` is the shared per-binary scan provenance and `Confidence`
// the shared 0–100 evidence score; both are re-exported so consumers name
// them through this crate, matching the typesdb, typeinfer, algorithm,
// memory, and sync convention.
pub use calxgloss_types::{Confidence, ScanMetadata};
use serde::{Deserialize, Serialize};

// ============================================================
// Function-pointer array calls
// ============================================================

/// One function-pointer array call observation about one function, with
/// the evidence behind it.
///
/// A record says the function calls through the indexed table named by
/// [`table`](Self::table) — a call shaped `(*handlers[i])(args)`, where
/// the callee is an element of a function-pointer array rather than a
/// named function — which reads like [`suggestion`](Self::suggestion):
/// an array of boxed closures, `Vec<Box<dyn Fn(...)>>`, so the handler
/// table survives translation as data the Rust compiler can check
/// instead of an opaque indirect call. The call line is kept as
/// [`evidence`](Self::evidence) so a reviewer (or a translation prompt)
/// can check the reasoning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FpArrayCall {
    /// The function the record is about, e.g. `FUN_18003ab00`.
    pub function: String,
    /// The table whose indexed element is called, e.g. `handlers`.
    pub table: String,
    /// The Rust pattern the call suggests, e.g.
    /// `Vec<Box<dyn Fn(...)>>`.
    pub suggestion: String,
    /// Confidence that the record is right, 0–100.
    pub confidence: Confidence,
    /// The decompiled line that supports the record — the indexed
    /// indirect call — kept so a reviewer (or a translation prompt) can
    /// check the reasoning.
    pub evidence: String,
}

// ============================================================
// Callback registrations
// ============================================================

/// One callback-registration observation about one function, with the
/// evidence behind it.
///
/// A record says the function calls a recognized registration function —
/// [`registration`](Self::registration), spelled e.g.
/// `register_callback` — and passes it a named callback the finding
/// binds in [`callback`](Self::callback), a function reference or
/// address-of the decompiler names directly. The registration reads like
/// [`suggestion`](Self::suggestion): a `Box<dyn Fn(...)>` closure stored
/// or passed where the original kept a raw function pointer, so the
/// callback boundary survives translation. The registration line is kept
/// as [`evidence`](Self::evidence) so a reviewer (or a translation
/// prompt) can check the reasoning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallbackRegistration {
    /// The function the record is about, e.g. `FUN_18003ab00`.
    pub function: String,
    /// The registration call spelling, e.g. `register_callback`.
    pub registration: String,
    /// The callback argument the registration binds, e.g. `my_handler`
    /// as written in `register_callback(my_handler)`.
    pub callback: String,
    /// The Rust pattern the registration suggests, e.g.
    /// `Box<dyn Fn(...)>`.
    pub suggestion: String,
    /// Confidence that the record is right, 0–100.
    pub confidence: Confidence,
    /// The decompiled line that supports the record — the registration
    /// call — kept so a reviewer (or a translation prompt) can check the
    /// reasoning.
    pub evidence: String,
}

// ============================================================
// Jump tables
// ============================================================

/// One jump-table dispatch observation about one function, with the
/// evidence behind it.
///
/// A record says the function dispatches through the address table named
/// by [`table`](Self::table) at the computed [`index`](Self::index) —
/// the shape Ghidra leaves behind for `jmp [table + index*N]`, a call
/// through a table of function addresses typically bracketed by a bounds
/// check or a switch over computed cases. When the bounds check or
/// switch is visible, [`target_count`](Self::target_count) carries how
/// many entries the dispatch spans. The dispatch reads like
/// [`suggestion`](Self::suggestion): a Rust `match` over the index at
/// three or more targets, or a function-pointer array when the table is
/// data-driven. The call line is kept as [`evidence`](Self::evidence) so
/// a reviewer (or a translation prompt) can check the reasoning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JumpTable {
    /// The function the record is about, e.g. `FUN_18003ab00`.
    pub function: String,
    /// The address table the dispatch reads through, e.g.
    /// `DAT_1400a1b60`.
    pub table: String,
    /// The computed index expression, e.g. `uVar2`.
    pub index: String,
    /// How many entries the dispatch spans, read from the bounds check
    /// or switch beside it, when one was visible.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_count: Option<usize>,
    /// The Rust pattern the dispatch suggests, e.g.
    /// `match index { ... }`.
    pub suggestion: String,
    /// Confidence that the record is right, 0–100.
    pub confidence: Confidence,
    /// The decompiled line that supports the record — the indexed table
    /// call — kept so a reviewer (or a translation prompt) can check the
    /// reasoning.
    pub evidence: String,
}

// ============================================================
// Finding union
// ============================================================

/// One callback finding, whichever detector made it.
///
/// The detectors emit the concrete records; the union is what the
/// persisted result carries, so one list can hold every finding for a
/// binary and a consumer reads the shared shape — function, suggestion,
/// confidence, evidence — without naming which detector produced it.
/// Unlike typeinfer's competing families, the three detectors read
/// disjoint body shapes and can't make competing claims for one target,
/// so nothing is resolved between variants. The serde `kind` tag names
/// the record shape in the persisted JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CallbackFinding {
    /// A call through an indexed function-pointer table.
    FpArray(FpArrayCall),
    /// A call to a registration function with its callback bound.
    Registration(CallbackRegistration),
    /// A dispatch through a table of function addresses.
    JumpTable(JumpTable),
}

impl CallbackFinding {
    /// The function the finding is about.
    pub fn function(&self) -> &str {
        match self {
            CallbackFinding::FpArray(record) => &record.function,
            CallbackFinding::Registration(record) => &record.function,
            CallbackFinding::JumpTable(record) => &record.function,
        }
    }

    /// The Rust dispatch pattern the finding suggests.
    pub fn suggestion(&self) -> &str {
        match self {
            CallbackFinding::FpArray(record) => &record.suggestion,
            CallbackFinding::Registration(record) => &record.suggestion,
            CallbackFinding::JumpTable(record) => &record.suggestion,
        }
    }

    /// Confidence that the finding is right.
    pub fn confidence(&self) -> Confidence {
        match self {
            CallbackFinding::FpArray(record) => record.confidence,
            CallbackFinding::Registration(record) => record.confidence,
            CallbackFinding::JumpTable(record) => record.confidence,
        }
    }

    /// The decompiled lines that support the finding.
    pub fn evidence(&self) -> &str {
        match self {
            CallbackFinding::FpArray(record) => &record.evidence,
            CallbackFinding::Registration(record) => &record.evidence,
            CallbackFinding::JumpTable(record) => &record.evidence,
        }
    }

    /// The serde `kind` tag — `fp_array`, `registration`, or
    /// `jump_table` — naming the detector behind the finding.
    pub fn kind(&self) -> &'static str {
        match self {
            CallbackFinding::FpArray(_) => "fp_array",
            CallbackFinding::Registration(_) => "registration",
            CallbackFinding::JumpTable(_) => "jump_table",
        }
    }

    /// What the finding names, spelled for a report row: the table the
    /// indexed call reads through, the registration call and its bound
    /// callback, or the table and index of the computed dispatch.
    pub fn target(&self) -> String {
        match self {
            CallbackFinding::FpArray(record) => record.table.clone(),
            CallbackFinding::Registration(record) => {
                format!("{}→{}", record.registration, record.callback)
            }
            CallbackFinding::JumpTable(record) => format!("{}[{}]", record.table, record.index),
        }
    }
}

/// Render a finding as prompt data: the function it is about, the kind
/// of pattern the detector read, the Rust callback pattern the finding
/// suggests, and the confidence and evidence behind the claim — so the
/// escalate prompt shows the hypothesis and how strongly it was made,
/// whichever detector produced it.
impl From<&CallbackFinding> for calxgloss_prompts::CallbackInfo {
    fn from(finding: &CallbackFinding) -> Self {
        Self {
            function: finding.function().to_string(),
            kind: finding.kind().to_string(),
            suggestion: finding.suggestion().to_string(),
            confidence: finding.confidence().value(),
            evidence: finding.evidence().to_string(),
        }
    }
}

// ============================================================
// Persisted result
// ============================================================

/// The callback result for one binary — the document persisted to
/// `re/analysis/callback/{dll}.json`.
///
/// The findings are the three detectors' outputs in scan order: function
/// by function, and within one function the function-pointer array
/// calls, then the registrations, then the jump tables. The detectors
/// read disjoint body shapes, so a function can carry findings of every
/// kind at once and none competes with another; the stable order means
/// two scans of the same program diff cleanly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallbackResult {
    /// Provenance of the scan that produced these findings.
    pub metadata: ScanMetadata,
    /// Every finding the detectors made, in scan order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<CallbackFinding>,
}

impl CallbackResult {
    /// An empty result for the binary described by `metadata`.
    pub fn new(metadata: ScanMetadata) -> Self {
        Self {
            metadata,
            findings: Vec::new(),
        }
    }

    /// The findings recorded for one function, e.g. `FUN_18003ab00`.
    pub fn for_function(&self, function: &str) -> impl Iterator<Item = &CallbackFinding> {
        self.findings
            .iter()
            .filter(move |finding| finding.function() == function)
    }

    /// Whether the scan found nothing at all.
    pub fn is_empty(&self) -> bool {
        self.findings.is_empty()
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn fp_array_call() -> FpArrayCall {
        FpArrayCall {
            function: "FUN_18003ab00".into(),
            table: "handlers".into(),
            suggestion: "Vec<Box<dyn Fn(...)>>".into(),
            confidence: Confidence::new(70),
            evidence: "(*(int (**)(int))handlers[uVar1])(param_1);".into(),
        }
    }

    #[test]
    fn an_fp_array_call_serde_round_trips() {
        let record = fp_array_call();
        let json = serde_json::to_string(&record).unwrap();
        // The confidence serializes as a plain number, matching the
        // workspace's serde convention.
        assert!(json.contains("\"table\":\"handlers\""));
        assert!(json.contains("\"confidence\":70"));
        let back: FpArrayCall = serde_json::from_str(&json).unwrap();
        assert_eq!(back, record);
    }

    #[test]
    fn an_fp_array_record_names_the_function_the_table_and_the_pattern() {
        let json = serde_json::to_value(fp_array_call()).unwrap();
        assert_eq!(json["function"], "FUN_18003ab00");
        assert_eq!(json["table"], "handlers");
        assert_eq!(json["suggestion"], "Vec<Box<dyn Fn(...)>>");
        assert_eq!(json["confidence"], 70);
    }

    fn registration() -> CallbackRegistration {
        CallbackRegistration {
            function: "FUN_18003ab00".into(),
            registration: "register_callback".into(),
            callback: "my_handler".into(),
            suggestion: "Box<dyn Fn(...)>".into(),
            confidence: Confidence::new(70),
            evidence: "register_callback(my_handler);".into(),
        }
    }

    #[test]
    fn a_registration_serde_round_trips() {
        let record = registration();
        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("\"registration\":\"register_callback\""));
        assert!(json.contains("\"callback\":\"my_handler\""));
        let back: CallbackRegistration = serde_json::from_str(&json).unwrap();
        assert_eq!(back, record);
    }

    #[test]
    fn a_registration_record_names_the_call_the_callback_and_the_pattern() {
        let json = serde_json::to_value(registration()).unwrap();
        assert_eq!(json["function"], "FUN_18003ab00");
        assert_eq!(json["registration"], "register_callback");
        assert_eq!(json["callback"], "my_handler");
        assert_eq!(json["suggestion"], "Box<dyn Fn(...)>");
        assert_eq!(json["confidence"], 70);
    }

    fn jump_table() -> JumpTable {
        JumpTable {
            function: "FUN_18003ab00".into(),
            table: "DAT_1400a1b60".into(),
            index: "uVar2".into(),
            target_count: Some(5),
            suggestion: "[fn(...); 5]".into(),
            confidence: Confidence::new(70),
            evidence: "if (uVar2 < 5) { (*DAT_1400a1b60[uVar2])(); }".into(),
        }
    }

    #[test]
    fn a_jump_table_serde_round_trips() {
        let record = jump_table();
        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("\"table\":\"DAT_1400a1b60\""));
        assert!(json.contains("\"index\":\"uVar2\""));
        assert!(json.contains("\"target_count\":5"));
        let back: JumpTable = serde_json::from_str(&json).unwrap();
        assert_eq!(back, record);
    }

    #[test]
    fn a_jump_table_without_a_visible_target_count_omits_it_and_reads_back_none() {
        let record = JumpTable {
            target_count: None,
            ..jump_table()
        };
        let json = serde_json::to_string(&record).unwrap();
        assert!(!json.contains("\"target_count\""));
        let back: JumpTable = serde_json::from_str(&json).unwrap();
        assert_eq!(back, record);
        assert_eq!(back.target_count, None);
    }

    #[test]
    fn a_jump_table_record_names_the_table_the_index_and_the_pattern() {
        let json = serde_json::to_value(jump_table()).unwrap();
        assert_eq!(json["function"], "FUN_18003ab00");
        assert_eq!(json["table"], "DAT_1400a1b60");
        assert_eq!(json["index"], "uVar2");
        assert_eq!(json["target_count"], 5);
        assert_eq!(json["suggestion"], "[fn(...); 5]");
        assert_eq!(json["confidence"], 70);
    }

    #[test]
    fn an_fp_array_finding_serde_round_trips_under_its_kind_tag() {
        let finding = CallbackFinding::FpArray(fp_array_call());
        let json = serde_json::to_string(&finding).expect("fp array finding should serialize");
        // The union is internally tagged: the kind names the record
        // shape and the payload's own fields sit beside it.
        assert!(json.contains("\"kind\":\"fp_array\""));
        assert!(json.contains("\"table\":\"handlers\""));
        let back: CallbackFinding =
            serde_json::from_str(&json).expect("fp array finding should read back");
        assert_eq!(back, finding);
    }

    #[test]
    fn a_registration_finding_serde_round_trips_under_its_kind_tag() {
        let finding = CallbackFinding::Registration(registration());
        let json = serde_json::to_string(&finding).expect("registration finding should serialize");
        assert!(json.contains("\"kind\":\"registration\""));
        assert!(json.contains("\"registration\":\"register_callback\""));
        let back: CallbackFinding =
            serde_json::from_str(&json).expect("registration finding should read back");
        assert_eq!(back, finding);
    }

    #[test]
    fn a_jump_table_finding_serde_round_trips_under_its_kind_tag() {
        let finding = CallbackFinding::JumpTable(jump_table());
        let json = serde_json::to_string(&finding).expect("jump table finding should serialize");
        assert!(json.contains("\"kind\":\"jump_table\""));
        assert!(json.contains("\"index\":\"uVar2\""));
        let back: CallbackFinding =
            serde_json::from_str(&json).expect("jump table finding should read back");
        assert_eq!(back, finding);
    }

    #[test]
    fn the_union_accessors_reach_through_every_variant() {
        let findings = [
            CallbackFinding::FpArray(fp_array_call()),
            CallbackFinding::Registration(registration()),
            CallbackFinding::JumpTable(jump_table()),
        ];
        for finding in &findings {
            assert_eq!(finding.function(), "FUN_18003ab00");
            assert_eq!(finding.confidence(), Confidence::new(70));
            assert!(!finding.suggestion().is_empty());
            assert!(!finding.evidence().is_empty());
        }
        let kinds: Vec<&str> = findings.iter().map(|f| f.kind()).collect();
        assert_eq!(kinds, vec!["fp_array", "registration", "jump_table"]);
        let suggestions: Vec<&str> = findings.iter().map(|f| f.suggestion()).collect();
        assert_eq!(
            suggestions,
            vec!["Vec<Box<dyn Fn(...)>>", "Box<dyn Fn(...)>", "[fn(...); 5]"]
        );
        let targets: Vec<String> = findings.iter().map(|f| f.target()).collect();
        assert_eq!(
            targets,
            vec![
                "handlers",
                "register_callback→my_handler",
                "DAT_1400a1b60[uVar2]"
            ]
        );
    }

    #[test]
    fn every_finding_variant_renders_as_prompt_data() {
        let fp_array = CallbackFinding::FpArray(fp_array_call());
        let info = calxgloss_prompts::CallbackInfo::from(&fp_array);
        assert_eq!(info.function, "FUN_18003ab00");
        assert_eq!(info.kind, "fp_array");
        assert_eq!(info.suggestion, "Vec<Box<dyn Fn(...)>>");
        assert_eq!(info.confidence, 70);
        assert_eq!(info.evidence, "(*(int (**)(int))handlers[uVar1])(param_1);");

        let registration = CallbackFinding::Registration(registration());
        let info = calxgloss_prompts::CallbackInfo::from(&registration);
        assert_eq!(info.kind, "registration");
        assert_eq!(info.suggestion, "Box<dyn Fn(...)>");

        let jump_table = CallbackFinding::JumpTable(jump_table());
        let info = calxgloss_prompts::CallbackInfo::from(&jump_table);
        assert_eq!(info.kind, "jump_table");
        assert_eq!(info.suggestion, "[fn(...); 5]");
    }

    #[test]
    fn a_callback_result_serde_round_trips() {
        let result = CallbackResult {
            metadata: ScanMetadata {
                binary: "eqmain.dll".into(),
                scanned_at: 1_759_488_000,
                duration_secs: 12,
            },
            findings: vec![
                CallbackFinding::FpArray(fp_array_call()),
                CallbackFinding::Registration(registration()),
                CallbackFinding::JumpTable(jump_table()),
            ],
        };
        let json = serde_json::to_string(&result).expect("callback result should serialize");
        let back: CallbackResult =
            serde_json::from_str(&json).expect("callback result should read back");
        assert_eq!(back, result);
    }

    #[test]
    fn a_result_without_findings_omits_them_and_reads_back_empty() {
        // Documents persisted before a finding landed still load, and an
        // empty scan stays small on disk.
        let result = CallbackResult::new(ScanMetadata::new("eqmain.dll"));
        let json = serde_json::to_string(&result).expect("empty callback result should serialize");
        assert!(!json.contains("\"findings\""));
        let back: CallbackResult =
            serde_json::from_str(&json).expect("empty callback result should read back");
        assert!(back.is_empty());
        assert_eq!(back.metadata.binary, "eqmain.dll");
    }

    #[test]
    fn for_function_yields_only_that_function_s_findings_in_order() {
        let other = CallbackFinding::FpArray(FpArrayCall {
            function: "FUN_18003e750".into(),
            table: "callbacks".into(),
            suggestion: "Vec<Box<dyn Fn(...)>>".into(),
            confidence: Confidence::new(70),
            evidence: "callbacks[uVar3](param_2);".into(),
        });
        let result = CallbackResult {
            metadata: ScanMetadata::new("eqmain.dll"),
            findings: vec![other.clone(), CallbackFinding::Registration(registration())],
        };
        let found: Vec<&CallbackFinding> = result.for_function("FUN_18003e750").collect();
        assert_eq!(found, vec![&other]);
        assert!(result.for_function("FUN_180099999").next().is_none());
        assert!(!result.is_empty());
    }
}
