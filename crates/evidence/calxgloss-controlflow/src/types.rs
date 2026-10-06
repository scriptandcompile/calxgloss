//! Core data types for control-flow pattern information.
//!
//! This module holds the serialized shape of everything the control-flow
//! detectors produce:
//!
//! - `SwitchChain`: a switch-shaped if/else-if chain on one variable —
//!   the shape Ghidra leaves behind for a C `switch`.
//! - `SelfRecursion`: a function that calls itself, with its self-call
//!   count and tail-call status.
//! - `StateMachine`: a state-machine-shaped chain — named-constant
//!   cases, transition assignments, and an idle state.
//! - `ControlFlowFinding`: the union over the three record kinds — one
//!   finding whichever detector made it — serde-tagged by `kind`.
//! - `ControlFlowResult`, `ScanMetadata`: the persisted per-binary result
//!   and its scan provenance.
//!
//! All types derive `Serialize`/`Deserialize`.

// `ScanMetadata` is the shared per-binary scan provenance and `Confidence`
// the shared 0–100 evidence score; both are re-exported so consumers name
// them through this crate, matching the typesdb, typeinfer, algorithm,
// memory, sync, and callback convention.
pub use calxgloss_types::{Confidence, ScanMetadata};
use serde::{Deserialize, Serialize};

// ============================================================
// Switch-shaped chains
// ============================================================

/// One switch-shaped if/else-if chain observation about one function,
/// with the evidence behind it.
///
/// A record says the function compares the variable named by
/// [`variable`](Self::variable) against a run of constants in an
/// if/else-if chain — the shape Ghidra renders a C `switch` into — with
/// the constants collected in [`cases`](Self::cases) and a trailing
/// `else` recorded as [`has_default`](Self::has_default). The chain
/// reads like [`suggestion`](Self::suggestion): a Rust `match`, or a
/// dispatch table when the chain is very wide. The chain head and last
/// arm are kept as [`evidence`](Self::evidence) so a reviewer (or a
/// translation prompt) can check the reasoning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwitchChain {
    /// The function the record is about, e.g. `FUN_18003ab00`.
    pub function: String,
    /// The variable the chain compares, e.g. `local_4`.
    pub variable: String,
    /// The compared constants, in chain order, e.g. `["1", "2", "0x10"]`.
    pub cases: Vec<String>,
    /// Whether the chain ends in a trailing `else` (a switch default).
    pub has_default: bool,
    /// The Rust pattern the chain suggests, e.g. `match local_4 { ... }`.
    pub suggestion: String,
    /// Confidence that the record is right, 0–100.
    pub confidence: Confidence,
    /// The chain head and last arm that support the record, kept so a
    /// reviewer (or a translation prompt) can check the reasoning.
    pub evidence: String,
}

// ============================================================
// Self-recursion
// ============================================================

/// One self-recursion observation about one function, with the evidence
/// behind it.
///
/// A record says the function calls itself — [`self_calls`](Self::self_calls)
/// times — and whether any of those calls sits in tail position, i.e.
/// `return name(...)` ([`is_tail_call`](Self::is_tail_call)). A tail
/// call reads like [`suggestion`](Self::suggestion): a plain `loop`,
/// which Rust needs no tail-call optimization for; a non-tail recursion
/// suggests keeping the recursive `fn` or converting to an explicit
/// stack. The self-call count is kept as [`evidence`](Self::evidence).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelfRecursion {
    /// The function the record is about, e.g. `FUN_18003ab00`.
    pub function: String,
    /// Whether a self-call sits in tail position (`return name(...)`).
    pub is_tail_call: bool,
    /// How many times the function calls itself.
    pub self_calls: usize,
    /// The Rust pattern the recursion suggests, e.g. `loop { ... }`.
    pub suggestion: String,
    /// Confidence that the record is right, 0–100.
    pub confidence: Confidence,
    /// The self-call count and tail-call status that support the
    /// record, kept so a reviewer (or a translation prompt) can check
    /// the reasoning.
    pub evidence: String,
}

// ============================================================
// State machines
// ============================================================

/// One state-machine observation about one function, with the evidence
/// behind it.
///
/// A record says the function dispatches on the state variable named by
/// [`state_var`](Self::state_var) through an if/else-if chain whose
/// cases are [`states`](Self::states) and whose bodies assign new values
/// to that variable — the [`transitions`](Self::transitions). A state
/// that is compared but never entered by a transition assignment (or one
/// with an idle-like name) is the [`idle_state`](Self::idle_state). The
/// pattern reads like [`suggestion`](Self::suggestion): a Rust `enum
/// State` plus a `match`. The state variable and state count are kept as
/// [`evidence`](Self::evidence) so a reviewer (or a translation prompt)
/// can check the reasoning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateMachine {
    /// The function the record is about, e.g. `FUN_18003ab00`.
    pub function: String,
    /// The state variable the chain dispatches on, e.g. `local_4`.
    pub state_var: String,
    /// The case constants, in chain order, e.g.
    /// `["STATE_IDLE", "STATE_RUNNING"]`.
    pub states: Vec<String>,
    /// The distinct values assigned to the state variable inside the
    /// case bodies, in first-seen order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transitions: Vec<String>,
    /// A state that is compared but never entered by a transition
    /// assignment (or, failing that, one with an idle-like name), when one
    /// was visible.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle_state: Option<String>,
    /// The Rust pattern the machine suggests, e.g.
    /// `enum State + match local_4 { ... }`.
    pub suggestion: String,
    /// Confidence that the record is right, 0–100.
    pub confidence: Confidence,
    /// The state variable and state count that support the record,
    /// kept so a reviewer (or a translation prompt) can check the
    /// reasoning.
    pub evidence: String,
}

// ============================================================
// Finding union
// ============================================================

/// One control-flow finding, whichever detector made it.
///
/// The detectors emit the concrete records; the union is what the
/// persisted result carries, so one list can hold every finding for a
/// binary and a consumer reads the shared shape — function, suggestion,
/// confidence, evidence — without naming which detector produced it.
/// The switch and state-machine detectors read the same chain shape from
/// opposite sides (a named-constant chain with transitions is both), so
/// one function can carry findings of several kinds at once; nothing is
/// resolved between them. The serde `kind` tag names the record shape
/// in the persisted JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ControlFlowFinding {
    /// A switch-shaped if/else-if chain.
    Switch(SwitchChain),
    /// A function that calls itself.
    Recursion(SelfRecursion),
    /// A state-machine-shaped chain.
    StateMachine(StateMachine),
}

impl ControlFlowFinding {
    /// The function the finding is about.
    pub fn function(&self) -> &str {
        match self {
            ControlFlowFinding::Switch(record) => &record.function,
            ControlFlowFinding::Recursion(record) => &record.function,
            ControlFlowFinding::StateMachine(record) => &record.function,
        }
    }

    /// The Rust pattern the finding suggests.
    pub fn suggestion(&self) -> &str {
        match self {
            ControlFlowFinding::Switch(record) => &record.suggestion,
            ControlFlowFinding::Recursion(record) => &record.suggestion,
            ControlFlowFinding::StateMachine(record) => &record.suggestion,
        }
    }

    /// Confidence that the finding is right.
    pub fn confidence(&self) -> Confidence {
        match self {
            ControlFlowFinding::Switch(record) => record.confidence,
            ControlFlowFinding::Recursion(record) => record.confidence,
            ControlFlowFinding::StateMachine(record) => record.confidence,
        }
    }

    /// The decompiled lines that support the finding.
    pub fn evidence(&self) -> &str {
        match self {
            ControlFlowFinding::Switch(record) => &record.evidence,
            ControlFlowFinding::Recursion(record) => &record.evidence,
            ControlFlowFinding::StateMachine(record) => &record.evidence,
        }
    }

    /// The serde `kind` tag — `switch`, `recursion`, or
    /// `state_machine` — naming the detector behind the finding.
    pub fn kind(&self) -> &'static str {
        match self {
            ControlFlowFinding::Switch(_) => "switch",
            ControlFlowFinding::Recursion(_) => "recursion",
            ControlFlowFinding::StateMachine(_) => "state_machine",
        }
    }

    /// What the finding names, spelled for a report row: the variable
    /// the switch chain compares, the function that recurses, or the
    /// state variable the machine dispatches on.
    pub fn target(&self) -> String {
        match self {
            ControlFlowFinding::Switch(record) => record.variable.clone(),
            ControlFlowFinding::Recursion(record) => record.function.clone(),
            ControlFlowFinding::StateMachine(record) => record.state_var.clone(),
        }
    }
}

/// Render a finding as prompt data: the function it is about, the kind
/// of pattern the detector read, the Rust control-flow pattern the
/// finding suggests, and the confidence and evidence behind the claim —
/// so the escalate prompt shows the hypothesis and how strongly it was
/// made, whichever detector produced it.
impl From<&ControlFlowFinding> for calxgloss_prompts::ControlFlowInfo {
    fn from(finding: &ControlFlowFinding) -> Self {
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

/// The control-flow result for one binary — the document persisted to
/// `re/analysis/controlflow/{dll}.json`.
///
/// The findings are the three detectors' outputs in scan order: function
/// by function, and within one function the switch chains, then the
/// recursion, then the state machines. A function can carry findings of
/// several kinds at once — the switch and state-machine detectors read
/// the same chain shape from opposite sides — and the stable order means
/// two scans of the same program diff cleanly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlFlowResult {
    /// Provenance of the scan that produced these findings.
    pub metadata: ScanMetadata,
    /// Every finding the detectors made, in scan order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<ControlFlowFinding>,
}

impl ControlFlowResult {
    /// An empty result for the binary described by `metadata`.
    pub fn new(metadata: ScanMetadata) -> Self {
        Self {
            metadata,
            findings: Vec::new(),
        }
    }

    /// The findings recorded for one function, e.g. `FUN_18003ab00`.
    pub fn for_function(&self, function: &str) -> impl Iterator<Item = &ControlFlowFinding> {
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

    fn switch_chain() -> SwitchChain {
        SwitchChain {
            function: "FUN_18003ab00".into(),
            variable: "local_4".into(),
            cases: vec!["1".into(), "2".into(), "0x10".into()],
            has_default: true,
            suggestion: "match local_4 { /* 3 arms */ } + _".into(),
            confidence: Confidence::new(70),
            evidence: "if (local_4 == 1) ... else if (local_4 == 0x10) + default".into(),
        }
    }

    fn recursion() -> SelfRecursion {
        SelfRecursion {
            function: "FUN_18003e750".into(),
            is_tail_call: true,
            self_calls: 1,
            suggestion: "replace with loop { ... } (tail call)".into(),
            confidence: Confidence::new(80),
            evidence: "FUN_18003e750() calls itself 1x (tail call)".into(),
        }
    }

    fn state_machine() -> StateMachine {
        StateMachine {
            function: "FUN_1800412a0".into(),
            state_var: "local_4".into(),
            states: vec![
                "STATE_IDLE".into(),
                "STATE_RUNNING".into(),
                "STATE_DONE".into(),
            ],
            transitions: vec!["STATE_DONE".into(), "STATE_IDLE".into()],
            idle_state: Some("STATE_IDLE".into()),
            suggestion: "enum State + match local_4 { /* 3 states */ }".into(),
            confidence: Confidence::new(70),
            evidence: "state variable local_4 with 3 states idle: STATE_IDLE".into(),
        }
    }

    #[test]
    fn a_switch_chain_serde_round_trips() {
        let record = switch_chain();
        let json = serde_json::to_string(&record).unwrap();
        // The confidence serializes as a plain number, matching the
        // workspace's serde convention.
        assert!(json.contains("\"variable\":\"local_4\""));
        assert!(json.contains("\"confidence\":70"));
        let back: SwitchChain = serde_json::from_str(&json).unwrap();
        assert_eq!(back, record);
    }

    #[test]
    fn a_self_recursion_serde_round_trips() {
        let record = recursion();
        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("\"is_tail_call\":true"));
        assert!(json.contains("\"self_calls\":1"));
        let back: SelfRecursion = serde_json::from_str(&json).unwrap();
        assert_eq!(back, record);
    }

    #[test]
    fn a_state_machine_serde_round_trips() {
        let record = state_machine();
        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("\"state_var\":\"local_4\""));
        assert!(json.contains("\"idle_state\":\"STATE_IDLE\""));
        let back: StateMachine = serde_json::from_str(&json).unwrap();
        assert_eq!(back, record);
    }

    #[test]
    fn a_state_machine_without_transitions_or_idle_omits_them_and_reads_back_empty() {
        // Documents persisted before a transition landed still load, and
        // a bare chain stays small on disk.
        let record = StateMachine {
            transitions: Vec::new(),
            idle_state: None,
            ..state_machine()
        };
        let json = serde_json::to_string(&record).unwrap();
        assert!(!json.contains("\"transitions\""));
        assert!(!json.contains("\"idle_state\""));
        let back: StateMachine = serde_json::from_str(&json).unwrap();
        assert_eq!(back, record);
        assert!(back.transitions.is_empty());
        assert_eq!(back.idle_state, None);
    }

    #[test]
    fn a_switch_finding_serde_round_trips_under_its_kind_tag() {
        let finding = ControlFlowFinding::Switch(switch_chain());
        let json = serde_json::to_string(&finding).expect("switch finding should serialize");
        // The union is internally tagged: the kind names the record
        // shape and the payload's own fields sit beside it.
        assert!(json.contains("\"kind\":\"switch\""));
        assert!(json.contains("\"variable\":\"local_4\""));
        let back: ControlFlowFinding =
            serde_json::from_str(&json).expect("switch finding should read back");
        assert_eq!(back, finding);
    }

    #[test]
    fn a_recursion_finding_serde_round_trips_under_its_kind_tag() {
        let finding = ControlFlowFinding::Recursion(recursion());
        let json = serde_json::to_string(&finding).expect("recursion finding should serialize");
        assert!(json.contains("\"kind\":\"recursion\""));
        assert!(json.contains("\"self_calls\":1"));
        let back: ControlFlowFinding =
            serde_json::from_str(&json).expect("recursion finding should read back");
        assert_eq!(back, finding);
    }

    #[test]
    fn a_state_machine_finding_serde_round_trips_under_its_kind_tag() {
        let finding = ControlFlowFinding::StateMachine(state_machine());
        let json = serde_json::to_string(&finding).expect("state machine finding should serialize");
        assert!(json.contains("\"kind\":\"state_machine\""));
        assert!(json.contains("\"state_var\":\"local_4\""));
        let back: ControlFlowFinding =
            serde_json::from_str(&json).expect("state machine finding should read back");
        assert_eq!(back, finding);
    }

    #[test]
    fn the_union_accessors_reach_through_every_variant() {
        let findings = [
            ControlFlowFinding::Switch(switch_chain()),
            ControlFlowFinding::Recursion(recursion()),
            ControlFlowFinding::StateMachine(state_machine()),
        ];
        for finding in &findings {
            assert!(!finding.function().is_empty());
            assert!(!finding.suggestion().is_empty());
            assert!(!finding.evidence().is_empty());
        }
        let kinds: Vec<&str> = findings.iter().map(|f| f.kind()).collect();
        assert_eq!(kinds, vec!["switch", "recursion", "state_machine"]);
        let functions: Vec<&str> = findings.iter().map(|f| f.function()).collect();
        assert_eq!(
            functions,
            vec!["FUN_18003ab00", "FUN_18003e750", "FUN_1800412a0"]
        );
        assert_eq!(u8::from(findings[0].confidence()), 70);
        assert_eq!(u8::from(findings[1].confidence()), 80);
        let targets: Vec<String> = findings.iter().map(|f| f.target()).collect();
        assert_eq!(targets, vec!["local_4", "FUN_18003e750", "local_4"]);
    }

    #[test]
    fn every_finding_variant_renders_as_prompt_data() {
        let switch = ControlFlowFinding::Switch(switch_chain());
        let info = calxgloss_prompts::ControlFlowInfo::from(&switch);
        assert_eq!(info.function, "FUN_18003ab00");
        assert_eq!(info.kind, "switch");
        assert_eq!(info.suggestion, "match local_4 { /* 3 arms */ } + _");
        assert_eq!(info.confidence, 70);
        assert!(info.evidence.contains("else if (local_4 == 0x10)"));

        let recursion = ControlFlowFinding::Recursion(recursion());
        let info = calxgloss_prompts::ControlFlowInfo::from(&recursion);
        assert_eq!(info.kind, "recursion");
        assert_eq!(info.confidence, 80);

        let machine = ControlFlowFinding::StateMachine(state_machine());
        let info = calxgloss_prompts::ControlFlowInfo::from(&machine);
        assert_eq!(info.kind, "state_machine");
        assert_eq!(
            info.suggestion,
            "enum State + match local_4 { /* 3 states */ }"
        );
    }

    #[test]
    fn a_control_flow_result_serde_round_trips() {
        let result = ControlFlowResult {
            metadata: ScanMetadata {
                binary: "eqmain.dll".into(),
                scanned_at: 1_759_488_000,
                duration_secs: 12,
            },
            findings: vec![
                ControlFlowFinding::Switch(switch_chain()),
                ControlFlowFinding::Recursion(recursion()),
                ControlFlowFinding::StateMachine(state_machine()),
            ],
        };
        let json = serde_json::to_string(&result).expect("control flow result should serialize");
        let back: ControlFlowResult =
            serde_json::from_str(&json).expect("control flow result should read back");
        assert_eq!(back, result);
    }

    #[test]
    fn a_result_without_findings_omits_them_and_reads_back_empty() {
        let result = ControlFlowResult::new(ScanMetadata::new("eqmain.dll"));
        let json =
            serde_json::to_string(&result).expect("empty control flow result should serialize");
        assert!(!json.contains("\"findings\""));
        let back: ControlFlowResult =
            serde_json::from_str(&json).expect("empty control flow result should read back");
        assert!(back.is_empty());
        assert_eq!(back.metadata.binary, "eqmain.dll");
    }

    #[test]
    fn for_function_yields_only_that_function_s_findings_in_order() {
        let other = ControlFlowFinding::Recursion(SelfRecursion {
            function: "FUN_18003ab00".into(),
            is_tail_call: false,
            self_calls: 2,
            suggestion: "keep recursive fn FUN_18003ab00(...) or convert to loop".into(),
            confidence: Confidence::new(75),
            evidence: "FUN_18003ab00() calls itself 2x".into(),
        });
        let unrelated = ControlFlowFinding::StateMachine(state_machine());
        let switch = ControlFlowFinding::Switch(switch_chain());
        let result = ControlFlowResult {
            metadata: ScanMetadata::new("eqmain.dll"),
            findings: vec![other.clone(), switch.clone(), unrelated],
        };
        let found: Vec<&ControlFlowFinding> = result.for_function("FUN_18003ab00").collect();
        assert_eq!(found, vec![&other, &switch]);
        assert!(result.for_function("FUN_180099999").next().is_none());
        assert!(!result.is_empty());
    }
}
