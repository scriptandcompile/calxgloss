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
//! - `LoopNesting` (with `LoopKind`): the loop structure of one body —
//!   loop count, maximum nesting depth, and the shapes seen, read off
//!   the control flow graph.
//! - `BranchDensity` (with `BranchClassification`): the branching
//!   structure of one body — conditional-edge count against basic-block
//!   count, classified as a dispatch-table candidate or a sequential
//!   scan, read off the same graph.
//! - `MutualRecursion`: a call cycle of two or more functions —
//!   `A ↔ B`, `A → B → C → A` — read across the bodies one scan keeps.
//! - `ControlFlowFinding`: the union over the record kinds — one
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
/// times — and whether any of those calls sits in tail position
/// ([`is_tail_call`](Self::is_tail_call)): the call block's only exit is
/// the function's return and that return hands back exactly the call's
/// result. A tail call reads like [`suggestion`](Self::suggestion): a
/// plain `loop`, which Rust needs no tail-call optimization for; a
/// non-tail recursion suggests keeping the recursive `fn` or converting
/// to an explicit stack. When the control flow graph shows a self-call
/// nested inside a loop body, [`in_loop`](Self::in_loop) says so —
/// recursion a loop re-enters every iteration is a stack-depth
/// multiplier — and the suggestion names the explicit-stack conversion.
/// The self-call count and those readings are kept as
/// [`evidence`](Self::evidence).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelfRecursion {
    /// The function the record is about, e.g. `FUN_18003ab00`.
    pub function: String,
    /// Whether a self-call sits in tail position: the graph shows the
    /// call block's only exit is the function's return and the return
    /// hands back exactly the call's result (`return name(...)`, or the
    /// spread-over-lines `v = name(...); return v;`).
    pub is_tail_call: bool,
    /// How many times the function calls itself.
    pub self_calls: usize,
    /// Whether a self-call sits inside a loop body — the depth
    /// multiplier reading. An optional serde field, so a document
    /// persisted before the deepening still loads, and a self-call
    /// outside any loop keeps the exact record it wrote then.
    #[serde(default, skip_serializing_if = "is_false")]
    pub in_loop: bool,
    /// The Rust pattern the recursion suggests, e.g. `loop { ... }`.
    pub suggestion: String,
    /// Confidence that the record is right, 0–100.
    pub confidence: Confidence,
    /// The self-call count and the tail-call and loop-nesting readings
    /// that support the record, kept so a reviewer (or a translation
    /// prompt) can check the reasoning.
    pub evidence: String,
}

/// serde skip predicate: the depth flag leaves the JSON of a self-call
/// outside any loop, keeping such records exactly what they were before
/// the deepening.
fn is_false(value: &bool) -> bool {
    !*value
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
// Loop structure
// ============================================================

/// The loop shapes Ghidra's pseudo-C spells out, plus the goto-driven
/// one.
///
/// The control flow graph reads a shape off the body and the persisted
/// record names it in `kinds_seen`, so one enum carries the vocabulary
/// on both sides — the graph's loop kinds and the finding's kind list
/// cannot drift apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoopKind {
    /// A counted `for (..; ..; ..) { }` header.
    For,
    /// A conditional `while (..) { }` header.
    While,
    /// A `do { } while (..);` shape, head and tail read together.
    DoWhile,
    /// A `goto` back to an earlier label — the flattened-loop shape.
    Goto,
}

impl LoopKind {
    /// The shape spelled for a report row: `for`, `while`, `do-while`,
    /// or `goto`.
    pub fn label(&self) -> &'static str {
        match self {
            LoopKind::For => "for",
            LoopKind::While => "while",
            LoopKind::DoWhile => "do-while",
            LoopKind::Goto => "goto",
        }
    }

    /// Whether the shape is a spelled-out loop header — the strong
    /// evidence a structured loop leaves — rather than a `goto` back to
    /// a label, whose loop reading is an inference over the jump.
    pub fn is_structured(&self) -> bool {
        !matches!(self, LoopKind::Goto)
    }

    /// The Rust loop structure this shape corresponds to, spelled for a
    /// suggestion: `for`, `while`, or `loop` — Rust has no `do-while`,
    /// and a goto-driven loop is a plain `loop` too.
    pub fn rust_shape(&self) -> &'static str {
        match self {
            LoopKind::For => "for",
            LoopKind::While => "while",
            LoopKind::DoWhile | LoopKind::Goto => "loop",
        }
    }

    /// The kinds' labels in order joined with `/` — the shape story one
    /// body tells, spelled the same in the report row and the evidence.
    pub fn labels(kinds: &[LoopKind]) -> String {
        kinds
            .iter()
            .map(|kind| kind.label())
            .collect::<Vec<_>>()
            .join("/")
    }
}

/// One loop-structure observation about one function, with the evidence
/// behind it.
///
/// A record says the body carries [`loop_count`](Self::loop_count)
/// loops of the [`kinds_seen`](Self::kinds_seen) shapes, nested to
/// [`max_depth`](Self::max_depth): 1 for a top-level loop, 2 for a loop
/// inside a loop or inside a switch/state-machine case body, and so on
/// — the depth the graph's brace discipline shows, so a chain reading
/// and a loop reading never contradict each other. The body reads like
/// [`suggestion`](Self::suggestion): the Rust loop structure at that
/// nesting depth. Confidence is 70 when a spelled-out loop header
/// stands in the body and 60 when the only loops visible are
/// goto-driven — a goto shape is a weaker inference than a loop header.
/// The count, kinds, and depth are kept as [`evidence`](Self::evidence)
/// so a reviewer (or a translation prompt) can check the reasoning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoopNesting {
    /// The function the record is about, e.g. `FUN_18003ab00`.
    pub function: String,
    /// How many loops the body carries.
    pub loop_count: usize,
    /// The maximum loop nesting depth: 1 for a top-level loop, +1 per
    /// level of nesting — a loop inside a loop, or inside a chain case
    /// body, reads 2.
    pub max_depth: usize,
    /// The loop shapes seen, in first-seen body order, deduped.
    pub kinds_seen: Vec<LoopKind>,
    /// The Rust pattern the loops suggest, e.g.
    /// `express as Rust for/while/loop at nesting depth 2`.
    pub suggestion: String,
    /// Confidence that the record is right, 0–100.
    pub confidence: Confidence,
    /// The loop count, kinds, and depth that support the record, kept
    /// so a reviewer (or a translation prompt) can check the reasoning.
    pub evidence: String,
}

// ============================================================
// Branch density
// ============================================================

/// How branch-heavy a body reads, decided from its control flow graph.
///
/// The branch-density detector makes the call and the persisted record
/// names it, so one enum carries the verdict vocabulary on both sides.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BranchClassification {
    /// Enough conditional edges per block that the body reads as a
    /// dispatcher — a wide if/else-if ladder or many conditionals — and
    /// a `match` or dispatch table would express it better than the
    /// ladder it was decompiled into.
    DispatchTable,
    /// Few enough conditional edges that the body reads as a
    /// straight-line scan with the odd test; keeping it sequential (or
    /// reaching for an iterator) beats inventing dispatch for it.
    SequentialScan,
}

impl BranchClassification {
    /// The verdict spelled for a report row: `dispatch-table candidate`
    /// or `sequential scan`.
    pub fn label(&self) -> &'static str {
        match self {
            BranchClassification::DispatchTable => "dispatch-table candidate",
            BranchClassification::SequentialScan => "sequential scan",
        }
    }
}

/// One branch-density observation about one function, with the evidence
/// behind it.
///
/// A record says the body's [`branch_count`](Self::branch_count)
/// conditional edges spread over [`block_count`](Self::block_count)
/// basic blocks classify it as [`classification`](Self::classification):
/// at or above the detector's heavy threshold the body reads as a
/// dispatch-table candidate, below it as a sequential scan. Loop
/// conditions are iteration, not branching, so a loop scan stays a scan
/// — the loop finding already tells the loop story. Confidence is 60 —
/// the classification is a structural inference over the graph, visibly
/// weaker than a named shape like a switch chain. The two counts are
/// kept as [`evidence`](Self::evidence) so a reviewer (or a translation
/// prompt) can check the reasoning against the body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BranchDensity {
    /// The function the record is about, e.g. `FUN_18003ab00`.
    pub function: String,
    /// How many conditional edges (branch taken / not-taken out of an
    /// `if`/`else if` head) the graph carries.
    pub branch_count: usize,
    /// How many basic blocks the graph carries.
    pub block_count: usize,
    /// The classification the ratio came out at.
    pub classification: BranchClassification,
    /// The Rust pattern the classification suggests, e.g.
    /// `express as a match or dispatch table`.
    pub suggestion: String,
    /// Confidence that the record is right, 0–100.
    pub confidence: Confidence,
    /// The branch and block counts behind the classification, kept so a
    /// reviewer (or a translation prompt) can check the reasoning.
    pub evidence: String,
}

// ============================================================
// Mutual recursion
// ============================================================

/// One mutual-recursion observation spanning two or more functions,
/// with the evidence behind it.
///
/// A record says the functions named in [`cycle`](Self::cycle) call
/// each other in a ring — `A ↔ B`, `A → B → C → A` — the recursion
/// shape no single body can see because every call sits in somebody
/// else's closing brace. The record attaches to the cycle's earliest
/// member in listing order ([`function`](Self::function)) and names
/// every member in cycle order, the ring closing back onto the first.
/// The cycle reads like [`suggestion`](Self::suggestion): translate it
/// together — an explicit stack, a trampoline, or an enum-driven loop.
/// Every edge of the cycle is an explicit call in a kept body, so the
/// claim sits level with an in-body self-call, at confidence **70**.
/// The cycle's call edges, spelled in cycle order and closing back on
/// the first member, are kept as [`evidence`](Self::evidence) so a
/// reviewer (or a translation prompt) can check the reasoning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MutualRecursion {
    /// The function the record is attached to — the cycle's earliest
    /// member in listing order.
    pub function: String,
    /// Every function in the cycle, in cycle order, starting from
    /// [`function`](Self::function); the ring closes back onto it.
    pub cycle: Vec<String>,
    /// The Rust pattern the cycle suggests, e.g. translating the cycle
    /// together via an explicit stack, a trampoline, or an enum-driven
    /// loop.
    pub suggestion: String,
    /// Confidence that the record is right, 0–100.
    pub confidence: Confidence,
    /// The cycle's call edges in cycle order, closing back on the first
    /// member, kept so a reviewer (or a translation prompt) can check
    /// the reasoning.
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
    /// The loop structure of a body — count, nesting depth, kinds seen.
    Loop(LoopNesting),
    /// The branching structure of a body — conditional edges against
    /// basic blocks, classified dispatch-table candidate or sequential
    /// scan.
    BranchDensity(BranchDensity),
    /// A call cycle of two or more functions — mutual recursion read
    /// across the bodies one scan keeps.
    MutualRecursion(MutualRecursion),
}

impl ControlFlowFinding {
    /// The function the finding is about.
    pub fn function(&self) -> &str {
        match self {
            ControlFlowFinding::Switch(record) => &record.function,
            ControlFlowFinding::Recursion(record) => &record.function,
            ControlFlowFinding::StateMachine(record) => &record.function,
            ControlFlowFinding::Loop(record) => &record.function,
            ControlFlowFinding::BranchDensity(record) => &record.function,
            ControlFlowFinding::MutualRecursion(record) => &record.function,
        }
    }

    /// The Rust pattern the finding suggests.
    pub fn suggestion(&self) -> &str {
        match self {
            ControlFlowFinding::Switch(record) => &record.suggestion,
            ControlFlowFinding::Recursion(record) => &record.suggestion,
            ControlFlowFinding::StateMachine(record) => &record.suggestion,
            ControlFlowFinding::Loop(record) => &record.suggestion,
            ControlFlowFinding::BranchDensity(record) => &record.suggestion,
            ControlFlowFinding::MutualRecursion(record) => &record.suggestion,
        }
    }

    /// Confidence that the finding is right.
    pub fn confidence(&self) -> Confidence {
        match self {
            ControlFlowFinding::Switch(record) => record.confidence,
            ControlFlowFinding::Recursion(record) => record.confidence,
            ControlFlowFinding::StateMachine(record) => record.confidence,
            ControlFlowFinding::Loop(record) => record.confidence,
            ControlFlowFinding::BranchDensity(record) => record.confidence,
            ControlFlowFinding::MutualRecursion(record) => record.confidence,
        }
    }

    /// The decompiled lines that support the finding.
    pub fn evidence(&self) -> &str {
        match self {
            ControlFlowFinding::Switch(record) => &record.evidence,
            ControlFlowFinding::Recursion(record) => &record.evidence,
            ControlFlowFinding::StateMachine(record) => &record.evidence,
            ControlFlowFinding::Loop(record) => &record.evidence,
            ControlFlowFinding::BranchDensity(record) => &record.evidence,
            ControlFlowFinding::MutualRecursion(record) => &record.evidence,
        }
    }

    /// The serde `kind` tag — `switch`, `recursion`, `state_machine`,
    /// `loop`, `branch_density`, or `mutual_recursion` — naming the
    /// detector behind the finding.
    pub fn kind(&self) -> &'static str {
        match self {
            ControlFlowFinding::Switch(_) => "switch",
            ControlFlowFinding::Recursion(_) => "recursion",
            ControlFlowFinding::StateMachine(_) => "state_machine",
            ControlFlowFinding::Loop(_) => "loop",
            ControlFlowFinding::BranchDensity(_) => "branch_density",
            ControlFlowFinding::MutualRecursion(_) => "mutual_recursion",
        }
    }

    /// What the finding names, spelled for a report row: the variable
    /// the switch chain compares, the function that recurses, the state
    /// variable the machine dispatches on, the loop shapes the body
    /// carries, the branch-density verdict, or the functions in the
    /// call cycle.
    pub fn target(&self) -> String {
        match self {
            ControlFlowFinding::Switch(record) => record.variable.clone(),
            ControlFlowFinding::Recursion(record) => record.function.clone(),
            ControlFlowFinding::StateMachine(record) => record.state_var.clone(),
            ControlFlowFinding::Loop(record) => LoopKind::labels(&record.kinds_seen),
            ControlFlowFinding::BranchDensity(record) => record.classification.label().to_string(),
            ControlFlowFinding::MutualRecursion(record) => record.cycle.join(" → "),
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
/// The findings are the detectors' outputs in scan order: function by
/// function, and within one function the switch chains, then the
/// recursion, then the state machines, then the loop structure, then
/// the branch density — and after every function, the cross-function
/// mutual-recursion cycles in listing order. A
/// function can carry findings of several kinds at once — the switch
/// and state-machine detectors read the same chain shape from opposite
/// sides — and the stable order means two scans of the same program
/// diff cleanly.
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
            in_loop: false,
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

    fn loop_nesting() -> LoopNesting {
        LoopNesting {
            function: "FUN_18003e750".into(),
            loop_count: 3,
            max_depth: 2,
            kinds_seen: vec![LoopKind::For, LoopKind::While, LoopKind::DoWhile],
            suggestion: "express as Rust for/while/loop at nesting depth 2".into(),
            confidence: Confidence::new(70),
            evidence: "3 loops: for/while/do-while (max depth 2)".into(),
        }
    }

    fn branch_density() -> BranchDensity {
        BranchDensity {
            function: "FUN_18003ab00".into(),
            branch_count: 6,
            block_count: 8,
            classification: BranchClassification::DispatchTable,
            suggestion: "express as a match or dispatch table".into(),
            confidence: Confidence::new(60),
            evidence: "6 conditional edges / 8 blocks (density 0.75)".into(),
        }
    }

    fn mutual_recursion() -> MutualRecursion {
        MutualRecursion {
            function: "FUN_18003ab00".into(),
            cycle: vec!["FUN_18003ab00".into(), "FUN_18003e750".into()],
            suggestion: "translate the cycle together via an explicit stack, a trampoline, or an \
                         enum-driven loop"
                .into(),
            confidence: Confidence::new(70),
            evidence: "FUN_18003ab00() -> FUN_18003e750() -> FUN_18003ab00()".into(),
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
    fn a_deepened_self_recursion_round_trips_and_a_plain_one_stays_small() {
        // The depth multiplier reading rides the record...
        let record = SelfRecursion {
            in_loop: true,
            ..recursion()
        };
        let json = serde_json::to_string(&record).expect("deepened record should serialize");
        assert!(json.contains("\"in_loop\":true"));
        let back: SelfRecursion =
            serde_json::from_str(&json).expect("deepened record should load back");
        assert_eq!(back, record);

        // ...and a self-call outside any loop keeps the pre-deepening
        // shape on disk, mirroring the state-machine record's optional
        // fields.
        let json = serde_json::to_string(&recursion()).expect("plain record should serialize");
        assert!(!json.contains("\"in_loop\""));
    }

    #[test]
    fn a_self_recursion_document_persisted_before_the_deepening_loads() {
        let json = r#"{"function":"FUN_18003e750","is_tail_call":true,"self_calls":1,"suggestion":"replace with loop { ... } (tail call)","confidence":80,"evidence":"FUN_18003e750() calls itself 1x (tail call)"}"#;
        let back: SelfRecursion =
            serde_json::from_str(json).expect("pre-deepening document should load");
        assert!(!back.in_loop, "the depth flag reads absent as false");
        assert_eq!(back.self_calls, 1);
        assert!(back.is_tail_call);
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
    fn a_loop_nesting_serde_round_trips() {
        let record = loop_nesting();
        let json = serde_json::to_string(&record).expect("loop nesting record should serialize");
        // The kinds serialize as their snake_case spellings, matching the
        // union's serde convention.
        assert!(json.contains("\"loop_count\":3"));
        assert!(json.contains("\"max_depth\":2"));
        assert!(json.contains("\"kinds_seen\":[\"for\",\"while\",\"do_while\"]"));
        let back: LoopNesting =
            serde_json::from_str(&json).expect("loop nesting record should read back");
        assert_eq!(back, record);
    }

    #[test]
    fn a_branch_density_serde_round_trips() {
        let record = branch_density();
        let json = serde_json::to_string(&record).expect("branch density record should serialize");
        // The classification serializes as its snake_case spelling,
        // matching the union's serde convention.
        assert!(json.contains("\"branch_count\":6"));
        assert!(json.contains("\"block_count\":8"));
        assert!(json.contains("\"classification\":\"dispatch_table\""));
        let back: BranchDensity =
            serde_json::from_str(&json).expect("branch density record should read back");
        assert_eq!(back, record);
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
    fn a_loop_finding_serde_round_trips_under_its_kind_tag() {
        let finding = ControlFlowFinding::Loop(loop_nesting());
        let json = serde_json::to_string(&finding).expect("loop finding should serialize");
        assert!(json.contains("\"kind\":\"loop\""));
        assert!(json.contains("\"loop_count\":3"));
        let back: ControlFlowFinding =
            serde_json::from_str(&json).expect("loop finding should read back");
        assert_eq!(back, finding);
    }

    #[test]
    fn a_branch_density_finding_serde_round_trips_under_its_kind_tag() {
        let finding = ControlFlowFinding::BranchDensity(branch_density());
        let json =
            serde_json::to_string(&finding).expect("branch density finding should serialize");
        assert!(json.contains("\"kind\":\"branch_density\""));
        assert!(json.contains("\"branch_count\":6"));
        let back: ControlFlowFinding =
            serde_json::from_str(&json).expect("branch density finding should read back");
        assert_eq!(back, finding);
    }

    #[test]
    fn a_mutual_recursion_serde_round_trips() {
        let record = mutual_recursion();
        let json =
            serde_json::to_string(&record).expect("mutual recursion record should serialize");
        // The cycle serializes as a plain list of names in cycle order.
        assert!(json.contains("\"cycle\":[\"FUN_18003ab00\",\"FUN_18003e750\"]"));
        assert!(json.contains("\"confidence\":70"));
        let back: MutualRecursion =
            serde_json::from_str(&json).expect("mutual recursion record should read back");
        assert_eq!(back, record);
    }

    #[test]
    fn a_mutual_recursion_finding_serde_round_trips_under_its_kind_tag() {
        let finding = ControlFlowFinding::MutualRecursion(mutual_recursion());
        let json =
            serde_json::to_string(&finding).expect("mutual recursion finding should serialize");
        assert!(json.contains("\"kind\":\"mutual_recursion\""));
        assert!(json.contains("\"cycle\":[\"FUN_18003ab00\",\"FUN_18003e750\"]"));
        let back: ControlFlowFinding =
            serde_json::from_str(&json).expect("mutual recursion finding should read back");
        assert_eq!(back, finding);
    }

    #[test]
    fn the_union_accessors_reach_through_every_variant() {
        let findings = [
            ControlFlowFinding::Switch(switch_chain()),
            ControlFlowFinding::Recursion(recursion()),
            ControlFlowFinding::StateMachine(state_machine()),
            ControlFlowFinding::Loop(loop_nesting()),
            ControlFlowFinding::BranchDensity(branch_density()),
            ControlFlowFinding::MutualRecursion(mutual_recursion()),
        ];
        for finding in &findings {
            assert!(!finding.function().is_empty());
            assert!(!finding.suggestion().is_empty());
            assert!(!finding.evidence().is_empty());
        }
        let kinds: Vec<&str> = findings.iter().map(|f| f.kind()).collect();
        assert_eq!(
            kinds,
            vec![
                "switch",
                "recursion",
                "state_machine",
                "loop",
                "branch_density",
                "mutual_recursion"
            ]
        );
        let functions: Vec<&str> = findings.iter().map(|f| f.function()).collect();
        assert_eq!(
            functions,
            vec![
                "FUN_18003ab00",
                "FUN_18003e750",
                "FUN_1800412a0",
                "FUN_18003e750",
                "FUN_18003ab00",
                "FUN_18003ab00"
            ]
        );
        assert_eq!(u8::from(findings[0].confidence()), 70);
        assert_eq!(u8::from(findings[1].confidence()), 80);
        let targets: Vec<String> = findings.iter().map(|f| f.target()).collect();
        assert_eq!(
            targets,
            vec![
                "local_4",
                "FUN_18003e750",
                "local_4",
                "for/while/do-while",
                "dispatch-table candidate",
                "FUN_18003ab00 → FUN_18003e750"
            ]
        );
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

        let loops = ControlFlowFinding::Loop(loop_nesting());
        let info = calxgloss_prompts::ControlFlowInfo::from(&loops);
        assert_eq!(info.kind, "loop");
        assert_eq!(info.confidence, 70);
        assert_eq!(
            info.suggestion,
            "express as Rust for/while/loop at nesting depth 2"
        );
        assert!(
            info.evidence
                .contains("3 loops: for/while/do-while (max depth 2)")
        );

        let density = ControlFlowFinding::BranchDensity(branch_density());
        let info = calxgloss_prompts::ControlFlowInfo::from(&density);
        assert_eq!(info.kind, "branch_density");
        assert_eq!(info.confidence, 60);
        assert_eq!(info.suggestion, "express as a match or dispatch table");
        assert!(
            info.evidence
                .contains("6 conditional edges / 8 blocks (density 0.75)")
        );

        let mutual = ControlFlowFinding::MutualRecursion(mutual_recursion());
        let info = calxgloss_prompts::ControlFlowInfo::from(&mutual);
        assert_eq!(info.function, "FUN_18003ab00");
        assert_eq!(info.kind, "mutual_recursion");
        assert_eq!(info.confidence, 70);
        assert!(info.suggestion.contains("explicit stack"));
        assert!(
            info.evidence
                .contains("FUN_18003ab00() -> FUN_18003e750() -> FUN_18003ab00()")
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
            in_loop: false,
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
