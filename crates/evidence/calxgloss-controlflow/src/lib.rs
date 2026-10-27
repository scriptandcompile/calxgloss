//! Control-flow pattern recognition for calxgloss.
//!
//! Within each function of a loaded program, this crate reads
//! switch-shaped if/else-if chains, self-recursion, state-machine
//! patterns, loop structure, and branch density. Across the bodies a
//! scan keeps, it also reads mutual-recursion call cycles. The results
//! are injected as structured CONTROL FLOW sections that name the Rust
//! pattern the translation should aim at — `match`, a dispatch table,
//! `loop`, `enum State`. The goal: the target binary's dispatching and
//! looping structure survives translation, instead of being carried
//! across as raw conditional jumps.
//!
//! # Architecture
//!
//! The crate is organized into thirteen modules:
//!
//! - [`types`] - Core data types. The detection records: `SwitchChain`,
//!   `SelfRecursion`, `StateMachine`, `LoopNesting` (with `LoopKind`),
//!   `BranchDensity` (with `BranchClassification`), `BranchSite` (with
//!   `GuardedTarget`), and `MutualRecursion`. `ControlFlowFinding` is
//!   the union over the seven record kinds; `ControlFlowResult` and
//!   `ScanMetadata` are the persisted per-binary results.
//! - `chain` (crate-internal) - Shared chain walker: brace-depth-aware
//!   discovery of if/else-if chains over one decompiled body, used by both
//!   the switch and state-machine detectors.
//! - `cfg` (crate-internal) - Per-body control flow graph. Basic blocks
//!   split at branch heads, loop heads, labels, `goto`s, and `return`s.
//!   The blocks are connected by fall-through, branch, jump, and back
//!   edges, following the chain walker's brace-counting and
//!   string-literal rules. The graph is working machinery, not a saved
//!   artifact: the loop, branch-density, and recursion readings share
//!   one graph per body, so their nesting and depth claims cannot
//!   disagree.
//! - [`switch`] - Switch-shaped chain detection: `SwitchChainDetector`
//!   collects the compared constants, flags a trailing-`else` default,
//!   and suggests a dispatch table for very wide chains.
//! - [`recursion`] - Self-recursion detection: `RecursionDetector`
//!   counts self-calls and flags tail calls (`return name(...)`).
//! - [`state_machine`] - State-machine detection: `StateMachineDetector`
//!   reads named-constant chains (default name set `STATE_*`/`IDLE`/
//!   `RUNNING`, swappable), transition assignments, and the idle state.
//! - `loop_detect` - Loop structure detection: `LoopDetector` reads
//!   for/while/do-while/goto loops and their nesting depth from the
//!   CFG, and records one `LoopNesting` finding per function.
//! - `branch_density` - Branch density classification:
//!   `BranchDensityDetector` counts the conditional edges leaving
//!   `if`/`else if` heads against the CFG's basic blocks and records
//!   one `BranchDensity` finding per function — dispatch-table
//!   candidate or sequential scan — and nothing for bodies too small
//!   to classify.
//! - `branch_inventory` - Branch inventory: `BranchInventoryDetector`
//!   walks the same CFG and records one `BranchSite` record per branch
//!   site — condition text, tested names, operator and immediate where
//!   readable, and the guarded target (early return, error path, loop
//!   exit, else arm, switch arm). It records nothing for plain guarded
//!   bodies whose story the other findings already tell.
//! - [`cross_function`] - Cross-function recursion readings:
//!   `CrossFunctionAnalyzer` derives call edges from the bodies the
//!   scan keeps — with the recursion detector's own call-site scan, no
//!   new `ScanSource` reads — and lands one `MutualRecursion` finding
//!   per call cycle of two or more functions, attached to the cycle's
//!   earliest member in listing order.
//! - [`engine`] - Scan orchestration: `ControlFlowEngine` runs the six
//!   detectors over one loaded program through a `ScanSource` (function
//!   listing + decompile-by-name). It is one sequential pass: it
//!   decompiles each function exactly once, keeps the bodies for the
//!   cross-function pass, and keeps the findings in scan order.
//! - [`persist`] - JSON persistence: `ControlFlowPersistor` saves and
//!   loads the per-binary detection results under
//!   `re/analysis/controlflow/`.
//! - [`error`] - [`ControlFlowError`] and the crate-wide [`Result`]
//!   alias.

pub mod branch_density;
pub mod branch_inventory;
pub(crate) mod chain;
// The loop and branch-density detectors (issues #176, #177) read loops,
// blocks, and edges from the CFG. The entry, reachability, and back-edge
// accessors are still unused: they wait on the self-recursion deepening
// ticket (#179), and the cross-function pass (#178) derives its edges
// from the kept body text, not from the graph. So the dead-code warning
// stays allowed for those accessors.
#[allow(dead_code)]
pub(crate) mod cfg;
pub mod cross_function;
pub mod engine;
pub mod error;
pub mod loop_detect;
pub mod persist;
pub mod recursion;
pub mod state_machine;
pub mod switch;
pub mod types;

pub use error::{ControlFlowError, Result};
