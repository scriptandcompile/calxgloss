//! Control-flow pattern recognition for calxgloss.
//!
//! Analyzes switch-shaped if/else-if chains, self-recursion,
//! state-machine patterns, loop structure, and branch density within
//! each function of
//! an open Ghidra
//! program. Results are injected as structured CONTROL FLOW sections
//! that name the Rust pattern — `match`, a dispatch table, `loop`,
//! `enum State` — the translation should aim at, so a binary's
//! dispatching and looping structure survives translation instead of
//! being transliterated into raw conditional jumps.
//!
//! # Architecture
//!
//! The crate is organized into eleven modules:
//!
//! - [`types`] - Core data types: `SwitchChain`, `SelfRecursion`,
//!   `StateMachine`, `LoopNesting` (with `LoopKind`), and `BranchDensity`
//!   (with `BranchClassification`) for the per-function detection
//!   records;
//!   `ControlFlowFinding` as the union over the five record kinds;
//!   `ControlFlowResult`, `ScanMetadata` for the persisted per-binary
//!   results.
//! - `chain` (crate-internal) - Shared chain walker: brace-depth-aware
//!   discovery of if/else-if chains over one decompiled body, used by both
//!   the switch and state-machine detectors.
//! - `cfg` (crate-internal) - Per-body control flow graph: basic blocks
//!   split at branch heads, loop heads, labels, `goto`s, and `return`s,
//!   wired with fall-through, branch, jump, and back edges on the chain
//!   walker's brace and string-literal discipline. Machinery, not an
//!   artifact: the loop, branch-density, and recursion readings share one
//!   graph per body so their nesting and depth claims cannot disagree.
//! - [`switch`] - Switch-shaped chain detection: `SwitchChainDetector`
//!   collects the compared constants, flags a trailing-`else` default,
//!   and suggests a dispatch table for very wide chains.
//! - [`recursion`] - Self-recursion detection: `RecursionDetector`
//!   counts self-calls and flags tail calls (`return name(...)`).
//! - [`state_machine`] - State-machine detection: `StateMachineDetector`
//!   reads named-constant chains (default name set `STATE_*`/`IDLE`/
//!   `RUNNING`, swappable), transition assignments, and the idle state.
//! - `loop_detect` - Loop structure detection: `LoopDetector` reads
//!   for/while/do-while/goto loops and their nesting depth off the CFG,
//!   landing one `LoopNesting` finding per function.
//! - `branch_density` - Branch density classification:
//!   `BranchDensityDetector` counts the conditional edges out of
//!   `if`/`else if` heads against the CFG's basic blocks, landing one
//!   `BranchDensity` finding per function — dispatch-table candidate or
//!   sequential scan — and nothing for bodies too small to classify.
//! - [`engine`] - Scan orchestration: `ControlFlowEngine` runs the
//!   five detectors over one open Ghidra program through a
//!   `ScanSource` (function listing + decompile-by-name), one
//!   sequential pass that decompiles each function exactly once and
//!   keeps the findings in scan order.
//! - [`persist`] - JSON persistence: `ControlFlowPersistor` saves and
//!   loads the per-binary detection results under
//!   `re/analysis/controlflow/`.
//! - [`error`] - [`ControlFlowError`] and the crate-wide [`Result`]
//!   alias.

pub mod branch_density;
pub(crate) mod chain;
// The loop and branch-density detectors (issues #176, #177) read loops,
// blocks, and edges off the CFG; the entry, reachability, and back-edge
// accessors still wait on the call-graph and recursion tickets
// (#178, #179), so the dead-code warning stays allowed for those.
#[allow(dead_code)]
pub(crate) mod cfg;
pub mod engine;
pub mod error;
pub mod loop_detect;
pub mod persist;
pub mod recursion;
pub mod state_machine;
pub mod switch;
pub mod types;

pub use error::{ControlFlowError, Result};
