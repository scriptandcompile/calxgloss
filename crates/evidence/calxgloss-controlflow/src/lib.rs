//! Control-flow pattern recognition for calxgloss.
//!
//! Analyzes switch-shaped if/else-if chains, self-recursion, and
//! state-machine patterns within each function of an open Ghidra
//! program. Results are injected as structured CONTROL FLOW sections
//! that name the Rust pattern — `match`, a dispatch table, `loop`,
//! `enum State` — the translation should aim at, so a binary's
//! dispatching and looping structure survives translation instead of
//! being transliterated into raw conditional jumps.
//!
//! # Architecture
//!
//! The crate is organized into nine modules:
//!
//! - [`types`] - Core data types: `SwitchChain`, `SelfRecursion`, and
//!   `StateMachine` for the per-function detection records;
//!   `ControlFlowFinding` as the union over the three record kinds;
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
//! - [`engine`] - Scan orchestration: `ControlFlowEngine` runs the
//!   three detectors over one open Ghidra program through a
//!   `ScanSource` (function listing + decompile-by-name), one
//!   sequential pass that decompiles each function exactly once and
//!   keeps the findings in scan order.
//! - [`persist`] - JSON persistence: `ControlFlowPersistor` saves and
//!   loads the per-binary detection results under
//!   `re/analysis/controlflow/`.
//! - [`error`] - [`ControlFlowError`] and the crate-wide [`Result`]
//!   alias.

pub(crate) mod chain;
// The CFG foundation lands ahead of its consumers (issues #176-#178): no
// detector builds a graph in the scan yet, so the dead-code warning is
// allowed until the loop, branch-density, and recursion readings wire it in.
#[allow(dead_code)]
pub(crate) mod cfg;
pub mod engine;
pub mod error;
pub mod persist;
pub mod recursion;
pub mod state_machine;
pub mod switch;
pub mod types;

pub use error::{ControlFlowError, Result};
