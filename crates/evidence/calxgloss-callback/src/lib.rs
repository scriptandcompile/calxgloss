//! Callback and function-pointer table detection for calxgloss.
//!
//! Analyzes function-pointer array calls, callback registration sites,
//! and jump-table dispatches within each function of an open Ghidra
//! program. Results are injected as structured CALLBACKS sections that
//! name the Rust dispatch pattern — `Vec<Box<dyn Fn(...)>>` for handler
//! arrays, `Box<dyn Fn(...)>` closures for registered callbacks, `match`
//! for jump tables — the translation should aim at, so a binary's
//! polymorphic dispatch survives translation instead of collapsing into
//! opaque indirect calls.
//!
//! # Architecture
//!
//! The crate is organized into seven modules:
//!
//! - [`types`] - Core data types: `FpArrayCall`, `CallbackRegistration`,
//!   and `JumpTable` for the per-function detection records;
//!   `CallbackFinding` as the union over the three record kinds;
//!   `CallbackResult`, `ScanMetadata` for the persisted per-binary
//!   results.
//! - [`engine`] - Scan orchestration: `CallbackEngine` runs the three
//!   detectors over one open Ghidra program through a `ScanSource`
//!   (function listing + decompile-by-name), one sequential pass that
//!   decompiles each function exactly once and keeps the findings in
//!   scan order.
//! - [`fp_array`] - Function-pointer array detection: `FpArrayDetector`
//!   recognizes the indexed indirect-call shapes Ghidra decompiles out
//!   of `*(handlers[i])(args)` and suggests boxed closures for the
//!   elements.
//! - [`callback_reg`] - Callback registration detection:
//!   `CallbackRegDetector` recognizes calls to configured registration
//!   names (`register_callback`, `set_on_message`, and their kin) with
//!   the callback argument bound, and suggests a stored closure.
//! - [`jump_table`] - Jump-table detection: `JumpTableDetector`
//!   recognizes the indexed-dispatch shapes Ghidra leaves behind for
//!   `jmp [table + index*N]` and suggests a `match`, or a function-
//!   pointer array when the table is data-driven.
//! - [`persist`] - JSON persistence: `CallbackPersistor` saves and loads
//!   the per-binary detection results under `re/analysis/callback/`.
//! - [`error`] - [`CallbackError`] and the crate-wide [`Result`] alias.

pub mod error;
pub mod persist;
pub mod types;

pub use error::{CallbackError, Result};
