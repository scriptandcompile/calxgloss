//! Callback and function-pointer table detection for calxgloss.
//!
//! Within each function of a loaded program, this crate finds
//! function-pointer array calls, callback registration sites, jump-table
//! dispatches, and dynamic-loading plugin shapes. It also links a
//! callback registered in one function to another function that calls
//! it, working across the kept bodies.
//!
//! Results are injected as structured CALLBACKS sections that name the
//! Rust dispatch pattern the translation should aim at:
//! `Vec<Box<dyn Fn(...)>>` for handler arrays, `Box<dyn Fn(...)>`
//! closures for registered callbacks, `match` for jump tables,
//! `Box<dyn Plugin>` trait objects for plugin boundaries, and a shared
//! boxed closure for a register-then-call chain. Naming the pattern
//! keeps a binary's polymorphic dispatch intact through translation,
//! instead of letting it turn into opaque indirect calls.
//!
//! # Architecture
//!
//! The crate is organized into ten modules:
//!
//! - [`types`] - Core data types: `FpArrayCall`, `CallbackRegistration`,
//!   `JumpTable`, `PluginArchitecture`, `CallbackChain`, and
//!   `EventSystem` for the detection records; `CallbackFinding` as the
//!   union over the six record kinds; `CallbackResult`, `ScanMetadata`
//!   for the persisted per-binary results.
//! - [`engine`] - Scan orchestration: `CallbackEngine` runs the four
//!   per-body detectors and then the cross-function pass over one open
//!   program through a `ScanSource` (function listing +
//!   decompile-by-name). One sequential pass decompiles each function
//!   exactly once and keeps the findings in scan order.
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
//!   `jmp [table + index*N]` and suggests a `match` for the
//!   decompiler's own `switchD` case table, or a function-pointer
//!   array for any other table.
//! - [`plugin`] - Plugin architecture detection: `PluginDetector`
//!   recognizes the dynamic-loading shapes — `LoadLibrary`/
//!   `GetProcAddress` and `dlopen`/`dlsym` pairs, plugin entry-point
//!   names, and the host API table passed to an entry point — and
//!   suggests a trait-object plugin boundary.
//! - [`cross_function`] - Cross-function callback readings:
//!   `CrossFunctionAnalyzer` links a registration in one kept body to
//!   a direct call of the bound callback — or a call through a table
//!   the registration site named — in another body. It also
//!   reconstructs event systems from many registrations to one point
//!   plus a visible dispatch site. It reads only the bodies the scan
//!   already holds.
//! - [`signatures`] - Injected callable contracts: `CallableSignature`
//!   and `SignatureMap` hold a caller-composed map of callback name to
//!   known parameter and return types, and the enrichment renders the
//!   real `Fn(...)` contract into the registration and chain
//!   suggestions with no dependency on the type-inference crate.
//! - [`persist`] - JSON persistence: `CallbackPersistor` saves and loads
//!   the per-binary detection results under `re/analysis/callback/`.
//! - [`error`] - [`CallbackError`] and the crate-wide [`Result`] alias.

pub mod callback_reg;
pub mod cross_function;
pub mod engine;
pub mod error;
pub mod fp_array;
pub mod jump_table;
pub mod persist;
pub mod plugin;
pub mod signatures;
pub mod types;

pub use error::{CallbackError, Result};
