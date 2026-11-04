//! Test generation infrastructure for the Calxgloss reverse engineering harness.
//!
//! This crate provides tools for reading Windows DLL metadata, generating FFI
//! bindings, creating diverse test inputs from function signatures and disassembly
//! analysis, and executing baseline tests to capture the original binary's
//! behavior.
//!
//! # Workflow
//!
//! 1. Read the DLL's metadata with [`PeImage`]: image base, architecture, and
//!    the export and import tables
//! 2. Extract function signatures from the decompiler or the export table
//! 3. Generate FFI bindings (`extern "system"` blocks) for the original DLL
//! 4. Generate test inputs covering boundary values, typical values, edge
//!    cases, and one branch-targeted case per branch target of the scan's
//!    branch inventory
//! 5. Execute those inputs against the original binary under Wine to capture
//!    baseline behavior
//! 6. Save baseline results as JSON for verification against Rust translations
//!
//! Baseline execution calls into the real DLL, so it needs the module mapped at
//! runtime rather than a link-time binding: [`WineRunner`] generates a small
//! harness per function, cross-compiles it for the DLL's own architecture, and
//! runs it under Wine. See the `run` module for the details.
//!
//! An honest note on test-input generation: the inputs generated today are
//! signature-derived guesses — a real caller's argument vector enters the
//! suite only when a run is armed to capture it. The P23 mining lane adds
//! *mined inputs* captured at export entries by entry-recording trampolines
//! in the harness itself (see the `wine` module), written as an entry-event
//! log beside the results, and replayed through the same ground-truth walk
//! (the shared `CapturedCallEntry` record lives in
//! `calxgloss_types::capture`); mining is additive, and an un-armed baseline
//! run emits exactly the suite this crate invented. See the Pipeline glossary
//! for *mined input*, *captured call entry*, *entry hook*, *entry event*,
//! *recording proxy*, *reference-app run*, and *case origin*. The recording
//! proxy (the `wine::proxy` module) is the P23.5 collector: a generated DLL
//! that wears a target's binary identity, exports its full export name set,
//! records the calls that arrive through it, and forwards them transparently
//! to the real module.
//!
//! Global side-effect expectations are not captured from the Wine run — the
//! harness reports return values only. They come from the global-state scan
//! instead: [`global_state_expectations`] turns the function's access records
//! in the persisted global-state document into typed `GlobalRead`/
//! `GlobalWrite` expectations, each naming one global.
//!
//! # Example
//!
//! ```no_run
//! use calxgloss_testgen::TestGenerator;
//!
//! // Generate FFI binding from a signature
//! let binding = calxgloss_testgen::generate_ffi_binding(
//!     "game_logic.dll",
//!     "DrawSprite",
//!     "int __stdcall DrawSprite(int x, int y, unsigned int texture_index)",
//! ).unwrap();
//!
//! // Generate test inputs
//! let tests = calxgloss_testgen::generate_test_inputs(
//!     "int __stdcall DrawSprite(int x, int y, unsigned int texture_index)",
//!     "cmp eax, 0\nje null_handler",
//!     &[],
//! ).unwrap();
//! ```

mod expectations;
mod ffi;
mod generator;
mod inputs;
mod minidump;
mod pe;
mod record_replay;
mod run;
mod wine;

pub use expectations::global_state_expectations;
pub use ffi::{
    FfiBinding, FfiBindingBuilder, ParameterTypeInfo, ParsedSignature, decompiler_type_to_rust,
    generate_ffi_binding, parse_signature,
};
pub use generator::TestGenerator;
pub use inputs::{DisassemblyEdgeCases, EdgeCaseSource, generate_test_inputs};
pub use minidump::{
    AMD64, Minidump, MinidumpException, MinidumpFolded, MinidumpModule, MinidumpThread, X64Context,
    fold_minidumps,
};
pub use pe::{ExportEntry, ImportEntry, Machine, PeImage};
pub use record_replay::{
    Folded, MineReport, Refusal, RefusalReason, Replay, ReplayOutcome, file_capture_records,
    fold_capture_event_log,
};
pub use run::{BaselineRunner, TestContext};
pub use wine::capture::{
    BudgetStop, CAPTURE_LOG_NAME, CaptureBudgets, CaptureRun, derive_proxy_slots,
};
pub use wine::owned::{OwnedProcess, OwnershipToken, Stopped};
pub use wine::proxy::{
    ProxyGeneration, ProxySlot, REFERENCE_APP_CAPTURE_PREFIX, RecordedSlot,
    generate_recording_proxy, px_notes, px_real_name, px_stderr_notes,
};
pub use wine::{
    EntryHook, FunctionLocator, HarnessReport, HarnessSpec, HarnessTestResult, LoadMode, ParamSpec,
    ScalarKind, WineRunner, encode_test_case, generate_harness, locator_for_function,
    locator_for_va,
};
