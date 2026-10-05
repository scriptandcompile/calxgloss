//! Test generation infrastructure for the Calxgloss reverse engineering harness.
//!
//! This crate provides tools for reading Windows DLL metadata, generating FFI
//! stubs, creating diverse test inputs from function signatures and disassembly
//! analysis, and executing baseline tests to capture the original binary's
//! behavior.
//!
//! # Workflow
//!
//! 1. Read the DLL's metadata with [`PeImage`]: image base, architecture, and
//!    the export and import tables
//! 2. Extract function signatures from Ghidra or the export table
//! 3. Generate FFI stubs (`extern "system"` blocks) for the original DLL
//! 4. Generate test inputs covering boundary values, typical values, and edge cases
//! 5. Execute those inputs against the original binary under Wine to capture
//!    baseline behavior
//! 6. Save baseline results as JSON for verification against Rust translations
//!
//! Baseline execution calls into the real DLL, so it needs the module mapped at
//! runtime rather than a link-time stub: [`WineRunner`] generates a small
//! harness per function, cross-compiles it for the DLL's own architecture, and
//! runs it under Wine. See the `run` module for the details.
//!
//! # Example
//!
//! ```no_run
//! use calxgloss_testgen::TestGenerator;
//!
//! // Generate FFI stub from a signature
//! let stub = calxgloss_testgen::generate_ffi_stub(
//!     "game_logic.dll",
//!     "DrawSprite",
//!     "int __stdcall DrawSprite(int x, int y, unsigned int texture_index)",
//! ).unwrap();
//!
//! // Generate test inputs
//! let tests = calxgloss_testgen::generate_test_inputs(
//!     "int __stdcall DrawSprite(int x, int y, unsigned int texture_index)",
//!     "cmp eax, 0\nje null_handler",
//! ).unwrap();
//! ```

mod ffi;
mod generator;
mod inputs;
mod pe;
mod run;
mod wine;

pub use ffi::{
    FfiStub, FfiStubBuilder, ParameterTypeInfo, ParsedSignature, generate_ffi_stub,
    ghidra_type_to_rust, parse_signature,
};
pub use generator::TestGenerator;
pub use inputs::{DisassemblyEdgeCases, EdgeCaseSource, generate_test_inputs};
pub use pe::{ExportEntry, ImportEntry, Machine, PeImage};
pub use run::{BaselineRunner, TestContext};
pub use wine::{
    FunctionLocator, HarnessReport, HarnessSpec, HarnessTestResult, LoadMode, ParamSpec,
    ScalarKind, WineRunner, encode_test_case, generate_harness, locator_for_function,
    locator_for_va,
};
