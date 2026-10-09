//! Verification — compile and test translated Rust code against baseline behavior.
//!
//! This crate provides the [`Verifier`] struct, which takes translated Rust code
//! and baseline test cases, compiles the code in a sandboxed temporary project,
//! and verifies that the output matches the original binary's behavior.
//!
//! # Workflow
//!
//! 1. Scaffold a minimal Cargo project in a temporary directory
//! 2. Write the translated code as a library module
//! 3. Provide stub implementations for common external dependencies (PAL traits, etc.)
//! 4. Run `cargo check` to verify compilation
//! 5. If compilation succeeds, generate and run behavioral tests against baseline inputs
//! 6. Return a [`VerificationResult`] with compilation status and test pass/fail details
//!
//! # Example
//!
//! ```ignore
//! use calxgloss_verify::Verifier;
//! use std::path::Path;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let verifier = Verifier::new(Path::new("/tmp/calxgloss-work"))?;
//!
//! let rust_code = r#"
//! pub fn draw_sprite(x: i32, y: i32, texture_index: u32) -> i32 {
//!     (x + y) as i32
//! }
//! "#;
//!
//! let baseline_tests = vec![];
//!
//! let results = verifier.verify(
//!     "game_logic.dll",
//!     "draw_sprite",
//!     rust_code,
//!     &baseline_tests,
//! ).await?;
//!
//! assert!(results.compiled);
//! assert_eq!(results.tests_passed, results.tests_total);
//! # Ok(())
//! # }
//! ```

mod cargo;
mod engine;
mod helpers;
mod parse;
mod stubs;

pub use calxgloss_types::{
    FailedTest, ShimMappingTestResult, ShimVerificationResult, TestCase, VerificationResult,
};
pub use engine::{CompileResult, Verifier};
pub use helpers::{sanitize_crate_name, sanitize_identifier};
pub use parse::{
    extract_mapping_function, parse_cargo_output, parse_shim_test_results, parse_test_line,
    parse_test_results,
};
pub use stubs::Stubs;
