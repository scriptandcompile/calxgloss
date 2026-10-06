//! Constant and enum recovery for calxgloss.
//!
//! Analyzes bitflag usage, enumerated dispatch, and repeated magic
//! numbers within each function of an open Ghidra program. Results are
//! injected as structured CONSTANTS sections that name the Rust shape
//! the translation should aim at — a `bitflags!`-style struct for a
//! flag-bit group, an `enum` for a contiguous switch run, a named
//! `const` for a value repeated across the program — so a binary's
//! constants survive translation as named items instead of scattering
//! as bare integer literals.
//!
//! # Architecture
//!
//! The crate is organized into eight modules:
//!
//! - [`types`] - Core data types: `BitflagGroup`, `EnumCandidate`, and
//!   `NamedConstant` for the detection records; `ConstFinding` as the
//!   union over the three record kinds; `ConstResult`, `ScanMetadata`
//!   for the persisted per-binary results.
//! - [`bitmask`] - Bitflag group detection: `BitmaskDetector` collects
//!   power-of-two literals used in bitwise contexts (`&`, `|`, `^`,
//!   `&= ~`, `1 << n`) per function into one flag-group finding and
//!   suggests a `bitflags!`-style struct.
//! - [`sequential`] - Enum candidate detection: `SequentialDetector`
//!   parses switch case values and turns runs of three or more
//!   contiguous ascending values into enum-candidate findings
//!   suggesting a Rust `enum`.
//! - [`frequency`] - Repeated-value analysis: `FrequencyAnalyzer`
//!   counts integer literals across the whole program and reports
//!   values used often enough across enough functions as named
//!   constants suggesting a `const`.
//! - [`engine`] - Scan orchestration: `ConstEngine` runs the three
//!   detectors over one open Ghidra program through a `ScanSource`
//!   (function listing + decompile-by-name), one sequential pass that
//!   decompiles each function exactly once and keeps the findings in
//!   scan order.
//! - [`persist`] - JSON persistence: `ConstPersistor` saves and loads
//!   the per-binary detection results under `re/analysis/consts/`.
//! - [`error`] - [`ConstError`] and the crate-wide [`Result`] alias.
//! - `tokenize` - a crate-private pseudo-C tokenizer the three
//!   detectors share, keeping string contents and identifier-embedded
//!   digits out of the literal stream.

pub mod bitmask;
pub mod engine;
pub mod error;
pub mod frequency;
pub mod persist;
pub mod sequential;
pub mod types;

pub(crate) mod tokenize;

pub use error::{ConstError, Result};
