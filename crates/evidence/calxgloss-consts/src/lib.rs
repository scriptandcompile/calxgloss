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
//! The crate is organized into thirteen modules:
//!
//! - [`types`] - Core data types: `BitflagGroup`, `EnumCandidate`, and
//!   `NamedConstant` for the detection records; `FlagFamily` for the
//!   program-level merged flag-family record; `ProtocolConstant` for
//!   the program-level known-magic record; `ColorConstant` for the
//!   program-level palette record; `ConstFinding` as the
//!   union over the record kinds; `ConstResult`, `ScanMetadata` for
//!   the persisted per-binary results.
//! - [`bitmask`] - Bitflag group detection: `BitmaskDetector` collects
//!   power-of-two literals used in bitwise contexts (`&`, `|`, `^`,
//!   `&= ~`, `1 << n`) per function into one flag-group finding,
//!   decomposing a composite mask into its set bits when every bit
//!   was independently seen singly in the same body, and suggests a
//!   `bitflags!`-style struct.
//! - [`sequential`] - Enum candidate detection: `SequentialDetector`
//!   parses switch case values and turns runs of three or more
//!   contiguous ascending values into enum-candidate findings
//!   suggesting a Rust `enum`.
//! - [`frequency`] - Repeated-value analysis: `FrequencyAnalyzer`
//!   counts integer literals across the whole program and reports
//!   values used often enough across enough functions as named
//!   constants suggesting a `const`, carrying the context names the
//!   naming reading derived from the same bodies.
//! - [`codegen`] - Rust codegen: [`codegen::render_codegen`] turns a
//!   loaded result into one reviewable Rust source string — a
//!   `bitflags!`-style block per flag family, an `enum` block per enum
//!   candidate, and `const` items for the named, protocol, and color
//!   constants — deterministic, naming only what the findings support,
//!   and never read back (ADR-0013).
//! - [`engine`] - Scan orchestration: `ConstEngine` runs the three
//!   detectors over one open Ghidra program through a `ScanSource`
//!   (function listing + decompile-by-name), one sequential pass that
//!   decompiles each function exactly once and keeps the findings in
//!   scan order, then merges the scan's own bitflag groups into
//!   program-level flag families and appends them after the named
//!   constants.
//! - [`persist`] - JSON persistence: `ConstPersistor` saves and loads
//!   the per-binary detection results under `re/analysis/consts/`.
//! - [`error`] - [`ConstError`] and the crate-wide [`Result`] alias.
//! - `flag_family` - a crate-private merge post-pass: `merge_families`
//!   ties the per-function bitflag groups the scan just built through
//!   shared bits, transitively, and renders each merged set as one
//!   program-level flag-family record — no bodies kept, no new reads.
//! - `naming` - a crate-private context-naming reading: `context_names`
//!   walks one body's token stream for assignments and comparisons that
//!   name their literals, with the placeholder-identifier gate that
//!   keeps decompiler-minted names from naming anything.
//! - `protocol` - a crate-private known-magic reading: `protocol_constants`
//!   reads the program-wide literal tally before the frequency threshold
//!   applies and reports each tallied value that matches the built-in
//!   table of well-known protocol/format magics and sentinels as one
//!   named `protocol_constant` record, single use included.
//! - `color` - a crate-private color-grouping reading: `color_palette`
//!   walks the same literal tally and groups the color-shaped values
//!   (≤ 24-bit, not powers of two) into at most one program-level
//!   `color_constant` palette finding per binary — two distinct
//!   qualifying values make a palette, a lone one claims nothing.
//! - `tokenize` - a crate-private pseudo-C tokenizer the three
//!   detectors and the naming reading share, keeping string contents
//!   and identifier-embedded digits out of the literal stream.

pub mod bitmask;
pub mod codegen;
pub mod engine;
pub mod error;
pub mod frequency;
pub mod persist;
pub mod sequential;
pub mod types;

pub(crate) mod color;
pub(crate) mod flag_family;
pub(crate) mod naming;
pub(crate) mod protocol;
pub(crate) mod tokenize;

pub use error::{ConstError, Result};
