//! Constant and enum recovery for calxgloss.
//!
//! The scan analyzes bitflag usage, enumerated dispatch, and repeated
//! magic numbers in each function of a loaded program. Its results are
//! injected as structured CONSTANTS sections that name the Rust shape
//! the translation should aim at: a `bitflags!`-style struct for a
//! flag-bit group, an `enum` for a contiguous switch run, and a named
//! `const` for a value repeated across the program. This keeps a
//! binary's constants in the translation as named items, instead of
//! leaving them scattered as bare integer literals.
//!
//! # Architecture
//!
//! The crate is organized into fourteen modules:
//!
//! - [`types`] - Core data types: `BitflagGroup`, `EnumCandidate`, and
//!   `NamedConstant` for the detection records; `FlagFamily` for the
//!   program-level merged flag-family record; `ProtocolConstant` for
//!   the program-level known-magic record; `ColorConstant` for the
//!   program-level palette record; `DataTable` for the program-level
//!   data-table record; `ConstFinding` as the
//!   union over the record kinds; `ConstResult`, `ScanMetadata` for
//!   the persisted per-binary results.
//! - [`bitmask`] - Bitflag group detection: `BitmaskDetector` collects
//!   the power-of-two literals used in bitwise contexts (`&`, `|`,
//!   `^`, `&= ~`, `1 << n`) in each function into one flag-group
//!   finding. When every bit of a composite mask was also seen on its
//!   own in the same body, it breaks the mask down into its set bits.
//!   It suggests a `bitflags!`-style struct.
//! - [`sequential`] - Enum candidate detection: `SequentialDetector`
//!   parses switch case values. A run of three or more contiguous
//!   ascending values becomes an enum-candidate finding suggesting a
//!   Rust `enum`.
//! - [`frequency`] - Repeated-value analysis: `FrequencyAnalyzer`
//!   counts integer literals across the whole program. It reports
//!   values used often enough, and across enough functions, as named
//!   constants suggesting a `const`. Each record also carries the
//!   context names the naming reading derived from the same bodies.
//! - [`codegen`] - Rust codegen: [`codegen::render_codegen`] turns a
//!   loaded result into one reviewable Rust source string. It renders
//!   a `bitflags!`-style block per flag family, an `enum` block per
//!   enum candidate, and `const` items for the named, protocol, and
//!   color constants. It is deterministic, names only what the
//!   findings support, and nothing reads its output back (ADR-0013).
//! - [`engine`] - Scan orchestration: `ConstEngine` runs the three
//!   detectors over one loaded program through a `ScanSource`
//!   (function listing + decompile-by-name). One sequential pass
//!   decompiles each function exactly once and keeps the findings in
//!   scan order. It then merges the scan's own bitflag groups into
//!   program-level flag families and appends them after the named
//!   constants.
//! - [`persist`] - JSON persistence: `ConstPersistor` saves and loads
//!   the per-binary detection results under `re/analysis/consts/`.
//! - [`error`] - [`ConstError`] and the crate-wide [`Result`] alias.
//! - `flag_family` - a crate-private merge post-pass:
//!   `merge_families` joins the per-function bitflag groups the scan
//!   just built through shared bits, transitively, and renders each
//!   merged set as one program-level flag-family record. It keeps no
//!   bodies and makes no new reads.
//! - `naming` - a crate-private context-naming reading:
//!   `context_names` walks one body's token stream to find assignments
//!   and comparisons that name their literals. A gate on placeholder
//!   identifiers keeps decompiler-minted names from naming anything.
//! - `protocol` - a crate-private known-magic reading:
//!   `protocol_constants` reads the program-wide literal tally before
//!   the frequency threshold applies. It reports each tallied value
//!   that matches the built-in table of well-known protocol/format
//!   magics and sentinels as one named `protocol_constant` record,
//!   even when the value appears only once.
//! - `color` - a crate-private color-grouping reading: `color_palette`
//!   walks the same literal tally and groups the color-shaped values
//!   (≤ 24-bit, not powers of two) into at most one program-level
//!   `color_constant` palette finding per binary. Two distinct
//!   qualifying values make a palette; a lone one claims nothing.
//! - `data_table` - a crate-private data-table reading: `data_tables`
//!   checks each object the analysis engine's data listing defines
//!   against how the kept bodies use it — an indexed read corroborates
//!   a claim, and a store through the symbol disqualifies one. It
//!   decodes the object's bytes uniformly at one stride, and a bounds
//!   guard picks the stride when several decode cleanly. It reports
//!   each corroborated table as one program-level `data_table` record,
//!   in listing order. An object a kept body writes, or whose entries
//!   resolve to function starts at all, claims nothing: whatever the
//!   bytes, the guards, and the bodies disagree on, claims nothing.
//! - `tokenize` - a crate-private pseudo-C tokenizer shared by the
//!   three detectors and the naming reading. It keeps string contents
//!   and digits inside identifiers out of the literal stream.

pub mod bitmask;
pub mod codegen;
pub mod engine;
pub mod error;
pub mod frequency;
pub mod persist;
pub mod sequential;
pub mod types;

pub(crate) mod color;
pub(crate) mod data_table;
pub(crate) mod flag_family;
pub(crate) mod naming;
pub(crate) mod protocol;
pub(crate) mod tokenize;

pub use error::{ConstError, Result};
