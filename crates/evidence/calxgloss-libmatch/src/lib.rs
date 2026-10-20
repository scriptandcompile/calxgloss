//! Known-library function identification for calxgloss.
//!
//! When a target binary statically links CRT or STL code, that code
//! arrives as ordinary-looking `FUN_…` bodies with no names saying what
//! they are. This crate identifies those functions by *body signature*:
//! it reads each function's decompiled body, normalizes away the parts
//! that vary between builds — Ghidra variable names, register
//! temporaries, and volatile addresses become wildcards, while calls,
//! operators, constants, string literals, and control-flow keywords are
//! preserved — and matches the shape against a signature set of
//! statically-linked library code. A match lands a finding naming the
//! matched library symbol and its family (CRT/STL), with evidence and
//! confidence.
//!
//! Matching is body-shape, not bytes — the body-based complement to
//! ADR-0012's name-shape flagging; the two never touch each other's
//! records. Nothing is written back to the program (ADR-0020): findings
//! are flag-only, and what a match instructs downstream (call-graph
//! `Skip` marking, prompt sections) is derived from the persisted
//! document elsewhere.
//!
//! # Architecture
//!
//! The crate is organized into nine modules:
//!
//! - [`types`] - Core data types: `LibmatchMatch` and `LibraryFamily`
//!   for per-function detection records; `LibmatchFinding` as the
//!   finding union; `LibmatchResult`, `ScanMetadata` for the persisted
//!   per-binary results.
//! - [`signature`] - The signature record: `LibmatchSignature`, a named
//!   bundle of normalized-line regexes with an exclusion bundle, a
//!   line-count floor, and an optional per-entry confidence;
//!   `default_signatures` is the built-in starter set carrying the
//!   highest-frequency MSVC CRT shapes.
//! - [`signature_db`] - The operator-supplied signature database:
//!   `SignatureDatabase`, one strict JSON document carrying the
//!   signature set whole, per ADR-0023's pattern-database contract; a
//!   supplied file replaces the built-in set.
//! - [`normalize`] - Body normalization: the wildcards that make a body
//!   shape comparable. Internal; never tested directly, only through
//!   scan findings.
//! - [`matcher`] - Signature matching: `LibmatchMatcher` carries the
//!   signature set a scan reads normalized bodies against.
//! - [`cross_function`] - Cross-function propagation over the bodies
//!   one scan keeps: identical-body duplicates inherit a match, and
//!   tail-call thunks inherit at a penalty. Internal to the scan.
//! - [`engine`] - Scan orchestration: `LibmatchEngine` runs the matcher
//!   over one loaded program through a `ScanSource` (function listing +
//!   decompile-by-name), one sequential pass that decompiles each
//!   function exactly once, keeps findings in scan order, and resolves
//!   competing claims for one function to the strongest (ADR-0022).
//! - [`persist`] - JSON persistence: `LibmatchPersistor` saves and loads
//!   the per-binary identification results under `re/analysis/libmatch/`.
//! - [`error`] - [`LibmatchError`] and the crate-wide [`Result`] alias.

pub mod confidence;
pub(crate) mod cross_function;
pub mod engine;
pub mod error;
pub mod matcher;
pub(crate) mod normalize;
pub mod persist;
pub mod signature;
pub mod signature_db;
pub mod types;

pub use error::{LibmatchError, Result};
