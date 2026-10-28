//! Known-library function identification for calxgloss.
//!
//! When a target binary statically links CRT or STL code, that code
//! arrives as ordinary-looking `FUN_…` bodies whose names say nothing
//! about what the code is. This crate identifies those functions by
//! *body signature*. It reads each function's decompiled body and
//! normalizes away the parts that change between builds: Ghidra
//! variable names, register temporaries, and addresses that move with
//! the image layout become wildcards, while calls, operators,
//! constants, string literals, and control-flow keywords are kept.
//! It then matches that shape against a signature set of statically
//! linked library code. A library match produces a finding naming the
//! matched library symbol and its family (CRT/STL), with an evidence
//! line and an evidence confidence.
//!
//! Matching is body shape, not bytes — the body-based complement to
//! ADR-0012's name-shape flagging; the two never touch each other's
//! records. Nothing is written back to the program (ADR-0020): findings
//! are flag-only, and what a match tells downstream to do (call-graph
//! `Skip` marking, prompt sections) is derived from the persisted
//! document elsewhere.
//!
//! # Architecture
//!
//! The crate is organized into ten modules:
//!
//! - [`types`] - Core data types: `LibmatchMatch` and `LibraryFamily`
//!   as the per-function match record, `LibmatchFinding` as the
//!   finding union, and `LibmatchResult` with `ScanMetadata` as the
//!   persisted per-binary document.
//! - [`signature`] - The signature record: `LibmatchSignature`, a named
//!   bundle of normalized-line regexes with an exclusion bundle, a
//!   line-count floor, and an optional per-entry confidence.
//!   `default_signatures` is the built-in starter set, holding the
//!   highest-frequency MSVC CRT and STL shapes.
//! - [`signature_db`] - The operator-supplied signature database:
//!   `SignatureDatabase`, one strict JSON document that carries the
//!   signature set whole (ADR-0023's pattern-database contract). A
//!   supplied file replaces the built-in set entirely.
//! - [`normalize`] - Body normalization: the wildcards that make a body
//!   shape comparable. [`normalize`] is shared corpus-wide: its entry
//!   point is public, and cross-crate consumers use it as-is without
//!   re-testing its contract; the contract stays pinned here, through
//!   scan findings.
//! - [`matcher`] - Signature matching: `LibmatchMatcher` carries the
//!   signature set a scan reads normalized bodies against.
//! - [`confidence`] - The evidence-confidence model:
//!   `BODY_MATCH_CONFIDENCE` as the standard score for a library
//!   match, `TAIL_CALL_CONFIDENCE_PENALTY` for a tail-call thunk, and
//!   `resolve_matches` settling competing claims for one function down
//!   to the strongest.
//! - `cross_function` - Cross-function propagation over the bodies
//!   one scan keeps: identical-body duplicates inherit a match, and
//!   tail-call thunks inherit at a confidence penalty. Internal to the
//!   scan (the module is `pub(crate)`, so its name is not a doc link).
//! - [`engine`] - Scan orchestration: `LibmatchEngine` runs the matcher
//!   over one loaded program through a `ScanSource` (function listing +
//!   decompile-by-name). Its per-function pass decompiles each function
//!   exactly once, findings keep scan order, and competing claims for
//!   one function resolve to the strongest (ADR-0022).
//! - [`persist`] - JSON persistence: `LibmatchPersistor` saves and
//!   loads the per-binary document under `re/analysis/libmatch/`.
//! - [`error`] - [`LibmatchError`] and the crate-wide [`Result`] alias.

pub mod confidence;
pub(crate) mod cross_function;
pub mod engine;
pub mod error;
pub mod matcher;
pub mod normalize;
pub mod persist;
pub mod signature;
pub mod signature_db;
pub mod types;

pub use error::{LibmatchError, Result};
