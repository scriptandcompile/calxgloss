//! Algorithm recognition for calxgloss.
//!
//! Detects when a function implements a known algorithm — sorting, hashing,
//! parsing, compression, graph traversal — so the LLM gets a high-level
//! specification to target. Results are cached per-DLL and injected into
//! LLM prompts as structured `AlgorithmHint` sections.
//!
//! # Architecture
//!
//! The crate is organized into ten modules:
//!
//! - [`types`] - Core data types: `AlgorithmHint`, `AlgorithmCategory`,
//!   `DetectionMethod`, `AlgorithmPattern` for per-function detection
//!   records; `AlgorithmRecognitionResult`, `ScanMetadata` for the
//!   persisted per-binary results.
//! - [`cfg_patterns`] - Control flow signature matching: `CfgPatternMatcher`
//!   scans decompiled bodies against hardcoded patterns — the standard set
//!   `default_patterns` carries: comparison sort, binary search, linear
//!   search, hash table lookup, state machine, recursion, and linked list
//!   traversal — with configurable match/exclude
//!   patterns and a minimum line count check that prevents false matches
//!   on tiny functions.
//! - [`string_hints`] - String-guided algorithm hints: `StringHintEngine`
//!   scans decompiled bodies and the binary's string listing against a
//!   signature database — the standard set `default_signatures` carries:
//!   CRC, checksum, inflate, deflate, gzip, bz2, lzo, serialize,
//!   deserialize, md5, sha, hmac, http, tcp, and udp — with
//!   case-insensitive matching per signature and per-function
//!   deduplication.
//! - [`callback_db`] - Callback pattern detection: `CallbackPatternDb`
//!   matches function signatures and usage against callback shapes — the
//!   standard set `default_patterns` carries: qsort compare, bsearch
//!   compare, and hash table comparator — with caller name pattern
//!   matching through the call graph.
//! - [`cross_function`] - Multi-function correlation: `CrossFunctionDetector`
//!   recognizes algorithms that span a call relationship — the standard
//!   set `default_relationships` carries: recursive divide-and-conquer
//!   (a self-call plus a halving split) and a sort driven by a comparator
//!   callback (a `qsort` call plus a comparator-shaped callee) — reading
//!   a call map derived from the bodies the scan already decompiles, so
//!   the pass costs no extra Ghidra round trips; hints name the partner
//!   function in their evidence.
//! - [`engine`] - Scan orchestration: `AlgorithmEngine` decompiles each
//!   function of an open program exactly once — the per-function pass
//!   running with bounded concurrency, at most eight decompiles in
//!   flight, while results land in listing order — reads it with all
//!   three per-function detectors and then the correlation pass over
//!   the whole listing, resolves competing claims for one algorithm
//!   down to their strongest reading, and assembles the survivors into
//!   one `AlgorithmRecognitionResult` with its scan provenance;
//!   `with_min_confidence` sets a floor below which hints never reach
//!   the persisted result.
//! - [`confidence`] - Shared confidence model: the standard score each
//!   detection method pays out (control flow 60, string body match 60 /
//!   listing-only match 30, callback contract 75, cross-function
//!   correlation 70), and highest-confidence-wins resolution when
//!   several detectors claim the same algorithm for one function — ties
//!   keep the claim the scan surfaced first, and the survivor stands
//!   where that algorithm first appeared.
//! - [`persist`] - JSON persistence: `AlgorithmPersistor` saves and loads
//!   the per-binary recognition results under `re/analysis/algorithm/`.
//! - [`pattern_db`] - Dynamic pattern database: `PatternDatabase`, one
//!   JSON document with a section per detector, lets a scan read the
//!   operator's own signature sets — exactly the pattern types' serde
//!   shapes plus an optional per-entry confidence — instead of the
//!   built-in standard sets; a malformed file fails the run naming its
//!   path.
//! - [`error`] - [`AlgorithmError`] and the crate-wide [`Result`] alias.

pub mod callback_db;
pub mod cfg_patterns;
pub mod confidence;
pub mod cross_function;
pub mod engine;
pub mod error;
pub mod pattern_db;
pub mod persist;
pub mod string_hints;
pub mod types;

pub use error::{AlgorithmError, Result};
