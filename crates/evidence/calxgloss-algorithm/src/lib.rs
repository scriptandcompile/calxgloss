//! Algorithm recognition for calxgloss.
//!
//! Detects when a function implements a known algorithm — sorting, hashing,
//! parsing, compression, graph traversal — so the LLM gets a high-level
//! specification to target. Results are cached per-binary and injected into
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
//!   scans decompiled bodies against hardcoded patterns. The standard set
//!   `default_patterns` includes: comparison sort, binary search, linear
//!   search, hash table lookup, state machine, recursion, and linked list
//!   traversal. The matcher also takes configurable match/exclude
//!   patterns and a minimum line count check that prevents false matches
//!   on tiny functions.
//! - [`string_hints`] - String-guided algorithm hints: `StringHintEngine`
//!   scans decompiled bodies and the binary's string listing against a
//!   set of string signatures. The standard set `default_signatures`
//!   includes: CRC, checksum, inflate, deflate, gzip, bz2, lzo,
//!   serialize, deserialize, md5, sha, hmac, http, tcp, and udp.
//!   Matching is case-insensitive per signature, with per-function
//!   deduplication.
//! - [`callback_db`] - Callback pattern detection: `CallbackPatternDb`
//!   matches function signatures and usage against callback shapes. The
//!   standard set `default_patterns` includes: qsort compare, bsearch
//!   compare, and hash table comparator. Caller name patterns are matched
//!   through the call graph.
//! - [`cross_function`] - Multi-function correlation: `CrossFunctionDetector`
//!   recognizes algorithms that span a call relationship. The standard
//!   set `default_relationships` includes: recursive divide-and-conquer
//!   (a self-call plus a halving split) and a sort driven by a comparator
//!   callback (a `qsort` call plus a comparator-shaped callee). The
//!   detector reads a call map built from the bodies the scan already
//!   decompiled, so this pass costs no extra analysis engine reads. Each
//!   hint records the partner function in its evidence.
//! - [`engine`] - Scan orchestration: `AlgorithmEngine` decompiles each
//!   function of an open program exactly once. The per-function pass runs
//!   with bounded concurrency — at most eight decompiles in flight —
//!   while results are recorded in listing order. Every body goes to all
//!   three per-function detectors, then a correlation pass runs over the
//!   whole listing. The scan resolves competing claims for one algorithm
//!   down to their strongest reading and assembles the survivors into
//!   one `AlgorithmRecognitionResult` with its scan provenance.
//!   `with_min_confidence` sets a floor below which hints never reach
//!   the persisted result.
//! - [`confidence`] - Shared confidence model: the standard score for
//!   each detection method (control flow 60, string body match 60 /
//!   listing-only match 30, callback contract 75, cross-function
//!   correlation 70). When several detectors claim the same algorithm for
//!   one function, resolution keeps the highest-confidence claim; ties
//!   keep the claim the scan surfaced first, and the winning claim stays
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
