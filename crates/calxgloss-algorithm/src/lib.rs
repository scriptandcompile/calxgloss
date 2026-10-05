//! Algorithm recognition for calxgloss.
//!
//! Detects when a function implements a known algorithm — sorting, hashing,
//! parsing, compression, graph traversal — so the LLM gets a high-level
//! specification to target. Results are cached per-DLL and injected into
//! LLM prompts as structured `AlgorithmHint` sections.
//!
//! # Architecture
//!
//! The crate is organized into seven modules:
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
//!   matches function signatures and usage against callback shapes —
//!   qsort compare, bsearch compare, hash table comparator — with caller
//!   name pattern matching through the call graph.
//! - [`confidence`] - Shared confidence model: score composition per
//!   detection method, configurable thresholds, and highest-confidence-wins
//!   resolution when several detectors hint at different algorithms for
//!   one function.
//! - [`persist`] - JSON persistence: `AlgorithmPersistor` saves and loads
//!   the per-binary recognition results under `re/analysis/algorithm/`.
//! - [`error`] - [`AlgorithmError`] and the crate-wide [`Result`] alias.

pub mod callback_db;
pub mod cfg_patterns;
pub mod confidence;
pub mod error;
pub mod persist;
pub mod string_hints;
pub mod types;

pub use error::{AlgorithmError, Result};
