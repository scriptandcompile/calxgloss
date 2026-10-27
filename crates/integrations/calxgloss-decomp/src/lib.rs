//! The analysis-engine seam: the shared read/write interfaces every
//! evidence engine pulls its program facts through, backed by the Kuna
//! engine (issue #214, part of epic #203).
//!
//! The GhidraMCP client and the headless-JVM lifecycle that used to live
//! here are retired: Kuna is the only analysis engine, loaded in-process
//! from the target binary. What stays is the vocabulary the pipeline and
//! the evidence engines were built against:
//!
//! * [`ScanSource`] is the shared read-only seam — functions, decompilations,
//!   disassembly listings, strings, xrefs, type listings, memory.
//!   [`PipelineSource`] is the seam's dispatch enum: `Cached | Kuna`.
//! * [`TypeWriteSource`] is the write-side seam — setting prototypes and
//!   variable types, creating the named types an inferred type refers to.
//!   Kuna answers these through its directive plane (issue #209).
//! * [`CachedScanSource`] wraps the engine with the two-tier read cache
//!   every scan reads through, keyed by the target binary's file bytes.
//!   The module also carries the surviving-scan surface — [`is_surviving_scan`]
//!   and the [`cached_functions`], [`cached_exports`], [`cached_body`] readers —
//!   the read-only way to answer an older version's scan document set with no
//!   engine in sight (track P18, issue #298).
//! * [`EngineError`] is the seam's error vocabulary — a named miss, a
//!   malformed answer, an engine-reported failure — into which every
//!   engine-native error folds.
//! * [`parse`] and [`model`] hold the Ghidra-shaped text formats and record
//!   types that remain live vocabulary: decompiled pseudo-C in the FUN_…
//!   dialect, the scraper over it, and the shapes the persisted records
//!   carry.
//! * `noise_filter` is the decompiler-noise pre-filter — the one pure text
//!   pass applied at the exit of the `decompile` read in both sources, so
//!   every consumer sees pseudo-C with recognized compiler noise (the GS
//!   stack-canary family first, issue #232) already stripped. It changes
//!   nothing on disk: the cache keeps the engine's raw text (issue #271).
//!
//! The crate was named `calxgloss-ghidra` until ADR-0042 took up ADR-0041's
//! deferred renames, and the scan read cache filed under `re/ghidra-cache`
//! and then `re/decomp-cache` files under `re/cache` from ADR-0043; each
//! on-disk rename resets old caches, which the cache-format version marker
//! would have forced anyway once the engine changed.

mod cache;
mod error;
mod model;
mod noise_filter;
pub mod parse;
mod scan_source;
mod type_write_source;

pub use cache::{
    CACHE_FORMAT_VERSION, CacheManifest, CachedScanSource, cache_root, cached_body, cached_exports,
    cached_functions, is_surviving_scan, sha256_of_file,
};
pub use error::{EngineError, Result};
pub use model::{
    DataItem, DataTypeEntry, DecompiledFunction, EnumDefinition, EnumMember, FunctionSummary,
    StringLiteral, StructFieldLayout, StructLayout, Symbol, Xref, rva_from_va,
};
pub use scan_source::{PipelineSource, QUERY_FAMILIES, ScanSource};
pub use type_write_source::{NewStructField, TypeWriteSource};
