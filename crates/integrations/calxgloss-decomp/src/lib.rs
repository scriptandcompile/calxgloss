//! The analysis-engine seam: the shared read and write interfaces that every
//! evidence engine uses to get facts about the loaded program, backed by the
//! Kuna analysis engine (issue #214, part of epic #203).
//!
//! The GhidraMCP client and the headless-JVM lifecycle that used to live
//! here are retired. Kuna is the only analysis engine, and it loads the
//! target binary in-process. What this crate keeps is the vocabulary the
//! pipeline and the evidence engines were built against:
//!
//! * [`ScanSource`] is the shared read-only seam — functions, decompilations,
//!   disassembly listings, strings, xrefs, type listings, memory.
//!   [`PipelineSource`] is the seam's dispatch enum: `Cached | Kuna`.
//! * [`TypeWriteSource`] is the write-side seam — setting prototypes and
//!   variable types, creating the named types an inferred type refers to.
//!   Kuna answers these through its directive plane (issue #209).
//! * [`CachedScanSource`] wraps the analysis engine with the two-tier read
//!   cache every scan reads through, keyed by the target binary's file
//!   bytes. The module also carries the surviving-scan surface —
//!   [`is_surviving_scan`] and the [`cached_functions`], [`cached_exports`],
//!   [`cached_body`] readers — the read-only way to answer an older
//!   version's scan document set with no analysis engine loaded (track P18,
//!   issue #298).
//! * [`EngineError`] is the seam's error vocabulary — a named miss, a
//!   malformed answer, an analysis-engine failure report. Every error the
//!   analysis engine itself raises is converted into one of these three.
//! * [`parse`] and [`model`] hold the Ghidra-shaped text formats and record
//!   types that remain live vocabulary: decompiled pseudo-C in the FUN_…
//!   dialect, the scraper that reads it, and the shapes the persisted
//!   records carry.
//! * `noise_filter` is the decompile noise filter — the one pure text pass
//!   applied at the exit of the `decompile` read in both sources, so every
//!   consumer sees pseudo-C with recognized compiler noise (the GS
//!   stack-canary family first, issue #232) already stripped. It changes
//!   nothing on disk: the cache keeps the analysis engine's raw text
//!   (issue #271).
//!
//! The crate was named `calxgloss-ghidra` until ADR-0042 took up ADR-0041's
//! deferred renames. The scan read cache's files moved from
//! `re/ghidra-cache` to `re/decomp-cache`, then to `re/cache` from
//! ADR-0043. Each of those on-disk moves resets old caches. Since #358 a
//! reset is also forced by mechanism whenever the analysis engine's build
//! changes: every cache manifest carries an analysis-engine identity field.

mod cache;
mod error;
mod model;
mod noise_filter;
pub mod parse;
mod scan_source;
mod type_write_source;

pub use cache::{
    CACHE_FORMAT_VERSION, CacheManifest, CachedScanSource, cache_root, cached_body, cached_exports,
    cached_functions, current_engine_identity, is_surviving_scan, sha256_of_file,
};
pub use error::{EngineError, Result};
pub use model::{
    DataItem, DataTypeEntry, DecompiledFunction, EnumDefinition, EnumMember, FunctionSummary,
    StringLiteral, StructFieldLayout, StructLayout, Symbol, Xref, rva_from_va,
};
pub use scan_source::{PipelineSource, QUERY_FAMILIES, ScanSource};
pub use type_write_source::{NewStructField, TypeWriteSource};
