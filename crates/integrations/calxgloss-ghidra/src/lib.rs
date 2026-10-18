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
//!   strings, xrefs, type listings, memory. [`PipelineSource`] is the seam's
//!   dispatch enum: `Cached | Kuna`.
//! * [`TypeWriteSource`] is the write-side seam — setting prototypes and
//!   variable types, creating the named types an inferred type refers to.
//!   Kuna answers these through its directive plane (issue #209).
//! * [`CachedScanSource`] wraps the engine with the two-tier read cache
//!   every scan reads through, keyed by the target binary's file bytes.
//! * [`EngineError`] is the seam's error vocabulary — a named miss, a
//!   malformed answer, an engine-reported failure — into which every
//!   engine-native error folds.
//! * [`parse`] and [`model`] hold the Ghidra-shaped text formats and record
//!   types that remain live vocabulary: decompiled pseudo-C in the FUN_…
//!   dialect, the scraper over it, and the shapes the persisted records
//!   carry.
//!
//! The crate is still named `calxgloss-ghidra` and the cache still files
//! under `re/ghidra-cache`; ADR-0041 records those names as deferrals —
//! renaming them moves on-disk paths and every import in the workspace for
//! no behavioural change.

mod cache;
mod error;
mod model;
pub mod parse;
mod scan_source;
mod type_write_source;

pub use cache::CachedScanSource;
pub use error::{EngineError, Result};
pub use model::{
    DataItem, DataTypeEntry, DecompiledFunction, EnumDefinition, EnumMember, FunctionSummary,
    StringLiteral, StructFieldLayout, StructLayout, Symbol, Xref, rva_from_va,
};
pub use scan_source::{PipelineSource, ScanSource};
pub use type_write_source::{NewStructField, TypeWriteSource};
