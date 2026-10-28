//! Memory lifecycle and RAII detection for calxgloss.
//!
//! The memory-lifecycle evidence engine finds allocation and release
//! pairs, ownership transfers, and resource lifetimes inside each
//! function and across the call graph. Its findings go into the
//! translation prompts as structured `MemoryHint` sections that
//! suggest the Rust ownership pattern to use — `Box`, `Rc`, `Arc`,
//! `Cow`, `ManuallyDrop`.
//!
//! # Architecture
//!
//! The crate is organized into seven modules:
//!
//! - [`types`] - Core data types: `MemoryHint`, `AllocationType` for
//!   per-function detection records; `HandleLifecycle` and
//!   `ReferenceCount` for the handle and reference-counting shapes;
//!   `MemoryFinding` as the union over the three record kinds;
//!   `MemoryResult`, `ScanMetadata` for the persisted per-binary
//!   results.
//! - [`allocator`] - Allocation/deallocation pair tracking:
//!   `AllocatorTracker` detects `malloc`/`calloc`/`realloc` → `free`
//!   pairs within a function and suggests `Box<T>` or stack allocation
//!   for short-lived allocations.
//! - [`handle`] - Handle lifecycle detection: detects
//!   `CreateFileW`/`CloseHandle` and `fopen`/`fclose` patterns and
//!   suggests RAII guard structs with `Drop` impls.
//! - [`refcount`] - Reference counting detection: detects
//!   `ref_count++`/`ref_count--` and `AddRef`/`Release` patterns and
//!   suggests `Rc<T>`/`Arc<T>`.
//! - [`cross_function`] - Cross-function lifecycle tracking: one
//!   function leaves an allocation open and a callee it was handed to
//!   releases it. The pass reads the kept bodies the scan already
//!   holds, so it makes no extra reads from the analysis engine.
//! - [`engine`] - Scan orchestration: `MemoryEngine` runs the three
//!   detectors over one loaded program through a `ScanSource` (a
//!   function listing plus decompile-by-name). It is one sequential
//!   pass: it decompiles each function exactly once and keeps the
//!   findings in scan order.
//! - [`persist`] - JSON persistence: `MemoryPersistor` saves and loads
//!   the per-binary document under `re/analysis/memory/`.
//! - [`error`] - [`MemoryError`] and the crate-wide [`Result`] alias.

pub mod allocator;
pub mod cross_function;
pub mod engine;
pub mod error;
pub mod handle;
pub mod persist;
pub mod refcount;
pub mod types;

pub use error::{MemoryError, Result};
