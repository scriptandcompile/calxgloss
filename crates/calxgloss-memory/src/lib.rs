//! Memory lifecycle and RAII detection for calxgloss.
//!
//! Analyzes allocation/deallocation pairs, ownership transfer patterns,
//! and resource lifetimes within each function and across the call
//! graph. Results are injected as structured `MemoryHint` sections that
//! suggest the appropriate Rust ownership pattern — `Box`, `Rc`, `Arc`,
//! `Cow`, `ManuallyDrop` — to the translation prompts.
//!
//! # Architecture
//!
//! The crate is organized into six modules:
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
//! - [`persist`] - JSON persistence: `MemoryPersistor` saves and loads
//!   the per-binary detection results under `re/analysis/memory/`.
//! - [`error`] - [`MemoryError`] and the crate-wide [`Result`] alias.

pub mod allocator;
pub mod error;
pub mod handle;
pub mod persist;
pub mod refcount;
pub mod types;

pub use error::{MemoryError, Result};
