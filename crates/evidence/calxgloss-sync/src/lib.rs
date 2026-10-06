//! Concurrency and synchronization detection for calxgloss.
//!
//! Analyzes mutex/lock usage, atomic operations, and threading
//! constructs within each function of an open Ghidra program. Results
//! are injected as structured CONCURRENCY sections that name the Rust
//! synchronization primitive — `std::sync::Mutex`, `parking_lot::Mutex`,
//! `std::sync::RwLock`, `std::sync::atomic::*`, `std::thread::spawn`,
//! `tokio::spawn` — the translation should aim at, so a multithreaded
//! binary's synchronization survives translation instead of being
//! transliterated into plain calls.
//!
//! # Architecture
//!
//! The crate is organized into seven modules:
//!
//! - [`types`] - Core data types: `SyncType` for the lock family a
//!   recognized acquire belongs to; `ConcurrencyHint`, `AtomicOperation`,
//!   and `ThreadSpawn` for the per-function detection records;
//!   `SyncFinding` as the union over the three record kinds;
//!   `SyncResult`, `ScanMetadata` for the persisted per-binary results.
//! - [`mutex`] - Mutex/lock pair tracking: `MutexDetector` pairs
//!   `pthread_mutex_lock`/`unlock`, `EnterCriticalSection`/
//!   `LeaveCriticalSection`, and `pthread_rwlock_rdlock`/`wrlock`/
//!   `unlock` acquisitions with their releases and suggests the matching
//!   Rust lock type.
//! - [`atomic`] - Atomic operation detection: `AtomicDetector`
//!   recognizes `__atomic_fetch_add`, `__sync_fetch_and_add`, and
//!   `InterlockedIncrement`/`InterlockedDecrement` calls and suggests
//!   `std::sync::atomic::AtomicU32`/`AtomicU64`.
//! - [`threading`] - Threading pattern detection: `ThreadingDetector`
//!   recognizes `CreateThread`, `pthread_create`, and
//!   `std::thread::spawn` call sites, ties them to their join patterns,
//!   and suggests `std::thread::spawn` or `tokio::spawn`.
//! - [`engine`] - Scan orchestration: `SyncEngine` runs the three
//!   detectors over one open Ghidra program through a `ScanSource`
//!   (function listing + decompile-by-name), one sequential pass that
//!   decompiles each function exactly once and keeps the findings in
//!   scan order.
//! - [`persist`] - JSON persistence: `SyncPersistor` saves and loads
//!   the per-binary detection results under `re/analysis/sync/`.
//! - [`error`] - [`SyncError`] and the crate-wide [`Result`] alias.

pub mod error;
pub mod mutex;
pub mod types;

pub use error::{Result, SyncError};
