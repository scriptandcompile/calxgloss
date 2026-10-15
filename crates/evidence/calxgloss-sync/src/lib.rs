//! Concurrency and synchronization detection for calxgloss.
//!
//! Analyzes mutex/lock usage, atomic operations, threading
//! constructs, and thread-local storage within each function of an
//! open Ghidra program. Results are injected as structured
//! CONCURRENCY sections that name the Rust synchronization primitive —
//! `std::sync::Mutex`, `parking_lot::Mutex`, `std::sync::RwLock`,
//! `std::sync::atomic::*`, `std::thread::spawn`, `tokio::spawn`,
//! `thread_local!` — the translation should aim at, so a
//! multithreaded binary's synchronization survives translation instead
//! of being transliterated into plain calls.
//!
//! # Architecture
//!
//! The crate is organized into eight modules:
//!
//! - [`types`] - Core data types: `SyncType` for the lock family a
//!   recognized acquire belongs to; `ConcurrencyHint`, `AtomicOperation`,
//!   `ThreadSpawn`, and `TlsUsage` for the per-function detection
//!   records; `SyncFinding` as the union over the record kinds;
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
//! - [`tls`] - Thread-local storage detection: `TlsDetector`
//!   recognizes the Win32 `TlsAlloc`/`TlsGetValue`/`TlsSetValue`/
//!   `TlsFree` and POSIX `pthread_key_create`/`pthread_getspecific`/
//!   `pthread_setspecific`/`pthread_key_delete` families, ties each
//!   access to the key creation naming the same variable, and suggests
//!   `thread_local!` storage.
//! - [`engine`] - Scan orchestration: `SyncEngine` runs the four
//!   detectors over one open Ghidra program through a `ScanSource`
//!   (function listing + decompile-by-name), one sequential pass that
//!   decompiles each function exactly once and keeps the findings in
//!   scan order.
//! - [`persist`] - JSON persistence: `SyncPersistor` saves and loads
//!   the per-binary detection results under `re/analysis/sync/`.
//! - [`error`] - [`SyncError`] and the crate-wide [`Result`] alias.

pub mod async_runtime;
pub mod atomic;
pub mod engine;
pub mod error;
pub mod mutex;
pub mod persist;
pub mod threading;
pub mod tls;
pub mod types;

pub use async_runtime::AsyncDetector;
pub use async_runtime::default_async_runtime_names;
pub use error::{Result, SyncError};
pub use types::AsyncLoop;
pub use types::AsyncOperation;
pub use types::AsyncRuntime;
pub use types::AsyncRuntimeUsage;
