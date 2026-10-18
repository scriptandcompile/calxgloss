//! Concurrency and synchronization detection for calxgloss.
//!
//! Analyzes mutex/lock usage, atomic operations, threading
//! constructs, and thread-local storage within each function of an
//! open program. Results are injected as structured
//! CONCURRENCY sections that name the Rust synchronization primitive —
//! `std::sync::Mutex`, `parking_lot::Mutex`, `std::sync::RwLock`,
//! `std::sync::atomic::*`, `std::thread::spawn`, `tokio::spawn`,
//! `thread_local!` — the translation should aim at, so a
//! multithreaded binary's synchronization survives translation instead
//! of being transliterated into plain calls.
//!
//! # Architecture
//!
//! The crate is organized into eleven modules:
//!
//! - [`types`] - Core data types: `SyncType` for the lock family a
//!   recognized acquire belongs to; `ConcurrencyHint`, `AtomicOperation`,
//!   `ThreadSpawn`, `TlsUsage`, `AsyncRuntime`, `Futex`, and `LockOrder`
//!   for the detection records; `SyncFinding` as the union over the
//!   record kinds; `SyncResult`, `ScanMetadata` for the persisted
//!   per-binary results.
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
//! - [`futex`] - Futex-based synchronization detection: `FutexDetector`
//!   recognizes direct `futex` calls and `syscall(SYS_futex, …)` shapes
//!   and suggests standard synchronization (`std::sync::Mutex`/
//!   `Condvar`).
//! - [`async_runtime`] - Async runtime detection: `AsyncDetector`
//!   recognizes event-loop shapes — I/O completion ports, epoll,
//!   select/poll, and the Win32 message pump — and suggests the Rust
//!   async shape each one reads as.
//! - [`cross_function`] - Cross-function readings over the bodies the
//!   scan keeps: `CrossFunctionAnalyzer` derives each body's lock
//!   acquisition sequence from the already-fetched decompiles and
//!   reports two functions acquiring the same two locks in opposite
//!   orders as a `lock_order` conflict, then reads the same bodies for
//!   one function writing a program global another reads with no lock
//!   both sides respect, as a `data_race` claim — no extra Ghidra
//!   round trips.
//! - [`engine`] - Scan orchestration: `SyncEngine` runs the per-body
//!   detectors over one loaded program through a `ScanSource`
//!   (function listing + decompile-by-name), one sequential pass that
//!   decompiles each function exactly once and keeps the findings in
//!   scan order, then the cross-function pass over the kept bodies.
//! - [`persist`] - JSON persistence: `SyncPersistor` saves and loads
//!   the per-binary detection results under `re/analysis/sync/`.
//! - [`error`] - [`SyncError`] and the crate-wide [`Result`] alias.

pub mod async_runtime;
pub mod atomic;
pub mod cross_function;
pub mod engine;
pub mod error;
pub mod futex;
pub mod mutex;
pub mod persist;
pub mod threading;
pub mod tls;
pub mod types;

pub use async_runtime::AsyncDetector;
pub use async_runtime::default_async_runtime_names;
pub use cross_function::CrossFunctionAnalyzer;
pub use error::{Result, SyncError};
pub use futex::FutexDetector;
pub use futex::default_futex_names;
pub use futex::default_futexes;
pub use types::AsyncLoop;
pub use types::AsyncOperation;
pub use types::AsyncRuntime;
pub use types::AsyncRuntimeUsage;
pub use types::CrossFunctionDataRace;
pub use types::CrossFunctionLockOrder;
pub use types::DataRace;
pub use types::DataRaceConflict;
pub use types::DataRaceRecord;
pub use types::Futex;
pub use types::FutexCall;
pub use types::FutexOperation;
pub use types::FutexRecord;
pub use types::FutexUsage;
pub use types::LockOrder;
pub use types::LockOrderRecord;
pub use types::LockOrdering;
