//! Core data types for concurrency and synchronization information.
//!
//! This module holds the serialized shape of everything the concurrency
//! detectors produce:
//!
//! - `ConcurrencyHint`, `SyncType`: per-function mutex records — the
//!   lock a function acquires and releases, and the Rust synchronization
//!   type the pairing suggests.
//! - `AtomicOperation`, `ThreadSpawn`: the atomic-call and thread-spawn
//!   shapes beside plain lock pairings.
//! - `SyncFinding`: the union over the three record kinds — one finding
//!   whichever detector made it — serde-tagged by `kind`.
//! - `SyncResult`, `ScanMetadata`: the persisted per-binary result and
//!   its scan provenance.
//!
//! All types derive `Serialize`/`Deserialize`.

// `ScanMetadata` is the shared per-binary scan provenance and `Confidence`
// the shared 0–100 evidence score; both are re-exported so consumers name
// them through this crate, matching the typesdb, typeinfer, algorithm, and
// memory convention.
pub use calxgloss_types::{Confidence, ScanMetadata};
use serde::{Deserialize, Serialize};

// ============================================================
// Sync type
// ============================================================

/// The lock family a recognized acquire belongs to.
///
/// The family says which acquire and release spellings bracket the
/// critical section — a Win32 critical section entered by
/// `EnterCriticalSection`, a POSIX mutex locked by `pthread_mutex_lock`,
/// or a POSIX reader/writer lock locked by `pthread_rwlock_rdlock` — and
/// which Rust synchronization type stands in for the pairing: a poisoned
/// `std::sync::Mutex` for the critical section, an unpoisoned
/// `parking_lot::Mutex` for the POSIX mutex (pthread locking has no
/// poisoning to translate), and a `std::sync::RwLock` for the
/// reader/writer lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncType {
    /// A Win32 critical section — `EnterCriticalSection`/
    /// `LeaveCriticalSection` — reading as a poisoned `std::sync::Mutex`.
    StdMutex,
    /// A POSIX mutex — `pthread_mutex_lock`/`pthread_mutex_unlock` —
    /// reading as an unpoisoned `parking_lot::Mutex`.
    ParkingMutex,
    /// A POSIX reader/writer lock — `pthread_rwlock_rdlock`/`wrlock`/
    /// `unlock` — reading as a `std::sync::RwLock`.
    RwLock,
}

calxgloss_types::display_serde_label!(SyncType {
    StdMutex => "std_mutex",
    ParkingMutex => "parking_mutex",
    RwLock => "rw_lock",
});

// ============================================================
// Mutex pairings
// ============================================================

/// One mutex pairing observation about one function, with the evidence
/// behind it.
///
/// A hint is a hypothesis, not a fact applied to the program: it says
/// the function acquires a lock of [`sync_type`](Self::sync_type) —
/// through the recognized acquire spelling [`acquire`](Self::acquire) —
/// and releases it again through [`release`](Self::release), the two
/// tied by the lock object the decompiler passed to both calls. The
/// pairing reads like [`suggestion`](Self::suggestion) — the Rust
/// synchronization type standing in for the manual lock and unlock —
/// and the confidence says how strongly the pairing was read. The
/// acquire and release lines are kept as [`evidence`](Self::evidence)
/// so a reviewer (or a translation prompt) can check the reasoning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConcurrencyHint {
    /// The function the hint is about, e.g. `FUN_18003ab00`.
    pub function: String,
    /// The lock family the acquire and the release belong to.
    pub sync_type: SyncType,
    /// The acquire spelling that took the lock, e.g.
    /// `EnterCriticalSection`.
    pub acquire: String,
    /// The release spelling that gave the lock back, e.g.
    /// `LeaveCriticalSection`.
    pub release: String,
    /// The Rust synchronization type the pairing suggests, e.g.
    /// `std::sync::Mutex<T>`.
    pub suggestion: String,
    /// Confidence that the hint is right, 0–100.
    pub confidence: Confidence,
    /// The decompiled lines that support the hint — the acquire and
    /// its release — kept so a reviewer (or a translation prompt) can
    /// check the reasoning.
    pub evidence: String,
}

// ============================================================
// Atomic operations
// ============================================================

/// One atomic operation observation about one function, with the
/// evidence behind it.
///
/// A record says the function performs a read-modify-write through the
/// recognized call spelling [`operation`](Self::operation) —
/// `InterlockedIncrement`, `__atomic_fetch_add`, and their kin — which
/// reads like [`suggestion`](Self::suggestion): the sized atomic type
/// whose methods carry the same operation, `AtomicU32` for the Win32
/// interlocked family and `AtomicU64` for the GCC builtins by default.
/// Unlike the lock pairing, one call site is a whole finding — an
/// atomic needs no release to complete the picture. The call line is
/// kept as [`evidence`](Self::evidence) so a reviewer (or a translation
/// prompt) can check the reasoning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtomicOperation {
    /// The function the record is about, e.g. `FUN_18003ab00`.
    pub function: String,
    /// The call spelling that performed the atomic operation, e.g.
    /// `InterlockedIncrement`.
    pub operation: String,
    /// The Rust atomic type the call suggests, e.g.
    /// `std::sync::atomic::AtomicU32`.
    pub suggestion: String,
    /// Confidence that the record is right, 0–100.
    pub confidence: Confidence,
    /// The decompiled line that supports the record — the atomic call
    /// — kept so a reviewer (or a translation prompt) can check the
    /// reasoning.
    pub evidence: String,
}

// ============================================================
// Thread spawns
// ============================================================

/// One thread-spawn observation about one function, with the evidence
/// behind it.
///
/// A record says the function starts a thread through the recognized
/// spawn spelling [`spawn`](Self::spawn) — `CreateThread`,
/// `pthread_create`, `std::thread::spawn` — and, when the spawned
/// thread's handle is waited on through a recognized join spelling,
/// names that join in [`join`](Self::join), the two tied by the handle
/// variable the decompiler stored the spawn's result in (or passed to
/// it, for `pthread_create`). A joined spawn reads like
/// [`suggestion`](Self::suggestion) `std::thread::spawn` — the join is
/// the `JoinHandle` the translation can keep — and an unjoined one
/// reads like `tokio::spawn`, the fire-and-forget shape. The spawn and
/// join lines are kept as [`evidence`](Self::evidence) so a reviewer
/// (or a translation prompt) can check the reasoning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreadSpawn {
    /// The function the record is about, e.g. `FUN_18003ab00`.
    pub function: String,
    /// The spawn spelling that started the thread, e.g. `CreateThread`.
    pub spawn: String,
    /// The join spelling that waited for the thread, e.g.
    /// `WaitForSingleObject`, when the spawn was joined.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub join: Option<String>,
    /// The Rust pattern the spawn reads like, e.g.
    /// `std::thread::spawn` or `tokio::spawn`.
    pub suggestion: String,
    /// Confidence that the record is right, 0–100.
    pub confidence: Confidence,
    /// The decompiled lines that support the record — the spawn and
    /// its join, when there is one — kept so a reviewer (or a
    /// translation prompt) can check the reasoning.
    pub evidence: String,
}

// ============================================================
// Finding union
// ============================================================

/// One concurrency finding, whichever detector made it.
///
/// The detectors emit the concrete records; the union is what the
/// persisted result carries, so one list can hold every finding for a
/// binary and a consumer reads the shared shape — function, suggestion,
/// confidence, evidence — without naming which detector produced it.
/// Unlike typeinfer's competing families, the three detectors read
/// disjoint body shapes and can't make competing claims for one target,
/// so nothing is resolved between variants. The serde `kind` tag names
/// the record shape in the persisted JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SyncFinding {
    /// A lock acquired and released again.
    Mutex(ConcurrencyHint),
    /// A read-modify-write through a recognized atomic call.
    Atomic(AtomicOperation),
    /// A thread spawned, joined or not.
    Thread(ThreadSpawn),
}

impl SyncFinding {
    /// The function the finding is about.
    pub fn function(&self) -> &str {
        match self {
            SyncFinding::Mutex(record) => &record.function,
            SyncFinding::Atomic(record) => &record.function,
            SyncFinding::Thread(record) => &record.function,
        }
    }

    /// The Rust synchronization pattern the finding suggests.
    pub fn suggestion(&self) -> &str {
        match self {
            SyncFinding::Mutex(record) => &record.suggestion,
            SyncFinding::Atomic(record) => &record.suggestion,
            SyncFinding::Thread(record) => &record.suggestion,
        }
    }

    /// Confidence that the finding is right.
    pub fn confidence(&self) -> Confidence {
        match self {
            SyncFinding::Mutex(record) => record.confidence,
            SyncFinding::Atomic(record) => record.confidence,
            SyncFinding::Thread(record) => record.confidence,
        }
    }

    /// The decompiled lines that support the finding.
    pub fn evidence(&self) -> &str {
        match self {
            SyncFinding::Mutex(record) => &record.evidence,
            SyncFinding::Atomic(record) => &record.evidence,
            SyncFinding::Thread(record) => &record.evidence,
        }
    }

    /// The serde `kind` tag — `mutex`, `atomic`, or `thread` — naming
    /// the detector behind the finding.
    pub fn kind(&self) -> &'static str {
        match self {
            SyncFinding::Mutex(_) => "mutex",
            SyncFinding::Atomic(_) => "atomic",
            SyncFinding::Thread(_) => "thread",
        }
    }

    /// What the finding names, spelled for a report row: the acquire/
    /// release spellings, the atomic call spelling, or the spawn/join
    /// spellings.
    pub fn target(&self) -> String {
        match self {
            SyncFinding::Mutex(record) => format!("{}→{}", record.acquire, record.release),
            SyncFinding::Atomic(record) => record.operation.clone(),
            SyncFinding::Thread(record) => match &record.join {
                Some(join) => format!("{}→{}", record.spawn, join),
                None => record.spawn.clone(),
            },
        }
    }
}

// ============================================================
// Prompt conversions
// ============================================================

/// Render a finding as prompt data: the function it is about, the kind
/// of construct the detector read, the Rust synchronization pattern the
/// finding suggests, and the confidence and evidence behind the claim —
/// so the escalate prompt shows the hypothesis and how strongly it was
/// made, whichever detector produced it.
impl From<&SyncFinding> for calxgloss_prompts::ConcurrencyInfo {
    fn from(finding: &SyncFinding) -> Self {
        Self {
            function: finding.function().to_string(),
            kind: finding.kind().to_string(),
            suggestion: finding.suggestion().to_string(),
            confidence: finding.confidence().value(),
            evidence: finding.evidence().to_string(),
        }
    }
}

// ============================================================
// Persisted result
// ============================================================

/// The concurrency result for one binary — the document persisted to
/// `re/analysis/sync/{binary}.json`.
///
/// The findings are the three detectors' outputs in scan order:
/// function by function, and within one function the mutex pairings,
/// then the atomic calls, then the thread spawns. The detectors read
/// disjoint body shapes, so a function can carry findings of every
/// kind at once and none competes with another; the stable order means
/// two scans of the same program diff cleanly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncResult {
    /// Provenance of the scan that produced these findings.
    pub metadata: ScanMetadata,
    /// Every finding the detectors made, in scan order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<SyncFinding>,
}

impl SyncResult {
    /// An empty result for the binary described by `metadata`.
    pub fn new(metadata: ScanMetadata) -> Self {
        Self {
            metadata,
            findings: Vec::new(),
        }
    }

    /// The findings recorded for one function, e.g. `FUN_18003ab00`.
    pub fn for_function(&self, function: &str) -> impl Iterator<Item = &SyncFinding> {
        self.findings
            .iter()
            .filter(move |finding| finding.function() == function)
    }

    /// Whether the scan found nothing at all.
    pub fn is_empty(&self) -> bool {
        self.findings.is_empty()
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_SYNC_TYPES: [SyncType; 3] =
        [SyncType::StdMutex, SyncType::ParkingMutex, SyncType::RwLock];

    fn mutex_hint() -> ConcurrencyHint {
        ConcurrencyHint {
            function: "FUN_18003ab00".into(),
            sync_type: SyncType::StdMutex,
            acquire: "EnterCriticalSection".into(),
            release: "LeaveCriticalSection".into(),
            suggestion: "std::sync::Mutex<T>".into(),
            confidence: Confidence::new(70),
            evidence: "EnterCriticalSection(&local_20); /* ... */ LeaveCriticalSection(&local_20);"
                .into(),
        }
    }

    #[test]
    fn a_mutex_hint_serde_round_trips() {
        let record = mutex_hint();
        let json = serde_json::to_string(&record).unwrap();
        // The lock family serializes snake_case and the confidence as
        // a plain number, matching the workspace's serde convention.
        assert!(json.contains("\"sync_type\":\"std_mutex\""));
        assert!(json.contains("\"confidence\":70"));
        let back: ConcurrencyHint = serde_json::from_str(&json).unwrap();
        assert_eq!(back, record);
    }

    #[test]
    fn sync_types_display_their_serde_labels() {
        for sync_type in ALL_SYNC_TYPES {
            let label = serde_json::to_value(sync_type).unwrap();
            assert_eq!(sync_type.to_string(), label.as_str().unwrap());
        }
        assert_eq!(SyncType::ParkingMutex.to_string(), "parking_mutex");
        assert_eq!(SyncType::RwLock.to_string(), "rw_lock");
    }

    #[test]
    fn a_hint_names_the_function_the_family_the_spellings_and_the_type() {
        let json = serde_json::to_value(mutex_hint()).unwrap();
        assert_eq!(json["function"], "FUN_18003ab00");
        assert_eq!(json["sync_type"], "std_mutex");
        assert_eq!(json["acquire"], "EnterCriticalSection");
        assert_eq!(json["release"], "LeaveCriticalSection");
        assert_eq!(json["suggestion"], "std::sync::Mutex<T>");
        assert_eq!(json["confidence"], 70);
    }

    #[test]
    fn a_pthread_mutex_hint_reads_back_from_json() {
        let json = r#"{
            "function": "FUN_18003e750",
            "sync_type": "parking_mutex",
            "acquire": "pthread_mutex_lock",
            "release": "pthread_mutex_unlock",
            "suggestion": "parking_lot::Mutex<T>",
            "confidence": 70,
            "evidence": "pthread_mutex_lock(&mtx); pthread_mutex_unlock(&mtx);"
        }"#;
        let back: ConcurrencyHint = serde_json::from_str(json).unwrap();
        assert_eq!(back.sync_type, SyncType::ParkingMutex);
        assert_eq!(back.acquire, "pthread_mutex_lock");
        assert_eq!(back.release, "pthread_mutex_unlock");
        assert_eq!(back.suggestion, "parking_lot::Mutex<T>");
    }

    fn atomic_operation() -> AtomicOperation {
        AtomicOperation {
            function: "FUN_18003ab00".into(),
            operation: "InterlockedIncrement".into(),
            suggestion: "std::sync::atomic::AtomicU32".into(),
            confidence: Confidence::new(70),
            evidence: "uVar1 = InterlockedIncrement(&local_18);".into(),
        }
    }

    #[test]
    fn an_atomic_operation_serde_round_trips() {
        let record = atomic_operation();
        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("\"operation\":\"InterlockedIncrement\""));
        assert!(json.contains("\"confidence\":70"));
        let back: AtomicOperation = serde_json::from_str(&json).unwrap();
        assert_eq!(back, record);
    }

    #[test]
    fn an_atomic_record_names_the_function_the_call_and_the_type() {
        let json = serde_json::to_value(atomic_operation()).unwrap();
        assert_eq!(json["function"], "FUN_18003ab00");
        assert_eq!(json["operation"], "InterlockedIncrement");
        assert_eq!(json["suggestion"], "std::sync::atomic::AtomicU32");
        assert_eq!(json["confidence"], 70);
    }

    #[test]
    fn a_gcc_builtin_atomic_record_reads_back_from_json() {
        let json = r#"{
            "function": "FUN_18003e750",
            "operation": "__atomic_fetch_add",
            "suggestion": "std::sync::atomic::AtomicU64",
            "confidence": 70,
            "evidence": "__atomic_fetch_add(&counter,1,5);"
        }"#;
        let back: AtomicOperation = serde_json::from_str(json).unwrap();
        assert_eq!(back.operation, "__atomic_fetch_add");
        assert_eq!(back.suggestion, "std::sync::atomic::AtomicU64");
    }

    fn thread_spawn() -> ThreadSpawn {
        ThreadSpawn {
            function: "FUN_18003ab00".into(),
            spawn: "CreateThread".into(),
            join: Some("WaitForSingleObject".into()),
            suggestion: "std::thread::spawn".into(),
            confidence: Confidence::new(70),
            evidence: "hThread = CreateThread(...); WaitForSingleObject(hThread,0xffffffff);"
                .into(),
        }
    }

    #[test]
    fn a_joined_thread_spawn_serde_round_trips() {
        let record = thread_spawn();
        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("\"spawn\":\"CreateThread\""));
        assert!(json.contains("\"join\":\"WaitForSingleObject\""));
        let back: ThreadSpawn = serde_json::from_str(&json).unwrap();
        assert_eq!(back, record);
    }

    #[test]
    fn an_unjoined_thread_spawn_omits_the_join_and_reads_back_none() {
        let record = ThreadSpawn {
            join: None,
            ..thread_spawn()
        };
        let json = serde_json::to_string(&record).unwrap();
        assert!(!json.contains("\"join\""));
        let back: ThreadSpawn = serde_json::from_str(&json).unwrap();
        assert_eq!(back, record);
        assert_eq!(back.join, None);
    }

    #[test]
    fn a_thread_record_names_the_function_the_spellings_and_the_pattern() {
        let json = serde_json::to_value(thread_spawn()).unwrap();
        assert_eq!(json["function"], "FUN_18003ab00");
        assert_eq!(json["spawn"], "CreateThread");
        assert_eq!(json["join"], "WaitForSingleObject");
        assert_eq!(json["suggestion"], "std::thread::spawn");
        assert_eq!(json["confidence"], 70);
    }

    #[test]
    fn a_mutex_finding_serde_round_trips_under_its_kind_tag() {
        let finding = SyncFinding::Mutex(mutex_hint());
        let json = serde_json::to_string(&finding).expect("mutex finding should serialize");
        // The union is internally tagged: the kind names the record
        // shape and the payload's own fields sit beside it.
        assert!(json.contains("\"kind\":\"mutex\""));
        assert!(json.contains("\"sync_type\":\"std_mutex\""));
        let back: SyncFinding =
            serde_json::from_str(&json).expect("mutex finding should read back");
        assert_eq!(back, finding);
    }

    #[test]
    fn an_atomic_finding_serde_round_trips_under_its_kind_tag() {
        let finding = SyncFinding::Atomic(atomic_operation());
        let json = serde_json::to_string(&finding).expect("atomic finding should serialize");
        assert!(json.contains("\"kind\":\"atomic\""));
        assert!(json.contains("\"operation\":\"InterlockedIncrement\""));
        let back: SyncFinding =
            serde_json::from_str(&json).expect("atomic finding should read back");
        assert_eq!(back, finding);
    }

    #[test]
    fn a_thread_finding_serde_round_trips_under_its_kind_tag() {
        let finding = SyncFinding::Thread(thread_spawn());
        let json = serde_json::to_string(&finding).expect("thread finding should serialize");
        assert!(json.contains("\"kind\":\"thread\""));
        assert!(json.contains("\"spawn\":\"CreateThread\""));
        let back: SyncFinding =
            serde_json::from_str(&json).expect("thread finding should read back");
        assert_eq!(back, finding);
    }

    #[test]
    fn the_union_accessors_reach_through_every_variant() {
        let findings = [
            SyncFinding::Mutex(mutex_hint()),
            SyncFinding::Atomic(atomic_operation()),
            SyncFinding::Thread(thread_spawn()),
        ];
        for finding in &findings {
            assert_eq!(finding.function(), "FUN_18003ab00");
            assert_eq!(finding.confidence(), Confidence::new(70));
            assert!(!finding.suggestion().is_empty());
            assert!(!finding.evidence().is_empty());
        }
        let kinds: Vec<&str> = findings.iter().map(|f| f.kind()).collect();
        assert_eq!(kinds, vec!["mutex", "atomic", "thread"]);
        let suggestions: Vec<&str> = findings.iter().map(|f| f.suggestion()).collect();
        assert_eq!(
            suggestions,
            vec![
                "std::sync::Mutex<T>",
                "std::sync::atomic::AtomicU32",
                "std::thread::spawn"
            ]
        );
        let targets: Vec<String> = findings.iter().map(|f| f.target()).collect();
        assert_eq!(
            targets,
            vec![
                "EnterCriticalSection→LeaveCriticalSection",
                "InterlockedIncrement",
                "CreateThread→WaitForSingleObject"
            ]
        );
    }

    #[test]
    fn an_unjoined_thread_target_names_only_the_spawn() {
        let finding = SyncFinding::Thread(ThreadSpawn {
            join: None,
            ..thread_spawn()
        });
        assert_eq!(finding.target(), "CreateThread");
    }

    #[test]
    fn a_sync_result_serde_round_trips() {
        let result = SyncResult {
            metadata: ScanMetadata {
                binary: "eqmain.dll".into(),
                scanned_at: 1_759_488_000,
                duration_secs: 12,
            },
            findings: vec![
                SyncFinding::Mutex(mutex_hint()),
                SyncFinding::Atomic(atomic_operation()),
                SyncFinding::Thread(thread_spawn()),
            ],
        };
        let json = serde_json::to_string(&result).expect("sync result should serialize");
        let back: SyncResult = serde_json::from_str(&json).expect("sync result should read back");
        assert_eq!(back, result);
    }

    #[test]
    fn a_result_without_findings_omits_them_and_reads_back_empty() {
        // Documents persisted before a finding landed still load, and an
        // empty scan stays small on disk.
        let result = SyncResult::new(ScanMetadata::new("eqmain.dll"));
        let json = serde_json::to_string(&result).expect("empty sync result should serialize");
        assert!(!json.contains("\"findings\""));
        let back: SyncResult =
            serde_json::from_str(&json).expect("empty sync result should read back");
        assert!(back.is_empty());
        assert_eq!(back.metadata.binary, "eqmain.dll");
    }

    #[test]
    fn for_function_yields_only_that_function_s_findings_in_order() {
        let other = SyncFinding::Atomic(AtomicOperation {
            function: "FUN_18003e750".into(),
            operation: "__sync_fetch_and_add".into(),
            suggestion: "std::sync::atomic::AtomicU64".into(),
            confidence: Confidence::new(70),
            evidence: "__sync_fetch_and_add(&counter,1);".into(),
        });
        let result = SyncResult {
            metadata: ScanMetadata::new("eqmain.dll"),
            findings: vec![other.clone(), SyncFinding::Mutex(mutex_hint())],
        };
        let found: Vec<&SyncFinding> = result.for_function("FUN_18003e750").collect();
        assert_eq!(found, vec![&other]);
        assert!(result.for_function("FUN_180099999").next().is_none());
        assert!(!result.is_empty());
    }

    #[test]
    fn a_finding_renders_into_prompt_data_whichever_kind_it_is() {
        // The prompt conversion reaches through the union, so every kind
        // carries its label, suggestion, confidence, and evidence whole
        // into `ConcurrencyInfo`.
        let mutex = SyncFinding::Mutex(mutex_hint());
        let info = calxgloss_prompts::ConcurrencyInfo::from(&mutex);
        assert_eq!(info.function, "FUN_18003ab00");
        assert_eq!(info.kind, "mutex");
        assert_eq!(info.suggestion, "std::sync::Mutex<T>");
        assert_eq!(info.confidence, 70);
        assert_eq!(
            info.evidence,
            "EnterCriticalSection(&local_20); /* ... */ LeaveCriticalSection(&local_20);"
        );

        let atomic = SyncFinding::Atomic(atomic_operation());
        let info = calxgloss_prompts::ConcurrencyInfo::from(&atomic);
        assert_eq!(info.kind, "atomic");
        assert_eq!(info.suggestion, "std::sync::atomic::AtomicU32");
        assert_eq!(info.confidence, 70);

        let thread = SyncFinding::Thread(thread_spawn());
        let info = calxgloss_prompts::ConcurrencyInfo::from(&thread);
        assert_eq!(info.kind, "thread");
        assert_eq!(info.suggestion, "std::thread::spawn");
        assert_eq!(info.confidence, 70);
    }
}
