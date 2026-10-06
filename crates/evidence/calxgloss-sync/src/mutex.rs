//! Mutex/lock acquire/release pair tracking.
//!
//! This module provides [`MutexDetector`], which carries the acquire
//! and release names a scan reads decompiled bodies against — the
//! Win32 `EnterCriticalSection`/`LeaveCriticalSection` pair, the POSIX
//! `pthread_mutex_lock`/`pthread_mutex_unlock` pair, and the POSIX
//! reader/writer `pthread_rwlock_rdlock`/`wrlock`/`unlock` trio —
//! pairing each acquisition with its release inside a single function
//! so the prompt can suggest the Rust lock type that stands in for
//! the manual locking.
//!
//! Each acquire name is a [`MutexSignature`]: the callee spelling as
//! the decompiler writes it and the [`SyncType`] it stands for.
//! [`default_acquires`] and [`default_releases`] carry the standard
//! name sets, and [`MutexDetector::with_default_names`] builds a
//! detector that scans against them.
//!
//! [`MutexDetector::detect_pairs`] runs the reading: it walks a
//! decompiled body's direct calls in source order, binds each
//! recognized acquire to the lock object named by its first argument,
//! and closes that acquire when a recognized release names the same
//! lock object — one [`ConcurrencyHint`] per pair.

use crate::types::{ConcurrencyHint, SyncType};
use calxgloss_ghidra::DecompiledFunction;
use serde::{Deserialize, Serialize};

// ============================================================
// Acquire names
// ============================================================

/// One acquire name the detector recognizes: the callee spelling and
/// the lock family it stands for.
///
/// A signature is a name, not a shape: it only says that a call to
/// [`name`](Self::name) took a lock of [`sync_type`](Self::sync_type)
/// — `pthread_rwlock_wrlock` an exclusive reader/writer lock — while
/// where the call sits in the function and what releases it is the
/// detector's reading.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MutexSignature {
    /// The callee spelling as the decompiler writes it, e.g.
    /// `EnterCriticalSection`, `pthread_mutex_lock`.
    pub name: String,
    /// The lock family this spelling stands for.
    pub sync_type: SyncType,
}

impl MutexSignature {
    /// A signature recognizing the callee spelling `name` as an
    /// acquire of `sync_type`.
    pub fn new(name: impl Into<String>, sync_type: SyncType) -> Self {
        Self {
            name: name.into(),
            sync_type,
        }
    }
}

// ============================================================
// Detector
// ============================================================

/// Mutex/lock acquire/release pair tracking over decompiled functions.
///
/// The detector owns the name set a scan reads bodies against:
/// [`MutexSignature`] records for the acquiring side and plain callee
/// spellings for the releasing side. Both sets are configurable —
/// supply them whole through [`with_names`](Self::with_names) or grow
/// them one name at a time with [`add_acquire`](Self::add_acquire) and
/// [`add_release`](Self::add_release) — and [`acquires`](Self::acquires)
/// and [`releases`](Self::releases) report them in configuration
/// order, so two detectors built the same way scan identically and
/// results diff cleanly. The detector holds no Ghidra client of its own
/// and never writes back to the program; one detector serves an entire
/// scan and can be shared by reference across concurrent per-function
/// passes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MutexDetector {
    acquires: Vec<MutexSignature>,
    releases: Vec<String>,
}

impl MutexDetector {
    /// A detector with no names configured: every body it is handed
    /// pairs nothing until the standard sets arrive through
    /// [`with_default_names`](Self::with_default_names) or names join
    /// one at a time through [`add_acquire`](Self::add_acquire) and
    /// [`add_release`](Self::add_release).
    pub fn new() -> Self {
        Self::default()
    }

    /// A detector that scans against the standard name sets —
    /// [`default_acquires`] and [`default_releases`] — in their
    /// configuration order.
    pub fn with_default_names() -> Self {
        Self::with_names(default_acquires(), default_releases())
    }

    /// A detector that scans against exactly `acquires` and
    /// `releases`, each kept in the order it is given.
    pub fn with_names(
        acquires: impl IntoIterator<Item = MutexSignature>,
        releases: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            acquires: acquires.into_iter().collect(),
            releases: releases.into_iter().map(Into::into).collect(),
        }
    }

    /// Add one acquire name to the set this detector scans against.
    pub fn add_acquire(&mut self, acquire: MutexSignature) {
        self.acquires.push(acquire);
    }

    /// Add one release name to the set this detector scans against.
    pub fn add_release(&mut self, release: impl Into<String>) {
        self.releases.push(release.into());
    }

    /// The acquire names this detector scans against, in
    /// configuration order.
    pub fn acquires(&self) -> &[MutexSignature] {
        &self.acquires
    }

    /// The release names this detector scans against, in
    /// configuration order.
    pub fn releases(&self) -> &[String] {
        &self.releases
    }

    /// The acquire/release pairs one function's body carries.
    ///
    /// The reading walks the body's direct calls in source order —
    /// outside string literals, whole names only — and classifies each
    /// against the configured sets. An acquire counts only where its
    /// first argument names one plain lock object — a variable, seen
    /// through any cast and a leading `&` the decompiler writes for
    /// the lock's address (`EnterCriticalSection(&local_20);`); an
    /// acquire whose first argument is something else — a field, an
    /// indexed element, a global — locks something the pairing cannot
    /// key on. A release closes the most recent still-open acquire of
    /// the lock object it names — so where a body locks one object
    /// twice before one release, the release closes the second
    /// acquisition and the first stands unpaired — and an acquire
    /// with no release naming its lock object in this function is
    /// reported by nothing: whether the lock is held across a return
    /// is a cross-function question, outside this pairing.
    ///
    /// Each pair becomes one [`ConcurrencyHint`] naming the lock's
    /// family and suggesting the Rust synchronization type that family
    /// reads as, at [`PAIR_CONFIDENCE`], with the acquire line and
    /// the release line joined as the evidence. Hints come back in
    /// acquire order, so two scans of one body diff cleanly.
    pub fn detect_pairs(&self, func: &DecompiledFunction) -> Vec<ConcurrencyHint> {
        let mut open: Vec<OpenAcquire> = Vec::new();
        let mut pairs: Vec<(usize, ConcurrencyHint)> = Vec::new();
        for call in direct_calls(&func.body) {
            if let Some(signature) = self.acquires.iter().find(|a| a.name == call.callee)
                // An acquire locking something other than one plain
                // variable names no lock object this pairing keys on.
                && let Some(lock) = call.args.first().and_then(|arg| lock_object(arg))
            {
                open.push(OpenAcquire {
                    lock,
                    name: signature.name.clone(),
                    sync_type: signature.sync_type,
                    offset: call.offset,
                    line: line_at(&func.body, call.offset),
                });
            } else if self.releases.iter().any(|r| r == call.callee)
                && let Some(lock) = call.args.first().and_then(|arg| lock_object(arg))
                && let Some(at) = open.iter().rposition(|o| o.lock == lock)
            {
                let acquire = open.remove(at);
                pairs.push((
                    acquire.offset,
                    ConcurrencyHint {
                        function: func.name.clone(),
                        sync_type: acquire.sync_type,
                        acquire: acquire.name,
                        release: call.callee.to_string(),
                        suggestion: suggestion_for(acquire.sync_type).to_string(),
                        confidence: PAIR_CONFIDENCE.into(),
                        evidence: format!("{} {}", acquire.line, line_at(&func.body, call.offset)),
                    },
                ));
            }
        }
        pairs.sort_by_key(|(offset, _)| *offset);
        pairs.into_iter().map(|(_, hint)| hint).collect()
    }
}

// ============================================================
// The pairing reading
// ============================================================

/// Confidence of a pairing read from an acquire and a release of the
/// same lock object in one body: both sides are explicit calls to
/// recognized names, and the lock object the acquire passes is the
/// lock object the release names — but the tie between them is the
/// decompiler's naming, not resolved data flow, and a branch could
/// leave either side unreached.
const PAIR_CONFIDENCE: u8 = 70;

/// The Rust synchronization type one lock family reads as.
///
/// A Win32 critical section maps to the standard library's mutex,
/// poisoning and all; a POSIX mutex maps to `parking_lot`'s, because
/// pthread locking has no poisoning to translate and `std::sync`'s
/// would invent a failure mode the original never had; a POSIX
/// reader/writer lock maps to the standard library's reader/writer
/// lock.
fn suggestion_for(sync_type: SyncType) -> &'static str {
    match sync_type {
        SyncType::StdMutex => "std::sync::Mutex<T>",
        SyncType::ParkingMutex => "parking_lot::Mutex<T>",
        SyncType::RwLock => "std::sync::RwLock<T>",
    }
}

/// An acquire still waiting for its release while the body is walked:
/// the lock object it names, the acquire spelling behind it, the
/// family that spelling stands for, and where and on which line the
/// acquire sits.
struct OpenAcquire {
    lock: String,
    name: String,
    sync_type: SyncType,
    offset: usize,
    line: String,
}

/// The control-flow keywords Ghidra writes with a parenthesised
/// operand; none of them is a callee.
const NON_CALL_KEYWORDS: [&str; 7] = ["if", "while", "for", "switch", "case", "return", "sizeof"];

/// A direct call found in a body: the callee name, the text of each
/// top-level argument, and the byte offset of the callee.
struct CallSite<'a> {
    callee: &'a str,
    args: Vec<&'a str>,
    offset: usize,
}

/// Every direct call `name(args)` in the body whose callee is a plain
/// identifier, scanned outside string literals so a stray `(` in a
/// format string cannot be read as a call. A name preceded by an
/// identifier byte is the tail of a longer identifier, and one
/// preceded by a `.` or a `>` is a member access through an object;
/// neither is a plain call — every lock spelling this detector reads
/// is a plain C function name. A call whose `(` never closes — a
/// truncated decompile — yields nothing, and nested calls are each
/// visited.
fn direct_calls(body: &str) -> Vec<CallSite<'_>> {
    let bytes = body.as_bytes();
    let mut calls = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => i = skip_string(bytes, i + 1),
            b if b.is_ascii_alphabetic() || b == b'_' => {
                if i > 0
                    && (is_ident_byte(bytes[i - 1]) || bytes[i - 1] == b'.' || bytes[i - 1] == b'>')
                {
                    i += 1;
                    continue;
                }
                let mut j = i;
                while j < bytes.len() && is_ident_byte(bytes[j]) {
                    j += 1;
                }
                let open = skip_ws(bytes, j);
                if bytes.get(open) == Some(&b'(')
                    && !NON_CALL_KEYWORDS.contains(&&body[i..j])
                    && let Some(close) = closing_paren(body, open)
                {
                    calls.push(CallSite {
                        callee: &body[i..j],
                        args: split_arguments(body, open, close),
                        offset: i,
                    });
                }
                i = j;
            }
            _ => i += 1,
        }
    }
    calls
}

/// The text of each top-level argument of the call whose `(` sits at
/// `open` and whose `)` sits at `close`, in order. A call with no
/// arguments yields none, and commas nested inside a parenthesised or
/// bracketed argument — a nested call, an array index — belong to that
/// argument rather than splitting it.
fn split_arguments(body: &str, open: usize, close: usize) -> Vec<&str> {
    let bytes = body.as_bytes();
    let mut args = Vec::new();
    let mut depth = 0usize;
    let mut start = open + 1;
    let mut i = start;
    while i < close {
        match bytes[i] {
            b'"' => i = skip_string(bytes, i + 1),
            b'(' | b'[' => {
                depth += 1;
                i += 1;
            }
            b')' | b']' => {
                depth -= 1;
                i += 1;
            }
            b',' if depth == 0 => {
                args.push(body[start..i].trim());
                start = i + 1;
                i += 1;
            }
            _ => i += 1,
        }
    }
    let last = body[start..close].trim();
    if !last.is_empty() {
        args.push(last);
    }
    args
}

/// The index of `)` matching the `(` at `open`, skipping string literals.
fn closing_paren(body: &str, open: usize) -> Option<usize> {
    let bytes = body.as_bytes();
    let mut depth = 0usize;
    let mut i = open;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => i = skip_string(bytes, i + 1),
            b'(' => {
                depth += 1;
                i += 1;
            }
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
                i += 1;
            }
            _ => i += 1,
        }
    }
    None
}

/// The index just past the string literal whose opening `"` sits at `open`.
fn skip_string(bytes: &[u8], mut i: usize) -> usize {
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2,
            b'"' => return i + 1,
            _ => i += 1,
        }
    }
    bytes.len()
}

fn skip_ws(bytes: &[u8], mut i: usize) -> usize {
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    i
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// The trimmed source line containing `offset`.
fn line_at(body: &str, offset: usize) -> String {
    let line = body[..offset].matches('\n').count();
    body.lines().nth(line).unwrap_or("").trim().to_string()
}

/// The lock object a call's first argument names: a plain variable,
/// seen through any cast and a leading `&` — the decompiler writes
/// `EnterCriticalSection(&local_20)` and
/// `pthread_mutex_lock((pthread_mutex_t *)param_1)` for the same
/// shape of lock. Anything else — a field, an indexed element, a
/// global address — names no local lock object the pairing can key
/// on.
fn lock_object(arg: &str) -> Option<String> {
    let stripped = strip_casts(arg);
    let name = stripped.strip_prefix('&').unwrap_or(&stripped);
    plain_variable(name).map(str::to_string)
}

/// The argument text when it is one plain variable name — the
/// spelling a lock call names its lock object by. Anything else — an
/// offset into the object, an indexed element, a literal — names no
/// variable the pairing can key on.
fn plain_variable(arg: &str) -> Option<&str> {
    let trimmed = arg.trim();
    let mut bytes = trimmed.bytes();
    let first = bytes.next()?;
    if !(first.is_ascii_alphabetic() || first == b'_') || !bytes.all(is_ident_byte) {
        return None;
    }
    Some(trimmed)
}

/// A call argument with Ghidra casts stripped: the decompiler writes
/// `pthread_mutex_lock((pthread_mutex_t *)param_1)` when the
/// argument's applied type differs from the callee's parameter, and
/// the value behind the cast is the lock the call names.
fn strip_casts(arg: &str) -> String {
    let bytes = arg.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'('
            && let Some(close) = cast_group(bytes, i)
        {
            i = skip_ws(bytes, close + 1);
            while bytes.get(i) == Some(&b'*') {
                i = skip_ws(bytes, i + 1);
            }
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).trim().to_string()
}

/// The index of `)` when the `(` at `open` opens a Ghidra type cast —
/// a group holding only type words and stars, like `(void *)` or
/// `(pthread_mutex_t *)` — and `None` when it opens a call or a
/// grouped expression instead.
fn cast_group(bytes: &[u8], open: usize) -> Option<usize> {
    let mut i = open + 1;
    let mut saw_word = false;
    loop {
        i = skip_ws(bytes, i);
        let b = *bytes.get(i)?;
        match b {
            b'*' => i += 1,
            b')' => return saw_word.then_some(i),
            b if b.is_ascii_alphabetic() || b == b'_' => {
                let start = i;
                while i < bytes.len() && is_ident_byte(bytes[i]) {
                    i += 1;
                }
                let word = String::from_utf8_lossy(&bytes[start..i]).to_lowercase();
                if !is_type_word(&word) {
                    return None;
                }
                saw_word = true;
            }
            _ => return None,
        }
    }
}

/// The type words a Ghidra cast may spell, matching the decompiler's
/// vocabulary the other detectors' scans strip, plus the lock struct
/// names the decompiler writes when the program carries pthread debug
/// info.
fn is_type_word(word: &str) -> bool {
    matches!(
        word,
        "undefined"
            | "undefined1"
            | "undefined2"
            | "undefined3"
            | "undefined4"
            | "undefined5"
            | "undefined6"
            | "undefined7"
            | "undefined8"
            | "ushort"
            | "uint"
            | "ulong"
            | "ulonglong"
            | "longlong"
            | "short"
            | "uchar"
            | "char"
            | "byte"
            | "word"
            | "dword"
            | "qword"
            | "void"
            | "code"
            | "size_t"
            | "wchar_t"
            | "bool"
            | "int"
            | "float"
            | "double"
            | "long"
            | "pthread_mutex_t"
            | "pthread_rwlock_t"
            | "pthread_mutexattr_t"
            | "pthread_rwlockattr_t"
    )
}

// ============================================================
// The standard name sets
// ============================================================

/// The standard acquire names: the spellings a scan recognizes as
/// lock acquisitions out of the box — the Win32 critical section
/// enter, the POSIX mutex lock, and both POSIX reader/writer lock
/// acquisitions, which share one release spelling and one Rust
/// reader/writer lock behind them. Each name carries the family it
/// stands for, so a recognized acquire knows which Rust
/// synchronization type the pairing should suggest.
pub fn default_acquires() -> Vec<MutexSignature> {
    vec![
        MutexSignature::new("EnterCriticalSection", SyncType::StdMutex),
        MutexSignature::new("pthread_mutex_lock", SyncType::ParkingMutex),
        MutexSignature::new("pthread_rwlock_rdlock", SyncType::RwLock),
        MutexSignature::new("pthread_rwlock_wrlock", SyncType::RwLock),
    ]
}

/// The standard release names: the spellings a scan recognizes as
/// lock releases — `LeaveCriticalSection`, closing the Win32 critical
/// section, `pthread_mutex_unlock`, closing the POSIX mutex, and
/// `pthread_rwlock_unlock`, closing either POSIX reader/writer
/// acquisition.
pub fn default_releases() -> Vec<String> {
    vec![
        "LeaveCriticalSection".into(),
        "pthread_mutex_unlock".into(),
        "pthread_rwlock_unlock".into(),
    ]
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_detector_starts_with_no_names() {
        // Construction is free: empty, equal however it is made, and
        // clones interchangeable.
        let detector = MutexDetector::new();
        assert!(detector.acquires().is_empty());
        assert!(detector.releases().is_empty());
        assert_eq!(detector, MutexDetector::default());
        assert_eq!(detector.clone(), detector);
    }

    #[test]
    fn a_detector_keeps_the_names_it_is_configured_with() {
        let detector = MutexDetector::with_names(
            [
                MutexSignature::new("EnterCriticalSection", SyncType::StdMutex),
                MutexSignature::new("pthread_mutex_lock", SyncType::ParkingMutex),
            ],
            ["LeaveCriticalSection", "pthread_mutex_unlock"],
        );
        // Configuration order is scan order: two detectors built the
        // same way see the same names in the same order.
        assert_eq!(detector.acquires().len(), 2);
        assert_eq!(detector.acquires()[0].name, "EnterCriticalSection");
        assert_eq!(detector.acquires()[1].sync_type, SyncType::ParkingMutex);
        assert_eq!(
            detector.releases(),
            ["LeaveCriticalSection", "pthread_mutex_unlock"]
        );
    }

    #[test]
    fn added_names_join_their_sets_in_order() {
        let mut detector = MutexDetector::new();
        detector.add_acquire(MutexSignature::new(
            "EnterCriticalSection",
            SyncType::StdMutex,
        ));
        detector.add_acquire(MutexSignature::new(
            "pthread_mutex_lock",
            SyncType::ParkingMutex,
        ));
        detector.add_release("LeaveCriticalSection");
        detector.add_release("pthread_mutex_unlock");
        let names: Vec<&str> = detector
            .acquires()
            .iter()
            .map(|a| a.name.as_str())
            .collect();
        assert_eq!(names, ["EnterCriticalSection", "pthread_mutex_lock"]);
        assert_eq!(
            detector.releases(),
            ["LeaveCriticalSection", "pthread_mutex_unlock"]
        );
    }

    #[test]
    fn a_detector_can_be_shared_across_scans() {
        // One detector is driven concurrently over a program's
        // functions, so sharing one by reference across tasks must
        // stay sound.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<MutexDetector>();
    }

    #[test]
    fn a_mutex_signature_serde_round_trips() {
        let signature = MutexSignature::new("pthread_rwlock_wrlock", SyncType::RwLock);
        let json = serde_json::to_string(&signature).unwrap();
        assert!(json.contains("\"sync_type\":\"rw_lock\""));
        let back: MutexSignature = serde_json::from_str(&json).unwrap();
        assert_eq!(back, signature);
    }

    #[test]
    fn the_standard_acquires_name_the_three_lock_families() {
        let acquires = default_acquires();
        let named: Vec<(&str, SyncType)> = acquires
            .iter()
            .map(|a| (a.name.as_str(), a.sync_type))
            .collect();
        assert_eq!(
            named,
            [
                ("EnterCriticalSection", SyncType::StdMutex),
                ("pthread_mutex_lock", SyncType::ParkingMutex),
                ("pthread_rwlock_rdlock", SyncType::RwLock),
                ("pthread_rwlock_wrlock", SyncType::RwLock),
            ]
        );
    }

    #[test]
    fn the_standard_releases_name_the_three_release_spellings() {
        assert_eq!(
            default_releases(),
            [
                "LeaveCriticalSection",
                "pthread_mutex_unlock",
                "pthread_rwlock_unlock",
            ]
        );
    }

    #[test]
    fn a_detector_built_with_the_standard_sets_carries_them() {
        let detector = MutexDetector::with_default_names();
        assert_eq!(detector.acquires(), default_acquires());
        assert_eq!(detector.releases(), default_releases());
    }

    // ------------------------------------------------------------
    // Pairing
    // ------------------------------------------------------------

    fn function(body: &str) -> DecompiledFunction {
        DecompiledFunction {
            name: "FUN_18003ab00".into(),
            signature: "undefined FUN_18003ab00(void)".into(),
            body: body.into(),
        }
    }

    fn pairs(body: &str) -> Vec<ConcurrencyHint> {
        MutexDetector::with_default_names().detect_pairs(&function(body))
    }

    #[test]
    fn a_critical_section_pair_is_detected() {
        let hints = pairs(
            "\
undefined FUN_18003ab00(void) {
  EnterCriticalSection(&local_20);
  *(int *)local_18 = 5;
  LeaveCriticalSection(&local_20);
  return;
}",
        );
        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0].function, "FUN_18003ab00");
        assert_eq!(hints[0].sync_type, SyncType::StdMutex);
        assert_eq!(hints[0].acquire, "EnterCriticalSection");
        assert_eq!(hints[0].release, "LeaveCriticalSection");
        // A Win32 critical section reads as the standard library's
        // poisoned mutex.
        assert_eq!(hints[0].suggestion, "std::sync::Mutex<T>");
        assert_eq!(hints[0].confidence, PAIR_CONFIDENCE);
        // The evidence carries both sides of the pairing.
        assert_eq!(
            hints[0].evidence,
            "EnterCriticalSection(&local_20); LeaveCriticalSection(&local_20);"
        );
    }

    #[test]
    fn a_pthread_mutex_pair_reads_as_an_unpoisoned_mutex() {
        // pthread locking has no poisoning; suggesting `std::sync`
        // would invent a failure mode the original never had.
        let hints = pairs(
            "\
  pthread_mutex_lock(&local_20);
  iVar1 = *(int *)local_18;
  pthread_mutex_unlock(&local_20);",
        );
        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0].sync_type, SyncType::ParkingMutex);
        assert_eq!(hints[0].suggestion, "parking_lot::Mutex<T>");
    }

    #[test]
    fn a_reader_and_a_writer_lock_each_pair_with_the_shared_unlock() {
        let hints = pairs(
            "\
  pthread_rwlock_rdlock(&local_40);
  iVar1 = *(int *)local_18;
  pthread_rwlock_unlock(&local_40);
  pthread_rwlock_wrlock(&local_40);
  *(int *)local_18 = 2;
  pthread_rwlock_unlock(&local_40);",
        );
        assert_eq!(hints.len(), 2);
        assert_eq!(hints[0].sync_type, SyncType::RwLock);
        assert_eq!(hints[1].sync_type, SyncType::RwLock);
        assert_eq!(hints[0].acquire, "pthread_rwlock_rdlock");
        assert_eq!(hints[1].acquire, "pthread_rwlock_wrlock");
        assert_eq!(hints[0].suggestion, "std::sync::RwLock<T>");
    }

    #[test]
    fn a_cast_over_the_lock_argument_is_seen_through() {
        let hints = pairs(
            "\
  pthread_mutex_lock((pthread_mutex_t *)param_1);
  pthread_mutex_unlock((pthread_mutex_t *)param_1);",
        );
        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0].sync_type, SyncType::ParkingMutex);
    }

    #[test]
    fn a_lock_argument_without_a_leading_address_of_still_pairs() {
        // Where the variable already holds the lock's address, the
        // decompiler passes it plain.
        let hints = pairs(
            "\
  EnterCriticalSection(local_8);
  LeaveCriticalSection(local_8);",
        );
        assert_eq!(hints.len(), 1);
    }

    #[test]
    fn an_acquire_never_released_is_not_reported() {
        // Whether the lock is held across a return is a cross-function
        // question; this pairing stays quiet on it.
        assert!(
            pairs(
                "\
  EnterCriticalSection(&local_20);
  return;"
            )
            .is_empty()
        );
    }

    #[test]
    fn a_release_before_the_acquire_pairs_nothing() {
        // The release closes an earlier acquisition, not the one the
        // body makes after it.
        assert!(
            pairs(
                "\
  LeaveCriticalSection(&local_20);
  EnterCriticalSection(&local_20);"
            )
            .is_empty()
        );
    }

    #[test]
    fn the_latest_acquire_of_a_lock_object_pairs_with_the_release() {
        // Two acquisitions under one name, one release: the release
        // closes the second, and the first stands unpaired.
        let hints = pairs(
            "\
  EnterCriticalSection(&local_20);
  EnterCriticalSection(&local_20);
  LeaveCriticalSection(&local_20);",
        );
        assert_eq!(hints.len(), 1);
        assert_eq!(
            hints[0].evidence,
            "EnterCriticalSection(&local_20); LeaveCriticalSection(&local_20);"
        );
    }

    #[test]
    fn independent_lock_objects_each_pair_in_acquire_order() {
        // Releases close out of nesting order, but the hints come
        // back in acquire order so two scans diff cleanly.
        let hints = pairs(
            "\
  EnterCriticalSection(&local_20);
  pthread_mutex_lock(&local_40);
  pthread_mutex_unlock(&local_40);
  LeaveCriticalSection(&local_20);",
        );
        assert_eq!(hints.len(), 2);
        assert_eq!(hints[0].sync_type, SyncType::StdMutex);
        assert_eq!(hints[1].sync_type, SyncType::ParkingMutex);
    }

    #[test]
    fn a_pair_inside_a_loop_body_is_detected() {
        let hints = pairs(
            "\
  while (iVar1 != 0) {
    pthread_mutex_lock(&local_20);
    iVar2 = iVar2 + 1;
    pthread_mutex_unlock(&local_20);
  }",
        );
        assert_eq!(hints.len(), 1);
    }

    #[test]
    fn a_name_spelled_inside_a_string_literal_invents_no_pair() {
        assert!(pairs("  printf(\"pthread_mutex_lock then unlock\");").is_empty());
    }

    #[test]
    fn a_longer_or_qualified_name_matches_no_configured_name() {
        // Whole names only: `pthread_mutex_trylock` is a different
        // callee, and a member access through an object is no plain
        // call.
        assert!(
            pairs(
                "\
  iVar1 = pthread_mutex_trylock(&local_20);
  x.LeaveCriticalSection(&local_20);
  LeaveCriticalSection(&local_20);"
            )
            .is_empty()
        );
    }

    #[test]
    fn an_acquire_naming_something_other_than_a_variable_pairs_nothing() {
        // A field of a struct names no local lock object the pairing
        // can key on.
        assert!(
            pairs(
                "\
  EnterCriticalSection(&(local_10.field_0));
  LeaveCriticalSection(&(local_10.field_0));"
            )
            .is_empty()
        );
    }

    #[test]
    fn a_truncated_body_pairs_nothing() {
        assert!(pairs("  EnterCriticalSection(&local_20;").is_empty());
    }

    #[test]
    fn nested_calls_do_not_disturb_the_pairing() {
        let hints = pairs(
            "\
  EnterCriticalSection(&local_20);
  puts(get_name(local_18));
  LeaveCriticalSection(&local_20);",
        );
        assert_eq!(hints.len(), 1);
    }

    #[test]
    fn a_detector_with_no_names_pairs_nothing() {
        let detector = MutexDetector::new();
        let hints = detector.detect_pairs(&function(
            "\
  EnterCriticalSection(&local_20);
  LeaveCriticalSection(&local_20);",
        ));
        assert!(hints.is_empty());
    }

    #[test]
    fn custom_names_pair_like_the_standard_ones() {
        let mut detector = MutexDetector::new();
        detector.add_acquire(MutexSignature::new("my_lock", SyncType::ParkingMutex));
        detector.add_release("my_unlock");
        let hints = detector.detect_pairs(&function(
            "\
  my_lock(&local_20);
  my_unlock(&local_20);",
        ));
        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0].sync_type, SyncType::ParkingMutex);
    }
}
