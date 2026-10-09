//! Thread spawn and join pattern detection.
//!
//! This module provides [`ThreadingDetector`], which carries the
//! spawn and join names a scan reads decompiled bodies against —
//! `CreateThread` and `std::thread::spawn` waited on by
//! `WaitForSingleObject` and the demangled `std::thread::JoinHandle::join`,
//! `pthread_create` joined by `pthread_join` —
//! and reads each spawn site as the Rust spawning pattern standing in
//! for it.
//!
//! Each spawn name is a [`ThreadSpawnSignature`]: the callee spelling
//! as the decompiler writes it and the [`binding`](
//! ThreadSpawnSignature::binding) that names the thread handle —
//! whether the decompiler stores the spawn's result into a variable
//! or the body passes the handle in as the first argument, the
//! `pthread_create` spelling. [`default_spawns`] and [`default_joins`]
//! carry the standard name sets, and [`ThreadingDetector::
//! with_default_names`] builds a detector that scans against them.
//!
//! [`ThreadingDetector::detect`] runs the reading: it walks a
//! decompiled body's direct calls in source order, binds each
//! recognized spawn to its thread handle, and marks the spawn joined
//! when a recognized join names the same handle — one [`ThreadSpawn`]
//! per spawn site, joined or not.

use crate::types::ThreadSpawn;
use calxgloss_ghidra::DecompiledFunction;
use serde::{Deserialize, Serialize};

use calxgloss_types::{
    CallSite, NON_CALL_KEYWORDS, NameContinuation, ScanOptions, call_sites, is_ident_byte, line_at,
    strip_casts,
};

/// The scan: `::`-qualified demangled names (`std::thread::spawn`) stay
/// whole, member accesses are skipped, and C keywords are not calls.
const CALL_SCAN: ScanOptions = ScanOptions {
    continuation: NameContinuation::ColonColon,
    reject_preceding: b".>:",
    skip_keywords: &NON_CALL_KEYWORDS,
};

/// Every direct call `name(args)` in the body — the shared pseudo-C
/// scan configured by [`CALL_SCAN`].
fn direct_calls(body: &str) -> Vec<CallSite<'_>> {
    call_sites(body, &CALL_SCAN)
}

// ============================================================
// Spawn names
// ============================================================

/// Where a spawn spelling keeps the thread handle the join ties on.
///
/// The binding says which side of the call carries the handle: a
/// Win32 `CreateThread` returns its thread handle, which the
/// decompiler stores into a variable the later wait names, while
/// `pthread_create` takes the handle through its first argument, the
/// address of a local the join reads back. A join only ever ties to a
/// spawn through the handle, so the binding decides which spelling of
/// the spawn the pairing can key on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpawnBinding {
    /// The spawn returns the handle, and the decompiler's assignment
    /// stores it into a variable.
    ReturnValue,
    /// The body passes the handle as the spawn's first argument,
    /// spelled as the address of a local.
    FirstArg,
}

calxgloss_types::display_serde_label!(SpawnBinding {
    ReturnValue => "return_value",
    FirstArg => "first_arg",
});

/// One spawn name the detector recognizes: the callee spelling and
/// the binding that names its thread handle.
///
/// A signature is a name, not a shape: it only says that a call to
/// [`name`](Self::name) started a thread whose handle the body keeps
/// through [`binding`](Self::binding) — `CreateThread` returning it,
/// `pthread_create` taking its address — while where the call sits in
/// the function and whether the body waits for the thread is the
/// detector's reading.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreadSpawnSignature {
    /// The callee spelling as the decompiler writes it, e.g.
    /// `CreateThread`, `pthread_create`.
    pub name: String,
    /// Where this spelling keeps the thread handle.
    pub binding: SpawnBinding,
}

impl ThreadSpawnSignature {
    /// A signature recognizing the callee spelling `name` as a thread
    /// spawn whose handle the body keeps through `binding`.
    pub fn new(name: impl Into<String>, binding: SpawnBinding) -> Self {
        Self {
            name: name.into(),
            binding,
        }
    }
}

// ============================================================
// Detector
// ============================================================

/// Thread spawn and join pattern detection over decompiled functions.
///
/// The detector owns the name sets a scan reads bodies against:
/// [`ThreadSpawnSignature`] records for the spawning side and plain
/// callee spellings for the joining side. Both sets are configurable —
/// supply them whole through [`with_names`](Self::with_names) or grow
/// them one name at a time with [`add_spawn`](Self::add_spawn) and
/// [`add_join`](Self::add_join) — and [`spawns`](Self::spawns) and
/// [`joins`](Self::joins) report them in configuration order, so two
/// detectors built the same way scan identically and results diff
/// cleanly. The detector holds no Ghidra client of its own and never
/// writes back to the program; one detector serves an entire scan and
/// can be shared by reference across concurrent per-function passes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ThreadingDetector {
    spawns: Vec<ThreadSpawnSignature>,
    joins: Vec<String>,
}

impl ThreadingDetector {
    /// A detector with no names configured: every body it is handed
    /// reports nothing until the standard sets arrive through
    /// [`with_default_names`](Self::with_default_names) or names join
    /// one at a time through [`add_spawn`](Self::add_spawn) and
    /// [`add_join`](Self::add_join).
    pub fn new() -> Self {
        Self::default()
    }

    /// A detector that scans against the standard name sets —
    /// [`default_spawns`] and [`default_joins`] — in their
    /// configuration order.
    pub fn with_default_names() -> Self {
        Self::with_names(default_spawns(), default_joins())
    }

    /// A detector that scans against exactly `spawns` and `joins`,
    /// each kept in the order it is given.
    pub fn with_names(
        spawns: impl IntoIterator<Item = ThreadSpawnSignature>,
        joins: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            spawns: spawns.into_iter().collect(),
            joins: joins.into_iter().map(Into::into).collect(),
        }
    }

    /// Add one spawn name to the set this detector scans against.
    pub fn add_spawn(&mut self, spawn: ThreadSpawnSignature) {
        self.spawns.push(spawn);
    }

    /// Add one join name to the set this detector scans against.
    pub fn add_join(&mut self, join: impl Into<String>) {
        self.joins.push(join.into());
    }

    /// The spawn names this detector scans against, in configuration
    /// order.
    pub fn spawns(&self) -> &[ThreadSpawnSignature] {
        &self.spawns
    }

    /// The join names this detector scans against, in configuration
    /// order.
    pub fn joins(&self) -> &[String] {
        &self.joins
    }

    /// The thread spawn sites one function's body carries.
    ///
    /// The reading walks the body's direct calls in source order —
    /// outside string literals, whole names only — and classifies
    /// each against the configured sets. A spawn binds its thread
    /// handle through its signature's [`SpawnBinding`]: the variable
    /// the decompiler stores the result into, or the plain variable
    /// its first argument names, seen through any cast and a leading
    /// `&`. A spawn whose handle the body keeps nowhere the pairing
    /// can key on is still a spawn — just one no join can tie to. A
    /// join counts only where its first argument names one plain
    /// variable, and it ties to the most recent still-unjoined spawn
    /// of the handle it names.
    ///
    /// Each spawn becomes one [`ThreadSpawn`]: joined spawns suggest
    /// [`JOINED_SUGGESTION`] at [`JOINED_CONFIDENCE`] — the body
    /// waits for the thread, which is what a `JoinHandle` stands in
    /// for — and unjoined ones [`UNJOINED_SUGGESTION`] at
    /// [`UNJOINED_CONFIDENCE`], the fire-and-forget shape a detached
    /// thread reads as. The spawn line, and the join line when there
    /// is one, are joined as the evidence. Findings come back in
    /// spawn order, so two scans of one body diff cleanly.
    pub fn detect(&self, func: &DecompiledFunction) -> Vec<ThreadSpawn> {
        let mut spawns: Vec<OpenSpawn> = Vec::new();
        for call in direct_calls(&func.body) {
            if let Some(signature) = self.spawns.iter().find(|s| s.name == call.callee) {
                let handle = match signature.binding {
                    SpawnBinding::ReturnValue => assigned_variable(&func.body, call.offset),
                    SpawnBinding::FirstArg => call.args.first().and_then(|arg| lock_object(arg)),
                };
                spawns.push(OpenSpawn {
                    handle,
                    name: signature.name.clone(),
                    line: line_at(&func.body, call.offset),
                    joined: None,
                });
            } else if self.joins.iter().any(|j| j == call.callee)
                && let Some(handle) = call.args.first().and_then(|arg| lock_object(arg))
                && let Some(at) = spawns.iter().rposition(|s| {
                    s.joined.is_none() && s.handle.as_deref() == Some(handle.as_str())
                })
            {
                spawns[at].joined = Some(JoinRecord {
                    name: call.callee.to_string(),
                    line: line_at(&func.body, call.offset),
                });
            }
        }
        spawns
            .into_iter()
            .map(|spawn| {
                let evidence = match &spawn.joined {
                    Some(join) => format!("{} {}", spawn.line, join.line),
                    None => spawn.line,
                };
                let (join, suggestion, confidence) = match spawn.joined {
                    Some(join) => (Some(join.name), JOINED_SUGGESTION, JOINED_CONFIDENCE),
                    None => (None, UNJOINED_SUGGESTION, UNJOINED_CONFIDENCE),
                };
                ThreadSpawn {
                    function: func.name.clone(),
                    spawn: spawn.name,
                    join,
                    suggestion: suggestion.to_string(),
                    confidence: confidence.into(),
                    evidence,
                }
            })
            .collect()
    }
}

// ============================================================
// The reading
// ============================================================

/// Confidence of a spawn read as joined: the spawn and the wait are
/// both explicit calls to recognized names, and the handle the spawn
/// keeps is the handle the wait names — but the tie between them is
/// the decompiler's naming, not resolved data flow.
const JOINED_CONFIDENCE: u8 = 70;

/// Confidence of a spawn read as unjoined: the spawn is explicit, but
/// the reading rests on an absence — no recognized wait names the
/// handle in this function — and the thread could be waited on from
/// elsewhere, or its handle handed off.
const UNJOINED_CONFIDENCE: u8 = 60;

/// The Rust spawning pattern a joined spawn reads as: the body waits
/// for the thread to finish, which is exactly the `JoinHandle` a
/// scoped thread keeps.
const JOINED_SUGGESTION: &str = "std::thread::spawn";

/// The Rust spawning pattern an unjoined spawn reads as: the body
/// starts the thread and never waits, the fire-and-forget shape a
/// runtime task stands in for.
const UNJOINED_SUGGESTION: &str = "tokio::spawn";

/// A spawn the body has waited on: the join spelling and its line.
struct JoinRecord {
    name: String,
    line: String,
}

/// A spawn site while the body is walked: the thread handle the body
/// keeps for it, the spawn spelling behind it, the line it sits on,
/// and the join that has tied to it, if any.
struct OpenSpawn {
    handle: Option<String>,
    name: String,
    line: String,
    joined: Option<JoinRecord>,
}
/// The variable a call's result is stored into, read from the call's
/// own line: walking left from the callee to the `=` that assigns,
/// the plain identifier sitting left of that `=`. A `=` that is part
/// of a comparison (`==`, `!=`, `<=`, `>=`) or a compound assignment
/// (`+=` and friends) assigns no result, and a target that is not a
/// plain variable — a dereference, an indexed element, a field —
/// stores the handle somewhere the pairing cannot key on, so neither
/// binds anything.
fn assigned_variable(body: &str, callee_offset: usize) -> Option<String> {
    let line_start = body[..callee_offset]
        .rfind('\n')
        .map(|p| p + 1)
        .unwrap_or(0);
    let line_end = body[callee_offset..]
        .find('\n')
        .map(|p| callee_offset + p)
        .unwrap_or(body.len());
    let line = &body[line_start..line_end];
    let bytes = line.as_bytes();
    let col = callee_offset - line_start;
    let mut k = col;
    let eq = loop {
        if k == 0 {
            return None;
        }
        k -= 1;
        if bytes[k] == b'=' {
            if k == 0
                || matches!(
                    bytes[k - 1],
                    b'=' | b'!'
                        | b'<'
                        | b'>'
                        | b'+'
                        | b'-'
                        | b'*'
                        | b'/'
                        | b'%'
                        | b'&'
                        | b'|'
                        | b'^'
                )
            {
                return None;
            }
            break k;
        }
    };
    let mut end = eq;
    while end > 0 && bytes[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    let mut start = end;
    while start > 0 && is_ident_byte(bytes[start - 1]) {
        start -= 1;
    }
    if start == end {
        return None;
    }
    if start > 0 && matches!(bytes[start - 1], b'*' | b'&' | b'.' | b')' | b']') {
        return None;
    }
    Some(line[start..end].to_string())
}

/// The handle a call's first argument names: a plain variable, seen
/// through any cast and a leading `&` — the decompiler writes
/// `pthread_create(&local_18,...)` for the handle's address and
/// `pthread_join(local_18,...)` for the handle itself. Anything else
/// names no local handle the pairing can key on.
fn lock_object(arg: &str) -> Option<String> {
    let stripped = strip_casts(arg, is_type_word);
    let name = stripped.strip_prefix('&').unwrap_or(&stripped);
    plain_variable(name).map(str::to_string)
}

/// The argument text when it is one plain variable name. Anything
/// else — an offset, an indexed element, a literal — names no
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
/// The type words a Ghidra cast may spell, matching the decompiler's
/// vocabulary the other detectors' scans strip, plus the thread
/// handle names the decompiler writes when the program carries
/// pthread debug info.
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
            | "pthread_t"
            | "pthread_attr_t"
            | "HANDLE"
    )
}

// ============================================================
// The standard name sets
// ============================================================

/// The standard spawn names: the spellings a scan recognizes as
/// thread spawns out of the box — the Win32 `CreateThread`, which
/// returns its thread handle, the POSIX `pthread_create`, which
/// takes the handle through its first argument, and the demangled
/// Rust stdlib `std::thread::spawn`, which returns its handle. Each
/// name carries the binding that names the handle, so a recognized
/// spawn knows which spelling the join pairing keys on.
pub fn default_spawns() -> Vec<ThreadSpawnSignature> {
    vec![
        ThreadSpawnSignature::new("CreateThread", SpawnBinding::ReturnValue),
        ThreadSpawnSignature::new("pthread_create", SpawnBinding::FirstArg),
        ThreadSpawnSignature::new("std::thread::spawn", SpawnBinding::ReturnValue),
    ]
}

/// The standard join names: the spellings a scan recognizes as waits
/// for a spawned thread — `WaitForSingleObject`, which waits on the
/// Win32 thread handle, `pthread_join`, which joins the POSIX thread,
/// and the demangled `std::thread::JoinHandle::join`, which joins a
/// Rust stdlib spawn the way the decompiler writes it. All three name
/// the handle through their first argument.
pub fn default_joins() -> Vec<String> {
    vec![
        "WaitForSingleObject".into(),
        "pthread_join".into(),
        "std::thread::JoinHandle::join".into(),
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
        let detector = ThreadingDetector::new();
        assert!(detector.spawns().is_empty());
        assert!(detector.joins().is_empty());
        assert_eq!(detector, ThreadingDetector::default());
        assert_eq!(detector.clone(), detector);
    }

    #[test]
    fn a_detector_keeps_the_names_it_is_configured_with() {
        let detector = ThreadingDetector::with_names(
            [
                ThreadSpawnSignature::new("CreateThread", SpawnBinding::ReturnValue),
                ThreadSpawnSignature::new("pthread_create", SpawnBinding::FirstArg),
            ],
            ["WaitForSingleObject", "pthread_join"],
        );
        // Configuration order is scan order: two detectors built the
        // same way see the same names in the same order.
        assert_eq!(detector.spawns().len(), 2);
        assert_eq!(detector.spawns()[0].name, "CreateThread");
        assert_eq!(detector.spawns()[1].binding, SpawnBinding::FirstArg);
        assert_eq!(detector.joins(), ["WaitForSingleObject", "pthread_join"]);
    }

    #[test]
    fn added_names_join_their_sets_in_order() {
        let mut detector = ThreadingDetector::new();
        detector.add_spawn(ThreadSpawnSignature::new(
            "CreateThread",
            SpawnBinding::ReturnValue,
        ));
        detector.add_spawn(ThreadSpawnSignature::new(
            "pthread_create",
            SpawnBinding::FirstArg,
        ));
        detector.add_join("WaitForSingleObject");
        detector.add_join("pthread_join");
        let names: Vec<&str> = detector.spawns().iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, ["CreateThread", "pthread_create"]);
        assert_eq!(detector.joins(), ["WaitForSingleObject", "pthread_join"]);
    }

    #[test]
    fn a_detector_can_be_shared_across_scans() {
        // One detector is driven concurrently over a program's
        // functions, so sharing one by reference across tasks must
        // stay sound.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ThreadingDetector>();
    }

    #[test]
    fn a_thread_spawn_signature_serde_round_trips() {
        let signature = ThreadSpawnSignature::new("pthread_create", SpawnBinding::FirstArg);
        let json = serde_json::to_string(&signature).unwrap();
        assert!(json.contains("\"binding\":\"first_arg\""));
        let back: ThreadSpawnSignature = serde_json::from_str(&json).unwrap();
        assert_eq!(back, signature);
    }

    #[test]
    fn spawn_bindings_display_their_serde_labels() {
        for binding in [SpawnBinding::ReturnValue, SpawnBinding::FirstArg] {
            let label = serde_json::to_value(binding).unwrap();
            assert_eq!(binding.to_string(), label.as_str().unwrap());
        }
        assert_eq!(SpawnBinding::ReturnValue.to_string(), "return_value");
    }

    #[test]
    fn the_standard_spawns_name_the_three_spawn_spellings() {
        let spawns = default_spawns();
        let named: Vec<(&str, SpawnBinding)> = spawns
            .iter()
            .map(|s| (s.name.as_str(), s.binding))
            .collect();
        assert_eq!(
            named,
            [
                ("CreateThread", SpawnBinding::ReturnValue),
                ("pthread_create", SpawnBinding::FirstArg),
                ("std::thread::spawn", SpawnBinding::ReturnValue),
            ]
        );
    }

    #[test]
    fn the_standard_joins_name_the_three_wait_spellings() {
        assert_eq!(
            default_joins(),
            [
                "WaitForSingleObject",
                "pthread_join",
                "std::thread::JoinHandle::join"
            ]
        );
    }

    #[test]
    fn a_joined_std_thread_spawn_reads_as_a_scoped_thread() {
        // The Rust stdlib spawn joined through its demangled
        // `JoinHandle::join` stays `std::thread::spawn`: the join the
        // body already performs is the `JoinHandle` the translation keeps.
        let spawns = detect(
            "\
undefined FUN_18003ab00(void) {
  local_8 = std::thread::spawn(worker);
  std::thread::JoinHandle::join(&local_8);
  return;
}",
        );
        assert_eq!(spawns.len(), 1);
        assert_eq!(spawns[0].spawn, "std::thread::spawn");
        assert_eq!(
            spawns[0].join.as_deref(),
            Some("std::thread::JoinHandle::join")
        );
        assert_eq!(spawns[0].suggestion, "std::thread::spawn");
        assert_eq!(spawns[0].confidence, JOINED_CONFIDENCE);
    }

    #[test]
    fn a_detector_built_with_the_standard_sets_carries_them() {
        let detector = ThreadingDetector::with_default_names();
        assert_eq!(detector.spawns(), default_spawns());
        assert_eq!(detector.joins(), default_joins());
    }

    // ------------------------------------------------------------
    // Detection
    // ------------------------------------------------------------

    fn function(body: &str) -> DecompiledFunction {
        DecompiledFunction {
            name: "FUN_18003ab00".into(),
            signature: "undefined FUN_18003ab00(void)".into(),
            body: body.into(),
        }
    }

    fn detect(body: &str) -> Vec<ThreadSpawn> {
        ThreadingDetector::with_default_names().detect(&function(body))
    }

    #[test]
    fn a_joined_create_thread_reads_as_a_scoped_thread() {
        let spawns = detect(
            "\
undefined FUN_18003ab00(void) {
  hThread = CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,worker,0x0,0,&local_14);
  worker_stuff();
  WaitForSingleObject(hThread,0xffffffff);
  return;
}",
        );
        assert_eq!(spawns.len(), 1);
        assert_eq!(spawns[0].function, "FUN_18003ab00");
        assert_eq!(spawns[0].spawn, "CreateThread");
        assert_eq!(spawns[0].join.as_deref(), Some("WaitForSingleObject"));
        // The body waits for the thread: the `JoinHandle` a scoped
        // thread keeps stands in for the wait.
        assert_eq!(spawns[0].suggestion, "std::thread::spawn");
        assert_eq!(spawns[0].confidence, JOINED_CONFIDENCE);
        // The evidence carries both sides of the pairing.
        assert_eq!(
            spawns[0].evidence,
            "hThread = CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,worker,0x0,0,&local_14); WaitForSingleObject(hThread,0xffffffff);"
        );
    }

    #[test]
    fn a_joined_pthread_create_reads_as_a_scoped_thread_too() {
        // `pthread_create` keeps the handle through its first
        // argument, and `pthread_join` names the same variable.
        let spawns = detect(
            "\
  pthread_create(&local_18,(pthread_attr_t *)0x0,worker,0x0);
  pthread_join(local_18,(void **)0x0);",
        );
        assert_eq!(spawns.len(), 1);
        assert_eq!(spawns[0].spawn, "pthread_create");
        assert_eq!(spawns[0].join.as_deref(), Some("pthread_join"));
        assert_eq!(spawns[0].suggestion, "std::thread::spawn");
    }

    #[test]
    fn an_unjoined_spawn_reads_as_a_runtime_task() {
        // No recognized wait names the handle in this function: the
        // fire-and-forget shape a detached task stands in for, at
        // the weaker confidence an absence earns.
        let spawns = detect(
            "\
  hThread = CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,worker,0x0,0,&local_14);
  return;",
        );
        assert_eq!(spawns.len(), 1);
        assert_eq!(spawns[0].join, None);
        assert_eq!(spawns[0].suggestion, "tokio::spawn");
        assert_eq!(spawns[0].confidence, UNJOINED_CONFIDENCE);
        // The evidence is the spawn line alone.
        assert!(spawns[0].evidence.starts_with("hThread = CreateThread("));
    }

    #[test]
    fn a_spawn_that_keeps_its_handle_nowhere_is_still_a_spawn() {
        // The result is discarded, so no join could tie to it — but
        // the spawn site itself is the finding.
        let spawns = detect(
            "\
  CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,worker,0x0,0,&local_14);",
        );
        assert_eq!(spawns.len(), 1);
        assert_eq!(spawns[0].join, None);
        assert_eq!(spawns[0].suggestion, "tokio::spawn");
    }

    #[test]
    fn a_join_before_the_spawn_leaves_it_unjoined() {
        // The wait answers an earlier thread, not the one the body
        // starts after it.
        let spawns = detect(
            "\
  WaitForSingleObject(hThread,0xffffffff);
  hThread = CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,worker,0x0,0,&local_14);",
        );
        assert_eq!(spawns.len(), 1);
        assert_eq!(spawns[0].join, None);
    }

    #[test]
    fn a_join_naming_another_handle_leaves_the_spawn_unjoined() {
        let spawns = detect(
            "\
  hThread = CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,worker,0x0,0,&local_14);
  WaitForSingleObject(hOther,0xffffffff);",
        );
        assert_eq!(spawns.len(), 1);
        assert_eq!(spawns[0].join, None);
    }

    #[test]
    fn each_spawn_site_is_its_own_finding_in_spawn_order() {
        let spawns = detect(
            "\
  hThread1 = CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,worker,0x0,0,&local_14);
  hThread2 = CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,worker,0x0,0,&local_10);
  WaitForSingleObject(hThread2,0xffffffff);
  WaitForSingleObject(hThread1,0xffffffff);",
        );
        assert_eq!(spawns.len(), 2);
        // Out-of-order waits still tie to their own spawns, and the
        // findings keep spawn order.
        assert_eq!(spawns[0].join.as_deref(), Some("WaitForSingleObject"));
        assert_eq!(spawns[1].join.as_deref(), Some("WaitForSingleObject"));
    }

    #[test]
    fn a_demangled_std_thread_spawn_site_is_detected() {
        // The decompiler writes the Rust stdlib spawn demangled and
        // qualified; the scan reads `::`-qualified names whole.
        let spawns = detect("  local_8 = std::thread::spawn(worker);");
        assert_eq!(spawns.len(), 1);
        assert_eq!(spawns[0].spawn, "std::thread::spawn");
    }

    #[test]
    fn a_name_spelled_inside_a_string_literal_invents_nothing() {
        assert!(detect("  printf(\"CreateThread then WaitForSingleObject\");").is_empty());
    }

    #[test]
    fn a_longer_or_qualified_name_matches_no_configured_name() {
        // Whole names only: `CreateThreadEx` is a different callee,
        // and a member access through an object is no plain call.
        assert!(
            detect(
                "\
  hThread = CreateThreadEx(0,0,worker,0x0,0,0,&local_14);
  x.WaitForSingleObject(hThread,0xffffffff);"
            )
            .is_empty()
        );
    }

    #[test]
    fn a_truncated_body_detects_nothing() {
        assert!(detect("  hThread = CreateThread((LPSECURITY_ATTRIBUTES)0x0,0;").is_empty());
    }

    #[test]
    fn a_detector_with_no_names_detects_nothing() {
        let detector = ThreadingDetector::new();
        let spawns = detector.detect(&function(
            "\
  hThread = CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,worker,0x0,0,&local_14);
  WaitForSingleObject(hThread,0xffffffff);",
        ));
        assert!(spawns.is_empty());
    }

    #[test]
    fn custom_names_pair_like_the_standard_ones() {
        let mut detector = ThreadingDetector::new();
        detector.add_spawn(ThreadSpawnSignature::new(
            "my_spawn",
            SpawnBinding::ReturnValue,
        ));
        detector.add_join("my_join");
        let spawns = detector.detect(&function(
            "\
  h = my_spawn(worker);
  my_join(h);",
        ));
        assert_eq!(spawns.len(), 1);
        assert_eq!(spawns[0].join.as_deref(), Some("my_join"));
        assert_eq!(spawns[0].suggestion, "std::thread::spawn");
    }
}
