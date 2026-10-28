//! Thread-local storage detection.
//!
//! This module provides [`TlsDetector`]. The detector holds the
//! key-creation and access names a scan reads decompiled bodies
//! against. In the Win32 TLS family, `TlsAlloc` returns an index
//! read back by `TlsGetValue`/`TlsSetValue` and released by `TlsFree`.
//! In the POSIX thread-key family, `pthread_key_create` takes the
//! key's address for `pthread_getspecific`/`pthread_setspecific` and
//! `pthread_key_delete`. For each key site, the detector records the
//! Rust thread-local storage that stands in for it.
//!
//! Each creation name is a [`TlsKeySignature`]: the callee spelling as
//! the decompiler writes it and the [`binding`](TlsKeySignature::binding)
//! that identifies the key — whether the decompiler stores the
//! creation's result into a variable or the body passes the key's
//! address as the first argument, the `pthread_key_create` spelling.
//! [`default_creations`] and [`default_accesses`] hold the standard
//! name sets, and [`TlsDetector::with_default_names`] builds a
//! detector that scans against them.
//!
//! [`TlsDetector::detect`] runs the reading. It walks a decompiled
//! body's direct calls in source order and binds each recognized key
//! creation to its key variable. It ties each recognized access to
//! the creation naming the same variable. The result is one
//! [`TlsUsage`] per key site, paired or a lone-access fragment.

use crate::types::TlsUsage;
use calxgloss_decomp::DecompiledFunction;
use serde::{Deserialize, Serialize};

use calxgloss_types::{
    CallSite, NON_CALL_KEYWORDS, NameContinuation, ScanOptions, call_sites, is_ident_byte, line_at,
    strip_casts,
};

/// The scan: plain-identifier callees, member accesses skipped, and C
/// keywords — `if (x)` — not calls.
const CALL_SCAN: ScanOptions = ScanOptions {
    continuation: NameContinuation::Ident,
    reject_preceding: b".>",
    skip_keywords: &NON_CALL_KEYWORDS,
};

/// Every direct call `name(args)` in the body — the shared pseudo-C
/// scan configured by [`CALL_SCAN`].
fn direct_calls(body: &str) -> Vec<CallSite<'_>> {
    call_sites(body, &CALL_SCAN)
}

// ============================================================
// Key-creation names
// ============================================================

/// Where a key-creation spelling keeps the thread-local key the
/// accesses tie on.
///
/// The binding says which side of the call the key sits on. A Win32
/// `TlsAlloc` returns its index, and the decompiler stores it into a
/// variable the later accesses name. `pthread_key_create` takes the
/// key through its first argument: the address of a local they read
/// back. An access only ever ties to a creation through the key, so
/// the binding decides which spelling of the creation the pairing can
/// key on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyBinding {
    /// The creation returns the key, and the decompiler's assignment
    /// stores it into a variable.
    ReturnValue,
    /// The body passes the key's address as the creation's first
    /// argument.
    FirstArg,
}

calxgloss_types::display_serde_label!(KeyBinding {
    ReturnValue => "return_value",
    FirstArg => "first_arg",
});

/// One key-creation name the detector recognizes: the callee spelling
/// and the binding that identifies its key.
///
/// A signature is a name, not a shape. It only says that a call to
/// [`name`](Self::name) allocated a thread-local key the body keeps
/// through [`binding`](Self::binding) — `TlsAlloc` returning it,
/// `pthread_key_create` taking its address. Where the call sits in the
/// function, and whether the body ever reads the key, is the
/// detector's reading.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsKeySignature {
    /// The callee spelling as the decompiler writes it, e.g.
    /// `TlsAlloc`, `pthread_key_create`.
    pub name: String,
    /// Where this spelling keeps the key.
    pub binding: KeyBinding,
}

impl TlsKeySignature {
    /// A signature recognizing the callee spelling `name` as a
    /// thread-local key creation whose key the body keeps through
    /// `binding`.
    pub fn new(name: impl Into<String>, binding: KeyBinding) -> Self {
        Self {
            name: name.into(),
            binding,
        }
    }
}

// ============================================================
// Detector
// ============================================================

/// Thread-local storage detection over decompiled functions.
///
/// The detector owns the name sets a scan reads bodies against:
/// [`TlsKeySignature`] records for the creating side and plain callee
/// spellings for the accessing side. Both sets are configurable:
/// supply them whole through [`with_names`](Self::with_names), or add
/// them one name at a time with [`add_creation`](Self::add_creation)
/// and [`add_access`](Self::add_access). [`creations`](Self::creations)
/// and [`accesses`](Self::accesses) report them in configuration
/// order, so two detectors built the same way scan identically and
/// results diff cleanly. The detector holds no scan source of its own
/// and never writes back to the program; one detector serves an
/// entire scan and can be shared by reference across concurrent
/// per-function passes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TlsDetector {
    creations: Vec<TlsKeySignature>,
    accesses: Vec<String>,
}

impl TlsDetector {
    /// A detector with no names configured: every body it is handed
    /// reports nothing until the standard sets are configured through
    /// [`with_default_names`](Self::with_default_names), or names are
    /// added one at a time through [`add_creation`](Self::add_creation)
    /// and [`add_access`](Self::add_access).
    pub fn new() -> Self {
        Self::default()
    }

    /// A detector that scans against the standard name sets —
    /// [`default_creations`] and [`default_accesses`] — in their
    /// configuration order.
    pub fn with_default_names() -> Self {
        Self::with_names(default_creations(), default_accesses())
    }

    /// A detector that scans against exactly `creations` and
    /// `accesses`, each kept in the order it is given.
    pub fn with_names(
        creations: impl IntoIterator<Item = TlsKeySignature>,
        accesses: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            creations: creations.into_iter().collect(),
            accesses: accesses.into_iter().map(Into::into).collect(),
        }
    }

    /// Add one key-creation name to the set this detector scans
    /// against.
    pub fn add_creation(&mut self, creation: TlsKeySignature) {
        self.creations.push(creation);
    }

    /// Add one access name to the set this detector scans against.
    pub fn add_access(&mut self, access: impl Into<String>) {
        self.accesses.push(access.into());
    }

    /// The key-creation names this detector scans against, in
    /// configuration order.
    pub fn creations(&self) -> &[TlsKeySignature] {
        &self.creations
    }

    /// The access names this detector scans against, in configuration
    /// order.
    pub fn accesses(&self) -> &[String] {
        &self.accesses
    }

    /// The thread-local key sites found in one function's body.
    ///
    /// The reading walks the body's direct calls in source order —
    /// outside string literals, whole names only — and classifies
    /// each against the configured sets. A creation binds its key
    /// through its signature's [`KeyBinding`]: the variable the
    /// decompiler stores the result into, or the plain variable its
    /// first argument names, seen through any cast and a leading `&`.
    /// An access names its key through its first argument, and ties
    /// to the most recent still-unaccessed creation of the key it
    /// names. Further accesses to a key the body already accounts for
    /// add no new finding: that key's finding already covers them.
    ///
    /// Each key the body accesses becomes one [`TlsUsage`]. A key
    /// created and accessed in one body suggests `SUGGESTION` at
    /// `PAIRED_CONFIDENCE` — the full thread-local shape, key and
    /// all, is visible. A lone access with no visible creation
    /// suggests it at `FRAGMENT_CONFIDENCE`: the shape is half seen,
    /// with the key's origin elsewhere. A creation the body never
    /// accesses claims nothing: there is no per-thread data touched
    /// here to translate. The evidence is the creation line and the
    /// first access line. Findings come back in first-seen order, so
    /// two scans of one body diff cleanly.
    pub fn detect(&self, func: &DecompiledFunction) -> Vec<TlsUsage> {
        let mut keys: Vec<OpenKey> = Vec::new();
        for call in direct_calls(&func.body) {
            if let Some(signature) = self.creations.iter().find(|c| c.name == call.callee) {
                let key = match signature.binding {
                    KeyBinding::ReturnValue => assigned_variable(&func.body, call.offset),
                    KeyBinding::FirstArg => call.args.first().and_then(|arg| key_object(arg)),
                };
                keys.push(OpenKey {
                    key,
                    creation: Some(UsageRecord {
                        name: signature.name.clone(),
                        line: line_at(&func.body, call.offset),
                    }),
                    access: None,
                });
            } else if self.accesses.iter().any(|a| a == call.callee) {
                let record = UsageRecord {
                    name: call.callee.to_string(),
                    line: line_at(&func.body, call.offset),
                };
                let key = call.args.first().and_then(|arg| key_object(arg));
                let open = key.as_deref().and_then(|name| {
                    keys.iter().rposition(|k| {
                        k.key.as_deref() == Some(name) && k.creation.is_some() && k.access.is_none()
                    })
                });
                let seen = key
                    .as_deref()
                    .is_some_and(|name| keys.iter().any(|k| k.key.as_deref() == Some(name)));
                match open {
                    Some(at) => keys[at].access = Some(record),
                    None if seen => {
                        // The key already stands in a finding of its
                        // own — further accesses to it add no new
                        // finding.
                    }
                    None => keys.push(OpenKey {
                        key,
                        creation: None,
                        access: Some(record),
                    }),
                }
            }
        }
        keys.into_iter()
            .filter_map(|key| {
                let access = key.access?;
                let (creation, confidence, evidence) = match &key.creation {
                    Some(creation) => (
                        Some(creation.name.clone()),
                        PAIRED_CONFIDENCE,
                        format!("{} {}", creation.line, access.line),
                    ),
                    None => (None, FRAGMENT_CONFIDENCE, access.line),
                };
                Some(TlsUsage {
                    function: func.name.clone(),
                    creation,
                    access: access.name,
                    suggestion: SUGGESTION.to_string(),
                    confidence: confidence.into(),
                    evidence,
                })
            })
            .collect()
    }
}

// ============================================================
// The reading
// ============================================================

/// Evidence confidence of a key created and accessed in one body:
/// both sides are explicit calls to recognized names, and the key
/// the creation keeps is the key the access names — but the tie
/// between them is the decompiler's naming, not resolved data flow.
const PAIRED_CONFIDENCE: u8 = 70;

/// Evidence confidence of a lone access with no visible key creation:
/// the access is explicit, but the reading rests on an absence — the
/// key was created outside this function — and the thread-local
/// shape is only half seen.
const FRAGMENT_CONFIDENCE: u8 = 60;

/// The Rust storage pattern thread-local data reads as: a
/// `thread_local!` static stands in for the key-indexed per-thread
/// slot, with no key plumbing to transliterate.
const SUGGESTION: &str = "thread_local!";

/// One side of a thread-local reading: the spelling behind the call
/// and the line it sits on.
struct UsageRecord {
    name: String,
    line: String,
}

/// A key site while the body is walked: the key variable the body
/// keeps for it, the creation that allocated it when the body shows
/// one, and the first access that named it.
struct OpenKey {
    key: Option<String>,
    creation: Option<UsageRecord>,
    access: Option<UsageRecord>,
}

/// The variable a call's result is stored into, read from the call's
/// own line: walking left from the callee to the `=` that assigns,
/// the plain identifier sitting left of that `=`. A `=` that is part
/// of a comparison (`==`, `!=`, `<=`, `>=`) or a compound assignment
/// (`+=` and friends) assigns no result, and a target that is not a
/// plain variable — a dereference, an indexed element, a field —
/// stores the key somewhere the pairing cannot key on, so neither
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

/// The key a call's first argument names: a plain variable, seen
/// through any cast and a leading `&` — the decompiler writes
/// `pthread_key_create(&local_8,...)` for the key's address and
/// `pthread_getspecific(local_8)` for the key itself. Anything else
/// names no local key the pairing can key on.
fn key_object(arg: &str) -> Option<String> {
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

/// The type words a decompiler cast may spell, matching the decompiler's
/// vocabulary the other detectors' scans strip, plus the thread-key
/// type the decompiler writes when the program has pthread debug
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
            | "pthread_key_t"
            | "LPVOID"
    )
}

// ============================================================
// The standard name sets
// ============================================================

/// The standard key-creation names: the spellings a scan recognizes
/// as thread-local key allocations out of the box — the Win32
/// `TlsAlloc`, which returns its index, and the POSIX
/// `pthread_key_create`, which takes the key through its first
/// argument. Each name includes the binding that identifies the key,
/// so a recognized creation knows which spelling the access pairing
/// keys on.
pub fn default_creations() -> Vec<TlsKeySignature> {
    vec![
        TlsKeySignature::new("TlsAlloc", KeyBinding::ReturnValue),
        TlsKeySignature::new("pthread_key_create", KeyBinding::FirstArg),
    ]
}

/// The standard access names: the spellings a scan recognizes as
/// reads and writes of a thread-local key — the Win32
/// `TlsGetValue`/`TlsSetValue` pair and `TlsFree`, and the POSIX
/// `pthread_getspecific`/`pthread_setspecific` pair and
/// `pthread_key_delete`. All name the key through their first
/// argument.
pub fn default_accesses() -> Vec<String> {
    vec![
        "TlsGetValue".into(),
        "TlsSetValue".into(),
        "TlsFree".into(),
        "pthread_getspecific".into(),
        "pthread_setspecific".into(),
        "pthread_key_delete".into(),
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
        let detector = TlsDetector::new();
        assert!(detector.creations().is_empty());
        assert!(detector.accesses().is_empty());
        assert_eq!(detector, TlsDetector::default());
        assert_eq!(detector.clone(), detector);
    }

    #[test]
    fn a_detector_keeps_the_names_it_is_configured_with() {
        let detector = TlsDetector::with_names(
            [
                TlsKeySignature::new("TlsAlloc", KeyBinding::ReturnValue),
                TlsKeySignature::new("pthread_key_create", KeyBinding::FirstArg),
            ],
            ["TlsGetValue", "pthread_getspecific"],
        );
        // Configuration order is scan order: two detectors built the
        // same way see the same names in the same order.
        assert_eq!(detector.creations().len(), 2);
        assert_eq!(detector.creations()[0].name, "TlsAlloc");
        assert_eq!(detector.creations()[1].binding, KeyBinding::FirstArg);
        assert_eq!(detector.accesses(), ["TlsGetValue", "pthread_getspecific"]);
    }

    #[test]
    fn added_names_join_their_sets_in_order() {
        let mut detector = TlsDetector::new();
        detector.add_creation(TlsKeySignature::new("TlsAlloc", KeyBinding::ReturnValue));
        detector.add_creation(TlsKeySignature::new(
            "pthread_key_create",
            KeyBinding::FirstArg,
        ));
        detector.add_access("TlsGetValue");
        detector.add_access("pthread_getspecific");
        let names: Vec<&str> = detector
            .creations()
            .iter()
            .map(|c| c.name.as_str())
            .collect();
        assert_eq!(names, ["TlsAlloc", "pthread_key_create"]);
        assert_eq!(detector.accesses(), ["TlsGetValue", "pthread_getspecific"]);
    }

    #[test]
    fn a_detector_can_be_shared_across_scans() {
        // One detector is driven concurrently over a program's
        // functions, so sharing one by reference across tasks must
        // stay sound.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<TlsDetector>();
    }

    #[test]
    fn a_tls_key_signature_serde_round_trips() {
        let signature = TlsKeySignature::new("pthread_key_create", KeyBinding::FirstArg);
        let json = serde_json::to_string(&signature).unwrap();
        assert!(json.contains("\"binding\":\"first_arg\""));
        let back: TlsKeySignature = serde_json::from_str(&json).unwrap();
        assert_eq!(back, signature);
    }

    #[test]
    fn key_bindings_display_their_serde_labels() {
        for binding in [KeyBinding::ReturnValue, KeyBinding::FirstArg] {
            let label = serde_json::to_value(binding).unwrap();
            assert_eq!(binding.to_string(), label.as_str().unwrap());
        }
        assert_eq!(KeyBinding::ReturnValue.to_string(), "return_value");
    }

    #[test]
    fn the_standard_creations_name_the_two_creation_spellings() {
        let creations = default_creations();
        let named: Vec<(&str, KeyBinding)> = creations
            .iter()
            .map(|c| (c.name.as_str(), c.binding))
            .collect();
        assert_eq!(
            named,
            [
                ("TlsAlloc", KeyBinding::ReturnValue),
                ("pthread_key_create", KeyBinding::FirstArg),
            ]
        );
    }

    #[test]
    fn the_standard_accesses_name_the_six_access_spellings() {
        assert_eq!(
            default_accesses(),
            [
                "TlsGetValue",
                "TlsSetValue",
                "TlsFree",
                "pthread_getspecific",
                "pthread_setspecific",
                "pthread_key_delete",
            ]
        );
    }

    #[test]
    fn a_detector_built_with_the_standard_sets_carries_them() {
        let detector = TlsDetector::with_default_names();
        assert_eq!(detector.creations(), default_creations());
        assert_eq!(detector.accesses(), default_accesses());
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

    fn detect(body: &str) -> Vec<TlsUsage> {
        TlsDetector::with_default_names().detect(&function(body))
    }

    #[test]
    fn a_tls_alloc_and_get_value_read_as_one_thread_local_key() {
        // The Win32 shape: `TlsAlloc` returns the index the
        // assignment stores, and `TlsGetValue` names the same
        // variable — the full thread-local shape, key and all.
        let usages = detect(
            "\
undefined FUN_18003ab00(void) {
  local_4 = TlsAlloc();
  pvVar1 = TlsGetValue(local_4);
  return;
}",
        );
        assert_eq!(usages.len(), 1);
        assert_eq!(usages[0].function, "FUN_18003ab00");
        assert_eq!(usages[0].creation.as_deref(), Some("TlsAlloc"));
        assert_eq!(usages[0].access, "TlsGetValue");
        assert_eq!(usages[0].suggestion, "thread_local!");
        assert_eq!(usages[0].confidence, PAIRED_CONFIDENCE);
        // The evidence includes both sides of the pairing.
        assert_eq!(
            usages[0].evidence,
            "local_4 = TlsAlloc(); pvVar1 = TlsGetValue(local_4);"
        );
    }

    #[test]
    fn a_pthread_key_pair_reads_as_one_thread_local_key_too() {
        // `pthread_key_create` keeps the key through its first
        // argument, and `pthread_setspecific` names the same
        // variable.
        let usages = detect(
            "\
  pthread_key_create(&local_8,(function *)0x0);
  pthread_setspecific(local_8,(void *)0x0);",
        );
        assert_eq!(usages.len(), 1);
        assert_eq!(usages[0].creation.as_deref(), Some("pthread_key_create"));
        assert_eq!(usages[0].access, "pthread_setspecific");
        assert_eq!(usages[0].confidence, PAIRED_CONFIDENCE);
    }

    #[test]
    fn a_free_names_the_key_like_a_read_or_write() {
        // Releasing the key is an access to it too.
        let usages = detect(
            "\
  local_4 = TlsAlloc();
  TlsFree(local_4);",
        );
        assert_eq!(usages.len(), 1);
        assert_eq!(usages[0].creation.as_deref(), Some("TlsAlloc"));
        assert_eq!(usages[0].access, "TlsFree");
    }

    #[test]
    fn an_access_with_no_visible_creation_reads_as_a_fragment() {
        // The key was created outside this function: the
        // thread-local shape is there, but only half of it is
        // visible — the weaker evidence confidence an absence earns.
        let usages = detect("  pvVar1 = TlsGetValue(local_4);");
        assert_eq!(usages.len(), 1);
        assert_eq!(usages[0].creation, None);
        assert_eq!(usages[0].access, "TlsGetValue");
        assert_eq!(usages[0].suggestion, "thread_local!");
        assert_eq!(usages[0].confidence, FRAGMENT_CONFIDENCE);
        // The evidence is the access line alone.
        assert_eq!(usages[0].evidence, "pvVar1 = TlsGetValue(local_4);");
    }

    #[test]
    fn further_accesses_to_a_created_key_fold_into_its_finding() {
        // One key is one finding however often the body reads it.
        let usages = detect(
            "\
  local_4 = TlsAlloc();
  pvVar1 = TlsGetValue(local_4);
  TlsSetValue(local_4,(void *)0x1);
  TlsFree(local_4);",
        );
        assert_eq!(usages.len(), 1);
        assert_eq!(usages[0].creation.as_deref(), Some("TlsAlloc"));
        assert_eq!(usages[0].access, "TlsGetValue");
    }

    #[test]
    fn further_accesses_to_a_fragment_fold_into_it() {
        let usages = detect(
            "\
  pvVar1 = TlsGetValue(local_4);
  TlsSetValue(local_4,(void *)0x1);",
        );
        assert_eq!(usages.len(), 1);
        assert_eq!(usages[0].creation, None);
        assert_eq!(usages[0].access, "TlsGetValue");
    }

    #[test]
    fn an_access_before_the_creation_reads_as_a_fragment() {
        // The access reads a key this body did not create; the
        // creation that follows is never accessed here.
        let usages = detect(
            "\
  pvVar1 = TlsGetValue(local_4);
  local_4 = TlsAlloc();",
        );
        assert_eq!(usages.len(), 1);
        assert_eq!(usages[0].creation, None);
        assert_eq!(usages[0].confidence, FRAGMENT_CONFIDENCE);
    }

    #[test]
    fn a_creation_the_body_never_accesses_claims_nothing() {
        // An allocated key no per-thread data is read through here —
        // there is nothing in this body to translate.
        let usages = detect("  local_4 = TlsAlloc();");
        assert!(usages.is_empty());
    }

    #[test]
    fn each_key_site_is_its_own_finding_in_first_seen_order() {
        let usages = detect(
            "\
  local_4 = TlsAlloc();
  pvVar1 = TlsGetValue(local_4);
  pvVar2 = pthread_getspecific(local_8);
  pthread_key_create(&local_c,(function *)0x0);
  pthread_setspecific(local_c,(void *)0x0);",
        );
        assert_eq!(usages.len(), 3);
        // The paired Win32 key, the lone POSIX access, and the later
        // paired POSIX key — each in the order its key first showed
        // up in the body.
        assert_eq!(usages[0].creation.as_deref(), Some("TlsAlloc"));
        assert_eq!(usages[1].creation, None);
        assert_eq!(usages[1].access, "pthread_getspecific");
        assert_eq!(usages[2].creation.as_deref(), Some("pthread_key_create"));
    }

    #[test]
    fn a_name_spelled_inside_a_string_literal_invents_nothing() {
        assert!(detect("  printf(\"TlsAlloc then TlsGetValue\");").is_empty());
    }

    #[test]
    fn a_longer_or_qualified_name_matches_no_configured_name() {
        // Whole names only: `TlsAllocEx` is a different callee, and
        // a member access through an object is no plain call.
        assert!(
            detect(
                "\
  local_4 = TlsAllocEx(0);
  x.TlsGetValue(local_4);"
            )
            .is_empty()
        );
    }

    #[test]
    fn a_truncated_body_detects_nothing() {
        assert!(detect("  pvVar1 = TlsGetValue(local_4;").is_empty());
    }

    #[test]
    fn a_detector_with_no_names_detects_nothing() {
        let detector = TlsDetector::new();
        let usages = detector.detect(&function(
            "\
  local_4 = TlsAlloc();
  pvVar1 = TlsGetValue(local_4);",
        ));
        assert!(usages.is_empty());
    }

    #[test]
    fn custom_names_pair_like_the_standard_ones() {
        let mut detector = TlsDetector::new();
        detector.add_creation(TlsKeySignature::new("my_key_new", KeyBinding::ReturnValue));
        detector.add_access("my_key_get");
        let usages = detector.detect(&function(
            "\
  k = my_key_new();
  my_key_get(k);",
        ));
        assert_eq!(usages.len(), 1);
        assert_eq!(usages[0].creation.as_deref(), Some("my_key_new"));
        assert_eq!(usages[0].access, "my_key_get");
        assert_eq!(usages[0].suggestion, "thread_local!");
    }
}
