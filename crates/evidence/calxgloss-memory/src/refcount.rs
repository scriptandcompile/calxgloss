//! Reference counting detection.
//!
//! This module provides [`ReferenceCountDetector`], which carries the
//! counter names a scan reads decompiled bodies against — the named
//! count fields a body raises and lowers by arithmetic (`ref_count++`
//! and `ref_count--`) and the COM `AddRef`/`Release` method pair —
//! pairing each bump with its drop inside a single function so the
//! prompt can later weigh the manual counting against `Rc<T>` or
//! `Arc<T>`.
//!
//! The count is read in two shapes. Where the code counts through
//! arithmetic on a named field, a bump is a `++` or `+= 1` on a
//! configured field name hanging off a plain-owner variable and a
//! drop is a `--` or `-= 1` on the same field of the same owner.
//! Where the code counts through the COM method pair, a bump is a
//! call to a recognized increment name and a drop is a call to a
//! recognized decrement name, the two tied by the object variable
//! their first argument names. [`default_field_names`],
//! [`default_increments`] and [`default_decrements`] carry the
//! standard name sets, and [`ReferenceCountDetector::with_default_names`]
//! builds a detector that scans against them.
//!
//! [`ReferenceCountDetector::detect_reference_counts`] runs the
//! reading: it walks a decompiled body in source order, answers each
//! recognized bump with the drop that closes it, and reports one
//! [`ReferenceCount`] per pair. Each pair carries the shared-ownership
//! pattern standing in for the manual counting: `Rc<T>` wherever the
//! counted object stays inside this function, `Arc<T>` wherever the
//! body hands the object to a thread-spawn call — a count reaching
//! another thread has to be atomic, and `Arc` is the shared ownership
//! that spells it. [`default_thread_spawns`] carries the standard
//! spawn names the narrowing reads against.

use crate::types::{CountStyle, ReferenceCount};
use calxgloss_ghidra::DecompiledFunction;

use calxgloss_types::{
    CallSite, NON_CALL_KEYWORDS, NameContinuation, ScanOptions, call_sites, is_ident_byte, line_at,
    skip_string, skip_ws, strip_casts,
};

/// The scan: a `.` followed by an identifier byte continues a demangled
/// spelling (`operator.delete`), member accesses through `->` are
/// skipped, and C keywords are not calls.
const CALL_SCAN: ScanOptions = ScanOptions {
    continuation: NameContinuation::DemangledDot,
    reject_preceding: b".>",
    skip_keywords: &NON_CALL_KEYWORDS,
};

/// Every direct call `name(args)` in the body — the shared pseudo-C
/// scan configured by [`CALL_SCAN`].
fn direct_calls(body: &str) -> Vec<CallSite<'_>> {
    call_sites(body, &CALL_SCAN)
}

// ============================================================
// Detector
// ============================================================

/// Reference-count bump/drop pair tracking over decompiled functions.
///
/// The detector owns the name sets a scan reads bodies against:
/// counter field names for the arithmetic shape, increment and
/// decrement method names for the COM shape, and thread-spawn names
/// for the shared-across-threads reading that picks `Arc<T>` over
/// `Rc<T>`. All four sets are configurable — supply them whole
/// through [`with_names`](Self::with_names) or grow them one name at
/// a time with [`add_field`](Self::add_field),
/// [`add_increment`](Self::add_increment),
/// [`add_decrement`](Self::add_decrement) and
/// [`add_thread_spawn`](Self::add_thread_spawn) — and
/// [`fields`](Self::fields), [`increments`](Self::increments),
/// [`decrements`](Self::decrements) and
/// [`thread_spawns`](Self::thread_spawns) report them in configuration
/// order, so two detectors built the same way scan identically and
/// results diff cleanly. The detector holds no Ghidra client of its
/// own and never writes back to the program; one detector serves an
/// entire scan and can be shared by reference across concurrent
/// per-function passes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReferenceCountDetector {
    fields: Vec<String>,
    increments: Vec<String>,
    decrements: Vec<String>,
    thread_spawns: Vec<String>,
}

impl ReferenceCountDetector {
    /// A detector with no names configured: every body it is handed
    /// pairs nothing until the standard sets arrive through
    /// [`with_default_names`](Self::with_default_names) or names join
    /// one at a time through [`add_field`](Self::add_field),
    /// [`add_increment`](Self::add_increment),
    /// [`add_decrement`](Self::add_decrement) and
    /// [`add_thread_spawn`](Self::add_thread_spawn).
    pub fn new() -> Self {
        Self::default()
    }

    /// A detector that scans against the standard name sets —
    /// [`default_field_names`], [`default_increments`],
    /// [`default_decrements`] and [`default_thread_spawns`] — in their
    /// configuration order.
    pub fn with_default_names() -> Self {
        Self::with_names(
            default_field_names(),
            default_increments(),
            default_decrements(),
            default_thread_spawns(),
        )
    }

    /// A detector that scans against exactly `fields`, `increments`,
    /// `decrements` and `thread_spawns`, each kept in the order it is
    /// given.
    pub fn with_names(
        fields: impl IntoIterator<Item = impl Into<String>>,
        increments: impl IntoIterator<Item = impl Into<String>>,
        decrements: impl IntoIterator<Item = impl Into<String>>,
        thread_spawns: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            fields: fields.into_iter().map(Into::into).collect(),
            increments: increments.into_iter().map(Into::into).collect(),
            decrements: decrements.into_iter().map(Into::into).collect(),
            thread_spawns: thread_spawns.into_iter().map(Into::into).collect(),
        }
    }

    /// Add one counter field name to the set this detector scans
    /// against.
    pub fn add_field(&mut self, field: impl Into<String>) {
        self.fields.push(field.into());
    }

    /// Add one increment method name to the set this detector scans
    /// against.
    pub fn add_increment(&mut self, increment: impl Into<String>) {
        self.increments.push(increment.into());
    }

    /// Add one decrement method name to the set this detector scans
    /// against.
    pub fn add_decrement(&mut self, decrement: impl Into<String>) {
        self.decrements.push(decrement.into());
    }

    /// Add one thread-spawn name to the set this detector scans
    /// against for the shared-across-threads reading.
    pub fn add_thread_spawn(&mut self, spawn: impl Into<String>) {
        self.thread_spawns.push(spawn.into());
    }

    /// The counter field names this detector scans against, in
    /// configuration order.
    pub fn fields(&self) -> &[String] {
        &self.fields
    }

    /// The increment method names this detector scans against, in
    /// configuration order.
    pub fn increments(&self) -> &[String] {
        &self.increments
    }

    /// The decrement method names this detector scans against, in
    /// configuration order.
    pub fn decrements(&self) -> &[String] {
        &self.decrements
    }

    /// The thread-spawn names this detector scans against, in
    /// configuration order.
    pub fn thread_spawns(&self) -> &[String] {
        &self.thread_spawns
    }

    /// The bump/drop pairs one function's body carries.
    ///
    /// The reading walks the body in source order — outside string
    /// literals, whole names only — and reads both counting shapes.
    /// The arithmetic shape keys on a configured field name hanging
    /// off a plain-owner variable through `->` or `.`: a bump is `++`
    /// or `+= 1` on it, a drop is `--` or `-= 1`, and a field reached
    /// through a chain or a dereference (`a->next->ref_count`,
    /// `(*pObj)->ref_count`) hangs off no owner the pairing can key
    /// on. The COM shape keys on the object variable a recognized
    /// increment or decrement call names as its first argument, seen
    /// through any cast; a member-spelled `param_1->Release(param_1)`
    /// is a member access, not a plain call, and names nothing. A
    /// drop answers the most recent still-open bump of the same
    /// counter *in its own shape* — bumps never cross shapes — and a
    /// bump with no drop naming its counter in this function is
    /// reported by nothing: whether the count escapes or leaks is a
    /// cross-function question, outside this pairing.
    ///
    /// Each pair becomes one [`ReferenceCount`] naming the shape and
    /// the two recognized spellings that raised and lowered the
    /// count, with the bump line and the drop line joined as the
    /// evidence. The record carries the shared-ownership pattern
    /// standing in for the manual counting: [`RC_SUGGESTION`] at
    /// [`COUNT_PAIR_CONFIDENCE`], narrowed to [`ARC_SUGGESTION`] at
    /// [`ARC_CONFIDENCE`] where the body hands the counted object to
    /// one of the configured thread-spawn names. Records come back in
    /// bump order, so two scans of one body diff cleanly.
    pub fn detect_reference_counts(&self, func: &DecompiledFunction) -> Vec<ReferenceCount> {
        let calls = direct_calls(&func.body);
        let mut pairs: Vec<(usize, ReferenceCount)> = Vec::new();
        self.detect_field_pairs(&func.body, &calls, &func.name, &mut pairs);
        self.detect_com_pairs(&func.body, &calls, &func.name, &mut pairs);
        pairs.sort_by_key(|(offset, _)| *offset);
        pairs.into_iter().map(|(_, record)| record).collect()
    }

    /// The arithmetic-shape pairs one body carries: a configured
    /// counter field on a plain owner, raised by `++`/`+= 1` and
    /// lowered by `--`/`-= 1`, a drop answering the most recent
    /// still-open bump on the same field of the same owner.
    fn detect_field_pairs(
        &self,
        body: &str,
        calls: &[CallSite<'_>],
        function: &str,
        pairs: &mut Vec<(usize, ReferenceCount)>,
    ) {
        let mut open: Vec<CountSite<'_>> = Vec::new();
        for site in count_sites(body, &self.fields) {
            if site.bump {
                open.push(site);
            } else if let Some(at) = open
                .iter()
                .rposition(|bump| bump.owner == site.owner && bump.field == site.field)
            {
                let bump = open.remove(at);
                let (suggestion, confidence) = self.ownership_pattern(calls, bump.owner);
                pairs.push((
                    bump.offset,
                    ReferenceCount {
                        function: function.to_string(),
                        style: CountStyle::FieldArithmetic,
                        increment: format!("{}++", bump.field),
                        decrement: format!("{}--", bump.field),
                        suggestion: suggestion.to_string(),
                        confidence: confidence.into(),
                        evidence: format!("{} {}", bump.line, site.line),
                    },
                ));
            }
        }
    }

    /// The COM-shape pairs one body carries: a recognized increment
    /// call bound to the plain variable its first argument names, and
    /// a recognized decrement naming that same variable, the drop
    /// answering the most recent still-open bump of the variable.
    fn detect_com_pairs(
        &self,
        body: &str,
        calls: &[CallSite<'_>],
        function: &str,
        pairs: &mut Vec<(usize, ReferenceCount)>,
    ) {
        let mut open: Vec<OpenCall> = Vec::new();
        for call in calls {
            if let Some(name) = self.increments.iter().find(|n| n == &call.callee) {
                // An increment naming no variable its drop could
                // answer counts no object this function releases.
                let bumped = call.args.first().map(|arg| strip_casts(arg, is_type_word));
                if let Some(object) = bumped.as_deref().and_then(plain_variable) {
                    open.push(OpenCall {
                        object: object.to_string(),
                        method: name.clone(),
                        offset: call.offset,
                        line: line_at(body, call.offset),
                    });
                }
            } else if let Some(name) = self.decrements.iter().find(|n| n == &call.callee) {
                let dropped = call.args.first().map(|arg| strip_casts(arg, is_type_word));
                if let Some(object) = dropped.as_deref().and_then(plain_variable)
                    && let Some(at) = open.iter().rposition(|bump| bump.object == object)
                {
                    let bump = open.remove(at);
                    let (suggestion, confidence) = self.ownership_pattern(calls, object);
                    pairs.push((
                        bump.offset,
                        ReferenceCount {
                            function: function.to_string(),
                            style: CountStyle::ComMethods,
                            increment: bump.method,
                            decrement: name.clone(),
                            suggestion: suggestion.to_string(),
                            confidence: confidence.into(),
                            evidence: format!("{} {}", bump.line, line_at(body, call.offset)),
                        },
                    ));
                }
            }
        }
    }

    /// The shared-ownership pattern a counted object reads as:
    /// [`ARC_SUGGESTION`] where the body hands the object to one of
    /// the configured thread-spawn names — the new thread works
    /// through the same object, so its count is shared across threads
    /// and only an atomic count is safe there — and [`RC_SUGGESTION`]
    /// wherever the object stays inside this function.
    fn ownership_pattern(&self, calls: &[CallSite<'_>], object: &str) -> (&'static str, u8) {
        let shared = calls.iter().any(|call| {
            self.thread_spawns.iter().any(|spawn| spawn == call.callee)
                && call
                    .args
                    .iter()
                    .any(|arg| plain_variable(&strip_casts(arg, is_type_word)) == Some(object))
        });
        if shared {
            (ARC_SUGGESTION, ARC_CONFIDENCE)
        } else {
            (RC_SUGGESTION, COUNT_PAIR_CONFIDENCE)
        }
    }
}

// ============================================================
// The pairing reading
// ============================================================

/// Confidence of a pairing read from a bump and a drop of the same
/// counter in one body: both sides are explicit recognized
/// spellings — arithmetic on a configured field name, or calls to
/// configured method names — but the tie between them is the
/// decompiler's naming rather than resolved data flow, and a branch
/// could leave either side unreached.
const COUNT_PAIR_CONFIDENCE: u8 = 70;

/// The Rust pattern a bump/drop pairing stands in for: the manual
/// counting is exactly what `Rc<T>` automates — handing out a shared
/// owner bumps the count and dropping one lowers it — and where the
/// counted object never reaches another thread in this body, the
/// non-atomic `Rc` is the pattern to translate toward.
const RC_SUGGESTION: &str = "Rc<T>";

/// The pattern a pairing reads as where the body hands the counted
/// object to a thread spawn: the new thread works through the same
/// object, so its count is shared across threads and only an atomic
/// count is safe there — `Arc<T>` is the shared ownership that spells it.
const ARC_SUGGESTION: &str = "Arc<T>";

/// Confidence of the `Arc` narrowing: the pairing evidence is
/// [`COUNT_PAIR_CONFIDENCE`]'s, but the narrowing rests on reading
/// which call the object sits in — a recognized spawn rather than an
/// ordinary callee — and a spawn the reading misses keeps an `Rc`
/// suggestion on a count that crosses threads.
const ARC_CONFIDENCE: u8 = 65;

/// A reference-count bump or drop found in a body: the plain owner
/// variable the counted field hangs off, the field name, whether the
/// site raises (`++`, `+= 1`) or lowers (`--`, `-= 1`) the count, and
/// where and on which line the site sits.
struct CountSite<'a> {
    owner: &'a str,
    field: &'a str,
    bump: bool,
    offset: usize,
    line: String,
}

/// A recognized increment still waiting for its drop while the body
/// is walked: the object variable it bumped, the recognized method
/// spelling behind it, and where and on which line the call sits.
struct OpenCall {
    object: String,
    method: String,
    offset: usize,
    line: String,
}

/// Every bump and drop of a configured counter field in the body, in
/// source order: a configured field name hanging off a plain-owner
/// variable through `->` or `.`, followed by `++` or `+= 1` (a bump)
/// or `--` or `-= 1` (a drop). The scan runs outside string literals,
/// and a field name carried by a longer identifier names nothing. A
/// field reached through a chain or a dereference (`a->next->ref_count`,
/// `(*pObj)->ref_count`) hangs off no plain owner the pairing can key
/// on, and a comparison (`ref_count == 1`), a bare read, or a bump by
/// anything but one (`+= 2`) counts nothing.
fn count_sites<'a>(body: &'a str, fields: &[String]) -> Vec<CountSite<'a>> {
    let bytes = body.as_bytes();
    let mut sites = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => i = skip_string(bytes, i + 1),
            b if is_ident_byte(b) => {
                if i > 0 && is_ident_byte(bytes[i - 1]) {
                    i += 1;
                    continue;
                }
                let mut end = i;
                while end < bytes.len() && is_ident_byte(bytes[end]) {
                    end += 1;
                }
                let arrow = i >= 2 && bytes[i - 1] == b'>' && bytes[i - 2] == b'-';
                let dot = i >= 1 && bytes[i - 1] == b'.';
                if (arrow || dot)
                    && fields.iter().any(|f| f.as_str() == &body[i..end])
                    && let Some(owner_start) =
                        plain_owner_start(bytes, if arrow { i - 2 } else { i - 1 })
                    && let Some(bump) = bump_operator(bytes, end)
                {
                    sites.push(CountSite {
                        owner: &body[owner_start..if arrow { i - 2 } else { i - 1 }],
                        field: &body[i..end],
                        bump,
                        offset: i,
                        line: line_at(body, i),
                    });
                }
                i = end;
            }
            _ => i += 1,
        }
    }
    sites
}

/// The start of the plain owner identifier ending at `owner_end` —
/// the identifier immediately left of the `->` or `.` the counted
/// field hangs off — or `None` when nothing plain ends there: no
/// identifier at all, or one reached through a chain, a dereference,
/// or an index (`a->next->ref_count`, `(*pObj)->ref_count`,
/// `p[1]->ref_count`), where the owner is no variable the pairing can
/// key on.
fn plain_owner_start(bytes: &[u8], owner_end: usize) -> Option<usize> {
    let mut start = owner_end;
    while start > 0 && is_ident_byte(bytes[start - 1]) {
        start -= 1;
    }
    if start == owner_end {
        return None;
    }
    if start > 0 && matches!(bytes[start - 1], b'*' | b'&' | b'.' | b')' | b']' | b'>') {
        return None;
    }
    Some(start)
}

/// The direction the operator following a counter field moves it:
/// `true` for `++` and `+= 1`, `false` for `--` and `-= 1`, and
/// `None` for anything else — a comparison, a bare read, or a bump by
/// any other amount (`+= 2`, `+= 1u`).
fn bump_operator(bytes: &[u8], name_end: usize) -> Option<bool> {
    let i = skip_ws(bytes, name_end);
    let first = *bytes.get(i)?;
    let second = *bytes.get(i + 1)?;
    match (first, second) {
        (b'+', b'+') => Some(true),
        (b'-', b'-') => Some(false),
        (b'+', b'=') | (b'-', b'=') => {
            let n = skip_ws(bytes, i + 2);
            if bytes.get(n) == Some(&b'1')
                && !bytes
                    .get(n + 1)
                    .is_some_and(|b| is_ident_byte(*b) || *b == b'.')
            {
                Some(first == b'+')
            } else {
                None
            }
        }
        _ => None,
    }
}
/// The type words a Ghidra cast may spell, the decompiler's
/// vocabulary the other detectors' scans strip plus the interface
/// typedefs this detector's casts carry: COM analysis types an
/// `AddRef` or `Release` argument as `IUnknown *` or `IDispatch *`,
/// the pointer typedef a thread spawn passes its argument as
/// (`LPVOID`), and the decompiler writes those names on a cast when
/// the applied type differs from the callee's parameter.
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
            | "iunknown"
            | "idispatch"
            | "lpvoid"
    )
}

/// The argument text when it is one plain variable name — the spelling
/// a bump or drop names the counted object by. Anything else — a
/// dereferenced pointer, an offset into a table, a literal — names no
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

// ============================================================
// The standard name sets
// ============================================================

/// The standard counter field names: the field spellings a scan
/// recognizes as reference counts read through arithmetic —
/// `ref_count` and its compact and long spellings, and the
/// standard-library `use_count`. A bump on one name answers a drop on
/// that same name; the names never cross.
pub fn default_field_names() -> Vec<String> {
    vec![
        "ref_count".into(),
        "refcount".into(),
        "reference_count".into(),
        "use_count".into(),
    ]
}

/// The standard increment names: the method spellings a scan
/// recognizes as raising an object's reference count — the COM
/// `AddRef`.
pub fn default_increments() -> Vec<String> {
    vec!["AddRef".into()]
}

/// The standard decrement names: the method spellings a scan
/// recognizes as releasing an object's reference count — the COM
/// `Release`.
pub fn default_decrements() -> Vec<String> {
    vec!["Release".into()]
}

/// The standard thread-spawn names: the callee spellings a scan
/// recognizes as starting a thread that works through an argument —
/// the Win32 `CreateThread` and the CRT's `_beginthread`/
/// `_beginthreadex` twins, and the POSIX `pthread_create`. An object
/// handed to one of these reaches another thread, which is what turns
/// an `Rc<T>` reading into an `Arc<T>` one.
pub fn default_thread_spawns() -> Vec<String> {
    vec![
        "CreateThread".into(),
        "_beginthread".into(),
        "_beginthreadex".into(),
        "pthread_create".into(),
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
        let detector = ReferenceCountDetector::new();
        assert!(detector.fields().is_empty());
        assert!(detector.increments().is_empty());
        assert!(detector.decrements().is_empty());
        assert!(detector.thread_spawns().is_empty());
        assert_eq!(detector, ReferenceCountDetector::default());
        assert_eq!(detector.clone(), detector);
    }

    #[test]
    fn a_detector_keeps_the_names_it_is_configured_with() {
        let detector = ReferenceCountDetector::with_names(
            ["ref_count", "use_count"],
            ["AddRef"],
            ["Release"],
            ["CreateThread"],
        );
        // Configuration order is scan order: two detectors built the
        // same way see the same names in the same order.
        assert_eq!(detector.fields(), ["ref_count", "use_count"]);
        assert_eq!(detector.increments(), ["AddRef"]);
        assert_eq!(detector.decrements(), ["Release"]);
        assert_eq!(detector.thread_spawns(), ["CreateThread"]);
    }

    #[test]
    fn added_names_join_their_sets_in_order() {
        let mut detector = ReferenceCountDetector::new();
        detector.add_field("ref_count");
        detector.add_field("use_count");
        detector.add_increment("AddRef");
        detector.add_decrement("Release");
        detector.add_decrement("release");
        detector.add_thread_spawn("CreateThread");
        detector.add_thread_spawn("pthread_create");
        assert_eq!(detector.fields(), ["ref_count", "use_count"]);
        assert_eq!(detector.increments(), ["AddRef"]);
        assert_eq!(detector.decrements(), ["Release", "release"]);
        assert_eq!(detector.thread_spawns(), ["CreateThread", "pthread_create"]);
    }

    #[test]
    fn a_detector_can_be_shared_across_scans() {
        // One detector is driven concurrently over a program's
        // functions, so sharing one by reference across tasks must
        // stay sound.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ReferenceCountDetector>();
    }

    #[test]
    fn the_standard_field_names_name_the_counter_spellings() {
        assert_eq!(
            default_field_names(),
            ["ref_count", "refcount", "reference_count", "use_count"]
        );
    }

    #[test]
    fn the_standard_com_names_name_the_add_ref_and_release_pair() {
        assert_eq!(default_increments(), ["AddRef"]);
        assert_eq!(default_decrements(), ["Release"]);
    }

    #[test]
    fn the_standard_thread_spawns_name_the_win32_crt_and_posix_spawn_calls() {
        assert_eq!(
            default_thread_spawns(),
            [
                "CreateThread",
                "_beginthread",
                "_beginthreadex",
                "pthread_create"
            ]
        );
    }

    #[test]
    fn a_detector_built_with_the_standard_sets_carries_them() {
        let detector = ReferenceCountDetector::with_default_names();
        assert_eq!(detector.fields(), default_field_names());
        assert_eq!(detector.increments(), default_increments());
        assert_eq!(detector.decrements(), default_decrements());
        assert_eq!(detector.thread_spawns(), default_thread_spawns());
    }

    // ------------------------------------------------------------
    // COM method pairs
    // ------------------------------------------------------------

    fn function(body: &str) -> DecompiledFunction {
        DecompiledFunction {
            name: "FUN_18003ab00".into(),
            signature: "undefined FUN_18003ab00(void)".into(),
            body: body.into(),
        }
    }

    fn counts(body: &str) -> Vec<ReferenceCount> {
        ReferenceCountDetector::with_default_names().detect_reference_counts(&function(body))
    }

    #[test]
    fn an_add_ref_release_pair_is_detected() {
        let records = counts(
            "\
undefined4 FUN_18003ab00(IUnknown *param_1) {
  AddRef((IUnknown *)param_1);
  iVar1 = some_method(param_1);
  Release((IUnknown *)param_1);
  return iVar1;
}",
        );
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].function, "FUN_18003ab00");
        assert_eq!(records[0].style, CountStyle::ComMethods);
        // The record names the two recognized spellings the pairing
        // read, so a prompt sees which method bumped the count.
        assert_eq!(records[0].increment, "AddRef");
        assert_eq!(records[0].decrement, "Release");
        // The object stays inside this function: the manual counting
        // reads as the non-atomic shared owner.
        assert_eq!(records[0].suggestion, "Rc<T>");
        assert_eq!(records[0].confidence, COUNT_PAIR_CONFIDENCE);
        // The evidence carries both sides of the pairing.
        assert_eq!(
            records[0].evidence,
            "AddRef((IUnknown *)param_1); Release((IUnknown *)param_1);"
        );
    }

    #[test]
    fn a_cast_over_the_counted_object_is_seen_through() {
        let records = counts(
            "\
  AddRef((IUnknown *)param_1);
  Release((IUnknown *)param_1);",
        );
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].style, CountStyle::ComMethods);
    }

    #[test]
    fn a_qualified_method_spelling_names_the_pair() {
        // Ghidra writes the interface-qualified thunk spelling; the
        // `::` separators break the name, and the method word behind
        // them is the recognized callee.
        let records = counts(
            "\
  IUnknown::AddRef(param_1);
  IUnknown::Release(param_1);",
        );
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].increment, "AddRef");
        assert_eq!(records[0].decrement, "Release");
    }

    #[test]
    fn an_increment_with_no_decrement_is_not_reported() {
        // Whether the extra reference escapes or leaks is a
        // cross-function question; this pairing stays quiet on it.
        assert!(
            counts(
                "\
  AddRef((IUnknown *)param_1);
  return param_1;"
            )
            .is_empty()
        );
    }

    #[test]
    fn a_decrement_before_the_increment_pairs_nothing() {
        // The drop answers an earlier bump, not the one the body
        // raises after it.
        assert!(
            counts(
                "\
  Release((IUnknown *)param_1);
  AddRef((IUnknown *)param_1);"
            )
            .is_empty()
        );
    }

    #[test]
    fn a_bump_and_drop_of_different_objects_pair_nothing() {
        assert!(
            counts(
                "\
  AddRef((IUnknown *)param_1);
  Release((IUnknown *)param_2);"
            )
            .is_empty()
        );
    }

    #[test]
    fn a_bump_naming_something_other_than_a_variable_pairs_nothing() {
        // A dereferenced pointer names no variable the pairing can
        // key on.
        assert!(
            counts(
                "\
  AddRef(*ppObj);
  Release(*ppObj);"
            )
            .is_empty()
        );
    }

    #[test]
    fn two_bumps_and_two_drops_pair_in_bump_order() {
        // Drops answer out of nesting order, but the records come
        // back in bump order so two scans diff cleanly.
        let records = counts(
            "\
  AddRef((IUnknown *)param_1);
  AddRef((IUnknown *)param_2);
  Release((IUnknown *)param_2);
  Release((IUnknown *)param_1);",
        );
        assert_eq!(records.len(), 2);
        assert_eq!(
            records[0].evidence,
            "AddRef((IUnknown *)param_1); Release((IUnknown *)param_1);"
        );
        assert_eq!(
            records[1].evidence,
            "AddRef((IUnknown *)param_2); Release((IUnknown *)param_2);"
        );
    }

    #[test]
    fn one_drop_answers_the_latest_bump_of_a_reused_variable() {
        let records = counts(
            "\
  AddRef((IUnknown *)param_1);
  AddRef((IUnknown *)param_1);
  Release((IUnknown *)param_1);",
        );
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].evidence,
            "AddRef((IUnknown *)param_1); Release((IUnknown *)param_1);"
        );
    }

    #[test]
    fn a_member_spelling_or_a_longer_name_matches_no_configured_name() {
        // Whole plain calls only: a member access through an object
        // is no call the pairing reads, and a longer spelling is a
        // different callee.
        assert!(
            counts(
                "\
  param_1->AddRef(param_1);
  MyRelease(param_1);
  Release2(param_1);"
            )
            .is_empty()
        );
    }

    #[test]
    fn a_name_spelled_inside_a_string_literal_invents_no_pair() {
        assert!(counts("  printf(\"AddRef then Release\");").is_empty());
    }

    #[test]
    fn a_truncated_body_pairs_nothing() {
        assert!(counts("  AddRef((IUnknown *)param_1;").is_empty());
    }

    // ------------------------------------------------------------
    // Field arithmetic pairs
    // ------------------------------------------------------------

    #[test]
    fn a_ref_count_bump_and_drop_are_detected() {
        let records = counts(
            "\
void FUN_18003ab00(void) {
  param_1->ref_count++;
  uVar2 = read_something(param_1);
  param_1->ref_count--;
  return;
}",
        );
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].function, "FUN_18003ab00");
        assert_eq!(records[0].style, CountStyle::FieldArithmetic);
        // The record names the two recognized spellings the pairing
        // read, so a prompt sees which field carried the count.
        assert_eq!(records[0].increment, "ref_count++");
        assert_eq!(records[0].decrement, "ref_count--");
        assert_eq!(records[0].suggestion, "Rc<T>");
        assert_eq!(records[0].confidence, COUNT_PAIR_CONFIDENCE);
        assert_eq!(
            records[0].evidence,
            "param_1->ref_count++; param_1->ref_count--;"
        );
    }

    #[test]
    fn the_compound_assignment_forms_pair() {
        let records = counts(
            "\
  param_1->ref_count += 1;
  param_1->ref_count -= 1;",
        );
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].style, CountStyle::FieldArithmetic);
    }

    #[test]
    fn a_bump_on_one_owner_does_not_answer_a_drop_on_another() {
        // The owner is part of the counter's identity: two objects
        // carrying the same field name count separately.
        assert!(
            counts(
                "\
  a->ref_count++;
  b->ref_count--;"
            )
            .is_empty()
        );
    }

    #[test]
    fn independent_owners_each_pair_in_bump_order() {
        let records = counts(
            "\
  a->ref_count++;
  b->ref_count++;
  b->ref_count--;
  a->ref_count--;",
        );
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].evidence, "a->ref_count++; a->ref_count--;");
        assert_eq!(records[1].evidence, "b->ref_count++; b->ref_count--;");
    }

    #[test]
    fn one_drop_answers_the_latest_bump_of_a_field() {
        // Two bumps under one owner and field, one drop: the drop
        // answers the second, and the first stands unpaired.
        let records = counts(
            "\
  p->ref_count = 2;
  p->ref_count++;
  p->ref_count++;
  p->ref_count--;",
        );
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].evidence, "p->ref_count++; p->ref_count--;");
    }

    #[test]
    fn a_comparison_or_a_bare_read_is_not_a_bump() {
        // The `==` moves nothing, and the verbose rewrite
        // `x = x + 1` is an assignment, not the bump shape the
        // pairing reads.
        assert!(
            counts(
                "\
  if (p->ref_count == 1) { iVar1 = 1; }
  p->ref_count = p->ref_count + 1;"
            )
            .is_empty()
        );
    }

    #[test]
    fn a_bump_by_any_other_amount_is_not_a_bump() {
        // Only a move by one reads as counting: `+= 2` scales a
        // value, and `+= 1u` carries the constant's type suffix.
        assert!(
            counts(
                "\
  p->ref_count += 2;
  p->ref_count -= 2;
  p->ref_count += 1u;
  p->ref_count -= 1u;"
            )
            .is_empty()
        );
    }

    #[test]
    fn a_longer_name_or_a_string_names_no_bump() {
        // Whole field names outside string literals only: a longer
        // spelling is a different field, and the field's letters
        // inside a format string name nothing.
        assert!(
            counts(
                "\
  p->ref_count_x++;
  p->ref_count_x--;
  printf(\"ref_count++\");
  printf(\"ref_count--\");"
            )
            .is_empty()
        );
    }

    #[test]
    fn a_chained_or_dereferenced_owner_names_no_pair() {
        // The owner must be one plain variable: a field reached
        // through a chain or a dereference hangs off something the
        // pairing cannot key on.
        assert!(
            counts(
                "\
  a->next->ref_count++;
  (*pObj)->ref_count--;"
            )
            .is_empty()
        );
    }

    #[test]
    fn a_pair_inside_a_loop_body_is_detected() {
        let records = counts(
            "\
  while (iVar1 != 0) {
    param_1->ref_count++;
    param_1->ref_count--;
  }",
        );
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].style, CountStyle::FieldArithmetic);
    }

    // ------------------------------------------------------------
    // Shared-ownership suggestions
    // ------------------------------------------------------------

    #[test]
    fn an_object_handed_to_create_thread_suggests_arc() {
        // The new thread works through the same interface pointer, so
        // the count is shared across threads and only an atomic count
        // is safe there.
        let records = counts(
            "\
undefined FUN_18003ab00(IUnknown *param_1) {
  AddRef((IUnknown *)param_1);
  hThread = CreateThread(0,0,thread_main,(LPVOID)param_1,0,0);
  Release((IUnknown *)param_1);
  return;
}",
        );
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].suggestion, "Arc<T>");
        assert_eq!(records[0].confidence, ARC_CONFIDENCE);
    }

    #[test]
    fn a_field_owner_handed_to_a_thread_suggests_arc() {
        // The narrowing keys on the owner the field arithmetic names,
        // not only on COM objects.
        let records = counts(
            "\
  obj->ref_count++;
  pthread_create(&local_10,0,worker,(void *)obj);
  obj->ref_count--;",
        );
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].suggestion, "Arc<T>");
    }

    #[test]
    fn the_spawn_may_sit_before_the_bump() {
        // The object reaches the thread wherever the spawn sits in
        // the body; the count is shared either way.
        let records = counts(
            "\
  CreateThread(0,0,thread_main,(LPVOID)param_1,0,0);
  AddRef((IUnknown *)param_1);
  Release((IUnknown *)param_1);",
        );
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].suggestion, "Arc<T>");
    }

    #[test]
    fn a_spawn_naming_another_variable_keeps_rc() {
        // The spawn shares that other object, not the counted one.
        let records = counts(
            "\
  AddRef((IUnknown *)param_1);
  CreateThread(0,0,thread_main,(LPVOID)param_2,0,0);
  Release((IUnknown *)param_1);",
        );
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].suggestion, "Rc<T>");
        assert_eq!(records[0].confidence, COUNT_PAIR_CONFIDENCE);
    }

    #[test]
    fn each_object_takes_its_own_reading() {
        // One pair's object reaches a thread and the other's does
        // not: the two records carry the two patterns.
        let records = counts(
            "\
  AddRef((IUnknown *)param_1);
  AddRef((IUnknown *)param_2);
  CreateThread(0,0,thread_main,(LPVOID)param_2,0,0);
  Release((IUnknown *)param_2);
  Release((IUnknown *)param_1);",
        );
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].suggestion, "Rc<T>");
        assert_eq!(records[1].suggestion, "Arc<T>");
    }

    #[test]
    fn a_spawn_name_inside_a_string_invents_no_narrowing() {
        let records = counts(
            "\
  AddRef((IUnknown *)param_1);
  printf(\"CreateThread %p\", param_1);
  Release((IUnknown *)param_1);",
        );
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].suggestion, "Rc<T>");
    }

    #[test]
    fn a_longer_spawn_name_names_no_spawn() {
        // Whole names only: a longer spelling is a different callee.
        let records = counts(
            "\
  AddRef((IUnknown *)param_1);
  MyCreateThread((LPVOID)param_1);
  Release((IUnknown *)param_1);",
        );
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].suggestion, "Rc<T>");
    }

    #[test]
    fn a_thread_argument_that_is_not_a_plain_variable_keeps_rc() {
        // `&obj` passes the variable's own storage, not the object
        // the pairing keyed on; nothing here names the counted object
        // to the new thread.
        let records = counts(
            "\
  obj->ref_count++;
  pthread_create(&local_10,0,worker,&obj);
  obj->ref_count--;",
        );
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].suggestion, "Rc<T>");
    }

    #[test]
    fn custom_thread_spawn_names_narrow_too() {
        let mut detector = ReferenceCountDetector::new();
        detector.add_field("mCount");
        detector.add_thread_spawn("spawn_worker");
        let records = detector.detect_reference_counts(&function(
            "\
  obj->mCount++;
  spawn_worker(obj);
  obj->mCount--;",
        ));
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].suggestion, "Arc<T>");
    }

    #[test]
    fn a_detector_without_thread_spawn_names_never_narrows() {
        let mut detector = ReferenceCountDetector::new();
        detector.add_field("ref_count");
        let records = detector.detect_reference_counts(&function(
            "\
  obj->ref_count++;
  CreateThread(0,0,thread_main,(LPVOID)obj,0,0);
  obj->ref_count--;",
        ));
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].suggestion, "Rc<T>");
    }

    // ------------------------------------------------------------
    // Shapes and configuration
    // ------------------------------------------------------------

    #[test]
    fn the_shapes_do_not_cross_pair() {
        // A method drop answers a method bump and a field drop
        // answers a field bump; neither spelling answers the other
        // shape's bump.
        assert!(
            counts(
                "\
  AddRef((IUnknown *)param_1);
  param_1->ref_count--;"
            )
            .is_empty()
        );
        assert!(
            counts(
                "\
  param_1->ref_count++;
  Release((IUnknown *)param_1);"
            )
            .is_empty()
        );
    }

    #[test]
    fn both_shapes_report_in_bump_order() {
        // The two shape readings merge into one source-ordered list
        // so two scans of one body diff cleanly.
        let records = counts(
            "\
  AddRef((IUnknown *)param_1);
  param_1->ref_count++;
  param_1->ref_count--;
  Release((IUnknown *)param_1);",
        );
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].increment, "AddRef");
        assert_eq!(records[1].increment, "ref_count++");
    }

    #[test]
    fn a_detector_with_no_names_detects_nothing() {
        let detector = ReferenceCountDetector::new();
        let records = detector.detect_reference_counts(&function(
            "\
  AddRef((IUnknown *)param_1);
  Release((IUnknown *)param_1);
  param_1->ref_count++;
  param_1->ref_count--;",
        ));
        assert!(records.is_empty());
    }

    #[test]
    fn custom_names_pair_like_the_standard_ones() {
        let mut detector = ReferenceCountDetector::new();
        detector.add_field("mCount");
        detector.add_increment("retain");
        detector.add_decrement("release");
        let records = detector.detect_reference_counts(&function(
            "\
  obj->mCount++;
  obj->mCount--;
  retain(p);
  release(p);",
        ));
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].style, CountStyle::FieldArithmetic);
        assert_eq!(records[0].increment, "mCount++");
        assert_eq!(records[0].decrement, "mCount--");
        assert_eq!(records[1].style, CountStyle::ComMethods);
        assert_eq!(records[1].increment, "retain");
        assert_eq!(records[1].decrement, "release");
        // No spawn names configured: both pairs keep the plain
        // shared-ownership reading.
        for record in &records {
            assert_eq!(record.suggestion, "Rc<T>");
        }
    }
}
