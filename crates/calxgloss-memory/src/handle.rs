//! Handle lifecycle detection.
//!
//! This module provides [`HandleDetector`], which carries the opener
//! and closer names a scan reads decompiled bodies against — the
//! Win32 `CreateFileW` and its ANSI twin `CreateFileA` closed by
//! `CloseHandle`, and the C stdio `fopen` closed by `fclose` —
//! pairing each open with its close inside a single function so the
//! prompt can suggest an RAII guard struct with a `Drop` impl
//! standing in for the manual close.
//!
//! Each recognized name is a [`HandleSignature`]: the callee spelling
//! as the decompiler writes it and the [`HandleType`] family it stands
//! for, on the opening side or the closing one. [`default_openers`]
//! and [`default_closers`] carry the standard name sets, and
//! [`HandleDetector::with_default_names`] builds a detector that
//! scans against them.
//!
//! [`HandleDetector::detect_handles`] runs the reading: it walks a
//! decompiled body's direct calls in source order, binds each
//! recognized open to the variable the decompiler stores its result
//! in, and closes that handle when a recognized closer of the same
//! family names the same variable — one [`HandleLifecycle`] per pair.
//! The pairing carries the guard pattern that stands in for the
//! manual close: a whole-scope guard wherever the handle is dead at
//! its close, a guard scoped to the open-to-close span wherever the
//! body reads the handle value after the close.

use crate::types::{HandleLifecycle, HandleType};
use calxgloss_ghidra::DecompiledFunction;
use serde::{Deserialize, Serialize};

// ============================================================
// Handle names
// ============================================================

/// One handle name the detector recognizes: the callee spelling and
/// the handle family it stands for, as an opener or as a closer.
///
/// A signature is a name, not a shape: it only says that a call to
/// [`name`](Self::name) opens or closes a handle of
/// [`handle_type`](Self::handle_type) — `CreateFileW` a kernel object
/// handle, `fclose` a stdio stream — while where the call sits in the
/// function and which open its closer answers is the detector's
/// reading. The family is what keeps the two sides straight: a closer
/// only pairs with an open of its own family.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandleSignature {
    /// The callee spelling as the decompiler writes it, e.g.
    /// `CreateFileW`, `fclose`.
    pub name: String,
    /// The handle family this spelling stands for.
    pub handle_type: HandleType,
}

impl HandleSignature {
    /// A signature recognizing the callee spelling `name` as an open
    /// or close of a `handle_type` handle.
    pub fn new(name: impl Into<String>, handle_type: HandleType) -> Self {
        Self {
            name: name.into(),
            handle_type,
        }
    }
}

// ============================================================
// Detector
// ============================================================

/// Handle open/close pair tracking over decompiled functions.
///
/// The detector owns the name set a scan reads bodies against:
/// [`HandleSignature`] records for the opening side and for the
/// closing side. Both sets are configurable — supply them whole
/// through [`with_names`](Self::with_names) or grow them one name at
/// a time with [`add_opener`](Self::add_opener) and
/// [`add_closer`](Self::add_closer) — and [`openers`](Self::openers)
/// and [`closers`](Self::closers) report them in configuration order,
/// so two detectors built the same way scan identically and results
/// diff cleanly. The detector holds no Ghidra client of its own and
/// never writes back to the program; one detector serves an entire
/// scan and can be shared by reference across concurrent per-function
/// passes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HandleDetector {
    openers: Vec<HandleSignature>,
    closers: Vec<HandleSignature>,
}

impl HandleDetector {
    /// A detector with no names configured: every body it is handed
    /// pairs nothing until the standard sets arrive through
    /// [`with_default_names`](Self::with_default_names) or names join
    /// one at a time through [`add_opener`](Self::add_opener) and
    /// [`add_closer`](Self::add_closer).
    pub fn new() -> Self {
        Self::default()
    }

    /// A detector that scans against the standard name sets —
    /// [`default_openers`] and [`default_closers`] — in their
    /// configuration order.
    pub fn with_default_names() -> Self {
        Self::with_names(default_openers(), default_closers())
    }

    /// A detector that scans against exactly `openers` and `closers`,
    /// each kept in the order it is given.
    pub fn with_names(
        openers: impl IntoIterator<Item = HandleSignature>,
        closers: impl IntoIterator<Item = HandleSignature>,
    ) -> Self {
        Self {
            openers: openers.into_iter().collect(),
            closers: closers.into_iter().collect(),
        }
    }

    /// Add one opener name to the set this detector scans against.
    pub fn add_opener(&mut self, opener: HandleSignature) {
        self.openers.push(opener);
    }

    /// Add one closer name to the set this detector scans against.
    pub fn add_closer(&mut self, closer: HandleSignature) {
        self.closers.push(closer);
    }

    /// The opener names this detector scans against, in
    /// configuration order.
    pub fn openers(&self) -> &[HandleSignature] {
        &self.openers
    }

    /// The closer names this detector scans against, in
    /// configuration order.
    pub fn closers(&self) -> &[HandleSignature] {
        &self.closers
    }

    /// The open/close pairs one function's body carries.
    ///
    /// The reading walks the body's direct calls in source order —
    /// outside string literals, whole names only — and classifies each
    /// against the configured sets. An open counts only where its
    /// result is stored into a plain variable, the spelling the
    /// decompiler writes on the assignment (`hFile =
    /// CreateFileW(...);`); a close counts only where its first
    /// argument, seen through any cast, names one plain variable
    /// (`CloseHandle(hFile);`). A closer answers the most recent
    /// still-open handle of the variable it names *and its own
    /// family* — so where a variable is opened twice before one
    /// close, the close pairs with the second handle and the first
    /// stands unpaired, and a closer of another family (`fclose` on a
    /// kernel object handle) pairs with nothing — and an open with no
    /// close naming its variable in this function is reported by
    /// nothing: whether the handle escapes or leaks is a cross-function
    /// question, outside this pairing.
    ///
    /// Each pair becomes one [`HandleLifecycle`] naming the family,
    /// the two recognized spellings that opened and closed the
    /// handle, and the guard pattern standing in for the manual
    /// close — [`GUARD_SUGGESTION`] at [`HANDLE_PAIR_CONFIDENCE`],
    /// narrowed to [`SCOPED_GUARD_SUGGESTION`] at
    /// [`SCOPED_GUARD_CONFIDENCE`] where the body reads the handle
    /// value after the close — with the open line and the close line
    /// joined as the evidence. Records come back in open order, so
    /// two scans of one body diff cleanly.
    pub fn detect_handles(&self, func: &DecompiledFunction) -> Vec<HandleLifecycle> {
        let calls = direct_calls(&func.body);
        let mut open: Vec<OpenHandle> = Vec::new();
        let mut pairs: Vec<(usize, HandleLifecycle)> = Vec::new();
        for call in &calls {
            if let Some(signature) = self.openers.iter().find(|o| o.name == call.callee) {
                // An open the body stores nowhere the pairing can key
                // on names no handle this function closes.
                if let Some(variable) = assigned_variable(&func.body, call.offset) {
                    open.push(OpenHandle {
                        variable: variable.to_string(),
                        handle_type: signature.handle_type,
                        opener: signature.name.clone(),
                        offset: call.offset,
                        line: line_at(&func.body, call.offset),
                    });
                }
            } else if let Some(signature) = self.closers.iter().find(|c| c.name == call.callee) {
                let closed = call.args.first().map(|arg| strip_casts(arg));
                if let Some(closed) = closed.as_deref().and_then(plain_variable)
                    && let Some(at) = open.iter().rposition(|o| {
                        o.variable == closed && o.handle_type == signature.handle_type
                    })
                {
                    let handle = open.remove(at);
                    let (suggestion, confidence) =
                        if self.read_after_close(&func.body, &calls, closed, call.close) {
                            (SCOPED_GUARD_SUGGESTION, SCOPED_GUARD_CONFIDENCE)
                        } else {
                            (GUARD_SUGGESTION, HANDLE_PAIR_CONFIDENCE)
                        };
                    pairs.push((
                        handle.offset,
                        HandleLifecycle {
                            function: func.name.clone(),
                            handle_type: handle.handle_type,
                            opener: handle.opener,
                            closer: signature.name.clone(),
                            suggestion: suggestion.to_string(),
                            confidence: confidence.into(),
                            evidence: format!(
                                "{} {}",
                                handle.line,
                                line_at(&func.body, call.offset)
                            ),
                        },
                    ));
                }
            }
        }
        pairs.sort_by_key(|(offset, _)| *offset);
        pairs.into_iter().map(|(_, record)| record).collect()
    }

    /// Whether the body reads a closed handle's variable after the
    /// close that released it: a whole-word occurrence of the name
    /// outside string literals, past the closing `)` at `closed_at`,
    /// that is neither the first argument of a later recognized open
    /// or close — where the name belongs to another handle's
    /// lifecycle, the decompiler reusing the variable being idiomatic
    /// — nor the target of a plain assignment, the decompiler
    /// rebinding the name to a new handle or clearing it. A
    /// comparison, a return, or an argument to any other call reads
    /// the closed handle's value, and a value read after its close
    /// outlives any guard that would own it.
    fn read_after_close(
        &self,
        body: &str,
        calls: &[CallSite<'_>],
        variable: &str,
        closed_at: usize,
    ) -> bool {
        let bytes = body.as_bytes();
        let name = variable.as_bytes();
        let mut i = closed_at + 1;
        while i < bytes.len() {
            match bytes[i] {
                b'"' => i = skip_string(bytes, i + 1),
                b if is_ident_byte(b) => {
                    if i > 0 && is_ident_byte(bytes[i - 1]) {
                        i += 1;
                        continue;
                    }
                    let end = i + name.len();
                    if bytes.get(i..end) != Some(name)
                        || bytes.get(end).is_some_and(|b| is_ident_byte(*b))
                    {
                        while i < bytes.len() && is_ident_byte(bytes[i]) {
                            i += 1;
                        }
                        continue;
                    }
                    if !self.inside_recognized_call(calls, i) && !rebinds_variable(body, end) {
                        return true;
                    }
                    i = end;
                }
                _ => i += 1,
            }
        }
        false
    }

    /// Whether the occurrence at `at` sits inside a call to one of
    /// this detector's recognized opener or closer names — a mention
    /// belonging to another handle's open or close rather than a
    /// read of the closed one.
    fn inside_recognized_call(&self, calls: &[CallSite<'_>], at: usize) -> bool {
        calls.iter().any(|call| {
            (self.openers.iter().any(|o| o.name == call.callee)
                || self.closers.iter().any(|c| c.name == call.callee))
                && call.offset <= at
                && at < call.close
        })
    }
}

// ============================================================
// The pairing reading
// ============================================================

/// Confidence of a pairing read from an open and a close of the same
/// variable in one body: both sides are explicit calls to recognized
/// names, and the variable the decompiler stored the opener's result
/// into is the variable the closer names — but the tie between them
/// is the decompiler's naming, not resolved data flow, and a branch
/// could leave either side unreached. The failure check every handle
/// opener invites (`if (hFile == INVALID_HANDLE_VALUE)`) sits between
/// the two sides without strengthening or weakening either.
const HANDLE_PAIR_CONFIDENCE: u8 = 70;

/// The Rust pattern an open/close pairing stands in for: a guard
/// struct that owns the handle and calls the closer in its `Drop`, so
/// the manual close disappears and every exit path — including the
/// early returns a failure check invites — still releases the handle.
const GUARD_SUGGESTION: &str = "RAII guard struct with Drop impl";

/// The pattern a pairing reads as where the body reads the handle
/// value after the close: the value outlives the close, so a guard
/// cannot own the handle for the whole enclosing scope — it owns the
/// open-to-close span, and the rest of the body keeps the bare value.
const SCOPED_GUARD_SUGGESTION: &str = "scoped RAII guard struct with Drop impl";

/// Confidence of the scoped narrowing: the pairing evidence is
/// [`HANDLE_PAIR_CONFIDENCE`]'s, but the narrowing rests on reading
/// what each later naming of the variable is — a read of the closed
/// handle rather than the decompiler rebinding the name to a new
/// handle or clearing it — and a misread there scopes a guard that
/// did not need scoping.
const SCOPED_GUARD_CONFIDENCE: u8 = 65;

/// A handle still waiting for its close while the body is walked: the
/// variable holding it, the family behind it, the recognized opener
/// spelling that obtained it, and where and on which line the open
/// sits.
struct OpenHandle {
    variable: String,
    handle_type: HandleType,
    opener: String,
    offset: usize,
    line: String,
}

/// The control-flow keywords Ghidra writes with a parenthesised
/// operand; none of them is a callee.
const NON_CALL_KEYWORDS: [&str; 7] = ["if", "while", "for", "switch", "case", "return", "sizeof"];

/// A direct call found in a body: the callee name, the text of each
/// top-level argument, and the byte offsets of the callee and of the
/// call's closing `)`.
struct CallSite<'a> {
    callee: &'a str,
    args: Vec<&'a str>,
    offset: usize,
    close: usize,
}

/// Every direct call `name(args)` in the body whose callee is a plain
/// identifier, scanned outside string literals so a stray `(` in a
/// format string cannot be read as a call. A name preceded by an
/// identifier byte is the tail of a longer identifier, and one
/// preceded by a `>` is a member access through a pointer; neither is
/// a plain call. Like the allocator tracker's scan this one keeps a
/// demangled spelling whole: a `.` followed by an identifier byte
/// continues the name — Ghidra writes demangled `operator new` as
/// `operator.new` — and a trailing `[]` belongs to the name too. A
/// call whose `(` never closes — a truncated decompile — yields
/// nothing, and nested calls are each visited, so
/// `fclose(fopen(name, mode))` yields both sites.
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
                while j < bytes.len() {
                    // A `.` followed by an identifier byte continues
                    // the name: Ghidra writes demangled `operator new`
                    // as `operator.new`.
                    let continues = is_ident_byte(bytes[j])
                        || (bytes[j] == b'.'
                            && bytes
                                .get(j + 1)
                                .is_some_and(|b| b.is_ascii_alphabetic() || *b == b'_'));
                    if continues {
                        j += 1;
                    } else {
                        break;
                    }
                }
                // The array spelling carries its brackets: `operator.new[]`.
                let mut name_end = j;
                let bracket = skip_ws(bytes, j);
                if bytes.get(bracket) == Some(&b'[')
                    && bytes.get(skip_ws(bytes, bracket + 1)) == Some(&b']')
                {
                    name_end = skip_ws(bytes, bracket + 1) + 1;
                }
                let open = skip_ws(bytes, name_end);
                if bytes.get(open) == Some(&b'(')
                    && !NON_CALL_KEYWORDS.contains(&&body[i..j])
                    && let Some(close) = closing_paren(body, open)
                {
                    calls.push(CallSite {
                        callee: &body[i..name_end],
                        args: split_arguments(body, open, close),
                        offset: i,
                        close,
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
/// argument rather than splitting it. `CreateFileW` takes seven
/// arguments; only the pairing's first-argument reading cares which
/// is which.
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

/// The variable a call's result is stored into, read from the call's
/// own line: walking left from the callee to the `=` that assigns,
/// the plain identifier sitting left of that `=`. A `=` that is part
/// of a comparison (`==`, `!=`, `<=`, `>=`) or a compound assignment
/// (`+=` and friends) assigns no result, and a target that is not a
/// plain variable — a dereference, an indexed element, a field —
/// stores the handle somewhere the pairing cannot key on, so neither
/// binds anything.
fn assigned_variable(body: &str, callee_offset: usize) -> Option<&str> {
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
    Some(&line[start..end])
}

/// A call argument with Ghidra casts stripped: the decompiler writes
/// `CloseHandle((HANDLE)hFile)` when the argument's applied type
/// differs from the callee's parameter, and the value behind the cast
/// is the handle the close names.
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
/// a group holding only type words and stars, like `(HANDLE)` or
/// `(FILE *)` — and `None` when it opens a call or a grouped
/// expression instead.
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

/// The type words a Ghidra cast may spell, the decompiler's
/// vocabulary the other detectors' scans strip plus the handle
/// typedefs this detector's casts carry: win32 analysis types a
/// `CreateFile` result as `HANDLE` and a `fopen` result as `FILE *`,
/// and the decompiler writes those names on a cast when the applied
/// type differs from the callee's parameter.
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
            | "handle"
            | "file"
    )
}

/// The argument text when it is one plain variable name — the spelling
/// a close names the handle it closes by. Anything else — an offset
/// into the handle table, a dereferenced pointer, a literal — names no
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

/// Whether the variable occurrence ending at `name_end` opens a plain
/// assignment — the decompiler rebinding the name to a new handle or
/// clearing it — rather than reading the value it held. A comparison
/// (`==`, `!=`, `<=`, `>=`) or a compound assignment (`+=` and
/// friends) reads the value, so it is no rebinding.
fn rebinds_variable(body: &str, name_end: usize) -> bool {
    let rest = body[name_end..].trim_start();
    let Some(rest) = rest.strip_prefix('=') else {
        return false;
    };
    !rest.starts_with('=')
}

// ============================================================
// The standard name sets
// ============================================================

/// The standard opener names: the spellings a scan recognizes as
/// handle opens out of the box — the Win32 `CreateFileW` and its ANSI
/// twin `CreateFileA`, each standing for a kernel object handle, and
/// the C stdio `fopen`, standing for a stream. Each name carries the
/// family it stands for, so a recognized closer knows which opens it
/// could answer.
pub fn default_openers() -> Vec<HandleSignature> {
    vec![
        HandleSignature::new("CreateFileW", HandleType::KernelObject),
        HandleSignature::new("CreateFileA", HandleType::KernelObject),
        HandleSignature::new("fopen", HandleType::FileStream),
    ]
}

/// The standard closer names: the spellings a scan recognizes as
/// handle releases — `CloseHandle`, which closes any kernel object
/// handle however it was obtained, and `fclose`, which closes a stdio
/// stream. Each carries the family it closes, so a closer of one
/// family never answers an open of another.
pub fn default_closers() -> Vec<HandleSignature> {
    vec![
        HandleSignature::new("CloseHandle", HandleType::KernelObject),
        HandleSignature::new("fclose", HandleType::FileStream),
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
        let detector = HandleDetector::new();
        assert!(detector.openers().is_empty());
        assert!(detector.closers().is_empty());
        assert_eq!(detector, HandleDetector::default());
        assert_eq!(detector.clone(), detector);
    }

    #[test]
    fn a_detector_keeps_the_names_it_is_configured_with() {
        let detector = HandleDetector::with_names(
            [
                HandleSignature::new("CreateFileW", HandleType::KernelObject),
                HandleSignature::new("fopen", HandleType::FileStream),
            ],
            [HandleSignature::new("fclose", HandleType::FileStream)],
        );
        // Configuration order is scan order: two detectors built the
        // same way see the same names in the same order.
        assert_eq!(detector.openers().len(), 2);
        assert_eq!(detector.openers()[0].name, "CreateFileW");
        assert_eq!(detector.openers()[1].handle_type, HandleType::FileStream);
        assert_eq!(detector.closers().len(), 1);
        assert_eq!(detector.closers()[0].name, "fclose");
    }

    #[test]
    fn added_names_join_their_sets_in_order() {
        let mut detector = HandleDetector::new();
        detector.add_opener(HandleSignature::new(
            "CreateFileW",
            HandleType::KernelObject,
        ));
        detector.add_opener(HandleSignature::new("fopen", HandleType::FileStream));
        detector.add_closer(HandleSignature::new(
            "CloseHandle",
            HandleType::KernelObject,
        ));
        detector.add_closer(HandleSignature::new("fclose", HandleType::FileStream));
        let openers: Vec<&str> = detector.openers().iter().map(|o| o.name.as_str()).collect();
        let closers: Vec<&str> = detector.closers().iter().map(|c| c.name.as_str()).collect();
        assert_eq!(openers, ["CreateFileW", "fopen"]);
        assert_eq!(closers, ["CloseHandle", "fclose"]);
    }

    #[test]
    fn a_detector_can_be_shared_across_scans() {
        // One detector is driven concurrently over a program's
        // functions, so sharing one by reference across tasks must
        // stay sound.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<HandleDetector>();
    }

    #[test]
    fn a_handle_signature_serde_round_trips() {
        let signature = HandleSignature::new("CreateFileA", HandleType::KernelObject);
        let json = serde_json::to_string(&signature).unwrap();
        assert!(json.contains("\"handle_type\":\"kernel_object\""));
        let back: HandleSignature = serde_json::from_str(&json).unwrap();
        assert_eq!(back, signature);
    }

    #[test]
    fn a_handle_signature_reads_back_with_its_spelling() {
        // Documents persisted for a custom name set still load.
        let json = r#"{
            "name": "open",
            "handle_type": "file_stream"
        }"#;
        let back: HandleSignature = serde_json::from_str(json).unwrap();
        assert_eq!(back.name, "open");
        assert_eq!(back.handle_type, HandleType::FileStream);
    }

    #[test]
    fn the_standard_openers_name_the_win32_and_stdio_families() {
        let openers = default_openers();
        let named: Vec<(&str, HandleType)> = openers
            .iter()
            .map(|o| (o.name.as_str(), o.handle_type))
            .collect();
        assert_eq!(
            named,
            [
                ("CreateFileW", HandleType::KernelObject),
                ("CreateFileA", HandleType::KernelObject),
                ("fopen", HandleType::FileStream),
            ]
        );
    }

    #[test]
    fn the_standard_closers_name_the_kernel_and_stdio_releases() {
        let closers = default_closers();
        let named: Vec<(&str, HandleType)> = closers
            .iter()
            .map(|c| (c.name.as_str(), c.handle_type))
            .collect();
        assert_eq!(
            named,
            [
                ("CloseHandle", HandleType::KernelObject),
                ("fclose", HandleType::FileStream),
            ]
        );
    }

    #[test]
    fn a_detector_built_with_the_standard_sets_carries_them() {
        let detector = HandleDetector::with_default_names();
        assert_eq!(detector.openers(), default_openers());
        assert_eq!(detector.closers(), default_closers());
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

    fn pairs(body: &str) -> Vec<HandleLifecycle> {
        HandleDetector::with_default_names().detect_handles(&function(body))
    }

    #[test]
    fn a_create_file_close_handle_pair_is_detected() {
        let records = pairs(
            "\
undefined FUN_18003ab00(void) {
  hFile = CreateFileW(&DAT_3801a2b0,0xc0000000,0,(LPSECURITY_ATTRIBUTES)0x0,3,0x80,0);
  iVar1 = ReadFile(hFile,&local_20,4,&local_18,(LPOVERLAPPED)0x0);
  CloseHandle(hFile);
  return;
}",
        );
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].function, "FUN_18003ab00");
        assert_eq!(records[0].handle_type, HandleType::KernelObject);
        // The record names the two recognized spellings the pairing
        // read, so a prompt sees which opener obtained the handle.
        assert_eq!(records[0].opener, "CreateFileW");
        assert_eq!(records[0].closer, "CloseHandle");
        // The reads between the sides sit inside the handle's life,
        // and nothing names the handle after the close: the guard can
        // own it for the whole scope.
        assert_eq!(records[0].suggestion, "RAII guard struct with Drop impl");
        assert_eq!(records[0].confidence, HANDLE_PAIR_CONFIDENCE);
        // The evidence carries both sides of the pairing.
        assert_eq!(
            records[0].evidence,
            "hFile = CreateFileW(&DAT_3801a2b0,0xc0000000,0,(LPSECURITY_ATTRIBUTES)0x0,3,0x80,0); CloseHandle(hFile);"
        );
    }

    #[test]
    fn a_fopen_fclose_pair_is_detected() {
        let records = pairs(
            "\
  local_10 = fopen(&DAT_3801a2b0,\"rb\");
  fread(local_18,1,4,local_10);
  fclose(local_10);",
        );
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].handle_type, HandleType::FileStream);
        assert_eq!(records[0].opener, "fopen");
        assert_eq!(records[0].closer, "fclose");
    }

    #[test]
    fn the_ansi_twin_names_the_same_family() {
        let records = pairs(
            "\
  hFile = CreateFileA(\"data.bin\",0xc0000000,0,(LPSECURITY_ATTRIBUTES)0x0,3,0x80,0);
  CloseHandle(hFile);",
        );
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].handle_type, HandleType::KernelObject);
        assert_eq!(records[0].opener, "CreateFileA");
    }

    #[test]
    fn a_cast_over_the_closed_handle_is_seen_through() {
        let records = pairs(
            "\
  local_20 = CreateFileW(&DAT_3801a2b0,0xc0000000,0,(LPSECURITY_ATTRIBUTES)0x0,3,0x80,0);
  CloseHandle((HANDLE)local_20);",
        );
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].handle_type, HandleType::KernelObject);
    }

    #[test]
    fn a_cast_over_the_opened_result_still_binds_the_variable() {
        let records = pairs(
            "\
  local_10 = (FILE *)fopen(&DAT_3801a2b0,\"rb\");
  fclose(local_10);",
        );
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].handle_type, HandleType::FileStream);
    }

    #[test]
    fn a_failure_check_between_the_sides_does_not_disturb_the_pair() {
        // The invalid-handle guard every `CreateFile` invites names
        // the variable without opening or closing anything.
        let records = pairs(
            "\
  hFile = CreateFileW(&DAT_3801a2b0,0x80000000,0,(LPSECURITY_ATTRIBUTES)0x0,2,0x80,0);
  if (hFile == INVALID_HANDLE_VALUE) {
    iVar1 = 0;
  }
  else {
    CloseHandle(hFile);
    iVar1 = 1;
  }",
        );
        assert_eq!(records.len(), 1);
    }

    #[test]
    fn an_open_stored_in_no_variable_pairs_nothing() {
        // `CloseHandle(CreateFileW(...))` names no variable on either
        // side for the pairing to key on.
        assert!(
            pairs(
                "  CloseHandle(CreateFileW(&DAT_3801a2b0,0x80000000,0,(LPSECURITY_ATTRIBUTES)0x0,2,0x80,0));"
            )
            .is_empty()
        );
    }

    #[test]
    fn an_open_never_closed_is_not_reported() {
        // Whether the handle escapes or leaks is a cross-function
        // question; this pairing stays quiet on it.
        assert!(
            pairs(
                "\
  hFile = CreateFileW(&DAT_3801a2b0,0x80000000,0,(LPSECURITY_ATTRIBUTES)0x0,2,0x80,0);
  return hFile;"
            )
            .is_empty()
        );
    }

    #[test]
    fn a_close_before_the_open_pairs_nothing() {
        // The close answers an earlier handle, not the one the body
        // opens after it.
        assert!(
            pairs(
                "\
  CloseHandle(hFile);
  hFile = CreateFileW(&DAT_3801a2b0,0x80000000,0,(LPSECURITY_ATTRIBUTES)0x0,2,0x80,0);"
            )
            .is_empty()
        );
    }

    #[test]
    fn a_closer_of_another_family_pairs_nothing() {
        // The families keep the sides straight: `fclose` answers a
        // stream, `CloseHandle` a kernel object handle, and neither
        // spelling pairs an open of the other family.
        assert!(
            pairs(
                "\
  hFile = CreateFileW(&DAT_3801a2b0,0x80000000,0,(LPSECURITY_ATTRIBUTES)0x0,2,0x80,0);
  fclose(hFile);"
            )
            .is_empty()
        );
        assert!(
            pairs(
                "\
  local_10 = fopen(&DAT_3801a2b0,\"rb\");
  CloseHandle(local_10);"
            )
            .is_empty()
        );
    }

    #[test]
    fn the_latest_open_of_a_variable_pairs_with_the_close() {
        // Two handles stored under one name, one close: the close
        // answers the second, and the first stands unpaired.
        let records = pairs(
            "\
  local_10 = fopen(&DAT_3801a2b0,\"rb\");
  fclose(local_10);
  local_10 = fopen(&DAT_3801a4c0,\"wb\");
  fclose(local_10);",
        );
        assert_eq!(records.len(), 2);
    }

    #[test]
    fn one_close_answers_the_latest_open_of_a_reused_variable() {
        let records = pairs(
            "\
  local_10 = fopen(&DAT_3801a2b0,\"rb\");
  local_10 = fopen(&DAT_3801a4c0,\"rb\");
  fclose(local_10);",
        );
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].evidence,
            "local_10 = fopen(&DAT_3801a4c0,\"rb\"); fclose(local_10);"
        );
    }

    #[test]
    fn independent_variables_each_pair_in_open_order() {
        // Closes answer out of nesting order, but the records come
        // back in open order so two scans diff cleanly.
        let records = pairs(
            "\
  local_10 = fopen(&DAT_3801a2b0,\"rb\");
  local_18 = fopen(&DAT_3801a4c0,\"rb\");
  fclose(local_18);
  fclose(local_10);",
        );
        assert_eq!(records.len(), 2);
        assert_eq!(
            records[0].evidence,
            "local_10 = fopen(&DAT_3801a2b0,\"rb\"); fclose(local_10);"
        );
        assert_eq!(
            records[1].evidence,
            "local_18 = fopen(&DAT_3801a4c0,\"rb\"); fclose(local_18);"
        );
    }

    #[test]
    fn a_pair_inside_a_loop_body_is_detected() {
        let records = pairs(
            "\
  while (iVar1 != 0) {
    local_10 = fopen(&DAT_3801a2b0,\"rb\");
    fclose(local_10);
  }",
        );
        assert_eq!(records.len(), 1);
    }

    #[test]
    fn a_name_spelled_inside_a_string_literal_invents_no_pair() {
        assert!(pairs("  printf(\"CreateFileW then CloseHandle\");").is_empty());
    }

    #[test]
    fn a_longer_or_qualified_name_matches_no_configured_name() {
        // Whole names only: a longer spelling is a different callee,
        // and a member access through an object is no plain call.
        assert!(
            pairs(
                "\
  hFile = MyCreateFileW(&DAT_3801a2b0,0x80000000,0,(LPSECURITY_ATTRIBUTES)0x0,2,0x80,0);
  hFile = CreateFileExW(&DAT_3801a2b0,0x80000000,0);
  x.fclose(local_10);
  fclose(local_10);"
            )
            .is_empty()
        );
    }

    #[test]
    fn a_close_naming_something_other_than_a_variable_pairs_nothing() {
        // A dereferenced pointer names no variable the pairing can
        // key on.
        assert!(
            pairs(
                "\
  local_10 = fopen(&DAT_3801a2b0,\"rb\");
  fclose(*ppfile);"
            )
            .is_empty()
        );
    }

    #[test]
    fn a_comparison_is_not_an_assignment() {
        // The `==` assigns nothing, so the recognized open stores its
        // result nowhere the pairing keys on.
        assert!(pairs("  if (local_10 == fopen(&DAT_3801a2b0,\"rb\")) { iVar1 = 1; }").is_empty());
    }

    #[test]
    fn a_truncated_body_pairs_nothing() {
        assert!(pairs("  hFile = CreateFileW(&DAT_3801a2b0,0x80000000;").is_empty());
    }

    #[test]
    fn nested_calls_do_not_disturb_the_pairing() {
        let records = pairs(
            "\
  local_10 = fopen(strlen(local_20),\"rb\");
  fclose(local_10);",
        );
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].handle_type, HandleType::FileStream);
    }

    // ------------------------------------------------------------
    // Guard suggestions
    // ------------------------------------------------------------

    #[test]
    fn a_comparison_after_the_close_scopes_the_guard() {
        // Reading the closed handle's value against null keeps it
        // alive past the close, so the guard can only own the
        // open-to-close span.
        let records = pairs(
            "\
  hFile = CreateFileW(&DAT_3801a2b0,0x80000000,0,(LPSECURITY_ATTRIBUTES)0x0,2,0x80,0);
  CloseHandle(hFile);
  if (hFile != (HANDLE)0x0) { iVar1 = 1; }",
        );
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].suggestion,
            "scoped RAII guard struct with Drop impl"
        );
        assert_eq!(records[0].confidence, SCOPED_GUARD_CONFIDENCE);
    }

    #[test]
    fn a_call_on_the_handle_after_the_close_scopes_the_guard() {
        // An unrecognized call naming the closed handle reads its
        // value after the release.
        let records = pairs(
            "\
  hFile = CreateFileW(&DAT_3801a2b0,0x80000000,0,(LPSECURITY_ATTRIBUTES)0x0,2,0x80,0);
  CloseHandle(hFile);
  SetFilePointer(hFile,0,(PLONG)0x0,0);",
        );
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].suggestion,
            "scoped RAII guard struct with Drop impl"
        );
    }

    #[test]
    fn a_return_of_the_closed_handle_scopes_the_guard() {
        // The value leaves the function after its close; no guard
        // could own it for the whole scope.
        let records = pairs(
            "\
  hFile = CreateFileW(&DAT_3801a2b0,0x80000000,0,(LPSECURITY_ATTRIBUTES)0x0,2,0x80,0);
  CloseHandle(hFile);
  return hFile;",
        );
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].suggestion,
            "scoped RAII guard struct with Drop impl"
        );
    }

    #[test]
    fn a_reopen_of_the_variable_after_the_close_keeps_the_plain_guard() {
        // The decompiler reuses the variable for a second handle: the
        // rebinding and the second close name that handle, not the
        // first one, and each pair gets its own whole-scope guard.
        let records = pairs(
            "\
  local_10 = fopen(&DAT_3801a2b0,\"rb\");
  fclose(local_10);
  local_10 = fopen(&DAT_3801a4c0,\"wb\");
  fclose(local_10);",
        );
        assert_eq!(records.len(), 2);
        for record in &records {
            assert_eq!(record.suggestion, "RAII guard struct with Drop impl");
            assert_eq!(record.confidence, HANDLE_PAIR_CONFIDENCE);
        }
    }

    #[test]
    fn clearing_a_closed_handle_is_not_a_read() {
        // The decompiler's habit of nulling a closed handle names the
        // variable after the close without reading the handle; the
        // guard still owns the whole scope.
        let records = pairs(
            "\
  hFile = CreateFileW(&DAT_3801a2b0,0x80000000,0,(LPSECURITY_ATTRIBUTES)0x0,2,0x80,0);
  CloseHandle(hFile);
  hFile = (HANDLE)0x0;",
        );
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].suggestion, "RAII guard struct with Drop impl");
    }

    #[test]
    fn a_string_or_a_longer_name_after_the_close_is_not_a_read() {
        // Whole words outside string literals only: the handle's
        // letters inside a format string or inside a longer name name
        // no read of the closed handle.
        let records = pairs(
            "\
  hFile = CreateFileW(&DAT_3801a2b0,0x80000000,0,(LPSECURITY_ATTRIBUTES)0x0,2,0x80,0);
  CloseHandle(hFile);
  printf(\"hFile closed\");
  CloseHandle(hFile2);",
        );
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].suggestion, "RAII guard struct with Drop impl");
    }

    #[test]
    fn a_pair_inside_a_loop_keeps_its_guard_suggestion() {
        // The close sits inside the loop that opens; the handle is
        // dead at every iteration's close either way.
        let records = pairs(
            "\
  while (iVar1 != 0) {
    local_10 = fopen(&DAT_3801a2b0,\"rb\");
    fclose(local_10);
  }",
        );
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].suggestion, "RAII guard struct with Drop impl");
    }

    #[test]
    fn a_detector_with_no_names_pairs_nothing() {
        let detector = HandleDetector::new();
        let records = detector.detect_handles(&function(
            "\
  hFile = CreateFileW(&DAT_3801a2b0,0x80000000,0,(LPSECURITY_ATTRIBUTES)0x0,2,0x80,0);
  CloseHandle(hFile);",
        ));
        assert!(records.is_empty());
    }

    #[test]
    fn custom_names_pair_like_the_standard_ones() {
        let mut detector = HandleDetector::new();
        detector.add_opener(HandleSignature::new("open", HandleType::KernelObject));
        detector.add_closer(HandleSignature::new("close", HandleType::KernelObject));
        let records = detector.detect_handles(&function(
            "\
  iVar2 = open(&DAT_3801a2b0,2);
  close(iVar2);",
        ));
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].handle_type, HandleType::KernelObject);
        assert_eq!(records[0].opener, "open");
        assert_eq!(records[0].closer, "close");
    }
}
