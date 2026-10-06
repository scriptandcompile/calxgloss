//! Allocation/deallocation pair tracking.
//!
//! This module provides [`AllocatorTracker`], which carries the
//! allocator and deallocator names a scan reads decompiled bodies
//! against — the C trio `malloc`/`calloc`/`realloc` closed by `free`,
//! and the C++ `operator new` pair closed by `operator delete` —
//! pairing each allocation with its release inside a single function
//! so the prompt can suggest `Box<T>` or stack allocation for the
//! short-lived cases.
//!
//! Each allocator name is an [`AllocatorSignature`]: the callee
//! spelling as the decompiler writes it and the [`AllocationType`] it
//! stands for. [`default_allocators`] and [`default_deallocators`]
//! carry the standard name sets, covering both spellings Ghidra has
//! written the C++ operators in — the demangled dot form
//! (`operator.new`) and the 6.x decompiler's underscore form
//! (`operator_new`) — and
//! [`AllocatorTracker::with_default_names`] builds a tracker that
//! scans against them.
//!
//! [`AllocatorTracker::detect_pairs`] runs the reading: it walks a
//! decompiled body's direct calls in source order, binds each
//! recognized allocation to the variable the decompiler stores its
//! result in, and closes that allocation when a recognized release
//! names the same variable — one [`MemoryHint`] per pair.

use crate::types::{AllocationType, MemoryHint};
use calxgloss_ghidra::DecompiledFunction;
use serde::{Deserialize, Serialize};

// ============================================================
// Allocator names
// ============================================================

/// One allocator name the tracker recognizes: the callee spelling and
/// the allocation family it stands for.
///
/// A signature is a name, not a shape: it only says that a call to
/// [`name`](Self::name) obtained a resource of
/// [`allocation_type`](Self::allocation_type) — `calloc` a zero-filled
/// block, `operator.new[]` array storage — while where the call sits
/// in the function and what releases it is the tracker's reading.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllocatorSignature {
    /// The callee spelling as the decompiler writes it, e.g. `malloc`,
    /// `operator.new`.
    pub name: String,
    /// The allocation family this spelling stands for.
    pub allocation_type: AllocationType,
}

impl AllocatorSignature {
    /// A signature recognizing the callee spelling `name` as an
    /// allocation of `allocation_type`.
    pub fn new(name: impl Into<String>, allocation_type: AllocationType) -> Self {
        Self {
            name: name.into(),
            allocation_type,
        }
    }
}

// ============================================================
// Tracker
// ============================================================

/// Allocation/deallocation pair tracking over decompiled functions.
///
/// The tracker owns the name set a scan reads bodies against:
/// [`AllocatorSignature`] records for the allocating side and plain
/// callee spellings for the releasing side. Both sets are configurable
/// — supply them whole through [`with_names`](Self::with_names) or
/// grow them one name at a time with [`add_allocator`](Self::add_allocator)
/// and [`add_deallocator`](Self::add_deallocator) — and
/// [`allocators`](Self::allocators) and [`deallocators`](Self::deallocators)
/// report them in configuration order, so two trackers built the same
/// way scan identically and results diff cleanly. The tracker holds no
/// Ghidra client of its own and never writes back to the program; one
/// tracker serves an entire scan and can be shared by reference across
/// concurrent per-function passes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AllocatorTracker {
    allocators: Vec<AllocatorSignature>,
    deallocators: Vec<String>,
}

impl AllocatorTracker {
    /// A tracker with no names configured: every body it is handed
    /// pairs nothing until the standard sets arrive through
    /// [`with_default_names`](Self::with_default_names) or names join
    /// one at a time through [`add_allocator`](Self::add_allocator)
    /// and [`add_deallocator`](Self::add_deallocator).
    pub fn new() -> Self {
        Self::default()
    }

    /// A tracker that scans against the standard name sets —
    /// [`default_allocators`] and [`default_deallocators`] — in their
    /// configuration order.
    pub fn with_default_names() -> Self {
        Self::with_names(default_allocators(), default_deallocators())
    }

    /// A tracker that scans against exactly `allocators` and
    /// `deallocators`, each kept in the order it is given.
    pub fn with_names(
        allocators: impl IntoIterator<Item = AllocatorSignature>,
        deallocators: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            allocators: allocators.into_iter().collect(),
            deallocators: deallocators.into_iter().map(Into::into).collect(),
        }
    }

    /// Add one allocator name to the set this tracker scans against.
    pub fn add_allocator(&mut self, allocator: AllocatorSignature) {
        self.allocators.push(allocator);
    }

    /// Add one deallocator name to the set this tracker scans against.
    pub fn add_deallocator(&mut self, deallocator: impl Into<String>) {
        self.deallocators.push(deallocator.into());
    }

    /// The allocator names this tracker scans against, in
    /// configuration order.
    pub fn allocators(&self) -> &[AllocatorSignature] {
        &self.allocators
    }

    /// The deallocator names this tracker scans against, in
    /// configuration order.
    pub fn deallocators(&self) -> &[String] {
        &self.deallocators
    }

    /// The allocation/release pairs one function's body carries.
    ///
    /// The reading walks the body's direct calls in source order —
    /// outside string literals, whole names only — and classifies each
    /// against the configured sets. An allocation counts only where
    /// its result is stored into a plain variable, the spelling the
    /// decompiler writes on the assignment (`pvVar1 = malloc(0x20);`);
    /// a release counts only where its first argument, seen through
    /// any cast, names one plain variable (`free((void *)pvVar1);`).
    /// A release closes the most recent still-open allocation of the
    /// variable it names — so where a variable is allocated twice
    /// before one release, the release closes the second block and
    /// the first stands unpaired — and an allocation with no release
    /// naming its variable in this function is reported by nothing:
    /// whether the block escapes or leaks is a cross-function
    /// question, outside this pairing.
    ///
    /// Each pair becomes one [`MemoryHint`] naming the allocation's
    /// family. The pairing reads as [`STACK_SUGGESTION`] when the
    /// block is short-lived — a constant-size block from a family
    /// that never resizes it, its variable used nowhere after the
    /// release, so the block is dead at its release and its whole
    /// lifetime sits inside the function — and otherwise as
    /// [`BOX_SUGGESTION`] ([`VEC_SUGGESTION`] for `operator new[]`
    /// storage), at [`STACK_CONFIDENCE`] or [`PAIR_CONFIDENCE`]
    /// respectively, with the allocation line and the release line
    /// joined as the evidence. Hints come back in allocation order,
    /// so two scans of one body diff cleanly.
    pub fn detect_pairs(&self, func: &DecompiledFunction) -> Vec<MemoryHint> {
        let mut open: Vec<OpenAllocation> = Vec::new();
        let mut pairs: Vec<(usize, MemoryHint)> = Vec::new();
        for call in direct_calls(&func.body) {
            if let Some(signature) = self.allocators.iter().find(|a| a.name == call.callee) {
                // An allocation the body stores nowhere the pairing
                // can key on names no block this function closes.
                if let Some(variable) = assigned_variable(&func.body, call.offset) {
                    open.push(OpenAllocation {
                        variable: variable.to_string(),
                        allocation_type: signature.allocation_type,
                        constant_size: sizes_constant(signature.allocation_type, &call.args),
                        offset: call.offset,
                        line: line_at(&func.body, call.offset),
                    });
                }
            } else if self.deallocators.iter().any(|d| d == call.callee) {
                let freed = call.args.first().map(|arg| strip_casts(arg));
                if let Some(freed) = freed.as_deref().and_then(plain_variable)
                    && let Some(at) = open.iter().rposition(|o| o.variable == freed)
                {
                    let allocation = open.remove(at);
                    let (suggestion, confidence) =
                        if is_short_lived(&allocation, &func.body, call.close) {
                            (STACK_SUGGESTION, STACK_CONFIDENCE)
                        } else {
                            (suggestion_for(allocation.allocation_type), PAIR_CONFIDENCE)
                        };
                    pairs.push((
                        allocation.offset,
                        MemoryHint {
                            function: func.name.clone(),
                            allocation_type: allocation.allocation_type,
                            suggestion: suggestion.to_string(),
                            confidence: confidence.into(),
                            evidence: format!(
                                "{} {}",
                                allocation.line,
                                line_at(&func.body, call.offset)
                            ),
                        },
                    ));
                }
            }
        }
        pairs.sort_by_key(|(offset, _)| *offset);
        pairs.into_iter().map(|(_, hint)| hint).collect()
    }
}

// ============================================================
// The pairing reading
// ============================================================

/// Confidence of a pairing read from an allocation and a release of
/// the same variable in one body: both sides are explicit calls to
/// recognized names, and the variable the decompiler stored the
/// result into is the variable the release names — but the tie
/// between them is the decompiler's naming, not resolved data flow,
/// and a branch could leave either side unreached.
const PAIR_CONFIDENCE: u8 = 70;

/// The ownership pattern a heap block allocated and released inside
/// one function reads as: the block has exactly the lifetime a
/// boxed value owns.
const BOX_SUGGESTION: &str = "Box<T>";

/// The ownership pattern `operator new[]` storage allocated and
/// released inside one function reads as: array storage with a known
/// release point is what a growable sequence stands in for.
const VEC_SUGGESTION: &str = "Vec<T>";

/// The ownership pattern a short-lived block reads as: a fixed-size
/// block that is dead at its release never needs the heap at all — a
/// local value stands in for it.
const STACK_SUGGESTION: &str = "stack allocation";

/// Confidence of a pairing additionally read as short-lived: the
/// pairing evidence is [`PAIR_CONFIDENCE`]'s, but the stack reading
/// rests on absences — no resize in the family, no size beyond the
/// constant the decompiler wrote, no use of the variable after the
/// release — and an absence is weaker evidence than a presence: a
/// pointer copied out of the variable, or a size the decompiler
/// folded from a runtime value, would keep the block on the heap.
const STACK_CONFIDENCE: u8 = 65;

/// The ownership pattern the pairing of one allocation family reads
/// as.
fn suggestion_for(allocation_type: AllocationType) -> &'static str {
    match allocation_type {
        AllocationType::NewArray => VEC_SUGGESTION,
        _ => BOX_SUGGESTION,
    }
}

/// Whether a closed pair's block is short-lived: a fixed-size block
/// from a family that never resizes it — the C block families and
/// single-object `operator new`, not `realloc`'s resized block or
/// `operator new[]`'s array storage — carrying a size the decompiler
/// wrote as a plain constant, and named nowhere in the body after
/// the release that closed it, so the block is dead at its release
/// and its whole lifetime sits inside the function.
fn is_short_lived(allocation: &OpenAllocation, body: &str, released_at: usize) -> bool {
    matches!(
        allocation.allocation_type,
        AllocationType::Malloc | AllocationType::Calloc | AllocationType::New
    ) && allocation.constant_size
        && !used_after(body, released_at, &allocation.variable)
}

/// An allocation still waiting for its release while the body is
/// walked: the variable holding the block, the family behind it,
/// whether the size arguments are plain constants, and where and on
/// which line the allocation sits.
struct OpenAllocation {
    variable: String,
    allocation_type: AllocationType,
    constant_size: bool,
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
/// a plain call. Unlike the other detectors' scans this one keeps a
/// demangled spelling whole: a `.` followed by an identifier byte
/// continues the name — Ghidra writes `operator new` as
/// `operator.new` — and a trailing `[]` belongs to the name too, the
/// array spelling `operator.new[]`. (The 6.x decompiler's underscore
/// form `operator_new[]` is a plain identifier plus the same bracket
/// suffix, so it needs no further special handling.) A call whose
/// `(` never closes — a truncated decompile — yields nothing, and
/// nested calls are each visited, so `malloc(strlen(name))` yields
/// both sites.
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

/// The variable a call's result is stored into, read from the call's
/// own line: walking left from the callee to the `=` that assigns,
/// the plain identifier sitting left of that `=`. A `=` that is part
/// of a comparison (`==`, `!=`, `<=`, `>=`) or a compound assignment
/// (`+=` and friends) assigns no result, and a target that is not a
/// plain variable — a dereference, an indexed element, a field —
/// stores the block somewhere the pairing cannot key on, so neither
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

/// Whether an allocation's size arguments are plain integer
/// constants: the C block families and `operator new` take their
/// byte size as the first argument, `calloc` its count and element
/// size as the first two. A size the decompiler wrote as a bare
/// literal is known at compile time, which is what a fixed local
/// needs; a size spelled as an expression is a runtime question the
/// heap answers.
fn sizes_constant(allocation_type: AllocationType, args: &[&str]) -> bool {
    let count = match allocation_type {
        AllocationType::Calloc => 2,
        _ => 1,
    };
    args.len() >= count && args[..count].iter().all(|arg| constant_size(arg))
}

/// The argument text when it is one plain integer constant — decimal
/// or `0x`-prefixed hex, seen through any cast — as the decompiler
/// writes a compile-time-known block size. Anything else — a
/// variable, a product, a global — spells a size the compiler does
/// not know.
fn constant_size(arg: &str) -> bool {
    let value = strip_casts(arg);
    let digits = value.strip_prefix("0x").unwrap_or(&value);
    !digits.is_empty()
        && digits.bytes().all(|b| b.is_ascii_hexdigit())
        && (value.starts_with("0x") || digits.bytes().all(|b| b.is_ascii_digit()))
}

/// Whether `variable` is named anywhere in the body at or after
/// `from`, outside string literals and whole-word only — a longer
/// name merely carrying it is a different variable. The decompiler's
/// habit of clearing a released pointer (`pvVar1 = (void *)0x0;`)
/// names the variable without using the block: the assignment
/// happens after the block is dead and keeps it dead, so it counts
/// as no use.
fn used_after(body: &str, from: usize, variable: &str) -> bool {
    let bytes = body.as_bytes();
    let name = variable.as_bytes();
    let mut i = from;
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
                if !nulls_variable(body, i, name.len()) {
                    return true;
                }
                i = end;
            }
            _ => i += 1,
        }
    }
    false
}

/// Whether the variable occurrence at `at` opens a whole statement
/// that assigns it a null literal — the decompiler clearing a
/// released pointer — rather than reading it. A comparison against
/// null (`pvVar1 == (void *)0x0`) still reads the value, so it is a
/// use; only a plain `variable = <null>;` is not.
fn nulls_variable(body: &str, at: usize, name_len: usize) -> bool {
    let before = body[..at].trim_end();
    if !(before.is_empty() || before.ends_with([';', '{', '}'])) {
        return false;
    }
    let rest = body[at + name_len..].trim_start();
    let Some(rest) = rest.strip_prefix('=') else {
        return false;
    };
    if rest.starts_with('=') {
        return false;
    }
    let statement = &rest[..rest.find(';').unwrap_or(rest.len())];
    matches!(strip_casts(statement).as_str(), "0" | "0x0" | "NULL")
}

/// A call argument with Ghidra casts stripped: the decompiler writes
/// `free((void *)pvVar1)` when the argument's applied type differs
/// from the callee's parameter, and the value behind the cast is the
/// block the release names.
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
/// `(ulonglong *)` — and `None` when it opens a call or a grouped
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

/// The type words a Ghidra cast may spell, matching the decompiler's
/// vocabulary the other detectors' scans strip.
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
    )
}

/// The argument text when it is one plain variable name — the spelling
/// a release names the block it closes by. Anything else — an offset
/// into the block, an indexed element, a literal — names no variable
/// the pairing can key on.
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

/// The standard allocator names: the spellings a scan recognizes as
/// allocations out of the box — the C trio `malloc`, `calloc`, and
/// `realloc`, and both renderings of the C++ `operator new` pair.
/// Ghidra has written demangled `operator new` two ways: the demangled
/// dot form `operator.new`/`operator.new[]` and, in the live 6.x
/// decompiler, the underscore form `operator_new`/`operator_new[]`
/// (`local_220 = operator_new(0x660);`) — the default set carries both
/// spellings rather than normalizing `.`/`_` in the matcher, so each
/// name stays exactly a callee spelling the scan matches whole and a
/// per-scan override through [`with_names`](AllocatorTracker::with_names)
/// can still name one spelling alone. Each name carries the family it
/// stands for, so a recognized call knows whether it obtained a raw
/// block, a zero-filled block, a resized block, object storage, or
/// array storage.
pub fn default_allocators() -> Vec<AllocatorSignature> {
    vec![
        AllocatorSignature::new("malloc", AllocationType::Malloc),
        AllocatorSignature::new("calloc", AllocationType::Calloc),
        AllocatorSignature::new("realloc", AllocationType::Realloc),
        AllocatorSignature::new("operator.new", AllocationType::New),
        AllocatorSignature::new("operator.new[]", AllocationType::NewArray),
        AllocatorSignature::new("operator_new", AllocationType::New),
        AllocatorSignature::new("operator_new[]", AllocationType::NewArray),
    ]
}

/// The standard deallocator names: the spellings a scan recognizes as
/// releases — `free`, which closes every C allocation including the
/// block `realloc` replaces, and both renderings of `operator delete`:
/// the demangled dot form `operator.delete`/`operator.delete[]` and
/// the 6.x decompiler's underscore form
/// `operator_delete`/`operator_delete[]`, which close C++ object and
/// array storage. As in [`default_allocators`], both spellings are
/// carried whole rather than normalized in the matcher.
pub fn default_deallocators() -> Vec<String> {
    vec![
        "free".into(),
        "operator.delete".into(),
        "operator.delete[]".into(),
        "operator_delete".into(),
        "operator_delete[]".into(),
    ]
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_tracker_starts_with_no_names() {
        // Construction is free: empty, equal however it is made, and
        // clones interchangeable.
        let tracker = AllocatorTracker::new();
        assert!(tracker.allocators().is_empty());
        assert!(tracker.deallocators().is_empty());
        assert_eq!(tracker, AllocatorTracker::default());
        assert_eq!(tracker.clone(), tracker);
    }

    #[test]
    fn a_tracker_keeps_the_names_it_is_configured_with() {
        let tracker = AllocatorTracker::with_names(
            [
                AllocatorSignature::new("malloc", AllocationType::Malloc),
                AllocatorSignature::new("calloc", AllocationType::Calloc),
            ],
            ["free"],
        );
        // Configuration order is scan order: two trackers built the
        // same way see the same names in the same order.
        assert_eq!(tracker.allocators().len(), 2);
        assert_eq!(tracker.allocators()[0].name, "malloc");
        assert_eq!(
            tracker.allocators()[1].allocation_type,
            AllocationType::Calloc
        );
        assert_eq!(tracker.deallocators(), ["free"]);
    }

    #[test]
    fn added_names_join_their_sets_in_order() {
        let mut tracker = AllocatorTracker::new();
        tracker.add_allocator(AllocatorSignature::new("malloc", AllocationType::Malloc));
        tracker.add_allocator(AllocatorSignature::new("realloc", AllocationType::Realloc));
        tracker.add_deallocator("free");
        tracker.add_deallocator("operator.delete");
        let names: Vec<&str> = tracker
            .allocators()
            .iter()
            .map(|a| a.name.as_str())
            .collect();
        assert_eq!(names, ["malloc", "realloc"]);
        assert_eq!(tracker.deallocators(), ["free", "operator.delete"]);
    }

    #[test]
    fn a_tracker_can_be_shared_across_scans() {
        // One tracker is driven concurrently over a program's
        // functions, so sharing one by reference across tasks must
        // stay sound.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<AllocatorTracker>();
    }

    #[test]
    fn an_allocator_signature_serde_round_trips() {
        let signature = AllocatorSignature::new("operator.new[]", AllocationType::NewArray);
        let json = serde_json::to_string(&signature).unwrap();
        assert!(json.contains("\"allocation_type\":\"new_array\""));
        let back: AllocatorSignature = serde_json::from_str(&json).unwrap();
        assert_eq!(back, signature);
    }

    #[test]
    fn an_allocator_signature_without_optional_fields_reads_back_with_its_spelling() {
        // Documents persisted for a custom name set still load.
        let json = r#"{
            "name": "my_alloc",
            "allocation_type": "malloc"
        }"#;
        let back: AllocatorSignature = serde_json::from_str(json).unwrap();
        assert_eq!(back.name, "my_alloc");
        assert_eq!(back.allocation_type, AllocationType::Malloc);
    }

    #[test]
    fn the_standard_allocators_name_the_c_and_cxx_families() {
        let allocators = default_allocators();
        let named: Vec<(&str, AllocationType)> = allocators
            .iter()
            .map(|a| (a.name.as_str(), a.allocation_type))
            .collect();
        assert_eq!(
            named,
            [
                ("malloc", AllocationType::Malloc),
                ("calloc", AllocationType::Calloc),
                ("realloc", AllocationType::Realloc),
                ("operator.new", AllocationType::New),
                ("operator.new[]", AllocationType::NewArray),
                ("operator_new", AllocationType::New),
                ("operator_new[]", AllocationType::NewArray),
            ]
        );
    }

    #[test]
    fn the_standard_deallocators_name_free_and_the_delete_pair() {
        assert_eq!(
            default_deallocators(),
            [
                "free",
                "operator.delete",
                "operator.delete[]",
                "operator_delete",
                "operator_delete[]",
            ]
        );
    }

    #[test]
    fn a_tracker_built_with_the_standard_sets_carries_them() {
        let tracker = AllocatorTracker::with_default_names();
        assert_eq!(tracker.allocators(), default_allocators());
        assert_eq!(tracker.deallocators(), default_deallocators());
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

    fn pairs(body: &str) -> Vec<MemoryHint> {
        AllocatorTracker::with_default_names().detect_pairs(&function(body))
    }

    #[test]
    fn a_malloc_free_pair_is_detected() {
        let hints = pairs(
            "\
undefined FUN_18003ab00(void) {
  pvVar1 = malloc(0x20);
  *(int *)pvVar1 = 5;
  free(pvVar1);
  return;
}",
        );
        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0].function, "FUN_18003ab00");
        assert_eq!(hints[0].allocation_type, AllocationType::Malloc);
        // A constant-size block dead at its release: the whole
        // lifetime sits inside the function, so the pairing reads as
        // a local value rather than a boxed one.
        assert_eq!(hints[0].suggestion, "stack allocation");
        assert_eq!(hints[0].confidence, STACK_CONFIDENCE);
        // The evidence carries both sides of the pairing.
        assert_eq!(hints[0].evidence, "pvVar1 = malloc(0x20); free(pvVar1);");
    }

    #[test]
    fn calloc_and_realloc_pairs_carry_their_families() {
        let hints = pairs(
            "\
  puVar1 = calloc(2, 0x10);
  free(puVar1);
  pvVar2 = realloc(pvVar2, 0x40);
  free(pvVar2);",
        );
        assert_eq!(hints.len(), 2);
        assert_eq!(hints[0].allocation_type, AllocationType::Calloc);
        assert_eq!(hints[1].allocation_type, AllocationType::Realloc);
        assert_eq!(hints[0].suggestion, "stack allocation");
        assert_eq!(hints[1].suggestion, "Box<T>");
    }

    #[test]
    fn an_operator_new_pair_is_detected() {
        let hints = pairs(
            "\
  pvVar1 = operator.new(0x20);
  operator.delete(pvVar1);",
        );
        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0].allocation_type, AllocationType::New);
        assert_eq!(hints[0].suggestion, "stack allocation");
    }

    #[test]
    fn an_operator_new_array_pair_reads_as_a_sequence() {
        // The demangled array spelling keeps its dot and brackets:
        // `operator.new[]` is one callee, and its storage reads as
        // what a growable sequence stands in for.
        let hints = pairs(
            "\
  puVar2 = (ulonglong *)operator.new[](0x40);
  operator.delete[](puVar2);",
        );
        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0].allocation_type, AllocationType::NewArray);
        assert_eq!(hints[0].suggestion, "Vec<T>");
    }

    #[test]
    fn an_underscore_spelled_operator_new_pair_pairs_like_the_dot_form() {
        // The live 6.x decompiler writes the C++ operators with
        // underscores (`local_220 = operator_new(0x660);`); the
        // underscore spelling is a plain identifier to the scan and
        // pairs exactly as the demangled dot form does.
        let hints = pairs(
            "\
  local_220 = operator_new(0x660);
  operator_delete(local_220);",
        );
        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0].allocation_type, AllocationType::New);
        assert_eq!(hints[0].suggestion, "stack allocation");
        assert_eq!(
            hints[0].evidence,
            "local_220 = operator_new(0x660); operator_delete(local_220);"
        );
    }

    #[test]
    fn an_underscore_spelled_operator_new_array_pair_reads_as_a_sequence() {
        // The array spelling carries its brackets the same way in
        // either form: `operator_new[]` is one callee and its storage
        // reads as what a growable sequence stands in for.
        let hints = pairs(
            "\
  puVar2 = (ulonglong *)operator_new[](0x40);
  operator_delete[](puVar2);",
        );
        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0].allocation_type, AllocationType::NewArray);
        assert_eq!(hints[0].suggestion, "Vec<T>");
    }

    #[test]
    fn an_underscore_spelled_name_inside_a_longer_name_matches_nothing() {
        // Whole names still: a Ghidra body calling the new handler is
        // not calling `operator_new`.
        assert!(
            pairs(
                "\
  pvVar1 = operator_new_handler(0x10);
  operator_delete_wrapper(pvVar1);"
            )
            .is_empty()
        );
    }

    #[test]
    fn a_cast_over_the_released_variable_is_seen_through() {
        let hints = pairs(
            "\
  local_20 = malloc(0x10);
  free((void *)local_20);",
        );
        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0].allocation_type, AllocationType::Malloc);
    }

    #[test]
    fn a_cast_over_the_allocated_result_still_binds_the_variable() {
        let hints = pairs(
            "\
  pvVar1 = (void *)malloc(0x20);
  free(pvVar1);",
        );
        assert_eq!(hints.len(), 1);
    }

    #[test]
    fn an_allocation_stored_in_no_variable_pairs_nothing() {
        // `free(malloc(0x10))` names no variable on either side for
        // the pairing to key on.
        assert!(pairs("  free(malloc(0x10));").is_empty());
    }

    #[test]
    fn an_allocation_never_released_is_not_reported() {
        // Whether the block escapes or leaks is a cross-function
        // question; this pairing stays quiet on it.
        assert!(
            pairs(
                "\
  pvVar1 = malloc(0x20);
  return pvVar1;"
            )
            .is_empty()
        );
    }

    #[test]
    fn a_release_before_the_allocation_pairs_nothing() {
        // The release closes an earlier block, not the one the body
        // allocates after it.
        assert!(
            pairs(
                "\
  free(pvVar1);
  pvVar1 = malloc(0x20);"
            )
            .is_empty()
        );
    }

    #[test]
    fn the_latest_allocation_of_a_variable_pairs_with_the_release() {
        // Two blocks stored under one name, one release: the release
        // closes the second, and the first stands unpaired.
        let hints = pairs(
            "\
  pvVar1 = malloc(0x10);
  pvVar1 = malloc(0x20);
  free(pvVar1);",
        );
        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0].evidence, "pvVar1 = malloc(0x20); free(pvVar1);");
    }

    #[test]
    fn independent_variables_each_pair_in_allocation_order() {
        // Releases close out of nesting order, but the hints come
        // back in allocation order so two scans diff cleanly.
        let hints = pairs(
            "\
  pvVar1 = malloc(0x10);
  pvVar2 = malloc(0x20);
  free(pvVar2);
  free(pvVar1);",
        );
        assert_eq!(hints.len(), 2);
        assert_eq!(hints[0].evidence, "pvVar1 = malloc(0x10); free(pvVar1);");
        assert_eq!(hints[1].evidence, "pvVar2 = malloc(0x20); free(pvVar2);");
    }

    #[test]
    fn a_pair_inside_a_loop_body_is_detected() {
        let hints = pairs(
            "\
  while (iVar1 != 0) {
    pvVar1 = malloc(0x20);
    free(pvVar1);
  }",
        );
        assert_eq!(hints.len(), 1);
    }

    #[test]
    fn a_name_spelled_inside_a_string_literal_invents_no_pair() {
        assert!(pairs("  printf(\"malloc %d then free\", iVar1);").is_empty());
    }

    #[test]
    fn a_longer_or_qualified_name_matches_no_configured_name() {
        // Whole names only: a longer spelling is a different callee,
        // and a member access through an object is no plain call.
        assert!(
            pairs(
                "\
  iVar1 = my_malloc(0x10);
  pvVar1 = malloc_x(8);
  x.free(pvVar1);
  free(pvVar1);"
            )
            .is_empty()
        );
    }

    #[test]
    fn a_release_naming_something_other_than_a_variable_pairs_nothing() {
        // An offset into the block names no variable the pairing can
        // key on.
        assert!(
            pairs(
                "\
  pvVar1 = malloc(0x10);
  free((char *)pvVar1 + 8);"
            )
            .is_empty()
        );
    }

    #[test]
    fn a_dereference_assignment_binds_no_variable() {
        // `*ppvVar1 = malloc(...)` stores the block through a
        // pointer-to-pointer the pairing cannot follow.
        assert!(
            pairs(
                "\
  *ppvVar1 = malloc(0x20);
  free(ppvVar1);"
            )
            .is_empty()
        );
    }

    #[test]
    fn a_comparison_is_not_an_assignment() {
        // The `==` assigns nothing, so the recognized allocation
        // stores its result nowhere the pairing keys on.
        assert!(pairs("  if (pvVar1 == realloc(pvVar1, 0x20)) { iVar1 = 1; }").is_empty());
    }

    #[test]
    fn a_truncated_body_pairs_nothing() {
        assert!(pairs("  pvVar1 = malloc(0x20;").is_empty());
    }

    #[test]
    fn nested_calls_do_not_disturb_the_pairing() {
        let hints = pairs(
            "\
  pvVar1 = malloc(strlen(local_10));
  free(pvVar1);",
        );
        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0].allocation_type, AllocationType::Malloc);
    }

    // ------------------------------------------------------------
    // Short-lived readings
    // ------------------------------------------------------------

    #[test]
    fn a_dynamic_size_pair_keeps_the_box_suggestion() {
        // A size spelled as an expression is a runtime question; a
        // block whose size the compiler does not know has no fixed
        // local that could stand in for it.
        let hints = pairs(
            "\
  pvVar1 = malloc(uVar1);
  free(pvVar1);",
        );
        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0].suggestion, "Box<T>");
        assert_eq!(hints[0].confidence, PAIR_CONFIDENCE);
    }

    #[test]
    fn a_realloc_pair_never_reads_as_stack_allocation() {
        // A resized block has no fixed size however constant this
        // resize's argument is.
        let hints = pairs(
            "\
  pvVar2 = realloc(pvVar2, 0x40);
  free(pvVar2);",
        );
        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0].suggestion, "Box<T>");
    }

    #[test]
    fn a_calloc_pair_reads_as_stack_only_with_both_sizes_constant() {
        // `calloc` takes a count and an element size; the total is
        // compile-time-known only when both are constants.
        let hints = pairs(
            "\
  puVar1 = calloc(2, 0x10);
  free(puVar1);",
        );
        assert_eq!(hints[0].suggestion, "stack allocation");
        let hints = pairs(
            "\
  puVar1 = calloc(2, uVar2);
  free(puVar1);",
        );
        assert_eq!(hints[0].suggestion, "Box<T>");
    }

    #[test]
    fn a_variable_named_after_the_release_keeps_the_box_suggestion() {
        // The block's story does not end at the release line, so the
        // reading stays with the safe heap pattern.
        let hints = pairs(
            "\
  pvVar1 = malloc(0x20);
  free(pvVar1);
  puts(pvVar1);",
        );
        assert_eq!(hints[0].suggestion, "Box<T>");
    }

    #[test]
    fn a_comparison_after_the_release_is_a_use() {
        // Reading the variable against null still names it; only a
        // plain null assignment clears it.
        let hints = pairs(
            "\
  pvVar1 = malloc(0x20);
  free(pvVar1);
  if (pvVar1 == (void *)0x0) { iVar1 = 1; }",
        );
        assert_eq!(hints[0].suggestion, "Box<T>");
    }

    #[test]
    fn clearing_a_released_pointer_is_not_a_use() {
        // The decompiler's habit of nulling a freed pointer names the
        // variable after the release without reading the block; the
        // pair still reads as a local value.
        let hints = pairs(
            "\
  pvVar1 = malloc(0x20);
  free(pvVar1);
  pvVar1 = (void *)0x0;",
        );
        assert_eq!(hints[0].suggestion, "stack allocation");
    }

    #[test]
    fn a_string_or_a_longer_name_after_the_release_is_not_a_use() {
        // Whole words outside string literals only: the variable's
        // letters inside a format string or inside a longer name name
        // no use of the block.
        let hints = pairs(
            "\
  pvVar1 = malloc(0x20);
  free(pvVar1);
  printf(\"pvVar1 done\");
  puts(pvVar10);",
        );
        assert_eq!(hints[0].suggestion, "stack allocation");
    }

    #[test]
    fn a_pair_inside_a_loop_keeps_its_short_lived_reading() {
        // The release sits inside the loop that allocates; the block
        // is dead at every iteration's release either way.
        let hints = pairs(
            "\
  while (iVar1 != 0) {
    pvVar1 = malloc(0x20);
    free(pvVar1);
  }",
        );
        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0].suggestion, "stack allocation");
    }

    #[test]
    fn a_tracker_with_no_names_pairs_nothing() {
        let tracker = AllocatorTracker::new();
        let hints = tracker.detect_pairs(&function(
            "\
  pvVar1 = malloc(0x20);
  free(pvVar1);",
        ));
        assert!(hints.is_empty());
    }

    #[test]
    fn custom_names_pair_like_the_standard_ones() {
        let mut tracker = AllocatorTracker::new();
        tracker.add_allocator(AllocatorSignature::new(
            "CoTaskMemAlloc",
            AllocationType::Malloc,
        ));
        tracker.add_deallocator("CoTaskMemFree");
        let hints = tracker.detect_pairs(&function(
            "\
  pvVar1 = CoTaskMemAlloc(0x10);
  CoTaskMemFree(pvVar1);",
        ));
        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0].allocation_type, AllocationType::Malloc);
    }
}
