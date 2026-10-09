//! Shared scanner for Ghidra pseudo-C function bodies.
//!
//! Every evidence crate that reads decompiler output needs the same
//! primitives: find direct calls, split their arguments, and walk the
//! body without mistaking a string or char literal for code. Those
//! primitives were restated (byte-identically, then subtly diverging)
//! in a dozen engine files; they live here instead, with one
//! configuration point — [`ScanOptions`] — for the ways the scans
//! legitimately differ: how a callee name continues past identifier
//! bytes, which preceding bytes disqualify a name start, and which
//! callee names are keywords rather than calls.
//!
//! The scanner is lexical, not a parser: it never claims the body is
//! valid C, only that a `name(` ... `)` pair balances outside literals.
//! A truncated decompile (an unclosed `(`) simply yields nothing.

/// Callee names the decompiler emits like calls but that name no call —
/// `if (x)` reads as a call to `if` unless filtered.
pub const NON_CALL_KEYWORDS: [&str; 7] =
    ["if", "while", "for", "switch", "case", "return", "sizeof"];

/// How a callee name continues past plain identifier bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameContinuation {
    /// Plain identifier bytes only.
    Ident,
    /// `::` continues a demangled qualified name: `std::thread::spawn`.
    ColonColon,
    /// A `.` followed by an identifier byte continues a demangled
    /// spelling — Ghidra writes `operator new` as `operator.new` — and
    /// a trailing `[]` belongs to the name: `operator.new[]`.
    DemangledDot,
}

/// A direct call found in a body: the callee name, the text of each
/// top-level argument, the byte offset of the callee, and the offset
/// of the closing `)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallSite<'a> {
    pub callee: &'a str,
    pub args: Vec<&'a str>,
    pub offset: usize,
    pub close: usize,
}

/// What a [`call_sites`] scan accepts as a callee.
#[derive(Debug, Clone, Copy)]
pub struct ScanOptions {
    /// How callee names continue past identifier bytes.
    pub continuation: NameContinuation,
    /// Bytes that additionally disqualify a name start, on top of
    /// identifier bytes (which always do). A name preceded by `.` is a
    /// member access; by `>`, an access through a pointer; by `:`, the
    /// tail of a qualified name. Common sets: `b"."`, `b".>"`, `b".>:"`.
    pub reject_preceding: &'static [u8],
    /// Callee names to skip — usually [`NON_CALL_KEYWORDS`], or empty
    /// to record every balanced `name(`.
    pub skip_keywords: &'static [&'static str],
}

/// Every direct call `name(args)` in the body, scanned outside string
/// and char literals so a stray `(` in a literal cannot read as a
/// call. A name preceded by an identifier byte or one of
/// [`ScanOptions::reject_preceding`] is the tail of a longer name or a
/// member access, not a plain call. A call whose `(` never closes — a
/// truncated decompile — yields nothing, and nested calls are each
/// visited.
pub fn call_sites<'a>(body: &'a str, opts: &ScanOptions) -> Vec<CallSite<'a>> {
    let bytes = body.as_bytes();
    let mut calls = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => i = skip_string(bytes, i + 1),
            b'\'' => i = skip_char(bytes, i + 1),
            b if b.is_ascii_alphabetic() || b == b'_' => {
                if i > 0
                    && (is_ident_byte(bytes[i - 1])
                        || opts.reject_preceding.contains(&bytes[i - 1]))
                {
                    i += 1;
                    continue;
                }
                let j = name_end(bytes, i, opts.continuation);
                let open = skip_ws(bytes, j);
                if bytes.get(open) == Some(&b'(')
                    && !opts.skip_keywords.contains(&&body[i..j])
                    && let Some(close) = closing_paren(body, open)
                {
                    calls.push(CallSite {
                        callee: &body[i..j],
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

/// The offset just past the callee name starting at `start`, honoring
/// the continuation rule.
fn name_end(bytes: &[u8], start: usize, continuation: NameContinuation) -> usize {
    let mut j = start;
    loop {
        if j < bytes.len() && is_ident_byte(bytes[j]) {
            j += 1;
            continue;
        }
        match continuation {
            NameContinuation::ColonColon
                if bytes.get(j) == Some(&b':')
                    && bytes.get(j + 1) == Some(&b':')
                    && bytes
                        .get(j + 2)
                        .is_some_and(|b| b.is_ascii_alphabetic() || *b == b'_') =>
            {
                j += 2;
            }
            NameContinuation::DemangledDot
                if bytes.get(j) == Some(&b'.')
                    && bytes
                        .get(j + 1)
                        .is_some_and(|b| b.is_ascii_alphabetic() || *b == b'_') =>
            {
                j += 1;
            }
            _ => break,
        }
    }
    if continuation == NameContinuation::DemangledDot {
        // The array spelling carries its brackets: `operator.new[]`.
        let bracket = skip_ws(bytes, j);
        if bytes.get(bracket) == Some(&b'[')
            && bytes.get(skip_ws(bytes, bracket + 1)) == Some(&b']')
        {
            j = skip_ws(bytes, bracket + 1) + 1;
        }
    }
    j
}

/// The text of each top-level argument of the call whose `(` sits at
/// `open` and whose `)` sits at `close`, in order. A call with no
/// arguments yields none, and commas nested inside a parenthesised,
/// bracketed, or quoted argument — a nested call, an array index, a
/// char literal — belong to that argument rather than splitting it.
pub fn split_arguments(body: &str, open: usize, close: usize) -> Vec<&str> {
    let bytes = body.as_bytes();
    let mut args = Vec::new();
    let mut depth = 0usize;
    let mut start = open + 1;
    let mut i = start;
    while i < close {
        match bytes[i] {
            b'"' => i = skip_string(bytes, i + 1),
            b'\'' => i = skip_char(bytes, i + 1),
            b'(' | b'[' => {
                depth += 1;
                i += 1;
            }
            b')' | b']' => {
                // A closer at depth 0 is unbalanced input (a stray `]`
                // in a malformed body); it belongs to the current
                // argument rather than underflowing the counter.
                depth = depth.saturating_sub(1);
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

/// The index of `)` matching the `(` at `open`, skipping string and
/// char literals so a `)` inside one cannot close the call early.
pub fn closing_paren(body: &str, open: usize) -> Option<usize> {
    let bytes = body.as_bytes();
    let mut depth = 0usize;
    let mut i = open;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => i = skip_string(bytes, i + 1),
            b'\'' => i = skip_char(bytes, i + 1),
            b'(' => {
                depth += 1;
                i += 1;
            }
            b')' => {
                depth = depth.saturating_sub(1);
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

/// The index just past the string literal whose opening `"` sits at
/// `open`. An unterminated literal runs to the end of the body.
pub fn skip_string(bytes: &[u8], mut i: usize) -> usize {
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2,
            b'"' => return i + 1,
            _ => i += 1,
        }
    }
    bytes.len()
}

/// The index just past the string or char literal whose opening quote
/// sits at `i` — for scans that treat any literal as opaque text.
pub fn skip_literal(bytes: &[u8], i: usize) -> usize {
    match bytes[i] {
        b'\'' => skip_char(bytes, i + 1),
        _ => skip_string(bytes, i + 1),
    }
}

/// The index just past the char literal whose opening `'` sits at
/// `open`. An unterminated literal runs to the end of the body.
/// Decompiler output carries char literals like `']'` and `')'` in
/// parsing code; without this skip their closers read as unbalanced
/// brackets.
pub fn skip_char(bytes: &[u8], mut i: usize) -> usize {
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2,
            b'\'' => return i + 1,
            _ => i += 1,
        }
    }
    bytes.len()
}

/// The index of the first non-whitespace byte at or after `i`.
pub fn skip_ws(bytes: &[u8], mut i: usize) -> usize {
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    i
}

/// Whether `b` continues an identifier.
pub fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// The full text of the line containing byte `offset` of `body`,
/// trimmed — what an evidence record quotes as the call's context.
pub fn line_at(body: &str, offset: usize) -> String {
    let line = body[..offset.min(body.len())].matches('\n').count();
    body.lines().nth(line).unwrap_or("").trim().to_string()
}

/// The argument text with leading C casts stripped: `(DWORD)x` reduces
/// to `x` and `*(DWORD *)ptr` to `*ptr` — the cast group goes, a
/// dereference stays — so a caller can match an argument against a
/// plain variable name. `is_type_word` decides which words inside a
/// leading group name a type — the word list is domain data each
/// evidence crate owns.
pub fn strip_casts(arg: &str, is_type_word: impl Fn(&str) -> bool) -> String {
    let bytes = arg.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'('
            && let Some(close) = cast_group(bytes, i, &is_type_word)
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

/// The index of the `)` closing a leading type-cast group at `open` —
/// `*`s and identifier words that [`is_type_word`](is_type_word)
/// accepts, and nothing else. `None` when the group is not a cast.
pub fn cast_group(bytes: &[u8], open: usize, is_type_word: impl Fn(&str) -> bool) -> Option<usize> {
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

#[cfg(test)]
mod tests {
    use super::*;

    const PLAIN: ScanOptions = ScanOptions {
        continuation: NameContinuation::Ident,
        reject_preceding: b".",
        skip_keywords: &[],
    };

    const C_CALLS: ScanOptions = ScanOptions {
        continuation: NameContinuation::Ident,
        reject_preceding: b".>",
        skip_keywords: &NON_CALL_KEYWORDS,
    };

    #[test]
    fn plain_calls_are_recorded_with_args_and_offsets() {
        let body = "local_1 = foo(a, b) + bar();";
        let calls = call_sites(body, &PLAIN);
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].callee, "foo");
        assert_eq!(calls[0].args, ["a", "b"]);
        assert_eq!(calls[0].offset, body.find("foo").unwrap());
        assert_eq!(calls[1].callee, "bar");
        assert_eq!(calls[1].args, Vec::<&str>::new());
    }

    #[test]
    fn nested_calls_are_each_visited_and_nested_commas_do_not_split() {
        let body = "foo(bar(x, y), z[1,2]);";
        let calls = call_sites(body, &C_CALLS);
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].callee, "foo");
        assert_eq!(calls[0].args, ["bar(x, y)", "z[1,2]"]);
        assert_eq!(calls[1].callee, "bar");
        assert_eq!(calls[1].args, ["x", "y"]);
    }

    #[test]
    fn keywords_are_skipped_when_configured_and_kept_when_not() {
        let body = "if (x) { while (y) foo(z); }";
        let filtered = call_sites(body, &C_CALLS);
        assert_eq!(
            filtered.iter().map(|c| c.callee).collect::<Vec<_>>(),
            ["foo"]
        );
        let unfiltered = call_sites(body, &PLAIN);
        assert_eq!(
            unfiltered.iter().map(|c| c.callee).collect::<Vec<_>>(),
            ["if", "while", "foo"]
        );
    }

    #[test]
    fn member_access_is_rejected_per_the_preceding_set() {
        let body = "param_1->Release(param_1); obj.field(x);";
        // Rejecting `>` (the common setting) sees no calls.
        assert!(call_sites(body, &C_CALLS).is_empty());
        // Accepting member calls (the param-size setting) sees Release.
        let opts = ScanOptions {
            reject_preceding: b".",
            ..C_CALLS
        };
        assert_eq!(call_sites(body, &opts)[0].callee, "Release");
    }

    #[test]
    fn qualified_names_stay_whole() {
        let body = "std::thread::spawn(local_1);";
        let opts = ScanOptions {
            continuation: NameContinuation::ColonColon,
            reject_preceding: b".>:",
            skip_keywords: &NON_CALL_KEYWORDS,
        };
        let calls = call_sites(body, &opts);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].callee, "std::thread::spawn");
        assert_eq!(calls[0].args, ["local_1"]);
    }

    #[test]
    fn demangled_dot_names_stay_whole_including_array_brackets() {
        let body = "operator.new(0x10); operator.new[](0x8);";
        let opts = ScanOptions {
            continuation: NameContinuation::DemangledDot,
            reject_preceding: b".>",
            skip_keywords: &NON_CALL_KEYWORDS,
        };
        let calls = call_sites(body, &opts);
        assert_eq!(
            calls.iter().map(|c| c.callee).collect::<Vec<_>>(),
            ["operator.new", "operator.new[]"]
        );
    }

    #[test]
    fn parens_inside_string_literals_do_not_close_a_call() {
        let body = "printf(\"a)b\", x);";
        let calls = call_sites(body, &C_CALLS);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].args, ["\"a)b\"", "x"]);
    }

    #[test]
    fn char_literal_closers_do_not_break_the_scan() {
        // The regression: `']'` at depth 0 underflowed the argument
        // depth counter and panicked debug builds.
        let body = "if (*pc == ']') { break; }";
        let calls = call_sites(body, &PLAIN);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].args, ["*pc == ']'"]);

        let body = "foo(a, ')');";
        let calls = call_sites(body, &C_CALLS);
        assert_eq!(calls[0].args, ["a", "')'"]);
    }

    #[test]
    fn unbalanced_closers_in_malformed_bodies_do_not_panic() {
        let body = "foo(a]b);";
        let calls = call_sites(body, &C_CALLS);
        assert_eq!(calls[0].args, ["a]b"]);
    }

    #[test]
    fn truncated_decompiles_yield_nothing() {
        assert!(call_sites("foo(\"abc", &C_CALLS).is_empty());
        assert!(call_sites("foo(a[0", &C_CALLS).is_empty());
    }

    #[test]
    fn closing_paren_skips_literals() {
        let body = "foo(')')";
        assert_eq!(closing_paren(body, 3), Some(7));
    }

    #[test]
    fn line_at_returns_the_trimmed_line_containing_the_offset() {
        let body = "a();\n  b();\nc();";
        assert_eq!(line_at(body, body.find("b(").unwrap()), "b();");
    }

    #[test]
    fn strip_casts_reduces_arguments_to_their_variable() {
        let is_type = |w: &str| w == "dword" || w == "int";
        assert_eq!(strip_casts("(DWORD)x", is_type), "x");
        assert_eq!(strip_casts("*(DWORD *)ptr", is_type), "*ptr");
        assert_eq!(strip_casts("x", is_type), "x");
        // A group whose words are not types is an expression, not a cast.
        assert_eq!(strip_casts("(a + b)", is_type), "(a + b)");
    }
}
