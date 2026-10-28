//! Triage of decompiler warnings, in either engine's dialect.
//!
//! The decompiler writes its analysis failures into the pseudo-C itself:
//! Ghidra as `/* WARNING: ... */` banners, Kuna as terse `// slug`
//! end-of-line comments. If nothing reads them they are easy to miss and
//! costly to ignore. An unrecovered jump table decompiles to an
//! `UNRECOVERED_JUMPTABLE` local called through a code pointer and a bare
//! `return` (Ghidra), or to a truncated dispatch (Kuna). The LLM renders
//! that broken output faithfully into plausible, hollow Rust. This module
//! reads the warnings out of the decompiler body before a prompt is
//! built, so the pipeline can name the jump a human must inspect.
//!
//! Alongside the warnings it reads one body *shape*: an import thunk the
//! symbol table names after its import decompiles as a call to its own
//! name, and [`is_self_call_thunk`] recognizes it, so the pipeline refuses
//! the veneer instead of translating the apparent recursion into a Rust
//! function that calls itself (issue #269).

/// An indirect jump the decompiler could not resolve into a switch: it gave
/// up on the jump table and treats the jump as a call. Ghidra says so with a
/// `Could not recover jumptable at 0x…` banner; Kuna truncates the function
/// and marks the line with a `jump-as-call` comment slug.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnrecoveredJumpTable {
    /// Virtual address of the indirect jump, when the warning names one.
    /// Ghidra's marker carries it; Kuna's inline slug comment does not.
    pub address: Option<u64>,

    /// The decompiler's stated reason, e.g. "Too many branches". Empty when
    /// the warning carries none.
    pub reason: String,
}

/// Find every unrecovered-jumptable warning in a decompiler body, in order
/// of appearance, in either engine's spelling.
///
/// The reading is deliberately string-level: the decompiler text is opaque
/// input, and the warning's own wording is the evidence — Ghidra's
/// `Could not recover jumptable at 0x<hex>. <reason>` marker, or Kuna's
/// `jump-as-call` slug inside a `//` comment (the slug carries no address).
/// One warning per line is assumed, as both engines emit them. A Ghidra
/// warning whose address does not parse as hexadecimal is dropped rather
/// than failing the scan: this is triage, not a gate, and a miss costs only
/// the log line it would have produced.
pub fn scan_unrecovered_jump_tables(decompiler_output: &str) -> Vec<UnrecoveredJumpTable> {
    const MARKER: &str = "Could not recover jumptable at ";
    // Kuna's inline warning slug for the jump table it truncates
    // (`// jt: jump-as-call`; the `jt: ` category prefix is only attached to
    // jumptable-tagged warnings, so the bare slug is accepted too).
    const KUNA_SLUG: &str = "jump-as-call";
    // Kuna's fallback slug form keeps unrecognized warnings in full behind a
    // `warn:` marker; match the warning's own stem so that form reads too.
    const KUNA_WARNING: &str = "Treating indirect jump as call";

    let mut found = Vec::new();
    for line in decompiler_output.lines() {
        if let Some(rest) = line.split(MARKER).nth(1) {
            // `rest` reads like "0x004712d7. Too many branches */": the address
            // token ends at whitespace (with a trailing period), the reason runs
            // to the comment closer.
            let mut tokens = rest.splitn(2, char::is_whitespace);
            let address_hex = tokens.next().unwrap_or("").trim_end_matches('.');
            let Ok(address) = u64::from_str_radix(address_hex.trim_start_matches("0x"), 16) else {
                continue;
            };
            let reason = tokens
                .next()
                .unwrap_or("")
                .trim_end_matches("*/")
                .trim()
                .to_string();
            found.push(UnrecoveredJumpTable {
                address: Some(address),
                reason,
            });
            continue;
        }
        // Kuna dialect: the signal is a slug inside a `//` comment, never a
        // marker. Several slugs share one comment, comma-separated.
        let Some(comment) = line.split_once("//").map(|(_, comment)| comment) else {
            continue;
        };
        let flagged = comment.split(',').any(|slug| {
            let slug = slug.trim();
            // A slug may carry a `category:` (or `warn:`) prefix.
            let bare = slug.rsplit(':').next().unwrap_or(slug).trim();
            bare == KUNA_SLUG || slug.contains(KUNA_WARNING)
        });
        if flagged {
            found.push(UnrecoveredJumpTable {
                address: None,
                reason: String::new(),
            });
        }
    }
    found
}

// ============================================================
// Self-call thunk shape
// ============================================================

/// Whether the whole decompiled body is one unconditional call to the
/// function's own name — an import thunk the decompiler renders as a
/// self-call (issue #269).
///
/// The PE carries a one-instruction veneer whose body is a tail-jump to the
/// real imported API (`jmp [__imp_SetCursor]` → `user32!SetCursor`), and the
/// symbol table names the veneer after the import it jumps to. The decompiler
/// renders a tail-jump to a symbol as a call to that symbol, which prints as
/// a call to the function's own name: Ghidra spells it `SetCursor(); return;`,
/// Kuna spells it `return SetCursor(); // jump-as-call`, adding a cast
/// when the veneer converts the return type. It reads as infinite
/// recursion; at runtime it is a single jump, and the veneer contains no
/// logic of its own — callers reach the real API through the PAL mappings.
///
/// The reading is deliberately strict. Comments are stripped, the body is
/// split into `;`-terminated statements, and the statements must be exactly
/// one call to `function` — bare, `return`-prefixed, or cast-wrapped —
/// optionally followed by a bare `return`. A genuine recursive function
/// always carries a base case, so its body holds more than the self-call and
/// reads `false`; a call to any other name is a wrapper or a veneer under a
/// name the root patterns already catch, and reads `false` too. A `;` inside
/// a string literal in the call's arguments would split the statements
/// wrongly and miss the shape — a miss costs only a translation attempt,
/// today's behavior, never a wrong refusal.
pub fn is_self_call_thunk(function: &str, decompiler_output: &str) -> bool {
    if function.is_empty() {
        return false;
    }
    let Some(body) = between_braces(decompiler_output) else {
        return false;
    };
    let body = strip_comments(&body);
    let statements: Vec<&str> = body
        .split(';')
        .map(str::trim)
        .filter(|statement| !statement.is_empty())
        .collect();
    match statements.as_slice() {
        // The whole body is the call: `return puts(a0);` (Kuna's tail-call
        // spelling) or a lone `SetCursor();` with nothing after it.
        [call] => is_self_call(call, function),
        // The call followed by a bare `return`: Ghidra's `SetCursor();
        // return;` and Kuna's `free(a0); // jump-as-call` + `return;`.
        [call, tail] => *tail == "return" && is_self_call(call, function),
        _ => false,
    }
}

/// The body text between the first `{` and the last `}` that follows it —
/// the decompiler's brace block, with the signature line and all text after
/// the closing brace dropped. With no braces there is no body to read.
fn between_braces(decompiler_output: &str) -> Option<String> {
    let open = decompiler_output.find('{')?;
    let close = decompiler_output[open + 1..].rfind('}')?;
    Some(decompiler_output[open + 1..open + 1 + close].to_string())
}

/// Drop `//` and `/* */` comments, keeping string literals intact so a
/// comment marker inside a literal is never mistaken for a comment.
fn strip_comments(body: &str) -> String {
    let mut out = String::with_capacity(body.len());
    let mut chars = body.chars().peekable();
    let mut in_string = false;
    while let Some(c) = chars.next() {
        match c {
            '"' if !in_string => {
                in_string = true;
                out.push(c);
            }
            '"' => {
                in_string = false;
                out.push(c);
            }
            '\\' if in_string => {
                out.push(c);
                if let Some(escaped) = chars.next() {
                    out.push(escaped);
                }
            }
            '/' if !in_string && chars.peek() == Some(&'/') => {
                for c in chars.by_ref() {
                    if c == '\n' {
                        out.push(c);
                        break;
                    }
                }
            }
            '/' if !in_string && chars.peek() == Some(&'*') => {
                chars.next();
                while let (Some(a), Some(b)) = (chars.next(), chars.peek()) {
                    if a == '*' && *b == '/' {
                        chars.next();
                        break;
                    }
                }
            }
            _ => out.push(c),
        }
    }
    out
}

/// Whether one statement is a call to `function`: an optional `return`
/// prefix, any cast wrappers, then the name immediately followed by its
/// argument list, closing at the end of the statement. The name must be
/// *called*, not merely mentioned: `SetCursorEx()` is not `SetCursor()`,
/// and the `(` required right after the name is what enforces that.
fn is_self_call(statement: &str, function: &str) -> bool {
    let rest = strip_casts(strip_word(statement, "return").trim());
    let Some(args) = rest
        .strip_prefix(function)
        .and_then(|r| r.trim_start().strip_prefix('('))
    else {
        return false;
    };
    matching_paren(args).is_some_and(|end| end + 1 == args.len())
}

/// Strip a leading keyword (`return`) when the statement continues past it.
fn strip_word<'a>(statement: &'a str, word: &str) -> &'a str {
    match statement.strip_prefix(word) {
        Some(rest) if rest.starts_with(char::is_whitespace) => rest,
        _ => statement,
    }
}

/// Strip leading cast wrappers like `(void *)` — a parenthesized group with
/// no nested call inside it — so Kuna's `return (void *)malloc(a0)` reads as
/// a call to `malloc`.
fn strip_casts(mut rest: &str) -> &str {
    while let Some(inner_end) = rest
        .strip_prefix('(')
        .and_then(|r| matching_paren(r).map(|e| e + 1))
    {
        let inner = &rest[1..inner_end];
        if inner.contains('(') || inner.contains(',') {
            break;
        }
        rest = rest[1 + inner_end..].trim_start();
    }
    rest
}

/// Index of the `)` closing an argument list that has already been opened:
/// `s` starts just after the `(`, and the answer is the index in `s` where
/// the depth returns to zero. `None` when the parens never balance.
fn matching_paren(s: &str) -> Option<usize> {
    let mut depth = 1usize;
    for (index, c) in s.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(index);
                }
            }
            _ => {}
        }
    }
    None
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// A delay-load thunk body as Ghidra actually reports it: the helper
    /// call, the two warnings, and the indirect call the LLM would
    /// otherwise translate into a bare `return`.
    fn delay_load_body() -> &'static str {
        "\
void __fastcall DelayLoad_cef_string_utf16_clear(undefined4 param_1,undefined4 param_2)

{
  code *UNRECOVERED_JUMPTABLE;

  UNRECOVERED_JUMPTABLE =
       (code *)func_0x0049ce2d(&#38;ImgDelayDescr_0055e8c0,&#38;cef_string_utf16_clear_exref,param_2,param_1
                              );
                    /* WARNING: Could not recover jumptable at 0x004712d7. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (*UNRECOVERED_JUMPTABLE)();
  return;
}"
    }

    #[test]
    fn a_real_delay_load_warning_reads_with_address_and_reason() {
        let found = scan_unrecovered_jump_tables(delay_load_body());
        assert_eq!(
            found,
            vec![UnrecoveredJumpTable {
                address: Some(0x004712d7),
                reason: "Too many branches".to_string(),
            }],
            "the Ghidra banner reports once even though the body also carries \
             the 'Treating indirect jump as call' banner"
        );
    }

    #[test]
    fn several_warnings_report_in_order_of_appearance() {
        let body = "\
/* WARNING: Could not recover jumptable at 0x004010a0. Too many branches */
/* WARNING: Could not recover jumptable at 0x0040ff1f. Bad jumptable */";
        let found = scan_unrecovered_jump_tables(body);
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].address, Some(0x004010a0));
        assert_eq!(found[1].address, Some(0x0040ff1f));
        assert_eq!(found[1].reason, "Bad jumptable");
    }

    #[test]
    fn a_warning_without_a_reason_reads_empty() {
        let body = "/* WARNING: Could not recover jumptable at 0x180001234. */";
        let found = scan_unrecovered_jump_tables(body);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].address, Some(0x180001234));
        assert_eq!(found[0].reason, "");
    }

    #[test]
    fn a_malformed_address_is_dropped_not_fatal() {
        let body = "\
/* WARNING: Could not recover jumptable at 0xZZZ. Bad jumptable */
/* WARNING: Could not recover jumptable at 0x4010a0. Too many branches */";
        let found = scan_unrecovered_jump_tables(body);
        assert_eq!(found.len(), 1, "only the parseable warning reports");
        assert_eq!(found[0].address, Some(0x4010a0));
    }

    #[test]
    fn a_clean_body_finds_nothing() {
        let body = "\
undefined8 FUN_18003e750(undefined8 param_1)
{
  switch(param_1) {
  case 1:
    break;
  }
  return 0;
}";
        assert!(scan_unrecovered_jump_tables(body).is_empty());
    }

    // --- Kuna dialect ----------------------------------------------------

    /// The same unrecovered jump table as Kuna renders it (default
    /// `warnstyle inline`): the truncated dispatch carries a `// jt:
    /// jump-as-call` end-of-line comment instead of a Ghidra banner.
    #[test]
    fn a_kuna_slug_comment_reads_without_an_address() {
        let body = "\
undefined8 sub_140002490(undefined8 param_1)

{
  long lVar1;
  (*puVar4)(); // jt: jump-as-call
  return 0;
}";
        let found = scan_unrecovered_jump_tables(body);
        assert_eq!(
            found,
            vec![UnrecoveredJumpTable {
                address: None,
                reason: String::new()
            }]
        );
    }

    #[test]
    fn a_kuna_slug_without_the_category_prefix_reads() {
        let body = "  (*code)(); // jump-as-call";
        let found = scan_unrecovered_jump_tables(body);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].address, None);
    }

    #[test]
    fn a_kuna_line_with_several_slugs_reports_once() {
        let body = "  switch(lVar3) { // jt: jump-as-call, no-return";
        let found = scan_unrecovered_jump_tables(body);
        assert_eq!(found.len(), 1, "one warning per line, as Kuna emits them");
    }

    #[test]
    fn a_kuna_warn_fallback_slug_reads() {
        // Unrecognized warning text keeps its full text behind `warn:`.
        let body = "  (*code)(); // warn: WARNING (jumptable): Treating indirect jump as call";
        let found = scan_unrecovered_jump_tables(body);
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn a_kuna_body_without_the_slug_finds_nothing() {
        let body = "\
undefined8 sub_140002490(undefined8 param_1)
{
  switch(param_1) {
  case 1:
    break;
  }
  return 0;
}";
        assert!(scan_unrecovered_jump_tables(body).is_empty());
    }

    // --- Self-call thunk shape (issue #269) ------------------------------

    /// The observed body that motivated the shape: `LaunchPad.exe`'s
    /// `SetCursor` veneer, named after the user32 import it tail-jumps to,
    /// decompiled as a call to its own name.
    fn set_cursor_body() -> &'static str {
        "\
void SetCursor(void)
{
  SetCursor();
  return;
}"
    }

    #[test]
    fn the_observed_set_cursor_body_reads_as_a_self_call_thunk() {
        assert!(is_self_call_thunk("SetCursor", set_cursor_body()));
    }

    /// The same veneer as Kuna renders it, straight from the fixture's
    /// MinGW import thunks: the `// jump-as-call` slug, the `return`-prefixed
    /// tail call, and the cast wrapper when the veneer converts the type.
    #[test]
    fn the_kuna_spellings_of_the_same_shape_all_read() {
        let bare = "\
void free(void *a0)
{
  free(a0); // jump-as-call
  return;
}";
        let returned = "\
int4 puts(char *a0)
{
  return puts(a0); // jump-as-call
}";
        let cast = "\
void * malloc(uint8 a0)
{
  return (void *)malloc(a0); // jump-as-call
}";
        assert!(is_self_call_thunk("free", bare));
        assert!(is_self_call_thunk("puts", returned));
        assert!(is_self_call_thunk("malloc", cast));
    }

    /// A genuine recursive function keeps its base case, so its body is
    /// never just the self-call — the shape refuses the veneer, not
    /// recursion.
    #[test]
    fn a_genuine_recursion_with_a_base_case_is_not_the_shape() {
        let body = "\
int4 fact(int4 n)
{
  if (n <= 1) {
    return 1;
  }
  return n * fact(n - 1);
}";
        assert!(!is_self_call_thunk("fact", body));
    }

    #[test]
    fn a_call_to_another_name_is_not_a_self_call() {
        let body = "\
void thunk_FUN_180098765(undefined8 param_1)
{
  FUN_18003ab00(param_1);
  return;
}";
        assert!(!is_self_call_thunk("thunk_FUN_180098765", body));
    }

    /// The name must be *called*, not merely similar: a longer name sharing
    /// the prefix, and the same call under a different function name, both
    /// read false.
    #[test]
    fn a_name_lookalike_is_not_a_self_call() {
        let body = "\
void SetCursor(void)
{
  SetCursorEx();
  return;
}";
        assert!(!is_self_call_thunk("SetCursor", body));
        assert!(!is_self_call_thunk("SetCursorEx", set_cursor_body()));
    }

    #[test]
    fn an_empty_body_or_a_body_without_braces_is_not_the_shape() {
        assert!(!is_self_call_thunk(
            "SetCursor",
            "void SetCursor(void)\n{\n}"
        ));
        assert!(!is_self_call_thunk("SetCursor", ""));
        assert!(!is_self_call_thunk("SetCursor", "SetCursor(); return;"));
    }

    /// The call must be the whole body: a self-call with anything else —
    /// a second call, an assignment, a return value — is not the veneer.
    #[test]
    fn a_self_call_with_anything_else_in_the_body_is_not_the_shape() {
        let twice = "\
void loop(void)
{
  loop();
  loop();
}";
        let assigned = "\
int4 puts(char *a0)
{
  int4 iVar1;
  iVar1 = puts(a0);
  return iVar1;
}";
        assert!(!is_self_call_thunk("loop", twice));
        assert!(!is_self_call_thunk("puts", assigned));
    }

    /// A Ghidra spelling with the `return`-prefixed tail call reads too —
    /// the shape is engine-agnostic, the comment slugs are decoration.
    #[test]
    fn a_return_prefixed_self_call_without_a_comment_reads() {
        let body = "\
undefined4 GetTickCount(void)
{
  return GetTickCount();
}";
        assert!(is_self_call_thunk("GetTickCount", body));
    }
}
