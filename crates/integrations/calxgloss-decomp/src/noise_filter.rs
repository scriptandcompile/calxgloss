//! The decompiler-noise pre-filter: compiler theater stripped from the
//! pseudo-C every consumer sees (issue #232; #271 opened the module with
//! the named guard calls, #272 added the if-wrapped compare epilogue, and
//! #273 closes the canary family with the prologue cookie-save and the
//! cookie declaration its strips leave orphaned).
//!
//! Every MSVC-compiled function carries the same piece of theater: the /GS
//! stack canary's cookie-save prologue, its compare epilogue, and calls into
//! the guard runtime (`__security_init_cookie`, `__security_check_cookie`,
//! `__report_gsfailure`). The code is compiler-generated, never fires under
//! baseline-test inputs, and yet it rode into every prompt, evidence
//! reading, and branch inventory as if it were the function's own logic.
//!
//! This module is the single home for stripping it: a pure text filter over
//! the body a [`DecompiledFunction`] carries, applied at the exit of the
//! `decompile` read in both analysis sources — the in-process Kuna arm
//! ([`ScanSource`](crate::ScanSource) over `KunaSource`) and the cached arm
//! ([`CachedScanSource`](crate::CachedScanSource)) — through the one entry
//! point [`strip_decompiler_noise`]. The seam trait itself does not change,
//! and test fakes in other crates are untouched because they never route
//! through this crate.
//!
//! **Raw stays raw on disk.** The cache's live tier fetches the engine's
//! unfiltered text and the filter runs *after* the cache read (ADR-0043
//! unchanged): the documents on disk remain the engine's own text for
//! debugging, and the whole filter is reversible by deleting the cache.
//!
//! **Hygiene, not evidence.** The filter names no findings, persists no
//! document, and adds no engine reads (ADR-0026's one-decompile-per-function
//! discipline untouched). Stripping is reported only through a debug-level
//! log naming the function and the families stripped. It is always on: no
//! per-binary or per-run toggle, because the filter is deterministic and
//! part of what the seam means.
//!
//! **Conservative by construction.** Only a complete recognized idiom
//! strips — never a lone XOR, cookie read, or comparison that might be the
//! function's own logic (ADR-0038's "a lone reading claims nothing"
//! precedent). And the never-empties rule: when stripping would leave a
//! body with no real content — a function that *is* the guard code, a
//! cookie thunk — nothing is stripped and the body passes through whole.
//!
//! **Locals survive unless orphaned.** A cookie local's declaration leaves
//! with the idiom only when the strips leave it unreferenced; any statement
//! that still names it keeps the declaration byte-for-byte.
//!
//! **How a family joins:** add a recognizer `fn(&str) -> Option<String>`
//! below that returns the stripped body only when it recognized and removed
//! a complete idiom, and one line in [`filter_body`] naming its family.
//! The seam, the trait, and both read exits never move.

use crate::model::DecompiledFunction;
use tracing::debug;

/// The guard runtime's named functions — the first recognized family, the
/// named guard calls. A /GS build calls these and nothing else in the guard
/// runtime by name, so a call statement naming one is compiler theater
/// wherever it sits in a body.
const GUARD_CALL_FUNCTIONS: [&str; 3] = [
    "__security_init_cookie",
    "__security_check_cookie",
    "__report_gsfailure",
];

/// The family labels the debug log names. Labels are stable across releases
/// so an operator's log filter keeps working as families join.
const NAMED_GUARD_CALLS: &str = "named-guard-calls";
const EPILOGUE_COOKIE_CHECK: &str = "epilogue-cookie-check";
const PROLOGUE_COOKIE_SAVE: &str = "prologue-cookie-save";

/// The pre-filter's one entry point, applied at the exit of both sources'
/// `decompile` read: in with the record as the engine rendered it, out with
/// every recognized noise family stripped from the body.
///
/// The name and signature ride through byte-for-byte — signature synthesis
/// and FFI binding read them, and the filter does not touch them. When
/// anything was stripped, a debug-level log names the function and the
/// families, so a run can be audited without re-decompiling anything.
pub(crate) fn strip_decompiler_noise(function: DecompiledFunction) -> DecompiledFunction {
    let (body, families) = filter_body(&function.body);
    if !families.is_empty() {
        debug!(
            function = %function.name,
            families = ?families,
            "decompiler-noise pre-filter stripped guard code from the decompile read"
        );
    }
    DecompiledFunction { body, ..function }
}

/// Run every family recognizer over one body, collecting the families that
/// actually stripped something. An unchanged body comes back byte-identical
/// and reports nothing.
///
/// Recognizers compose: each sees the body as the previous family left it.
/// The epilogue pass runs first because the complete idiom it recognizes
/// still carries its failure call inside the `if` — wrapper, comparison,
/// and call come out together as one shape. The named-guard-call pass then
/// clears the standalone calls that sit outside any wrapper, and the
/// comparison wrappers those calls hollow out are deliberately left behind:
/// a hollowed `if` is a lone comparison, which claims nothing to either
/// pass. The prologue pass runs last because whether its saved local is
/// orphaned is only knowable once the other families have had their turn:
/// the epilogue comparison and a standalone check call are the local's
/// usual last uses, and its declaration can go only after they are gone.
///
/// The never-empties rule lives here, over the combined strips: if they
/// would leave a body with not one word of real content in it — a function
/// that *is* the guard code — nothing stripped at all, and the original
/// body comes back whole with no families reported.
fn filter_body(body: &str) -> (String, Vec<&'static str>) {
    let mut stripped = body.to_string();
    let mut families: Vec<&'static str> = Vec::new();
    if let Some(after_epilogue) = strip_epilogue_cookie_check(&stripped) {
        stripped = after_epilogue;
        families.push(EPILOGUE_COOKIE_CHECK);
    }
    if let Some(after_calls) = strip_named_guard_calls(&stripped) {
        stripped = after_calls;
        families.push(NAMED_GUARD_CALLS);
    }
    if let Some(after_prologue) = strip_prologue_cookie_save(&stripped) {
        stripped = after_prologue;
        families.push(PROLOGUE_COOKIE_SAVE);
    }
    if !stripped.chars().any(|c| c.is_alphanumeric()) {
        return (body.to_string(), Vec::new());
    }
    (stripped, families)
}

/// The named-guard-calls family: a line carrying nothing but a call to one
/// of [`GUARD_CALL_FUNCTIONS`] — any indentation, any arguments — vanishes
/// along with its line break.
///
/// Everything else survives byte-for-byte: the call as part of a larger
/// statement (`x = __security_check_cookie(local_8);`), a call spelled with
/// a space before the parenthesis, a warning comment that merely names a
/// guard function, and a line whose call carries a trailing comment. The
/// whole-line match is the conservative gate: a line that is not exactly
/// one complete call claims nothing.
///
/// Answers [`None`] when no line matched. A body left with no real content
/// is caught not here but by the never-empties rule in [`filter_body`],
/// which passes the whole body through when the strips would empty it.
fn strip_named_guard_calls(body: &str) -> Option<String> {
    let mut stripped = String::with_capacity(body.len());
    let mut removed = false;
    for line in body.split_inclusive('\n') {
        let content = line.trim_end_matches(['\n', '\r']);
        if is_standalone_guard_call(content.trim()) {
            removed = true;
        } else {
            stripped.push_str(line);
        }
    }
    removed.then_some(stripped)
}

/// Whether `statement` is exactly one call — `name(arguments);` — to a
/// guard runtime function. The arguments may not cross a statement
/// boundary (no `;` inside), so a call that runs on into more code on its
/// line is not a standalone call and claims nothing.
fn is_standalone_guard_call(statement: &str) -> bool {
    let Some((name, rest)) = statement.split_once('(') else {
        return false;
    };
    GUARD_CALL_FUNCTIONS.contains(&name)
        && rest
            .strip_suffix(");")
            .is_some_and(|arguments| !arguments.contains(';'))
}

/// The cookie global's recognized spellings — the named MSVC global (the
/// engine's import-prefixed `___security_cookie` form carries this whole)
/// and the Ghidra-side alias — and `DAT_`-shaped unnamed globals, the form
/// the cookie takes when the engine leaves it unnamed.
const COOKIE_GLOBAL_SPELLINGS: [&str; 2] = ["__security_cookie", "stack_cookie_guard"];

/// The epilogue-cookie-check family (issue #272): the compare half of the
/// /GS canary — an `if (saved local compared against the cookie global)`
/// whose whole block is one standalone guard-runtime call — vanishes as
/// one shape, wrapper, comparison, and failure call together, from the
/// `if` line through the closing brace's line break.
///
/// Every partial shape claims nothing (the conservative gate, ADR-0038's
/// "a lone reading claims nothing" precedent): a condition without a
/// cookie-global spelling — that wrapper's call is the named-guard-call
/// family's business and its own; a block holding anything besides one
/// complete guard call, comments included; an empty block — the shell the
/// named-guard pass leaves behind is a lone comparison; an `else` attached
/// to the wrapper on either side, whose chain the removal would break; and
/// a paren or brace the scan cannot close, a truncated decompile. SEH/EH
/// frames, `try`/`catch` shapes, and landing pads never join a match —
/// only line-initial `if` statements are candidates, and a body's
/// exception structure survives byte-for-byte around any strip (P15's
/// findings territory; issue #272).
///
/// Answers [`None`] when no wrapper matched. A body a strip would empty is
/// caught by the never-empties rule in [`filter_body`], the same as the
/// named-guard family's.
fn strip_epilogue_cookie_check(body: &str) -> Option<String> {
    let mut stripped = String::with_capacity(body.len());
    // `copied` is the body's end already appended; `probe` is where the
    // candidate scan resumes — they part ways because a rejected candidate
    // survives in full while the scan moves past it.
    let mut copied = 0;
    let mut probe = 0;
    let mut removed = false;
    while let Some((line_start, if_start)) = find_if_statement(body, probe) {
        match epilogue_wrapper(body, if_start) {
            Some(remove_end) => {
                stripped.push_str(&body[copied..line_start]);
                copied = remove_end;
                probe = remove_end;
                removed = true;
            }
            None => probe = if_start + "if".len(),
        }
    }
    stripped.push_str(&body[copied..]);
    removed.then_some(stripped)
}

/// The next candidate `if` at or after `from`: a line whose trimmed content
/// opens with the `if` keyword and a word boundary, returning its line
/// start and the keyword. Decompiled statements open at the line start
/// (modulo indentation), so a line-opening `if` is what the wrapper parser
/// takes — an `if` reached through `else if` never opens its line and is
/// never a candidate.
fn find_if_statement(body: &str, from: usize) -> Option<(usize, usize)> {
    let mut offset = 0;
    for line in body.split_inclusive('\n') {
        if offset >= from {
            let content = line.trim_start();
            if content.starts_with("if") && !content["if".len()..].starts_with(is_identifier_char) {
                return Some((offset, offset + (line.len() - content.len())));
            }
        }
        offset += line.len();
    }
    None
}

/// Parse the candidate `if` keyword at `if_start` as one complete epilogue
/// idiom. The shape: `if (condition) {` with `condition` passing
/// [`is_cookie_comparison`], then a block — brace-matched string- and
/// comment-aware from the opening brace — holding nothing but one complete
/// standalone guard call, and no `else` attached to the wrapper on either
/// side. On success, the byte just past the closing brace's line break —
/// the end of the region the recognizer removes whole; on every other
/// shape, [`None`].
fn epilogue_wrapper(body: &str, if_start: usize) -> Option<usize> {
    let open_paren = skip_whitespace(body, if_start + "if".len());
    if body.get(open_paren..open_paren + "(".len()) != Some("(") {
        return None;
    }
    let close_paren = find_bounded(body, open_paren, b'(', b')')?;
    if !is_cookie_comparison(&body[open_paren + "(".len()..close_paren]) {
        return None;
    }
    let open_brace = skip_whitespace(body, close_paren + ")".len());
    if body.get(open_brace..open_brace + "{".len()) != Some("{") {
        return None;
    }
    let close_brace = find_bounded(body, open_brace, b'{', b'}')?;
    // The block is the failure call and nothing else — one statement, one
    // guard name, no comment or trailing text on it.
    let block = body[open_brace + "{".len()..close_brace].trim();
    if block.contains('\n') || !is_standalone_guard_call(block) {
        return None;
    }
    // The wrapper has to stand alone: an `else` joined to it on either
    // side would dangle from the wrong branch once the `if` is gone.
    if attached_else_before(body, if_start) || attached_else_after(&body[close_brace + "}".len()..])
    {
        return None;
    }
    // The removal takes the closing brace's whole line: only whitespace
    // may follow the brace, or the line's remaining text would slide up.
    let after_brace = &body[close_brace + "}".len()..];
    let line_end = after_brace.find('\n').unwrap_or(after_brace.len());
    if !after_brace[..line_end].trim_end().is_empty() {
        return None;
    }
    Some(
        close_brace
            + "}".len()
            + line_end
            + usize::from(after_brace.get(line_end..line_end + "\n".len()) == Some("\n")),
    )
}

/// The condition gate: the condition carries a comparison (`==` or `!=`)
/// and one of the cookie global's spellings. The saved local itself is
/// not named — chasing data flow is not a text filter's job — what keeps
/// the shape safe is the anchor the caller has already verified: the
/// wrapper's whole block is the guard runtime's failure call, which no
/// function's own logic ever names. A cookie global or comparison standing
/// without that anchor claims nothing.
fn is_cookie_comparison(condition: &str) -> bool {
    (condition.contains("==") || condition.contains("!=")) && names_cookie_global(condition)
}

/// Whether `text` names the cookie global under any recognized spelling.
fn names_cookie_global(text: &str) -> bool {
    COOKIE_GLOBAL_SPELLINGS
        .iter()
        .any(|spelling| text.contains(spelling))
        || names_dat_global(text)
}

/// Whether `text` names an unnamed engine global — `DAT_` followed by hex
/// digits, whole-word on both sides, so `XDAT_ff` names nothing.
fn names_dat_global(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut search = 0;
    while let Some(found) = text[search..].find("DAT_") {
        let at = search + found;
        let mut end = at + "DAT_".len();
        while bytes.get(end).is_some_and(u8::is_ascii_hexdigit) {
            end += 1;
        }
        let whole_word = (at == 0 || !identifier_byte(bytes[at - 1]))
            && end > at + "DAT_".len()
            && !bytes.get(end).copied().is_some_and(identifier_byte);
        if whole_word {
            return true;
        }
        search = at + "DAT_".len();
    }
    false
}

/// Whether the non-whitespace text right before the candidate keyword ends
/// in a whole-word `else` — an `else if` chain this removal must not break.
fn attached_else_before(body: &str, keyword: usize) -> bool {
    let before = body[..keyword].trim_end();
    before.ends_with("else") && !before[..before.len() - "else".len()].ends_with(is_identifier_char)
}

/// Whether the text right after the closing brace opens with a whole-word
/// `else` — the wrapper's own else arm.
fn attached_else_after(after_brace: &str) -> bool {
    let after = after_brace.trim_start();
    after.starts_with("else") && !after["else".len()..].starts_with(is_identifier_char)
}

/// The prologue-cookie-save family (issue #273): the save half of the /GS
/// canary — a line that is exactly one assignment storing the cookie global
/// XOR'd with a stack-slot address into a local (`local_8 = DAT_18004a040 ^
/// (ulonglong)&stack0x00000008;`) — vanishes along with its line break, and
/// each local the stripped saves wrote loses its bare declaration line once
/// no surviving statement names it — inside the body's declaration block
/// only, the run of bare declarations the decompiler opens right after the
/// body's brace. A local still referenced anywhere — a real statement, a
/// comment, a declaration beside the idiom — keeps its declaration
/// byte-for-byte; the sweep only ever follows a strip of the local's own
/// save.
///
/// The assignment shape is itself the anchor (the conservative gate,
/// ADR-0038's "a lone reading claims nothing" precedent): a lone XOR
/// (`x = a ^ b` with neither side the cookie or the stack slot), a lone
/// cookie save without the XOR (`uVar = __security_cookie;`), a cookie
/// XOR'd with a plain constant instead of a stack-slot address, a store
/// through a pointer or into a global, and a save sharing its line with
/// any other text all claim nothing and pass through.
///
/// Answers [`None`] when no save line matched. A body a strip would empty
/// is caught by the never-empties rule in [`filter_body`], the same as the
/// other families'.
fn strip_prologue_cookie_save(body: &str) -> Option<String> {
    let mut saved: Vec<&str> = Vec::new();
    let mut stripped = String::with_capacity(body.len());
    for line in body.split_inclusive('\n') {
        let content = line.trim_end_matches(['\n', '\r']);
        match cookie_save_local(content.trim()) {
            // A matched save line goes whole; the local it wrote is remembered
            // for the orphan sweep below.
            Some(local) => saved.push(local),
            None => stripped.push_str(line),
        }
    }
    if saved.is_empty() {
        return None;
    }
    // The orphan sweep, line-indexed so removals stay inside the body's
    // declaration block: Ghidra emits the local declarations as one block
    // opening right after the body's brace line, and that block — nothing
    // else — is where a declaration may go.
    let lines: Vec<&str> = stripped.split_inclusive('\n').collect();
    let block_end = declaration_block_end(&lines);
    let mut dropped = vec![false; lines.len()];
    for local in &saved {
        let referenced = lines.iter().enumerate().any(|(at, line)| {
            let content = line.trim_end_matches(['\n', '\r']).trim();
            !(at < block_end && is_declaration_of(content, local))
                && mentions_identifier(content, local)
        });
        if !referenced {
            for (at, line) in lines.iter().enumerate().take(block_end) {
                if is_declaration_of(line.trim_end_matches(['\n', '\r']).trim(), local) {
                    dropped[at] = true;
                }
            }
        }
    }
    Some(
        lines
            .iter()
            .enumerate()
            .filter(|(at, _)| !dropped[*at])
            .map(|(_, line)| *line)
            .collect(),
    )
}

/// The save-statement gate: the whole trimmed line is one simple
/// assignment `local = <cookie global> ^ <stack-slot address>;` — either
/// operand order — whose target is a plain local name, not a global or a
/// store through a pointer. Answers the local's name for the complete
/// shape, [`None`] for anything else.
fn cookie_save_local(statement: &str) -> Option<&str> {
    let assignment = statement.strip_suffix(';')?.trim_end();
    let (target, operands) = assignment.split_once('=')?;
    let (target, operands) = (target.trim(), operands.trim());
    if operands.contains('=')
        || target.is_empty()
        || !target.chars().all(is_identifier_char)
        || names_cookie_global(target)
        || names_dat_global(target)
    {
        return None;
    }
    // Exactly two operands — any third operand or nested expression is
    // the function's own arithmetic, not the save.
    let (first, second) = operands.split_once('^')?;
    if first.contains('^') || second.contains('^') {
        return None;
    }
    let is_save = (is_cookie_global_read(first) && is_stack_pointer_operand(second))
        || (is_cookie_global_read(second) && is_stack_pointer_operand(first));
    is_save.then_some(target)
}

/// Whether `operand` is a read of a cookie global whole — one of the named
/// spellings, with only import-prefixed underscores in front, or a bare
/// `DAT_`-shaped name — behind at most one cast. An expression that merely
/// mentions a cookie spelling (`__security_cookie - cookie`, a call) names
/// the global's value being computed on, not a read of the global itself,
/// and claims nothing.
fn is_cookie_global_read(operand: &str) -> bool {
    let operand = strip_cast(operand).trim();
    COOKIE_GLOBAL_SPELLINGS.iter().any(|spelling| {
        operand
            .strip_suffix(spelling)
            .is_some_and(|prefix| prefix.chars().all(|c| c == '_'))
    }) || operand
        .strip_prefix("DAT_")
        .is_some_and(|digits| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// Whether `operand` is the address of a stack slot — the decompiler's
/// `&stack0x`-plus-hex spelling of the stack-pointer-shaped operand the
/// save XORs the cookie with, behind at most one cast — and nothing else.
fn is_stack_pointer_operand(operand: &str) -> bool {
    strip_cast(operand)
        .trim()
        .strip_prefix("&stack0x")
        .is_some_and(|digits| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// Peel one leading `(cast)` off an operand so a cast global read or stack
/// address still reads as its bare shape; `(long)&stack0x...` →
/// `&stack0x...`.
fn strip_cast(operand: &str) -> &str {
    let operand = operand.trim();
    let Some(rest) = operand.strip_prefix('(') else {
        return operand;
    };
    match rest.find(')') {
        Some(close) if close > 0 => rest[close + 1..].trim_start(),
        _ => operand,
    }
}

/// One past the last line of the body's declaration block: the maximal run
/// of bare declaration lines opening right after the first line bearing an
/// opening brace. A body whose brace line never comes, or whose first line
/// after the brace already says something (a statement, a comment, even a
/// blank line), has no block at `0`, and no declaration is ever removed
/// from it — the sweep's removal candidates live only inside the block the
/// decompiler itself drew.
fn declaration_block_end(lines: &[&str]) -> usize {
    let open = match lines.iter().position(|line| {
        line.trim_end_matches(['\n', '\r'])
            .trim_end()
            .ends_with('{')
    }) {
        Some(at) => at + 1,
        None => return 0,
    };
    let mut end = open;
    while end < lines.len() && is_declaration(lines[end].trim_end_matches(['\n', '\r']).trim()) {
        end += 1;
    }
    end
}

/// Whether the trimmed line content is a bare declaration of `local`.
fn is_declaration_of(content: &str, local: &str) -> bool {
    declaration_parts(content).is_some_and(|(_, declared)| declared == local)
}

/// Whether the trimmed line content is a bare declaration of any local.
fn is_declaration(content: &str) -> bool {
    declaration_parts(content).is_some()
}

/// Split the trimmed line content into its declaration shape — non-empty
/// declarator text and the identifier declared just before the closing
/// semicolon — answering [`None`] for everything else: no semicolon, a
/// line ending on anything but an identifier, an assignment, a bare name
/// with nothing declaring it, or a line opening on a statement keyword.
/// `return local_8;` and `goto local_8;` end in a whole identifier plus a
/// semicolon exactly like a declaration does; it is the opening word that
/// tells them apart.
fn declaration_parts(content: &str) -> Option<(&str, &str)> {
    let declared = content.strip_suffix(';')?.trim_end();
    let bytes = declared.as_bytes();
    let last = *bytes.last()?;
    if !identifier_byte(last) || declared.contains('=') {
        return None;
    }
    let mut at = bytes.len() - 1;
    while at > 0 && identifier_byte(bytes[at - 1]) {
        at -= 1;
    }
    let (declarator, name) = declared.split_at(at);
    if declarator.is_empty() || opens_on_statement_keyword(declarator) {
        return None;
    }
    Some((declarator, name))
}

/// Whether a would-be declaration's declarator text opens on a C statement
/// keyword — the tell that a `<keyword> <name>;` line is a statement
/// wearing a declaration's shape. Types (`unsigned long`, `ulonglong`,
/// `undefined8`) are no member of the set.
fn opens_on_statement_keyword(declarator: &str) -> bool {
    const STATEMENT_KEYWORDS: [&str; 7] = [
        "return", "goto", "break", "continue", "case", "default", "else",
    ];
    STATEMENT_KEYWORDS.contains(&declarator.split_whitespace().next().unwrap_or_default())
}

/// Whether `text` names `identifier` as a whole word — the bytes on either
/// side are never identifier bytes, so `local_8` never reads inside
/// `local_88` or `savelocal_8`.
fn mentions_identifier(text: &str, identifier: &str) -> bool {
    let bytes = text.as_bytes();
    let mut search = 0;
    while let Some(found) = text[search..].find(identifier) {
        let at = search + found;
        let end = at + identifier.len();
        let whole_word = (at == 0 || !identifier_byte(bytes[at - 1]))
            && !bytes.get(end).copied().is_some_and(identifier_byte);
        if whole_word {
            return true;
        }
        search = end;
    }
    false
}

/// Walk from `open` (naming an opener byte) to its matching closer:
/// nesting is tracked, and string literals, character literals, and `//`
/// and `/* */` comments are skipped whole, so a closer spelled inside
/// text — `FUN_x("}")` — never ends the scan. [`None`] for a construct the
/// body never closes, a truncated decompile, which claims nothing.
fn find_bounded(body: &str, open: usize, open_char: u8, close_char: u8) -> Option<usize> {
    let bytes = body.as_bytes();
    let mut depth = 0usize;
    let mut at = open;
    while at < bytes.len() {
        match bytes[at] {
            b'"' | b'\'' => at = skip_literal(bytes, at)?,
            b'/' if bytes.get(at + 1) == Some(&b'/') => {
                at = body[at..].find('\n').map_or(bytes.len(), |line| at + line);
            }
            b'/' if bytes.get(at + 1) == Some(&b'*') => {
                at = body[at..]
                    .find("*/")
                    .map_or(bytes.len(), |end| at + end + 2);
            }
            byte if byte == open_char => depth += 1,
            byte if byte == close_char => {
                depth -= 1;
                if depth == 0 {
                    return Some(at);
                }
            }
            _ => {}
        }
        at += 1;
    }
    None
}

/// The byte just past a `"` or `'` literal opening at `open`, honoring `\`
/// escapes; [`None`] when the line never closes it — a truncated
/// decompile's dangling literal claims nothing.
fn skip_literal(bytes: &[u8], open: usize) -> Option<usize> {
    let quote = bytes[open];
    let mut at = open + 1;
    while at < bytes.len() {
        match bytes[at] {
            b'\\' => at += 2,
            b'\n' => return None,
            byte if byte == quote => return Some(at + 1),
            _ => at += 1,
        }
    }
    None
}

fn skip_whitespace(text: &str, mut at: usize) -> usize {
    let bytes = text.as_bytes();
    while matches!(bytes.get(at).copied(), Some(b' ' | b'\t' | b'\r' | b'\n')) {
        at += 1;
    }
    at
}

fn is_identifier_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

fn identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Debug;
    use std::sync::{Arc, Mutex};
    use tracing::field::{Field, Visit};
    use tracing::{Event, Level, Metadata, Subscriber};

    /// A minimal capturing subscriber: every event's level and its
    /// `%`/`?`-formatted fields (both arrive through `record_debug`).
    type CapturedEvents = Vec<(Level, Vec<(String, String)>)>;

    #[derive(Default)]
    struct Capture(Arc<Mutex<CapturedEvents>>);

    impl Subscriber for Capture {
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, event: &Event<'_>) {
            let mut values = Values::default();
            event.record(&mut values);
            self.0
                .lock()
                .expect("capture lock")
                .push((*event.metadata().level(), values.0));
        }
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
        fn current_span(&self) -> tracing_core::span::Current {
            tracing_core::span::Current::none()
        }
        fn enabled(&self, _: &Metadata<'_>) -> bool {
            true
        }
    }

    #[derive(Default)]
    struct Values(Vec<(String, String)>);

    impl Visit for Values {
        fn record_debug(&mut self, field: &Field, value: &dyn Debug) {
            self.0
                .push((field.name().to_string(), format!("{value:?}")));
        }
    }

    fn function(name: &str, signature: &str, body: &str) -> DecompiledFunction {
        DecompiledFunction {
            name: name.into(),
            signature: signature.into(),
            body: body.into(),
        }
    }

    /// Strip one body and return what came back, asserting the identity
    /// fields rode through untouched on every call.
    fn strip(name: &str, body: &str) -> DecompiledFunction {
        let signature = format!("{name}(int param_1)");
        let out = strip_decompiler_noise(function(name, &signature, body));
        assert_eq!(out.name, name);
        assert_eq!(out.signature, signature);
        out
    }

    #[test]
    fn a_standalone_guard_call_vanishes_wherever_it_sits() {
        let stripped = strip(
            "FUN_180045a00",
            "{\n  __security_init_cookie();\n  if (param_1 != 0) {\n\t\t__security_check_cookie(local_8);\n  }\n  FUN_180045a00(param_1 + 1);\n  __report_gsfailure();\n  return;\n}\n",
        );
        assert_eq!(
            stripped.body,
            "{\n  if (param_1 != 0) {\n  }\n  FUN_180045a00(param_1 + 1);\n  return;\n}\n",
            "every standalone call line is gone, real statements and braces byte-identical"
        );
    }

    #[test]
    fn a_body_without_guard_calls_survives_byte_for_byte() {
        let body = "undefined8\nfixture_tick(int param_1)\n\n{\n  int local_8;\n  local_8 = param_1 ^ 0x22;\n  return (ulong)(local_8 == DAT_18004a040);\n}\n";
        let stripped = strip("fixture_tick", body);
        assert_eq!(
            stripped.body, body,
            "a canary-free body passes through unchanged"
        );
    }

    #[test]
    fn a_call_that_is_not_a_whole_line_claims_nothing() {
        let body = concat!(
            "{\n",
            "  uVar = __security_check_cookie(local_8);\n",
            "  __report_gsfailure (1234);\n",
            "  __report_gsfailure(); /* never returns */\n",
            "  /* WARNING: Function: __security_check_cookie replaced with injection */\n",
            "  FUN_180004470(\"__report_gsfailure();\");\n",
            "  my_report_gsfailure();\n",
            "  __security_check_cookie(local_8);\n",
            "}\n",
        );
        let stripped = strip("FUN_180045a00", body);
        assert_eq!(
            stripped.body,
            concat!(
                "{\n",
                "  uVar = __security_check_cookie(local_8);\n",
                "  __report_gsfailure (1234);\n",
                "  __report_gsfailure(); /* never returns */\n",
                "  /* WARNING: Function: __security_check_cookie replaced with injection */\n",
                "  FUN_180004470(\"__report_gsfailure();\");\n",
                "  my_report_gsfailure();\n",
                "}\n",
            ),
            "only the final line was one complete standalone call"
        );
    }

    #[test]
    fn a_body_that_is_entirely_guard_calls_passes_through_whole() {
        let calls = "  __security_init_cookie();\n  __security_check_cookie(local_8);\n  __report_gsfailure();\n";
        let stripped = strip("__security_init_cookie", calls);
        assert_eq!(
            stripped.body, calls,
            "never-empties: the call listing survives whole"
        );

        let thunk = "{\n  __report_gsfailure();\n}\n";
        let stripped = strip("thunk_gsfailure", thunk);
        assert_eq!(
            stripped.body, thunk,
            "never-empties: a body left with only braces has no real content, so nothing strips"
        );
    }

    #[test]
    fn the_if_wrapped_cookie_compare_strips_whole_with_the_failure_call() {
        let stripped = strip(
            "FUN_1800012a0",
            concat!(
                "{\n",
                "  undefined8 local_8;\n",
                "  local_8 = DAT_18004a040 ^ (ulonglong)&stack0x00000008;\n",
                "  FUN_180045a00(param_1);\n",
                "  if (local_8 != DAT_18004a040) {\n",
                "    __report_gsfailure();\n",
                "  }\n",
                "  if (local_8 == __security_cookie ^ 0x22) { __report_gsfailure(); }\n",
                "  if (local_8 != stack_cookie_guard) {\n",
                "    __report_gsfailure();\n",
                "  }\n",
                "  return local_8;\n",
                "}\n",
            ),
        );
        assert_eq!(
            stripped.body,
            concat!(
                "{\n",
                "  undefined8 local_8;\n",
                "  FUN_180045a00(param_1);\n",
                "  return local_8;\n",
                "}\n",
            ),
            "every complete wrapper — multi-line and single-line, every cookie-global \
             spelling — is gone whole, the prologue save line went with the #273 \
             family, and the local keeps its declaration because the return still \
             names it while the real statements around all this are byte-identical"
        );
    }

    #[test]
    fn a_lone_comparison_claims_nothing() {
        let body = concat!(
            "{\n",
            "  bVar = local_8 == DAT_18004a040;\n",
            "  if (local_8 != DAT_18004a040) {\n",
            "    FUN_180045a00(param_1);\n",
            "  }\n",
            "  if (local_8 != DAT_18004a040) {\n",
            "  }\n",
            "  return (ulong)bVar;\n",
            "}\n",
        );
        let stripped = strip("FUN_180045a00", body);
        assert_eq!(
            stripped.body, body,
            "a bare comparison, a wrapper holding real statements, and an empty \
             comparison shell all lack the failure-call anchor and stand untouched — \
             ADR-0038's lone reading claims nothing"
        );
    }

    #[test]
    fn a_lone_cookie_global_read_claims_nothing() {
        let body = concat!(
            "{\n",
            "  local_8 = DAT_18004a040;\n",
            "  uVar = __security_cookie;\n",
            "  if (uVar != 0) {\n",
            "    FUN_180045a00(uVar);\n",
            "  }\n",
            "  return uVar ^ local_8;\n",
            "}\n",
        );
        let stripped = strip("FUN_180045a00", body);
        assert_eq!(
            stripped.body, body,
            "cookie globals copied whole into locals, without the save's XOR against \
             a stack-slot address or a compare-check shape, pass through byte-for-byte"
        );
    }

    #[test]
    fn a_full_prologue_and_epilogue_canary_body_comes_back_with_the_idiom_gone() {
        let stripped = strip(
            "FUN_1800012a0",
            concat!(
                "{\n",
                "  undefined8 local_8;\n",
                "  ulong local_4;\n",
                "  local_8 = DAT_18004a040 ^ (ulonglong)&stack0x00000008;\n",
                "  local_4 = param_1 * 3;\n",
                "  FUN_180045a00(local_4);\n",
                "  if (local_8 != DAT_18004a040) {\n",
                "    __report_gsfailure();\n",
                "  }\n",
                "  return local_4;\n",
                "}\n",
            ),
        );
        assert_eq!(
            stripped.body,
            concat!(
                "{\n",
                "  ulong local_4;\n",
                "  local_4 = param_1 * 3;\n",
                "  FUN_180045a00(local_4);\n",
                "  return local_4;\n",
                "}\n",
            ),
            "the whole canary idiom — save line, wrapper with its failure call — is \
             gone and the cookie local its strips orphaned lost its declaration too, \
             while the referenced local and the real statements are byte-identical"
        );
    }

    #[test]
    fn a_local_still_referenced_after_the_save_strips_keeps_its_declaration() {
        let stripped = strip(
            "FUN_1800012a0",
            concat!(
                "{\n",
                "  undefined8 local_8;\n",
                "  local_8 = DAT_18004a040 ^ (ulonglong)&stack0x00000008;\n",
                "  FUN_180045a00(param_1);\n",
                "  if (local_8 != DAT_18004a040) {\n",
                "    FUN_180045a00(local_8);\n",
                "    __report_gsfailure();\n",
                "  }\n",
                "  return local_8;\n",
                "}\n",
            ),
        );
        assert_eq!(
            stripped.body,
            concat!(
                "{\n",
                "  undefined8 local_8;\n",
                "  FUN_180045a00(param_1);\n",
                "  if (local_8 != DAT_18004a040) {\n",
                "    FUN_180045a00(local_8);\n",
                "  }\n",
                "  return local_8;\n",
                "}\n",
            ),
            "the save line goes, but the statements around it still name local_8 — \
             its declaration and every reference to it survive byte-for-byte"
        );
    }

    #[test]
    fn a_lone_xor_or_a_lone_cookie_save_claims_nothing() {
        let body = concat!(
            "{\n",
            "  local_8 = param_1 ^ 0x22;\n",
            "  uVar = __security_cookie;\n",
            "  local_c = __security_cookie ^ 0x22;\n",
            "  DAT_18004a040 = local_8 ^ (ulonglong)&stack0x00000008;\n",
            "  local_10 = (ulonglong)&stack0x00000010;\n",
            "  if (local_8 == DAT_18004a040 ^ (ulonglong)&stack0x00000008) {\n",
            "    FUN_180045a00(local_8);\n",
            "  }\n",
            "  return local_8 ^ uVar ^ local_c ^ local_10;\n",
            "}\n",
        );
        let stripped = strip("FUN_180045a00", body);
        assert_eq!(
            stripped.body, body,
            "the function's own XOR, a cookie copied without the XOR, a cookie XOR'd \
             with a constant instead of a stack-slot address, a store into a global, \
             a stack address without a cookie, and the shape sitting inside an `if` \
             are all incomplete idioms and pass through byte-for-byte"
        );
    }

    #[test]
    fn every_cookie_spelling_and_the_reversed_operand_join_the_prologue_family() {
        let stripped = strip(
            "FUN_1800012a0",
            concat!(
                "{\n",
                "  local_8 = ___security_cookie ^ (ulonglong)&stack0x00000008;\n",
                "  local_18 = stack_cookie_guard ^ (long)&stack0xffffffffffffffe8;\n",
                "  local_20 = (ulonglong)&stack0x00000018 ^ DAT_18004a040;\n",
                "  return local_8 ^ local_18 ^ local_20;\n",
                "}\n",
            ),
        );
        assert_eq!(
            stripped.body, "{\n  return local_8 ^ local_18 ^ local_20;\n}\n",
            "the import-prefixed `___security_cookie` and `stack_cookie_guard` \
             spellings and their DAT_-shaped forms, either operand order, and any \
             cast shape strip; the return naming the locals keeps them referenced"
        );
    }

    #[test]
    fn a_save_sharing_its_line_with_anything_else_claims_nothing() {
        let body = concat!(
            "{\n",
            "  local_8 = DAT_18004a040 ^ (ulonglong)&stack0x00000008; // security cookie\n",
            "  local_8 = DAT_18004a040 ^ (ulonglong)&stack0x00000008 + 4;\n",
            "  local_8 ^= DAT_18004a040 ^ (ulonglong)&stack0x00000008;\n",
            "  uVar = DAT_18004a040 ^ (ulonglong)&stack0x00000008 ^ DAT_18004a050;\n",
            "  return uVar;\n",
            "}\n",
        );
        let stripped = strip("FUN_180045a00", body);
        assert_eq!(
            stripped.body, body,
            "a trailing comment, an offset stack address, a compound assignment, and \
             a three-operand XOR are not the one complete save statement and stand"
        );
    }

    #[test]
    fn an_seh_shaped_body_with_canary_decoys_survives_byte_for_byte() {
        let body = concat!(
            "{\n",
            "  try {\n",
            "    FUN_180001160(param_1);\n",
            "  }\n",
            "  catch(...){\n",
            "    FUN_180001180(local_8);\n",
            "  }\n",
            "  local_8 = local_8 ^ 0x22;\n",
            "  if (local_8 != DAT_18004a040) {\n",
            "  }\n",
            "  return;\n",
            "}\n",
        );
        let stripped = strip("FUN_180001140", body);
        assert_eq!(
            stripped.body, body,
            "the try/catch frame and the hollowed cookie-compare shell beside it are \
             P15's findings territory and pass through untouched"
        );
    }

    #[test]
    fn the_epilogue_strips_from_an_seh_function_and_the_frame_stands_byte_identical() {
        let stripped = strip(
            "FUN_180001140",
            concat!(
                "{\n",
                "  try {\n",
                "    FUN_180001160(param_1);\n",
                "  }\n",
                "  catch(...){\n",
                "    FUN_180001180(local_8);\n",
                "  }\n",
                "  if (local_8 != DAT_18004a040) {\n",
                "    __report_gsfailure();\n",
                "  }\n",
                "  return;\n",
                "}\n",
            ),
        );
        assert_eq!(
            stripped.body,
            concat!(
                "{\n",
                "  try {\n",
                "    FUN_180001160(param_1);\n",
                "  }\n",
                "  catch(...){\n",
                "    FUN_180001180(local_8);\n",
                "  }\n",
                "  return;\n",
                "}\n",
            ),
            "the cookie check riding in an SEH function's epilogue is gone — which is \
             what makes P15's canary false-fire gate redundant insurance — while the \
             try/catch frame around it is byte-identical"
        );
    }

    #[test]
    fn a_wrapper_condition_naming_no_cookie_global_claims_nothing() {
        let stripped = strip(
            "FUN_180045a00",
            "{\n  if (param_1 != 0) {\n    __report_gsfailure();\n  }\n  return;\n}\n",
        );
        assert_eq!(
            stripped.body, "{\n  if (param_1 != 0) {\n  }\n  return;\n}\n",
            "the standalone call still goes (the named-guard family's), but a \
             comparison without a cookie global is not the epilogue idiom — the \
             wrapper stands"
        );
    }

    #[test]
    fn a_wrapper_block_holding_more_than_the_failure_call_claims_nothing() {
        let stripped = strip(
            "FUN_180045a00",
            concat!(
                "{\n",
                "  if (local_8 != DAT_18004a040) {\n",
                "    FUN_180045a00(param_1);\n",
                "    __report_gsfailure();\n",
                "  }\n",
                "  return;\n",
                "}\n",
            ),
        );
        assert_eq!(
            stripped.body,
            concat!(
                "{\n",
                "  if (local_8 != DAT_18004a040) {\n",
                "    FUN_180045a00(param_1);\n",
                "  }\n",
                "  return;\n",
                "}\n",
            ),
            "the wrapper is not the complete idiom — only its standalone call line \
             goes, and the comparison and braces survive byte-for-byte"
        );
    }

    #[test]
    fn an_else_attached_wrapper_is_left_whole() {
        let stripped = strip(
            "FUN_180045a00",
            concat!(
                "{\n",
                "  if (param_1 != 0) {\n",
                "    FUN_180045a00(param_1);\n",
                "  } else if (local_8 != DAT_18004a040) {\n",
                "    __report_gsfailure();\n",
                "  }\n",
                "  if (local_8 != DAT_18004a040) {\n",
                "    __report_gsfailure();\n",
                "  } else {\n",
                "    FUN_180045a00(local_8);\n",
                "  }\n",
                "  return;\n",
                "}\n",
            ),
        );
        assert_eq!(
            stripped.body,
            concat!(
                "{\n",
                "  if (param_1 != 0) {\n",
                "    FUN_180045a00(param_1);\n",
                "  } else if (local_8 != DAT_18004a040) {\n",
                "  }\n",
                "  if (local_8 != DAT_18004a040) {\n",
                "  } else {\n",
                "    FUN_180045a00(local_8);\n",
                "  }\n",
                "  return;\n",
                "}\n",
            ),
            "removing an else-attached wrapper would dangle the chain, so both \
             wrappers stand whole — only their standalone call lines go"
        );
    }

    #[test]
    fn a_wrapper_nested_in_an_unrecognized_if_strips_from_inside() {
        let stripped = strip(
            "FUN_180045a00",
            concat!(
                "{\n",
                "  if (param_1 != 0) {\n",
                "    if (local_8 != DAT_18004a040) {\n",
                "      __report_gsfailure();\n",
                "    }\n",
                "  }\n",
                "  return;\n",
                "}\n",
            ),
        );
        assert_eq!(
            stripped.body, "{\n  if (param_1 != 0) {\n  }\n  return;\n}\n",
            "the unrecognized outer wrapper stays and the complete inner idiom is \
             removed whole from within it"
        );
    }

    #[test]
    fn a_body_that_is_only_the_cookie_check_passes_through_whole() {
        let body = "{\n  if (local_8 != DAT_18004a040) {\n    __report_gsfailure();\n  }\n}\n";
        let stripped = strip("gsfailure_thunk", body);
        assert_eq!(
            stripped.body, body,
            "never-empties: stripping the only idiom would leave bare braces, so the \
             body passes through whole"
        );
    }

    #[test]
    fn string_and_comment_text_naming_the_idiom_claims_nothing() {
        let body = concat!(
            "{\n",
            "  FUN_180004470(\"__report_gsfailure();\");\n",
            "  if (local_8 == DAT_18004a040) { FUN_180004470(\"}\"); }\n",
            "  /* if (local_8 != DAT_18004a040) { __report_gsfailure(); } */\n",
            "  return;\n",
            "}\n",
        );
        let stripped = strip("FUN_180045a00", body);
        assert_eq!(
            stripped.body, body,
            "the idiom spelled inside a string literal or a comment claims nothing, \
             and a brace inside a string never ends the block scan"
        );
    }

    #[test]
    fn the_epilogue_strip_is_logged_naming_its_family() {
        let capture = std::sync::Arc::new(Capture::default());
        let shared = Arc::clone(&capture.0);
        tracing::subscriber::with_default(Arc::clone(&capture), || {
            strip(
                "FUN_1800012a0",
                "{\n  if (local_8 != DAT_18004a040) {\n    __report_gsfailure();\n  }\n  return;\n}\n",
            );
        });
        let events = shared.lock().expect("capture lock");
        let stripping = events
            .iter()
            .find(|(_, values)| values.iter().any(|(name, _)| name == "families"))
            .expect("the stripping is reported");
        assert_eq!(stripping.0, Level::DEBUG, "the report is debug-level");
        let fields: std::collections::BTreeMap<_, _> = stripping.1.iter().cloned().collect();
        assert_eq!(
            fields.get("function").map(String::as_str),
            Some("FUN_1800012a0")
        );
        assert_eq!(
            fields.get("families").map(String::as_str),
            Some(format!("{:?}", vec![EPILOGUE_COOKIE_CHECK]).as_str()),
            "the failure call went with its wrapper, so only the epilogue family fired"
        );
    }

    #[test]
    fn the_signature_field_survives_filtering_byte_for_byte() {
        // The guard functions' own signatures name guard functions — the
        // filter must respect the field even where the words appear.
        let signature = "void __security_check_cookie(uint param_1)";
        let out = strip_decompiler_noise(function(
            "__security_check_cookie",
            signature,
            "{\n  if (param_1 == DAT_18004a040) { return; }\n  __report_gsfailure();\n}\n",
        ));
        assert_eq!(out.signature, signature);
        assert_eq!(out.name, "__security_check_cookie");
        assert!(
            out.body
                .contains("if (param_1 == DAT_18004a040) { return; }"),
            "the body around the stripped call survives"
        );
    }

    #[test]
    fn stripping_is_logged_at_debug_naming_the_function_and_family() {
        let capture = std::sync::Arc::new(Capture::default());
        let shared = Arc::clone(&capture.0);
        tracing::subscriber::with_default(Arc::clone(&capture), || {
            strip(
                "FUN_1800011c0",
                "{\n  __security_init_cookie();\n  return;\n}\n",
            );
        });
        let events = shared.lock().expect("capture lock");
        let stripping = events
            .iter()
            .find(|(_, values)| values.iter().any(|(name, _)| name == "families"))
            .expect("the stripping is reported");
        assert_eq!(stripping.0, Level::DEBUG, "the report is debug-level");
        let fields: std::collections::BTreeMap<_, _> = stripping.1.iter().cloned().collect();
        assert_eq!(
            fields.get("function").map(String::as_str),
            Some("FUN_1800011c0")
        );
        assert_eq!(
            fields.get("families").map(String::as_str),
            Some(format!("{:?}", vec![NAMED_GUARD_CALLS]).as_str())
        );
    }

    #[test]
    fn the_prologue_strip_is_logged_naming_both_canary_families() {
        let capture = std::sync::Arc::new(Capture::default());
        let shared = Arc::clone(&capture.0);
        tracing::subscriber::with_default(Arc::clone(&capture), || {
            strip(
                "FUN_1800012a0",
                concat!(
                    "{\n",
                    "  undefined8 local_8;\n",
                    "  local_8 = DAT_18004a040 ^ (ulonglong)&stack0x00000008;\n",
                    "  if (local_8 != DAT_18004a040) {\n",
                    "    __report_gsfailure();\n",
                    "  }\n",
                    "  return;\n",
                    "}\n",
                ),
            );
        });
        let events = shared.lock().expect("capture lock");
        let stripping = events
            .iter()
            .find(|(_, values)| values.iter().any(|(name, _)| name == "families"))
            .expect("the stripping is reported");
        assert_eq!(stripping.0, Level::DEBUG, "the report is debug-level");
        let fields: std::collections::BTreeMap<_, _> = stripping.1.iter().cloned().collect();
        assert_eq!(
            fields.get("families").map(String::as_str),
            Some(format!("{:?}", vec![EPILOGUE_COOKIE_CHECK, PROLOGUE_COOKIE_SAVE]).as_str()),
            "the whole canary body reports its two families in pass order, and the \
             failure call went with its wrapper so the named-guard family stayed quiet"
        );
    }

    #[test]
    fn a_body_that_strips_nothing_logs_nothing() {
        let capture = std::sync::Arc::new(Capture::default());
        let shared = Arc::clone(&capture.0);
        tracing::subscriber::with_default(Arc::clone(&capture), || {
            strip("fixture_tick", "{\n  return 1;\n}\n");
        });
        let events = shared.lock().expect("capture lock");
        assert!(
            events
                .iter()
                .all(|(_, values)| !values.iter().any(|(name, _)| name == "families")),
            "hygiene stays silent when it changes nothing: {events:?}"
        );
    }

    /// The module doc's promise: the filter is a pure text pass — the same
    /// input never strips differently, so deleting the cache really is the
    /// whole undo.
    #[test]
    fn filtering_is_idempotent_so_a_double_pass_changes_nothing() {
        let body = "{\n  __report_gsfailure();\n  return;\n}\n";
        let once = strip("FUN_180045a00", body);
        let twice = strip("FUN_180045a00", &once.body);
        assert_eq!(
            twice.body, once.body,
            "a second pass over a clean body is nothing"
        );

        let idiom = concat!(
            "{\n",
            "  undefined8 local_8;\n",
            "  local_8 = DAT_18004a040 ^ (ulonglong)&stack0x00000008;\n",
            "  if (local_8 != DAT_18004a040) {\n",
            "    __report_gsfailure();\n",
            "  }\n",
            "  __security_init_cookie();\n",
            "  return;\n",
            "}\n",
        );
        let once = strip("FUN_1800012a0", idiom);
        assert_eq!(
            once.body, "{\n  return;\n}\n",
            "the wrapper goes with its call, the save line and the orphaned \
             declaration with it, and the standalone init call follows them"
        );
        let twice = strip("FUN_1800012a0", &once.body);
        assert_eq!(
            twice.body, once.body,
            "a second pass strips nothing further"
        );
    }
}
