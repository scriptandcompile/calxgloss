//! Self-recursion detection.
//!
//! A function that calls itself is reported with its self-call count and
//! whether any call sits in tail position. The line scan starts after the
//! body's opening brace, so the signature line — which contains the
//! function's own name — never counts as a call.
//!
//! The same control flow graph the loop and density readings use also
//! sharpens this record in place. Where the graph shows a self-call
//! nested inside a loop body, the record flags it as a stack-depth
//! multiplier. The graph also sharpens the tail-call reading: a call
//! counts as a tail call when the call block's only exit is the
//! function's return and that return hands back exactly the call's
//! result. This catches tail calls spread over several lines or nested
//! in a block, which the line rule misses. The line rule
//! (`return name(...)`) stays as the floor, so the graph reading only
//! ever adds tail calls, never drops one.

use calxgloss_types::Confidence;

use crate::cfg::{Cfg, Terminator};
use crate::chain::outside_strings;
use crate::types::SelfRecursion;

/// Detector for functions that call themselves.
#[derive(Debug, Clone, Default)]
pub struct RecursionDetector;

impl RecursionDetector {
    /// Create a detector (the detector has no tunable thresholds).
    pub fn new() -> Self {
        RecursionDetector
    }

    /// Detect self-recursion in one decompiled function body.
    pub(crate) fn detect(&self, name: &str, code: &str) -> Option<SelfRecursion> {
        let lines: Vec<&str> = code.lines().collect();
        let body_start = lines
            .iter()
            .position(|l| l.trim_start().starts_with('{'))
            .map(|i| i + 1)
            .unwrap_or(0);

        let needle = format!("{}(", name);
        let cfg = Cfg::build(code);
        let loop_bodies = cfg.loop_body_spans();
        let mut calls = 0usize;
        let mut tail_call = false;
        let mut in_loop = false;
        for (idx, line) in lines.iter().enumerate().skip(body_start) {
            let trimmed = line.trim();
            let hits = count_ident_calls(trimmed, &needle);
            if hits == 0 {
                continue;
            }
            calls += hits;
            // The line rule is the floor; the graph reading only adds.
            tail_call |= is_tail_return(trimmed, name) || graph_tail_call(&cfg, &lines, idx, name);
            in_loop |= loop_bodies
                .iter()
                .any(|(start, end)| *start <= idx && idx < *end);
        }
        if calls == 0 {
            return None;
        }

        // Base 70, +10 for a tail call, +5 per extra self-call, capped at 90.
        let score = (70 + u8::from(tail_call) * 10 + (calls as u8 - 1) * 5).min(90);
        let suggestion = if tail_call {
            "replace with loop { ... } (tail call)".to_string()
        } else if in_loop || calls >= 2 {
            // The self-call is one a loop re-enters every iteration, or
            // the recursion branches: the call tree's depth can outgrow
            // the stack, so the suggestion names the explicit-stack
            // alternative too.
            format!(
                "keep recursive fn {}(...) or carry the work on an explicit stack",
                name
            )
        } else {
            format!("keep recursive fn {}(...) or convert to loop", name)
        };
        let mut evidence = format!("{}() calls itself {}x", name, calls);
        if tail_call {
            evidence.push_str(" (tail call)");
        }
        if in_loop {
            evidence.push_str(" (nested in a loop)");
        }
        Some(SelfRecursion {
            function: name.to_string(),
            is_tail_call: tail_call,
            self_calls: calls,
            in_loop,
            suggestion,
            confidence: Confidence::new(score),
            evidence,
        })
    }
}

/// True when the line returns the call's result directly — a `return
/// name(...)` whose call result is all that is returned (also behind a
/// one-line guard like `if (a) return name(x);`), so the frame can be
/// reused. `return name(x) + 1` is *not* a tail call.
fn is_tail_return(line: &str, name: &str) -> bool {
    let marker = format!("return {name}(");
    let mut from = 0usize;
    while let Some(pos) = line[from..].find(&marker) {
        let rest = &line[from + pos + marker.len()..];
        if returns_call_result(rest) {
            return true;
        }
        from += pos + marker.len();
    }
    false
}

/// The graph's tail reading of a call site. Two things must hold.
/// First, the call sits in a block whose only exit is the function's
/// return: the block ends at the `return` itself, or falls or jumps to
/// a return block as its one and only way out. Second, that return
/// hands back exactly what the call produced: `return name(...)` read
/// across the block, or the spread-over-lines `v = name(...); ...
/// return v;`. A combined result (`return name(x) + 1`) hands back
/// more than the call, so it is not a tail call.
fn graph_tail_call(cfg: &Cfg, lines: &[&str], line: usize, name: &str) -> bool {
    let Some(block) = cfg.block_at(line).and_then(|id| cfg.block(id)) else {
        return false;
    };
    // The block's one exit, if it is a return at all: its own last
    // line, or the single return block it falls or jumps to as its one
    // and only way out.
    let return_block = match block.terminator {
        Terminator::Return => block,
        Terminator::FallThrough | Terminator::Goto => {
            let mut successors = cfg.successors(block.id);
            let (Some(next), None) = (successors.next(), successors.next()) else {
                return false;
            };
            match cfg.block(next) {
                Some(b) if b.terminator == Terminator::Return => b,
                _ => return false,
            }
        }
        _ => return false,
    };
    // The return statement: the block's last line, which the graph
    // classified as a return (a leading `}` peeled like `classify`
    // peels it).
    let ret_stmt = lines[return_block.end - 1].trim();
    let ret_stmt = ret_stmt.strip_prefix('}').unwrap_or(ret_stmt).trim_start();
    let Some(expr) = ret_stmt.strip_prefix("return").map(str::trim) else {
        return false;
    };
    let expr = expr.trim_end_matches(';').trim();
    // `return name(...)`: the call's result is all that comes back.
    if let Some(args) = call_args(expr, name) {
        return returns_call_result(args);
    }
    // `return v;` — the call's result stored in a local and handed
    // straight back. The assignment scan runs over the call block,
    // minus its own return line when the two share one block.
    if !is_identifier(expr) {
        return false;
    }
    let scan_end = if block.id == return_block.id {
        block.end - 1
    } else {
        block.end
    };
    returns_assigned_call(lines, block.start, scan_end, name, expr)
}

/// True when the last plain assignment to `var` in `lines[start..end]`
/// is exactly `var = name(...)` — the call's result, nothing combined.
/// A later reassignment (`v = 0;`) breaks the reading.
fn returns_assigned_call(lines: &[&str], start: usize, end: usize, name: &str, var: &str) -> bool {
    let mut call_returns = false;
    for raw in &lines[start..end] {
        // String-blind, like every other reading in the crate.
        let line = outside_strings(raw);
        if let Some(rhs) = assignment_rhs(&line, var) {
            call_returns = matches!(call_args(rhs, name), Some(args) if returns_call_result(args));
        }
    }
    call_returns
}

/// The text following the opening parenthesis when `s` starts with a
/// bare call `name(`. Both tail readings check this shape — at the
/// return site and at the assignment site — before confirming that
/// nothing but the call's result follows.
fn call_args<'a>(s: &'a str, name: &str) -> Option<&'a str> {
    s.strip_prefix(&format!("{name}("))
}

/// The right-hand side of the last plain `var =` assignment on the
/// (string-blanked) line, or `None` when the line does not assign to
/// `var`. Comparisons (`==`) and compound assignments (`+=`) are not
/// plain assignments. A store through a pointer (`*v =` or `p->v =`)
/// does not bind `var` itself. The last assignment wins, so
/// `v = name(x); v = 0;` on one line does not read as the call.
fn assignment_rhs<'a>(line: &'a str, var: &str) -> Option<&'a str> {
    let bytes = line.as_bytes();
    let mut from = 0usize;
    let mut rhs = None;
    while let Some(offset) = line[from..].find(var) {
        let pos = from + offset;
        from = pos + var.len();
        let binds_var = pos == 0
            || !(bytes[pos - 1].is_ascii_alphanumeric()
                || bytes[pos - 1] == b'_'
                || bytes[pos - 1] == b'*'
                || bytes[pos - 1] == b'>');
        let after = line[pos + var.len()..].trim_start();
        if binds_var && after.starts_with('=') && !after.starts_with("==") {
            rhs = Some(after[1..].trim_start());
        }
    }
    rhs
}

/// Whether `s` is a bare identifier — the shape a `return v;` local
/// takes before the assignment scan looks for the call behind it.
fn is_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// True when `rest` (just past `name(`) closes the call and nothing but an
/// optional `;` follows it.
fn returns_call_result(rest: &str) -> bool {
    let bytes = rest.as_bytes();
    let mut depth = 1usize;
    let mut in_string = false;
    let mut escaped = false;
    for (idx, b) in bytes.iter().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        match b {
            b'\\' if in_string => escaped = true,
            b'"' => in_string = !in_string,
            b'(' if !in_string => depth += 1,
            b')' if !in_string => {
                depth -= 1;
                if depth == 0 {
                    return rest[idx + 1..]
                        .trim()
                        .trim_end_matches(';')
                        .trim()
                        .is_empty();
                }
            }
            _ => {}
        }
    }
    false
}

/// How many times `needle` ("name(") appears in `line` outside a string
/// literal and not as part of a longer identifier (`foo_bar(` must not
/// match `foo(`). The cross-function pass reuses this same scan to
/// derive its call edges, so the recursion reading and the cycle
/// reading cannot disagree about what a call site is.
pub(crate) fn count_ident_calls(line: &str, needle: &str) -> usize {
    let bytes = line.as_bytes();
    let mut in_string = false;
    let mut escaped = false;
    let mut hits = 0usize;
    for idx in 0..bytes.len() {
        if escaped {
            escaped = false;
            continue;
        }
        match bytes[idx] {
            b'\\' if in_string => escaped = true,
            b'"' => in_string = !in_string,
            _ => {}
        }
        if !in_string
            // Byte-level so `idx` landing on a UTF-8 continuation byte of
            // a multi-byte char (outside a string literal) cannot panic.
            // The needle starts with an ASCII identifier byte, so a match
            // can never begin mid-char anyway.
            && bytes[idx..].starts_with(needle.as_bytes())
            && (idx == 0 || !(bytes[idx - 1].is_ascii_alphanumeric() || bytes[idx - 1] == b'_'))
        {
            hits += 1;
        }
    }
    hits
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(name: &str, inner: &str) -> String {
        format!("\nundefined {name}(int n)\n\n{{\n{inner}}}\n")
    }

    #[test]
    fn detects_direct_self_call() {
        let code = body(
            "factorial",
            "    if (n == 0) return 1;\n    return n * factorial(n - 1);\n",
        );
        let f = RecursionDetector.detect("factorial", &code).unwrap();
        assert_eq!(f.function, "factorial");
        assert_eq!(f.self_calls, 1);
        assert!(!f.is_tail_call);
        assert!(!f.in_loop);
        assert_eq!(u8::from(f.confidence), 70);
        assert_eq!(
            f.suggestion,
            "keep recursive fn factorial(...) or convert to loop"
        );
    }

    #[test]
    fn signature_line_is_not_a_call() {
        let code = body("factorial", "    return 0;\n");
        assert!(RecursionDetector.detect("factorial", &code).is_none());
    }

    #[test]
    fn tail_call_detected_and_boosts_confidence() {
        let code = body(
            "walk",
            "    if (n == 0) return 0;\n    return walk(n - 1);\n",
        );
        let f = RecursionDetector.detect("walk", &code).unwrap();
        assert!(f.is_tail_call);
        assert_eq!(u8::from(f.confidence), 80);
        assert_eq!(f.suggestion, "replace with loop { ... } (tail call)");
        assert!(f.evidence.ends_with("(tail call)"));
    }

    #[test]
    fn extra_self_calls_add_confidence_up_to_cap() {
        let code = body(
            "fib",
            "    if (n < 2) return n;\n    return fib(n - 1) + fib(n - 2);\n",
        );
        let f = RecursionDetector.detect("fib", &code).unwrap();
        assert_eq!(f.self_calls, 2);
        assert_eq!(u8::from(f.confidence), 75);
        assert_eq!(
            f.suggestion,
            "keep recursive fn fib(...) or carry the work on an explicit stack"
        );

        let code = body(
            "m",
            "    if (a) return m(1);\n    if (b) return m(2);\n    return m(3) + m(4);\n",
        );
        let f = RecursionDetector.detect("m", &code).unwrap();
        assert_eq!(f.self_calls, 4);
        assert_eq!(u8::from(f.confidence), 90);
    }

    #[test]
    fn similar_names_are_not_self_calls() {
        let code = body("foo", "    return foo_bar(1) + myfoo(2);\n");
        assert!(RecursionDetector.detect("foo", &code).is_none());
    }

    #[test]
    fn string_literals_are_not_calls() {
        let code = body("logger", "    puts(\"logger(started)\");\n");
        assert!(RecursionDetector.detect("logger", &code).is_none());
    }

    #[test]
    fn a_self_call_nested_in_a_loop_is_flagged_as_a_depth_multiplier() {
        let code = body(
            "traverse",
            "    while (node != 0) {\n        traverse(node - 1);\n        node = node - 1;\n    }\n",
        );
        let f = RecursionDetector
            .detect("traverse", &code)
            .expect("loop-nested self-call should be detected");
        assert!(f.in_loop, "the graph shows the call inside the loop body");
        assert!(!f.is_tail_call);
        assert_eq!(
            u8::from(f.confidence),
            70,
            "the depth flag does not move the confidence",
        );
        assert_eq!(
            f.suggestion, "keep recursive fn traverse(...) or carry the work on an explicit stack",
            "the suggestion names the explicit-stack conversion",
        );
        assert_eq!(f.evidence, "traverse() calls itself 1x (nested in a loop)");
    }

    #[test]
    fn a_self_call_in_a_goto_loop_body_reads_as_nested_too() {
        let code = body(
            "traverse",
            "LAB_top:\n    traverse(node - 1);\n    node = node - 1;\n    goto LAB_top;\n",
        );
        let f = RecursionDetector
            .detect("traverse", &code)
            .expect("goto-loop self-call should be detected");
        assert!(f.in_loop, "a goto back to a label is a loop body too");
    }

    #[test]
    fn a_self_call_outside_any_loop_reads_exactly_as_today() {
        let code = body(
            "traverse",
            "    while (node != 0) {\n        node = node - 1;\n    }\n    traverse(node - 1);\n",
        );
        let f = RecursionDetector
            .detect("traverse", &code)
            .expect("past-the-loop self-call should be detected");
        assert!(!f.in_loop, "the call sits past the loop's closing brace",);
        assert_eq!(
            f.suggestion,
            "keep recursive fn traverse(...) or convert to loop"
        );
        assert_eq!(f.evidence, "traverse() calls itself 1x");
    }

    #[test]
    fn loop_shape_spelled_in_a_string_literal_invents_no_depth_flag() {
        let code = body(
            "logger",
            "    puts(\"while (logger) { logger(1); }\");\n    logger(0);\n",
        );
        let f = RecursionDetector
            .detect("logger", &code)
            .expect("spelled-out self-call should be detected");
        assert_eq!(f.self_calls, 1);
        assert!(
            !f.in_loop,
            "the while spelled inside the string invents no loop body",
        );
    }

    #[test]
    fn a_tail_call_spread_over_lines_reads_as_a_tail_call() {
        // The Ghidra tail shape the line rule misses: the call's
        // result stored in a local, then returned from the same block
        // whose only exit is that return.
        let code = body(
            "walk",
            "    int uVar1;\n    uVar1 = walk(n - 1);\n    return uVar1;\n",
        );
        let f = RecursionDetector
            .detect("walk", &code)
            .expect("spread-over-lines self-call should be detected");
        assert!(f.is_tail_call, "the return hands back exactly the call");
        assert_eq!(u8::from(f.confidence), 80);
        assert_eq!(f.suggestion, "replace with loop { ... } (tail call)");
    }

    #[test]
    fn a_tail_call_nested_in_a_block_reads_as_a_tail_call() {
        let code = body(
            "walk",
            "    if (n == 0) {\n        int uVar1;\n        uVar1 = walk(n - 1);\n        return uVar1;\n    }\n    return 0;\n",
        );
        let f = RecursionDetector
            .detect("walk", &code)
            .expect("block-nested self-call should be detected");
        assert!(
            f.is_tail_call,
            "the if-body block's only exit is the return of the call's result",
        );
    }

    #[test]
    fn a_return_join_after_a_label_reads_the_call_block_s_only_exit() {
        // The call block falls through to the return block as its one
        // and only way out — the graph's tail position.
        let code = body(
            "walk",
            "    int uVar1;\n    uVar1 = walk(n - 1);\nLAB_join:\n    return uVar1;\n",
        );
        let f = RecursionDetector
            .detect("walk", &code)
            .expect("join-block self-call should be detected");
        assert!(f.is_tail_call, "the call block's only exit is the return");
    }

    #[test]
    fn a_combined_result_is_not_a_tail_call_under_the_graph_reading() {
        let code = body(
            "factorial",
            "    int uVar1;\n    uVar1 = factorial(n - 1) + 1;\n    return uVar1;\n",
        );
        let f = RecursionDetector
            .detect("factorial", &code)
            .expect("combined-result self-call should be detected");
        assert!(
            !f.is_tail_call,
            "returning more than the call's result is not a tail call",
        );
    }

    #[test]
    fn a_discarded_call_before_a_return_is_not_a_tail_call() {
        let code = body("walk", "    walk(n - 1);\n    return 0;\n");
        let f = RecursionDetector
            .detect("walk", &code)
            .expect("discarded self-call should be detected");
        assert!(
            !f.is_tail_call,
            "the call's result never reaches the return, so the frame is still needed",
        );
    }

    #[test]
    fn a_reassigned_local_breaks_the_graph_tail_reading() {
        let code = body(
            "walk",
            "    uVar1 = walk(n - 1);\n    uVar1 = 0;\n    return uVar1;\n",
        );
        let f = RecursionDetector
            .detect("walk", &code)
            .expect("reassigned-local self-call should be detected");
        assert!(
            !f.is_tail_call,
            "the last assignment to the returned local is not the call",
        );
    }

    #[test]
    fn a_tail_call_inside_a_loop_carries_both_readings() {
        let code = body(
            "walk",
            "    while (n > 0) {\n        n = n - 1;\n        return walk(n);\n    }\n",
        );
        let f = RecursionDetector
            .detect("walk", &code)
            .expect("loop-nested tail self-call should be detected");
        assert!(f.is_tail_call, "the block's exit is the return");
        assert!(f.in_loop, "and that block sits inside the loop body");
        assert_eq!(u8::from(f.confidence), 80);
        assert_eq!(
            f.evidence,
            "walk() calls itself 1x (tail call) (nested in a loop)"
        );
    }

    #[test]
    fn a_goto_onto_a_return_block_reads_as_a_tail_call_too() {
        // Ghidra's join shape with the jump spelled out: the call
        // block's one and only way out is a `goto` onto the return
        // block — the same tail position the fall-through case has.
        let code = body(
            "walk",
            "    int uVar1;\n    if (n == 0) return 0;\n    uVar1 = walk(n - 1);\n    goto LAB_join;\nLAB_join:\n    return uVar1;\n",
        );
        let f = RecursionDetector
            .detect("walk", &code)
            .expect("goto-join self-call should be detected");
        assert!(
            f.is_tail_call,
            "the call block's only exit jumps to the return"
        );
    }

    #[test]
    fn a_same_line_reassignment_breaks_the_graph_tail_reading() {
        let code = body(
            "walk",
            "    int uVar1;\n    uVar1 = walk(n - 1); uVar1 = 0;\n    return uVar1;\n",
        );
        let f = RecursionDetector
            .detect("walk", &code)
            .expect("same-line reassignment self-call should be detected");
        assert!(
            !f.is_tail_call,
            "the last assignment to the returned local on the line is not the call",
        );
    }

    #[test]
    fn a_store_through_a_pointer_does_not_park_the_call_result_in_the_local() {
        let code = body(
            "walk",
            "    int *pv;\n    *pv = walk(n - 1);\n    return pv;\n",
        );
        let f = RecursionDetector
            .detect("walk", &code)
            .expect("pointer-store self-call should be detected");
        assert!(
            !f.is_tail_call,
            "the call's result lands behind the pointer, not in the returned local",
        );
    }

    #[test]
    fn multibyte_chars_outside_strings_do_not_panic_the_byte_scan() {
        // 'ﾟ' is 3 bytes; the scan walks every byte index, and slicing the
        // line at one of its continuation bytes used to panic.
        let line = "    // ﾟﾟﾟ comment ﾟ\n    return n * factorial(n - 1);";
        assert_eq!(count_ident_calls(line, "factorial("), 1);
    }
}
