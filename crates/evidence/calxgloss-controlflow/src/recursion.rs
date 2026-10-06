//! Self-recursion detection.
//!
//! A function that calls itself is reported with its self-call count and
//! whether any call sits in tail position (`return name(...)`). The scan
//! starts after the body's opening brace so the signature line — which
//! contains the function's own name — never counts as a call.

use calxgloss_types::Confidence;

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
        let mut calls = 0usize;
        let mut tail_call = false;
        for line in &lines[body_start..] {
            let trimmed = line.trim();
            let hits = count_ident_calls(trimmed, &needle);
            calls += hits;
            if hits > 0 && is_tail_return(trimmed, name) {
                tail_call = true;
            }
        }
        if calls == 0 {
            return None;
        }

        // Base 70, +10 for a tail call, +5 per extra self-call, capped at 90.
        let score = (70 + u8::from(tail_call) * 10 + (calls as u8 - 1) * 5).min(90);
        let suggestion = if tail_call {
            "replace with loop { ... } (tail call)".to_string()
        } else if calls >= 2 {
            // Branching recursion: the call tree's depth can outgrow the
            // stack, so name the explicit-stack alternative too.
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
        Some(SelfRecursion {
            function: name.to_string(),
            is_tail_call: tail_call,
            self_calls: calls,
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
/// match `foo(`).
fn count_ident_calls(line: &str, needle: &str) -> usize {
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
            && line[idx..].starts_with(needle)
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
}
