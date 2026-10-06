//! Function-pointer array detection.
//!
//! This module provides [`FpArrayDetector`], which carries the table
//! names a scan reads decompiled bodies against — the handler-array
//! spellings a program keeps its dispatch in, `handlers` and
//! `callback_table` and their kin — and reads each indexed indirect
//! call as a call through an array of function pointers.
//!
//! Ghidra decompiles a call through a function-pointer array element
//! into one of three shapes: the bare indexed call `handlers[i](args)`
//! when the array's element type is known, the dereference
//! `(*handlers[i])(args)` when it is not, and the cast dereference
//! `(*(int (**)(int))handlers[i])(args)` when the call site carries an
//! explicit function-pointer cast. All three read the same way here:
//! a configured table name, indexed, called.
//!
//! [`FpArrayDetector::detect`] runs the reading: it walks a decompiled
//! body's indexed calls in source order and emits one [`FpArrayCall`]
//! per call site — a table call needs no pairing to complete the
//! picture, so one call is a whole finding.

use crate::types::FpArrayCall;
use calxgloss_ghidra::DecompiledFunction;

// ============================================================
// Detector
// ============================================================

/// Function-pointer array detection over decompiled functions.
///
/// The detector owns the table-name set a scan reads bodies against:
/// plain identifier spellings, matched whole. The set is configurable
/// — supply it whole through [`with_names`](Self::with_names) or grow
/// it one name at a time with [`add_name`](Self::add_name) — and
/// [`names`](Self::names) reports it in configuration order, so two
/// detectors built the same way scan identically and results diff
/// cleanly. The standard set ([`default_fp_array_tables`]) names the
/// handler-array spellings decompiled binaries most often use; a
/// program that files its dispatch under a different name configures
/// it through [`with_names`](Self::with_names). The detector holds no
/// Ghidra client of its own and never writes back to the program; one
/// detector serves an entire scan and can be shared by reference
/// across concurrent per-function passes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FpArrayDetector {
    names: Vec<String>,
}

impl FpArrayDetector {
    /// A detector with no names configured: every body it is handed
    /// reads nothing until the standard set arrives through
    /// [`with_default_names`](Self::with_default_names) or names join
    /// one at a time through [`add_name`](Self::add_name).
    pub fn new() -> Self {
        Self::default()
    }

    /// A detector that scans against the standard name set —
    /// [`default_fp_array_tables`] — in its configuration order.
    pub fn with_default_names() -> Self {
        Self::with_names(default_fp_array_tables())
    }

    /// A detector that scans against exactly `names`, each kept in the
    /// order it is given.
    pub fn with_names(names: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            names: names.into_iter().map(Into::into).collect(),
        }
    }

    /// Add one name to the set this detector scans against.
    pub fn add_name(&mut self, name: impl Into<String>) {
        self.names.push(name.into());
    }

    /// The names this detector scans against, in configuration order.
    pub fn names(&self) -> &[String] {
        &self.names
    }

    /// The function-pointer array calls one function's body carries.
    ///
    /// The reading walks the body's indexed indirect calls in source
    /// order — outside string literals, whole names only, through the
    /// bare `table[i](args)`, dereference `(*table[i])(args)`, and
    /// cast-dereference `(*(cast)table[i])(args)` shapes — and
    /// reports every call through a configured table name as one
    /// [`FpArrayCall`]: the table is the name as written, the
    /// suggestion the boxed-closure array the elements read as, and
    /// the evidence the call's own line. Findings come back in call
    /// order, so two scans of one body diff cleanly.
    pub fn detect(&self, func: &DecompiledFunction) -> Vec<FpArrayCall> {
        let mut calls = Vec::new();
        for site in indexed_calls(&func.body, &self.names) {
            calls.push(FpArrayCall {
                function: func.name.clone(),
                table: site.table.to_string(),
                suggestion: FP_ARRAY_SUGGESTION.to_string(),
                confidence: FP_ARRAY_CONFIDENCE.into(),
                evidence: line_at(&func.body, site.offset),
            });
        }
        calls
    }
}

// ============================================================
// The reading
// ============================================================

/// Confidence of an fp-array reading from a single indexed indirect
/// call through a configured table name: the call shape is explicit —
/// an element of a named table is being called — but the element type
/// is the decompiler's guess, not a fact read from the body.
const FP_ARRAY_CONFIDENCE: u8 = 70;

/// The Rust pattern a function-pointer array call suggests: an array
/// of boxed closures, so the handler table survives translation as
/// data the compiler can check instead of an opaque indirect call.
const FP_ARRAY_SUGGESTION: &str = "Vec<Box<dyn Fn(...)>>";

/// An indexed indirect call found in a body: the table name and the
/// byte offset of the table name.
struct IndexedCallSite<'a> {
    table: &'a str,
    offset: usize,
}

/// Every indexed indirect call `table[...]` in the body whose table
/// name is configured, scanned outside string literals so a stray
/// name in a format string cannot be read as a call. A name preceded
/// by an identifier byte is the tail of a longer identifier, and one
/// preceded by `:` is a qualified name the decompiler resolved to a
/// different symbol; neither matches a plain table — a table reached
/// through an object (`obj.handlers[i]`, `p->callbacks[i]`) does, the
/// same table spelled through a field. The call must actually be
/// called: the indexed read `x = handlers[i];` stores a pointer and
/// says nothing about dispatch. A call whose brackets or argument
/// list never close — a truncated decompile — yields nothing.
fn indexed_calls<'a>(body: &'a str, names: &[String]) -> Vec<IndexedCallSite<'a>> {
    let bytes = body.as_bytes();
    let mut calls = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => i = skip_string(bytes, i + 1),
            b if b.is_ascii_alphabetic() || b == b'_' => {
                if i > 0 && (is_ident_byte(bytes[i - 1]) || bytes[i - 1] == b':') {
                    i += 1;
                    continue;
                }
                let mut j = i;
                while j < bytes.len() && is_ident_byte(bytes[j]) {
                    j += 1;
                }
                let name = &body[i..j];
                if names.iter().any(|n| n == name) {
                    let open = skip_ws(bytes, j);
                    if bytes.get(open) == Some(&b'[')
                        && let Some(close) = matching_bracket(bytes, open)
                        && let Some(call_open) = call_open_after(bytes, close)
                        && closing_paren(body, call_open).is_some()
                    {
                        calls.push(IndexedCallSite {
                            table: name,
                            offset: i,
                        });
                    }
                }
                i = j;
            }
            _ => i += 1,
        }
    }
    calls
}

/// The offset of the argument-list `(` of a call through the indexed
/// read whose `]` sits at `close`, for any of the three call shapes.
///
/// The bare shape `table[i](args)` puts the `(` straight after the
/// `]`. The dereference and cast shapes wrap the read — `(*table[i])`
/// and `(*(cast)table[i])`, however the table itself is reached
/// (`p->handlers[i]`) — so the `(` follows the wrapping `)`: the `)`
/// after the `]` must close a parenthesis whose contents start with
/// `*`, and the call's `(` follows it. A read that is not called — an
/// assignment or a comparison — has no such `(` and returns `None`.
fn call_open_after(bytes: &[u8], close: usize) -> Option<usize> {
    let mut k = skip_ws(bytes, close + 1);
    if bytes.get(k) == Some(&b'(') {
        return Some(k);
    }
    if bytes.get(k) == Some(&b')') {
        let wrap_open = matching_open_paren_back(bytes, k)?;
        if bytes.get(wrap_open + 1) != Some(&b'*') {
            return None;
        }
        k = skip_ws(bytes, k + 1);
        if bytes.get(k) == Some(&b'(') {
            return Some(k);
        }
    }
    None
}

/// The index of `]` matching the `[` at `open`, skipping string literals.
fn matching_bracket(bytes: &[u8], open: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut i = open;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => i = skip_string(bytes, i + 1),
            b'[' => {
                depth += 1;
                i += 1;
            }
            b']' => {
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

/// The index of the `(` matching the `)` at `close`, walking back
/// through nested parentheses. String literals are not re-scanned
/// backwards; a decompiled string's parentheses balance in the source
/// the decompiler wrote, so the walk stays exact on real bodies.
fn matching_open_paren_back(bytes: &[u8], close: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut i = close;
    loop {
        match bytes[i] {
            b')' => depth += 1,
            b'(' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
        if i == 0 {
            return None;
        }
        i -= 1;
    }
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// The trimmed source line containing `offset`.
fn line_at(body: &str, offset: usize) -> String {
    let line = body[..offset].matches('\n').count();
    body.lines().nth(line).unwrap_or("").trim().to_string()
}

// ============================================================
// The standard name set
// ============================================================

/// The standard table names: the handler-array spellings a scan
/// recognizes as function-pointer tables out of the box — the
/// `handlers` family and the `callbacks` family, the plain `dispatch`
/// and `funcs` spellings, and the `fn_table` and `events` spellings a
/// message loop or event system keeps its targets in. These are
/// conventions, not laws: a program that files its dispatch under a
/// different name configures it through [`FpArrayDetector::with_names`].
pub fn default_fp_array_tables() -> Vec<String> {
    [
        "handlers",
        "handler_table",
        "callbacks",
        "callback_table",
        "dispatch",
        "dispatch_table",
        "funcs",
        "functions",
        "fn_table",
        "events",
    ]
    .into_iter()
    .map(String::from)
    .collect()
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
        let detector = FpArrayDetector::new();
        assert!(detector.names().is_empty());
        assert_eq!(detector, FpArrayDetector::default());
        assert_eq!(detector.clone(), detector);
    }

    #[test]
    fn a_detector_keeps_the_names_it_is_configured_with() {
        let detector = FpArrayDetector::with_names(["handlers", "callbacks"]);
        // Configuration order is scan order: two detectors built the
        // same way see the same names in the same order.
        let names: Vec<&str> = detector.names().iter().map(String::as_str).collect();
        assert_eq!(names, ["handlers", "callbacks"]);
    }

    #[test]
    fn added_names_join_the_set_in_order() {
        let mut detector = FpArrayDetector::new();
        detector.add_name("handlers");
        detector.add_name("events");
        let names: Vec<&str> = detector.names().iter().map(String::as_str).collect();
        assert_eq!(names, ["handlers", "events"]);
    }

    #[test]
    fn a_detector_can_be_shared_across_scans() {
        // One detector is driven concurrently over a program's
        // functions, so sharing one by reference across tasks must
        // stay sound.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<FpArrayDetector>();
    }

    #[test]
    fn the_standard_tables_name_the_handler_and_callback_families() {
        let tables = default_fp_array_tables();
        let named: Vec<&str> = tables.iter().map(String::as_str).collect();
        assert_eq!(
            named,
            [
                "handlers",
                "handler_table",
                "callbacks",
                "callback_table",
                "dispatch",
                "dispatch_table",
                "funcs",
                "functions",
                "fn_table",
                "events",
            ]
        );
    }

    #[test]
    fn a_detector_built_with_the_standard_set_carries_it() {
        let detector = FpArrayDetector::with_default_names();
        assert_eq!(detector.names(), default_fp_array_tables());
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

    fn detect(body: &str) -> Vec<FpArrayCall> {
        FpArrayDetector::with_default_names().detect(&function(body))
    }

    #[test]
    fn a_cast_dereference_call_is_detected_as_an_fp_array_call() {
        let calls = detect("  (*(int (**)(int))handlers[uVar1])(param_1);");
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].function, "FUN_18003ab00");
        assert_eq!(calls[0].table, "handlers");
        assert_eq!(calls[0].suggestion, "Vec<Box<dyn Fn(...)>>");
        assert_eq!(calls[0].confidence, FP_ARRAY_CONFIDENCE);
        // The evidence is the call's own line.
        assert_eq!(
            calls[0].evidence,
            "(*(int (**)(int))handlers[uVar1])(param_1);"
        );
    }

    #[test]
    fn a_dereference_call_is_detected_too() {
        let calls = detect("  (*callbacks[uVar2])(param_1,param_2);");
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].table, "callbacks");
        assert_eq!(calls[0].suggestion, "Vec<Box<dyn Fn(...)>>");
    }

    #[test]
    fn a_bare_indexed_call_is_detected_when_the_element_type_is_known() {
        let calls = detect("  dispatch[uVar3](param_1);");
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].table, "dispatch");
    }

    #[test]
    fn a_table_reached_through_an_object_is_detected() {
        // The same table spelled through a field: Ghidra writes
        // `p->handlers` for a table held in a struct.
        let calls = detect("  (*(int (**)(int))p->handlers[uVar1])(param_1);");
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].table, "handlers");
    }

    #[test]
    fn each_call_site_is_its_own_finding_in_call_order() {
        let calls = detect(
            "\
  (*(int (**)(int))handlers[uVar1])(param_1);
  iVar2 = iVar2 + 1;
  (*(int (**)(int))handlers[uVar2])(param_2);",
        );
        assert_eq!(calls.len(), 2);
        assert_eq!(
            calls[0].evidence,
            "(*(int (**)(int))handlers[uVar1])(param_1);"
        );
        assert_eq!(
            calls[1].evidence,
            "(*(int (**)(int))handlers[uVar2])(param_2);"
        );
    }

    #[test]
    fn a_name_spelled_inside_a_string_literal_invents_no_call() {
        assert!(detect("  printf(\"handlers[i] dispatch\");").is_empty());
    }

    #[test]
    fn a_longer_or_qualified_name_matches_no_configured_name() {
        // Whole names only: a longer spelling is a different symbol,
        // and a qualified name the decompiler resolved is another one.
        assert!(
            detect(
                "\
  (*(int (**)(int))my_handlers[uVar1])(param_1);
  ns::handlers[uVar2](param_2);"
            )
            .is_empty()
        );
    }

    #[test]
    fn an_indexed_read_that_is_not_called_detects_nothing() {
        // Storing or comparing a table element says nothing about
        // dispatch; only a call through the element is a finding.
        assert!(
            detect(
                "\
  pf = handlers[uVar1];
  if (handlers[uVar2] == (code *)0x0) { return; }",
            )
            .is_empty()
        );
    }

    #[test]
    fn a_dereferenced_read_that_is_not_called_detects_nothing() {
        assert!(detect("  pf = *handlers[uVar1];").is_empty());
    }

    #[test]
    fn a_truncated_body_detects_nothing() {
        // An unclosed bracket or argument list is a partial decompile;
        // nothing can be said about the call it was reaching for.
        assert!(detect("  (*(int (**)(int))handlers[uVar1])(param_1;").is_empty());
        assert!(detect("  (*handlers[uVar1])(param_1").is_empty());
    }

    #[test]
    fn a_detector_with_no_names_detects_nothing() {
        let detector = FpArrayDetector::new();
        let calls = detector.detect(&function("  (*(int (**)(int))handlers[uVar1])(param_1);"));
        assert!(calls.is_empty());
    }

    #[test]
    fn custom_names_behave_like_the_standard_ones() {
        // The name set is swappable whole: a program that files its
        // dispatch under its own spelling scans the same way.
        let detector = FpArrayDetector::with_names(["msg_table"]);
        let calls = detector.detect(&function("  (*(code *)msg_table[uVar1])(param_1);"));
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].table, "msg_table");
        assert_eq!(calls[0].confidence, FP_ARRAY_CONFIDENCE);
    }
}
